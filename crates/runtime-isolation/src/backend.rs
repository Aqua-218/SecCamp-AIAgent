//! Backend-independent isolation orchestration and failure handling.

use std::{error::Error, fmt};

use crate::{IsolationConfig, Syscall};

/// One irreversible security boundary or reversible setup operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IsolationStep {
    /// Create the required user, mount, PID, network, IPC, UTS, and cgroup namespaces.
    Namespaces,
    /// Install the single-entry UID/GID mapping.
    IdentityMap,
    /// Create and join a cgroup v2 with resource limits.
    CgroupV2,
    /// Bind-mount and pivot into the read-only root filesystem.
    ReadOnlyRootfs,
    /// Attach the capability filesystem workspace.
    Workspace,
    /// Attach the size-limited writable tmpfs.
    LimitedTmpfs,
    /// Replace `/proc` with an empty read-only mask.
    MaskProc,
    /// Replace `/dev` with an empty read-only, node-free mask.
    MaskDevices,
    /// Close inherited descriptors that are not part of the workload contract.
    CloseInheritedFileDescriptors,
    /// Install the static Landlock file envelope.
    Landlock,
    /// Clear effective, permitted, inheritable, and bounding capabilities.
    DropCapabilities,
    /// Set `PR_SET_NO_NEW_PRIVS`.
    NoNewPrivs,
    /// Install the default-deny seccomp filter.
    Seccomp,
}

/// A privileged backend operation failure.
#[derive(Clone, Debug)]
pub struct BackendError {
    /// Operation that failed.
    pub step: IsolationStep,
    /// Human-readable failure context.
    pub message: String,
    /// Linux errno when the kernel supplied one.
    pub errno: Option<i32>,
}

impl BackendError {
    /// Creates a backend failure with optional errno.
    pub fn new(step: IsolationStep, message: impl Into<String>, errno: Option<i32>) -> Self {
        Self {
            step,
            message: message.into(),
            errno,
        }
    }
}

impl fmt::Display for BackendError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.errno {
            Some(errno) => write!(
                formatter,
                "{} failed ({}) with errno {errno}",
                self.step, self.message
            ),
            None => write!(formatter, "{} failed ({})", self.step, self.message),
        }
    }
}

impl Error for BackendError {}

impl fmt::Display for IsolationStep {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Namespaces => "namespace setup",
            Self::IdentityMap => "identity map",
            Self::CgroupV2 => "cgroup v2 setup",
            Self::ReadOnlyRootfs => "read-only rootfs setup",
            Self::Workspace => "workspace mount",
            Self::LimitedTmpfs => "limited tmpfs setup",
            Self::MaskProc => "/proc mask",
            Self::MaskDevices => "/dev mask",
            Self::CloseInheritedFileDescriptors => "inherited descriptor close",
            Self::Landlock => "Landlock setup",
            Self::DropCapabilities => "capability drop",
            Self::NoNewPrivs => "no_new_privs setup",
            Self::Seccomp => "seccomp setup",
        };
        formatter.write_str(name)
    }
}

impl IsolationStep {
    const fn is_irreversible(self) -> bool {
        match self {
            Self::Namespaces
            | Self::IdentityMap
            | Self::ReadOnlyRootfs
            | Self::CloseInheritedFileDescriptors
            | Self::Landlock
            | Self::DropCapabilities
            | Self::NoNewPrivs
            | Self::Seccomp => true,
            Self::CgroupV2
            | Self::Workspace
            | Self::LimitedTmpfs
            | Self::MaskProc
            | Self::MaskDevices => false,
        }
    }
}

/// Non-mutating host capability detection output.
#[derive(Clone, Debug)]
pub struct CapabilityReport {
    /// Whether the required namespace operations are available.
    pub namespaces_available: bool,
    /// Whether the configured cgroup v2 hierarchy is writable.
    pub cgroup_v2_available: bool,
    /// Kernel Landlock ABI, if it could be queried.
    pub landlock_abi: Option<u32>,
    /// Whether seccomp filter installation is available.
    pub seccomp_available: bool,
    /// Explicit reasons the report is insufficient.
    pub reasons: Vec<String>,
}

impl CapabilityReport {
    /// Creates a report suitable for a host with all required facilities.
    pub fn supported(landlock_abi: u32) -> Self {
        Self {
            namespaces_available: true,
            cgroup_v2_available: true,
            landlock_abi: Some(landlock_abi),
            seccomp_available: true,
            reasons: Vec::new(),
        }
    }

    /// Creates a report for a host where isolation cannot be attempted.
    pub fn unavailable<I, S>(reasons: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            namespaces_available: false,
            cgroup_v2_available: false,
            landlock_abi: None,
            seccomp_available: false,
            reasons: reasons.into_iter().map(Into::into).collect(),
        }
    }

    /// Returns whether this report satisfies a policy.
    pub fn is_sufficient(&self, config: &IsolationConfig) -> bool {
        self.namespaces_available
            && self.cgroup_v2_available
            && self.seccomp_available
            && self
                .landlock_abi
                .is_some_and(|abi| abi >= config.landlock.required_abi)
            && self.reasons.is_empty()
    }
}

/// Errors returned while validating or applying an isolation policy.
#[derive(Debug)]
pub enum IsolationError {
    /// The policy contains an unsafe or impossible combination.
    InvalidConfig(String),
    /// Host capability detection refused to start the workload.
    CapabilityUnavailable(CapabilityReport),
    /// A privileged operation failed.
    Backend(BackendError),
    /// A rollback operation failed after an earlier operation failed.
    Rollback {
        /// The operation that caused the transaction to stop.
        original: BackendError,
        /// Rollback failures, in reverse completion order.
        failures: Vec<BackendError>,
    },
    /// Applying an irreversible step may have partially changed process state.
    ///
    /// [`RuntimeIsolation::apply`] enforces this obligation by aborting the
    /// current process. Code using the crate-internal non-enforcing transaction
    /// path must not allow the process to continue.
    TerminationRequired {
        /// The operation that caused the transaction to stop.
        original: BackendError,
        /// Rollback failures, in reverse completion order.
        failures: Vec<BackendError>,
    },
    /// A network, namespace, or other forbidden syscall was requested.
    ForbiddenSyscall(Syscall),
    /// A syscall has no verified number on this target architecture.
    UnsupportedSyscall(Syscall),
}

impl fmt::Display for IsolationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig(message) => {
                write!(formatter, "invalid isolation config: {message}")
            }
            Self::CapabilityUnavailable(report) => write!(
                formatter,
                "isolation capability detection failed: {}",
                report.reasons.join("; ")
            ),
            Self::Backend(error) => error.fmt(formatter),
            Self::Rollback { original, failures } => write!(
                formatter,
                "{}; rollback failed for {} completed step(s)",
                original,
                failures.len()
            ),
            Self::TerminationRequired { original, failures } => write!(
                formatter,
                "{}; process termination is required after irreversible isolation setup ({} rollback failure(s))",
                original,
                failures.len()
            ),
            Self::ForbiddenSyscall(syscall) => {
                write!(
                    formatter,
                    "forbidden syscall '{syscall}' cannot enter the allowlist"
                )
            }
            Self::UnsupportedSyscall(syscall) => {
                write!(
                    formatter,
                    "syscall '{syscall}' is unsupported on this architecture"
                )
            }
        }
    }
}

impl Error for IsolationError {}

/// Proof that every isolation step completed in the required order.
#[derive(Clone, Debug)]
pub struct IsolationReceipt {
    steps: Vec<IsolationStep>,
}

impl IsolationReceipt {
    /// Returns the completed steps in execution order.
    pub fn steps(&self) -> &[IsolationStep] {
        &self.steps
    }
}

/// Interface for privileged isolation operations.
pub trait IsolationBackend {
    /// Detects host capabilities without mutating the process.
    fn detect_capabilities(&mut self, config: &IsolationConfig) -> CapabilityReport;

    /// Executes one named setup operation.
    fn apply_step(
        &mut self,
        step: IsolationStep,
        config: &IsolationConfig,
    ) -> Result<(), BackendError>;

    /// Rolls back one previously completed operation.
    fn rollback_step(
        &mut self,
        step: IsolationStep,
        config: &IsolationConfig,
    ) -> Result<(), BackendError>;
}

/// Ordered isolation transaction coordinator.
pub struct RuntimeIsolation;

impl RuntimeIsolation {
    /// Applies a policy, rolling back reversible operations on failure.
    ///
    /// This function aborts the current process if an irreversible operation
    /// may have been partially applied. It must therefore run only in the
    /// expendable child process that will execute the workload.
    pub fn apply<B: IsolationBackend>(
        backend: &mut B,
        config: &IsolationConfig,
    ) -> Result<IsolationReceipt, IsolationError> {
        match Self::apply_transaction(backend, config) {
            Err(IsolationError::TerminationRequired { .. }) => std::process::abort(),
            outcome => outcome,
        }
    }

    /// Runs the isolation transaction without enforcing required termination.
    ///
    /// This is crate-visible only so tests can inspect the typed obligation
    /// without aborting the test process. Production callers must use
    /// [`Self::apply`].
    pub(crate) fn apply_transaction<B: IsolationBackend>(
        backend: &mut B,
        config: &IsolationConfig,
    ) -> Result<IsolationReceipt, IsolationError> {
        config.validate()?;
        let report = backend.detect_capabilities(config);
        if !report.is_sufficient(config) {
            return Err(IsolationError::CapabilityUnavailable(report));
        }

        let mut completed = Vec::new();
        for step in required_steps() {
            match backend.apply_step(step, config) {
                Ok(()) => completed.push(step),
                Err(original) => {
                    // A failed backend call may have applied only part of its
                    // operation, so attempting an irreversible step is enough
                    // to make reuse of this process unsafe.
                    let termination_required = step.is_irreversible()
                        || completed
                            .iter()
                            .copied()
                            .any(IsolationStep::is_irreversible);
                    let failures = completed
                        .iter()
                        .rev()
                        .filter_map(|completed_step| {
                            backend.rollback_step(*completed_step, config).err()
                        })
                        .collect::<Vec<_>>();
                    return if termination_required {
                        Err(IsolationError::TerminationRequired { original, failures })
                    } else if failures.is_empty() {
                        Err(IsolationError::Backend(original))
                    } else {
                        Err(IsolationError::Rollback { original, failures })
                    };
                }
            }
        }
        Ok(IsolationReceipt { steps: completed })
    }
}

/// Applies an isolation policy through the supplied backend.
///
/// Aborts the current process when an irreversible operation may have been
/// partially applied.
pub fn apply<B: IsolationBackend>(
    backend: &mut B,
    config: &IsolationConfig,
) -> Result<IsolationReceipt, IsolationError> {
    RuntimeIsolation::apply(backend, config)
}

fn required_steps() -> [IsolationStep; 13] {
    [
        IsolationStep::Namespaces,
        IsolationStep::IdentityMap,
        IsolationStep::CgroupV2,
        IsolationStep::ReadOnlyRootfs,
        IsolationStep::Workspace,
        IsolationStep::LimitedTmpfs,
        IsolationStep::MaskProc,
        IsolationStep::MaskDevices,
        IsolationStep::CloseInheritedFileDescriptors,
        IsolationStep::Landlock,
        IsolationStep::DropCapabilities,
        IsolationStep::NoNewPrivs,
        IsolationStep::Seccomp,
    ]
}

#[cfg(test)]
mod tests {
    use super::IsolationStep;

    #[test]
    fn irreversible_apply_attempt_requires_process_termination() {
        assert!(IsolationStep::Landlock.is_irreversible());
    }

    #[test]
    fn reversible_apply_attempt_does_not_itself_require_process_termination() {
        assert!(!IsolationStep::Workspace.is_irreversible());
    }
}
