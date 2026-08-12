//! Backend-independent isolation orchestration and failure handling.

use std::{error::Error, fmt, num::NonZeroU32};

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
    /// The legacy in-process API cannot perform the required PID child handoff.
    ChildHandoffRequired,
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
    /// [`RuntimeIsolation::spawn_isolated`] enforces this obligation by aborting
    /// the current process. Code using the crate-internal non-enforcing
    /// transaction path must not allow the process to continue.
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
            Self::ChildHandoffRequired => formatter.write_str(
                "isolation requires spawn_isolated so namespace preparation can hand off to a PID namespace child",
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

/// Stable kernel identity of one namespace inode.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NamespaceIdentity {
    device: u64,
    inode: u64,
}

impl NamespaceIdentity {
    /// Records the device and inode returned by a namespace link observation.
    pub const fn from_kernel(device: u64, inode: u64) -> Self {
        Self { device, inode }
    }

    /// Returns the namespace filesystem device number.
    pub const fn device(self) -> u64 {
        self.device
    }

    /// Returns the namespace inode number.
    pub const fn inode(self) -> u64 {
        self.inode
    }
}

/// Linear proof that the backend prepared a distinct PID namespace for a child.
#[derive(Debug, Eq, PartialEq)]
pub struct NamespacePreparation {
    parent: NamespaceIdentity,
    child: NamespaceIdentity,
}

impl NamespacePreparation {
    /// Creates a preparation attestation from kernel-observed namespace identities.
    ///
    /// Backend implementations are trusted to call this only after preparing all
    /// required namespaces and observing a child PID namespace distinct from the
    /// current process PID namespace.
    pub const fn attest(parent: NamespaceIdentity, child: NamespaceIdentity) -> Self {
        Self { parent, child }
    }

    /// Returns the PID namespace occupied by the preparing parent.
    pub const fn parent(&self) -> NamespaceIdentity {
        self.parent
    }

    /// Returns the PID namespace reserved for the spawned workload child.
    pub const fn child(&self) -> NamespaceIdentity {
        self.child
    }
}

/// Linear proof that kernel observation placed this process in the prepared namespace.
#[derive(Debug, Eq, PartialEq)]
pub struct PidNamespaceChild {
    namespace: NamespaceIdentity,
}

impl PidNamespaceChild {
    /// Creates a child-entry attestation after backend kernel verification.
    ///
    /// Backend implementations are trusted to compare the current PID namespace
    /// to [`NamespacePreparation::child`] before constructing this value.
    pub const fn attest(namespace: NamespaceIdentity) -> Self {
        Self { namespace }
    }

    /// Returns the verified workload PID namespace.
    pub const fn namespace(&self) -> NamespaceIdentity {
        self.namespace
    }
}

/// Namespace-launcher ownership of a successfully spawned isolation child.
///
/// This handle is returned in the process that prepared namespaces. That
/// launcher may already have irreversible process-global namespace changes and
/// must not resume trusted supervisor work.
#[derive(Debug, Eq, PartialEq)]
pub struct IsolatedChildProcess {
    pid: NonZeroU32,
    pid_namespace: NamespaceIdentity,
}

impl IsolatedChildProcess {
    /// Creates a parent handle from a positive child PID and prepared namespace.
    ///
    /// Backend implementations are trusted to use the PID returned by the spawn
    /// operation that consumed the corresponding [`NamespacePreparation`].
    pub const fn attest(pid: NonZeroU32, pid_namespace: NamespaceIdentity) -> Self {
        Self { pid, pid_namespace }
    }

    /// Returns the child PID as seen by the preparing parent.
    pub const fn pid(&self) -> NonZeroU32 {
        self.pid
    }

    /// Returns the PID namespace prepared for the child.
    pub const fn pid_namespace(&self) -> NamespaceIdentity {
        self.pid_namespace
    }
}

/// Process role returned by an explicit isolation spawn.
#[derive(Debug, Eq, PartialEq)]
pub enum SpawnOutcome<T> {
    /// The preparing launcher owns the spawned child and never receives a receipt.
    Parent(IsolatedChildProcess),
    /// The verified PID namespace child completed isolation and ran the entry point.
    Child(T),
}

/// Child-owned proof that every isolation step completed in the required order.
#[derive(Debug)]
pub struct IsolationReceipt {
    steps: Vec<IsolationStep>,
    pid_namespace_child: PidNamespaceChild,
}

impl IsolationReceipt {
    /// Returns the completed steps in execution order.
    pub fn steps(&self) -> &[IsolationStep] {
        &self.steps
    }

    /// Returns the kernel-observed PID namespace entered by this child.
    pub const fn pid_namespace(&self) -> NamespaceIdentity {
        self.pid_namespace_child.namespace()
    }
}

/// Interface for privileged isolation operations.
pub trait IsolationBackend {
    /// Detects host capabilities without mutating the process.
    fn detect_capabilities(&mut self, config: &IsolationConfig) -> CapabilityReport;

    /// Prepares all required namespaces and returns a linear child-handoff token.
    ///
    /// This operation may irreversibly mutate the calling launcher process. It
    /// must run only in an expendable process dedicated to this isolation spawn.
    ///
    /// The default rejects before mutation. A production backend must override
    /// this together with [`Self::spawn_isolated`] and
    /// [`Self::verify_pid_namespace_child`].
    fn prepare_namespaces(
        &mut self,
        _config: &IsolationConfig,
    ) -> Result<NamespacePreparation, BackendError> {
        Err(BackendError::new(
            IsolationStep::Namespaces,
            "backend does not implement explicit namespace preparation",
            None,
        ))
    }

    /// Consumes prepared namespaces, spawning a child that invokes `child_entry`.
    ///
    /// The parent must return [`SpawnOutcome::Parent`] without invoking the entry
    /// point. Only the spawned child may invoke it and return
    /// [`SpawnOutcome::Child`]. A production implementation must arrange for the
    /// child to execute in `preparation.child()`.
    fn spawn_isolated<T, F>(
        &mut self,
        _preparation: NamespacePreparation,
        _child_entry: F,
    ) -> Result<SpawnOutcome<T>, BackendError>
    where
        Self: Sized,
        F: FnOnce(&mut Self, NamespacePreparation) -> T,
    {
        Err(BackendError::new(
            IsolationStep::Namespaces,
            "backend does not implement explicit PID namespace child handoff",
            None,
        ))
    }

    /// Verifies that the current process entered the prepared child PID namespace.
    fn verify_pid_namespace_child(
        &mut self,
        _preparation: NamespacePreparation,
    ) -> Result<PidNamespaceChild, BackendError> {
        Err(BackendError::new(
            IsolationStep::Namespaces,
            "backend does not implement PID namespace child verification",
            None,
        ))
    }

    /// Executes one post-handoff setup operation.
    ///
    /// Coordinators never pass [`IsolationStep::Namespaces`] through this method.
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
    /// Rejects the legacy in-process API before namespace mutation.
    ///
    /// PID namespaces apply to the next child, not the process calling
    /// `unshare`. Call [`Self::spawn_isolated`] with an explicit workload entry
    /// point instead.
    pub fn apply<B: IsolationBackend>(
        backend: &mut B,
        config: &IsolationConfig,
    ) -> Result<IsolationReceipt, IsolationError> {
        Self::preflight(backend, config)?;
        Err(IsolationError::ChildHandoffRequired)
    }

    /// Spawns an explicitly isolated process and runs `workload_entry` only in its child.
    ///
    /// Call this only in an expendable namespace-launcher process. Its parent
    /// branch may already have irreversible namespace changes; it returns an
    /// [`IsolatedChildProcess`] but cannot receive an [`IsolationReceipt`]. The
    /// child verifies PID namespace entry, applies the remaining isolation
    /// stages, then supplies the receipt to the workload entry point. An
    /// irreversible failure aborts whichever process observed it.
    pub fn spawn_isolated<B, F, T>(
        backend: &mut B,
        config: &IsolationConfig,
        workload_entry: F,
    ) -> Result<SpawnOutcome<T>, IsolationError>
    where
        B: IsolationBackend,
        F: FnOnce(IsolationReceipt) -> T,
    {
        match Self::spawn_isolated_transaction(backend, config, workload_entry) {
            Err(IsolationError::TerminationRequired { .. }) => std::process::abort(),
            outcome => outcome,
        }
    }

    /// Runs explicit spawn orchestration without enforcing required termination.
    ///
    /// This is crate-visible only so tests can inspect the typed obligation
    /// without aborting the test process. Production callers must use the
    /// enforcing [`Self::spawn_isolated`] entry point.
    pub(crate) fn spawn_isolated_transaction<B, F, T>(
        backend: &mut B,
        config: &IsolationConfig,
        workload_entry: F,
    ) -> Result<SpawnOutcome<T>, IsolationError>
    where
        B: IsolationBackend,
        F: FnOnce(IsolationReceipt) -> T,
    {
        Self::preflight(backend, config)?;

        let preparation = backend.prepare_namespaces(config).map_err(|original| {
            IsolationError::TerminationRequired {
                original,
                failures: Vec::new(),
            }
        })?;
        let spawned = backend
            .spawn_isolated(preparation, |child_backend, child_preparation| {
                Self::enter_isolated_child(child_backend, config, child_preparation)
                    .map(workload_entry)
            })
            .map_err(|original| IsolationError::TerminationRequired {
                original,
                failures: Vec::new(),
            })?;

        match spawned {
            SpawnOutcome::Parent(child) => Ok(SpawnOutcome::Parent(child)),
            SpawnOutcome::Child(result) => result.map(SpawnOutcome::Child),
        }
    }

    fn preflight<B: IsolationBackend>(
        backend: &mut B,
        config: &IsolationConfig,
    ) -> Result<(), IsolationError> {
        config.validate()?;
        let report = backend.detect_capabilities(config);
        if !report.is_sufficient(config) {
            return Err(IsolationError::CapabilityUnavailable(report));
        }
        Ok(())
    }

    fn enter_isolated_child<B: IsolationBackend>(
        backend: &mut B,
        config: &IsolationConfig,
        preparation: NamespacePreparation,
    ) -> Result<IsolationReceipt, IsolationError> {
        let pid_namespace_child = match backend.verify_pid_namespace_child(preparation) {
            Ok(child) => child,
            Err(original) => {
                return Err(Self::failure_after_steps(
                    backend,
                    config,
                    &[IsolationStep::Namespaces],
                    original,
                ));
            }
        };
        Self::apply_child_transaction(backend, config, pid_namespace_child)
    }

    fn apply_child_transaction<B: IsolationBackend>(
        backend: &mut B,
        config: &IsolationConfig,
        pid_namespace_child: PidNamespaceChild,
    ) -> Result<IsolationReceipt, IsolationError> {
        let mut completed = vec![IsolationStep::Namespaces];
        for step in required_steps().into_iter().skip(1) {
            match backend.apply_step(step, config) {
                Ok(()) => completed.push(step),
                Err(original) => {
                    return Err(Self::failure_after_steps(
                        backend, config, &completed, original,
                    ));
                }
            }
        }
        Ok(IsolationReceipt {
            steps: completed,
            pid_namespace_child,
        })
    }

    fn failure_after_steps<B: IsolationBackend>(
        backend: &mut B,
        config: &IsolationConfig,
        completed: &[IsolationStep],
        original: BackendError,
    ) -> IsolationError {
        // A failed backend call may have applied only part of its operation, so
        // attempting an irreversible step is enough to make process reuse unsafe.
        let termination_required = original.step.is_irreversible()
            || completed
                .iter()
                .copied()
                .any(IsolationStep::is_irreversible);
        let failures = completed
            .iter()
            .rev()
            .filter_map(|completed_step| backend.rollback_step(*completed_step, config).err())
            .collect::<Vec<_>>();
        if termination_required {
            IsolationError::TerminationRequired { original, failures }
        } else if failures.is_empty() {
            IsolationError::Backend(original)
        } else {
            IsolationError::Rollback { original, failures }
        }
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

/// Spawns an isolated child and invokes `workload_entry` only after verified setup.
///
/// Call this only in an expendable namespace-launcher process. An irreversible
/// isolation failure aborts the process that observes it.
pub fn spawn_isolated<B, F, T>(
    backend: &mut B,
    config: &IsolationConfig,
    workload_entry: F,
) -> Result<SpawnOutcome<T>, IsolationError>
where
    B: IsolationBackend,
    F: FnOnce(IsolationReceipt) -> T,
{
    RuntimeIsolation::spawn_isolated(backend, config, workload_entry)
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
