//! Backend-independent isolation orchestration and failure handling.

use std::{
    error::Error,
    fmt,
    fs::File,
    io::{self, Read, Write},
    num::NonZeroU32,
    os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd},
    time::{Duration, Instant},
};

#[cfg(test)]
use std::sync::atomic::{AtomicBool, Ordering};

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

const REQUIRED_STEPS: [IsolationStep; 13] = [
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
];

pub(crate) mod private {
    /// Unforgeable permission to invoke process-global backend operations.
    pub(crate) struct OperationPermit(());

    impl OperationPermit {
        pub(super) const fn new() -> Self {
            Self(())
        }
    }

    /// Prevents downstream crates from supplying authority-bearing backends.
    pub(crate) trait Sealed {}

    #[cfg(not(test))]
    impl Sealed for crate::LinuxBackend {}

    // Unit tests remain able to exercise the coordinator with in-crate models.
    #[cfg(test)]
    impl<T> Sealed for T {}
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

    const fn wire_code(self) -> u8 {
        match self {
            Self::Namespaces => 0,
            Self::IdentityMap => 1,
            Self::CgroupV2 => 2,
            Self::ReadOnlyRootfs => 3,
            Self::Workspace => 4,
            Self::LimitedTmpfs => 5,
            Self::MaskProc => 6,
            Self::MaskDevices => 7,
            Self::CloseInheritedFileDescriptors => 8,
            Self::Landlock => 9,
            Self::DropCapabilities => 10,
            Self::NoNewPrivs => 11,
            Self::Seccomp => 12,
        }
    }

    const fn from_wire_code(code: u8) -> Option<Self> {
        match code {
            0 => Some(Self::Namespaces),
            1 => Some(Self::IdentityMap),
            2 => Some(Self::CgroupV2),
            3 => Some(Self::ReadOnlyRootfs),
            4 => Some(Self::Workspace),
            5 => Some(Self::LimitedTmpfs),
            6 => Some(Self::MaskProc),
            7 => Some(Self::MaskDevices),
            8 => Some(Self::CloseInheritedFileDescriptors),
            9 => Some(Self::Landlock),
            10 => Some(Self::DropCapabilities),
            11 => Some(Self::NoNewPrivs),
            12 => Some(Self::Seccomp),
            _ => None,
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
    pub(crate) const fn attest(parent: NamespaceIdentity, child: NamespaceIdentity) -> Self {
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
    pub(crate) const fn attest(namespace: NamespaceIdentity) -> Self {
        Self { namespace }
    }

    /// Returns the verified workload PID namespace.
    pub const fn namespace(&self) -> NamespaceIdentity {
        self.namespace
    }
}

const STARTUP_MESSAGE_MAGIC: [u8; 4] = *b"LISO";
const STARTUP_MESSAGE_VERSION: u8 = 1;
const STARTUP_MESSAGE_LEN: usize = 32;
const STARTUP_READY: u8 = 1;
const STARTUP_FAILED: u8 = 2;
const TERMINATION_REQUIRED: u8 = 1;
const ERRNO_UNAVAILABLE: i32 = i32::MIN;
const DROP_REAP_TIMEOUT: Duration = Duration::from_secs(1);

#[cfg(test)]
static FORCE_PIDFD_TERMINATION_FAILURE: AtomicBool = AtomicBool::new(false);

/// A child's kernel-observed startup result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChildStartupStatus {
    /// Every required isolation step completed in the child.
    Ready(ChildStartupReady),
    /// Isolation failed before the workload entry point ran.
    Failed(ChildStartupFailure),
}

/// Parent-observable proof that the child reached the final isolation boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChildStartupReady {
    pid_namespace: NamespaceIdentity,
}

impl ChildStartupReady {
    /// Returns the namespace the child observed after handoff.
    pub const fn pid_namespace(self) -> NamespaceIdentity {
        self.pid_namespace
    }

    /// Returns the exact ordered isolation contract completed by the child.
    pub const fn completed_steps() -> &'static [IsolationStep; 13] {
        &REQUIRED_STEPS
    }
}

/// Parent-observable isolation failure reported before the child terminates.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChildStartupFailure {
    step: IsolationStep,
    errno: Option<i32>,
    rollback_failure_count: u32,
    termination_required: bool,
}

impl ChildStartupFailure {
    /// Returns the operation that stopped isolation.
    pub const fn step(self) -> IsolationStep {
        self.step
    }

    /// Returns the kernel errno, when the failed operation supplied one.
    pub const fn errno(self) -> Option<i32> {
        self.errno
    }

    /// Returns how many best-effort rollback operations also failed.
    pub const fn rollback_failure_count(self) -> u32 {
        self.rollback_failure_count
    }

    /// Returns whether the child must terminate rather than continue execution.
    pub const fn termination_required(self) -> bool {
        self.termination_required
    }
}

/// Terminal state reaped from the direct isolation child.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChildExit {
    /// The child called `_exit` or returned from its process entry point.
    Exited(i32),
    /// The child was terminated by a signal.
    Signaled(i32),
}

/// Failure while observing or controlling an owned isolation child.
#[derive(Debug)]
pub enum ChildProcessError {
    /// This handle was created by an in-crate test double and owns no process.
    OwnershipUnavailable,
    /// The one-shot startup channel was consumed without yielding a status.
    StartupAlreadyObserved,
    /// The child closed its status channel before sending a complete message.
    StartupChannelClosed,
    /// The child supplied a malformed or contradictory status message.
    InvalidStartupStatus(&'static str),
    /// The direct child has already been reaped through this handle.
    AlreadyReaped,
    /// The stored child PID cannot be represented by the host wait API.
    InvalidChildPid,
    /// `waitpid` returned a state that was not terminal.
    InvalidWaitStatus,
    /// The child did not become reapable before the fail-stop deadline.
    ReapTimedOut,
    /// A kernel operation on the owned child failed.
    Io {
        /// Operation that failed.
        operation: &'static str,
        /// Operating-system failure.
        source: io::Error,
    },
}

impl ChildProcessError {
    fn io(operation: &'static str, source: io::Error) -> Self {
        Self::Io { operation, source }
    }

    fn raw_os_error(&self) -> Option<i32> {
        match self {
            Self::Io { source, .. } => source.raw_os_error(),
            _ => None,
        }
    }
}

impl fmt::Display for ChildProcessError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OwnershipUnavailable => {
                formatter.write_str("isolation child ownership is unavailable")
            }
            Self::StartupAlreadyObserved => {
                formatter.write_str("child startup status was already consumed")
            }
            Self::StartupChannelClosed => {
                formatter.write_str("child startup channel closed before a complete status")
            }
            Self::InvalidStartupStatus(reason) => {
                write!(formatter, "invalid child startup status: {reason}")
            }
            Self::AlreadyReaped => formatter.write_str("isolation child was already reaped"),
            Self::InvalidChildPid => formatter.write_str("isolation child PID is invalid"),
            Self::InvalidWaitStatus => {
                formatter.write_str("waitpid returned a non-terminal child status")
            }
            Self::ReapTimedOut => {
                formatter.write_str("isolation child did not become reapable before the deadline")
            }
            Self::Io { operation, source } => {
                write!(formatter, "{operation} failed: {source}")
            }
        }
    }
}

impl Error for ChildProcessError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

#[derive(Debug)]
struct OwnedChildControl {
    pidfd: OwnedFd,
    startup_reader: Option<OwnedFd>,
    startup_status: Option<ChildStartupStatus>,
    startup_read_attempted: bool,
    reaped: bool,
}

/// The only child endpoint permitted to attest startup to its launcher.
#[derive(Debug)]
pub(crate) struct ChildStartupNotifier {
    writer: OwnedFd,
}

impl ChildStartupNotifier {
    /// Creates the child endpoint of a close-on-exec status pipe.
    pub(crate) const fn from_fd(writer: OwnedFd) -> Self {
        Self { writer }
    }

    fn report_ready(self, receipt: &IsolationReceipt) -> Result<(), ChildProcessError> {
        self.write_message(encode_startup_ready(receipt.pid_namespace()))
    }

    fn report_failure(self, failure: &IsolationError) -> Result<(), ChildProcessError> {
        self.write_message(encode_startup_failure(failure))
    }

    fn write_message(self, message: [u8; STARTUP_MESSAGE_LEN]) -> Result<(), ChildProcessError> {
        let mut writer = File::from(self.writer);
        writer
            .write_all(&message)
            .map_err(|error| ChildProcessError::io("write child startup status", error))
    }
}

fn encode_startup_ready(namespace: NamespaceIdentity) -> [u8; STARTUP_MESSAGE_LEN] {
    let mut message = [0_u8; STARTUP_MESSAGE_LEN];
    message[..4].copy_from_slice(&STARTUP_MESSAGE_MAGIC);
    message[4] = STARTUP_MESSAGE_VERSION;
    message[5] = STARTUP_READY;
    message[6] = IsolationStep::Seccomp.wire_code();
    message[8..12].copy_from_slice(&ERRNO_UNAVAILABLE.to_le_bytes());
    message[12..20].copy_from_slice(&namespace.device().to_le_bytes());
    message[20..28].copy_from_slice(&namespace.inode().to_le_bytes());
    message
}

fn encode_startup_failure(failure: &IsolationError) -> [u8; STARTUP_MESSAGE_LEN] {
    let (original, failures, termination_required) = match failure {
        IsolationError::Backend(original) => (original, 0, false),
        IsolationError::Rollback { original, failures } => (original, failures.len(), false),
        IsolationError::TerminationRequired { original, failures } => {
            (original, failures.len(), true)
        }
        // The child protocol is emitted only after successful preflight and
        // namespace preparation. Retain a fail-closed representation if that
        // invariant is violated by a future coordinator change.
        IsolationError::InvalidConfig(_)
        | IsolationError::CapabilityUnavailable(_)
        | IsolationError::ChildHandoffRequired
        | IsolationError::ForbiddenSyscall(_)
        | IsolationError::UnsupportedSyscall(_) => {
            let mut message = [0_u8; STARTUP_MESSAGE_LEN];
            message[..4].copy_from_slice(&STARTUP_MESSAGE_MAGIC);
            message[4] = STARTUP_MESSAGE_VERSION;
            message[5] = STARTUP_FAILED;
            message[6] = IsolationStep::Namespaces.wire_code();
            message[7] = TERMINATION_REQUIRED;
            message[8..12].copy_from_slice(&ERRNO_UNAVAILABLE.to_le_bytes());
            return message;
        }
    };

    let mut message = [0_u8; STARTUP_MESSAGE_LEN];
    message[..4].copy_from_slice(&STARTUP_MESSAGE_MAGIC);
    message[4] = STARTUP_MESSAGE_VERSION;
    message[5] = STARTUP_FAILED;
    message[6] = original.step.wire_code();
    message[7] = u8::from(termination_required) * TERMINATION_REQUIRED;
    message[8..12].copy_from_slice(&original.errno.unwrap_or(ERRNO_UNAVAILABLE).to_le_bytes());
    message[28..32].copy_from_slice(&u32::try_from(failures).unwrap_or(u32::MAX).to_le_bytes());
    message
}

fn read_startup_status(reader: OwnedFd) -> Result<ChildStartupStatus, ChildProcessError> {
    let mut reader = File::from(reader);
    let mut message = [0_u8; STARTUP_MESSAGE_LEN];
    reader.read_exact(&mut message).map_err(|error| {
        if error.kind() == io::ErrorKind::UnexpectedEof {
            ChildProcessError::StartupChannelClosed
        } else {
            ChildProcessError::io("read child startup status", error)
        }
    })?;
    decode_startup_status(message)
}

fn decode_startup_status(
    message: [u8; STARTUP_MESSAGE_LEN],
) -> Result<ChildStartupStatus, ChildProcessError> {
    if message[..4] != STARTUP_MESSAGE_MAGIC {
        return Err(ChildProcessError::InvalidStartupStatus(
            "message magic did not match",
        ));
    }
    if message[4] != STARTUP_MESSAGE_VERSION {
        return Err(ChildProcessError::InvalidStartupStatus(
            "message version is unsupported",
        ));
    }
    let step = IsolationStep::from_wire_code(message[6]).ok_or(
        ChildProcessError::InvalidStartupStatus("isolation step code is unknown"),
    )?;
    if message[7] & !TERMINATION_REQUIRED != 0 {
        return Err(ChildProcessError::InvalidStartupStatus(
            "message flags contain unknown bits",
        ));
    }
    let errno = i32::from_le_bytes(
        message[8..12]
            .try_into()
            .expect("fixed status errno field has the correct length"),
    );
    let device = u64::from_le_bytes(
        message[12..20]
            .try_into()
            .expect("fixed status device field has the correct length"),
    );
    let inode = u64::from_le_bytes(
        message[20..28]
            .try_into()
            .expect("fixed status inode field has the correct length"),
    );
    let rollback_failure_count = u32::from_le_bytes(
        message[28..32]
            .try_into()
            .expect("fixed status rollback field has the correct length"),
    );

    match message[5] {
        STARTUP_READY => {
            if step != IsolationStep::Seccomp
                || message[7] != 0
                || errno != ERRNO_UNAVAILABLE
                || rollback_failure_count != 0
            {
                return Err(ChildProcessError::InvalidStartupStatus(
                    "ready message did not attest the final isolation step",
                ));
            }
            Ok(ChildStartupStatus::Ready(ChildStartupReady {
                pid_namespace: NamespaceIdentity::from_kernel(device, inode),
            }))
        }
        STARTUP_FAILED => {
            if device != 0 || inode != 0 {
                return Err(ChildProcessError::InvalidStartupStatus(
                    "failure message contained a namespace attestation",
                ));
            }
            Ok(ChildStartupStatus::Failed(ChildStartupFailure {
                step,
                errno: (errno != ERRNO_UNAVAILABLE).then_some(errno),
                rollback_failure_count,
                termination_required: message[7] == TERMINATION_REQUIRED,
            }))
        }
        _ => Err(ChildProcessError::InvalidStartupStatus(
            "message kind is unknown",
        )),
    }
}

fn wait_for_child(
    pid: NonZeroU32,
    options: libc::c_int,
    control: &mut OwnedChildControl,
) -> Result<Option<ChildExit>, ChildProcessError> {
    let pid = libc::pid_t::try_from(pid.get()).map_err(|_| ChildProcessError::InvalidChildPid)?;
    loop {
        let mut status = 0;
        // SAFETY: `status` is a valid writable pointer, and the handle records
        // ownership of the direct child identified by `pid` until it is reaped.
        let result = unsafe { libc::waitpid(pid, &raw mut status, options) };
        if result == 0 {
            return Ok(None);
        }
        if result == -1 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            if error.raw_os_error() == Some(libc::ECHILD) {
                control.reaped = true;
            }
            return Err(ChildProcessError::io("wait for isolation child", error));
        }
        control.reaped = true;
        if libc::WIFEXITED(status) {
            return Ok(Some(ChildExit::Exited(libc::WEXITSTATUS(status))));
        }
        if libc::WIFSIGNALED(status) {
            return Ok(Some(ChildExit::Signaled(libc::WTERMSIG(status))));
        }
        return Err(ChildProcessError::InvalidWaitStatus);
    }
}

#[cfg(target_os = "linux")]
fn terminate_child(control: &OwnedChildControl) -> Result<(), ChildProcessError> {
    #[cfg(test)]
    if FORCE_PIDFD_TERMINATION_FAILURE.load(Ordering::SeqCst) {
        return Err(ChildProcessError::io(
            "terminate isolation child through pidfd",
            io::Error::from_raw_os_error(libc::EPERM),
        ));
    }
    loop {
        // SAFETY: the pidfd is owned by this handle, the signal has no payload,
        // and pidfd addressing prevents PID-reuse races.
        let result = unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                control.pidfd.as_raw_fd(),
                libc::SIGKILL,
                std::ptr::null::<libc::siginfo_t>(),
                0_u32,
            )
        };
        if result == 0 {
            return Ok(());
        }
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::Interrupted {
            continue;
        }
        if error.raw_os_error() == Some(libc::ESRCH) {
            return Ok(());
        }
        return Err(ChildProcessError::io(
            "terminate isolation child through pidfd",
            error,
        ));
    }
}

#[cfg(target_os = "linux")]
fn terminate_child_by_pid(pid: NonZeroU32) -> Result<(), ChildProcessError> {
    let pid = libc::pid_t::try_from(pid.get()).map_err(|_| ChildProcessError::InvalidChildPid)?;
    loop {
        // SAFETY: the PID identifies this launcher's direct, unreaped child, so
        // the kernel cannot reuse it until waitpid consumes the terminal state.
        let result = unsafe { libc::kill(pid, libc::SIGKILL) };
        if result == 0
            || (result == -1 && io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH))
        {
            return Ok(());
        }
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::Interrupted {
            continue;
        }
        return Err(ChildProcessError::io(
            "terminate direct isolation child by PID",
            error,
        ));
    }
}

#[cfg(not(target_os = "linux"))]
fn terminate_child_by_pid(_pid: NonZeroU32) -> Result<(), ChildProcessError> {
    Err(ChildProcessError::io(
        "terminate direct isolation child by PID",
        io::Error::new(
            io::ErrorKind::Unsupported,
            "direct child signaling is available only on Linux",
        ),
    ))
}

fn terminate_owned_child(
    pid: NonZeroU32,
    control: &OwnedChildControl,
) -> Result<(), ChildProcessError> {
    match terminate_child(control) {
        Ok(()) => Ok(()),
        Err(_pidfd_error) => terminate_child_by_pid(pid),
    }
}

fn reap_child_before_deadline(
    pid: NonZeroU32,
    control: &mut OwnedChildControl,
) -> Result<ChildExit, ChildProcessError> {
    let deadline = Instant::now() + DROP_REAP_TIMEOUT;
    loop {
        if let Some(exit) = wait_for_child(pid, libc::WNOHANG, control)? {
            return Ok(exit);
        }
        let now = Instant::now();
        if now >= deadline {
            return Err(ChildProcessError::ReapTimedOut);
        }
        let timeout = i32::try_from((deadline - now).as_millis()).unwrap_or(i32::MAX);
        let mut descriptor = libc::pollfd {
            fd: control.pidfd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: descriptor points to one initialized pollfd and timeout is
        // bounded by DROP_REAP_TIMEOUT.
        let result = unsafe { libc::poll(&raw mut descriptor, 1, timeout) };
        if result == -1 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(ChildProcessError::io(
                "poll isolation child pidfd for exit",
                error,
            ));
        }
        if result == 0 {
            return Err(ChildProcessError::ReapTimedOut);
        }
    }
}

fn terminate_and_reap_or_abort(pid: NonZeroU32, control: &mut OwnedChildControl) {
    if control.reaped {
        return;
    }
    if terminate_owned_child(pid, control).is_err()
        || reap_child_before_deadline(pid, control).is_err()
    {
        std::process::abort();
    }
}

#[cfg(not(target_os = "linux"))]
fn terminate_child(_control: &OwnedChildControl) -> Result<(), ChildProcessError> {
    Err(ChildProcessError::io(
        "terminate isolation child through pidfd",
        io::Error::new(
            io::ErrorKind::Unsupported,
            "pidfds are available only on Linux",
        ),
    ))
}

/// Namespace-launcher ownership of a successfully spawned isolation child.
///
/// This handle is returned in the process that prepared namespaces. That
/// launcher may already have irreversible process-global namespace changes and
/// must not resume trusted supervisor work.
#[derive(Debug)]
pub struct IsolatedChildProcess {
    pid: NonZeroU32,
    pid_namespace: NamespaceIdentity,
    control: Option<OwnedChildControl>,
}

impl IsolatedChildProcess {
    /// Creates an owned parent handle from kernel-created process descriptors.
    pub(crate) fn from_spawn(
        pid: NonZeroU32,
        pid_namespace: NamespaceIdentity,
        pidfd: OwnedFd,
        startup_reader: OwnedFd,
    ) -> Self {
        Self {
            pid,
            pid_namespace,
            control: Some(OwnedChildControl {
                pidfd,
                startup_reader: Some(startup_reader),
                startup_status: None,
                startup_read_attempted: false,
                reaped: false,
            }),
        }
    }

    /// Returns the child PID as seen by the preparing parent.
    pub const fn pid(&self) -> NonZeroU32 {
        self.pid
    }

    /// Returns the PID namespace prepared for the child.
    pub const fn pid_namespace(&self) -> NamespaceIdentity {
        self.pid_namespace
    }

    /// Returns the stable process descriptor owned by this launcher.
    pub fn pidfd(&self) -> Result<BorrowedFd<'_>, ChildProcessError> {
        self.control
            .as_ref()
            .map(|control| control.pidfd.as_fd())
            .ok_or(ChildProcessError::OwnershipUnavailable)
    }

    /// Blocks until the child reports complete isolation or a typed startup failure.
    ///
    /// Every failure, malformed message, or premature channel close is fail-stop:
    /// this method terminates and reaps the still-owned child before returning.
    pub fn wait_for_startup(&mut self) -> Result<&ChildStartupStatus, ChildProcessError> {
        let pid = self.pid;
        let control = self
            .control
            .as_mut()
            .ok_or(ChildProcessError::OwnershipUnavailable)?;
        if control.startup_status.is_none() {
            if control.startup_read_attempted {
                return Err(ChildProcessError::StartupAlreadyObserved);
            }
            control.startup_read_attempted = true;
            let reader = control
                .startup_reader
                .take()
                .ok_or(ChildProcessError::StartupAlreadyObserved)?;
            let status = match read_startup_status(reader) {
                Ok(status) => status,
                Err(error) => {
                    terminate_and_reap_or_abort(pid, control);
                    return Err(error);
                }
            };
            if let ChildStartupStatus::Ready(ready) = &status
                && ready.pid_namespace != self.pid_namespace
            {
                terminate_and_reap_or_abort(pid, control);
                return Err(ChildProcessError::InvalidStartupStatus(
                    "ready namespace did not match the namespace prepared for this child",
                ));
            }
            if matches!(status, ChildStartupStatus::Failed(_)) {
                terminate_and_reap_or_abort(pid, control);
            }
            control.startup_status = Some(status);
        }
        control
            .startup_status
            .as_ref()
            .ok_or(ChildProcessError::StartupAlreadyObserved)
    }

    /// Returns the child's terminal state without blocking.
    pub fn try_wait(&mut self) -> Result<Option<ChildExit>, ChildProcessError> {
        let pid = self.pid;
        let control = self
            .control
            .as_mut()
            .ok_or(ChildProcessError::OwnershipUnavailable)?;
        if control.reaped {
            return Err(ChildProcessError::AlreadyReaped);
        }
        wait_for_child(pid, libc::WNOHANG, control)
    }

    /// Blocks until the child exits and reaps it exactly once.
    pub fn wait(&mut self) -> Result<ChildExit, ChildProcessError> {
        let pid = self.pid;
        let control = self
            .control
            .as_mut()
            .ok_or(ChildProcessError::OwnershipUnavailable)?;
        if control.reaped {
            return Err(ChildProcessError::AlreadyReaped);
        }
        wait_for_child(pid, 0, control)?.ok_or(ChildProcessError::InvalidWaitStatus)
    }

    /// Sends `SIGKILL` and waits for a bounded interval to reap the direct child.
    ///
    /// A timeout leaves the process capability owned by this handle so the
    /// caller may retry. Dropping it later remains fail-stop.
    pub fn terminate(&mut self) -> Result<ChildExit, ChildProcessError> {
        let pid = self.pid;
        let control = self
            .control
            .as_mut()
            .ok_or(ChildProcessError::OwnershipUnavailable)?;
        if control.reaped {
            return Err(ChildProcessError::AlreadyReaped);
        }
        terminate_owned_child(pid, control)?;
        reap_child_before_deadline(pid, control)
    }

    #[cfg(test)]
    pub(crate) const fn unattested_for_test(
        pid: NonZeroU32,
        pid_namespace: NamespaceIdentity,
    ) -> Self {
        Self {
            pid,
            pid_namespace,
            control: None,
        }
    }
}

impl Drop for IsolatedChildProcess {
    fn drop(&mut self) {
        let pid = self.pid;
        let Some(control) = self.control.as_mut() else {
            return;
        };
        if control.reaped {
            return;
        }
        // Dropping the only process capability must not detach an untrusted
        // child. PID fallback is identity-safe while this unreaped direct child
        // still owns its kernel PID. If termination or bounded reap nevertheless
        // fails, aborting the launcher preserves the fail-stop contract.
        terminate_and_reap_or_abort(pid, control);
    }
}

/// Process role returned by an explicit isolation spawn.
#[derive(Debug)]
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

/// Sealed interface for the crate's privileged isolation implementation.
///
/// Downstream crates can use [`LinuxBackend`](crate::LinuxBackend) through the
/// safe coordinator APIs, but cannot implement this authority-bearing trait or
/// invoke its process-global mutation methods directly.
#[allow(private_bounds, private_interfaces)]
pub trait IsolationBackend: private::Sealed {
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
        _permit: private::OperationPermit,
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
        _permit: private::OperationPermit,
        _preparation: NamespacePreparation,
        _child_entry: F,
    ) -> Result<SpawnOutcome<T>, BackendError>
    where
        Self: Sized,
        F: FnOnce(&mut Self, NamespacePreparation, ChildStartupNotifier) -> T,
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
        _permit: private::OperationPermit,
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
        _permit: private::OperationPermit,
        step: IsolationStep,
        config: &IsolationConfig,
    ) -> Result<(), BackendError>;

    /// Rolls back one previously completed operation.
    fn rollback_step(
        &mut self,
        _permit: private::OperationPermit,
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
            Err(error @ IsolationError::TerminationRequired { .. }) => {
                eprintln!("runtime-isolation: aborting an irreversibly mutated launcher: {error}");
                std::process::abort();
            }
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

        let preparation = backend
            .prepare_namespaces(private::OperationPermit::new(), config)
            .map_err(|original| IsolationError::TerminationRequired {
                original,
                failures: Vec::new(),
            })?;
        let spawned = backend
            .spawn_isolated(
                private::OperationPermit::new(),
                preparation,
                |child_backend, child_preparation, startup_notifier| {
                    match Self::enter_isolated_child(child_backend, config, child_preparation) {
                        Ok(receipt) => match startup_notifier.report_ready(&receipt) {
                            Ok(()) => Ok(workload_entry(receipt)),
                            Err(error) => Err(IsolationError::TerminationRequired {
                                original: BackendError::new(
                                    IsolationStep::Seccomp,
                                    format!("report isolated child readiness to launcher: {error}"),
                                    error.raw_os_error(),
                                ),
                                failures: Vec::new(),
                            }),
                        },
                        Err(error) => {
                            let _ = startup_notifier.report_failure(&error);
                            Err(error)
                        }
                    }
                },
            )
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
        let pid_namespace_child = match backend
            .verify_pid_namespace_child(private::OperationPermit::new(), preparation)
        {
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
            match backend.apply_step(private::OperationPermit::new(), step, config) {
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
            .filter_map(|completed_step| {
                backend
                    .rollback_step(private::OperationPermit::new(), *completed_step, config)
                    .err()
            })
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
    REQUIRED_STEPS
}

#[cfg(test)]
mod tests {
    use std::{
        num::NonZeroU32,
        os::fd::{FromRawFd, OwnedFd, RawFd},
        sync::atomic::Ordering,
    };

    use super::{
        BackendError, ChildProcessError, ChildStartupReady, ChildStartupStatus,
        FORCE_PIDFD_TERMINATION_FAILURE, IsolatedChildProcess, IsolationError, IsolationStep,
        NamespaceIdentity, REQUIRED_STEPS, STARTUP_MESSAGE_VERSION, decode_startup_status,
        encode_startup_failure, encode_startup_ready,
    };

    #[test]
    fn irreversible_apply_attempt_requires_process_termination() {
        assert!(IsolationStep::Landlock.is_irreversible());
    }

    #[test]
    fn reversible_apply_attempt_does_not_itself_require_process_termination() {
        assert!(!IsolationStep::Workspace.is_irreversible());
    }

    #[test]
    fn ready_status_attests_the_exact_final_boundary() {
        let namespace = NamespaceIdentity::from_kernel(4, 81);
        let status = decode_startup_status(encode_startup_ready(namespace))
            .expect("internally encoded status must decode");
        let ChildStartupStatus::Ready(ready) = status else {
            panic!("ready encoding must not decode as failure");
        };
        assert_eq!(ready.pid_namespace(), namespace);
        assert_eq!(ChildStartupReady::completed_steps(), &REQUIRED_STEPS);
    }

    #[test]
    fn failure_status_preserves_parent_actionable_fields() {
        let error = IsolationError::TerminationRequired {
            original: BackendError::new(IsolationStep::Landlock, "denied", Some(libc::EACCES)),
            failures: vec![BackendError::new(
                IsolationStep::Workspace,
                "unmount failed",
                Some(libc::EBUSY),
            )],
        };
        let status = decode_startup_status(encode_startup_failure(&error))
            .expect("internally encoded status must decode");
        let ChildStartupStatus::Failed(failure) = status else {
            panic!("failure encoding must not decode as ready");
        };
        assert_eq!(failure.step(), IsolationStep::Landlock);
        assert_eq!(failure.errno(), Some(libc::EACCES));
        assert_eq!(failure.rollback_failure_count(), 1);
        assert!(failure.termination_required());
    }

    #[test]
    fn malformed_ready_status_is_rejected() {
        let mut message = encode_startup_ready(NamespaceIdentity::from_kernel(4, 81));
        message[4] = STARTUP_MESSAGE_VERSION.wrapping_add(1);
        assert!(matches!(
            decode_startup_status(message),
            Err(ChildProcessError::InvalidStartupStatus(_))
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn drop_falls_back_to_direct_child_pid_and_reaps() {
        let mut pipe = [-1; 2];
        // SAFETY: the array contains storage for both returned descriptors.
        assert_eq!(
            unsafe { libc::pipe2(pipe.as_mut_ptr(), libc::O_CLOEXEC) },
            0
        );
        // SAFETY: fork has no pointer arguments. The child calls only
        // async-signal-safe libc operations before `_exit`.
        let child_pid = unsafe { libc::fork() };
        assert_ne!(child_pid, -1, "fork must create the lifecycle test child");
        if child_pid == 0 {
            loop {
                // SAFETY: pause has no pointer arguments and is async-signal-safe.
                unsafe { libc::pause() };
            }
        }

        // SAFETY: successful pipe2 returned two descriptors owned by this process.
        let reader = unsafe { OwnedFd::from_raw_fd(pipe[0]) };
        // SAFETY: the parent owns the unused writer endpoint.
        drop(unsafe { OwnedFd::from_raw_fd(pipe[1]) });
        // SAFETY: pidfd_open receives the live direct child PID and zero flags.
        let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, child_pid, 0_u32) };
        assert_ne!(pidfd, -1, "pidfd_open must own the lifecycle test child");
        // SAFETY: successful pidfd_open returned an owned descriptor.
        let pidfd = RawFd::try_from(pidfd).expect("pidfd must fit the descriptor ABI");
        // SAFETY: successful pidfd_open returned an owned descriptor.
        let pidfd = unsafe { OwnedFd::from_raw_fd(pidfd) };
        let pid = NonZeroU32::new(child_pid.cast_unsigned()).expect("fork PID must be positive");
        let child = IsolatedChildProcess::from_spawn(
            pid,
            NamespaceIdentity::from_kernel(4, 81),
            pidfd,
            reader,
        );

        FORCE_PIDFD_TERMINATION_FAILURE.store(true, Ordering::SeqCst);
        drop(child);
        FORCE_PIDFD_TERMINATION_FAILURE.store(false, Ordering::SeqCst);

        let mut status = 0;
        // SAFETY: this query checks that Drop already consumed the child status.
        assert_eq!(
            unsafe { libc::waitpid(child_pid, &raw mut status, libc::WNOHANG) },
            -1
        );
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::ECHILD)
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn startup_failure_is_reaped_before_parent_observes_it() {
        let message = encode_startup_failure(&IsolationError::TerminationRequired {
            original: BackendError::new(
                IsolationStep::IdentityMap,
                "injected credential failure",
                Some(libc::EPERM),
            ),
            failures: Vec::new(),
        });
        let mut pipe = [-1; 2];
        // SAFETY: the array contains storage for both returned descriptors.
        assert_eq!(
            unsafe { libc::pipe2(pipe.as_mut_ptr(), libc::O_CLOEXEC) },
            0
        );
        // SAFETY: the child uses only async-signal-safe libc calls before `_exit`.
        let child_pid = unsafe { libc::fork() };
        assert_ne!(child_pid, -1, "fork must create the startup-failure child");
        if child_pid == 0 {
            // SAFETY: the child owns the writer and no longer needs the reader.
            unsafe { libc::close(pipe[0]) };
            // SAFETY: the message is live and the pipe owns enough capacity for it.
            let written = unsafe {
                libc::write(
                    pipe[1],
                    message.as_ptr().cast::<libc::c_void>(),
                    message.len(),
                )
            };
            if written != isize::try_from(message.len()).expect("message length must fit ssize_t") {
                // SAFETY: the fork child must never return into the test harness.
                unsafe { libc::_exit(2) }
            }
            loop {
                // SAFETY: pause has no pointer arguments and is async-signal-safe.
                unsafe { libc::pause() };
            }
        }

        // SAFETY: the parent owns the unused writer endpoint.
        drop(unsafe { OwnedFd::from_raw_fd(pipe[1]) });
        // SAFETY: the parent owns the reader endpoint.
        let reader = unsafe { OwnedFd::from_raw_fd(pipe[0]) };
        // SAFETY: pidfd_open receives the live direct child PID and zero flags.
        let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, child_pid, 0_u32) };
        assert_ne!(pidfd, -1, "pidfd_open must own the startup-failure child");
        let pidfd = RawFd::try_from(pidfd).expect("pidfd must fit the descriptor ABI");
        // SAFETY: successful pidfd_open returned an owned descriptor.
        let pidfd = unsafe { OwnedFd::from_raw_fd(pidfd) };
        let pid = NonZeroU32::new(child_pid.cast_unsigned()).expect("fork PID must be positive");
        let mut child = IsolatedChildProcess::from_spawn(
            pid,
            NamespaceIdentity::from_kernel(4, 81),
            pidfd,
            reader,
        );

        let status = child
            .wait_for_startup()
            .expect("typed startup failure must remain observable");
        let ChildStartupStatus::Failed(failure) = status else {
            panic!("failure wire message must not decode as ready");
        };
        assert_eq!(failure.step(), IsolationStep::IdentityMap);
        assert!(matches!(
            child.wait(),
            Err(ChildProcessError::AlreadyReaped)
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn explicit_terminate_reaps_once_within_the_deadline() {
        let mut pipe = [-1; 2];
        // SAFETY: the array contains storage for both returned descriptors.
        assert_eq!(
            unsafe { libc::pipe2(pipe.as_mut_ptr(), libc::O_CLOEXEC) },
            0
        );
        // SAFETY: the child calls only async-signal-safe libc operations.
        let child_pid = unsafe { libc::fork() };
        assert_ne!(child_pid, -1, "fork must create the termination test child");
        if child_pid == 0 {
            loop {
                // SAFETY: pause has no pointer arguments and is async-signal-safe.
                unsafe { libc::pause() };
            }
        }

        // SAFETY: successful pipe2 returned two descriptors owned by this process.
        let reader = unsafe { OwnedFd::from_raw_fd(pipe[0]) };
        // SAFETY: the parent owns the unused writer endpoint.
        drop(unsafe { OwnedFd::from_raw_fd(pipe[1]) });
        // SAFETY: pidfd_open receives the live direct child PID and zero flags.
        let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, child_pid, 0_u32) };
        assert_ne!(pidfd, -1, "pidfd_open must own the termination test child");
        let pidfd = RawFd::try_from(pidfd).expect("pidfd must fit the descriptor ABI");
        // SAFETY: successful pidfd_open returned an owned descriptor.
        let pidfd = unsafe { OwnedFd::from_raw_fd(pidfd) };
        let pid = NonZeroU32::new(child_pid.cast_unsigned()).expect("fork PID must be positive");
        let mut child = IsolatedChildProcess::from_spawn(
            pid,
            NamespaceIdentity::from_kernel(4, 81),
            pidfd,
            reader,
        );

        assert_eq!(
            child
                .terminate()
                .expect("SIGKILL child must become reapable before the deadline"),
            super::ChildExit::Signaled(libc::SIGKILL)
        );
        assert!(matches!(
            child.terminate(),
            Err(ChildProcessError::AlreadyReaped)
        ));
    }
}
