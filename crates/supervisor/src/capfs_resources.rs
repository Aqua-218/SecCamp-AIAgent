//! Production composition of the supervisor lifecycle with `CapFS`.

use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt, fs, io,
    os::unix::{ffi::OsStrExt, fs::PermissionsExt},
    path::{Path, PathBuf},
    process::{self, Command},
    sync::Arc,
};

use authority_core::{
    audit::AuditError,
    capability::{AuthorityBody, CapId, SubjectId},
    durable_audit::DurableAuditLog,
    handle::{HandleId, OpenHandle},
    kernel::{CapabilityKernel, CapabilityKernelError},
    state::{
        CapabilityGrant, CapabilityState, HandleCloseStatus, RevocationStatus, Subject,
        SubjectCloseStatus, SubjectFinishStatus,
    },
    time::MonotonicTime,
};
use capfs::{
    backing::ImportedRepository,
    namespace::NamespaceError,
    read_only::{
        AuthorizationClock, CapabilityFilesystem, CapabilityFilesystemError, MountAuthority,
        MountInstanceId, spawn_mount,
    },
};
use fuser::BackgroundSession;
use rustix::{
    fs::statfs,
    mount::{UnmountFlags, unmount},
};

use crate::{
    AuthorityKernel, CallerResolver, CgroupHandle, ControlFdHandle, MountHandle,
    ResourceAcquisition, ResourceMutation, RuntimeResources, Supervisor, SupervisorError,
    WorkloadHandle,
};

/// Host operations that surround, but do not implement, a `CapFS` mount.
///
/// This is a production boundary, not a fallback implementation. Callers must
/// supply the cgroup, control-descriptor, workload, and runtime-handle owner.
/// Its tokens inherit the stability and idempotency requirements documented by
/// [`RuntimeResources`]. The mount point passed to [`Self::start_workload`] is
/// the exact canonical path whose ready FUSE session is retained by `mount`.
pub trait CapfsHostResources {
    /// Host-adapter failure type.
    type Error: Error + Send + Sync + 'static;

    /// Allocates the workload cgroup before any child can run.
    fn create_cgroup(
        &mut self,
        subject: &SubjectId,
    ) -> ResourceAcquisition<CgroupHandle, Self::Error>;

    /// Removes a cgroup after the workload and mount are stopped.
    fn remove_cgroup(&mut self, cgroup: CgroupHandle) -> ResourceMutation<Self::Error>;

    /// Opens the subject's private control descriptor.
    fn open_control_fd(
        &mut self,
        subject: &SubjectId,
    ) -> ResourceAcquisition<ControlFdHandle, Self::Error>;

    /// Closes the subject's private control descriptor.
    fn close_control_fd(&mut self, control: ControlFdHandle) -> ResourceMutation<Self::Error>;

    /// Starts a workload with the exact ready `CapFS` mount retained by `mount`.
    fn start_workload(
        &mut self,
        subject: &SubjectId,
        cgroup: CgroupHandle,
        mount: MountHandle,
        mountpoint: &Path,
        control: ControlFdHandle,
    ) -> ResourceAcquisition<WorkloadHandle, Self::Error>;

    /// Stops the workload before descriptors and the mount are closed.
    fn stop_workload(
        &mut self,
        workload: WorkloadHandle,
        cgroup: CgroupHandle,
    ) -> ResourceMutation<Self::Error>;

    /// Opens one runtime handle before authority registration.
    fn open_handle(
        &mut self,
        subject: &SubjectId,
        handle: &HandleId,
    ) -> ResourceMutation<Self::Error>;

    /// Closes one runtime handle under the idempotent cleanup contract.
    fn close_handle(
        &mut self,
        subject: &SubjectId,
        handle: &HandleId,
    ) -> ResourceMutation<Self::Error>;
}

/// One host-assigned subject mount and its preallocated root capability.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapfsMountPlan {
    subject: SubjectId,
    mount_instance: MountInstanceId,
    capability: CapId,
    grant: CapabilityGrant,
    mountpoint: PathBuf,
}

impl CapfsMountPlan {
    /// Creates a plan whose identities will be validated by the runtime manager.
    #[must_use]
    pub fn new(
        subject: SubjectId,
        mount_instance: MountInstanceId,
        capability: CapId,
        grant: CapabilityGrant,
        mountpoint: impl Into<PathBuf>,
    ) -> Self {
        Self {
            subject,
            mount_instance,
            capability,
            grant,
            mountpoint: mountpoint.into(),
        }
    }

    /// Returns the subject reserved by this plan.
    #[must_use]
    pub const fn subject(&self) -> &SubjectId {
        &self.subject
    }

    /// Returns the mount identity reserved by this plan.
    #[must_use]
    pub const fn mount_instance(&self) -> &MountInstanceId {
        &self.mount_instance
    }

    /// Returns the root capability identity reserved by this plan.
    #[must_use]
    pub const fn capability(&self) -> &CapId {
        &self.capability
    }

    /// Returns the root grant installed immediately before workload start.
    #[must_use]
    pub const fn grant(&self) -> &CapabilityGrant {
        &self.grant
    }

    /// Returns the configured mount point.
    #[must_use]
    pub fn mountpoint(&self) -> &Path {
        &self.mountpoint
    }
}

/// Mandatory inputs for one durable `CapFS` supervisor session.
pub struct CapfsRuntimeConfig {
    state: CapabilityState,
    audit: DurableAuditLog,
    repository: ImportedRepository,
    clock: Arc<dyn AuthorizationClock>,
    unmount: CapfsUnmountStrategy,
    mounts: Vec<CapfsMountPlan>,
}

impl CapfsRuntimeConfig {
    /// Creates a configuration with no in-memory or unchecked audit fallback.
    #[must_use]
    pub fn new(
        state: CapabilityState,
        audit: DurableAuditLog,
        repository: ImportedRepository,
        clock: Arc<dyn AuthorizationClock>,
        unmount: CapfsUnmountStrategy,
        mounts: Vec<CapfsMountPlan>,
    ) -> Self {
        Self {
            state,
            audit,
            repository,
            clock,
            unmount,
            mounts,
        }
    }
}

/// Explicit production mechanism used to unmount retained FUSE sessions.
///
/// This type has no default: deployments must choose either a privileged
/// kernel syscall or one exact, validated `fusermount` executable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapfsUnmountStrategy {
    mechanism: UnmountMechanism,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum UnmountMechanism {
    Kernel,
    Helper(PathBuf),
}

impl CapfsUnmountStrategy {
    /// Uses `umount2` directly in a mount namespace where it is permitted.
    #[must_use]
    pub const fn kernel() -> Self {
        Self {
            mechanism: UnmountMechanism::Kernel,
        }
    }

    /// Uses one explicitly configured `fusermount` executable.
    ///
    /// The manager requires an absolute path and canonicalizes it before any
    /// mount is created. It rejects non-files and files without an executable
    /// permission bit.
    #[must_use]
    pub fn helper(executable: impl Into<PathBuf>) -> Self {
        Self {
            mechanism: UnmountMechanism::Helper(executable.into()),
        }
    }

    fn validate(self) -> Result<Self, CapfsPlanError> {
        let UnmountMechanism::Helper(executable) = self.mechanism else {
            return Ok(self);
        };
        if !executable.is_absolute() {
            return Err(CapfsPlanError::UnmountHelperNotAbsolute(executable));
        }
        let canonical =
            fs::canonicalize(&executable).map_err(|source| CapfsPlanError::UnmountHelperIo {
                path: executable,
                source,
            })?;
        let metadata =
            fs::metadata(&canonical).map_err(|source| CapfsPlanError::UnmountHelperIo {
                path: canonical.clone(),
                source,
            })?;
        if !metadata.is_file() || metadata.permissions().mode() & 0o111 == 0 {
            return Err(CapfsPlanError::UnmountHelperNotExecutable(canonical));
        }
        Ok(Self {
            mechanism: UnmountMechanism::Helper(canonical),
        })
    }

    fn unmount(&self, mountpoint: &Path) -> UnmountAttempt {
        match &self.mechanism {
            UnmountMechanism::Kernel => match unmount(mountpoint, UnmountFlags::NOFOLLOW) {
                Ok(()) => UnmountAttempt::Applied,
                Err(error) => {
                    UnmountAttempt::Unchanged(io::Error::from_raw_os_error(error.raw_os_error()))
                }
            },
            UnmountMechanism::Helper(executable) => {
                let mut child = match Command::new(executable)
                    .arg("-u")
                    .arg("--")
                    .arg(mountpoint)
                    .spawn()
                {
                    Ok(child) => child,
                    Err(error) => return UnmountAttempt::Unchanged(error),
                };
                match child.wait() {
                    Ok(status) if status.success() => UnmountAttempt::Applied,
                    Ok(status) => UnmountAttempt::Unknown(io::Error::other(format!(
                        "unmount helper exited with status {status}"
                    ))),
                    Err(error) => UnmountAttempt::Unknown(error),
                }
            }
        }
    }
}

enum UnmountAttempt {
    Applied,
    Unchanged(io::Error),
    Unknown(io::Error),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MountPresence {
    Active,
    Absent,
    Replaced,
}

const FUSE_SUPER_MAGIC: u64 = 0x6573_5546;

#[derive(Debug, Clone, PartialEq, Eq)]
struct MountInfo {
    id: u64,
    filesystem: Vec<u8>,
    source: Vec<u8>,
}

fn decode_mountinfo_path(encoded: &[u8]) -> io::Result<Vec<u8>> {
    let mut decoded = Vec::with_capacity(encoded.len());
    let mut index = 0;
    while index < encoded.len() {
        if encoded[index] != b'\\' {
            decoded.push(encoded[index]);
            index += 1;
            continue;
        }
        let Some(octal) = encoded.get(index + 1..index + 4) else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "truncated mountinfo escape",
            ));
        };
        if !octal.iter().all(|byte| (b'0'..=b'7').contains(byte)) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid mountinfo escape",
            ));
        }
        decoded.push((octal[0] - b'0') * 64 + (octal[1] - b'0') * 8 + octal[2] - b'0');
        index += 4;
    }
    Ok(decoded)
}

fn exact_mounts(path: &Path) -> io::Result<Vec<MountInfo>> {
    let bytes = fs::read("/proc/self/mountinfo")?;
    let expected = path.as_os_str().as_bytes();
    let mut matches = Vec::new();
    for line in bytes
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
    {
        let fields = line
            .split(|byte| *byte == b' ')
            .filter(|field| !field.is_empty())
            .collect::<Vec<_>>();
        let separator = fields
            .iter()
            .position(|field| *field == b"-")
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "mountinfo has no separator")
            })?;
        if fields.len() < 6 || separator + 2 >= fields.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "mountinfo record is incomplete",
            ));
        }
        if decode_mountinfo_path(fields[4])? != expected {
            continue;
        }
        let id = std::str::from_utf8(fields[0])
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "mount ID is not UTF-8"))?
            .parse::<u64>()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "mount ID is not numeric"))?;
        matches.push(MountInfo {
            id,
            filesystem: fields[separator + 1].to_vec(),
            source: fields[separator + 2].to_vec(),
        });
    }
    Ok(matches)
}

fn is_capfs_mount(mount: &MountInfo) -> bool {
    matches!(mount.filesystem.as_slice(), b"fuse" | b"fuse.capfs") && mount.source == b"capfs"
}

fn exact_capfs_mount_id(path: &Path) -> io::Result<Option<u64>> {
    let mounts = exact_mounts(path)?;
    match mounts.as_slice() {
        [] => Ok(None),
        [mount] if is_capfs_mount(mount) => Ok(Some(mount.id)),
        _ => Err(io::Error::other(format!(
            "mount point does not have one exact fuse.capfs mount: {mounts:?}"
        ))),
    }
}

fn mount_presence(path: &Path, mount_id: u64) -> io::Result<MountPresence> {
    let mounts = exact_mounts(path)?;
    match mounts.as_slice() {
        [] => Ok(MountPresence::Absent),
        [mount] if mount.id == mount_id && is_capfs_mount(mount) => Ok(MountPresence::Active),
        _ => Ok(MountPresence::Replaced),
    }
}

fn classify_unmount_attempt(path: &Path, mount_id: u64, attempt: UnmountAttempt) -> UnmountAttempt {
    match mount_presence(path, mount_id) {
        Ok(MountPresence::Absent) => UnmountAttempt::Applied,
        Ok(MountPresence::Active) => UnmountAttempt::Unchanged(match attempt {
            UnmountAttempt::Unchanged(error) | UnmountAttempt::Unknown(error) => error,
            UnmountAttempt::Applied => {
                io::Error::other("unmount reported success but the exact FUSE mount remains active")
            }
        }),
        Ok(MountPresence::Replaced) => UnmountAttempt::Unknown(io::Error::other(
            "mount point was rebound to a different filesystem during cleanup",
        )),
        Err(error) => UnmountAttempt::Unknown(io::Error::new(
            error.kind(),
            format!("cannot verify unmount completion: {error}"),
        )),
    }
}

/// A rejected production `CapFS` composition.
#[derive(Debug)]
pub enum CapfsBuildError {
    /// Durable recovery is ambiguous or its journal cannot be trusted.
    Audit(AuditError),
    /// The authority state cannot be inspected.
    Kernel(CapabilityKernelError),
    /// The supplied authority state already contains issued session state.
    KernelNotPristine,
    /// The imported repository is poisoned or quarantined.
    RepositoryHealth(NamespaceError),
    /// A mount plan violates a production identity or path requirement.
    InvalidPlan(CapfsPlanError),
}

impl fmt::Display for CapfsBuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Audit(error) => write!(formatter, "durable authority recovery failed: {error}"),
            Self::Kernel(error) => write!(formatter, "authority state inspection failed: {error}"),
            Self::KernelNotPristine => {
                formatter.write_str("CapFS supervisor requires pristine authority state")
            }
            Self::RepositoryHealth(error) => {
                write!(formatter, "imported repository is not operational: {error}")
            }
            Self::InvalidPlan(error) => write!(formatter, "invalid CapFS mount plan: {error}"),
        }
    }
}

impl Error for CapfsBuildError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Audit(error) => Some(error),
            Self::Kernel(error) => Some(error),
            Self::RepositoryHealth(error) => Some(error),
            Self::InvalidPlan(error) => Some(error),
            Self::KernelNotPristine => None,
        }
    }
}

/// A malformed or unsafe mount plan.
#[derive(Debug)]
pub enum CapfsPlanError {
    /// An opaque identity was empty.
    EmptyIdentity(&'static str),
    /// Two plans reused a subject identity.
    DuplicateSubject(SubjectId),
    /// Two plans reused a mount identity.
    DuplicateMountInstance(MountInstanceId),
    /// Two plans reused a capability identity.
    DuplicateCapability(CapId),
    /// A grant names a subject other than its mount.
    GrantSubjectMismatch {
        /// Subject named by the mount plan.
        planned: SubjectId,
        /// Subject named by the capability grant.
        granted: SubjectId,
    },
    /// A grant is not repository filesystem authority.
    NonFileAuthority(SubjectId),
    /// A file grant has no usable operation.
    EmptyFileEffects(SubjectId),
    /// A grant names a repository other than the imported owner.
    RepositoryMismatch {
        /// Repository owned by the imported backing.
        imported: authority_core::repository::RepoId,
        /// Repository named by the grant.
        granted: authority_core::repository::RepoId,
    },
    /// The mount point could not be inspected.
    MountpointIo {
        /// Configured mount point.
        path: PathBuf,
        /// Failed path operation.
        operation: &'static str,
        /// Operating-system failure.
        source: io::Error,
    },
    /// The mount point is not a directory.
    MountpointNotDirectory(PathBuf),
    /// The mount point contains host files that a FUSE mount would hide.
    MountpointNotEmpty(PathBuf),
    /// Two plans resolve to the same mount point.
    DuplicateMountpoint(PathBuf),
    /// The configured mount point is already a mount root.
    MountpointAlreadyMounted(PathBuf),
    /// The mount point overlaps the repository backing path.
    MountpointOverlapsBacking {
        /// Canonical mount point.
        mountpoint: PathBuf,
        /// Canonical backing root.
        backing: PathBuf,
    },
    /// The configured unmount helper path was not absolute.
    UnmountHelperNotAbsolute(PathBuf),
    /// The configured unmount helper could not be inspected.
    UnmountHelperIo {
        /// Configured helper path.
        path: PathBuf,
        /// Operating-system failure.
        source: io::Error,
    },
    /// The configured unmount helper is not an executable regular file.
    UnmountHelperNotExecutable(PathBuf),
}

impl fmt::Display for CapfsPlanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyIdentity(kind) => write!(formatter, "{kind} must not be empty"),
            Self::DuplicateSubject(subject) => {
                write!(
                    formatter,
                    "subject `{subject}` has more than one mount plan"
                )
            }
            Self::DuplicateMountInstance(mount) => {
                write!(formatter, "mount instance `{mount}` is reused")
            }
            Self::DuplicateCapability(capability) => {
                write!(formatter, "capability `{capability}` is reused")
            }
            Self::GrantSubjectMismatch { planned, granted } => write!(
                formatter,
                "mount subject `{planned}` does not match grant subject `{granted}`"
            ),
            Self::NonFileAuthority(subject) => {
                write!(
                    formatter,
                    "mount subject `{subject}` has non-file authority"
                )
            }
            Self::EmptyFileEffects(subject) => {
                write!(formatter, "mount subject `{subject}` has no file effects")
            }
            Self::RepositoryMismatch { imported, granted } => write!(
                formatter,
                "imported repository `{imported}` does not match grant repository `{granted}`"
            ),
            Self::MountpointIo {
                path,
                operation,
                source,
            } => write!(
                formatter,
                "cannot {operation} mount point `{}`: {source}",
                path.display()
            ),
            Self::MountpointNotDirectory(path) => {
                write!(
                    formatter,
                    "mount point `{}` is not a directory",
                    path.display()
                )
            }
            Self::MountpointNotEmpty(path) => {
                write!(formatter, "mount point `{}` is not empty", path.display())
            }
            Self::DuplicateMountpoint(path) => {
                write!(formatter, "mount point `{}` is reused", path.display())
            }
            Self::MountpointAlreadyMounted(path) => write!(
                formatter,
                "mount point `{}` is already mounted",
                path.display()
            ),
            Self::MountpointOverlapsBacking {
                mountpoint,
                backing,
            } => write!(
                formatter,
                "mount point `{}` overlaps backing root `{}`",
                mountpoint.display(),
                backing.display()
            ),
            Self::UnmountHelperNotAbsolute(path) => write!(
                formatter,
                "unmount helper `{}` is not an absolute path",
                path.display()
            ),
            Self::UnmountHelperIo { path, source } => write!(
                formatter,
                "cannot inspect unmount helper `{}`: {source}",
                path.display()
            ),
            Self::UnmountHelperNotExecutable(path) => write!(
                formatter,
                "unmount helper `{}` is not an executable regular file",
                path.display()
            ),
        }
    }
}

impl Error for CapfsPlanError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::MountpointIo { source, .. } | Self::UnmountHelperIo { source, .. } => {
                Some(source)
            }
            _ => None,
        }
    }
}

/// A production `CapFS` runtime operation failure.
#[derive(Debug)]
pub enum CapfsResourceError<E> {
    /// The surrounding host resource adapter failed.
    Host(E),
    /// No unused mount plan exists for the requested subject.
    UnknownMountSubject(SubjectId),
    /// The requested mount plan was already consumed or became ambiguous.
    MountSubjectAlreadyIssued(SubjectId),
    /// Stable mount-token allocation is exhausted.
    MountHandleExhausted,
    /// A mount token does not identify an active `CapFS` session.
    UnknownMountHandle(MountHandle),
    /// A mount token belongs to another subject.
    MountSubjectMismatch {
        /// Subject selected by workload setup.
        requested: SubjectId,
        /// Subject that owns the stable mount token.
        mounted: SubjectId,
    },
    /// The imported repository became poisoned or quarantined.
    RepositoryHealth(NamespaceError),
    /// `CapFS` rejected the imported repository/authority composition.
    Filesystem(CapabilityFilesystemError),
    /// Root capability installation failed after subject registration.
    Capability(CapabilityKernelError),
    /// A mount, readiness, or drain system call failed.
    Io {
        /// Operation that failed.
        operation: &'static str,
        /// Exact canonical mount point.
        path: PathBuf,
        /// Operating-system error.
        source: io::Error,
    },
    /// A readiness probe reached the underlying host directory instead of `CapFS`.
    ReadinessBypassed(PathBuf),
}

impl<E: fmt::Display> fmt::Display for CapfsResourceError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Host(error) => write!(formatter, "host resource operation failed: {error}"),
            Self::UnknownMountSubject(subject) => {
                write!(formatter, "subject `{subject}` has no CapFS mount plan")
            }
            Self::MountSubjectAlreadyIssued(subject) => {
                write!(
                    formatter,
                    "subject `{subject}` already consumed its mount identity"
                )
            }
            Self::MountHandleExhausted => {
                formatter.write_str("stable CapFS mount handle space is exhausted")
            }
            Self::UnknownMountHandle(handle) => {
                write!(formatter, "unknown CapFS mount handle {handle:?}")
            }
            Self::MountSubjectMismatch { requested, mounted } => write!(
                formatter,
                "subject `{requested}` cannot start with mount owned by `{mounted}`"
            ),
            Self::RepositoryHealth(error) => {
                write!(formatter, "imported repository is not operational: {error}")
            }
            Self::Filesystem(error) => write!(formatter, "cannot construct CapFS: {error}"),
            Self::Capability(error) => {
                write!(formatter, "cannot install planned root capability: {error}")
            }
            Self::Io {
                operation,
                path,
                source,
            } => write!(
                formatter,
                "cannot {operation} CapFS mount `{}`: {source}",
                path.display()
            ),
            Self::ReadinessBypassed(path) => write!(
                formatter,
                "CapFS readiness probe reached the host directory `{}`",
                path.display()
            ),
        }
    }
}

impl<E: Error + 'static> Error for CapfsResourceError<E> {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Host(error) => Some(error),
            Self::RepositoryHealth(error) => Some(error),
            Self::Filesystem(error) => Some(error),
            Self::Capability(error) => Some(error),
            Self::Io { source, .. } => Some(source),
            Self::UnknownMountSubject(_)
            | Self::MountSubjectAlreadyIssued(_)
            | Self::MountHandleExhausted
            | Self::UnknownMountHandle(_)
            | Self::MountSubjectMismatch { .. }
            | Self::ReadinessBypassed(_) => None,
        }
    }
}

#[derive(Debug)]
struct ActiveMount {
    subject: SubjectId,
    capability: CapId,
    grant: CapabilityGrant,
    mountpoint: PathBuf,
    mount_id: u64,
    session: BackgroundSession,
    capability_issued: bool,
}

/// CapFS-owning implementation of the supervisor's resource contract.
///
/// Values are constructed only through [`CapfsRuntimeManager`], which prevents
/// pairing this adapter with a different authority kernel.
pub struct CapfsRuntimeResources<B> {
    host: B,
    kernel: Arc<CapabilityKernel>,
    repository: ImportedRepository,
    clock: Arc<dyn AuthorizationClock>,
    unmount: CapfsUnmountStrategy,
    plans: BTreeMap<SubjectId, CapfsMountPlan>,
    issued_subjects: BTreeSet<SubjectId>,
    uncertain_subjects: BTreeSet<SubjectId>,
    unresolved_mounts: Vec<BackgroundSession>,
    active_mounts: BTreeMap<MountHandle, ActiveMount>,
    retired_mounts: BTreeSet<MountHandle>,
    next_mount_handle: Option<u64>,
    drain_failures: Vec<String>,
}

impl<B> fmt::Debug for CapfsRuntimeResources<B>
where
    B: fmt::Debug,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CapfsRuntimeResources")
            .field("host", &self.host)
            .field("kernel", &self.kernel)
            .field("repository", &self.repository)
            .field("clock", &"<authorization clock>")
            .field("unmount", &self.unmount)
            .field("plans", &self.plans)
            .field("issued_subjects", &self.issued_subjects)
            .field("uncertain_subjects", &self.uncertain_subjects)
            .field("unresolved_mounts", &self.unresolved_mounts.len())
            .field("active_mounts", &self.active_mounts.keys())
            .field("retired_mounts", &self.retired_mounts)
            .field("next_mount_handle", &self.next_mount_handle)
            .field("drain_failures", &self.drain_failures)
            .finish()
    }
}

impl<B> CapfsRuntimeResources<B> {
    /// Returns the surrounding production host adapter.
    #[must_use]
    pub const fn host(&self) -> &B {
        &self.host
    }

    /// Returns a mutable view of the surrounding production host adapter.
    pub const fn host_mut(&mut self) -> &mut B {
        &mut self.host
    }

    /// Returns the number of FUSE sessions whose backing ownership is retained.
    #[must_use]
    pub fn active_mount_count(&self) -> usize {
        self.active_mounts.len()
    }

    /// Returns post-unmount worker failures observed after the mount was absent.
    ///
    /// Such a worker has already been joined, so the stable mount token is
    /// retired and cleanup is complete. The diagnostic is retained rather than
    /// misclassifying an absent resource as retryable.
    #[must_use]
    pub fn drain_failures(&self) -> &[String] {
        &self.drain_failures
    }

    fn reserve_mount_handle(&mut self) -> Option<MountHandle> {
        let sequence = self.next_mount_handle.take()?;
        self.next_mount_handle = sequence.checked_add(1);
        Some(MountHandle::new(sequence))
    }

    fn map_acquisition<T, E>(
        acquisition: ResourceAcquisition<T, E>,
    ) -> ResourceAcquisition<T, CapfsResourceError<E>> {
        match acquisition {
            ResourceAcquisition::Acquired(resource) => ResourceAcquisition::Acquired(resource),
            ResourceAcquisition::NoEffect(error) => {
                ResourceAcquisition::NoEffect(CapfsResourceError::Host(error))
            }
            ResourceAcquisition::CleanupRequired { resource, error } => {
                ResourceAcquisition::CleanupRequired {
                    resource,
                    error: CapfsResourceError::Host(error),
                }
            }
            ResourceAcquisition::EffectUnknown(error) => {
                ResourceAcquisition::EffectUnknown(CapfsResourceError::Host(error))
            }
        }
    }

    fn map_mutation<E>(mutation: ResourceMutation<E>) -> ResourceMutation<CapfsResourceError<E>> {
        match mutation {
            ResourceMutation::Applied => ResourceMutation::Applied,
            ResourceMutation::NoEffect(error) => {
                ResourceMutation::NoEffect(CapfsResourceError::Host(error))
            }
            ResourceMutation::CleanupRequired(error) => {
                ResourceMutation::CleanupRequired(CapfsResourceError::Host(error))
            }
            ResourceMutation::EffectUnknown(error) => {
                ResourceMutation::EffectUnknown(CapfsResourceError::Host(error))
            }
        }
    }

    fn readiness_result(path: &Path, mount_id: u64) -> Result<(), CapfsResourceError<B::Error>>
    where
        B: CapfsHostResources,
    {
        match mount_presence(path, mount_id) {
            Ok(MountPresence::Active) => {}
            Ok(MountPresence::Absent | MountPresence::Replaced) => {
                return Err(CapfsResourceError::ReadinessBypassed(path.to_path_buf()));
            }
            Err(source) => {
                return Err(CapfsResourceError::Io {
                    operation: "verify exact FUSE mount identity for",
                    path: path.to_path_buf(),
                    source,
                });
            }
        }
        let filesystem = statfs(path).map_err(|error| CapfsResourceError::Io {
            operation: "complete FUSE readiness request for",
            path: path.to_path_buf(),
            source: io::Error::from_raw_os_error(error.raw_os_error()),
        })?;
        let filesystem_type =
            u64::try_from(filesystem.f_type).map_err(|_| CapfsResourceError::Io {
                operation: "interpret FUSE filesystem type for",
                path: path.to_path_buf(),
                source: io::Error::other("filesystem type cannot be represented as u64"),
            })?;
        if filesystem_type == FUSE_SUPER_MAGIC {
            Ok(())
        } else {
            Err(CapfsResourceError::ReadinessBypassed(path.to_path_buf()))
        }
    }

    fn unmount_session(
        strategy: &CapfsUnmountStrategy,
        path: &Path,
        mount_id: u64,
        session: BackgroundSession,
    ) -> Result<Option<String>, (BackgroundSession, UnmountAttempt)> {
        let attempt = match mount_presence(path, mount_id) {
            Ok(MountPresence::Active) => strategy.unmount(path),
            Ok(MountPresence::Absent) => UnmountAttempt::Applied,
            Ok(MountPresence::Replaced) => {
                UnmountAttempt::Unknown(io::Error::other("mount point was rebound before cleanup"))
            }
            Err(error) => UnmountAttempt::Unknown(error),
        };
        match classify_unmount_attempt(path, mount_id, attempt) {
            UnmountAttempt::Applied => {}
            failure @ (UnmountAttempt::Unchanged(_) | UnmountAttempt::Unknown(_)) => {
                return Err((session, failure));
            }
        }
        Ok(session.join().err().map(|error| error.to_string()))
    }
}

impl<B> RuntimeResources for CapfsRuntimeResources<B>
where
    B: CapfsHostResources,
{
    type Error = CapfsResourceError<B::Error>;

    fn create_cgroup(
        &mut self,
        subject: &SubjectId,
    ) -> ResourceAcquisition<CgroupHandle, Self::Error> {
        Self::map_acquisition(self.host.create_cgroup(subject))
    }

    fn remove_cgroup(&mut self, cgroup: CgroupHandle) -> ResourceMutation<Self::Error> {
        Self::map_mutation(self.host.remove_cgroup(cgroup))
    }

    #[allow(clippy::too_many_lines)]
    fn mount_capfs(
        &mut self,
        subject: &SubjectId,
    ) -> ResourceAcquisition<MountHandle, Self::Error> {
        if self.issued_subjects.contains(subject) || self.uncertain_subjects.contains(subject) {
            return ResourceAcquisition::NoEffect(CapfsResourceError::MountSubjectAlreadyIssued(
                subject.clone(),
            ));
        }
        let Some(plan) = self.plans.get(subject).cloned() else {
            return ResourceAcquisition::NoEffect(CapfsResourceError::UnknownMountSubject(
                subject.clone(),
            ));
        };
        if let Err(error) = self.repository.namespace().generation() {
            return ResourceAcquisition::NoEffect(CapfsResourceError::RepositoryHealth(error));
        }
        match exact_mounts(&plan.mountpoint) {
            Ok(mounts) if mounts.is_empty() => {}
            Ok(_) => {
                return ResourceAcquisition::NoEffect(CapfsResourceError::ReadinessBypassed(
                    plan.mountpoint,
                ));
            }
            Err(source) => {
                return ResourceAcquisition::NoEffect(CapfsResourceError::Io {
                    operation: "verify unused mount point",
                    path: plan.mountpoint,
                    source,
                });
            }
        }
        let Some(handle) = self.reserve_mount_handle() else {
            return ResourceAcquisition::NoEffect(CapfsResourceError::MountHandleExhausted);
        };
        let authority = MountAuthority::new(
            plan.mount_instance.clone(),
            plan.subject.clone(),
            plan.capability.clone(),
            self.repository.repository().clone(),
        );
        let filesystem = match CapabilityFilesystem::new(
            self.repository.clone(),
            Arc::clone(&self.kernel),
            authority,
            Arc::clone(&self.clock),
        ) {
            Ok(filesystem) => filesystem,
            Err(error) => {
                self.retired_mounts.insert(handle);
                return ResourceAcquisition::NoEffect(CapfsResourceError::Filesystem(error));
            }
        };
        let session = match spawn_mount(filesystem, &plan.mountpoint) {
            Ok(session) => session,
            Err(source) => {
                self.retired_mounts.insert(handle);
                self.uncertain_subjects.insert(subject.clone());
                return ResourceAcquisition::EffectUnknown(CapfsResourceError::Io {
                    operation: "spawn",
                    path: plan.mountpoint,
                    source,
                });
            }
        };
        let mount_id = match exact_capfs_mount_id(&plan.mountpoint) {
            Ok(Some(mount_id)) => mount_id,
            Ok(None) => {
                self.retired_mounts.insert(handle);
                self.uncertain_subjects.insert(subject.clone());
                self.unresolved_mounts.push(session);
                return ResourceAcquisition::EffectUnknown(CapfsResourceError::Io {
                    operation: "resolve spawned mount identity for",
                    path: plan.mountpoint,
                    source: io::Error::other("spawn returned without an exact fuse.capfs mount"),
                });
            }
            Err(source) => {
                self.retired_mounts.insert(handle);
                self.uncertain_subjects.insert(subject.clone());
                self.unresolved_mounts.push(session);
                return ResourceAcquisition::EffectUnknown(CapfsResourceError::Io {
                    operation: "resolve spawned mount identity for",
                    path: plan.mountpoint,
                    source,
                });
            }
        };
        self.issued_subjects.insert(subject.clone());
        self.active_mounts.insert(
            handle,
            ActiveMount {
                subject: plan.subject,
                capability: plan.capability,
                grant: plan.grant,
                mountpoint: plan.mountpoint,
                mount_id,
                session,
                capability_issued: false,
            },
        );

        let readiness = {
            let active = self
                .active_mounts
                .get(&handle)
                .expect("newly inserted mount token must remain live");
            Self::readiness_result(&active.mountpoint, active.mount_id)
        };
        match readiness {
            Ok(()) => ResourceAcquisition::Acquired(handle),
            Err(error) => ResourceAcquisition::CleanupRequired {
                resource: handle,
                error,
            },
        }
    }

    fn unmount_capfs(&mut self, mount: MountHandle) -> ResourceMutation<Self::Error> {
        if self.retired_mounts.contains(&mount) {
            return ResourceMutation::Applied;
        }
        let Some(mut active) = self.active_mounts.remove(&mount) else {
            return ResourceMutation::NoEffect(CapfsResourceError::UnknownMountHandle(mount));
        };
        let path = active.mountpoint.clone();
        match Self::unmount_session(&self.unmount, &path, active.mount_id, active.session) {
            Ok(drain_failure) => {
                if let Some(error) = drain_failure {
                    self.drain_failures.push(format!(
                        "CapFS worker for `{}` ended with an error after unmount: {error}",
                        path.display()
                    ));
                }
                self.retired_mounts.insert(mount);
                ResourceMutation::Applied
            }
            Err((session, failure)) => {
                active.session = session;
                self.active_mounts.insert(mount, active);
                let error = |source| CapfsResourceError::Io {
                    operation: "unmount",
                    path,
                    source,
                };
                match failure {
                    UnmountAttempt::Unchanged(source) => {
                        ResourceMutation::CleanupRequired(error(source))
                    }
                    UnmountAttempt::Unknown(source) => {
                        ResourceMutation::EffectUnknown(error(source))
                    }
                    UnmountAttempt::Applied => {
                        unreachable!("applied unmount is returned through the success branch")
                    }
                }
            }
        }
    }

    fn open_control_fd(
        &mut self,
        subject: &SubjectId,
    ) -> ResourceAcquisition<ControlFdHandle, Self::Error> {
        Self::map_acquisition(self.host.open_control_fd(subject))
    }

    fn close_control_fd(&mut self, control: ControlFdHandle) -> ResourceMutation<Self::Error> {
        Self::map_mutation(self.host.close_control_fd(control))
    }

    fn start_workload(
        &mut self,
        subject: &SubjectId,
        cgroup: CgroupHandle,
        mount: MountHandle,
        control: ControlFdHandle,
    ) -> ResourceAcquisition<WorkloadHandle, Self::Error> {
        let Some(active) = self.active_mounts.get(&mount) else {
            return ResourceAcquisition::NoEffect(CapfsResourceError::UnknownMountHandle(mount));
        };
        if &active.subject != subject {
            return ResourceAcquisition::NoEffect(CapfsResourceError::MountSubjectMismatch {
                requested: subject.clone(),
                mounted: active.subject.clone(),
            });
        }
        let capability = active.capability.clone();
        let grant = active.grant.clone();
        let mountpoint = active.mountpoint.clone();
        if !active.capability_issued {
            if let Err(error) = self.kernel.issue_root_with_id(capability, grant) {
                return ResourceAcquisition::NoEffect(CapfsResourceError::Capability(error));
            }
            self.active_mounts
                .get_mut(&mount)
                .expect("validated mount token must remain live")
                .capability_issued = true;
        }
        Self::map_acquisition(self.host.start_workload(
            subject,
            cgroup,
            mount,
            &mountpoint,
            control,
        ))
    }

    fn stop_workload(
        &mut self,
        workload: WorkloadHandle,
        cgroup: CgroupHandle,
    ) -> ResourceMutation<Self::Error> {
        Self::map_mutation(self.host.stop_workload(workload, cgroup))
    }

    fn open_handle(
        &mut self,
        subject: &SubjectId,
        handle: &HandleId,
    ) -> ResourceMutation<Self::Error> {
        Self::map_mutation(self.host.open_handle(subject, handle))
    }

    fn close_handle(
        &mut self,
        subject: &SubjectId,
        handle: &HandleId,
    ) -> ResourceMutation<Self::Error> {
        Self::map_mutation(self.host.close_handle(subject, handle))
    }
}

impl<B> Drop for CapfsRuntimeResources<B> {
    fn drop(&mut self) {
        if !self.unresolved_mounts.is_empty() {
            // No path-addressed cleanup is safe without the exact mount ID.
            // Abort before any session or repository owner can be released.
            process::abort();
        }
        while let Some((_handle, active)) = self.active_mounts.pop_first() {
            let path = active.mountpoint.clone();
            match Self::unmount_session(&self.unmount, &path, active.mount_id, active.session) {
                Ok(drain_failure) => {
                    if let Some(error) = drain_failure {
                        self.drain_failures.push(format!(
                            "CapFS worker for `{}` ended with an error after unmount: {error}",
                            path.display()
                        ));
                    }
                }
                Err((_session, _error)) => {
                    // Dropping BackgroundSession would detach its JoinHandle
                    // after a best-effort unmount. Terminate instead of leaving
                    // a live filesystem worker with released backing ownership.
                    process::abort();
                }
            }
        }
    }
}

/// One-shot builder that binds a durable kernel to its `CapFS` resource owner.
pub struct CapfsRuntimeManager<B> {
    kernel: Arc<CapabilityKernel>,
    resources: CapfsRuntimeResources<B>,
}

/// Fully composed supervisor type produced by [`CapfsRuntimeManager`].
pub type CapfsSupervisor<B, C> = Supervisor<Arc<CapabilityKernel>, CapfsRuntimeResources<B>, C>;

/// Construction error for a [`CapfsSupervisor`].
pub type CapfsSupervisorError<B, C> = SupervisorError<
    CapabilityKernelError,
    CapfsResourceError<<B as CapfsHostResources>::Error>,
    <C as CallerResolver>::Error,
>;

impl<B> CapfsRuntimeManager<B> {
    /// Validates every production input and constructs the sole kernel owner.
    ///
    /// # Errors
    ///
    /// Recovery with `Started` or `CommitUnknown` audit records is rejected,
    /// as is non-pristine state, repository quarantine, duplicate identities,
    /// or an unsafe mount point.
    pub fn new(host: B, config: CapfsRuntimeConfig) -> Result<Self, CapfsBuildError> {
        let kernel = Arc::new(
            CapabilityKernel::try_new_with_durable_audit(config.state, config.audit)
                .map_err(CapfsBuildError::Audit)?,
        );
        if !kernel.is_pristine().map_err(CapfsBuildError::Kernel)? {
            return Err(CapfsBuildError::KernelNotPristine);
        }
        config
            .repository
            .namespace()
            .generation()
            .map_err(CapfsBuildError::RepositoryHealth)?;
        let unmount = config
            .unmount
            .validate()
            .map_err(CapfsBuildError::InvalidPlan)?;
        let plans = validate_plans(&config.repository, config.mounts)
            .map_err(CapfsBuildError::InvalidPlan)?;
        Ok(Self {
            kernel: Arc::clone(&kernel),
            resources: CapfsRuntimeResources {
                host,
                kernel,
                repository: config.repository,
                clock: config.clock,
                unmount,
                plans,
                issued_subjects: BTreeSet::new(),
                uncertain_subjects: BTreeSet::new(),
                unresolved_mounts: Vec::new(),
                active_mounts: BTreeMap::new(),
                retired_mounts: BTreeSet::new(),
                next_mount_handle: Some(0),
                drain_failures: Vec::new(),
            },
        })
    }

    /// Consumes the builder and gives the same kernel `Arc` to the supervisor
    /// and every `CapFS` mount.
    ///
    /// # Errors
    ///
    /// Returns the ordinary supervisor construction error if its final
    /// pristine-state check cannot be completed.
    pub fn into_supervisor<C>(
        self,
        callers: C,
    ) -> Result<CapfsSupervisor<B, C>, CapfsSupervisorError<B, C>>
    where
        B: CapfsHostResources,
        C: CallerResolver,
    {
        Supervisor::new(self.kernel, self.resources, callers)
    }
}

fn validate_plans(
    repository: &ImportedRepository,
    mounts: Vec<CapfsMountPlan>,
) -> Result<BTreeMap<SubjectId, CapfsMountPlan>, CapfsPlanError> {
    let mut plans = BTreeMap::new();
    let mut mount_instances = BTreeSet::new();
    let mut capabilities = BTreeSet::new();
    let mut mountpoints = BTreeSet::new();
    let backing = repository.backing().canonical_root();

    for mut plan in mounts {
        if plan.subject.as_str().is_empty() {
            return Err(CapfsPlanError::EmptyIdentity("subject identity"));
        }
        if plan.mount_instance.as_str().is_empty() {
            return Err(CapfsPlanError::EmptyIdentity("mount instance identity"));
        }
        if plan.capability.as_str().is_empty() {
            return Err(CapfsPlanError::EmptyIdentity("capability identity"));
        }
        if plan.grant.subject() != &plan.subject {
            return Err(CapfsPlanError::GrantSubjectMismatch {
                planned: plan.subject,
                granted: plan.grant.subject().clone(),
            });
        }
        let AuthorityBody::File(authority) = plan.grant.authority() else {
            return Err(CapfsPlanError::NonFileAuthority(plan.subject));
        };
        if authority.effects().is_empty() {
            return Err(CapfsPlanError::EmptyFileEffects(plan.subject));
        }
        if authority.repository() != repository.repository() {
            return Err(CapfsPlanError::RepositoryMismatch {
                imported: repository.repository().clone(),
                granted: authority.repository().clone(),
            });
        }
        if !mount_instances.insert(plan.mount_instance.clone()) {
            return Err(CapfsPlanError::DuplicateMountInstance(plan.mount_instance));
        }
        if !capabilities.insert(plan.capability.clone()) {
            return Err(CapfsPlanError::DuplicateCapability(plan.capability));
        }
        let metadata =
            fs::metadata(&plan.mountpoint).map_err(|source| CapfsPlanError::MountpointIo {
                path: plan.mountpoint.clone(),
                operation: "inspect",
                source,
            })?;
        if !metadata.is_dir() {
            return Err(CapfsPlanError::MountpointNotDirectory(plan.mountpoint));
        }
        let mut entries =
            fs::read_dir(&plan.mountpoint).map_err(|source| CapfsPlanError::MountpointIo {
                path: plan.mountpoint.clone(),
                operation: "read",
                source,
            })?;
        if entries
            .next()
            .transpose()
            .map_err(|source| CapfsPlanError::MountpointIo {
                path: plan.mountpoint.clone(),
                operation: "read",
                source,
            })?
            .is_some()
        {
            return Err(CapfsPlanError::MountpointNotEmpty(plan.mountpoint));
        }
        let canonical =
            fs::canonicalize(&plan.mountpoint).map_err(|source| CapfsPlanError::MountpointIo {
                path: plan.mountpoint.clone(),
                operation: "canonicalize",
                source,
            })?;
        if canonical.starts_with(backing) || backing.starts_with(&canonical) {
            return Err(CapfsPlanError::MountpointOverlapsBacking {
                mountpoint: canonical,
                backing: backing.to_path_buf(),
            });
        }
        if !mountpoints.insert(canonical.clone()) {
            return Err(CapfsPlanError::DuplicateMountpoint(canonical));
        }
        let existing_mounts =
            exact_mounts(&canonical).map_err(|source| CapfsPlanError::MountpointIo {
                path: canonical.clone(),
                operation: "inspect mount table for",
                source,
            })?;
        if !existing_mounts.is_empty() {
            return Err(CapfsPlanError::MountpointAlreadyMounted(canonical));
        }
        plan.mountpoint = canonical;
        let subject = plan.subject.clone();
        if plans.insert(subject.clone(), plan).is_some() {
            return Err(CapfsPlanError::DuplicateSubject(subject));
        }
    }
    Ok(plans)
}

impl AuthorityKernel for Arc<CapabilityKernel> {
    type Error = CapabilityKernelError;

    fn is_pristine(&self) -> Result<bool, Self::Error> {
        CapabilityKernel::is_pristine(self.as_ref())
    }

    fn register_subject(&self, subject: Subject) -> Result<(), Self::Error> {
        CapabilityKernel::register_subject(self.as_ref(), subject)
    }

    fn issue_root(&self, grant: CapabilityGrant) -> Result<CapId, Self::Error> {
        CapabilityKernel::issue_root(self.as_ref(), grant)
    }

    fn derive(
        &self,
        caller: &SubjectId,
        parent: &CapId,
        grant: CapabilityGrant,
        now: MonotonicTime,
    ) -> Result<CapId, Self::Error> {
        CapabilityKernel::derive(self.as_ref(), caller, parent, grant, now)
    }

    fn revoke(
        &self,
        caller: &SubjectId,
        capability: &CapId,
    ) -> Result<RevocationStatus, Self::Error> {
        CapabilityKernel::revoke_held_by(self.as_ref(), caller, capability)
    }

    fn begin_subject_close(&self, subject: &SubjectId) -> Result<SubjectCloseStatus, Self::Error> {
        CapabilityKernel::begin_subject_close(self.as_ref(), subject)
    }

    fn finish_subject_close(
        &self,
        subject: &SubjectId,
    ) -> Result<SubjectFinishStatus, Self::Error> {
        CapabilityKernel::finish_subject_close(self.as_ref(), subject)
    }

    fn register_open_handle(&self, handle: OpenHandle) -> Result<(), Self::Error> {
        CapabilityKernel::register_open_handle(self.as_ref(), handle)
    }

    fn close_handle(
        &self,
        caller: &SubjectId,
        handle: &HandleId,
    ) -> Result<HandleCloseStatus, Self::Error> {
        CapabilityKernel::close_handle(self.as_ref(), caller, handle)
    }

    fn open_handle(&self, handle: &HandleId) -> Result<Option<OpenHandle>, Self::Error> {
        CapabilityKernel::open_handle(self.as_ref(), handle)
    }
}

#[cfg(test)]
mod tests {
    use std::{convert::Infallible, env, num::NonZeroUsize};

    use authority_core::{
        capability::{AuthorityRequest, CapabilityRequest, IssuerId},
        file::{FileAuthority, FileEffect, FileEffects, FileRequest},
        kernel::EffectExecution,
        path::{CanonicalPath, PathPattern},
        repository::RepoId,
        state::StaticAuthorityEnvelope,
        time::TimeWindow,
    };
    use capfs::backing::{PreflightLimits, RepositoryStartupError};
    use tempfile::{TempDir, tempdir};

    use super::*;
    use crate::{ConnectionIdentity, StaticCallerResolver, SubjectLifecycle};

    #[derive(Debug, Default)]
    struct TestHostResources {
        events: Vec<&'static str>,
    }

    impl CapfsHostResources for TestHostResources {
        type Error = io::Error;

        fn create_cgroup(
            &mut self,
            _subject: &SubjectId,
        ) -> ResourceAcquisition<CgroupHandle, Self::Error> {
            self.events.push("create cgroup");
            ResourceAcquisition::Acquired(CgroupHandle::new(1))
        }

        fn remove_cgroup(&mut self, _cgroup: CgroupHandle) -> ResourceMutation<Self::Error> {
            self.events.push("remove cgroup");
            ResourceMutation::Applied
        }

        fn open_control_fd(
            &mut self,
            _subject: &SubjectId,
        ) -> ResourceAcquisition<ControlFdHandle, Self::Error> {
            self.events.push("open control");
            ResourceAcquisition::Acquired(ControlFdHandle::new(2))
        }

        fn close_control_fd(&mut self, _control: ControlFdHandle) -> ResourceMutation<Self::Error> {
            self.events.push("close control");
            ResourceMutation::Applied
        }

        fn start_workload(
            &mut self,
            _subject: &SubjectId,
            _cgroup: CgroupHandle,
            _mount: MountHandle,
            mountpoint: &Path,
            _control: ControlFdHandle,
        ) -> ResourceAcquisition<WorkloadHandle, Self::Error> {
            match fs::read_to_string(mountpoint.join("allowed.txt")) {
                Ok(contents) if contents == "capability" => {
                    self.events.push("start workload");
                    ResourceAcquisition::Acquired(WorkloadHandle::new(3))
                }
                Ok(contents) => ResourceAcquisition::NoEffect(io::Error::other(format!(
                    "CapFS returned unexpected test contents `{contents}`"
                ))),
                Err(error) => ResourceAcquisition::NoEffect(error),
            }
        }

        fn stop_workload(
            &mut self,
            _workload: WorkloadHandle,
            _cgroup: CgroupHandle,
        ) -> ResourceMutation<Self::Error> {
            self.events.push("stop workload");
            ResourceMutation::Applied
        }

        fn open_handle(
            &mut self,
            _subject: &SubjectId,
            _handle: &HandleId,
        ) -> ResourceMutation<Self::Error> {
            ResourceMutation::Applied
        }

        fn close_handle(
            &mut self,
            _subject: &SubjectId,
            _handle: &HandleId,
        ) -> ResourceMutation<Self::Error> {
            ResourceMutation::Applied
        }
    }

    fn limits() -> PreflightLimits {
        PreflightLimits::new(
            NonZeroUsize::new(16).expect("test limit must be non-zero"),
            2,
        )
    }

    fn validity() -> TimeWindow {
        TimeWindow::new(MonotonicTime::from_ticks(0), MonotonicTime::from_ticks(10))
            .expect("test validity must be non-empty")
    }

    fn file_authority(repository: RepoId) -> AuthorityBody {
        AuthorityBody::File(FileAuthority::new(
            repository,
            FileEffects::from_effects([FileEffect::ReadData, FileEffect::ListDirectory]),
            PathPattern::Prefix(CanonicalPath::root()),
        ))
    }

    fn imported_repository(repository: &RepoId, backing: &TempDir) -> ImportedRepository {
        ImportedRepository::open(repository.clone(), backing.path(), limits())
            .expect("test repository must pass production import")
    }

    fn test_unmount_strategy() -> CapfsUnmountStrategy {
        [
            "/usr/bin/fusermount3",
            "/bin/fusermount3",
            "/usr/bin/fusermount",
            "/bin/fusermount",
        ]
        .into_iter()
        .find(|path| {
            fs::metadata(path).is_ok_and(|metadata| {
                metadata.is_file() && metadata.permissions().mode() & 0o111 != 0
            })
        })
        .map_or_else(CapfsUnmountStrategy::kernel, |path| {
            CapfsUnmountStrategy::helper(PathBuf::from(path))
        })
    }

    fn fuse_test_available() -> bool {
        let required = match env::var("SUPERVISOR_REQUIRE_FUSE_TESTS") {
            Ok(value) if value == "1" => true,
            Ok(value) => panic!(
                "SUPERVISOR_REQUIRE_FUSE_TESTS must be exactly `1` when present, got `{value}`"
            ),
            Err(env::VarError::NotPresent) => false,
            Err(env::VarError::NotUnicode(_)) => {
                panic!("SUPERVISOR_REQUIRE_FUSE_TESTS must be valid UTF-8")
            }
        };
        if Path::new("/dev/fuse").exists() {
            return true;
        }
        assert!(
            !required,
            "SUPERVISOR_REQUIRE_FUSE_TESTS=1 but /dev/fuse is unavailable"
        );
        eprintln!(
            "skipping production CapFS integration test: /dev/fuse is unavailable; set SUPERVISOR_REQUIRE_FUSE_TESTS=1 to make absence fatal"
        );
        false
    }

    fn config(
        imported: ImportedRepository,
        journal: &Path,
        subject: &SubjectId,
        repository: &RepoId,
        mountpoint: &Path,
    ) -> CapfsRuntimeConfig {
        let authority = file_authority(repository.clone());
        CapfsRuntimeConfig::new(
            CapabilityState::new(IssuerId::new("production-test-session")),
            DurableAuditLog::create(journal).expect("test WAL must be durable"),
            imported,
            Arc::new(MonotonicTime::from_ticks(5)),
            test_unmount_strategy(),
            vec![CapfsMountPlan::new(
                subject.clone(),
                MountInstanceId::new("production-test-mount"),
                CapId::new("production-test-root"),
                CapabilityGrant::new(subject.clone(), validity(), authority),
                mountpoint,
            )],
        )
    }

    // Requirement: startup must reject durable attempts whose external effect
    // remains unresolved. Category: unit/security. Risk: critical.
    #[test]
    fn durable_commit_unknown_prevents_production_manager_startup() {
        let temporary = tempdir().expect("temporary directory must be creatable");
        let journal = temporary.path().join("authority.wal");
        let audit = DurableAuditLog::create(&journal).expect("test WAL must be durable");
        let subject = SubjectId::new("ambiguous-subject");
        let repository = RepoId::new("ambiguous-repository");
        let authority = file_authority(repository.clone());
        let kernel = CapabilityKernel::try_new_with_durable_audit(
            CapabilityState::new(IssuerId::new("ambiguous-session")),
            audit,
        )
        .expect("empty durable recovery must be accepted");
        kernel
            .register_subject(Subject::new(
                subject.clone(),
                StaticAuthorityEnvelope::new(validity(), authority.clone()),
            ))
            .expect("test subject must register");
        let capability = kernel
            .issue_root(CapabilityGrant::new(subject.clone(), validity(), authority))
            .expect("test root must issue");
        let request = CapabilityRequest::new(
            MonotonicTime::from_ticks(5),
            AuthorityRequest::File(FileRequest::new(
                repository.clone(),
                FileEffect::ReadData,
                CanonicalPath::root(),
            )),
        );
        let outcome = kernel.authorize_and_execute_classified::<(), Infallible>(
            &subject,
            &capability,
            &request,
            |_| EffectExecution::CommitUnknown {
                evidence: b"provider completion unavailable".to_vec(),
            },
        );
        assert!(matches!(
            outcome,
            Err(authority_core::kernel::EffectCommitError::CommitUnknown { .. })
        ));
        drop(kernel);

        let backing = tempdir().expect("temporary backing directory must be creatable");
        let mountpoint = tempdir().expect("temporary mountpoint must be creatable");
        let imported = imported_repository(&repository, &backing);
        let recovered = CapfsRuntimeConfig::new(
            CapabilityState::new(IssuerId::new("ambiguous-session")),
            DurableAuditLog::open(&journal).expect("test WAL must reopen"),
            imported,
            Arc::new(MonotonicTime::from_ticks(5)),
            CapfsUnmountStrategy::kernel(),
            vec![CapfsMountPlan::new(
                subject.clone(),
                MountInstanceId::new("ambiguous-mount"),
                CapId::new("ambiguous-root"),
                CapabilityGrant::new(subject, validity(), file_authority(repository)),
                mountpoint.path(),
            )],
        );

        assert!(matches!(
            CapfsRuntimeManager::new(TestHostResources::default(), recovered),
            Err(CapfsBuildError::Audit(AuditError::StateRecoveryRequired { attempts }))
                if attempts.len() == 1 && attempts[0].as_u64() == 0
        ));
    }

    // Requirement: an ordinary host directory is never accepted as a ready
    // FUSE mount. Category: unit/security. Risk: critical.
    #[test]
    fn readiness_rejects_unmounted_host_directory() {
        let mountpoint = tempdir().expect("temporary mountpoint must be creatable");

        assert!(matches!(
            CapfsRuntimeResources::<TestHostResources>::readiness_result(
                mountpoint.path(),
                u64::MAX,
            ),
            Err(CapfsResourceError::ReadinessBypassed(path)) if path == mountpoint.path()
        ));
    }

    // Requirement: an imported root remains process-exclusive while the
    // production manager owns its health and backing fd. Category: unit/security.
    // Risk: high.
    #[test]
    fn production_manager_retains_exclusive_imported_repository_owner() {
        let temporary = tempdir().expect("temporary directory must be creatable");
        let backing = tempdir().expect("temporary backing directory must be creatable");
        let mountpoint = tempdir().expect("temporary mountpoint must be creatable");
        let repository = RepoId::new("exclusive-repository");
        let subject = SubjectId::new("exclusive-subject");
        let imported = imported_repository(&repository, &backing);
        let manager = CapfsRuntimeManager::new(
            TestHostResources::default(),
            config(
                imported,
                &temporary.path().join("authority.wal"),
                &subject,
                &repository,
                mountpoint.path(),
            ),
        )
        .expect("production manager must accept healthy inputs");

        assert!(matches!(
            ImportedRepository::open(repository.clone(), backing.path(), limits()),
            Err(RepositoryStartupError::AlreadyOpen { .. })
        ));
        drop(manager);
        ImportedRepository::open(repository, backing.path(), limits())
            .expect("dropping the drained manager must release the exact repository lease");
    }

    // Requirement: when FUSE exists, production composition must prove mount
    // readiness before workload release and join the session during ordered
    // shutdown. Category: integration/security. Risk: critical.
    #[test]
    fn production_supervisor_mounts_releases_workload_and_drains_fuse() {
        if !fuse_test_available() {
            return;
        }

        let temporary = tempdir().expect("temporary directory must be creatable");
        let backing = tempdir().expect("temporary backing directory must be creatable");
        let mountpoint = tempdir().expect("temporary mountpoint must be creatable");
        fs::write(backing.path().join("allowed.txt"), "capability")
            .expect("test backing file must be writable");
        let repository = RepoId::new("production-repository");
        let subject_id = SubjectId::new("production-subject");
        let authority = file_authority(repository.clone());
        let imported = imported_repository(&repository, &backing);
        let manager = CapfsRuntimeManager::new(
            TestHostResources::default(),
            config(
                imported,
                &temporary.path().join("authority.wal"),
                &subject_id,
                &repository,
                mountpoint.path(),
            ),
        )
        .expect("production manager must accept healthy inputs");
        let connection = ConnectionIdentity::new(7, 8, 9, 10);
        let mut callers = StaticCallerResolver::new();
        callers
            .bind(connection, subject_id.clone())
            .expect("test connection must bind exactly once");
        let mut supervisor = manager
            .into_supervisor(callers)
            .expect("same-kernel production composition must be pristine");

        supervisor
            .create_subject(
                Subject::new(
                    subject_id.clone(),
                    StaticAuthorityEnvelope::new(validity(), authority),
                ),
                connection,
            )
            .expect("ready CapFS mount must precede workload success");
        assert_eq!(
            supervisor
                .lifecycle(&subject_id)
                .expect("subject must be tracked"),
            SubjectLifecycle::Running
        );
        assert_eq!(supervisor.resources().active_mount_count(), 1);
        assert_eq!(
            fs::read_to_string(mountpoint.path().join("allowed.txt"))
                .expect("running workload view must remain readable"),
            "capability"
        );

        supervisor
            .shutdown_subject(&subject_id)
            .expect("ordered shutdown must unmount and join CapFS");
        assert_eq!(
            supervisor
                .lifecycle(&subject_id)
                .expect("subject tombstone must remain tracked"),
            SubjectLifecycle::Closed
        );
        assert_eq!(supervisor.resources().active_mount_count(), 0);
        assert!(supervisor.resources().drain_failures().is_empty());
        assert_eq!(
            supervisor.resources().host().events,
            [
                "create cgroup",
                "open control",
                "start workload",
                "stop workload",
                "close control",
                "remove cgroup",
            ]
        );
        assert!(
            fs::metadata(mountpoint.path()).is_ok(),
            "mount point must expose its host directory after drain"
        );
    }
}
