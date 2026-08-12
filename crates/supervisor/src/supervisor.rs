//! Subject lifecycle orchestration and transport identity binding.

use std::{
    collections::{BTreeMap, BTreeSet, btree_map::Entry},
    error::Error,
    fmt,
};

use authority_core::{
    capability::{CapId, SubjectId},
    handle::{HandleId, ObjectId, OpenHandle},
    kernel::CapabilityKernel,
    state::{
        CapabilityGrant, HandleCloseStatus, RevocationStatus, Subject, SubjectCloseStatus,
        SubjectFinishStatus,
    },
    time::MonotonicTime,
};

use crate::protocol::{WireDecodeError, WireRequest};

/// Identity obtained from an accepted, authenticated local connection.
///
/// A production listener should construct this value from its accepted
/// `SOCK_SEQPACKET` (or equivalent) connection and peer credentials. It must
/// never be constructed from bytes in [`WireRequest`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ConnectionIdentity {
    socket_id: u64,
    peer_pid: u32,
    peer_uid: u32,
    peer_gid: u32,
}

impl ConnectionIdentity {
    /// Creates an identity representing one accepted transport connection.
    #[must_use]
    pub const fn new(
        socket_id: u64,
        peer_process_id: u32,
        peer_user_id: u32,
        peer_group_id: u32,
    ) -> Self {
        Self {
            socket_id,
            peer_pid: peer_process_id,
            peer_uid: peer_user_id,
            peer_gid: peer_group_id,
        }
    }

    /// Returns the supervisor-local accepted socket identity.
    #[must_use]
    pub const fn socket_id(self) -> u64 {
        self.socket_id
    }

    /// Returns the peer process ID captured by the transport boundary.
    #[must_use]
    pub const fn peer_pid(self) -> u32 {
        self.peer_pid
    }

    /// Returns the peer user ID captured by the transport boundary.
    #[must_use]
    pub const fn peer_uid(self) -> u32 {
        self.peer_uid
    }

    /// Returns the peer group ID captured by the transport boundary.
    #[must_use]
    pub const fn peer_gid(self) -> u32 {
        self.peer_gid
    }
}

/// Resolves an authenticated connection identity to the host-assigned subject.
pub trait CallerResolver {
    /// Resolver-specific failure type.
    type Error: Error + Send + Sync + 'static;

    /// Returns the caller bound to an accepted connection.
    fn resolve(&self, identity: &ConnectionIdentity) -> Result<SubjectId, Self::Error>;
}

/// An in-memory resolver useful for tests and small host adapters.
#[derive(Debug, Default, Clone)]
pub struct StaticCallerResolver {
    bindings: BTreeMap<ConnectionIdentity, SubjectId>,
}

impl StaticCallerResolver {
    /// Creates an empty connection-to-subject binding table.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            bindings: BTreeMap::new(),
        }
    }

    /// Binds an accepted connection once and rejects accidental rebinding.
    pub fn bind(
        &mut self,
        identity: ConnectionIdentity,
        subject: SubjectId,
    ) -> Result<(), SubjectId> {
        match self.bindings.entry(identity) {
            Entry::Occupied(_) => Err(subject),
            Entry::Vacant(entry) => {
                entry.insert(subject);
                Ok(())
            }
        }
    }
}

/// The resolver error returned for an unbound connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallerBindingError {
    identity: ConnectionIdentity,
}

impl fmt::Display for CallerBindingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "connection {} has no subject binding",
            self.identity.socket_id()
        )
    }
}

impl Error for CallerBindingError {}

impl CallerResolver for StaticCallerResolver {
    type Error = CallerBindingError;

    fn resolve(&self, identity: &ConnectionIdentity) -> Result<SubjectId, Self::Error> {
        self.bindings
            .get(identity)
            .cloned()
            .ok_or(CallerBindingError {
                identity: *identity,
            })
    }
}

/// A typed resource token returned by an OS-specific cgroup adapter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CgroupHandle(u64);

impl CgroupHandle {
    /// Creates an opaque cgroup token owned by a resource adapter.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }
}

/// A typed resource token returned by an OS-specific mount adapter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MountHandle(u64);

impl MountHandle {
    /// Creates an opaque mount token owned by a resource adapter.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }
}

/// A typed resource token returned by an OS-specific control-fd adapter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ControlFdHandle(u64);

impl ControlFdHandle {
    /// Creates an opaque control-fd token owned by a resource adapter.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }
}

/// A typed resource token returned by an OS-specific workload adapter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct WorkloadHandle(u64);

impl WorkloadHandle {
    /// Creates an opaque workload token owned by a resource adapter.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }
}

/// Resource operations required by the supervisor lifecycle.
pub trait RuntimeResources {
    /// Resource-adapter failure type.
    type Error: Error + Send + Sync + 'static;

    /// Allocates the workload cgroup before any child can run.
    fn create_cgroup(&mut self, subject: &SubjectId) -> Result<CgroupHandle, Self::Error>;

    /// Removes a cgroup after its workload and mount are stopped.
    fn remove_cgroup(&mut self, cgroup: CgroupHandle) -> Result<(), Self::Error>;

    /// Mounts the subject's capability filesystem.
    fn mount_capfs(&mut self, subject: &SubjectId) -> Result<MountHandle, Self::Error>;

    /// Unmounts the subject's capability filesystem.
    fn unmount_capfs(&mut self, mount: MountHandle) -> Result<(), Self::Error>;

    /// Opens the subject's private control descriptor.
    fn open_control_fd(&mut self, subject: &SubjectId) -> Result<ControlFdHandle, Self::Error>;

    /// Closes the subject's private control descriptor.
    fn close_control_fd(&mut self, control: ControlFdHandle) -> Result<(), Self::Error>;

    /// Starts the workload after authority registration has completed.
    fn start_workload(
        &mut self,
        subject: &SubjectId,
        cgroup: CgroupHandle,
        mount: MountHandle,
        control: ControlFdHandle,
    ) -> Result<WorkloadHandle, Self::Error>;

    /// Stops the workload before descriptors, handles, or mounts are closed.
    fn stop_workload(
        &mut self,
        workload: WorkloadHandle,
        cgroup: CgroupHandle,
    ) -> Result<(), Self::Error>;

    /// Opens a runtime handle before it is registered with the authority kernel.
    fn open_handle(&mut self, subject: &SubjectId, handle: &HandleId) -> Result<(), Self::Error>;

    /// Closes a runtime handle. Implementations should make this idempotent so
    /// authority registration rollback can retry safely.
    fn close_handle(&mut self, subject: &SubjectId, handle: &HandleId) -> Result<(), Self::Error>;
}

/// The authority-kernel surface used by the supervisor.
pub trait AuthorityKernel {
    /// Kernel failure type.
    type Error: Error + Send + Sync + 'static;

    /// Registers a fully prepared subject as running.
    fn register_subject(&self, subject: Subject) -> Result<(), Self::Error>;

    /// Issues a host-created root capability.
    fn issue_root(&self, grant: CapabilityGrant) -> Result<CapId, Self::Error>;

    /// Derives a child capability using the transport-authenticated caller.
    fn derive(
        &self,
        caller: &SubjectId,
        parent: &CapId,
        grant: CapabilityGrant,
        now: MonotonicTime,
    ) -> Result<CapId, Self::Error>;

    /// Revokes a capability and all authority derived from it.
    fn revoke(&self, capability: &CapId) -> Result<RevocationStatus, Self::Error>;

    /// Begins shutdown and stops new authorization before resource cleanup.
    fn begin_subject_close(&self, subject: &SubjectId) -> Result<SubjectCloseStatus, Self::Error>;

    /// Completes shutdown after all external resources and handles are gone.
    fn finish_subject_close(&self, subject: &SubjectId)
    -> Result<SubjectFinishStatus, Self::Error>;

    /// Registers one already-open runtime handle.
    fn register_open_handle(&self, handle: OpenHandle) -> Result<(), Self::Error>;

    /// Closes one authority handle for its authenticated owner.
    fn close_handle(
        &self,
        caller: &SubjectId,
        handle: &HandleId,
    ) -> Result<HandleCloseStatus, Self::Error>;

    /// Returns the live handle record, if the kernel still owns it.
    fn open_handle(&self, handle: &HandleId) -> Result<Option<OpenHandle>, Self::Error>;
}

impl AuthorityKernel for CapabilityKernel {
    type Error = authority_core::kernel::CapabilityKernelError;

    fn register_subject(&self, subject: Subject) -> Result<(), Self::Error> {
        CapabilityKernel::register_subject(self, subject)
    }

    fn issue_root(&self, grant: CapabilityGrant) -> Result<CapId, Self::Error> {
        CapabilityKernel::issue_root(self, grant)
    }

    fn derive(
        &self,
        caller: &SubjectId,
        parent: &CapId,
        grant: CapabilityGrant,
        now: MonotonicTime,
    ) -> Result<CapId, Self::Error> {
        CapabilityKernel::derive(self, caller, parent, grant, now)
    }

    fn revoke(&self, capability: &CapId) -> Result<RevocationStatus, Self::Error> {
        CapabilityKernel::revoke(self, capability)
    }

    fn begin_subject_close(&self, subject: &SubjectId) -> Result<SubjectCloseStatus, Self::Error> {
        CapabilityKernel::begin_subject_close(self, subject)
    }

    fn finish_subject_close(
        &self,
        subject: &SubjectId,
    ) -> Result<SubjectFinishStatus, Self::Error> {
        CapabilityKernel::finish_subject_close(self, subject)
    }

    fn register_open_handle(&self, handle: OpenHandle) -> Result<(), Self::Error> {
        CapabilityKernel::register_open_handle(self, handle)
    }

    fn close_handle(
        &self,
        caller: &SubjectId,
        handle: &HandleId,
    ) -> Result<HandleCloseStatus, Self::Error> {
        CapabilityKernel::close_handle(self, caller, handle)
    }

    fn open_handle(&self, handle: &HandleId) -> Result<Option<OpenHandle>, Self::Error> {
        CapabilityKernel::open_handle(self, handle)
    }
}

/// The subject lifecycle enforced by this adapter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SubjectLifecycle {
    /// Resources are being prepared and the subject is not authorized yet.
    Creating,
    /// Resources are ready and the workload may receive requests.
    Running,
    /// Authorization is stopped while external resources are cleaned up.
    Closing,
    /// Cleanup completed and no future request is accepted.
    Closed,
}

/// Cleanup phase associated with a reported failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CleanupStep {
    /// Authority shutdown began and revocation was requested.
    BeginClose,
    /// Workload stop or cgroup stop failed.
    StopWorkload,
    /// Control descriptor close failed.
    CloseControlFd,
    /// Runtime or authority handle close failed.
    CloseHandle,
    /// Capability filesystem unmount failed.
    Unmount,
    /// Cgroup removal failed.
    RemoveCgroup,
    /// Authority close completion was rejected.
    FinishClose,
}

/// A failure retained while attempting all safe cleanup phases.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CleanupFailure {
    /// Phase that failed.
    pub step: CleanupStep,
    /// Full adapter error text for diagnostics.
    pub message: String,
}

/// Setup phase associated with a failed creation transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SetupStep {
    /// Cgroup allocation failed.
    CreateCgroup,
    /// Capability filesystem mount failed.
    Mount,
    /// Control descriptor setup failed.
    OpenControlFd,
    /// Authority registration failed.
    RegisterSubject,
    /// Runtime-handle authority registration failed.
    RegisterHandle,
    /// Workload start failed.
    StartWorkload,
}

/// A marker error for resource implementations that only need a string message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceError(pub String);

impl fmt::Display for ResourceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl Error for ResourceError {}

/// A dispatch result for a successfully applied wire control request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DispatchResponse {
    /// The caller's subject entered the closed state.
    SubjectClosed,
    /// The caller's handle was closed.
    HandleClosed,
}

/// Errors returned by supervisor orchestration.
#[derive(Debug)]
pub enum SupervisorError<KE, RE, CE> {
    /// The transport identity could not be mapped to a subject.
    Caller(CE),
    /// The authority kernel rejected a transition.
    Kernel(KE),
    /// The runtime resource adapter rejected an operation.
    Resource(RE),
    /// The wire request failed closed decoding.
    Wire(WireDecodeError),
    /// A subject identity is already owned by this supervisor.
    DuplicateSubject(SubjectId),
    /// A requested subject is not known to this supervisor.
    UnknownSubject(SubjectId),
    /// A subject is not in the Running state required by the operation.
    SubjectNotRunning(SubjectId),
    /// A subject is already in cleanup and cannot receive new requests.
    SubjectClosing(SubjectId),
    /// A subject has completed cleanup and rejects all requests.
    SubjectClosed(SubjectId),
    /// A connection was resolved to a subject different from the requested binding.
    ConnectionSubjectMismatch {
        /// Subject requested by the host setup operation.
        requested: SubjectId,
        /// Subject returned by the authenticated connection binding.
        bound: SubjectId,
    },
    /// A root grant was addressed to a different subject than its API target.
    GrantSubjectMismatch {
        /// Subject selected by the API caller.
        requested: SubjectId,
        /// Subject embedded in the typed capability grant.
        granted: SubjectId,
    },
    /// A known subject was addressed through a different accepted connection.
    ConnectionNotBoundToSubject {
        /// Subject associated with the accepted connection in the resolver.
        subject: SubjectId,
        /// Connection identity that did not match the subject's bound channel.
        identity: ConnectionIdentity,
    },
    /// A handle belongs to another authenticated subject.
    HandleNotOwned {
        /// Authenticated subject attempting the close.
        caller: SubjectId,
        /// Handle selected by the request.
        handle: HandleId,
    },
    /// A handle was never live or was already closed.
    StaleHandle(HandleId),
    /// Setup failed and rollback was attempted.
    SetupFailed {
        /// Subject whose setup transaction failed.
        subject: SubjectId,
        /// Setup phase that failed.
        step: SetupStep,
        /// Primary error text.
        primary: String,
        /// Rollback failures, if any.
        rollback: Vec<CleanupFailure>,
    },
    /// Cleanup failed; the subject remains Closing and rejects new requests.
    CleanupFailed {
        /// Subject whose cleanup remains incomplete.
        subject: SubjectId,
        /// Every cleanup phase that failed during this attempt.
        failures: Vec<CleanupFailure>,
    },
}

impl<KE: fmt::Display, RE: fmt::Display, CE: fmt::Display> fmt::Display
    for SupervisorError<KE, RE, CE>
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Caller(error) => write!(formatter, "caller resolution failed: {error}"),
            Self::Kernel(error) => {
                write!(formatter, "authority kernel rejected operation: {error}")
            }
            Self::Resource(error) => {
                write!(formatter, "runtime resource operation failed: {error}")
            }
            Self::Wire(error) => write!(formatter, "wire request rejected: {error}"),
            Self::DuplicateSubject(subject) => {
                write!(formatter, "subject `{subject}` is already supervised")
            }
            Self::UnknownSubject(subject) => {
                write!(formatter, "subject `{subject}` is not supervised")
            }
            Self::SubjectNotRunning(subject) => {
                write!(formatter, "subject `{subject}` is not running")
            }
            Self::SubjectClosing(subject) => write!(formatter, "subject `{subject}` is closing"),
            Self::SubjectClosed(subject) => write!(formatter, "subject `{subject}` is closed"),
            Self::ConnectionSubjectMismatch { requested, bound } => write!(
                formatter,
                "connection is bound to subject `{bound}`, not requested subject `{requested}`"
            ),
            Self::GrantSubjectMismatch { requested, granted } => write!(
                formatter,
                "root grant targets subject `{granted}`, not requested subject `{requested}`"
            ),
            Self::ConnectionNotBoundToSubject { subject, identity } => write!(
                formatter,
                "connection {} is not the accepted connection bound to subject `{subject}`",
                identity.socket_id()
            ),
            Self::HandleNotOwned { caller, handle } => {
                write!(
                    formatter,
                    "subject `{caller}` does not own handle `{handle}`"
                )
            }
            Self::StaleHandle(handle) => write!(formatter, "handle `{handle}` is stale or closed"),
            Self::SetupFailed {
                subject,
                step,
                primary,
                rollback,
            } => write!(
                formatter,
                "setup for subject `{subject}` failed at {step:?}: {primary}; rollback failures: {rollback:?}"
            ),
            Self::CleanupFailed { subject, failures } => write!(
                formatter,
                "cleanup for subject `{subject}` failed and remains fail-closed: {failures:?}"
            ),
        }
    }
}

impl<KE, RE, CE> Error for SupervisorError<KE, RE, CE>
where
    KE: Error + 'static,
    RE: Error + 'static,
    CE: Error + 'static,
{
}

type SupervisorResult<KE, RE, CE, T> = Result<T, SupervisorError<KE, RE, CE>>;

struct SubjectRecord {
    connection: ConnectionIdentity,
    lifecycle: SubjectLifecycle,
    authority_registered: bool,
    cgroup: Option<CgroupHandle>,
    mount: Option<MountHandle>,
    control: Option<ControlFdHandle>,
    workload: Option<WorkloadHandle>,
    /// Every runtime handle that remains open, including one awaiting
    /// authority registration.
    runtime_handles: BTreeSet<HandleId>,
    /// Handles that are live in the authority kernel.
    handles: BTreeSet<HandleId>,
}

struct SetupRollback {
    failures: Vec<CleanupFailure>,
    authority_registered: bool,
    cgroup: Option<CgroupHandle>,
    mount: Option<MountHandle>,
    control: Option<ControlFdHandle>,
    workload: Option<WorkloadHandle>,
}

/// The supervisor owning all subjects in one authority session.
pub struct Supervisor<K, R, C> {
    kernel: K,
    resources: R,
    callers: C,
    subjects: BTreeMap<SubjectId, SubjectRecord>,
    /// Session-local handle IDs are never eligible for reuse after issuance.
    issued_handles: BTreeMap<HandleId, SubjectId>,
}

impl<K, R, C> Supervisor<K, R, C>
where
    K: AuthorityKernel,
    R: RuntimeResources,
    C: CallerResolver,
{
    /// Creates an empty supervisor around an authority kernel and adapters.
    #[must_use]
    pub fn new(kernel: K, resources: R, callers: C) -> Self {
        Self {
            kernel,
            resources,
            callers,
            subjects: BTreeMap::new(),
            issued_handles: BTreeMap::new(),
        }
    }

    /// Returns the locally tracked lifecycle state for a subject.
    pub fn lifecycle(
        &self,
        subject: &SubjectId,
    ) -> SupervisorResult<K::Error, R::Error, C::Error, SubjectLifecycle> {
        self.subjects
            .get(subject)
            .map(|record| record.lifecycle)
            .ok_or_else(|| SupervisorError::UnknownSubject(subject.clone()))
    }

    /// Returns an immutable view of the resource adapter state.
    #[must_use]
    pub const fn resources(&self) -> &R {
        &self.resources
    }

    /// Returns a mutable resource-adapter view for host-side fault recovery.
    pub fn resources_mut(&mut self) -> &mut R {
        &mut self.resources
    }

    /// Creates a subject transaction and exposes it only after workload start succeeds.
    #[allow(clippy::needless_pass_by_value, clippy::too_many_lines)]
    pub fn create_subject(
        &mut self,
        subject: Subject,
        connection: ConnectionIdentity,
    ) -> SupervisorResult<K::Error, R::Error, C::Error, ()> {
        let subject_id = subject.id().clone();
        if self.subjects.contains_key(&subject_id) {
            return Err(SupervisorError::DuplicateSubject(subject_id));
        }
        let bound_subject = self
            .callers
            .resolve(&connection)
            .map_err(SupervisorError::Caller)?;
        if bound_subject != subject_id {
            return Err(SupervisorError::ConnectionSubjectMismatch {
                requested: subject_id,
                bound: bound_subject,
            });
        }
        if let Some(parent) = subject.parent() {
            match self.lifecycle(parent) {
                Ok(SubjectLifecycle::Running) => {}
                Ok(SubjectLifecycle::Creating) => {
                    return Err(SupervisorError::SubjectNotRunning(parent.clone()));
                }
                Ok(SubjectLifecycle::Closing) => {
                    return Err(SupervisorError::SubjectClosing(parent.clone()));
                }
                Ok(SubjectLifecycle::Closed) => {
                    return Err(SupervisorError::SubjectClosed(parent.clone()));
                }
                Err(SupervisorError::UnknownSubject(_)) => {
                    return Err(SupervisorError::UnknownSubject(parent.clone()));
                }
                Err(error) => return Err(error),
            }
        }

        let mut cgroup = None;
        let mut mount = None;
        let mut control = None;
        let mut workload = None;
        let mut kernel_registered = false;

        let result = (|| {
            cgroup = Some(
                self.resources
                    .create_cgroup(&subject_id)
                    .map_err(|error| (SetupStep::CreateCgroup, error.to_string()))?,
            );
            mount = Some(
                self.resources
                    .mount_capfs(&subject_id)
                    .map_err(|error| (SetupStep::Mount, error.to_string()))?,
            );
            control = Some(
                self.resources
                    .open_control_fd(&subject_id)
                    .map_err(|error| (SetupStep::OpenControlFd, error.to_string()))?,
            );
            self.kernel
                .register_subject(subject.clone())
                .map_err(|error| (SetupStep::RegisterSubject, error.to_string()))?;
            kernel_registered = true;
            workload = Some(
                self.resources
                    .start_workload(
                        &subject_id,
                        cgroup.as_ref().copied().ok_or((
                            SetupStep::StartWorkload,
                            "cgroup setup invariant was lost".to_owned(),
                        ))?,
                        mount.as_ref().copied().ok_or((
                            SetupStep::StartWorkload,
                            "mount setup invariant was lost".to_owned(),
                        ))?,
                        control.as_ref().copied().ok_or((
                            SetupStep::StartWorkload,
                            "control fd setup invariant was lost".to_owned(),
                        ))?,
                    )
                    .map_err(|error| (SetupStep::StartWorkload, error.to_string()))?,
            );
            Ok::<(), (SetupStep, String)>(())
        })();

        if let Err((step, primary)) = result {
            let rollback = self.rollback_setup(
                &subject_id,
                cgroup,
                mount,
                control,
                workload,
                kernel_registered,
            );
            if !rollback.failures.is_empty()
                || rollback.authority_registered
                || rollback.cgroup.is_some()
                || rollback.mount.is_some()
                || rollback.control.is_some()
                || rollback.workload.is_some()
            {
                self.subjects.insert(
                    subject_id.clone(),
                    SubjectRecord {
                        connection,
                        lifecycle: if rollback.authority_registered {
                            SubjectLifecycle::Closing
                        } else {
                            SubjectLifecycle::Creating
                        },
                        authority_registered: rollback.authority_registered,
                        cgroup: rollback.cgroup,
                        mount: rollback.mount,
                        control: rollback.control,
                        workload: rollback.workload,
                        runtime_handles: BTreeSet::new(),
                        handles: BTreeSet::new(),
                    },
                );
            }
            return Err(SupervisorError::SetupFailed {
                subject: subject_id,
                step,
                primary,
                rollback: rollback.failures,
            });
        }

        self.subjects.insert(
            subject_id,
            SubjectRecord {
                connection,
                lifecycle: SubjectLifecycle::Running,
                authority_registered: true,
                cgroup,
                mount,
                control,
                workload,
                runtime_handles: BTreeSet::new(),
                handles: BTreeSet::new(),
            },
        );
        Ok(())
    }

    /// Issues a root capability for a running subject's static envelope.
    pub fn issue_root(
        &self,
        subject: &SubjectId,
        grant: CapabilityGrant,
    ) -> SupervisorResult<K::Error, R::Error, C::Error, CapId> {
        self.ensure_running(subject)?;
        if grant.subject() != subject {
            return Err(SupervisorError::GrantSubjectMismatch {
                requested: subject.clone(),
                granted: grant.subject().clone(),
            });
        }
        self.kernel
            .issue_root(grant)
            .map_err(SupervisorError::Kernel)
    }

    /// Derives a capability using caller identity from the accepted connection.
    pub fn derive(
        &self,
        identity: &ConnectionIdentity,
        parent: &CapId,
        grant: CapabilityGrant,
        now: MonotonicTime,
    ) -> SupervisorResult<K::Error, R::Error, C::Error, CapId> {
        let caller = self.resolve_caller(identity)?;
        self.ensure_running(&caller)?;
        self.kernel
            .derive(&caller, parent, grant, now)
            .map_err(SupervisorError::Kernel)
    }

    /// Revokes a capability through the authority kernel.
    pub fn revoke(
        &self,
        capability: &CapId,
    ) -> SupervisorResult<K::Error, R::Error, C::Error, RevocationStatus> {
        self.kernel
            .revoke(capability)
            .map_err(SupervisorError::Kernel)
    }

    /// Opens and then registers a runtime handle for the connection caller.
    pub fn open_handle(
        &mut self,
        identity: &ConnectionIdentity,
        handle: HandleId,
        object: ObjectId,
    ) -> SupervisorResult<K::Error, R::Error, C::Error, ()> {
        let caller = self.resolve_caller(identity)?;
        self.ensure_running(&caller)?;
        if self.issued_handles.contains_key(&handle) {
            return Err(SupervisorError::StaleHandle(handle));
        }
        self.resources
            .open_handle(&caller, &handle)
            .map_err(SupervisorError::Resource)?;
        self.issued_handles.insert(handle.clone(), caller.clone());
        self.subjects
            .get_mut(&caller)
            .ok_or_else(|| SupervisorError::UnknownSubject(caller.clone()))?
            .runtime_handles
            .insert(handle.clone());
        let authority_handle = OpenHandle::new(handle.clone(), caller.clone(), object);
        if let Err(error) = self.kernel.register_open_handle(authority_handle) {
            if let Err(rollback) = self.resources.close_handle(&caller, &handle) {
                return Err(SupervisorError::SetupFailed {
                    subject: caller,
                    step: SetupStep::RegisterHandle,
                    primary: error.to_string(),
                    rollback: vec![CleanupFailure {
                        step: CleanupStep::CloseHandle,
                        message: rollback.to_string(),
                    }],
                });
            }
            self.subjects
                .get_mut(&caller)
                .ok_or_else(|| SupervisorError::UnknownSubject(caller.clone()))?
                .runtime_handles
                .remove(&handle);
            return Err(SupervisorError::Kernel(error));
        }
        self.subjects
            .get_mut(&caller)
            .ok_or_else(|| SupervisorError::UnknownSubject(caller.clone()))?
            .handles
            .insert(handle);
        Ok(())
    }

    /// Closes a handle after resolving its owner from the connection identity.
    pub fn close_handle(
        &mut self,
        identity: &ConnectionIdentity,
        handle: &HandleId,
    ) -> SupervisorResult<K::Error, R::Error, C::Error, ()> {
        let caller = self.resolve_caller(identity)?;
        self.ensure_running(&caller)?;
        let Some(open_handle) = self
            .kernel
            .open_handle(handle)
            .map_err(SupervisorError::Kernel)?
        else {
            return Err(SupervisorError::StaleHandle(handle.clone()));
        };
        if open_handle.subject() != &caller {
            return Err(SupervisorError::HandleNotOwned {
                caller,
                handle: handle.clone(),
            });
        }
        self.resources
            .close_handle(&caller, handle)
            .map_err(SupervisorError::Resource)?;
        match self
            .kernel
            .close_handle(&caller, handle)
            .map_err(SupervisorError::Kernel)?
        {
            HandleCloseStatus::Closed => {
                let record = self
                    .subjects
                    .get_mut(&caller)
                    .ok_or_else(|| SupervisorError::UnknownSubject(caller.clone()))?;
                record.runtime_handles.remove(handle);
                record.handles.remove(handle);
                Ok(())
            }
            HandleCloseStatus::AlreadyClosed => {
                let record = self
                    .subjects
                    .get_mut(&caller)
                    .ok_or_else(|| SupervisorError::UnknownSubject(caller.clone()))?;
                record.runtime_handles.remove(handle);
                record.handles.remove(handle);
                Err(SupervisorError::StaleHandle(handle.clone()))
            }
        }
    }

    /// Stops authorization and performs ordered, best-effort fail-closed cleanup.
    #[allow(clippy::too_many_lines)]
    pub fn shutdown_subject(
        &mut self,
        subject: &SubjectId,
    ) -> SupervisorResult<K::Error, R::Error, C::Error, ()> {
        let record = self
            .subjects
            .get(subject)
            .ok_or_else(|| SupervisorError::UnknownSubject(subject.clone()))?;
        if record.lifecycle == SubjectLifecycle::Closed {
            return Err(SupervisorError::SubjectClosed(subject.clone()));
        }
        let authority_registered = record.authority_registered;

        if let Some(record) = self.subjects.get_mut(subject) {
            record.lifecycle = SubjectLifecycle::Closing;
        }
        if authority_registered {
            match self
                .kernel
                .begin_subject_close(subject)
                .map_err(SupervisorError::Kernel)?
            {
                SubjectCloseStatus::Started
                | SubjectCloseStatus::AlreadyClosing
                | SubjectCloseStatus::AlreadyClosed => {}
            }
        }
        let (cgroup, mount, control, workload, runtime_handles) = {
            let record = self
                .subjects
                .get(subject)
                .ok_or_else(|| SupervisorError::UnknownSubject(subject.clone()))?;
            (
                record.cgroup,
                record.mount,
                record.control,
                record.workload,
                record.runtime_handles.iter().cloned().collect::<Vec<_>>(),
            )
        };
        let mut failures = Vec::new();
        let mut workload_stopped = workload.is_none();
        let mut control_closed = control.is_none();
        let mut mount_unmounted = mount.is_none();

        if let Some(workload) = workload {
            match cgroup {
                Some(cgroup) => match self.resources.stop_workload(workload, cgroup) {
                    Ok(()) => {
                        self.subjects
                            .get_mut(subject)
                            .ok_or_else(|| SupervisorError::UnknownSubject(subject.clone()))?
                            .workload = None;
                        workload_stopped = true;
                    }
                    Err(error) => failures.push(CleanupFailure {
                        step: CleanupStep::StopWorkload,
                        message: error.to_string(),
                    }),
                },
                None => failures.push(CleanupFailure {
                    step: CleanupStep::StopWorkload,
                    message: "workload token exists without its cgroup token".to_owned(),
                }),
            }
        }

        if let Some(control) = control {
            match self.resources.close_control_fd(control) {
                Ok(()) => {
                    self.subjects
                        .get_mut(subject)
                        .ok_or_else(|| SupervisorError::UnknownSubject(subject.clone()))?
                        .control = None;
                    control_closed = true;
                }
                Err(error) => failures.push(CleanupFailure {
                    step: CleanupStep::CloseControlFd,
                    message: error.to_string(),
                }),
            }
        }

        for handle in runtime_handles {
            let close_result = self.resources.close_handle(subject, &handle);
            if let Err(error) = close_result {
                failures.push(CleanupFailure {
                    step: CleanupStep::CloseHandle,
                    message: error.to_string(),
                });
                continue;
            }
            let authority_handle = self
                .subjects
                .get(subject)
                .ok_or_else(|| SupervisorError::UnknownSubject(subject.clone()))?
                .handles
                .contains(&handle);
            if authority_handle {
                match self.kernel.close_handle(subject, &handle) {
                    Ok(HandleCloseStatus::Closed | HandleCloseStatus::AlreadyClosed) => {
                        let record = self
                            .subjects
                            .get_mut(subject)
                            .ok_or_else(|| SupervisorError::UnknownSubject(subject.clone()))?;
                        record.runtime_handles.remove(&handle);
                        record.handles.remove(&handle);
                    }
                    Err(error) => failures.push(CleanupFailure {
                        step: CleanupStep::CloseHandle,
                        message: error.to_string(),
                    }),
                }
            } else {
                self.subjects
                    .get_mut(subject)
                    .ok_or_else(|| SupervisorError::UnknownSubject(subject.clone()))?
                    .runtime_handles
                    .remove(&handle);
            }
        }
        let handles_closed = self
            .subjects
            .get(subject)
            .ok_or_else(|| SupervisorError::UnknownSubject(subject.clone()))?
            .runtime_handles
            .is_empty();

        if let Some(mount) = mount
            && workload_stopped
            && control_closed
            && handles_closed
        {
            match self.resources.unmount_capfs(mount) {
                Ok(()) => {
                    self.subjects
                        .get_mut(subject)
                        .ok_or_else(|| SupervisorError::UnknownSubject(subject.clone()))?
                        .mount = None;
                    mount_unmounted = true;
                }
                Err(error) => failures.push(CleanupFailure {
                    step: CleanupStep::Unmount,
                    message: error.to_string(),
                }),
            }
        }

        if let Some(cgroup) = cgroup
            && workload_stopped
            && mount_unmounted
        {
            match self.resources.remove_cgroup(cgroup) {
                Ok(()) => {
                    self.subjects
                        .get_mut(subject)
                        .ok_or_else(|| SupervisorError::UnknownSubject(subject.clone()))?
                        .cgroup = None;
                }
                Err(error) => failures.push(CleanupFailure {
                    step: CleanupStep::RemoveCgroup,
                    message: error.to_string(),
                }),
            }
        }

        if failures.is_empty() {
            if authority_registered {
                match self.kernel.finish_subject_close(subject) {
                    Ok(SubjectFinishStatus::Closed | SubjectFinishStatus::AlreadyClosed) => {
                        let record = self
                            .subjects
                            .get_mut(subject)
                            .ok_or_else(|| SupervisorError::UnknownSubject(subject.clone()))?;
                        record.lifecycle = SubjectLifecycle::Closed;
                        record.authority_registered = false;
                        return Ok(());
                    }
                    Err(error) => failures.push(CleanupFailure {
                        step: CleanupStep::FinishClose,
                        message: error.to_string(),
                    }),
                }
            } else {
                let record = self
                    .subjects
                    .get_mut(subject)
                    .ok_or_else(|| SupervisorError::UnknownSubject(subject.clone()))?;
                record.lifecycle = SubjectLifecycle::Closed;
                return Ok(());
            }
        }

        Err(SupervisorError::CleanupFailed {
            subject: subject.clone(),
            failures,
        })
    }

    /// Decodes and dispatches a request using only the accepted connection identity.
    pub fn dispatch_wire(
        &mut self,
        identity: &ConnectionIdentity,
        bytes: &[u8],
    ) -> SupervisorResult<K::Error, R::Error, C::Error, DispatchResponse> {
        let request = WireRequest::decode(bytes).map_err(SupervisorError::Wire)?;
        match request {
            WireRequest::CloseSubject { claimed_subject: _ } => {
                let caller = self.resolve_caller(identity)?;
                self.ensure_running(&caller)?;
                self.shutdown_subject(&caller)?;
                Ok(DispatchResponse::SubjectClosed)
            }
            WireRequest::CloseHandle {
                claimed_subject: _,
                handle,
            } => {
                self.close_handle(identity, &handle)?;
                Ok(DispatchResponse::HandleClosed)
            }
        }
    }

    fn resolve_caller(
        &self,
        identity: &ConnectionIdentity,
    ) -> SupervisorResult<K::Error, R::Error, C::Error, SubjectId> {
        let caller = self
            .callers
            .resolve(identity)
            .map_err(SupervisorError::Caller)?;
        if self
            .subjects
            .get(&caller)
            .is_some_and(|record| record.connection != *identity)
        {
            return Err(SupervisorError::ConnectionNotBoundToSubject {
                subject: caller,
                identity: *identity,
            });
        }
        Ok(caller)
    }

    fn ensure_running(
        &self,
        subject: &SubjectId,
    ) -> SupervisorResult<K::Error, R::Error, C::Error, ()> {
        match self.lifecycle(subject)? {
            SubjectLifecycle::Running => Ok(()),
            SubjectLifecycle::Creating => Err(SupervisorError::SubjectNotRunning(subject.clone())),
            SubjectLifecycle::Closing => Err(SupervisorError::SubjectClosing(subject.clone())),
            SubjectLifecycle::Closed => Err(SupervisorError::SubjectClosed(subject.clone())),
        }
    }

    #[allow(clippy::too_many_lines)]
    fn rollback_setup(
        &mut self,
        subject: &SubjectId,
        cgroup: Option<CgroupHandle>,
        mount: Option<MountHandle>,
        control: Option<ControlFdHandle>,
        workload: Option<WorkloadHandle>,
        kernel_registered: bool,
    ) -> SetupRollback {
        let mut failures = Vec::new();
        let mut authority_registered = kernel_registered;
        let mut close_started = !kernel_registered;
        if kernel_registered {
            match self.kernel.begin_subject_close(subject) {
                Ok(
                    SubjectCloseStatus::Started
                    | SubjectCloseStatus::AlreadyClosing
                    | SubjectCloseStatus::AlreadyClosed,
                ) => {
                    close_started = true;
                }
                Err(error) => failures.push(CleanupFailure {
                    step: CleanupStep::BeginClose,
                    message: error.to_string(),
                }),
            }
        }

        let mut cgroup = cgroup;
        let mut mount = mount;
        let mut control = control;
        let mut workload = workload;
        let mut workload_stopped = workload.is_none();
        let mut control_closed = control.is_none();
        let mut mount_unmounted = mount.is_none();

        if let Some(workload_token) = workload {
            match cgroup {
                Some(cgroup_token) => {
                    match self.resources.stop_workload(workload_token, cgroup_token) {
                        Ok(()) => {
                            workload = None;
                            workload_stopped = true;
                        }
                        Err(error) => failures.push(CleanupFailure {
                            step: CleanupStep::StopWorkload,
                            message: error.to_string(),
                        }),
                    }
                }
                None => failures.push(CleanupFailure {
                    step: CleanupStep::StopWorkload,
                    message: "workload token exists without its cgroup token".to_owned(),
                }),
            }
        }

        if let Some(control_token) = control {
            match self.resources.close_control_fd(control_token) {
                Ok(()) => {
                    control = None;
                    control_closed = true;
                }
                Err(error) => failures.push(CleanupFailure {
                    step: CleanupStep::CloseControlFd,
                    message: error.to_string(),
                }),
            }
        }

        if let Some(mount_token) = mount
            && workload_stopped
            && control_closed
        {
            match self.resources.unmount_capfs(mount_token) {
                Ok(()) => {
                    mount = None;
                    mount_unmounted = true;
                }
                Err(error) => failures.push(CleanupFailure {
                    step: CleanupStep::Unmount,
                    message: error.to_string(),
                }),
            }
        }

        if let Some(cgroup_token) = cgroup
            && workload_stopped
            && mount_unmounted
        {
            match self.resources.remove_cgroup(cgroup_token) {
                Ok(()) => cgroup = None,
                Err(error) => failures.push(CleanupFailure {
                    step: CleanupStep::RemoveCgroup,
                    message: error.to_string(),
                }),
            }
        }

        if kernel_registered && close_started && failures.is_empty() {
            match self.kernel.finish_subject_close(subject) {
                Ok(SubjectFinishStatus::Closed | SubjectFinishStatus::AlreadyClosed) => {
                    authority_registered = false;
                }
                Err(error) => failures.push(CleanupFailure {
                    step: CleanupStep::FinishClose,
                    message: error.to_string(),
                }),
            }
        }

        SetupRollback {
            failures,
            authority_registered,
            cgroup,
            mount,
            control,
            workload,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{ConnectionIdentity, StaticCallerResolver};
    use authority_core::capability::SubjectId;

    #[test]
    fn static_caller_binding_rejects_rebinding() {
        let identity = ConnectionIdentity::new(7, 42, 1000, 1000);
        let mut resolver = StaticCallerResolver::new();
        resolver
            .bind(identity, SubjectId::new("subject-a"))
            .expect("first binding must succeed");
        assert_eq!(
            resolver.bind(identity, SubjectId::new("subject-b")),
            Err(SubjectId::new("subject-b"))
        );
    }
}
