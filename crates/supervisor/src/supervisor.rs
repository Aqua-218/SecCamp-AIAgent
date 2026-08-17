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
        AuthorizationEpoch, CapabilityGrant, HandleCloseStatus, RevocationStatus, Subject,
        SubjectCloseStatus, SubjectFinishStatus, SubjectStatus,
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

/// Typed result of an operation that acquires an externally owned resource.
///
/// Adapters must not collapse a partial effect into an ordinary error. The
/// supervisor can only retry cleanup when it knows whether ownership exists
/// and, for token-addressed resources, which token identifies it.
#[derive(Debug)]
pub enum ResourceAcquisition<T, E> {
    /// The operation completed and transferred ownership to the supervisor.
    Acquired(T),
    /// The operation failed before producing any externally visible effect.
    NoEffect(E),
    /// The operation failed after producing a resource that must be cleaned up.
    CleanupRequired {
        /// Resource ownership transferred despite the reported failure.
        resource: T,
        /// Adapter failure that accompanied the partial effect.
        error: E,
    },
    /// The adapter cannot determine whether an effect occurred.
    EffectUnknown(E),
}

/// Typed result of a resource mutation whose target identity is already known.
#[derive(Debug)]
pub enum ResourceMutation<E> {
    /// The requested mutation completed.
    Applied,
    /// The operation failed before changing the target.
    NoEffect(E),
    /// The operation failed and the target still requires cleanup.
    CleanupRequired(E),
    /// The adapter cannot determine whether the mutation took effect.
    EffectUnknown(E),
}

/// Resource operations required by the supervisor lifecycle.
///
/// # Implementation contract
///
/// Resource tokens must remain stable and must not be reused for another
/// resource while this supervisor can retain or retry them. Every cleanup
/// mutation (`remove_cgroup`, `unmount_capfs`, `close_control_fd`,
/// `stop_workload`, and `close_handle`) must be idempotent for its token: if a
/// prior call may already have completed, repeating the call must not affect a
/// replacement resource, and an already-absent target must be reported as
/// [`ResourceMutation::Applied`]. Implementations must classify effects
/// honestly; in particular, [`ResourceMutation::NoEffect`] must mean the
/// target still exists unchanged and [`ResourceMutation::EffectUnknown`] must
/// be used when completion cannot be determined.
///
/// Violating this contract can make failure recovery repeat an effect against
/// the wrong OS resource. Implementations are therefore part of the trusted
/// host boundary and must be reviewed together with their token allocator.
pub trait RuntimeResources {
    /// Resource-adapter failure type.
    type Error: Error + Send + Sync + 'static;

    /// Allocates the workload cgroup before any child can run.
    fn create_cgroup(
        &mut self,
        subject: &SubjectId,
    ) -> ResourceAcquisition<CgroupHandle, Self::Error>;

    /// Removes a cgroup after its workload and mount are stopped.
    fn remove_cgroup(&mut self, cgroup: CgroupHandle) -> ResourceMutation<Self::Error>;

    /// Mounts the subject's capability filesystem.
    fn mount_capfs(&mut self, subject: &SubjectId)
    -> ResourceAcquisition<MountHandle, Self::Error>;

    /// Unmounts the subject's capability filesystem.
    fn unmount_capfs(&mut self, mount: MountHandle) -> ResourceMutation<Self::Error>;

    /// Opens the subject's private control descriptor.
    fn open_control_fd(
        &mut self,
        subject: &SubjectId,
    ) -> ResourceAcquisition<ControlFdHandle, Self::Error>;

    /// Closes the subject's private control descriptor.
    fn close_control_fd(&mut self, control: ControlFdHandle) -> ResourceMutation<Self::Error>;

    /// Starts the workload after authority registration has completed.
    fn start_workload(
        &mut self,
        subject: &SubjectId,
        cgroup: CgroupHandle,
        mount: MountHandle,
        control: ControlFdHandle,
    ) -> ResourceAcquisition<WorkloadHandle, Self::Error>;

    /// Stops the workload before descriptors, handles, or mounts are closed.
    fn stop_workload(
        &mut self,
        workload: WorkloadHandle,
        cgroup: CgroupHandle,
    ) -> ResourceMutation<Self::Error>;

    /// Opens a runtime handle before it is registered with the authority kernel.
    fn open_handle(
        &mut self,
        subject: &SubjectId,
        handle: &HandleId,
    ) -> ResourceMutation<Self::Error>;

    /// Closes a runtime handle under the trait-wide idempotent cleanup contract.
    fn close_handle(
        &mut self,
        subject: &SubjectId,
        handle: &HandleId,
    ) -> ResourceMutation<Self::Error>;
}

/// The authority-kernel surface used by the supervisor.
pub trait AuthorityKernel {
    /// Kernel failure type.
    type Error: Error + Send + Sync + 'static;

    /// Returns whether no session authority or identity has been issued.
    ///
    /// Supervisor construction requires a pristine kernel because an empty
    /// local ownership ledger cannot safely adopt pre-existing kernel state.
    fn is_pristine(&self) -> Result<bool, Self::Error>;

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

    /// Revokes a capability held by the transport-authenticated caller and all
    /// authority derived from it.
    fn revoke(
        &self,
        caller: &SubjectId,
        capability: &CapId,
    ) -> Result<RevocationStatus, Self::Error>;

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

    /// Captures the authority state that must remain valid while a newly registered subject's
    /// external workload crosses its start boundary.
    ///
    /// Implementations that can be shared with another authority caller should override this
    /// method. The default keeps compatibility with small adapters that have no lifecycle
    /// inspection surface; production kernels return the subject status and authorization epoch
    /// so a concurrent close or revocation fails closed before setup is published.
    fn startup_snapshot(
        &self,
        _subject: &SubjectId,
    ) -> Result<Option<AuthorityStartupSnapshot>, Self::Error> {
        Ok(None)
    }
}

/// Authority state observed around the register-to-workload-start boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthorityStartupSnapshot {
    /// Lifecycle state of the subject at the observation point.
    pub status: SubjectStatus,
    /// Authorization epoch used to detect a revocation during startup.
    pub authorization_epoch: AuthorizationEpoch,
}

impl AuthorityKernel for CapabilityKernel {
    type Error = authority_core::kernel::CapabilityKernelError;

    fn is_pristine(&self) -> Result<bool, Self::Error> {
        CapabilityKernel::is_pristine(self)
    }

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

    fn revoke(
        &self,
        caller: &SubjectId,
        capability: &CapId,
    ) -> Result<RevocationStatus, Self::Error> {
        CapabilityKernel::revoke_held_by(self, caller, capability)
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

    fn startup_snapshot(
        &self,
        subject: &SubjectId,
    ) -> Result<Option<AuthorityStartupSnapshot>, Self::Error> {
        Ok(Some(AuthorityStartupSnapshot {
            status: CapabilityKernel::subject_status(self, subject)?.ok_or_else(|| {
                authority_core::kernel::CapabilityKernelError::StateTransition(
                    authority_core::state::CapabilityStateError::UnknownSubject(subject.clone()),
                )
            })?,
            authorization_epoch: CapabilityKernel::authorization_epoch(self)?,
        }))
    }
}

/// Registry whose identities remain reserved for the lifetime of one supervisor session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SupervisorCapacity {
    /// Subject identities, including identities from cleanly rolled-back setup attempts.
    Subjects,
    /// Runtime handle identities, including identities whose open operation had no effect.
    IssuedHandles,
}

impl fmt::Display for SupervisorCapacity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Subjects => "subjects",
            Self::IssuedHandles => "issued handles",
        })
    }
}

/// Validation failure for an explicit supervisor registry bound.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SupervisorLimitsError {
    /// A registry bound of zero cannot admit even the first identity.
    Zero(SupervisorCapacity),
}

impl fmt::Display for SupervisorLimitsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Zero(capacity) => write!(formatter, "{capacity} capacity must be non-zero"),
        }
    }
}

impl Error for SupervisorLimitsError {}

/// Explicit bounds for the supervisor's permanent identity registries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SupervisorLimits {
    max_subjects: usize,
    max_issued_handles: usize,
}

/// Safe default bound for permanent subject identities in one session.
pub const DEFAULT_MAX_SUBJECTS: usize = 1_024;
/// Safe default bound for permanent runtime-handle identities in one session.
pub const DEFAULT_MAX_ISSUED_HANDLES: usize = 65_536;

impl Default for SupervisorLimits {
    fn default() -> Self {
        Self {
            max_subjects: DEFAULT_MAX_SUBJECTS,
            max_issued_handles: DEFAULT_MAX_ISSUED_HANDLES,
        }
    }
}

impl SupervisorLimits {
    /// Creates explicit permanent registry bounds.
    #[must_use]
    pub const fn new(max_subjects: usize, max_issued_handles: usize) -> Self {
        Self {
            max_subjects,
            max_issued_handles,
        }
    }

    /// Returns the maximum number of permanently reserved subject identities.
    #[must_use]
    pub const fn max_subjects(self) -> usize {
        self.max_subjects
    }

    /// Returns the maximum number of permanently reserved handle identities.
    #[must_use]
    pub const fn max_issued_handles(self) -> usize {
        self.max_issued_handles
    }

    fn validate(self) -> Result<(), SupervisorLimitsError> {
        if self.max_subjects == 0 {
            return Err(SupervisorLimitsError::Zero(SupervisorCapacity::Subjects));
        }
        if self.max_issued_handles == 0 {
            return Err(SupervisorLimitsError::Zero(
                SupervisorCapacity::IssuedHandles,
            ));
        }
        Ok(())
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

/// Effect classification retained with a resource-adapter error.
#[derive(Debug)]
pub enum ResourceFailure<E> {
    /// The adapter guarantees that the failed call had no effect.
    NoEffect(E),
    /// A resource is known to remain owned and cleanup must be retried.
    CleanupRequired(E),
    /// The adapter cannot determine whether the call had an effect.
    EffectUnknown(E),
}

/// Typed cause of a setup or cleanup failure.
#[derive(Debug)]
pub enum OperationFailure<KE, RE> {
    /// The authority kernel rejected the transition.
    Kernel(KE),
    /// The runtime adapter reported a classified resource failure.
    Resource(ResourceFailure<RE>),
    /// A prior unknown acquisition effect cannot be addressed by a token.
    UnresolvedEffect,
    /// Internal ownership bookkeeping violated a required invariant.
    Invariant(&'static str),
}

/// A failure retained while attempting all safe cleanup phases.
#[derive(Debug)]
pub struct CleanupFailure<KE, RE> {
    /// Phase that failed.
    pub step: CleanupStep,
    /// Typed error and effect classification for retry policy.
    pub cause: OperationFailure<KE, RE>,
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
    /// Runtime handle open failed after its identity was issued.
    OpenHandle,
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

impl From<DispatchResponse> for crate::protocol::WireResponse {
    fn from(response: DispatchResponse) -> Self {
        match response {
            DispatchResponse::SubjectClosed => Self::SubjectClosed,
            DispatchResponse::HandleClosed => Self::HandleClosed,
        }
    }
}

impl<KE, RE, CE> SupervisorError<KE, RE, CE> {
    /// Returns the coarse refusal a guest may be told about this failure.
    ///
    /// Every authorization and lifecycle failure maps to the same code on purpose. A guest that
    /// could tell "not yours" from "does not exist" could enumerate another subject's handles one
    /// refusal at a time. The distinguishing detail stays on the host.
    #[must_use]
    pub const fn refusal(&self) -> crate::protocol::RefusalCode {
        use crate::protocol::RefusalCode;
        match self {
            Self::Wire(_) => RefusalCode::Malformed,
            Self::Resource(_)
            | Self::SetupFailed { .. }
            | Self::CleanupFailed { .. }
            | Self::CleanupBlocked { .. }
            | Self::InvalidLimits(_)
            | Self::CapacityExceeded(_) => RefusalCode::Unavailable,
            Self::Caller(_)
            | Self::Kernel(_)
            | Self::DuplicateSubject(_)
            | Self::KernelNotPristine
            | Self::UnknownSubject(_)
            | Self::SubjectNotRunning(_)
            | Self::SubjectClosing(_)
            | Self::SubjectClosed(_)
            | Self::ConnectionSubjectMismatch { .. }
            | Self::GrantSubjectMismatch { .. }
            | Self::ConnectionNotBoundToSubject { .. }
            | Self::HandleNotOwned { .. }
            | Self::StaleHandle(_) => RefusalCode::NotPermitted,
        }
    }
}

/// Errors returned by supervisor orchestration.
#[derive(Debug)]
pub enum SupervisorError<KE, RE, CE> {
    /// The transport identity could not be mapped to a subject.
    Caller(CE),
    /// The authority kernel rejected a transition.
    Kernel(KE),
    /// The runtime resource adapter rejected an operation.
    Resource(ResourceFailure<RE>),
    /// The wire request failed closed decoding.
    Wire(WireDecodeError),
    /// A subject identity is already owned by this supervisor.
    DuplicateSubject(SubjectId),
    /// The supplied authority kernel already contains session state.
    KernelNotPristine,
    /// The configured permanent registry bounds are invalid.
    InvalidLimits(SupervisorLimitsError),
    /// The configured permanent registry has no remaining identity capacity.
    CapacityExceeded(SupervisorCapacity),
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
        /// Primary typed failure.
        primary: OperationFailure<KE, RE>,
        /// Rollback failures, if any.
        rollback: Vec<CleanupFailure<KE, RE>>,
    },
    /// Cleanup failed; the subject remains Closing and rejects new requests.
    CleanupFailed {
        /// Subject whose cleanup remains incomplete.
        subject: SubjectId,
        /// Every cleanup phase that failed during this attempt.
        failures: Vec<CleanupFailure<KE, RE>>,
    },
    /// Cleanup cannot be retried because an acquisition may have taken effect
    /// without returning the token required to address that resource.
    CleanupBlocked {
        /// Subject whose ownership remains unresolved.
        subject: SubjectId,
        /// Fail-stop phases, including every unaddressable effect.
        failures: Vec<CleanupFailure<KE, RE>>,
    },
}

impl<KE: fmt::Display + fmt::Debug, RE: fmt::Display + fmt::Debug, CE: fmt::Display> fmt::Display
    for SupervisorError<KE, RE, CE>
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Caller(error) => write!(formatter, "caller resolution failed: {error}"),
            Self::Kernel(error) => {
                write!(formatter, "authority kernel rejected operation: {error}")
            }
            Self::Resource(failure) => write_resource_failure(formatter, failure),
            Self::Wire(error) => write!(formatter, "wire request rejected: {error}"),
            Self::DuplicateSubject(subject) => {
                write!(formatter, "subject `{subject}` is already supervised")
            }
            Self::KernelNotPristine => formatter.write_str(
                "authority kernel is not pristine and cannot be paired with an empty ownership ledger",
            ),
            Self::InvalidLimits(error) => write!(formatter, "invalid supervisor limits: {error}"),
            Self::CapacityExceeded(capacity) => {
                write!(formatter, "supervisor {capacity} capacity is exhausted")
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
                "setup for subject `{subject}` failed at {step:?}: {primary:?}; rollback failures: {rollback:?}"
            ),
            Self::CleanupFailed { subject, failures } => write!(
                formatter,
                "cleanup for subject `{subject}` failed and remains fail-closed: {failures:?}"
            ),
            Self::CleanupBlocked { subject, failures } => write!(
                formatter,
                "cleanup for subject `{subject}` is permanently fail-stopped by an unaddressable effect: {failures:?}"
            ),
        }
    }
}

fn write_resource_failure<E: fmt::Display>(
    formatter: &mut fmt::Formatter<'_>,
    failure: &ResourceFailure<E>,
) -> fmt::Result {
    match failure {
        ResourceFailure::NoEffect(error) => {
            write!(
                formatter,
                "runtime resource operation had no effect: {error}"
            )
        }
        ResourceFailure::CleanupRequired(error) => write!(
            formatter,
            "runtime resource operation requires cleanup: {error}"
        ),
        ResourceFailure::EffectUnknown(error) => write!(
            formatter,
            "runtime resource operation has an unknown effect: {error}"
        ),
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
type CleanupFailures<KE, RE> = Vec<CleanupFailure<KE, RE>>;
type RollbackHandleResult<KE, RE, CE> = SupervisorResult<KE, RE, CE, CleanupFailures<KE, RE>>;

#[derive(Debug, Clone, Copy)]
enum ResourceOwnership<T> {
    Owned(T),
    EffectUnknown,
}

impl<T: Copy> ResourceOwnership<T> {
    const fn token(self) -> Option<T> {
        match self {
            Self::Owned(token) => Some(token),
            Self::EffectUnknown => None,
        }
    }
}

struct SubjectRecord {
    connection: ConnectionIdentity,
    lifecycle: SubjectLifecycle,
    authority_registered: bool,
    cgroup: Option<ResourceOwnership<CgroupHandle>>,
    mount: Option<ResourceOwnership<MountHandle>>,
    control: Option<ResourceOwnership<ControlFdHandle>>,
    workload: Option<ResourceOwnership<WorkloadHandle>>,
    /// Every runtime handle that remains open, including one awaiting
    /// authority registration.
    runtime_handles: BTreeSet<HandleId>,
    /// Handles that are live in the authority kernel.
    handles: BTreeSet<HandleId>,
}

struct SetupRollback<KE, RE> {
    failures: Vec<CleanupFailure<KE, RE>>,
    authority_registered: bool,
    cgroup: Option<ResourceOwnership<CgroupHandle>>,
    mount: Option<ResourceOwnership<MountHandle>>,
    control: Option<ResourceOwnership<ControlFdHandle>>,
    workload: Option<ResourceOwnership<WorkloadHandle>>,
}

/// The supervisor owning all subjects in one authority session.
pub struct Supervisor<K, R, C> {
    kernel: K,
    resources: R,
    callers: C,
    limits: SupervisorLimits,
    subjects: BTreeMap<SubjectId, SubjectRecord>,
    /// Subject IDs remain reserved after every setup attempt that reached an
    /// effectful phase, even when rollback releases every resource.
    issued_subjects: BTreeSet<SubjectId>,
    /// Session-local handle IDs are never eligible for reuse after issuance.
    issued_handles: BTreeMap<HandleId, SubjectId>,
}

impl<K, R, C> Supervisor<K, R, C>
where
    K: AuthorityKernel,
    R: RuntimeResources,
    C: CallerResolver,
{
    /// Creates an empty supervisor around a pristine authority kernel.
    ///
    /// # Errors
    ///
    /// Returns [`SupervisorError::KernelNotPristine`] when the kernel already
    /// owns session state, or [`SupervisorError::Kernel`] when its state cannot
    /// be inspected. A pre-populated kernel requires a durable ownership
    /// manifest and must not be paired with this empty-ledger constructor.
    pub fn new(
        kernel: K,
        resources: R,
        callers: C,
    ) -> SupervisorResult<K::Error, R::Error, C::Error, Self> {
        Self::new_with_limits(kernel, resources, callers, SupervisorLimits::default())
    }

    /// Creates an empty supervisor with explicit permanent identity bounds.
    ///
    /// A bound is validated before the kernel is inspected. The registry never evicts closed
    /// subjects or issued handles, so exhaustion is permanent for the lifetime of this session.
    pub fn new_with_limits(
        kernel: K,
        resources: R,
        callers: C,
        limits: SupervisorLimits,
    ) -> SupervisorResult<K::Error, R::Error, C::Error, Self> {
        limits.validate().map_err(SupervisorError::InvalidLimits)?;
        if !kernel.is_pristine().map_err(SupervisorError::Kernel)? {
            return Err(SupervisorError::KernelNotPristine);
        }
        Ok(Self {
            kernel,
            resources,
            callers,
            limits,
            subjects: BTreeMap::new(),
            issued_subjects: BTreeSet::new(),
            issued_handles: BTreeMap::new(),
        })
    }

    /// Returns the immutable registry bounds selected for this session.
    #[must_use]
    pub const fn limits(&self) -> SupervisorLimits {
        self.limits
    }

    /// Returns the number of subject identities permanently reserved in this session.
    #[must_use]
    pub fn issued_subject_count(&self) -> usize {
        self.issued_subjects.len()
    }

    /// Returns the number of runtime-handle identities permanently reserved in this session.
    #[must_use]
    pub fn issued_handle_count(&self) -> usize {
        self.issued_handles.len()
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

    /// Temporarily borrows the resource and caller-identity adapters together.
    ///
    /// A production transport must bind an accepted connection in `callers` before exposing its
    /// bytes to [`Self::dispatch_wire`]. Keeping both mutable borrows inside one closure lets the
    /// host adapter accept the connection and register that binding without exposing either
    /// partially-updated adapter to unrelated supervisor operations.
    pub fn with_resources_and_callers<T>(
        &mut self,
        operation: impl FnOnce(&mut R, &mut C) -> T,
    ) -> T {
        operation(&mut self.resources, &mut self.callers)
    }

    /// Replaces a bootstrap channel with one freshly accepted subject channel.
    ///
    /// The caller must arrange for `identity` to be bound by the transport before invoking this
    /// method. This is used exactly once after the fixed workload has crossed its isolation
    /// boundary: its preconnected control descriptor is accepted by the supervisor and supersedes
    /// the short-lived bootstrap connection that authorized setup. Any request on the old channel
    /// then fails the record's exact connection comparison in [`Self::dispatch_wire`].
    pub fn bind_accepted_connection(
        &mut self,
        identity: ConnectionIdentity,
    ) -> SupervisorResult<K::Error, R::Error, C::Error, SubjectId> {
        let subject = self
            .callers
            .resolve(&identity)
            .map_err(SupervisorError::Caller)?;
        self.ensure_running(&subject)?;
        let record = self
            .subjects
            .get_mut(&subject)
            .ok_or_else(|| SupervisorError::UnknownSubject(subject.clone()))?;
        record.connection = identity;
        Ok(subject)
    }

    /// Creates a subject transaction and exposes it only after workload start succeeds.
    #[allow(clippy::needless_pass_by_value, clippy::too_many_lines)]
    pub fn create_subject(
        &mut self,
        subject: Subject,
        connection: ConnectionIdentity,
    ) -> SupervisorResult<K::Error, R::Error, C::Error, ()> {
        let subject_id = subject.id().clone();
        if self.issued_subjects.contains(&subject_id) {
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
        if self.issued_subjects.len() >= self.limits.max_subjects {
            return Err(SupervisorError::CapacityExceeded(
                SupervisorCapacity::Subjects,
            ));
        }

        // Reserve before the first adapter call. A delayed completion from any
        // later setup phase must never be rebound to a fresh local subject.
        self.issued_subjects.insert(subject_id.clone());

        let mut cgroup = None;
        let mut mount = None;
        let mut control = None;
        let mut workload = None;
        let mut kernel_registered = false;

        let result = (|| {
            Self::record_acquisition(self.resources.create_cgroup(&subject_id), &mut cgroup)
                .map_err(|failure| (SetupStep::CreateCgroup, failure))?;
            Self::record_acquisition(self.resources.mount_capfs(&subject_id), &mut mount)
                .map_err(|failure| (SetupStep::Mount, failure))?;
            Self::record_acquisition(self.resources.open_control_fd(&subject_id), &mut control)
                .map_err(|failure| (SetupStep::OpenControlFd, failure))?;
            self.kernel
                .register_subject(subject.clone())
                .map_err(|error| (SetupStep::RegisterSubject, OperationFailure::Kernel(error)))?;
            kernel_registered = true;
            let startup_snapshot = self
                .kernel
                .startup_snapshot(&subject_id)
                .map_err(|error| (SetupStep::StartWorkload, OperationFailure::Kernel(error)))?;
            if startup_snapshot.is_some_and(|snapshot| snapshot.status != SubjectStatus::Running) {
                return Err((
                    SetupStep::StartWorkload,
                    OperationFailure::Invariant("authority subject changed before workload start"),
                ));
            }
            let cgroup_token = cgroup.and_then(ResourceOwnership::token).ok_or((
                SetupStep::StartWorkload,
                OperationFailure::Invariant("cgroup setup ownership is unresolved"),
            ))?;
            let mount_token = mount.and_then(ResourceOwnership::token).ok_or((
                SetupStep::StartWorkload,
                OperationFailure::Invariant("mount setup ownership is unresolved"),
            ))?;
            let control_token = control.and_then(ResourceOwnership::token).ok_or((
                SetupStep::StartWorkload,
                OperationFailure::Invariant("control fd setup ownership is unresolved"),
            ))?;
            Self::record_acquisition(
                self.resources.start_workload(
                    &subject_id,
                    cgroup_token,
                    mount_token,
                    control_token,
                ),
                &mut workload,
            )
            .map_err(|failure| (SetupStep::StartWorkload, failure))?;
            if let Some(expected) = startup_snapshot {
                let observed = self
                    .kernel
                    .startup_snapshot(&subject_id)
                    .map_err(|error| (SetupStep::StartWorkload, OperationFailure::Kernel(error)))?;
                if observed != Some(expected) {
                    return Err((
                        SetupStep::StartWorkload,
                        OperationFailure::Invariant(
                            "authority subject changed during workload start",
                        ),
                    ));
                }
            }
            Ok::<(), (SetupStep, OperationFailure<K::Error, R::Error>)>(())
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

    /// Revokes a capability on behalf of an accepted connection.
    ///
    /// Takes the same connection identity and lifecycle gate as every other
    /// authority operation. Without them, any holder of a `&Supervisor` could
    /// revoke any `CapId` in the session, and adding a third wire tag would
    /// hand that primitive to every connected subject.
    pub fn revoke(
        &self,
        identity: &ConnectionIdentity,
        capability: &CapId,
    ) -> SupervisorResult<K::Error, R::Error, C::Error, RevocationStatus> {
        let caller = self.resolve_caller(identity)?;
        self.ensure_running(&caller)?;
        self.kernel
            .revoke(&caller, capability)
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
        if self.issued_handles.len() >= self.limits.max_issued_handles {
            return Err(SupervisorError::CapacityExceeded(
                SupervisorCapacity::IssuedHandles,
            ));
        }
        // The adapter has observed this ID after this point, so even a
        // guaranteed no-effect failure consumes its session-local identity.
        self.issued_handles.insert(handle.clone(), caller.clone());
        match self.resources.open_handle(&caller, &handle) {
            ResourceMutation::Applied => {
                self.track_runtime_handle(&caller, &handle)?;
            }
            ResourceMutation::NoEffect(error) => {
                return Err(SupervisorError::Resource(ResourceFailure::NoEffect(error)));
            }
            ResourceMutation::CleanupRequired(error) => {
                self.track_runtime_handle(&caller, &handle)?;
                let rollback = self.rollback_runtime_handle(&caller, &handle)?;
                return Err(SupervisorError::SetupFailed {
                    subject: caller,
                    step: SetupStep::OpenHandle,
                    primary: OperationFailure::Resource(ResourceFailure::CleanupRequired(error)),
                    rollback,
                });
            }
            ResourceMutation::EffectUnknown(error) => {
                self.track_runtime_handle(&caller, &handle)?;
                let rollback = self.rollback_runtime_handle(&caller, &handle)?;
                return Err(SupervisorError::SetupFailed {
                    subject: caller,
                    step: SetupStep::OpenHandle,
                    primary: OperationFailure::Resource(ResourceFailure::EffectUnknown(error)),
                    rollback,
                });
            }
        }
        let authority_handle = OpenHandle::new(handle.clone(), caller.clone(), object);
        if let Err(error) = self.kernel.register_open_handle(authority_handle) {
            let rollback = self.rollback_runtime_handle(&caller, &handle)?;
            return Err(SupervisorError::SetupFailed {
                subject: caller,
                step: SetupStep::RegisterHandle,
                primary: OperationFailure::Kernel(error),
                rollback,
            });
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
        match self.resources.close_handle(&caller, handle) {
            ResourceMutation::Applied => {}
            ResourceMutation::NoEffect(error) => {
                return Err(SupervisorError::Resource(ResourceFailure::NoEffect(error)));
            }
            ResourceMutation::CleanupRequired(error) => {
                return Err(SupervisorError::Resource(ResourceFailure::CleanupRequired(
                    error,
                )));
            }
            ResourceMutation::EffectUnknown(error) => {
                return Err(SupervisorError::Resource(ResourceFailure::EffectUnknown(
                    error,
                )));
            }
        }
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
        let mut failures = Vec::new();
        if authority_registered {
            match self.kernel.begin_subject_close(subject) {
                Ok(
                    SubjectCloseStatus::Started
                    | SubjectCloseStatus::AlreadyClosing
                    | SubjectCloseStatus::AlreadyClosed,
                ) => {}
                Err(error) => {
                    failures.push(CleanupFailure {
                        step: CleanupStep::BeginClose,
                        cause: OperationFailure::Kernel(error),
                    });
                    return Err(SupervisorError::CleanupFailed {
                        subject: subject.clone(),
                        failures,
                    });
                }
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
        let mut workload_stopped = workload.is_none();
        let mut control_closed = control.is_none();
        let mut mount_unmounted = mount.is_none();

        if let Some(workload_ownership) = workload {
            match (
                workload_ownership.token(),
                cgroup.and_then(ResourceOwnership::token),
            ) {
                (Some(workload_token), Some(cgroup_token)) => {
                    match self.resources.stop_workload(workload_token, cgroup_token) {
                        ResourceMutation::Applied => {
                            self.subjects
                                .get_mut(subject)
                                .ok_or_else(|| SupervisorError::UnknownSubject(subject.clone()))?
                                .workload = None;
                            workload_stopped = true;
                        }
                        outcome => failures
                            .push(Self::mutation_failure(CleanupStep::StopWorkload, outcome)),
                    }
                }
                _ => failures.push(CleanupFailure {
                    step: CleanupStep::StopWorkload,
                    cause: OperationFailure::UnresolvedEffect,
                }),
            }
        }

        if let Some(control_ownership) = control {
            match control_ownership.token() {
                Some(control_token) => match self.resources.close_control_fd(control_token) {
                    ResourceMutation::Applied => {
                        self.subjects
                            .get_mut(subject)
                            .ok_or_else(|| SupervisorError::UnknownSubject(subject.clone()))?
                            .control = None;
                        control_closed = true;
                    }
                    outcome => {
                        failures.push(Self::mutation_failure(CleanupStep::CloseControlFd, outcome));
                    }
                },
                None => failures.push(CleanupFailure {
                    step: CleanupStep::CloseControlFd,
                    cause: OperationFailure::UnresolvedEffect,
                }),
            }
        }

        for handle in runtime_handles {
            match self.resources.close_handle(subject, &handle) {
                ResourceMutation::Applied => {}
                outcome => {
                    failures.push(Self::mutation_failure(CleanupStep::CloseHandle, outcome));
                    continue;
                }
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
                        self.subjects
                            .get_mut(subject)
                            .ok_or_else(|| SupervisorError::UnknownSubject(subject.clone()))?
                            .runtime_handles
                            .remove(&handle);
                        self.subjects
                            .get_mut(subject)
                            .ok_or_else(|| SupervisorError::UnknownSubject(subject.clone()))?
                            .handles
                            .remove(&handle);
                    }
                    Err(error) => failures.push(CleanupFailure {
                        step: CleanupStep::CloseHandle,
                        cause: OperationFailure::Kernel(error),
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

        if let Some(mount_ownership) = mount
            && workload_stopped
            && control_closed
            && handles_closed
        {
            match mount_ownership.token() {
                Some(mount_token) => match self.resources.unmount_capfs(mount_token) {
                    ResourceMutation::Applied => {
                        self.subjects
                            .get_mut(subject)
                            .ok_or_else(|| SupervisorError::UnknownSubject(subject.clone()))?
                            .mount = None;
                        mount_unmounted = true;
                    }
                    outcome => failures.push(Self::mutation_failure(CleanupStep::Unmount, outcome)),
                },
                None => failures.push(CleanupFailure {
                    step: CleanupStep::Unmount,
                    cause: OperationFailure::UnresolvedEffect,
                }),
            }
        }

        if let Some(cgroup_ownership) = cgroup
            && workload_stopped
            && mount_unmounted
        {
            match cgroup_ownership.token() {
                Some(cgroup_token) => match self.resources.remove_cgroup(cgroup_token) {
                    ResourceMutation::Applied => {
                        self.subjects
                            .get_mut(subject)
                            .ok_or_else(|| SupervisorError::UnknownSubject(subject.clone()))?
                            .cgroup = None;
                    }
                    outcome => {
                        failures.push(Self::mutation_failure(CleanupStep::RemoveCgroup, outcome));
                    }
                },
                None => failures.push(CleanupFailure {
                    step: CleanupStep::RemoveCgroup,
                    cause: OperationFailure::UnresolvedEffect,
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
                        cause: OperationFailure::Kernel(error),
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

        if failures
            .iter()
            .any(|failure| matches!(failure.cause, OperationFailure::UnresolvedEffect))
        {
            Err(SupervisorError::CleanupBlocked {
                subject: subject.clone(),
                failures,
            })
        } else {
            Err(SupervisorError::CleanupFailed {
                subject: subject.clone(),
                failures,
            })
        }
    }

    /// Decodes and dispatches a request using only the accepted connection identity.
    pub fn dispatch_wire(
        &mut self,
        identity: &ConnectionIdentity,
        bytes: &[u8],
    ) -> SupervisorResult<K::Error, R::Error, C::Error, DispatchResponse> {
        let request = WireRequest::decode(bytes).map_err(SupervisorError::Wire)?;
        self.dispatch_request(identity, request)
    }

    /// Dispatches one already-decoded closed control request.
    ///
    /// Production transports that decode a bounded datagram before handing it to the supervisor
    /// can use this method without re-encoding the request. Authorization still selects the
    /// caller only from `identity`; the request's claimed subject remains diagnostic data.
    pub fn dispatch_request(
        &mut self,
        identity: &ConnectionIdentity,
        request: WireRequest,
    ) -> SupervisorResult<K::Error, R::Error, C::Error, DispatchResponse> {
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

    fn record_acquisition<T>(
        outcome: ResourceAcquisition<T, R::Error>,
        ownership: &mut Option<ResourceOwnership<T>>,
    ) -> Result<(), OperationFailure<K::Error, R::Error>> {
        match outcome {
            ResourceAcquisition::Acquired(resource) => {
                *ownership = Some(ResourceOwnership::Owned(resource));
                Ok(())
            }
            ResourceAcquisition::NoEffect(error) => {
                Err(OperationFailure::Resource(ResourceFailure::NoEffect(error)))
            }
            ResourceAcquisition::CleanupRequired { resource, error } => {
                *ownership = Some(ResourceOwnership::Owned(resource));
                Err(OperationFailure::Resource(
                    ResourceFailure::CleanupRequired(error),
                ))
            }
            ResourceAcquisition::EffectUnknown(error) => {
                *ownership = Some(ResourceOwnership::EffectUnknown);
                Err(OperationFailure::Resource(ResourceFailure::EffectUnknown(
                    error,
                )))
            }
        }
    }

    fn mutation_failure(
        step: CleanupStep,
        outcome: ResourceMutation<R::Error>,
    ) -> CleanupFailure<K::Error, R::Error> {
        let failure = match outcome {
            ResourceMutation::Applied => {
                return CleanupFailure {
                    step,
                    cause: OperationFailure::Invariant(
                        "an applied resource mutation was reported as a failure",
                    ),
                };
            }
            ResourceMutation::NoEffect(error) => ResourceFailure::NoEffect(error),
            ResourceMutation::CleanupRequired(error) => ResourceFailure::CleanupRequired(error),
            ResourceMutation::EffectUnknown(error) => ResourceFailure::EffectUnknown(error),
        };
        CleanupFailure {
            step,
            cause: OperationFailure::Resource(failure),
        }
    }

    fn track_runtime_handle(
        &mut self,
        subject: &SubjectId,
        handle: &HandleId,
    ) -> SupervisorResult<K::Error, R::Error, C::Error, ()> {
        self.subjects
            .get_mut(subject)
            .ok_or_else(|| SupervisorError::UnknownSubject(subject.clone()))?
            .runtime_handles
            .insert(handle.clone());
        Ok(())
    }

    fn rollback_runtime_handle(
        &mut self,
        subject: &SubjectId,
        handle: &HandleId,
    ) -> RollbackHandleResult<K::Error, R::Error, C::Error> {
        match self.resources.close_handle(subject, handle) {
            ResourceMutation::Applied => {
                self.subjects
                    .get_mut(subject)
                    .ok_or_else(|| SupervisorError::UnknownSubject(subject.clone()))?
                    .runtime_handles
                    .remove(handle);
                Ok(Vec::new())
            }
            outcome => {
                // An unregistered runtime handle is cleanup-only ownership.
                // Stop admitting new work until shutdown has retried the
                // idempotent close and removed that ownership record.
                self.subjects
                    .get_mut(subject)
                    .ok_or_else(|| SupervisorError::UnknownSubject(subject.clone()))?
                    .lifecycle = SubjectLifecycle::Closing;
                Ok(vec![Self::mutation_failure(
                    CleanupStep::CloseHandle,
                    outcome,
                )])
            }
        }
    }

    #[allow(clippy::too_many_lines)]
    fn rollback_setup(
        &mut self,
        subject: &SubjectId,
        cgroup: Option<ResourceOwnership<CgroupHandle>>,
        mount: Option<ResourceOwnership<MountHandle>>,
        control: Option<ResourceOwnership<ControlFdHandle>>,
        workload: Option<ResourceOwnership<WorkloadHandle>>,
        kernel_registered: bool,
    ) -> SetupRollback<K::Error, R::Error> {
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
                    cause: OperationFailure::Kernel(error),
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

        // Resource teardown must not race ahead of failed authority shutdown.
        if kernel_registered && !close_started {
            return SetupRollback {
                failures,
                authority_registered,
                cgroup,
                mount,
                control,
                workload,
            };
        }

        if let Some(workload_ownership) = workload {
            match (
                workload_ownership.token(),
                cgroup.and_then(ResourceOwnership::token),
            ) {
                (Some(workload_token), Some(cgroup_token)) => {
                    match self.resources.stop_workload(workload_token, cgroup_token) {
                        ResourceMutation::Applied => {
                            workload = None;
                            workload_stopped = true;
                        }
                        outcome => failures
                            .push(Self::mutation_failure(CleanupStep::StopWorkload, outcome)),
                    }
                }
                _ => failures.push(CleanupFailure {
                    step: CleanupStep::StopWorkload,
                    cause: OperationFailure::UnresolvedEffect,
                }),
            }
        }

        if let Some(control_ownership) = control {
            match control_ownership.token() {
                Some(control_token) => match self.resources.close_control_fd(control_token) {
                    ResourceMutation::Applied => {
                        control = None;
                        control_closed = true;
                    }
                    outcome => {
                        failures.push(Self::mutation_failure(CleanupStep::CloseControlFd, outcome));
                    }
                },
                None => failures.push(CleanupFailure {
                    step: CleanupStep::CloseControlFd,
                    cause: OperationFailure::UnresolvedEffect,
                }),
            }
        }

        if let Some(mount_ownership) = mount
            && workload_stopped
            && control_closed
        {
            match mount_ownership.token() {
                Some(mount_token) => match self.resources.unmount_capfs(mount_token) {
                    ResourceMutation::Applied => {
                        mount = None;
                        mount_unmounted = true;
                    }
                    outcome => failures.push(Self::mutation_failure(CleanupStep::Unmount, outcome)),
                },
                None => failures.push(CleanupFailure {
                    step: CleanupStep::Unmount,
                    cause: OperationFailure::UnresolvedEffect,
                }),
            }
        }

        if let Some(cgroup_ownership) = cgroup
            && workload_stopped
            && mount_unmounted
        {
            match cgroup_ownership.token() {
                Some(cgroup_token) => match self.resources.remove_cgroup(cgroup_token) {
                    ResourceMutation::Applied => cgroup = None,
                    outcome => {
                        failures.push(Self::mutation_failure(CleanupStep::RemoveCgroup, outcome));
                    }
                },
                None => failures.push(CleanupFailure {
                    step: CleanupStep::RemoveCgroup,
                    cause: OperationFailure::UnresolvedEffect,
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
                    cause: OperationFailure::Kernel(error),
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
    use std::{
        error::Error,
        fmt,
        sync::atomic::{AtomicBool, Ordering},
    };

    use super::{
        AuthorityKernel, CgroupHandle, CleanupStep, ConnectionIdentity, ControlFdHandle,
        MountHandle, OperationFailure, ResourceAcquisition, ResourceError, ResourceFailure,
        ResourceMutation, RuntimeResources, SetupStep, StaticCallerResolver, SubjectLifecycle,
        Supervisor, SupervisorError, WorkloadHandle,
    };
    use authority_core::{
        capability::{AuthorityBody, CapId, IssuerId, SubjectId},
        file::{FileAuthority, FileEffect, FileEffects},
        handle::{HandleId, ObjectId, OpenHandle},
        kernel::{CapabilityKernel, CapabilityKernelError},
        path::{CanonicalPath, PathPattern},
        repository::RepoId,
        state::{
            CapabilityGrant, CapabilityState, HandleCloseStatus, RevocationStatus,
            StaticAuthorityEnvelope, Subject, SubjectCloseStatus, SubjectFinishStatus,
        },
        time::{MonotonicTime, TimeWindow},
    };

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum TestFault {
        StartNoEffect,
        CgroupEffectUnknown,
        HandleOpenEffectUnknown,
        HandleCloseEffectUnknown,
    }

    #[derive(Debug, Default)]
    struct TestResources {
        events: Vec<&'static str>,
        faults: Vec<TestFault>,
        next_token: u64,
    }

    #[derive(Debug)]
    enum FaultKernelError {
        Injected(&'static str),
        Inner(CapabilityKernelError),
    }

    impl fmt::Display for FaultKernelError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                Self::Injected(operation) => write!(formatter, "injected {operation} failure"),
                Self::Inner(error) => error.fmt(formatter),
            }
        }
    }

    impl Error for FaultKernelError {}

    #[derive(Debug)]
    struct FaultKernel {
        inner: CapabilityKernel,
        fail_begin: AtomicBool,
        fail_finish: AtomicBool,
    }

    impl FaultKernel {
        fn new(fail_begin: bool, fail_finish: bool) -> Self {
            Self {
                inner: kernel(),
                fail_begin: AtomicBool::new(fail_begin),
                fail_finish: AtomicBool::new(fail_finish),
            }
        }

        fn inner<T>(result: Result<T, CapabilityKernelError>) -> Result<T, FaultKernelError> {
            result.map_err(FaultKernelError::Inner)
        }
    }

    impl AuthorityKernel for FaultKernel {
        type Error = FaultKernelError;

        fn is_pristine(&self) -> Result<bool, Self::Error> {
            Self::inner(CapabilityKernel::is_pristine(&self.inner))
        }

        fn register_subject(&self, subject: Subject) -> Result<(), Self::Error> {
            Self::inner(CapabilityKernel::register_subject(&self.inner, subject))
        }

        fn issue_root(&self, grant: CapabilityGrant) -> Result<CapId, Self::Error> {
            Self::inner(CapabilityKernel::issue_root(&self.inner, grant))
        }

        fn derive(
            &self,
            caller: &SubjectId,
            parent: &CapId,
            grant: CapabilityGrant,
            now: MonotonicTime,
        ) -> Result<CapId, Self::Error> {
            Self::inner(CapabilityKernel::derive(
                &self.inner,
                caller,
                parent,
                grant,
                now,
            ))
        }

        fn revoke(
            &self,
            caller: &SubjectId,
            capability: &CapId,
        ) -> Result<RevocationStatus, Self::Error> {
            Self::inner(CapabilityKernel::revoke_held_by(
                &self.inner,
                caller,
                capability,
            ))
        }

        fn begin_subject_close(
            &self,
            subject: &SubjectId,
        ) -> Result<SubjectCloseStatus, Self::Error> {
            if self.fail_begin.swap(false, Ordering::SeqCst) {
                return Err(FaultKernelError::Injected("begin_subject_close"));
            }
            Self::inner(CapabilityKernel::begin_subject_close(&self.inner, subject))
        }

        fn finish_subject_close(
            &self,
            subject: &SubjectId,
        ) -> Result<SubjectFinishStatus, Self::Error> {
            if self.fail_finish.swap(false, Ordering::SeqCst) {
                return Err(FaultKernelError::Injected("finish_subject_close"));
            }
            Self::inner(CapabilityKernel::finish_subject_close(&self.inner, subject))
        }

        fn register_open_handle(&self, handle: OpenHandle) -> Result<(), Self::Error> {
            Self::inner(CapabilityKernel::register_open_handle(&self.inner, handle))
        }

        fn close_handle(
            &self,
            caller: &SubjectId,
            handle: &HandleId,
        ) -> Result<HandleCloseStatus, Self::Error> {
            Self::inner(CapabilityKernel::close_handle(&self.inner, caller, handle))
        }

        fn open_handle(&self, handle: &HandleId) -> Result<Option<OpenHandle>, Self::Error> {
            Self::inner(CapabilityKernel::open_handle(&self.inner, handle))
        }
    }

    impl TestResources {
        fn token(&mut self) -> u64 {
            self.next_token += 1;
            self.next_token
        }

        fn take_fault(&mut self, fault: TestFault) -> bool {
            self.faults
                .iter()
                .position(|candidate| *candidate == fault)
                .is_some_and(|index| {
                    self.faults.remove(index);
                    true
                })
        }
    }

    impl RuntimeResources for TestResources {
        type Error = ResourceError;

        fn create_cgroup(
            &mut self,
            _subject: &SubjectId,
        ) -> ResourceAcquisition<CgroupHandle, Self::Error> {
            self.events.push("create_cgroup");
            if self.take_fault(TestFault::CgroupEffectUnknown) {
                ResourceAcquisition::EffectUnknown(ResourceError(
                    "cgroup creation completion was not observed".to_owned(),
                ))
            } else {
                ResourceAcquisition::Acquired(CgroupHandle::new(self.token()))
            }
        }

        fn remove_cgroup(&mut self, _cgroup: CgroupHandle) -> ResourceMutation<Self::Error> {
            self.events.push("remove_cgroup");
            ResourceMutation::Applied
        }

        fn mount_capfs(
            &mut self,
            _subject: &SubjectId,
        ) -> ResourceAcquisition<MountHandle, Self::Error> {
            self.events.push("mount");
            ResourceAcquisition::Acquired(MountHandle::new(self.token()))
        }

        fn unmount_capfs(&mut self, _mount: MountHandle) -> ResourceMutation<Self::Error> {
            self.events.push("unmount");
            ResourceMutation::Applied
        }

        fn open_control_fd(
            &mut self,
            _subject: &SubjectId,
        ) -> ResourceAcquisition<ControlFdHandle, Self::Error> {
            self.events.push("open_control");
            ResourceAcquisition::Acquired(ControlFdHandle::new(self.token()))
        }

        fn close_control_fd(&mut self, _control: ControlFdHandle) -> ResourceMutation<Self::Error> {
            self.events.push("close_control");
            ResourceMutation::Applied
        }

        fn start_workload(
            &mut self,
            _subject: &SubjectId,
            _cgroup: CgroupHandle,
            _mount: MountHandle,
            _control: ControlFdHandle,
        ) -> ResourceAcquisition<WorkloadHandle, Self::Error> {
            self.events.push("start_workload");
            if self.take_fault(TestFault::StartNoEffect) {
                ResourceAcquisition::NoEffect(ResourceError(
                    "start failed before spawning".to_owned(),
                ))
            } else {
                ResourceAcquisition::Acquired(WorkloadHandle::new(self.token()))
            }
        }

        fn stop_workload(
            &mut self,
            _workload: WorkloadHandle,
            _cgroup: CgroupHandle,
        ) -> ResourceMutation<Self::Error> {
            self.events.push("stop_workload");
            ResourceMutation::Applied
        }

        fn open_handle(
            &mut self,
            _subject: &SubjectId,
            _handle: &HandleId,
        ) -> ResourceMutation<Self::Error> {
            self.events.push("open_handle");
            if self.take_fault(TestFault::HandleOpenEffectUnknown) {
                ResourceMutation::EffectUnknown(ResourceError(
                    "open completion was not observed".to_owned(),
                ))
            } else {
                ResourceMutation::Applied
            }
        }

        fn close_handle(
            &mut self,
            _subject: &SubjectId,
            _handle: &HandleId,
        ) -> ResourceMutation<Self::Error> {
            self.events.push("close_handle");
            if self.take_fault(TestFault::HandleCloseEffectUnknown) {
                ResourceMutation::EffectUnknown(ResourceError(
                    "close completion was not observed".to_owned(),
                ))
            } else {
                ResourceMutation::Applied
            }
        }
    }

    fn envelope() -> StaticAuthorityEnvelope {
        let validity = TimeWindow::new(MonotonicTime::from_ticks(0), MonotonicTime::from_ticks(10))
            .expect("test validity must be non-empty");
        StaticAuthorityEnvelope::new(
            validity,
            AuthorityBody::File(FileAuthority::new(
                RepoId::new("workspace"),
                FileEffects::only(FileEffect::ReadData),
                PathPattern::Prefix(CanonicalPath::root()),
            )),
        )
    }

    fn kernel() -> CapabilityKernel {
        CapabilityKernel::new(CapabilityState::new(IssuerId::new("test-session")))
    }

    fn prepared_fault_supervisor(
        fail_begin: bool,
        fail_finish: bool,
    ) -> (
        Supervisor<FaultKernel, TestResources, StaticCallerResolver>,
        SubjectId,
    ) {
        let identity = ConnectionIdentity::new(90, 190, 1000, 1000);
        let subject = SubjectId::new(if fail_begin {
            "begin-close-retry"
        } else {
            "finish-close-retry"
        });
        let mut callers = StaticCallerResolver::new();
        callers
            .bind(identity, subject.clone())
            .expect("caller binding must be unique");
        let mut supervisor = Supervisor::new(
            FaultKernel::new(fail_begin, fail_finish),
            TestResources::default(),
            callers,
        )
        .expect("fault kernel must start pristine");
        supervisor
            .create_subject(Subject::new(subject.clone(), envelope()), identity)
            .expect("subject setup must succeed");
        (supervisor, subject)
    }

    #[test]
    fn begin_close_failure_is_retryable_after_local_closing_transition() {
        let (mut supervisor, subject) = prepared_fault_supervisor(true, false);

        let first = supervisor
            .shutdown_subject(&subject)
            .expect_err("injected begin failure must be observable");
        assert!(matches!(
            first,
            SupervisorError::CleanupFailed { failures, .. }
                if matches!(
                    failures.as_slice(),
                    [super::CleanupFailure {
                        step: CleanupStep::BeginClose,
                        cause: OperationFailure::Kernel(FaultKernelError::Injected(
                            "begin_subject_close"
                        )),
                    }]
                )
        ));
        assert_eq!(
            supervisor
                .lifecycle(&subject)
                .expect("subject must remain tracked"),
            SubjectLifecycle::Closing
        );

        supervisor
            .shutdown_subject(&subject)
            .expect("retry must complete begin-close cleanup");
        assert_eq!(
            supervisor
                .lifecycle(&subject)
                .expect("closed subject must remain inspectable"),
            SubjectLifecycle::Closed
        );
    }

    #[test]
    fn finish_close_failure_is_retryable_after_external_cleanup() {
        let (mut supervisor, subject) = prepared_fault_supervisor(false, true);

        let first = supervisor
            .shutdown_subject(&subject)
            .expect_err("injected finish failure must be observable");
        assert!(matches!(
            first,
            SupervisorError::CleanupFailed { failures, .. }
                if matches!(
                    failures.as_slice(),
                    [super::CleanupFailure {
                        step: CleanupStep::FinishClose,
                        cause: OperationFailure::Kernel(FaultKernelError::Injected(
                            "finish_subject_close"
                        )),
                    }]
                )
        ));
        assert_eq!(
            supervisor
                .lifecycle(&subject)
                .expect("subject must remain tracked"),
            SubjectLifecycle::Closing
        );

        supervisor
            .shutdown_subject(&subject)
            .expect("retry must finish authority close after resources are gone");
        assert_eq!(
            supervisor
                .lifecycle(&subject)
                .expect("closed subject must remain inspectable"),
            SubjectLifecycle::Closed
        );
    }

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

    #[test]
    fn constructor_rejects_a_prepopulated_kernel() {
        let kernel = kernel();
        kernel
            .register_subject(Subject::new(SubjectId::new("existing"), envelope()))
            .expect("prepopulation must succeed");

        let result = Supervisor::new(
            kernel,
            TestResources::default(),
            StaticCallerResolver::new(),
        );

        assert!(matches!(result, Err(SupervisorError::KernelNotPristine)));
    }

    #[test]
    fn registered_create_failure_permanently_reserves_subject_id() {
        let identity = ConnectionIdentity::new(11, 111, 1000, 1000);
        let subject_id = SubjectId::new("failed-after-registration");
        let mut callers = StaticCallerResolver::new();
        callers
            .bind(identity, subject_id.clone())
            .expect("caller binding must be unique");
        let resources = TestResources {
            faults: vec![TestFault::StartNoEffect],
            ..TestResources::default()
        };
        let mut supervisor =
            Supervisor::new(kernel(), resources, callers).expect("pristine kernel must initialize");

        let first =
            supervisor.create_subject(Subject::new(subject_id.clone(), envelope()), identity);
        assert!(matches!(
            first,
            Err(SupervisorError::SetupFailed {
                step: SetupStep::StartWorkload,
                primary: OperationFailure::Resource(ResourceFailure::NoEffect(_)),
                rollback,
                ..
            }) if rollback.is_empty()
        ));
        let events_after_rollback = supervisor.resources().events.clone();

        assert!(matches!(
            supervisor.create_subject(Subject::new(subject_id.clone(), envelope()), identity),
            Err(SupervisorError::DuplicateSubject(duplicate)) if duplicate == subject_id
        ));
        assert_eq!(supervisor.resources().events, events_after_rollback);
    }

    #[test]
    fn partial_open_cleanup_is_retained_and_retried_by_shutdown() {
        let identity = ConnectionIdentity::new(12, 112, 1000, 1000);
        let subject_id = SubjectId::new("partial-open-owner");
        let mut callers = StaticCallerResolver::new();
        callers
            .bind(identity, subject_id.clone())
            .expect("caller binding must be unique");
        let resources = TestResources {
            faults: vec![
                TestFault::HandleOpenEffectUnknown,
                TestFault::HandleCloseEffectUnknown,
            ],
            ..TestResources::default()
        };
        let mut supervisor =
            Supervisor::new(kernel(), resources, callers).expect("pristine kernel must initialize");
        supervisor
            .create_subject(Subject::new(subject_id.clone(), envelope()), identity)
            .expect("subject setup must succeed");
        let handle = HandleId::new("partial-open");

        let error = supervisor
            .open_handle(&identity, handle.clone(), ObjectId::new("object"))
            .expect_err("unknown open and rollback effects must fail closed");
        assert!(matches!(
            error,
            SupervisorError::SetupFailed {
                step: SetupStep::OpenHandle,
                primary: OperationFailure::Resource(ResourceFailure::EffectUnknown(_)),
                rollback,
                ..
            } if matches!(
                rollback.as_slice(),
                [super::CleanupFailure {
                    step: CleanupStep::CloseHandle,
                    cause: OperationFailure::Resource(ResourceFailure::EffectUnknown(_)),
                }]
            )
        ));
        assert!(matches!(
            supervisor.open_handle(&identity, handle, ObjectId::new("replacement")),
            Err(SupervisorError::SubjectClosing(_))
        ));

        supervisor
            .shutdown_subject(&subject_id)
            .expect("shutdown must retry and finish partial-open cleanup");
        assert_eq!(
            supervisor
                .resources()
                .events
                .iter()
                .filter(|event| **event == "close_handle")
                .count(),
            2
        );
    }

    #[test]
    fn unknown_token_acquisition_is_explicitly_fail_stopped() {
        let identity = ConnectionIdentity::new(13, 113, 1000, 1000);
        let subject_id = SubjectId::new("unknown-cgroup-owner");
        let mut callers = StaticCallerResolver::new();
        callers
            .bind(identity, subject_id.clone())
            .expect("caller binding must be unique");
        let resources = TestResources {
            faults: vec![TestFault::CgroupEffectUnknown],
            ..TestResources::default()
        };
        let mut supervisor =
            Supervisor::new(kernel(), resources, callers).expect("pristine kernel must initialize");

        let setup = supervisor
            .create_subject(Subject::new(subject_id.clone(), envelope()), identity)
            .expect_err("unknown acquisition effect must fail setup");
        assert!(matches!(
            setup,
            SupervisorError::SetupFailed {
                step: SetupStep::CreateCgroup,
                primary: OperationFailure::Resource(ResourceFailure::EffectUnknown(_)),
                rollback,
                ..
            } if matches!(
                rollback.as_slice(),
                [super::CleanupFailure {
                    step: CleanupStep::RemoveCgroup,
                    cause: OperationFailure::UnresolvedEffect,
                }]
            )
        ));

        assert!(matches!(
            supervisor.shutdown_subject(&subject_id),
            Err(SupervisorError::CleanupBlocked { failures, .. })
                if failures.iter().any(|failure| {
                    matches!(failure.cause, OperationFailure::UnresolvedEffect)
                })
        ));
    }
}
