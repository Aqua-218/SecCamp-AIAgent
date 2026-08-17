//! Fail-closed host composition for one production session owner.
//!
//! This module composes the production-owned lifecycle pieces that already
//! exist in this crate. It deliberately does not pretend that the guest-side supervisor,
//! session-jail provisioning, snapshot provenance, or host egress secrets can
//! be inferred safely before [`SessionIdentity`] allocation. Callers must
//! provide proof-carrying factories for those per-session boundaries.

use std::{
    error::Error,
    fmt, fs,
    num::{NonZeroU64, NonZeroUsize},
    path::{Component, Path, PathBuf},
    sync::{Arc, Mutex, MutexGuard},
};

#[cfg(unix)]
use std::os::unix::fs::MetadataExt as _;

use authority_core::{
    capability::IssuerId,
    durable_audit::{DurableAuditError, DurableAuditLog},
    kernel::CapabilityKernel,
    policy::AuthorityPolicyDigest,
    state::CapabilityState,
    time::MonotonicTime,
};
use egress_broker::{
    dispatch::{BrokerDispatcher, DispatchContext, PublicDispatchAdapter},
    durable::{DurableSessionConfig, MAX_DURABLE_BROKER_WAL_BYTES},
    github::GitHubAdapter,
    transport::DeadlineStream,
};
use egress_protocol::{
    budget::SessionBudgetLimits, session::BrokerSessionId as WireBrokerSessionId,
};
use firecracker_runtime::{
    FirecrackerVsockApiClient, RealCommandRunner, RealFileSystem, Runtime, RuntimeConfig,
    RuntimeError, Snapshot, SystemIdentitySource, UnixApiClient,
    recovery::{
        FirecrackerRecovery, LinuxFirecrackerRecovery, ProvisioningRecovery, RecoveryError,
        RecoveryStage, RecoveryTools, SessionResourceOwnership,
    },
};

#[cfg(test)]
use firecracker_runtime::{ApiClient, ApiRequest};

#[cfg(test)]
use firecracker_runtime::firecracker_guest_port_path;

#[cfg(test)]
use crate::egress_backend::FirecrackerUnixStream;

use crate::{
    BackendError, BrokerLease, BrokerSessionId, CapabilityId, CapabilityLease,
    DurableIdentityLedger, ID_BYTES, IdentityKind, IdentityLedger, LedgerError, LifecycleState,
    OsEntropy, RequestId, SessionId, SessionIdentity, SessionInfo, SessionOrchestrator,
    SnapshotDescriptor, SnapshotId, StartError, SubjectId, VmBackend, VmId, VmLease,
    WorkloadBackend, WorkloadLease, WorkspaceBackend, WorkspaceId, WorkspaceLease,
    WorkspaceTemplateId,
    authority_backend::{AuthorityCoreBackend, AuthorityRootGrant},
    egress_backend::{
        BrokerBackend, BrokerRuntimeFactory, BuiltBrokerRuntime, FirecrackerPeerCredentials,
        ProductionBrokerBackend,
    },
    firecracker_backend::{
        FirecrackerVmBackend, FirecrackerWorkloadBackend, new_firecracker_backends,
    },
    firecracker_workspace::{
        FirecrackerFileSystem, FirecrackerWorkspaceBackend, new_firecracker_workspace_adapters,
    },
    recovery::{
        DurableSessionRecoveryJournal, SessionRecoveryError, SessionRecoveryIntent,
        SessionRecoveryStage,
    },
    session_owner::{
        OwnerPollError, OwnerPollOutcome, OwnerPollRequest, SessionBackends, SessionOwner,
    },
};

/// Explicit authority audit-journal ownership policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthorityAuditMode {
    /// Exclusively creates a new journal and rejects an existing path.
    CreateNew(PathBuf),
    /// Requests recovery of an existing journal.
    ///
    /// The journal's prior attempts stay as history belonging to an earlier capability-state
    /// instance. They are never re-authorized, and each attempt left `Started` by an unclean
    /// shutdown is durably closed as `CommitUnknown` before the owner is returned. Recovery runs
    /// after host resource reconciliation, so the prior instance owns nothing by then.
    OpenExisting(PathBuf),
}

impl AuthorityAuditMode {
    fn path(&self) -> &Path {
        match self {
            Self::CreateNew(path) | Self::OpenExisting(path) => path,
        }
    }
}

/// Durable paths owned by one host runtime instance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProductionDurabilityConfig {
    identity_ledger_path: PathBuf,
    recovery_journal_path: PathBuf,
    authority_audit: AuthorityAuditMode,
    broker_wal_root: PathBuf,
}

impl ProductionDurabilityConfig {
    /// Creates the mandatory durable path configuration.
    #[must_use]
    pub fn new(
        identity_ledger_path: impl Into<PathBuf>,
        recovery_journal_path: impl Into<PathBuf>,
        authority_audit: AuthorityAuditMode,
        broker_wal_root: impl Into<PathBuf>,
    ) -> Self {
        Self {
            identity_ledger_path: identity_ledger_path.into(),
            recovery_journal_path: recovery_journal_path.into(),
            authority_audit,
            broker_wal_root: broker_wal_root.into(),
        }
    }
}

/// Host and guest endpoint values for the owned Broker listener.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProductionBrokerEndpoint {
    host_cid: u32,
    expected_guest_cid: u32,
    port: u32,
    backlog: i32,
}

/// Fixed guest-supervisor endpoint on the session's verified Firecracker vsock device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProductionGuestControlEndpoint {
    port: u32,
}

impl ProductionGuestControlEndpoint {
    /// Creates a mandatory fixed port. Validation happens before owner construction.
    #[must_use]
    pub const fn new(port: u32) -> Self {
        Self { port }
    }
}

impl ProductionBrokerEndpoint {
    /// Creates an endpoint configuration validated again by the production listener backend.
    #[must_use]
    pub const fn new(host_cid: u32, expected_guest_cid: u32, port: u32, backlog: i32) -> Self {
        Self {
            host_cid,
            expected_guest_cid,
            port,
            backlog,
        }
    }
}

/// Hard upper bound for the replay identities retained by one production Broker session.
pub const MAX_PRODUCTION_BROKER_REPLAY_CAPACITY: usize = 4096;

/// Hard upper bound for the requests served on one production Broker connection.
pub const MAX_PRODUCTION_BROKER_CONNECTION_REQUESTS: usize = 4096;

/// Hard upper bound for concurrent requests admitted by one production Broker session.
pub const MAX_PRODUCTION_BROKER_CONCURRENT_REQUESTS: usize = 256;

/// Maximum cumulative response budget that leaves at least half of the durable WAL for request,
/// settlement, checksum, and crash-recovery framing overhead.
pub const MAX_PRODUCTION_BROKER_RESPONSE_BUDGET_BYTES: u64 = MAX_DURABLE_BROKER_WAL_BYTES / 2;

/// Durable replay, budget, and connection ceilings for one Broker session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProductionBrokerLimits {
    replay_capacity: NonZeroUsize,
    budget_requests: NonZeroU64,
    budget_response_bytes: u64,
    budget_concurrent: NonZeroUsize,
    github_response_cap: u64,
    max_connection_requests: NonZeroUsize,
}

impl ProductionBrokerLimits {
    /// Creates mandatory Broker limits without applying implicit defaults.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        replay_capacity: NonZeroUsize,
        budget_requests: NonZeroU64,
        budget_response_bytes: u64,
        budget_concurrent: NonZeroUsize,
        github_response_cap: u64,
        max_connection_requests: NonZeroUsize,
    ) -> Self {
        Self {
            replay_capacity,
            budget_requests,
            budget_response_bytes,
            budget_concurrent,
            github_response_cap,
            max_connection_requests,
        }
    }

    /// Returns the maximum number of durable replay identities.
    #[must_use]
    pub const fn replay_capacity(self) -> NonZeroUsize {
        self.replay_capacity
    }

    /// Returns the session-wide request budget.
    #[must_use]
    pub const fn budget_requests(self) -> NonZeroU64 {
        self.budget_requests
    }

    /// Returns the session-wide committed response-byte budget.
    #[must_use]
    pub const fn budget_response_bytes(self) -> u64 {
        self.budget_response_bytes
    }

    /// Returns the session-wide concurrent request budget.
    #[must_use]
    pub const fn budget_concurrent(self) -> NonZeroUsize {
        self.budget_concurrent
    }

    /// Returns the maximum response bytes passed to the GitHub adapter.
    #[must_use]
    pub const fn github_response_cap(self) -> u64 {
        self.github_response_cap
    }

    /// Returns the maximum requests served on the authenticated connection.
    #[must_use]
    pub const fn max_connection_requests(self) -> NonZeroUsize {
        self.max_connection_requests
    }
}

/// One session runtime configuration together with the pinned tools that clean it up.
///
/// Both halves describe the same host resources: `runtime` names the cgroup, jail, workspace,
/// and dm-verity mapping a session owns, and `recovery_tools` are the exact pinned binaries the
/// crash-recovery driver is allowed to run against them.
#[derive(Debug, Clone)]
pub struct ProductionFirecrackerConfig {
    runtime: RuntimeConfig,
    recovery_tools: RecoveryTools,
}

impl ProductionFirecrackerConfig {
    /// Binds one runtime configuration to the recovery tools that release its resources.
    #[must_use]
    pub const fn new(runtime: RuntimeConfig, recovery_tools: RecoveryTools) -> Self {
        Self {
            runtime,
            recovery_tools,
        }
    }
}

/// Complete immutable input for the host production composition.
#[derive(Debug, Clone)]
pub struct ProductionSessionConfig {
    durability: ProductionDurabilityConfig,
    issuer: IssuerId,
    firecracker: ProductionFirecrackerConfig,
    workspace_template: WorkspaceTemplateId,
    broker_endpoint: ProductionBrokerEndpoint,
    guest_control_endpoint: ProductionGuestControlEndpoint,
    broker_limits: ProductionBrokerLimits,
}

impl ProductionSessionConfig {
    /// Creates a complete configuration. Validation and resource acquisition happen in `build`.
    #[must_use]
    pub const fn new(
        durability: ProductionDurabilityConfig,
        issuer: IssuerId,
        firecracker: ProductionFirecrackerConfig,
        workspace_template: WorkspaceTemplateId,
        broker_endpoint: ProductionBrokerEndpoint,
        guest_control_endpoint: ProductionGuestControlEndpoint,
        broker_limits: ProductionBrokerLimits,
    ) -> Self {
        Self {
            durability,
            issuer,
            firecracker,
            workspace_template,
            broker_endpoint,
            guest_control_endpoint,
            broker_limits,
        }
    }
}

/// Exact persisted ownership supplied only to crash-recovery provisioning cleanup.
pub struct SessionFirecrackerRecoveryRequest {
    identity: SessionIdentity,
    runtime_config: RuntimeConfig,
    ownership: SessionResourceOwnership,
}

impl SessionFirecrackerRecoveryRequest {
    /// Returns the session whose factory-owned provisioning state must be released.
    #[must_use]
    pub const fn identity(&self) -> SessionIdentity {
        self.identity
    }

    /// Returns the exact rebound configuration reconstructed from durable identity history.
    #[must_use]
    pub const fn runtime_config(&self) -> &RuntimeConfig {
        &self.runtime_config
    }

    /// Returns the sealed host resources that the recovery driver is advancing.
    #[must_use]
    pub const fn ownership(&self) -> &SessionResourceOwnership {
        &self.ownership
    }
}

/// Exact session-scoped values a Firecracker provisioner must prepare.
pub struct SessionFirecrackerRequest {
    identity: SessionIdentity,
    runtime_config: RuntimeConfig,
    snapshot_id: SnapshotId,
    snapshot_path: PathBuf,
    memory_path: PathBuf,
    guest_control_port: u32,
    policy_digest: AuthorityPolicyDigest,
}

impl SessionFirecrackerRequest {
    /// Creates the exact session-scoped input supplied to a Firecracker provisioner.
    ///
    /// Callers that implement [`PerSessionFirecrackerFactory`] can use this constructor in
    /// integration tests. Production composition constructs the request only after the
    /// orchestrator has durably allocated `identity`; provisioners must still validate every
    /// field before creating a session-owned resource.
    #[must_use]
    pub fn new(
        identity: SessionIdentity,
        runtime_config: RuntimeConfig,
        snapshot_id: SnapshotId,
        snapshot_path: impl Into<PathBuf>,
        memory_path: impl Into<PathBuf>,
        guest_control_port: u32,
        policy_digest: AuthorityPolicyDigest,
    ) -> Self {
        Self {
            identity,
            runtime_config,
            snapshot_id,
            snapshot_path: snapshot_path.into(),
            memory_path: memory_path.into(),
            guest_control_port,
            policy_digest,
        }
    }

    /// Returns the only session identity accepted for this preparation.
    #[must_use]
    pub const fn identity(&self) -> SessionIdentity {
        self.identity
    }

    /// Returns the exact session-bound runtime configuration.
    #[must_use]
    pub const fn runtime_config(&self) -> &RuntimeConfig {
        &self.runtime_config
    }

    /// Returns the trusted snapshot identity required by the owner.
    #[must_use]
    pub const fn snapshot_id(&self) -> SnapshotId {
        self.snapshot_id
    }

    /// Returns the exact state-file path inside the session jail.
    #[must_use]
    pub fn snapshot_path(&self) -> &Path {
        &self.snapshot_path
    }

    /// Returns the exact memory-file path inside the session jail.
    #[must_use]
    pub fn memory_path(&self) -> &Path {
        &self.memory_path
    }

    /// Returns the fixed guest-supervisor vsock port the snapshot must serve.
    #[must_use]
    pub const fn guest_control_port(&self) -> u32 {
        self.guest_control_port
    }

    /// Returns the exact guest root policy required from the snapshot template.
    #[must_use]
    pub const fn policy_digest(&self) -> AuthorityPolicyDigest {
        self.policy_digest
    }
}

/// Verified output of one identity-bound Firecracker preparation.
///
/// Construction rechecks the exact config, snapshot identity, paths, and compatibility
/// fingerprint supplied by the runtime. The runtime owns Firecracker API and guest-control
/// transport construction from the exact session-bound socket configuration.
pub struct PreparedFirecrackerSession {
    identity: SessionIdentity,
    runtime_config: RuntimeConfig,
    snapshot: Snapshot,
    snapshot_id: SnapshotId,
}

impl PreparedFirecrackerSession {
    /// Verifies and seals per-session provisioning output.
    ///
    /// # Errors
    ///
    /// Returns [`SessionPreparationError`] unless every restore-relevant value is bound to
    /// `request`. The Firecracker runtime repeats file digest and exported-resource checks at
    /// restore time.
    pub fn verify(
        request: &SessionFirecrackerRequest,
        runtime_config: RuntimeConfig,
        snapshot: Snapshot,
        snapshot_id: SnapshotId,
    ) -> Result<Self, SessionPreparationError> {
        runtime_config
            .validate()
            .map_err(SessionPreparationError::RuntimeConfig)?;
        if runtime_config != request.runtime_config {
            return Err(SessionPreparationError::RuntimeConfigMismatch);
        }
        if snapshot_id != request.snapshot_id {
            return Err(SessionPreparationError::SnapshotIdMismatch);
        }
        if snapshot.snapshot_path != request.snapshot_path {
            return Err(SessionPreparationError::SnapshotPathMismatch {
                resource: SnapshotResource::State,
            });
        }
        if snapshot.memory_path != request.memory_path {
            return Err(SessionPreparationError::SnapshotPathMismatch {
                resource: SnapshotResource::Memory,
            });
        }
        if snapshot.artifact_fingerprint != runtime_config.snapshot_fingerprint() {
            return Err(SessionPreparationError::SnapshotFingerprintMismatch);
        }
        if snapshot.policy_digest() != Some(request.policy_digest) {
            return Err(SessionPreparationError::SnapshotPolicyMismatch);
        }
        Ok(Self {
            identity: request.identity,
            runtime_config,
            snapshot,
            snapshot_id,
        })
    }
}

/// Mandatory session-aware provisioning boundary for Firecracker artifacts and its session jail.
pub trait PerSessionFirecrackerFactory: Send + 'static {
    /// Returns the provisioned snapshot identity whose image contains no live session identity.
    fn snapshot_id(&self) -> SnapshotId;

    /// Prepares the exact session jail and snapshot provenance.
    ///
    /// An error must leave no unowned process or mount behind. A successful result transfers all
    /// later VM cleanup responsibility into the returned Firecracker runtime backends.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] if the exact session jail and snapshot cannot be prepared and
    /// sealed into [`PreparedFirecrackerSession`]. Neither API transport is supplied by this
    /// factory; the runtime constructs both from the verified config.
    fn prepare(
        &mut self,
        request: &SessionFirecrackerRequest,
    ) -> Result<PreparedFirecrackerSession, BackendError>;

    /// Idempotently releases factory-owned provisioning for one exact persisted session.
    ///
    /// This callback runs only after the recovery driver has verified the session cgroup empty,
    /// before mapper and jail cleanup. It must reject ownership not represented by `request` and
    /// must return an error while any owned resource remains.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] while exact provisioning cleanup is incomplete or ambiguous.
    fn recover_provisioning(
        &mut self,
        request: &SessionFirecrackerRecoveryRequest,
    ) -> Result<(), BackendError>;
}

/// Exact session identity for which host-owned egress adapters must be prepared.
pub struct SessionEgressRequest {
    identity: SessionIdentity,
}

impl SessionEgressRequest {
    /// Creates the exact identity-bound input supplied to an egress provisioner.
    ///
    /// Production composition creates this request only after durable identity allocation. The
    /// constructor is also available to integration tests that verify a concrete
    /// [`PerSessionEgressFactory`] without constructing a live Broker listener.
    #[must_use]
    pub const fn new(identity: SessionIdentity) -> Self {
        Self { identity }
    }

    /// Returns the exact orchestrator identity for this dispatcher.
    #[must_use]
    pub const fn identity(&self) -> SessionIdentity {
        self.identity
    }
}

struct BoxedPublicAdapter(Box<dyn PublicDispatchAdapter + Send>);

impl PublicDispatchAdapter for BoxedPublicAdapter {
    fn fetch(
        &self,
        request: &authority_core::http::HttpFetchRequest,
        authority: &authority_core::http::HttpFetchAuthority,
    ) -> Result<egress_broker::public_fetch::PublicResponse, egress_broker::public_fetch::FetchError>
    {
        self.0.fetch(request, authority)
    }
}

struct BoxedGitHubAdapter(Box<dyn GitHubAdapter>);

impl GitHubAdapter for BoxedGitHubAdapter {
    fn execute(
        &mut self,
        request_id: egress_protocol::session::BrokerRequestId,
        request: &authority_core::github::GitHubRequest,
        authority: &authority_core::github::GitHubAuthority,
        max_response_bytes: u64,
    ) -> Result<egress_broker::github::GitHubResponse, egress_broker::github::GitHubAdapterError>
    {
        self.0
            .execute(request_id, request, authority, max_response_bytes)
    }
}

/// Host adapter and clock inputs sealed for one Broker worker.
///
/// Authority, durable WAL, replay, and budget state cannot be supplied here. The production
/// runtime constructs those controls itself after this value is returned.
pub struct PreparedEgressSession {
    identity: SessionIdentity,
    public_adapter: BoxedPublicAdapter,
    github_adapter: BoxedGitHubAdapter,
    clock: Box<dyn FnMut() -> MonotonicTime + Send>,
}

impl PreparedEgressSession {
    /// Seals provider adapters and a monotonic clock for exactly `request`.
    #[must_use]
    pub fn new<P, G, C>(
        request: &SessionEgressRequest,
        public_adapter: P,
        github_adapter: G,
        clock: C,
    ) -> Self
    where
        P: PublicDispatchAdapter + Send + 'static,
        G: GitHubAdapter + 'static,
        C: FnMut() -> MonotonicTime + Send + 'static,
    {
        Self {
            identity: request.identity,
            public_adapter: BoxedPublicAdapter(Box::new(public_adapter)),
            github_adapter: BoxedGitHubAdapter(Box::new(github_adapter)),
            clock: Box::new(clock),
        }
    }

    fn matches(&self, request: &SessionEgressRequest) -> bool {
        self.identity == request.identity
    }
}

/// Mandatory host-owned provider-adapter, secret, plan, and clock boundary.
pub trait PerSessionEgressFactory: Send + Sync + 'static {
    /// Builds only provider adapters and a clock for exactly `request`.
    ///
    /// Secret material remains inside the returned provider adapters. The runtime retains sole
    /// control of the authority kernel, caller/capability binding, durable WAL, and all limits.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] if the exact session's provider adapters or monotonic clock cannot
    /// be prepared and sealed into [`PreparedEgressSession`].
    fn prepare(
        &self,
        request: &SessionEgressRequest,
    ) -> Result<PreparedEgressSession, BackendError>;
}

/// Snapshot file whose exact path did not match its session request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnapshotResource {
    /// Firecracker state file.
    State,
    /// Guest memory file.
    Memory,
}

/// Failure while sealing proof-carrying per-session output.
#[derive(Debug)]
pub enum SessionPreparationError {
    /// The returned Runtime configuration is invalid.
    RuntimeConfig(RuntimeError),
    /// The returned Runtime configuration is not byte-for-byte the requested config.
    RuntimeConfigMismatch,
    /// The returned snapshot identity differs from the trusted source.
    SnapshotIdMismatch,
    /// A snapshot file is not at the exact session jail path.
    SnapshotPathMismatch {
        /// Mismatched file kind.
        resource: SnapshotResource,
    },
    /// Snapshot compatibility is not bound to the exact Runtime configuration.
    SnapshotFingerprintMismatch,
    /// Snapshot image policy metadata differs from the exact session grant.
    SnapshotPolicyMismatch,
}

impl fmt::Display for SessionPreparationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RuntimeConfig(error) => {
                write!(formatter, "invalid session Runtime config: {error}")
            }
            Self::RuntimeConfigMismatch => formatter
                .write_str("prepared Runtime config does not equal the exact session request"),
            Self::SnapshotIdMismatch => formatter
                .write_str("prepared snapshot identity does not equal the trusted snapshot source"),
            Self::SnapshotPathMismatch { resource } => {
                write!(
                    formatter,
                    "prepared {resource:?} snapshot path is not session-bound"
                )
            }
            Self::SnapshotFingerprintMismatch => formatter
                .write_str("prepared snapshot fingerprint does not match the exact Runtime config"),
            Self::SnapshotPolicyMismatch => formatter.write_str(
                "prepared snapshot policy digest does not match the exact session request",
            ),
        }
    }
}

impl Error for SessionPreparationError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::RuntimeConfig(error) => Some(error),
            Self::RuntimeConfigMismatch
            | Self::SnapshotIdMismatch
            | Self::SnapshotPathMismatch { .. }
            | Self::SnapshotFingerprintMismatch
            | Self::SnapshotPolicyMismatch => None,
        }
    }
}

/// Typed failure while reconciling or advancing durable session recovery.
#[derive(Debug)]
pub enum ProductionRecoveryError {
    /// The durable recovery journal could not be read or advanced safely.
    Journal(SessionRecoveryError),
    /// Exact Firecracker resource ownership could not be reconstructed.
    Runtime(RuntimeError),
    /// A physical cleanup stage remains incomplete.
    Firecracker(RecoveryError),
    /// Recovery history and the no-reuse identity ledger disagree.
    IdentityMismatch(String),
}

impl fmt::Display for ProductionRecoveryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Journal(error) => write!(formatter, "session recovery journal failed: {error}"),
            Self::Runtime(error) => write!(
                formatter,
                "session recovery ownership could not be reconstructed: {error}"
            ),
            Self::Firecracker(error) => error.fmt(formatter),
            Self::IdentityMismatch(message) => {
                write!(formatter, "session recovery identity mismatch: {message}")
            }
        }
    }
}

impl Error for ProductionRecoveryError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Journal(error) => Some(error),
            Self::Runtime(error) => Some(error),
            Self::Firecracker(error) => Some(error),
            Self::IdentityMismatch(_) => None,
        }
    }
}

/// Failure before a production session owner can be returned.
#[derive(Debug)]
pub enum ProductionBuildError {
    /// A static path, identity, or limit violates the composition contract.
    InvalidConfig(String),
    /// Runtime configuration validation failed.
    Runtime(RuntimeError),
    /// Durable identity-ledger acquisition or recovery failed.
    IdentityLedger(LedgerError),
    /// Durable session ownership recovery or ledger reconciliation failed.
    Recovery(Box<ProductionRecoveryError>),
    /// Durable authority journal creation failed.
    AuthorityAudit(DurableAuditError),
    /// Production Broker backend validation failed.
    Broker(BackendError),
    /// Authority Core could not inspect the fresh journal.
    AuthorityKernel(authority_core::audit::AuditError),
}

impl ProductionBuildError {
    fn recovery(error: ProductionRecoveryError) -> Self {
        Self::Recovery(Box::new(error))
    }
}

impl fmt::Display for ProductionBuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig(message) => {
                write!(formatter, "invalid production config: {message}")
            }
            Self::Runtime(error) => {
                write!(formatter, "invalid Firecracker Runtime config: {error}")
            }
            Self::IdentityLedger(error) => {
                write!(formatter, "identity ledger unavailable: {error}")
            }
            Self::Recovery(error) => error.fmt(formatter),
            Self::AuthorityAudit(error) => {
                write!(formatter, "authority audit WAL unavailable: {error}")
            }
            Self::Broker(error) => write!(
                formatter,
                "production Broker backend rejected config: {error}"
            ),
            Self::AuthorityKernel(error) => write!(
                formatter,
                "durable Authority Core initialization failed: {error}"
            ),
        }
    }
}

impl Error for ProductionBuildError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Runtime(error) => Some(error),
            Self::IdentityLedger(error) => Some(error),
            Self::Recovery(error) => Some(error),
            Self::AuthorityAudit(error) => Some(error),
            Self::Broker(error) => Some(error),
            Self::AuthorityKernel(error) => Some(error),
            Self::InvalidConfig(_) => None,
        }
    }
}

/// One-shot startup failure for an already composed owner.
#[derive(Debug)]
pub enum ProductionStartError {
    /// This composition has already consumed its one session identity allocation attempt.
    AlreadyStarted,
    /// A pending durable recovery obligation could not be drained before startup effects.
    Recovery(Box<ProductionRecoveryError>),
    /// The underlying fail-closed lifecycle start failed.
    Start(StartError),
}

impl ProductionStartError {
    fn recovery(error: ProductionRecoveryError) -> Self {
        Self::Recovery(Box::new(error))
    }
}

impl fmt::Display for ProductionStartError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AlreadyStarted => formatter.write_str(
                "production session runtime is one-shot and has already attempted startup",
            ),
            Self::Recovery(error) => error.fmt(formatter),
            Self::Start(error) => error.fmt(formatter),
        }
    }
}

impl Error for ProductionStartError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::AlreadyStarted => None,
            Self::Recovery(error) => Some(error),
            Self::Start(error) => Some(error),
        }
    }
}

type ProductionRecoveryDriver = FirecrackerRecovery<LinuxFirecrackerRecovery>;
type SharedProductionRecovery = Arc<Mutex<ProductionRecoveryState>>;

struct ProductionRecoveryState {
    journal: DurableSessionRecoveryJournal,
    driver: ProductionRecoveryDriver,
}

struct RecoveryAwareIdentityLedger {
    inner: DurableIdentityLedger,
    recovery: SharedProductionRecovery,
    base_config: RuntimeConfig,
}

impl RecoveryAwareIdentityLedger {
    const fn new(
        inner: DurableIdentityLedger,
        recovery: SharedProductionRecovery,
        base_config: RuntimeConfig,
    ) -> Self {
        Self {
            inner,
            recovery,
            base_config,
        }
    }
}

impl IdentityLedger for RecoveryAwareIdentityLedger {
    fn reserve_batch(
        &mut self,
        identities: &[(IdentityKind, [u8; ID_BYTES])],
    ) -> Result<(), LedgerError> {
        let identity = session_identity_from_reservation(identities)?;
        let request = recovery_request(&self.base_config, identity)
            .map_err(|error| recovery_ledger_error(&error))?;
        let mut recovery = self.recovery.lock().map_err(|_| LedgerError::Unavailable {
            reason: "session recovery state is poisoned before identity reservation".to_owned(),
        })?;
        let lease = recovery
            .journal
            .prepare(SessionRecoveryIntent::new(
                identity,
                request.ownership.config_fingerprint(),
            ))
            .map_err(recovery_journal_ledger_error)?;

        if let Err(error) = self.inner.reserve_batch(identities) {
            if matches!(
                error,
                LedgerError::Duplicate { .. } | LedgerError::CapacityExceeded { .. }
            ) && let Err(abandon_error) = recovery.journal.abandon(&lease)
            {
                return Err(LedgerError::Unavailable {
                    reason: format!(
                        "identity reservation failed without effect ({error}), but its durable recovery intent could not be abandoned: {abandon_error}"
                    ),
                });
            }
            return Err(error);
        }

        recovery
            .journal
            .checkpoint(&lease, SessionRecoveryStage::IdentityReserved)
            .map(|_| ())
            .map_err(recovery_journal_ledger_error)
    }
}

fn session_identity_from_reservation(
    identities: &[(IdentityKind, [u8; ID_BYTES])],
) -> Result<SessionIdentity, LedgerError> {
    const EXPECTED: [IdentityKind; 7] = [
        IdentityKind::Session,
        IdentityKind::Request,
        IdentityKind::Vm,
        IdentityKind::Subject,
        IdentityKind::Workspace,
        IdentityKind::Capability,
        IdentityKind::BrokerSession,
    ];
    if identities.len() != EXPECTED.len()
        || identities
            .iter()
            .zip(EXPECTED)
            .any(|((actual, _), expected)| *actual != expected)
    {
        return Err(LedgerError::Unavailable {
            reason: "production identity reservation is not the exact seven-kind session batch"
                .to_owned(),
        });
    }
    for (index, (_, identity)) in identities.iter().enumerate() {
        if identities
            .iter()
            .skip(index + 1)
            .any(|(_, candidate)| candidate == identity)
        {
            return Err(LedgerError::Duplicate {
                kind: identities[index].0,
                identity: *identity,
            });
        }
    }
    Ok(SessionIdentity {
        session_id: SessionId::new(identities[0].1),
        request_id: RequestId::new(identities[1].1),
        vm_id: VmId::new(identities[2].1),
        subject_id: SubjectId::new(identities[3].1),
        workspace_id: WorkspaceId::new(identities[4].1),
        capability_id: CapabilityId::new(identities[5].1),
        broker_session_id: BrokerSessionId::new(identities[6].1),
    })
}

fn recovery_request(
    base_config: &RuntimeConfig,
    identity: SessionIdentity,
) -> Result<SessionFirecrackerRecoveryRequest, ProductionRecoveryError> {
    let runtime_config = rebind_runtime_config(base_config, identity)
        .map_err(|error| ProductionRecoveryError::IdentityMismatch(error.to_string()))?;
    let ownership = SessionResourceOwnership::from_runtime_config(&runtime_config)
        .map_err(ProductionRecoveryError::Runtime)?;
    Ok(SessionFirecrackerRecoveryRequest {
        identity,
        runtime_config,
        ownership,
    })
}

fn recovery_ledger_error(error: &ProductionRecoveryError) -> LedgerError {
    LedgerError::Unavailable {
        reason: error.to_string(),
    }
}

fn recovery_journal_ledger_error(error: SessionRecoveryError) -> LedgerError {
    recovery_ledger_error(&ProductionRecoveryError::Journal(error))
}

struct FactoryProvisioningRecovery<'a> {
    factory: &'a mut dyn PerSessionFirecrackerFactory,
    request: &'a SessionFirecrackerRecoveryRequest,
}

impl ProvisioningRecovery for FactoryProvisioningRecovery<'_> {
    fn release_provisioning(
        &mut self,
        ownership: &SessionResourceOwnership,
    ) -> Result<(), RuntimeError> {
        if ownership != self.request.ownership() {
            return Err(RuntimeError::Cleanup(
                "provisioning recovery received foreign resource ownership".to_owned(),
            ));
        }
        self.factory
            .recover_provisioning(self.request)
            .map_err(|error| RuntimeError::Cleanup(error.to_string()))
    }
}

fn firecracker_stage(
    stage: SessionRecoveryStage,
) -> Result<RecoveryStage, ProductionRecoveryError> {
    match stage {
        SessionRecoveryStage::IdentityReserved => Ok(RecoveryStage::IdentityReserved),
        SessionRecoveryStage::CgroupEmpty => Ok(RecoveryStage::CgroupEmpty),
        SessionRecoveryStage::MapperClosed => Ok(RecoveryStage::MapperClosed),
        SessionRecoveryStage::ProvisioningReleased => Ok(RecoveryStage::ProvisioningReleased),
        SessionRecoveryStage::JailRemoved => Ok(RecoveryStage::JailRemoved),
        SessionRecoveryStage::Complete => Ok(RecoveryStage::Complete),
        SessionRecoveryStage::Intent | SessionRecoveryStage::Abandoned => {
            Err(ProductionRecoveryError::IdentityMismatch(format!(
                "stage {stage} has no Firecracker cleanup ownership"
            )))
        }
    }
}

const fn journal_stage(stage: RecoveryStage) -> SessionRecoveryStage {
    match stage {
        RecoveryStage::IdentityReserved => SessionRecoveryStage::IdentityReserved,
        RecoveryStage::CgroupEmpty => SessionRecoveryStage::CgroupEmpty,
        RecoveryStage::MapperClosed => SessionRecoveryStage::MapperClosed,
        RecoveryStage::ProvisioningReleased => SessionRecoveryStage::ProvisioningReleased,
        RecoveryStage::JailRemoved => SessionRecoveryStage::JailRemoved,
        RecoveryStage::Complete => SessionRecoveryStage::Complete,
    }
}

fn drain_recovery_to(
    recovery: &mut ProductionRecoveryState,
    base_config: &RuntimeConfig,
    factory: &mut dyn PerSessionFirecrackerFactory,
    target: SessionRecoveryStage,
) -> Result<(), ProductionRecoveryError> {
    loop {
        let Some(lease) = recovery.journal.pending() else {
            return Ok(());
        };
        if lease.stage() == SessionRecoveryStage::Intent {
            return Err(ProductionRecoveryError::IdentityMismatch(
                "recovery intent has not durably reserved its seven identities".to_owned(),
            ));
        }
        if lease.stage() >= target {
            return Ok(());
        }
        if lease.stage() == SessionRecoveryStage::JailRemoved {
            recovery
                .journal
                .complete(&lease)
                .map_err(ProductionRecoveryError::Journal)?;
            continue;
        }
        let request = recovery_request(base_config, lease.intent().identity())?;
        if request.ownership.config_fingerprint() != lease.intent().config_fingerprint() {
            return Err(ProductionRecoveryError::IdentityMismatch(format!(
                "persisted config fingerprint for session {} does not match reconstructed ownership",
                lease.intent().identity().session_id()
            )));
        }
        let mut provisioning = FactoryProvisioningRecovery {
            factory,
            request: &request,
        };
        let progress = ProductionRecoveryDriver::begin(
            &request.ownership,
            lease.intent().config_fingerprint(),
            firecracker_stage(lease.stage())?,
        )
        .map_err(ProductionRecoveryError::Firecracker)?;
        let advanced = recovery
            .driver
            .recover_next(&request.ownership, progress, &mut provisioning)
            .map_err(ProductionRecoveryError::Firecracker)?;
        if advanced == RecoveryStage::Complete {
            recovery
                .journal
                .complete(&lease)
                .map_err(ProductionRecoveryError::Journal)?;
        } else {
            recovery
                .journal
                .checkpoint(&lease, journal_stage(advanced))
                .map_err(ProductionRecoveryError::Journal)?;
        }
    }
}

fn reconcile_recovery(
    ledger: &mut DurableIdentityLedger,
    recovery: &mut ProductionRecoveryState,
    base_config: &RuntimeConfig,
    factory: &mut dyn PerSessionFirecrackerFactory,
) -> Result<(), ProductionBuildError> {
    if let Some(lease) = recovery.journal.pending()
        && lease.stage() == SessionRecoveryStage::Intent
    {
        let request = recovery_request(base_config, lease.intent().identity())
            .map_err(ProductionBuildError::recovery)?;
        if request.ownership.config_fingerprint() != lease.intent().config_fingerprint() {
            return Err(ProductionBuildError::recovery(
                ProductionRecoveryError::IdentityMismatch(format!(
                    "persisted config fingerprint for session {} does not match reconstructed ownership",
                    lease.intent().identity().session_id()
                )),
            ));
        }
        let identities = lease.intent().identities();
        require_distinct_intent_identities(&identities).map_err(ProductionBuildError::recovery)?;
        let present = identities
            .iter()
            .filter(|(_, identity)| ledger.contains(*identity))
            .count();
        match present {
            0 => {
                if let Err(error) = ledger.reserve_batch(&identities) {
                    if matches!(
                        error,
                        LedgerError::Duplicate { .. } | LedgerError::CapacityExceeded { .. }
                    ) {
                        recovery
                            .journal
                            .abandon(&lease)
                            .map_err(ProductionRecoveryError::Journal)
                            .map_err(ProductionBuildError::recovery)?;
                    }
                    return Err(ProductionBuildError::IdentityLedger(error));
                }
            }
            7 => {}
            count => {
                return Err(ProductionBuildError::recovery(
                    ProductionRecoveryError::IdentityMismatch(format!(
                        "pending intent has only {count} of seven identities in the ledger"
                    )),
                ));
            }
        }
        recovery
            .journal
            .checkpoint(&lease, SessionRecoveryStage::IdentityReserved)
            .map_err(ProductionRecoveryError::Journal)
            .map_err(ProductionBuildError::recovery)?;
    }

    validate_recovery_ledger_exactness(ledger, &recovery.journal)
        .map_err(ProductionBuildError::recovery)?;
    drain_recovery_to(
        recovery,
        base_config,
        factory,
        SessionRecoveryStage::Complete,
    )
    .map_err(ProductionBuildError::recovery)
}

fn require_distinct_intent_identities(
    identities: &[(IdentityKind, [u8; ID_BYTES]); 7],
) -> Result<(), ProductionRecoveryError> {
    for (index, (_, identity)) in identities.iter().enumerate() {
        if identities
            .iter()
            .skip(index + 1)
            .any(|(_, candidate)| candidate == identity)
        {
            return Err(ProductionRecoveryError::IdentityMismatch(
                "one recovery intent repeats a supposedly disjoint identity".to_owned(),
            ));
        }
    }
    Ok(())
}

fn validate_recovery_ledger_exactness(
    ledger: &DurableIdentityLedger,
    journal: &DurableSessionRecoveryJournal,
) -> Result<(), ProductionRecoveryError> {
    let reserved = journal.identity_reserved_intent_count();
    let expected = reserved.checked_mul(7).ok_or_else(|| {
        ProductionRecoveryError::IdentityMismatch(
            "reserved recovery history exceeds identity-count capacity".to_owned(),
        )
    })?;
    if ledger.committed_count() != expected {
        return Err(ProductionRecoveryError::IdentityMismatch(format!(
            "ledger contains {} identities but recovery history accounts for exactly {expected}",
            ledger.committed_count()
        )));
    }
    for intent in journal.identity_reserved_intents() {
        let identities = intent.identities();
        require_distinct_intent_identities(&identities)?;
        if identities
            .iter()
            .any(|(_, identity)| !ledger.contains(*identity))
        {
            return Err(ProductionRecoveryError::IdentityMismatch(format!(
                "ledger is missing an identity reserved for session {}",
                intent.identity().session_id()
            )));
        }
    }
    Ok(())
}

/// Fail-closed builder for one non-cloneable production session runtime.
pub struct ProductionSessionRuntimeBuilder {
    config: ProductionSessionConfig,
    firecracker_factory: Box<dyn PerSessionFirecrackerFactory>,
    egress_factory: Arc<dyn PerSessionEgressFactory>,
}

impl ProductionSessionRuntimeBuilder {
    /// Captures all mandatory host inputs without installing fallback adapters.
    #[must_use]
    pub fn new<F, E>(
        config: ProductionSessionConfig,
        firecracker_factory: F,
        egress_factory: E,
    ) -> Self
    where
        F: PerSessionFirecrackerFactory,
        E: PerSessionEgressFactory,
    {
        Self {
            config,
            firecracker_factory: Box::new(firecracker_factory),
            egress_factory: Arc::new(egress_factory),
        }
    }

    /// Validates static invariants, exclusively acquires durable writers, and constructs an
    /// actual [`SessionOwner`] with production workspace, Broker, Firecracker, and authority
    /// backends.
    ///
    /// This does not start a VM. Per-session provisioning and construction of the exact
    /// Firecracker API and guest-control vsock clients happen only after the orchestrator durably
    /// allocates [`SessionIdentity`].
    ///
    /// # Errors
    ///
    /// Returns [`ProductionBuildError`] before an owner is exposed if validation, durable writer
    /// acquisition, or backend construction fails.
    pub fn build(self) -> Result<ProductionSessionRuntime, ProductionBuildError> {
        validate_production_config(&self.config)?;
        let snapshot_id = self.firecracker_factory.snapshot_id();
        if snapshot_id.as_bytes() == [0; crate::ID_BYTES] {
            return Err(ProductionBuildError::InvalidConfig(
                "trusted snapshot identity cannot be all zeroes".to_owned(),
            ));
        }

        let mut ledger = DurableIdentityLedger::open(&self.config.durability.identity_ledger_path)
            .map_err(ProductionBuildError::IdentityLedger)?;
        let journal =
            DurableSessionRecoveryJournal::open(&self.config.durability.recovery_journal_path)
                .map_err(ProductionRecoveryError::Journal)
                .map_err(ProductionBuildError::recovery)?;
        let recovery_backend =
            LinuxFirecrackerRecovery::new(self.config.firecracker.recovery_tools)
                .map_err(ProductionBuildError::Runtime)?;
        let mut recovery = ProductionRecoveryState {
            journal,
            driver: FirecrackerRecovery::new(recovery_backend),
        };
        let mut firecracker_factory = self.firecracker_factory;
        reconcile_recovery(
            &mut ledger,
            &mut recovery,
            &self.config.firecracker.runtime,
            firecracker_factory.as_mut(),
        )?;
        let recovery = Arc::new(Mutex::new(recovery));
        let ledger = RecoveryAwareIdentityLedger::new(
            ledger,
            Arc::clone(&recovery),
            self.config.firecracker.runtime.clone(),
        );
        let orchestrator = SessionOrchestrator::with_ledger(OsEntropy, ledger);
        let kernel = Arc::new(open_authority_kernel(
            &self.config.durability.authority_audit,
            self.config.issuer,
        )?);
        let capability = AuthorityCoreBackend::new(Arc::clone(&kernel));

        let jail_root = executable_jail_root(&self.config.firecracker.runtime)?;
        let (workspace, runtime_filesystem) = new_firecracker_workspace_adapters(
            RealFileSystem::new(),
            self.config.workspace_template.clone(),
            self.config.firecracker.runtime.workspace.source.clone(),
            jail_root,
        );
        let broker_runtime_config = self.config.firecracker.runtime.clone();
        let firecracker_peer_credentials = FirecrackerPeerCredentials::new(
            broker_runtime_config.jailer_config.uid,
            broker_runtime_config.jailer_config.gid,
        );
        let deferred = DeferredFirecrackerFactory::new(
            firecracker_factory,
            runtime_filesystem,
            self.config.firecracker.runtime,
            snapshot_id,
            self.config.guest_control_endpoint,
            recovery,
        );
        let deferred_state = Arc::clone(&deferred.shared);
        let (vm, workload) = deferred.into_handles();
        let workspace = RecoveryAwareWorkspace {
            inner: workspace,
            deferred: Arc::clone(&deferred_state),
        };

        let broker_runtime_factory = ProductionBrokerRuntimeFactory {
            authority: AuthorityCoreBackend::new(kernel),
            egress_factory: self.egress_factory,
            wal_root: self.config.durability.broker_wal_root,
            limits: self.config.broker_limits,
        };
        let endpoint = self.config.broker_endpoint;
        let broker = BrokerBackend::firecracker_with_peer_credentials(
            broker_runtime_factory,
            move |identity| {
                rebind_runtime_config(&broker_runtime_config, *identity)
                    .map(|config| config.vsock.uds_path)
            },
            endpoint.host_cid,
            endpoint.expected_guest_cid,
            endpoint.port,
            endpoint.backlog,
            firecracker_peer_credentials,
        )
        .map_err(ProductionBuildError::Broker)?;
        let owner = SessionOwner::new(
            orchestrator,
            SessionBackends::new(workspace, broker, vm, capability, workload),
        );
        Ok(ProductionSessionRuntime {
            owner: Box::new(ConcreteOwnedSession {
                owner,
                snapshot: SnapshotDescriptor::clean(snapshot_id),
                workspace_template: self.config.workspace_template,
                deferred: deferred_state,
                start_attempted: false,
            }),
        })
    }
}

/// Non-cloneable synchronous owner of one fully composed host session.
pub struct ProductionSessionRuntime {
    owner: Box<dyn OwnedSession + Send>,
}

impl ProductionSessionRuntime {
    /// Returns the underlying lifecycle state.
    #[must_use]
    pub fn state(&self) -> LifecycleState {
        self.owner.state()
    }

    /// Returns the active session identity summary after startup commits.
    #[must_use]
    pub fn active_session(&self) -> Option<SessionInfo> {
        self.owner.active_session()
    }

    /// Starts the one configured session with a caller-supplied typed authority grant.
    ///
    /// # Errors
    ///
    /// Returns [`ProductionStartError`] for any lifecycle failure or repeated start attempt.
    pub fn start(
        &mut self,
        grant: &AuthorityRootGrant,
    ) -> Result<SessionInfo, ProductionStartError> {
        self.owner.start(grant)
    }

    /// Polls exact Broker health or advances retryable shutdown cleanup.
    ///
    /// # Errors
    ///
    /// Returns [`OwnerPollError`] when status is unavailable or cleanup remains incomplete.
    pub fn poll(&mut self, request: OwnerPollRequest) -> Result<OwnerPollOutcome, OwnerPollError> {
        self.owner.poll(request)
    }

    /// Requests fail-closed shutdown and retains unfinished cleanup for a later retry.
    ///
    /// # Errors
    ///
    /// Returns [`OwnerPollError`] when cleanup remains incomplete.
    pub fn stop(&mut self) -> Result<OwnerPollOutcome, OwnerPollError> {
        self.owner.stop()
    }
}

trait OwnedSession {
    fn state(&self) -> LifecycleState;
    fn active_session(&self) -> Option<SessionInfo>;
    fn start(&mut self, grant: &AuthorityRootGrant) -> Result<SessionInfo, ProductionStartError>;
    fn poll(&mut self, request: OwnerPollRequest) -> Result<OwnerPollOutcome, OwnerPollError>;
    fn stop(&mut self) -> Result<OwnerPollOutcome, OwnerPollError>;
}

type OwnedWorkspaceInner = FirecrackerWorkspaceBackend<RealFileSystem>;
type OwnedWorkspace = RecoveryAwareWorkspace;
type OwnedBroker = ProductionBrokerBackend<ProductionBrokerRuntimeFactory>;
type OwnedVm = DeferredFirecrackerVm;
type OwnedWorkload = DeferredFirecrackerWorkload;
type ConcreteSessionOwner = SessionOwner<
    OsEntropy,
    RecoveryAwareIdentityLedger,
    OwnedWorkspace,
    OwnedBroker,
    OwnedVm,
    AuthorityCoreBackend,
    OwnedWorkload,
>;

struct ConcreteOwnedSession {
    owner: ConcreteSessionOwner,
    snapshot: SnapshotDescriptor,
    workspace_template: WorkspaceTemplateId,
    deferred: Arc<Mutex<DeferredFirecrackerState>>,
    start_attempted: bool,
}

impl OwnedSession for ConcreteOwnedSession {
    fn state(&self) -> LifecycleState {
        self.owner.state()
    }

    fn active_session(&self) -> Option<SessionInfo> {
        self.owner.active_session()
    }

    fn start(&mut self, grant: &AuthorityRootGrant) -> Result<SessionInfo, ProductionStartError> {
        if self.start_attempted {
            return Err(ProductionStartError::AlreadyStarted);
        }
        {
            let mut state = lock_deferred_for_recovery(&self.deferred)
                .map_err(ProductionStartError::recovery)?;
            drain_deferred_recovery(&mut state, SessionRecoveryStage::Complete)
                .map_err(ProductionStartError::recovery)?;
            if state
                .expected_policy_digest
                .replace(grant.policy_digest())
                .is_some()
            {
                return Err(ProductionStartError::AlreadyStarted);
            }
        }
        self.start_attempted = true;
        let started = self
            .owner
            .start(&self.snapshot, &self.workspace_template, grant);
        if started.is_err() && self.owner.state() == LifecycleState::Ready {
            let mut state = lock_deferred_for_recovery(&self.deferred)
                .map_err(ProductionStartError::recovery)?;
            drain_deferred_recovery(&mut state, SessionRecoveryStage::Complete)
                .map_err(ProductionStartError::recovery)?;
        }
        started.map_err(ProductionStartError::Start)
    }

    fn poll(&mut self, request: OwnerPollRequest) -> Result<OwnerPollOutcome, OwnerPollError> {
        self.owner.poll(request)
    }

    fn stop(&mut self) -> Result<OwnerPollOutcome, OwnerPollError> {
        self.owner.stop()
    }
}

type OwnedRuntime = Runtime<
    RealCommandRunner,
    FirecrackerFileSystem<RealFileSystem>,
    UnixApiClient,
    FirecrackerVsockApiClient,
    SystemIdentitySource,
>;
type OwnedFirecrackerVm = FirecrackerVmBackend<
    RealCommandRunner,
    FirecrackerFileSystem<RealFileSystem>,
    UnixApiClient,
    FirecrackerVsockApiClient,
    SystemIdentitySource,
>;
type OwnedFirecrackerWorkload = FirecrackerWorkloadBackend<
    RealCommandRunner,
    FirecrackerFileSystem<RealFileSystem>,
    UnixApiClient,
    FirecrackerVsockApiClient,
    SystemIdentitySource,
>;

struct DeferredFirecrackerState {
    factory: Box<dyn PerSessionFirecrackerFactory>,
    filesystem: Option<FirecrackerFileSystem<RealFileSystem>>,
    base_config: RuntimeConfig,
    snapshot_id: SnapshotId,
    guest_control_endpoint: ProductionGuestControlEndpoint,
    recovery: SharedProductionRecovery,
    prepared_identity: Option<SessionIdentity>,
    expected_policy_digest: Option<AuthorityPolicyDigest>,
    vm: Option<OwnedFirecrackerVm>,
    workload: Option<OwnedFirecrackerWorkload>,
}

struct DeferredFirecrackerFactory {
    shared: Arc<Mutex<DeferredFirecrackerState>>,
}

impl DeferredFirecrackerFactory {
    fn new(
        factory: Box<dyn PerSessionFirecrackerFactory>,
        filesystem: FirecrackerFileSystem<RealFileSystem>,
        base_config: RuntimeConfig,
        snapshot_id: SnapshotId,
        guest_control_endpoint: ProductionGuestControlEndpoint,
        recovery: SharedProductionRecovery,
    ) -> Self {
        Self {
            shared: Arc::new(Mutex::new(DeferredFirecrackerState {
                factory,
                filesystem: Some(filesystem),
                base_config,
                snapshot_id,
                guest_control_endpoint,
                recovery,
                prepared_identity: None,
                expected_policy_digest: None,
                vm: None,
                workload: None,
            })),
        }
    }

    fn into_handles(self) -> (DeferredFirecrackerVm, DeferredFirecrackerWorkload) {
        (
            DeferredFirecrackerVm {
                shared: Arc::clone(&self.shared),
            },
            DeferredFirecrackerWorkload {
                shared: self.shared,
            },
        )
    }
}

struct DeferredFirecrackerVm {
    shared: Arc<Mutex<DeferredFirecrackerState>>,
}

struct DeferredFirecrackerWorkload {
    shared: Arc<Mutex<DeferredFirecrackerState>>,
}

struct RecoveryAwareWorkspace {
    inner: OwnedWorkspaceInner,
    deferred: Arc<Mutex<DeferredFirecrackerState>>,
}

impl WorkspaceBackend for RecoveryAwareWorkspace {
    fn clone_workspace(
        &mut self,
        identity: &SessionIdentity,
        template: &WorkspaceTemplateId,
    ) -> Result<WorkspaceLease, BackendError> {
        self.inner.clone_workspace(identity, template)
    }

    fn isolate_workspace(&mut self, lease: &WorkspaceLease) -> Result<(), BackendError> {
        let mut state = lock_deferred(&self.deferred)?;
        drain_deferred_recovery(&mut state, SessionRecoveryStage::ProvisioningReleased)
            .map_err(|error| recovery_backend_error(&error))?;
        self.inner.isolate_workspace(lease)?;
        drain_deferred_recovery(&mut state, SessionRecoveryStage::Complete)
            .map_err(|error| recovery_backend_error(&error))
    }
}

impl VmBackend for DeferredFirecrackerVm {
    fn start_vm(
        &mut self,
        snapshot: &SnapshotDescriptor,
        identity: &SessionIdentity,
        workspace: &WorkspaceLease,
        broker: &BrokerLease,
    ) -> Result<VmLease, BackendError> {
        let mut state = lock_deferred(&self.shared)?;
        if snapshot.snapshot_id() != state.snapshot_id {
            return Err(BackendError::new(
                "production snapshot descriptor does not match the trusted source",
            ));
        }
        if state.vm.is_none() {
            prepare_firecracker(&mut state, *identity)?;
        }
        if state.prepared_identity != Some(*identity) {
            return Err(BackendError::new(
                "prepared Firecracker resources belong to another session identity",
            ));
        }
        state
            .vm
            .as_mut()
            .ok_or_else(|| BackendError::new("prepared Firecracker VM backend disappeared"))?
            .start_vm(snapshot, identity, workspace, broker)
    }

    fn cleanup_failed_start(&mut self) -> Result<(), BackendError> {
        let mut state = lock_deferred(&self.shared)?;
        match state.vm.as_mut() {
            Some(vm) => vm.cleanup_failed_start(),
            None => Ok(()),
        }?;
        drain_deferred_recovery(&mut state, SessionRecoveryStage::ProvisioningReleased)
            .map_err(|error| recovery_backend_error(&error))
    }

    fn kill_vm(&mut self, lease: &VmLease) -> Result<(), BackendError> {
        let mut state = lock_deferred(&self.shared)?;
        state
            .vm
            .as_mut()
            .ok_or_else(|| BackendError::new("no prepared Firecracker VM owns this lease"))?
            .kill_vm(lease)?;
        drain_deferred_recovery(&mut state, SessionRecoveryStage::ProvisioningReleased)
            .map_err(|error| recovery_backend_error(&error))
    }
}

impl WorkloadBackend for DeferredFirecrackerWorkload {
    fn release_workload(
        &mut self,
        identity: &SessionIdentity,
        vm: &VmLease,
        capability: &CapabilityLease,
    ) -> Result<WorkloadLease, BackendError> {
        if capability.policy_digest().is_none() {
            return Err(BackendError::new(
                "production Firecracker workload release requires a policy-bound capability lease",
            ));
        }
        let mut state = lock_deferred(&self.shared)?;
        if state.prepared_identity != Some(*identity) {
            return Err(BackendError::new(
                "prepared guest control channel belongs to another session identity",
            ));
        }
        state
            .workload
            .as_mut()
            .ok_or_else(|| BackendError::new("prepared guest control backend disappeared"))?
            .release_workload(identity, vm, capability)
    }
}

fn lock_deferred(
    shared: &Arc<Mutex<DeferredFirecrackerState>>,
) -> Result<MutexGuard<'_, DeferredFirecrackerState>, BackendError> {
    shared.lock().map_err(|_| {
        BackendError::new("deferred Firecracker state is poisoned; refusing lifecycle operation")
    })
}

fn lock_deferred_for_recovery(
    shared: &Arc<Mutex<DeferredFirecrackerState>>,
) -> Result<MutexGuard<'_, DeferredFirecrackerState>, ProductionRecoveryError> {
    shared.lock().map_err(|_| {
        ProductionRecoveryError::IdentityMismatch(
            "deferred Firecracker state is poisoned; refusing recovery".to_owned(),
        )
    })
}

fn drain_deferred_recovery(
    state: &mut DeferredFirecrackerState,
    target: SessionRecoveryStage,
) -> Result<(), ProductionRecoveryError> {
    let shared_recovery = Arc::clone(&state.recovery);
    let base_config = state.base_config.clone();
    let mut recovery = shared_recovery.lock().map_err(|_| {
        ProductionRecoveryError::IdentityMismatch(
            "session recovery state is poisoned; refusing cleanup".to_owned(),
        )
    })?;
    drain_recovery_to(&mut recovery, &base_config, state.factory.as_mut(), target)
}

fn recovery_backend_error(error: &ProductionRecoveryError) -> BackendError {
    BackendError::new(error.to_string())
}

fn prepare_firecracker(
    state: &mut DeferredFirecrackerState,
    identity: SessionIdentity,
) -> Result<(), BackendError> {
    let policy_digest = state.expected_policy_digest.ok_or_else(|| {
        BackendError::new(
            "production Firecracker preparation requires the exact session policy digest",
        )
    })?;
    let runtime_config = rebind_runtime_config(&state.base_config, identity)?;
    let jail_root = session_jail_root(&runtime_config)?;
    let request = SessionFirecrackerRequest {
        identity,
        runtime_config,
        snapshot_id: state.snapshot_id,
        snapshot_path: jail_root.join("snapshots/state"),
        memory_path: jail_root.join("snapshots/memory"),
        guest_control_port: state.guest_control_endpoint.port,
        policy_digest,
    };
    let prepared = state.factory.prepare(&request)?;
    if prepared.identity != identity
        || prepared.runtime_config != request.runtime_config
        || prepared.snapshot_id != request.snapshot_id
    {
        return Err(BackendError::new(
            "Firecracker factory returned a proof for another session request",
        ));
    }
    let backend_template =
        verified_backend_template(&state.base_config, identity, &prepared.runtime_config)?;
    let firecracker_api = firecracker_api_for(&prepared.runtime_config)?;
    let guest_control = guest_control_for(&prepared.runtime_config, state.guest_control_endpoint)?;
    let filesystem = state.filesystem.take().ok_or_else(|| {
        BackendError::new("session Runtime filesystem was already consumed by another preparation")
    })?;
    let runtime: OwnedRuntime = Runtime::new(
        RealCommandRunner::new(),
        filesystem,
        firecracker_api,
        guest_control,
        SystemIdentitySource,
    );
    let (vm, workload) = new_firecracker_backends(
        runtime,
        backend_template,
        prepared.snapshot,
        prepared.snapshot_id,
    );
    state.prepared_identity = Some(identity);
    state.vm = Some(vm);
    state.workload = Some(workload);
    Ok(())
}

fn firecracker_api_for(config: &RuntimeConfig) -> Result<UnixApiClient, BackendError> {
    UnixApiClient::new(config.api_socket.clone()).map_err(|error| {
        BackendError::new(format!(
            "verified Firecracker API socket is not usable: {error}"
        ))
    })
}

fn guest_control_for(
    config: &RuntimeConfig,
    endpoint: ProductionGuestControlEndpoint,
) -> Result<FirecrackerVsockApiClient, BackendError> {
    FirecrackerVsockApiClient::new(
        config.vsock.uds_path.clone(),
        config.vsock.guest_cid,
        endpoint.port,
    )
    .map_err(|error| {
        BackendError::new(format!(
            "verified guest-control vsock endpoint is not usable: {error}"
        ))
    })
}

fn verified_backend_template(
    template: &RuntimeConfig,
    identity: SessionIdentity,
    prepared: &RuntimeConfig,
) -> Result<RuntimeConfig, BackendError> {
    let execution_config = rebind_runtime_config(template, identity)?;
    if execution_config != *prepared {
        return Err(BackendError::new(
            "prepared Firecracker config does not equal the backend's exact execution config",
        ));
    }
    // FirecrackerVmBackend performs the one session rebind immediately before restore. Passing
    // `prepared` here would append session-scoped fields such as the dm-verity mapper twice.
    Ok(template.clone())
}

struct ProductionBrokerRuntimeFactory {
    authority: AuthorityCoreBackend,
    egress_factory: Arc<dyn PerSessionEgressFactory>,
    wal_root: PathBuf,
    limits: ProductionBrokerLimits,
}

impl<S> BrokerRuntimeFactory<S> for ProductionBrokerRuntimeFactory
where
    S: DeadlineStream + Send + 'static,
{
    type Runtime = BuiltBrokerRuntime<Box<dyn FnMut() -> MonotonicTime + Send>>;

    fn build(&self, identity: &SessionIdentity) -> Result<Self::Runtime, BackendError> {
        let wal_path = self
            .wal_root
            .join(format!("{}.wal", identity.broker_session_id()));
        match fs::symlink_metadata(&wal_path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Ok(_) => {
                return Err(BackendError::new(format!(
                    "Broker WAL path already exists for fresh session identity: {}",
                    wal_path.display()
                )));
            }
            Err(error) => {
                return Err(BackendError::new(format!(
                    "Broker WAL path cannot be inspected before creation: {}: {error}",
                    wal_path.display()
                )));
            }
        }
        let request = SessionEgressRequest {
            identity: *identity,
        };
        let prepared = self.egress_factory.prepare(&request)?;
        if !prepared.matches(&request) {
            return Err(BackendError::new(
                "egress factory returned a proof for another session request",
            ));
        }
        match fs::symlink_metadata(&wal_path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Ok(_) => {
                return Err(BackendError::new(format!(
                    "host-owned durable Broker dispatcher creation failed: egress factory created the reserved WAL path: {}",
                    wal_path.display()
                )));
            }
            Err(error) => {
                return Err(BackendError::new(format!(
                    "host-owned durable Broker dispatcher creation failed: reserved WAL path cannot be re-inspected: {}: {error}",
                    wal_path.display()
                )));
            }
        }
        let authority = self.authority.broker_binding(identity);
        let context = DispatchContext {
            caller: authority.caller,
            capability: authority.capability,
            now: MonotonicTime::from_ticks(0),
        };
        let durable_config = DurableSessionConfig::new(
            WireBrokerSessionId::new(identity.broker_session_id().as_bytes()),
            self.limits.replay_capacity,
            SessionBudgetLimits::new(
                self.limits.budget_requests,
                self.limits.budget_response_bytes,
                self.limits.budget_concurrent,
            ),
        );
        let dispatcher = match BrokerDispatcher::new_durable(
            self.authority.broker_executor(),
            prepared.public_adapter,
            prepared.github_adapter,
            durable_config,
            self.limits.github_response_cap,
            &wal_path,
        ) {
            Ok(dispatcher) => dispatcher,
            Err(error) => {
                let cleanup = remove_unstarted_broker_wal(&wal_path);
                return Err(BackendError::new(match cleanup {
                    Ok(()) => {
                        format!("host-owned durable Broker dispatcher creation failed: {error}")
                    }
                    Err(cleanup) => format!(
                        "host-owned durable Broker dispatcher creation failed: {error}; removing its unleased WAL also failed: {cleanup}"
                    ),
                }));
            }
        };
        Ok(BuiltBrokerRuntime::new(
            Box::new(dispatcher),
            context,
            prepared.clock,
            self.limits.max_connection_requests,
        ))
    }

    fn discard_unstarted(&self, identity: &SessionIdentity) -> Result<(), BackendError> {
        remove_unstarted_broker_wal(
            &self
                .wal_root
                .join(format!("{}.wal", identity.broker_session_id())),
        )
    }
}

fn remove_unstarted_broker_wal(path: &Path) -> Result<(), BackendError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(BackendError::new(format!(
                "cannot inspect unstarted Broker WAL {}: {error}",
                path.display()
            )));
        }
    };
    #[cfg(unix)]
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.nlink() != 1
        || (metadata.uid() != 0 && metadata.uid() != rustix::process::geteuid().as_raw())
    {
        return Err(BackendError::new(format!(
            "unstarted Broker WAL ownership is ambiguous and will not be removed: {}",
            path.display()
        )));
    }
    #[cfg(not(unix))]
    if !metadata.is_file() {
        return Err(BackendError::new(format!(
            "unstarted Broker WAL is not a regular file: {}",
            path.display()
        )));
    }
    fs::remove_file(path).map_err(|error| {
        BackendError::new(format!(
            "cannot remove unstarted Broker WAL {}: {error}",
            path.display()
        ))
    })
}

/// Attaches capability state to the configured authority journal.
///
/// Host resource recovery runs before this, so by the time an existing journal is reopened the
/// instance that wrote it no longer owns any session resource this kernel could collide with.
fn open_authority_kernel(
    mode: &AuthorityAuditMode,
    issuer: IssuerId,
) -> Result<CapabilityKernel, ProductionBuildError> {
    let state = CapabilityState::new(issuer);
    match mode {
        AuthorityAuditMode::CreateNew(path) => {
            let audit =
                DurableAuditLog::create(path).map_err(ProductionBuildError::AuthorityAudit)?;
            CapabilityKernel::try_new_with_durable_audit(state, audit)
                .map_err(ProductionBuildError::AuthorityKernel)
        }
        AuthorityAuditMode::OpenExisting(path) => {
            let audit =
                DurableAuditLog::open(path).map_err(ProductionBuildError::AuthorityAudit)?;
            CapabilityKernel::try_recover_with_durable_audit(state, audit)
                .map(|(kernel, _recovery)| kernel)
                .map_err(ProductionBuildError::AuthorityKernel)
        }
    }
}

fn validate_production_config(
    config: &ProductionSessionConfig,
) -> Result<(), ProductionBuildError> {
    config
        .firecracker
        .runtime
        .validate()
        .map_err(ProductionBuildError::Runtime)?;
    for (label, path) in [
        (
            "identity ledger",
            config.durability.identity_ledger_path.as_path(),
        ),
        (
            "session recovery WAL",
            config.durability.recovery_journal_path.as_path(),
        ),
        (
            "authority audit WAL",
            config.durability.authority_audit.path(),
        ),
        (
            "Broker WAL root",
            config.durability.broker_wal_root.as_path(),
        ),
    ] {
        validate_owned_absolute_path(label, path)?;
    }
    if config.durability.identity_ledger_path == config.durability.authority_audit.path() {
        return Err(ProductionBuildError::InvalidConfig(
            "identity ledger and authority audit WAL must use distinct paths".to_owned(),
        ));
    }
    validate_durability_path_separation(config)?;
    let broker_root_metadata =
        fs::symlink_metadata(&config.durability.broker_wal_root).map_err(|error| {
            ProductionBuildError::InvalidConfig(format!(
                "Broker WAL root cannot be inspected: {}: {error}",
                config.durability.broker_wal_root.display()
            ))
        })?;
    if broker_root_metadata.file_type().is_symlink() || !broker_root_metadata.is_dir() {
        return Err(ProductionBuildError::InvalidConfig(format!(
            "Broker WAL root must be an existing non-symlink directory: {}",
            config.durability.broker_wal_root.display()
        )));
    }
    if config.broker_endpoint.expected_guest_cid != config.firecracker.runtime.vsock.guest_cid {
        return Err(ProductionBuildError::InvalidConfig(
            "Broker guest CID must equal the Firecracker vsock guest CID".to_owned(),
        ));
    }
    if config.guest_control_endpoint.port == 0 || config.guest_control_endpoint.port == u32::MAX {
        return Err(ProductionBuildError::InvalidConfig(
            "guest-control vsock port must be explicit, non-zero, and non-wildcard".to_owned(),
        ));
    }
    validate_production_broker_limits(config.broker_limits)
}

fn validate_production_broker_limits(
    limits: ProductionBrokerLimits,
) -> Result<(), ProductionBuildError> {
    if limits.budget_response_bytes == 0 || limits.github_response_cap == 0 {
        return Err(ProductionBuildError::InvalidConfig(
            "Broker response budgets and provider cap must be non-zero".to_owned(),
        ));
    }
    if limits.budget_response_bytes > MAX_PRODUCTION_BROKER_RESPONSE_BUDGET_BYTES {
        return Err(ProductionBuildError::InvalidConfig(format!(
            "Broker response budget {} exceeds the durable-WAL-safe maximum {MAX_PRODUCTION_BROKER_RESPONSE_BUDGET_BYTES}",
            limits.budget_response_bytes
        )));
    }
    if limits.replay_capacity.get() > MAX_PRODUCTION_BROKER_REPLAY_CAPACITY {
        return Err(ProductionBuildError::InvalidConfig(format!(
            "Broker replay capacity {} exceeds the production maximum {}",
            limits.replay_capacity, MAX_PRODUCTION_BROKER_REPLAY_CAPACITY
        )));
    }
    if limits.max_connection_requests.get() > MAX_PRODUCTION_BROKER_CONNECTION_REQUESTS {
        return Err(ProductionBuildError::InvalidConfig(format!(
            "Broker connection request ceiling {} exceeds the production maximum {}",
            limits.max_connection_requests, MAX_PRODUCTION_BROKER_CONNECTION_REQUESTS
        )));
    }
    if limits.budget_concurrent.get() > MAX_PRODUCTION_BROKER_CONCURRENT_REQUESTS {
        return Err(ProductionBuildError::InvalidConfig(format!(
            "Broker concurrent request limit {} exceeds the production maximum {}",
            limits.budget_concurrent, MAX_PRODUCTION_BROKER_CONCURRENT_REQUESTS
        )));
    }
    let replay_requests = u64::try_from(limits.replay_capacity.get()).map_err(|_| {
        ProductionBuildError::InvalidConfig(
            "Broker replay capacity does not fit the durable request budget".to_owned(),
        )
    })?;
    if replay_requests > limits.budget_requests.get() {
        return Err(ProductionBuildError::InvalidConfig(
            "Broker replay capacity exceeds the durable request budget".to_owned(),
        ));
    }
    if limits.replay_capacity.get() < limits.max_connection_requests.get() {
        return Err(ProductionBuildError::InvalidConfig(
            "Broker replay capacity must cover the connection request ceiling".to_owned(),
        ));
    }
    let connection_requests =
        u64::try_from(limits.max_connection_requests.get()).map_err(|_| {
            ProductionBuildError::InvalidConfig(
                "Broker connection request ceiling does not fit the durable budget".to_owned(),
            )
        })?;
    if connection_requests > limits.budget_requests.get() {
        return Err(ProductionBuildError::InvalidConfig(
            "Broker connection request ceiling exceeds the durable request budget".to_owned(),
        ));
    }
    Ok(())
}

#[derive(Debug)]
struct ComparedPath {
    label: &'static str,
    lexical: PathBuf,
    resolved: PathBuf,
}

impl ComparedPath {
    fn new(label: &'static str, path: &Path) -> Result<Self, ProductionBuildError> {
        let lexical = normalize_absolute_path(label, path)?;
        let resolved = resolve_from_existing_ancestor(label, &lexical)?;
        Ok(Self {
            label,
            lexical,
            resolved,
        })
    }
}

fn validate_durability_path_separation(
    config: &ProductionSessionConfig,
) -> Result<(), ProductionBuildError> {
    let durability = [
        ComparedPath::new("identity ledger", &config.durability.identity_ledger_path)?,
        ComparedPath::new(
            "session recovery WAL",
            &config.durability.recovery_journal_path,
        )?,
        ComparedPath::new(
            "authority audit WAL",
            config.durability.authority_audit.path(),
        )?,
        ComparedPath::new("Broker WAL root", &config.durability.broker_wal_root)?,
    ];
    for (index, left) in durability.iter().enumerate() {
        for right in durability.iter().skip(index + 1) {
            require_disjoint(left, right)?;
        }
    }

    let runtime_paths = [
        ComparedPath::new(
            "workspace template source",
            &config.firecracker.runtime.workspace.source,
        )?,
        ComparedPath::new(
            "workspace clone tree",
            &config.firecracker.runtime.workspace.clone_root,
        )?,
        ComparedPath::new(
            "Firecracker jail tree",
            &config.firecracker.runtime.jailer_config.chroot_base_dir,
        )?,
        ComparedPath::new(
            "Firecracker executable",
            &config.firecracker.runtime.firecracker.path,
        )?,
        ComparedPath::new("kernel artifact", &config.firecracker.runtime.kernel.path)?,
        ComparedPath::new("rootfs artifact", &config.firecracker.runtime.rootfs.path)?,
        ComparedPath::new(
            "dm-verity hash artifact",
            &config.firecracker.runtime.verity_hash.path,
        )?,
        ComparedPath::new("jailer executable", &config.firecracker.runtime.jailer.path)?,
        ComparedPath::new(
            "seccomp filter artifact",
            &config.firecracker.runtime.isolation.seccomp.filter.path,
        )?,
        ComparedPath::new(
            "Firecracker API socket",
            &config.firecracker.runtime.api_socket,
        )?,
        ComparedPath::new(
            "Firecracker vsock socket",
            &config.firecracker.runtime.vsock.uds_path,
        )?,
        ComparedPath::new(
            "jailed dm-verity device",
            &config.firecracker.runtime.dm_verity.jailed_device_path,
        )?,
        ComparedPath::new(
            "Firecracker cgroup",
            &config.firecracker.runtime.isolation.cgroup.path,
        )?,
    ];
    for durable in &durability {
        for runtime in &runtime_paths {
            require_disjoint(durable, runtime)?;
        }
    }
    Ok(())
}

fn normalize_absolute_path(
    label: &'static str,
    path: &Path,
) -> Result<PathBuf, ProductionBuildError> {
    if !path.is_absolute() {
        return Err(ProductionBuildError::InvalidConfig(format!(
            "{label} path must be absolute: {}",
            path.display()
        )));
    }
    let mut normalized = PathBuf::from("/");
    for component in path.components() {
        match component {
            Component::RootDir | Component::CurDir => {}
            Component::Normal(component) => normalized.push(component),
            Component::ParentDir | Component::Prefix(_) => {
                return Err(ProductionBuildError::InvalidConfig(format!(
                    "{label} path contains a non-normal component: {}",
                    path.display()
                )));
            }
        }
    }
    Ok(normalized)
}

fn resolve_from_existing_ancestor(
    label: &'static str,
    path: &Path,
) -> Result<PathBuf, ProductionBuildError> {
    let mut ancestor = path;
    let mut missing = Vec::new();
    loop {
        match fs::symlink_metadata(ancestor) {
            Ok(_) => {
                let mut resolved = fs::canonicalize(ancestor).map_err(|error| {
                    ProductionBuildError::InvalidConfig(format!(
                        "{label} existing ancestor cannot be canonicalized: {}: {error}",
                        ancestor.display()
                    ))
                })?;
                if !missing.is_empty()
                    && !fs::metadata(&resolved)
                        .map_err(|error| {
                            ProductionBuildError::InvalidConfig(format!(
                                "{label} resolved ancestor cannot be inspected: {}: {error}",
                                resolved.display()
                            ))
                        })?
                        .is_dir()
                {
                    return Err(ProductionBuildError::InvalidConfig(format!(
                        "{label} path descends from a non-directory: {}",
                        resolved.display()
                    )));
                }
                for component in missing.iter().rev() {
                    resolved.push(component);
                }
                return Ok(resolved);
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let component = ancestor.file_name().ok_or_else(|| {
                    ProductionBuildError::InvalidConfig(format!(
                        "{label} path has no canonicalizable existing ancestor: {}",
                        path.display()
                    ))
                })?;
                missing.push(component.to_os_string());
                ancestor = ancestor.parent().ok_or_else(|| {
                    ProductionBuildError::InvalidConfig(format!(
                        "{label} path has no parent: {}",
                        path.display()
                    ))
                })?;
            }
            Err(error) => {
                return Err(ProductionBuildError::InvalidConfig(format!(
                    "{label} path ancestor cannot be inspected: {}: {error}",
                    ancestor.display()
                )));
            }
        }
    }
}

fn require_disjoint(left: &ComparedPath, right: &ComparedPath) -> Result<(), ProductionBuildError> {
    let lexical_overlap = paths_overlap(&left.lexical, &right.lexical);
    let resolved_overlap = paths_overlap(&left.resolved, &right.resolved);
    if lexical_overlap || resolved_overlap {
        return Err(ProductionBuildError::InvalidConfig(format!(
            "{} and {} paths must be disjoint: {} and {}",
            left.label,
            right.label,
            left.lexical.display(),
            right.lexical.display()
        )));
    }
    Ok(())
}

fn paths_overlap(left: &Path, right: &Path) -> bool {
    left == right || left.starts_with(right) || right.starts_with(left)
}

fn validate_owned_absolute_path(label: &str, path: &Path) -> Result<(), ProductionBuildError> {
    if !path.is_absolute() || path == Path::new("/") {
        return Err(ProductionBuildError::InvalidConfig(format!(
            "{label} path must be absolute and cannot be the host root: {}",
            path.display()
        )));
    }
    if path.components().any(|component| {
        matches!(
            component,
            Component::ParentDir | Component::CurDir | Component::Prefix(_)
        )
    }) {
        return Err(ProductionBuildError::InvalidConfig(format!(
            "{label} path contains a non-normal component: {}",
            path.display()
        )));
    }
    Ok(())
}

fn executable_jail_root(config: &RuntimeConfig) -> Result<PathBuf, ProductionBuildError> {
    let executable = config
        .firecracker
        .path
        .file_name()
        .filter(|name| !name.is_empty())
        .ok_or_else(|| {
            ProductionBuildError::InvalidConfig(
                "Firecracker executable path has no filename".to_owned(),
            )
        })?;
    Ok(config.jailer_config.chroot_base_dir.join(executable))
}

fn session_jail_root(config: &RuntimeConfig) -> Result<PathBuf, BackendError> {
    let executable = config
        .firecracker
        .path
        .file_name()
        .filter(|name| !name.is_empty())
        .ok_or_else(|| BackendError::new("Firecracker executable path has no filename"))?;
    Ok(config
        .jailer_config
        .chroot_base_dir
        .join(executable)
        .join(&config.workspace.clone_id)
        .join("root"))
}

fn rebind_runtime_config(
    base: &RuntimeConfig,
    identity: SessionIdentity,
) -> Result<RuntimeConfig, BackendError> {
    let clone_id = identity.workspace_id().to_string();
    let old_root = session_jail_root(base)?;
    let mut rebound = base.clone();
    rebound.workspace.clone_id.clone_from(&clone_id);
    let new_root = session_jail_root(&rebound)?;
    rebound.kernel.path = rebind_jail_path("kernel", &base.kernel.path, &old_root, &new_root)?;
    rebound.workspace.clone_root = rebind_jail_path(
        "workspace clone root",
        &base.workspace.clone_root,
        &old_root,
        &new_root,
    )?;
    rebound.api_socket = rebind_jail_path("API socket", &base.api_socket, &old_root, &new_root)?;
    rebound.isolation.seccomp.filter.path = rebind_jail_path(
        "seccomp filter",
        &base.isolation.seccomp.filter.path,
        &old_root,
        &new_root,
    )?;
    rebound.vsock.uds_path =
        rebind_jail_path("vsock UDS", &base.vsock.uds_path, &old_root, &new_root)?;
    rebound.dm_verity.jailed_device_path = rebind_jail_path(
        "jailed dm-verity device",
        &base.dm_verity.jailed_device_path,
        &old_root,
        &new_root,
    )?;
    rebound.isolation.cgroup.path = rebind_cgroup_path(
        &base.isolation.cgroup.path,
        &base.workspace.clone_id,
        &clone_id,
    )?;
    rebound.dm_verity.mapper_name = format!("{}-{clone_id}", base.dm_verity.mapper_name);
    rebound.validate().map_err(|error| {
        BackendError::new(format!("session Runtime config is invalid: {error}"))
    })?;
    Ok(rebound)
}

fn rebind_jail_path(
    label: &str,
    path: &Path,
    old_root: &Path,
    new_root: &Path,
) -> Result<PathBuf, BackendError> {
    let relative = path.strip_prefix(old_root).map_err(|_| {
        BackendError::new(format!(
            "configured {label} path is outside the template jail root: {}",
            path.display()
        ))
    })?;
    Ok(new_root.join(relative))
}

fn rebind_cgroup_path(
    path: &Path,
    old_clone_id: &str,
    new_clone_id: &str,
) -> Result<PathBuf, BackendError> {
    if path.file_name().and_then(|name| name.to_str()) != Some(old_clone_id) {
        return Err(BackendError::new(format!(
            "configured cgroup path is not bound to template clone ID `{old_clone_id}`: {}",
            path.display()
        )));
    }
    let parent = path
        .parent()
        .ok_or_else(|| BackendError::new("configured cgroup path has no parent"))?;
    Ok(parent.join(new_clone_id))
}

#[cfg(test)]
mod tests {
    use std::{
        sync::atomic::{AtomicU64, Ordering},
        thread::sleep,
        time::{Duration, Instant, SystemTime, UNIX_EPOCH},
    };

    use egress_broker::durable::DurableBrokerView;
    use firecracker_runtime::{
        ApiResponse, CgroupConfig, CgroupVersion, CommandOutput, CommandRunner, CommandSpec,
        DmVerityConfig, FileSystem, HostIsolationConfig, JailerConfig, NamespaceConfig,
        PinnedArtifact, ProcessHandle, ProcessOwnership, SeccompConfig, Sha256Digest, VsockConfig,
        WorkspaceConfig, WorkspaceImageConfig, sha256,
    };

    use super::*;
    use crate::filesystem_factory::{
        FilesystemFirecrackerFactory, GuestArtifactTemplate, SnapshotTemplate,
    };
    use crate::recovery::SessionRecoveryLease;
    use crate::{IdentityKind, IdentityLedger};

    struct TestApi;

    impl ApiClient for TestApi {
        fn request(&mut self, _request: &ApiRequest) -> Result<ApiResponse, RuntimeError> {
            Ok(ApiResponse {
                status: 204,
                body: String::new(),
            })
        }
    }

    #[derive(Default)]
    struct ExecutionCapture {
        block_device_bind: Option<(PathBuf, PathBuf)>,
        block_binding: Option<(PathBuf, PathBuf)>,
        cloned_workspace: Option<(PathBuf, PathBuf)>,
        workspace_image: Option<(PathBuf, PathBuf, u64)>,
        ownership: Option<ProcessOwnership>,
        restored_resources: Option<(PathBuf, PathBuf, u32)>,
    }

    struct ExecutionRunner {
        capture: Arc<Mutex<ExecutionCapture>>,
    }

    impl CommandRunner for ExecutionRunner {
        fn run(&mut self, _command: &CommandSpec) -> Result<CommandOutput, RuntimeError> {
            Ok(CommandOutput {
                status: 0,
                stdout: Vec::new(),
                stderr: Vec::new(),
            })
        }

        fn start(&mut self, _command: &CommandSpec) -> Result<ProcessHandle, RuntimeError> {
            Err(RuntimeError::Command(
                "test requires owned Firecracker startup".to_owned(),
            ))
        }

        fn verify_verity(
            &mut self,
            _veritysetup: &PinnedArtifact,
            _expected: &DmVerityConfig,
        ) -> Result<(), RuntimeError> {
            Ok(())
        }

        fn start_owned(
            &mut self,
            _command: &CommandSpec,
            ownership: &ProcessOwnership,
        ) -> Result<ProcessHandle, RuntimeError> {
            self.capture
                .lock()
                .expect("execution capture must not be poisoned")
                .ownership = Some(ownership.clone());
            Ok(ProcessHandle { pid: 41 })
        }

        fn verify_running(&mut self, _process: ProcessHandle) -> Result<(), RuntimeError> {
            Ok(())
        }

        fn stop(&mut self, _process: ProcessHandle) -> Result<(), RuntimeError> {
            Ok(())
        }
    }

    struct ExecutionFileSystem {
        capture: Arc<Mutex<ExecutionCapture>>,
    }

    impl FileSystem for ExecutionFileSystem {
        fn read(&mut self, _path: &Path) -> Result<Vec<u8>, RuntimeError> {
            Ok(b"pinned".to_vec())
        }

        fn bind_block_device(
            &mut self,
            source: &Path,
            jailed_device: &Path,
        ) -> Result<(), RuntimeError> {
            self.capture
                .lock()
                .expect("execution capture must not be poisoned")
                .block_device_bind = Some((source.to_owned(), jailed_device.to_owned()));
            Ok(())
        }

        fn unbind_block_device(
            &mut self,
            _source: &Path,
            _jailed_device: &Path,
        ) -> Result<(), RuntimeError> {
            Ok(())
        }

        fn verify_block_device_binding(
            &mut self,
            source: &Path,
            jailed_device: &Path,
        ) -> Result<(), RuntimeError> {
            self.capture
                .lock()
                .expect("execution capture must not be poisoned")
                .block_binding = Some((source.to_owned(), jailed_device.to_owned()));
            Ok(())
        }

        fn clone_workspace(
            &mut self,
            source: &Path,
            destination: &Path,
        ) -> Result<(), RuntimeError> {
            self.capture
                .lock()
                .expect("execution capture must not be poisoned")
                .cloned_workspace = Some((source.to_owned(), destination.to_owned()));
            Ok(())
        }

        fn create_workspace_image(
            &mut self,
            workspace: &Path,
            image: &Path,
            size_bytes: u64,
        ) -> Result<(), RuntimeError> {
            self.capture
                .lock()
                .expect("execution capture must not be poisoned")
                .workspace_image = Some((workspace.to_owned(), image.to_owned(), size_bytes));
            Ok(())
        }

        fn remove_workspace(&mut self, _path: &Path) -> Result<(), RuntimeError> {
            Ok(())
        }
    }

    struct ExecutionApi {
        capture: Arc<Mutex<ExecutionCapture>>,
    }

    impl ApiClient for ExecutionApi {
        fn request(&mut self, _request: &ApiRequest) -> Result<ApiResponse, RuntimeError> {
            Ok(ApiResponse {
                status: 204,
                body: String::new(),
            })
        }

        fn verify_restore_resources(
            &mut self,
            workspace_path: &Path,
            vsock_uds_path: &Path,
            guest_cid: u32,
        ) -> Result<(), RuntimeError> {
            self.capture
                .lock()
                .expect("execution capture must not be poisoned")
                .restored_resources = Some((
                workspace_path.to_owned(),
                vsock_uds_path.to_owned(),
                guest_cid,
            ));
            Ok(())
        }
    }

    struct TestFirecrackerFactory {
        snapshot_id: SnapshotId,
    }

    impl PerSessionFirecrackerFactory for TestFirecrackerFactory {
        fn snapshot_id(&self) -> SnapshotId {
            self.snapshot_id
        }

        fn prepare(
            &mut self,
            _request: &SessionFirecrackerRequest,
        ) -> Result<PreparedFirecrackerSession, BackendError> {
            Err(BackendError::new("test factory must not run during build"))
        }

        fn recover_provisioning(
            &mut self,
            _request: &SessionFirecrackerRecoveryRequest,
        ) -> Result<(), BackendError> {
            Ok(())
        }
    }

    struct FailingRecoveryFactory {
        snapshot_id: SnapshotId,
        attempts: Arc<AtomicU64>,
    }

    struct RecordingRecoveryFactory {
        snapshot_id: SnapshotId,
        attempts: Arc<AtomicU64>,
    }

    impl PerSessionFirecrackerFactory for RecordingRecoveryFactory {
        fn snapshot_id(&self) -> SnapshotId {
            self.snapshot_id
        }

        fn prepare(
            &mut self,
            _request: &SessionFirecrackerRequest,
        ) -> Result<PreparedFirecrackerSession, BackendError> {
            Err(BackendError::new(
                "test factory must not prepare during recovery",
            ))
        }

        fn recover_provisioning(
            &mut self,
            _request: &SessionFirecrackerRecoveryRequest,
        ) -> Result<(), BackendError> {
            self.attempts.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
    }

    impl PerSessionFirecrackerFactory for FailingRecoveryFactory {
        fn snapshot_id(&self) -> SnapshotId {
            self.snapshot_id
        }

        fn prepare(
            &mut self,
            _request: &SessionFirecrackerRequest,
        ) -> Result<PreparedFirecrackerSession, BackendError> {
            Err(BackendError::new(
                "test factory must not prepare during recovery",
            ))
        }

        fn recover_provisioning(
            &mut self,
            _request: &SessionFirecrackerRecoveryRequest,
        ) -> Result<(), BackendError> {
            self.attempts.fetch_add(1, Ordering::Relaxed);
            Err(BackendError::new(
                "factory provisioning cleanup remains incomplete",
            ))
        }
    }

    struct TestEgressFactory;

    impl PerSessionEgressFactory for TestEgressFactory {
        fn prepare(
            &self,
            _request: &SessionEgressRequest,
        ) -> Result<PreparedEgressSession, BackendError> {
            Err(BackendError::new("test factory must not run during build"))
        }
    }

    struct TestPublicAdapter;

    impl PublicDispatchAdapter for TestPublicAdapter {
        fn fetch(
            &self,
            _request: &authority_core::http::HttpFetchRequest,
            _authority: &authority_core::http::HttpFetchAuthority,
        ) -> Result<
            egress_broker::public_fetch::PublicResponse,
            egress_broker::public_fetch::FetchError,
        > {
            Err(egress_broker::public_fetch::FetchError::OperationRejected)
        }
    }

    struct TestGitHubAdapter;

    impl GitHubAdapter for TestGitHubAdapter {
        fn execute(
            &mut self,
            _request_id: egress_protocol::session::BrokerRequestId,
            _request: &authority_core::github::GitHubRequest,
            _authority: &authority_core::github::GitHubAuthority,
            _max_response_bytes: u64,
        ) -> Result<egress_broker::github::GitHubResponse, egress_broker::github::GitHubAdapterError>
        {
            Err(egress_broker::github::GitHubAdapterError::NotAuthorized)
        }
    }

    struct ObservedEgressRequest {
        identity: SessionIdentity,
        wal_absent_during_prepare: bool,
    }

    struct CapturingEgressFactory {
        expected_wal: PathBuf,
        observed: Arc<Mutex<Option<ObservedEgressRequest>>>,
    }

    impl PerSessionEgressFactory for CapturingEgressFactory {
        fn prepare(
            &self,
            request: &SessionEgressRequest,
        ) -> Result<PreparedEgressSession, BackendError> {
            *self
                .observed
                .lock()
                .map_err(|_| BackendError::new("test observation mutex is poisoned"))? =
                Some(ObservedEgressRequest {
                    identity: request.identity(),
                    wal_absent_during_prepare: matches!(
                        fs::symlink_metadata(&self.expected_wal),
                        Err(error) if error.kind() == std::io::ErrorKind::NotFound
                    ),
                });
            Ok(PreparedEgressSession::new(
                request,
                TestPublicAdapter,
                TestGitHubAdapter,
                || MonotonicTime::from_ticks(1),
            ))
        }
    }

    struct PrecreatingEgressFactory {
        wal_path: PathBuf,
    }

    impl PerSessionEgressFactory for PrecreatingEgressFactory {
        fn prepare(
            &self,
            request: &SessionEgressRequest,
        ) -> Result<PreparedEgressSession, BackendError> {
            fs::write(&self.wal_path, b"factory-controlled")
                .map_err(|error| BackendError::new(format!("test precreation failed: {error}")))?;
            Ok(PreparedEgressSession::new(
                request,
                TestPublicAdapter,
                TestGitHubAdapter,
                || MonotonicTime::from_ticks(1),
            ))
        }
    }

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system clock must follow the epoch")
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "session-production-runtime-{}-{nonce}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).expect("unique test directory must be creatable");
            Self(path)
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn artifact(path: impl Into<PathBuf>) -> PinnedArtifact {
        PinnedArtifact::new(path, sha256(b"pinned"))
    }

    fn recovery_tools(root: &Path) -> RecoveryTools {
        let veritysetup = root.join("veritysetup-v1");
        let dmsetup = root.join("dmsetup-v1");
        fs::write(&veritysetup, b"pinned").expect("recovery tool fixture must be writable");
        fs::write(&dmsetup, b"pinned").expect("recovery tool fixture must be writable");
        RecoveryTools::new(artifact(veritysetup), artifact(dmsetup))
    }

    fn cgroup_parent() -> PathBuf {
        PathBuf::from("/sys/fs/cgroup/session-runtime")
    }

    fn recovery_platform_or_skip() -> bool {
        let Ok(mountinfo) = fs::read_to_string("/proc/self/mountinfo") else {
            eprintln!("skipping recovery composition: /proc/self/mountinfo is unavailable");
            return false;
        };
        let cgroup2 = mountinfo.lines().any(|line| {
            let Some((mount, filesystem)) = line.split_once(" - ") else {
                return false;
            };
            mount.split_ascii_whitespace().nth(4) == Some("/sys/fs/cgroup")
                && filesystem.split_ascii_whitespace().next() == Some("cgroup2")
        });
        if !cgroup2 {
            eprintln!("skipping recovery composition: /sys/fs/cgroup is not cgroup2");
            return false;
        }
        let parent = cgroup_parent();
        let Ok(metadata) = fs::symlink_metadata(&parent) else {
            eprintln!(
                "skipping recovery composition: production-valid cgroup parent is absent: {}",
                parent.display()
            );
            return false;
        };
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt as _;

            let effective_uid = fs::read_to_string("/proc/self/status")
                .ok()
                .and_then(|status| {
                    status
                        .lines()
                        .find_map(|line| line.strip_prefix("Uid:"))
                        .and_then(|uids| uids.split_ascii_whitespace().nth(1))
                        .and_then(|uid| uid.parse::<u32>().ok())
                });
            if metadata.file_type().is_symlink()
                || !metadata.is_dir()
                || metadata.mode() & 0o022 != 0
                || !matches!(effective_uid, Some(uid) if metadata.uid() == 0 || metadata.uid() == uid)
            {
                eprintln!(
                    "skipping recovery composition: cgroup parent is not a stable trusted directory: {}",
                    parent.display()
                );
                return false;
            }
        }
        true
    }

    fn runtime_config(root: &Path) -> RuntimeConfig {
        let clone_id = "template";
        let jail_root = root
            .join("jailer")
            .join("firecracker-v1")
            .join(clone_id)
            .join("root");
        let rootfs = artifact(root.join("rootfs-v1"));
        let verity = artifact(root.join("verity-v1"));
        RuntimeConfig {
            firecracker: artifact(root.join("firecracker-v1")),
            kernel: artifact(jail_root.join("artifacts/kernel")),
            rootfs: rootfs.clone(),
            verity_hash: verity.clone(),
            veritysetup: artifact(root.join("veritysetup-v1")),
            dm_verity: DmVerityConfig {
                data_device: rootfs.path.clone(),
                hash_device: verity.path.clone(),
                mapper_name: "session-root".to_owned(),
                root_hash: sha256(b"verity-root"),
                jailed_device_path: jail_root.join("dev/rootfs"),
            },
            workspace: WorkspaceConfig {
                source: root.join("workspace-source"),
                clone_root: jail_root.join("workspace"),
                clone_id: clone_id.to_owned(),
                image: WorkspaceImageConfig {
                    formatter: artifact(root.join("mke2fs-v1")),
                    size_bytes: 64 * 1024 * 1024,
                },
            },
            jailer: artifact(root.join("jailer-v1")),
            jailer_config: JailerConfig {
                uid: 1000,
                gid: 1000,
                chroot_base_dir: root.join("jailer"),
                cgroup_version: CgroupVersion::V2,
            },
            api_socket: jail_root.join("run/firecracker.sock"),
            isolation: HostIsolationConfig {
                namespaces: NamespaceConfig {
                    user: false,
                    pid: true,
                    mount: true,
                    network: false,
                    ipc: false,
                    uts: false,
                },
                cgroup: CgroupConfig {
                    path: cgroup_parent().join(clone_id),
                    memory_max_bytes: 1024 * 1024,
                    cpu_quota_micros: 10_000,
                    cpu_period_micros: 100_000,
                },
                seccomp: SeccompConfig {
                    filter: artifact(jail_root.join("artifacts/seccomp")),
                    blocked_syscalls: [
                        "bpf",
                        "connect",
                        "mount",
                        "perf_event_open",
                        "ptrace",
                        "setns",
                        "socket",
                        "unshare",
                    ]
                    .into_iter()
                    .map(str::to_owned)
                    .collect(),
                },
            },
            vsock: VsockConfig {
                guest_cid: 7,
                uds_path: jail_root.join("run/vsock.sock"),
            },
            network_devices: Vec::new(),
            vcpu_count: 1,
            memory_mib: 128,
            boot_args:
                "console=ttyS0 reboot=k panic=1 pci=off init=/usr/local/libexec/guest-control-init"
                    .to_owned(),
        }
    }

    fn broker_limits() -> ProductionBrokerLimits {
        ProductionBrokerLimits::new(
            NonZeroUsize::new(8).expect("nonzero"),
            NonZeroU64::new(8).expect("nonzero"),
            1024 * 1024,
            NonZeroUsize::new(1).expect("nonzero"),
            64 * 1024,
            NonZeroUsize::new(8).expect("nonzero"),
        )
    }

    fn production_config(root: &Path, audit: AuthorityAuditMode) -> ProductionSessionConfig {
        ProductionSessionConfig::new(
            ProductionDurabilityConfig::new(
                root.join("identity.ledger"),
                root.join("session-recovery.wal"),
                audit,
                root.join("broker-wal"),
            ),
            IssuerId::new("production-test"),
            ProductionFirecrackerConfig::new(runtime_config(root), recovery_tools(root)),
            WorkspaceTemplateId::new("workspace-template-v1"),
            ProductionBrokerEndpoint::new(2, 7, 19_001, 16),
            ProductionGuestControlEndpoint::new(19_002),
            broker_limits(),
        )
    }

    fn identity(seed: u8) -> SessionIdentity {
        SessionIdentity {
            session_id: crate::SessionId::new([seed; crate::ID_BYTES]),
            request_id: crate::RequestId::new([seed.wrapping_add(1); crate::ID_BYTES]),
            vm_id: crate::VmId::new([seed.wrapping_add(2); crate::ID_BYTES]),
            subject_id: crate::SubjectId::new([seed.wrapping_add(3); crate::ID_BYTES]),
            workspace_id: crate::WorkspaceId::new([seed.wrapping_add(4); crate::ID_BYTES]),
            broker_session_id: crate::BrokerSessionId::new([seed.wrapping_add(5); crate::ID_BYTES]),
            capability_id: crate::CapabilityId::new([seed.wrapping_add(6); crate::ID_BYTES]),
        }
    }

    fn identity_reservation(
        identity: SessionIdentity,
    ) -> [(IdentityKind, [u8; crate::ID_BYTES]); 7] {
        [
            (IdentityKind::Session, identity.session_id().as_bytes()),
            (IdentityKind::Request, identity.request_id().as_bytes()),
            (IdentityKind::Vm, identity.vm_id().as_bytes()),
            (IdentityKind::Subject, identity.subject_id().as_bytes()),
            (IdentityKind::Workspace, identity.workspace_id().as_bytes()),
            (
                IdentityKind::Capability,
                identity.capability_id().as_bytes(),
            ),
            (
                IdentityKind::BrokerSession,
                identity.broker_session_id().as_bytes(),
            ),
        ]
    }

    /// Creates the jail parent that [`SessionResourceOwnership`] seals before any cleanup.
    ///
    /// The jailer creates `<chroot base>/<jailer executable name>` once per host, so recovery
    /// requires it to already exist rather than inventing it during cleanup.
    fn create_jail_parent(root: &Path) {
        fs::create_dir_all(root.join("jailer").join("firecracker-v1"))
            .expect("jail parent fixture must be creatable");
    }

    fn recovery_intent(root: &Path, session: SessionIdentity) -> SessionRecoveryIntent {
        let request = recovery_request(&runtime_config(root), session)
            .expect("test recovery ownership must be reconstructable");
        SessionRecoveryIntent::new(session, request.ownership.config_fingerprint())
    }

    fn write_recovery_crash_point(
        root: &Path,
        session: SessionIdentity,
        stage: SessionRecoveryStage,
    ) {
        let intent = recovery_intent(root, session);
        let mut journal = DurableSessionRecoveryJournal::open(root.join("session-recovery.wal"))
            .expect("test recovery journal must open");
        let mut lease = journal
            .prepare(intent)
            .expect("test recovery intent must be durable");
        if stage == SessionRecoveryStage::Intent {
            return;
        }
        let mut ledger = DurableIdentityLedger::open(root.join("identity.ledger"))
            .expect("test identity ledger must open");
        ledger
            .reserve_batch(&intent.identities())
            .expect("test identities must be durable");
        drop(ledger);
        for checkpoint in [
            SessionRecoveryStage::IdentityReserved,
            SessionRecoveryStage::CgroupEmpty,
            SessionRecoveryStage::ProvisioningReleased,
            SessionRecoveryStage::MapperClosed,
            SessionRecoveryStage::JailRemoved,
            SessionRecoveryStage::Complete,
        ] {
            if checkpoint == SessionRecoveryStage::Complete {
                journal
                    .complete(&lease)
                    .expect("test completion must be durable");
            } else {
                lease = journal
                    .checkpoint(&lease, checkpoint)
                    .expect("test checkpoint must be durable");
            }
            if checkpoint == stage {
                break;
            }
        }
    }

    /// Reopens a durable file whose owner this test just dropped.
    ///
    /// `Command::spawn` forks, and a fork duplicates every descriptor in the process, including
    /// the journal descriptors other test threads hold. `CLOEXEC` closes them in the child, but
    /// only at `exec`, so between fork and exec a concurrent `Drop` cannot yet release its
    /// `flock`. The cross-process locking tests in this binary fork while these tests run, so a
    /// reopen can observe a `Locked` that belongs to a descriptor nobody is using. The wait is
    /// bounded and reports the last real error, so a genuine leaked writer still fails the test.
    fn reopen_after_release<T, E: fmt::Debug>(
        what: &str,
        mut open: impl FnMut() -> Result<T, E>,
        transient: impl Fn(&E) -> bool,
    ) -> T {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            match open() {
                Ok(value) => return value,
                Err(error) if transient(&error) && Instant::now() < deadline => {
                    sleep(Duration::from_millis(5));
                }
                Err(error) => panic!("{what} must reopen after its owner released it: {error:?}"),
            }
        }
    }

    fn reopened_recovery_state(
        root: &Path,
    ) -> (DurableSessionRecoveryJournal, DurableIdentityLedger) {
        (
            reopen_after_release(
                "recovery journal",
                || DurableSessionRecoveryJournal::open(root.join("session-recovery.wal")),
                |error| matches!(error, SessionRecoveryError::Locked { .. }),
            ),
            reopen_after_release(
                "identity ledger",
                || DurableIdentityLedger::open(root.join("identity.ledger")),
                |error| matches!(error, LedgerError::Unavailable { .. }),
            ),
        )
    }

    fn build_test_runtime<F>(
        root: &Path,
        factory: F,
    ) -> Result<ProductionSessionRuntime, ProductionBuildError>
    where
        F: PerSessionFirecrackerFactory,
    {
        ProductionSessionRuntimeBuilder::new(
            production_config(
                root,
                AuthorityAuditMode::CreateNew(root.join("authority.wal")),
            ),
            factory,
            TestEgressFactory,
        )
        .build()
    }

    #[test]
    fn build_drains_every_durable_recovery_crash_point_to_completion() {
        if !recovery_platform_or_skip() {
            return;
        }
        for (seed, stage) in [
            SessionRecoveryStage::IdentityReserved,
            SessionRecoveryStage::CgroupEmpty,
            SessionRecoveryStage::ProvisioningReleased,
            SessionRecoveryStage::MapperClosed,
            SessionRecoveryStage::JailRemoved,
        ]
        .into_iter()
        .enumerate()
        {
            let root = TestDirectory::new();
            fs::create_dir(root.0.join("broker-wal")).expect("broker WAL root must be creatable");
            create_jail_parent(&root.0);
            let session = identity(u8::try_from(seed).expect("seed fits a byte") + 1);
            write_recovery_crash_point(&root.0, session, stage);

            let runtime = ProductionSessionRuntimeBuilder::new(
                production_config(
                    &root.0,
                    AuthorityAuditMode::CreateNew(root.0.join("authority.wal")),
                ),
                TestFirecrackerFactory {
                    snapshot_id: SnapshotId::new([0x91; crate::ID_BYTES]),
                },
                TestEgressFactory,
            )
            .build()
            .unwrap_or_else(|error| {
                panic!("crash point {stage} must be recoverable during build: {error}")
            });
            assert_eq!(runtime.state(), LifecycleState::Ready);
            drop(runtime);

            let (journal, ledger) = reopened_recovery_state(&root.0);
            assert!(
                journal.pending().is_none(),
                "crash point {stage} left a pending recovery obligation"
            );
            assert_eq!(journal.identity_reserved_intent_count(), 1);
            assert_eq!(ledger.committed_count(), 7);
            for (_, value) in recovery_intent(&root.0, session).identities() {
                assert!(
                    ledger.contains(value),
                    "crash point {stage} dropped a durably reserved identity"
                );
            }
        }
    }

    #[test]
    fn build_reserves_identities_for_an_intent_that_crashed_before_the_ledger() {
        if !recovery_platform_or_skip() {
            return;
        }
        let root = TestDirectory::new();
        fs::create_dir(root.0.join("broker-wal")).expect("broker WAL root must be creatable");
        create_jail_parent(&root.0);
        let session = identity(0x21);
        write_recovery_crash_point(&root.0, session, SessionRecoveryStage::Intent);
        assert!(!root.0.join("identity.ledger").exists());

        let runtime = ProductionSessionRuntimeBuilder::new(
            production_config(
                &root.0,
                AuthorityAuditMode::CreateNew(root.0.join("authority.wal")),
            ),
            TestFirecrackerFactory {
                snapshot_id: SnapshotId::new([0x91; crate::ID_BYTES]),
            },
            TestEgressFactory,
        )
        .build()
        .expect("an intent-only crash point must be reconcilable");
        drop(runtime);

        let (journal, ledger) = reopened_recovery_state(&root.0);
        assert!(journal.pending().is_none());
        assert_eq!(ledger.committed_count(), 7);
        for (_, value) in recovery_intent(&root.0, session).identities() {
            assert!(
                ledger.contains(value),
                "reconciliation must durably reserve the whole intent before any cleanup effect"
            );
        }
    }

    #[test]
    fn build_accepts_an_intent_whose_exact_seven_identities_were_already_reserved() {
        if !recovery_platform_or_skip() {
            return;
        }
        let root = TestDirectory::new();
        fs::create_dir(root.0.join("broker-wal")).expect("broker WAL root must be creatable");
        create_jail_parent(&root.0);
        let session = identity(0x22);
        let intent = recovery_intent(&root.0, session);
        write_recovery_crash_point(&root.0, session, SessionRecoveryStage::Intent);
        let mut ledger = DurableIdentityLedger::open(root.0.join("identity.ledger"))
            .expect("test identity ledger must open");
        ledger
            .reserve_batch(&intent.identities())
            .expect("all seven identities must become durable");
        drop(ledger);

        let runtime = build_test_runtime(
            &root.0,
            TestFirecrackerFactory {
                snapshot_id: SnapshotId::new([0x91; crate::ID_BYTES]),
            },
        )
        .expect("the exact seven-identity crash window must reconcile");
        drop(runtime);

        let (journal, ledger) = reopened_recovery_state(&root.0);
        assert!(journal.pending().is_none());
        assert_eq!(journal.identity_reserved_intent_count(), 1);
        assert_eq!(ledger.committed_count(), 7);
    }

    #[test]
    fn build_rejects_a_partially_reserved_intent_before_new_effects() {
        if !recovery_platform_or_skip() {
            return;
        }
        let root = TestDirectory::new();
        fs::create_dir(root.0.join("broker-wal")).expect("broker WAL root must be creatable");
        create_jail_parent(&root.0);
        let session = identity(0x23);
        let intent = recovery_intent(&root.0, session);
        write_recovery_crash_point(&root.0, session, SessionRecoveryStage::Intent);
        let mut ledger = DurableIdentityLedger::open(root.0.join("identity.ledger"))
            .expect("test identity ledger must open");
        ledger
            .reserve_batch(&intent.identities()[..3])
            .expect("the partial crash fixture must become durable");
        drop(ledger);

        let error = build_test_runtime(
            &root.0,
            TestFirecrackerFactory {
                snapshot_id: SnapshotId::new([0x91; crate::ID_BYTES]),
            },
        )
        .err()
        .expect("a partially reserved identity batch must fail closed");
        assert!(matches!(
            error,
            ProductionBuildError::Recovery(recovery)
                if matches!(&*recovery, ProductionRecoveryError::IdentityMismatch(message)
                    if message.contains("only 3 of seven"))
        ));
        assert!(!root.0.join("authority.wal").exists());

        let (journal, ledger) = reopened_recovery_state(&root.0);
        assert_eq!(
            journal.pending().map(SessionRecoveryLease::stage),
            Some(SessionRecoveryStage::Intent)
        );
        assert_eq!(ledger.committed_count(), 3);
    }

    #[test]
    fn build_rejects_a_foreign_recovery_fingerprint_before_reserving_identities() {
        if !recovery_platform_or_skip() {
            return;
        }
        let root = TestDirectory::new();
        fs::create_dir(root.0.join("broker-wal")).expect("broker WAL root must be creatable");
        create_jail_parent(&root.0);
        let session = identity(0x24);
        let mut journal = DurableSessionRecoveryJournal::open(root.0.join("session-recovery.wal"))
            .expect("test recovery journal must open");
        journal
            .prepare(SessionRecoveryIntent::new(
                session,
                Sha256Digest::from_bytes([0xa5; 32]),
            ))
            .expect("foreign fingerprint fixture must be durable");
        drop(journal);

        let error = build_test_runtime(
            &root.0,
            TestFirecrackerFactory {
                snapshot_id: SnapshotId::new([0x91; crate::ID_BYTES]),
            },
        )
        .err()
        .expect("a foreign ownership fingerprint must fail closed");
        assert!(matches!(
            error,
            ProductionBuildError::Recovery(recovery)
                if matches!(&*recovery, ProductionRecoveryError::IdentityMismatch(message)
                    if message.contains("config fingerprint"))
        ));
        assert!(!root.0.join("authority.wal").exists());

        let (journal, ledger) = reopened_recovery_state(&root.0);
        assert_eq!(
            journal.pending().map(SessionRecoveryLease::stage),
            Some(SessionRecoveryStage::Intent)
        );
        assert_eq!(ledger.committed_count(), 0);
    }

    #[test]
    fn build_accepts_a_fully_reconciled_nonempty_history() {
        if !recovery_platform_or_skip() {
            return;
        }
        let root = TestDirectory::new();
        fs::create_dir(root.0.join("broker-wal")).expect("broker WAL root must be creatable");
        create_jail_parent(&root.0);
        write_recovery_crash_point(&root.0, identity(0x25), SessionRecoveryStage::Complete);

        let runtime = build_test_runtime(
            &root.0,
            TestFirecrackerFactory {
                snapshot_id: SnapshotId::new([0x91; crate::ID_BYTES]),
            },
        )
        .expect("fully reconciled nonempty history must be reusable");
        assert_eq!(runtime.state(), LifecycleState::Ready);
        drop(runtime);

        let (journal, ledger) = reopened_recovery_state(&root.0);
        assert!(journal.pending().is_none());
        assert_eq!(journal.identity_reserved_intent_count(), 1);
        assert_eq!(ledger.committed_count(), 7);
    }

    #[test]
    fn known_identity_collision_durably_abandons_the_pre_effect_intent() {
        if !recovery_platform_or_skip() {
            return;
        }
        let root = TestDirectory::new();
        create_jail_parent(&root.0);
        let session = identity(0x26);
        let ledger_path = root.0.join("identity.ledger");
        let journal_path = root.0.join("session-recovery.wal");
        let mut inner =
            DurableIdentityLedger::open(&ledger_path).expect("test identity ledger must open");
        inner
            .reserve(IdentityKind::Session, session.session_id().as_bytes())
            .expect("collision fixture must become durable");
        let journal = DurableSessionRecoveryJournal::open(&journal_path)
            .expect("test recovery journal must open");
        let driver = FirecrackerRecovery::new(
            LinuxFirecrackerRecovery::new(recovery_tools(&root.0))
                .expect("test recovery driver must construct"),
        );
        let recovery = Arc::new(Mutex::new(ProductionRecoveryState { journal, driver }));
        let mut ledger =
            RecoveryAwareIdentityLedger::new(inner, Arc::clone(&recovery), runtime_config(&root.0));

        let error = ledger
            .reserve_batch(&identity_reservation(session))
            .expect_err("a known collision must remain rejected");
        assert!(matches!(error, LedgerError::Duplicate { .. }));
        drop(ledger);
        drop(recovery);

        let journal = DurableSessionRecoveryJournal::open(&journal_path)
            .expect("abandoned journal must reopen");
        assert!(journal.pending().is_none());
        assert_eq!(
            journal.history().last().map(|history| history.stage()),
            Some(SessionRecoveryStage::Abandoned)
        );
        let ledger =
            DurableIdentityLedger::open(&ledger_path).expect("collision ledger must reopen");
        assert_eq!(ledger.committed_count(), 1);
    }

    #[test]
    fn incomplete_provisioning_recovery_fails_the_build_closed() {
        if !recovery_platform_or_skip() {
            return;
        }
        let root = TestDirectory::new();
        fs::create_dir(root.0.join("broker-wal")).expect("broker WAL root must be creatable");
        create_jail_parent(&root.0);
        let session = identity(0x31);
        write_recovery_crash_point(&root.0, session, SessionRecoveryStage::CgroupEmpty);
        let attempts = Arc::new(AtomicU64::new(0));

        let error = ProductionSessionRuntimeBuilder::new(
            production_config(
                &root.0,
                AuthorityAuditMode::CreateNew(root.0.join("authority.wal")),
            ),
            FailingRecoveryFactory {
                snapshot_id: SnapshotId::new([0x91; crate::ID_BYTES]),
                attempts: Arc::clone(&attempts),
            },
            TestEgressFactory,
        )
        .build()
        .err()
        .expect("unreleased provisioning must fail the build closed");

        assert_eq!(attempts.load(Ordering::Relaxed), 1);
        assert!(matches!(
            error,
            ProductionBuildError::Recovery(recovery)
                if matches!(&*recovery, ProductionRecoveryError::Firecracker(failure)
                    if failure.pending_stage() == RecoveryStage::CgroupEmpty)
        ));
        assert!(
            !root.0.join("authority.wal").exists(),
            "no durable authority journal may exist while recovery is incomplete"
        );

        let (journal, _) = reopened_recovery_state(&root.0);
        assert_eq!(
            journal.pending().map(SessionRecoveryLease::stage),
            Some(SessionRecoveryStage::CgroupEmpty),
            "a failed cleanup must retain its exact durable retry point"
        );
    }

    #[test]
    fn crash_after_provisioning_effect_retries_the_same_durable_stage() {
        if !recovery_platform_or_skip() {
            return;
        }
        let root = TestDirectory::new();
        fs::create_dir(root.0.join("broker-wal")).expect("broker WAL root must be creatable");
        create_jail_parent(&root.0);
        write_recovery_crash_point(&root.0, identity(0x32), SessionRecoveryStage::CgroupEmpty);
        let attempts = Arc::new(AtomicU64::new(1));

        let runtime = build_test_runtime(
            &root.0,
            RecordingRecoveryFactory {
                snapshot_id: SnapshotId::new([0x91; crate::ID_BYTES]),
                attempts: Arc::clone(&attempts),
            },
        )
        .expect("an idempotent uncheckpointed provisioning effect must be retried");
        drop(runtime);

        assert_eq!(
            attempts.load(Ordering::Relaxed),
            2,
            "the persisted CgroupEmpty stage must retry provisioning after reopen"
        );
        let (journal, _) = reopened_recovery_state(&root.0);
        assert!(journal.pending().is_none());
    }

    #[test]
    fn builder_constructs_a_real_ready_owner_without_running_session_factories() {
        let root = TestDirectory::new();
        fs::create_dir(root.0.join("broker-wal")).expect("broker WAL root must be creatable");
        let audit = root.0.join("authority.wal");
        let runtime = ProductionSessionRuntimeBuilder::new(
            production_config(&root.0, AuthorityAuditMode::CreateNew(audit.clone())),
            TestFirecrackerFactory {
                snapshot_id: SnapshotId::new([0x91; crate::ID_BYTES]),
            },
            TestEgressFactory,
        )
        .build()
        .expect("complete static composition must build");

        assert_eq!(runtime.state(), LifecycleState::Ready);
        assert!(runtime.active_session().is_none());
        assert!(audit.is_file());
        assert!(root.0.join("identity.ledger").is_file());
    }

    #[test]
    fn existing_authority_wal_is_recovered_into_a_fresh_capability_state() {
        let root = TestDirectory::new();
        fs::create_dir(root.0.join("broker-wal")).expect("broker WAL root must be creatable");
        let audit = root.0.join("authority.wal");
        drop(DurableAuditLog::create(&audit).expect("a prior instance's WAL must be creatable"));

        let runtime = ProductionSessionRuntimeBuilder::new(
            production_config(&root.0, AuthorityAuditMode::OpenExisting(audit.clone())),
            TestFirecrackerFactory {
                snapshot_id: SnapshotId::new([0x91; crate::ID_BYTES]),
            },
            TestEgressFactory,
        )
        .build()
        .expect("an existing authority WAL must be recoverable after resource reconciliation");

        assert_eq!(runtime.state(), LifecycleState::Ready);
        assert!(audit.is_file());
    }

    #[test]
    fn unreadable_authority_wal_still_fails_closed() {
        let root = TestDirectory::new();
        fs::create_dir(root.0.join("broker-wal")).expect("broker WAL root must be creatable");
        let audit = root.0.join("authority.wal");
        fs::write(&audit, b"existing").expect("test WAL must be writable");

        let error = ProductionSessionRuntimeBuilder::new(
            production_config(&root.0, AuthorityAuditMode::OpenExisting(audit.clone())),
            TestFirecrackerFactory {
                snapshot_id: SnapshotId::new([0x91; crate::ID_BYTES]),
            },
            TestEgressFactory,
        )
        .build()
        .err()
        .expect("a WAL that is not a journal must fail closed");

        assert!(matches!(error, ProductionBuildError::AuthorityAudit(_)));
    }

    #[test]
    fn nonempty_identity_ledger_without_recovery_history_fails_closed() {
        let root = TestDirectory::new();
        fs::create_dir(root.0.join("broker-wal")).expect("broker WAL root must be creatable");
        let ledger_path = root.0.join("identity.ledger");
        let mut ledger =
            DurableIdentityLedger::open(&ledger_path).expect("test ledger must be creatable");
        ledger
            .reserve_batch(&[(IdentityKind::Session, [0x44; crate::ID_BYTES])])
            .expect("test identity must become durable");
        drop(ledger);

        let error = ProductionSessionRuntimeBuilder::new(
            production_config(
                &root.0,
                AuthorityAuditMode::CreateNew(root.0.join("authority.wal")),
            ),
            TestFirecrackerFactory {
                snapshot_id: SnapshotId::new([0x91; crate::ID_BYTES]),
            },
            TestEgressFactory,
        )
        .build()
        .err()
        .expect("unreconciled identity history must fail closed");

        assert!(matches!(
            error,
            ProductionBuildError::Recovery(recovery)
                if matches!(&*recovery, ProductionRecoveryError::IdentityMismatch(message)
                    if message.contains("ledger contains 1 identities"))
        ));
        assert!(!root.0.join("authority.wal").exists());
    }

    #[test]
    fn firecracker_proof_rejects_snapshot_path_and_config_mismatch() {
        let root = TestDirectory::new();
        let base = runtime_config(&root.0);
        let session = identity(0x11);
        let exact = rebind_runtime_config(&base, session).expect("session config must rebind");
        let jail_root = session_jail_root(&exact).expect("jail root must resolve");
        let policy_digest = AuthorityPolicyDigest::from_hex(&"11".repeat(32))
            .expect("test policy digest must be valid");
        let request = SessionFirecrackerRequest {
            identity: session,
            runtime_config: exact.clone(),
            snapshot_id: SnapshotId::new([0x77; crate::ID_BYTES]),
            snapshot_path: jail_root.join("snapshots/state"),
            memory_path: jail_root.join("snapshots/memory"),
            guest_control_port: 19_002,
            policy_digest,
        };
        let snapshot = Snapshot::new_bound(
            request.snapshot_path.clone(),
            root.0.join("foreign-memory"),
            exact.snapshot_fingerprint(),
            Sha256Digest::from_bytes([1; 32]),
            Sha256Digest::from_bytes([2; 32]),
            policy_digest,
            Vec::new(),
        );
        let error = PreparedFirecrackerSession::verify(
            &request,
            exact.clone(),
            snapshot,
            request.snapshot_id,
        )
        .err()
        .expect("foreign memory path must be rejected");
        assert!(matches!(
            error,
            SessionPreparationError::SnapshotPathMismatch {
                resource: SnapshotResource::Memory
            }
        ));

        let mut changed = exact.clone();
        changed.memory_mib += 1;
        let snapshot = Snapshot::new_bound(
            request.snapshot_path.clone(),
            request.memory_path.clone(),
            changed.snapshot_fingerprint(),
            Sha256Digest::from_bytes([1; 32]),
            Sha256Digest::from_bytes([2; 32]),
            policy_digest,
            Vec::new(),
        );
        assert!(matches!(
            PreparedFirecrackerSession::verify(&request, changed, snapshot, request.snapshot_id,),
            Err(SessionPreparationError::RuntimeConfigMismatch)
        ));
    }

    #[test]
    fn filesystem_factory_copies_pinned_artifacts_into_the_exact_session_jail() {
        let root = TestDirectory::new();
        create_jail_parent(&root.0);
        let mut template = runtime_config(&root.0);
        let template_jail =
            session_jail_root(&template).expect("template jail root must be derivable");
        let kernel_source = root.0.join("guest-kernel-source");
        let seccomp_source = root.0.join("guest-seccomp-source");
        let state_source = root.0.join("clean-snapshot-state");
        let memory_source = root.0.join("clean-snapshot-memory");
        fs::write(&kernel_source, b"kernel-v1").expect("kernel source must be writable");
        fs::write(&seccomp_source, b"seccomp-v1").expect("seccomp source must be writable");
        fs::write(&state_source, b"snapshot-state-v1").expect("state source must be writable");
        fs::write(&memory_source, b"snapshot-memory-v1").expect("memory source must be writable");
        template.kernel =
            PinnedArtifact::new(template_jail.join("artifacts/kernel"), sha256(b"kernel-v1"));
        template.isolation.seccomp.filter = PinnedArtifact::new(
            template_jail.join("artifacts/seccomp"),
            sha256(b"seccomp-v1"),
        );

        let session = identity(0x61);
        let session_config =
            rebind_runtime_config(&template, session).expect("session config must rebind");
        let session_jail =
            session_jail_root(&session_config).expect("session jail root must be derivable");
        fs::create_dir_all(session_config.workspace.clone_path())
            .expect("workspace clone fixture must be creatable");
        let policy_digest = AuthorityPolicyDigest::from_hex(&"12".repeat(32))
            .expect("test policy digest must be valid");
        let request = SessionFirecrackerRequest::new(
            session,
            session_config.clone(),
            SnapshotId::new([0x62; crate::ID_BYTES]),
            session_jail.join("snapshots/state"),
            session_jail.join("snapshots/memory"),
            19_002,
            policy_digest,
        );
        let mut factory = FilesystemFirecrackerFactory::with_guest_artifacts(
            request.snapshot_id(),
            template.clone(),
            GuestArtifactTemplate::new(
                PinnedArtifact::new(&kernel_source, sha256(b"kernel-v1")),
                PinnedArtifact::new(&seccomp_source, sha256(b"seccomp-v1")),
            ),
            SnapshotTemplate::new(
                PinnedArtifact::new(&state_source, sha256(b"snapshot-state-v1")),
                PinnedArtifact::new(&memory_source, sha256(b"snapshot-memory-v1")),
                policy_digest,
            ),
        );

        let wrong_policy = AuthorityPolicyDigest::from_hex(&"13".repeat(32))
            .expect("different test policy digest must be valid");
        let mismatched = SessionFirecrackerRequest::new(
            session,
            session_config.clone(),
            request.snapshot_id(),
            request.snapshot_path(),
            request.memory_path(),
            request.guest_control_port(),
            wrong_policy,
        );
        let error = factory
            .prepare(&mismatched)
            .err()
            .expect("a policy-mismatched snapshot must fail before provisioning");
        assert!(error.to_string().contains("policy digest"));
        assert!(!request.snapshot_path().exists());
        assert!(!request.memory_path().exists());

        factory
            .prepare(&request)
            .expect("pinned session artifacts must be prepared");

        assert_eq!(fs::read(&session_config.kernel.path).unwrap(), b"kernel-v1");
        assert_eq!(
            fs::read(&session_config.isolation.seccomp.filter.path).unwrap(),
            b"seccomp-v1"
        );
        assert_eq!(
            fs::read(request.snapshot_path()).unwrap(),
            b"snapshot-state-v1"
        );
        assert_eq!(
            fs::read(request.memory_path()).unwrap(),
            b"snapshot-memory-v1"
        );
        for absent in [
            &session_config.api_socket,
            &session_config.vsock.uds_path,
            &session_config.dm_verity.jailed_device_path,
        ] {
            assert!(
                !absent.exists(),
                "factory must reserve but not create runtime-owned path {}",
                absent.display()
            );
        }
        assert!(
            factory.prepare(&request).is_err(),
            "a second prepare must not replace the session-owned immutable files"
        );
    }

    // The scenario is one uninterrupted lifecycle: splitting it into helpers would hide the
    // ordering this test exists to pin down.
    #[allow(clippy::too_many_lines)]
    #[test]
    fn firecracker_backend_executes_the_exact_once_rebound_proven_config() {
        let root = TestDirectory::new();
        let template = runtime_config(&root.0);
        let session = identity(0x21);
        let prepared = rebind_runtime_config(&template, session)
            .expect("the factory request must contain one session rebind");
        let backend_template = verified_backend_template(&template, session, &prepared)
            .expect("the exact prepared config must pass the execution gate");
        let workspace_id = session.workspace_id().to_string();
        let jail_root = session_jail_root(&prepared).expect("session jail root must resolve");
        let expected_mapper = format!("session-root-{workspace_id}");
        let expected_cgroup = cgroup_parent().join(&workspace_id);
        let expected_workspace = jail_root.join("workspace").join(&workspace_id);
        let expected_workspace_image = jail_root
            .join("workspace")
            .join(format!("{workspace_id}.ext4"));

        assert_eq!(prepared.dm_verity.mapper_name, expected_mapper);
        assert_eq!(prepared.isolation.cgroup.path, expected_cgroup);
        assert_eq!(prepared.workspace.clone_path(), expected_workspace);
        assert_eq!(
            prepared.dm_verity.jailed_device_path,
            jail_root.join("dev/rootfs")
        );

        let snapshot_id = SnapshotId::new([0x72; crate::ID_BYTES]);
        let snapshot = Snapshot::new(
            jail_root.join("snapshots/state"),
            jail_root.join("snapshots/memory"),
            prepared.snapshot_fingerprint(),
            sha256(b"pinned"),
            sha256(b"pinned"),
            Vec::new(),
        );
        let capture = Arc::new(Mutex::new(ExecutionCapture::default()));
        let runtime = Runtime::new(
            ExecutionRunner {
                capture: Arc::clone(&capture),
            },
            ExecutionFileSystem {
                capture: Arc::clone(&capture),
            },
            ExecutionApi {
                capture: Arc::clone(&capture),
            },
            TestApi,
            SystemIdentitySource,
        );
        let (mut vm, _workload) =
            new_firecracker_backends(runtime, backend_template, snapshot, snapshot_id);
        vm.start_vm(
            &SnapshotDescriptor::clean(snapshot_id),
            &session,
            &WorkspaceLease::new(session.session_id(), session.workspace_id()),
            &BrokerLease::new(session.session_id(), session.broker_session_id()),
        )
        .expect("the exact once-rebound config must restore");

        let capture = capture
            .lock()
            .expect("execution capture must not be poisoned");
        assert_eq!(
            capture.block_device_bind,
            Some((
                Path::new("/dev/mapper").join(&expected_mapper),
                jail_root.join("dev/rootfs"),
            ))
        );
        assert_eq!(
            capture.block_binding,
            Some((
                Path::new("/dev/mapper").join(&expected_mapper),
                jail_root.join("dev/rootfs"),
            ))
        );
        assert_eq!(
            capture.cloned_workspace,
            Some((template.workspace.source.clone(), expected_workspace))
        );
        assert_eq!(
            capture.workspace_image,
            Some((
                prepared.workspace.clone_path(),
                expected_workspace_image.clone(),
                prepared.workspace.image.size_bytes,
            ))
        );
        assert_eq!(
            capture
                .ownership
                .as_ref()
                .map(|ownership| ownership.cgroup_path.as_path()),
            Some(expected_cgroup.as_path())
        );
        assert_eq!(
            capture.restored_resources,
            Some((
                Path::new("/workspace").join(format!("{workspace_id}.ext4")),
                PathBuf::from("/run/vsock.sock"),
                prepared.vsock.guest_cid,
            ))
        );

        let mut foreign = prepared;
        foreign.dm_verity.mapper_name.push_str("-foreign");
        assert!(verified_backend_template(&template, session, &foreign).is_err());
    }

    #[test]
    fn durability_paths_inside_the_cloned_workspace_fail_closed() {
        let root = TestDirectory::new();
        let workspace = root.0.join("workspace-source");
        fs::create_dir(&workspace).expect("workspace source must be creatable");

        let mut identity_config = production_config(
            &root.0,
            AuthorityAuditMode::CreateNew(root.0.join("authority.wal")),
        );
        identity_config.durability.identity_ledger_path = workspace.join("identity.ledger");
        assert!(matches!(
            validate_production_config(&identity_config),
            Err(ProductionBuildError::InvalidConfig(message))
                if message.contains("identity ledger")
                    && message.contains("workspace template source")
        ));

        let mut audit_config = production_config(
            &root.0,
            AuthorityAuditMode::CreateNew(workspace.join("authority.wal")),
        );
        assert!(matches!(
            validate_production_config(&audit_config),
            Err(ProductionBuildError::InvalidConfig(message))
                if message.contains("authority audit WAL")
                    && message.contains("workspace template source")
        ));

        let mut recovery_config = production_config(
            &root.0,
            AuthorityAuditMode::CreateNew(root.0.join("authority.wal")),
        );
        recovery_config.durability.recovery_journal_path = workspace.join("recovery.wal");
        assert!(matches!(
            validate_production_config(&recovery_config),
            Err(ProductionBuildError::InvalidConfig(message))
                if message.contains("session recovery WAL")
                    && message.contains("workspace template source")
        ));

        let broker_root = workspace.join("broker-wal");
        fs::create_dir(&broker_root).expect("nested Broker WAL root must be creatable");
        audit_config.durability.authority_audit =
            AuthorityAuditMode::CreateNew(root.0.join("authority.wal"));
        audit_config.durability.broker_wal_root = broker_root;
        assert!(matches!(
            validate_production_config(&audit_config),
            Err(ProductionBuildError::InvalidConfig(message))
                if message.contains("Broker WAL root")
                    && message.contains("workspace template source")
        ));
    }

    #[cfg(unix)]
    #[test]
    fn durability_symlink_alias_into_the_cloned_workspace_fails_closed() {
        use std::os::unix::fs::symlink;

        let root = TestDirectory::new();
        let workspace = root.0.join("workspace-source");
        fs::create_dir(&workspace).expect("workspace source must be creatable");
        let alias = root.0.join("durability-alias");
        symlink(&workspace, &alias).expect("test alias must be creatable");
        let mut config = production_config(
            &root.0,
            AuthorityAuditMode::CreateNew(root.0.join("authority.wal")),
        );
        config.durability.identity_ledger_path = alias.join("identity.ledger");

        assert!(matches!(
            validate_production_config(&config),
            Err(ProductionBuildError::InvalidConfig(message))
                if message.contains("identity ledger")
                    && message.contains("workspace template source")
        ));
    }

    fn assert_broker_limit_rejected_before_backend_side_effects(
        mut config: ProductionSessionConfig,
        mutate: impl FnOnce(&mut ProductionBrokerLimits),
        expected_message: &str,
    ) {
        let identity_ledger_path = config.durability.identity_ledger_path.clone();
        let recovery_journal_path = config.durability.recovery_journal_path.clone();
        let authority_audit_path = config.durability.authority_audit.path().to_owned();
        mutate(&mut config.broker_limits);

        let error = ProductionSessionRuntimeBuilder::new(
            config,
            TestFirecrackerFactory {
                snapshot_id: SnapshotId::new([0x91; crate::ID_BYTES]),
            },
            TestEgressFactory,
        )
        .build()
        .err()
        .expect("invalid Broker limits must fail closed before backend construction");

        assert!(matches!(
            error,
            ProductionBuildError::InvalidConfig(message)
                if message.contains(expected_message)
        ));
        assert!(!identity_ledger_path.exists());
        assert!(!recovery_journal_path.exists());
        assert!(!authority_audit_path.exists());
    }

    #[test]
    fn broker_limits_accept_small_and_hard_cap_boundaries() {
        assert!(validate_production_broker_limits(broker_limits()).is_ok());

        let maximum = ProductionBrokerLimits::new(
            NonZeroUsize::new(MAX_PRODUCTION_BROKER_REPLAY_CAPACITY).expect("nonzero"),
            NonZeroU64::new(
                u64::try_from(MAX_PRODUCTION_BROKER_REPLAY_CAPACITY).expect("u64 capacity"),
            )
            .expect("nonzero"),
            1024,
            NonZeroUsize::new(MAX_PRODUCTION_BROKER_CONCURRENT_REQUESTS).expect("nonzero"),
            1024,
            NonZeroUsize::new(MAX_PRODUCTION_BROKER_CONNECTION_REQUESTS).expect("nonzero"),
        );
        assert!(validate_production_broker_limits(maximum).is_ok());
    }

    #[test]
    fn broker_limits_reject_replay_capacity_above_production_cap_before_side_effects() {
        let root = TestDirectory::new();
        fs::create_dir(root.0.join("broker-wal")).expect("Broker WAL root must be creatable");
        let config = production_config(
            &root.0,
            AuthorityAuditMode::CreateNew(root.0.join("authority.wal")),
        );
        assert_broker_limit_rejected_before_backend_side_effects(
            config,
            |limits| {
                limits.replay_capacity =
                    NonZeroUsize::new(MAX_PRODUCTION_BROKER_REPLAY_CAPACITY + 1).expect("nonzero");
                limits.budget_requests = NonZeroU64::new(
                    u64::try_from(MAX_PRODUCTION_BROKER_REPLAY_CAPACITY + 1).expect("u64 capacity"),
                )
                .expect("nonzero");
                limits.max_connection_requests =
                    NonZeroUsize::new(MAX_PRODUCTION_BROKER_CONNECTION_REQUESTS).expect("nonzero");
            },
            "replay capacity",
        );
    }

    #[test]
    fn broker_limits_reject_connection_requests_above_production_cap_before_side_effects() {
        let root = TestDirectory::new();
        fs::create_dir(root.0.join("broker-wal")).expect("Broker WAL root must be creatable");
        let config = production_config(
            &root.0,
            AuthorityAuditMode::CreateNew(root.0.join("authority.wal")),
        );
        assert_broker_limit_rejected_before_backend_side_effects(
            config,
            |limits| {
                limits.replay_capacity =
                    NonZeroUsize::new(MAX_PRODUCTION_BROKER_REPLAY_CAPACITY).expect("nonzero");
                limits.max_connection_requests =
                    NonZeroUsize::new(MAX_PRODUCTION_BROKER_CONNECTION_REQUESTS + 1)
                        .expect("nonzero");
                limits.budget_requests = NonZeroU64::new(
                    u64::try_from(MAX_PRODUCTION_BROKER_CONNECTION_REQUESTS + 1)
                        .expect("u64 capacity"),
                )
                .expect("nonzero");
            },
            "connection request ceiling",
        );
    }

    #[test]
    fn broker_limits_reject_concurrency_above_production_cap_before_side_effects() {
        let root = TestDirectory::new();
        fs::create_dir(root.0.join("broker-wal")).expect("Broker WAL root must be creatable");
        let config = production_config(
            &root.0,
            AuthorityAuditMode::CreateNew(root.0.join("authority.wal")),
        );
        assert_broker_limit_rejected_before_backend_side_effects(
            config,
            |limits| {
                limits.budget_concurrent =
                    NonZeroUsize::new(MAX_PRODUCTION_BROKER_CONCURRENT_REQUESTS + 1)
                        .expect("nonzero");
            },
            "concurrent request limit",
        );
    }

    #[test]
    fn broker_limits_reject_replay_capacity_above_durable_request_budget() {
        let root = TestDirectory::new();
        fs::create_dir(root.0.join("broker-wal")).expect("Broker WAL root must be creatable");
        let config = production_config(
            &root.0,
            AuthorityAuditMode::CreateNew(root.0.join("authority.wal")),
        );
        assert_broker_limit_rejected_before_backend_side_effects(
            config,
            |limits| {
                limits.replay_capacity = NonZeroUsize::new(9).expect("nonzero");
                limits.budget_requests = NonZeroU64::new(8).expect("nonzero");
                limits.max_connection_requests = NonZeroUsize::new(8).expect("nonzero");
            },
            "replay capacity exceeds the durable request budget",
        );
    }

    #[test]
    fn broker_limits_reject_capacity_below_connection_ceiling() {
        let root = TestDirectory::new();
        fs::create_dir(root.0.join("broker-wal")).expect("broker WAL root must be creatable");
        let mut config = production_config(
            &root.0,
            AuthorityAuditMode::CreateNew(root.0.join("authority.wal")),
        );
        config.broker_limits.replay_capacity = NonZeroUsize::new(1).expect("nonzero");
        let error = ProductionSessionRuntimeBuilder::new(
            config,
            TestFirecrackerFactory {
                snapshot_id: SnapshotId::new([0x91; crate::ID_BYTES]),
            },
            TestEgressFactory,
        )
        .build()
        .err()
        .expect("undersized replay guard must fail closed");
        assert!(matches!(error, ProductionBuildError::InvalidConfig(_)));
    }

    #[test]
    fn guest_control_rejects_wildcard_port_before_owner_construction() {
        let root = TestDirectory::new();
        fs::create_dir(root.0.join("broker-wal")).expect("broker WAL root must be creatable");
        let mut config = production_config(
            &root.0,
            AuthorityAuditMode::CreateNew(root.0.join("authority.wal")),
        );
        config.guest_control_endpoint = ProductionGuestControlEndpoint::new(u32::MAX);

        let error = ProductionSessionRuntimeBuilder::new(
            config,
            TestFirecrackerFactory {
                snapshot_id: SnapshotId::new([0x91; crate::ID_BYTES]),
            },
            TestEgressFactory,
        )
        .build()
        .err()
        .expect("wildcard guest-control port must fail closed");

        assert!(matches!(
            error,
            ProductionBuildError::InvalidConfig(message)
                if message.contains("guest-control vsock port")
        ));
    }

    #[test]
    fn broker_runtime_factory_owns_the_exact_kernel_wal_and_limits() {
        let root = TestDirectory::new();
        let wal_root = root.0.join("broker-wal");
        fs::create_dir(&wal_root).expect("Broker WAL root must be creatable");
        let kernel = Arc::new(CapabilityKernel::new(CapabilityState::new(IssuerId::new(
            "production-test",
        ))));
        let observed = Arc::new(Mutex::new(None));
        let exact_identity = identity(0x31);
        let wal_path = wal_root.join(format!("{}.wal", exact_identity.broker_session_id()));
        let limits = broker_limits();
        let factory = ProductionBrokerRuntimeFactory {
            authority: AuthorityCoreBackend::new(Arc::clone(&kernel)),
            egress_factory: Arc::new(CapturingEgressFactory {
                expected_wal: wal_path.clone(),
                observed: Arc::clone(&observed),
            }),
            wal_root,
            limits,
        };
        assert_eq!(Arc::strong_count(&kernel), 2);

        let runtime = <ProductionBrokerRuntimeFactory as BrokerRuntimeFactory<
            FirecrackerUnixStream,
        >>::build(&factory, &exact_identity)
        .expect("an exact prepared dispatcher must build");
        assert_eq!(Arc::strong_count(&kernel), 3);
        let observed = observed
            .lock()
            .expect("test observation mutex must be healthy")
            .take()
            .expect("the per-session factory must be invoked");

        assert_eq!(observed.identity, exact_identity);
        assert!(observed.wal_absent_during_prepare);
        assert!(wal_path.is_file());

        drop(runtime);
        assert_eq!(Arc::strong_count(&kernel), 2);
        let recovered = reopen_after_release(
            "host-created Broker WAL",
            || DurableBrokerView::open(&wal_path),
            |error| format!("{error:?}").contains("Locked"),
        );
        assert_eq!(
            recovered.config(),
            DurableSessionConfig::new(
                WireBrokerSessionId::new(exact_identity.broker_session_id().as_bytes()),
                limits.replay_capacity,
                SessionBudgetLimits::new(
                    limits.budget_requests,
                    limits.budget_response_bytes,
                    limits.budget_concurrent,
                ),
            )
        );
    }

    #[test]
    fn egress_factory_cannot_substitute_a_precreated_wal() {
        let root = TestDirectory::new();
        let wal_root = root.0.join("broker-wal");
        fs::create_dir(&wal_root).expect("Broker WAL root must be creatable");
        let exact_identity = identity(0x41);
        let wal_path = wal_root.join(format!("{}.wal", exact_identity.broker_session_id()));
        let kernel = Arc::new(CapabilityKernel::new(CapabilityState::new(IssuerId::new(
            "production-test",
        ))));
        let factory = ProductionBrokerRuntimeFactory {
            authority: AuthorityCoreBackend::new(kernel),
            egress_factory: Arc::new(PrecreatingEgressFactory {
                wal_path: wal_path.clone(),
            }),
            wal_root,
            limits: broker_limits(),
        };

        let error = <ProductionBrokerRuntimeFactory as BrokerRuntimeFactory<
            FirecrackerUnixStream,
        >>::build(&factory, &exact_identity)
        .err()
        .expect("factory-controlled WAL precreation must fail closed");
        assert!(
            error
                .to_string()
                .contains("host-owned durable Broker dispatcher creation failed")
        );
        assert_eq!(
            fs::read(&wal_path).expect("malicious fixture must remain inspectable"),
            b"factory-controlled"
        );
    }

    #[test]
    fn production_firecracker_api_uses_the_exact_verified_socket() {
        let root = TestDirectory::new();
        let template = runtime_config(&root.0);
        let config =
            rebind_runtime_config(&template, identity(0x41)).expect("session config must rebind");
        let client = firecracker_api_for(&config)
            .expect("an absolute verified API socket must construct a client");

        assert_eq!(client.socket_path(), config.api_socket);
    }

    #[test]
    fn production_guest_control_uses_the_exact_session_vsock_endpoint() {
        let root = TestDirectory::new();
        let template = runtime_config(&root.0);
        let config =
            rebind_runtime_config(&template, identity(0x42)).expect("session config must rebind");
        let endpoint = ProductionGuestControlEndpoint::new(19_002);
        let client = guest_control_for(&config, endpoint)
            .expect("the verified session endpoint must construct a client");

        assert_eq!(client.uds_path(), config.vsock.uds_path);
        assert_eq!(client.guest_cid(), config.vsock.guest_cid);
        assert_eq!(client.guest_port(), endpoint.port);
        assert_ne!(client.uds_path(), template.vsock.uds_path);
    }

    #[test]
    fn production_broker_port_uses_the_rebound_session_vsock_endpoint() {
        let root = TestDirectory::new();
        let template = runtime_config(&root.0);
        let config =
            rebind_runtime_config(&template, identity(0x43)).expect("session config must rebind");
        let broker_port = 19_001;
        let endpoint = firecracker_guest_port_path(&config.vsock.uds_path, broker_port)
            .expect("rebound Firecracker UDS must derive a Broker endpoint");
        let template_endpoint = firecracker_guest_port_path(&template.vsock.uds_path, broker_port)
            .expect("template Firecracker UDS must derive an endpoint");

        assert_eq!(
            endpoint,
            config
                .vsock
                .uds_path
                .with_file_name(format!("vsock.sock_{broker_port}"))
        );
        assert_ne!(endpoint, template_endpoint);
    }

    #[test]
    fn path_validation_rejects_escape_components() {
        let error = validate_owned_absolute_path("test", Path::new("/safe/../escape"))
            .expect_err("parent traversal must fail closed");
        assert!(matches!(error, ProductionBuildError::InvalidConfig(_)));
    }
}
