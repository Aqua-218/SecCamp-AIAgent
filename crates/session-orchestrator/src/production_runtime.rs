//! Fail-closed host composition for one production session owner.
//!
//! This module composes the production-owned lifecycle pieces that already
//! exist in this crate. It deliberately does not pretend that guest control,
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

use authority_core::{
    capability::IssuerId,
    durable_audit::{DurableAuditError, DurableAuditLog},
    kernel::CapabilityKernel,
    state::CapabilityState,
    time::MonotonicTime,
};
use egress_broker::{dispatch::DispatchContext, server::RequestDispatcher, transport::VsockStream};
use firecracker_runtime::{
    ApiClient, ApiRequest, ApiResponse, RealCommandRunner, RealFileSystem, Runtime, RuntimeConfig,
    RuntimeError, Snapshot, SystemIdentitySource,
};

use crate::{
    BackendError, BrokerLease, CapabilityLease, DurableIdentityLedger, LedgerError, LifecycleState,
    OsEntropy, SessionIdentity, SessionInfo, SessionOrchestrator, SnapshotDescriptor, SnapshotId,
    StartError, VmBackend, VmLease, WorkloadBackend, WorkloadLease, WorkspaceLease,
    WorkspaceTemplateId,
    authority_backend::{AuthorityBrokerBinding, AuthorityCoreBackend, AuthorityRootGrant},
    egress_backend::{
        BrokerBackend, BrokerRuntimeFactory, BuiltBrokerRuntime, ProductionBrokerBackend,
    },
    firecracker_backend::{
        FirecrackerVmBackend, FirecrackerWorkloadBackend, new_firecracker_backends,
    },
    firecracker_workspace::{
        FirecrackerFileSystem, FirecrackerWorkspaceBackend, new_firecracker_workspace_adapters,
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
    /// Production runtime recovery is not implemented, so [`ProductionSessionRuntimeBuilder`]
    /// rejects this mode instead of inferring how an incomplete effect should be reconciled.
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
    authority_audit: AuthorityAuditMode,
    broker_wal_root: PathBuf,
}

impl ProductionDurabilityConfig {
    /// Creates the mandatory durable path configuration.
    #[must_use]
    pub fn new(
        identity_ledger_path: impl Into<PathBuf>,
        authority_audit: AuthorityAuditMode,
        broker_wal_root: impl Into<PathBuf>,
    ) -> Self {
        Self {
            identity_ledger_path: identity_ledger_path.into(),
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

/// Complete immutable input for the host production composition.
#[derive(Debug, Clone)]
pub struct ProductionSessionConfig {
    durability: ProductionDurabilityConfig,
    issuer: IssuerId,
    firecracker: RuntimeConfig,
    workspace_template: WorkspaceTemplateId,
    broker_endpoint: ProductionBrokerEndpoint,
    broker_limits: ProductionBrokerLimits,
}

impl ProductionSessionConfig {
    /// Creates a complete configuration. Validation and resource acquisition happen in `build`.
    #[must_use]
    pub const fn new(
        durability: ProductionDurabilityConfig,
        issuer: IssuerId,
        firecracker: RuntimeConfig,
        workspace_template: WorkspaceTemplateId,
        broker_endpoint: ProductionBrokerEndpoint,
        broker_limits: ProductionBrokerLimits,
    ) -> Self {
        Self {
            durability,
            issuer,
            firecracker,
            workspace_template,
            broker_endpoint,
            broker_limits,
        }
    }
}

/// Exact session-scoped values a Firecracker provisioner must prepare.
pub struct SessionFirecrackerRequest {
    identity: SessionIdentity,
    runtime_config: RuntimeConfig,
    snapshot_id: SnapshotId,
    snapshot_path: PathBuf,
    memory_path: PathBuf,
}

impl SessionFirecrackerRequest {
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
}

struct BoxedApiClient(Box<dyn ApiClient + Send>);

impl ApiClient for BoxedApiClient {
    fn request(&mut self, request: &ApiRequest) -> Result<ApiResponse, RuntimeError> {
        self.0.request(request)
    }

    fn verify_restore_resources(
        &mut self,
        workspace_path: &Path,
        vsock_uds_path: &Path,
        guest_cid: u32,
    ) -> Result<(), RuntimeError> {
        self.0
            .verify_restore_resources(workspace_path, vsock_uds_path, guest_cid)
    }
}

/// Verified output of one identity-bound Firecracker preparation.
///
/// Construction rechecks the exact config, snapshot identity, paths, and compatibility
/// fingerprint supplied by the runtime. The guest client remains a mandatory external seam;
/// this crate provides no dummy guest control implementation.
pub struct PreparedFirecrackerSession {
    identity: SessionIdentity,
    runtime_config: RuntimeConfig,
    snapshot: Snapshot,
    snapshot_id: SnapshotId,
    firecracker_api: BoxedApiClient,
    guest_control_api: BoxedApiClient,
}

impl PreparedFirecrackerSession {
    /// Verifies and seals per-session provisioning output.
    ///
    /// # Errors
    ///
    /// Returns [`SessionPreparationError`] unless every restore-relevant value is bound to
    /// `request`. The Firecracker runtime repeats file digest and exported-resource checks at
    /// restore time.
    pub fn verify<A, G>(
        request: &SessionFirecrackerRequest,
        runtime_config: RuntimeConfig,
        snapshot: Snapshot,
        snapshot_id: SnapshotId,
        firecracker_api: A,
        guest_control_api: G,
    ) -> Result<Self, SessionPreparationError>
    where
        A: ApiClient + Send + 'static,
        G: ApiClient + Send + 'static,
    {
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
        Ok(Self {
            identity: request.identity,
            runtime_config,
            snapshot,
            snapshot_id,
            firecracker_api: BoxedApiClient(Box::new(firecracker_api)),
            guest_control_api: BoxedApiClient(Box::new(guest_control_api)),
        })
    }
}

/// Mandatory session-aware provisioning boundary for Firecracker and guest control.
pub trait PerSessionFirecrackerFactory: Send + 'static {
    /// Returns the provisioned snapshot identity whose image contains no live session identity.
    fn snapshot_id(&self) -> SnapshotId;

    /// Prepares the exact session jail and returns verified API clients and snapshot provenance.
    ///
    /// An error must leave no unowned process or mount behind. A successful result transfers all
    /// later VM cleanup responsibility into the returned Firecracker runtime backends.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] if the exact session jail, snapshot, Firecracker API, or guest
    /// control channel cannot be prepared and sealed into [`PreparedFirecrackerSession`].
    fn prepare(
        &mut self,
        request: &SessionFirecrackerRequest,
    ) -> Result<PreparedFirecrackerSession, BackendError>;
}

/// Exact authority and durability values a Broker dispatcher factory must consume.
pub struct SessionEgressRequest {
    identity: SessionIdentity,
    authority: AuthorityBrokerBinding,
    executor: Arc<CapabilityKernel>,
    wal_path: PathBuf,
    limits: ProductionBrokerLimits,
}

impl SessionEgressRequest {
    /// Returns the exact orchestrator identity for this dispatcher.
    #[must_use]
    pub const fn identity(&self) -> SessionIdentity {
        self.identity
    }

    /// Returns the exact Authority Core subject and capability binding.
    #[must_use]
    pub const fn authority(&self) -> &AuthorityBrokerBinding {
        &self.authority
    }

    /// Returns the same kernel used by root issuance and revocation.
    #[must_use]
    pub const fn executor(&self) -> &Arc<CapabilityKernel> {
        &self.executor
    }

    /// Returns the fresh, session-identity-derived WAL path the dispatcher must exclusively own.
    #[must_use]
    pub fn wal_path(&self) -> &Path {
        &self.wal_path
    }

    /// Returns the mandatory durable replay and budget limits.
    #[must_use]
    pub const fn limits(&self) -> ProductionBrokerLimits {
        self.limits
    }
}

/// Verified dispatcher, monotonic clock, and exact-request proof for one Broker worker.
pub struct PreparedEgressSession {
    identity: SessionIdentity,
    authority: AuthorityBrokerBinding,
    executor: Arc<CapabilityKernel>,
    wal_path: PathBuf,
    limits: ProductionBrokerLimits,
    dispatcher: Box<dyn RequestDispatcher + Send>,
    clock: Box<dyn FnMut() -> MonotonicTime + Send>,
}

impl PreparedEgressSession {
    /// Verifies that a dispatcher created the exact requested durable WAL and seals its proof.
    ///
    /// # Errors
    ///
    /// Returns [`SessionPreparationError`] if the requested WAL is absent, empty, a symlink, or
    /// not a regular file. The factory contract additionally requires the dispatcher to own that
    /// WAL and bind all request limits; no unchecked constructor exists.
    pub fn verify<D, C>(
        request: &SessionEgressRequest,
        dispatcher: D,
        clock: C,
    ) -> Result<Self, SessionPreparationError>
    where
        D: RequestDispatcher + Send + 'static,
        C: FnMut() -> MonotonicTime + Send + 'static,
    {
        verify_created_wal(&request.wal_path)?;
        Ok(Self {
            identity: request.identity,
            authority: request.authority.clone(),
            executor: Arc::clone(&request.executor),
            wal_path: request.wal_path.clone(),
            limits: request.limits,
            dispatcher: Box::new(dispatcher),
            clock: Box::new(clock),
        })
    }

    fn matches(&self, request: &SessionEgressRequest) -> bool {
        self.identity == request.identity
            && self.authority == request.authority
            && Arc::ptr_eq(&self.executor, &request.executor)
            && self.wal_path == request.wal_path
            && self.limits == request.limits
    }
}

/// Mandatory host-owned adapter, secret, plan, clock, and durable-dispatch boundary.
pub trait PerSessionEgressFactory: Send + Sync + 'static {
    /// Builds a durable dispatcher for exactly `request`.
    ///
    /// Implementations must use the supplied kernel, authority identities, fresh WAL path, and
    /// every limit. Secret material remains inside the returned dispatcher's provider adapters.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] if the exact session's durable dispatcher, provider adapters, or
    /// monotonic clock cannot be prepared and sealed into [`PreparedEgressSession`].
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
    /// The requested Broker WAL did not become an owned regular nonempty file.
    BrokerWal(String),
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
            Self::BrokerWal(message) => write!(formatter, "Broker WAL proof failed: {message}"),
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
            | Self::BrokerWal(_) => None,
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
    /// A nonempty identity ledger requires host session reconciliation.
    UnsupportedIdentityRecovery {
        /// Ledger that already records allocated session identities.
        path: PathBuf,
        /// Number of durable identity records already present.
        committed_records: usize,
    },
    /// Durable authority journal creation failed.
    AuthorityAudit(DurableAuditError),
    /// Existing authority journals need explicit reconciliation that is not implemented.
    UnsupportedAuthorityRecovery {
        /// Existing WAL that requires operator reconciliation.
        path: PathBuf,
    },
    /// Production Broker backend validation failed.
    Broker(BackendError),
    /// Authority Core could not inspect the fresh journal.
    AuthorityKernel(authority_core::audit::AuditError),
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
            Self::UnsupportedIdentityRecovery {
                path,
                committed_records,
            } => write!(
                formatter,
                "identity ledger recovery is unsupported without session reconciliation: {} contains {committed_records} records",
                path.display()
            ),
            Self::AuthorityAudit(error) => {
                write!(formatter, "authority audit WAL unavailable: {error}")
            }
            Self::UnsupportedAuthorityRecovery { path } => write!(
                formatter,
                "authority audit recovery is unsupported without reconciliation: {}",
                path.display()
            ),
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
            Self::AuthorityAudit(error) => Some(error),
            Self::Broker(error) => Some(error),
            Self::AuthorityKernel(error) => Some(error),
            Self::InvalidConfig(_)
            | Self::UnsupportedIdentityRecovery { .. }
            | Self::UnsupportedAuthorityRecovery { .. } => None,
        }
    }
}

/// One-shot startup failure for an already composed owner.
#[derive(Debug)]
pub enum ProductionStartError {
    /// This composition has already consumed its one session identity allocation attempt.
    AlreadyStarted,
    /// The underlying fail-closed lifecycle start failed.
    Start(StartError),
}

impl fmt::Display for ProductionStartError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AlreadyStarted => formatter.write_str(
                "production session runtime is one-shot and has already attempted startup",
            ),
            Self::Start(error) => error.fmt(formatter),
        }
    }
}

impl Error for ProductionStartError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::AlreadyStarted => None,
            Self::Start(error) => Some(error),
        }
    }
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
    /// This does not start a VM or claim the guest control seam is implemented. Per-session
    /// provisioning happens only after the orchestrator durably allocates [`SessionIdentity`].
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

        let AuthorityAuditMode::CreateNew(audit_path) = &self.config.durability.authority_audit
        else {
            return Err(ProductionBuildError::UnsupportedAuthorityRecovery {
                path: self.config.durability.authority_audit.path().to_owned(),
            });
        };
        let ledger = DurableIdentityLedger::open(&self.config.durability.identity_ledger_path)
            .map_err(ProductionBuildError::IdentityLedger)?;
        let committed_records = ledger.committed_count();
        if committed_records != 0 {
            return Err(ProductionBuildError::UnsupportedIdentityRecovery {
                path: self.config.durability.identity_ledger_path.clone(),
                committed_records,
            });
        }
        let orchestrator = SessionOrchestrator::with_ledger(OsEntropy, ledger);
        let audit =
            DurableAuditLog::create(audit_path).map_err(ProductionBuildError::AuthorityAudit)?;
        let kernel = Arc::new(
            CapabilityKernel::try_new_with_durable_audit(
                CapabilityState::new(self.config.issuer),
                audit,
            )
            .map_err(ProductionBuildError::AuthorityKernel)?,
        );
        let capability = AuthorityCoreBackend::new(Arc::clone(&kernel));

        let jail_root = executable_jail_root(&self.config.firecracker)?;
        let (workspace, runtime_filesystem) = new_firecracker_workspace_adapters(
            RealFileSystem::new(),
            self.config.workspace_template.clone(),
            self.config.firecracker.workspace.source.clone(),
            jail_root,
        );
        let deferred = DeferredFirecrackerFactory::new(
            self.firecracker_factory,
            runtime_filesystem,
            self.config.firecracker,
            snapshot_id,
        );
        let (vm, workload) = deferred.into_handles();

        let broker_runtime_factory = ProductionBrokerRuntimeFactory {
            authority: AuthorityCoreBackend::new(kernel),
            egress_factory: self.egress_factory,
            wal_root: self.config.durability.broker_wal_root,
            limits: self.config.broker_limits,
        };
        let endpoint = self.config.broker_endpoint;
        let broker = BrokerBackend::production(
            broker_runtime_factory,
            endpoint.host_cid,
            endpoint.expected_guest_cid,
            endpoint.port,
            endpoint.backlog,
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

type OwnedWorkspace = FirecrackerWorkspaceBackend<RealFileSystem>;
type OwnedBroker = ProductionBrokerBackend<ProductionBrokerRuntimeFactory>;
type OwnedVm = DeferredFirecrackerVm;
type OwnedWorkload = DeferredFirecrackerWorkload;
type ConcreteSessionOwner = SessionOwner<
    OsEntropy,
    DurableIdentityLedger,
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
        self.start_attempted = true;
        self.owner
            .start(&self.snapshot, &self.workspace_template, grant)
            .map_err(ProductionStartError::Start)
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
    BoxedApiClient,
    BoxedApiClient,
    SystemIdentitySource,
>;
type OwnedFirecrackerVm = FirecrackerVmBackend<
    RealCommandRunner,
    FirecrackerFileSystem<RealFileSystem>,
    BoxedApiClient,
    BoxedApiClient,
    SystemIdentitySource,
>;
type OwnedFirecrackerWorkload = FirecrackerWorkloadBackend<
    RealCommandRunner,
    FirecrackerFileSystem<RealFileSystem>,
    BoxedApiClient,
    BoxedApiClient,
    SystemIdentitySource,
>;

struct DeferredFirecrackerState {
    factory: Box<dyn PerSessionFirecrackerFactory>,
    filesystem: Option<FirecrackerFileSystem<RealFileSystem>>,
    base_config: RuntimeConfig,
    snapshot_id: SnapshotId,
    prepared_identity: Option<SessionIdentity>,
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
    ) -> Self {
        Self {
            shared: Arc::new(Mutex::new(DeferredFirecrackerState {
                factory,
                filesystem: Some(filesystem),
                base_config,
                snapshot_id,
                prepared_identity: None,
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
        }
    }

    fn kill_vm(&mut self, lease: &VmLease) -> Result<(), BackendError> {
        let mut state = lock_deferred(&self.shared)?;
        state
            .vm
            .as_mut()
            .ok_or_else(|| BackendError::new("no prepared Firecracker VM owns this lease"))?
            .kill_vm(lease)
    }
}

impl WorkloadBackend for DeferredFirecrackerWorkload {
    fn release_workload(
        &mut self,
        identity: &SessionIdentity,
        vm: &VmLease,
        capability: &CapabilityLease,
    ) -> Result<WorkloadLease, BackendError> {
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

fn prepare_firecracker(
    state: &mut DeferredFirecrackerState,
    identity: SessionIdentity,
) -> Result<(), BackendError> {
    let runtime_config = rebind_runtime_config(&state.base_config, identity)?;
    let jail_root = session_jail_root(&runtime_config)?;
    let request = SessionFirecrackerRequest {
        identity,
        runtime_config,
        snapshot_id: state.snapshot_id,
        snapshot_path: jail_root.join("snapshots/state"),
        memory_path: jail_root.join("snapshots/memory"),
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
    let filesystem = state.filesystem.take().ok_or_else(|| {
        BackendError::new("session Runtime filesystem was already consumed by another preparation")
    })?;
    let runtime: OwnedRuntime = Runtime::new(
        RealCommandRunner::new(),
        filesystem,
        prepared.firecracker_api,
        prepared.guest_control_api,
        SystemIdentitySource,
    );
    let (vm, workload) = new_firecracker_backends(
        runtime,
        prepared.runtime_config,
        prepared.snapshot,
        prepared.snapshot_id,
    );
    state.prepared_identity = Some(identity);
    state.vm = Some(vm);
    state.workload = Some(workload);
    Ok(())
}

struct ProductionBrokerRuntimeFactory {
    authority: AuthorityCoreBackend,
    egress_factory: Arc<dyn PerSessionEgressFactory>,
    wal_root: PathBuf,
    limits: ProductionBrokerLimits,
}

impl BrokerRuntimeFactory<VsockStream> for ProductionBrokerRuntimeFactory {
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
            authority: self.authority.broker_binding(identity),
            executor: self.authority.broker_executor(),
            wal_path,
            limits: self.limits,
        };
        let prepared = self.egress_factory.prepare(&request)?;
        if !prepared.matches(&request) {
            return Err(BackendError::new(
                "egress factory returned a proof for another session request",
            ));
        }
        let context = DispatchContext {
            caller: prepared.authority.caller.clone(),
            capability: prepared.authority.capability.clone(),
            now: MonotonicTime::from_ticks(0),
        };
        Ok(BuiltBrokerRuntime::new(
            prepared.dispatcher,
            context,
            prepared.clock,
            self.limits.max_connection_requests,
        ))
    }
}

fn validate_production_config(
    config: &ProductionSessionConfig,
) -> Result<(), ProductionBuildError> {
    config
        .firecracker
        .validate()
        .map_err(ProductionBuildError::Runtime)?;
    for (label, path) in [
        (
            "identity ledger",
            config.durability.identity_ledger_path.as_path(),
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
    if config.broker_endpoint.expected_guest_cid != config.firecracker.vsock.guest_cid {
        return Err(ProductionBuildError::InvalidConfig(
            "Broker guest CID must equal the Firecracker vsock guest CID".to_owned(),
        ));
    }
    if config.broker_limits.budget_response_bytes == 0
        || config.broker_limits.github_response_cap == 0
    {
        return Err(ProductionBuildError::InvalidConfig(
            "Broker response budgets and provider cap must be non-zero".to_owned(),
        ));
    }
    if config.broker_limits.replay_capacity.get()
        < config.broker_limits.max_connection_requests.get()
    {
        return Err(ProductionBuildError::InvalidConfig(
            "Broker replay capacity must cover the connection request ceiling".to_owned(),
        ));
    }
    let connection_requests = u64::try_from(config.broker_limits.max_connection_requests.get())
        .map_err(|_| {
            ProductionBuildError::InvalidConfig(
                "Broker connection request ceiling does not fit the durable budget".to_owned(),
            )
        })?;
    if connection_requests > config.broker_limits.budget_requests.get() {
        return Err(ProductionBuildError::InvalidConfig(
            "Broker connection request ceiling exceeds the durable request budget".to_owned(),
        ));
    }
    Ok(())
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

fn verify_created_wal(path: &Path) -> Result<(), SessionPreparationError> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        SessionPreparationError::BrokerWal(format!(
            "dispatcher did not create {}: {error}",
            path.display()
        ))
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() == 0 {
        return Err(SessionPreparationError::BrokerWal(format!(
            "dispatcher WAL is not a nonempty regular file: {}",
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
        time::{SystemTime, UNIX_EPOCH},
    };

    use firecracker_runtime::{
        ApiResponse, CgroupConfig, CgroupVersion, DmVerityConfig, HostIsolationConfig, HttpMethod,
        JailerConfig, NamespaceConfig, PinnedArtifact, SeccompConfig, Sha256Digest, VsockConfig,
        WorkspaceConfig, sha256,
    };

    use super::*;
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
                    path: PathBuf::from("/sys/fs/cgroup/session-runtime/template"),
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
            boot_args: "console=ttyS0".to_owned(),
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
                audit,
                root.join("broker-wal"),
            ),
            IssuerId::new("production-test"),
            runtime_config(root),
            WorkspaceTemplateId::new("workspace-template-v1"),
            ProductionBrokerEndpoint::new(2, 7, 19_001, 16),
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
    fn existing_authority_wal_recovery_is_rejected_before_owner_construction() {
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
        .expect("unsupported recovery must fail closed");

        assert!(matches!(
            error,
            ProductionBuildError::UnsupportedAuthorityRecovery { path } if path == audit
        ));
        assert!(!root.0.join("identity.ledger").exists());
    }

    #[test]
    fn nonempty_identity_ledger_requires_explicit_session_reconciliation() {
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
            ProductionBuildError::UnsupportedIdentityRecovery {
                path,
                committed_records: 1
            } if path == ledger_path
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
        let request = SessionFirecrackerRequest {
            identity: session,
            runtime_config: exact.clone(),
            snapshot_id: SnapshotId::new([0x77; crate::ID_BYTES]),
            snapshot_path: jail_root.join("snapshots/state"),
            memory_path: jail_root.join("snapshots/memory"),
        };
        let snapshot = Snapshot::new(
            request.snapshot_path.clone(),
            root.0.join("foreign-memory"),
            exact.snapshot_fingerprint(),
            Sha256Digest::from_bytes([1; 32]),
            Sha256Digest::from_bytes([2; 32]),
            Vec::new(),
        );
        let error = PreparedFirecrackerSession::verify(
            &request,
            exact.clone(),
            snapshot,
            request.snapshot_id,
            TestApi,
            TestApi,
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
        let snapshot = Snapshot::new(
            request.snapshot_path.clone(),
            request.memory_path.clone(),
            changed.snapshot_fingerprint(),
            Sha256Digest::from_bytes([1; 32]),
            Sha256Digest::from_bytes([2; 32]),
            Vec::new(),
        );
        assert!(matches!(
            PreparedFirecrackerSession::verify(
                &request,
                changed,
                snapshot,
                request.snapshot_id,
                TestApi,
                TestApi,
            ),
            Err(SessionPreparationError::RuntimeConfigMismatch)
        ));
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
    fn broker_wal_proof_rejects_missing_and_empty_files() {
        let root = TestDirectory::new();
        let wal = root.0.join("broker.wal");
        assert!(matches!(
            verify_created_wal(&wal),
            Err(SessionPreparationError::BrokerWal(_))
        ));

        fs::write(&wal, []).expect("empty test WAL must be writable");
        assert!(matches!(
            verify_created_wal(&wal),
            Err(SessionPreparationError::BrokerWal(_))
        ));

        fs::write(&wal, b"durable-header").expect("test WAL must be writable");
        verify_created_wal(&wal).expect("nonempty regular WAL must satisfy the filesystem proof");
    }

    #[test]
    fn boxed_api_delegates_restore_resource_observation() {
        struct ObservingApi(Arc<Mutex<bool>>);
        impl ApiClient for ObservingApi {
            fn request(&mut self, request: &ApiRequest) -> Result<ApiResponse, RuntimeError> {
                if request.method == HttpMethod::Get && request.path == "/vm/config" {
                    *self.0.lock().expect("observation lock must be healthy") = true;
                }
                Ok(ApiResponse {
                    status: 200,
                    body: r#"{"drives":[{"drive_id":"workspace","path_on_host":"/workspace/id"}],"vsock":{"guest_cid":7,"uds_path":"/run/vsock.sock"}}"#.to_owned(),
                })
            }
        }
        let observed = Arc::new(Mutex::new(false));
        let mut client = BoxedApiClient(Box::new(ObservingApi(Arc::clone(&observed))));
        client
            .verify_restore_resources(Path::new("/workspace/id"), Path::new("/run/vsock.sock"), 7)
            .expect("boxed API must delegate resource observation");
        assert!(*observed.lock().expect("observation lock must be healthy"));
    }

    #[test]
    fn path_validation_rejects_escape_components() {
        let error = validate_owned_absolute_path("test", Path::new("/safe/../escape"))
            .expect_err("parent traversal must fail closed");
        assert!(matches!(error, ProductionBuildError::InvalidConfig(_)));
    }
}
