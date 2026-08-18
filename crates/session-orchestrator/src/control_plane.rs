//! Durable, authenticated scheduling above one-session ownership workers.
//!
//! This layer deliberately does not merge multiple workloads into one [`SessionOwner`](crate::session_owner::SessionOwner).
//! It admits bounded requests, burns every reserved identifier durably before a worker is
//! created, and gives each admitted session to one independently owned worker. A stable sidecar
//! lock fences a second controller, while startup reconciliation asks the worker factory to clean
//! every reservation that was not durably closed.

use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt,
    fs::{self, File, OpenOptions, TryLockError},
    io::{self, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    thread,
    time::{Duration, Instant},
};

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::{CryptographicRandom, EntropyError, ID_BYTES};

const JOURNAL_MAGIC: [u8; 16] = *b"session-control1";
const JOURNAL_VERSION: u32 = 1;
const HEADER_BYTES: usize = 64;
const RECORD_MAGIC: [u8; 8] = *b"msctl-r1";
const RECORD_BYTES: usize = 128;
const RECORD_BYTES_U64: u64 = 128;
const RECORD_BODY_BYTES: usize = RECORD_BYTES - 32;
const MAX_CONTROL_RECORDS: usize = 1_000_000;
const MAX_CONTROL_RECORDS_U64: u64 = 1_000_000;
const START_DOMAIN: &[u8] = b"session-control/start/v1\0";
const STOP_DOMAIN: &[u8] = b"session-control/stop/v1\0";
const TRANSIENT_FORK_LOCK_RETRY: Duration = Duration::from_millis(250);
const TRANSIENT_FORK_LOCK_POLL: Duration = Duration::from_millis(2);

macro_rules! control_id {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name([u8; ID_BYTES]);

        impl $name {
            /// Creates an identifier from exact controller-protocol bytes.
            #[must_use]
            pub const fn new(bytes: [u8; ID_BYTES]) -> Self {
                Self(bytes)
            }

            /// Returns the fixed-width protocol bytes.
            #[must_use]
            pub const fn as_bytes(self) -> [u8; ID_BYTES] {
                self.0
            }

            const fn is_zero(self) -> bool {
                let mut index = 0;
                while index < ID_BYTES {
                    if self.0[index] != 0 {
                        return false;
                    }
                    index += 1;
                }
                true
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                for byte in self.0 {
                    write!(formatter, "{byte:02x}")?;
                }
                Ok(())
            }
        }
    };
}

control_id! {
    /// Authenticated tenant or caller identity used for admission quotas.
    PrincipalId
}

control_id! {
    /// Non-reusable identity of one control request.
    ControlRequestId
}

control_id! {
    /// Non-reusable identity assigned to one one-session worker.
    ControlSessionId
}

/// HMAC-SHA-256 tag on a closed control-plane operation.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ControlTag([u8; 32]);

impl ControlTag {
    /// Creates a tag received from an authenticated transport.
    #[must_use]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the fixed-width tag bytes.
    #[must_use]
    pub const fn as_bytes(self) -> [u8; 32] {
        self.0
    }
}

impl fmt::Debug for ControlTag {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ControlTag([redacted])")
    }
}

/// Exact authenticated request to allocate one worker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StartSessionRequest {
    principal: PrincipalId,
    request: ControlRequestId,
    tag: ControlTag,
}

impl StartSessionRequest {
    /// Constructs a transport-decoded request. Authentication happens inside the controller.
    #[must_use]
    pub const fn new(principal: PrincipalId, request: ControlRequestId, tag: ControlTag) -> Self {
        Self {
            principal,
            request,
            tag,
        }
    }

    /// Returns the requesting principal.
    #[must_use]
    pub const fn principal(self) -> PrincipalId {
        self.principal
    }

    /// Returns the non-reusable request identity.
    #[must_use]
    pub const fn request(self) -> ControlRequestId {
        self.request
    }

    /// Returns the fixed-width authentication tag for transport encoding.
    #[must_use]
    pub const fn tag(self) -> ControlTag {
        self.tag
    }
}

/// Exact authenticated request to stop one owned worker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StopSessionRequest {
    principal: PrincipalId,
    request: ControlRequestId,
    session: ControlSessionId,
    tag: ControlTag,
}

impl StopSessionRequest {
    /// Constructs a transport-decoded request. Authentication happens inside the controller.
    #[must_use]
    pub const fn new(
        principal: PrincipalId,
        request: ControlRequestId,
        session: ControlSessionId,
        tag: ControlTag,
    ) -> Self {
        Self {
            principal,
            request,
            session,
            tag,
        }
    }

    /// Returns the targeted session identity.
    #[must_use]
    pub const fn session(self) -> ControlSessionId {
        self.session
    }

    /// Returns the requesting principal.
    #[must_use]
    pub const fn principal(self) -> PrincipalId {
        self.principal
    }

    /// Returns the non-reusable request identity.
    #[must_use]
    pub const fn request(self) -> ControlRequestId {
        self.request
    }

    /// Returns the fixed-width authentication tag for transport encoding.
    #[must_use]
    pub const fn tag(self) -> ControlTag {
        self.tag
    }
}

/// Secret-key authenticator for the closed start/stop protocol.
pub struct ControlAuthenticator {
    key: [u8; 32],
}

impl ControlAuthenticator {
    /// Creates an authenticator from a host-only 256-bit key.
    #[must_use]
    pub const fn new(key: [u8; 32]) -> Self {
        Self { key }
    }

    /// Signs a start request for a trusted local client or test fixture.
    #[must_use]
    pub fn sign_start(
        &self,
        principal: PrincipalId,
        request: ControlRequestId,
    ) -> StartSessionRequest {
        StartSessionRequest::new(
            principal,
            request,
            ControlTag(self.tag(START_DOMAIN, principal, request, None)),
        )
    }

    /// Signs a stop request for a trusted local client or test fixture.
    #[must_use]
    pub fn sign_stop(
        &self,
        principal: PrincipalId,
        request: ControlRequestId,
        session: ControlSessionId,
    ) -> StopSessionRequest {
        StopSessionRequest::new(
            principal,
            request,
            session,
            ControlTag(self.tag(STOP_DOMAIN, principal, request, Some(session))),
        )
    }

    fn verify_start(&self, request: StartSessionRequest) -> Result<(), ControlError> {
        self.verify(
            START_DOMAIN,
            request.principal,
            request.request,
            None,
            request.tag,
        )
    }

    fn verify_stop(&self, request: StopSessionRequest) -> Result<(), ControlError> {
        self.verify(
            STOP_DOMAIN,
            request.principal,
            request.request,
            Some(request.session),
            request.tag,
        )
    }

    fn tag(
        &self,
        domain: &[u8],
        principal: PrincipalId,
        request: ControlRequestId,
        session: Option<ControlSessionId>,
    ) -> [u8; 32] {
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.key)
            .expect("HMAC accepts every fixed-width controller key");
        mac.update(domain);
        mac.update(&principal.0);
        mac.update(&request.0);
        if let Some(session) = session {
            mac.update(&session.0);
        }
        mac.finalize().into_bytes().into()
    }

    fn verify(
        &self,
        domain: &[u8],
        principal: PrincipalId,
        request: ControlRequestId,
        session: Option<ControlSessionId>,
        tag: ControlTag,
    ) -> Result<(), ControlError> {
        if principal.is_zero()
            || request.is_zero()
            || session.is_some_and(ControlSessionId::is_zero)
        {
            return Err(ControlError::InvalidIdentity);
        }
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.key)
            .expect("HMAC accepts every fixed-width controller key");
        mac.update(domain);
        mac.update(&principal.0);
        mac.update(&request.0);
        if let Some(session) = session {
            mac.update(&session.0);
        }
        mac.verify_slice(&tag.0)
            .map_err(|_| ControlError::Authentication)
    }
}

impl Drop for ControlAuthenticator {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

/// Global and per-principal worker ceilings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ControlLimits {
    max_sessions: usize,
    max_sessions_per_principal: usize,
}

impl ControlLimits {
    /// Creates non-zero limits, requiring the principal ceiling not exceed the global ceiling.
    ///
    /// # Errors
    ///
    /// Returns [`ControlError::InvalidLimits`] for zero or inconsistent limits.
    pub const fn new(
        max_sessions: usize,
        max_sessions_per_principal: usize,
    ) -> Result<Self, ControlError> {
        if max_sessions == 0
            || max_sessions_per_principal == 0
            || max_sessions_per_principal > max_sessions
        {
            Err(ControlError::InvalidLimits)
        } else {
            Ok(Self {
                max_sessions,
                max_sessions_per_principal,
            })
        }
    }

    /// Returns the process-wide worker ceiling.
    #[must_use]
    pub const fn max_sessions(self) -> usize {
        self.max_sessions
    }

    /// Returns the worker ceiling for one principal.
    #[must_use]
    pub const fn max_sessions_per_principal(self) -> usize {
        self.max_sessions_per_principal
    }
}

/// Health state returned by one exact one-session worker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlWorkerStatus {
    /// The worker still owns its session.
    Running,
    /// The worker completed cleanup and owns no session resource.
    Closed,
}

/// Closed, non-secret diagnostic returned across the worker boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlWorkerError {
    /// A worker could not be created without transferring ownership.
    StartupFailed,
    /// Exact worker health could not be established.
    StatusUnavailable,
    /// A request referred to resources outside the worker's exact ownership.
    OwnershipMismatch,
    /// Exact cleanup is incomplete and must be retried.
    CleanupIncomplete,
}

impl fmt::Display for ControlWorkerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::StartupFailed => "startup-failed",
            Self::StatusUnavailable => "status-unavailable",
            Self::OwnershipMismatch => "ownership-mismatch",
            Self::CleanupIncomplete => "cleanup-incomplete",
        })
    }
}

/// Narrow lifecycle surface implemented by one-session workers.
pub trait ControlWorker {
    /// Polls only this worker's exact session.
    ///
    /// # Errors
    ///
    /// Returns a bounded operator-facing reason when health cannot be established.
    fn poll(&mut self) -> Result<ControlWorkerStatus, ControlWorkerError>;

    /// Stops this worker and completes its dependency-ordered cleanup.
    ///
    /// # Errors
    ///
    /// Returns a bounded operator-facing reason while cleanup remains retryable.
    fn stop(&mut self) -> Result<(), ControlWorkerError>;
}

/// Factory boundary that owns worker creation and crash reconciliation.
pub trait ControlWorkerFactory {
    /// Concrete non-cloneable worker type.
    type Worker: ControlWorker;

    /// Starts exactly one worker for the durably reserved identity pair.
    ///
    /// # Errors
    ///
    /// Returns a bounded reason when no worker was safely transferred to the controller.
    fn spawn(
        &mut self,
        principal: PrincipalId,
        session: ControlSessionId,
    ) -> Result<Self::Worker, ControlWorkerError>;

    /// Reconciles one reservation found open after a controller crash.
    ///
    /// This operation must be idempotent and return success only after the exact worker and every
    /// resource derived from `session` are gone.
    ///
    /// # Errors
    ///
    /// Returns a bounded reason while exact cleanup cannot be proven complete.
    fn recover(
        &mut self,
        principal: PrincipalId,
        session: ControlSessionId,
    ) -> Result<(), ControlWorkerError>;
}

/// Complete admission or durable-control failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlError {
    /// The configured limits are zero or inconsistent.
    InvalidLimits,
    /// A zero principal, request, or session identity was supplied.
    InvalidIdentity,
    /// HMAC authentication failed.
    Authentication,
    /// This request identity was already durably consumed.
    RequestReplay(ControlRequestId),
    /// The process-wide worker limit was reached.
    GlobalQuota,
    /// The requesting principal's worker limit was reached.
    PrincipalQuota(PrincipalId),
    /// The targeted worker does not exist or belongs to another principal.
    UnknownSession(ControlSessionId),
    /// Fresh entropy repeatedly collided with a previously reserved session.
    IdentityExhausted,
    /// A second controller already owns the journal lock.
    Fenced(PathBuf),
    /// Journal bytes, metadata, or transition history were unsafe.
    Journal(String),
    /// Worker startup failed after the session identity was durably burned.
    WorkerStart(ControlWorkerError),
    /// Worker health failed and fail-closed cleanup was attempted.
    WorkerPoll {
        /// Closed status failure returned by the exact worker.
        error: ControlWorkerError,
        /// Cleanup failure retained with the worker, if cleanup did not complete.
        cleanup_error: Option<ControlWorkerError>,
    },
    /// Worker cleanup remains retryable.
    WorkerStop(ControlWorkerError),
    /// Crash reconciliation remains incomplete.
    Recovery(ControlWorkerError),
    /// OS entropy was unavailable.
    Entropy(String),
}

impl fmt::Display for ControlError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimits => {
                formatter.write_str("control limits must be non-zero and ordered")
            }
            Self::InvalidIdentity => formatter.write_str("control identities must be non-zero"),
            Self::Authentication => formatter.write_str("control request authentication failed"),
            Self::RequestReplay(request) => {
                write!(formatter, "control request {request} was already consumed")
            }
            Self::GlobalQuota => formatter.write_str("global session quota was reached"),
            Self::PrincipalQuota(principal) => {
                write!(formatter, "principal {principal} session quota was reached")
            }
            Self::UnknownSession(session) => {
                write!(formatter, "session {session} is absent or foreign")
            }
            Self::IdentityExhausted => {
                formatter.write_str("fresh control session identity could not be allocated")
            }
            Self::Fenced(path) => write!(formatter, "another controller owns {}", path.display()),
            Self::Journal(reason) => write!(formatter, "control journal failed closed: {reason}"),
            Self::WorkerStart(reason) => {
                write!(formatter, "session worker startup failed: {reason}")
            }
            Self::WorkerPoll {
                error,
                cleanup_error: None,
            } => write!(
                formatter,
                "session worker health failed and cleanup completed: {error}"
            ),
            Self::WorkerPoll {
                error,
                cleanup_error: Some(cleanup_error),
            } => write!(
                formatter,
                "session worker health failed and cleanup remains incomplete: {error}; {cleanup_error}"
            ),
            Self::WorkerStop(reason) => write!(
                formatter,
                "session worker cleanup remains incomplete: {reason}"
            ),
            Self::Recovery(reason) => write!(
                formatter,
                "stale session recovery remains incomplete: {reason}"
            ),
            Self::Entropy(reason) => write!(formatter, "control identity entropy failed: {reason}"),
        }
    }
}

impl Error for ControlError {}

impl From<EntropyError> for ControlError {
    fn from(error: EntropyError) -> Self {
        Self::Entropy(error.to_string())
    }
}

/// Durable multi-session scheduler retaining one worker value per admitted session.
pub struct MultiSessionController<F, R>
where
    F: ControlWorkerFactory,
    R: CryptographicRandom,
{
    journal: ControlJournal,
    limits: ControlLimits,
    authenticator: ControlAuthenticator,
    factory: F,
    random: R,
    workers: BTreeMap<ControlSessionId, ActiveWorker<F::Worker>>,
}

struct ActiveWorker<W> {
    principal: PrincipalId,
    worker: W,
}

impl<F, R> MultiSessionController<F, R>
where
    F: ControlWorkerFactory,
    R: CryptographicRandom,
{
    /// Opens the exclusive journal, reconciles every stale reservation, and returns an empty
    /// live-worker set.
    ///
    /// # Errors
    ///
    /// Fails closed on unsafe journal state, lock contention, or incomplete stale cleanup.
    pub fn open(
        path: impl AsRef<Path>,
        limits: ControlLimits,
        authenticator: ControlAuthenticator,
        mut factory: F,
        random: R,
    ) -> Result<Self, ControlError> {
        let mut journal = ControlJournal::open(path.as_ref())?;
        let stale = journal.open_sessions();
        for (session, principal) in stale {
            journal.ensure_healthy()?;
            factory
                .recover(principal, session)
                .map_err(ControlError::Recovery)?;
            journal.append(JournalEvent::Closed, principal, None, session)?;
        }
        Ok(Self {
            journal,
            limits,
            authenticator,
            factory,
            random,
            workers: BTreeMap::new(),
        })
    }

    /// Authenticates, quota-checks, durably reserves, and starts one worker.
    ///
    /// # Errors
    ///
    /// Fails before worker creation on authentication, replay, quota, entropy, or journal error.
    /// A worker-start failure closes the durable reservation but never makes its IDs reusable.
    pub fn start(
        &mut self,
        request: StartSessionRequest,
    ) -> Result<ControlSessionId, ControlError> {
        self.authenticator.verify_start(request)?;
        if self.journal.used_requests.contains(&request.request) {
            return Err(ControlError::RequestReplay(request.request));
        }
        if self.workers.len() >= self.limits.max_sessions {
            return Err(ControlError::GlobalQuota);
        }
        if self
            .workers
            .values()
            .filter(|worker| worker.principal == request.principal)
            .count()
            >= self.limits.max_sessions_per_principal
        {
            return Err(ControlError::PrincipalQuota(request.principal));
        }
        self.journal.ensure_healthy()?;
        let session = self.fresh_session_id()?;
        self.journal.append(
            JournalEvent::Reserved,
            request.principal,
            Some(request.request),
            session,
        )?;
        let worker = match self.factory.spawn(request.principal, session) {
            Ok(worker) => worker,
            Err(error) => {
                self.journal
                    .append(JournalEvent::Closed, request.principal, None, session)?;
                return Err(ControlError::WorkerStart(error));
            }
        };
        if let Err(error) =
            self.journal
                .append(JournalEvent::Active, request.principal, None, session)
        {
            let mut worker = worker;
            let _ = worker.stop();
            return Err(error);
        }
        self.workers.insert(
            session,
            ActiveWorker {
                principal: request.principal,
                worker,
            },
        );
        Ok(session)
    }

    /// Stops one exact worker after authenticating principal and session binding.
    ///
    /// # Errors
    ///
    /// Returns an error for replay, foreign sessions, retryable worker cleanup, or journal
    /// persistence failure. The worker remains owned when cleanup reports failure.
    pub fn stop(&mut self, request: StopSessionRequest) -> Result<(), ControlError> {
        self.authenticator.verify_stop(request)?;
        if self.journal.used_requests.contains(&request.request) {
            return Err(ControlError::RequestReplay(request.request));
        }
        self.workers
            .get(&request.session)
            .filter(|worker| worker.principal == request.principal)
            .ok_or(ControlError::UnknownSession(request.session))?;
        self.journal.ensure_healthy()?;
        let worker = self.workers.get_mut(&request.session).ok_or_else(|| {
            ControlError::Journal("live worker map changed during synchronous stop".to_owned())
        })?;
        worker.worker.stop().map_err(ControlError::WorkerStop)?;
        self.journal.append(
            JournalEvent::Closed,
            request.principal,
            Some(request.request),
            request.session,
        )?;
        self.workers.remove(&request.session);
        Ok(())
    }

    /// Polls every live worker in stable session-ID order and durably closes workers that report
    /// completion.
    ///
    /// # Errors
    ///
    /// Fails closed on the first unavailable worker or journal error; remaining workers stay
    /// owned for a later call.
    pub fn poll_all(&mut self) -> Result<(), ControlError> {
        let sessions: Vec<_> = self.workers.keys().copied().collect();
        for session in sessions {
            self.journal.ensure_healthy()?;
            let Some(active) = self.workers.get_mut(&session) else {
                return Err(ControlError::Journal(
                    "live worker map changed during a synchronous poll".to_owned(),
                ));
            };
            match active.worker.poll() {
                Err(error) => {
                    let principal = active.principal;
                    if let Err(cleanup_error) = active.worker.stop() {
                        return Err(ControlError::WorkerPoll {
                            error,
                            cleanup_error: Some(cleanup_error),
                        });
                    }
                    self.journal
                        .append(JournalEvent::Closed, principal, None, session)?;
                    self.workers.remove(&session);
                    return Err(ControlError::WorkerPoll {
                        error,
                        cleanup_error: None,
                    });
                }
                Ok(ControlWorkerStatus::Closed) => {
                    let principal = active.principal;
                    self.journal
                        .append(JournalEvent::Closed, principal, None, session)?;
                    self.workers.remove(&session);
                }
                Ok(ControlWorkerStatus::Running) => {}
            }
        }
        Ok(())
    }

    /// Stops every worker in stable session-ID order and durably closes each completed worker.
    ///
    /// # Errors
    ///
    /// Returns on the first retryable cleanup or journal failure. That worker and every later
    /// worker remain owned, so a later call can resume without losing cleanup responsibility.
    pub fn shutdown_all(&mut self) -> Result<(), ControlError> {
        let sessions: Vec<_> = self.workers.keys().copied().collect();
        for session in sessions {
            self.journal.ensure_healthy()?;
            let Some(active) = self.workers.get_mut(&session) else {
                return Err(ControlError::Journal(
                    "live worker map changed during synchronous shutdown".to_owned(),
                ));
            };
            active.worker.stop().map_err(ControlError::WorkerStop)?;
            let principal = active.principal;
            self.journal
                .append(JournalEvent::Closed, principal, None, session)?;
            self.workers.remove(&session);
        }
        Ok(())
    }

    /// Returns the number of currently owned workers.
    #[must_use]
    pub fn active_sessions(&self) -> usize {
        self.workers.len()
    }

    /// Returns the number of currently owned workers for one principal.
    #[must_use]
    pub fn active_sessions_for(&self, principal: PrincipalId) -> usize {
        self.workers
            .values()
            .filter(|worker| worker.principal == principal)
            .count()
    }

    /// Returns whether this controller owns the exact live session.
    #[must_use]
    pub fn owns(&self, principal: PrincipalId, session: ControlSessionId) -> bool {
        self.workers
            .get(&session)
            .is_some_and(|worker| worker.principal == principal)
    }

    /// Returns the durable journal path whose lock fences this controller.
    #[must_use]
    pub fn journal_path(&self) -> &Path {
        &self.journal.path
    }

    fn fresh_session_id(&mut self) -> Result<ControlSessionId, ControlError> {
        for _ in 0..32 {
            let candidate = ControlSessionId(self.random.random_128()?);
            if !candidate.is_zero() && !self.journal.used_sessions.contains(&candidate) {
                return Ok(candidate);
            }
        }
        Err(ControlError::IdentityExhausted)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum JournalEvent {
    Reserved = 1,
    Active = 2,
    Closed = 3,
}

impl JournalEvent {
    fn parse(value: u8) -> Result<Self, ControlError> {
        match value {
            1 => Ok(Self::Reserved),
            2 => Ok(Self::Active),
            3 => Ok(Self::Closed),
            _ => Err(ControlError::Journal(format!(
                "unknown event value {value}"
            ))),
        }
    }
}

struct ControlJournal {
    path: PathBuf,
    file: File,
    lock: File,
    file_identity: ControlFileIdentity,
    lock_identity: ControlFileIdentity,
    length: u64,
    next_sequence: u64,
    used_requests: BTreeSet<ControlRequestId>,
    used_sessions: BTreeSet<ControlSessionId>,
    states: BTreeMap<ControlSessionId, (PrincipalId, JournalEvent)>,
    poisoned: bool,
}

impl ControlJournal {
    fn open(path: &Path) -> Result<Self, ControlError> {
        validate_parent(path)?;
        let lock_path = lock_path(path)?;
        let lock = open_private(&lock_path)?;
        let deadline = Instant::now() + TRANSIENT_FORK_LOCK_RETRY;
        loop {
            match lock.try_lock() {
                Ok(()) => break,
                Err(TryLockError::WouldBlock) if Instant::now() < deadline => {
                    thread::sleep(TRANSIENT_FORK_LOCK_POLL);
                }
                Err(TryLockError::WouldBlock) => {
                    return Err(ControlError::Fenced(path.to_path_buf()));
                }
                Err(TryLockError::Error(error)) => {
                    return Err(journal_io("locking controller journal", &lock_path, &error));
                }
            }
        }
        let lock_identity = validate_private_file(&lock_path, &lock)?;

        let (mut file, created) = open_or_create_private_journal(path)?;
        let file_identity = validate_private_file(path, &file)?;
        if created {
            let header = encode_header();
            file.write_all(&header)
                .and_then(|()| file.sync_all())
                .map_err(|error| journal_io("creating controller journal", path, &error))?;
            sync_parent(path)?;
        }
        let metadata = file
            .metadata()
            .map_err(|error| journal_io("reading controller journal metadata", path, &error))?;
        let maximum = HEADER_BYTES
            .checked_add(MAX_CONTROL_RECORDS.saturating_mul(RECORD_BYTES))
            .expect("control journal maximum fits usize");
        if metadata.len() > maximum as u64 {
            return Err(ControlError::Journal(format!(
                "{} exceeds the {}-byte limit",
                path.display(),
                maximum
            )));
        }
        file.seek(SeekFrom::Start(0))
            .map_err(|error| journal_io("seeking controller journal", path, &error))?;
        let expected_length = usize::try_from(metadata.len()).map_err(|_| {
            ControlError::Journal(format!(
                "{} length does not fit this platform",
                path.display()
            ))
        })?;
        let mut bytes = Vec::with_capacity(expected_length);
        file.read_to_end(&mut bytes)
            .map_err(|error| journal_io("reading controller journal", path, &error))?;
        if bytes.len() != expected_length {
            return Err(ControlError::Journal(format!(
                "{} changed length while being read",
                path.display()
            )));
        }
        validate_header(&bytes)?;
        let complete_bytes = bytes.len() - HEADER_BYTES;
        let full_records = complete_bytes / RECORD_BYTES;
        let tail = complete_bytes % RECORD_BYTES;
        let mut used_requests = BTreeSet::new();
        let mut used_sessions = BTreeSet::new();
        let mut states = BTreeMap::new();
        for index in 0..full_records {
            let offset = HEADER_BYTES + index * RECORD_BYTES;
            let record = decode_record(&bytes[offset..offset + RECORD_BYTES], index as u64)?;
            apply_record(record, &mut used_requests, &mut used_sessions, &mut states)?;
        }
        if tail != 0 {
            let tail_bytes = &bytes[HEADER_BYTES + full_records * RECORD_BYTES..];
            if !valid_partial_record(tail_bytes, full_records as u64) {
                return Err(ControlError::Journal(format!(
                    "{} has a non-record partial tail",
                    path.display()
                )));
            }
            let retained = HEADER_BYTES + full_records * RECORD_BYTES;
            file.set_len(retained as u64)
                .and_then(|()| file.sync_all())
                .map_err(|error| journal_io("truncating torn controller record", path, &error))?;
        }
        let length = file
            .seek(SeekFrom::End(0))
            .map_err(|error| journal_io("seeking controller journal tail", path, &error))?;
        Ok(Self {
            path: path.to_path_buf(),
            file,
            lock,
            file_identity,
            lock_identity,
            length,
            next_sequence: full_records as u64,
            used_requests,
            used_sessions,
            states,
            poisoned: false,
        })
    }

    fn append(
        &mut self,
        event: JournalEvent,
        principal: PrincipalId,
        request: Option<ControlRequestId>,
        session: ControlSessionId,
    ) -> Result<(), ControlError> {
        self.ensure_healthy()?;
        if self.next_sequence >= MAX_CONTROL_RECORDS_U64 {
            return Err(ControlError::Journal(format!(
                "record limit {MAX_CONTROL_RECORDS} reached"
            )));
        }
        let record = DecodedRecord {
            event,
            principal,
            request,
            session,
        };
        validate_next_record(
            record,
            &self.used_requests,
            &self.used_sessions,
            &self.states,
        )?;
        let encoded = encode_record(self.next_sequence, record);
        if let Err(error) = self
            .file
            .write_all(&encoded)
            .and_then(|()| self.file.sync_data())
        {
            self.poisoned = true;
            return Err(journal_io(
                "appending controller journal",
                &self.path,
                &error,
            ));
        }
        if let Err(error) = apply_record(
            record,
            &mut self.used_requests,
            &mut self.used_sessions,
            &mut self.states,
        ) {
            self.poisoned = true;
            return Err(error);
        }
        self.next_sequence = self
            .next_sequence
            .checked_add(1)
            .ok_or_else(|| ControlError::Journal("record sequence exhausted".to_owned()))?;
        self.length = self
            .length
            .checked_add(RECORD_BYTES_U64)
            .ok_or_else(|| ControlError::Journal("journal length exhausted".to_owned()))?;
        Ok(())
    }

    fn open_sessions(&self) -> Vec<(ControlSessionId, PrincipalId)> {
        self.states
            .iter()
            .filter(|(_, (_, state))| *state != JournalEvent::Closed)
            .map(|(session, (principal, _))| (*session, *principal))
            .collect()
    }

    fn ensure_healthy(&mut self) -> Result<(), ControlError> {
        if self.poisoned {
            return Err(ControlError::Journal(
                "a prior journal integrity check or write failed; restart is required".to_owned(),
            ));
        }
        self.validate_live_ownership()
    }

    fn validate_live_ownership(&mut self) -> Result<(), ControlError> {
        let result = self.validate_live_ownership_inner();
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }

    fn validate_live_ownership_inner(&mut self) -> Result<(), ControlError> {
        validate_parent(&self.path)?;
        let current_file = validate_private_file(&self.path, &self.file)?;
        let lock_path = lock_path(&self.path)?;
        let current_lock = validate_private_file(&lock_path, &self.lock)?;
        if current_file != self.file_identity || current_lock != self.lock_identity {
            return Err(ControlError::Journal(
                "controller journal or stable lock was replaced".to_owned(),
            ));
        }
        let observed_length = self
            .file
            .metadata()
            .map_err(|error| journal_io("checking controller journal length", &self.path, &error))?
            .len();
        if observed_length != self.length {
            return Err(ControlError::Journal(format!(
                "controller journal length changed: expected {}, found {observed_length}",
                self.length
            )));
        }
        let offset = self.file.seek(SeekFrom::End(0)).map_err(|error| {
            journal_io(
                "seeking controller journal append point",
                &self.path,
                &error,
            )
        })?;
        if offset != self.length {
            return Err(ControlError::Journal(
                "controller journal append offset changed".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ControlFileIdentity {
    device: u64,
    inode: u64,
}

#[derive(Clone, Copy)]
struct DecodedRecord {
    event: JournalEvent,
    principal: PrincipalId,
    request: Option<ControlRequestId>,
    session: ControlSessionId,
}

fn encode_header() -> [u8; HEADER_BYTES] {
    let mut bytes = [0_u8; HEADER_BYTES];
    bytes[..16].copy_from_slice(&JOURNAL_MAGIC);
    bytes[16..20].copy_from_slice(&JOURNAL_VERSION.to_be_bytes());
    let digest = Sha256::digest(&bytes[..32]);
    bytes[32..].copy_from_slice(&digest);
    bytes
}

fn validate_header(bytes: &[u8]) -> Result<(), ControlError> {
    if bytes.len() < HEADER_BYTES {
        return Err(ControlError::Journal(
            "controller journal header is truncated".to_owned(),
        ));
    }
    if bytes[..16] != JOURNAL_MAGIC {
        return Err(ControlError::Journal(
            "controller journal magic is invalid".to_owned(),
        ));
    }
    if bytes[16..20] != JOURNAL_VERSION.to_be_bytes() {
        return Err(ControlError::Journal(
            "controller journal version is unsupported".to_owned(),
        ));
    }
    let digest = Sha256::digest(&bytes[..32]);
    if bytes[32..64] != digest[..] {
        return Err(ControlError::Journal(
            "controller journal header checksum is invalid".to_owned(),
        ));
    }
    Ok(())
}

fn encode_record(sequence: u64, record: DecodedRecord) -> [u8; RECORD_BYTES] {
    let mut bytes = [0_u8; RECORD_BYTES];
    bytes[..8].copy_from_slice(&RECORD_MAGIC);
    bytes[8..16].copy_from_slice(&sequence.to_be_bytes());
    bytes[16] = record.event as u8;
    bytes[24..40].copy_from_slice(&record.principal.0);
    if let Some(request) = record.request {
        bytes[40..56].copy_from_slice(&request.0);
    }
    bytes[56..72].copy_from_slice(&record.session.0);
    let digest = Sha256::digest(&bytes[..RECORD_BODY_BYTES]);
    bytes[RECORD_BODY_BYTES..].copy_from_slice(&digest);
    bytes
}

fn decode_record(bytes: &[u8], expected_sequence: u64) -> Result<DecodedRecord, ControlError> {
    if bytes[..8] != RECORD_MAGIC {
        return Err(ControlError::Journal(format!(
            "record {expected_sequence} magic is invalid"
        )));
    }
    let sequence = u64::from_be_bytes(bytes[8..16].try_into().expect("fixed record sequence"));
    if sequence != expected_sequence {
        return Err(ControlError::Journal(format!(
            "record sequence {sequence} does not equal {expected_sequence}"
        )));
    }
    if bytes[17..24].iter().any(|byte| *byte != 0)
        || bytes[72..RECORD_BODY_BYTES].iter().any(|byte| *byte != 0)
    {
        return Err(ControlError::Journal(format!(
            "record {sequence} has non-zero reserved bytes"
        )));
    }
    let digest = Sha256::digest(&bytes[..RECORD_BODY_BYTES]);
    if bytes[RECORD_BODY_BYTES..] != digest[..] {
        return Err(ControlError::Journal(format!(
            "record {sequence} checksum is invalid"
        )));
    }
    let event = JournalEvent::parse(bytes[16])?;
    let principal = PrincipalId(bytes[24..40].try_into().expect("fixed principal"));
    let request_bytes: [u8; ID_BYTES] = bytes[40..56].try_into().expect("fixed request");
    let request = (request_bytes != [0; ID_BYTES]).then_some(ControlRequestId(request_bytes));
    let session = ControlSessionId(bytes[56..72].try_into().expect("fixed session"));
    if principal.is_zero() || session.is_zero() {
        return Err(ControlError::Journal(format!(
            "record {sequence} contains a zero identity"
        )));
    }
    if event == JournalEvent::Reserved && request.is_none() {
        return Err(ControlError::Journal(format!(
            "reservation record {sequence} has no request identity"
        )));
    }
    Ok(DecodedRecord {
        event,
        principal,
        request,
        session,
    })
}

fn apply_record(
    record: DecodedRecord,
    requests: &mut BTreeSet<ControlRequestId>,
    sessions: &mut BTreeSet<ControlSessionId>,
    states: &mut BTreeMap<ControlSessionId, (PrincipalId, JournalEvent)>,
) -> Result<(), ControlError> {
    if let Some(request) = record.request
        && !requests.insert(request)
    {
        return Err(ControlError::Journal(format!(
            "request {request} is duplicated in durable history"
        )));
    }
    match record.event {
        JournalEvent::Reserved => {
            if !sessions.insert(record.session) || states.contains_key(&record.session) {
                return Err(ControlError::Journal(format!(
                    "session {} is reused in durable history",
                    record.session
                )));
            }
            states.insert(record.session, (record.principal, record.event));
        }
        JournalEvent::Active => {
            let Some((principal, state)) = states.get_mut(&record.session) else {
                return Err(ControlError::Journal(format!(
                    "session {} became active before reservation",
                    record.session
                )));
            };
            if *principal != record.principal || *state != JournalEvent::Reserved {
                return Err(ControlError::Journal(format!(
                    "session {} has an invalid active transition",
                    record.session
                )));
            }
            *state = JournalEvent::Active;
        }
        JournalEvent::Closed => {
            let Some((principal, state)) = states.get_mut(&record.session) else {
                return Err(ControlError::Journal(format!(
                    "session {} closed before reservation",
                    record.session
                )));
            };
            if *principal != record.principal || *state == JournalEvent::Closed {
                return Err(ControlError::Journal(format!(
                    "session {} has an invalid close transition",
                    record.session
                )));
            }
            *state = JournalEvent::Closed;
        }
    }
    Ok(())
}

fn validate_next_record(
    record: DecodedRecord,
    requests: &BTreeSet<ControlRequestId>,
    sessions: &BTreeSet<ControlSessionId>,
    states: &BTreeMap<ControlSessionId, (PrincipalId, JournalEvent)>,
) -> Result<(), ControlError> {
    if record
        .request
        .is_some_and(|request| requests.contains(&request))
    {
        return Err(ControlError::Journal(
            "attempted to append a duplicate control request".to_owned(),
        ));
    }
    match record.event {
        JournalEvent::Reserved => {
            if record.request.is_none()
                || sessions.contains(&record.session)
                || states.contains_key(&record.session)
            {
                return Err(ControlError::Journal(
                    "attempted to append an invalid reservation".to_owned(),
                ));
            }
        }
        JournalEvent::Active => {
            if !matches!(
                states.get(&record.session),
                Some((principal, JournalEvent::Reserved)) if *principal == record.principal
            ) {
                return Err(ControlError::Journal(
                    "attempted to append an invalid active transition".to_owned(),
                ));
            }
        }
        JournalEvent::Closed => {
            if !matches!(
                states.get(&record.session),
                Some((principal, JournalEvent::Reserved | JournalEvent::Active))
                    if *principal == record.principal
            ) {
                return Err(ControlError::Journal(
                    "attempted to append an invalid close transition".to_owned(),
                ));
            }
        }
    }
    Ok(())
}

fn valid_partial_record(bytes: &[u8], expected_sequence: u64) -> bool {
    let prefix_len = bytes.len().min(RECORD_MAGIC.len());
    if bytes[..prefix_len] != RECORD_MAGIC[..prefix_len] {
        return false;
    }
    if bytes.len() > 8 {
        let sequence = expected_sequence.to_be_bytes();
        let available = (bytes.len() - 8).min(sequence.len());
        if bytes[8..8 + available] != sequence[..available] {
            return false;
        }
    }
    if bytes.len() > 16 && JournalEvent::parse(bytes[16]).is_err() {
        return false;
    }
    true
}

fn lock_path(path: &Path) -> Result<PathBuf, ControlError> {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty())
        .ok_or_else(|| ControlError::Journal("journal path has no UTF-8 file name".to_owned()))?;
    Ok(path.with_file_name(format!("{name}.lock")))
}

fn open_private(path: &Path) -> Result<File, ControlError> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true);
    #[cfg(unix)]
    options.mode(0o600).custom_flags(
        i32::try_from(rustix::fs::OFlags::NOFOLLOW.bits())
            .expect("O_NOFOLLOW flag fits platform custom flags"),
    );
    options
        .open(path)
        .map_err(|error| journal_io("opening private controller file", path, &error))
}

fn open_or_create_private_journal(path: &Path) -> Result<(File, bool), ControlError> {
    let mut create = OpenOptions::new();
    create.read(true).write(true).create_new(true);
    #[cfg(unix)]
    create.mode(0o600).custom_flags(
        i32::try_from(rustix::fs::OFlags::NOFOLLOW.bits())
            .expect("O_NOFOLLOW flag fits platform custom flags"),
    );
    match create.open(path) {
        Ok(file) => Ok((file, true)),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            let mut existing = OpenOptions::new();
            existing.read(true).write(true);
            #[cfg(unix)]
            existing.custom_flags(
                i32::try_from(rustix::fs::OFlags::NOFOLLOW.bits())
                    .expect("O_NOFOLLOW flag fits platform custom flags"),
            );
            existing
                .open(path)
                .map(|file| (file, false))
                .map_err(|error| journal_io("opening existing controller journal", path, &error))
        }
        Err(error) => Err(journal_io(
            "atomically creating controller journal",
            path,
            &error,
        )),
    }
}

#[cfg(unix)]
fn validate_parent(path: &Path) -> Result<(), ControlError> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let metadata = fs::symlink_metadata(parent)
        .map_err(|error| journal_io("validating controller parent", parent, &error))?;
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        return Err(ControlError::Journal(format!(
            "controller parent is not a real directory: {}",
            parent.display()
        )));
    }
    let effective_uid = rustix::process::geteuid().as_raw();
    if metadata.uid() != effective_uid || metadata.permissions().mode() & 0o022 != 0 {
        return Err(ControlError::Journal(format!(
            "controller parent must be owned by uid {effective_uid} and not group/world writable: {}",
            parent.display()
        )));
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_parent(_path: &Path) -> Result<(), ControlError> {
    Err(ControlError::Journal(
        "durable controller ownership requires Unix file metadata".to_owned(),
    ))
}

#[cfg(unix)]
fn validate_private_file(path: &Path, file: &File) -> Result<ControlFileIdentity, ControlError> {
    let metadata = file
        .metadata()
        .map_err(|error| journal_io("validating private controller file", path, &error))?;
    let path_metadata = fs::symlink_metadata(path)
        .map_err(|error| journal_io("validating controller path", path, &error))?;
    let effective_uid = rustix::process::geteuid().as_raw();
    if !metadata.is_file()
        || path_metadata.file_type().is_symlink()
        || metadata.uid() != effective_uid
        || metadata.permissions().mode() & 0o777 != 0o600
        || metadata.dev() != path_metadata.dev()
        || metadata.ino() != path_metadata.ino()
    {
        return Err(ControlError::Journal(format!(
            "controller file must be an owner-only stable regular file: {}",
            path.display()
        )));
    }
    Ok(ControlFileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

#[cfg(not(unix))]
fn validate_private_file(_path: &Path, _file: &File) -> Result<ControlFileIdentity, ControlError> {
    Err(ControlError::Journal(
        "durable controller ownership requires Unix file metadata".to_owned(),
    ))
}

fn sync_parent(path: &Path) -> Result<(), ControlError> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| journal_io("syncing controller parent", parent, &error))
}

fn journal_io(operation: &str, path: &Path, error: &io::Error) -> ControlError {
    ControlError::Journal(format!("{operation} at {}: {error}", path.display()))
}

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        env, fs,
        sync::atomic::{AtomicU64, Ordering},
    };

    #[cfg(unix)]
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt, symlink};

    use super::*;

    static FIXTURE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    struct Fixture {
        directory: PathBuf,
        path: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let sequence = FIXTURE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let directory =
                env::temp_dir().join(format!("session-control-{}-{sequence}", std::process::id()));
            fs::create_dir(&directory).expect("fixture directory");
            #[cfg(unix)]
            fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))
                .expect("private fixture directory");
            let path = directory.join("control.journal");
            Self { directory, path }
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.directory);
        }
    }

    #[derive(Default)]
    struct ScriptedRandom {
        bytes: VecDeque<[u8; ID_BYTES]>,
    }

    impl ScriptedRandom {
        fn new(values: impl IntoIterator<Item = u8>) -> Self {
            Self {
                bytes: values.into_iter().map(|value| [value; ID_BYTES]).collect(),
            }
        }
    }

    impl CryptographicRandom for ScriptedRandom {
        fn random_128(&mut self) -> Result<[u8; ID_BYTES], EntropyError> {
            self.bytes
                .pop_front()
                .ok_or_else(|| EntropyError::new("script exhausted"))
        }
    }

    struct TestWorker {
        closed: bool,
        poll_fails: bool,
        stop_fails: bool,
    }

    impl ControlWorker for TestWorker {
        fn poll(&mut self) -> Result<ControlWorkerStatus, ControlWorkerError> {
            if self.poll_fails {
                return Err(ControlWorkerError::StatusUnavailable);
            }
            Ok(if self.closed {
                ControlWorkerStatus::Closed
            } else {
                ControlWorkerStatus::Running
            })
        }

        fn stop(&mut self) -> Result<(), ControlWorkerError> {
            if self.stop_fails {
                Err(ControlWorkerError::CleanupIncomplete)
            } else {
                self.closed = true;
                Ok(())
            }
        }
    }

    #[derive(Default)]
    #[allow(clippy::struct_excessive_bools)] // Independent fault switches keep matrix fixtures explicit.
    struct TestFactory {
        spawned: Vec<(PrincipalId, ControlSessionId)>,
        recovered: Vec<(PrincipalId, ControlSessionId)>,
        fail_spawn: bool,
        fail_recovery: bool,
        poll_fails: bool,
        stop_fails: bool,
    }

    impl ControlWorkerFactory for TestFactory {
        type Worker = TestWorker;

        fn spawn(
            &mut self,
            principal: PrincipalId,
            session: ControlSessionId,
        ) -> Result<Self::Worker, ControlWorkerError> {
            self.spawned.push((principal, session));
            if self.fail_spawn {
                Err(ControlWorkerError::StartupFailed)
            } else {
                Ok(TestWorker {
                    closed: false,
                    poll_fails: self.poll_fails,
                    stop_fails: self.stop_fails,
                })
            }
        }

        fn recover(
            &mut self,
            principal: PrincipalId,
            session: ControlSessionId,
        ) -> Result<(), ControlWorkerError> {
            self.recovered.push((principal, session));
            if self.fail_recovery {
                Err(ControlWorkerError::CleanupIncomplete)
            } else {
                Ok(())
            }
        }
    }

    fn principal(value: u8) -> PrincipalId {
        PrincipalId::new([value; ID_BYTES])
    }

    fn request(value: u8) -> ControlRequestId {
        ControlRequestId::new([value; ID_BYTES])
    }

    fn auth() -> ControlAuthenticator {
        ControlAuthenticator::new([0x5a; 32])
    }

    fn controller(
        path: &Path,
        factory: TestFactory,
        random: ScriptedRandom,
    ) -> MultiSessionController<TestFactory, ScriptedRandom> {
        MultiSessionController::open(
            path,
            ControlLimits::new(3, 2).expect("limits"),
            auth(),
            factory,
            random,
        )
        .expect("controller")
    }

    #[cfg(unix)]
    #[test]
    fn journal_creation_rejects_dangling_links_without_initializing_their_target() {
        let fixture = Fixture::new();
        let missing_target = fixture.directory.join("missing-target");
        symlink(&missing_target, &fixture.path).expect("create dangling journal link");
        assert!(matches!(
            ControlJournal::open(&fixture.path),
            Err(ControlError::Journal(_))
        ));
        assert!(
            !missing_target.exists(),
            "rejecting a dangling journal link must not initialize its target"
        );
    }

    #[test]
    fn authenticated_scheduler_runs_multiple_one_session_workers_with_quotas() {
        let fixture = Fixture::new();
        let mut controller = controller(
            &fixture.path,
            TestFactory::default(),
            ScriptedRandom::new([11, 12, 13, 14]),
        );
        let first = controller
            .start(auth().sign_start(principal(1), request(1)))
            .expect("first");
        let second = controller
            .start(auth().sign_start(principal(1), request(2)))
            .expect("second");
        let third = controller
            .start(auth().sign_start(principal(2), request(3)))
            .expect("third");
        assert_ne!(first, second);
        assert_eq!(controller.active_sessions(), 3);
        assert_eq!(controller.active_sessions_for(principal(1)), 2);
        assert_eq!(controller.active_sessions_for(principal(2)), 1);
        assert_eq!(
            controller.start(auth().sign_start(principal(1), request(4))),
            Err(ControlError::GlobalQuota)
        );
        controller
            .stop(auth().sign_stop(principal(2), request(5), third))
            .expect("stop third");
        assert_eq!(
            controller.start(auth().sign_start(principal(1), request(6))),
            Err(ControlError::PrincipalQuota(principal(1)))
        );
    }

    #[test]
    fn bad_authentication_foreign_stop_and_request_replay_fail_closed() {
        let fixture = Fixture::new();
        let mut controller = controller(
            &fixture.path,
            TestFactory::default(),
            ScriptedRandom::new([21]),
        );
        let bad = ControlAuthenticator::new([0x99; 32]).sign_start(principal(1), request(1));
        assert_eq!(controller.start(bad), Err(ControlError::Authentication));
        let session = controller
            .start(auth().sign_start(principal(1), request(1)))
            .expect("start");
        assert_eq!(
            controller.stop(auth().sign_stop(principal(2), request(2), session)),
            Err(ControlError::UnknownSession(session))
        );
        controller
            .stop(auth().sign_stop(principal(1), request(2), session))
            .expect("owned stop");
        assert_eq!(
            controller.start(auth().sign_start(principal(1), request(1))),
            Err(ControlError::RequestReplay(request(1)))
        );
    }

    #[test]
    fn second_controller_is_fenced_while_the_first_holds_the_lock() {
        let fixture = Fixture::new();
        let first = controller(
            &fixture.path,
            TestFactory::default(),
            ScriptedRandom::new([]),
        );
        let second = MultiSessionController::open(
            &fixture.path,
            ControlLimits::new(1, 1).expect("limits"),
            auth(),
            TestFactory::default(),
            ScriptedRandom::new([]),
        );
        assert!(matches!(second, Err(ControlError::Fenced(_))));
        drop(first);
        controller(
            &fixture.path,
            TestFactory::default(),
            ScriptedRandom::new([]),
        );
    }

    #[test]
    fn restart_recovers_reserved_or_active_workers_and_never_reuses_ids() {
        let fixture = Fixture::new();
        let session = {
            let mut first = controller(
                &fixture.path,
                TestFactory::default(),
                ScriptedRandom::new([31]),
            );
            first
                .start(auth().sign_start(principal(3), request(3)))
                .expect("start")
        };
        let mut reopened = controller(
            &fixture.path,
            TestFactory::default(),
            ScriptedRandom::new([31, 32]),
        );
        assert_eq!(reopened.factory.recovered, vec![(principal(3), session)]);
        let new_session = reopened
            .start(auth().sign_start(principal(3), request(4)))
            .expect("new start");
        assert_eq!(new_session, ControlSessionId::new([32; ID_BYTES]));
        assert_ne!(new_session, session);
    }

    #[test]
    fn spawn_failure_burns_both_request_and_session() {
        let fixture = Fixture::new();
        let mut first = controller(
            &fixture.path,
            TestFactory {
                fail_spawn: true,
                ..TestFactory::default()
            },
            ScriptedRandom::new([41]),
        );
        assert!(matches!(
            first.start(auth().sign_start(principal(4), request(4))),
            Err(ControlError::WorkerStart(_))
        ));
        drop(first);
        let mut reopened = controller(
            &fixture.path,
            TestFactory::default(),
            ScriptedRandom::new([41, 42]),
        );
        assert_eq!(
            reopened.start(auth().sign_start(principal(4), request(4))),
            Err(ControlError::RequestReplay(request(4)))
        );
        let session = reopened
            .start(auth().sign_start(principal(4), request(5)))
            .expect("fresh request");
        assert_eq!(session, ControlSessionId::new([42; ID_BYTES]));
    }

    #[test]
    fn valid_torn_tail_is_truncated_but_corrupt_full_record_is_rejected() {
        let fixture = Fixture::new();
        {
            let controller = controller(
                &fixture.path,
                TestFactory::default(),
                ScriptedRandom::new([]),
            );
            drop(controller);
        }
        let partial = encode_record(
            0,
            DecodedRecord {
                event: JournalEvent::Reserved,
                principal: principal(1),
                request: Some(request(1)),
                session: ControlSessionId::new([1; ID_BYTES]),
            },
        );
        OpenOptions::new()
            .append(true)
            .open(&fixture.path)
            .expect("append")
            .write_all(&partial[..37])
            .expect("partial tail");
        let reopened = controller(
            &fixture.path,
            TestFactory::default(),
            ScriptedRandom::new([]),
        );
        drop(reopened);
        assert_eq!(
            fs::metadata(&fixture.path).expect("metadata").len(),
            HEADER_BYTES as u64
        );

        let mut corrupt = partial;
        corrupt[80] = 1;
        OpenOptions::new()
            .append(true)
            .open(&fixture.path)
            .expect("append corrupt")
            .write_all(&corrupt)
            .expect("corrupt record");
        let result = MultiSessionController::open(
            &fixture.path,
            ControlLimits::new(1, 1).expect("limits"),
            auth(),
            TestFactory::default(),
            ScriptedRandom::new([]),
        );
        assert!(matches!(result, Err(ControlError::Journal(_))));
    }

    #[test]
    fn unsafe_permissions_and_retryable_stop_are_not_hidden() {
        let fixture = Fixture::new();
        let mut controller = controller(
            &fixture.path,
            TestFactory {
                stop_fails: true,
                ..TestFactory::default()
            },
            ScriptedRandom::new([51]),
        );
        let session = controller
            .start(auth().sign_start(principal(5), request(5)))
            .expect("start");
        assert!(matches!(
            controller.stop(auth().sign_stop(principal(5), request(6), session)),
            Err(ControlError::WorkerStop(_))
        ));
        assert!(controller.owns(principal(5), session));
        drop(controller);

        #[cfg(unix)]
        fs::set_permissions(&fixture.path, fs::Permissions::from_mode(0o644))
            .expect("loosen journal");
        let result = MultiSessionController::open(
            &fixture.path,
            ControlLimits::new(1, 1).expect("limits"),
            auth(),
            TestFactory::default(),
            ScriptedRandom::new([]),
        );
        assert!(matches!(result, Err(ControlError::Journal(_))));
    }

    #[test]
    fn partial_tail_rejects_bytes_that_are_not_the_next_record_prefix() {
        let fixture = Fixture::new();
        {
            let controller = controller(
                &fixture.path,
                TestFactory::default(),
                ScriptedRandom::new([]),
            );
            drop(controller);
        }
        let mut options = OpenOptions::new();
        options.append(true);
        #[cfg(unix)]
        options.mode(0o600);
        options
            .open(&fixture.path)
            .expect("journal")
            .write_all(b"attacker-tail")
            .expect("tail");
        let result = MultiSessionController::open(
            &fixture.path,
            ControlLimits::new(1, 1).expect("limits"),
            auth(),
            TestFactory::default(),
            ScriptedRandom::new([]),
        );
        assert!(matches!(result, Err(ControlError::Journal(_))));
    }

    #[test]
    fn poll_closes_only_workers_that_report_completed_cleanup() {
        let fixture = Fixture::new();
        let mut controller = controller(
            &fixture.path,
            TestFactory::default(),
            ScriptedRandom::new([61]),
        );
        let session = controller
            .start(auth().sign_start(principal(6), request(6)))
            .expect("start");
        controller
            .workers
            .get_mut(&session)
            .expect("worker")
            .worker
            .closed = true;
        controller.poll_all().expect("poll");
        assert_eq!(controller.active_sessions(), 0);
    }

    #[test]
    fn unavailable_health_fails_closed_and_retains_incomplete_cleanup() {
        let clean_fixture = Fixture::new();
        let mut clean = controller(
            &clean_fixture.path,
            TestFactory {
                poll_fails: true,
                ..TestFactory::default()
            },
            ScriptedRandom::new([62]),
        );
        clean
            .start(auth().sign_start(principal(6), request(7)))
            .expect("start cleanable worker");
        assert_eq!(
            clean.poll_all(),
            Err(ControlError::WorkerPoll {
                error: ControlWorkerError::StatusUnavailable,
                cleanup_error: None,
            })
        );
        assert_eq!(clean.active_sessions(), 0);

        let retained_fixture = Fixture::new();
        let mut retained = controller(
            &retained_fixture.path,
            TestFactory {
                poll_fails: true,
                stop_fails: true,
                ..TestFactory::default()
            },
            ScriptedRandom::new([63]),
        );
        let session = retained
            .start(auth().sign_start(principal(6), request(8)))
            .expect("start retryable worker");
        assert_eq!(
            retained.poll_all(),
            Err(ControlError::WorkerPoll {
                error: ControlWorkerError::StatusUnavailable,
                cleanup_error: Some(ControlWorkerError::CleanupIncomplete),
            })
        );
        assert!(retained.owns(principal(6), session));
    }

    #[test]
    fn live_length_and_path_replacement_poison_the_controller_before_worker_effects() {
        let fixture = Fixture::new();
        let mut length_changed = controller(
            &fixture.path,
            TestFactory::default(),
            ScriptedRandom::new([71]),
        );
        OpenOptions::new()
            .append(true)
            .open(&fixture.path)
            .expect("journal append")
            .write_all(b"x")
            .expect("length drift");
        assert!(matches!(
            length_changed.start(auth().sign_start(principal(7), request(7))),
            Err(ControlError::Journal(_))
        ));
        assert!(length_changed.factory.spawned.is_empty());
        drop(length_changed);

        let replacement_fixture = Fixture::new();
        let mut replaced = controller(
            &replacement_fixture.path,
            TestFactory::default(),
            ScriptedRandom::new([72]),
        );
        let displaced = replacement_fixture.directory.join("displaced.journal");
        fs::rename(&replacement_fixture.path, &displaced).expect("displace journal");
        fs::copy(&displaced, &replacement_fixture.path).expect("replace journal path");
        #[cfg(unix)]
        fs::set_permissions(&replacement_fixture.path, fs::Permissions::from_mode(0o600))
            .expect("replacement mode");
        assert!(matches!(
            replaced.start(auth().sign_start(principal(7), request(8))),
            Err(ControlError::Journal(_))
        ));
        assert!(replaced.factory.spawned.is_empty());
    }

    #[test]
    fn transient_journal_path_loss_permanently_poisons_the_controller() {
        let fixture = Fixture::new();
        let mut controller = controller(
            &fixture.path,
            TestFactory::default(),
            ScriptedRandom::new([73, 74]),
        );
        let displaced = fixture.directory.join("temporarily-displaced.journal");
        fs::rename(&fixture.path, &displaced).expect("displace journal");
        assert!(matches!(
            controller.start(auth().sign_start(principal(7), request(9))),
            Err(ControlError::Journal(_))
        ));
        fs::rename(&displaced, &fixture.path).expect("restore journal path");

        let error = controller
            .start(auth().sign_start(principal(7), request(10)))
            .expect_err("poisoned controller must not recover in place");
        assert!(matches!(
            error,
            ControlError::Journal(message) if message.contains("prior journal integrity check or write failed")
        ));
        assert!(controller.factory.spawned.is_empty());
    }

    #[test]
    fn journal_drift_is_rejected_before_worker_cleanup() {
        let fixture = Fixture::new();
        let mut controller = controller(
            &fixture.path,
            TestFactory::default(),
            ScriptedRandom::new([75]),
        );
        let session = controller
            .start(auth().sign_start(principal(7), request(11)))
            .expect("start worker");
        let displaced = fixture.directory.join("cleanup-displaced.journal");
        fs::rename(&fixture.path, &displaced).expect("displace journal");

        assert!(matches!(
            controller.stop(auth().sign_stop(principal(7), request(12), session)),
            Err(ControlError::Journal(_))
        ));
        assert!(controller.owns(principal(7), session));
        assert!(
            !controller
                .workers
                .get(&session)
                .expect("owned worker")
                .worker
                .closed
        );

        fs::rename(&displaced, &fixture.path).expect("restore journal path");
    }

    #[test]
    fn shutdown_all_is_ordered_and_retains_retryable_workers() {
        let fixture = Fixture::new();
        let mut first_controller = controller(
            &fixture.path,
            TestFactory::default(),
            ScriptedRandom::new([81, 82]),
        );
        first_controller
            .start(auth().sign_start(principal(8), request(8)))
            .expect("first");
        first_controller
            .start(auth().sign_start(principal(8), request(9)))
            .expect("second");
        first_controller.shutdown_all().expect("shutdown");
        assert_eq!(first_controller.active_sessions(), 0);

        drop(first_controller);
        let mut retrying = controller(
            &fixture.path,
            TestFactory {
                stop_fails: true,
                ..TestFactory::default()
            },
            ScriptedRandom::new([83]),
        );
        retrying
            .start(auth().sign_start(principal(8), request(10)))
            .expect("retry worker");
        assert_eq!(
            retrying.shutdown_all(),
            Err(ControlError::WorkerStop(
                ControlWorkerError::CleanupIncomplete
            ))
        );
        assert_eq!(retrying.active_sessions(), 1);
    }

    #[test]
    fn created_files_are_owner_only() {
        let fixture = Fixture::new();
        let controller = controller(
            &fixture.path,
            TestFactory::default(),
            ScriptedRandom::new([]),
        );
        drop(controller);
        #[cfg(unix)]
        {
            assert_eq!(
                fs::metadata(&fixture.path)
                    .expect("journal metadata")
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
            assert_eq!(
                fs::metadata(lock_path(&fixture.path).expect("lock path"))
                    .expect("lock metadata")
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
    }
}
