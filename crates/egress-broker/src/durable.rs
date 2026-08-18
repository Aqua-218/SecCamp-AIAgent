//! Crash-recoverable replay and budget state for one broker session.
//!
//! Every state transition is appended to a bounded, checksummed WAL and
//! `fsync`ed before it becomes visible through this API. An `AcceptedPending`
//! record is therefore the durable no-reexecution marker: after a process
//! restart, callers must finalize it conservatively instead of calling an
//! adapter again. Final records retain the exact canonical response bytes so
//! exact duplicates are observationally identical across restarts.

use std::{
    collections::BTreeMap,
    error::Error,
    ffi::{OsStr, OsString},
    fmt,
    fs::{self, File, OpenOptions, TryLockError},
    io::{self, Read, Seek, SeekFrom, Write},
    num::{NonZeroU64, NonZeroUsize},
    path::{Path, PathBuf},
    sync::OnceLock,
    thread,
    time::{Duration, Instant},
};

#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

use egress_protocol::{
    budget::{SessionBudget, SessionBudgetError, SessionBudgetLimits},
    response::{
        CanonicalBrokerResponse, CanonicalResponseChunk, MAX_EXPANDED_CANONICAL_RESPONSE_BYTES,
        MAX_PUBLIC_WIRE_BODY_BYTES, MAX_RESPONSE_CHUNK_BYTES, ResponseCborError,
        ResponseChunkError,
    },
    session::{BrokerEnvelope, BrokerRequestId, BrokerSessionId},
};

const MAGIC: &[u8; 8] = b"EGBWAL01";
const VERSION: u16 = 1;
const INIT_KIND: u8 = 0;
const ACCEPT_KIND: u8 = 1;
const RESERVE_KIND: u8 = 2;
const RETRYABLE_BUDGET_KIND: u8 = 3;
const FINAL_KIND: u8 = 4;
const HEADER_LEN: usize = 8 + 2 + 1 + 1 + 8 + 4;
const CHECKSUM_LEN: usize = 8;
const INIT_PAYLOAD_LEN: usize = 16 + 8 + 8 + 8 + 8;
const ACCEPT_PAYLOAD_LEN: usize = 8 + 16 + 32 + 8;
const REQUEST_PAYLOAD_LEN: usize = 16;
const FINAL_PREFIX_LEN: usize = 16 + 1 + 7 + 8 + 4;
const MAX_RECORD_PAYLOAD_BYTES: usize = MAX_EXPANDED_CANONICAL_RESPONSE_BYTES + 64 * 1024;
const MAX_FINAL_WIRE_PAYLOADS: usize =
    MAX_EXPANDED_CANONICAL_RESPONSE_BYTES.div_ceil(MAX_RESPONSE_CHUNK_BYTES);
const MAX_TERMINAL_RECORD_OVERHEAD: usize = MAX_RECORD_PAYLOAD_BYTES - 32 * 1024 * 1024;
#[cfg(test)]
const MAX_FINAL_APPEND_TRANSIENT_DATA_BYTES: usize = MAX_RECORD_PAYLOAD_BYTES * 2;
const TRANSIENT_FORK_LOCK_RETRY: Duration = Duration::from_millis(250);
const TRANSIENT_FORK_LOCK_POLL: Duration = Duration::from_millis(2);
#[cfg(target_os = "linux")]
const O_NOFOLLOW: i32 = 0o400_000;
#[cfg(unix)]
const PRIVATE_FILE_MODE: u32 = 0o600;
#[cfg(unix)]
const WRITE_BY_GROUP_OR_OTHER: u32 = 0o022;
const ACCESS_BY_GROUP_OR_OTHER: u32 = 0o077;
const STICKY_DIRECTORY: u32 = 0o1000;

/// Maximum on-disk size accepted for one broker WAL.
pub const MAX_DURABLE_BROKER_WAL_BYTES: u64 = 128 * 1024 * 1024;

/// Immutable configuration bound to one durable broker session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DurableSessionConfig {
    session: BrokerSessionId,
    replay_capacity: NonZeroUsize,
    budget_limits: SessionBudgetLimits,
}

impl DurableSessionConfig {
    /// Creates a durable session configuration.
    #[must_use]
    pub const fn new(
        session: BrokerSessionId,
        replay_capacity: NonZeroUsize,
        budget_limits: SessionBudgetLimits,
    ) -> Self {
        Self {
            session,
            replay_capacity,
            budget_limits,
        }
    }

    /// Returns the session identity bound to the WAL.
    #[must_use]
    pub const fn session(self) -> BrokerSessionId {
        self.session
    }

    /// Returns the maximum number of replay identities retained.
    #[must_use]
    pub const fn replay_capacity(self) -> NonZeroUsize {
        self.replay_capacity
    }

    /// Returns the immutable session budget ceilings.
    #[must_use]
    pub const fn budget_limits(self) -> SessionBudgetLimits {
        self.budget_limits
    }
}

/// How an active budget reservation is settled by a final outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BudgetSettlement {
    /// The request reached a terminal response before a budget reservation.
    NotStarted,
    /// An attempted request failed before a response was committed.
    Abort,
    /// The request consumes the stated number of response bytes.
    Complete {
        /// Actual bytes charged, or the full cap for an ambiguous commit.
        response_bytes: u64,
    },
}

/// One exact canonical response retained in a terminal WAL record.
#[derive(Debug)]
pub struct DurableCanonicalResponse {
    response: CanonicalBrokerResponse,
    wire_payloads: OnceLock<Vec<Vec<u8>>>,
}

impl Clone for DurableCanonicalResponse {
    fn clone(&self) -> Self {
        Self {
            response: self.response.clone(),
            wire_payloads: OnceLock::new(),
        }
    }
}

impl PartialEq for DurableCanonicalResponse {
    fn eq(&self, other: &Self) -> bool {
        self.response == other.response
    }
}

impl Eq for DurableCanonicalResponse {}

impl DurableCanonicalResponse {
    /// Returns the decoded, typed canonical response.
    #[must_use]
    pub const fn response(&self) -> &CanonicalBrokerResponse {
        &self.response
    }

    /// Returns the exact ordered frame payloads to replay to the guest.
    ///
    /// A response fitting one control frame has one direct response payload.
    /// An expanded response has its complete canonical chunk payload sequence.
    ///
    /// # Panics
    ///
    /// Panics only if an internally validated canonical response can no longer
    /// be encoded by the same protocol version that accepted it.
    #[must_use]
    pub fn wire_payloads(&self) -> &[Vec<u8>] {
        self.wire_payloads
            .get_or_init(|| {
                canonical_wire_payloads(&self.response)
                    .expect("validated durable response must retain a canonical wire sequence")
            })
            .as_slice()
    }

    fn from_wire_payloads(
        request: BrokerRequestId,
        wire_payloads: &[Vec<u8>],
    ) -> Result<Self, DurableWalError> {
        let response = decode_wire_payloads(wire_payloads)?;
        if response.request() != request {
            return Err(DurableWalError::ResponseRequestMismatch {
                expected: request,
                received: response.request(),
            });
        }
        if canonical_wire_payloads(&response)? != wire_payloads {
            return Err(DurableWalError::InvalidRecord(
                "terminal response payloads are not the canonical wire sequence".to_owned(),
            ));
        }
        Ok(Self {
            response,
            wire_payloads: OnceLock::new(),
        })
    }
}

/// Durable phase of one accepted request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DurableRequestPhase {
    /// Admission is durable and the adapter must never be re-executed on recovery.
    AcceptedPending,
    /// Budget admission failed transiently before the adapter was invoked.
    RetryableBudget,
    /// An exact canonical terminal response has been retained.
    Final(DurableCanonicalResponse),
}

/// One request reconstructed from the durable WAL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DurableRequest {
    sequence: u64,
    request: BrokerRequestId,
    payload_hash: [u8; 32],
    response_cap: u64,
    phase: DurableRequestPhase,
    reservation: Option<u64>,
    final_settlement: Option<BudgetSettlement>,
}

impl DurableRequest {
    /// Returns the strict session sequence admitted for this request.
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Returns the admitted idempotency identity.
    #[must_use]
    pub const fn request(&self) -> BrokerRequestId {
        self.request
    }

    /// Returns the admitted canonical payload digest bytes.
    #[must_use]
    pub const fn payload_hash(&self) -> &[u8; 32] {
        &self.payload_hash
    }

    /// Returns the response-byte cap bound at admission.
    #[must_use]
    pub const fn response_cap(&self) -> u64 {
        self.response_cap
    }

    /// Returns the recovered request phase.
    #[must_use]
    pub const fn phase(&self) -> &DurableRequestPhase {
        &self.phase
    }

    /// Returns the active reservation cap, if budget start was durable.
    #[must_use]
    pub const fn active_reservation(&self) -> Option<u64> {
        self.reservation
    }

    /// Returns the terminal budget settlement, if the request is final.
    #[must_use]
    pub const fn final_settlement(&self) -> Option<BudgetSettlement> {
        self.final_settlement
    }
}

/// Result of durably admitting an envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DurableAcceptance {
    /// A new `AcceptedPending` record was appended and synced.
    New,
    /// This exact request was already admitted; use its recovered phase.
    ExactDuplicate(Box<DurableRequest>),
}

/// One active response reservation reconstructed from the WAL.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DurableReservation {
    request: BrokerRequestId,
    response_cap: u64,
}

impl DurableReservation {
    /// Returns the request that owns this reservation.
    #[must_use]
    pub const fn request(self) -> BrokerRequestId {
        self.request
    }

    /// Returns the maximum response bytes reserved for the request.
    #[must_use]
    pub const fn response_cap(self) -> u64 {
        self.response_cap
    }
}

/// Read-only recovered budget counters and active reservations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DurableBudgetSnapshot {
    limits: SessionBudgetLimits,
    started_requests: u64,
    committed_response_bytes: u64,
    reserved_response_bytes: u64,
    active: Vec<DurableReservation>,
}

impl DurableBudgetSnapshot {
    /// Returns the immutable session budget ceilings.
    #[must_use]
    pub const fn limits(&self) -> SessionBudgetLimits {
        self.limits
    }

    /// Returns the number of request-count tokens consumed.
    #[must_use]
    pub const fn started_requests(&self) -> u64 {
        self.started_requests
    }

    /// Returns response bytes committed by terminal requests.
    #[must_use]
    pub const fn committed_response_bytes(&self) -> u64 {
        self.committed_response_bytes
    }

    /// Returns response bytes held by durable active reservations.
    #[must_use]
    pub const fn reserved_response_bytes(&self) -> u64 {
        self.reserved_response_bytes
    }

    /// Returns active reservations in request identity order.
    #[must_use]
    pub fn active_reservations(&self) -> &[DurableReservation] {
        &self.active
    }
}

/// Why a durable broker WAL cannot be created, recovered, or advanced.
#[derive(Debug)]
pub enum DurableWalError {
    /// A filesystem operation failed before an append became uncertain.
    Io(io::Error),
    /// Another writer currently owns the WAL.
    Locked,
    /// The WAL path is a symbolic link and is rejected fail-closed.
    Symlink,
    /// The WAL path is not a regular file.
    NotRegularFile,
    /// A path component changed after its directory or file descriptor was opened.
    PathIdentityChanged,
    /// The WAL or lock file is not owned by the process effective user.
    WrongOwner {
        /// Effective user required to own the file.
        expected: u32,
        /// Owner observed on the file.
        actual: u32,
    },
    /// The WAL or lock file grants access to group or other principals.
    UnsafePermissions {
        /// Observed Unix permission bits.
        mode: u32,
    },
    /// The containing directory can be replaced by an untrusted local principal.
    UnsafeParentDirectory,
    /// The complete WAL exceeds its fixed recovery bound.
    WalTooLarge {
        /// Observed file length.
        length: u64,
        /// Maximum accepted file length.
        maximum: u64,
    },
    /// One record declares or constructs an excessive payload.
    RecordTooLarge(usize),
    /// The WAL ended partway through a frame.
    TruncatedRecord,
    /// A frame has the wrong fixed magic.
    InvalidMagic,
    /// A frame uses an unsupported version.
    UnsupportedVersion(u16),
    /// WAL record sequence order is not contiguous.
    SequenceMismatch {
        /// Required record sequence.
        expected: u64,
        /// Observed record sequence.
        actual: u64,
    },
    /// A frame checksum did not validate.
    ChecksumMismatch,
    /// A decoded frame violates the durable state machine.
    InvalidRecord(String),
    /// The recovered immutable configuration differs from the expected session.
    ConfigurationMismatch {
        /// Configuration required by the caller.
        expected: DurableSessionConfig,
        /// Configuration recovered from disk.
        recovered: DurableSessionConfig,
    },
    /// A new request did not carry the next strict sequence.
    OutOfOrderSequence {
        /// Only sequence accepted for a new request.
        expected: u64,
        /// Sequence received from the caller.
        received: u64,
    },
    /// An existing request ID was reused with different durable identity fields.
    RequestIdentityMismatch {
        /// Reused request identity.
        request: BrokerRequestId,
    },
    /// The configured replay-retention capacity is exhausted.
    RequestCapacityExhausted,
    /// A mutation named a request that was never durably accepted.
    UnknownRequest(BrokerRequestId),
    /// A mutation is forbidden from the request's current phase.
    InvalidTransition {
        /// Request whose durable phase cannot be mutated as requested.
        request: BrokerRequestId,
    },
    /// A canonical terminal response was bound to another request.
    ResponseRequestMismatch {
        /// Request being finalized.
        expected: BrokerRequestId,
        /// Request carried by the canonical response.
        received: BrokerRequestId,
    },
    /// The budget state machine rejected a reservation or settlement.
    Budget(SessionBudgetError),
    /// The canonical wire response was invalid or oversized.
    Response(ResponseCborError),
    /// The canonical response chunk sequence was invalid or oversized.
    ResponseChunk(ResponseChunkError),
    /// The WAL record sequence cannot advance without wrapping.
    SequenceExhausted,
    /// A prior write or sync failure made the durable prefix uncertain.
    DurabilityUncertain(io::Error),
    /// This writer was sealed after a prior uncertain append.
    Sealed,
}

impl fmt::Display for DurableWalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "durable broker WAL IO failed: {error}"),
            Self::Locked => formatter.write_str("durable broker WAL already has a writer"),
            Self::Symlink => formatter.write_str("durable broker WAL path is a symbolic link"),
            Self::NotRegularFile => {
                formatter.write_str("durable broker WAL path is not a regular file")
            }
            Self::PathIdentityChanged => {
                formatter.write_str("durable broker WAL path identity changed")
            }
            Self::WrongOwner { expected, actual } => write!(
                formatter,
                "durable broker WAL owner {actual} does not match effective user {expected}"
            ),
            Self::UnsafePermissions { mode } => write!(
                formatter,
                "durable broker WAL permissions {mode:o} grant group or other access"
            ),
            Self::UnsafeParentDirectory => formatter
                .write_str("durable broker WAL parent directory is not a trusted namespace"),
            Self::WalTooLarge { length, maximum } => write!(
                formatter,
                "durable broker WAL length {length} exceeds maximum {maximum}"
            ),
            Self::RecordTooLarge(length) => {
                write!(
                    formatter,
                    "durable broker WAL record length {length} is excessive"
                )
            }
            Self::TruncatedRecord => formatter.write_str("durable broker WAL record is truncated"),
            Self::InvalidMagic => formatter.write_str("durable broker WAL magic is invalid"),
            Self::UnsupportedVersion(version) => {
                write!(
                    formatter,
                    "durable broker WAL version {version} is unsupported"
                )
            }
            Self::SequenceMismatch { expected, actual } => write!(
                formatter,
                "durable broker WAL sequence {actual} is invalid; expected {expected}"
            ),
            Self::ChecksumMismatch => {
                formatter.write_str("durable broker WAL checksum does not match")
            }
            Self::InvalidRecord(reason) => {
                write!(formatter, "durable broker WAL record is invalid: {reason}")
            }
            Self::ConfigurationMismatch { .. } => {
                formatter.write_str("durable broker WAL configuration does not match this session")
            }
            Self::OutOfOrderSequence { expected, received } => write!(
                formatter,
                "durable broker request sequence {received} is invalid; expected {expected}"
            ),
            Self::RequestIdentityMismatch { .. } => {
                formatter.write_str("durable broker request identity was reused inconsistently")
            }
            Self::RequestCapacityExhausted => {
                formatter.write_str("durable broker replay capacity is exhausted")
            }
            Self::UnknownRequest(_) => {
                formatter.write_str("durable broker mutation names an unknown request")
            }
            Self::InvalidTransition { .. } => {
                formatter.write_str("durable broker request phase forbids this transition")
            }
            Self::ResponseRequestMismatch { .. } => {
                formatter.write_str("canonical broker response is bound to another request")
            }
            Self::Budget(error) => error.fmt(formatter),
            Self::Response(error) => error.fmt(formatter),
            Self::ResponseChunk(error) => error.fmt(formatter),
            Self::SequenceExhausted => {
                formatter.write_str("durable broker WAL sequence is exhausted")
            }
            Self::DurabilityUncertain(error) => write!(
                formatter,
                "durable broker WAL append may have reached storage: {error}"
            ),
            Self::Sealed => formatter.write_str("durable broker WAL writer is sealed"),
        }
    }
}

impl Error for DurableWalError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(error) | Self::DurabilityUncertain(error) => Some(error),
            Self::Budget(error) => Some(error),
            Self::Response(error) => Some(error),
            Self::ResponseChunk(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for DurableWalError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BudgetEvent {
    Reserve {
        request: BrokerRequestId,
        response_cap: u64,
    },
    Abort {
        request: BrokerRequestId,
    },
    Complete {
        request: BrokerRequestId,
        response_bytes: u64,
    },
}

#[derive(Debug, Clone)]
struct BudgetState {
    started_requests: u64,
    committed_response_bytes: u64,
    reserved_response_bytes: u64,
    active: BTreeMap<BrokerRequestId, u64>,
}

impl BudgetState {
    const fn empty() -> Self {
        Self {
            started_requests: 0,
            committed_response_bytes: 0,
            reserved_response_bytes: 0,
            active: BTreeMap::new(),
        }
    }

    fn validate_reserve(
        &self,
        request: BrokerRequestId,
        response_cap: u64,
        limits: SessionBudgetLimits,
    ) -> Result<(), DurableWalError> {
        if self.active.contains_key(&request) {
            return Err(DurableWalError::Budget(
                SessionBudgetError::ReservationAlreadyActive { request },
            ));
        }
        if self.started_requests >= limits.max_requests().get() {
            return Err(DurableWalError::Budget(
                SessionBudgetError::RequestCountExhausted,
            ));
        }
        if self.active.len() >= limits.max_concurrent_requests().get() {
            return Err(DurableWalError::Budget(
                SessionBudgetError::ConcurrentRequestLimitReached,
            ));
        }
        let used = self
            .committed_response_bytes
            .checked_add(self.reserved_response_bytes)
            .ok_or(DurableWalError::Budget(
                SessionBudgetError::AccountingInvariantBroken,
            ))?;
        let remaining =
            limits
                .max_response_bytes()
                .checked_sub(used)
                .ok_or(DurableWalError::Budget(
                    SessionBudgetError::AccountingInvariantBroken,
                ))?;
        if response_cap > remaining {
            return Err(DurableWalError::Budget(
                SessionBudgetError::ResponseBytesExhausted {
                    requested: response_cap,
                    remaining,
                },
            ));
        }
        self.started_requests
            .checked_add(1)
            .and_then(|_| self.reserved_response_bytes.checked_add(response_cap))
            .ok_or(DurableWalError::Budget(
                SessionBudgetError::AccountingInvariantBroken,
            ))?;
        Ok(())
    }

    fn apply_reserve(&mut self, request: BrokerRequestId, response_cap: u64) {
        self.started_requests += 1;
        self.reserved_response_bytes += response_cap;
        self.active.insert(request, response_cap);
    }

    fn validate_settlement(
        &self,
        request: BrokerRequestId,
        settlement: BudgetSettlement,
    ) -> Result<(), DurableWalError> {
        match settlement {
            BudgetSettlement::NotStarted => {
                if self.active.contains_key(&request) {
                    return Err(DurableWalError::InvalidTransition { request });
                }
            }
            BudgetSettlement::Abort => {
                if !self.active.contains_key(&request) {
                    return Err(DurableWalError::Budget(
                        SessionBudgetError::UnknownReservation { request },
                    ));
                }
            }
            BudgetSettlement::Complete { response_bytes } => {
                let response_cap =
                    self.active
                        .get(&request)
                        .copied()
                        .ok_or(DurableWalError::Budget(
                            SessionBudgetError::UnknownReservation { request },
                        ))?;
                if response_bytes > response_cap {
                    return Err(DurableWalError::Budget(
                        SessionBudgetError::ResponseExceedsReservation {
                            request,
                            received: response_bytes,
                            reserved: response_cap,
                        },
                    ));
                }
                self.committed_response_bytes
                    .checked_add(response_bytes)
                    .and_then(|_| self.reserved_response_bytes.checked_sub(response_cap))
                    .ok_or(DurableWalError::Budget(
                        SessionBudgetError::AccountingInvariantBroken,
                    ))?;
            }
        }
        Ok(())
    }

    fn apply_settlement(&mut self, request: BrokerRequestId, settlement: BudgetSettlement) {
        match settlement {
            BudgetSettlement::NotStarted => {}
            BudgetSettlement::Abort => {
                let response_cap = self
                    .active
                    .remove(&request)
                    .expect("validated abort must have a reservation");
                self.reserved_response_bytes -= response_cap;
            }
            BudgetSettlement::Complete { response_bytes } => {
                let response_cap = self
                    .active
                    .remove(&request)
                    .expect("validated completion must have a reservation");
                self.reserved_response_bytes -= response_cap;
                self.committed_response_bytes += response_bytes;
            }
        }
    }

    fn snapshot(&self, limits: SessionBudgetLimits) -> DurableBudgetSnapshot {
        DurableBudgetSnapshot {
            limits,
            started_requests: self.started_requests,
            committed_response_bytes: self.committed_response_bytes,
            reserved_response_bytes: self.reserved_response_bytes,
            active: self
                .active
                .iter()
                .map(|(request, response_cap)| DurableReservation {
                    request: *request,
                    response_cap: *response_cap,
                })
                .collect(),
        }
    }
}

#[derive(Debug, Clone)]
struct RecoveredState {
    config: DurableSessionConfig,
    requests: Vec<DurableRequest>,
    request_indexes: BTreeMap<BrokerRequestId, usize>,
    budget: BudgetState,
    budget_events: Vec<BudgetEvent>,
    next_wal_sequence: Option<u64>,
}

impl RecoveredState {
    fn new(config: DurableSessionConfig) -> Self {
        Self {
            config,
            requests: Vec::new(),
            request_indexes: BTreeMap::new(),
            budget: BudgetState::empty(),
            budget_events: Vec::new(),
            next_wal_sequence: Some(1),
        }
    }

    fn request(&self, request: BrokerRequestId) -> Result<&DurableRequest, DurableWalError> {
        let index = self
            .request_indexes
            .get(&request)
            .copied()
            .ok_or(DurableWalError::UnknownRequest(request))?;
        self.requests.get(index).ok_or_else(|| {
            DurableWalError::InvalidRecord("request index is inconsistent".to_owned())
        })
    }

    fn request_mut(
        &mut self,
        request: BrokerRequestId,
    ) -> Result<&mut DurableRequest, DurableWalError> {
        let index = self
            .request_indexes
            .get(&request)
            .copied()
            .ok_or(DurableWalError::UnknownRequest(request))?;
        self.requests.get_mut(index).ok_or_else(|| {
            DurableWalError::InvalidRecord("request index is inconsistent".to_owned())
        })
    }

    fn apply_accept(
        &mut self,
        envelope: BrokerEnvelope,
        response_cap: u64,
    ) -> Result<(), DurableWalError> {
        if envelope.session() != self.config.session() {
            return Err(DurableWalError::InvalidRecord(
                "accepted request belongs to another session".to_owned(),
            ));
        }
        self.apply_accept_parts(
            envelope.sequence(),
            envelope.request(),
            *envelope.payload_hash().as_bytes(),
            response_cap,
        )
    }

    fn apply_accept_parts(
        &mut self,
        sequence: u64,
        request: BrokerRequestId,
        payload_hash: [u8; 32],
        response_cap: u64,
    ) -> Result<(), DurableWalError> {
        let expected = u64::try_from(self.requests.len()).map_err(|_| {
            DurableWalError::InvalidRecord("request sequence cannot fit u64".to_owned())
        })?;
        if sequence != expected {
            return Err(DurableWalError::OutOfOrderSequence {
                expected,
                received: sequence,
            });
        }
        if self.requests.len() >= self.config.replay_capacity().get() {
            return Err(DurableWalError::RequestCapacityExhausted);
        }
        if self.request_indexes.contains_key(&request) {
            return Err(DurableWalError::RequestIdentityMismatch { request });
        }
        let index = self.requests.len();
        self.requests.push(DurableRequest {
            sequence,
            request,
            payload_hash,
            response_cap,
            phase: DurableRequestPhase::AcceptedPending,
            reservation: None,
            final_settlement: None,
        });
        self.request_indexes.insert(request, index);
        Ok(())
    }

    fn apply_reserve(&mut self, request: BrokerRequestId) -> Result<(), DurableWalError> {
        let response_cap = {
            let entry = self.request(request)?;
            if !matches!(
                entry.phase,
                DurableRequestPhase::AcceptedPending | DurableRequestPhase::RetryableBudget
            ) || entry.reservation.is_some()
            {
                return Err(DurableWalError::InvalidTransition { request });
            }
            entry.response_cap
        };
        self.budget
            .validate_reserve(request, response_cap, self.config.budget_limits())?;
        self.budget.apply_reserve(request, response_cap);
        self.budget_events.push(BudgetEvent::Reserve {
            request,
            response_cap,
        });
        let entry = self.request_mut(request)?;
        entry.phase = DurableRequestPhase::AcceptedPending;
        entry.reservation = Some(response_cap);
        Ok(())
    }

    fn apply_retryable(&mut self, request: BrokerRequestId) -> Result<(), DurableWalError> {
        let entry = self.request_mut(request)?;
        if !matches!(entry.phase, DurableRequestPhase::AcceptedPending)
            || entry.reservation.is_some()
        {
            return Err(DurableWalError::InvalidTransition { request });
        }
        entry.phase = DurableRequestPhase::RetryableBudget;
        Ok(())
    }

    fn apply_final(
        &mut self,
        request: BrokerRequestId,
        settlement: BudgetSettlement,
        response: DurableCanonicalResponse,
    ) -> Result<(), DurableWalError> {
        {
            let entry = self.request(request)?;
            if matches!(entry.phase, DurableRequestPhase::Final(_)) {
                return Err(DurableWalError::InvalidTransition { request });
            }
            match settlement {
                BudgetSettlement::NotStarted if entry.reservation.is_some() => {
                    return Err(DurableWalError::InvalidTransition { request });
                }
                BudgetSettlement::Abort | BudgetSettlement::Complete { .. }
                    if entry.reservation.is_none() =>
                {
                    return Err(DurableWalError::InvalidTransition { request });
                }
                _ => {}
            }
        }
        self.budget.validate_settlement(request, settlement)?;
        self.budget.apply_settlement(request, settlement);
        match settlement {
            BudgetSettlement::NotStarted => {}
            BudgetSettlement::Abort => self.budget_events.push(BudgetEvent::Abort { request }),
            BudgetSettlement::Complete { response_bytes } => {
                self.budget_events.push(BudgetEvent::Complete {
                    request,
                    response_bytes,
                });
            }
        }
        let entry = self.request_mut(request)?;
        entry.reservation = None;
        entry.final_settlement = Some(settlement);
        entry.phase = DurableRequestPhase::Final(response);
        Ok(())
    }

    fn validate_duplicate(
        &self,
        envelope: BrokerEnvelope,
        response_cap: u64,
    ) -> Result<Option<DurableRequest>, DurableWalError> {
        let Some(index) = self.request_indexes.get(&envelope.request()).copied() else {
            return Ok(None);
        };
        let entry = self.requests.get(index).ok_or_else(|| {
            DurableWalError::InvalidRecord("request index is inconsistent".to_owned())
        })?;
        if entry.sequence == envelope.sequence()
            && entry.payload_hash == *envelope.payload_hash().as_bytes()
            && entry.response_cap == response_cap
        {
            Ok(Some(entry.clone()))
        } else {
            Err(DurableWalError::RequestIdentityMismatch {
                request: envelope.request(),
            })
        }
    }
}

#[derive(Debug)]
struct DurableDirectory {
    file: File,
    path: PathBuf,
    wal_name: OsString,
    lock_name: OsString,
    effective_uid: u32,
}

impl DurableDirectory {
    fn open(wal_path: &Path) -> Result<Self, DurableWalError> {
        let wal_name = wal_path
            .file_name()
            .filter(|name| !name.is_empty())
            .ok_or(DurableWalError::UnsafeParentDirectory)?
            .to_os_string();
        let path = wal_path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf();
        let effective_uid = effective_uid()?;
        let expected = validate_parent_path(&path, effective_uid)?;
        let file = File::open(&path)?;
        validate_directory_metadata(&file.metadata()?, effective_uid)?;
        let actual = file_identity(&file.metadata()?);
        if expected != actual {
            return Err(DurableWalError::PathIdentityChanged);
        }
        validate_parent_path_identity(&path, &file, effective_uid)?;
        let lock_name = durable_lock_name(&wal_name);
        Ok(Self {
            file,
            path,
            wal_name,
            lock_name,
            effective_uid,
        })
    }

    fn wal_path(&self) -> PathBuf {
        self.child_path(&self.wal_name)
    }

    fn lock_path(&self) -> PathBuf {
        self.child_path(&self.lock_name)
    }

    fn child_path(&self, name: &OsStr) -> PathBuf {
        #[cfg(target_os = "linux")]
        {
            let mut path = PathBuf::from(format!("/proc/self/fd/{}", self.file.as_raw_fd()));
            path.push(name);
            path
        }
        #[cfg(not(target_os = "linux"))]
        {
            self.path.join(name)
        }
    }

    fn validate(&self) -> Result<(), DurableWalError> {
        validate_parent_path_identity(&self.path, &self.file, self.effective_uid)
    }

    fn sync(&self) -> io::Result<()> {
        self.file.sync_all()
    }
}

/// Immutable, fully validated state reconstructed from a broker WAL.
#[derive(Debug, Clone)]
pub struct DurableBrokerView {
    path: PathBuf,
    state: RecoveredState,
}

impl DurableBrokerView {
    /// Opens, bounds, shared-locks, and completely validates an existing WAL.
    ///
    /// # Errors
    ///
    /// Returns [`DurableWalError`] for IO, lock contention, corruption,
    /// truncation, unsupported versions, or invalid state transitions.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, DurableWalError> {
        let path = path.as_ref().to_path_buf();
        let directory = DurableDirectory::open(&path)?;
        let lock_file = open_session_lock(&directory, false)?;
        validate_existing_path(&directory)?;
        let mut file = open_existing_file(&directory.wal_path(), false)?;
        acquire_shared_lock(&file)?;
        validate_open_file(&directory, &file)?;
        let (state, _) = read_and_parse(&mut file, TailPolicy::Reject)?;
        validate_open_file(&directory, &file)?;
        validate_open_lock(&directory, &lock_file)?;
        Ok(Self { path, state })
    }

    /// Returns the WAL path represented by this snapshot.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Returns the immutable recovered session configuration.
    #[must_use]
    pub const fn config(&self) -> DurableSessionConfig {
        self.state.config
    }

    /// Returns accepted requests in strict session sequence order.
    #[must_use]
    pub fn requests(&self) -> &[DurableRequest] {
        &self.state.requests
    }

    /// Finds one accepted request by idempotency identity.
    #[must_use]
    pub fn request(&self, request: BrokerRequestId) -> Option<&DurableRequest> {
        self.state
            .request_indexes
            .get(&request)
            .and_then(|index| self.state.requests.get(*index))
    }

    /// Returns recovered budget counters and active reservations.
    #[must_use]
    pub fn budget(&self) -> DurableBudgetSnapshot {
        self.state
            .budget
            .snapshot(self.state.config.budget_limits())
    }

    /// Reconstructs the protocol budget including active reservations.
    ///
    /// # Errors
    ///
    /// Returns [`DurableWalError::InvalidRecord`] if validated budget history
    /// cannot be replayed into the protocol state machine.
    pub fn restore_budget(&self) -> Result<SessionBudget, DurableWalError> {
        let mut budget = SessionBudget::new(self.state.config.budget_limits());
        for event in &self.state.budget_events {
            let result = match *event {
                BudgetEvent::Reserve {
                    request,
                    response_cap,
                } => budget.start(request, response_cap).map(|_| ()),
                BudgetEvent::Abort { request } => budget.abort(request),
                BudgetEvent::Complete {
                    request,
                    response_bytes,
                } => budget.complete(request, response_bytes),
            };
            if result.is_err() {
                return Err(DurableWalError::InvalidRecord(
                    "budget history cannot reconstruct the session budget".to_owned(),
                ));
            }
        }
        Ok(budget)
    }
}

/// Exclusive append writer for one durable broker session WAL.
#[derive(Debug)]
pub struct DurableBrokerWal {
    path: PathBuf,
    directory: DurableDirectory,
    lock_file: File,
    file: File,
    state: RecoveredState,
    length: u64,
    sealed: bool,
}

#[derive(Debug, Clone, Copy)]
enum TerminalHeadroomChange {
    Preserve,
    Add(u64),
    Release(BrokerRequestId),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TailPolicy {
    Reject,
    Repair,
}

struct ParsedWal {
    state: RecoveredState,
    verified_length: usize,
}

impl DurableBrokerWal {
    /// Creates and durably initializes a new exclusively owned WAL.
    ///
    /// # Errors
    ///
    /// Returns [`DurableWalError`] if the path already exists, is unsafe, or
    /// the initial session record and containing directory cannot be synced.
    pub fn create(
        path: impl AsRef<Path>,
        config: DurableSessionConfig,
    ) -> Result<Self, DurableWalError> {
        let path = path.as_ref().to_path_buf();
        let directory = DurableDirectory::open(&path)?;
        let lock_file = open_session_lock(&directory, true)?;
        validate_new_path(&directory)?;
        let mut file = create_private_file(&directory.wal_path())?;
        acquire_exclusive_lock(&file)?;
        validate_open_file(&directory, &file)?;
        let payload = encode_init(config)?;
        let frame = encode_frame(0, INIT_KIND, &payload)?;
        if let Err(error) = file
            .write_all(&frame)
            .and_then(|()| file.sync_all())
            .and_then(|()| directory.sync())
        {
            return Err(DurableWalError::DurabilityUncertain(error));
        }
        validate_open_file(&directory, &file)?;
        validate_open_lock(&directory, &lock_file)?;
        Ok(Self {
            path,
            directory,
            lock_file,
            file,
            state: RecoveredState::new(config),
            length: u64::try_from(frame.len())
                .map_err(|_| DurableWalError::RecordTooLarge(frame.len()))?,
            sealed: false,
        })
    }

    /// Reopens a WAL and verifies its immutable session configuration.
    ///
    /// # Errors
    ///
    /// Returns [`DurableWalError`] for writer contention, corruption,
    /// truncation, unsafe paths, or a configuration mismatch.
    pub fn open(
        path: impl AsRef<Path>,
        expected: DurableSessionConfig,
    ) -> Result<Self, DurableWalError> {
        let path = path.as_ref().to_path_buf();
        let directory = DurableDirectory::open(&path)?;
        let lock_file = open_session_lock(&directory, true)?;
        validate_existing_path(&directory)?;
        let mut file = open_existing_file(&directory.wal_path(), true)?;
        acquire_exclusive_lock(&file)?;
        validate_open_file(&directory, &file)?;
        let (state, length) = read_and_parse(&mut file, TailPolicy::Repair)?;
        validate_open_file(&directory, &file)?;
        validate_open_lock(&directory, &lock_file)?;
        validate_recovered_headroom(&state, length)?;
        if state.config != expected {
            return Err(DurableWalError::ConfigurationMismatch {
                expected,
                recovered: state.config,
            });
        }
        file.seek(SeekFrom::End(0))?;
        Ok(Self {
            path,
            directory,
            lock_file,
            file,
            state,
            length,
            sealed: false,
        })
    }

    /// Returns the path of the exclusively owned WAL.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Returns whether an uncertain append has permanently sealed this writer.
    #[must_use]
    pub const fn is_sealed(&self) -> bool {
        self.sealed
    }

    /// Returns a detached immutable snapshot of current durable state.
    ///
    /// # Errors
    ///
    /// Returns [`DurableWalError::Sealed`] after any uncertain append.
    pub fn read_only_view(&self) -> Result<DurableBrokerView, DurableWalError> {
        if self.sealed {
            return Err(DurableWalError::Sealed);
        }
        Ok(DurableBrokerView {
            path: self.path.clone(),
            state: self.state.clone(),
        })
    }

    /// Durably admits a new envelope or returns its exact recovered duplicate.
    ///
    /// A returned [`DurableAcceptance::New`] means the `AcceptedPending`
    /// no-reexecution marker has crossed `fsync`.
    ///
    /// # Errors
    ///
    /// Returns an error without appending for wrong session/order, identity or
    /// response-cap reuse, capacity exhaustion, or a sealed writer.
    pub fn accept(
        &mut self,
        envelope: BrokerEnvelope,
        response_cap: u64,
    ) -> Result<DurableAcceptance, DurableWalError> {
        self.ensure_writable()?;
        if envelope.session() != self.state.config.session() {
            return Err(DurableWalError::InvalidRecord(
                "request belongs to another durable session".to_owned(),
            ));
        }
        if let Some(request) = self.state.validate_duplicate(envelope, response_cap)? {
            return Ok(DurableAcceptance::ExactDuplicate(Box::new(request)));
        }
        let expected = u64::try_from(self.state.requests.len())
            .map_err(|_| DurableWalError::SequenceExhausted)?;
        if envelope.sequence() != expected {
            return Err(DurableWalError::OutOfOrderSequence {
                expected,
                received: envelope.sequence(),
            });
        }
        if self.state.requests.len() >= self.state.config.replay_capacity().get() {
            return Err(DurableWalError::RequestCapacityExhausted);
        }
        let payload = encode_accept(envelope, response_cap);
        self.append(ACCEPT_KIND, &payload, TerminalHeadroomChange::Preserve)?;
        self.state.apply_accept(envelope, response_cap)?;
        Ok(DurableAcceptance::New)
    }

    /// Durably records a successful budget start before adapter execution.
    ///
    /// `RetryableBudget` is returned to `AcceptedPending` when its retry can
    /// finally reserve budget. No request may own two active reservations.
    ///
    /// # Errors
    ///
    /// Returns [`DurableWalError`] when the request/phase is invalid, a budget
    /// ceiling is exceeded, or the append cannot be trusted.
    pub fn reserve(&mut self, request: BrokerRequestId) -> Result<(), DurableWalError> {
        self.ensure_writable()?;
        let entry = self.state.request(request)?;
        if !matches!(
            entry.phase,
            DurableRequestPhase::AcceptedPending | DurableRequestPhase::RetryableBudget
        ) || entry.reservation.is_some()
        {
            return Err(DurableWalError::InvalidTransition { request });
        }
        self.state.budget.validate_reserve(
            request,
            entry.response_cap,
            self.state.config.budget_limits(),
        )?;
        self.append(
            RESERVE_KIND,
            request.as_bytes(),
            TerminalHeadroomChange::Add(entry.response_cap),
        )?;
        self.state.apply_reserve(request)
    }

    /// Durably marks a budget denial that an exact retry may re-evaluate.
    ///
    /// # Errors
    ///
    /// Only an unreserved `AcceptedPending` request may enter this phase.
    pub fn mark_retryable_budget(
        &mut self,
        request: BrokerRequestId,
    ) -> Result<(), DurableWalError> {
        self.ensure_writable()?;
        let entry = self.state.request(request)?;
        if !matches!(entry.phase, DurableRequestPhase::AcceptedPending)
            || entry.reservation.is_some()
        {
            return Err(DurableWalError::InvalidTransition { request });
        }
        self.append(
            RETRYABLE_BUDGET_KIND,
            request.as_bytes(),
            TerminalHeadroomChange::Preserve,
        )?;
        self.state.apply_retryable(request)
    }

    /// Durably seals a request with its exact canonical response and settlement.
    ///
    /// # Errors
    ///
    /// Returns an error for request/response mismatch, repeated finalization,
    /// invalid reservation settlement, an invalid wire response, or an
    /// uncertain append. A final request can never transition again.
    pub fn finalize(
        &mut self,
        request: BrokerRequestId,
        response: &CanonicalBrokerResponse,
        settlement: BudgetSettlement,
    ) -> Result<(), DurableWalError> {
        self.ensure_writable()?;
        if response.request() != request {
            return Err(DurableWalError::ResponseRequestMismatch {
                expected: request,
                received: response.request(),
            });
        }
        let releases_headroom = {
            let entry = self.state.request(request)?;
            if matches!(entry.phase, DurableRequestPhase::Final(_)) {
                return Err(DurableWalError::InvalidTransition { request });
            }
            match settlement {
                BudgetSettlement::NotStarted if entry.reservation.is_some() => {
                    return Err(DurableWalError::InvalidTransition { request });
                }
                BudgetSettlement::Abort | BudgetSettlement::Complete { .. }
                    if entry.reservation.is_none() =>
                {
                    return Err(DurableWalError::InvalidTransition { request });
                }
                _ => {}
            }
            entry.reservation.is_some()
        };
        self.state.budget.validate_settlement(request, settlement)?;
        let wire_payloads = canonical_wire_payloads(response)?;
        let payload = encode_final(request, settlement, &wire_payloads)?;
        let headroom = if releases_headroom {
            TerminalHeadroomChange::Release(request)
        } else {
            TerminalHeadroomChange::Preserve
        };
        self.append(FINAL_KIND, &payload, headroom)?;
        drop(payload);
        drop(wire_payloads);
        let canonical = DurableCanonicalResponse {
            response: response.clone(),
            wire_payloads: OnceLock::new(),
        };
        self.state.apply_final(request, settlement, canonical)
    }

    fn ensure_writable(&self) -> Result<(), DurableWalError> {
        if self.sealed {
            Err(DurableWalError::Sealed)
        } else {
            Ok(())
        }
    }

    fn append(
        &mut self,
        kind: u8,
        payload: &[u8],
        headroom_change: TerminalHeadroomChange,
    ) -> Result<(), DurableWalError> {
        if let Err(error) = self.validate_append_target() {
            self.sealed = true;
            return Err(error);
        }
        let sequence = self
            .state
            .next_wal_sequence
            .ok_or(DurableWalError::SequenceExhausted)?;
        let header = encode_frame_header(sequence, kind, payload.len())?;
        let frame_size = HEADER_LEN
            .checked_add(payload.len())
            .and_then(|length| length.checked_add(CHECKSUM_LEN))
            .ok_or(DurableWalError::RecordTooLarge(payload.len()))?;
        let frame_length =
            u64::try_from(frame_size).map_err(|_| DurableWalError::RecordTooLarge(frame_size))?;
        if let TerminalHeadroomChange::Release(request) = headroom_change {
            let response_cap = self
                .state
                .budget
                .active
                .get(&request)
                .copied()
                .ok_or(DurableWalError::InvalidTransition { request })?;
            if frame_length > maximum_terminal_frame_bytes(response_cap)? {
                self.sealed = true;
                return Err(DurableWalError::RecordTooLarge(frame_size));
            }
        }
        let next_length =
            self.length
                .checked_add(frame_length)
                .ok_or(DurableWalError::WalTooLarge {
                    length: u64::MAX,
                    maximum: MAX_DURABLE_BROKER_WAL_BYTES,
                })?;
        let protected_headroom = match self.protected_terminal_headroom(headroom_change) {
            Ok(headroom) => headroom,
            Err(error) => {
                self.sealed = true;
                return Err(error);
            }
        };
        let projected_length =
            next_length
                .checked_add(protected_headroom)
                .ok_or(DurableWalError::WalTooLarge {
                    length: u64::MAX,
                    maximum: MAX_DURABLE_BROKER_WAL_BYTES,
                })?;
        if projected_length > MAX_DURABLE_BROKER_WAL_BYTES {
            self.sealed = true;
            return Err(DurableWalError::WalTooLarge {
                length: projected_length,
                maximum: MAX_DURABLE_BROKER_WAL_BYTES,
            });
        }
        let frame_checksum = checksum_parts(&header, payload).to_le_bytes();
        let append_result = (|| {
            self.file.write_all(&header)?;
            self.file.write_all(payload)?;
            self.file.write_all(&frame_checksum)?;
            self.file.sync_all()
        })();
        if let Err(error) = append_result {
            self.sealed = true;
            return Err(DurableWalError::DurabilityUncertain(error));
        }
        if let Err(error) = self.validate_append_target() {
            self.sealed = true;
            return Err(error);
        }
        self.length = next_length;
        self.state.next_wal_sequence = sequence.checked_add(1);
        Ok(())
    }

    fn protected_terminal_headroom(
        &self,
        change: TerminalHeadroomChange,
    ) -> Result<u64, DurableWalError> {
        let released = match change {
            TerminalHeadroomChange::Release(request) => Some(request),
            TerminalHeadroomChange::Preserve | TerminalHeadroomChange::Add(_) => None,
        };
        let mut headroom =
            self.state
                .budget
                .active
                .iter()
                .try_fold(0_u64, |total, (request, response_cap)| {
                    if Some(*request) == released {
                        Ok(total)
                    } else {
                        total
                            .checked_add(maximum_terminal_frame_bytes(*response_cap)?)
                            .ok_or(DurableWalError::WalTooLarge {
                                length: u64::MAX,
                                maximum: MAX_DURABLE_BROKER_WAL_BYTES,
                            })
                    }
                })?;
        if let TerminalHeadroomChange::Add(response_cap) = change {
            headroom = headroom
                .checked_add(maximum_terminal_frame_bytes(response_cap)?)
                .ok_or(DurableWalError::WalTooLarge {
                    length: u64::MAX,
                    maximum: MAX_DURABLE_BROKER_WAL_BYTES,
                })?;
        }
        Ok(headroom)
    }

    fn validate_append_target(&self) -> Result<(), DurableWalError> {
        self.directory.validate()?;
        validate_open_lock(&self.directory, &self.lock_file)?;
        validate_open_file(&self.directory, &self.file)
    }
}

fn encode_init(config: DurableSessionConfig) -> Result<Vec<u8>, DurableWalError> {
    let replay_capacity = u64::try_from(config.replay_capacity().get())
        .map_err(|_| DurableWalError::RecordTooLarge(usize::MAX))?;
    let concurrency = u64::try_from(config.budget_limits().max_concurrent_requests().get())
        .map_err(|_| DurableWalError::RecordTooLarge(usize::MAX))?;
    let mut payload = Vec::with_capacity(INIT_PAYLOAD_LEN);
    payload.extend_from_slice(config.session().as_bytes());
    payload.extend_from_slice(&replay_capacity.to_le_bytes());
    payload.extend_from_slice(&config.budget_limits().max_requests().get().to_le_bytes());
    payload.extend_from_slice(&config.budget_limits().max_response_bytes().to_le_bytes());
    payload.extend_from_slice(&concurrency.to_le_bytes());
    Ok(payload)
}

fn decode_init(payload: &[u8]) -> Result<DurableSessionConfig, DurableWalError> {
    if payload.len() != INIT_PAYLOAD_LEN {
        return Err(DurableWalError::InvalidRecord(
            "session record has the wrong length".to_owned(),
        ));
    }
    let mut cursor = 0;
    let session = BrokerSessionId::new(read_fixed(payload, &mut cursor)?);
    let replay_capacity = nonzero_usize(read_u64(payload, &mut cursor)?, "replay capacity")?;
    let max_requests = NonZeroU64::new(read_u64(payload, &mut cursor)?).ok_or_else(|| {
        DurableWalError::InvalidRecord("request budget must be non-zero".to_owned())
    })?;
    let max_response_bytes = read_u64(payload, &mut cursor)?;
    let concurrency = nonzero_usize(read_u64(payload, &mut cursor)?, "concurrency budget")?;
    Ok(DurableSessionConfig::new(
        session,
        replay_capacity,
        SessionBudgetLimits::new(max_requests, max_response_bytes, concurrency),
    ))
}

fn nonzero_usize(value: u64, field: &str) -> Result<NonZeroUsize, DurableWalError> {
    let value = usize::try_from(value).map_err(|_| {
        DurableWalError::InvalidRecord(format!("{field} does not fit this platform"))
    })?;
    NonZeroUsize::new(value)
        .ok_or_else(|| DurableWalError::InvalidRecord(format!("{field} must be non-zero")))
}

fn encode_accept(envelope: BrokerEnvelope, response_cap: u64) -> Vec<u8> {
    let mut payload = Vec::with_capacity(ACCEPT_PAYLOAD_LEN);
    payload.extend_from_slice(&envelope.sequence().to_le_bytes());
    payload.extend_from_slice(envelope.request().as_bytes());
    payload.extend_from_slice(envelope.payload_hash().as_bytes());
    payload.extend_from_slice(&response_cap.to_le_bytes());
    payload
}

fn decode_accept(
    payload: &[u8],
    _session: BrokerSessionId,
) -> Result<(u64, BrokerRequestId, [u8; 32], u64), DurableWalError> {
    if payload.len() != ACCEPT_PAYLOAD_LEN {
        return Err(DurableWalError::InvalidRecord(
            "accept record has the wrong length".to_owned(),
        ));
    }
    let mut cursor = 0;
    let sequence = read_u64(payload, &mut cursor)?;
    let request = BrokerRequestId::new(read_fixed(payload, &mut cursor)?);
    let payload_hash = read_fixed(payload, &mut cursor)?;
    let response_cap = read_u64(payload, &mut cursor)?;
    Ok((sequence, request, payload_hash, response_cap))
}

fn encode_final(
    request: BrokerRequestId,
    settlement: BudgetSettlement,
    wire_payloads: &[Vec<u8>],
) -> Result<Vec<u8>, DurableWalError> {
    let wire_payload_count = u32::try_from(wire_payloads.len())
        .map_err(|_| DurableWalError::RecordTooLarge(usize::MAX))?;
    let wire_bytes = wire_payloads
        .iter()
        .try_fold(0_usize, |total, wire_payload| {
            total
                .checked_add(4)
                .and_then(|value| value.checked_add(wire_payload.len()))
                .ok_or(DurableWalError::RecordTooLarge(usize::MAX))
        })?;
    let capacity = FINAL_PREFIX_LEN
        .checked_add(wire_bytes)
        .ok_or(DurableWalError::RecordTooLarge(usize::MAX))?;
    let mut payload = Vec::with_capacity(capacity);
    payload.extend_from_slice(request.as_bytes());
    let (kind, response_bytes) = match settlement {
        BudgetSettlement::NotStarted => (0, 0),
        BudgetSettlement::Abort => (1, 0),
        BudgetSettlement::Complete { response_bytes } => (2, response_bytes),
    };
    payload.push(kind);
    payload.extend_from_slice(&[0; 7]);
    payload.extend_from_slice(&response_bytes.to_le_bytes());
    payload.extend_from_slice(&wire_payload_count.to_le_bytes());
    for wire_payload in wire_payloads {
        let length = u32::try_from(wire_payload.len())
            .map_err(|_| DurableWalError::RecordTooLarge(wire_payload.len()))?;
        payload.extend_from_slice(&length.to_le_bytes());
        payload.extend_from_slice(wire_payload);
    }
    Ok(payload)
}

fn decode_final(
    payload: &[u8],
) -> Result<(BrokerRequestId, BudgetSettlement, DurableCanonicalResponse), DurableWalError> {
    if payload.len() < FINAL_PREFIX_LEN {
        return Err(DurableWalError::InvalidRecord(
            "final record is too short".to_owned(),
        ));
    }
    let mut cursor = 0;
    let request = BrokerRequestId::new(read_fixed(payload, &mut cursor)?);
    let settlement_kind = read_byte(payload, &mut cursor)?;
    if read_fixed::<7>(payload, &mut cursor)? != [0; 7] {
        return Err(DurableWalError::InvalidRecord(
            "final record reserved bits are non-zero".to_owned(),
        ));
    }
    let response_bytes = read_u64(payload, &mut cursor)?;
    let wire_payload_count = usize::try_from(read_u32(payload, &mut cursor)?)
        .map_err(|_| DurableWalError::RecordTooLarge(usize::MAX))?;
    if wire_payload_count == 0 {
        return Err(DurableWalError::InvalidRecord(
            "final response has no wire payload".to_owned(),
        ));
    }
    let settlement = match (settlement_kind, response_bytes) {
        (0, 0) => BudgetSettlement::NotStarted,
        (1, 0) => BudgetSettlement::Abort,
        (2, response_bytes) => BudgetSettlement::Complete { response_bytes },
        _ => {
            return Err(DurableWalError::InvalidRecord(
                "final settlement encoding is invalid".to_owned(),
            ));
        }
    };
    let remaining = payload.len().saturating_sub(cursor);
    if wire_payload_count > MAX_FINAL_WIRE_PAYLOADS || wire_payload_count > remaining / 4 {
        return Err(DurableWalError::RecordTooLarge(wire_payload_count));
    }
    let mut wire_payloads = Vec::new();
    wire_payloads
        .try_reserve_exact(wire_payload_count)
        .map_err(|_| DurableWalError::RecordTooLarge(wire_payload_count))?;
    for _ in 0..wire_payload_count {
        let length = usize::try_from(read_u32(payload, &mut cursor)?)
            .map_err(|_| DurableWalError::RecordTooLarge(usize::MAX))?;
        let end = cursor
            .checked_add(length)
            .ok_or(DurableWalError::TruncatedRecord)?;
        let wire_payload = payload
            .get(cursor..end)
            .ok_or(DurableWalError::TruncatedRecord)?;
        wire_payloads.push(wire_payload.to_vec());
        cursor = end;
    }
    if cursor != payload.len() {
        return Err(DurableWalError::InvalidRecord(
            "final response payload sequence has trailing bytes".to_owned(),
        ));
    }
    let response = DurableCanonicalResponse::from_wire_payloads(request, &wire_payloads)?;
    Ok((request, settlement, response))
}

fn canonical_wire_payloads(
    response: &CanonicalBrokerResponse,
) -> Result<Vec<Vec<u8>>, DurableWalError> {
    match response.encode() {
        Ok(payload) => Ok(vec![payload]),
        Err(ResponseCborError::PayloadTooLarge { .. }) => response
            .chunks()
            .map_err(DurableWalError::ResponseChunk)?
            .into_iter()
            .map(|chunk| chunk.encode().map_err(DurableWalError::ResponseChunk))
            .collect(),
        Err(error) => Err(DurableWalError::Response(error)),
    }
}

fn decode_wire_payloads(
    wire_payloads: &[Vec<u8>],
) -> Result<CanonicalBrokerResponse, DurableWalError> {
    let Some(first) = wire_payloads.first() else {
        return Err(DurableWalError::InvalidRecord(
            "terminal response has no wire payload".to_owned(),
        ));
    };
    if wire_payloads.len() == 1
        && let Ok(response) = CanonicalBrokerResponse::decode(first)
    {
        return Ok(response);
    }
    let chunks = wire_payloads
        .iter()
        .map(|payload| {
            CanonicalResponseChunk::decode(payload).map_err(DurableWalError::ResponseChunk)
        })
        .collect::<Result<Vec<_>, _>>()?;
    CanonicalBrokerResponse::from_chunks(&chunks).map_err(DurableWalError::ResponseChunk)
}

fn encode_frame(sequence: u64, kind: u8, payload: &[u8]) -> Result<Vec<u8>, DurableWalError> {
    let header = encode_frame_header(sequence, kind, payload.len())?;
    let capacity = HEADER_LEN
        .checked_add(payload.len())
        .and_then(|length| length.checked_add(CHECKSUM_LEN))
        .ok_or(DurableWalError::RecordTooLarge(payload.len()))?;
    let mut frame = Vec::with_capacity(capacity);
    frame.extend_from_slice(&header);
    frame.extend_from_slice(payload);
    frame.extend_from_slice(&checksum_parts(&header, payload).to_le_bytes());
    Ok(frame)
}

fn encode_frame_header(
    sequence: u64,
    kind: u8,
    payload_length: usize,
) -> Result<[u8; HEADER_LEN], DurableWalError> {
    if payload_length > MAX_RECORD_PAYLOAD_BYTES {
        return Err(DurableWalError::RecordTooLarge(payload_length));
    }
    let payload_length = u32::try_from(payload_length)
        .map_err(|_| DurableWalError::RecordTooLarge(payload_length))?;
    let mut header = [0_u8; HEADER_LEN];
    header[..8].copy_from_slice(MAGIC);
    header[8..10].copy_from_slice(&VERSION.to_le_bytes());
    header[10] = kind;
    header[12..20].copy_from_slice(&sequence.to_le_bytes());
    header[20..24].copy_from_slice(&payload_length.to_le_bytes());
    Ok(header)
}

fn maximum_terminal_frame_bytes(response_cap: u64) -> Result<u64, DurableWalError> {
    let bounded_body = response_cap.min(MAX_PUBLIC_WIRE_BODY_BYTES);
    let bounded_body =
        usize::try_from(bounded_body).map_err(|_| DurableWalError::RecordTooLarge(usize::MAX))?;
    let payload_length = bounded_body
        .checked_add(MAX_TERMINAL_RECORD_OVERHEAD)
        .ok_or(DurableWalError::RecordTooLarge(usize::MAX))?;
    let frame_length = HEADER_LEN
        .checked_add(payload_length)
        .and_then(|length| length.checked_add(CHECKSUM_LEN))
        .ok_or(DurableWalError::RecordTooLarge(usize::MAX))?;
    u64::try_from(frame_length).map_err(|_| DurableWalError::RecordTooLarge(frame_length))
}

fn validate_recovered_headroom(
    state: &RecoveredState,
    wal_length: u64,
) -> Result<(), DurableWalError> {
    let headroom = state
        .budget
        .active
        .values()
        .try_fold(0_u64, |total, response_cap| {
            total
                .checked_add(maximum_terminal_frame_bytes(*response_cap)?)
                .ok_or(DurableWalError::WalTooLarge {
                    length: u64::MAX,
                    maximum: MAX_DURABLE_BROKER_WAL_BYTES,
                })
        })?;
    let projected = wal_length
        .checked_add(headroom)
        .ok_or(DurableWalError::WalTooLarge {
            length: u64::MAX,
            maximum: MAX_DURABLE_BROKER_WAL_BYTES,
        })?;
    if projected > MAX_DURABLE_BROKER_WAL_BYTES {
        return Err(DurableWalError::WalTooLarge {
            length: projected,
            maximum: MAX_DURABLE_BROKER_WAL_BYTES,
        });
    }
    Ok(())
}

fn read_and_parse(
    file: &mut File,
    tail_policy: TailPolicy,
) -> Result<(RecoveredState, u64), DurableWalError> {
    let length = file.metadata()?.len();
    if length > MAX_DURABLE_BROKER_WAL_BYTES {
        return Err(DurableWalError::WalTooLarge {
            length,
            maximum: MAX_DURABLE_BROKER_WAL_BYTES,
        });
    }
    let capacity = usize::try_from(length).map_err(|_| DurableWalError::WalTooLarge {
        length,
        maximum: MAX_DURABLE_BROKER_WAL_BYTES,
    })?;
    let mut bytes = Vec::with_capacity(capacity);
    file.take(MAX_DURABLE_BROKER_WAL_BYTES + 1)
        .read_to_end(&mut bytes)?;
    let observed_length = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    if observed_length > MAX_DURABLE_BROKER_WAL_BYTES {
        return Err(DurableWalError::WalTooLarge {
            length: observed_length,
            maximum: MAX_DURABLE_BROKER_WAL_BYTES,
        });
    }
    if file.metadata()?.len() != observed_length {
        return Err(DurableWalError::InvalidRecord(
            "WAL length changed during recovery".to_owned(),
        ));
    }
    let parsed = parse_wal(&bytes, tail_policy)?;
    let verified_length = u64::try_from(parsed.verified_length).unwrap_or(u64::MAX);
    if verified_length < observed_length {
        if tail_policy != TailPolicy::Repair {
            return Err(DurableWalError::TruncatedRecord);
        }
        if let Err(error) = file.set_len(verified_length).and_then(|()| file.sync_all()) {
            return Err(DurableWalError::DurabilityUncertain(error));
        }
    }
    Ok((parsed.state, verified_length))
}

fn parse_wal(bytes: &[u8], tail_policy: TailPolicy) -> Result<ParsedWal, DurableWalError> {
    if bytes.len() > usize::try_from(MAX_DURABLE_BROKER_WAL_BYTES).unwrap_or(usize::MAX) {
        return Err(DurableWalError::WalTooLarge {
            length: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
            maximum: MAX_DURABLE_BROKER_WAL_BYTES,
        });
    }
    let mut offset = 0;
    let mut expected_sequence = 0;
    let mut state = None;
    while offset < bytes.len() {
        let frame_start = offset;
        let remaining = bytes.len() - frame_start;
        if remaining < HEADER_LEN {
            validate_partial_header(&bytes[frame_start..], expected_sequence)?;
            return finish_torn_tail(state, expected_sequence, frame_start, tail_policy);
        }
        if &bytes[offset..offset + MAGIC.len()] != MAGIC {
            return Err(DurableWalError::InvalidMagic);
        }
        offset += MAGIC.len();
        let version = read_u16(bytes, &mut offset)?;
        if version != VERSION {
            return Err(DurableWalError::UnsupportedVersion(version));
        }
        let kind = read_byte(bytes, &mut offset)?;
        if read_byte(bytes, &mut offset)? != 0 {
            return Err(DurableWalError::InvalidRecord(
                "frame reserved bits are non-zero".to_owned(),
            ));
        }
        let sequence = read_u64(bytes, &mut offset)?;
        if sequence != expected_sequence {
            return Err(DurableWalError::SequenceMismatch {
                expected: expected_sequence,
                actual: sequence,
            });
        }
        let payload_length = usize::try_from(read_u32(bytes, &mut offset)?)
            .map_err(|_| DurableWalError::RecordTooLarge(usize::MAX))?;
        if payload_length > MAX_RECORD_PAYLOAD_BYTES {
            return Err(DurableWalError::RecordTooLarge(payload_length));
        }
        validate_frame_shape(kind, expected_sequence, payload_length)?;
        let frame_length = HEADER_LEN
            .checked_add(payload_length)
            .and_then(|length| length.checked_add(CHECKSUM_LEN))
            .ok_or(DurableWalError::RecordTooLarge(payload_length))?;
        if bytes.len() - frame_start < frame_length {
            if has_complete_following_frame(
                bytes,
                frame_start + HEADER_LEN,
                expected_sequence.saturating_add(1),
            ) {
                return Err(DurableWalError::TruncatedRecord);
            }
            return finish_torn_tail(state, expected_sequence, frame_start, tail_policy);
        }
        let payload_end = offset + payload_length;
        let payload = &bytes[offset..payload_end];
        offset = payload_end;
        let stored_checksum = read_u64(bytes, &mut offset)?;
        if stored_checksum != checksum(&bytes[frame_start..payload_end]) {
            return Err(DurableWalError::ChecksumMismatch);
        }
        apply_recovered_frame(&mut state, kind, expected_sequence, payload)?;
        expected_sequence = expected_sequence
            .checked_add(1)
            .ok_or(DurableWalError::SequenceExhausted)?;
    }
    finish_parsed_wal(state, expected_sequence, offset)
}

fn apply_recovered_frame(
    state: &mut Option<RecoveredState>,
    kind: u8,
    expected_sequence: u64,
    payload: &[u8],
) -> Result<(), DurableWalError> {
    match kind {
        INIT_KIND if expected_sequence == 0 => {
            *state = Some(RecoveredState::new(decode_init(payload)?));
        }
        INIT_KIND => {
            return Err(DurableWalError::InvalidRecord(
                "session record is repeated".to_owned(),
            ));
        }
        ACCEPT_KIND => {
            let recovered = state.as_mut().ok_or_else(|| {
                DurableWalError::InvalidRecord(
                    "request appears before the session record".to_owned(),
                )
            })?;
            let (sequence, request, payload_hash, response_cap) =
                decode_accept(payload, recovered.config.session())?;
            recovered.apply_accept_parts(sequence, request, payload_hash, response_cap)?;
        }
        RESERVE_KIND => {
            let request = decode_request(payload)?;
            recovered_state(state)?.apply_reserve(request)?;
        }
        RETRYABLE_BUDGET_KIND => {
            let request = decode_request(payload)?;
            recovered_state(state)?.apply_retryable(request)?;
        }
        FINAL_KIND => {
            let (request, settlement, response) = decode_final(payload)?;
            recovered_state(state)?.apply_final(request, settlement, response)?;
        }
        _ => {
            return Err(DurableWalError::InvalidRecord(
                "frame kind is unknown".to_owned(),
            ));
        }
    }
    Ok(())
}

fn finish_torn_tail(
    state: Option<RecoveredState>,
    expected_sequence: u64,
    verified_length: usize,
    tail_policy: TailPolicy,
) -> Result<ParsedWal, DurableWalError> {
    if tail_policy == TailPolicy::Reject {
        return Err(DurableWalError::TruncatedRecord);
    }
    finish_parsed_wal(state, expected_sequence, verified_length)
}

fn finish_parsed_wal(
    state: Option<RecoveredState>,
    expected_sequence: u64,
    verified_length: usize,
) -> Result<ParsedWal, DurableWalError> {
    let mut state = state
        .ok_or_else(|| DurableWalError::InvalidRecord("WAL has no session record".to_owned()))?;
    state.next_wal_sequence = Some(expected_sequence);
    Ok(ParsedWal {
        state,
        verified_length,
    })
}

fn validate_partial_header(bytes: &[u8], expected_sequence: u64) -> Result<(), DurableWalError> {
    let magic_length = bytes.len().min(MAGIC.len());
    if bytes[..magic_length] != MAGIC[..magic_length] {
        return Err(DurableWalError::InvalidMagic);
    }
    if bytes.len() >= MAGIC.len() + 2 {
        let version = u16::from_le_bytes(
            bytes[MAGIC.len()..MAGIC.len() + 2]
                .try_into()
                .map_err(|_| DurableWalError::TruncatedRecord)?,
        );
        if version != VERSION {
            return Err(DurableWalError::UnsupportedVersion(version));
        }
    }
    if bytes.len() > MAGIC.len() + 2 {
        validate_frame_kind(bytes[MAGIC.len() + 2], expected_sequence)?;
    }
    if bytes.len() > MAGIC.len() + 3 && bytes[MAGIC.len() + 3] != 0 {
        return Err(DurableWalError::InvalidRecord(
            "frame reserved bits are non-zero".to_owned(),
        ));
    }
    if bytes.len() >= MAGIC.len() + 2 + 1 + 1 + 8 {
        let sequence_start = MAGIC.len() + 2 + 1 + 1;
        let sequence = u64::from_le_bytes(
            bytes[sequence_start..sequence_start + 8]
                .try_into()
                .map_err(|_| DurableWalError::TruncatedRecord)?,
        );
        if sequence != expected_sequence {
            return Err(DurableWalError::SequenceMismatch {
                expected: expected_sequence,
                actual: sequence,
            });
        }
    }
    Ok(())
}

fn validate_frame_shape(
    kind: u8,
    expected_sequence: u64,
    payload_length: usize,
) -> Result<(), DurableWalError> {
    validate_frame_kind(kind, expected_sequence)?;
    let valid_length = match kind {
        INIT_KIND => payload_length == INIT_PAYLOAD_LEN,
        ACCEPT_KIND => payload_length == ACCEPT_PAYLOAD_LEN,
        RESERVE_KIND | RETRYABLE_BUDGET_KIND => payload_length == REQUEST_PAYLOAD_LEN,
        FINAL_KIND => (FINAL_PREFIX_LEN..=MAX_RECORD_PAYLOAD_BYTES).contains(&payload_length),
        _ => false,
    };
    if !valid_length {
        return Err(DurableWalError::InvalidRecord(
            "frame kind and payload length are inconsistent".to_owned(),
        ));
    }
    Ok(())
}

fn validate_frame_kind(kind: u8, expected_sequence: u64) -> Result<(), DurableWalError> {
    match kind {
        INIT_KIND if expected_sequence == 0 => Ok(()),
        INIT_KIND => Err(DurableWalError::InvalidRecord(
            "session record is repeated".to_owned(),
        )),
        ACCEPT_KIND | RESERVE_KIND | RETRYABLE_BUDGET_KIND | FINAL_KIND
            if expected_sequence > 0 =>
        {
            Ok(())
        }
        _ => Err(DurableWalError::InvalidRecord(
            "frame kind is unknown".to_owned(),
        )),
    }
}

fn has_complete_following_frame(bytes: &[u8], start: usize, expected_sequence: u64) -> bool {
    let Some(search) = bytes.get(start..) else {
        return false;
    };
    for relative in 0..search.len().saturating_sub(MAGIC.len()).saturating_add(1) {
        let frame_start = start + relative;
        if bytes.get(frame_start..frame_start + MAGIC.len()) != Some(MAGIC.as_slice()) {
            continue;
        }
        let Some(header) = bytes.get(frame_start..frame_start + HEADER_LEN) else {
            continue;
        };
        if u16::from_le_bytes([header[8], header[9]]) != VERSION || header[11] != 0 {
            continue;
        }
        let sequence = u64::from_le_bytes(
            header[12..20]
                .try_into()
                .expect("fixed WAL sequence header slice"),
        );
        if sequence != expected_sequence {
            continue;
        }
        let payload_length = usize::try_from(u32::from_le_bytes(
            header[20..24]
                .try_into()
                .expect("fixed WAL length header slice"),
        ))
        .unwrap_or(usize::MAX);
        if payload_length > MAX_RECORD_PAYLOAD_BYTES
            || validate_frame_shape(header[10], sequence, payload_length).is_err()
        {
            continue;
        }
        let Some(frame_length) = HEADER_LEN
            .checked_add(payload_length)
            .and_then(|length| length.checked_add(CHECKSUM_LEN))
        else {
            continue;
        };
        let Some(frame) = bytes.get(frame_start..frame_start + frame_length) else {
            continue;
        };
        let payload_end = HEADER_LEN + payload_length;
        let stored_checksum = u64::from_le_bytes(
            frame[payload_end..]
                .try_into()
                .expect("fixed WAL checksum trailer slice"),
        );
        if stored_checksum == checksum(&frame[..payload_end]) {
            return true;
        }
    }
    false
}

fn recovered_state(
    state: &mut Option<RecoveredState>,
) -> Result<&mut RecoveredState, DurableWalError> {
    state.as_mut().ok_or_else(|| {
        DurableWalError::InvalidRecord("mutation appears before the session record".to_owned())
    })
}

fn decode_request(payload: &[u8]) -> Result<BrokerRequestId, DurableWalError> {
    if payload.len() != REQUEST_PAYLOAD_LEN {
        return Err(DurableWalError::InvalidRecord(
            "request mutation has the wrong length".to_owned(),
        ));
    }
    let mut cursor = 0;
    Ok(BrokerRequestId::new(read_fixed(payload, &mut cursor)?))
}

fn read_byte(bytes: &[u8], cursor: &mut usize) -> Result<u8, DurableWalError> {
    let byte = bytes
        .get(*cursor)
        .copied()
        .ok_or(DurableWalError::TruncatedRecord)?;
    *cursor += 1;
    Ok(byte)
}

fn read_u16(bytes: &[u8], cursor: &mut usize) -> Result<u16, DurableWalError> {
    Ok(u16::from_le_bytes(read_fixed(bytes, cursor)?))
}

fn read_u32(bytes: &[u8], cursor: &mut usize) -> Result<u32, DurableWalError> {
    Ok(u32::from_le_bytes(read_fixed(bytes, cursor)?))
}

fn read_u64(bytes: &[u8], cursor: &mut usize) -> Result<u64, DurableWalError> {
    Ok(u64::from_le_bytes(read_fixed(bytes, cursor)?))
}

fn read_fixed<const N: usize>(
    bytes: &[u8],
    cursor: &mut usize,
) -> Result<[u8; N], DurableWalError> {
    let end = cursor
        .checked_add(N)
        .ok_or(DurableWalError::TruncatedRecord)?;
    let value = bytes
        .get(*cursor..end)
        .ok_or(DurableWalError::TruncatedRecord)?
        .try_into()
        .map_err(|_| DurableWalError::TruncatedRecord)?;
    *cursor = end;
    Ok(value)
}

fn checksum(bytes: &[u8]) -> u64 {
    checksum_parts(bytes, &[])
}

fn checksum_parts(first: &[u8], second: &[u8]) -> u64 {
    let mut state = 0xcbf2_9ce4_8422_2325_u64;
    for byte in first.iter().chain(second) {
        state ^= u64::from(*byte);
        state = state.wrapping_mul(0x0000_0100_0000_01b3);
    }
    state
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileIdentity {
    device: u64,
    inode: u64,
}

fn validate_new_path(directory: &DurableDirectory) -> Result<(), DurableWalError> {
    directory.validate()?;
    match fs::symlink_metadata(directory.wal_path()) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(DurableWalError::Symlink),
        Ok(_) => Err(DurableWalError::Io(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "durable broker WAL already exists",
        ))),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(DurableWalError::Io(error)),
    }
}

fn validate_existing_path(directory: &DurableDirectory) -> Result<(), DurableWalError> {
    directory.validate()?;
    let metadata = fs::symlink_metadata(directory.wal_path())?;
    if metadata.file_type().is_symlink() {
        return Err(DurableWalError::Symlink);
    }
    if !metadata.is_file() {
        return Err(DurableWalError::NotRegularFile);
    }
    if metadata.len() > MAX_DURABLE_BROKER_WAL_BYTES {
        return Err(DurableWalError::WalTooLarge {
            length: metadata.len(),
            maximum: MAX_DURABLE_BROKER_WAL_BYTES,
        });
    }
    validate_file_metadata(&metadata, directory.effective_uid)?;
    Ok(())
}

fn validate_open_file(directory: &DurableDirectory, file: &File) -> Result<(), DurableWalError> {
    validate_open_named_file(
        directory,
        &directory.wal_name,
        file,
        Some(MAX_DURABLE_BROKER_WAL_BYTES),
    )
}

fn validate_open_lock(directory: &DurableDirectory, file: &File) -> Result<(), DurableWalError> {
    validate_open_named_file(directory, &directory.lock_name, file, Some(0))
}

fn validate_open_named_file(
    directory: &DurableDirectory,
    name: &OsStr,
    file: &File,
    maximum_length: Option<u64>,
) -> Result<(), DurableWalError> {
    directory.validate()?;
    let path_metadata = fs::symlink_metadata(directory.child_path(name)).map_err(|error| {
        if error.kind() == io::ErrorKind::NotFound {
            DurableWalError::PathIdentityChanged
        } else {
            DurableWalError::Io(error)
        }
    })?;
    if path_metadata.file_type().is_symlink() {
        return Err(DurableWalError::Symlink);
    }
    let metadata = file.metadata()?;
    if !metadata.is_file() || !path_metadata.is_file() {
        return Err(DurableWalError::NotRegularFile);
    }
    if file_identity(&metadata) != file_identity(&path_metadata) {
        return Err(DurableWalError::PathIdentityChanged);
    }
    validate_file_metadata(&metadata, directory.effective_uid)?;
    if let Some(maximum) = maximum_length
        && metadata.len() > maximum
    {
        return Err(DurableWalError::WalTooLarge {
            length: metadata.len(),
            maximum,
        });
    }
    Ok(())
}

fn open_session_lock(
    directory: &DurableDirectory,
    exclusive: bool,
) -> Result<File, DurableWalError> {
    directory.validate()?;
    let path = directory.lock_path();
    let (file, created) = match create_private_file(&path) {
        Ok(file) => (file, true),
        Err(DurableWalError::Io(error)) if error.kind() == io::ErrorKind::AlreadyExists => {
            (open_existing_file(&path, exclusive)?, false)
        }
        Err(error) => return Err(error),
    };
    if exclusive {
        acquire_exclusive_lock(&file)?;
    } else {
        acquire_shared_lock(&file)?;
    }
    validate_open_lock(directory, &file)?;
    if created {
        file.sync_all()?;
        directory.sync()?;
    }
    Ok(file)
}

fn create_private_file(path: &Path) -> Result<File, DurableWalError> {
    let mut options = OpenOptions::new();
    options.create_new(true).read(true).write(true);
    configure_secure_open(&mut options);
    let file = options.open(path)?;
    set_private_permissions(&file)?;
    Ok(file)
}

fn open_existing_file(path: &Path, write: bool) -> Result<File, DurableWalError> {
    let mut options = OpenOptions::new();
    options.read(true).write(write);
    configure_secure_open(&mut options);
    Ok(options.open(path)?)
}

fn configure_secure_open(options: &mut OpenOptions) {
    #[cfg(unix)]
    options.mode(PRIVATE_FILE_MODE);
    #[cfg(target_os = "linux")]
    options.custom_flags(O_NOFOLLOW);
}

fn set_private_permissions(file: &File) -> io::Result<()> {
    #[cfg(unix)]
    file.set_permissions(fs::Permissions::from_mode(PRIVATE_FILE_MODE))?;
    Ok(())
}

fn validate_parent_path(path: &Path, effective_uid: u32) -> Result<FileIdentity, DurableWalError> {
    let mut current = if path.is_absolute() {
        PathBuf::new()
    } else {
        PathBuf::from(".")
    };
    let mut final_identity = None;
    for component in path.components() {
        match component {
            std::path::Component::RootDir => current.push(Path::new("/")),
            std::path::Component::CurDir => continue,
            std::path::Component::Normal(name) => current.push(name),
            std::path::Component::ParentDir | std::path::Component::Prefix(_) => {
                return Err(DurableWalError::UnsafeParentDirectory);
            }
        }
        let metadata = fs::symlink_metadata(&current)?;
        if metadata.file_type().is_symlink() {
            return Err(DurableWalError::Symlink);
        }
        validate_directory_metadata(&metadata, effective_uid)?;
        final_identity = Some(file_identity(&metadata));
    }
    if final_identity.is_none() {
        let metadata = fs::symlink_metadata(&current)?;
        if metadata.file_type().is_symlink() {
            return Err(DurableWalError::Symlink);
        }
        validate_directory_metadata(&metadata, effective_uid)?;
        final_identity = Some(file_identity(&metadata));
    }
    final_identity.ok_or(DurableWalError::UnsafeParentDirectory)
}

fn validate_parent_path_identity(
    path: &Path,
    directory: &File,
    effective_uid: u32,
) -> Result<(), DurableWalError> {
    let path_identity = validate_parent_path(path, effective_uid)?;
    let metadata = directory.metadata()?;
    validate_directory_metadata(&metadata, effective_uid)?;
    if path_identity != file_identity(&metadata) {
        return Err(DurableWalError::PathIdentityChanged);
    }
    Ok(())
}

fn validate_directory_metadata(
    metadata: &fs::Metadata,
    effective_uid: u32,
) -> Result<(), DurableWalError> {
    if !metadata.is_dir() {
        return Err(DurableWalError::UnsafeParentDirectory);
    }
    #[cfg(unix)]
    {
        let mode = metadata.mode();
        let owner = metadata.uid();
        if mode & WRITE_BY_GROUP_OR_OTHER != 0
            && (mode & STICKY_DIRECTORY == 0 || (owner != 0 && owner != effective_uid))
        {
            return Err(DurableWalError::UnsafeParentDirectory);
        }
    }
    Ok(())
}

fn validate_file_metadata(
    metadata: &fs::Metadata,
    effective_uid: u32,
) -> Result<(), DurableWalError> {
    #[cfg(unix)]
    validate_owner_and_permissions(metadata.uid(), metadata.mode(), effective_uid)?;
    Ok(())
}

fn validate_owner_and_permissions(
    owner: u32,
    mode: u32,
    effective_uid: u32,
) -> Result<(), DurableWalError> {
    if owner != effective_uid {
        return Err(DurableWalError::WrongOwner {
            expected: effective_uid,
            actual: owner,
        });
    }
    if mode & ACCESS_BY_GROUP_OR_OTHER != 0 {
        return Err(DurableWalError::UnsafePermissions { mode: mode & 0o777 });
    }
    Ok(())
}

#[cfg(unix)]
fn file_identity(metadata: &fs::Metadata) -> FileIdentity {
    FileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    }
}

#[cfg(not(unix))]
fn file_identity(_metadata: &fs::Metadata) -> FileIdentity {
    FileIdentity {
        device: 0,
        inode: 0,
    }
}

#[cfg(target_os = "linux")]
fn effective_uid() -> Result<u32, DurableWalError> {
    let status = fs::read_to_string("/proc/self/status")?;
    let line = status
        .lines()
        .find(|line| line.starts_with("Uid:"))
        .ok_or_else(|| io::Error::other("/proc/self/status has no effective uid"))?;
    line.split_ascii_whitespace()
        .nth(2)
        .ok_or_else(|| io::Error::other("/proc/self/status effective uid is missing"))?
        .parse::<u32>()
        .map_err(|_| io::Error::other("/proc/self/status effective uid is invalid"))
        .map_err(DurableWalError::Io)
}

#[cfg(not(target_os = "linux"))]
fn effective_uid() -> Result<u32, DurableWalError> {
    Err(DurableWalError::Io(io::Error::new(
        io::ErrorKind::Unsupported,
        "durable broker WAL ownership validation requires Linux",
    )))
}

fn durable_lock_name(wal_name: &OsStr) -> OsString {
    #[cfg(unix)]
    let bytes = std::os::unix::ffi::OsStrExt::as_bytes(wal_name);
    #[cfg(not(unix))]
    let bytes = wal_name.to_string_lossy().as_bytes();
    OsString::from(format!(".egress-broker-{:016x}.lock", checksum(bytes)))
}

fn acquire_exclusive_lock(file: &File) -> Result<(), DurableWalError> {
    let deadline = Instant::now() + TRANSIENT_FORK_LOCK_RETRY;
    loop {
        match file.try_lock() {
            Ok(()) => return Ok(()),
            Err(TryLockError::WouldBlock) if Instant::now() < deadline => {
                thread::sleep(TRANSIENT_FORK_LOCK_POLL);
            }
            Err(TryLockError::WouldBlock) => return Err(DurableWalError::Locked),
            Err(TryLockError::Error(error)) => return Err(DurableWalError::Io(error)),
        }
    }
}

fn acquire_shared_lock(file: &File) -> Result<(), DurableWalError> {
    let deadline = Instant::now() + TRANSIENT_FORK_LOCK_RETRY;
    loop {
        match file.try_lock_shared() {
            Ok(()) => return Ok(()),
            Err(TryLockError::WouldBlock) if Instant::now() < deadline => {
                // Only a transient kernel-lock conflict on this pre-opened file is retried. All
                // path, inode, link, owner, and mode checks remain mandatory after acquisition.
                thread::sleep(TRANSIENT_FORK_LOCK_POLL);
            }
            Err(TryLockError::WouldBlock) => return Err(DurableWalError::Locked),
            Err(TryLockError::Error(error)) => return Err(DurableWalError::Io(error)),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs::{self, OpenOptions},
        io::{Seek, SeekFrom, Write},
        num::{NonZeroU64, NonZeroUsize},
        os::unix::fs::PermissionsExt,
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };

    use authority_core::http::{CanonicalHost, CanonicalUrlPath};
    use egress_protocol::{
        budget::SessionBudgetLimits,
        response::{
            BrokerWireOutcome, BrokerWireRejection, CanonicalBrokerResponse,
            MAX_PUBLIC_WIRE_BODY_BYTES, PublicWireResponse,
        },
        session::{BrokerEnvelope, BrokerRequestId, BrokerSessionId},
    };

    use super::{
        BudgetSettlement, DurableAcceptance, DurableBrokerView, DurableBrokerWal,
        DurableRequestPhase, DurableSessionConfig, DurableWalError, FINAL_KIND, HEADER_LEN,
        MAX_DURABLE_BROKER_WAL_BYTES, MAX_FINAL_APPEND_TRANSIENT_DATA_BYTES, PRIVATE_FILE_MODE,
        RETRYABLE_BUDGET_KIND, canonical_wire_payloads, durable_lock_name, encode_final,
        encode_frame, validate_owner_and_permissions,
    };

    static NEXT_PATH: AtomicU64 = AtomicU64::new(0);

    struct TestPath(PathBuf);

    impl TestPath {
        fn new(name: &str) -> Self {
            let nonce = NEXT_PATH.fetch_add(1, Ordering::Relaxed);
            Self(std::env::temp_dir().join(format!(
                "egress-broker-durable-{}-{name}-{nonce}.wal",
                std::process::id()
            )))
        }
    }

    impl Drop for TestPath {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.0);
            if let (Some(parent), Some(name)) = (self.0.parent(), self.0.file_name()) {
                let _ = fs::remove_file(parent.join(durable_lock_name(name)));
            }
        }
    }

    fn config() -> DurableSessionConfig {
        DurableSessionConfig::new(
            BrokerSessionId::new([7; 16]),
            NonZeroUsize::new(8).expect("test replay capacity is non-zero"),
            SessionBudgetLimits::new(
                NonZeroU64::new(4).expect("test request budget is non-zero"),
                100,
                NonZeroUsize::new(2).expect("test concurrency budget is non-zero"),
            ),
        )
    }

    fn envelope(sequence: u64, value: u8) -> BrokerEnvelope {
        BrokerEnvelope::from_canonical_payload(
            config().session(),
            sequence,
            BrokerRequestId::new([value; 16]),
            &[value],
        )
    }

    fn rejection(request: BrokerRequestId) -> CanonicalBrokerResponse {
        CanonicalBrokerResponse::new(
            request,
            BrokerWireOutcome::Rejected(BrokerWireRejection::CommittedButUnrecorded),
        )
    }

    fn maximum_public_response(request: BrokerRequestId, byte: u8) -> CanonicalBrokerResponse {
        let body_length = usize::try_from(MAX_PUBLIC_WIRE_BODY_BYTES)
            .expect("public response cap fits this platform");
        let public = PublicWireResponse::new(
            200,
            CanonicalHost::new("example.com").expect("fixture host is canonical"),
            CanonicalUrlPath::root(),
            vec![byte; body_length],
        )
        .expect("maximum public response is valid");
        CanonicalBrokerResponse::new(request, BrokerWireOutcome::Public(public))
    }

    fn append_fixture(path: &PathBuf, bytes: &[u8]) {
        let mut file = OpenOptions::new()
            .append(true)
            .open(path)
            .expect("open WAL fixture");
        file.write_all(bytes).expect("append WAL fixture");
        file.sync_all().expect("sync WAL fixture");
    }

    #[test]
    fn cross_restart_retains_exact_final_response_and_budget() {
        let path = TestPath::new("cross-restart");
        let first = envelope(0, 1);
        let encoded = {
            let mut wal = DurableBrokerWal::create(&path.0, config()).expect("create WAL");
            assert!(matches!(wal.accept(first, 80), Ok(DurableAcceptance::New)));
            wal.reserve(first.request()).expect("reserve budget");
            let response = rejection(first.request());
            let encoded = response.encode().expect("encode response");
            wal.finalize(
                first.request(),
                &response,
                BudgetSettlement::Complete { response_bytes: 80 },
            )
            .expect("finalize request");
            encoded
        };

        let mut reopened = DurableBrokerWal::open(&path.0, config()).expect("reopen WAL");
        let DurableAcceptance::ExactDuplicate(recovered) =
            reopened.accept(first, 80).expect("admit exact duplicate")
        else {
            panic!("restart must recover an exact duplicate");
        };
        let DurableRequestPhase::Final(response) = recovered.phase() else {
            panic!("restart must recover the terminal phase");
        };
        assert_eq!(response.wire_payloads(), &[encoded]);
        assert_eq!(response.response(), &rejection(first.request()));
        let view = reopened.read_only_view().expect("snapshot WAL");
        assert_eq!(view.budget().started_requests(), 1);
        assert_eq!(view.budget().committed_response_bytes(), 80);
        assert_eq!(view.budget().reserved_response_bytes(), 0);
        let restored_usage = view.restore_budget().expect("restore budget").usage();
        assert_eq!(restored_usage.started_requests(), 1);
        assert_eq!(restored_usage.committed_response_bytes(), 80);
        assert_eq!(restored_usage.reserved_response_bytes(), 0);
        assert_eq!(restored_usage.active_requests(), 0);
    }

    #[test]
    fn accepted_pending_recovery_never_becomes_new() {
        let path = TestPath::new("pending");
        let first = envelope(0, 1);
        {
            let mut wal = DurableBrokerWal::create(&path.0, config()).expect("create WAL");
            assert!(matches!(wal.accept(first, 50), Ok(DurableAcceptance::New)));
        }
        let mut reopened = DurableBrokerWal::open(&path.0, config()).expect("reopen WAL");
        let DurableAcceptance::ExactDuplicate(request) = reopened
            .accept(first, 50)
            .expect("recover pending duplicate")
        else {
            panic!("pending request must remain admitted");
        };
        assert!(matches!(
            request.phase(),
            DurableRequestPhase::AcceptedPending
        ));
        assert_eq!(request.active_reservation(), None);
        reopened
            .finalize(
                first.request(),
                &rejection(first.request()),
                BudgetSettlement::NotStarted,
            )
            .expect("seal pre-budget recovery");
        assert_eq!(
            reopened
                .read_only_view()
                .expect("view")
                .budget()
                .started_requests(),
            0
        );
    }

    #[test]
    fn active_pending_recovery_can_be_conservatively_charged_at_full_cap() {
        let path = TestPath::new("active-pending");
        let first = envelope(0, 1);
        {
            let mut wal = DurableBrokerWal::create(&path.0, config()).expect("create WAL");
            wal.accept(first, 60).expect("accept request");
            wal.reserve(first.request()).expect("reserve request");
        }
        let mut reopened = DurableBrokerWal::open(&path.0, config()).expect("reopen WAL");
        let request = reopened
            .read_only_view()
            .expect("view")
            .request(first.request())
            .expect("request")
            .clone();
        assert_eq!(request.active_reservation(), Some(60));
        reopened
            .finalize(
                first.request(),
                &rejection(first.request()),
                BudgetSettlement::Complete { response_bytes: 60 },
            )
            .expect("seal ambiguous request");
        let usage = reopened.read_only_view().expect("view").budget();
        assert_eq!(usage.started_requests(), 1);
        assert_eq!(usage.committed_response_bytes(), 60);
        assert_eq!(usage.reserved_response_bytes(), 0);
    }

    #[test]
    fn retryable_budget_survives_restart_and_can_reserve_once() {
        let path = TestPath::new("retryable");
        let first = envelope(0, 1);
        {
            let mut wal = DurableBrokerWal::create(&path.0, config()).expect("create WAL");
            wal.accept(first, 50).expect("accept request");
            wal.mark_retryable_budget(first.request())
                .expect("mark retryable");
        }
        let mut reopened = DurableBrokerWal::open(&path.0, config()).expect("reopen WAL");
        let request = reopened
            .read_only_view()
            .expect("view")
            .request(first.request())
            .expect("request")
            .clone();
        assert!(matches!(
            request.phase(),
            DurableRequestPhase::RetryableBudget
        ));
        reopened.reserve(first.request()).expect("reserve retry");
        assert!(matches!(
            reopened.reserve(first.request()),
            Err(DurableWalError::InvalidTransition { .. })
        ));
    }

    #[test]
    fn writer_is_exclusive_and_detached_view_is_read_only() {
        let path = TestPath::new("exclusive");
        let wal = DurableBrokerWal::create(&path.0, config()).expect("create WAL");
        assert!(matches!(
            DurableBrokerWal::open(&path.0, config()),
            Err(DurableWalError::Locked)
        ));
        assert!(matches!(
            DurableBrokerView::open(&path.0),
            Err(DurableWalError::Locked)
        ));
        let detached = wal.read_only_view().expect("in-process view");
        assert!(detached.requests().is_empty());
        drop(wal);
        assert_eq!(
            DurableBrokerView::open(&path.0)
                .expect("external read-only view")
                .config(),
            config()
        );
    }

    #[test]
    fn truncation_and_checksum_corruption_fail_closed() {
        let truncated_path = TestPath::new("truncated");
        {
            let mut wal =
                DurableBrokerWal::create(&truncated_path.0, config()).expect("create WAL");
            wal.accept(envelope(0, 1), 10).expect("accept request");
        }
        let length = fs::metadata(&truncated_path.0).expect("metadata").len();
        OpenOptions::new()
            .write(true)
            .open(&truncated_path.0)
            .expect("open WAL")
            .set_len(length - 1)
            .expect("truncate WAL");
        assert!(matches!(
            DurableBrokerView::open(&truncated_path.0),
            Err(DurableWalError::TruncatedRecord)
        ));

        let corrupt_path = TestPath::new("corrupt");
        {
            let mut wal = DurableBrokerWal::create(&corrupt_path.0, config()).expect("create WAL");
            wal.accept(envelope(0, 1), 10).expect("accept request");
        }
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&corrupt_path.0)
            .expect("open WAL");
        file.seek(SeekFrom::End(-1)).expect("seek checksum");
        file.write_all(&[0xff]).expect("corrupt checksum");
        file.sync_all().expect("sync corruption");
        let corrupt_length = file.metadata().expect("corrupt metadata").len();
        drop(file);
        assert!(matches!(
            DurableBrokerView::open(&corrupt_path.0),
            Err(DurableWalError::ChecksumMismatch)
        ));
        assert!(matches!(
            DurableBrokerWal::open(&corrupt_path.0, config()),
            Err(DurableWalError::ChecksumMismatch)
        ));
        assert_eq!(
            fs::metadata(&corrupt_path.0)
                .expect("corrupt WAL metadata")
                .len(),
            corrupt_length
        );
    }

    #[test]
    fn exclusive_open_repairs_only_a_torn_tail_and_preserves_pending_reservation() {
        let path = TestPath::new("repair-tail");
        let first = envelope(0, 1);
        let verified_length = {
            let mut wal = DurableBrokerWal::create(&path.0, config()).expect("create WAL");
            wal.accept(first, 10).expect("accept request");
            wal.reserve(first.request()).expect("reserve request");
            fs::metadata(&path.0).expect("verified WAL metadata").len()
        };
        let response = rejection(first.request());
        let wire_payloads = vec![response.encode().expect("encode response")];
        let payload = encode_final(
            first.request(),
            BudgetSettlement::Complete { response_bytes: 10 },
            &wire_payloads,
        )
        .expect("encode final payload");
        let frame = encode_frame(3, FINAL_KIND, &payload).expect("encode final frame");
        append_fixture(&path.0, &frame[..frame.len() - 3]);
        let torn_length = fs::metadata(&path.0).expect("torn WAL metadata").len();

        assert!(matches!(
            DurableBrokerView::open(&path.0),
            Err(DurableWalError::TruncatedRecord)
        ));
        assert_eq!(
            fs::metadata(&path.0)
                .expect("unrepaired WAL metadata")
                .len(),
            torn_length
        );

        let mut repaired = DurableBrokerWal::open(&path.0, config()).expect("repair torn tail");
        assert_eq!(
            fs::metadata(&path.0).expect("repaired WAL metadata").len(),
            verified_length
        );
        let recovered = repaired
            .read_only_view()
            .expect("repaired view")
            .request(first.request())
            .expect("recovered request")
            .clone();
        assert!(matches!(
            recovered.phase(),
            DurableRequestPhase::AcceptedPending
        ));
        assert_eq!(recovered.active_reservation(), Some(10));
        repaired
            .finalize(
                first.request(),
                &response,
                BudgetSettlement::Complete { response_bytes: 10 },
            )
            .expect("conservatively finalize recovered request");
        drop(repaired);
        DurableBrokerWal::open(&path.0, config()).expect("reopen repaired WAL");
    }

    #[test]
    fn truncation_before_a_later_frame_is_corruption_and_is_not_repaired() {
        let path = TestPath::new("middle-truncation");
        let first = envelope(0, 1);
        {
            let mut wal = DurableBrokerWal::create(&path.0, config()).expect("create WAL");
            wal.accept(first, 10).expect("accept request");
        }
        let response = rejection(first.request());
        let wire_payloads = vec![response.encode().expect("encode response")];
        let payload = encode_final(
            first.request(),
            BudgetSettlement::NotStarted,
            &wire_payloads,
        )
        .expect("encode final payload");
        let mut truncated = encode_frame(2, FINAL_KIND, &payload).expect("encode final frame");
        truncated[20..24].copy_from_slice(&(1024_u32 * 1024).to_le_bytes());
        let later = encode_frame(3, RETRYABLE_BUDGET_KIND, first.request().as_bytes())
            .expect("encode later frame");
        append_fixture(&path.0, &truncated[..HEADER_LEN + 8]);
        append_fixture(&path.0, &later);
        let corrupt_length = fs::metadata(&path.0).expect("corrupt WAL metadata").len();

        assert!(matches!(
            DurableBrokerWal::open(&path.0, config()),
            Err(DurableWalError::TruncatedRecord)
        ));
        assert_eq!(
            fs::metadata(&path.0)
                .expect("still-corrupt WAL metadata")
                .len(),
            corrupt_length
        );
    }

    #[test]
    fn path_replacement_preserves_lock_exclusion_and_seals_writer() {
        let path = TestPath::new("path-replacement");
        let moved = path.0.with_extension("moved");
        let mut wal = DurableBrokerWal::create(&path.0, config()).expect("create WAL");
        fs::rename(&path.0, &moved).expect("move locked WAL inode");
        fs::copy(&moved, &path.0).expect("replace WAL pathname");

        assert!(matches!(
            DurableBrokerWal::open(&path.0, config()),
            Err(DurableWalError::Locked)
        ));
        assert!(matches!(
            wal.accept(envelope(0, 1), 10),
            Err(DurableWalError::PathIdentityChanged)
        ));
        assert!(wal.is_sealed());
        assert!(matches!(
            wal.accept(envelope(0, 1), 10),
            Err(DurableWalError::Sealed)
        ));

        drop(wal);
        fs::remove_file(moved).expect("remove moved WAL");
    }

    #[test]
    fn private_permissions_are_created_and_enforced_on_reopen() {
        let path = TestPath::new("permissions");
        let wal = DurableBrokerWal::create(&path.0, config()).expect("create WAL");
        let lock_path = path.0.parent().expect("WAL parent").join(durable_lock_name(
            path.0.file_name().expect("WAL file name"),
        ));
        assert_eq!(
            fs::metadata(&path.0)
                .expect("WAL metadata")
                .permissions()
                .mode()
                & 0o777,
            PRIVATE_FILE_MODE
        );
        assert_eq!(
            fs::metadata(&lock_path)
                .expect("lock metadata")
                .permissions()
                .mode()
                & 0o777,
            PRIVATE_FILE_MODE
        );
        drop(wal);

        fs::set_permissions(&lock_path, fs::Permissions::from_mode(0o640))
            .expect("make lock group-readable");
        assert!(matches!(
            DurableBrokerWal::open(&path.0, config()),
            Err(DurableWalError::UnsafePermissions { .. })
        ));
        fs::set_permissions(&lock_path, fs::Permissions::from_mode(PRIVATE_FILE_MODE))
            .expect("restore private lock mode");
        fs::set_permissions(&path.0, fs::Permissions::from_mode(0o640))
            .expect("make WAL group-readable");
        assert!(matches!(
            DurableBrokerWal::open(&path.0, config()),
            Err(DurableWalError::UnsafePermissions { .. })
        ));
        assert!(matches!(
            validate_owner_and_permissions(1_001, PRIVATE_FILE_MODE, 1_000),
            Err(DurableWalError::WrongOwner {
                expected: 1_000,
                actual: 1_001
            })
        ));
    }

    #[test]
    fn unsafe_parent_and_parent_symlink_are_rejected() {
        let target = TestPath::new("symlink-target");
        let link = target.0.with_extension("link");
        let target_directory = target.0.with_extension("directory");
        fs::create_dir(&target_directory).expect("create target directory");
        std::os::unix::fs::symlink(&target_directory, &link).expect("create parent symlink");
        let wal_path = link.join("broker.wal");

        assert!(matches!(
            DurableBrokerWal::create(&wal_path, config()),
            Err(DurableWalError::Symlink)
        ));

        fs::remove_file(link).expect("remove parent symlink");
        fs::set_permissions(&target_directory, fs::Permissions::from_mode(0o777))
            .expect("make target directory untrusted");
        assert!(matches!(
            DurableBrokerWal::create(target_directory.join("broker.wal"), config()),
            Err(DurableWalError::UnsafeParentDirectory)
        ));
        fs::set_permissions(&target_directory, fs::Permissions::from_mode(0o700))
            .expect("restore target directory permissions");
        fs::remove_dir(target_directory).expect("remove target directory");
    }

    #[test]
    fn excessive_final_payload_count_is_rejected_before_allocation() {
        let path = TestPath::new("final-count");
        let first = envelope(0, 1);
        {
            let mut wal = DurableBrokerWal::create(&path.0, config()).expect("create WAL");
            wal.accept(first, 10).expect("accept request");
        }
        let mut payload = Vec::new();
        payload.extend_from_slice(first.request().as_bytes());
        payload.push(0);
        payload.extend_from_slice(&[0; 7]);
        payload.extend_from_slice(&0_u64.to_le_bytes());
        payload.extend_from_slice(&u32::MAX.to_le_bytes());
        let frame = encode_frame(2, FINAL_KIND, &payload).expect("encode corrupt final frame");
        let mut file = OpenOptions::new()
            .append(true)
            .open(&path.0)
            .expect("open WAL for corruption fixture");
        file.write_all(&frame).expect("append corrupt final frame");
        file.sync_all().expect("sync corrupt final frame");
        drop(file);

        assert!(matches!(
            DurableBrokerView::open(&path.0),
            Err(DurableWalError::RecordTooLarge(length)) if length == u32::MAX as usize
        ));
    }

    #[test]
    fn active_terminal_headroom_cannot_be_consumed_by_retryable_markers() {
        let path = TestPath::new("headroom-markers");
        let active = envelope(0, 1);
        let retryable = envelope(1, 2);
        let mut wal = DurableBrokerWal::create(&path.0, config()).expect("create WAL");
        wal.accept(active, 10).expect("accept active request");
        wal.reserve(active.request())
            .expect("reserve active request");
        wal.accept(retryable, 10).expect("accept retryable request");
        let marker_length = u64::try_from(
            encode_frame(4, RETRYABLE_BUDGET_KIND, retryable.request().as_bytes())
                .expect("encode retryable marker")
                .len(),
        )
        .expect("marker length fits u64");
        let headroom = super::maximum_terminal_frame_bytes(10).expect("terminal headroom");
        wal.length = MAX_DURABLE_BROKER_WAL_BYTES - headroom - marker_length + 1;
        let physical_length = fs::metadata(&path.0).expect("WAL metadata").len();

        assert!(matches!(
            wal.mark_retryable_budget(retryable.request()),
            Err(DurableWalError::WalTooLarge { .. })
        ));
        assert!(wal.is_sealed());
        assert_eq!(
            fs::metadata(&path.0).expect("WAL metadata").len(),
            physical_length
        );
    }

    #[test]
    fn fourth_maximum_effect_is_refused_before_reserve_and_first_three_reopen() {
        let path = TestPath::new("four-maximum-effects");
        let config = DurableSessionConfig::new(
            config().session(),
            NonZeroUsize::new(4).expect("test replay capacity is non-zero"),
            SessionBudgetLimits::new(
                NonZeroU64::new(4).expect("test request budget is non-zero"),
                MAX_PUBLIC_WIRE_BODY_BYTES * 4,
                NonZeroUsize::new(1).expect("test concurrency budget is non-zero"),
            ),
        );
        let mut wal = DurableBrokerWal::create(&path.0, config).expect("create WAL");
        for sequence in 0_u8..3 {
            let request = envelope(u64::from(sequence), sequence + 1);
            wal.accept(request, MAX_PUBLIC_WIRE_BODY_BYTES)
                .expect("accept maximum request");
            wal.reserve(request.request())
                .expect("reserve maximum request");
            let response = maximum_public_response(request.request(), sequence);
            if sequence == 0 {
                let wire_payloads =
                    canonical_wire_payloads(&response).expect("encode maximum wire sequence");
                let payload = encode_final(
                    request.request(),
                    BudgetSettlement::Complete {
                        response_bytes: MAX_PUBLIC_WIRE_BODY_BYTES,
                    },
                    &wire_payloads,
                )
                .expect("encode maximum final payload");
                let wire_bytes = wire_payloads.iter().map(Vec::len).sum::<usize>();
                assert!(payload.len() <= super::MAX_RECORD_PAYLOAD_BYTES);
                assert!(
                    wire_bytes + payload.len() <= MAX_FINAL_APPEND_TRANSIENT_DATA_BYTES,
                    "maximum final append data must stay within two bounded record buffers"
                );
            }
            wal.finalize(
                request.request(),
                &response,
                BudgetSettlement::Complete {
                    response_bytes: MAX_PUBLIC_WIRE_BODY_BYTES,
                },
            )
            .expect("finalize maximum request");
            let DurableRequestPhase::Final(canonical) = wal
                .state
                .request(request.request())
                .expect("terminal durable request")
                .phase()
            else {
                panic!("maximum request must be terminal");
            };
            assert!(canonical.wire_payloads.get().is_none());
        }
        let fourth = envelope(3, 4);
        wal.accept(fourth, MAX_PUBLIC_WIRE_BODY_BYTES)
            .expect("accept fourth request before effect");
        assert!(matches!(
            wal.reserve(fourth.request()),
            Err(DurableWalError::WalTooLarge { .. })
        ));
        assert!(wal.is_sealed());
        drop(wal);

        let reopened = DurableBrokerWal::open(&path.0, config).expect("reopen valid prefix");
        let view = reopened.read_only_view().expect("reopened view");
        for value in 1_u8..=3 {
            let DurableRequestPhase::Final(canonical) = view
                .request(BrokerRequestId::new([value; 16]))
                .expect("terminal request")
                .phase()
            else {
                panic!("reopened maximum request must be terminal");
            };
            assert!(canonical.wire_payloads.get().is_none());
        }
        let recovered_fourth = view
            .request(fourth.request())
            .expect("fourth request marker");
        assert!(matches!(
            recovered_fourth.phase(),
            DurableRequestPhase::AcceptedPending
        ));
        assert_eq!(recovered_fourth.active_reservation(), None);
    }

    #[test]
    fn identity_cap_and_final_phase_are_sealed() {
        let path = TestPath::new("sealed-phases");
        let first = envelope(0, 1);
        let mut wal = DurableBrokerWal::create(&path.0, config()).expect("create WAL");
        wal.accept(first, 10).expect("accept request");
        assert!(matches!(
            wal.accept(envelope(0, 2), 10),
            Err(DurableWalError::OutOfOrderSequence { .. })
        ));
        assert!(matches!(
            wal.accept(first, 11),
            Err(DurableWalError::RequestIdentityMismatch { .. })
        ));
        wal.finalize(
            first.request(),
            &rejection(first.request()),
            BudgetSettlement::NotStarted,
        )
        .expect("finalize request");
        assert!(matches!(
            wal.finalize(
                first.request(),
                &rejection(first.request()),
                BudgetSettlement::NotStarted
            ),
            Err(DurableWalError::InvalidTransition { .. })
        ));
        assert!(matches!(
            wal.reserve(first.request()),
            Err(DurableWalError::InvalidTransition { .. })
        ));
    }
}
