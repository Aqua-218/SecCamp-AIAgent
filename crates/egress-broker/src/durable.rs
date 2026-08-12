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
    fmt,
    fs::{self, File, OpenOptions, TryLockError},
    io::{self, Read, Seek, SeekFrom, Write},
    num::{NonZeroU64, NonZeroUsize},
    path::{Path, PathBuf},
};

use egress_protocol::{
    budget::{SessionBudget, SessionBudgetError, SessionBudgetLimits},
    response::{
        CanonicalBrokerResponse, CanonicalResponseChunk, MAX_EXPANDED_CANONICAL_RESPONSE_BYTES,
        ResponseCborError, ResponseChunkError,
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DurableCanonicalResponse {
    response: CanonicalBrokerResponse,
    wire_payloads: Vec<Vec<u8>>,
}

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
    #[must_use]
    pub fn wire_payloads(&self) -> &[Vec<u8>] {
        &self.wire_payloads
    }

    fn from_response(
        request: BrokerRequestId,
        response: &CanonicalBrokerResponse,
    ) -> Result<Self, DurableWalError> {
        if response.request() != request {
            return Err(DurableWalError::ResponseRequestMismatch {
                expected: request,
                received: response.request(),
            });
        }
        let wire_payloads = canonical_wire_payloads(response)?;
        Ok(Self {
            response: response.clone(),
            wire_payloads,
        })
    }

    fn from_wire_payloads(
        request: BrokerRequestId,
        wire_payloads: Vec<Vec<u8>>,
    ) -> Result<Self, DurableWalError> {
        let response = decode_wire_payloads(&wire_payloads)?;
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
            wire_payloads,
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
        validate_existing_path(&path)?;
        let mut file = File::open(&path)?;
        acquire_shared_lock(&file)?;
        validate_open_file(&path, &file)?;
        let (state, _) = read_and_parse(&mut file)?;
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
    file: File,
    state: RecoveredState,
    length: u64,
    sealed: bool,
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
        validate_new_path(&path)?;
        let mut file = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&path)?;
        acquire_exclusive_lock(&file)?;
        validate_open_file(&path, &file)?;
        let payload = encode_init(config)?;
        let frame = encode_frame(0, INIT_KIND, &payload)?;
        if let Err(error) = file
            .write_all(&frame)
            .and_then(|()| file.sync_all())
            .and_then(|()| sync_parent_directory(&path))
        {
            return Err(DurableWalError::DurabilityUncertain(error));
        }
        Ok(Self {
            path,
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
        validate_existing_path(&path)?;
        let mut file = OpenOptions::new().read(true).write(true).open(&path)?;
        acquire_exclusive_lock(&file)?;
        validate_open_file(&path, &file)?;
        let (state, length) = read_and_parse(&mut file)?;
        if state.config != expected {
            return Err(DurableWalError::ConfigurationMismatch {
                expected,
                recovered: state.config,
            });
        }
        file.seek(SeekFrom::End(0))?;
        Ok(Self {
            path,
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
        self.append(ACCEPT_KIND, &payload)?;
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
        self.append(RESERVE_KIND, request.as_bytes())?;
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
        self.append(RETRYABLE_BUDGET_KIND, request.as_bytes())?;
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
        let canonical = DurableCanonicalResponse::from_response(request, response)?;
        {
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
        }
        self.state.budget.validate_settlement(request, settlement)?;
        let payload = encode_final(request, settlement, canonical.wire_payloads())?;
        self.append(FINAL_KIND, &payload)?;
        self.state.apply_final(request, settlement, canonical)
    }

    fn ensure_writable(&self) -> Result<(), DurableWalError> {
        if self.sealed {
            Err(DurableWalError::Sealed)
        } else {
            Ok(())
        }
    }

    fn append(&mut self, kind: u8, payload: &[u8]) -> Result<(), DurableWalError> {
        let sequence = self
            .state
            .next_wal_sequence
            .ok_or(DurableWalError::SequenceExhausted)?;
        let frame = encode_frame(sequence, kind, payload)?;
        let frame_length =
            u64::try_from(frame.len()).map_err(|_| DurableWalError::RecordTooLarge(frame.len()))?;
        let next_length =
            self.length
                .checked_add(frame_length)
                .ok_or(DurableWalError::WalTooLarge {
                    length: u64::MAX,
                    maximum: MAX_DURABLE_BROKER_WAL_BYTES,
                })?;
        if next_length > MAX_DURABLE_BROKER_WAL_BYTES {
            return Err(DurableWalError::WalTooLarge {
                length: next_length,
                maximum: MAX_DURABLE_BROKER_WAL_BYTES,
            });
        }
        if let Err(error) = self
            .file
            .write_all(&frame)
            .and_then(|()| self.file.sync_all())
        {
            self.sealed = true;
            return Err(DurableWalError::DurabilityUncertain(error));
        }
        self.length = next_length;
        self.state.next_wal_sequence = sequence.checked_add(1);
        Ok(())
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
    let mut wire_payloads = Vec::with_capacity(wire_payload_count);
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
    let response = DurableCanonicalResponse::from_wire_payloads(request, wire_payloads)?;
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
    if payload.len() > MAX_RECORD_PAYLOAD_BYTES {
        return Err(DurableWalError::RecordTooLarge(payload.len()));
    }
    let payload_length =
        u32::try_from(payload.len()).map_err(|_| DurableWalError::RecordTooLarge(payload.len()))?;
    let capacity = HEADER_LEN
        .checked_add(payload.len())
        .and_then(|length| length.checked_add(CHECKSUM_LEN))
        .ok_or(DurableWalError::RecordTooLarge(payload.len()))?;
    let mut frame = Vec::with_capacity(capacity);
    frame.extend_from_slice(MAGIC);
    frame.extend_from_slice(&VERSION.to_le_bytes());
    frame.push(kind);
    frame.push(0);
    frame.extend_from_slice(&sequence.to_le_bytes());
    frame.extend_from_slice(&payload_length.to_le_bytes());
    frame.extend_from_slice(payload);
    frame.extend_from_slice(&checksum(&frame).to_le_bytes());
    Ok(frame)
}

fn read_and_parse(file: &mut File) -> Result<(RecoveredState, u64), DurableWalError> {
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
    file.read_to_end(&mut bytes)?;
    let state = parse_wal(&bytes)?;
    Ok((state, length))
}

fn parse_wal(bytes: &[u8]) -> Result<RecoveredState, DurableWalError> {
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
        if bytes.len() - offset < HEADER_LEN + CHECKSUM_LEN {
            return Err(DurableWalError::TruncatedRecord);
        }
        let frame_start = offset;
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
        let frame_length = HEADER_LEN
            .checked_add(payload_length)
            .and_then(|length| length.checked_add(CHECKSUM_LEN))
            .ok_or(DurableWalError::RecordTooLarge(payload_length))?;
        if bytes.len() - frame_start < frame_length {
            return Err(DurableWalError::TruncatedRecord);
        }
        let payload_end = offset + payload_length;
        let payload = &bytes[offset..payload_end];
        offset = payload_end;
        let stored_checksum = read_u64(bytes, &mut offset)?;
        if stored_checksum != checksum(&bytes[frame_start..payload_end]) {
            return Err(DurableWalError::ChecksumMismatch);
        }
        match kind {
            INIT_KIND if expected_sequence == 0 => {
                state = Some(RecoveredState::new(decode_init(payload)?));
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
                recovered_state(&mut state)?.apply_reserve(request)?;
            }
            RETRYABLE_BUDGET_KIND => {
                let request = decode_request(payload)?;
                recovered_state(&mut state)?.apply_retryable(request)?;
            }
            FINAL_KIND => {
                let (request, settlement, response) = decode_final(payload)?;
                recovered_state(&mut state)?.apply_final(request, settlement, response)?;
            }
            _ => {
                return Err(DurableWalError::InvalidRecord(
                    "frame kind is unknown".to_owned(),
                ));
            }
        }
        expected_sequence = expected_sequence
            .checked_add(1)
            .ok_or(DurableWalError::SequenceExhausted)?;
    }
    let mut state = state
        .ok_or_else(|| DurableWalError::InvalidRecord("WAL has no session record".to_owned()))?;
    state.next_wal_sequence = Some(expected_sequence);
    Ok(state)
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
    let mut state = 0xcbf2_9ce4_8422_2325_u64;
    for byte in bytes {
        state ^= u64::from(*byte);
        state = state.wrapping_mul(0x0000_0100_0000_01b3);
    }
    state
}

fn validate_new_path(path: &Path) -> Result<(), DurableWalError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(DurableWalError::Symlink),
        Ok(_) => Err(DurableWalError::Io(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "durable broker WAL already exists",
        ))),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(DurableWalError::Io(error)),
    }
}

fn validate_existing_path(path: &Path) -> Result<(), DurableWalError> {
    let metadata = fs::symlink_metadata(path)?;
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
    Ok(())
}

fn validate_open_file(path: &Path, file: &File) -> Result<(), DurableWalError> {
    let path_metadata = fs::symlink_metadata(path)?;
    if path_metadata.file_type().is_symlink() {
        return Err(DurableWalError::Symlink);
    }
    let metadata = file.metadata()?;
    if !metadata.is_file() || !path_metadata.is_file() {
        return Err(DurableWalError::NotRegularFile);
    }
    if metadata.len() > MAX_DURABLE_BROKER_WAL_BYTES {
        return Err(DurableWalError::WalTooLarge {
            length: metadata.len(),
            maximum: MAX_DURABLE_BROKER_WAL_BYTES,
        });
    }
    Ok(())
}

fn acquire_exclusive_lock(file: &File) -> Result<(), DurableWalError> {
    match file.try_lock() {
        Ok(()) => Ok(()),
        Err(TryLockError::WouldBlock) => Err(DurableWalError::Locked),
        Err(TryLockError::Error(error)) => Err(DurableWalError::Io(error)),
    }
}

fn acquire_shared_lock(file: &File) -> Result<(), DurableWalError> {
    match file.try_lock_shared() {
        Ok(()) => Ok(()),
        Err(TryLockError::WouldBlock) => Err(DurableWalError::Locked),
        Err(TryLockError::Error(error)) => Err(DurableWalError::Io(error)),
    }
}

fn sync_parent_directory(path: &Path) -> io::Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty());
    File::open(parent.unwrap_or_else(|| Path::new(".")))?.sync_all()
}

#[cfg(test)]
mod tests {
    use std::{
        fs::{self, OpenOptions},
        io::{Seek, SeekFrom, Write},
        num::{NonZeroU64, NonZeroUsize},
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };

    use egress_protocol::{
        budget::SessionBudgetLimits,
        response::{BrokerWireOutcome, BrokerWireRejection, CanonicalBrokerResponse},
        session::{BrokerEnvelope, BrokerRequestId, BrokerSessionId, PayloadHash},
    };

    use super::{
        BudgetSettlement, DurableAcceptance, DurableBrokerView, DurableBrokerWal,
        DurableRequestPhase, DurableSessionConfig, DurableWalError,
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
        BrokerEnvelope::new(
            config().session(),
            sequence,
            BrokerRequestId::new([value; 16]),
            PayloadHash::of_canonical_payload(&[value]),
        )
    }

    fn rejection(request: BrokerRequestId) -> CanonicalBrokerResponse {
        CanonicalBrokerResponse::new(
            request,
            BrokerWireOutcome::Rejected(BrokerWireRejection::CommittedButUnrecorded),
        )
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
        assert!(matches!(
            DurableBrokerView::open(&corrupt_path.0),
            Err(DurableWalError::ChecksumMismatch)
        ));
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
