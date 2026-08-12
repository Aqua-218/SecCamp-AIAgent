//! Crash-recoverable write-ahead audit storage for authority attempts.
//!
//! The journal deliberately separates an attempt start from its terminal
//! outcome. The start is synced before an executor is called; the terminal
//! record is synced after the executor reports a committed, definitely failed,
//! denied, or evidence-backed ambiguous result. A crash between those writes
//! therefore reopens as `Started`, never as an inferred success.

use std::{
    collections::BTreeMap,
    error::Error,
    fmt,
    fs::{File, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::{Arc, Mutex, MutexGuard},
};

use crate::{
    audit::AttemptOutcome,
    capability::{AuthorityRequest, CapId, CapabilityRequest, CapabilityRequestSet, SubjectId},
    state::AuthorizationEpoch,
};

const MAGIC: &[u8; 8] = b"AUTHWAL1";
const VERSION: u16 = 1;
const START_KIND: u8 = 1;
const FINISH_KIND: u8 = 2;
const HEADER_LEN: usize = 8 + 2 + 1 + 1 + 8 + 8 + 4;
const CHECKSUM_LEN: usize = 8;
const MAX_RECORD_PAYLOAD: usize = 8 * 1024 * 1024;
const MAX_JOURNAL_BYTES: u64 = 128 * 1024 * 1024;
const ATTEMPT_PAYLOAD_VERSION: u8 = 1;
/// Maximum opaque evidence retained for one `CommitUnknown` terminal outcome.
pub const MAX_COMMIT_UNKNOWN_EVIDENCE_BYTES: usize = 64 * 1024;

/// A bounded receipt that identifies the external acceptance observed by the
/// executor.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CommitReceipt {
    attempt_id: crate::audit::AttemptId,
    token: Vec<u8>,
}

impl CommitReceipt {
    /// Creates a receipt for one attempt from an adapter-provided token.
    #[must_use]
    pub(crate) fn new(attempt_id: crate::audit::AttemptId, token: impl Into<Vec<u8>>) -> Self {
        Self {
            attempt_id,
            token: token.into(),
        }
    }

    /// Creates the receipt used by the kernel when an executor returns success
    /// without providing a provider-specific token.
    #[must_use]
    pub(crate) fn kernel_success(attempt_id: crate::audit::AttemptId) -> Self {
        Self::new(attempt_id, b"kernel-executor-returned-success".to_vec())
    }

    /// Returns the attempt identity covered by this receipt.
    #[must_use]
    pub const fn attempt_id(&self) -> crate::audit::AttemptId {
        self.attempt_id
    }

    /// Returns the opaque adapter or executor token.
    #[must_use]
    pub fn token(&self) -> &[u8] {
        &self.token
    }
}

/// Bounded opaque evidence that an executor's commit result is ambiguous.
///
/// Evidence is bound to one attempt when constructed by authority-core and cannot be used to
/// produce an effect snapshot. It is retained only for reconciliation and incident analysis.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CommitUnknownEvidence {
    attempt_id: crate::audit::AttemptId,
    token: Vec<u8>,
}

impl CommitUnknownEvidence {
    /// Binds non-empty bounded executor evidence to an existing attempt.
    ///
    /// # Errors
    ///
    /// Returns [`DurableAuditError::InvalidRecord`] for empty evidence and
    /// [`DurableAuditError::RecordTooLarge`] when the evidence exceeds
    /// [`MAX_COMMIT_UNKNOWN_EVIDENCE_BYTES`].
    pub(crate) fn new(
        attempt_id: crate::audit::AttemptId,
        token: impl Into<Vec<u8>>,
    ) -> Result<Self, DurableAuditError> {
        let token = token.into();
        validate_commit_unknown_token(&token)?;
        Ok(Self { attempt_id, token })
    }

    /// Returns the attempt identity covered by this evidence.
    #[must_use]
    pub const fn attempt_id(&self) -> crate::audit::AttemptId {
        self.attempt_id
    }

    /// Returns the opaque adapter or executor evidence.
    #[must_use]
    pub fn token(&self) -> &[u8] {
        &self.token
    }
}

/// A recovered durable attempt, including attempts whose completion was not
/// known when the process stopped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DurableAttempt {
    attempt_id: crate::audit::AttemptId,
    start_sequence: u64,
    payload: Vec<u8>,
    outcome: AttemptOutcome,
    finish_sequence: Option<u64>,
    receipt: Option<CommitReceipt>,
    commit_unknown_evidence: Option<CommitUnknownEvidence>,
}

impl DurableAttempt {
    /// Returns the session-local attempt identity.
    #[must_use]
    pub const fn attempt_id(&self) -> crate::audit::AttemptId {
        self.attempt_id
    }

    /// Returns the WAL sequence at which the attempt was started.
    #[must_use]
    pub const fn start_sequence(&self) -> u64 {
        self.start_sequence
    }

    /// Returns the canonical encoded attempt metadata.
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// Returns the recovered outcome. `Started` means completion is unknown.
    #[must_use]
    pub const fn outcome(&self) -> AttemptOutcome {
        self.outcome
    }

    /// Returns the terminal WAL sequence, if a terminal record was durable.
    #[must_use]
    pub const fn finish_sequence(&self) -> Option<u64> {
        self.finish_sequence
    }

    /// Returns the durable commit receipt, if the attempt committed.
    #[must_use]
    pub fn receipt(&self) -> Option<&CommitReceipt> {
        self.receipt.as_ref()
    }

    /// Returns the durable ambiguity evidence, if commit completion is unknown.
    #[must_use]
    pub fn commit_unknown_evidence(&self) -> Option<&CommitUnknownEvidence> {
        self.commit_unknown_evidence.as_ref()
    }
}

/// A failure that prevents a durable audit log from being trusted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DurableAuditError {
    /// The underlying file operation failed.
    Io {
        /// The operating-system error category.
        kind: io::ErrorKind,
        /// A context string retained without storing a non-cloneable IO error.
        message: String,
    },
    /// The journal mutex was poisoned by a writer panic.
    LockPoisoned,
    /// A previous write or sync failed, so this log stays unusable.
    JournalUnavailable,
    /// Appending this frame would push the journal past its size ceiling.
    JournalFull {
        /// Byte length the journal would reach.
        length: u64,
        /// Maximum byte length this crate will reopen.
        max_length: u64,
    },
    /// The file header does not identify this journal format.
    InvalidMagic,
    /// The file uses a format version this crate cannot validate.
    UnsupportedVersion(u16),
    /// The final frame is incomplete and cannot be interpreted safely.
    TruncatedRecord,
    /// A frame checksum does not match its bytes.
    ChecksumMismatch {
        /// The frame sequence whose checksum failed.
        sequence: u64,
    },
    /// A frame sequence is not the next expected sequence.
    SequenceMismatch {
        /// The sequence required by the preceding valid frame.
        expected: u64,
        /// The sequence found in the file.
        actual: u64,
    },
    /// An attempt or receipt was replayed after reaching a terminal state.
    ReplayDetected {
        /// The attempt identity that was reused or completed twice.
        attempt_id: crate::audit::AttemptId,
    },
    /// A record violates the journal state machine or payload grammar.
    InvalidRecord(String),
    /// A record exceeds the bounded journal frame size.
    RecordTooLarge(usize),
    /// The journal sequence cannot advance without wrapping.
    SequenceExhausted,
}

impl fmt::Display for DurableAuditError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { kind, message } => {
                write!(formatter, "durable audit IO error ({kind}): {message}")
            }
            Self::LockPoisoned => formatter.write_str("durable audit lock is poisoned"),
            Self::JournalFull { length, max_length } => write!(
                formatter,
                "durable audit journal would reach {length} bytes, above the {max_length} byte ceiling"
            ),
            Self::JournalUnavailable => formatter.write_str("durable audit journal is unavailable"),
            Self::InvalidMagic => {
                formatter.write_str("durable audit journal has an invalid magic header")
            }
            Self::UnsupportedVersion(version) => {
                write!(
                    formatter,
                    "unsupported durable audit journal version {version}"
                )
            }
            Self::TruncatedRecord => {
                formatter.write_str("durable audit journal contains a truncated record")
            }
            Self::ChecksumMismatch { sequence } => {
                write!(
                    formatter,
                    "durable audit checksum mismatch at sequence {sequence}"
                )
            }
            Self::SequenceMismatch { expected, actual } => write!(
                formatter,
                "durable audit sequence mismatch: expected {expected}, got {actual}"
            ),
            Self::ReplayDetected { attempt_id } => {
                write!(
                    formatter,
                    "durable audit replay detected for attempt {}",
                    attempt_id.as_u64()
                )
            }
            Self::InvalidRecord(message) => {
                write!(formatter, "invalid durable audit record: {message}")
            }
            Self::RecordTooLarge(length) => {
                write!(
                    formatter,
                    "durable audit record payload is too large: {length} bytes"
                )
            }
            Self::SequenceExhausted => formatter.write_str("durable audit sequence is exhausted"),
        }
    }
}

impl Error for DurableAuditError {}

impl From<io::Error> for DurableAuditError {
    fn from(error: io::Error) -> Self {
        Self::Io {
            kind: error.kind(),
            message: error.to_string(),
        }
    }
}

#[derive(Debug, Clone)]
struct DurableAttemptState {
    attempt_id: crate::audit::AttemptId,
    start_sequence: u64,
    payload: Vec<u8>,
    outcome: AttemptOutcome,
    finish_sequence: Option<u64>,
    receipt: Option<CommitReceipt>,
    commit_unknown_evidence: Option<CommitUnknownEvidence>,
}

impl DurableAttemptState {
    fn snapshot(&self) -> DurableAttempt {
        DurableAttempt {
            attempt_id: self.attempt_id,
            start_sequence: self.start_sequence,
            payload: self.payload.clone(),
            outcome: self.outcome,
            finish_sequence: self.finish_sequence,
            receipt: self.receipt.clone(),
            commit_unknown_evidence: self.commit_unknown_evidence.clone(),
        }
    }
}

#[derive(Debug)]
struct DurableState {
    file: File,
    next_sequence: Option<u64>,
    attempts: BTreeMap<crate::audit::AttemptId, DurableAttemptState>,
    unusable: bool,
    /// Bytes currently on disk. Tracked so an append can refuse to grow the
    /// journal past the ceiling that `open` enforces; without it a running
    /// process writes a file it can never reopen.
    length: u64,
}

/// A process-local, single-writer WAL for authorization audit records.
///
/// The mutex protects one open handle in one process. Cross-process writer
/// coordination is intentionally outside authority-core; callers must assign
/// one journal owner. Reopening validates the complete prefix and rejects all
/// malformed or ambiguous suffixes instead of silently truncating them.
#[derive(Debug)]
pub struct DurableAuditLog {
    state: Arc<Mutex<DurableState>>,
    path: PathBuf,
}

/// An immutable snapshot of a validated durable audit journal.
///
/// Unlike [`DurableAuditLog`], this view is freely cloneable because it owns no
/// journal writer and exposes no state transition operations. Use
/// [`Self::open`] to inspect recovery state without acquiring a WAL writer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DurableAuditView {
    path: PathBuf,
    next_attempt_sequence: Option<u64>,
    attempts: Vec<DurableAttempt>,
}

impl DurableAuditView {
    /// Opens, validates, and snapshots an existing journal without write
    /// access.
    ///
    /// # Errors
    ///
    /// Returns [`DurableAuditError`] when the file cannot be read or contains
    /// an invalid, truncated, replayed, or checksum-invalid frame.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, DurableAuditError> {
        let path = path.as_ref().to_owned();
        let mut file = File::open(&path).map_err(DurableAuditError::from)?;
        let file_length = file.metadata().map_err(DurableAuditError::from)?.len();
        if file_length > MAX_JOURNAL_BYTES {
            return Err(DurableAuditError::RecordTooLarge(
                usize::try_from(file_length).unwrap_or(usize::MAX),
            ));
        }

        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)
            .map_err(DurableAuditError::from)?;
        let (_, attempts) = parse_journal(&bytes)?;
        Ok(Self::from_attempts(path, &attempts))
    }

    /// Returns the path from which this snapshot was recovered.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Returns the next session-local attempt sequence in this snapshot.
    ///
    /// `None` means no further attempt identity can be allocated.
    #[must_use]
    pub const fn next_attempt_sequence(&self) -> Option<u64> {
        self.next_attempt_sequence
    }

    /// Returns the validated attempts in attempt identity order.
    #[must_use]
    pub fn attempts(&self) -> &[DurableAttempt] {
        &self.attempts
    }

    fn from_attempts(
        path: PathBuf,
        attempts: &BTreeMap<crate::audit::AttemptId, DurableAttemptState>,
    ) -> Self {
        Self {
            path,
            next_attempt_sequence: next_attempt_sequence(attempts),
            attempts: attempts
                .values()
                .map(DurableAttemptState::snapshot)
                .collect(),
        }
    }
}

impl DurableAuditLog {
    /// Creates a new empty journal at `path` using exclusive file creation.
    ///
    /// # Errors
    ///
    /// Returns an IO error when the path already exists or cannot be synced.
    pub fn create(path: impl AsRef<Path>) -> Result<Self, DurableAuditError> {
        let path = path.as_ref().to_owned();
        let file = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&path)
            .map_err(DurableAuditError::from)?;
        file.sync_all().map_err(DurableAuditError::from)?;
        Ok(Self {
            state: Arc::new(Mutex::new(DurableState {
                file,
                next_sequence: Some(0),
                attempts: BTreeMap::new(),
                unusable: false,
                length: 0,
            })),
            path,
        })
    }

    /// Reopens and validates an existing journal.
    ///
    /// A complete start frame without a terminal frame is valid and is
    /// returned as `Started`, representing the external-effect crash window.
    /// A partial frame, checksum failure, sequence gap, or replayed transition
    /// is rejected and never repaired automatically.
    ///
    /// # Errors
    ///
    /// Returns [`DurableAuditError`] when the file cannot be read or contains
    /// an invalid, truncated, replayed, or checksum-invalid frame.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, DurableAuditError> {
        let path = path.as_ref().to_owned();
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .map_err(DurableAuditError::from)?;
        let file_length = file.metadata().map_err(DurableAuditError::from)?.len();
        if file_length > MAX_JOURNAL_BYTES {
            return Err(DurableAuditError::RecordTooLarge(
                usize::try_from(file_length).unwrap_or(usize::MAX),
            ));
        }

        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)
            .map_err(DurableAuditError::from)?;
        let (next_sequence, attempts) = parse_journal(&bytes)?;
        file.seek(SeekFrom::End(0))
            .map_err(DurableAuditError::from)?;
        Ok(Self {
            state: Arc::new(Mutex::new(DurableState {
                file,
                next_sequence,
                attempts,
                unusable: false,
                length: file_length,
            })),
            path,
        })
    }

    /// Returns the path of the underlying journal file.
    #[must_use]
    pub fn path(&self) -> PathBuf {
        self.path.clone()
    }

    /// Returns an immutable snapshot that can be retained after this writer is
    /// moved into a [`crate::kernel::CapabilityKernel`].
    ///
    /// # Errors
    ///
    /// Returns [`DurableAuditError::LockPoisoned`] or
    /// [`DurableAuditError::JournalUnavailable`] when the backend is not
    /// trustworthy.
    pub fn read_only_view(&self) -> Result<DurableAuditView, DurableAuditError> {
        let state = self.lock_state()?;
        if state.unusable {
            return Err(DurableAuditError::JournalUnavailable);
        }
        Ok(DurableAuditView::from_attempts(
            self.path.clone(),
            &state.attempts,
        ))
    }

    /// Returns the next session-local attempt sequence for a reopened kernel.
    ///
    /// `None` means no further attempt identity can be allocated.
    ///
    /// # Errors
    ///
    /// Returns [`DurableAuditError::LockPoisoned`] or
    /// [`DurableAuditError::JournalUnavailable`] when the backend is not
    /// trustworthy.
    pub fn next_attempt_sequence(&self) -> Result<Option<u64>, DurableAuditError> {
        let state = self.lock_state()?;
        if state.unusable {
            return Err(DurableAuditError::JournalUnavailable);
        }
        Ok(next_attempt_sequence(&state.attempts))
    }

    /// Returns all recovered attempts in attempt identity order.
    ///
    /// # Errors
    ///
    /// Returns [`DurableAuditError::LockPoisoned`] or
    /// [`DurableAuditError::JournalUnavailable`] when the backend is not
    /// trustworthy.
    pub fn attempts(&self) -> Result<Vec<DurableAttempt>, DurableAuditError> {
        let state = self.lock_state()?;
        if state.unusable {
            return Err(DurableAuditError::JournalUnavailable);
        }
        Ok(state
            .attempts
            .values()
            .map(DurableAttemptState::snapshot)
            .collect())
    }

    /// Appends and syncs a `Started` record before executor invocation.
    ///
    /// # Errors
    ///
    /// Returns a durable journal error when the attempt is a replay, the
    /// payload is too large, or the frame cannot be synced.
    pub(crate) fn begin_attempt(
        &self,
        attempt_id: crate::audit::AttemptId,
        caller: &SubjectId,
        capability_id: &CapId,
        requests: &CapabilityRequestSet,
        authorization_epoch: AuthorizationEpoch,
    ) -> Result<(), DurableAuditError> {
        let payload = encode_attempt_payload(caller, capability_id, requests, authorization_epoch)?;
        let mut state = self.lock_state()?;
        if state.unusable {
            return Err(DurableAuditError::JournalUnavailable);
        }
        if state.attempts.contains_key(&attempt_id) {
            return Err(DurableAuditError::ReplayDetected { attempt_id });
        }
        let sequence = next_sequence(&state)?;
        append_frame(&mut state, sequence, START_KIND, attempt_id, &payload)?;
        state.attempts.insert(
            attempt_id,
            DurableAttemptState {
                attempt_id,
                start_sequence: sequence,
                payload,
                outcome: AttemptOutcome::Started,
                finish_sequence: None,
                receipt: None,
                commit_unknown_evidence: None,
            },
        );
        state.next_sequence = sequence.checked_add(1);
        Ok(())
    }

    /// Appends and syncs a terminal outcome after executor completion.
    ///
    /// `Committed` requires a receipt tied to the same attempt; `CommitUnknown` requires
    /// separately typed, bounded ambiguity evidence. Denied and pre-commit failures reject all
    /// terminal evidence. Invalid combinations are rejected before any frame is appended.
    ///
    /// # Errors
    ///
    /// Returns a durable journal error when the attempt is unknown or already
    /// terminal, the receipt does not match, or the terminal frame cannot be
    /// synced.
    pub(crate) fn finish_attempt(
        &self,
        attempt_id: crate::audit::AttemptId,
        outcome: AttemptOutcome,
        receipt: Option<&CommitReceipt>,
        commit_unknown_evidence: Option<&CommitUnknownEvidence>,
    ) -> Result<(), DurableAuditError> {
        let payload = encode_finish_payload(attempt_id, outcome, receipt, commit_unknown_evidence)?;
        let mut state = self.lock_state()?;
        if state.unusable {
            return Err(DurableAuditError::JournalUnavailable);
        }
        let Some(attempt) = state.attempts.get(&attempt_id) else {
            return Err(DurableAuditError::ReplayDetected { attempt_id });
        };
        if attempt.outcome != AttemptOutcome::Started {
            return Err(DurableAuditError::ReplayDetected { attempt_id });
        }
        let sequence = next_sequence(&state)?;
        append_frame(&mut state, sequence, FINISH_KIND, attempt_id, &payload)?;
        let attempt = state.attempts.get_mut(&attempt_id).ok_or_else(|| {
            DurableAuditError::InvalidRecord("attempt disappeared during finish".to_owned())
        })?;
        attempt.outcome = outcome;
        attempt.finish_sequence = Some(sequence);
        attempt.receipt = receipt.cloned();
        attempt.commit_unknown_evidence = commit_unknown_evidence.cloned();
        state.next_sequence = sequence.checked_add(1);
        Ok(())
    }

    fn lock_state(&self) -> Result<MutexGuard<'_, DurableState>, DurableAuditError> {
        self.state
            .lock()
            .map_err(|_| DurableAuditError::LockPoisoned)
    }
}

fn next_attempt_sequence(
    attempts: &BTreeMap<crate::audit::AttemptId, DurableAttemptState>,
) -> Option<u64> {
    match attempts.keys().next_back() {
        Some(attempt_id) => attempt_id.as_u64().checked_add(1),
        None => Some(0),
    }
}

fn next_sequence(state: &DurableState) -> Result<u64, DurableAuditError> {
    state
        .next_sequence
        .ok_or(DurableAuditError::SequenceExhausted)
}

fn append_frame(
    state: &mut DurableState,
    sequence: u64,
    kind: u8,
    attempt_id: crate::audit::AttemptId,
    payload: &[u8],
) -> Result<(), DurableAuditError> {
    if payload.len() > MAX_RECORD_PAYLOAD {
        return Err(DurableAuditError::RecordTooLarge(payload.len()));
    }
    let frame_length = u64::try_from(HEADER_LEN + payload.len() + CHECKSUM_LEN)
        .map_err(|_| DurableAuditError::RecordTooLarge(payload.len()))?;
    let new_length =
        state
            .length
            .checked_add(frame_length)
            .ok_or(DurableAuditError::JournalFull {
                length: u64::MAX,
                max_length: MAX_JOURNAL_BYTES,
            })?;
    if new_length > MAX_JOURNAL_BYTES {
        return Err(DurableAuditError::JournalFull {
            length: new_length,
            max_length: MAX_JOURNAL_BYTES,
        });
    }
    let payload_length = u32::try_from(payload.len())
        .map_err(|_| DurableAuditError::RecordTooLarge(payload.len()))?;
    let mut frame = Vec::with_capacity(
        HEADER_LEN
            .checked_add(payload.len())
            .and_then(|length| length.checked_add(CHECKSUM_LEN))
            .ok_or(DurableAuditError::RecordTooLarge(payload.len()))?,
    );
    frame.extend_from_slice(MAGIC);
    frame.extend_from_slice(&VERSION.to_le_bytes());
    frame.push(kind);
    frame.push(0);
    frame.extend_from_slice(&sequence.to_le_bytes());
    frame.extend_from_slice(&attempt_id.as_u64().to_le_bytes());
    frame.extend_from_slice(&payload_length.to_le_bytes());
    frame.extend_from_slice(payload);
    let checksum = checksum(&frame);
    frame.extend_from_slice(&checksum.to_le_bytes());

    if let Err(error) = state
        .file
        .write_all(&frame)
        .and_then(|()| state.file.sync_all())
    {
        state.unusable = true;
        return Err(DurableAuditError::from(error));
    }
    state.length = new_length;
    Ok(())
}

fn parse_journal(
    bytes: &[u8],
) -> Result<
    (
        Option<u64>,
        BTreeMap<crate::audit::AttemptId, DurableAttemptState>,
    ),
    DurableAuditError,
> {
    let mut offset = 0_usize;
    let mut expected_sequence = 0_u64;
    let mut attempts = BTreeMap::new();
    while offset < bytes.len() {
        let remaining = bytes.len() - offset;
        if remaining < HEADER_LEN + CHECKSUM_LEN {
            return Err(DurableAuditError::TruncatedRecord);
        }
        let frame_start = offset;
        if &bytes[offset..offset + MAGIC.len()] != MAGIC {
            return Err(DurableAuditError::InvalidMagic);
        }
        offset += MAGIC.len();
        let version = read_u16(bytes, &mut offset)?;
        if version != VERSION {
            return Err(DurableAuditError::UnsupportedVersion(version));
        }
        let kind = read_byte(bytes, &mut offset)?;
        let reserved = read_byte(bytes, &mut offset)?;
        if reserved != 0 {
            return Err(DurableAuditError::InvalidRecord(
                "reserved frame bits are non-zero".to_owned(),
            ));
        }
        let sequence = read_u64(bytes, &mut offset)?;
        if sequence != expected_sequence {
            return Err(DurableAuditError::SequenceMismatch {
                expected: expected_sequence,
                actual: sequence,
            });
        }
        let attempt_id = crate::audit::AttemptId::from_u64(read_u64(bytes, &mut offset)?);
        let payload_length = usize::try_from(read_u32(bytes, &mut offset)?)
            .map_err(|_| DurableAuditError::RecordTooLarge(usize::MAX))?;
        if payload_length > MAX_RECORD_PAYLOAD {
            return Err(DurableAuditError::RecordTooLarge(payload_length));
        }
        let frame_length = HEADER_LEN
            .checked_add(payload_length)
            .and_then(|length| length.checked_add(CHECKSUM_LEN))
            .ok_or(DurableAuditError::RecordTooLarge(payload_length))?;
        if bytes.len() - frame_start < frame_length {
            return Err(DurableAuditError::TruncatedRecord);
        }
        let payload_start = offset;
        let payload_end = payload_start + payload_length;
        let payload = &bytes[payload_start..payload_end];
        offset = payload_end;
        let stored_checksum = read_u64(bytes, &mut offset)?;
        if checksum(&bytes[frame_start..payload_end]) != stored_checksum {
            return Err(DurableAuditError::ChecksumMismatch { sequence });
        }

        match kind {
            START_KIND => {
                if attempts.contains_key(&attempt_id) {
                    return Err(DurableAuditError::ReplayDetected { attempt_id });
                }
                attempts.insert(
                    attempt_id,
                    DurableAttemptState {
                        attempt_id,
                        start_sequence: sequence,
                        payload: payload.to_vec(),
                        outcome: AttemptOutcome::Started,
                        finish_sequence: None,
                        receipt: None,
                        commit_unknown_evidence: None,
                    },
                );
            }
            FINISH_KIND => {
                let (outcome, receipt, commit_unknown_evidence) =
                    decode_finish_payload(payload, attempt_id)?;
                let Some(attempt) = attempts.get_mut(&attempt_id) else {
                    return Err(DurableAuditError::ReplayDetected { attempt_id });
                };
                if attempt.outcome != AttemptOutcome::Started {
                    return Err(DurableAuditError::ReplayDetected { attempt_id });
                }
                attempt.outcome = outcome;
                attempt.finish_sequence = Some(sequence);
                attempt.receipt = receipt;
                attempt.commit_unknown_evidence = commit_unknown_evidence;
            }
            _ => {
                return Err(DurableAuditError::InvalidRecord(
                    "unknown journal record kind".to_owned(),
                ));
            }
        }
        expected_sequence = expected_sequence
            .checked_add(1)
            .ok_or(DurableAuditError::SequenceExhausted)?;
    }
    Ok((Some(expected_sequence), attempts))
}

fn validate_finish(
    outcome: AttemptOutcome,
    receipt: Option<&CommitReceipt>,
    commit_unknown_evidence: Option<&CommitUnknownEvidence>,
    attempt_id: crate::audit::AttemptId,
) -> Result<(), DurableAuditError> {
    if let Some(receipt) = receipt
        && receipt.attempt_id() != attempt_id
    {
        return Err(DurableAuditError::InvalidRecord(
            "commit receipt belongs to another attempt".to_owned(),
        ));
    }
    if let Some(evidence) = commit_unknown_evidence {
        if evidence.attempt_id() != attempt_id {
            return Err(DurableAuditError::InvalidRecord(
                "commit-unknown evidence belongs to another attempt".to_owned(),
            ));
        }
        validate_commit_unknown_token(evidence.token())?;
    }
    if outcome == AttemptOutcome::Started {
        return Err(DurableAuditError::InvalidRecord(
            "Started is not a terminal outcome".to_owned(),
        ));
    }
    match outcome {
        AttemptOutcome::Committed if receipt.is_some() && commit_unknown_evidence.is_none() => {}
        AttemptOutcome::Committed => {
            return Err(DurableAuditError::InvalidRecord(
                "Committed requires only a commit receipt".to_owned(),
            ));
        }
        AttemptOutcome::CommitUnknown if receipt.is_none() && commit_unknown_evidence.is_some() => {
        }
        AttemptOutcome::CommitUnknown => {
            return Err(DurableAuditError::InvalidRecord(
                "CommitUnknown requires only bounded ambiguity evidence".to_owned(),
            ));
        }
        AttemptOutcome::Denied | AttemptOutcome::FailedBeforeCommit
            if receipt.is_none() && commit_unknown_evidence.is_none() => {}
        AttemptOutcome::Denied | AttemptOutcome::FailedBeforeCommit => {
            return Err(DurableAuditError::InvalidRecord(
                "Denied and FailedBeforeCommit cannot carry terminal evidence".to_owned(),
            ));
        }
        AttemptOutcome::Started => unreachable!("Started was rejected above"),
    }
    Ok(())
}

fn validate_commit_unknown_token(token: &[u8]) -> Result<(), DurableAuditError> {
    if token.is_empty() {
        return Err(DurableAuditError::InvalidRecord(
            "CommitUnknown evidence cannot be empty".to_owned(),
        ));
    }
    if token.len() > MAX_COMMIT_UNKNOWN_EVIDENCE_BYTES {
        return Err(DurableAuditError::RecordTooLarge(token.len()));
    }
    Ok(())
}

fn encode_finish_payload(
    attempt_id: crate::audit::AttemptId,
    outcome: AttemptOutcome,
    receipt: Option<&CommitReceipt>,
    commit_unknown_evidence: Option<&CommitUnknownEvidence>,
) -> Result<Vec<u8>, DurableAuditError> {
    validate_finish(outcome, receipt, commit_unknown_evidence, attempt_id)?;
    let mut payload = vec![outcome_code(outcome)];
    if let Some(token) = receipt
        .map(CommitReceipt::token)
        .or_else(|| commit_unknown_evidence.map(CommitUnknownEvidence::token))
    {
        let token_length = u32::try_from(token.len())
            .map_err(|_| DurableAuditError::RecordTooLarge(token.len()))?;
        payload.extend_from_slice(&token_length.to_le_bytes());
        payload.extend_from_slice(token);
    }
    Ok(payload)
}

fn decode_finish_payload(
    payload: &[u8],
    attempt_id: crate::audit::AttemptId,
) -> Result<
    (
        AttemptOutcome,
        Option<CommitReceipt>,
        Option<CommitUnknownEvidence>,
    ),
    DurableAuditError,
> {
    let Some((&code, rest)) = payload.split_first() else {
        return Err(DurableAuditError::InvalidRecord(
            "empty finish payload".to_owned(),
        ));
    };
    let outcome = decode_outcome(code)?;
    if matches!(
        outcome,
        AttemptOutcome::Committed | AttemptOutcome::CommitUnknown
    ) {
        if rest.len() < 4 {
            return Err(DurableAuditError::TruncatedRecord);
        }
        let token_length =
            usize::try_from(u32::from_le_bytes([rest[0], rest[1], rest[2], rest[3]]))
                .map_err(|_| DurableAuditError::RecordTooLarge(usize::MAX))?;
        let expected_length = 4_usize
            .checked_add(token_length)
            .ok_or(DurableAuditError::RecordTooLarge(token_length))?;
        if rest.len() != expected_length {
            return Err(DurableAuditError::InvalidRecord(
                "terminal evidence length does not match finish payload".to_owned(),
            ));
        }
        let token = rest[4..].to_vec();
        return match outcome {
            AttemptOutcome::Committed => {
                Ok((outcome, Some(CommitReceipt::new(attempt_id, token)), None))
            }
            AttemptOutcome::CommitUnknown => Ok((
                outcome,
                None,
                Some(CommitUnknownEvidence::new(attempt_id, token)?),
            )),
            _ => unreachable!("terminal evidence outcomes were matched above"),
        };
    }
    if !rest.is_empty() {
        return Err(DurableAuditError::InvalidRecord(
            "non-committed finish payload has trailing bytes".to_owned(),
        ));
    }
    Ok((outcome, None, None))
}

fn outcome_code(outcome: AttemptOutcome) -> u8 {
    match outcome {
        AttemptOutcome::Started => 0,
        AttemptOutcome::Denied => 1,
        AttemptOutcome::FailedBeforeCommit => 2,
        AttemptOutcome::Committed => 3,
        AttemptOutcome::CommitUnknown => 4,
    }
}

fn decode_outcome(code: u8) -> Result<AttemptOutcome, DurableAuditError> {
    match code {
        1 => Ok(AttemptOutcome::Denied),
        2 => Ok(AttemptOutcome::FailedBeforeCommit),
        3 => Ok(AttemptOutcome::Committed),
        4 => Ok(AttemptOutcome::CommitUnknown),
        _ => Err(DurableAuditError::InvalidRecord(
            "unknown terminal outcome".to_owned(),
        )),
    }
}

fn checksum(bytes: &[u8]) -> u64 {
    // FNV-1a detects torn or accidental mutation. It is not a tamper-evident
    // MAC; authenticity belongs to a higher-level signed audit transport.
    bytes.iter().fold(0xcbf2_9ce4_8422_2325, |hash, byte| {
        (hash ^ u64::from(*byte)).wrapping_mul(0x0100_0000_01b3)
    })
}

fn read_byte(bytes: &[u8], offset: &mut usize) -> Result<u8, DurableAuditError> {
    let byte = *bytes
        .get(*offset)
        .ok_or(DurableAuditError::TruncatedRecord)?;
    *offset += 1;
    Ok(byte)
}

fn read_u16(bytes: &[u8], offset: &mut usize) -> Result<u16, DurableAuditError> {
    let end = offset
        .checked_add(2)
        .ok_or(DurableAuditError::TruncatedRecord)?;
    let value = bytes
        .get(*offset..end)
        .ok_or(DurableAuditError::TruncatedRecord)?;
    *offset = end;
    Ok(u16::from_le_bytes([value[0], value[1]]))
}

fn read_u32(bytes: &[u8], offset: &mut usize) -> Result<u32, DurableAuditError> {
    let end = offset
        .checked_add(4)
        .ok_or(DurableAuditError::TruncatedRecord)?;
    let value = bytes
        .get(*offset..end)
        .ok_or(DurableAuditError::TruncatedRecord)?;
    *offset = end;
    Ok(u32::from_le_bytes([value[0], value[1], value[2], value[3]]))
}

fn read_u64(bytes: &[u8], offset: &mut usize) -> Result<u64, DurableAuditError> {
    let end = offset
        .checked_add(8)
        .ok_or(DurableAuditError::TruncatedRecord)?;
    let value = bytes
        .get(*offset..end)
        .ok_or(DurableAuditError::TruncatedRecord)?;
    *offset = end;
    Ok(u64::from_le_bytes([
        value[0], value[1], value[2], value[3], value[4], value[5], value[6], value[7],
    ]))
}

fn encode_attempt_payload(
    caller: &SubjectId,
    capability_id: &CapId,
    requests: &CapabilityRequestSet,
    authorization_epoch: AuthorizationEpoch,
) -> Result<Vec<u8>, DurableAuditError> {
    let mut writer = PayloadWriter::new();
    writer.byte(ATTEMPT_PAYLOAD_VERSION);
    writer.string(caller.as_str())?;
    writer.string(capability_id.as_str())?;
    writer.u64(authorization_epoch.as_u64());
    let requests = requests.iter().collect::<Vec<_>>();
    writer.u32(
        u32::try_from(requests.len())
            .map_err(|_| DurableAuditError::RecordTooLarge(requests.len()))?,
    );
    for request in requests {
        writer.u64(request.time().ticks());
        encode_authority_request(&mut writer, request)?;
    }
    let payload = writer.finish();
    if payload.len() > MAX_RECORD_PAYLOAD {
        return Err(DurableAuditError::RecordTooLarge(payload.len()));
    }
    Ok(payload)
}

struct PayloadWriter {
    bytes: Vec<u8>,
}

impl PayloadWriter {
    fn new() -> Self {
        Self { bytes: Vec::new() }
    }

    fn byte(&mut self, value: u8) {
        self.bytes.push(value);
    }

    fn u32(&mut self, value: u32) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn u64(&mut self, value: u64) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn string(&mut self, value: &str) -> Result<(), DurableAuditError> {
        let bytes = value.as_bytes();
        let length = u32::try_from(bytes.len())
            .map_err(|_| DurableAuditError::RecordTooLarge(bytes.len()))?;
        self.u32(length);
        self.bytes.extend_from_slice(bytes);
        if self.bytes.len() > MAX_RECORD_PAYLOAD {
            return Err(DurableAuditError::RecordTooLarge(self.bytes.len()));
        }
        Ok(())
    }

    fn finish(self) -> Vec<u8> {
        self.bytes
    }
}

fn encode_authority_request(
    writer: &mut PayloadWriter,
    request: &CapabilityRequest,
) -> Result<(), DurableAuditError> {
    match request.authority() {
        AuthorityRequest::File(request) => {
            writer.byte(1);
            writer.string(request.repository().as_str())?;
            writer.byte(request.effect() as u8);
            writer.u32(
                u32::try_from(request.path().as_segments().len()).map_err(|_| {
                    DurableAuditError::RecordTooLarge(request.path().as_segments().len())
                })?,
            );
            for segment in request.path().as_segments() {
                writer.string(segment)?;
            }
        }
        AuthorityRequest::HttpFetch(request) => {
            writer.byte(2);
            writer.byte(request.method() as u8);
            writer.string(request.host().as_str())?;
            writer.u32(
                u32::try_from(request.path().as_segments().len()).map_err(|_| {
                    DurableAuditError::RecordTooLarge(request.path().as_segments().len())
                })?,
            );
            for segment in request.path().as_segments() {
                writer.string(segment)?;
            }
            writer.u64(request.max_response_bytes());
        }
        AuthorityRequest::GitHub(request) => {
            writer.byte(3);
            writer.string(request.installation().as_str())?;
            writer.string(request.repository().as_str())?;
            writer.byte(request.operation() as u8);
            writer.u32(
                u32::try_from(request.base().as_segments().len()).map_err(|_| {
                    DurableAuditError::RecordTooLarge(request.base().as_segments().len())
                })?,
            );
            for segment in request.base().as_segments() {
                writer.string(segment)?;
            }
            writer.u32(
                u32::try_from(request.head().as_segments().len()).map_err(|_| {
                    DurableAuditError::RecordTooLarge(request.head().as_segments().len())
                })?,
            );
            for segment in request.head().as_segments() {
                writer.string(segment)?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{
        fs::{self, OpenOptions},
        sync::Arc,
        sync::atomic::{AtomicU64, Ordering},
        thread,
    };

    use super::{
        CommitReceipt, CommitUnknownEvidence, DurableAuditError, DurableAuditLog, DurableAuditView,
        MAX_COMMIT_UNKNOWN_EVIDENCE_BYTES,
    };
    use crate::{
        audit::{AttemptId, AttemptOutcome},
        capability::{AuthorityRequest, CapId, CapabilityRequest, CapabilityRequestSet, SubjectId},
        file::{FileEffect, FileRequest},
        path::CanonicalPath,
        repository::RepoId,
        state::AuthorizationEpoch,
        time::MonotonicTime,
    };

    static NEXT_PATH: AtomicU64 = AtomicU64::new(0);

    struct TestJournal {
        path: std::path::PathBuf,
    }

    impl TestJournal {
        fn new() -> Self {
            let serial = NEXT_PATH.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "authority-core-durable-audit-{}-{serial}.wal",
                std::process::id()
            ));
            let _ = fs::remove_file(&path);
            Self { path }
        }
    }

    impl Drop for TestJournal {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.path);
        }
    }

    fn request_set() -> CapabilityRequestSet {
        CapabilityRequestSet::one(CapabilityRequest::new(
            MonotonicTime::from_ticks(7),
            AuthorityRequest::File(FileRequest::new(
                RepoId::new("workspace"),
                FileEffect::ReadData,
                CanonicalPath::new(["src", "main.rs"]).expect("test path is valid"),
            )),
        ))
    }

    fn begin(log: &DurableAuditLog, attempt: u64) {
        log.begin_attempt(
            AttemptId::from_u64(attempt),
            &SubjectId::new("subject"),
            &CapId::new("capability"),
            &request_set(),
            AuthorizationEpoch::default(),
        )
        .expect("test attempt must be durable");
    }

    #[test]
    fn durable_log_reopens_committed_unknown_and_incomplete_attempts() {
        let journal = TestJournal::new();
        let log = DurableAuditLog::create(&journal.path).expect("journal creation must sync");
        begin(&log, 0);
        log.finish_attempt(
            AttemptId::from_u64(0),
            AttemptOutcome::Committed,
            Some(&CommitReceipt::new(
                AttemptId::from_u64(0),
                b"provider-7".to_vec(),
            )),
            None,
        )
        .expect("commit receipt must be durable");
        begin(&log, 1);
        let unknown = CommitUnknownEvidence::new(
            AttemptId::from_u64(1),
            b"provider-timeout-after-request-write",
        )
        .expect("bounded ambiguity evidence must validate");
        log.finish_attempt(
            AttemptId::from_u64(1),
            AttemptOutcome::CommitUnknown,
            None,
            Some(&unknown),
        )
        .expect("commit-unknown evidence must be durable");
        begin(&log, 2);
        drop(log);

        let reopened = DurableAuditLog::open(&journal.path).expect("complete frames must reopen");
        let attempts = reopened
            .attempts()
            .expect("recovered attempts must be readable");
        assert_eq!(attempts.len(), 3);
        assert_eq!(attempts[0].outcome(), AttemptOutcome::Committed);
        assert_eq!(
            attempts[0].receipt().expect("receipt must survive").token(),
            b"provider-7"
        );
        assert!(attempts[0].commit_unknown_evidence().is_none());
        assert_eq!(attempts[1].outcome(), AttemptOutcome::CommitUnknown);
        assert!(attempts[1].receipt().is_none());
        assert_eq!(
            attempts[1]
                .commit_unknown_evidence()
                .expect("ambiguity evidence must survive recovery")
                .token(),
            b"provider-timeout-after-request-write"
        );
        assert_eq!(attempts[2].outcome(), AttemptOutcome::Started);
        assert!(attempts[2].receipt().is_none());
        assert!(attempts[2].commit_unknown_evidence().is_none());
        assert_eq!(reopened.next_attempt_sequence(), Ok(Some(3)));
    }

    #[test]
    fn read_only_view_recovers_without_a_writer() {
        let journal = TestJournal::new();
        let log = DurableAuditLog::create(&journal.path).expect("journal creation must sync");
        begin(&log, 0);
        let live_view = log
            .read_only_view()
            .expect("a healthy writer must produce a read-only snapshot");
        drop(log);

        let recovered = DurableAuditView::open(&journal.path)
            .expect("a complete start frame must be recoverable read-only");
        assert_eq!(live_view, recovered);
        assert_eq!(recovered.path(), journal.path);
        assert_eq!(recovered.next_attempt_sequence(), Some(1));
        assert_eq!(recovered.attempts()[0].outcome(), AttemptOutcome::Started);
    }

    #[test]
    fn truncated_tail_is_rejected_without_silent_repair() {
        let journal = TestJournal::new();
        let log = DurableAuditLog::create(&journal.path).expect("journal creation must sync");
        begin(&log, 0);
        drop(log);
        let length = fs::metadata(&journal.path)
            .expect("journal must exist")
            .len();
        let file = OpenOptions::new()
            .write(true)
            .open(&journal.path)
            .expect("journal must be writable for corruption fixture");
        file.set_len(length - 1)
            .expect("fixture truncation must succeed");

        assert!(matches!(
            DurableAuditLog::open(&journal.path),
            Err(DurableAuditError::TruncatedRecord)
        ));
    }

    #[test]
    fn sequence_replay_and_duplicate_finish_are_rejected() {
        let journal = TestJournal::new();
        let log = DurableAuditLog::create(&journal.path).expect("journal creation must sync");
        begin(&log, 0);
        log.finish_attempt(AttemptId::from_u64(0), AttemptOutcome::Denied, None, None)
            .expect("denial must be durable");
        assert!(matches!(
            log.finish_attempt(AttemptId::from_u64(0), AttemptOutcome::Denied, None, None,),
            Err(DurableAuditError::ReplayDetected { .. })
        ));
        drop(log);

        let mut bytes = fs::read(&journal.path).expect("journal bytes must be readable");
        let sequence_offset = 8 + 2 + 1 + 1;
        bytes[sequence_offset..sequence_offset + 8].copy_from_slice(&99_u64.to_le_bytes());
        fs::write(&journal.path, bytes).expect("fixture rewrite must succeed");
        assert!(matches!(
            DurableAuditLog::open(&journal.path),
            Err(DurableAuditError::ChecksumMismatch { .. }
                | DurableAuditError::SequenceMismatch { .. })
        ));
    }

    #[test]
    fn poisoned_durable_lock_fails_closed() {
        let journal = TestJournal::new();
        let log = DurableAuditLog::create(&journal.path).expect("journal creation must sync");
        let poisoned = Arc::clone(&log.state);
        thread::scope(|scope| {
            scope
                .spawn(|| {
                    let _guard = poisoned
                        .lock()
                        .expect("test lock must initially be healthy");
                    panic!("poison durable audit lock");
                })
                .join()
                .expect_err("the fixture thread must panic");
        });
        assert_eq!(
            log.next_attempt_sequence(),
            Err(DurableAuditError::LockPoisoned)
        );
    }

    #[test]
    fn committed_outcome_requires_a_matching_receipt() {
        let journal = TestJournal::new();
        let log = DurableAuditLog::create(&journal.path).expect("journal creation must sync");
        begin(&log, 0);
        assert!(matches!(
            log.finish_attempt(
                AttemptId::from_u64(0),
                AttemptOutcome::Committed,
                None,
                None,
            ),
            Err(DurableAuditError::InvalidRecord(_))
        ));
        assert_eq!(
            log.attempts()
                .expect("the rejected finish must not poison the journal")[0]
                .outcome(),
            AttemptOutcome::Started
        );
    }

    #[test]
    fn commit_unknown_evidence_is_non_empty_and_bounded() {
        let attempt_id = AttemptId::from_u64(0);
        assert!(matches!(
            CommitUnknownEvidence::new(attempt_id, Vec::new()),
            Err(DurableAuditError::InvalidRecord(message))
                if message == "CommitUnknown evidence cannot be empty"
        ));
        let maximum = vec![0x5a; MAX_COMMIT_UNKNOWN_EVIDENCE_BYTES];
        assert_eq!(
            CommitUnknownEvidence::new(attempt_id, maximum.clone())
                .expect("maximum-sized ambiguity evidence must validate")
                .token(),
            maximum
        );
        assert_eq!(
            CommitUnknownEvidence::new(
                attempt_id,
                vec![0x5a; MAX_COMMIT_UNKNOWN_EVIDENCE_BYTES + 1],
            ),
            Err(DurableAuditError::RecordTooLarge(
                MAX_COMMIT_UNKNOWN_EVIDENCE_BYTES + 1
            ))
        );
    }

    #[test]
    fn terminal_outcomes_require_exactly_their_own_evidence_type() {
        let journal = TestJournal::new();
        let log = DurableAuditLog::create(&journal.path).expect("journal creation must sync");
        let attempt_id = AttemptId::from_u64(0);
        begin(&log, attempt_id.as_u64());
        let receipt = CommitReceipt::new(attempt_id, b"provider-accepted");
        let unknown = CommitUnknownEvidence::new(attempt_id, b"provider-timeout")
            .expect("bounded ambiguity evidence must validate");

        for result in [
            log.finish_attempt(attempt_id, AttemptOutcome::CommitUnknown, None, None),
            log.finish_attempt(
                attempt_id,
                AttemptOutcome::CommitUnknown,
                Some(&receipt),
                None,
            ),
            log.finish_attempt(attempt_id, AttemptOutcome::Committed, None, Some(&unknown)),
            log.finish_attempt(attempt_id, AttemptOutcome::Denied, None, Some(&unknown)),
            log.finish_attempt(
                attempt_id,
                AttemptOutcome::FailedBeforeCommit,
                Some(&receipt),
                None,
            ),
        ] {
            assert!(matches!(result, Err(DurableAuditError::InvalidRecord(_))));
            assert_eq!(
                log.attempts()
                    .expect("rejected finish must leave the journal readable")[0]
                    .outcome(),
                AttemptOutcome::Started
            );
        }

        log.finish_attempt(
            attempt_id,
            AttemptOutcome::CommitUnknown,
            None,
            Some(&unknown),
        )
        .expect("exact ambiguity evidence must terminate the attempt");
    }

    #[test]
    fn mismatched_commit_unknown_evidence_is_rejected_without_mutation() {
        let journal = TestJournal::new();
        let log = DurableAuditLog::create(&journal.path).expect("journal creation must sync");
        begin(&log, 0);
        let mismatched = CommitUnknownEvidence::new(AttemptId::from_u64(1), b"provider-timeout")
            .expect("bounded ambiguity evidence must validate");

        assert!(matches!(
            log.finish_attempt(
                AttemptId::from_u64(0),
                AttemptOutcome::CommitUnknown,
                None,
                Some(&mismatched),
            ),
            Err(DurableAuditError::InvalidRecord(message))
                if message == "commit-unknown evidence belongs to another attempt"
        ));
        assert_eq!(
            log.attempts()
                .expect("rejected evidence must leave the journal readable")[0]
                .outcome(),
            AttemptOutcome::Started
        );
    }

    #[test]
    fn recovery_rejects_empty_and_oversized_commit_unknown_evidence() {
        fn journal_with_raw_unknown(token: &[u8]) -> TestJournal {
            let journal = TestJournal::new();
            let log = DurableAuditLog::create(&journal.path).expect("journal creation must sync");
            let attempt_id = AttemptId::from_u64(0);
            begin(&log, attempt_id.as_u64());
            let mut payload = vec![super::outcome_code(AttemptOutcome::CommitUnknown)];
            payload.extend_from_slice(
                &u32::try_from(token.len())
                    .expect("test evidence length must fit the wire field")
                    .to_le_bytes(),
            );
            payload.extend_from_slice(token);
            {
                let mut state = log.state.lock().expect("journal lock must remain healthy");
                super::append_frame(&mut state, 1, super::FINISH_KIND, attempt_id, &payload)
                    .expect("malformed fixture frame must have valid framing");
            }
            drop(log);
            journal
        }

        let empty = journal_with_raw_unknown(&[]);
        assert!(matches!(
            DurableAuditView::open(&empty.path),
            Err(DurableAuditError::InvalidRecord(message))
                if message == "CommitUnknown evidence cannot be empty"
        ));

        let oversized =
            journal_with_raw_unknown(&vec![0x5a; MAX_COMMIT_UNKNOWN_EVIDENCE_BYTES + 1]);
        assert_eq!(
            DurableAuditView::open(&oversized.path),
            Err(DurableAuditError::RecordTooLarge(
                MAX_COMMIT_UNKNOWN_EVIDENCE_BYTES + 1
            ))
        );
    }

    #[test]
    fn mismatched_reconciliation_receipt_is_rejected_without_mutation() {
        let journal = TestJournal::new();
        let log = DurableAuditLog::create(&journal.path).expect("journal creation must sync");
        begin(&log, 0);
        let mismatched = CommitReceipt::new(AttemptId::from_u64(1), b"provider-attempt-1");

        assert!(matches!(
            log.finish_attempt(
                AttemptId::from_u64(0),
                AttemptOutcome::Committed,
                Some(&mismatched),
                None,
            ),
            Err(DurableAuditError::InvalidRecord(message))
                if message == "commit receipt belongs to another attempt"
        ));
        assert_eq!(
            log.attempts()
                .expect("rejected evidence must leave the journal readable")[0]
                .outcome(),
            AttemptOutcome::Started
        );
    }

    #[test]
    fn reconciliation_cannot_create_an_arbitrary_terminal_attempt() {
        let journal = TestJournal::new();
        let log = DurableAuditLog::create(&journal.path).expect("journal creation must sync");
        begin(&log, 0);
        let arbitrary = CommitReceipt::new(AttemptId::from_u64(7), b"invented-evidence");

        assert_eq!(
            log.finish_attempt(
                AttemptId::from_u64(7),
                AttemptOutcome::Committed,
                Some(&arbitrary),
                None,
            ),
            Err(DurableAuditError::ReplayDetected {
                attempt_id: AttemptId::from_u64(7),
            })
        );
        assert_eq!(
            log.attempts()
                .expect("rejected evidence must leave the journal readable")[0]
                .outcome(),
            AttemptOutcome::Started
        );
    }
}
