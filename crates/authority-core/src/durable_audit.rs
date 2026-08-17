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
    ffi::{OsStr, OsString},
    fmt,
    fs::{self, File, OpenOptions, TryLockError},
    io::{self, Read, Write},
    path::{Path, PathBuf},
    sync::{Arc, Mutex, MutexGuard},
};

#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

use crate::{
    audit::AttemptOutcome,
    capability::{
        AuthorityRequest, CapId, CapabilityRequest, CapabilityRequestSet, MAX_REQUESTS_PER_EFFECT,
        SubjectId,
    },
    file::{FileEffect, FileRequest},
    github::{BranchName, GitHubOperation, GitHubRequest, InstallationId},
    http::{CanonicalHost, CanonicalUrlPath, HttpFetchMethod, HttpFetchRequest},
    path::CanonicalPath,
    repository::RepoId,
    state::AuthorizationEpoch,
    time::MonotonicTime,
};

const MAGIC: &[u8; 8] = b"AUTHWAL1";
const VERSION: u16 = 1;
const START_KIND: u8 = 1;
const FINISH_KIND: u8 = 2;
/// A later verdict attached to an attempt whose commit was recorded as unknown.
///
/// Reconciliation never rewrites the terminal record. The ambiguity actually happened, and an
/// audit trail that edits it away cannot be used to answer "what did this host believe, and
/// when". The verdict is a new append-only frame that refers back to the attempt.
const RECONCILE_KIND: u8 = 3;
const RECONCILE_PAYLOAD_VERSION: u8 = 1;
const RECONCILED_COMMITTED: u8 = 1;
const RECONCILED_NOT_COMMITTED: u8 = 2;
const HEADER_LEN: usize = 8 + 2 + 1 + 1 + 8 + 8 + 4;
const CHECKSUM_LEN: usize = 8;
const MAX_RECORD_PAYLOAD: usize = 8 * 1024 * 1024;
/// Hard upper bound for one durable audit WAL in production.
///
/// A smaller cap can be supplied to the explicit test/integration constructors, but no caller
/// can raise the limit above this bound. The journal never evicts or compacts committed frames.
pub const MAX_JOURNAL_BYTES: u64 = 128 * 1024 * 1024;
/// The default cap used by [`DurableAuditLog::create`] and [`DurableAuditLog::open`].
pub const DEFAULT_MAX_JOURNAL_BYTES: u64 = MAX_JOURNAL_BYTES;
/// Version 2 prefixes the attempt metadata with the capability-state instance that authorized it.
///
/// A journal outlives the process that created it, so one file can hold attempts from several
/// capability-state instances. `CapId` and `SubjectId` are only unique inside one instance, so
/// without the instance an offline auditor cannot tell whether two records naming `cap-3` describe
/// the same capability. Version 1 records are still readable and belong to instance 0.
const ATTEMPT_PAYLOAD_VERSION: u8 = 2;
#[cfg(target_os = "linux")]
const O_NOFOLLOW: i32 = 0o400_000;
#[cfg(unix)]
const PRIVATE_FILE_MODE: u32 = 0o600;
#[cfg(unix)]
const WRITE_BY_GROUP_OR_OTHER: u32 = 0o022;
const PERMISSION_MODE_BITS: u32 = 0o7777;
const STICKY_DIRECTORY: u32 = 0o1000;
/// Maximum opaque evidence retained for one `CommitUnknown` terminal outcome.
pub const MAX_COMMIT_UNKNOWN_EVIDENCE_BYTES: usize = 64 * 1024;
/// Maximum opaque provider acceptance token retained in one durable commit receipt.
pub const MAX_COMMIT_RECEIPT_BYTES: usize = 64 * 1024;

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

/// What an external provider reported about an attempt whose commit was unknown.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReconciledCommit {
    /// The provider confirmed the effect landed, with the receipt it reported.
    Committed(CommitReceipt),
    /// The provider confirmed the effect never landed.
    NotCommitted,
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
    reconciliation: Option<ReconciledCommit>,
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

    /// Returns the later provider verdict, if this attempt's ambiguity was resolved.
    ///
    /// `None` on a `CommitUnknown` attempt means the ambiguity is still open, not that the effect
    /// did not happen.
    #[must_use]
    pub const fn reconciliation(&self) -> Option<&ReconciledCommit> {
        self.reconciliation.as_ref()
    }

    /// Decodes the canonical attempt metadata this record was started with.
    ///
    /// Without this an audit reader sees opaque bytes and has to reimplement the writer's format
    /// to learn who was authorized for what. Reading through the same module that writes is what
    /// keeps the two from drifting.
    ///
    /// # Errors
    ///
    /// Returns [`DurableAuditError::InvalidRecord`] when the payload is truncated, uses an
    /// unknown version or authority tag, or contains a value the typed request rejects.
    pub fn metadata(&self) -> Result<DurableAttemptMetadata, DurableAuditError> {
        decode_attempt_payload(&self.payload)
    }
}

/// Canonical metadata decoded from one attempt START record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DurableAttemptMetadata {
    state_instance: u64,
    caller: SubjectId,
    capability_id: CapId,
    authorization_epoch: AuthorizationEpoch,
    requests: CapabilityRequestSet,
}

impl DurableAttemptMetadata {
    /// Returns the capability-state instance that authorized this attempt.
    ///
    /// `CapId` and `SubjectId` are unique only inside one [`crate::state::CapabilityState`], so
    /// two records naming the same capability describe the same capability only when this value
    /// matches. Records written before the instance was recorded decode as instance 0.
    #[must_use]
    pub const fn state_instance(&self) -> u64 {
        self.state_instance
    }

    /// Returns the subject the attempt was authorized for.
    #[must_use]
    pub const fn caller(&self) -> &SubjectId {
        &self.caller
    }

    /// Returns the capability the attempt was authorized against.
    #[must_use]
    pub const fn capability_id(&self) -> &CapId {
        &self.capability_id
    }

    /// Returns the authorization epoch current when the attempt started.
    #[must_use]
    pub const fn authorization_epoch(&self) -> AuthorizationEpoch {
        self.authorization_epoch
    }

    /// Returns the complete request set authorized as one atomic operation.
    #[must_use]
    pub const fn requests(&self) -> &CapabilityRequestSet {
        &self.requests
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
    /// Another process or handle currently owns the journal writer lock.
    Locked,
    /// The journal, lock, or parent path contains a symbolic link.
    Symlink,
    /// The journal or lock path does not name a regular file.
    NotRegularFile,
    /// A pathname no longer resolves to the opened directory or file identity.
    PathIdentityChanged,
    /// The journal or lock file is not owned by the effective user.
    WrongOwner {
        /// Effective user required to own the file.
        expected: u32,
        /// Owner observed on the file.
        actual: u32,
    },
    /// The journal or lock file does not have exact mode `0600`.
    UnsafePermissions {
        /// Observed Unix permission and special mode bits.
        mode: u32,
    },
    /// The containing directory is not a stable trusted namespace.
    UnsafeParentDirectory,
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
    /// Appending or reopening a journal would exceed its configured byte capacity.
    CapacityExceeded {
        /// Bytes currently present in the journal.
        current: u64,
        /// Bytes the serialized frame or existing file would occupy.
        projected: u64,
        /// Configured hard byte capacity.
        capacity: u64,
    },
    /// A caller supplied a test/integration capacity above the production hard bound.
    InvalidCapacity {
        /// Requested capacity.
        requested: u64,
        /// Maximum accepted capacity.
        maximum: u64,
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
            Self::Locked => formatter.write_str("durable audit journal already has a writer"),
            Self::Symlink => formatter.write_str("durable audit path contains a symbolic link"),
            Self::NotRegularFile => formatter.write_str("durable audit path is not a regular file"),
            Self::PathIdentityChanged => formatter.write_str("durable audit path identity changed"),
            Self::WrongOwner { expected, actual } => write!(
                formatter,
                "durable audit file owner {actual} does not match effective user {expected}"
            ),
            Self::UnsafePermissions { mode } => write!(
                formatter,
                "durable audit file permissions {mode:o} are not exact mode 600"
            ),
            Self::UnsafeParentDirectory => {
                formatter.write_str("durable audit parent directory is not a trusted namespace")
            }
            Self::LockPoisoned => formatter.write_str("durable audit lock is poisoned"),
            Self::JournalFull { length, max_length } => write!(
                formatter,
                "durable audit journal would reach {length} bytes, above the {max_length} byte ceiling"
            ),
            Self::CapacityExceeded {
                current,
                projected,
                capacity,
            } => write!(
                formatter,
                "durable audit journal capacity exceeded: {current} -> {projected} bytes (capacity {capacity})"
            ),
            Self::InvalidCapacity { requested, maximum } => write!(
                formatter,
                "durable audit capacity {requested} exceeds the production maximum {maximum}"
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
    reconciliation: Option<ReconciledCommit>,
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
            reconciliation: self.reconciliation.clone(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileIdentity {
    device: u64,
    inode: u64,
}

#[derive(Debug)]
struct DurableDirectory {
    file: File,
    path: PathBuf,
    journal_name: OsString,
    lock_name: OsString,
    effective_uid: u32,
}

impl DurableDirectory {
    fn open(journal_path: &Path) -> Result<Self, DurableAuditError> {
        let journal_name = journal_path
            .file_name()
            .filter(|name| !name.is_empty())
            .ok_or(DurableAuditError::UnsafeParentDirectory)?
            .to_os_string();
        let path = journal_path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf();
        let effective_uid = effective_uid()?;
        let expected = validate_parent_path(&path, effective_uid)?;
        let file = File::open(&path).map_err(DurableAuditError::from)?;
        validate_directory_metadata(
            &file.metadata().map_err(DurableAuditError::from)?,
            effective_uid,
        )?;
        if expected != file_identity(&file.metadata().map_err(DurableAuditError::from)?) {
            return Err(DurableAuditError::PathIdentityChanged);
        }
        validate_parent_path_identity(&path, &file, effective_uid)?;
        let lock_name = durable_lock_name(&journal_name);
        Ok(Self {
            file,
            path,
            journal_name,
            lock_name,
            effective_uid,
        })
    }

    fn journal_path(&self) -> PathBuf {
        self.child_path(&self.journal_name)
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

    fn validate(&self) -> Result<(), DurableAuditError> {
        validate_parent_path_identity(&self.path, &self.file, self.effective_uid)
    }

    fn sync(&self) -> Result<(), DurableAuditError> {
        self.file.sync_all().map_err(DurableAuditError::from)
    }
}

#[derive(Debug)]
struct DurableState {
    directory: DurableDirectory,
    lock_file: File,
    file: File,
    next_sequence: Option<u64>,
    attempts: BTreeMap<crate::audit::AttemptId, DurableAttemptState>,
    unusable: bool,
    /// Bytes currently on disk. Tracked so an append can refuse to grow the
    /// journal past the ceiling that `open` enforces; without it a running
    /// process writes a file it can never reopen.
    length: u64,
    /// Configured byte capacity for this writer.
    capacity: u64,
}

/// An exclusively owned WAL for authorization audit records.
///
/// The writer holds process- and cross-process locks for its lifetime. Every
/// append revalidates the held parent directory plus the lock and journal file
/// identities, and permanently seals the writer after any mismatch or
/// uncertain write. Reopening validates the complete prefix and rejects all
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
        Self::open_with_max_bytes(path, DEFAULT_MAX_JOURNAL_BYTES)
    }

    /// Opens and validates an existing journal with an explicit byte capacity.
    ///
    /// This constructor is intended for bounded integration tests and controlled deployments.
    /// The capacity may be lower than the production default, but never higher than
    /// [`MAX_JOURNAL_BYTES`].
    ///
    /// # Errors
    ///
    /// Returns [`DurableAuditError::CapacityExceeded`] when the existing file is above the
    /// requested capacity, or another [`DurableAuditError`] when the file is malformed.
    pub fn open_with_max_bytes(
        path: impl AsRef<Path>,
        max_bytes: u64,
    ) -> Result<Self, DurableAuditError> {
        validate_capacity(max_bytes)?;
        let path = path.as_ref().to_owned();
        let directory = DurableDirectory::open(&path)?;
        validate_existing_path(&directory, max_bytes)?;
        let mut file = open_existing_file(&directory.journal_path(), false)?;
        validate_open_journal(&directory, &file, max_bytes)?;
        let bytes = read_bounded_journal(&mut file, max_bytes)?;
        validate_open_journal_length(&directory, &file, bytes.len(), max_bytes)?;
        let (_, attempts) = parse_journal(&bytes, max_bytes)?;
        Ok(Self::from_attempts(path, &attempts))
    }

    /// Alias for [`Self::open_with_max_bytes`] using capacity terminology.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::open_with_max_bytes`].
    pub fn open_with_capacity(
        path: impl AsRef<Path>,
        capacity: u64,
    ) -> Result<Self, DurableAuditError> {
        Self::open_with_max_bytes(path, capacity)
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
        Self::create_with_max_bytes(path, DEFAULT_MAX_JOURNAL_BYTES)
    }

    /// Creates a new empty journal with an explicit byte capacity.
    ///
    /// The capacity is useful for bounded integration tests and controlled deployments. It may
    /// be lower than the production default, but never higher than [`MAX_JOURNAL_BYTES`].
    ///
    /// # Errors
    ///
    /// Returns [`DurableAuditError::InvalidCapacity`] when the requested capacity exceeds the
    /// production hard bound, or an IO error when the path already exists or cannot be synced.
    pub fn create_with_max_bytes(
        path: impl AsRef<Path>,
        max_bytes: u64,
    ) -> Result<Self, DurableAuditError> {
        validate_capacity(max_bytes)?;
        let path = path.as_ref().to_owned();
        let directory = DurableDirectory::open(&path)?;
        let lock_file = open_writer_lock(&directory)?;
        validate_new_path(&directory)?;
        let file = create_private_file(&directory.journal_path())?;
        acquire_exclusive_lock(&file)?;
        validate_open_journal(&directory, &file, max_bytes)?;
        file.sync_all().map_err(DurableAuditError::from)?;
        directory.sync()?;
        validate_open_journal_length(&directory, &file, 0, max_bytes)?;
        validate_open_lock(&directory, &lock_file)?;
        Ok(Self {
            state: Arc::new(Mutex::new(DurableState {
                directory,
                lock_file,
                file,
                next_sequence: Some(0),
                attempts: BTreeMap::new(),
                unusable: false,
                length: 0,
                capacity: max_bytes,
            })),
            path,
        })
    }

    /// Alias for [`Self::create_with_max_bytes`] using capacity terminology.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::create_with_max_bytes`].
    pub fn create_with_capacity(
        path: impl AsRef<Path>,
        capacity: u64,
    ) -> Result<Self, DurableAuditError> {
        Self::create_with_max_bytes(path, capacity)
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
        Self::open_with_max_bytes(path, DEFAULT_MAX_JOURNAL_BYTES)
    }

    /// Reopens and validates an existing journal with an explicit byte capacity.
    ///
    /// This is the bounded integration-test/deployment counterpart of [`Self::open`]. Existing
    /// bytes are never truncated or compacted; a file above the requested capacity is rejected.
    ///
    /// # Errors
    ///
    /// Returns [`DurableAuditError::CapacityExceeded`] when existing bytes exceed the capacity,
    /// or another [`DurableAuditError`] when the file cannot be trusted.
    pub fn open_with_max_bytes(
        path: impl AsRef<Path>,
        max_bytes: u64,
    ) -> Result<Self, DurableAuditError> {
        validate_capacity(max_bytes)?;
        let path = path.as_ref().to_owned();
        let directory = DurableDirectory::open(&path)?;
        let lock_file = open_writer_lock(&directory)?;
        validate_existing_path(&directory, max_bytes)?;
        let mut file = open_existing_file(&directory.journal_path(), true)?;
        acquire_exclusive_lock(&file)?;
        validate_open_journal(&directory, &file, max_bytes)?;
        let bytes = read_bounded_journal(&mut file, max_bytes)?;
        validate_open_journal_length(&directory, &file, bytes.len(), max_bytes)?;
        let (next_sequence, attempts) = parse_journal(&bytes, max_bytes)?;
        let file_length = u64::try_from(bytes.len())
            .map_err(|_| DurableAuditError::RecordTooLarge(bytes.len()))?;
        validate_open_lock(&directory, &lock_file)?;
        Ok(Self {
            state: Arc::new(Mutex::new(DurableState {
                directory,
                lock_file,
                file,
                next_sequence,
                attempts,
                unusable: false,
                length: file_length,
                capacity: max_bytes,
            })),
            path,
        })
    }

    /// Alias for [`Self::open_with_max_bytes`] using capacity terminology.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::open_with_max_bytes`].
    pub fn open_with_capacity(
        path: impl AsRef<Path>,
        capacity: u64,
    ) -> Result<Self, DurableAuditError> {
        Self::open_with_max_bytes(path, capacity)
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
        state_instance: u64,
        attempt_id: crate::audit::AttemptId,
        caller: &SubjectId,
        capability_id: &CapId,
        requests: &CapabilityRequestSet,
        authorization_epoch: AuthorizationEpoch,
    ) -> Result<(), DurableAuditError> {
        let payload = encode_attempt_payload(
            state_instance,
            caller,
            capability_id,
            requests,
            authorization_epoch,
        )?;
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
                reconciliation: None,
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

    /// Appends the provider verdict that resolves one previously unknown commit.
    ///
    /// The terminal `CommitUnknown` record stays exactly as written. This adds what was learned
    /// afterwards, so the journal shows both that the host could not tell at the time and what
    /// the provider said later.
    ///
    /// # Errors
    ///
    /// Returns a durable journal error when the attempt is unknown, is not `CommitUnknown`, has
    /// already been reconciled, carries a receipt for another attempt, or cannot be synced.
    pub fn reconcile_attempt(
        &self,
        attempt_id: crate::audit::AttemptId,
        verdict: &ReconciledCommit,
    ) -> Result<(), DurableAuditError> {
        if let ReconciledCommit::Committed(receipt) = verdict
            && receipt.attempt_id() != attempt_id
        {
            return Err(DurableAuditError::InvalidRecord(
                "reconciled receipt belongs to another attempt".to_owned(),
            ));
        }
        let payload = encode_reconcile_payload(verdict)?;
        let mut state = self.lock_state()?;
        if state.unusable {
            return Err(DurableAuditError::JournalUnavailable);
        }
        let Some(attempt) = state.attempts.get(&attempt_id) else {
            return Err(DurableAuditError::ReplayDetected { attempt_id });
        };
        if attempt.outcome != AttemptOutcome::CommitUnknown {
            return Err(DurableAuditError::InvalidRecord(
                "only an unknown commit can be reconciled".to_owned(),
            ));
        }
        if attempt.reconciliation.is_some() {
            return Err(DurableAuditError::ReplayDetected { attempt_id });
        }
        let sequence = next_sequence(&state)?;
        append_frame(&mut state, sequence, RECONCILE_KIND, attempt_id, &payload)?;
        let attempt = state.attempts.get_mut(&attempt_id).ok_or_else(|| {
            DurableAuditError::InvalidRecord("attempt disappeared during reconciliation".to_owned())
        })?;
        attempt.reconciliation = Some(verdict.clone());
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

fn validate_capacity(capacity: u64) -> Result<(), DurableAuditError> {
    if capacity > MAX_JOURNAL_BYTES {
        return Err(DurableAuditError::InvalidCapacity {
            requested: capacity,
            maximum: MAX_JOURNAL_BYTES,
        });
    }
    Ok(())
}

const fn capacity_exceeded(current: u64, capacity: u64) -> DurableAuditError {
    DurableAuditError::CapacityExceeded {
        current,
        projected: current,
        capacity,
    }
}

fn append_frame(
    state: &mut DurableState,
    sequence: u64,
    kind: u8,
    attempt_id: crate::audit::AttemptId,
    payload: &[u8],
) -> Result<(), DurableAuditError> {
    if let Err(error) = validate_append_target(state, state.length) {
        state.unusable = true;
        return Err(error);
    }
    if payload.len() > MAX_RECORD_PAYLOAD {
        return Err(DurableAuditError::RecordTooLarge(payload.len()));
    }
    let payload_length = u32::try_from(payload.len())
        .map_err(|_| DurableAuditError::RecordTooLarge(payload.len()))?;
    let frame_capacity = HEADER_LEN
        .checked_add(payload.len())
        .and_then(|length| length.checked_add(CHECKSUM_LEN))
        .ok_or(DurableAuditError::RecordTooLarge(payload.len()))?;
    let mut frame = Vec::with_capacity(frame_capacity);
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

    let frame_length =
        u64::try_from(frame.len()).map_err(|_| DurableAuditError::RecordTooLarge(frame.len()))?;
    let new_length =
        state
            .length
            .checked_add(frame_length)
            .ok_or(DurableAuditError::CapacityExceeded {
                current: state.length,
                projected: u64::MAX,
                capacity: state.capacity,
            })?;
    if new_length > state.capacity {
        return Err(DurableAuditError::CapacityExceeded {
            current: state.length,
            projected: new_length,
            capacity: state.capacity,
        });
    }

    if let Err(error) = state
        .file
        .write_all(&frame)
        .and_then(|()| state.file.sync_all())
    {
        state.unusable = true;
        return Err(DurableAuditError::from(error));
    }
    if let Err(error) = validate_append_target(state, new_length) {
        state.unusable = true;
        return Err(error);
    }
    state.length = new_length;
    Ok(())
}

fn validate_append_target(
    state: &DurableState,
    expected_length: u64,
) -> Result<(), DurableAuditError> {
    state.directory.validate()?;
    validate_open_lock(&state.directory, &state.lock_file)?;
    let actual_length = validate_open_journal(&state.directory, &state.file, state.capacity)?;
    if actual_length != expected_length {
        return Err(DurableAuditError::InvalidRecord(format!(
            "journal length changed outside the exclusive writer: expected {expected_length}, got {actual_length}"
        )));
    }
    Ok(())
}

fn validate_new_path(directory: &DurableDirectory) -> Result<(), DurableAuditError> {
    directory.validate()?;
    match fs::symlink_metadata(directory.journal_path()) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(DurableAuditError::Symlink),
        Ok(_) => Err(DurableAuditError::Io {
            kind: io::ErrorKind::AlreadyExists,
            message: "durable audit journal already exists".to_owned(),
        }),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(DurableAuditError::from(error)),
    }
}

fn validate_existing_path(
    directory: &DurableDirectory,
    maximum_length: u64,
) -> Result<(), DurableAuditError> {
    validate_existing_named_path(directory, &directory.journal_name, Some(maximum_length))
}

fn validate_existing_named_path(
    directory: &DurableDirectory,
    name: &OsStr,
    maximum_length: Option<u64>,
) -> Result<(), DurableAuditError> {
    directory.validate()?;
    let metadata =
        fs::symlink_metadata(directory.child_path(name)).map_err(DurableAuditError::from)?;
    if metadata.file_type().is_symlink() {
        return Err(DurableAuditError::Symlink);
    }
    if !metadata.is_file() {
        return Err(DurableAuditError::NotRegularFile);
    }
    validate_file_metadata(&metadata, directory.effective_uid)?;
    if let Some(maximum_length) = maximum_length
        && metadata.len() > maximum_length
    {
        return Err(capacity_exceeded(metadata.len(), maximum_length));
    }
    Ok(())
}

fn validate_open_journal(
    directory: &DurableDirectory,
    file: &File,
    maximum_length: u64,
) -> Result<u64, DurableAuditError> {
    validate_open_named_file(
        directory,
        &directory.journal_name,
        file,
        Some(maximum_length),
    )
}

fn validate_open_lock(directory: &DurableDirectory, file: &File) -> Result<u64, DurableAuditError> {
    validate_open_named_file(directory, &directory.lock_name, file, Some(0))
}

fn validate_open_named_file(
    directory: &DurableDirectory,
    name: &OsStr,
    file: &File,
    maximum_length: Option<u64>,
) -> Result<u64, DurableAuditError> {
    directory.validate()?;
    let path_metadata = fs::symlink_metadata(directory.child_path(name)).map_err(|error| {
        if error.kind() == io::ErrorKind::NotFound {
            DurableAuditError::PathIdentityChanged
        } else {
            DurableAuditError::from(error)
        }
    })?;
    if path_metadata.file_type().is_symlink() {
        return Err(DurableAuditError::Symlink);
    }
    let metadata = file.metadata().map_err(DurableAuditError::from)?;
    if !metadata.is_file() || !path_metadata.is_file() {
        return Err(DurableAuditError::NotRegularFile);
    }
    if file_identity(&metadata) != file_identity(&path_metadata) {
        return Err(DurableAuditError::PathIdentityChanged);
    }
    validate_file_metadata(&metadata, directory.effective_uid)?;
    if let Some(maximum_length) = maximum_length
        && metadata.len() > maximum_length
    {
        return Err(capacity_exceeded(metadata.len(), maximum_length));
    }
    Ok(metadata.len())
}

fn validate_open_journal_length(
    directory: &DurableDirectory,
    file: &File,
    expected_length: usize,
    maximum_length: u64,
) -> Result<(), DurableAuditError> {
    let expected_length = u64::try_from(expected_length)
        .map_err(|_| DurableAuditError::RecordTooLarge(expected_length))?;
    let actual_length = validate_open_journal(directory, file, maximum_length)?;
    if actual_length != expected_length {
        return Err(DurableAuditError::InvalidRecord(format!(
            "journal length changed while it was read: expected {expected_length}, got {actual_length}"
        )));
    }
    Ok(())
}

fn open_writer_lock(directory: &DurableDirectory) -> Result<File, DurableAuditError> {
    directory.validate()?;
    let path = directory.lock_path();
    let (file, created) = match create_private_file(&path) {
        Ok(file) => (file, true),
        Err(DurableAuditError::Io {
            kind: io::ErrorKind::AlreadyExists,
            ..
        }) => {
            validate_existing_named_path(directory, &directory.lock_name, Some(0))?;
            (open_existing_file(&path, true)?, false)
        }
        Err(error) => return Err(error),
    };
    acquire_exclusive_lock(&file)?;
    validate_open_lock(directory, &file)?;
    if created {
        file.sync_all().map_err(DurableAuditError::from)?;
        directory.sync()?;
    }
    Ok(file)
}

fn create_private_file(path: &Path) -> Result<File, DurableAuditError> {
    let mut options = OpenOptions::new();
    options.create_new(true).read(true).append(true);
    configure_secure_open(&mut options);
    let file = options.open(path).map_err(DurableAuditError::from)?;
    set_private_permissions(&file)?;
    Ok(file)
}

fn open_existing_file(path: &Path, write: bool) -> Result<File, DurableAuditError> {
    let mut options = OpenOptions::new();
    options.read(true).append(write);
    configure_secure_open(&mut options);
    options.open(path).map_err(DurableAuditError::from)
}

fn configure_secure_open(options: &mut OpenOptions) {
    #[cfg(unix)]
    options.mode(PRIVATE_FILE_MODE);
    #[cfg(target_os = "linux")]
    options.custom_flags(O_NOFOLLOW);
}

fn set_private_permissions(file: &File) -> Result<(), DurableAuditError> {
    #[cfg(unix)]
    file.set_permissions(fs::Permissions::from_mode(PRIVATE_FILE_MODE))
        .map_err(DurableAuditError::from)?;
    Ok(())
}

fn validate_parent_path(
    path: &Path,
    effective_uid: u32,
) -> Result<FileIdentity, DurableAuditError> {
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
                return Err(DurableAuditError::UnsafeParentDirectory);
            }
        }
        let metadata = fs::symlink_metadata(&current).map_err(DurableAuditError::from)?;
        if metadata.file_type().is_symlink() {
            return Err(DurableAuditError::Symlink);
        }
        validate_directory_metadata(&metadata, effective_uid)?;
        final_identity = Some(file_identity(&metadata));
    }
    if final_identity.is_none() {
        let metadata = fs::symlink_metadata(&current).map_err(DurableAuditError::from)?;
        if metadata.file_type().is_symlink() {
            return Err(DurableAuditError::Symlink);
        }
        validate_directory_metadata(&metadata, effective_uid)?;
        final_identity = Some(file_identity(&metadata));
    }
    final_identity.ok_or(DurableAuditError::UnsafeParentDirectory)
}

fn validate_parent_path_identity(
    path: &Path,
    directory: &File,
    effective_uid: u32,
) -> Result<(), DurableAuditError> {
    let path_identity = validate_parent_path(path, effective_uid)?;
    let metadata = directory.metadata().map_err(DurableAuditError::from)?;
    validate_directory_metadata(&metadata, effective_uid)?;
    if path_identity != file_identity(&metadata) {
        return Err(DurableAuditError::PathIdentityChanged);
    }
    Ok(())
}

fn validate_directory_metadata(
    metadata: &fs::Metadata,
    effective_uid: u32,
) -> Result<(), DurableAuditError> {
    if !metadata.is_dir() {
        return Err(DurableAuditError::UnsafeParentDirectory);
    }
    #[cfg(unix)]
    {
        let mode = metadata.mode();
        let owner = metadata.uid();
        if mode & WRITE_BY_GROUP_OR_OTHER != 0
            && (mode & STICKY_DIRECTORY == 0 || (owner != 0 && owner != effective_uid))
        {
            return Err(DurableAuditError::UnsafeParentDirectory);
        }
    }
    Ok(())
}

fn validate_file_metadata(
    metadata: &fs::Metadata,
    effective_uid: u32,
) -> Result<(), DurableAuditError> {
    #[cfg(unix)]
    validate_owner_and_permissions(metadata.uid(), metadata.mode(), effective_uid)?;
    Ok(())
}

fn validate_owner_and_permissions(
    owner: u32,
    mode: u32,
    effective_uid: u32,
) -> Result<(), DurableAuditError> {
    if owner != effective_uid {
        return Err(DurableAuditError::WrongOwner {
            expected: effective_uid,
            actual: owner,
        });
    }
    let access_mode = mode & PERMISSION_MODE_BITS;
    if access_mode != PRIVATE_FILE_MODE {
        return Err(DurableAuditError::UnsafePermissions { mode: access_mode });
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
fn effective_uid() -> Result<u32, DurableAuditError> {
    let status = fs::read_to_string("/proc/self/status").map_err(DurableAuditError::from)?;
    let line = status
        .lines()
        .find(|line| line.starts_with("Uid:"))
        .ok_or_else(|| io::Error::other("/proc/self/status has no effective uid"))?;
    line.split_ascii_whitespace()
        .nth(2)
        .ok_or_else(|| io::Error::other("/proc/self/status effective uid is missing"))?
        .parse::<u32>()
        .map_err(|_| io::Error::other("/proc/self/status effective uid is invalid"))
        .map_err(DurableAuditError::from)
}

#[cfg(not(target_os = "linux"))]
fn effective_uid() -> Result<u32, DurableAuditError> {
    Err(DurableAuditError::from(io::Error::new(
        io::ErrorKind::Unsupported,
        "durable audit ownership validation requires Linux",
    )))
}

fn durable_lock_name(journal_name: &OsStr) -> OsString {
    #[cfg(unix)]
    let bytes = std::os::unix::ffi::OsStrExt::as_bytes(journal_name);
    #[cfg(not(unix))]
    let bytes = journal_name.to_string_lossy().as_bytes();
    OsString::from(format!(".authority-audit-{:016x}.lock", checksum(bytes)))
}

fn acquire_exclusive_lock(file: &File) -> Result<(), DurableAuditError> {
    match file.try_lock() {
        Ok(()) => Ok(()),
        Err(TryLockError::WouldBlock) => Err(DurableAuditError::Locked),
        Err(TryLockError::Error(error)) => Err(DurableAuditError::from(error)),
    }
}

fn read_bounded_journal(
    file: &mut File,
    maximum_length: u64,
) -> Result<Vec<u8>, DurableAuditError> {
    let mut bytes = Vec::new();
    file.take(maximum_length.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(DurableAuditError::from)?;
    let length = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    if length > maximum_length {
        return Err(capacity_exceeded(length, maximum_length));
    }
    Ok(bytes)
}

#[allow(clippy::too_many_lines)]
fn parse_journal(
    bytes: &[u8],
    maximum_length: u64,
) -> Result<
    (
        Option<u64>,
        BTreeMap<crate::audit::AttemptId, DurableAttemptState>,
    ),
    DurableAuditError,
> {
    let byte_length = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    if byte_length > maximum_length {
        return Err(capacity_exceeded(byte_length, maximum_length));
    }
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
                        reconciliation: None,
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
            RECONCILE_KIND => apply_reconcile_frame(&mut attempts, attempt_id, payload)?,
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

fn apply_reconcile_frame(
    attempts: &mut BTreeMap<crate::audit::AttemptId, DurableAttemptState>,
    attempt_id: crate::audit::AttemptId,
    payload: &[u8],
) -> Result<(), DurableAuditError> {
    let verdict = decode_reconcile_payload(payload, attempt_id)?;
    let Some(attempt) = attempts.get_mut(&attempt_id) else {
        return Err(DurableAuditError::ReplayDetected { attempt_id });
    };
    if attempt.outcome != AttemptOutcome::CommitUnknown {
        return Err(DurableAuditError::InvalidRecord(
            "only an unknown commit can be reconciled".to_owned(),
        ));
    }
    if attempt.reconciliation.is_some() {
        return Err(DurableAuditError::ReplayDetected { attempt_id });
    }
    attempt.reconciliation = Some(verdict);
    Ok(())
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
    if let Some(receipt) = receipt {
        if receipt.token().is_empty() {
            return Err(DurableAuditError::InvalidRecord(
                "commit receipt token cannot be empty".to_owned(),
            ));
        }
        if receipt.token().len() > MAX_COMMIT_RECEIPT_BYTES {
            return Err(DurableAuditError::RecordTooLarge(receipt.token().len()));
        }
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
        let token_limit = match outcome {
            AttemptOutcome::Committed => MAX_COMMIT_RECEIPT_BYTES,
            AttemptOutcome::CommitUnknown => MAX_COMMIT_UNKNOWN_EVIDENCE_BYTES,
            _ => unreachable!("terminal evidence outcomes were matched above"),
        };
        if token_length == 0 {
            let message = match outcome {
                AttemptOutcome::Committed => "commit receipt token cannot be empty",
                AttemptOutcome::CommitUnknown => "CommitUnknown evidence cannot be empty",
                _ => unreachable!("terminal evidence outcomes were matched above"),
            };
            return Err(DurableAuditError::InvalidRecord(message.to_owned()));
        }
        if token_length > token_limit {
            return Err(DurableAuditError::RecordTooLarge(token_length));
        }
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
    state_instance: u64,
    caller: &SubjectId,
    capability_id: &CapId,
    requests: &CapabilityRequestSet,
    authorization_epoch: AuthorizationEpoch,
) -> Result<Vec<u8>, DurableAuditError> {
    if !requests.is_complete() {
        return Err(DurableAuditError::InvalidRecord(format!(
            "effect request set exceeds the {MAX_REQUESTS_PER_EFFECT}-request limit"
        )));
    }
    let mut writer = PayloadWriter::new();
    writer.byte(ATTEMPT_PAYLOAD_VERSION);
    writer.u64(state_instance);
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

    fn bytes(&mut self, value: &[u8]) {
        self.bytes.extend_from_slice(value);
    }

    fn finish(self) -> Vec<u8> {
        self.bytes
    }
}

struct PayloadReader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> PayloadReader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], DurableAuditError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or_else(|| invalid_payload("attempt payload length overflowed"))?;
        let slice = self
            .bytes
            .get(self.offset..end)
            .ok_or_else(|| invalid_payload("attempt payload ended early"))?;
        self.offset = end;
        Ok(slice)
    }

    fn byte(&mut self) -> Result<u8, DurableAuditError> {
        Ok(self.take(1)?[0])
    }

    fn u32(&mut self) -> Result<u32, DurableAuditError> {
        let bytes: [u8; 4] = self
            .take(4)?
            .try_into()
            .map_err(|_| invalid_payload("attempt payload holds a malformed u32"))?;
        Ok(u32::from_le_bytes(bytes))
    }

    fn u64(&mut self) -> Result<u64, DurableAuditError> {
        let bytes: [u8; 8] = self
            .take(8)?
            .try_into()
            .map_err(|_| invalid_payload("attempt payload holds a malformed u64"))?;
        Ok(u64::from_le_bytes(bytes))
    }

    fn string(&mut self) -> Result<String, DurableAuditError> {
        let length = usize::try_from(self.u32()?)
            .map_err(|_| invalid_payload("attempt payload string exceeds this platform"))?;
        let bytes = self.take(length)?;
        String::from_utf8(bytes.to_vec())
            .map_err(|_| invalid_payload("attempt payload string is not UTF-8"))
    }

    fn segments(&mut self) -> Result<Vec<String>, DurableAuditError> {
        let count = usize::try_from(self.u32()?)
            .map_err(|_| invalid_payload("attempt payload segment count exceeds this platform"))?;
        // A count is not evidence that the bytes exist, so each segment is read before the next
        // is expected. Preallocating from the count would let a corrupt record request any size.
        let mut segments = Vec::new();
        for _ in 0..count {
            segments.push(self.string()?);
        }
        Ok(segments)
    }

    const fn is_exhausted(&self) -> bool {
        self.offset == self.bytes.len()
    }
}

fn invalid_payload(message: &str) -> DurableAuditError {
    DurableAuditError::InvalidRecord(message.to_owned())
}

fn encode_reconcile_payload(verdict: &ReconciledCommit) -> Result<Vec<u8>, DurableAuditError> {
    let mut writer = PayloadWriter::new();
    writer.byte(RECONCILE_PAYLOAD_VERSION);
    match verdict {
        ReconciledCommit::Committed(receipt) => {
            writer.byte(RECONCILED_COMMITTED);
            writer.u64(receipt.attempt_id().as_u64());
            let token = receipt.token();
            let length = u32::try_from(token.len())
                .map_err(|_| DurableAuditError::RecordTooLarge(token.len()))?;
            writer.u32(length);
            writer.bytes(token);
        }
        ReconciledCommit::NotCommitted => writer.byte(RECONCILED_NOT_COMMITTED),
    }
    let payload = writer.finish();
    if payload.len() > MAX_RECORD_PAYLOAD {
        return Err(DurableAuditError::RecordTooLarge(payload.len()));
    }
    Ok(payload)
}

fn decode_reconcile_payload(
    payload: &[u8],
    attempt_id: crate::audit::AttemptId,
) -> Result<ReconciledCommit, DurableAuditError> {
    let mut reader = PayloadReader::new(payload);
    let version = reader.byte()?;
    if version != RECONCILE_PAYLOAD_VERSION {
        return Err(invalid_payload(&format!(
            "unsupported reconciliation payload version {version}"
        )));
    }
    let verdict = match reader.byte()? {
        RECONCILED_COMMITTED => {
            let recorded = crate::audit::AttemptId::from_u64(reader.u64()?);
            if recorded != attempt_id {
                return Err(invalid_payload(
                    "reconciled receipt belongs to another attempt",
                ));
            }
            let length = usize::try_from(reader.u32()?)
                .map_err(|_| invalid_payload("reconciled receipt exceeds this platform"))?;
            let token = reader.take(length)?.to_vec();
            if token.is_empty() {
                return Err(invalid_payload("reconciled receipt token is empty"));
            }
            ReconciledCommit::Committed(CommitReceipt::new(attempt_id, token))
        }
        RECONCILED_NOT_COMMITTED => ReconciledCommit::NotCommitted,
        tag => {
            return Err(invalid_payload(&format!(
                "unknown reconciliation verdict {tag}"
            )));
        }
    };
    if !reader.is_exhausted() {
        return Err(invalid_payload("reconciliation payload has trailing bytes"));
    }
    Ok(verdict)
}

fn decode_attempt_payload(payload: &[u8]) -> Result<DurableAttemptMetadata, DurableAuditError> {
    let mut reader = PayloadReader::new(payload);
    let version = reader.byte()?;
    let state_instance = match version {
        // Version 1 predates the recorded capability-state instance and is always the first one.
        1 => 0,
        2 => reader.u64()?,
        _ => {
            return Err(invalid_payload(&format!(
                "unsupported attempt payload version {version}"
            )));
        }
    };
    let caller = SubjectId::new(reader.string()?);
    let capability_id = CapId::new(reader.string()?);
    let authorization_epoch = AuthorizationEpoch::from_u64(reader.u64()?);
    let count = reader.u32()?;
    if count == 0 {
        return Err(invalid_payload("attempt payload authorized no request"));
    }
    if usize::try_from(count).unwrap_or(usize::MAX) > MAX_REQUESTS_PER_EFFECT {
        return Err(DurableAuditError::InvalidRecord(format!(
            "attempt payload exceeds the {MAX_REQUESTS_PER_EFFECT}-request limit"
        )));
    }
    let mut requests = Vec::new();
    for _ in 0..count {
        let time = MonotonicTime::from_ticks(reader.u64()?);
        requests.push(CapabilityRequest::new(
            time,
            decode_authority_request(&mut reader)?,
        ));
    }
    if !reader.is_exhausted() {
        return Err(invalid_payload("attempt payload has trailing bytes"));
    }
    let mut requests = requests.into_iter();
    let first = requests
        .next()
        .ok_or_else(|| invalid_payload("attempt payload authorized no request"))?;
    let requests = CapabilityRequestSet::new(first, requests);
    Ok(DurableAttemptMetadata {
        state_instance,
        caller,
        capability_id,
        authorization_epoch,
        requests,
    })
}

fn decode_file_effect(tag: u8) -> Result<FileEffect, DurableAuditError> {
    FileEffect::from_tag(tag)
        .ok_or_else(|| invalid_payload(&format!("attempt payload holds unknown file effect {tag}")))
}

fn decode_http_method(tag: u8) -> Result<HttpFetchMethod, DurableAuditError> {
    match tag {
        0 => Ok(HttpFetchMethod::Get),
        1 => Ok(HttpFetchMethod::Head),
        _ => Err(invalid_payload(&format!(
            "attempt payload holds unknown HTTP method {tag}"
        ))),
    }
}

fn decode_github_operation(tag: u8) -> Result<GitHubOperation, DurableAuditError> {
    match tag {
        0 => Ok(GitHubOperation::PublishBranch),
        1 => Ok(GitHubOperation::CreatePullRequest),
        _ => Err(invalid_payload(&format!(
            "attempt payload holds unknown GitHub operation {tag}"
        ))),
    }
}

fn decode_authority_request(
    reader: &mut PayloadReader<'_>,
) -> Result<AuthorityRequest, DurableAuditError> {
    match reader.byte()? {
        1 => {
            let repository = RepoId::new(reader.string()?);
            let effect = decode_file_effect(reader.byte()?)?;
            let path = CanonicalPath::new(reader.segments()?)
                .map_err(|error| invalid_payload(&format!("attempt payload path: {error}")))?;
            Ok(AuthorityRequest::File(FileRequest::new(
                repository, effect, path,
            )))
        }
        2 => {
            let method = decode_http_method(reader.byte()?)?;
            let host = CanonicalHost::new(reader.string()?)
                .map_err(|error| invalid_payload(&format!("attempt payload host: {error}")))?;
            let path = decode_url_path(&reader.segments()?)?;
            let max_response_bytes = reader.u64()?;
            Ok(AuthorityRequest::HttpFetch(HttpFetchRequest::new(
                method,
                host,
                path,
                max_response_bytes,
            )))
        }
        3 => {
            let installation = InstallationId::new(reader.string()?);
            let repository = RepoId::new(reader.string()?);
            let operation = decode_github_operation(reader.byte()?)?;
            let base = decode_branch(&reader.segments()?)?;
            let head = decode_branch(&reader.segments()?)?;
            Ok(AuthorityRequest::GitHub(GitHubRequest::new(
                installation,
                repository,
                operation,
                base,
                head,
            )))
        }
        tag => Err(invalid_payload(&format!(
            "attempt payload holds unknown authority tag {tag}"
        ))),
    }
}

fn decode_url_path(segments: &[String]) -> Result<CanonicalUrlPath, DurableAuditError> {
    if segments.is_empty() {
        return Ok(CanonicalUrlPath::root());
    }
    CanonicalUrlPath::new(format!("/{}", segments.join("/")))
        .map_err(|error| invalid_payload(&format!("attempt payload URL path: {error}")))
}

fn decode_branch(segments: &[String]) -> Result<BranchName, DurableAuditError> {
    BranchName::new(segments.join("/"))
        .map_err(|error| invalid_payload(&format!("attempt payload branch: {error}")))
}

fn encode_authority_request(
    writer: &mut PayloadWriter,
    request: &CapabilityRequest,
) -> Result<(), DurableAuditError> {
    match request.authority() {
        AuthorityRequest::File(request) => {
            writer.byte(1);
            writer.string(request.repository().as_str())?;
            writer.byte(request.effect().tag());
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
        io::{Seek, SeekFrom},
        os::unix::fs::PermissionsExt,
        path::PathBuf,
        process::Command,
        sync::Arc,
        sync::atomic::{AtomicU64, Ordering},
        thread,
    };

    use super::{
        CommitReceipt, CommitUnknownEvidence, DurableAuditError, DurableAuditLog, DurableAuditView,
        MAX_COMMIT_RECEIPT_BYTES, MAX_COMMIT_UNKNOWN_EVIDENCE_BYTES, MAX_JOURNAL_BYTES,
        PRIVATE_FILE_MODE, decode_attempt_payload, durable_lock_name, encode_attempt_payload,
        validate_owner_and_permissions,
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
    const CROSS_PROCESS_LOCK_PATH: &str = "AUTHORITY_CORE_TEST_AUDIT_LOCK_PATH";

    struct TestJournal {
        path: PathBuf,
    }

    impl TestJournal {
        fn new() -> Self {
            let serial = NEXT_PATH.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "authority-core-durable-audit-{}-{serial}.wal",
                std::process::id()
            ));
            let _ = fs::remove_file(&path);
            if let (Some(parent), Some(name)) = (path.parent(), path.file_name()) {
                let _ = fs::remove_file(parent.join(durable_lock_name(name)));
            }
            Self { path }
        }

        fn lock_path(&self) -> PathBuf {
            self.path
                .parent()
                .expect("test journal must have a parent")
                .join(durable_lock_name(
                    self.path
                        .file_name()
                        .expect("test journal must have a file name"),
                ))
        }
    }

    impl Drop for TestJournal {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.path);
            let _ = fs::remove_file(self.lock_path());
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
        begin_result(log, attempt).expect("test attempt must be durable");
    }

    fn begin_result(log: &DurableAuditLog, attempt: u64) -> Result<(), DurableAuditError> {
        log.begin_attempt(
            0,
            AttemptId::from_u64(attempt),
            &SubjectId::new("subject"),
            &CapId::new("capability"),
            &request_set(),
            AuthorizationEpoch::default(),
        )
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
        let concurrent_view = DurableAuditView::open(&journal.path)
            .expect("read-only recovery must not acquire the writer lock");
        assert_eq!(live_view, concurrent_view);
        drop(log);

        let recovered = DurableAuditView::open(&journal.path)
            .expect("a complete start frame must be recoverable read-only");
        assert_eq!(live_view, recovered);
        assert_eq!(recovered.path(), journal.path);
        assert_eq!(recovered.next_attempt_sequence(), Some(1));
        assert_eq!(recovered.attempts()[0].outcome(), AttemptOutcome::Started);
    }

    #[test]
    fn second_writer_is_rejected_until_the_first_writer_drops() {
        let journal = TestJournal::new();
        let first = DurableAuditLog::create(&journal.path).expect("first writer must create WAL");

        assert!(matches!(
            DurableAuditLog::open(&journal.path),
            Err(DurableAuditError::Locked)
        ));
        begin(&first, 0);
        drop(first);

        let reopened = DurableAuditLog::open(&journal.path)
            .expect("dropping the sole writer must release both locks");
        assert_eq!(reopened.next_attempt_sequence(), Ok(Some(1)));
    }

    #[test]
    fn writer_lock_is_exclusive_across_processes() {
        if let Some(path) = std::env::var_os(CROSS_PROCESS_LOCK_PATH) {
            assert!(matches!(
                DurableAuditLog::open(PathBuf::from(path)),
                Err(DurableAuditError::Locked)
            ));
            return;
        }

        let journal = TestJournal::new();
        let writer = DurableAuditLog::create(&journal.path).expect("parent must own the WAL");
        let status = Command::new(std::env::current_exe().expect("locate test executable"))
            .arg("--exact")
            .arg("durable_audit::tests::writer_lock_is_exclusive_across_processes")
            .arg("--nocapture")
            .env(CROSS_PROCESS_LOCK_PATH, &journal.path)
            .status()
            .expect("start lock contender process");
        assert!(status.success(), "child must observe the writer lock");
        drop(writer);
    }

    #[test]
    fn append_mode_does_not_depend_on_the_file_cursor() {
        let journal = TestJournal::new();
        let log = DurableAuditLog::create(&journal.path).expect("writer must create WAL");
        begin(&log, 0);
        log.state
            .lock()
            .expect("writer state must remain healthy")
            .file
            .seek(SeekFrom::Start(0))
            .expect("test must move the read cursor");

        begin(&log, 1);
        drop(log);

        let recovered = DurableAuditView::open(&journal.path)
            .expect("O_APPEND must preserve both complete frames");
        assert_eq!(recovered.attempts().len(), 2);
        assert_eq!(recovered.next_attempt_sequence(), Some(2));
    }

    #[test]
    fn path_replacement_seals_the_original_writer() {
        let journal = TestJournal::new();
        let moved = journal.path.with_extension("moved");
        let _ = fs::remove_file(&moved);
        let log = DurableAuditLog::create(&journal.path).expect("writer must create WAL");
        begin(&log, 0);
        fs::rename(&journal.path, &moved).expect("move the locked WAL inode");
        fs::copy(&moved, &journal.path).expect("replace the WAL pathname with another inode");

        assert!(matches!(
            log.begin_attempt(
                0,
                AttemptId::from_u64(1),
                &SubjectId::new("subject"),
                &CapId::new("capability"),
                &request_set(),
                AuthorizationEpoch::default(),
            ),
            Err(DurableAuditError::PathIdentityChanged)
        ));
        assert_eq!(
            log.next_attempt_sequence(),
            Err(DurableAuditError::JournalUnavailable)
        );
        assert!(matches!(
            DurableAuditLog::open(&journal.path),
            Err(DurableAuditError::Locked)
        ));

        drop(log);
        fs::remove_file(moved).expect("remove moved WAL fixture");
    }

    #[test]
    fn private_wal_and_lock_modes_are_created_and_enforced() {
        let journal = TestJournal::new();
        let log = DurableAuditLog::create(&journal.path).expect("writer must create WAL");
        assert_eq!(
            fs::metadata(&journal.path)
                .expect("WAL metadata")
                .permissions()
                .mode()
                & 0o777,
            PRIVATE_FILE_MODE
        );
        assert_eq!(
            fs::metadata(journal.lock_path())
                .expect("lock metadata")
                .permissions()
                .mode()
                & 0o777,
            PRIVATE_FILE_MODE
        );
        drop(log);

        fs::set_permissions(
            journal.lock_path(),
            fs::Permissions::from_mode(PRIVATE_FILE_MODE | 0o040),
        )
        .expect("make lock group-readable");
        assert!(matches!(
            DurableAuditLog::open(&journal.path),
            Err(DurableAuditError::UnsafePermissions { .. })
        ));
        fs::set_permissions(
            journal.lock_path(),
            fs::Permissions::from_mode(PRIVATE_FILE_MODE),
        )
        .expect("restore lock mode");
        fs::set_permissions(
            &journal.path,
            fs::Permissions::from_mode(PRIVATE_FILE_MODE | 0o040),
        )
        .expect("make WAL group-readable");
        assert!(matches!(
            DurableAuditLog::open(&journal.path),
            Err(DurableAuditError::UnsafePermissions { .. })
        ));
        assert!(matches!(
            DurableAuditView::open(&journal.path),
            Err(DurableAuditError::UnsafePermissions { .. })
        ));
        fs::set_permissions(
            &journal.path,
            fs::Permissions::from_mode(PRIVATE_FILE_MODE | 0o4000),
        )
        .expect("add a set-user-ID bit");
        assert!(matches!(
            DurableAuditLog::open(&journal.path),
            Err(DurableAuditError::UnsafePermissions { .. })
        ));
        assert!(matches!(
            validate_owner_and_permissions(1_001, PRIVATE_FILE_MODE, 1_000),
            Err(DurableAuditError::WrongOwner {
                expected: 1_000,
                actual: 1_001
            })
        ));
    }

    #[test]
    fn journal_and_parent_symlinks_are_rejected() {
        let target = TestJournal::new();
        let target_log =
            DurableAuditLog::create(&target.path).expect("target WAL must be created securely");
        drop(target_log);
        let journal_link = target.path.with_extension("symlink");
        let journal_link_lock =
            journal_link
                .parent()
                .expect("journal link parent")
                .join(durable_lock_name(
                    journal_link.file_name().expect("journal link name"),
                ));
        let _ = fs::remove_file(&journal_link);
        let _ = fs::remove_file(&journal_link_lock);
        std::os::unix::fs::symlink(&target.path, &journal_link)
            .expect("create journal symlink fixture");

        assert!(matches!(
            DurableAuditView::open(&journal_link),
            Err(DurableAuditError::Symlink)
        ));
        assert!(matches!(
            DurableAuditLog::open(&journal_link),
            Err(DurableAuditError::Symlink)
        ));
        fs::remove_file(&journal_link).expect("remove journal symlink fixture");
        let _ = fs::remove_file(journal_link_lock);

        let parent_target = target.path.with_extension("directory");
        let parent_link = target.path.with_extension("directory-link");
        let _ = fs::remove_file(&parent_link);
        let _ = fs::remove_dir(&parent_target);
        fs::create_dir(&parent_target).expect("create parent target");
        fs::set_permissions(
            &parent_target,
            fs::Permissions::from_mode(PRIVATE_FILE_MODE | 0o100),
        )
        .expect("make parent private");
        std::os::unix::fs::symlink(&parent_target, &parent_link)
            .expect("create parent symlink fixture");
        assert!(matches!(
            DurableAuditLog::create(parent_link.join("audit.wal")),
            Err(DurableAuditError::Symlink)
        ));
        fs::remove_file(parent_link).expect("remove parent symlink fixture");
        fs::remove_dir(parent_target).expect("remove parent target fixture");
    }

    #[test]
    fn group_writable_non_sticky_parent_is_rejected() {
        let journal = TestJournal::new();
        let parent = journal.path.with_extension("unsafe-directory");
        let _ = fs::remove_dir(&parent);
        fs::create_dir(&parent).expect("create unsafe parent fixture");
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o770))
            .expect("make parent group-writable");

        assert!(matches!(
            DurableAuditLog::create(parent.join("audit.wal")),
            Err(DurableAuditError::UnsafeParentDirectory)
        ));

        fs::set_permissions(&parent, fs::Permissions::from_mode(0o700))
            .expect("restore parent mode for cleanup");
        fs::remove_dir(parent).expect("remove unsafe parent fixture");
    }

    #[test]
    fn read_only_and_writer_open_bound_sparse_journal_length() {
        let journal = TestJournal::new();
        let file = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&journal.path)
            .expect("create oversized fixture");
        file.set_permissions(fs::Permissions::from_mode(PRIVATE_FILE_MODE))
            .expect("make oversized fixture private");
        file.set_len(MAX_JOURNAL_BYTES + 1)
            .expect("create sparse oversized fixture");
        file.sync_all().expect("sync oversized fixture metadata");
        drop(file);

        assert!(matches!(
            DurableAuditView::open(&journal.path),
            Err(DurableAuditError::CapacityExceeded { .. })
        ));
        assert!(matches!(
            DurableAuditLog::open(&journal.path),
            Err(DurableAuditError::CapacityExceeded { .. })
        ));
    }

    #[test]
    fn capacity_zero_rejects_before_any_file_or_memory_state_mutation() {
        let journal = TestJournal::new();
        let log = DurableAuditLog::create_with_max_bytes(&journal.path, 0)
            .expect("zero-capacity empty journal must be creatable");
        let before = fs::read(&journal.path).expect("empty journal must be readable");

        let error = begin_result(&log, 0).expect_err("first frame must exceed zero capacity");
        assert!(matches!(
            error,
            DurableAuditError::CapacityExceeded {
                current: 0,
                projected,
                capacity: 0
            } if projected > 0
        ));
        assert_eq!(
            fs::read(&journal.path).expect("rejected append must not write bytes"),
            before
        );
        assert!(
            log.attempts()
                .expect("rejected append keeps state readable")
                .is_empty()
        );
        assert_eq!(
            log.next_attempt_sequence()
                .expect("rejected append keeps sequence allocation unchanged"),
            Some(0)
        );
        drop(log);

        let view = DurableAuditView::open_with_max_bytes(&journal.path, 0)
            .expect("zero-capacity empty journal must reopen");
        drop(view);
        let reopened = DurableAuditLog::open_with_max_bytes(&journal.path, 0)
            .expect("zero-capacity empty journal must reopen writable");
        drop(reopened);
    }

    #[test]
    fn exact_capacity_preserves_existing_terminal_frames_when_next_append_is_rejected() {
        let journal = TestJournal::new();
        let log = DurableAuditLog::create(&journal.path).expect("journal creation must sync");
        begin(&log, 0);
        log.finish_attempt(AttemptId::from_u64(0), AttemptOutcome::Denied, None, None)
            .expect("terminal frame must be durable");
        let capacity = fs::metadata(&journal.path)
            .expect("journal metadata must be readable")
            .len();
        let before = fs::read(&journal.path).expect("committed journal bytes must be readable");
        drop(log);

        let log = DurableAuditLog::open_with_max_bytes(&journal.path, capacity)
            .expect("journal at exact capacity must reopen");
        let error = begin_result(&log, 1).expect_err("next frame must exceed exact capacity");
        assert!(matches!(
            error,
            DurableAuditError::CapacityExceeded {
                current,
                projected,
                capacity: actual_capacity
            } if current == capacity && projected > capacity && actual_capacity == capacity
        ));
        assert_eq!(
            fs::read(&journal.path).expect("rejected append must preserve terminal bytes"),
            before
        );
        let attempts = log
            .attempts()
            .expect("existing terminal frame must remain readable");
        assert_eq!(attempts.len(), 1);
        assert_eq!(attempts[0].outcome(), AttemptOutcome::Denied);
        drop(log);

        let reopened = DurableAuditView::open_with_max_bytes(&journal.path, capacity)
            .expect("unchanged exact-capacity journal must reopen read-only");
        assert_eq!(reopened.attempts().len(), 1);
        assert_eq!(reopened.attempts()[0].outcome(), AttemptOutcome::Denied);
    }

    #[test]
    fn reopen_rejects_capacity_before_parsing_torn_or_overlong_suffixes() {
        let journal = TestJournal::new();
        let log = DurableAuditLog::create(&journal.path).expect("journal creation must sync");
        begin(&log, 0);
        drop(log);
        let complete_length = fs::metadata(&journal.path)
            .expect("journal metadata must be readable")
            .len();

        let file = OpenOptions::new()
            .write(true)
            .open(&journal.path)
            .expect("journal must be writable for suffix fixture");
        file.set_len(complete_length + 1)
            .expect("suffix fixture must be representable");
        file.sync_all().expect("suffix fixture must be synced");
        drop(file);

        assert!(matches!(
            DurableAuditView::open_with_max_bytes(&journal.path, complete_length),
            Err(DurableAuditError::CapacityExceeded {
                current,
                projected,
                capacity
            }) if current == complete_length + 1
                && projected == complete_length + 1
                && capacity == complete_length
        ));
        assert!(matches!(
            DurableAuditLog::open_with_max_bytes(&journal.path, complete_length),
            Err(DurableAuditError::CapacityExceeded { .. })
        ));

        file_cleanup(&journal.path, complete_length - 1);
        assert!(matches!(
            DurableAuditView::open_with_max_bytes(&journal.path, complete_length),
            Err(DurableAuditError::TruncatedRecord)
        ));
    }

    #[test]
    fn custom_capacity_above_production_hard_bound_is_rejected_without_creating_paths() {
        let journal = TestJournal::new();
        let requested = MAX_JOURNAL_BYTES + 1;
        assert!(matches!(
            DurableAuditLog::create_with_max_bytes(&journal.path, requested),
            Err(DurableAuditError::InvalidCapacity {
                requested: actual,
                maximum: MAX_JOURNAL_BYTES,
            }) if actual == requested
        ));
        assert!(!journal.path.exists());
        assert!(!journal.lock_path().exists());
    }

    fn file_cleanup(path: &PathBuf, length: u64) {
        let file = OpenOptions::new()
            .write(true)
            .open(path)
            .expect("journal must be writable for suffix cleanup");
        file.set_len(length)
            .expect("suffix cleanup must restore complete prefix");
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
    fn commit_receipt_is_non_empty_and_bounded_before_payload_allocation() {
        let journal = TestJournal::new();
        let log = DurableAuditLog::create(&journal.path).expect("journal creation must sync");

        let empty_attempt = AttemptId::from_u64(0);
        begin(&log, empty_attempt.as_u64());
        assert!(matches!(
            log.finish_attempt(
                empty_attempt,
                AttemptOutcome::Committed,
                Some(&CommitReceipt::new(empty_attempt, Vec::new())),
                None,
            ),
            Err(DurableAuditError::InvalidRecord(message))
                if message == "commit receipt token cannot be empty"
        ));

        let oversized_attempt = AttemptId::from_u64(1);
        begin(&log, oversized_attempt.as_u64());
        assert_eq!(
            log.finish_attempt(
                oversized_attempt,
                AttemptOutcome::Committed,
                Some(&CommitReceipt::new(
                    oversized_attempt,
                    vec![0x5a; MAX_COMMIT_RECEIPT_BYTES + 1],
                )),
                None,
            ),
            Err(DurableAuditError::RecordTooLarge(
                MAX_COMMIT_RECEIPT_BYTES + 1
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
    #[test]
    fn attempt_payload_round_trips_every_authority_shape() {
        use crate::{
            github::{BranchName, GitHubOperation, GitHubRequest, InstallationId},
            http::{CanonicalHost, CanonicalUrlPath, HttpFetchMethod, HttpFetchRequest},
        };

        let file = CapabilityRequest::new(
            MonotonicTime::from_ticks(7),
            AuthorityRequest::File(FileRequest::new(
                RepoId::new("workspace"),
                FileEffect::CreateHardLink,
                CanonicalPath::new(["src", "main.rs"]).expect("canonical path"),
            )),
        );
        let http = CapabilityRequest::new(
            MonotonicTime::from_ticks(8),
            AuthorityRequest::HttpFetch(HttpFetchRequest::new(
                HttpFetchMethod::Head,
                CanonicalHost::new("example.test").expect("canonical host"),
                CanonicalUrlPath::new("/a/b").expect("canonical URL path"),
                4096,
            )),
        );
        let github = CapabilityRequest::new(
            MonotonicTime::from_ticks(9),
            AuthorityRequest::GitHub(GitHubRequest::new(
                InstallationId::new("install-1"),
                RepoId::new("workspace"),
                GitHubOperation::CreatePullRequest,
                BranchName::new("main").expect("branch"),
                BranchName::new("feature/topic").expect("branch"),
            )),
        );
        let requests = CapabilityRequestSet::new(file, [http, github]);
        let caller = SubjectId::new("subject-a");
        let capability = CapId::new("capability-a");
        let epoch = AuthorizationEpoch::from_u64(42);

        let payload = encode_attempt_payload(11, &caller, &capability, &requests, epoch)
            .expect("payload must encode");
        let decoded = decode_attempt_payload(&payload).expect("payload must decode");

        assert_eq!(decoded.state_instance(), 11);
        assert_eq!(decoded.caller(), &caller);
        assert_eq!(decoded.capability_id(), &capability);
        assert_eq!(decoded.authorization_epoch(), epoch);
        assert_eq!(decoded.requests(), &requests);
    }

    #[test]
    fn attempt_payload_round_trips_each_file_effect_tag() {
        let caller = SubjectId::new("subject-a");
        let capability = CapId::new("capability-a");
        let epoch = AuthorizationEpoch::from_u64(42);

        for effect in FileEffect::ALL {
            let request = CapabilityRequest::new(
                MonotonicTime::from_ticks(7),
                AuthorityRequest::File(FileRequest::new(
                    RepoId::new("workspace"),
                    effect,
                    CanonicalPath::new(["src", "main.rs"]).expect("canonical test path"),
                )),
            );
            let requests = CapabilityRequestSet::one(request);
            let payload = encode_attempt_payload(11, &caller, &capability, &requests, epoch)
                .expect("every closed file effect must encode");
            let decoded =
                decode_attempt_payload(&payload).expect("every closed file effect tag must decode");

            assert_eq!(decoded.requests(), &requests);
            match decoded
                .requests()
                .iter()
                .next()
                .expect("one request must be present")
                .authority()
            {
                AuthorityRequest::File(request) => assert_eq!(request.effect(), effect),
                _ => panic!("the fixture is a file request"),
            }
        }
    }

    #[test]
    fn version_one_payloads_decode_as_the_first_capability_state_instance() {
        let requests = CapabilityRequestSet::one(CapabilityRequest::new(
            MonotonicTime::from_ticks(1),
            AuthorityRequest::File(FileRequest::new(
                RepoId::new("workspace"),
                FileEffect::ReadData,
                CanonicalPath::root(),
            )),
        ));
        let current = encode_attempt_payload(
            0,
            &SubjectId::new("subject-a"),
            &CapId::new("capability-a"),
            &requests,
            AuthorizationEpoch::default(),
        )
        .expect("payload must encode");
        // Version 1 is the same bytes without the instance the writer now prefixes.
        let mut legacy = vec![1_u8];
        legacy.extend_from_slice(&current[9..]);

        let decoded = decode_attempt_payload(&legacy).expect("a version 1 payload must decode");
        assert_eq!(decoded.state_instance(), 0);
        assert_eq!(decoded.requests(), &requests);
    }

    #[test]
    fn malformed_attempt_payloads_fail_closed() {
        let requests = CapabilityRequestSet::one(CapabilityRequest::new(
            MonotonicTime::from_ticks(1),
            AuthorityRequest::File(FileRequest::new(
                RepoId::new("workspace"),
                FileEffect::ReadData,
                CanonicalPath::root(),
            )),
        ));
        let payload = encode_attempt_payload(
            3,
            &SubjectId::new("subject-a"),
            &CapId::new("capability-a"),
            &requests,
            AuthorizationEpoch::default(),
        )
        .expect("payload must encode");

        assert!(decode_attempt_payload(&[]).is_err(), "empty payload");
        let mut unknown_version = payload.clone();
        unknown_version[0] = 3;
        assert!(decode_attempt_payload(&unknown_version).is_err(), "version");
        assert!(
            decode_attempt_payload(&payload[..payload.len() - 1]).is_err(),
            "truncated payload"
        );
        let mut trailing = payload.clone();
        trailing.push(0);
        assert!(decode_attempt_payload(&trailing).is_err(), "trailing bytes");
        let mut unknown_effect = payload.clone();
        let effect_index = unknown_effect
            .len()
            .checked_sub(9)
            .expect("payload holds a file effect");
        unknown_effect[effect_index] = 200;
        assert!(
            decode_attempt_payload(&unknown_effect).is_err(),
            "unknown file effect"
        );
    }
}
