//! Durable ownership journal for crash-recoverable session teardown.
//!
//! The journal publishes a complete session identity and runtime-configuration
//! fingerprint before startup effects begin. Cleanup checkpoints are accepted
//! only for the exact lease returned by that publication, in dependency order.
//! A trusted parent-directory descriptor and stable kernel-locked sidecar bind
//! every write to the originally validated files.

use std::{
    error::Error,
    ffi::{OsStr, OsString},
    fmt,
    fs::{self, File, OpenOptions, TryLockError},
    io::{self, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};

use firecracker_runtime::Sha256Digest;

use crate::{
    BrokerSessionId, CapabilityId, ID_BYTES, IdentityKind, RequestId, SessionId, SessionIdentity,
    SubjectId, VmId, WorkspaceId,
};

#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

/// Maximum number of durable recovery records accepted by one journal.
pub const MAX_SESSION_RECOVERY_RECORDS: usize = 65_536;

const JOURNAL_MAGIC: [u8; 8] = *b"SORRECJ1";
const JOURNAL_VERSION: u8 = 1;
const JOURNAL_HEADER_SLOT_BYTES: usize = 32;
const JOURNAL_HEADER_SLOTS: usize = 2;
const JOURNAL_DATA_OFFSET: usize = JOURNAL_HEADER_SLOT_BYTES * JOURNAL_HEADER_SLOTS;
const JOURNAL_HEADER_LENGTH_FIELD: u8 = 32;
const JOURNAL_RECORD_BYTES: usize = 192;
const MAX_JOURNAL_BYTES: usize =
    JOURNAL_DATA_OFFSET + (MAX_SESSION_RECOVERY_RECORDS * JOURNAL_RECORD_BYTES);
const CONFIG_FINGERPRINT_BYTES: usize = 32;
const IDENTITY_COUNT: usize = 7;
const ENCODED_IDENTITY_BYTES: usize = IDENTITY_COUNT * ID_BYTES;
const RECORD_IDENTITY_OFFSET: usize = 20;
const RECORD_FINGERPRINT_OFFSET: usize = RECORD_IDENTITY_OFFSET + ENCODED_IDENTITY_BYTES;
const RECORD_RESERVED_OFFSET: usize = RECORD_FINGERPRINT_OFFSET + CONFIG_FINGERPRINT_BYTES;
const RECORD_CHECKSUM_OFFSET: usize = JOURNAL_RECORD_BYTES - 4;
#[cfg(target_os = "linux")]
const O_NOFOLLOW: i32 = 0o400_000;
#[cfg(unix)]
const PRIVATE_FILE_MODE: u32 = 0o600;
#[cfg(unix)]
const WRITE_BY_GROUP_OR_OTHER: u32 = 0o022;
#[cfg(unix)]
const STICKY_DIRECTORY: u32 = 0o1000;

/// Exact durable recovery ownership published before session effects begin.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionRecoveryIntent {
    identity: SessionIdentity,
    config_fingerprint: Sha256Digest,
}

impl SessionRecoveryIntent {
    /// Creates an intent for one exact session and runtime configuration.
    #[must_use]
    pub const fn new(identity: SessionIdentity, config_fingerprint: Sha256Digest) -> Self {
        Self {
            identity,
            config_fingerprint,
        }
    }

    /// Returns the exact session identity owned by this recovery intent.
    #[must_use]
    pub const fn identity(self) -> SessionIdentity {
        self.identity
    }

    /// Returns the runtime-configuration fingerprint bound to this intent.
    #[must_use]
    pub const fn config_fingerprint(self) -> Sha256Digest {
        self.config_fingerprint
    }

    /// Returns all exact no-reuse identities bound by this intent.
    #[must_use]
    pub fn identities(self) -> [(IdentityKind, [u8; ID_BYTES]); IDENTITY_COUNT] {
        [
            (IdentityKind::Session, self.identity.session_id().as_bytes()),
            (IdentityKind::Request, self.identity.request_id().as_bytes()),
            (IdentityKind::Vm, self.identity.vm_id().as_bytes()),
            (IdentityKind::Subject, self.identity.subject_id().as_bytes()),
            (
                IdentityKind::Workspace,
                self.identity.workspace_id().as_bytes(),
            ),
            (
                IdentityKind::BrokerSession,
                self.identity.broker_session_id().as_bytes(),
            ),
            (
                IdentityKind::Capability,
                self.identity.capability_id().as_bytes(),
            ),
        ]
    }
}

/// Monotone cleanup progress for one durable session recovery intent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SessionRecoveryStage {
    /// The exact identity and configuration are durable before any effect.
    Intent,
    /// The no-reuse ledger durably contains all seven exact identities.
    IdentityReserved,
    /// The session cgroup contains no processes.
    CgroupEmpty,
    /// The session device mapper has been closed.
    MapperClosed,
    /// Workspace provisioning state has been released.
    ProvisioningReleased,
    /// The jail and workspace paths have been removed.
    JailRemoved,
    /// Every recovery obligation is durably complete.
    Complete,
    /// The intent was abandoned before any identity was reserved.
    Abandoned,
}

impl SessionRecoveryStage {
    const fn tag(self) -> u8 {
        match self {
            Self::Intent => 1,
            Self::IdentityReserved => 2,
            Self::CgroupEmpty => 3,
            Self::MapperClosed => 4,
            Self::ProvisioningReleased => 5,
            Self::JailRemoved => 6,
            Self::Complete => 7,
            Self::Abandoned => 8,
        }
    }

    const fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            1 => Some(Self::Intent),
            2 => Some(Self::IdentityReserved),
            3 => Some(Self::CgroupEmpty),
            4 => Some(Self::MapperClosed),
            5 => Some(Self::ProvisioningReleased),
            6 => Some(Self::JailRemoved),
            7 => Some(Self::Complete),
            8 => Some(Self::Abandoned),
            _ => None,
        }
    }

    const fn next(self) -> Option<Self> {
        match self {
            Self::Intent => Some(Self::IdentityReserved),
            Self::IdentityReserved => Some(Self::CgroupEmpty),
            Self::CgroupEmpty => Some(Self::MapperClosed),
            Self::MapperClosed => Some(Self::ProvisioningReleased),
            Self::ProvisioningReleased => Some(Self::JailRemoved),
            Self::JailRemoved => Some(Self::Complete),
            Self::Complete | Self::Abandoned => None,
        }
    }

    const fn is_terminal(self) -> bool {
        matches!(self, Self::Complete | Self::Abandoned)
    }

    /// Reports whether the durable identity ledger must contain this intent.
    #[must_use]
    pub const fn identity_was_reserved(self) -> bool {
        !matches!(self, Self::Intent | Self::Abandoned)
    }
}

impl fmt::Display for SessionRecoveryStage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Intent => "intent",
            Self::IdentityReserved => "identity-reserved",
            Self::CgroupEmpty => "cgroup-empty",
            Self::MapperClosed => "mapper-closed",
            Self::ProvisioningReleased => "provisioning-released",
            Self::JailRemoved => "jail-removed",
            Self::Complete => "complete",
            Self::Abandoned => "abandoned",
        })
    }
}

/// One exact intent and its latest stage reconstructed from durable history.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionRecoveryHistory {
    intent: SessionRecoveryIntent,
    stage: SessionRecoveryStage,
}

impl SessionRecoveryHistory {
    /// Returns the exact durable intent.
    #[must_use]
    pub const fn intent(self) -> SessionRecoveryIntent {
        self.intent
    }

    /// Returns the latest durable stage for this intent.
    #[must_use]
    pub const fn stage(self) -> SessionRecoveryStage {
        self.stage
    }
}

/// Non-forgeable in-process evidence for the journal's exact pending intent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionRecoveryLease {
    intent: SessionRecoveryIntent,
    stage: SessionRecoveryStage,
    generation: u64,
    journal_identity: FileIdentity,
    intent_checksum: u32,
}

impl SessionRecoveryLease {
    /// Returns the exact recovery intent represented by this lease.
    #[must_use]
    pub const fn intent(self) -> SessionRecoveryIntent {
        self.intent
    }

    /// Returns the last durably committed cleanup stage.
    #[must_use]
    pub const fn stage(self) -> SessionRecoveryStage {
        self.stage
    }
}

/// Filesystem operations reported by recovery-journal I/O failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionRecoveryOperation {
    /// Opening and retaining the trusted parent directory.
    DirectoryOpen,
    /// Synchronizing a newly created directory entry.
    DirectorySync,
    /// Inspecting a path or open descriptor.
    Metadata,
    /// Opening the journal file.
    Open,
    /// Reading the durable journal.
    Read,
    /// Appending a recovery record.
    Append,
    /// Publishing the committed journal header.
    HeaderWrite,
    /// Synchronizing durable journal state.
    Sync,
    /// Opening or acquiring the stable ownership lock.
    Lock,
}

impl fmt::Display for SessionRecoveryOperation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::DirectoryOpen => "open recovery journal parent directory",
            Self::DirectorySync => "sync recovery journal parent directory",
            Self::Metadata => "inspect recovery journal metadata",
            Self::Open => "open recovery journal",
            Self::Read => "read recovery journal",
            Self::Append => "append recovery journal record",
            Self::HeaderWrite => "publish recovery journal header",
            Self::Sync => "sync recovery journal",
            Self::Lock => "acquire recovery journal lock",
        })
    }
}

/// A typed, fail-closed durable session recovery failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionRecoveryError {
    /// Another live writer owns the journal.
    Locked {
        /// Journal path whose stable sidecar is locked.
        path: PathBuf,
    },
    /// A journal, lock, or parent component is a symbolic link.
    Symlink {
        /// Rejected path.
        path: PathBuf,
    },
    /// A journal or lock path is not a regular file.
    NotRegularFile {
        /// Rejected path.
        path: PathBuf,
    },
    /// A validated path no longer names the retained device/inode.
    PathIdentityChanged {
        /// Replaced path.
        path: PathBuf,
    },
    /// A journal or lock file has an unexpected owner.
    WrongOwner {
        /// Path with the unexpected owner.
        path: PathBuf,
        /// Effective user required to own the file.
        expected: u32,
        /// Owner observed on the file.
        actual: u32,
    },
    /// A journal or lock file is not exact owner-only read/write mode.
    UnsafePermissions {
        /// Path with unsafe permissions.
        path: PathBuf,
        /// Observed Unix permission bits.
        mode: u32,
    },
    /// A parent directory is replaceable by an untrusted local principal.
    UnsafeParentDirectory {
        /// Rejected directory.
        path: PathBuf,
    },
    /// An open file length differs from the durably committed length.
    LengthChanged {
        /// Path whose length changed.
        path: PathBuf,
        /// Required length.
        expected: u64,
        /// Observed length.
        actual: u64,
    },
    /// A filesystem operation failed.
    Io {
        /// Failed operation.
        operation: SessionRecoveryOperation,
        /// Path involved in the operation.
        path: PathBuf,
        /// Original operating-system message.
        message: String,
    },
    /// The journal is structurally invalid or a checksum does not match.
    Corrupt {
        /// Byte offset at which corruption was detected.
        offset: u64,
        /// Operator-facing failure detail.
        reason: String,
    },
    /// The journal ends before a complete header or record is available.
    Truncated {
        /// Byte offset at which the incomplete value begins.
        offset: u64,
        /// Number of bytes required.
        expected: usize,
        /// Number of bytes available.
        actual: usize,
    },
    /// The journal uses an unsupported format version.
    UnsupportedVersion {
        /// Unsupported version tag.
        version: u8,
    },
    /// The bounded record capacity would be exceeded.
    CapacityExceeded {
        /// Requested committed record count.
        records: u64,
        /// Maximum accepted record count.
        max_records: u64,
    },
    /// A new intent cannot replace an incomplete recovery obligation.
    PendingRecovery {
        /// Identity of the still-pending session.
        identity: SessionIdentity,
        /// Last durable cleanup stage.
        stage: SessionRecoveryStage,
    },
    /// A checkpoint was requested without a pending recovery obligation.
    NoPendingRecovery,
    /// A checkpoint lease does not exactly match the active journal intent.
    StaleLease,
    /// A checkpoint skipped or regressed a cleanup dependency.
    InvalidStageTransition {
        /// Last durable stage.
        current: SessionRecoveryStage,
        /// Requested stage.
        requested: SessionRecoveryStage,
    },
    /// The journal generation counter cannot advance without reuse.
    GenerationExhausted,
    /// An earlier uncertain write permanently sealed this journal instance.
    Unavailable {
        /// Reason this instance cannot safely write again.
        reason: String,
    },
}

impl SessionRecoveryError {
    fn io(operation: SessionRecoveryOperation, path: &Path, error: &io::Error) -> Self {
        Self::Io {
            operation,
            path: path.to_path_buf(),
            message: error.to_string(),
        }
    }

    fn corrupt(offset: usize, reason: impl Into<String>) -> Self {
        Self::Corrupt {
            offset: offset as u64,
            reason: reason.into(),
        }
    }

    fn truncated(offset: usize, expected: usize, actual: usize) -> Self {
        Self::Truncated {
            offset: offset as u64,
            expected,
            actual,
        }
    }
}

impl fmt::Display for SessionRecoveryError {
    #[allow(clippy::too_many_lines)]
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Locked { path } => write!(
                formatter,
                "session recovery journal is locked: {}",
                path.display()
            ),
            Self::Symlink { path } => write!(
                formatter,
                "session recovery path is a symbolic link: {}",
                path.display()
            ),
            Self::NotRegularFile { path } => write!(
                formatter,
                "session recovery path is not a regular file: {}",
                path.display()
            ),
            Self::PathIdentityChanged { path } => write!(
                formatter,
                "session recovery path identity changed: {}",
                path.display()
            ),
            Self::WrongOwner {
                path,
                expected,
                actual,
            } => write!(
                formatter,
                "session recovery owner {actual} does not match effective user {expected}: {}",
                path.display()
            ),
            Self::UnsafePermissions { path, mode } => write!(
                formatter,
                "session recovery permissions {mode:o} are not 600: {}",
                path.display()
            ),
            Self::UnsafeParentDirectory { path } => write!(
                formatter,
                "session recovery parent directory is not trusted: {}",
                path.display()
            ),
            Self::LengthChanged {
                path,
                expected,
                actual,
            } => write!(
                formatter,
                "session recovery length changed at {}: expected {expected} bytes, found {actual}",
                path.display()
            ),
            Self::Io {
                operation,
                path,
                message,
            } => write!(
                formatter,
                "{operation} at {} failed: {message}",
                path.display()
            ),
            Self::Corrupt { offset, reason } => write!(
                formatter,
                "session recovery journal is corrupt at byte {offset}: {reason}"
            ),
            Self::Truncated {
                offset,
                expected,
                actual,
            } => write!(
                formatter,
                "session recovery journal is truncated at byte {offset}: expected {expected} bytes, found {actual}"
            ),
            Self::UnsupportedVersion { version } => write!(
                formatter,
                "session recovery journal format version {version} is unsupported"
            ),
            Self::CapacityExceeded {
                records,
                max_records,
            } => write!(
                formatter,
                "session recovery journal capacity exceeded: {records} records requested, maximum is {max_records}"
            ),
            Self::PendingRecovery { identity, stage } => write!(
                formatter,
                "session {} still requires recovery from stage {stage}",
                identity.session_id()
            ),
            Self::NoPendingRecovery => {
                formatter.write_str("session recovery journal has no pending intent")
            }
            Self::StaleLease => formatter
                .write_str("session recovery lease does not match the exact pending intent"),
            Self::InvalidStageTransition { current, requested } => write!(
                formatter,
                "session recovery stage cannot advance from {current} to {requested}"
            ),
            Self::GenerationExhausted => {
                formatter.write_str("session recovery generation is exhausted")
            }
            Self::Unavailable { reason } => write!(
                formatter,
                "session recovery journal is unavailable and fails closed: {reason}"
            ),
        }
    }
}

impl Error for SessionRecoveryError {}

#[derive(Debug)]
struct ExclusiveJournalLock {
    file: File,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct FileIdentity {
    device: u64,
    inode: u64,
}

#[derive(Debug)]
struct TrustedJournalDirectory {
    file: File,
    path: PathBuf,
    journal_name: OsString,
    lock_name: OsString,
    effective_uid: u32,
}

impl TrustedJournalDirectory {
    fn open(journal_path: &Path) -> Result<Self, SessionRecoveryError> {
        let journal_name = journal_path
            .file_name()
            .filter(|name| !name.is_empty())
            .ok_or_else(|| SessionRecoveryError::UnsafeParentDirectory {
                path: journal_path.to_path_buf(),
            })?
            .to_os_string();
        let path = journal_path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf();
        let effective_uid = effective_uid()?;
        let expected = validate_parent_path(&path, effective_uid)?;
        let file = File::open(&path).map_err(|error| {
            SessionRecoveryError::io(SessionRecoveryOperation::DirectoryOpen, &path, &error)
        })?;
        let metadata = file.metadata().map_err(|error| {
            SessionRecoveryError::io(SessionRecoveryOperation::Metadata, &path, &error)
        })?;
        validate_directory_metadata(&path, &metadata, effective_uid)?;
        if file_identity(&metadata) != expected {
            return Err(SessionRecoveryError::PathIdentityChanged { path });
        }
        let lock_name = journal_lock_name(&journal_name);
        let directory = Self {
            file,
            path,
            journal_name,
            lock_name,
            effective_uid,
        };
        directory.validate()?;
        Ok(directory)
    }

    fn journal_path(&self) -> PathBuf {
        self.child_path(&self.journal_name)
    }

    fn journal_display_path(&self) -> PathBuf {
        self.path.join(&self.journal_name)
    }

    fn lock_path(&self) -> PathBuf {
        self.child_path(&self.lock_name)
    }

    fn lock_display_path(&self) -> PathBuf {
        self.path.join(&self.lock_name)
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

    fn validate(&self) -> Result<(), SessionRecoveryError> {
        validate_parent_path_identity(&self.path, &self.file, self.effective_uid)
    }

    fn sync(&self) -> Result<(), SessionRecoveryError> {
        self.file.sync_all().map_err(|error| {
            SessionRecoveryError::io(SessionRecoveryOperation::DirectorySync, &self.path, &error)
        })
    }
}

/// Exclusive checksummed recovery journal for session startup and teardown.
#[derive(Debug)]
pub struct DurableSessionRecoveryJournal {
    path: PathBuf,
    directory: TrustedJournalDirectory,
    file: File,
    lock: ExclusiveJournalLock,
    journal_identity: FileIdentity,
    pending: Option<SessionRecoveryLease>,
    history: Vec<SessionRecoveryHistory>,
    header_generation: u64,
    active_header_slot: usize,
    next_generation: u64,
    record_count: u64,
    length: u64,
    poisoned: bool,
}

impl DurableSessionRecoveryJournal {
    /// Opens or creates a journal and acquires its single-writer lock.
    ///
    /// Existing bytes are reconstructed completely. Unsafe directories,
    /// symlinks, wrong ownership or mode, path replacement, truncation,
    /// invalid checksums, and impossible stage histories are rejected. A valid
    /// complete tail is rolled forward and only a final partial record is
    /// truncated, under the already-held exclusive writer lock.
    ///
    /// # Errors
    ///
    /// Returns [`SessionRecoveryError`] when exclusive ownership or complete
    /// fail-closed reconstruction cannot be established.
    #[allow(clippy::too_many_lines)]
    pub fn open(path: impl AsRef<Path>) -> Result<Self, SessionRecoveryError> {
        let path = path.as_ref().to_path_buf();
        let directory = TrustedJournalDirectory::open(&path)?;
        let lock = acquire_journal_lock(&directory, &path)?;
        let descriptor_path = directory.journal_path();
        let (mut file, created) = match create_private_file(&descriptor_path) {
            Ok(file) => (file, true),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => (
                open_existing_file(&descriptor_path).map_err(|error| {
                    classify_open_error(
                        SessionRecoveryOperation::Open,
                        &path,
                        &descriptor_path,
                        &error,
                    )
                })?,
                false,
            ),
            Err(error) => {
                return Err(classify_open_error(
                    SessionRecoveryOperation::Open,
                    &path,
                    &descriptor_path,
                    &error,
                ));
            }
        };

        if created {
            validate_open_journal(&directory, &file, Some(0))?;
            let header = journal_header(0, 0);
            let mut headers = [0_u8; JOURNAL_DATA_OFFSET];
            for slot in headers.chunks_exact_mut(JOURNAL_HEADER_SLOT_BYTES) {
                slot.copy_from_slice(&header);
            }
            write_and_sync(
                &mut file,
                &path,
                SessionRecoveryOperation::HeaderWrite,
                &headers,
            )?;
            let metadata =
                validate_open_journal(&directory, &file, Some(JOURNAL_DATA_OFFSET as u64))?;
            validate_open_lock(&directory, &lock.file)?;
            directory.sync()?;
            let metadata =
                validate_open_journal(&directory, &file, Some(JOURNAL_DATA_OFFSET as u64))
                    .map(|_| metadata)?;
            Ok(Self {
                path,
                directory,
                file,
                lock,
                journal_identity: file_identity(&metadata),
                pending: None,
                history: Vec::new(),
                header_generation: 0,
                active_header_slot: 0,
                next_generation: 0,
                record_count: 0,
                length: JOURNAL_DATA_OFFSET as u64,
                poisoned: false,
            })
        } else {
            let metadata = validate_open_journal(&directory, &file, None)?;
            let length = metadata.len();
            let capacity =
                usize::try_from(length).map_err(|_| SessionRecoveryError::CapacityExceeded {
                    records: u64::MAX,
                    max_records: MAX_SESSION_RECOVERY_RECORDS as u64,
                })?;
            let mut bytes = Vec::with_capacity(capacity);
            file.seek(SeekFrom::Start(0))
                .and_then(|_| {
                    (&mut file)
                        .take(MAX_JOURNAL_BYTES as u64 + 1)
                        .read_to_end(&mut bytes)
                })
                .map_err(|error| {
                    SessionRecoveryError::io(SessionRecoveryOperation::Read, &path, &error)
                })?;
            let observed = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
            if observed != length {
                return Err(SessionRecoveryError::LengthChanged {
                    path,
                    expected: length,
                    actual: observed,
                });
            }
            let recovered = recover_journal(&mut file, &path, &mut bytes)?;
            let length =
                u64::try_from(bytes.len()).map_err(|_| SessionRecoveryError::CapacityExceeded {
                    records: u64::MAX,
                    max_records: MAX_SESSION_RECOVERY_RECORDS as u64,
                })?;
            let metadata = validate_open_journal(&directory, &file, Some(length))?;
            validate_open_lock(&directory, &lock.file)?;
            let journal_identity = file_identity(&metadata);
            let pending = recovered
                .pending
                .map(|state| state.into_lease(journal_identity));
            Ok(Self {
                path,
                directory,
                file,
                lock,
                journal_identity,
                pending,
                history: recovered.history,
                header_generation: recovered.header_generation,
                active_header_slot: recovered.active_header_slot,
                next_generation: recovered.next_generation,
                record_count: recovered.record_count,
                length,
                poisoned: false,
            })
        }
    }

    /// Returns the exact incomplete recovery lease, if one exists.
    #[must_use]
    pub const fn pending(&self) -> Option<SessionRecoveryLease> {
        self.pending
    }

    /// Returns the path of the exclusively owned recovery journal.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Returns every retained intent and its latest durable stage.
    #[must_use]
    pub fn history(&self) -> &[SessionRecoveryHistory] {
        &self.history
    }

    /// Returns the number of retained intents, including abandoned intents.
    #[must_use]
    pub fn intent_count(&self) -> usize {
        self.history.len()
    }

    /// Returns intents whose seven identities must exist in the no-reuse ledger.
    pub fn identity_reserved_intents(&self) -> impl Iterator<Item = SessionRecoveryIntent> + '_ {
        self.history
            .iter()
            .filter(|entry| entry.stage.identity_was_reserved())
            .map(|entry| entry.intent)
    }

    /// Returns the number of intents that must exist in the no-reuse ledger.
    #[must_use]
    pub fn identity_reserved_intent_count(&self) -> usize {
        self.history
            .iter()
            .filter(|entry| entry.stage.identity_was_reserved())
            .count()
    }

    /// Durably publishes ownership before any session startup effect begins.
    ///
    /// The returned lease is valid only for this journal, generation, exact
    /// session identity, and configuration fingerprint.
    ///
    /// # Errors
    ///
    /// Returns [`SessionRecoveryError`] if another intent remains pending, the
    /// journal is unavailable, or the intent cannot be durably committed.
    pub fn prepare(
        &mut self,
        intent: SessionRecoveryIntent,
    ) -> Result<SessionRecoveryLease, SessionRecoveryError> {
        self.ensure_available()?;
        if let Some(pending) = self.pending {
            return Err(SessionRecoveryError::PendingRecovery {
                identity: pending.intent.identity,
                stage: pending.stage,
            });
        }
        let intent_checksum = intent_checksum(intent);
        let lease = SessionRecoveryLease {
            intent,
            stage: SessionRecoveryStage::Intent,
            generation: self.next_generation,
            journal_identity: self.journal_identity,
            intent_checksum,
        };
        self.append_committed_stage(lease)?;
        Ok(lease)
    }

    /// Durably advances cleanup for the exact active lease.
    ///
    /// Repeating the currently committed stage is an idempotent no-op. Every
    /// other successful checkpoint must be the immediate dependency successor.
    ///
    /// # Errors
    ///
    /// Returns [`SessionRecoveryError`] for a stale lease, missing intent,
    /// skipped or regressed stage, uncertain prior write, or durable I/O error.
    pub fn checkpoint(
        &mut self,
        lease: &SessionRecoveryLease,
        stage: SessionRecoveryStage,
    ) -> Result<SessionRecoveryLease, SessionRecoveryError> {
        self.ensure_available()?;
        let current = self
            .pending
            .ok_or(SessionRecoveryError::NoPendingRecovery)?;
        if !same_lease_identity(current, *lease) {
            return Err(SessionRecoveryError::StaleLease);
        }
        if stage == current.stage {
            return Ok(current);
        }
        let is_abandon = current.stage == SessionRecoveryStage::Intent
            && stage == SessionRecoveryStage::Abandoned;
        if current.stage.next() != Some(stage) && !is_abandon {
            return Err(SessionRecoveryError::InvalidStageTransition {
                current: current.stage,
                requested: stage,
            });
        }
        if stage.is_terminal() && current.generation == u64::MAX {
            return Err(SessionRecoveryError::GenerationExhausted);
        }
        let advanced = SessionRecoveryLease { stage, ..current };
        self.append_committed_stage(advanced)?;
        Ok(advanced)
    }

    /// Durably marks the exact recovery lease complete.
    ///
    /// # Errors
    ///
    /// Returns [`SessionRecoveryError`] unless `JailRemoved` is the last
    /// durable checkpoint for the exact active lease, or durable I/O fails.
    pub fn complete(&mut self, lease: &SessionRecoveryLease) -> Result<(), SessionRecoveryError> {
        self.checkpoint(lease, SessionRecoveryStage::Complete)
            .map(|_| ())
    }

    /// Durably abandons an intent proven absent from the no-reuse ledger.
    ///
    /// # Errors
    ///
    /// Returns [`SessionRecoveryError`] unless the exact lease is still at
    /// `Intent`, before any identity reservation was acknowledged.
    pub fn abandon(&mut self, lease: &SessionRecoveryLease) -> Result<(), SessionRecoveryError> {
        self.checkpoint(lease, SessionRecoveryStage::Abandoned)
            .map(|_| ())
    }

    fn ensure_available(&self) -> Result<(), SessionRecoveryError> {
        if self.poisoned {
            Err(SessionRecoveryError::Unavailable {
                reason:
                    "a previous validation, append, or sync failure left journal state uncertain"
                        .to_owned(),
            })
        } else {
            Ok(())
        }
    }

    #[allow(clippy::too_many_lines)]
    fn append_committed_stage(
        &mut self,
        committed: SessionRecoveryLease,
    ) -> Result<(), SessionRecoveryError> {
        let new_record_count =
            self.record_count
                .checked_add(1)
                .ok_or(SessionRecoveryError::CapacityExceeded {
                    records: u64::MAX,
                    max_records: MAX_SESSION_RECOVERY_RECORDS as u64,
                })?;
        if new_record_count > MAX_SESSION_RECOVERY_RECORDS as u64 {
            return Err(SessionRecoveryError::CapacityExceeded {
                records: new_record_count,
                max_records: MAX_SESSION_RECOVERY_RECORDS as u64,
            });
        }
        let record = journal_record(committed, self.record_count);
        if let Err(error) = self.validate_append_target(self.length) {
            self.poisoned = true;
            return Err(error);
        }
        if let Err(error) = self.file.seek(SeekFrom::Start(self.length)) {
            self.poisoned = true;
            return Err(SessionRecoveryError::io(
                SessionRecoveryOperation::Append,
                &self.path,
                &error,
            ));
        }
        if let Err(error) = self.file.write_all(&record) {
            self.poisoned = true;
            return Err(SessionRecoveryError::io(
                SessionRecoveryOperation::Append,
                &self.path,
                &error,
            ));
        }
        if let Err(error) = self.file.sync_all() {
            self.poisoned = true;
            return Err(SessionRecoveryError::io(
                SessionRecoveryOperation::Sync,
                &self.path,
                &error,
            ));
        }
        let committed_length =
            JOURNAL_DATA_OFFSET as u64 + new_record_count * JOURNAL_RECORD_BYTES as u64;
        if let Err(error) = self.validate_append_target(committed_length) {
            self.poisoned = true;
            return Err(error);
        }
        let Some(new_header_generation) = self.header_generation.checked_add(1) else {
            self.poisoned = true;
            return Err(SessionRecoveryError::GenerationExhausted);
        };
        let inactive_header_slot = (self.active_header_slot + 1) % JOURNAL_HEADER_SLOTS;
        let header_offset = u64::try_from(inactive_header_slot * JOURNAL_HEADER_SLOT_BYTES)
            .expect("header slot offset fits in u64");
        if let Err(error) = self.file.seek(SeekFrom::Start(header_offset)) {
            self.poisoned = true;
            return Err(SessionRecoveryError::io(
                SessionRecoveryOperation::HeaderWrite,
                &self.path,
                &error,
            ));
        }
        let header = journal_header(new_header_generation, new_record_count);
        if let Err(error) = self.file.write_all(&header) {
            self.poisoned = true;
            return Err(SessionRecoveryError::io(
                SessionRecoveryOperation::HeaderWrite,
                &self.path,
                &error,
            ));
        }
        if let Err(error) = self.file.sync_all() {
            self.poisoned = true;
            return Err(SessionRecoveryError::io(
                SessionRecoveryOperation::Sync,
                &self.path,
                &error,
            ));
        }

        self.record_count = new_record_count;
        self.length = committed_length;
        self.header_generation = new_header_generation;
        self.active_header_slot = inactive_header_slot;
        if committed.stage == SessionRecoveryStage::Intent {
            self.history.push(SessionRecoveryHistory {
                intent: committed.intent,
                stage: committed.stage,
            });
        } else if let Some(entry) = self.history.last_mut() {
            entry.stage = committed.stage;
        }
        if committed.stage.is_terminal() {
            self.pending = None;
            self.next_generation = committed
                .generation
                .checked_add(1)
                .ok_or(SessionRecoveryError::GenerationExhausted)?;
        } else {
            self.pending = Some(committed);
        }
        if let Err(error) = self.validate_append_target(committed_length) {
            self.poisoned = true;
            return Err(error);
        }
        Ok(())
    }

    fn validate_append_target(&self, expected_length: u64) -> Result<(), SessionRecoveryError> {
        self.directory.validate()?;
        validate_open_lock(&self.directory, &self.lock.file)?;
        let metadata = validate_open_journal(&self.directory, &self.file, Some(expected_length))?;
        if file_identity(&metadata) != self.journal_identity {
            return Err(SessionRecoveryError::PathIdentityChanged {
                path: self.path.clone(),
            });
        }
        Ok(())
    }
}

fn same_lease_identity(left: SessionRecoveryLease, right: SessionRecoveryLease) -> bool {
    left.intent == right.intent
        && left.generation == right.generation
        && left.journal_identity == right.journal_identity
        && left.intent_checksum == right.intent_checksum
}

fn journal_lock_name(journal_name: &OsStr) -> OsString {
    let mut lock_name = journal_name.to_os_string();
    lock_name.push(".lock");
    lock_name
}

fn acquire_journal_lock(
    directory: &TrustedJournalDirectory,
    journal_path: &Path,
) -> Result<ExclusiveJournalLock, SessionRecoveryError> {
    directory.validate()?;
    let descriptor_path = directory.lock_path();
    let display_path = directory.lock_display_path();
    let (file, created) = match create_private_file(&descriptor_path) {
        Ok(file) => (file, true),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => (
            open_existing_file(&descriptor_path).map_err(|error| {
                classify_open_error(
                    SessionRecoveryOperation::Lock,
                    &display_path,
                    &descriptor_path,
                    &error,
                )
            })?,
            false,
        ),
        Err(error) => {
            return Err(classify_open_error(
                SessionRecoveryOperation::Lock,
                &display_path,
                &descriptor_path,
                &error,
            ));
        }
    };
    match file.try_lock() {
        Ok(()) => {}
        Err(TryLockError::WouldBlock) => {
            return Err(SessionRecoveryError::Locked {
                path: journal_path.to_path_buf(),
            });
        }
        Err(TryLockError::Error(error)) => {
            return Err(SessionRecoveryError::io(
                SessionRecoveryOperation::Lock,
                &display_path,
                &error,
            ));
        }
    }
    validate_open_lock(directory, &file)?;
    if created {
        file.sync_all().map_err(|error| {
            SessionRecoveryError::io(SessionRecoveryOperation::Lock, &display_path, &error)
        })?;
        directory.sync()?;
        validate_open_lock(directory, &file)?;
    }
    Ok(ExclusiveJournalLock { file })
}

fn create_private_file(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.create_new(true).read(true).write(true);
    configure_secure_open(&mut options);
    let file = options.open(path)?;
    set_private_permissions(&file)?;
    Ok(file)
}

fn open_existing_file(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).write(true);
    configure_secure_open(&mut options);
    options.open(path)
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

fn classify_open_error(
    operation: SessionRecoveryOperation,
    display_path: &Path,
    descriptor_path: &Path,
    error: &io::Error,
) -> SessionRecoveryError {
    if fs::symlink_metadata(descriptor_path).is_ok_and(|metadata| metadata.is_symlink()) {
        SessionRecoveryError::Symlink {
            path: display_path.to_path_buf(),
        }
    } else {
        SessionRecoveryError::io(operation, display_path, error)
    }
}

fn validate_open_journal(
    directory: &TrustedJournalDirectory,
    file: &File,
    expected_length: Option<u64>,
) -> Result<fs::Metadata, SessionRecoveryError> {
    validate_open_named_file(
        directory,
        &directory.journal_name,
        &directory.journal_display_path(),
        file,
        expected_length,
        Some(MAX_JOURNAL_BYTES as u64),
    )
}

fn validate_open_lock(
    directory: &TrustedJournalDirectory,
    file: &File,
) -> Result<(), SessionRecoveryError> {
    validate_open_named_file(
        directory,
        &directory.lock_name,
        &directory.lock_display_path(),
        file,
        Some(0),
        Some(0),
    )
    .map(|_| ())
}

fn validate_open_named_file(
    directory: &TrustedJournalDirectory,
    name: &OsStr,
    display_path: &Path,
    file: &File,
    expected_length: Option<u64>,
    maximum_length: Option<u64>,
) -> Result<fs::Metadata, SessionRecoveryError> {
    directory.validate()?;
    let descriptor_path = directory.child_path(name);
    let path_metadata = fs::symlink_metadata(&descriptor_path).map_err(|error| {
        if error.kind() == io::ErrorKind::NotFound {
            SessionRecoveryError::PathIdentityChanged {
                path: display_path.to_path_buf(),
            }
        } else {
            SessionRecoveryError::io(SessionRecoveryOperation::Metadata, display_path, &error)
        }
    })?;
    if path_metadata.file_type().is_symlink() {
        return Err(SessionRecoveryError::Symlink {
            path: display_path.to_path_buf(),
        });
    }
    let metadata = file.metadata().map_err(|error| {
        SessionRecoveryError::io(SessionRecoveryOperation::Metadata, display_path, &error)
    })?;
    if !metadata.is_file() || !path_metadata.is_file() {
        return Err(SessionRecoveryError::NotRegularFile {
            path: display_path.to_path_buf(),
        });
    }
    if file_identity(&metadata) != file_identity(&path_metadata) {
        return Err(SessionRecoveryError::PathIdentityChanged {
            path: display_path.to_path_buf(),
        });
    }
    validate_file_metadata(display_path, &metadata, directory.effective_uid)?;
    if let Some(maximum) = maximum_length
        && metadata.len() > maximum
    {
        if display_path == directory.journal_display_path() {
            let records = metadata
                .len()
                .saturating_sub(JOURNAL_DATA_OFFSET as u64)
                .saturating_add(JOURNAL_RECORD_BYTES as u64 - 1)
                / JOURNAL_RECORD_BYTES as u64;
            return Err(SessionRecoveryError::CapacityExceeded {
                records,
                max_records: MAX_SESSION_RECOVERY_RECORDS as u64,
            });
        }
        return Err(SessionRecoveryError::LengthChanged {
            path: display_path.to_path_buf(),
            expected: maximum,
            actual: metadata.len(),
        });
    }
    if let Some(expected) = expected_length
        && metadata.len() != expected
    {
        return Err(SessionRecoveryError::LengthChanged {
            path: display_path.to_path_buf(),
            expected,
            actual: metadata.len(),
        });
    }
    Ok(metadata)
}

fn validate_parent_path(
    path: &Path,
    effective_uid: u32,
) -> Result<FileIdentity, SessionRecoveryError> {
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
                return Err(SessionRecoveryError::UnsafeParentDirectory {
                    path: path.to_path_buf(),
                });
            }
        }
        let metadata = fs::symlink_metadata(&current).map_err(|error| {
            SessionRecoveryError::io(SessionRecoveryOperation::Metadata, &current, &error)
        })?;
        if metadata.file_type().is_symlink() {
            return Err(SessionRecoveryError::Symlink {
                path: current.clone(),
            });
        }
        validate_directory_metadata(&current, &metadata, effective_uid)?;
        final_identity = Some(file_identity(&metadata));
    }
    if final_identity.is_none() {
        let metadata = fs::symlink_metadata(&current).map_err(|error| {
            SessionRecoveryError::io(SessionRecoveryOperation::Metadata, &current, &error)
        })?;
        if metadata.file_type().is_symlink() {
            return Err(SessionRecoveryError::Symlink {
                path: current.clone(),
            });
        }
        validate_directory_metadata(&current, &metadata, effective_uid)?;
        final_identity = Some(file_identity(&metadata));
    }
    final_identity.ok_or_else(|| SessionRecoveryError::UnsafeParentDirectory {
        path: path.to_path_buf(),
    })
}

fn validate_parent_path_identity(
    path: &Path,
    directory: &File,
    effective_uid: u32,
) -> Result<(), SessionRecoveryError> {
    let expected = validate_parent_path(path, effective_uid)?;
    let metadata = directory.metadata().map_err(|error| {
        SessionRecoveryError::io(SessionRecoveryOperation::Metadata, path, &error)
    })?;
    validate_directory_metadata(path, &metadata, effective_uid)?;
    if expected != file_identity(&metadata) {
        return Err(SessionRecoveryError::PathIdentityChanged {
            path: path.to_path_buf(),
        });
    }
    Ok(())
}

fn validate_directory_metadata(
    path: &Path,
    metadata: &fs::Metadata,
    effective_uid: u32,
) -> Result<(), SessionRecoveryError> {
    if !metadata.is_dir() {
        return Err(SessionRecoveryError::UnsafeParentDirectory {
            path: path.to_path_buf(),
        });
    }
    #[cfg(unix)]
    {
        let mode = metadata.mode();
        let owner = metadata.uid();
        if mode & WRITE_BY_GROUP_OR_OTHER != 0
            && (mode & STICKY_DIRECTORY == 0 || (owner != 0 && owner != effective_uid))
        {
            return Err(SessionRecoveryError::UnsafeParentDirectory {
                path: path.to_path_buf(),
            });
        }
    }
    Ok(())
}

fn validate_file_metadata(
    path: &Path,
    metadata: &fs::Metadata,
    effective_uid: u32,
) -> Result<(), SessionRecoveryError> {
    #[cfg(unix)]
    {
        if metadata.uid() != effective_uid {
            return Err(SessionRecoveryError::WrongOwner {
                path: path.to_path_buf(),
                expected: effective_uid,
                actual: metadata.uid(),
            });
        }
        let mode = metadata.mode() & 0o777;
        if mode != PRIVATE_FILE_MODE {
            return Err(SessionRecoveryError::UnsafePermissions {
                path: path.to_path_buf(),
                mode,
            });
        }
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
fn effective_uid() -> Result<u32, SessionRecoveryError> {
    let path = Path::new("/proc/self/status");
    let status = fs::read_to_string(path).map_err(|error| {
        SessionRecoveryError::io(SessionRecoveryOperation::Metadata, path, &error)
    })?;
    let value = status
        .lines()
        .find(|line| line.starts_with("Uid:"))
        .and_then(|line| line.split_ascii_whitespace().nth(2))
        .ok_or_else(|| SessionRecoveryError::Unavailable {
            reason: "/proc/self/status has no effective uid".to_owned(),
        })?;
    value
        .parse()
        .map_err(|_| SessionRecoveryError::Unavailable {
            reason: "/proc/self/status effective uid is invalid".to_owned(),
        })
}

#[cfg(not(target_os = "linux"))]
fn effective_uid() -> Result<u32, SessionRecoveryError> {
    Err(SessionRecoveryError::Unavailable {
        reason: "durable session recovery ownership validation requires Linux".to_owned(),
    })
}

fn write_and_sync(
    file: &mut File,
    path: &Path,
    operation: SessionRecoveryOperation,
    bytes: &[u8],
) -> Result<(), SessionRecoveryError> {
    file.write_all(bytes)
        .map_err(|error| SessionRecoveryError::io(operation, path, &error))?;
    file.sync_all()
        .map_err(|error| SessionRecoveryError::io(SessionRecoveryOperation::Sync, path, &error))
}

fn journal_header(generation: u64, record_count: u64) -> [u8; JOURNAL_HEADER_SLOT_BYTES] {
    let mut header = [0_u8; JOURNAL_HEADER_SLOT_BYTES];
    header[..JOURNAL_MAGIC.len()].copy_from_slice(&JOURNAL_MAGIC);
    header[8] = JOURNAL_VERSION;
    header[9] = JOURNAL_HEADER_LENGTH_FIELD;
    header[12..20].copy_from_slice(&generation.to_le_bytes());
    header[20..28].copy_from_slice(&record_count.to_le_bytes());
    let header_checksum = checksum(&header[..28]);
    header[28..].copy_from_slice(&header_checksum.to_le_bytes());
    header
}

fn journal_record(lease: SessionRecoveryLease, sequence: u64) -> [u8; JOURNAL_RECORD_BYTES] {
    let mut record = [0_u8; JOURNAL_RECORD_BYTES];
    record[0] = JOURNAL_VERSION;
    record[1] = lease.stage.tag();
    record[4..12].copy_from_slice(&sequence.to_le_bytes());
    record[12..20].copy_from_slice(&lease.generation.to_le_bytes());
    encode_identity(
        lease.intent.identity,
        &mut record[RECORD_IDENTITY_OFFSET..RECORD_FINGERPRINT_OFFSET],
    );
    record[RECORD_FINGERPRINT_OFFSET..RECORD_RESERVED_OFFSET]
        .copy_from_slice(&lease.intent.config_fingerprint.as_bytes());
    let record_checksum = checksum(&record[..RECORD_CHECKSUM_OFFSET]);
    record[RECORD_CHECKSUM_OFFSET..].copy_from_slice(&record_checksum.to_le_bytes());
    record
}

fn encode_identity(identity: SessionIdentity, output: &mut [u8]) {
    for (slot, bytes) in output
        .chunks_exact_mut(ID_BYTES)
        .zip(identity_parts(identity))
    {
        slot.copy_from_slice(&bytes);
    }
}

fn identity_parts(identity: SessionIdentity) -> [[u8; ID_BYTES]; IDENTITY_COUNT] {
    [
        identity.session_id().as_bytes(),
        identity.request_id().as_bytes(),
        identity.vm_id().as_bytes(),
        identity.subject_id().as_bytes(),
        identity.workspace_id().as_bytes(),
        identity.broker_session_id().as_bytes(),
        identity.capability_id().as_bytes(),
    ]
}

fn decode_identity(bytes: &[u8]) -> SessionIdentity {
    let mut parts = bytes.chunks_exact(ID_BYTES);
    let mut next = || -> [u8; ID_BYTES] {
        parts
            .next()
            .expect("fixed recovery identity")
            .try_into()
            .expect("fixed identity width")
    };
    SessionIdentity {
        session_id: SessionId::new(next()),
        request_id: RequestId::new(next()),
        vm_id: VmId::new(next()),
        subject_id: SubjectId::new(next()),
        workspace_id: WorkspaceId::new(next()),
        broker_session_id: BrokerSessionId::new(next()),
        capability_id: CapabilityId::new(next()),
    }
}

fn intent_checksum(intent: SessionRecoveryIntent) -> u32 {
    let mut bytes = [0_u8; ENCODED_IDENTITY_BYTES + CONFIG_FINGERPRINT_BYTES];
    encode_identity(intent.identity, &mut bytes[..ENCODED_IDENTITY_BYTES]);
    bytes[ENCODED_IDENTITY_BYTES..].copy_from_slice(&intent.config_fingerprint.as_bytes());
    checksum(&bytes)
}

#[derive(Debug, Clone, Copy)]
struct RecoveredPending {
    intent: SessionRecoveryIntent,
    stage: SessionRecoveryStage,
    generation: u64,
}

impl RecoveredPending {
    fn into_lease(self, journal_identity: FileIdentity) -> SessionRecoveryLease {
        SessionRecoveryLease {
            intent: self.intent,
            stage: self.stage,
            generation: self.generation,
            journal_identity,
            intent_checksum: intent_checksum(self.intent),
        }
    }
}

#[derive(Debug)]
struct RecoveredJournal {
    pending: Option<RecoveredPending>,
    history: Vec<SessionRecoveryHistory>,
    header_generation: u64,
    active_header_slot: usize,
    next_generation: u64,
    record_count: u64,
}

#[derive(Debug, Clone, Copy)]
struct ParsedHeader {
    generation: u64,
    record_count: u64,
    committed_length: usize,
    slot: usize,
}

fn parse_header_slot(bytes: &[u8], slot: usize) -> Result<ParsedHeader, SessionRecoveryError> {
    let offset = slot * JOURNAL_HEADER_SLOT_BYTES;
    if bytes.len() < offset + JOURNAL_HEADER_SLOT_BYTES {
        return Err(SessionRecoveryError::truncated(
            offset,
            JOURNAL_HEADER_SLOT_BYTES,
            bytes.len().saturating_sub(offset),
        ));
    }
    let header = &bytes[offset..offset + JOURNAL_HEADER_SLOT_BYTES];
    if header[..JOURNAL_MAGIC.len()] != JOURNAL_MAGIC {
        return Err(SessionRecoveryError::corrupt(
            offset,
            "header magic does not match",
        ));
    }
    if header[8] != JOURNAL_VERSION {
        return Err(SessionRecoveryError::UnsupportedVersion { version: header[8] });
    }
    if header[9] as usize != JOURNAL_HEADER_SLOT_BYTES || header[10..12] != [0, 0] {
        return Err(SessionRecoveryError::corrupt(
            offset + 9,
            "invalid header length or reserved bytes",
        ));
    }
    let generation = u64::from_le_bytes(header[12..20].try_into().expect("fixed header"));
    let record_count = u64::from_le_bytes(header[20..28].try_into().expect("fixed header"));
    let expected_checksum = u32::from_le_bytes(header[28..32].try_into().expect("fixed header"));
    if checksum(&header[..28]) != expected_checksum {
        return Err(SessionRecoveryError::corrupt(
            offset + 28,
            "header checksum mismatch",
        ));
    }
    if record_count > MAX_SESSION_RECOVERY_RECORDS as u64 {
        return Err(SessionRecoveryError::CapacityExceeded {
            records: record_count,
            max_records: MAX_SESSION_RECOVERY_RECORDS as u64,
        });
    }
    let record_count_usize =
        usize::try_from(record_count).map_err(|_| SessionRecoveryError::CapacityExceeded {
            records: record_count,
            max_records: MAX_SESSION_RECOVERY_RECORDS as u64,
        })?;
    let committed_length = JOURNAL_DATA_OFFSET
        .checked_add(record_count_usize.checked_mul(JOURNAL_RECORD_BYTES).ok_or(
            SessionRecoveryError::CapacityExceeded {
                records: record_count,
                max_records: MAX_SESSION_RECOVERY_RECORDS as u64,
            },
        )?)
        .ok_or(SessionRecoveryError::CapacityExceeded {
            records: record_count,
            max_records: MAX_SESSION_RECOVERY_RECORDS as u64,
        })?;
    if bytes.len() < committed_length {
        return Err(SessionRecoveryError::truncated(
            bytes.len(),
            committed_length,
            bytes.len(),
        ));
    }
    Ok(ParsedHeader {
        generation,
        record_count,
        committed_length,
        slot,
    })
}

fn select_header(bytes: &[u8]) -> Result<ParsedHeader, SessionRecoveryError> {
    let first = parse_header_slot(bytes, 0);
    let second = parse_header_slot(bytes, 1);
    match (first, second) {
        (Ok(first), Ok(second)) => {
            if first.generation == second.generation
                && (first.record_count != second.record_count
                    || first.committed_length != second.committed_length)
            {
                return Err(SessionRecoveryError::corrupt(
                    0,
                    "equal header generations disagree on committed state",
                ));
            }
            if second.generation > first.generation {
                Ok(second)
            } else {
                Ok(first)
            }
        }
        (Ok(header), Err(_)) | (Err(_), Ok(header)) => Ok(header),
        (Err(first), Err(_)) => Err(first),
    }
}

fn parse_committed_journal(
    bytes: &[u8],
    header: ParsedHeader,
) -> Result<RecoveredJournal, SessionRecoveryError> {
    let mut pending: Option<RecoveredPending> = None;
    let mut history = Vec::new();
    let mut next_generation = 0_u64;
    for (index, record) in bytes[JOURNAL_DATA_OFFSET..header.committed_length]
        .chunks_exact(JOURNAL_RECORD_BYTES)
        .enumerate()
    {
        let offset = JOURNAL_DATA_OFFSET + index * JOURNAL_RECORD_BYTES;
        apply_record(
            &mut pending,
            &mut history,
            &mut next_generation,
            record,
            u64::try_from(index).expect("record index fits in u64"),
            offset,
        )?;
    }
    Ok(RecoveredJournal {
        pending,
        history,
        header_generation: header.generation,
        active_header_slot: header.slot,
        next_generation,
        record_count: header.record_count,
    })
}

fn apply_record(
    pending: &mut Option<RecoveredPending>,
    history: &mut Vec<SessionRecoveryHistory>,
    next_generation: &mut u64,
    record: &[u8],
    expected_sequence: u64,
    offset: usize,
) -> Result<(), SessionRecoveryError> {
    if record[0] != JOURNAL_VERSION {
        return Err(SessionRecoveryError::UnsupportedVersion { version: record[0] });
    }
    if record[2..4] != [0, 0]
        || record[RECORD_RESERVED_OFFSET..RECORD_CHECKSUM_OFFSET]
            .iter()
            .any(|byte| *byte != 0)
    {
        return Err(SessionRecoveryError::corrupt(
            offset + 2,
            "record reserved bytes are non-zero",
        ));
    }
    let expected_record_checksum = u32::from_le_bytes(
        record[RECORD_CHECKSUM_OFFSET..]
            .try_into()
            .expect("fixed checksum"),
    );
    if checksum(&record[..RECORD_CHECKSUM_OFFSET]) != expected_record_checksum {
        return Err(SessionRecoveryError::corrupt(
            offset + RECORD_CHECKSUM_OFFSET,
            "record checksum mismatch",
        ));
    }
    let sequence = u64::from_le_bytes(record[4..12].try_into().expect("fixed record"));
    if sequence != expected_sequence {
        return Err(SessionRecoveryError::corrupt(
            offset + 4,
            "record sequence is not contiguous",
        ));
    }
    let generation = u64::from_le_bytes(record[12..20].try_into().expect("fixed record"));
    let Some(stage) = SessionRecoveryStage::from_tag(record[1]) else {
        return Err(SessionRecoveryError::corrupt(
            offset + 1,
            "unknown recovery stage",
        ));
    };
    let identity = decode_identity(&record[RECORD_IDENTITY_OFFSET..RECORD_FINGERPRINT_OFFSET]);
    let fingerprint = Sha256Digest::from_bytes(
        record[RECORD_FINGERPRINT_OFFSET..RECORD_RESERVED_OFFSET]
            .try_into()
            .expect("fixed fingerprint"),
    );
    let intent = SessionRecoveryIntent::new(identity, fingerprint);

    if stage == SessionRecoveryStage::Intent {
        if pending.is_some() || generation != *next_generation {
            return Err(SessionRecoveryError::corrupt(
                offset,
                "intent overlaps pending recovery or reuses a generation",
            ));
        }
        *pending = Some(RecoveredPending {
            intent,
            stage,
            generation,
        });
        history.push(SessionRecoveryHistory { intent, stage });
        return Ok(());
    }
    let Some(current) = *pending else {
        return Err(SessionRecoveryError::corrupt(
            offset,
            "checkpoint has no preceding pending intent",
        ));
    };
    if current.generation != generation || current.intent != intent {
        return Err(SessionRecoveryError::corrupt(
            offset,
            "checkpoint does not match the exact pending intent",
        ));
    }
    let is_abandon =
        current.stage == SessionRecoveryStage::Intent && stage == SessionRecoveryStage::Abandoned;
    if current.stage.next() != Some(stage) && !is_abandon {
        return Err(SessionRecoveryError::corrupt(
            offset + 1,
            "checkpoint is not the immediate monotone successor",
        ));
    }
    let Some(history_entry) = history.last_mut() else {
        return Err(SessionRecoveryError::corrupt(
            offset,
            "checkpoint has no retained intent history",
        ));
    };
    history_entry.stage = stage;
    if stage.is_terminal() {
        *pending = None;
        *next_generation = generation
            .checked_add(1)
            .ok_or(SessionRecoveryError::GenerationExhausted)?;
    } else {
        *pending = Some(RecoveredPending { stage, ..current });
    }
    Ok(())
}

fn recover_journal(
    file: &mut File,
    path: &Path,
    bytes: &mut Vec<u8>,
) -> Result<RecoveredJournal, SessionRecoveryError> {
    let header = select_header(bytes)?;
    let mut recovered = parse_committed_journal(bytes, header)?;
    let tail_length = bytes.len() - header.committed_length;
    if tail_length == 0 {
        return Ok(recovered);
    }
    let complete_tail_bytes = tail_length / JOURNAL_RECORD_BYTES * JOURNAL_RECORD_BYTES;
    let repaired_length = header.committed_length + complete_tail_bytes;
    for (tail_index, record) in bytes[header.committed_length..repaired_length]
        .chunks_exact(JOURNAL_RECORD_BYTES)
        .enumerate()
    {
        let tail_sequence = u64::try_from(tail_index).expect("bounded tail index fits in u64");
        let sequence = recovered.record_count.checked_add(tail_sequence).ok_or(
            SessionRecoveryError::CapacityExceeded {
                records: u64::MAX,
                max_records: MAX_SESSION_RECOVERY_RECORDS as u64,
            },
        )?;
        if sequence >= MAX_SESSION_RECOVERY_RECORDS as u64 {
            return Err(SessionRecoveryError::CapacityExceeded {
                records: sequence.saturating_add(1),
                max_records: MAX_SESSION_RECOVERY_RECORDS as u64,
            });
        }
        apply_record(
            &mut recovered.pending,
            &mut recovered.history,
            &mut recovered.next_generation,
            record,
            sequence,
            header.committed_length + tail_index * JOURNAL_RECORD_BYTES,
        )?;
    }
    let complete_tail_records = u64::try_from(complete_tail_bytes / JOURNAL_RECORD_BYTES)
        .expect("bounded tail record count fits in u64");
    recovered.record_count = recovered
        .record_count
        .checked_add(complete_tail_records)
        .ok_or(SessionRecoveryError::CapacityExceeded {
            records: u64::MAX,
            max_records: MAX_SESSION_RECOVERY_RECORDS as u64,
        })?;

    // A partial final frame was never published and cannot represent a usable
    // checkpoint. Truncate only that suffix after every preceding complete
    // frame has passed checksum, sequence, identity, and stage validation.
    if repaired_length != bytes.len() {
        file.set_len(u64::try_from(repaired_length).expect("bounded length fits in u64"))
            .map_err(|error| {
                SessionRecoveryError::io(SessionRecoveryOperation::Append, path, &error)
            })?;
        file.sync_all().map_err(|error| {
            SessionRecoveryError::io(SessionRecoveryOperation::Sync, path, &error)
        })?;
        bytes.truncate(repaired_length);
    } else if complete_tail_records != 0 {
        // The records were visible after reopen but may have been written just
        // before a crash. Establish their durability before publishing them.
        file.sync_all().map_err(|error| {
            SessionRecoveryError::io(SessionRecoveryOperation::Sync, path, &error)
        })?;
    }

    if complete_tail_records != 0 {
        let new_header_generation = recovered
            .header_generation
            .checked_add(1)
            .ok_or(SessionRecoveryError::GenerationExhausted)?;
        let inactive_header_slot = (recovered.active_header_slot + 1) % JOURNAL_HEADER_SLOTS;
        let header_offset = u64::try_from(inactive_header_slot * JOURNAL_HEADER_SLOT_BYTES)
            .expect("header slot offset fits in u64");
        file.seek(SeekFrom::Start(header_offset)).map_err(|error| {
            SessionRecoveryError::io(SessionRecoveryOperation::HeaderWrite, path, &error)
        })?;
        let header = journal_header(new_header_generation, recovered.record_count);
        write_and_sync(file, path, SessionRecoveryOperation::HeaderWrite, &header)?;
        let header_start = inactive_header_slot * JOURNAL_HEADER_SLOT_BYTES;
        bytes[header_start..header_start + JOURNAL_HEADER_SLOT_BYTES].copy_from_slice(&header);
        recovered.header_generation = new_header_generation;
        recovered.active_header_slot = inactive_header_slot;
    }
    Ok(recovered)
}

fn checksum(bytes: &[u8]) -> u32 {
    let mut value = u32::MAX;
    for byte in bytes {
        value ^= u32::from(*byte);
        for _ in 0..8 {
            let mask = 0_u32.wrapping_sub(value & 1);
            value = (value >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !value
}

#[cfg(test)]
mod tests {
    use std::{
        process::{Command, Stdio},
        sync::atomic::{AtomicU64, Ordering},
        thread,
        time::{Duration, SystemTime, UNIX_EPOCH},
    };

    use super::*;

    const CHILD_PATH: &str = "SESSION_RECOVERY_CHILD_PATH";
    const CHILD_READY: &str = "SESSION_RECOVERY_CHILD_READY";
    const CHILD_RELEASE: &str = "SESSION_RECOVERY_CHILD_RELEASE";
    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

    struct JournalFixture {
        directory: PathBuf,
        path: PathBuf,
    }

    impl JournalFixture {
        fn new(name: &str) -> Self {
            let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("test clock must follow Unix epoch")
                .as_nanos();
            let directory = std::env::temp_dir().join(format!(
                "session-recovery-{}-{name}-{nonce}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&directory).expect("test recovery directory must be created");
            #[cfg(unix)]
            fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))
                .expect("test recovery directory must be private");
            let path = directory.join("session.recovery");
            Self { directory, path }
        }

        fn lock_path(&self) -> PathBuf {
            self.directory.join("session.recovery.lock")
        }
    }

    impl Drop for JournalFixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.directory);
        }
    }

    fn identity(seed: u8) -> SessionIdentity {
        SessionIdentity {
            session_id: SessionId::new([seed; ID_BYTES]),
            request_id: RequestId::new([seed.wrapping_add(1); ID_BYTES]),
            vm_id: VmId::new([seed.wrapping_add(2); ID_BYTES]),
            subject_id: SubjectId::new([seed.wrapping_add(3); ID_BYTES]),
            workspace_id: WorkspaceId::new([seed.wrapping_add(4); ID_BYTES]),
            broker_session_id: BrokerSessionId::new([seed.wrapping_add(5); ID_BYTES]),
            capability_id: CapabilityId::new([seed.wrapping_add(6); ID_BYTES]),
        }
    }

    fn intent(seed: u8) -> SessionRecoveryIntent {
        SessionRecoveryIntent::new(identity(seed), Sha256Digest::from_bytes([seed; 32]))
    }

    fn checkpoint_through_jail(
        journal: &mut DurableSessionRecoveryJournal,
        mut lease: SessionRecoveryLease,
    ) -> SessionRecoveryLease {
        for stage in [
            SessionRecoveryStage::IdentityReserved,
            SessionRecoveryStage::CgroupEmpty,
            SessionRecoveryStage::MapperClosed,
            SessionRecoveryStage::ProvisioningReleased,
            SessionRecoveryStage::JailRemoved,
        ] {
            lease = journal
                .checkpoint(&lease, stage)
                .expect("ordered recovery checkpoint must commit");
        }
        lease
    }

    fn raw_lease(
        journal: &DurableSessionRecoveryJournal,
        intent: SessionRecoveryIntent,
        stage: SessionRecoveryStage,
        generation: u64,
    ) -> SessionRecoveryLease {
        SessionRecoveryLease {
            intent,
            stage,
            generation,
            journal_identity: journal.journal_identity,
            intent_checksum: intent_checksum(intent),
        }
    }

    fn append_durable(path: &Path, bytes: &[u8]) {
        OpenOptions::new()
            .append(true)
            .open(path)
            .and_then(|mut file| file.write_all(bytes).and_then(|()| file.sync_all()))
            .expect("test suffix must become durable");
    }

    #[test]
    fn cross_process_lock_helper() {
        let Some(path) = std::env::var_os(CHILD_PATH).map(PathBuf::from) else {
            return;
        };
        let ready = PathBuf::from(
            std::env::var_os(CHILD_READY).expect("child ready path must be provided"),
        );
        let release = PathBuf::from(
            std::env::var_os(CHILD_RELEASE).expect("child release path must be provided"),
        );
        let journal =
            DurableSessionRecoveryJournal::open(path).expect("child must own recovery journal");
        fs::write(&ready, b"ready").expect("child must publish readiness");
        for _ in 0..1_000 {
            if release.exists() {
                drop(journal);
                return;
            }
            thread::sleep(Duration::from_millis(10));
        }
        panic!("parent did not release recovery journal child");
    }

    #[test]
    fn stable_sidecar_serializes_same_process_writers() {
        let fixture = JournalFixture::new("same-process");
        let first =
            DurableSessionRecoveryJournal::open(&fixture.path).expect("first writer must open");
        let before = fs::metadata(fixture.lock_path()).expect("stable lock must exist");
        assert!(matches!(
            DurableSessionRecoveryJournal::open(&fixture.path),
            Err(SessionRecoveryError::Locked { .. })
        ));
        drop(first);
        let after = fs::metadata(fixture.lock_path()).expect("stable lock must survive drop");
        #[cfg(unix)]
        assert_eq!((before.dev(), before.ino()), (after.dev(), after.ino()));
        DurableSessionRecoveryJournal::open(&fixture.path)
            .expect("released writer lock must be reusable");
    }

    #[test]
    fn stable_sidecar_serializes_cross_process_writers() {
        let fixture = JournalFixture::new("cross-process");
        let ready = fixture.directory.join("child.ready");
        let release = fixture.directory.join("child.release");
        let mut child = Command::new(std::env::current_exe().expect("test executable must exist"))
            .args([
                "--exact",
                "recovery::tests::cross_process_lock_helper",
                "--nocapture",
            ])
            .env(CHILD_PATH, &fixture.path)
            .env(CHILD_READY, &ready)
            .env(CHILD_RELEASE, &release)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("recovery lock child must start");

        let mut child_ready = false;
        for _ in 0..500 {
            if ready.exists() {
                child_ready = true;
                break;
            }
            if child
                .try_wait()
                .expect("child status must be readable")
                .is_some()
            {
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }
        let contention = child_ready.then(|| {
            DurableSessionRecoveryJournal::open(&fixture.path)
                .expect_err("parent must not bypass child writer")
        });
        fs::write(&release, b"release").expect("parent must release child");
        let output = child.wait_with_output().expect("child must finish");
        assert!(
            child_ready,
            "child did not acquire journal: stdout={}, stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            output.status.success(),
            "child failed: stdout={}, stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(matches!(
            contention,
            Some(SessionRecoveryError::Locked { .. })
        ));
    }

    #[test]
    fn crash_reopen_reconstructs_exact_pending_lease() {
        let fixture = JournalFixture::new("crash-reopen");
        let expected = intent(0x21);
        {
            let mut journal =
                DurableSessionRecoveryJournal::open(&fixture.path).expect("journal must open");
            let lease = journal.prepare(expected).expect("intent must commit");
            let lease = journal
                .checkpoint(&lease, SessionRecoveryStage::IdentityReserved)
                .expect("identity checkpoint must commit");
            journal
                .checkpoint(&lease, SessionRecoveryStage::CgroupEmpty)
                .expect("cgroup checkpoint must commit");
        }

        let mut reopened = DurableSessionRecoveryJournal::open(&fixture.path)
            .expect("complete committed prefix must reopen");
        let pending = reopened.pending().expect("recovery must remain pending");
        assert_eq!(pending.intent(), expected);
        assert_eq!(pending.stage(), SessionRecoveryStage::CgroupEmpty);
        let pending = reopened
            .checkpoint(&pending, SessionRecoveryStage::MapperClosed)
            .expect("recovered exact lease must continue");
        assert_eq!(pending.stage(), SessionRecoveryStage::MapperClosed);
    }

    #[test]
    fn crash_after_intent_reopens_before_identity_reservation() {
        let fixture = JournalFixture::new("intent-crash");
        let expected = intent(0x22);
        {
            let mut journal =
                DurableSessionRecoveryJournal::open(&fixture.path).expect("journal must open");
            journal.prepare(expected).expect("intent must commit");
        }
        let mut reopened = DurableSessionRecoveryJournal::open(&fixture.path)
            .expect("intent-only history must reopen");
        let pending = reopened
            .pending()
            .expect("intent must require reconciliation");
        assert_eq!(pending.stage(), SessionRecoveryStage::Intent);
        assert_eq!(pending.intent().identities().len(), IDENTITY_COUNT);
        reopened
            .abandon(&pending)
            .expect("ledger-absent intent must become terminal");
        assert_eq!(reopened.pending(), None);
        assert_eq!(reopened.identity_reserved_intent_count(), 0);
    }

    #[test]
    fn stages_are_exact_monotone_and_completion_allows_next_generation() {
        let fixture = JournalFixture::new("monotone");
        let mut journal =
            DurableSessionRecoveryJournal::open(&fixture.path).expect("journal must open");
        let first = journal.prepare(intent(0x31)).expect("intent must commit");
        assert!(matches!(
            journal.checkpoint(&first, SessionRecoveryStage::MapperClosed),
            Err(SessionRecoveryError::InvalidStageTransition { .. })
        ));
        let first = journal
            .checkpoint(&first, SessionRecoveryStage::IdentityReserved)
            .expect("first checkpoint must commit");
        assert_eq!(
            journal
                .checkpoint(&first, SessionRecoveryStage::IdentityReserved)
                .expect("same checkpoint must be idempotent"),
            first
        );
        assert!(matches!(
            journal.checkpoint(&first, SessionRecoveryStage::Intent),
            Err(SessionRecoveryError::InvalidStageTransition { .. })
        ));
        assert!(matches!(
            journal.prepare(intent(0x32)),
            Err(SessionRecoveryError::PendingRecovery { .. })
        ));
        let first = checkpoint_through_jail(&mut journal, first);
        journal.complete(&first).expect("completion must commit");
        assert_eq!(journal.pending(), None);
        journal
            .prepare(intent(0x32))
            .expect("next generation must prepare after completion");
    }

    #[test]
    fn completed_history_reopens_without_pending_and_remains_inspectable() {
        let fixture = JournalFixture::new("completed-history");
        let expected = intent(0x35);
        {
            let mut journal =
                DurableSessionRecoveryJournal::open(&fixture.path).expect("journal must open");
            let lease = journal.prepare(expected).expect("intent must commit");
            let lease = checkpoint_through_jail(&mut journal, lease);
            journal.complete(&lease).expect("completion must commit");
        }
        let reopened = DurableSessionRecoveryJournal::open(&fixture.path)
            .expect("completed history must reopen");
        assert_eq!(reopened.pending(), None);
        assert_eq!(reopened.intent_count(), 1);
        assert_eq!(reopened.history()[0].intent(), expected);
        assert_eq!(
            reopened.history()[0].stage(),
            SessionRecoveryStage::Complete
        );
        assert_eq!(
            reopened.identity_reserved_intents().collect::<Vec<_>>(),
            vec![expected]
        );
    }

    #[test]
    fn colliding_later_intent_can_be_abandoned_and_reopened() {
        let fixture = JournalFixture::new("collision-abandon");
        let colliding = intent(0x36);
        {
            let mut journal =
                DurableSessionRecoveryJournal::open(&fixture.path).expect("journal must open");
            let lease = journal
                .prepare(colliding)
                .expect("first intent must commit");
            let lease = checkpoint_through_jail(&mut journal, lease);
            journal
                .complete(&lease)
                .expect("first intent must complete");
            let collision = journal
                .prepare(colliding)
                .expect("pre-ledger collision must remain representable");
            journal
                .abandon(&collision)
                .expect("ledger duplicate must terminate as abandoned");
        }
        let reopened = DurableSessionRecoveryJournal::open(&fixture.path)
            .expect("completed plus abandoned collision must reopen");
        assert_eq!(reopened.pending(), None);
        assert_eq!(reopened.intent_count(), 2);
        assert_eq!(reopened.identity_reserved_intent_count(), 1);
        assert_eq!(
            reopened.history()[1].stage(),
            SessionRecoveryStage::Abandoned
        );
    }

    #[test]
    fn empty_history_is_observable_for_ledger_composition_validation() {
        let fixture = JournalFixture::new("empty-history");
        let journal =
            DurableSessionRecoveryJournal::open(&fixture.path).expect("empty journal must open");
        assert_eq!(journal.intent_count(), 0);
        assert_eq!(journal.identity_reserved_intent_count(), 0);
        assert_eq!(journal.history(), []);
    }

    #[test]
    fn checkpoint_rejects_foreign_exact_lease() {
        let first_fixture = JournalFixture::new("lease-a");
        let second_fixture = JournalFixture::new("lease-b");
        let mut first = DurableSessionRecoveryJournal::open(&first_fixture.path)
            .expect("first journal must open");
        let mut second = DurableSessionRecoveryJournal::open(&second_fixture.path)
            .expect("second journal must open");
        let first_lease = first
            .prepare(intent(0x41))
            .expect("first intent must commit");
        let second_lease = second
            .prepare(intent(0x41))
            .expect("second intent must commit");
        assert!(matches!(
            first.checkpoint(&second_lease, SessionRecoveryStage::CgroupEmpty),
            Err(SessionRecoveryError::StaleLease)
        ));
        first
            .checkpoint(&first_lease, SessionRecoveryStage::IdentityReserved)
            .expect("exact first lease must commit");
    }

    #[test]
    fn journal_path_swap_seals_live_writer() {
        let fixture = JournalFixture::new("path-swap");
        let mut journal =
            DurableSessionRecoveryJournal::open(&fixture.path).expect("journal must open");
        let displaced = fixture.directory.join("displaced.recovery");
        fs::rename(&fixture.path, &displaced).expect("journal path must be displaced");
        fs::copy(&displaced, &fixture.path).expect("replacement journal must be installed");

        assert!(matches!(
            journal.prepare(intent(0x51)),
            Err(SessionRecoveryError::PathIdentityChanged { .. })
        ));
        assert!(matches!(
            journal.prepare(intent(0x52)),
            Err(SessionRecoveryError::Unavailable { .. })
        ));
    }

    #[test]
    fn partial_final_record_is_truncated_and_synced_on_reopen() {
        let fixture = JournalFixture::new("torn-tail");
        drop(DurableSessionRecoveryJournal::open(&fixture.path).expect("empty journal must open"));
        OpenOptions::new()
            .append(true)
            .open(&fixture.path)
            .and_then(|mut file| file.write_all(&[0xaa]).and_then(|()| file.sync_all()))
            .expect("test must append torn tail");
        DurableSessionRecoveryJournal::open(&fixture.path)
            .expect("exclusive writer must discard only the partial final frame");
        assert_eq!(
            fs::metadata(&fixture.path)
                .expect("repaired journal must remain")
                .len(),
            JOURNAL_DATA_OFFSET as u64
        );
    }

    #[test]
    fn complete_valid_tail_is_rolled_forward_before_returning_writer() {
        let fixture = JournalFixture::new("valid-tail");
        let expected = intent(0x61);
        let intent_record = {
            let journal = DurableSessionRecoveryJournal::open(&fixture.path)
                .expect("empty journal must open");
            journal_record(
                raw_lease(&journal, expected, SessionRecoveryStage::Intent, 0),
                0,
            )
        };
        append_durable(&fixture.path, &intent_record);

        let reopened = DurableSessionRecoveryJournal::open(&fixture.path)
            .expect("valid uncommitted record must roll forward");
        let pending = reopened
            .pending()
            .expect("rolled-forward intent must be pending");
        assert_eq!(pending.intent(), expected);
        assert_eq!(pending.stage(), SessionRecoveryStage::Intent);
        assert_eq!(reopened.intent_count(), 1);
        assert_eq!(
            fs::metadata(&fixture.path)
                .expect("journal must exist")
                .len(),
            (JOURNAL_DATA_OFFSET + JOURNAL_RECORD_BYTES) as u64
        );
    }

    #[test]
    fn overlapping_unfinished_intents_are_rejected_on_reopen() {
        let fixture = JournalFixture::new("overlapping-intents");
        let records = {
            let journal = DurableSessionRecoveryJournal::open(&fixture.path)
                .expect("empty journal must open");
            let first = journal_record(
                raw_lease(&journal, intent(0x67), SessionRecoveryStage::Intent, 0),
                0,
            );
            let second = journal_record(
                raw_lease(&journal, intent(0x68), SessionRecoveryStage::Intent, 1),
                1,
            );
            [first.as_slice(), second.as_slice()].concat()
        };
        append_durable(&fixture.path, &records);
        assert!(matches!(
            DurableSessionRecoveryJournal::open(&fixture.path),
            Err(SessionRecoveryError::Corrupt { .. })
        ));
    }

    #[test]
    fn valid_tail_before_partial_frame_rolls_forward_then_truncates() {
        let fixture = JournalFixture::new("valid-and-partial-tail");
        let expected = intent(0x62);
        let intent_record = {
            let journal = DurableSessionRecoveryJournal::open(&fixture.path)
                .expect("empty journal must open");
            journal_record(
                raw_lease(&journal, expected, SessionRecoveryStage::Intent, 0),
                0,
            )
        };
        append_durable(&fixture.path, &intent_record);
        append_durable(&fixture.path, &[0xbb; 17]);

        let reopened = DurableSessionRecoveryJournal::open(&fixture.path)
            .expect("valid prefix plus partial final frame must recover");
        assert_eq!(
            reopened.pending().expect("intent must remain").intent(),
            expected
        );
        assert_eq!(
            fs::metadata(&fixture.path)
                .expect("journal must exist")
                .len(),
            (JOURNAL_DATA_OFFSET + JOURNAL_RECORD_BYTES) as u64
        );
    }

    #[test]
    fn corrupt_complete_tail_frame_fails_closed() {
        let fixture = JournalFixture::new("corrupt-tail");
        let mut record = {
            let journal = DurableSessionRecoveryJournal::open(&fixture.path)
                .expect("empty journal must open");
            journal_record(
                raw_lease(&journal, intent(0x63), SessionRecoveryStage::Intent, 0),
                0,
            )
        };
        record[RECORD_IDENTITY_OFFSET] ^= 0x80;
        append_durable(&fixture.path, &record);
        assert!(matches!(
            DurableSessionRecoveryJournal::open(&fixture.path),
            Err(SessionRecoveryError::Corrupt { .. })
        ));
    }

    #[test]
    fn one_torn_header_slot_falls_back_to_the_other_slot() {
        let fixture = JournalFixture::new("one-torn-header");
        drop(DurableSessionRecoveryJournal::open(&fixture.path).expect("journal must open"));
        let mut file = OpenOptions::new()
            .write(true)
            .open(&fixture.path)
            .expect("journal must be writable by test");
        file.seek(SeekFrom::Start(28))
            .and_then(|_| file.write_all(&[0, 0]).and_then(|()| file.sync_all()))
            .expect("test must tear header checksum");
        DurableSessionRecoveryJournal::open(&fixture.path)
            .expect("the independent second header must remain authoritative");
    }

    #[test]
    fn every_single_header_byte_bitflip_leaves_one_recoverable_slot() {
        for slot in 0..JOURNAL_HEADER_SLOTS {
            for byte in 0..JOURNAL_HEADER_SLOT_BYTES {
                let fixture = JournalFixture::new("header-bitflip");
                let mut journal =
                    DurableSessionRecoveryJournal::open(&fixture.path).expect("journal must open");
                journal.prepare(intent(0x64)).expect("intent must commit");
                drop(journal);
                let offset = u64::try_from(slot * JOURNAL_HEADER_SLOT_BYTES + byte)
                    .expect("header offset fits in u64");
                let mut file = OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(&fixture.path)
                    .expect("journal must be writable by test");
                file.seek(SeekFrom::Start(offset))
                    .expect("test must seek header byte");
                let mut value = [0_u8; 1];
                file.read_exact(&mut value).expect("header byte must exist");
                value[0] ^= 0x80;
                file.seek(SeekFrom::Start(offset))
                    .and_then(|_| file.write_all(&value).and_then(|()| file.sync_all()))
                    .expect("test must flip one header byte");
                drop(file);
                let reopened = DurableSessionRecoveryJournal::open(&fixture.path)
                    .expect("one intact header must recover every one-byte tear");
                assert_eq!(
                    reopened.pending().expect("intent must recover").intent(),
                    intent(0x64)
                );
            }
        }
    }

    #[test]
    fn every_partial_header_overwrite_recovers_from_the_other_slot() {
        for prefix_length in 1..JOURNAL_HEADER_SLOT_BYTES {
            let fixture = JournalFixture::new("header-prefix");
            let mut journal =
                DurableSessionRecoveryJournal::open(&fixture.path).expect("journal must open");
            journal.prepare(intent(0x65)).expect("intent must commit");
            drop(journal);
            let replacement = journal_header(2, 2);
            let mut file = OpenOptions::new()
                .write(true)
                .open(&fixture.path)
                .expect("journal must be writable by test");
            file.seek(SeekFrom::Start(JOURNAL_HEADER_SLOT_BYTES as u64))
                .and_then(|_| {
                    file.write_all(&replacement[..prefix_length])
                        .and_then(|()| file.sync_all())
                })
                .expect("test must partially overwrite active header");
            drop(file);
            let reopened = DurableSessionRecoveryJournal::open(&fixture.path)
                .expect("old header plus complete tail must recover partial header write");
            assert_eq!(
                reopened.pending().expect("intent must recover").intent(),
                intent(0x65)
            );
        }
    }

    #[test]
    fn checkpoint_commits_alternate_header_slots() {
        let fixture = JournalFixture::new("alternating-headers");
        let mut journal =
            DurableSessionRecoveryJournal::open(&fixture.path).expect("journal must open");
        assert_eq!(
            (journal.header_generation, journal.active_header_slot),
            (0, 0)
        );
        let mut lease = journal.prepare(intent(0x66)).expect("intent must commit");
        assert_eq!(
            (journal.header_generation, journal.active_header_slot),
            (1, 1)
        );
        for (generation, slot, stage) in [
            (2, 0, SessionRecoveryStage::IdentityReserved),
            (3, 1, SessionRecoveryStage::CgroupEmpty),
            (4, 0, SessionRecoveryStage::MapperClosed),
            (5, 1, SessionRecoveryStage::ProvisioningReleased),
            (6, 0, SessionRecoveryStage::JailRemoved),
        ] {
            lease = journal
                .checkpoint(&lease, stage)
                .expect("checkpoint must commit through inactive slot");
            assert_eq!(
                (journal.header_generation, journal.active_header_slot),
                (generation, slot)
            );
        }
    }

    #[test]
    fn valid_newer_header_beyond_file_falls_back_to_older_slot() {
        let fixture = JournalFixture::new("future-header");
        drop(DurableSessionRecoveryJournal::open(&fixture.path).expect("journal must open"));
        let future = journal_header(10, 1);
        let mut file = OpenOptions::new()
            .write(true)
            .open(&fixture.path)
            .expect("journal must be writable by test");
        file.seek(SeekFrom::Start(JOURNAL_HEADER_SLOT_BYTES as u64))
            .and_then(|_| file.write_all(&future).and_then(|()| file.sync_all()))
            .expect("test must publish impossible future header");
        drop(file);
        let reopened = DurableSessionRecoveryJournal::open(&fixture.path)
            .expect("older file-consistent header must win");
        assert_eq!(reopened.pending(), None);
        assert_eq!(reopened.header_generation, 0);
        assert_eq!(reopened.active_header_slot, 0);
    }

    #[test]
    fn both_corrupt_header_slots_fail_closed() {
        let fixture = JournalFixture::new("both-headers-corrupt");
        drop(DurableSessionRecoveryJournal::open(&fixture.path).expect("journal must open"));
        let mut file = OpenOptions::new()
            .write(true)
            .open(&fixture.path)
            .expect("journal must be writable by test");
        file.seek(SeekFrom::Start(0))
            .and_then(|_| file.write_all(&[0xff]))
            .and_then(|()| file.seek(SeekFrom::Start(JOURNAL_HEADER_SLOT_BYTES as u64)))
            .and_then(|_| file.write_all(&[0xff]))
            .and_then(|()| file.sync_all())
            .expect("test must corrupt both header slots");
        assert!(matches!(
            DurableSessionRecoveryJournal::open(&fixture.path),
            Err(SessionRecoveryError::Corrupt { .. })
        ));
    }
}
