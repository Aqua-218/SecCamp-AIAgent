//! Transactional host orchestration for one isolated microVM session.
//!
//! The crate owns the lifecycle contract and identity binding between a cloned
//! workspace, one Broker connection, one Firecracker VM, one subject, one root
//! capability, and one released workload. Platform adapters implement the
//! backend traits; this crate keeps the ordering and rollback rules independent
//! from Firecracker, vsock, filesystem, and Authority Core I/O.
//!
//! ## 永続 identity ledger
//!
//! `SessionOrchestrator::new` は既存の contract test と組み込み用途のため、
//! process 内だけで動く `InMemoryIdentityLedger` を使用する。production host
//! は `SessionOrchestrator::new_durable` を使い、専用 ledger file を渡すこと。
//! `DurableIdentityLedger` は exclusive lock を取得し、versioned header と
//! checksummed fixed-size record を全て検証してから開く。session の七つの
//! identity は一つの batch として append され、`sync_data` が成功するまで
//! backend の副作用は開始されない。破損、切断、容量超過、write/sync failure
//! は operator-readable な typed error になり、identity を再利用できるように
//! ledger を修復・切り詰めることは許可しない。

#![forbid(unsafe_code)]

pub mod authority_backend;
pub mod egress_backend;
pub mod firecracker_backend;
pub mod firecracker_identity;
pub mod firecracker_workspace;
pub mod production_runtime;
pub mod session_owner;

use std::{
    collections::BTreeSet,
    error::Error,
    fmt,
    fs::{self, File, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};

/// Width of every cryptographic session-scoped identity.
pub const ID_BYTES: usize = 16;

macro_rules! fixed_identity {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name([u8; ID_BYTES]);

        impl $name {
            /// Creates an identity from exactly 128 bits supplied by the
            /// trusted session identity source.
            #[must_use]
            pub const fn new(bytes: [u8; ID_BYTES]) -> Self {
                Self(bytes)
            }

            /// Returns the identity's fixed-width bytes.
            #[must_use]
            pub const fn as_bytes(self) -> [u8; ID_BYTES] {
                self.0
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

fixed_identity! {
    /// A host identity for one Firecracker microVM.
    VmId
}

fixed_identity! {
    /// A host identity for one orchestrated session.
    SessionId
}

fixed_identity! {
    /// A host identity for one subject inside a session.
    SubjectId
}

fixed_identity! {
    /// A host identity for one workspace clone.
    WorkspaceId
}

fixed_identity! {
    /// A host identity for one root capability issued to a session subject.
    CapabilityId
}

fixed_identity! {
    /// A host identity for one lifecycle or Broker control request.
    RequestId
}

fixed_identity! {
    /// An identity for the snapshot image used as a session source.
    SnapshotId
}

fixed_identity! {
    /// A post-restore identity for one Host Egress Broker connection.
    BrokerSessionId
}

/// The identity domains tracked by the no-reuse ledger.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum IdentityKind {
    /// Firecracker VM identity.
    Vm,
    /// Orchestrated session identity.
    Session,
    /// In-VM subject identity.
    Subject,
    /// Workspace clone identity.
    Workspace,
    /// Root capability identity.
    Capability,
    /// Lifecycle or Broker control request identity.
    Request,
    /// Broker connection identity.
    BrokerSession,
}

impl fmt::Display for IdentityKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Vm => "VM",
            Self::Session => "session",
            Self::Subject => "subject",
            Self::Workspace => "workspace",
            Self::Capability => "capability",
            Self::Request => "request",
            Self::BrokerSession => "Broker session",
        };
        formatter.write_str(name)
    }
}

impl IdentityKind {
    const fn tag(self) -> u8 {
        match self {
            Self::Vm => 1,
            Self::Session => 2,
            Self::Subject => 3,
            Self::Workspace => 4,
            Self::Capability => 5,
            Self::Request => 6,
            Self::BrokerSession => 7,
        }
    }

    const fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            1 => Some(Self::Vm),
            2 => Some(Self::Session),
            3 => Some(Self::Subject),
            4 => Some(Self::Workspace),
            5 => Some(Self::Capability),
            6 => Some(Self::Request),
            7 => Some(Self::BrokerSession),
            _ => None,
        }
    }
}

/// Maximum number of identity records accepted by a durable ledger.
pub const MAX_LEDGER_RECORDS: usize = 1_048_576;

const LEDGER_MAGIC: [u8; 8] = *b"SORLEDG1";
const LEDGER_VERSION: u8 = 1;
const LEDGER_HEADER_BYTES: usize = 32;
const LEDGER_RECORD_BYTES: usize = 32;
const MAX_LEDGER_BYTES: usize = LEDGER_HEADER_BYTES + (MAX_LEDGER_RECORDS * LEDGER_RECORD_BYTES);

/// Operations reported by durable-ledger I/O failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LedgerOperation {
    /// Inspecting the ledger path.
    Metadata,
    /// Opening the ledger file.
    Open,
    /// Creating the ledger header.
    HeaderWrite,
    /// Reading existing ledger bytes.
    Read,
    /// Appending identity records.
    Append,
    /// Synchronizing appended identity records.
    Sync,
    /// Acquiring or writing the ownership lock.
    Lock,
}

impl fmt::Display for LedgerOperation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Metadata => "inspect ledger metadata",
            Self::Open => "open ledger",
            Self::HeaderWrite => "write ledger header",
            Self::Read => "read ledger",
            Self::Append => "append ledger records",
            Self::Sync => "sync ledger data",
            Self::Lock => "acquire ledger lock",
        };
        formatter.write_str(name)
    }
}

/// A typed, operator-readable identity-ledger failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LedgerError {
    /// Another live owner currently holds the ledger lock.
    Locked {
        /// Ledger path whose lock could not be acquired.
        path: PathBuf,
    },
    /// The ledger path or lock path is a symbolic link.
    Symlink {
        /// Rejected path.
        path: PathBuf,
    },
    /// The ledger path exists but is not a regular file.
    NotRegularFile {
        /// Rejected path.
        path: PathBuf,
    },
    /// A filesystem operation failed.
    Io {
        /// Operation that failed.
        operation: LedgerOperation,
        /// Path involved in the operation.
        path: PathBuf,
        /// Original operating-system message.
        message: String,
    },
    /// A write failed after reservation processing began.
    WriteFailed {
        /// Path involved in the write.
        path: PathBuf,
        /// Operator-facing failure detail.
        message: String,
    },
    /// Data synchronization failed after a record append.
    SyncFailed {
        /// Path involved in the synchronization.
        path: PathBuf,
        /// Operator-facing failure detail.
        message: String,
    },
    /// The file is structurally invalid or its checksum does not match.
    Corrupt {
        /// Byte offset at which corruption was found.
        offset: u64,
        /// Operator-facing failure detail.
        reason: String,
    },
    /// The file ends before a complete header or record is available.
    Truncated {
        /// Byte offset at which the incomplete value begins.
        offset: u64,
        /// Number of bytes required to complete the value.
        expected: usize,
        /// Number of bytes available.
        actual: usize,
    },
    /// The file uses a format version this crate does not understand.
    UnsupportedVersion {
        /// Unsupported format version.
        version: u8,
    },
    /// The identity is already committed in this ledger.
    Duplicate {
        /// Identity domain supplied by the caller or record.
        kind: IdentityKind,
        /// Reused 128-bit identity.
        identity: [u8; ID_BYTES],
    },
    /// The bounded ledger capacity would be exceeded.
    CapacityExceeded {
        /// Number of records requested after the append.
        records: u64,
        /// Maximum permitted record count.
        max_records: u64,
    },
    /// The ledger encountered an earlier uncertain write and now fails closed.
    Unavailable {
        /// Reason the ledger cannot safely accept another reservation.
        reason: String,
    },
}

impl LedgerError {
    fn io(operation: LedgerOperation, path: &Path, error: &io::Error) -> Self {
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

impl fmt::Display for LedgerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Locked { path } => {
                write!(formatter, "identity ledger is locked: {}", path.display())
            }
            Self::Symlink { path } => write!(
                formatter,
                "identity ledger path is a symbolic link: {}",
                path.display()
            ),
            Self::NotRegularFile { path } => write!(
                formatter,
                "identity ledger path is not a regular file: {}",
                path.display()
            ),
            Self::Io {
                operation,
                path,
                message,
            } => {
                write!(
                    formatter,
                    "{operation} at {} failed: {message}",
                    path.display()
                )
            }
            Self::WriteFailed { path, message } => {
                write!(
                    formatter,
                    "append ledger records at {} failed: {message}",
                    path.display()
                )
            }
            Self::SyncFailed { path, message } => {
                write!(
                    formatter,
                    "sync ledger data at {} failed: {message}",
                    path.display()
                )
            }
            Self::Corrupt { offset, reason } => {
                write!(
                    formatter,
                    "identity ledger is corrupt at byte {offset}: {reason}"
                )
            }
            Self::Truncated {
                offset,
                expected,
                actual,
            } => write!(
                formatter,
                "identity ledger is truncated at byte {offset}: expected {expected} bytes, found {actual}"
            ),
            Self::UnsupportedVersion { version } => {
                write!(
                    formatter,
                    "identity ledger format version {version} is unsupported"
                )
            }
            Self::Duplicate { kind, identity } => {
                write!(
                    formatter,
                    "identity {kind} {identity:02x?} is already committed"
                )
            }
            Self::CapacityExceeded {
                records,
                max_records,
            } => write!(
                formatter,
                "identity ledger capacity exceeded: {records} records requested, maximum is {max_records}"
            ),
            Self::Unavailable { reason } => {
                write!(
                    formatter,
                    "identity ledger is unavailable and fails closed: {reason}"
                )
            }
        }
    }
}

impl Error for LedgerError {}

/// A batch of identity reservations backed by either memory or durable storage.
pub trait IdentityLedger {
    /// Atomically reserves every supplied identity.
    ///
    /// Implementations must reject duplicates before making a partial
    /// reservation. A successful return means every identity is committed and
    /// safe for a backend effect.
    ///
    /// # Errors
    ///
    /// Returns [`LedgerError`] when a duplicate, capacity, corruption, write,
    /// or synchronization failure prevents a complete reservation.
    fn reserve_batch(
        &mut self,
        identities: &[(IdentityKind, [u8; ID_BYTES])],
    ) -> Result<(), LedgerError>;

    /// Reserves one identity through the same ledger abstraction.
    ///
    /// # Errors
    ///
    /// Returns [`LedgerError`] when the reservation cannot be committed.
    fn reserve(&mut self, kind: IdentityKind, identity: [u8; ID_BYTES]) -> Result<(), LedgerError> {
        self.reserve_batch(&[(kind, identity)])
    }
}

/// The backward-compatible process-local no-reuse ledger.
#[derive(Debug, Default)]
pub struct InMemoryIdentityLedger {
    issued: BTreeSet<[u8; ID_BYTES]>,
}

impl InMemoryIdentityLedger {
    /// Creates an empty process-local ledger.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            issued: BTreeSet::new(),
        }
    }

    fn check_batch(
        &self,
        identities: &[(IdentityKind, [u8; ID_BYTES])],
    ) -> Result<(), LedgerError> {
        let mut pending = BTreeSet::new();
        for (kind, identity) in identities {
            if self.issued.contains(identity) || !pending.insert(*identity) {
                return Err(LedgerError::Duplicate {
                    kind: *kind,
                    identity: *identity,
                });
            }
        }
        Ok(())
    }
}

impl IdentityLedger for InMemoryIdentityLedger {
    fn reserve_batch(
        &mut self,
        identities: &[(IdentityKind, [u8; ID_BYTES])],
    ) -> Result<(), LedgerError> {
        self.check_batch(identities)?;
        self.issued
            .extend(identities.iter().map(|(_, identity)| *identity));
        Ok(())
    }
}

#[derive(Debug)]
struct ExclusiveLedgerLock {
    path: PathBuf,
    _file: File,
}

impl Drop for ExclusiveLedgerLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

/// A versioned, checksummed, process-exclusive durable identity ledger.
#[derive(Debug)]
pub struct DurableIdentityLedger {
    path: PathBuf,
    file: File,
    _lock: ExclusiveLedgerLock,
    issued: BTreeSet<[u8; ID_BYTES]>,
    next_sequence: u64,
    poisoned: bool,
}

/// Backward-compatible name for [`DurableIdentityLedger`].
pub type FileIdentityLedger = DurableIdentityLedger;

impl DurableIdentityLedger {
    /// Opens or creates a durable ledger and acquires exclusive ownership.
    ///
    /// Existing bytes are parsed completely before the ledger is returned.
    /// Symlinks, non-regular files, malformed records, truncation, unsupported
    /// versions, duplicate records, and capacity violations are rejected.
    ///
    /// # Errors
    ///
    /// Returns [`LedgerError`] when ownership cannot be acquired or the file
    /// cannot be safely opened and recovered.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, LedgerError> {
        let path = path.as_ref().to_path_buf();
        validate_ledger_path(&path)?;
        let lock = acquire_ledger_lock(&path)?;
        let existing = fs::symlink_metadata(&path).map(|metadata| metadata.is_file());
        let mut file_options = OpenOptions::new();
        file_options.read(true).write(true);
        let (mut file, created) = match existing {
            Ok(true) => file_options
                .open(&path)
                .map(|file| (file, false))
                .map_err(|error| LedgerError::io(LedgerOperation::Open, &path, &error))?,
            Ok(false) => {
                return Err(LedgerError::NotRegularFile { path });
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => file_options
                .create_new(true)
                .open(&path)
                .map(|file| (file, true))
                .map_err(|error| LedgerError::io(LedgerOperation::Open, &path, &error))?,
            Err(error) => {
                return Err(LedgerError::io(LedgerOperation::Metadata, &path, &error));
            }
        };

        reject_non_regular_or_symlink(&path, &file)?;
        if created {
            let header = ledger_header(0, LEDGER_HEADER_BYTES as u64);
            file.write_all(&header)
                .map_err(|error| LedgerError::WriteFailed {
                    path: path.clone(),
                    message: error.to_string(),
                })?;
            file.sync_data().map_err(|error| LedgerError::SyncFailed {
                path: path.clone(),
                message: error.to_string(),
            })?;
            Ok(Self {
                path,
                file,
                _lock: lock,
                issued: BTreeSet::new(),
                next_sequence: 0,
                poisoned: false,
            })
        } else {
            let mut bytes = Vec::new();
            file.read_to_end(&mut bytes)
                .map_err(|error| LedgerError::io(LedgerOperation::Read, &path, &error))?;
            let (issued, next_sequence) = parse_ledger(&bytes)?;
            Ok(Self {
                path,
                file,
                _lock: lock,
                issued,
                next_sequence,
                poisoned: false,
            })
        }
    }

    /// Returns the path of the owned ledger file.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Returns the number of committed identity records.
    #[must_use]
    pub fn committed_count(&self) -> usize {
        self.issued.len()
    }

    /// Reports whether a 128-bit value is already committed in this ledger.
    #[must_use]
    pub fn contains(&self, identity: [u8; ID_BYTES]) -> bool {
        self.issued.contains(&identity)
    }
}

impl IdentityLedger for DurableIdentityLedger {
    fn reserve_batch(
        &mut self,
        identities: &[(IdentityKind, [u8; ID_BYTES])],
    ) -> Result<(), LedgerError> {
        if self.poisoned {
            return Err(LedgerError::Unavailable {
                reason: "a previous append or sync failure left file state uncertain".into(),
            });
        }
        let mut pending = BTreeSet::new();
        for (kind, identity) in identities {
            if self.issued.contains(identity) || !pending.insert(*identity) {
                return Err(LedgerError::Duplicate {
                    kind: *kind,
                    identity: *identity,
                });
            }
        }
        let current_records = self.next_sequence;
        let requested_records = u64::try_from(identities.len()).unwrap_or(u64::MAX);
        let new_records = current_records.saturating_add(requested_records);
        let max_records = MAX_LEDGER_RECORDS as u64;
        if new_records > max_records {
            return Err(LedgerError::CapacityExceeded {
                records: new_records,
                max_records,
            });
        }
        let mut encoded = Vec::with_capacity(identities.len() * LEDGER_RECORD_BYTES);
        for (offset, (kind, identity)) in identities.iter().enumerate() {
            let sequence = current_records + offset as u64;
            encoded.extend(ledger_record(*kind, *identity, sequence));
        }
        if encoded.is_empty() {
            return Ok(());
        }
        if let Err(error) = self.file.seek(SeekFrom::End(0)) {
            self.poisoned = true;
            return Err(LedgerError::io(LedgerOperation::Append, &self.path, &error));
        }
        if let Err(error) = self.file.write_all(&encoded) {
            self.poisoned = true;
            return Err(LedgerError::WriteFailed {
                path: self.path.clone(),
                message: error.to_string(),
            });
        }
        // Persist records while the old header still defines the committed
        // prefix. Only after this barrier may the header publish the new
        // record count. A crash can therefore leave an invalid trailing suffix,
        // but can never publish records that were not durably written first.
        if let Err(error) = self.file.sync_data() {
            self.poisoned = true;
            return Err(LedgerError::SyncFailed {
                path: self.path.clone(),
                message: error.to_string(),
            });
        }
        if let Err(error) = self.file.seek(SeekFrom::Start(0)) {
            self.poisoned = true;
            return Err(LedgerError::io(
                LedgerOperation::HeaderWrite,
                &self.path,
                &error,
            ));
        }
        let committed_length =
            LEDGER_HEADER_BYTES as u64 + new_records * LEDGER_RECORD_BYTES as u64;
        let header = ledger_header(new_records, committed_length);
        if let Err(error) = self.file.write_all(&header) {
            self.poisoned = true;
            return Err(LedgerError::WriteFailed {
                path: self.path.clone(),
                message: error.to_string(),
            });
        }
        if let Err(error) = self.file.sync_data() {
            self.poisoned = true;
            return Err(LedgerError::SyncFailed {
                path: self.path.clone(),
                message: error.to_string(),
            });
        }
        // The records and the header are both durable at this point, so the
        // reservation has committed. Commit the in-memory view first: returning
        // Err here would tell the caller the identities are free while they are
        // permanently on disk, and retrying them after a reopen yields
        // Duplicate. A failed reposition still poisons the ledger so no later
        // append writes at an unknown offset.
        self.issued.extend(pending);
        self.next_sequence = new_records;
        if self.file.seek(SeekFrom::End(0)).is_err() {
            self.poisoned = true;
        }
        Ok(())
    }
}

fn validate_ledger_path(path: &Path) -> Result<(), LedgerError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(LedgerError::Symlink {
            path: path.to_path_buf(),
        }),
        Ok(metadata) if !metadata.is_file() => Err(LedgerError::NotRegularFile {
            path: path.to_path_buf(),
        }),
        Ok(_) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(LedgerError::io(LedgerOperation::Metadata, path, &error)),
    }
}

fn reject_non_regular_or_symlink(path: &Path, file: &File) -> Result<(), LedgerError> {
    let link_metadata = fs::symlink_metadata(path)
        .map_err(|error| LedgerError::io(LedgerOperation::Metadata, path, &error))?;
    if link_metadata.file_type().is_symlink() {
        return Err(LedgerError::Symlink {
            path: path.to_path_buf(),
        });
    }
    let metadata = file
        .metadata()
        .map_err(|error| LedgerError::io(LedgerOperation::Metadata, path, &error))?;
    if !metadata.is_file() {
        return Err(LedgerError::NotRegularFile {
            path: path.to_path_buf(),
        });
    }
    let length = metadata.len();
    if length > MAX_LEDGER_BYTES as u64 {
        let records = (length - LEDGER_HEADER_BYTES as u64)
            .saturating_add(LEDGER_RECORD_BYTES as u64 - 1)
            / LEDGER_RECORD_BYTES as u64;
        return Err(LedgerError::CapacityExceeded {
            records,
            max_records: MAX_LEDGER_RECORDS as u64,
        });
    }
    Ok(())
}

fn ledger_lock_path(path: &Path) -> PathBuf {
    let mut lock_path = path.as_os_str().to_os_string();
    lock_path.push(".lock");
    PathBuf::from(lock_path)
}

fn acquire_ledger_lock(path: &Path) -> Result<ExclusiveLedgerLock, LedgerError> {
    let lock_path = ledger_lock_path(path);
    match fs::symlink_metadata(&lock_path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            return Err(LedgerError::Symlink { path: lock_path });
        }
        Ok(_) => {
            if !stale_lock(&lock_path) {
                return Err(LedgerError::Locked {
                    path: path.to_path_buf(),
                });
            }
            fs::remove_file(&lock_path)
                .map_err(|error| LedgerError::io(LedgerOperation::Lock, &lock_path, &error))?;
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(LedgerError::io(LedgerOperation::Lock, &lock_path, &error)),
    }
    let mut file = match OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&lock_path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            return Err(LedgerError::Locked {
                path: path.to_path_buf(),
            });
        }
        Err(error) => return Err(LedgerError::io(LedgerOperation::Lock, &lock_path, &error)),
    };
    let owner = format!("{}\n", std::process::id());
    if let Err(error) = file
        .write_all(owner.as_bytes())
        .and_then(|()| file.sync_data())
    {
        let _ = fs::remove_file(&lock_path);
        return Err(LedgerError::io(LedgerOperation::Lock, &lock_path, &error));
    }
    Ok(ExclusiveLedgerLock {
        path: lock_path,
        _file: file,
    })
}

fn stale_lock(path: &Path) -> bool {
    let Ok(contents) = fs::read_to_string(path) else {
        return false;
    };
    let Ok(pid) = contents.trim().parse::<u32>() else {
        return false;
    };
    #[cfg(target_os = "linux")]
    {
        pid != std::process::id() && fs::metadata(format!("/proc/{pid}")).is_err()
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = pid;
        false
    }
}

fn ledger_header(record_count: u64, data_length: u64) -> [u8; LEDGER_HEADER_BYTES] {
    let mut header = [0_u8; LEDGER_HEADER_BYTES];
    header[..LEDGER_MAGIC.len()].copy_from_slice(&LEDGER_MAGIC);
    header[8] = LEDGER_VERSION;
    header[9] = 32;
    header[12..20].copy_from_slice(&record_count.to_le_bytes());
    header[20..28].copy_from_slice(&data_length.to_le_bytes());
    let header_checksum = checksum(&header[..28]);
    header[28..].copy_from_slice(&header_checksum.to_le_bytes());
    header
}

fn ledger_record(
    kind: IdentityKind,
    identity: [u8; ID_BYTES],
    sequence: u64,
) -> [u8; LEDGER_RECORD_BYTES] {
    let mut record = [0_u8; LEDGER_RECORD_BYTES];
    record[0] = LEDGER_VERSION;
    record[1] = kind.tag();
    record[4..12].copy_from_slice(&sequence.to_le_bytes());
    record[12..28].copy_from_slice(&identity);
    let record_checksum = checksum(&record[..28]);
    record[28..].copy_from_slice(&record_checksum.to_le_bytes());
    record
}

#[allow(clippy::too_many_lines)]
fn parse_ledger(bytes: &[u8]) -> Result<(BTreeSet<[u8; ID_BYTES]>, u64), LedgerError> {
    if bytes.len() < LEDGER_HEADER_BYTES {
        return Err(LedgerError::truncated(0, LEDGER_HEADER_BYTES, bytes.len()));
    }
    if bytes[..LEDGER_MAGIC.len()] != LEDGER_MAGIC {
        return Err(LedgerError::corrupt(0, "header magic does not match"));
    }
    if bytes[8] != LEDGER_VERSION {
        return Err(LedgerError::UnsupportedVersion { version: bytes[8] });
    }
    if bytes[9] as usize != LEDGER_HEADER_BYTES || bytes[10..12] != [0, 0] {
        return Err(LedgerError::corrupt(
            9,
            "invalid header length or reserved bytes",
        ));
    }
    let record_count_u64 = u64::from_le_bytes(bytes[12..20].try_into().expect("fixed header"));
    let data_length = u64::from_le_bytes(bytes[20..28].try_into().expect("fixed header"));
    let expected_checksum = u32::from_le_bytes(bytes[28..32].try_into().expect("fixed header"));
    if checksum(&bytes[..28]) != expected_checksum {
        return Err(LedgerError::corrupt(28, "header checksum mismatch"));
    }
    let max_records = MAX_LEDGER_RECORDS as u64;
    if record_count_u64 > max_records {
        return Err(LedgerError::CapacityExceeded {
            records: record_count_u64,
            max_records,
        });
    }
    let record_count =
        usize::try_from(record_count_u64).map_err(|_| LedgerError::CapacityExceeded {
            records: record_count_u64,
            max_records,
        })?;
    let expected_length = LEDGER_HEADER_BYTES + record_count * LEDGER_RECORD_BYTES;
    if data_length != u64::try_from(expected_length).expect("ledger length fits in u64") {
        return Err(LedgerError::corrupt(
            20,
            "header data length does not match record count",
        ));
    }
    let data_length = usize::try_from(data_length)
        .map_err(|_| LedgerError::corrupt(20, "header data length does not fit host size"))?;
    if bytes.len() < data_length {
        return Err(LedgerError::truncated(
            bytes.len(),
            data_length,
            bytes.len(),
        ));
    }
    if bytes.len() > data_length {
        return Err(LedgerError::corrupt(
            data_length,
            "uncommitted trailing bytes follow the ledger header",
        ));
    }
    let record_bytes = &bytes[LEDGER_HEADER_BYTES..];
    if record_bytes.len() != record_count * LEDGER_RECORD_BYTES {
        return Err(LedgerError::corrupt(
            LEDGER_HEADER_BYTES,
            "record byte length does not match header",
        ));
    }
    let remainder = record_bytes.len() % LEDGER_RECORD_BYTES;
    if remainder != 0 {
        return Err(LedgerError::truncated(
            LEDGER_HEADER_BYTES + record_count * LEDGER_RECORD_BYTES,
            LEDGER_RECORD_BYTES,
            remainder,
        ));
    }
    let mut issued = BTreeSet::new();
    for (index, record) in record_bytes.chunks_exact(LEDGER_RECORD_BYTES).enumerate() {
        let offset = LEDGER_HEADER_BYTES + index * LEDGER_RECORD_BYTES;
        if record[0] != LEDGER_VERSION {
            return Err(LedgerError::UnsupportedVersion { version: record[0] });
        }
        if record[2..4] != [0, 0] {
            return Err(LedgerError::corrupt(
                offset + 2,
                "record reserved bytes are non-zero",
            ));
        }
        let sequence = u64::from_le_bytes(record[4..12].try_into().expect("fixed record"));
        if sequence != u64::try_from(index).expect("record index fits in u64") {
            return Err(LedgerError::corrupt(
                offset + 4,
                "record sequence is not contiguous",
            ));
        }
        let Some(kind) = IdentityKind::from_tag(record[1]) else {
            return Err(LedgerError::corrupt(offset + 1, "unknown identity kind"));
        };
        let expected_checksum =
            u32::from_le_bytes(record[28..32].try_into().expect("fixed record"));
        if checksum(&record[..28]) != expected_checksum {
            return Err(LedgerError::corrupt(
                offset + 28,
                "record checksum mismatch",
            ));
        }
        let identity: [u8; ID_BYTES] = record[12..28].try_into().expect("fixed identity");
        if !issued.insert(identity) {
            return Err(LedgerError::Duplicate { kind, identity });
        }
    }
    Ok((issued, record_count as u64))
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

/// A cryptographic random source used for every session-scoped identity.
pub trait CryptographicRandom {
    /// Returns fresh cryptographic random bytes.
    ///
    /// Implementations must use an operating-system CSPRNG or a stronger
    /// source. Deterministic implementations are intended only for tests.
    ///
    /// # Errors
    ///
    /// Returns [`EntropyError`] when the source cannot provide random bytes.
    fn random_128(&mut self) -> Result<[u8; ID_BYTES], EntropyError>;
}

/// An operating-system random source for production host use.
#[derive(Debug, Default)]
pub struct OsEntropy;

impl CryptographicRandom for OsEntropy {
    fn random_128(&mut self) -> Result<[u8; ID_BYTES], EntropyError> {
        let mut bytes = [0_u8; ID_BYTES];
        let mut random = File::open("/dev/urandom").map_err(EntropyError::from_io)?;
        random
            .read_exact(&mut bytes)
            .map_err(EntropyError::from_io)?;
        Ok(bytes)
    }
}

/// A failure to obtain cryptographic identity material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntropyError {
    message: String,
}

impl EntropyError {
    /// Creates an entropy failure with an operator-facing message.
    #[must_use]
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    #[allow(clippy::needless_pass_by_value)]
    fn from_io(error: io::Error) -> Self {
        Self::new(format!("OS entropy source failed: {error}"))
    }

    /// Returns the failure message.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for EntropyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl Error for EntropyError {}

/// A snapshot descriptor that is safe to restore for a new session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotDescriptor {
    snapshot_id: SnapshotId,
    inherited_ids: Vec<SnapshotIdentity>,
}

impl SnapshotDescriptor {
    /// Creates a descriptor for a snapshot that contains no session state.
    #[must_use]
    pub const fn clean(snapshot_id: SnapshotId) -> Self {
        Self {
            snapshot_id,
            inherited_ids: Vec::new(),
        }
    }

    /// Creates a descriptor including identities observed in a restored image.
    ///
    /// The orchestrator rejects such a descriptor. This constructor exists so
    /// restore validation can be tested without a Firecracker process.
    #[must_use]
    pub fn with_inherited_ids(
        snapshot_id: SnapshotId,
        inherited_ids: impl IntoIterator<Item = SnapshotIdentity>,
    ) -> Self {
        Self {
            snapshot_id,
            inherited_ids: inherited_ids.into_iter().collect(),
        }
    }

    /// Returns the source snapshot identity.
    #[must_use]
    pub const fn snapshot_id(&self) -> SnapshotId {
        self.snapshot_id
    }

    /// Returns identities that were present in the restored image.
    #[must_use]
    pub fn inherited_ids(&self) -> &[SnapshotIdentity] {
        &self.inherited_ids
    }
}

/// A typed identity found in a snapshot image.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SnapshotIdentity {
    kind: IdentityKind,
    bytes: [u8; ID_BYTES],
}

impl SnapshotIdentity {
    /// Creates a snapshot identity marker for restore validation.
    #[must_use]
    pub const fn new(kind: IdentityKind, bytes: [u8; ID_BYTES]) -> Self {
        Self { kind, bytes }
    }

    /// Returns the identity domain.
    #[must_use]
    pub const fn kind(self) -> IdentityKind {
        self.kind
    }

    /// Returns the identity bytes.
    #[must_use]
    pub const fn bytes(self) -> [u8; ID_BYTES] {
        self.bytes
    }
}

/// An opaque workspace template identity supplied by the host.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct WorkspaceTemplateId(String);

impl WorkspaceTemplateId {
    /// Creates a workspace template identity.
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Returns the host-assigned template identity.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// All identities that bind the resources of one session.
#[allow(clippy::struct_field_names)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionIdentity {
    session_id: SessionId,
    request_id: RequestId,
    vm_id: VmId,
    subject_id: SubjectId,
    workspace_id: WorkspaceId,
    broker_session_id: BrokerSessionId,
    capability_id: CapabilityId,
}

impl SessionIdentity {
    /// Returns the orchestrated session identity.
    #[must_use]
    pub const fn session_id(self) -> SessionId {
        self.session_id
    }

    /// Returns the lifecycle request identity.
    #[must_use]
    pub const fn request_id(self) -> RequestId {
        self.request_id
    }

    /// Returns the Firecracker VM identity.
    #[must_use]
    pub const fn vm_id(self) -> VmId {
        self.vm_id
    }

    /// Returns the in-VM subject identity.
    #[must_use]
    pub const fn subject_id(self) -> SubjectId {
        self.subject_id
    }

    /// Returns the clone-specific workspace identity.
    #[must_use]
    pub const fn workspace_id(self) -> WorkspaceId {
        self.workspace_id
    }

    /// Returns the post-restore Broker connection identity.
    #[must_use]
    pub const fn broker_session_id(self) -> BrokerSessionId {
        self.broker_session_id
    }

    /// Returns the root capability identity.
    #[must_use]
    pub const fn capability_id(self) -> CapabilityId {
        self.capability_id
    }
}

/// A workspace resource bound to exactly one session and clone identity.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct WorkspaceLease {
    session_id: SessionId,
    workspace_id: WorkspaceId,
}

impl WorkspaceLease {
    /// Creates a backend lease after a clone has been committed.
    #[must_use]
    pub const fn new(session_id: SessionId, workspace_id: WorkspaceId) -> Self {
        Self {
            session_id,
            workspace_id,
        }
    }

    /// Returns the owning session.
    #[must_use]
    pub const fn session_id(&self) -> SessionId {
        self.session_id
    }

    /// Returns the clone identity.
    #[must_use]
    pub const fn workspace_id(&self) -> WorkspaceId {
        self.workspace_id
    }
}

/// A Broker connection bound to exactly one session.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct BrokerLease {
    session_id: SessionId,
    broker_session_id: BrokerSessionId,
}

impl BrokerLease {
    /// Creates a backend lease after Broker session establishment.
    #[must_use]
    pub const fn new(session_id: SessionId, broker_session_id: BrokerSessionId) -> Self {
        Self {
            session_id,
            broker_session_id,
        }
    }

    /// Returns the owning orchestrated session.
    #[must_use]
    pub const fn session_id(&self) -> SessionId {
        self.session_id
    }

    /// Returns the post-restore Broker connection identity.
    #[must_use]
    pub const fn broker_session_id(&self) -> BrokerSessionId {
        self.broker_session_id
    }
}

/// A Firecracker VM resource bound to its workspace and Broker connection.
#[allow(clippy::struct_field_names)]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct VmLease {
    session_id: SessionId,
    vm_id: VmId,
    workspace_id: WorkspaceId,
    broker_session_id: BrokerSessionId,
}

impl VmLease {
    /// Creates a backend lease after Firecracker has started.
    #[must_use]
    pub const fn new(
        session_id: SessionId,
        vm_id: VmId,
        workspace_id: WorkspaceId,
        broker_session_id: BrokerSessionId,
    ) -> Self {
        Self {
            session_id,
            vm_id,
            workspace_id,
            broker_session_id,
        }
    }

    /// Returns the owning session.
    #[must_use]
    pub const fn session_id(&self) -> SessionId {
        self.session_id
    }

    /// Returns the VM identity.
    #[must_use]
    pub const fn vm_id(&self) -> VmId {
        self.vm_id
    }

    /// Returns the attached workspace identity.
    #[must_use]
    pub const fn workspace_id(&self) -> WorkspaceId {
        self.workspace_id
    }

    /// Returns the attached Broker session identity.
    #[must_use]
    pub const fn broker_session_id(&self) -> BrokerSessionId {
        self.broker_session_id
    }
}

/// A root capability resource bound to one session subject.
#[allow(clippy::struct_field_names)]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CapabilityLease {
    session_id: SessionId,
    subject_id: SubjectId,
    capability_id: CapabilityId,
}

impl CapabilityLease {
    /// Creates a backend lease after root capability injection.
    #[must_use]
    pub const fn new(
        session_id: SessionId,
        subject_id: SubjectId,
        capability_id: CapabilityId,
    ) -> Self {
        Self {
            session_id,
            subject_id,
            capability_id,
        }
    }

    /// Returns the owning session.
    #[must_use]
    pub const fn session_id(&self) -> SessionId {
        self.session_id
    }

    /// Returns the subject holding the capability.
    #[must_use]
    pub const fn subject_id(&self) -> SubjectId {
        self.subject_id
    }

    /// Returns the root capability identity.
    #[must_use]
    pub const fn capability_id(&self) -> CapabilityId {
        self.capability_id
    }
}

/// A released workload bound to one VM, subject, and root capability.
#[allow(clippy::struct_field_names)]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct WorkloadLease {
    session_id: SessionId,
    vm_id: VmId,
    subject_id: SubjectId,
    capability_id: CapabilityId,
}

impl WorkloadLease {
    /// Creates a backend lease after workload release.
    #[must_use]
    pub const fn new(
        session_id: SessionId,
        vm_id: VmId,
        subject_id: SubjectId,
        capability_id: CapabilityId,
    ) -> Self {
        Self {
            session_id,
            vm_id,
            subject_id,
            capability_id,
        }
    }

    /// Returns the owning session.
    #[must_use]
    pub const fn session_id(&self) -> SessionId {
        self.session_id
    }

    /// Returns the VM identity.
    #[must_use]
    pub const fn vm_id(&self) -> VmId {
        self.vm_id
    }

    /// Returns the released subject identity.
    #[must_use]
    pub const fn subject_id(&self) -> SubjectId {
        self.subject_id
    }

    /// Returns the injected root capability identity.
    #[must_use]
    pub const fn capability_id(&self) -> CapabilityId {
        self.capability_id
    }
}

/// A backend error normalized at the orchestration boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackendError {
    message: String,
}

impl BackendError {
    /// Creates a backend failure with its original operator-facing context.
    #[must_use]
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    /// Returns the backend failure message.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for BackendError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl Error for BackendError {}

/// Clones and later isolates a workspace for one session.
pub trait WorkspaceBackend {
    /// Creates a clone with the requested workspace identity.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] if cloning or lease creation fails.
    fn clone_workspace(
        &mut self,
        identity: &SessionIdentity,
        template: &WorkspaceTemplateId,
    ) -> Result<WorkspaceLease, BackendError>;

    /// Makes the clone unavailable for reuse and releases its host resources.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] if isolation cannot be committed.
    fn isolate_workspace(&mut self, lease: &WorkspaceLease) -> Result<(), BackendError>;
}

/// Establishes and closes one post-restore Host Egress Broker connection.
pub trait BrokerBackend {
    /// Establishes the requested Broker session identity.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] if the post-restore connection cannot be established.
    fn establish_broker_session(
        &mut self,
        identity: &SessionIdentity,
    ) -> Result<BrokerLease, BackendError>;

    /// Verifies that the exact Broker service is still running.
    ///
    /// This check is performed after capability injection and immediately
    /// before workload release. Implementations must reject foreign, closed,
    /// and already-exited leases; returning success without observing the
    /// owned service is not permitted.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] unless `lease` names the exact live service.
    fn ensure_broker_session_running(&mut self, lease: &BrokerLease) -> Result<(), BackendError>;

    /// Closes one Broker connection. The operation must be idempotent.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] if the connection cannot be closed.
    fn close_broker_session(&mut self, lease: &BrokerLease) -> Result<(), BackendError>;
}

/// Starts and kills exactly one Firecracker VM per session.
pub trait VmBackend {
    /// Starts Firecracker with the exact snapshot, workspace, and Broker bindings.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] if Firecracker cannot start with the requested bindings.
    fn start_vm(
        &mut self,
        snapshot: &SnapshotDescriptor,
        identity: &SessionIdentity,
        workspace: &WorkspaceLease,
        broker: &BrokerLease,
    ) -> Result<VmLease, BackendError>;

    /// Cleans up backend state left by a failed [`Self::start_vm`] attempt
    /// that did not return a lease. The operation must be idempotent.
    ///
    /// Backends whose failed startup is effect-free may use the default no-op.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] if failed-start cleanup cannot be committed.
    fn cleanup_failed_start(&mut self) -> Result<(), BackendError> {
        Ok(())
    }

    /// Kills the VM and all workload processes. The operation must be idempotent.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] if the VM cannot be killed.
    fn kill_vm(&mut self, lease: &VmLease) -> Result<(), BackendError>;
}

/// Revokes a subject's root capability during rollback and stop.
pub trait CapabilityRevocationBackend {
    /// Revokes the root capability. The operation must be idempotent.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] if revocation cannot be committed.
    fn revoke_root_capability(&mut self, lease: &CapabilityLease) -> Result<(), BackendError>;
}

/// Registers a subject and injects its typed root capability.
pub trait CapabilityBackend<G>: CapabilityRevocationBackend {
    /// Registers the subject and injects the typed root capability.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] if subject registration or capability injection fails.
    fn inject_root_capability(
        &mut self,
        identity: &SessionIdentity,
        grant: &G,
    ) -> Result<CapabilityLease, BackendError>;
}

/// Applies the final restrictions and releases the workload into one VM.
pub trait WorkloadBackend {
    /// Releases the workload only after the VM, subject, and capability are bound.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] if the final restriction or release cannot be committed.
    fn release_workload(
        &mut self,
        identity: &SessionIdentity,
        vm: &VmLease,
        capability: &CapabilityLease,
    ) -> Result<WorkloadLease, BackendError>;
}

/// The observable lifecycle phases of one orchestrated session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LifecycleState {
    /// No session resources are active.
    Ready,
    /// Workspace clone committed.
    WorkspaceCloned,
    /// Broker session committed.
    BrokerEstablished,
    /// Firecracker VM committed.
    VmStarted,
    /// Root capability injection committed.
    RootCapabilityInjected,
    /// Workload release committed.
    WorkloadReleased,
    /// All startup stages committed and workload is running.
    Running,
    /// Stop cleanup is in progress or awaiting retry.
    Stopping,
    /// The most recent session reached terminal cleanup.
    Closed,
}

impl fmt::Display for LifecycleState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Ready => "ready",
            Self::WorkspaceCloned => "workspace-cloned",
            Self::BrokerEstablished => "broker-established",
            Self::VmStarted => "vm-started",
            Self::RootCapabilityInjected => "root-capability-injected",
            Self::WorkloadReleased => "workload-released",
            Self::Running => "running",
            Self::Stopping => "stopping",
            Self::Closed => "closed",
        };
        formatter.write_str(name)
    }
}

/// Startup stages used in errors and rollback reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StartStage {
    /// Snapshot restore validation.
    SnapshotRestore,
    /// Cryptographic identity allocation.
    IdentityAllocation,
    /// Workspace cloning.
    WorkspaceClone,
    /// Broker session establishment.
    BrokerEstablishment,
    /// Firecracker startup.
    VmStart,
    /// Root capability injection.
    RootCapabilityInjection,
    /// Workload release.
    WorkloadRelease,
}

/// Cleanup stages used in rollback and stop errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CleanupStage {
    /// Root capability revocation.
    CapabilityRevoke,
    /// Firecracker VM kill.
    VmKill,
    /// Broker session close.
    BrokerClose,
    /// Workspace isolation.
    WorkspaceIsolation,
}

/// Resource kinds used when a backend returns an incorrectly bound lease.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ResourceKind {
    /// Workspace resource.
    Workspace,
    /// Broker connection.
    Broker,
    /// VM resource.
    Vm,
    /// Capability resource.
    Capability,
    /// Workload resource.
    Workload,
}

/// Why startup failed before or during one stage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StartFailure {
    /// The caller attempted a second active session.
    InvalidState(LifecycleState),
    /// The restored image contained session-scoped identity state.
    SnapshotContainsSessionIdentity {
        /// Source snapshot that was rejected.
        snapshot: SnapshotId,
        /// Identity domain found in the image.
        kind: IdentityKind,
    },
    /// A random identity source failed.
    Entropy(EntropyError),
    /// The identity ledger could not durably reserve the session identities.
    Ledger(LedgerError),
    /// An identity was returned again by the source or restored image.
    IdentityReused(IdentityKind),
    /// A backend failed its stage.
    Backend(BackendError),
    /// A backend returned a lease for another session.
    CrossSessionLease {
        /// Resource whose binding was rejected.
        resource: ResourceKind,
        /// Session requested by the orchestrator.
        expected: SessionId,
        /// Session returned by the backend.
        received: SessionId,
    },
    /// A backend returned a lease with the wrong resource identity.
    LeaseIdentityMismatch(ResourceKind),
}

impl fmt::Display for StartFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidState(state) => write!(formatter, "invalid lifecycle state: {state}"),
            Self::SnapshotContainsSessionIdentity { snapshot, kind } => write!(
                formatter,
                "snapshot {snapshot} contains session-scoped {kind} identity state"
            ),
            Self::Entropy(error) => write!(formatter, "cryptographic entropy unavailable: {error}"),
            Self::Ledger(error) => write!(formatter, "identity ledger reservation failed: {error}"),
            Self::IdentityReused(kind) => write!(formatter, "{kind} identity was already issued"),
            Self::Backend(error) => write!(formatter, "backend failed: {error}"),
            Self::CrossSessionLease {
                resource,
                expected,
                received,
            } => write!(
                formatter,
                "{resource:?} lease belongs to session {received}, expected {expected}"
            ),
            Self::LeaseIdentityMismatch(resource) => {
                write!(
                    formatter,
                    "{resource:?} lease identity does not match the allocation"
                )
            }
        }
    }
}

/// A failed startup and every cleanup failure observed while rolling it back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartError {
    stage: StartStage,
    failure: StartFailure,
    rollback_failures: Vec<CleanupFailure>,
}

impl StartError {
    fn new(stage: StartStage, failure: StartFailure) -> Self {
        Self {
            stage,
            failure,
            rollback_failures: Vec::new(),
        }
    }

    fn with_rollback(
        stage: StartStage,
        failure: StartFailure,
        rollback_failures: Vec<CleanupFailure>,
    ) -> Self {
        Self {
            stage,
            failure,
            rollback_failures,
        }
    }

    /// Returns the stage at which startup failed.
    #[must_use]
    pub const fn stage(&self) -> StartStage {
        self.stage
    }

    /// Returns the primary startup failure.
    #[must_use]
    pub const fn failure(&self) -> &StartFailure {
        &self.failure
    }

    /// Returns cleanup failures observed during rollback.
    #[must_use]
    pub fn rollback_failures(&self) -> &[CleanupFailure] {
        &self.rollback_failures
    }
}

impl fmt::Display for StartError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "session startup failed at {:?}: {}",
            self.stage, self.failure
        )
    }
}

impl Error for StartError {}

/// A cleanup failure with its ordered lifecycle stage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CleanupFailure {
    stage: CleanupStage,
    error: BackendError,
}

impl CleanupFailure {
    /// Returns the cleanup stage that failed.
    #[must_use]
    pub const fn stage(&self) -> CleanupStage {
        self.stage
    }

    /// Returns the backend error.
    #[must_use]
    pub const fn error(&self) -> &BackendError {
        &self.error
    }
}

/// Why stop could not complete.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StopError {
    /// No running or stopping session is available.
    InvalidState(LifecycleState),
    /// One or more cleanup stages failed and remain retryable.
    Cleanup(Vec<CleanupFailure>),
}

impl fmt::Display for StopError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidState(state) => write!(formatter, "cannot stop session in {state} state"),
            Self::Cleanup(failures) => {
                write!(
                    formatter,
                    "session cleanup failed at {} stage(s)",
                    failures.len()
                )
            }
        }
    }
}

impl Error for StopError {}

/// The public identity summary returned after startup commits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionInfo {
    identity: SessionIdentity,
}

impl SessionInfo {
    /// Returns the bound identity set for this session.
    #[must_use]
    pub const fn identity(self) -> SessionIdentity {
        self.identity
    }
}

#[derive(Debug)]
struct ActiveSession {
    info: SessionInfo,
    workspace: WorkspaceLease,
    broker: Option<BrokerLease>,
    vm: Option<VmLease>,
    vm_start_attempted: bool,
    capability: Option<CapabilityLease>,
    cleanup: CleanupProgress,
}

#[derive(Debug, Default)]
#[allow(clippy::struct_excessive_bools)]
struct CleanupProgress {
    capability_revoked: bool,
    vm_killed: bool,
    broker_closed: bool,
    workspace_isolated: bool,
}

impl ActiveSession {
    fn pending(
        info: SessionInfo,
        workspace: WorkspaceLease,
        broker: Option<BrokerLease>,
        vm: Option<VmLease>,
        capability: Option<CapabilityLease>,
    ) -> Self {
        let vm_start_attempted = vm.is_some();
        Self {
            info,
            workspace,
            cleanup: CleanupProgress {
                capability_revoked: capability.is_none(),
                vm_killed: vm.is_none(),
                broker_closed: broker.is_none(),
                workspace_isolated: false,
            },
            broker,
            vm,
            vm_start_attempted,
            capability,
        }
    }

    fn cleanup_complete(&self) -> bool {
        self.cleanup.capability_revoked
            && self.cleanup.vm_killed
            && self.cleanup.broker_closed
            && self.cleanup.workspace_isolated
    }
}

/// A single-session-at-a-time orchestrator with an injectable identity ledger.
#[derive(Debug)]
pub struct SessionOrchestrator<R, L = InMemoryIdentityLedger> {
    random: R,
    ledger: L,
    state: LifecycleState,
    active: Option<ActiveSession>,
}

impl<R> SessionOrchestrator<R, InMemoryIdentityLedger> {
    /// Creates an orchestrator with the supplied cryptographic identity source.
    #[must_use]
    pub const fn new(random: R) -> Self {
        Self {
            random,
            ledger: InMemoryIdentityLedger::new(),
            state: LifecycleState::Ready,
            active: None,
        }
    }
}

impl<R> SessionOrchestrator<R, DurableIdentityLedger> {
    /// Creates an orchestrator backed by an exclusive durable identity ledger.
    ///
    /// The ledger is opened and fully recovered before this method returns.
    /// Every later session allocation appends and data-syncs all seven session
    /// identities before the first backend effect.
    ///
    /// # Errors
    ///
    /// Returns [`LedgerError`] when the ledger cannot be opened, recovered, or
    /// exclusively owned by this orchestrator.
    pub fn new_durable(random: R, path: impl AsRef<Path>) -> Result<Self, LedgerError> {
        Ok(Self::with_ledger(
            random,
            DurableIdentityLedger::open(path)?,
        ))
    }
}

impl<R, L> SessionOrchestrator<R, L> {
    /// Creates an orchestrator with an explicitly supplied identity ledger.
    #[must_use]
    pub fn with_ledger(random: R, ledger: L) -> Self {
        Self {
            random,
            ledger,
            state: LifecycleState::Ready,
            active: None,
        }
    }

    /// Returns the current lifecycle phase.
    #[must_use]
    pub const fn state(&self) -> LifecycleState {
        self.state
    }

    /// Returns the current session summary, if startup committed.
    #[must_use]
    pub fn active_session(&self) -> Option<SessionInfo> {
        (self.state == LifecycleState::Running)
            .then(|| self.active.as_ref().map(|session| session.info))
            .flatten()
    }

    /// Returns the exact Broker lease retained by a running or stopping session.
    ///
    /// This is intentionally read-only: the session owner uses it to bind a
    /// service-status observation to the currently retained resource before
    /// deciding whether cleanup must begin.
    #[must_use]
    pub fn active_broker_lease(&self) -> Option<&BrokerLease> {
        self.active
            .as_ref()
            .and_then(|session| session.broker.as_ref())
    }

    fn finish_failed_start(&mut self, active: ActiveSession, rollback_failures: &[CleanupFailure]) {
        if rollback_failures.is_empty() {
            self.state = LifecycleState::Ready;
            self.active = None;
        } else {
            self.state = LifecycleState::Stopping;
            self.active = Some(active);
        }
    }
}

impl<R, L> SessionOrchestrator<R, L>
where
    R: CryptographicRandom,
    L: IdentityLedger,
{
    /// Starts one isolated session through the required commit order.
    ///
    /// The order is workspace clone, Broker connection, Firecracker VM, root
    /// capability injection, then workload release. Any failure after a
    /// resource commit rolls back later resources in reverse dependency order.
    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    ///
    /// # Errors
    ///
    /// Returns [`StartError`] when snapshot restore, identity allocation, a
    /// backend stage, lease binding, or rollback fails.
    pub fn start_session<W, B, V, C, Work, G>(
        &mut self,
        snapshot: &SnapshotDescriptor,
        workspace_template: &WorkspaceTemplateId,
        grant: &G,
        workspace_backend: &mut W,
        broker_backend: &mut B,
        vm_backend: &mut V,
        capability_backend: &mut C,
        workload_backend: &mut Work,
    ) -> Result<SessionInfo, StartError>
    where
        W: WorkspaceBackend,
        B: BrokerBackend,
        V: VmBackend,
        C: CapabilityBackend<G>,
        Work: WorkloadBackend,
    {
        if self.active.is_some()
            || !matches!(self.state, LifecycleState::Ready | LifecycleState::Closed)
        {
            return Err(StartError::new(
                StartStage::SnapshotRestore,
                StartFailure::InvalidState(self.state),
            ));
        }

        if let Some(inherited) = snapshot.inherited_ids().first() {
            return Err(StartError::new(
                StartStage::SnapshotRestore,
                StartFailure::SnapshotContainsSessionIdentity {
                    snapshot: snapshot.snapshot_id(),
                    kind: inherited.kind(),
                },
            ));
        }

        let identity = self
            .allocate_session_identity()
            .map_err(|failure| StartError::new(StartStage::IdentityAllocation, failure))?;
        let info = SessionInfo { identity };
        let workspace = match workspace_backend.clone_workspace(&identity, workspace_template) {
            Ok(lease) => {
                if let Some(error) = validate_workspace(&identity, &lease) {
                    // `Ok` means the backend effect committed even when the
                    // returned lease is incorrectly bound. Retain that exact
                    // lease until isolation succeeds so stop can retry it.
                    let mut active = ActiveSession::pending(info, lease, None, None, None);
                    let rollback = cleanup_active(
                        &mut active,
                        workspace_backend,
                        broker_backend,
                        vm_backend,
                        capability_backend,
                    );
                    self.finish_failed_start(active, &rollback);
                    return Err(StartError::with_rollback(
                        StartStage::WorkspaceClone,
                        error,
                        rollback,
                    ));
                }
                self.state = LifecycleState::WorkspaceCloned;
                lease
            }
            Err(error) => {
                return Err(StartError::new(
                    StartStage::WorkspaceClone,
                    StartFailure::Backend(error),
                ));
            }
        };
        let mut active = ActiveSession::pending(info, workspace, None, None, None);

        let broker = match broker_backend.establish_broker_session(&identity) {
            Ok(lease) => {
                active.broker = Some(lease.clone());
                active.cleanup.broker_closed = false;
                if let Some(error) = validate_broker(&identity, &lease) {
                    let rollback = cleanup_active(
                        &mut active,
                        workspace_backend,
                        broker_backend,
                        vm_backend,
                        capability_backend,
                    );
                    self.finish_failed_start(active, &rollback);
                    return Err(StartError::with_rollback(
                        StartStage::BrokerEstablishment,
                        error,
                        rollback,
                    ));
                }
                self.state = LifecycleState::BrokerEstablished;
                lease
            }
            Err(error) => {
                let rollback = cleanup_active(
                    &mut active,
                    workspace_backend,
                    broker_backend,
                    vm_backend,
                    capability_backend,
                );
                self.finish_failed_start(active, &rollback);
                return Err(StartError::with_rollback(
                    StartStage::BrokerEstablishment,
                    StartFailure::Backend(error),
                    rollback,
                ));
            }
        };

        active.vm_start_attempted = true;
        active.cleanup.vm_killed = false;
        let vm = match vm_backend.start_vm(snapshot, &identity, &active.workspace, &broker) {
            Ok(lease) => {
                active.vm = Some(lease.clone());
                if let Some(error) = validate_vm(&identity, &lease) {
                    let rollback = cleanup_active(
                        &mut active,
                        workspace_backend,
                        broker_backend,
                        vm_backend,
                        capability_backend,
                    );
                    self.finish_failed_start(active, &rollback);
                    return Err(StartError::with_rollback(
                        StartStage::VmStart,
                        error,
                        rollback,
                    ));
                }
                self.state = LifecycleState::VmStarted;
                lease
            }
            Err(error) => {
                let rollback = cleanup_active(
                    &mut active,
                    workspace_backend,
                    broker_backend,
                    vm_backend,
                    capability_backend,
                );
                self.finish_failed_start(active, &rollback);
                return Err(StartError::with_rollback(
                    StartStage::VmStart,
                    StartFailure::Backend(error),
                    rollback,
                ));
            }
        };

        let capability = match capability_backend.inject_root_capability(&identity, grant) {
            Ok(lease) => {
                active.capability = Some(lease.clone());
                active.cleanup.capability_revoked = false;
                if let Some(error) = validate_capability(&identity, &lease) {
                    let rollback = cleanup_active(
                        &mut active,
                        workspace_backend,
                        broker_backend,
                        vm_backend,
                        capability_backend,
                    );
                    self.finish_failed_start(active, &rollback);
                    return Err(StartError::with_rollback(
                        StartStage::RootCapabilityInjection,
                        error,
                        rollback,
                    ));
                }
                self.state = LifecycleState::RootCapabilityInjected;
                lease
            }
            Err(error) => {
                let rollback = cleanup_active(
                    &mut active,
                    workspace_backend,
                    broker_backend,
                    vm_backend,
                    capability_backend,
                );
                self.finish_failed_start(active, &rollback);
                return Err(StartError::with_rollback(
                    StartStage::RootCapabilityInjection,
                    StartFailure::Backend(error),
                    rollback,
                ));
            }
        };

        if let Err(error) = broker_backend.ensure_broker_session_running(&broker) {
            let rollback = cleanup_active(
                &mut active,
                workspace_backend,
                broker_backend,
                vm_backend,
                capability_backend,
            );
            self.finish_failed_start(active, &rollback);
            return Err(StartError::with_rollback(
                StartStage::WorkloadRelease,
                StartFailure::Backend(error),
                rollback,
            ));
        }

        match workload_backend.release_workload(&identity, &vm, &capability) {
            Ok(lease) => {
                if let Some(error) = validate_workload(&identity, &lease) {
                    let rollback = cleanup_active(
                        &mut active,
                        workspace_backend,
                        broker_backend,
                        vm_backend,
                        capability_backend,
                    );
                    self.finish_failed_start(active, &rollback);
                    return Err(StartError::with_rollback(
                        StartStage::WorkloadRelease,
                        error,
                        rollback,
                    ));
                }
                self.state = LifecycleState::WorkloadReleased;
            }
            Err(error) => {
                let rollback = cleanup_active(
                    &mut active,
                    workspace_backend,
                    broker_backend,
                    vm_backend,
                    capability_backend,
                );
                self.finish_failed_start(active, &rollback);
                return Err(StartError::with_rollback(
                    StartStage::WorkloadRelease,
                    StartFailure::Backend(error),
                    rollback,
                ));
            }
        }
        self.state = LifecycleState::Running;
        self.active = Some(active);
        Ok(info)
    }

    fn draw_identities<const N: usize>(
        &mut self,
        kinds: [IdentityKind; N],
    ) -> Result<[(IdentityKind, [u8; ID_BYTES]); N], StartFailure> {
        let mut identities = [(IdentityKind::Session, [0_u8; ID_BYTES]); N];
        for (slot, kind) in identities.iter_mut().zip(kinds) {
            slot.0 = kind;
            slot.1 = self.random.random_128().map_err(StartFailure::Entropy)?;
        }
        Ok(identities)
    }

    fn allocate_session_identity(&mut self) -> Result<SessionIdentity, StartFailure> {
        // One list, destructured by name. Keeping the kinds and the positional
        // reads as two arrays let a reordering compile while mislabelling every
        // ledger record and assigning each drawn value to the wrong field, and
        // an added kind was silently dropped by `zip`.
        let identities = self.draw_identities([
            IdentityKind::Session,
            IdentityKind::Request,
            IdentityKind::Vm,
            IdentityKind::Subject,
            IdentityKind::Workspace,
            IdentityKind::Capability,
            IdentityKind::BrokerSession,
        ])?;
        self.ledger
            .reserve_batch(&identities)
            .map_err(|error| match error {
                LedgerError::Duplicate { kind, .. } => StartFailure::IdentityReused(kind),
                error => StartFailure::Ledger(error),
            })?;
        let [
            (_, session_bytes),
            (_, request_bytes),
            (_, vm_bytes),
            (_, subject_bytes),
            (_, workspace_bytes),
            (_, capability_bytes),
            (_, broker_session_bytes),
        ] = identities;
        let session_id = SessionId::new(session_bytes);
        let request_id = RequestId::new(request_bytes);
        let vm_id = VmId::new(vm_bytes);
        let subject_id = SubjectId::new(subject_bytes);
        let workspace_id = WorkspaceId::new(workspace_bytes);
        let capability_id = CapabilityId::new(capability_bytes);
        let broker_session_id = BrokerSessionId::new(broker_session_bytes);
        Ok(SessionIdentity {
            session_id,
            request_id,
            vm_id,
            subject_id,
            workspace_id,
            broker_session_id,
            capability_id,
        })
    }

    /// Stops the active session and retries only unfinished cleanup stages.
    ///
    /// Revoke is attempted first, followed by VM kill, Broker close, and
    /// workspace isolation. A failed stop leaves the explicit `Stopping`
    /// state and retains resources so a later call can retry safely.
    ///
    /// # Errors
    ///
    /// Returns [`StopError`] when no active session exists or cleanup remains
    /// incomplete after one retry pass.
    pub fn stop_session<W, B, V, C>(
        &mut self,
        workspace_backend: &mut W,
        broker_backend: &mut B,
        vm_backend: &mut V,
        capability_backend: &mut C,
    ) -> Result<(), StopError>
    where
        W: WorkspaceBackend,
        B: BrokerBackend,
        V: VmBackend,
        C: CapabilityRevocationBackend,
    {
        if self.active.is_none()
            || !matches!(
                self.state,
                LifecycleState::Running | LifecycleState::Stopping
            )
        {
            return Err(StopError::InvalidState(self.state));
        }
        self.state = LifecycleState::Stopping;
        let Some(active) = self.active.as_mut() else {
            return Err(StopError::InvalidState(self.state));
        };
        let failures = cleanup_active(
            active,
            workspace_backend,
            broker_backend,
            vm_backend,
            capability_backend,
        );
        if active.cleanup_complete() {
            self.active = None;
            self.state = LifecycleState::Closed;
            Ok(())
        } else {
            Err(StopError::Cleanup(failures))
        }
    }
}

fn validate_workspace(identity: &SessionIdentity, lease: &WorkspaceLease) -> Option<StartFailure> {
    if lease.session_id() != identity.session_id() {
        return Some(StartFailure::CrossSessionLease {
            resource: ResourceKind::Workspace,
            expected: identity.session_id(),
            received: lease.session_id(),
        });
    }
    (lease.workspace_id() != identity.workspace_id())
        .then_some(StartFailure::LeaseIdentityMismatch(ResourceKind::Workspace))
}

fn validate_broker(identity: &SessionIdentity, lease: &BrokerLease) -> Option<StartFailure> {
    if lease.session_id() != identity.session_id() {
        return Some(StartFailure::CrossSessionLease {
            resource: ResourceKind::Broker,
            expected: identity.session_id(),
            received: lease.session_id(),
        });
    }
    (lease.broker_session_id() != identity.broker_session_id())
        .then_some(StartFailure::LeaseIdentityMismatch(ResourceKind::Broker))
}

fn validate_vm(identity: &SessionIdentity, lease: &VmLease) -> Option<StartFailure> {
    if lease.session_id() != identity.session_id() {
        return Some(StartFailure::CrossSessionLease {
            resource: ResourceKind::Vm,
            expected: identity.session_id(),
            received: lease.session_id(),
        });
    }
    (lease.vm_id() != identity.vm_id()
        || lease.workspace_id() != identity.workspace_id()
        || lease.broker_session_id() != identity.broker_session_id())
    .then_some(StartFailure::LeaseIdentityMismatch(ResourceKind::Vm))
}

fn validate_capability(
    identity: &SessionIdentity,
    lease: &CapabilityLease,
) -> Option<StartFailure> {
    if lease.session_id() != identity.session_id() {
        return Some(StartFailure::CrossSessionLease {
            resource: ResourceKind::Capability,
            expected: identity.session_id(),
            received: lease.session_id(),
        });
    }
    (lease.subject_id() != identity.subject_id()
        || lease.capability_id() != identity.capability_id())
    .then_some(StartFailure::LeaseIdentityMismatch(
        ResourceKind::Capability,
    ))
}

fn validate_workload(identity: &SessionIdentity, lease: &WorkloadLease) -> Option<StartFailure> {
    if lease.session_id() != identity.session_id() {
        return Some(StartFailure::CrossSessionLease {
            resource: ResourceKind::Workload,
            expected: identity.session_id(),
            received: lease.session_id(),
        });
    }
    (lease.vm_id() != identity.vm_id()
        || lease.subject_id() != identity.subject_id()
        || lease.capability_id() != identity.capability_id())
    .then_some(StartFailure::LeaseIdentityMismatch(ResourceKind::Workload))
}

#[allow(clippy::too_many_arguments)]
fn cleanup_active<W, B, V, C>(
    active: &mut ActiveSession,
    workspace_backend: &mut W,
    broker_backend: &mut B,
    vm_backend: &mut V,
    capability_backend: &mut C,
) -> Vec<CleanupFailure>
where
    W: WorkspaceBackend,
    B: BrokerBackend,
    V: VmBackend,
    C: CapabilityRevocationBackend,
{
    let mut failures = Vec::new();

    if !active.cleanup.capability_revoked
        && let Some(capability) = active.capability.as_ref()
    {
        match capability_backend.revoke_root_capability(capability) {
            Ok(()) => active.cleanup.capability_revoked = true,
            Err(error) => failures.push(CleanupFailure {
                stage: CleanupStage::CapabilityRevoke,
                error,
            }),
        }
    }

    if !active.cleanup.vm_killed {
        let result = if let Some(vm) = active.vm.as_ref() {
            vm_backend.kill_vm(vm)
        } else if active.vm_start_attempted {
            vm_backend.cleanup_failed_start()
        } else {
            Ok(())
        };
        match result {
            Ok(()) => active.cleanup.vm_killed = true,
            Err(error) => failures.push(CleanupFailure {
                stage: CleanupStage::VmKill,
                error,
            }),
        }
    }

    if !active.cleanup.broker_closed
        && let Some(broker) = active.broker.as_ref()
    {
        match broker_backend.close_broker_session(broker) {
            Ok(()) => active.cleanup.broker_closed = true,
            Err(error) => failures.push(CleanupFailure {
                stage: CleanupStage::BrokerClose,
                error,
            }),
        }
    }

    if active.cleanup.vm_killed
        && active.cleanup.broker_closed
        && !active.cleanup.workspace_isolated
    {
        match workspace_backend.isolate_workspace(&active.workspace) {
            Ok(()) => active.cleanup.workspace_isolated = true,
            Err(error) => failures.push(CleanupFailure {
                stage: CleanupStage::WorkspaceIsolation,
                error,
            }),
        }
    }

    failures
}

#[cfg(test)]
mod tests {
    use super::*;

    const FOREIGN_SESSION: SessionId = SessionId::new([0xee; ID_BYTES]);

    #[derive(Debug, Default)]
    struct TestRandom(u8);

    impl CryptographicRandom for TestRandom {
        fn random_128(&mut self) -> Result<[u8; ID_BYTES], EntropyError> {
            self.0 = self.0.wrapping_add(1);
            Ok([self.0; ID_BYTES])
        }
    }

    #[derive(Default)]
    struct TestWorkspace {
        mismatch: bool,
        fail_isolate: bool,
        isolated: Vec<WorkspaceLease>,
    }

    impl WorkspaceBackend for TestWorkspace {
        fn clone_workspace(
            &mut self,
            identity: &SessionIdentity,
            _template: &WorkspaceTemplateId,
        ) -> Result<WorkspaceLease, BackendError> {
            Ok(WorkspaceLease::new(
                if self.mismatch {
                    FOREIGN_SESSION
                } else {
                    identity.session_id()
                },
                identity.workspace_id(),
            ))
        }

        fn isolate_workspace(&mut self, lease: &WorkspaceLease) -> Result<(), BackendError> {
            self.isolated.push(lease.clone());
            if self.fail_isolate {
                Err(BackendError::new("workspace isolation failed"))
            } else {
                Ok(())
            }
        }
    }

    #[derive(Default)]
    struct TestBroker {
        mismatch: bool,
        fail_close: bool,
        closed: Vec<BrokerLease>,
    }

    impl BrokerBackend for TestBroker {
        fn establish_broker_session(
            &mut self,
            identity: &SessionIdentity,
        ) -> Result<BrokerLease, BackendError> {
            Ok(BrokerLease::new(
                if self.mismatch {
                    FOREIGN_SESSION
                } else {
                    identity.session_id()
                },
                identity.broker_session_id(),
            ))
        }

        fn ensure_broker_session_running(
            &mut self,
            _lease: &BrokerLease,
        ) -> Result<(), BackendError> {
            Ok(())
        }

        fn close_broker_session(&mut self, lease: &BrokerLease) -> Result<(), BackendError> {
            self.closed.push(lease.clone());
            if self.fail_close {
                Err(BackendError::new("Broker close failed"))
            } else {
                Ok(())
            }
        }
    }

    #[derive(Debug, Clone, Copy, Default)]
    enum FailedStartCleanup {
        #[default]
        Succeed,
        FailOnce,
        AlwaysFail,
    }

    #[derive(Default)]
    struct TestVm {
        mismatch: bool,
        fail_start: bool,
        fail_kill: bool,
        failed_start_cleanup: FailedStartCleanup,
        failed_start_cleanup_calls: usize,
        killed: Vec<VmLease>,
    }

    impl VmBackend for TestVm {
        fn start_vm(
            &mut self,
            _snapshot: &SnapshotDescriptor,
            identity: &SessionIdentity,
            _workspace: &WorkspaceLease,
            _broker: &BrokerLease,
        ) -> Result<VmLease, BackendError> {
            if self.fail_start {
                return Err(BackendError::new("VM start failed"));
            }
            Ok(VmLease::new(
                if self.mismatch {
                    FOREIGN_SESSION
                } else {
                    identity.session_id()
                },
                identity.vm_id(),
                identity.workspace_id(),
                identity.broker_session_id(),
            ))
        }

        fn cleanup_failed_start(&mut self) -> Result<(), BackendError> {
            self.failed_start_cleanup_calls += 1;
            let fail = match self.failed_start_cleanup {
                FailedStartCleanup::Succeed => false,
                FailedStartCleanup::FailOnce => self.failed_start_cleanup_calls == 1,
                FailedStartCleanup::AlwaysFail => true,
            };
            if fail {
                Err(BackendError::new("failed VM start cleanup failed"))
            } else {
                Ok(())
            }
        }

        fn kill_vm(&mut self, lease: &VmLease) -> Result<(), BackendError> {
            self.killed.push(lease.clone());
            if self.fail_kill {
                Err(BackendError::new("VM kill failed"))
            } else {
                Ok(())
            }
        }
    }

    #[derive(Default)]
    struct TestCapability {
        mismatch: bool,
        fail_revoke: bool,
        revoked: Vec<CapabilityLease>,
    }

    impl CapabilityRevocationBackend for TestCapability {
        fn revoke_root_capability(&mut self, lease: &CapabilityLease) -> Result<(), BackendError> {
            self.revoked.push(lease.clone());
            if self.fail_revoke {
                Err(BackendError::new("capability revoke failed"))
            } else {
                Ok(())
            }
        }
    }

    impl CapabilityBackend<()> for TestCapability {
        fn inject_root_capability(
            &mut self,
            identity: &SessionIdentity,
            _grant: &(),
        ) -> Result<CapabilityLease, BackendError> {
            Ok(CapabilityLease::new(
                if self.mismatch {
                    FOREIGN_SESSION
                } else {
                    identity.session_id()
                },
                identity.subject_id(),
                identity.capability_id(),
            ))
        }
    }

    struct TestWorkload;

    impl WorkloadBackend for TestWorkload {
        fn release_workload(
            &mut self,
            identity: &SessionIdentity,
            _vm: &VmLease,
            _capability: &CapabilityLease,
        ) -> Result<WorkloadLease, BackendError> {
            Ok(WorkloadLease::new(
                identity.session_id(),
                identity.vm_id(),
                identity.subject_id(),
                identity.capability_id(),
            ))
        }
    }

    #[derive(Debug, Clone, Copy)]
    enum MismatchCase {
        Workspace,
        Broker,
        Vm,
        Capability,
    }

    fn start(
        orchestrator: &mut SessionOrchestrator<TestRandom>,
        workspace: &mut TestWorkspace,
        broker: &mut TestBroker,
        vm: &mut TestVm,
        capability: &mut TestCapability,
    ) -> Result<SessionInfo, StartError> {
        orchestrator.start_session(
            &SnapshotDescriptor::clean(SnapshotId::new([0xa0; ID_BYTES])),
            &WorkspaceTemplateId::new("test-template"),
            &(),
            workspace,
            broker,
            vm,
            capability,
            &mut TestWorkload,
        )
    }

    fn mismatched_lease_cleanup_is_retryable(case: MismatchCase) {
        let mut workspace = TestWorkspace::default();
        let mut broker = TestBroker::default();
        let mut vm = TestVm::default();
        let mut capability = TestCapability::default();
        let (resource, cleanup_stage) = match case {
            MismatchCase::Workspace => {
                workspace.mismatch = true;
                workspace.fail_isolate = true;
                (ResourceKind::Workspace, CleanupStage::WorkspaceIsolation)
            }
            MismatchCase::Broker => {
                broker.mismatch = true;
                broker.fail_close = true;
                (ResourceKind::Broker, CleanupStage::BrokerClose)
            }
            MismatchCase::Vm => {
                vm.mismatch = true;
                vm.fail_kill = true;
                (ResourceKind::Vm, CleanupStage::VmKill)
            }
            MismatchCase::Capability => {
                capability.mismatch = true;
                capability.fail_revoke = true;
                (ResourceKind::Capability, CleanupStage::CapabilityRevoke)
            }
        };
        let mut orchestrator = SessionOrchestrator::new(TestRandom::default());

        let error = start(
            &mut orchestrator,
            &mut workspace,
            &mut broker,
            &mut vm,
            &mut capability,
        )
        .expect_err("mismatched lease must fail startup");
        assert!(matches!(
            error.failure(),
            StartFailure::CrossSessionLease {
                resource: actual,
                received: FOREIGN_SESSION,
                ..
            } if *actual == resource
        ));
        assert_eq!(error.rollback_failures()[0].stage(), cleanup_stage);
        assert_eq!(orchestrator.state(), LifecycleState::Stopping);

        workspace.fail_isolate = false;
        broker.fail_close = false;
        vm.fail_kill = false;
        capability.fail_revoke = false;
        orchestrator
            .stop_session(&mut workspace, &mut broker, &mut vm, &mut capability)
            .expect("cleanup retry must close the session");
        assert_eq!(orchestrator.state(), LifecycleState::Closed);

        match case {
            MismatchCase::Workspace => assert_eq!(
                workspace
                    .isolated
                    .iter()
                    .map(WorkspaceLease::session_id)
                    .collect::<Vec<_>>(),
                vec![FOREIGN_SESSION, FOREIGN_SESSION]
            ),
            MismatchCase::Broker => assert_eq!(
                broker
                    .closed
                    .iter()
                    .map(BrokerLease::session_id)
                    .collect::<Vec<_>>(),
                vec![FOREIGN_SESSION, FOREIGN_SESSION]
            ),
            MismatchCase::Vm => assert_eq!(
                vm.killed
                    .iter()
                    .map(VmLease::session_id)
                    .collect::<Vec<_>>(),
                vec![FOREIGN_SESSION, FOREIGN_SESSION]
            ),
            MismatchCase::Capability => assert_eq!(
                capability
                    .revoked
                    .iter()
                    .map(CapabilityLease::session_id)
                    .collect::<Vec<_>>(),
                vec![FOREIGN_SESSION, FOREIGN_SESSION]
            ),
        }
    }

    #[test]
    fn mismatched_workspace_lease_cleanup_is_retained_for_retry() {
        mismatched_lease_cleanup_is_retryable(MismatchCase::Workspace);
    }

    #[test]
    fn mismatched_broker_lease_cleanup_is_retained_for_retry() {
        mismatched_lease_cleanup_is_retryable(MismatchCase::Broker);
    }

    #[test]
    fn mismatched_vm_lease_cleanup_is_retained_for_retry() {
        mismatched_lease_cleanup_is_retryable(MismatchCase::Vm);
    }

    #[test]
    fn mismatched_capability_lease_cleanup_is_retained_for_retry() {
        mismatched_lease_cleanup_is_retryable(MismatchCase::Capability);
    }

    #[test]
    fn transient_failed_vm_start_cleanup_is_retried_to_closed() {
        let mut workspace = TestWorkspace::default();
        let mut broker = TestBroker::default();
        let mut vm = TestVm {
            fail_start: true,
            failed_start_cleanup: FailedStartCleanup::FailOnce,
            ..TestVm::default()
        };
        let mut capability = TestCapability::default();
        let mut orchestrator = SessionOrchestrator::new(TestRandom::default());

        let error = start(
            &mut orchestrator,
            &mut workspace,
            &mut broker,
            &mut vm,
            &mut capability,
        )
        .expect_err("VM start must fail");
        assert_eq!(error.rollback_failures()[0].stage(), CleanupStage::VmKill);
        assert_eq!(orchestrator.state(), LifecycleState::Stopping);
        assert!(workspace.isolated.is_empty());

        orchestrator
            .stop_session(&mut workspace, &mut broker, &mut vm, &mut capability)
            .expect("transient failed-start cleanup must be retryable");
        assert_eq!(vm.failed_start_cleanup_calls, 2);
        assert!(vm.killed.is_empty());
        assert_eq!(workspace.isolated.len(), 1);
        assert_eq!(orchestrator.state(), LifecycleState::Closed);
    }

    #[test]
    fn persistent_failed_vm_start_cleanup_remains_stopping() {
        let mut workspace = TestWorkspace::default();
        let mut broker = TestBroker::default();
        let mut vm = TestVm {
            fail_start: true,
            failed_start_cleanup: FailedStartCleanup::AlwaysFail,
            ..TestVm::default()
        };
        let mut capability = TestCapability::default();
        let mut orchestrator = SessionOrchestrator::new(TestRandom::default());

        let start_error = start(
            &mut orchestrator,
            &mut workspace,
            &mut broker,
            &mut vm,
            &mut capability,
        )
        .expect_err("VM start must fail");
        assert_eq!(
            start_error.rollback_failures()[0].stage(),
            CleanupStage::VmKill
        );
        let stop_error = orchestrator
            .stop_session(&mut workspace, &mut broker, &mut vm, &mut capability)
            .expect_err("persistent cleanup failure must remain retryable");
        assert!(matches!(stop_error, StopError::Cleanup(_)));
        assert_eq!(vm.failed_start_cleanup_calls, 2);
        assert!(vm.killed.is_empty());
        assert!(workspace.isolated.is_empty());
        assert_eq!(orchestrator.state(), LifecycleState::Stopping);
    }
}
