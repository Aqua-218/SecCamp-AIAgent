//! Linux backing-root validation and descriptor ownership.

use std::{
    error::Error,
    ffi::OsString,
    fmt, fs, io,
    num::NonZeroUsize,
    os::{
        fd::{AsFd, BorrowedFd},
        unix::ffi::OsStringExt,
    },
    path::{Path, PathBuf},
    sync::Arc,
};

use authority_core::{
    path::{CanonicalPath, InvalidPathSegment},
    repository::RepoId,
};
use rustix::{
    fd::OwnedFd,
    fs::{AtFlags, CWD, Dir, FileType, Mode, OFlags, StatxFlags, openat, openat2, statx},
    io::fcntl_dupfd_cloexec,
};

use crate::namespace::{NamespaceError, NamespaceObjectKind, NamespaceRegistry};

/// Resource bounds applied while validating an untrusted repository tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PreflightLimits {
    max_entries: NonZeroUsize,
    max_depth: usize,
}

impl PreflightLimits {
    /// Creates explicit bounds for manifest entries and repository depth.
    #[must_use]
    pub const fn new(max_entries: NonZeroUsize, max_depth: usize) -> Self {
        Self {
            max_entries,
            max_depth,
        }
    }

    /// Returns the maximum entry count, including the repository root.
    #[must_use]
    pub const fn max_entries(self) -> NonZeroUsize {
        self.max_entries
    }

    /// Returns the maximum number of segments below the repository root.
    #[must_use]
    pub const fn max_depth(self) -> usize {
        self.max_depth
    }
}

/// One validated object in a link-free repository manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepositoryEntry {
    path: CanonicalPath,
    kind: NamespaceObjectKind,
}

impl RepositoryEntry {
    const fn new(path: CanonicalPath, kind: NamespaceObjectKind) -> Self {
        Self { path, kind }
    }

    /// Returns the canonical repository-relative path.
    #[must_use]
    pub const fn path(&self) -> &CanonicalPath {
        &self.path
    }

    /// Returns the namespace kind accepted for this object.
    #[must_use]
    pub const fn kind(&self) -> NamespaceObjectKind {
        self.kind
    }
}

/// A filesystem object kind rejected by the initial link-free model.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RejectedObjectKind {
    /// A symbolic link.
    Symlink,
    /// A FIFO or named pipe.
    Fifo,
    /// A Unix-domain socket.
    Socket,
    /// A character device.
    CharacterDevice,
    /// A block device.
    BlockDevice,
    /// A kernel file type unknown to the scanner.
    Unknown,
}

impl fmt::Display for RejectedObjectKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Symlink => "symbolic link",
            Self::Fifo => "FIFO",
            Self::Socket => "socket",
            Self::CharacterDevice => "character device",
            Self::BlockDevice => "block device",
            Self::Unknown => "unknown object type",
        })
    }
}

/// A failed backing-root open or repository preflight validation.
#[derive(Debug)]
pub enum RepositoryPreflightError {
    /// A Linux filesystem operation failed.
    Io {
        /// The operation that failed.
        operation: &'static str,
        /// The root or repository-relative path being inspected.
        path: PathBuf,
        /// The underlying OS error.
        source: io::Error,
    },
    /// The configured repository root is not a directory.
    RootNotDirectory(PathBuf),
    /// The configured root changed between the no-follow check and fd open.
    RootChangedDuringOpen(PathBuf),
    /// A directory entry changed between metadata inspection and fd open.
    EntryChangedDuringScan(CanonicalPath),
    /// A name cannot be represented by the canonical UTF-8 path model.
    NonUtf8Name {
        /// The canonical parent directory.
        parent: CanonicalPath,
        /// The original non-UTF-8 filename.
        name: OsString,
    },
    /// A UTF-8 name violates the canonical path segment rules.
    InvalidCanonicalPath {
        /// The repository-relative path rejected by validation.
        path: PathBuf,
        /// The segment validation error.
        source: InvalidPathSegment,
    },
    /// The initial link-free model rejects this filesystem object type.
    UnsupportedObject {
        /// The repository-relative path.
        path: CanonicalPath,
        /// The rejected object kind.
        kind: RejectedObjectKind,
    },
    /// A regular file has an inode alias through another hard link.
    HardLink {
        /// The repository-relative path.
        path: CanonicalPath,
        /// The observed inode link count; exactly one is required.
        link_count: u32,
    },
    /// An entry belongs to a mount other than the opened repository root.
    NestedMount(CanonicalPath),
    /// The running kernel did not return a field required for safe validation.
    RequiredMetadataUnavailable {
        /// The path whose metadata was incomplete.
        path: PathBuf,
        /// The missing `statx` field group.
        field: &'static str,
    },
    /// The manifest would exceed the configured entry bound.
    EntryLimitExceeded(NonZeroUsize),
    /// A path exceeds the configured segment-depth bound.
    DepthLimitExceeded {
        /// The first path beyond the bound.
        path: CanonicalPath,
        /// The configured maximum depth.
        limit: usize,
    },
}

impl fmt::Display for RepositoryPreflightError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io {
                operation,
                path,
                source,
            } => write!(
                formatter,
                "failed to {operation} `{}` during repository preflight: {source}",
                path.display()
            ),
            Self::RootNotDirectory(path) => write!(
                formatter,
                "repository root `{}` is not a directory",
                path.display()
            ),
            Self::RootChangedDuringOpen(path) => write!(
                formatter,
                "repository root `{}` changed while its directory fd was opened",
                path.display()
            ),
            Self::EntryChangedDuringScan(path) => write!(
                formatter,
                "repository entry `{}` changed while its directory fd was opened",
                DisplayCanonicalPath(path)
            ),
            Self::NonUtf8Name { parent, name } => write!(
                formatter,
                "repository directory `{}` contains a non-UTF-8 name `{}`",
                DisplayCanonicalPath(parent),
                name.to_string_lossy()
            ),
            Self::InvalidCanonicalPath { path, source } => write!(
                formatter,
                "repository path `{}` is not canonical: {source}",
                path.display()
            ),
            Self::UnsupportedObject { path, kind } => write!(
                formatter,
                "repository path `{}` is a {kind}; only directories and regular files are accepted",
                DisplayCanonicalPath(path)
            ),
            Self::HardLink { path, link_count } => write!(
                formatter,
                "repository file `{}` has link count {link_count}; exactly one path per inode is required",
                DisplayCanonicalPath(path)
            ),
            Self::NestedMount(path) => write!(
                formatter,
                "repository path `{}` crosses into a nested mount",
                DisplayCanonicalPath(path)
            ),
            Self::RequiredMetadataUnavailable { path, field } => write!(
                formatter,
                "kernel metadata `{field}` is unavailable for `{}`; the repository cannot be validated safely",
                path.display()
            ),
            Self::EntryLimitExceeded(limit) => write!(
                formatter,
                "repository contains more than the configured {} entries",
                limit.get()
            ),
            Self::DepthLimitExceeded { path, limit } => write!(
                formatter,
                "repository path `{}` exceeds the configured depth {limit}",
                DisplayCanonicalPath(path)
            ),
        }
    }
}

impl Error for RepositoryPreflightError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::InvalidCanonicalPath { source, .. } => Some(source),
            _ => None,
        }
    }
}

/// A failed repository validation or atomic namespace import.
#[derive(Debug)]
pub enum RepositoryStartupError {
    /// The backing tree did not satisfy the link-free repository contract.
    Preflight(RepositoryPreflightError),
    /// The validated manifest could not initialize the namespace registry.
    Namespace(NamespaceError),
}

impl fmt::Display for RepositoryStartupError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Preflight(error) => write!(formatter, "repository preflight failed: {error}"),
            Self::Namespace(error) => {
                write!(formatter, "repository namespace import failed: {error}")
            }
        }
    }
}

impl Error for RepositoryStartupError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Preflight(error) => Some(error),
            Self::Namespace(error) => Some(error),
        }
    }
}

impl From<RepositoryPreflightError> for RepositoryStartupError {
    fn from(error: RepositoryPreflightError) -> Self {
        Self::Preflight(error)
    }
}

impl From<NamespaceError> for RepositoryStartupError {
    fn from(error: NamespaceError) -> Self {
        Self::Namespace(error)
    }
}

/// An opened repository root that passed the initial link-free preflight.
///
/// The owned directory fd is the anchor for later `openat2` operations. The
/// manifest is a startup snapshot: callers must prevent untrusted backing-tree
/// mutation after validation and route runtime changes through capfs.
#[derive(Debug)]
pub struct ValidatedRepository {
    root_fd: OwnedFd,
    canonical_root: PathBuf,
    root_mount_id: u64,
    entries: Vec<RepositoryEntry>,
}

/// A repository identity, validated backing root, and initialized namespace.
///
/// Keeping all three values under one owner prevents an adapter from pairing a
/// capability for one repository with another backing fd or manifest-derived
/// registry.
#[derive(Debug, Clone)]
pub struct ImportedRepository {
    repository: RepoId,
    backing: Arc<ValidatedRepository>,
    namespace: Arc<NamespaceRegistry>,
}

impl ImportedRepository {
    /// Binds an identity, validates a link-free tree, and imports its manifest.
    ///
    /// Object identities are assigned in deterministic manifest order and are
    /// never derived from paths, so later rename operations do not change them.
    /// The registry is returned only after every manifest entry is accepted.
    ///
    /// # Errors
    ///
    /// Returns [`RepositoryStartupError`] when preflight rejects the backing
    /// tree or the complete manifest cannot initialize one namespace registry.
    pub fn open(
        repository: RepoId,
        root: impl AsRef<Path>,
        limits: PreflightLimits,
    ) -> Result<Self, RepositoryStartupError> {
        Self::from_validated(repository, ValidatedRepository::open(root, limits)?)
    }

    /// Atomically binds and imports a repository that already passed preflight.
    ///
    /// # Errors
    ///
    /// Returns [`RepositoryStartupError::Namespace`] if the validated manifest
    /// cannot initialize a complete namespace registry.
    pub fn from_validated(
        repository: RepoId,
        backing: ValidatedRepository,
    ) -> Result<Self, RepositoryStartupError> {
        let namespace = NamespaceRegistry::from_manifest(
            backing
                .entries()
                .iter()
                .map(|entry| (entry.path().clone(), entry.kind())),
        )?;
        Ok(Self {
            repository,
            backing: Arc::new(backing),
            namespace: Arc::new(namespace),
        })
    }

    /// Returns the host-assigned identity bound to this backing root.
    #[must_use]
    pub const fn repository(&self) -> &RepoId {
        &self.repository
    }

    /// Returns the validated backing root and its owned directory fd.
    #[must_use]
    pub fn backing(&self) -> &ValidatedRepository {
        self.backing.as_ref()
    }

    /// Returns the registry initialized from this backing root's manifest.
    #[must_use]
    pub fn namespace(&self) -> &NamespaceRegistry {
        self.namespace.as_ref()
    }

    /// Separates the identity, backing root, and namespace for an adapter.
    #[must_use]
    pub fn into_parts(self) -> (RepoId, Arc<ValidatedRepository>, Arc<NamespaceRegistry>) {
        (self.repository, self.backing, self.namespace)
    }
}

impl ValidatedRepository {
    /// Opens `root` without following its final component and validates its tree.
    ///
    /// The scan uses fd-relative `statx` and `openat2`, rejects mount crossings,
    /// and returns a deterministic manifest sorted by canonical path.
    ///
    /// # Errors
    ///
    /// Returns [`RepositoryPreflightError`] when the root cannot be opened, a
    /// required kernel metadata field is unavailable, a resource limit is
    /// exceeded, or any entry violates the initial link-free tree model.
    pub fn open(
        root: impl AsRef<Path>,
        limits: PreflightLimits,
    ) -> Result<Self, RepositoryPreflightError> {
        let requested_root = root.as_ref().to_path_buf();
        let checked_root = read_metadata_at(CWD, &requested_root, false, &requested_root)?;
        if checked_root.kind != FileType::Directory {
            if let Some(kind) = rejected_kind(checked_root.kind) {
                return Err(RepositoryPreflightError::UnsupportedObject {
                    path: CanonicalPath::root(),
                    kind,
                });
            }
            return Err(RepositoryPreflightError::RootNotDirectory(requested_root));
        }

        let root_fd = openat(
            CWD,
            &requested_root,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(|error| io_error("open repository root", &requested_root, error))?;
        let opened_root = read_metadata_at(&root_fd, "", true, &requested_root)?;
        if checked_root.identity() != opened_root.identity() {
            return Err(RepositoryPreflightError::RootChangedDuringOpen(
                requested_root,
            ));
        }

        let canonical_root =
            fs::canonicalize(&requested_root).map_err(|error| RepositoryPreflightError::Io {
                operation: "canonicalize repository root",
                path: requested_root.clone(),
                source: error,
            })?;
        let canonical_metadata = read_metadata_at(CWD, &canonical_root, false, &canonical_root)?;
        if canonical_metadata.identity() != opened_root.identity() {
            return Err(RepositoryPreflightError::RootChangedDuringOpen(
                requested_root,
            ));
        }

        let entries = scan_repository(&root_fd, opened_root.mount_id, limits)?;
        Ok(Self {
            root_fd,
            canonical_root,
            root_mount_id: opened_root.mount_id,
            entries,
        })
    }

    /// Returns the canonical path corresponding to the opened root fd.
    #[must_use]
    pub fn canonical_root(&self) -> &Path {
        &self.canonical_root
    }

    /// Returns the root mount identity used to reject nested mounts.
    #[must_use]
    pub const fn root_mount_id(&self) -> u64 {
        self.root_mount_id
    }

    /// Returns the validated root-first, path-sorted manifest.
    #[must_use]
    pub const fn entries(&self) -> &[RepositoryEntry] {
        self.entries.as_slice()
    }

    /// Borrows the directory fd that anchors future backing operations.
    #[must_use]
    pub fn as_fd(&self) -> BorrowedFd<'_> {
        self.root_fd.as_fd()
    }
}

#[derive(Debug, Clone, Copy)]
struct EntryMetadata {
    kind: FileType,
    inode: u64,
    mount_id: u64,
    link_count: u32,
}

impl EntryMetadata {
    const fn identity(self) -> (u64, u64) {
        (self.mount_id, self.inode)
    }
}

struct PendingDirectory {
    fd: OwnedFd,
    segments: Vec<String>,
}

fn scan_repository(
    root_fd: &OwnedFd,
    root_mount_id: u64,
    limits: PreflightLimits,
) -> Result<Vec<RepositoryEntry>, RepositoryPreflightError> {
    let scan_root = fcntl_dupfd_cloexec(root_fd, 0)
        .map_err(|error| io_error("duplicate repository root fd", Path::new("/"), error))?;
    let mut pending = vec![PendingDirectory {
        fd: scan_root,
        segments: Vec::new(),
    }];
    let mut entries = vec![RepositoryEntry::new(
        CanonicalPath::root(),
        NamespaceObjectKind::Directory,
    )];

    while let Some(directory) = pending.pop() {
        scan_directory(directory, root_mount_id, limits, &mut entries, &mut pending)?;
    }

    entries.sort_by(|left, right| left.path.as_segments().cmp(right.path.as_segments()));
    Ok(entries)
}

fn scan_directory(
    directory: PendingDirectory,
    root_mount_id: u64,
    limits: PreflightLimits,
    entries: &mut Vec<RepositoryEntry>,
    pending: &mut Vec<PendingDirectory>,
) -> Result<(), RepositoryPreflightError> {
    let parent_path = canonical_path(&directory.segments)?;
    let mut directory_stream = Dir::new(directory.fd)
        .map_err(|error| io_error("read repository directory", &path_buf(&parent_path), error))?;

    while let Some(entry) = directory_stream.read() {
        let entry = entry.map_err(|error| {
            io_error(
                "read repository directory entry",
                &path_buf(&parent_path),
                error,
            )
        })?;
        let name_bytes = entry.file_name().to_bytes();
        if name_bytes == b"." || name_bytes == b".." {
            continue;
        }
        let Some(name) = std::str::from_utf8(name_bytes).ok() else {
            return Err(RepositoryPreflightError::NonUtf8Name {
                parent: parent_path,
                name: OsString::from_vec(name_bytes.to_vec()),
            });
        };
        let mut segments = directory.segments.clone();
        segments.push(name.to_owned());
        let path = canonical_path(&segments)?;
        if segments.len() > limits.max_depth {
            return Err(RepositoryPreflightError::DepthLimitExceeded {
                path,
                limit: limits.max_depth,
            });
        }
        if entries.len() >= limits.max_entries.get() {
            return Err(RepositoryPreflightError::EntryLimitExceeded(
                limits.max_entries,
            ));
        }

        let directory_fd = directory_stream.fd().map_err(|error| {
            io_error(
                "borrow repository directory fd",
                &path_buf(&parent_path),
                error,
            )
        })?;
        let metadata = read_metadata_at(directory_fd, entry.file_name(), false, &path_buf(&path))?;
        validate_entry_metadata(path.clone(), metadata, root_mount_id)?;

        let kind = match metadata.kind {
            FileType::RegularFile => NamespaceObjectKind::RegularFile,
            FileType::Directory => {
                let child_fd = openat2(
                    directory_fd,
                    entry.file_name(),
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                    Mode::empty(),
                    rustix::fs::ResolveFlags::BENEATH
                        | rustix::fs::ResolveFlags::NO_MAGICLINKS
                        | rustix::fs::ResolveFlags::NO_SYMLINKS
                        | rustix::fs::ResolveFlags::NO_XDEV,
                )
                .map_err(|error| io_error("open repository directory", &path_buf(&path), error))?;
                let opened_metadata = read_metadata_at(&child_fd, "", true, &path_buf(&path))?;
                if opened_metadata.identity() != metadata.identity()
                    || opened_metadata.kind != FileType::Directory
                {
                    return Err(RepositoryPreflightError::EntryChangedDuringScan(path));
                }
                pending.push(PendingDirectory {
                    fd: child_fd,
                    segments,
                });
                NamespaceObjectKind::Directory
            }
            _ => {
                return Err(RepositoryPreflightError::UnsupportedObject {
                    path,
                    kind: match rejected_kind(metadata.kind) {
                        Some(kind) => kind,
                        None => RejectedObjectKind::Unknown,
                    },
                });
            }
        };
        entries.push(RepositoryEntry::new(path, kind));
    }

    Ok(())
}

fn read_metadata_at(
    directory: impl AsFd,
    path: impl rustix::path::Arg,
    empty_path: bool,
    diagnostic_path: &Path,
) -> Result<EntryMetadata, RepositoryPreflightError> {
    let mut flags = AtFlags::NO_AUTOMOUNT | AtFlags::SYMLINK_NOFOLLOW;
    if empty_path {
        flags |= AtFlags::EMPTY_PATH;
    }
    let metadata = statx(
        directory,
        path,
        flags,
        StatxFlags::BASIC_STATS | StatxFlags::MNT_ID,
    )
    .map_err(|error| io_error("inspect repository metadata", diagnostic_path, error))?;
    let available = StatxFlags::from_bits_retain(metadata.stx_mask);
    let required = StatxFlags::TYPE | StatxFlags::NLINK | StatxFlags::INO | StatxFlags::MNT_ID;
    if !available.contains(required) {
        return Err(RepositoryPreflightError::RequiredMetadataUnavailable {
            path: diagnostic_path.to_path_buf(),
            field: "type, link count, inode, and mount ID",
        });
    }

    Ok(EntryMetadata {
        kind: FileType::from_raw_mode(metadata.stx_mode.into()),
        inode: metadata.stx_ino,
        mount_id: metadata.stx_mnt_id,
        link_count: metadata.stx_nlink,
    })
}

fn validate_entry_metadata(
    path: CanonicalPath,
    metadata: EntryMetadata,
    root_mount_id: u64,
) -> Result<(), RepositoryPreflightError> {
    if metadata.mount_id != root_mount_id {
        return Err(RepositoryPreflightError::NestedMount(path));
    }
    if metadata.kind == FileType::RegularFile && metadata.link_count != 1 {
        return Err(RepositoryPreflightError::HardLink {
            path,
            link_count: metadata.link_count,
        });
    }
    if let Some(kind) = rejected_kind(metadata.kind) {
        return Err(RepositoryPreflightError::UnsupportedObject { path, kind });
    }
    Ok(())
}

const fn rejected_kind(kind: FileType) -> Option<RejectedObjectKind> {
    match kind {
        FileType::RegularFile | FileType::Directory => None,
        FileType::Symlink => Some(RejectedObjectKind::Symlink),
        FileType::Fifo => Some(RejectedObjectKind::Fifo),
        FileType::Socket => Some(RejectedObjectKind::Socket),
        FileType::CharacterDevice => Some(RejectedObjectKind::CharacterDevice),
        FileType::BlockDevice => Some(RejectedObjectKind::BlockDevice),
        FileType::Unknown => Some(RejectedObjectKind::Unknown),
    }
}

fn canonical_path(segments: &[String]) -> Result<CanonicalPath, RepositoryPreflightError> {
    CanonicalPath::new(segments).map_err(|source| RepositoryPreflightError::InvalidCanonicalPath {
        path: segments.iter().collect(),
        source,
    })
}

fn path_buf(path: &CanonicalPath) -> PathBuf {
    path.as_segments().iter().collect()
}

fn io_error(
    operation: &'static str,
    path: &Path,
    source: rustix::io::Errno,
) -> RepositoryPreflightError {
    RepositoryPreflightError::Io {
        operation,
        path: path.to_path_buf(),
        source: io::Error::from_raw_os_error(source.raw_os_error()),
    }
}

struct DisplayCanonicalPath<'a>(&'a CanonicalPath);

impl fmt::Display for DisplayCanonicalPath<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("/")?;
        let mut segments = self.0.as_segments().iter();
        if let Some(first) = segments.next() {
            formatter.write_str(first)?;
        }
        for segment in segments {
            formatter.write_str("/")?;
            formatter.write_str(segment)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use authority_core::path::CanonicalPath;
    use rustix::fs::FileType;

    use super::{
        EntryMetadata, RejectedObjectKind, RepositoryPreflightError, validate_entry_metadata,
    };

    fn path(segments: &[&str]) -> CanonicalPath {
        CanonicalPath::new(segments).expect("test paths must be canonical")
    }

    #[test]
    fn metadata_validation_rejects_mount_crossing_and_hard_links() {
        assert!(matches!(
            validate_entry_metadata(
                path(&["mounted"]),
                EntryMetadata {
                    kind: FileType::Directory,
                    inode: 7,
                    mount_id: 2,
                    link_count: 1,
                },
                1,
            ),
            Err(RepositoryPreflightError::NestedMount(_))
        ));
        assert!(matches!(
            validate_entry_metadata(
                path(&["aliased.rs"]),
                EntryMetadata {
                    kind: FileType::RegularFile,
                    inode: 8,
                    mount_id: 1,
                    link_count: 2,
                },
                1,
            ),
            Err(RepositoryPreflightError::HardLink { link_count: 2, .. })
        ));
    }

    #[test]
    fn metadata_validation_rejects_every_unsupported_object_kind() {
        let cases = [
            (FileType::Symlink, RejectedObjectKind::Symlink),
            (FileType::Fifo, RejectedObjectKind::Fifo),
            (FileType::Socket, RejectedObjectKind::Socket),
            (
                FileType::CharacterDevice,
                RejectedObjectKind::CharacterDevice,
            ),
            (FileType::BlockDevice, RejectedObjectKind::BlockDevice),
            (FileType::Unknown, RejectedObjectKind::Unknown),
        ];

        for (file_type, expected) in cases {
            let result = validate_entry_metadata(
                path(&["unsupported"]),
                EntryMetadata {
                    kind: file_type,
                    inode: 9,
                    mount_id: 1,
                    link_count: 1,
                },
                1,
            );
            assert!(matches!(
                result,
                Err(RepositoryPreflightError::UnsupportedObject { kind, .. })
                    if kind == expected
            ));
        }
    }
}
