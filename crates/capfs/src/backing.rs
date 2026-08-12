//! Linux backing-root validation and descriptor ownership.

use std::{
    collections::{HashMap, HashSet},
    error::Error,
    ffi::{CStr, OsString},
    fmt, fs,
    fs::File,
    io,
    num::NonZeroUsize,
    os::{
        fd::{AsFd, BorrowedFd},
        unix::ffi::OsStringExt,
    },
    path::{Path, PathBuf},
    sync::{Arc, Mutex, OnceLock},
};

use authority_core::{
    path::{CanonicalPath, InvalidPathSegment},
    repository::RepoId,
};
use rustix::{
    fd::OwnedFd,
    fs::{
        AtFlags, CWD, Dir, FileType, Mode, OFlags, ResolveFlags, StatxFlags, StatxTimestamp,
        Timespec, Timestamps, fchmod, futimens, linkat, openat, openat2, readlinkat, renameat,
        statx, symlinkat, unlinkat,
    },
};

/// Resolve flags shared by every fd-relative preflight open.
///
/// The four are independent: staying beneath the root, refusing symlinks,
/// refusing `/proc` magic links, and refusing a mount crossing each close a
/// different way out of the repository.
const PREFLIGHT_RESOLVE: ResolveFlags = ResolveFlags::BENEATH
    .union(ResolveFlags::NO_MAGICLINKS)
    .union(ResolveFlags::NO_SYMLINKS)
    .union(ResolveFlags::NO_XDEV);

use crate::namespace::{
    AliasGroup, InvalidSymlinkTarget, ManifestEntry, NamespaceError, NamespaceObjectKind,
    NamespaceObjectSpec, NamespaceRegistry, SymlinkTarget,
};

/// The default ceiling on bytes copied to break external hard links.
///
/// Materialization is only reached for inodes that are named outside the
/// repository, which is rare. The bound exists so a hostile tree cannot turn
/// one startup into an unbounded copy.
pub const DEFAULT_MATERIALIZED_ALIAS_BYTES: u64 = 64 * 1024 * 1024;

/// What preflight does with an inode that is also named outside the repository.
///
/// Such an inode is a partial view: capfs can authorize the names it governs
/// and can say nothing about the one it does not. A write through the inside
/// name changes a file reachable under authority capfs cannot check, and
/// removing every inside name leaves the data alive under the outside one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ExternalAliasPolicy {
    /// Refuse the whole repository.
    Reject,
    /// Copy the contents into a fresh inode and move the repository's names
    /// onto that copy, so the repository stops sharing an inode with a name
    /// capfs does not govern.
    ///
    /// The outside name keeps the original inode and is never touched. Names
    /// that alias each other *inside* the repository stay aliases of the copy.
    /// This rewrites the backing tree during startup, which is why the caller
    /// chooses it and why the copied bytes are bounded and reported.
    Materialize {
        /// The most bytes one preflight may copy in total.
        max_total_bytes: u64,
    },
}

/// Resource bounds applied while validating an untrusted repository tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PreflightLimits {
    max_entries: NonZeroUsize,
    max_depth: usize,
    external_aliases: ExternalAliasPolicy,
}

impl PreflightLimits {
    /// Creates explicit bounds for manifest entries and repository depth.
    ///
    /// External hard links are materialized by default: a stray link to a file
    /// outside the repository otherwise makes the whole workspace unusable,
    /// with no way forward except editing the tree by hand.
    #[must_use]
    pub const fn new(max_entries: NonZeroUsize, max_depth: usize) -> Self {
        Self {
            max_entries,
            max_depth,
            external_aliases: ExternalAliasPolicy::Materialize {
                max_total_bytes: DEFAULT_MATERIALIZED_ALIAS_BYTES,
            },
        }
    }

    /// Refuses repositories with external hard links instead of copying.
    ///
    /// Use this where startup must not write to the backing tree at all.
    #[must_use]
    pub const fn rejecting_external_aliases(self) -> Self {
        Self {
            external_aliases: ExternalAliasPolicy::Reject,
            ..self
        }
    }

    /// Replaces the ceiling on bytes copied to break external hard links.
    #[must_use]
    pub const fn with_external_alias_bytes(self, max_total_bytes: u64) -> Self {
        Self {
            external_aliases: ExternalAliasPolicy::Materialize { max_total_bytes },
            ..self
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

    /// Returns how externally aliased inodes are handled.
    #[must_use]
    pub const fn external_aliases(self) -> ExternalAliasPolicy {
        self.external_aliases
    }
}

/// One repository name that was moved onto a private copy of its contents.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaterializedAlias {
    path: CanonicalPath,
    bytes: u64,
    additional_names: usize,
}

impl MaterializedAlias {
    /// Returns the repository-relative path whose inode was replaced.
    #[must_use]
    pub const fn path(&self) -> &CanonicalPath {
        &self.path
    }

    /// Returns how many bytes were copied for it.
    #[must_use]
    pub const fn bytes(&self) -> u64 {
        self.bytes
    }

    /// Returns how many further repository names were moved onto the copy.
    #[must_use]
    pub const fn additional_names(&self) -> usize {
        self.additional_names
    }
}

/// One validated object name in a repository manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepositoryEntry {
    path: CanonicalPath,
    spec: NamespaceObjectSpec,
    inode: u64,
}

impl RepositoryEntry {
    const fn new(path: CanonicalPath, spec: NamespaceObjectSpec, inode: u64) -> Self {
        Self { path, spec, inode }
    }

    /// Returns the canonical repository-relative path.
    #[must_use]
    pub const fn path(&self) -> &CanonicalPath {
        &self.path
    }

    /// Returns the namespace kind accepted for this object.
    #[must_use]
    pub const fn kind(&self) -> NamespaceObjectKind {
        self.spec.kind()
    }

    /// Returns what this name registers, including a symlink's target.
    #[must_use]
    pub const fn spec(&self) -> &NamespaceObjectSpec {
        &self.spec
    }

    /// Returns the backing inode that groups this name with its hard links.
    #[must_use]
    pub const fn inode(&self) -> u64 {
        self.inode
    }
}

/// A filesystem object kind capfs does not model.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RejectedObjectKind {
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
    /// capfs does not model this filesystem object type.
    UnsupportedObject {
        /// The repository-relative path.
        path: CanonicalPath,
        /// The rejected object kind.
        kind: RejectedObjectKind,
    },
    /// An inode has more names than the repository contains.
    ///
    /// The extra name is outside the tree capfs governs, so writing through a
    /// path inside the repository would change a file reachable under authority
    /// capfs cannot see, and removing every repository name would leave the data
    /// alive under that other name.
    ExternalHardLink {
        /// The backing inode with names on both sides of the boundary.
        inode: u64,
        /// The inode's real link count.
        link_count: u32,
        /// Every repository-relative path that names it, in path order.
        names_in_repository: Vec<CanonicalPath>,
    },
    /// Breaking one external hard link would exceed the copy budget.
    MaterializationBudgetExceeded {
        /// The repository-relative path that could not be copied.
        path: CanonicalPath,
        /// How many bytes copying it needs.
        required: u64,
        /// How many bytes of the budget remain.
        remaining: u64,
    },
    /// A symbolic link's target cannot be represented by the namespace model.
    UnsupportedSymlinkTarget {
        /// The repository-relative path of the link.
        path: CanonicalPath,
        /// Why the target was rejected.
        source: InvalidSymlinkTarget,
    },
    /// A symbolic link resolves outside the repository root.
    EscapingSymlinkTarget {
        /// The repository-relative path of the link.
        path: CanonicalPath,
        /// The rejected target.
        target: String,
    },
    /// A symbolic link's target is not valid UTF-8.
    NonUtf8SymlinkTarget {
        /// The repository-relative path of the link.
        path: CanonicalPath,
        /// The original target bytes.
        target: OsString,
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
                "repository path `{}` is a {kind}; only directories, regular files, and symbolic links are accepted",
                DisplayCanonicalPath(path)
            ),
            Self::ExternalHardLink {
                inode,
                link_count,
                names_in_repository,
            } => write!(
                formatter,
                "backing inode {inode} has link count {link_count} but only {} of its names are inside the repository ({})",
                names_in_repository.len(),
                DisplayCanonicalPaths(names_in_repository)
            ),
            Self::MaterializationBudgetExceeded {
                path,
                required,
                remaining,
            } => write!(
                formatter,
                "breaking the external hard link on `{}` needs {required} bytes but only {remaining} remain in the copy budget",
                DisplayCanonicalPath(path)
            ),
            Self::UnsupportedSymlinkTarget { path, source } => write!(
                formatter,
                "repository symbolic link `{}` is unusable: {source}",
                DisplayCanonicalPath(path)
            ),
            Self::EscapingSymlinkTarget { path, target } => write!(
                formatter,
                "repository symbolic link `{}` targets `{target}`, which leaves the repository root",
                DisplayCanonicalPath(path)
            ),
            Self::NonUtf8SymlinkTarget { path, target } => write!(
                formatter,
                "repository symbolic link `{}` has a non-UTF-8 target `{}`",
                DisplayCanonicalPath(path),
                target.to_string_lossy()
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
    /// The backing tree did not satisfy the repository contract.
    Preflight(RepositoryPreflightError),
    /// The validated manifest could not initialize the namespace registry.
    Namespace(NamespaceError),
    /// Another live import owns this repository identity and backing root.
    AlreadyOpen {
        /// The host-assigned repository identity.
        repository: RepoId,
        /// The canonical backing root already held by the process.
        root: PathBuf,
    },
    /// The process-wide repository lease registry cannot be trusted.
    LeaseRegistryUnavailable,
}

impl fmt::Display for RepositoryStartupError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Preflight(error) => write!(formatter, "repository preflight failed: {error}"),
            Self::Namespace(error) => {
                write!(formatter, "repository namespace import failed: {error}")
            }
            Self::AlreadyOpen { repository, root } => write!(
                formatter,
                "repository `{repository}` at `{}` is already open in this process",
                root.display()
            ),
            Self::LeaseRegistryUnavailable => {
                formatter.write_str("process-wide repository lease registry is unavailable")
            }
        }
    }
}

impl Error for RepositoryStartupError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Preflight(error) => Some(error),
            Self::Namespace(error) => Some(error),
            Self::AlreadyOpen { .. } | Self::LeaseRegistryUnavailable => None,
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

/// An opened repository root that passed preflight validation.
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
    materialized_aliases: Vec<MaterializedAlias>,
    // Kept on the backing owner so `ImportedRepository::into_parts` cannot
    // accidentally release exclusivity while an adapter still holds the fd.
    repository_lease: Option<Arc<RepositoryLease>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct RepositoryLeaseKey {
    repository: RepoId,
    canonical_root: PathBuf,
}

#[derive(Debug)]
struct RepositoryLease {
    key: RepositoryLeaseKey,
}

fn repository_leases() -> &'static Mutex<HashSet<RepositoryLeaseKey>> {
    static LEASES: OnceLock<Mutex<HashSet<RepositoryLeaseKey>>> = OnceLock::new();
    LEASES.get_or_init(|| Mutex::new(HashSet::new()))
}

impl RepositoryLease {
    fn acquire(
        repository: RepoId,
        canonical_root: PathBuf,
    ) -> Result<Arc<Self>, RepositoryStartupError> {
        let key = RepositoryLeaseKey {
            repository,
            canonical_root,
        };
        let mut leases = repository_leases()
            .lock()
            .map_err(|_| RepositoryStartupError::LeaseRegistryUnavailable)?;
        if !leases.insert(key.clone()) {
            return Err(RepositoryStartupError::AlreadyOpen {
                repository: key.repository,
                root: key.canonical_root,
            });
        }
        drop(leases);
        Ok(Arc::new(Self { key }))
    }
}

impl Drop for RepositoryLease {
    fn drop(&mut self) {
        // Drop must release the exact reservation even if an unrelated panic
        // poisoned the registry. New acquisitions still fail closed on poison.
        let mut leases = repository_leases()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        leases.remove(&self.key);
    }
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
    /// Binds an identity, validates the backing tree, and imports its manifest.
    ///
    /// Object identities are assigned in deterministic manifest order and are
    /// never derived from paths, so later rename operations do not change them.
    /// The registry is returned only after every manifest entry is accepted.
    ///
    /// # Errors
    ///
    /// Returns [`RepositoryStartupError`] when the process already owns the
    /// same repository/root pair, preflight rejects the backing tree, or the
    /// complete manifest cannot initialize one namespace registry.
    pub fn open(
        repository: RepoId,
        root: impl AsRef<Path>,
        limits: PreflightLimits,
    ) -> Result<Self, RepositoryStartupError> {
        let requested_root = root.as_ref();
        let canonical_root =
            fs::canonicalize(requested_root).map_err(|source| RepositoryPreflightError::Io {
                operation: "canonicalize repository root for process lease",
                path: requested_root.to_path_buf(),
                source,
            })?;
        // Reserve before preflight because materializing external hard links is
        // itself a backing mutation. A competing import must not run that scan
        // against the same repository concurrently.
        let lease = RepositoryLease::acquire(repository.clone(), canonical_root)?;
        let backing = ValidatedRepository::open(requested_root, limits)?;
        Self::from_validated_with_lease(repository, backing, lease)
    }

    /// Atomically binds and imports a repository that already passed preflight.
    ///
    /// # Errors
    ///
    /// Returns [`RepositoryStartupError::AlreadyOpen`] when the process already
    /// owns the same repository/root pair, or
    /// [`RepositoryStartupError::Namespace`] if the validated manifest cannot
    /// initialize a complete namespace registry.
    pub fn from_validated(
        repository: RepoId,
        backing: ValidatedRepository,
    ) -> Result<Self, RepositoryStartupError> {
        let lease =
            RepositoryLease::acquire(repository.clone(), backing.canonical_root().to_path_buf())?;
        Self::from_validated_with_lease(repository, backing, lease)
    }

    fn from_validated_with_lease(
        repository: RepoId,
        mut backing: ValidatedRepository,
        lease: Arc<RepositoryLease>,
    ) -> Result<Self, RepositoryStartupError> {
        let namespace = NamespaceRegistry::from_manifest(backing.entries().iter().map(|entry| {
            ManifestEntry::new(
                entry.path().clone(),
                entry.spec().clone(),
                AliasGroup::new(entry.inode()),
            )
        }))?;
        backing.repository_lease = Some(lease);
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
    /// exceeded, or any entry violates the repository tree model.
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

        let (entries, materialized_aliases) =
            validate_repository_tree(&root_fd, opened_root.inode, opened_root.mount_id, limits)?;
        Ok(Self {
            root_fd,
            canonical_root,
            root_mount_id: opened_root.mount_id,
            entries,
            materialized_aliases,
            repository_lease: None,
        })
    }

    /// Returns the names whose inode was replaced by a private copy.
    ///
    /// Non-empty only when [`ExternalAliasPolicy::Materialize`] had work to do.
    /// Callers should record it: the backing tree was rewritten, and the file
    /// at each of these paths no longer shares storage with the name outside
    /// the repository it used to share with.
    #[must_use]
    pub fn materialized_aliases(&self) -> &[MaterializedAlias] {
        self.materialized_aliases.as_slice()
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

/// Scans the tree, and breaks external hard links once if policy allows it.
///
/// Materialization changes the tree, so the manifest cannot be the one that
/// found the violation: inodes and link counts have moved. The tree is scanned
/// again afterwards and reconciled strictly. Exactly one repair pass is allowed,
/// so a tree that keeps producing external names — because something is racing
/// the scan — is refused rather than repaired in a loop.
fn validate_repository_tree(
    root_fd: &OwnedFd,
    root_inode: u64,
    root_mount_id: u64,
    limits: PreflightLimits,
) -> Result<(Vec<RepositoryEntry>, Vec<MaterializedAlias>), RepositoryPreflightError> {
    let (entries, link_counts) = scan_repository(root_fd, root_inode, root_mount_id, limits)?;
    let external = external_alias_inodes(&entries, &link_counts);
    if external.is_empty() {
        return Ok((entries, Vec::new()));
    }

    let ExternalAliasPolicy::Materialize { max_total_bytes } = limits.external_aliases else {
        return Err(external_hard_link_error(&external, &entries, &link_counts));
    };

    let materialized = materialize_external_aliases(root_fd, &external, &entries, max_total_bytes)?;
    let (entries, link_counts) = scan_repository(root_fd, root_inode, root_mount_id, limits)?;
    let external = external_alias_inodes(&entries, &link_counts);
    if !external.is_empty() {
        return Err(external_hard_link_error(&external, &entries, &link_counts));
    }
    Ok((entries, materialized))
}

fn scan_repository(
    root_fd: &OwnedFd,
    root_inode: u64,
    root_mount_id: u64,
    limits: PreflightLimits,
) -> Result<(Vec<RepositoryEntry>, HashMap<u64, u32>), RepositoryPreflightError> {
    // Reopen rather than duplicate. A duplicate shares the open file
    // description, and therefore the directory offset, with the root fd this
    // repository keeps: a second scan would start where the first one stopped
    // and see an empty tree.
    let scan_root = openat(
        root_fd,
        ".",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| io_error("reopen repository root for scanning", Path::new("/"), error))?;
    let mut pending = vec![PendingDirectory {
        fd: scan_root,
        segments: Vec::new(),
    }];
    let mut entries = vec![RepositoryEntry::new(
        CanonicalPath::root(),
        NamespaceObjectSpec::Directory,
        root_inode,
    )];
    let mut link_counts = HashMap::new();

    while let Some(directory) = pending.pop() {
        scan_directory(
            directory,
            root_mount_id,
            limits,
            &mut entries,
            &mut pending,
            &mut link_counts,
        )?;
    }

    entries.sort_by(|left, right| left.path.as_segments().cmp(right.path.as_segments()));
    Ok((entries, link_counts))
}

/// Returns every inode whose names are not all inside the repository.
///
/// A hard link is only representable here when capfs governs every name the
/// inode answers to. Otherwise the repository is a partial view of the inode:
/// authority checked on the names capfs knows would say nothing about the name
/// it does not, and removing the known names would not remove the data.
fn external_alias_inodes(entries: &[RepositoryEntry], link_counts: &HashMap<u64, u32>) -> Vec<u64> {
    let mut names_by_inode: HashMap<u64, usize> = HashMap::new();
    for entry in entries {
        if entry.kind() == NamespaceObjectKind::Directory {
            // Linux maintains a directory's link count from its `.` and `..`
            // entries, so it never indicates aliasing and never matches a name
            // count. Directories cannot be hard-linked at all.
            continue;
        }
        *names_by_inode.entry(entry.inode).or_default() += 1;
    }

    let mut external = names_by_inode
        .into_iter()
        .filter(|(inode, names)| {
            link_counts.get(inode).is_some_and(|link_count| {
                usize::try_from(*link_count).unwrap_or(usize::MAX) != *names
            })
        })
        .map(|(inode, _)| inode)
        .collect::<Vec<_>>();
    external.sort_unstable();
    external
}

fn repository_names(entries: &[RepositoryEntry], inode: u64) -> Vec<&RepositoryEntry> {
    entries
        .iter()
        .filter(|entry| entry.inode == inode && entry.kind() != NamespaceObjectKind::Directory)
        .collect()
}

fn external_hard_link_error(
    external: &[u64],
    entries: &[RepositoryEntry],
    link_counts: &HashMap<u64, u32>,
) -> RepositoryPreflightError {
    let inode = external.first().copied().unwrap_or_default();
    RepositoryPreflightError::ExternalHardLink {
        inode,
        link_count: link_counts.get(&inode).copied().unwrap_or_default(),
        names_in_repository: repository_names(entries, inode)
            .into_iter()
            .map(|entry| entry.path.clone())
            .collect(),
    }
}

fn scan_directory(
    directory: PendingDirectory,
    root_mount_id: u64,
    limits: PreflightLimits,
    entries: &mut Vec<RepositoryEntry>,
    pending: &mut Vec<PendingDirectory>,
    link_counts: &mut HashMap<u64, u32>,
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

        let spec = match metadata.kind {
            FileType::RegularFile => NamespaceObjectSpec::RegularFile,
            FileType::Symlink => NamespaceObjectSpec::Symlink(read_symlink_target(
                directory_fd,
                entry.file_name(),
                &path,
            )?),
            FileType::Directory => {
                let child_fd = openat2(
                    directory_fd,
                    entry.file_name(),
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                    Mode::empty(),
                    PREFLIGHT_RESOLVE,
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
                NamespaceObjectSpec::Directory
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
        if spec.kind() != NamespaceObjectKind::Directory {
            link_counts.insert(metadata.inode, metadata.link_count);
        }
        entries.push(RepositoryEntry::new(path, spec, metadata.inode));
    }

    Ok(())
}

/// Gives each externally aliased inode a private copy inside the repository.
///
/// For one inode, the first repository name receives a fresh copy of the
/// contents and the remaining repository names are relinked onto that copy, so
/// names that aliased each other inside the repository still do. The name
/// outside the repository keeps the original inode and is never touched.
///
/// Every replacement is built at a temporary name and moved into place with
/// `renameat`, so no repository name is ever missing: the path resolves to the
/// old inode until the instant it resolves to the new one.
fn materialize_external_aliases(
    root_fd: &OwnedFd,
    external: &[u64],
    entries: &[RepositoryEntry],
    max_total_bytes: u64,
) -> Result<Vec<MaterializedAlias>, RepositoryPreflightError> {
    let mut remaining = max_total_bytes;
    let mut materialized = Vec::new();
    for (index, inode) in external.iter().enumerate() {
        let names = repository_names(entries, *inode);
        let Some((first, rest)) = names.split_first() else {
            continue;
        };
        let first_parent = open_preflight_parent(root_fd, &first.path)?;
        let first_name = final_name(&first.path)?;
        let temporary = temporary_name(*inode, index, 0);

        let bytes = match first.spec() {
            NamespaceObjectSpec::Symlink(target) => {
                symlinkat(target.as_str(), &first_parent, temporary.as_str()).map_err(|error| {
                    io_error(
                        "create replacement symbolic link",
                        &path_buf(&first.path),
                        error,
                    )
                })?;
                0
            }
            NamespaceObjectSpec::RegularFile => copy_regular_file(
                &first_parent,
                first_name,
                temporary.as_str(),
                &first.path,
                &mut remaining,
            )?,
            NamespaceObjectSpec::Directory => continue,
        };
        replace_with_temporary(&first_parent, temporary.as_str(), first_name, &first.path)?;

        for (offset, alias) in rest.iter().enumerate() {
            let alias_parent = open_preflight_parent(root_fd, &alias.path)?;
            let alias_name = final_name(&alias.path)?;
            let temporary = temporary_name(*inode, index, offset + 1);
            linkat(
                &first_parent,
                first_name,
                &alias_parent,
                temporary.as_str(),
                AtFlags::empty(),
            )
            .map_err(|error| io_error("relink repository alias", &path_buf(&alias.path), error))?;
            replace_with_temporary(&alias_parent, temporary.as_str(), alias_name, &alias.path)?;
        }

        materialized.push(MaterializedAlias {
            path: first.path.clone(),
            bytes,
            additional_names: rest.len(),
        });
    }
    Ok(materialized)
}

/// Copies one regular file's contents, mode, and timestamps to a new inode.
///
/// Ownership is deliberately not copied: restoring another uid would need
/// `CAP_CHOWN`, and preflight must not require it. The copy belongs to the
/// process that runs capfs, which already owns everything it creates.
fn copy_regular_file(
    parent_fd: &OwnedFd,
    source_name: &str,
    temporary_name: &str,
    path: &CanonicalPath,
    remaining: &mut u64,
) -> Result<u64, RepositoryPreflightError> {
    let source_fd = openat2(
        parent_fd,
        source_name,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
        PREFLIGHT_RESOLVE,
    )
    .map_err(|error| io_error("open alias source", &path_buf(path), error))?;
    let metadata = statx(
        &source_fd,
        "",
        AtFlags::EMPTY_PATH | AtFlags::NO_AUTOMOUNT | AtFlags::SYMLINK_NOFOLLOW,
        StatxFlags::BASIC_STATS,
    )
    .map_err(|error| io_error("inspect alias source", &path_buf(path), error))?;
    if metadata.stx_size > *remaining {
        return Err(RepositoryPreflightError::MaterializationBudgetExceeded {
            path: path.clone(),
            required: metadata.stx_size,
            remaining: *remaining,
        });
    }

    let target_fd = openat2(
        parent_fd,
        temporary_name,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::RUSR | Mode::WUSR,
        PREFLIGHT_RESOLVE,
    )
    .map_err(|error| io_error("create alias replacement", &path_buf(path), error))?;

    let copy = (|| -> Result<u64, RepositoryPreflightError> {
        let mut source = File::from(source_fd);
        let mut target = File::from(target_fd);
        let copied =
            io::copy(&mut source, &mut target).map_err(|error| RepositoryPreflightError::Io {
                operation: "copy alias contents",
                path: path_buf(path),
                source: error,
            })?;
        if copied > *remaining {
            return Err(RepositoryPreflightError::MaterializationBudgetExceeded {
                path: path.clone(),
                required: copied,
                remaining: *remaining,
            });
        }
        fchmod(
            &target,
            Mode::from_raw_mode((metadata.stx_mode & 0o7777).into()),
        )
        .map_err(|error| io_error("apply alias permissions", &path_buf(path), error))?;
        futimens(
            &target,
            &Timestamps {
                last_access: statx_timespec(metadata.stx_atime),
                last_modification: statx_timespec(metadata.stx_mtime),
            },
        )
        .map_err(|error| io_error("apply alias timestamps", &path_buf(path), error))?;
        Ok(copied)
    })();

    match copy {
        Ok(copied) => {
            *remaining -= copied;
            Ok(copied)
        }
        Err(error) => {
            // The half-written replacement is not part of the repository yet;
            // leaving it behind would add an entry the manifest never saw.
            let _ = unlinkat(parent_fd, temporary_name, AtFlags::empty());
            Err(error)
        }
    }
}

/// Moves a prepared replacement onto a repository name.
fn replace_with_temporary(
    parent_fd: &OwnedFd,
    temporary: &str,
    name: &str,
    path: &CanonicalPath,
) -> Result<(), RepositoryPreflightError> {
    renameat(parent_fd, temporary, parent_fd, name).map_err(|error| {
        let _ = unlinkat(parent_fd, temporary, AtFlags::empty());
        io_error("replace aliased repository name", &path_buf(path), error)
    })
}

fn open_preflight_parent(
    root_fd: &OwnedFd,
    path: &CanonicalPath,
) -> Result<OwnedFd, RepositoryPreflightError> {
    let parent = path
        .parent()
        .ok_or_else(|| RepositoryPreflightError::RootNotDirectory(path_buf(path)))?;
    if parent.is_root() {
        // Reopen rather than duplicate, for the same reason the scan does: a
        // duplicate would share the root fd's directory offset.
        return openat(
            root_fd,
            ".",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|error| io_error("reopen repository root", Path::new("/"), error));
    }
    openat2(
        root_fd,
        path_buf(&parent),
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
        PREFLIGHT_RESOLVE,
    )
    .map_err(|error| io_error("open alias parent directory", &path_buf(&parent), error))
}

fn final_name(path: &CanonicalPath) -> Result<&str, RepositoryPreflightError> {
    path.as_segments()
        .last()
        .map(String::as_str)
        .ok_or_else(|| RepositoryPreflightError::RootNotDirectory(path_buf(path)))
}

/// Builds a replacement name that cannot collide with a repository entry.
///
/// The scan rejects names it cannot represent as canonical segments, but a
/// hostile tree can still contain one that looks like this. Every use creates
/// it with `O_EXCL`, `symlinkat`, or `linkat`, all of which fail on an existing
/// name rather than replacing it.
fn temporary_name(inode: u64, group: usize, index: usize) -> String {
    format!(".capfs-materialize.{inode}.{group}.{index}")
}

const fn statx_timespec(timestamp: StatxTimestamp) -> Timespec {
    Timespec {
        tv_sec: timestamp.tv_sec,
        tv_nsec: timestamp.tv_nsec as i64,
    }
}

/// Reads and validates one symbolic link body during preflight.
///
/// The link is read without following it and is accepted only when the stored
/// target is one the namespace model can serve back to the kernel: relative,
/// within the canonical segment rules, and resolving to a path inside the
/// repository from where the link currently sits.
fn read_symlink_target(
    directory_fd: BorrowedFd<'_>,
    name: &CStr,
    path: &CanonicalPath,
) -> Result<SymlinkTarget, RepositoryPreflightError> {
    let target = readlinkat(directory_fd, name, Vec::new())
        .map_err(|error| io_error("read repository symbolic link", &path_buf(path), error))?;
    let bytes = target.into_bytes();
    let Ok(literal) = String::from_utf8(bytes.clone()) else {
        return Err(RepositoryPreflightError::NonUtf8SymlinkTarget {
            path: path.clone(),
            target: OsString::from_vec(bytes),
        });
    };
    let target = SymlinkTarget::new(literal).map_err(|source| {
        RepositoryPreflightError::UnsupportedSymlinkTarget {
            path: path.clone(),
            source,
        }
    })?;
    target.resolve_from(path).map_err(|escape| {
        RepositoryPreflightError::EscapingSymlinkTarget {
            path: path.clone(),
            target: escape.target().to_owned(),
        }
    })?;
    Ok(target)
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
    if let Some(kind) = rejected_kind(metadata.kind) {
        return Err(RepositoryPreflightError::UnsupportedObject { path, kind });
    }
    Ok(())
}

const fn rejected_kind(kind: FileType) -> Option<RejectedObjectKind> {
    match kind {
        FileType::RegularFile | FileType::Directory | FileType::Symlink => None,
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

struct DisplayCanonicalPaths<'a>(&'a [CanonicalPath]);

impl fmt::Display for DisplayCanonicalPaths<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut paths = self.0.iter();
        if let Some(first) = paths.next() {
            write!(formatter, "`{}`", DisplayCanonicalPath(first))?;
        }
        for path in paths {
            write!(formatter, ", `{}`", DisplayCanonicalPath(path))?;
        }
        Ok(())
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
    use authority_core::{path::CanonicalPath, repository::RepoId};
    use rustix::fs::FileType;
    use tempfile::tempdir;

    use std::{collections::HashMap, num::NonZeroUsize};

    use super::{
        EntryMetadata, ImportedRepository, NamespaceObjectSpec, PreflightLimits,
        RejectedObjectKind, RepositoryEntry, RepositoryPreflightError, RepositoryStartupError,
        external_alias_inodes, validate_entry_metadata,
    };

    fn path(segments: &[&str]) -> CanonicalPath {
        CanonicalPath::new(segments).expect("test paths must be canonical")
    }

    fn entry(path: CanonicalPath, spec: NamespaceObjectSpec, inode: u64) -> RepositoryEntry {
        RepositoryEntry::new(path, spec, inode)
    }

    fn limits() -> PreflightLimits {
        PreflightLimits::new(NonZeroUsize::new(8).expect("limit must be non-zero"), 2)
    }

    // Requirement: two public imports cannot create independent quarantine
    // domains for the same repository. The backing Arc owns the reservation,
    // and releasing its last clone makes the exact key available again.
    #[test]
    fn repository_import_is_process_exclusive_until_last_backing_drop() {
        let directory = tempdir().expect("temporary repository must be creatable");
        let repository = RepoId::new("exclusive-workspace");
        let imported = ImportedRepository::open(repository.clone(), directory.path(), limits())
            .expect("first import must acquire the repository lease");
        let retained_backing = imported.clone().into_parts().1;

        assert!(matches!(
            ImportedRepository::open(repository.clone(), directory.path(), limits()),
            Err(RepositoryStartupError::AlreadyOpen {
                repository: held_repository,
                root: _
            }) if held_repository == repository
        ));

        drop(imported);
        assert!(matches!(
            ImportedRepository::open(repository.clone(), directory.path(), limits()),
            Err(RepositoryStartupError::AlreadyOpen { .. })
        ));

        drop(retained_backing);
        let reopened = ImportedRepository::open(repository, directory.path(), limits())
            .expect("dropping the final backing owner must release the exact lease");
        drop(reopened);
    }

    #[test]
    fn metadata_validation_rejects_mount_crossing() {
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
    }

    // Requirement: an inode may be hard-linked only when every one of its names
    // is inside the repository capfs governs.
    #[test]
    fn alias_detection_accepts_complete_sets_and_reports_partial_ones() {
        let complete = [
            entry(CanonicalPath::root(), NamespaceObjectSpec::Directory, 1),
            entry(path(&["a.rs"]), NamespaceObjectSpec::RegularFile, 8),
            entry(path(&["b.rs"]), NamespaceObjectSpec::RegularFile, 8),
        ];
        assert!(external_alias_inodes(&complete, &HashMap::from([(8, 2)])).is_empty());

        let partial = [
            entry(CanonicalPath::root(), NamespaceObjectSpec::Directory, 1),
            entry(path(&["a.rs"]), NamespaceObjectSpec::RegularFile, 8),
        ];
        assert_eq!(
            external_alias_inodes(&partial, &HashMap::from([(8, 2)])),
            vec![8]
        );
    }

    #[test]
    fn metadata_validation_rejects_every_unsupported_object_kind() {
        let cases = [
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
