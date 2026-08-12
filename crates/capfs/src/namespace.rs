//! VM-wide namespace identity, path, generation, and open-count state.

use std::{
    collections::{BTreeMap, HashMap},
    error::Error,
    fmt,
    sync::{
        RwLock, RwLockReadGuard, RwLockWriteGuard,
        atomic::{AtomicBool, Ordering},
    },
};

use authority_core::{
    handle::ObjectId,
    path::{CanonicalPath, InvalidPathSegment},
};

const ROOT_OBJECT_SEQUENCE: u64 = 0;

fn object_id(sequence: u64) -> ObjectId {
    // Object identities deliberately carry no path material, so rename cannot
    // alter or accidentally rebind the identity used by open handles.
    ObjectId::new(format!("object-{sequence}"))
}

/// A monotone version of the shared namespace path mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NamespaceGeneration(u64);

impl NamespaceGeneration {
    /// Returns the generation assigned to a complete initial namespace snapshot.
    #[must_use]
    pub const fn initial() -> Self {
        Self(0)
    }

    /// Returns the underlying monotone value.
    #[must_use]
    pub const fn as_u64(self) -> u64 {
        self.0
    }

    const fn checked_next(self) -> Option<Self> {
        match self.0.checked_add(1) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }
}

/// The object kinds carried by the namespace model.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NamespaceObjectKind {
    /// A directory that may own child paths.
    Directory,
    /// A regular file.
    RegularFile,
    /// A symbolic link whose target the registry owns.
    Symlink,
}

/// What one namespace object is, including a symlink's required target.
///
/// Kind and target travel together so a symlink cannot be registered without
/// the target the registry has to reauthorize on every `READLINK`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NamespaceObjectSpec {
    /// A directory that may own child paths.
    Directory,
    /// A regular file.
    RegularFile,
    /// A symbolic link with a validated repository-relative target.
    Symlink(SymlinkTarget),
}

impl NamespaceObjectSpec {
    /// Returns the kind this specification registers.
    #[must_use]
    pub const fn kind(&self) -> NamespaceObjectKind {
        match self {
            Self::Directory => NamespaceObjectKind::Directory,
            Self::RegularFile => NamespaceObjectKind::RegularFile,
            Self::Symlink(_) => NamespaceObjectKind::Symlink,
        }
    }

    /// Returns the symlink target, or `None` for other kinds.
    #[must_use]
    pub const fn target(&self) -> Option<&SymlinkTarget> {
        match self {
            Self::Symlink(target) => Some(target),
            Self::Directory | Self::RegularFile => None,
        }
    }
}

/// Why a symbolic-link target cannot be represented by this registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvalidSymlinkTargetReason {
    /// The target is empty.
    Empty,
    /// The target exceeds the accepted byte length.
    TooLong,
    /// The target begins at the caller's filesystem root.
    Absolute,
    /// The target contains a NUL byte.
    ContainsNul,
    /// A `..` component appears after a named component.
    InteriorParent,
    /// A named component is not one safe canonical path segment.
    InvalidSegment(InvalidPathSegment),
}

impl fmt::Display for InvalidSymlinkTargetReason {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("must not be empty"),
            Self::TooLong => write!(
                formatter,
                "must not exceed {MAX_SYMLINK_TARGET_BYTES} bytes"
            ),
            Self::Absolute => formatter.write_str("must not be absolute"),
            Self::ContainsNul => formatter.write_str("must not contain NUL"),
            Self::InteriorParent => {
                formatter.write_str("may only use `..` before its first named component")
            }
            Self::InvalidSegment(error) => write!(formatter, "has an invalid component: {error}"),
        }
    }
}

/// A rejected symbolic-link target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidSymlinkTarget {
    literal: String,
    reason: InvalidSymlinkTargetReason,
}

impl InvalidSymlinkTarget {
    /// Returns the rejected target exactly as it was supplied.
    #[must_use]
    pub fn literal(&self) -> &str {
        &self.literal
    }

    /// Returns why the target was rejected.
    #[must_use]
    pub const fn reason(&self) -> InvalidSymlinkTargetReason {
        self.reason
    }
}

impl fmt::Display for InvalidSymlinkTarget {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "symbolic link target `{}` {}",
            self.literal, self.reason
        )
    }
}

impl Error for InvalidSymlinkTarget {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match &self.reason {
            InvalidSymlinkTargetReason::InvalidSegment(error) => Some(error),
            _ => None,
        }
    }
}

/// The longest symbolic-link target this registry stores.
///
/// Linux bounds a link body by `PATH_MAX`. Repeating the bound here keeps a
/// hostile backing tree from turning one `READLINK` into an unbounded reply.
pub const MAX_SYMLINK_TARGET_BYTES: usize = 4096;

/// A validated, repository-relative symbolic-link target.
///
/// # Why the grammar is restricted
///
/// The operating system, not this adapter, resolves a symbolic link: the FUSE
/// kernel asks for the target with `READLINK` and then continues its own path
/// walk. The target string is therefore the *only* enforcement point, and it has
/// to be one whose resolution can be proven to stay inside the mount.
///
/// Absolute targets are rejected because they would resolve in the caller's
/// mount namespace, entirely outside this repository. `..` is accepted only as a
/// leading run, because those components pop through the link's own ancestor
/// directories, which the registry knows are directories. A `..` that follows a
/// named component would pop from wherever that component resolved to, and if
/// that component is itself a symlink pointing at a shallower directory the
/// kernel would end up above the mount root even though a purely lexical check
/// said otherwise. Rejecting the interior form removes that gap instead of
/// trying to predict it.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SymlinkTarget {
    literal: String,
    parents: usize,
    segments: Vec<String>,
}

impl SymlinkTarget {
    /// Validates one repository-relative link body.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidSymlinkTarget`] for an empty, oversized, absolute, or
    /// NUL-bearing target, for a `..` after a named component, or for a
    /// component that is not a safe canonical path segment.
    pub fn new(literal: impl Into<String>) -> Result<Self, InvalidSymlinkTarget> {
        let literal = literal.into();
        let reject = |reason| InvalidSymlinkTarget {
            literal: literal.clone(),
            reason,
        };
        if literal.is_empty() {
            return Err(reject(InvalidSymlinkTargetReason::Empty));
        }
        if literal.len() > MAX_SYMLINK_TARGET_BYTES {
            return Err(reject(InvalidSymlinkTargetReason::TooLong));
        }
        if literal.starts_with('/') {
            return Err(reject(InvalidSymlinkTargetReason::Absolute));
        }
        if literal.contains('\0') {
            return Err(reject(InvalidSymlinkTargetReason::ContainsNul));
        }

        let mut parents = 0_usize;
        let mut segments = Vec::new();
        for component in literal.split('/') {
            match component {
                "" | "." => {}
                ".." => {
                    if !segments.is_empty() {
                        return Err(reject(InvalidSymlinkTargetReason::InteriorParent));
                    }
                    parents += 1;
                }
                named => {
                    // Reuse the canonical segment rules so a target can never
                    // name something the path model itself cannot represent.
                    CanonicalPath::new([named]).map_err(|error| {
                        reject(InvalidSymlinkTargetReason::InvalidSegment(error))
                    })?;
                    segments.push(named.to_owned());
                }
            }
        }

        Ok(Self {
            literal,
            parents,
            segments,
        })
    }

    /// Returns the target exactly as it must be replied to `READLINK`.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.literal
    }

    /// Returns how many ancestor directories the target climbs.
    #[must_use]
    pub const fn parent_count(&self) -> usize {
        self.parents
    }

    /// Resolves this target against the link's current path.
    ///
    /// The result is where the operating system's own path walk will arrive,
    /// expressed as a repository-relative canonical path. It is recomputed for
    /// every request because a rename changes what the same literal denotes.
    ///
    /// # Errors
    ///
    /// Returns [`SymlinkTargetEscape`] when the link sits at the repository root
    /// or the target climbs above it. The registry must fail closed in that case
    /// rather than hand the literal to the kernel, which would resolve it in the
    /// caller's mount namespace.
    pub fn resolve_from(
        &self,
        link_path: &CanonicalPath,
    ) -> Result<CanonicalPath, SymlinkTargetEscape> {
        let escape = || SymlinkTargetEscape {
            link: link_path.clone(),
            target: self.literal.clone(),
        };
        let parent = link_path.parent().ok_or_else(escape)?;
        let mut segments = parent.as_segments().to_vec();
        for _ in 0..self.parents {
            segments.pop().ok_or_else(escape)?;
        }
        segments.extend(self.segments.iter().cloned());
        CanonicalPath::new(segments).map_err(|_| escape())
    }
}

/// A symbolic-link target that resolves outside the repository root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SymlinkTargetEscape {
    link: CanonicalPath,
    target: String,
}

impl SymlinkTargetEscape {
    /// Returns the path of the link whose target escapes.
    #[must_use]
    pub const fn link(&self) -> &CanonicalPath {
        &self.link
    }

    /// Returns the target that would leave the repository.
    #[must_use]
    pub fn target(&self) -> &str {
        &self.target
    }
}

impl fmt::Display for SymlinkTargetEscape {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "symbolic link `{}` targets `{}`, which leaves the repository root",
            DisplayPath(&self.link),
            self.target
        )
    }
}

impl Error for SymlinkTargetEscape {}

/// The set of startup manifest paths that name one backing inode.
///
/// The preflight scan supplies the inode number. Every manifest path carrying
/// the same value becomes one namespace object with that many names, which is
/// how an imported hard link keeps a single identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AliasGroup(u64);

impl AliasGroup {
    /// Groups manifest paths by the backing inode they were scanned from.
    #[must_use]
    pub const fn new(inode: u64) -> Self {
        Self(inode)
    }
}

/// One validated path in a startup manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestEntry {
    path: CanonicalPath,
    spec: NamespaceObjectSpec,
    alias_group: AliasGroup,
}

impl ManifestEntry {
    /// Records one scanned path, what it is, and which inode it names.
    #[must_use]
    pub const fn new(path: CanonicalPath, spec: NamespaceObjectSpec, group: AliasGroup) -> Self {
        Self {
            path,
            spec,
            alias_group: group,
        }
    }

    /// Returns the repository-relative path.
    #[must_use]
    pub const fn path(&self) -> &CanonicalPath {
        &self.path
    }

    /// Returns what the path names.
    #[must_use]
    pub const fn spec(&self) -> &NamespaceObjectSpec {
        &self.spec
    }
}

/// The current registry record for one live namespace object.
///
/// An object owns every canonical path that currently names it. A regular file
/// or symbolic link gains a second path through `LINK`; a directory always has
/// exactly one. Authorization must use [`Self::paths`], never a single path:
/// an operation on an aliased inode is only permitted when the capability
/// permits it on every name the inode answers to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamespaceObject {
    id: ObjectId,
    /// The lowest-sorting live path. Separating it from the alias list makes
    /// "a live object always has at least one path" a property of the type
    /// rather than a rule the registry has to remember.
    primary: CanonicalPath,
    aliases: Vec<CanonicalPath>,
    kind: NamespaceObjectKind,
    link_target: Option<SymlinkTarget>,
    open_handle_count: u64,
}

/// One name inside a directory and the object that name resolves to.
///
/// A directory listing enumerates names rather than objects, so a hard-linked
/// inode appears once per name it owns in that directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NamespaceChild<'a> {
    path: &'a CanonicalPath,
    object: &'a NamespaceObject,
}

impl<'a> NamespaceChild<'a> {
    /// Returns the full canonical path of this directory entry.
    #[must_use]
    pub const fn path(&self) -> &'a CanonicalPath {
        self.path
    }

    /// Returns the object this entry names.
    #[must_use]
    pub const fn object(&self) -> &'a NamespaceObject {
        self.object
    }

    /// Returns the entry's final path segment.
    #[must_use]
    pub fn name(&self) -> Option<&'a str> {
        self.path.as_segments().last().map(String::as_str)
    }
}

/// The committed result of creating one namespace object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamespaceObjectCreation<T> {
    object: ObjectId,
    value: T,
}

impl<T> NamespaceObjectCreation<T> {
    const fn new(object: ObjectId, value: T) -> Self {
        Self { object, value }
    }

    /// Returns the fresh session-local identity assigned to the object.
    #[must_use]
    pub const fn object(&self) -> &ObjectId {
        &self.object
    }

    /// Returns the backing executor's committed result.
    #[must_use]
    pub const fn value(&self) -> &T {
        &self.value
    }

    /// Separates the fresh object identity from the executor result.
    #[must_use]
    pub fn into_parts(self) -> (ObjectId, T) {
        (self.object, self.value)
    }
}

/// What removing one path did to the object that owned it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PathRemoval {
    /// Other paths still name the object, so the inode keeps a name.
    Detached,
    /// The last path is gone and the object must be retired.
    Retired,
}

impl NamespaceObject {
    fn new(id: ObjectId, path: CanonicalPath, spec: &NamespaceObjectSpec) -> Self {
        Self {
            id,
            primary: path,
            aliases: Vec::new(),
            kind: spec.kind(),
            link_target: spec.target().cloned(),
            open_handle_count: 0,
        }
    }

    /// Returns the session-local object identity.
    #[must_use]
    pub const fn id(&self) -> &ObjectId {
        &self.id
    }

    /// Returns the object's lowest-sorting current path.
    ///
    /// This names the inode for backing I/O and diagnostics, where every alias
    /// reaches the same object. It must never stand in for authorization: use
    /// [`Self::paths`], which is the set an authorization has to cover.
    #[must_use]
    pub const fn primary_path(&self) -> &CanonicalPath {
        &self.primary
    }

    /// Returns every canonical path that currently names this object, in order.
    ///
    /// The set is non-empty, and has more than one element only for a
    /// hard-linked regular file or symbolic link.
    pub fn paths(&self) -> impl Iterator<Item = &CanonicalPath> + Clone {
        std::iter::once(&self.primary).chain(self.aliases.iter())
    }

    /// Returns whether more than one path currently names this object.
    #[must_use]
    pub const fn is_aliased(&self) -> bool {
        !self.aliases.is_empty()
    }

    /// Returns how many names the backing inode is expected to have.
    ///
    /// Runtime validation compares this with the inode's real link count, which
    /// is what detects a hard link created outside capfs.
    #[must_use]
    pub const fn expected_link_count(&self) -> usize {
        self.aliases.len() + 1
    }

    /// Returns whether the object is a directory, regular file, or symlink.
    #[must_use]
    pub const fn kind(&self) -> NamespaceObjectKind {
        self.kind
    }

    /// Returns the owned link target, or `None` for other kinds.
    #[must_use]
    pub const fn link_target(&self) -> Option<&SymlinkTarget> {
        self.link_target.as_ref()
    }

    /// Returns the number of live handles registered for this object.
    #[must_use]
    pub const fn open_handle_count(&self) -> u64 {
        self.open_handle_count
    }

    fn owns_path(&self, path: &CanonicalPath) -> bool {
        &self.primary == path || self.aliases.contains(path)
    }

    fn insert_path(&mut self, path: CanonicalPath) -> Result<(), NamespaceError> {
        if self.owns_path(&path) {
            return Err(NamespaceError::PathOccupied(path));
        }
        if path.as_segments() < self.primary.as_segments() {
            let previous = std::mem::replace(&mut self.primary, path);
            self.aliases.push(previous);
        } else {
            self.aliases.push(path);
        }
        self.aliases
            .sort_unstable_by(|left, right| left.as_segments().cmp(right.as_segments()));
        Ok(())
    }

    fn remove_path(&mut self, path: &CanonicalPath) -> Result<PathRemoval, NamespaceError> {
        if &self.primary == path {
            if self.aliases.is_empty() {
                return Ok(PathRemoval::Retired);
            }
            self.primary = self.aliases.remove(0);
            return Ok(PathRemoval::Detached);
        }
        let Some(index) = self.aliases.iter().position(|candidate| candidate == path) else {
            return Err(NamespaceError::InvariantViolation);
        };
        self.aliases.remove(index);
        Ok(PathRemoval::Detached)
    }

    #[allow(
        clippy::needless_pass_by_value,
        reason = "the destination is stored, and taking it by value keeps that visible"
    )]
    fn replace_path(
        &mut self,
        source: &CanonicalPath,
        destination: CanonicalPath,
    ) -> Result<(), NamespaceError> {
        if !self.owns_path(source) {
            return Err(NamespaceError::InvariantViolation);
        }
        let mut paths = self.paths().cloned().collect::<Vec<_>>();
        for path in &mut paths {
            if path == source {
                path.clone_from(&destination);
            }
        }
        paths.sort_unstable_by(|left, right| left.as_segments().cmp(right.as_segments()));
        let mut ordered = paths.into_iter();
        self.primary = ordered.next().ok_or(NamespaceError::InvariantViolation)?;
        self.aliases = ordered.collect();
        Ok(())
    }
}

/// One object path changed by a subtree rename.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamespaceMove {
    object: ObjectId,
    source: CanonicalPath,
    destination: CanonicalPath,
    kind: NamespaceObjectKind,
    expected_link_count: usize,
}

impl NamespaceMove {
    /// Returns the object whose path changes.
    #[must_use]
    pub const fn object(&self) -> &ObjectId {
        &self.object
    }

    /// Returns the object's path before the rename.
    #[must_use]
    pub const fn source(&self) -> &CanonicalPath {
        &self.source
    }

    /// Returns the object's path after the rename.
    #[must_use]
    pub const fn destination(&self) -> &CanonicalPath {
        &self.destination
    }

    /// Returns the namespace kind that the backing rename must preserve.
    #[must_use]
    pub const fn kind(&self) -> NamespaceObjectKind {
        self.kind
    }

    /// Returns the link count the moved inode must still have.
    #[must_use]
    pub const fn expected_link_count(&self) -> usize {
        self.expected_link_count
    }
}

/// The complete path change presented to a backing rename executor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenamePlan {
    source: CanonicalPath,
    destination: CanonicalPath,
    moved_objects: Vec<NamespaceMove>,
}

impl RenamePlan {
    /// Returns the requested source path.
    #[must_use]
    pub const fn source(&self) -> &CanonicalPath {
        &self.source
    }

    /// Returns the requested no-replace destination path.
    #[must_use]
    pub const fn destination(&self) -> &CanonicalPath {
        &self.destination
    }

    /// Returns every object path changed by the subtree rename.
    #[must_use]
    pub const fn moved_objects(&self) -> &[NamespaceMove] {
        self.moved_objects.as_slice()
    }
}

/// A rejected namespace lookup or transition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NamespaceError {
    /// The registry lock was poisoned by a panicking writer.
    LockPoisoned,
    /// A committed effect could not be reconciled with its terminal audit record.
    RepositoryInDoubt,
    /// A startup manifest does not begin with exactly one directory root.
    InvalidManifestRoot,
    /// The session-local object identity sequence has no remaining values.
    ObjectIdExhausted,
    /// A live object already owns the requested path.
    PathOccupied(CanonicalPath),
    /// No live object has the requested identity.
    UnknownObject(ObjectId),
    /// No live object owns the requested path.
    UnknownPath(CanonicalPath),
    /// The requested path does not have a live parent directory.
    MissingParent(CanonicalPath),
    /// The requested parent exists but is not a directory.
    ParentNotDirectory(CanonicalPath),
    /// A child lookup name is not one safe canonical path segment.
    InvalidChildName(InvalidPathSegment),
    /// A symbolic link target cannot be represented by this registry.
    InvalidSymlinkTarget(InvalidSymlinkTarget),
    /// A symbolic link target resolves outside the repository root.
    SymlinkTargetEscapes(SymlinkTargetEscape),
    /// A second name was requested for an object that cannot be aliased.
    CannotAliasKind {
        /// The object that would gain a name.
        object: ObjectId,
        /// The kind that refuses additional names.
        kind: NamespaceObjectKind,
    },
    /// A manifest alias group describes one inode with conflicting records.
    InconsistentAliasGroup(CanonicalPath),
    /// An object-scoped removal cannot choose between an object's names.
    AmbiguousObjectPath(ObjectId),
    /// The repository root cannot be renamed or removed.
    CannotModifyRoot,
    /// A directory cannot be moved into its own subtree.
    DestinationInsideSource,
    /// A live handle prevents a subtree rename or object removal.
    OpenHandleInSubtree(ObjectId),
    /// A directory must be empty before removal.
    DirectoryNotEmpty(ObjectId),
    /// An object's open-handle count cannot advance without wrapping.
    OpenHandleCountExhausted(ObjectId),
    /// A close was recorded for an object with no live handles.
    NoOpenHandle(ObjectId),
    /// The namespace generation cannot advance without wrapping.
    NamespaceGenerationExhausted,
    /// A directory stream's namespace snapshot is no longer current.
    DirectoryGenerationChanged {
        /// Generation captured when the directory stream was opened.
        expected: NamespaceGeneration,
        /// Generation observed before producing the next directory entries.
        actual: NamespaceGeneration,
    },
    /// Internal path and object indexes no longer describe the same tree.
    InvariantViolation,
}

impl fmt::Display for NamespaceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LockPoisoned => formatter.write_str("namespace registry lock is poisoned"),
            Self::RepositoryInDoubt => formatter.write_str(
                "repository is quarantined after a committed effect lost its terminal outcome",
            ),
            Self::InvalidManifestRoot => {
                formatter.write_str("namespace manifest must begin with one directory root")
            }
            Self::ObjectIdExhausted => {
                formatter.write_str("session-local namespace object ID sequence is exhausted")
            }
            Self::PathOccupied(path) => {
                write!(
                    formatter,
                    "namespace path `{}` is already occupied",
                    DisplayPath(path)
                )
            }
            Self::UnknownObject(object) => {
                write!(formatter, "namespace object `{object}` is not live")
            }
            Self::UnknownPath(path) => {
                write!(
                    formatter,
                    "namespace path `{}` is not live",
                    DisplayPath(path)
                )
            }
            Self::MissingParent(path) => write!(
                formatter,
                "namespace path `{}` has no live parent directory",
                DisplayPath(path)
            ),
            Self::ParentNotDirectory(path) => write!(
                formatter,
                "namespace parent `{}` is not a directory",
                DisplayPath(path)
            ),
            Self::InvalidChildName(error) => write!(formatter, "invalid child name: {error}"),
            Self::InvalidSymlinkTarget(error) => write!(formatter, "{error}"),
            Self::SymlinkTargetEscapes(error) => write!(formatter, "{error}"),
            Self::CannotAliasKind { object, kind } => write!(
                formatter,
                "namespace object `{object}` is a {kind:?} and cannot have a second name"
            ),
            Self::InconsistentAliasGroup(path) => write!(
                formatter,
                "manifest path `{}` shares an inode with an entry of a different kind or target",
                DisplayPath(path)
            ),
            Self::AmbiguousObjectPath(object) => write!(
                formatter,
                "namespace object `{object}` has several names; removal must name one"
            ),
            Self::CannotModifyRoot => {
                formatter.write_str("the namespace root cannot be renamed or removed")
            }
            Self::DestinationInsideSource => {
                formatter.write_str("a namespace object cannot be moved into its own subtree")
            }
            Self::OpenHandleInSubtree(object) => write!(
                formatter,
                "namespace object `{object}` has a live handle in the affected subtree"
            ),
            Self::DirectoryNotEmpty(object) => {
                write!(formatter, "namespace directory `{object}` is not empty")
            }
            Self::OpenHandleCountExhausted(object) => write!(
                formatter,
                "namespace object `{object}` cannot accept another open handle"
            ),
            Self::NoOpenHandle(object) => {
                write!(
                    formatter,
                    "namespace object `{object}` has no open handle to close"
                )
            }
            Self::NamespaceGenerationExhausted => {
                formatter.write_str("namespace generation is exhausted")
            }
            Self::DirectoryGenerationChanged { expected, actual } => write!(
                formatter,
                "directory stream generation changed from {} to {}",
                expected.as_u64(),
                actual.as_u64()
            ),
            Self::InvariantViolation => {
                formatter.write_str("namespace path and object indexes are inconsistent")
            }
        }
    }
}

impl Error for NamespaceError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::InvalidChildName(error) => Some(error),
            Self::InvalidSymlinkTarget(error) => Some(error),
            Self::SymlinkTargetEscapes(error) => Some(error),
            _ => None,
        }
    }
}

impl From<InvalidSymlinkTarget> for NamespaceError {
    fn from(error: InvalidSymlinkTarget) -> Self {
        Self::InvalidSymlinkTarget(error)
    }
}

impl From<SymlinkTargetEscape> for NamespaceError {
    fn from(error: SymlinkTargetEscape) -> Self {
        Self::SymlinkTargetEscapes(error)
    }
}

/// A namespace rejection or an error reported by its backing executor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NamespaceOperationError<E> {
    /// The registry rejected the operation before invoking its executor.
    Namespace(NamespaceError),
    /// The backing executor returned an error.
    ///
    /// For ordinary methods this means failure before commit. Commit-aware
    /// methods can also return the error from a committed operation after they
    /// publish staged namespace state and quarantine the repository.
    Executor(E),
}

/// The executor's knowledge of whether an external namespace effect committed.
///
/// Ordinary [`Result::Err`] is insufficient at this boundary: a backing syscall
/// can cross its linearization point and only then lose its terminal audit
/// record. Mutating transactions publish their staged namespace state for
/// [`Self::CommittedWithError`] before quarantining the shared repository. This
/// keeps the in-memory namespace aligned with backing state while preventing
/// any later operation from trusting an unresolved audit outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NamespaceExecutorOutcome<T, E> {
    /// The external operation committed and produced its complete result.
    Committed(T),
    /// The external operation failed before its linearization point.
    FailedBeforeCommit(E),
    /// The external operation committed, but its terminal outcome is unresolved.
    CommittedWithError(E),
}

impl<T, E> From<Result<T, E>> for NamespaceExecutorOutcome<T, E> {
    fn from(result: Result<T, E>) -> Self {
        match result {
            Ok(value) => Self::Committed(value),
            Err(error) => Self::FailedBeforeCommit(error),
        }
    }
}

impl<E> From<NamespaceError> for NamespaceOperationError<E> {
    fn from(error: NamespaceError) -> Self {
        Self::Namespace(error)
    }
}

impl<E: fmt::Display> fmt::Display for NamespaceOperationError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Namespace(error) => write!(formatter, "namespace operation rejected: {error}"),
            Self::Executor(error) => {
                write!(formatter, "backing namespace operation failed: {error}")
            }
        }
    }
}

impl<E: Error + 'static> Error for NamespaceOperationError<E> {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Namespace(error) => Some(error),
            Self::Executor(error) => Some(error),
        }
    }
}

#[derive(Debug, Clone)]
struct NamespaceState {
    objects: BTreeMap<ObjectId, NamespaceObject>,
    paths: HashMap<CanonicalPath, ObjectId>,
    next_object_sequence: Option<u64>,
    generation: NamespaceGeneration,
}

impl NamespaceState {
    fn with_root() -> Self {
        let root = object_id(ROOT_OBJECT_SEQUENCE);
        let root_object = NamespaceObject::new(
            root.clone(),
            CanonicalPath::root(),
            &NamespaceObjectSpec::Directory,
        );
        let mut objects = BTreeMap::new();
        objects.insert(root.clone(), root_object);
        let mut paths = HashMap::new();
        paths.insert(CanonicalPath::root(), root);

        Self {
            objects,
            paths,
            next_object_sequence: ROOT_OBJECT_SEQUENCE.checked_add(1),
            generation: NamespaceGeneration::initial(),
        }
    }

    fn next_generation(&self) -> Result<NamespaceGeneration, NamespaceError> {
        self.generation
            .checked_next()
            .ok_or(NamespaceError::NamespaceGenerationExhausted)
    }

    fn validate_new_path(&self, path: &CanonicalPath) -> Result<(), NamespaceError> {
        if self.paths.contains_key(path) {
            return Err(NamespaceError::PathOccupied(path.clone()));
        }
        self.validate_parent(path)
    }

    fn validate_parent(&self, path: &CanonicalPath) -> Result<(), NamespaceError> {
        let Some(parent_path) = path.parent() else {
            return Err(NamespaceError::CannotModifyRoot);
        };
        let Some(parent_id) = self.paths.get(&parent_path) else {
            return Err(NamespaceError::MissingParent(parent_path));
        };
        let Some(parent) = self.objects.get(parent_id) else {
            return Err(NamespaceError::InvariantViolation);
        };
        if parent.kind != NamespaceObjectKind::Directory {
            return Err(NamespaceError::ParentNotDirectory(parent_path));
        }
        Ok(())
    }

    fn allocate_object(
        &mut self,
        path: CanonicalPath,
        spec: &NamespaceObjectSpec,
    ) -> Result<NamespaceObject, NamespaceError> {
        if let NamespaceObjectSpec::Symlink(target) = spec {
            // A link is registered only if it already resolves inside the
            // repository. Storing one that escapes would leave a record whose
            // only safe answer to `READLINK` is an error.
            target.resolve_from(&path)?;
        }
        let sequence = self
            .next_object_sequence
            .ok_or(NamespaceError::ObjectIdExhausted)?;
        let object_id = object_id(sequence);
        if self.objects.contains_key(&object_id) {
            return Err(NamespaceError::InvariantViolation);
        }
        self.next_object_sequence = sequence.checked_add(1);
        let object = NamespaceObject::new(object_id, path, spec);
        self.paths.insert(object.primary.clone(), object.id.clone());
        self.objects.insert(object.id.clone(), object.clone());
        Ok(object)
    }

    /// Gives one live object an additional name.
    ///
    /// Directories are refused: a second directory name would create a cycle
    /// the `..` walk and the subtree rules cannot reason about, and Linux
    /// refuses it for the same reason.
    fn attach_path(
        &mut self,
        object: &ObjectId,
        path: CanonicalPath,
    ) -> Result<NamespaceObject, NamespaceError> {
        let record = self
            .objects
            .get_mut(object)
            .ok_or_else(|| NamespaceError::UnknownObject(object.clone()))?;
        if record.kind == NamespaceObjectKind::Directory {
            return Err(NamespaceError::CannotAliasKind {
                object: object.clone(),
                kind: record.kind,
            });
        }
        record.insert_path(path.clone())?;
        let record = record.clone();
        self.paths.insert(path, object.clone());
        Ok(record)
    }
}

/// A VM-wide namespace registry protected by one reader-writer lock.
///
/// Read and write executors run while the relevant namespace guard remains held.
/// The ordinary `Result`-based APIs interpret executor errors as pre-commit
/// failures. Commit-aware APIs accept [`NamespaceExecutorOutcome`] so an error
/// after a backing mutation can publish the staged namespace transition before
/// quarantining the shared repository. A writer panic poisons the registry so
/// later operations fail closed instead of observing a possibly divergent
/// backing namespace. Executors must not reenter this registry. Filesystem
/// adapters must acquire the namespace guard before the Capability kernel guard
/// everywhere, keeping one global lock order for rename, revoke, and ordinary
/// I/O.
#[derive(Debug)]
pub struct NamespaceRegistry {
    state: RwLock<NamespaceState>,
    repository_in_doubt: AtomicBool,
}

impl Default for NamespaceRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl NamespaceRegistry {
    /// Creates a registry with one directory object at the repository root.
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: RwLock::new(NamespaceState::with_root()),
            repository_in_doubt: AtomicBool::new(false),
        }
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn from_manifest(
        entries: impl IntoIterator<Item = ManifestEntry>,
    ) -> Result<Self, NamespaceError> {
        let mut entries = entries.into_iter();
        let Some(root) = entries.next() else {
            return Err(NamespaceError::InvalidManifestRoot);
        };
        if !root.path.is_root() || root.spec != NamespaceObjectSpec::Directory {
            return Err(NamespaceError::InvalidManifestRoot);
        }

        let mut state = NamespaceState::with_root();
        let mut groups: HashMap<AliasGroup, ObjectId> = HashMap::new();
        for entry in entries {
            state.validate_new_path(&entry.path)?;
            if let Some(object) = groups.get(&entry.alias_group).cloned() {
                let record = state
                    .objects
                    .get(&object)
                    .ok_or(NamespaceError::InvariantViolation)?;
                // Two names for one inode must agree about what the inode
                // is. A disagreement means the scan and the filesystem
                // disagree, so the whole import fails rather than picking
                // one of the two records.
                if record.kind != entry.spec.kind()
                    || record.link_target.as_ref() != entry.spec.target()
                {
                    return Err(NamespaceError::InconsistentAliasGroup(entry.path));
                }
                state.attach_path(&object, entry.path)?;
            } else {
                let created = state.allocate_object(entry.path, &entry.spec)?;
                groups.insert(entry.alias_group, created.id.clone());
            }
        }
        Ok(Self {
            state: RwLock::new(state),
            repository_in_doubt: AtomicBool::new(false),
        })
    }

    /// Returns whether a committed effect has an unresolved terminal outcome.
    ///
    /// Every mount cloned from one imported repository shares this registry, so
    /// this bit is repository-wide rather than local to one FUSE adapter.
    #[must_use]
    pub fn is_in_doubt(&self) -> bool {
        self.repository_in_doubt.load(Ordering::Acquire)
    }

    /// Quarantines this repository after a non-namespace effect commits without
    /// a trustworthy terminal outcome.
    ///
    /// Namespace mutation methods do this automatically for
    /// [`NamespaceExecutorOutcome::CommittedWithError`]. The filesystem adapter
    /// uses this entry point for committed writes, truncates, and metadata
    /// changes that do not stage a namespace transition.
    pub(crate) fn mark_in_doubt(&self) {
        self.repository_in_doubt.store(true, Ordering::Release);
    }

    /// Rejects a normal repository operation after shared quarantine.
    ///
    /// Cleanup paths deliberately bypass this check so live handle counts can
    /// still be released while the containing session is discarded.
    pub(crate) fn ensure_operational(&self) -> Result<(), NamespaceError> {
        if self.is_in_doubt() {
            Err(NamespaceError::RepositoryInDoubt)
        } else {
            Ok(())
        }
    }

    /// Returns the current namespace generation.
    ///
    /// # Errors
    ///
    /// Returns [`NamespaceError::LockPoisoned`] after a writer panic or
    /// [`NamespaceError::RepositoryInDoubt`] after shared quarantine.
    pub fn generation(&self) -> Result<NamespaceGeneration, NamespaceError> {
        Ok(self.read_operational_state()?.generation)
    }

    /// Returns the number of live namespace objects.
    ///
    /// # Errors
    ///
    /// Returns [`NamespaceError::LockPoisoned`] after a writer panic or
    /// [`NamespaceError::RepositoryInDoubt`] after shared quarantine.
    pub fn object_count(&self) -> Result<usize, NamespaceError> {
        Ok(self.read_operational_state()?.objects.len())
    }

    /// Returns a point-in-time copy of an object record.
    ///
    /// This snapshot is for inspection only. Authorization and backing I/O must
    /// use [`Self::with_object`] so a rename cannot invalidate the path.
    ///
    /// # Errors
    ///
    /// Returns [`NamespaceError::LockPoisoned`] after a writer panic or
    /// [`NamespaceError::RepositoryInDoubt`] after shared quarantine.
    pub fn object_snapshot(
        &self,
        object: &ObjectId,
    ) -> Result<Option<NamespaceObject>, NamespaceError> {
        Ok(self.read_operational_state()?.objects.get(object).cloned())
    }

    /// Returns a point-in-time copy of the object at `path`.
    ///
    /// # Errors
    ///
    /// Returns [`NamespaceError::LockPoisoned`] after a writer panic or
    /// [`NamespaceError::RepositoryInDoubt`] after shared quarantine.
    pub fn object_at_path_snapshot(
        &self,
        path: &CanonicalPath,
    ) -> Result<Option<NamespaceObject>, NamespaceError> {
        let state = self.read_operational_state()?;
        Ok(state
            .paths
            .get(path)
            .and_then(|object| state.objects.get(object))
            .cloned())
    }

    /// Executes an object operation while its current path is protected from rename.
    ///
    /// The closure should perform Capability authorization and then reach the
    /// backing operation's linearization point before returning `Ok`.
    ///
    /// # Errors
    ///
    /// Returns a namespace error before invoking `operation`, or preserves the
    /// executor's typed failure.
    pub fn with_object<T, E>(
        &self,
        object: &ObjectId,
        operation: impl FnOnce(&NamespaceObject) -> Result<T, E>,
    ) -> Result<T, NamespaceOperationError<E>> {
        let state = self.read_operational_state()?;
        let object = state
            .objects
            .get(object)
            .ok_or_else(|| NamespaceError::UnknownObject(object.clone()))?;
        operation(object).map_err(NamespaceOperationError::Executor)
    }

    /// Resolves one child and executes an operation under a single read guard.
    ///
    /// Parent validation, child-path construction, path-to-object resolution,
    /// and `operation` all share the same namespace snapshot. A concurrent
    /// rename therefore cannot substitute a different object between lookup
    /// and the operation's linearization point.
    ///
    /// # Errors
    ///
    /// Returns a namespace error for an unknown parent, a non-directory
    /// parent, an invalid child name, or a missing child. Executor failures are
    /// preserved without changing namespace state.
    pub fn with_child<T, E>(
        &self,
        parent: &ObjectId,
        child_name: &str,
        operation: impl FnOnce(&NamespaceObject) -> Result<T, E>,
    ) -> Result<T, NamespaceOperationError<E>> {
        let state = self.read_operational_state()?;
        let parent = state
            .objects
            .get(parent)
            .ok_or_else(|| NamespaceError::UnknownObject(parent.clone()))?;
        if parent.kind != NamespaceObjectKind::Directory {
            return Err(NamespaceError::ParentNotDirectory(parent.primary.clone()).into());
        }
        let child_path = parent
            .primary
            .child(child_name)
            .map_err(NamespaceError::InvalidChildName)?;
        let child_id = state
            .paths
            .get(&child_path)
            .ok_or_else(|| NamespaceError::UnknownPath(child_path.clone()))?;
        let child = state
            .objects
            .get(child_id)
            .ok_or(NamespaceError::InvariantViolation)?;

        operation(child).map_err(NamespaceOperationError::Executor)
    }

    /// Enumerates one directory's direct children under a single read guard.
    ///
    /// The directory, its parent, the ordered child set, and `operation` all
    /// share one namespace snapshot. Children are sorted by canonical name,
    /// independent of object allocation or backing-directory iteration order.
    /// A concurrent create, remove, or rename cannot change the supplied view
    /// before `operation` reaches its linearization point.
    ///
    /// The repository root is its own parent for the `..` directory entry.
    ///
    /// # Errors
    ///
    /// Returns a namespace error for an unknown object, a non-directory object,
    /// a missing parent, poisoned state, or inconsistent indexes. Executor
    /// failures are preserved without changing namespace state.
    pub fn with_directory_children<T, E>(
        &self,
        directory: &ObjectId,
        operation: impl FnOnce(
            &NamespaceObject,
            &NamespaceObject,
            &[NamespaceChild<'_>],
        ) -> Result<T, E>,
    ) -> Result<T, NamespaceOperationError<E>> {
        self.with_directory_children_checked(directory, None, operation)
    }

    /// Enumerates direct children only when a captured namespace generation is
    /// still current.
    ///
    /// This gives stateful directory streams an explicit restart contract:
    /// after any committed namespace create, remove, or rename, callers must
    /// discard prior index cookies and begin a new stream. The check and the
    /// child view share one read guard, so a mutation cannot race between them.
    ///
    /// # Errors
    ///
    /// Returns [`NamespaceError::DirectoryGenerationChanged`] without invoking
    /// `operation` when the captured generation is stale. Other errors match
    /// [`Self::with_directory_children`].
    pub fn with_directory_children_at_generation<T, E>(
        &self,
        directory: &ObjectId,
        generation: NamespaceGeneration,
        operation: impl FnOnce(
            &NamespaceObject,
            &NamespaceObject,
            &[NamespaceChild<'_>],
        ) -> Result<T, E>,
    ) -> Result<T, NamespaceOperationError<E>> {
        self.with_directory_children_checked(directory, Some(generation), operation)
    }

    fn with_directory_children_checked<T, E>(
        &self,
        directory: &ObjectId,
        expected_generation: Option<NamespaceGeneration>,
        operation: impl FnOnce(
            &NamespaceObject,
            &NamespaceObject,
            &[NamespaceChild<'_>],
        ) -> Result<T, E>,
    ) -> Result<T, NamespaceOperationError<E>> {
        let state = self.read_operational_state()?;
        if let Some(expected) = expected_generation
            && state.generation != expected
        {
            return Err(NamespaceError::DirectoryGenerationChanged {
                expected,
                actual: state.generation,
            }
            .into());
        }
        let directory = state
            .objects
            .get(directory)
            .ok_or_else(|| NamespaceError::UnknownObject(directory.clone()))?;
        if directory.kind != NamespaceObjectKind::Directory {
            return Err(NamespaceError::ParentNotDirectory(directory.primary.clone()).into());
        }

        let parent = match directory.primary.parent() {
            Some(parent_path) => {
                let parent_id = state
                    .paths
                    .get(&parent_path)
                    .ok_or_else(|| NamespaceError::MissingParent(parent_path.clone()))?;
                state
                    .objects
                    .get(parent_id)
                    .ok_or(NamespaceError::InvariantViolation)?
            }
            None => directory,
        };
        // Enumerate names, not objects: one hard-linked inode can appear under
        // two names, and each name is its own directory entry.
        let child_depth = directory.primary.as_segments().len() + 1;
        let mut children = state
            .paths
            .iter()
            .filter(|(path, _)| {
                path.as_segments().len() == child_depth && path.is_at_or_below(&directory.primary)
            })
            .map(|(path, object)| {
                let object = state
                    .objects
                    .get(object)
                    .ok_or(NamespaceError::InvariantViolation)?;
                Ok(NamespaceChild { path, object })
            })
            .collect::<Result<Vec<_>, NamespaceError>>()?;
        children.sort_unstable_by(|left, right| {
            left.path
                .as_segments()
                .last()
                .cmp(&right.path.as_segments().last())
        });

        operation(directory, parent, children.as_slice()).map_err(NamespaceOperationError::Executor)
    }

    /// Commits one open while preventing concurrent rename or removal.
    ///
    /// The open count is rolled back when `operation` returns `Err`. A panic
    /// poisons the writer lock and therefore fails all later registry access.
    ///
    /// # Errors
    ///
    /// Returns an error for an unknown object, exhausted open count, poisoned
    /// registry, or backing operation failure.
    pub fn open_object<T, E>(
        &self,
        object: &ObjectId,
        operation: impl FnOnce(&NamespaceObject) -> Result<T, E>,
    ) -> Result<T, NamespaceOperationError<E>> {
        self.open_object_with_commit_outcome(object, |object| operation(object).into())
    }

    /// Commits one open while distinguishing pre-commit failure from an
    /// unresolved error after the external effect committed.
    ///
    /// A committed error does not publish an unusable open handle, but it does
    /// quarantine the shared repository before the writer guard is released.
    ///
    /// # Errors
    ///
    /// Uses the same namespace rejection conditions as [`Self::open_object`].
    /// [`NamespaceExecutorOutcome::FailedBeforeCommit`] and
    /// [`NamespaceExecutorOutcome::CommittedWithError`] preserve their executor
    /// error as [`NamespaceOperationError::Executor`].
    pub fn open_object_with_commit_outcome<T, E>(
        &self,
        object: &ObjectId,
        operation: impl FnOnce(&NamespaceObject) -> NamespaceExecutorOutcome<T, E>,
    ) -> Result<T, NamespaceOperationError<E>> {
        let mut state = self.write_operational_state()?;
        let object_record = state
            .objects
            .get_mut(object)
            .ok_or_else(|| NamespaceError::UnknownObject(object.clone()))?;
        let Some(next_count) = object_record.open_handle_count.checked_add(1) else {
            return Err(NamespaceError::OpenHandleCountExhausted(object.clone()).into());
        };
        let operation_record = object_record.clone();
        object_record.open_handle_count = next_count;

        match operation(&operation_record) {
            NamespaceExecutorOutcome::Committed(value) => Ok(value),
            NamespaceExecutorOutcome::FailedBeforeCommit(error) => {
                object_record.open_handle_count -= 1;
                Err(NamespaceOperationError::Executor(error))
            }
            NamespaceExecutorOutcome::CommittedWithError(error) => {
                object_record.open_handle_count -= 1;
                self.mark_in_doubt();
                Err(NamespaceOperationError::Executor(error))
            }
        }
    }

    /// Commits one close while preventing concurrent rename or removal.
    ///
    /// The open count is restored when `operation` returns `Err`.
    ///
    /// # Errors
    ///
    /// Returns an error for an unknown object, a zero open count, poisoned
    /// registry, or backing operation failure.
    pub fn close_object<T, E>(
        &self,
        object: &ObjectId,
        operation: impl FnOnce(&NamespaceObject) -> Result<T, E>,
    ) -> Result<T, NamespaceOperationError<E>> {
        let mut state = self.write_operational_state()?;
        close_object_in_state(&mut state, object, operation)
    }

    /// Releases an already-issued open count while the repository is
    /// quarantined.
    ///
    /// This is deliberately crate-private: filesystem destruction may need to
    /// retire handles after an unrelated committed error, but ordinary callers
    /// must not use cleanup as a way to execute new backing mutations while the
    /// repository is in doubt.
    #[allow(
        dead_code,
        reason = "the filesystem adapter uses this during destruction-only cleanup"
    )]
    pub(crate) fn close_object_for_cleanup<T, E>(
        &self,
        object: &ObjectId,
        operation: impl FnOnce(&NamespaceObject) -> Result<T, E>,
    ) -> Result<T, NamespaceOperationError<E>> {
        let mut state = self.write_state()?;
        close_object_in_state(&mut state, object, operation)
    }

    /// Creates an object and publishes it only after the backing executor succeeds.
    ///
    /// The registry stages a path-independent object identity and returns it only
    /// after `operation` commits. Executor failure leaves that identity unissued.
    ///
    /// # Errors
    ///
    /// Returns an error for an occupied path, invalid parent, exhausted object
    /// identity or generation, poisoned registry, or backing operation failure.
    #[allow(
        clippy::needless_pass_by_value,
        reason = "the specification is stored on the created object"
    )]
    pub fn create_object<T, E>(
        &self,
        path: CanonicalPath,
        spec: NamespaceObjectSpec,
        operation: impl FnOnce(&NamespaceObject) -> Result<T, E>,
    ) -> Result<NamespaceObjectCreation<T>, NamespaceOperationError<E>> {
        self.create_object_with_commit_outcome(path, spec, |object| operation(object).into())
    }

    /// Creates one object with an executor outcome that identifies committed
    /// errors explicitly.
    ///
    /// A committed error publishes the staged object and generation, marks the
    /// repository in doubt, and then returns the executor error. This preserves
    /// backing/namespace agreement without allowing later use of an unresolved
    /// repository.
    ///
    /// # Errors
    ///
    /// Uses the same namespace rejection conditions as [`Self::create_object`].
    #[allow(
        clippy::needless_pass_by_value,
        reason = "the specification is stored on the created object"
    )]
    pub fn create_object_with_commit_outcome<T, E>(
        &self,
        path: CanonicalPath,
        spec: NamespaceObjectSpec,
        operation: impl FnOnce(&NamespaceObject) -> NamespaceExecutorOutcome<T, E>,
    ) -> Result<NamespaceObjectCreation<T>, NamespaceOperationError<E>> {
        let mut state = self.write_operational_state()?;
        state.validate_new_path(&path)?;
        let next_generation = state.next_generation()?;
        let mut next_state = state.clone();
        let object_record = next_state.allocate_object(path, &spec)?;
        next_state.generation = next_generation;

        let object_id = object_record.id.clone();
        let result = finish_namespace_mutation(
            &mut state,
            &self.repository_in_doubt,
            next_state,
            operation(&object_record),
        )?;
        Ok(NamespaceObjectCreation::new(object_id, result))
    }

    /// Creates one direct child of a current parent object.
    ///
    /// The parent identity is resolved and its child path is constructed while
    /// the namespace write guard is held. This is required for filesystem
    /// create operations: deriving a child path from a snapshot before taking
    /// the guard could authorize an old parent path after a concurrent rename.
    ///
    /// # Errors
    ///
    /// Returns an error for an unknown or non-directory parent, invalid child
    /// name, occupied child path, exhausted identity or generation, poisoned
    /// registry, or backing operation failure.
    pub fn create_child<T, E>(
        &self,
        parent: &ObjectId,
        child_name: &str,
        spec: NamespaceObjectSpec,
        operation: impl FnOnce(&NamespaceObject, &NamespaceObject) -> Result<T, E>,
    ) -> Result<NamespaceObjectCreation<T>, NamespaceOperationError<E>> {
        self.create_child_with_commit_outcome(parent, child_name, spec, |parent, child| {
            operation(parent, child).into()
        })
    }

    /// Creates one direct child with explicit external commit classification.
    ///
    /// # Errors
    ///
    /// Uses the same namespace rejection conditions as [`Self::create_child`].
    pub fn create_child_with_commit_outcome<T, E>(
        &self,
        parent: &ObjectId,
        child_name: &str,
        spec: NamespaceObjectSpec,
        operation: impl FnOnce(&NamespaceObject, &NamespaceObject) -> NamespaceExecutorOutcome<T, E>,
    ) -> Result<NamespaceObjectCreation<T>, NamespaceOperationError<E>> {
        self.create_child_with_open_count(parent, child_name, spec, 0, operation)
    }

    /// Gives one live object an additional name below a current parent.
    ///
    /// The executor sees the parent record, the object as it will look once the
    /// new name is published, and that new path. Publishing only after the
    /// executor commits keeps a failed `linkat` from leaving a name the backing
    /// tree does not have.
    ///
    /// # Why this cannot widen authority
    ///
    /// Every later operation on the object is authorized against
    /// [`NamespaceObject::paths`], which now includes both names. Adding an
    /// alias therefore never grants access through the new name that the old
    /// name did not already require; it can only make the object harder to
    /// reach. The adapter separately requires authority over the existing name
    /// so a caller cannot make an object it does not hold unusable.
    ///
    /// # Errors
    ///
    /// Returns an error for an unknown or non-directory parent, an unknown
    /// source object, a directory source, an invalid or occupied child name,
    /// exhausted generation, poisoned registry, or backing operation failure.
    pub fn link_child<T, E>(
        &self,
        parent: &ObjectId,
        child_name: &str,
        source: &ObjectId,
        operation: impl FnOnce(&NamespaceObject, &NamespaceObject, &CanonicalPath) -> Result<T, E>,
    ) -> Result<T, NamespaceOperationError<E>> {
        self.link_child_with_commit_outcome(parent, child_name, source, |parent, linked, path| {
            operation(parent, linked, path).into()
        })
    }

    /// Adds one name with explicit external commit classification.
    ///
    /// A committed error publishes the new alias before quarantining the
    /// repository, so the registry retains the link count the backing inode now
    /// has.
    ///
    /// # Errors
    ///
    /// Uses the same namespace rejection conditions as [`Self::link_child`].
    pub fn link_child_with_commit_outcome<T, E>(
        &self,
        parent: &ObjectId,
        child_name: &str,
        source: &ObjectId,
        operation: impl FnOnce(
            &NamespaceObject,
            &NamespaceObject,
            &CanonicalPath,
        ) -> NamespaceExecutorOutcome<T, E>,
    ) -> Result<T, NamespaceOperationError<E>> {
        let mut state = self.write_operational_state()?;
        let parent_record = state
            .objects
            .get(parent)
            .cloned()
            .ok_or_else(|| NamespaceError::UnknownObject(parent.clone()))?;
        if parent_record.kind != NamespaceObjectKind::Directory {
            return Err(NamespaceError::ParentNotDirectory(parent_record.primary.clone()).into());
        }
        if !state.objects.contains_key(source) {
            return Err(NamespaceError::UnknownObject(source.clone()).into());
        }
        let path = parent_record
            .primary
            .child(child_name)
            .map_err(NamespaceError::InvalidChildName)?;
        state.validate_new_path(&path)?;
        let next_generation = state.next_generation()?;
        let mut next_state = state.clone();
        let linked_record = next_state.attach_path(source, path.clone())?;
        next_state.generation = next_generation;

        let outcome = operation(&parent_record, &linked_record, &path);
        finish_namespace_mutation(&mut state, &self.repository_in_doubt, next_state, outcome)
    }

    /// Creates and opens one direct child as one namespace transaction.
    ///
    /// The published record starts with exactly one open handle. Callers must
    /// create the corresponding Authority handle and backing descriptor inside
    /// `operation`; an executor error publishes neither the path nor that open
    /// count. This prevents `CREATE` from exposing a moment in which a newly
    /// created file can be removed before its returned FUSE handle is live.
    ///
    /// # Errors
    ///
    /// Uses the same rejection conditions as [`Self::create_child`].
    pub fn create_open_child<T, E>(
        &self,
        parent: &ObjectId,
        child_name: &str,
        spec: NamespaceObjectSpec,
        operation: impl FnOnce(&NamespaceObject, &NamespaceObject) -> Result<T, E>,
    ) -> Result<NamespaceObjectCreation<T>, NamespaceOperationError<E>> {
        self.create_open_child_with_commit_outcome(parent, child_name, spec, |parent, child| {
            operation(parent, child).into()
        })
    }

    /// Creates and opens one child with explicit external commit classification.
    ///
    /// A committed error publishes the backing-created object with zero open
    /// handles. The caller did not receive a usable descriptor and must release
    /// any Authority-side handle before returning that outcome.
    ///
    /// # Errors
    ///
    /// Uses the same namespace rejection conditions as
    /// [`Self::create_open_child`].
    pub fn create_open_child_with_commit_outcome<T, E>(
        &self,
        parent: &ObjectId,
        child_name: &str,
        spec: NamespaceObjectSpec,
        operation: impl FnOnce(&NamespaceObject, &NamespaceObject) -> NamespaceExecutorOutcome<T, E>,
    ) -> Result<NamespaceObjectCreation<T>, NamespaceOperationError<E>> {
        self.create_child_with_open_count(parent, child_name, spec, 1, operation)
    }

    /// Removes the single name of an empty, unopened object.
    ///
    /// # Errors
    ///
    /// Returns an error for root, unknown or non-empty objects, objects with
    /// more than one name, live handles, exhausted generation, poisoned
    /// registry, or backing operation failure.
    pub fn remove_object<T, E>(
        &self,
        object: &ObjectId,
        operation: impl FnOnce(&NamespaceObject) -> Result<T, E>,
    ) -> Result<T, NamespaceOperationError<E>> {
        self.remove_object_with_commit_outcome(object, |object| operation(object).into())
    }

    /// Removes an object's sole name with explicit commit classification.
    ///
    /// # Errors
    ///
    /// Uses the same namespace rejection conditions as [`Self::remove_object`].
    pub fn remove_object_with_commit_outcome<T, E>(
        &self,
        object: &ObjectId,
        operation: impl FnOnce(&NamespaceObject) -> NamespaceExecutorOutcome<T, E>,
    ) -> Result<T, NamespaceOperationError<E>> {
        let mut state = self.write_operational_state()?;
        let object_record = state
            .objects
            .get(object)
            .cloned()
            .ok_or_else(|| NamespaceError::UnknownObject(object.clone()))?;
        if object_record.is_aliased() {
            // Which name to drop is not derivable from the object alone.
            return Err(NamespaceError::AmbiguousObjectPath(object.clone()).into());
        }
        let removed_path = object_record.primary.clone();
        remove_record(
            &mut state,
            &self.repository_in_doubt,
            &object_record,
            &removed_path,
            |object, _| operation(object),
        )
    }

    /// Removes a direct child of its current parent as one namespace transaction.
    ///
    /// Both the parent-relative lookup and the removal executor run under the
    /// writer lock. This prevents a FUSE `UNLINK` or `RMDIR` request from
    /// resolving one name and later removing the same object after it has been
    /// renamed somewhere else. The executor receives the live parent record so
    /// its backing operation can use a validated parent descriptor directly.
    ///
    /// # Errors
    ///
    /// Returns an error for an unknown or non-directory parent, invalid or
    /// missing child name, root removal, live handles, a non-empty directory,
    /// exhausted generation, poisoned registry, or backing operation failure.
    pub fn remove_child<T, E>(
        &self,
        parent: &ObjectId,
        child_name: &str,
        operation: impl FnOnce(&NamespaceObject, &NamespaceObject, &CanonicalPath) -> Result<T, E>,
    ) -> Result<T, NamespaceOperationError<E>> {
        self.remove_child_with_commit_outcome(parent, child_name, |parent, child, path| {
            operation(parent, child, path).into()
        })
    }

    /// Removes one direct child with explicit external commit classification.
    ///
    /// A committed error publishes the staged path removal before quarantining
    /// the repository.
    ///
    /// # Errors
    ///
    /// Uses the same namespace rejection conditions as [`Self::remove_child`].
    pub fn remove_child_with_commit_outcome<T, E>(
        &self,
        parent: &ObjectId,
        child_name: &str,
        operation: impl FnOnce(
            &NamespaceObject,
            &NamespaceObject,
            &CanonicalPath,
        ) -> NamespaceExecutorOutcome<T, E>,
    ) -> Result<T, NamespaceOperationError<E>> {
        let mut state = self.write_operational_state()?;
        let parent_record = state
            .objects
            .get(parent)
            .cloned()
            .ok_or_else(|| NamespaceError::UnknownObject(parent.clone()))?;
        if parent_record.kind != NamespaceObjectKind::Directory {
            return Err(NamespaceError::ParentNotDirectory(parent_record.primary.clone()).into());
        }
        let child_path = parent_record
            .primary
            .child(child_name)
            .map_err(NamespaceError::InvalidChildName)?;
        let child_id = state
            .paths
            .get(&child_path)
            .ok_or_else(|| NamespaceError::UnknownPath(child_path.clone()))?;
        let child_record = state
            .objects
            .get(child_id)
            .cloned()
            .ok_or(NamespaceError::InvariantViolation)?;

        remove_record(
            &mut state,
            &self.repository_in_doubt,
            &child_record,
            &child_path,
            |child, path| operation(&parent_record, child, path),
        )
    }

    #[allow(
        clippy::needless_pass_by_value,
        reason = "the specification is stored on the created object"
    )]
    fn create_child_with_open_count<T, E>(
        &self,
        parent: &ObjectId,
        child_name: &str,
        spec: NamespaceObjectSpec,
        open_handle_count: u64,
        operation: impl FnOnce(&NamespaceObject, &NamespaceObject) -> NamespaceExecutorOutcome<T, E>,
    ) -> Result<NamespaceObjectCreation<T>, NamespaceOperationError<E>> {
        let mut state = self.write_operational_state()?;
        let parent_record = state
            .objects
            .get(parent)
            .cloned()
            .ok_or_else(|| NamespaceError::UnknownObject(parent.clone()))?;
        if parent_record.kind != NamespaceObjectKind::Directory {
            return Err(NamespaceError::ParentNotDirectory(parent_record.primary.clone()).into());
        }
        let path = parent_record
            .primary
            .child(child_name)
            .map_err(NamespaceError::InvalidChildName)?;
        state.validate_new_path(&path)?;
        let next_generation = state.next_generation()?;
        let mut next_state = state.clone();
        let object_record = next_state.allocate_object(path, &spec)?;
        let object_id = object_record.id.clone();
        if open_handle_count != 0 {
            let object_record = next_state
                .objects
                .get_mut(&object_id)
                .ok_or(NamespaceError::InvariantViolation)?;
            object_record.open_handle_count = open_handle_count;
        }
        let object_record = next_state
            .objects
            .get(&object_id)
            .cloned()
            .ok_or(NamespaceError::InvariantViolation)?;
        next_state.generation = next_generation;

        let outcome = operation(&parent_record, &object_record);
        if matches!(&outcome, NamespaceExecutorOutcome::CommittedWithError(_))
            && open_handle_count != 0
        {
            next_state
                .objects
                .get_mut(&object_id)
                .ok_or(NamespaceError::InvariantViolation)?
                .open_handle_count = 0;
        }
        let result =
            finish_namespace_mutation(&mut state, &self.repository_in_doubt, next_state, outcome)?;
        Ok(NamespaceObjectCreation::new(object_id, result))
    }

    /// Renames a closed subtree without replacing an existing destination.
    ///
    /// The closure runs under the namespace write lock and receives every path
    /// change, allowing the adapter to authorize both sides and execute one
    /// no-replace backing rename before the registry publishes the new paths.
    ///
    /// # Errors
    ///
    /// Returns an error for root or unknown sources, occupied or invalid
    /// destinations, moves into the source subtree, live handles, exhausted
    /// generation, poisoned registry, or backing operation failure.
    pub fn rename_subtree<T, E>(
        &self,
        source: &CanonicalPath,
        destination: CanonicalPath,
        operation: impl FnOnce(&RenamePlan) -> Result<T, E>,
    ) -> Result<T, NamespaceOperationError<E>> {
        self.rename_subtree_with_commit_outcome(source, destination, |plan| operation(plan).into())
    }

    /// Renames a subtree with explicit external commit classification.
    ///
    /// # Errors
    ///
    /// Uses the same namespace rejection conditions as [`Self::rename_subtree`].
    pub fn rename_subtree_with_commit_outcome<T, E>(
        &self,
        source: &CanonicalPath,
        destination: CanonicalPath,
        operation: impl FnOnce(&RenamePlan) -> NamespaceExecutorOutcome<T, E>,
    ) -> Result<T, NamespaceOperationError<E>> {
        let mut state = self.write_operational_state()?;
        rename_records(
            &mut state,
            &self.repository_in_doubt,
            source.clone(),
            destination,
            operation,
        )
    }

    /// Renames a direct child between current parent objects without replacement.
    ///
    /// Both names are constructed after the writer lock resolves the two
    /// parent identities. A parent rename therefore cannot turn an authorized
    /// FUSE `RENAME` source or destination into a different backing path before
    /// the no-replace rename reaches its linearization point.
    ///
    /// # Errors
    ///
    /// Returns an error for unknown or non-directory parents, invalid names,
    /// a missing source, occupied destination, a destination inside the source
    /// subtree, live handles, exhausted generation, poisoned registry, or
    /// backing operation failure.
    pub fn rename_child<T, E>(
        &self,
        source_parent: &ObjectId,
        source_name: &str,
        destination_parent: &ObjectId,
        destination_name: &str,
        operation: impl FnOnce(&RenamePlan) -> Result<T, E>,
    ) -> Result<T, NamespaceOperationError<E>> {
        self.rename_child_with_commit_outcome(
            source_parent,
            source_name,
            destination_parent,
            destination_name,
            |plan| operation(plan).into(),
        )
    }

    /// Renames one direct child with explicit external commit classification.
    ///
    /// A committed error publishes every staged path move before quarantining
    /// the repository.
    ///
    /// # Errors
    ///
    /// Uses the same namespace rejection conditions as [`Self::rename_child`].
    pub fn rename_child_with_commit_outcome<T, E>(
        &self,
        source_parent: &ObjectId,
        source_name: &str,
        destination_parent: &ObjectId,
        destination_name: &str,
        operation: impl FnOnce(&RenamePlan) -> NamespaceExecutorOutcome<T, E>,
    ) -> Result<T, NamespaceOperationError<E>> {
        let mut state = self.write_operational_state()?;
        let source_parent = state
            .objects
            .get(source_parent)
            .ok_or_else(|| NamespaceError::UnknownObject(source_parent.clone()))?;
        if source_parent.kind != NamespaceObjectKind::Directory {
            return Err(NamespaceError::ParentNotDirectory(source_parent.primary.clone()).into());
        }
        let source = source_parent
            .primary
            .child(source_name)
            .map_err(NamespaceError::InvalidChildName)?;
        let destination_parent = state
            .objects
            .get(destination_parent)
            .ok_or_else(|| NamespaceError::UnknownObject(destination_parent.clone()))?;
        if destination_parent.kind != NamespaceObjectKind::Directory {
            return Err(
                NamespaceError::ParentNotDirectory(destination_parent.primary.clone()).into(),
            );
        }
        let destination = destination_parent
            .primary
            .child(destination_name)
            .map_err(NamespaceError::InvalidChildName)?;

        rename_records(
            &mut state,
            &self.repository_in_doubt,
            source,
            destination,
            operation,
        )
    }

    fn read_state(&self) -> Result<RwLockReadGuard<'_, NamespaceState>, NamespaceError> {
        self.state.read().map_err(|_| NamespaceError::LockPoisoned)
    }

    fn read_operational_state(
        &self,
    ) -> Result<RwLockReadGuard<'_, NamespaceState>, NamespaceError> {
        let state = self.read_state()?;
        self.ensure_operational()?;
        Ok(state)
    }

    fn write_state(&self) -> Result<RwLockWriteGuard<'_, NamespaceState>, NamespaceError> {
        self.state.write().map_err(|_| NamespaceError::LockPoisoned)
    }

    fn write_operational_state(
        &self,
    ) -> Result<RwLockWriteGuard<'_, NamespaceState>, NamespaceError> {
        let state = self.write_state()?;
        self.ensure_operational()?;
        Ok(state)
    }
}

/// Detaches one name, retiring the object when that name was its last.
///
/// Removing a name an inode still shares with another name cannot orphan the
/// inode, so the open-handle rule does not apply to it: what that rule protects
/// against is a live object with no path left, and an aliased object keeps one.
/// Removing the *last* name keeps the original contract, including `EBUSY`
/// while a handle is open.
fn remove_record<T, E>(
    state: &mut NamespaceState,
    repository_in_doubt: &AtomicBool,
    object_record: &NamespaceObject,
    removed_path: &CanonicalPath,
    operation: impl FnOnce(&NamespaceObject, &CanonicalPath) -> NamespaceExecutorOutcome<T, E>,
) -> Result<T, NamespaceOperationError<E>> {
    if removed_path.is_root() {
        return Err(NamespaceError::CannotModifyRoot.into());
    }
    if !object_record.owns_path(removed_path) {
        return Err(NamespaceError::InvariantViolation.into());
    }
    let retires_object = !object_record.is_aliased();
    if retires_object {
        if object_record.open_handle_count != 0 {
            return Err(NamespaceError::OpenHandleInSubtree(object_record.id.clone()).into());
        }
        if state
            .paths
            .keys()
            .any(|candidate| candidate != removed_path && candidate.is_at_or_below(removed_path))
        {
            return Err(NamespaceError::DirectoryNotEmpty(object_record.id.clone()).into());
        }
    }
    let next_generation = state.next_generation()?;
    let mut next_state = state.clone();
    if next_state.paths.remove(removed_path).is_none() {
        return Err(NamespaceError::InvariantViolation.into());
    }
    let record = next_state
        .objects
        .get_mut(&object_record.id)
        .ok_or(NamespaceError::InvariantViolation)?;
    match record.remove_path(removed_path)? {
        PathRemoval::Retired => {
            if next_state.objects.remove(&object_record.id).is_none() {
                return Err(NamespaceError::InvariantViolation.into());
            }
        }
        PathRemoval::Detached => {}
    }
    next_state.generation = next_generation;

    let outcome = operation(object_record, removed_path);
    finish_namespace_mutation(state, repository_in_doubt, next_state, outcome)
}

fn rename_records<T, E>(
    state: &mut NamespaceState,
    repository_in_doubt: &AtomicBool,
    source: CanonicalPath,
    destination: CanonicalPath,
    operation: impl FnOnce(&RenamePlan) -> NamespaceExecutorOutcome<T, E>,
) -> Result<T, NamespaceOperationError<E>> {
    if source.is_root() {
        return Err(NamespaceError::CannotModifyRoot.into());
    }
    if !state.paths.contains_key(&source) {
        return Err(NamespaceError::UnknownPath(source).into());
    }
    if state.paths.contains_key(&destination) {
        return Err(NamespaceError::PathOccupied(destination).into());
    }
    if destination.is_at_or_below(&source) {
        return Err(NamespaceError::DestinationInsideSource.into());
    }
    state.validate_parent(&destination)?;

    // A rename moves names, not inodes. An aliased object whose other name
    // lives outside the moved subtree keeps that name untouched.
    let mut moved_objects = Vec::new();
    for (path, object_id) in state
        .paths
        .iter()
        .filter(|(path, _)| path.is_at_or_below(&source))
    {
        let object = state
            .objects
            .get(object_id)
            .ok_or(NamespaceError::InvariantViolation)?;
        if object.open_handle_count != 0 {
            return Err(NamespaceError::OpenHandleInSubtree(object.id.clone()).into());
        }
        let Some(rebased_path) = path.rebase(&source, &destination) else {
            return Err(NamespaceError::InvariantViolation.into());
        };
        moved_objects.push(NamespaceMove {
            object: object.id.clone(),
            source: path.clone(),
            destination: rebased_path,
            kind: object.kind,
            expected_link_count: object.expected_link_count(),
        });
    }
    moved_objects
        .sort_unstable_by(|left, right| left.source.as_segments().cmp(right.source.as_segments()));

    let next_generation = state.next_generation()?;
    let plan = RenamePlan {
        source,
        destination,
        moved_objects,
    };
    let mut next_state = state.clone();
    for movement in &plan.moved_objects {
        if next_state.paths.remove(&movement.source).is_none() {
            return Err(NamespaceError::InvariantViolation.into());
        }
    }
    for movement in &plan.moved_objects {
        if next_state.paths.contains_key(&movement.destination) {
            return Err(NamespaceError::PathOccupied(movement.destination.clone()).into());
        }
        let Some(object) = next_state.objects.get_mut(&movement.object) else {
            return Err(NamespaceError::InvariantViolation.into());
        };
        object.replace_path(&movement.source, movement.destination.clone())?;
        next_state
            .paths
            .insert(movement.destination.clone(), movement.object.clone());
    }
    next_state.generation = next_generation;

    let outcome = operation(&plan);
    finish_namespace_mutation(state, repository_in_doubt, next_state, outcome)
}

/// Applies one close transition to an already-selected namespace state.
fn close_object_in_state<T, E>(
    state: &mut NamespaceState,
    object: &ObjectId,
    operation: impl FnOnce(&NamespaceObject) -> Result<T, E>,
) -> Result<T, NamespaceOperationError<E>> {
    let object_record = state
        .objects
        .get_mut(object)
        .ok_or_else(|| NamespaceError::UnknownObject(object.clone()))?;
    if object_record.open_handle_count == 0 {
        return Err(NamespaceError::NoOpenHandle(object.clone()).into());
    }
    let operation_record = object_record.clone();
    object_record.open_handle_count -= 1;

    match operation(&operation_record) {
        Ok(value) => Ok(value),
        Err(error) => {
            object_record.open_handle_count += 1;
            Err(NamespaceOperationError::Executor(error))
        }
    }
}

/// Resolves a staged namespace transition without conflating executor error
/// reporting with external commit status.
fn finish_namespace_mutation<T, E>(
    state: &mut NamespaceState,
    repository_in_doubt: &AtomicBool,
    next_state: NamespaceState,
    outcome: NamespaceExecutorOutcome<T, E>,
) -> Result<T, NamespaceOperationError<E>> {
    match outcome {
        NamespaceExecutorOutcome::Committed(value) => {
            *state = next_state;
            Ok(value)
        }
        NamespaceExecutorOutcome::FailedBeforeCommit(error) => {
            Err(NamespaceOperationError::Executor(error))
        }
        NamespaceExecutorOutcome::CommittedWithError(error) => {
            *state = next_state;
            // The writer guard is still held here. The release store therefore
            // becomes visible before any later operation can acquire the guard
            // and inspect the published state.
            repository_in_doubt.store(true, Ordering::Release);
            Err(NamespaceOperationError::Executor(error))
        }
    }
}

struct DisplayPath<'a>(&'a CanonicalPath);

impl fmt::Display for DisplayPath<'_> {
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
    use std::{
        convert::Infallible,
        panic::{AssertUnwindSafe, catch_unwind},
        sync::Arc,
    };

    use authority_core::path::CanonicalPath;

    #[cfg(target_os = "linux")]
    use super::{AliasGroup, ManifestEntry};
    use super::{
        InvalidSymlinkTargetReason, MAX_SYMLINK_TARGET_BYTES, NamespaceError,
        NamespaceExecutorOutcome, NamespaceGeneration, NamespaceObject, NamespaceObjectSpec,
        NamespaceOperationError, NamespaceRegistry, SymlinkTarget,
    };

    fn path(segments: &[&str]) -> CanonicalPath {
        CanonicalPath::new(segments).expect("test paths must be canonical")
    }

    fn raw_object_at(
        registry: &NamespaceRegistry,
        object_path: &CanonicalPath,
    ) -> Option<NamespaceObject> {
        let state = registry
            .state
            .read()
            .expect("test registry state must remain readable");
        state
            .paths
            .get(object_path)
            .and_then(|object| state.objects.get(object))
            .cloned()
    }

    #[cfg(target_os = "linux")]
    fn manifest_entry(path: CanonicalPath, spec: NamespaceObjectSpec, inode: u64) -> ManifestEntry {
        ManifestEntry::new(path, spec, AliasGroup::new(inode))
    }

    // Requirement: only targets whose resolution can be proven to stay inside
    // the mount are representable, because the kernel resolves the string this
    // registry hands it without asking again.
    #[test]
    fn symlink_target_grammar_admits_only_provably_contained_bodies() {
        let accepted = [
            "main.rs",
            "src/main.rs",
            "../sibling.rs",
            "../../top.rs",
            "./here.rs",
        ];
        for literal in accepted {
            assert!(
                SymlinkTarget::new(literal).is_ok(),
                "`{literal}` should be representable"
            );
        }

        let rejected = [
            ("", InvalidSymlinkTargetReason::Empty),
            ("/etc/passwd", InvalidSymlinkTargetReason::Absolute),
            ("nul\0byte", InvalidSymlinkTargetReason::ContainsNul),
            // `s` could itself be a link to a shallower directory, so a lexical
            // containment check on this form would not bind the kernel's walk.
            (
                "s/../../elsewhere",
                InvalidSymlinkTargetReason::InteriorParent,
            ),
            ("a/..", InvalidSymlinkTargetReason::InteriorParent),
        ];
        for (literal, reason) in rejected {
            let error = SymlinkTarget::new(literal).expect_err("`{literal}` must be rejected");
            assert_eq!(error.reason(), reason, "for `{literal}`");
        }
        assert_eq!(
            SymlinkTarget::new("x".repeat(MAX_SYMLINK_TARGET_BYTES + 1))
                .expect_err("an oversized target must be rejected")
                .reason(),
            InvalidSymlinkTargetReason::TooLong
        );
    }

    // Requirement: resolution is relative to where the link is *now*, and a
    // target that would climb out of the repository is refused rather than
    // clamped to the root.
    #[test]
    fn symlink_target_resolves_against_the_links_current_path() {
        let target = SymlinkTarget::new("../shared/lib.rs").expect("target must be representable");
        assert_eq!(
            target.resolve_from(&path(&["src", "link.rs"])),
            Ok(path(&["shared", "lib.rs"]))
        );
        // The same body under a deeper parent denotes a different path, which is
        // why it cannot be resolved once and cached.
        assert_eq!(
            target.resolve_from(&path(&["a", "b", "link.rs"])),
            Ok(path(&["a", "shared", "lib.rs"]))
        );
        assert!(
            target.resolve_from(&path(&["link.rs"])).is_err(),
            "climbing above the repository root must fail closed"
        );
    }

    // Requirement: a link is registered only when it already resolves inside the
    // repository from the path it is being created at.
    #[test]
    fn symlink_creation_rejects_a_target_that_leaves_the_repository() {
        let registry = NamespaceRegistry::new();
        let mut executor_called = false;

        let result = registry.create_object(
            path(&["escape"]),
            NamespaceObjectSpec::Symlink(
                SymlinkTarget::new("../outside").expect("target must be representable"),
            ),
            |_| {
                executor_called = true;
                Ok::<_, Infallible>(())
            },
        );

        assert!(matches!(
            result,
            Err(NamespaceOperationError::Namespace(
                NamespaceError::SymlinkTargetEscapes(_)
            ))
        ));
        assert!(!executor_called);
        assert_eq!(registry.object_count(), Ok(1));
    }

    // Requirement: a second name belongs to the same object, and every name is
    // visible to authorization. Directories can never gain one.
    #[test]
    fn hard_links_add_names_to_one_object_and_never_to_a_directory() {
        let registry = NamespaceRegistry::new();
        let root = registry
            .object_at_path_snapshot(&CanonicalPath::root())
            .expect("registry must be readable")
            .expect("root must exist");
        let file = registry
            .create_child(
                root.id(),
                "original.rs",
                NamespaceObjectSpec::RegularFile,
                |_, _| Ok::<_, Infallible>(()),
            )
            .expect("file must register")
            .object()
            .clone();
        let directory = registry
            .create_child(root.id(), "dir", NamespaceObjectSpec::Directory, |_, _| {
                Ok::<_, Infallible>(())
            })
            .expect("directory must register")
            .object()
            .clone();

        registry
            .link_child(root.id(), "alias.rs", &file, |_, linked, link_path| {
                assert_eq!(link_path, &path(&["alias.rs"]));
                assert_eq!(linked.expected_link_count(), 2);
                Ok::<_, Infallible>(())
            })
            .expect("a regular file must accept a second name");

        let linked = registry
            .object_snapshot(&file)
            .expect("registry must be readable")
            .expect("the file must remain live");
        assert_eq!(
            linked.paths().cloned().collect::<Vec<_>>(),
            vec![path(&["alias.rs"]), path(&["original.rs"])],
            "both names must belong to one object, in sorted order"
        );
        assert_eq!(
            registry
                .object_at_path_snapshot(&path(&["alias.rs"]))
                .expect("registry must be readable")
                .map(|object| object.id().clone()),
            Some(file.clone())
        );

        assert!(matches!(
            registry.link_child(root.id(), "dir-alias", &directory, |_, _, _| Ok::<
                _,
                Infallible,
            >(
                ()
            )),
            Err(NamespaceOperationError::Namespace(
                NamespaceError::CannotAliasKind { .. }
            ))
        ));
    }

    // Requirement: dropping one of several names cannot orphan the inode, so it
    // is allowed even while a handle is open; dropping the last one keeps the
    // original `EBUSY` contract.
    #[test]
    fn removing_an_alias_keeps_the_object_until_its_last_name_goes() {
        let registry = NamespaceRegistry::new();
        let root = registry
            .object_at_path_snapshot(&CanonicalPath::root())
            .expect("registry must be readable")
            .expect("root must exist");
        let file = registry
            .create_child(
                root.id(),
                "original.rs",
                NamespaceObjectSpec::RegularFile,
                |_, _| Ok::<_, Infallible>(()),
            )
            .expect("file must register")
            .object()
            .clone();
        registry
            .link_child(root.id(), "alias.rs", &file, |_, _, _| {
                Ok::<_, Infallible>(())
            })
            .expect("second name must register");
        registry
            .open_object(&file, |_| Ok::<_, Infallible>(()))
            .expect("the file must open");

        registry
            .remove_child(root.id(), "alias.rs", |_, _, removed| {
                assert_eq!(removed, &path(&["alias.rs"]));
                Ok::<_, Infallible>(())
            })
            .expect("removing a non-final name must not depend on open handles");
        let remaining = registry
            .object_snapshot(&file)
            .expect("registry must be readable")
            .expect("the file must stay live while a name remains");
        assert_eq!(remaining.primary_path(), &path(&["original.rs"]));
        assert!(!remaining.is_aliased());

        assert!(matches!(
            registry.remove_child(root.id(), "original.rs", |_, _, _| Ok::<_, Infallible>(())),
            Err(NamespaceOperationError::Namespace(
                NamespaceError::OpenHandleInSubtree(_)
            )),
        ));
        registry
            .close_object(&file, |_| Ok::<_, Infallible>(()))
            .expect("the file must close");
        registry
            .remove_child(root.id(), "original.rs", |_, _, _| Ok::<_, Infallible>(()))
            .expect("the final name must be removable once closed");
        assert_eq!(
            registry
                .object_snapshot(&file)
                .expect("registry must be readable"),
            None
        );
    }

    // Requirement: a rename moves names. An alias outside the moved subtree
    // keeps its own name and stays part of the same object.
    #[test]
    fn renaming_a_subtree_moves_only_the_names_inside_it() {
        let registry = NamespaceRegistry::new();
        let root = registry
            .object_at_path_snapshot(&CanonicalPath::root())
            .expect("registry must be readable")
            .expect("root must exist");
        let source = registry
            .create_child(root.id(), "src", NamespaceObjectSpec::Directory, |_, _| {
                Ok::<_, Infallible>(())
            })
            .expect("directory must register")
            .object()
            .clone();
        let file = registry
            .create_child(
                &source,
                "main.rs",
                NamespaceObjectSpec::RegularFile,
                |_, _| Ok::<_, Infallible>(()),
            )
            .expect("file must register")
            .object()
            .clone();
        registry
            .link_child(root.id(), "outside.rs", &file, |_, _, _| {
                Ok::<_, Infallible>(())
            })
            .expect("second name must register");

        registry
            .rename_child(root.id(), "src", root.id(), "lib", |plan| {
                assert_eq!(plan.moved_objects().len(), 2, "only names under src move");
                Ok::<_, Infallible>(())
            })
            .expect("subtree rename must succeed");

        let moved = registry
            .object_snapshot(&file)
            .expect("registry must be readable")
            .expect("the file must remain live");
        assert_eq!(
            moved.paths().cloned().collect::<Vec<_>>(),
            vec![path(&["lib", "main.rs"]), path(&["outside.rs"])]
        );
    }

    // Requirement: a pre-commit executor failure consumes neither object IDs
    // nor generations and does not quarantine an otherwise healthy repository.
    #[test]
    fn classified_precommit_failure_rolls_back_without_quarantine() {
        let registry = NamespaceRegistry::new();
        let root = registry
            .object_at_path_snapshot(&CanonicalPath::root())
            .expect("registry must be readable")
            .expect("root must exist");

        let result = registry.create_child_with_commit_outcome(
            root.id(),
            "rejected.rs",
            NamespaceObjectSpec::RegularFile,
            |_, _| NamespaceExecutorOutcome::<(), _>::FailedBeforeCommit("pre-commit"),
        );

        assert_eq!(result, Err(NamespaceOperationError::Executor("pre-commit")));
        assert!(!registry.is_in_doubt());
        assert_eq!(registry.generation(), Ok(NamespaceGeneration::initial()));
        assert_eq!(
            registry
                .object_at_path_snapshot(&path(&["rejected.rs"]))
                .expect("healthy registry must remain readable"),
            None
        );
        let created = registry
            .create_child(
                root.id(),
                "accepted.rs",
                NamespaceObjectSpec::RegularFile,
                |_, _| Ok::<_, Infallible>(()),
            )
            .expect("the next create must remain usable");
        assert_eq!(created.object().as_str(), "object-1");
    }

    // Requirement: an error reported after backing creation publishes the
    // staged namespace before every clone observes shared quarantine.
    #[test]
    fn committed_create_error_publishes_before_shared_quarantine() {
        let registry = Arc::new(NamespaceRegistry::new());
        let second_mount = Arc::clone(&registry);
        let root = registry
            .object_at_path_snapshot(&CanonicalPath::root())
            .expect("registry must be readable")
            .expect("root must exist");

        let result = registry.create_child_with_commit_outcome(
            root.id(),
            "committed.rs",
            NamespaceObjectSpec::RegularFile,
            |_, _| NamespaceExecutorOutcome::<(), _>::CommittedWithError("audit"),
        );

        assert_eq!(result, Err(NamespaceOperationError::Executor("audit")));
        assert!(registry.is_in_doubt());
        assert!(second_mount.is_in_doubt());
        assert_eq!(
            registry.object_count(),
            Err(NamespaceError::RepositoryInDoubt),
            "ordinary inspection must fail closed after quarantine"
        );
        let object = raw_object_at(&registry, &path(&["committed.rs"]))
            .expect("the committed backing object must remain represented");
        assert_eq!(object.id().as_str(), "object-1");
        assert_eq!(
            registry
                .state
                .read()
                .expect("raw test state must remain readable")
                .generation,
            NamespaceGeneration(1)
        );
    }

    // Requirement: CREATE cannot publish an open count when no usable handle
    // can be returned, even though its backing object already committed.
    #[test]
    fn committed_open_create_error_publishes_a_closed_object() {
        let registry = NamespaceRegistry::new();
        let root = registry
            .object_at_path_snapshot(&CanonicalPath::root())
            .expect("registry must be readable")
            .expect("root must exist");

        let result = registry.create_open_child_with_commit_outcome(
            root.id(),
            "created.rs",
            NamespaceObjectSpec::RegularFile,
            |_, child| {
                assert_eq!(child.open_handle_count(), 1);
                NamespaceExecutorOutcome::<(), _>::CommittedWithError("audit")
            },
        );

        assert_eq!(result, Err(NamespaceOperationError::Executor("audit")));
        let object = raw_object_at(&registry, &path(&["created.rs"]))
            .expect("the backing-created object must be published");
        assert_eq!(object.open_handle_count(), 0);
    }

    // Requirement: a hard link that committed before terminal failure must be
    // represented by both names and the corresponding expected link count.
    #[test]
    fn committed_link_error_publishes_the_new_alias() {
        let registry = NamespaceRegistry::new();
        let root = registry
            .object_at_path_snapshot(&CanonicalPath::root())
            .expect("registry must be readable")
            .expect("root must exist");
        let file = registry
            .create_child(
                root.id(),
                "original.rs",
                NamespaceObjectSpec::RegularFile,
                |_, _| Ok::<_, Infallible>(()),
            )
            .expect("file must register")
            .object()
            .clone();

        let result =
            registry.link_child_with_commit_outcome(root.id(), "alias.rs", &file, |_, _, _| {
                NamespaceExecutorOutcome::<(), _>::CommittedWithError("audit")
            });

        assert_eq!(result, Err(NamespaceOperationError::Executor("audit")));
        let linked = raw_object_at(&registry, &path(&["alias.rs"]))
            .expect("the committed alias must be published");
        assert_eq!(linked.id(), &file);
        assert_eq!(linked.expected_link_count(), 2);
        assert!(linked.paths().any(|name| name == &path(&["original.rs"])));
    }

    // Requirement: committed removals and renames publish exactly the backing
    // path state before quarantine, never their pre-operation snapshot.
    #[test]
    fn committed_remove_and_rename_errors_publish_their_path_state() {
        let removed_registry = NamespaceRegistry::new();
        let removed_root = removed_registry
            .object_at_path_snapshot(&CanonicalPath::root())
            .expect("registry must be readable")
            .expect("root must exist");
        let removed = removed_registry
            .create_child(
                removed_root.id(),
                "removed.rs",
                NamespaceObjectSpec::RegularFile,
                |_, _| Ok::<_, Infallible>(()),
            )
            .expect("file must register")
            .object()
            .clone();
        let remove_result = removed_registry.remove_child_with_commit_outcome(
            removed_root.id(),
            "removed.rs",
            |_, _, _| NamespaceExecutorOutcome::<(), _>::CommittedWithError("audit"),
        );
        assert_eq!(
            remove_result,
            Err(NamespaceOperationError::Executor("audit"))
        );
        assert!(raw_object_at(&removed_registry, &path(&["removed.rs"])).is_none());
        assert!(
            !removed_registry
                .state
                .read()
                .expect("raw test state must remain readable")
                .objects
                .contains_key(&removed)
        );

        let renamed_registry = NamespaceRegistry::new();
        let renamed_root = renamed_registry
            .object_at_path_snapshot(&CanonicalPath::root())
            .expect("registry must be readable")
            .expect("root must exist");
        let renamed = renamed_registry
            .create_child(
                renamed_root.id(),
                "before.rs",
                NamespaceObjectSpec::RegularFile,
                |_, _| Ok::<_, Infallible>(()),
            )
            .expect("file must register")
            .object()
            .clone();
        let rename_result = renamed_registry.rename_child_with_commit_outcome(
            renamed_root.id(),
            "before.rs",
            renamed_root.id(),
            "after.rs",
            |_| NamespaceExecutorOutcome::<(), _>::CommittedWithError("audit"),
        );
        assert_eq!(
            rename_result,
            Err(NamespaceOperationError::Executor("audit"))
        );
        assert!(raw_object_at(&renamed_registry, &path(&["before.rs"])).is_none());
        assert_eq!(
            raw_object_at(&renamed_registry, &path(&["after.rs"]))
                .expect("the committed destination must be published")
                .id(),
            &renamed
        );
    }

    // Requirement: shared quarantine blocks new opens but does not prevent
    // teardown from releasing an already-live namespace handle count.
    #[test]
    fn quarantine_rejects_new_operations_but_allows_handle_cleanup() {
        let registry = NamespaceRegistry::new();
        let file = registry
            .create_object(path(&["open.rs"]), NamespaceObjectSpec::RegularFile, |_| {
                Ok::<_, Infallible>(())
            })
            .expect("file must register")
            .object()
            .clone();
        registry
            .open_object(&file, |_| Ok::<_, Infallible>(()))
            .expect("file must open before quarantine");
        registry.mark_in_doubt();

        assert!(matches!(
            registry.open_object(&file, |_| Ok::<_, Infallible>(())),
            Err(NamespaceOperationError::Namespace(
                NamespaceError::RepositoryInDoubt
            ))
        ));
        assert!(matches!(
            registry.close_object(&file, |_| Ok::<_, Infallible>(())),
            Err(NamespaceOperationError::Namespace(
                NamespaceError::RepositoryInDoubt
            ))
        ));
        registry
            .close_object_for_cleanup(&file, |_| Ok::<_, Infallible>(()))
            .expect("destruction-only cleanup must remain available after quarantine");
        assert_eq!(
            registry
                .state
                .read()
                .expect("raw test state must remain readable")
                .objects
                .get(&file)
                .expect("file must remain represented")
                .open_handle_count(),
            0
        );
    }

    #[test]
    fn generation_exhaustion_rejects_before_executor() {
        let registry = NamespaceRegistry::new();
        registry
            .state
            .write()
            .expect("test registry must be writable")
            .generation = NamespaceGeneration(u64::MAX);
        let mut executor_called = false;

        let result =
            registry.create_object(path(&["file"]), NamespaceObjectSpec::RegularFile, |_| {
                executor_called = true;
                Ok::<_, Infallible>(())
            });

        assert_eq!(
            result,
            Err(NamespaceOperationError::Namespace(
                NamespaceError::NamespaceGenerationExhausted
            ))
        );
        assert!(!executor_called);
        assert_eq!(registry.object_count(), Ok(1));
    }

    #[test]
    fn open_count_exhaustion_rejects_before_executor() {
        let registry = NamespaceRegistry::new();
        let file = registry
            .create_object(path(&["file"]), NamespaceObjectSpec::RegularFile, |_| {
                Ok::<_, Infallible>(())
            })
            .expect("test file should register")
            .object()
            .clone();
        registry
            .state
            .write()
            .expect("test registry must be writable")
            .objects
            .get_mut(&file)
            .expect("test file should remain live")
            .open_handle_count = u64::MAX;
        let mut executor_called = false;

        let result = registry.open_object(&file, |_| {
            executor_called = true;
            Ok::<_, Infallible>(())
        });

        assert_eq!(
            result,
            Err(NamespaceOperationError::Namespace(
                NamespaceError::OpenHandleCountExhausted(file)
            ))
        );
        assert!(!executor_called);
    }

    #[test]
    fn object_id_sequence_accepts_its_last_value_then_rejects() {
        let registry = NamespaceRegistry::new();
        registry
            .state
            .write()
            .expect("test registry must be writable")
            .next_object_sequence = Some(u64::MAX);
        let last_object = registry
            .create_object(path(&["last"]), NamespaceObjectSpec::RegularFile, |_| {
                Ok::<_, Infallible>(())
            })
            .expect("the final object ID should remain usable");
        assert_eq!(
            last_object.object().as_str(),
            format!("object-{}", u64::MAX)
        );
        let mut executor_called = false;

        let result =
            registry.create_object(path(&["next"]), NamespaceObjectSpec::RegularFile, |_| {
                executor_called = true;
                Ok::<_, Infallible>(())
            });

        assert_eq!(
            result,
            Err(NamespaceOperationError::Namespace(
                NamespaceError::ObjectIdExhausted
            ))
        );
        assert!(!executor_called);
        assert_eq!(registry.object_count(), Ok(2));
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn manifest_import_rejects_an_invalid_root_or_missing_parent() {
        assert!(matches!(
            NamespaceRegistry::from_manifest([]),
            Err(NamespaceError::InvalidManifestRoot)
        ));
        assert!(matches!(
            NamespaceRegistry::from_manifest([manifest_entry(
                CanonicalPath::root(),
                NamespaceObjectSpec::RegularFile,
                1,
            )]),
            Err(NamespaceError::InvalidManifestRoot)
        ));
        assert!(matches!(
            NamespaceRegistry::from_manifest([
                manifest_entry(CanonicalPath::root(), NamespaceObjectSpec::Directory, 1),
                manifest_entry(
                    path(&["missing", "child"]),
                    NamespaceObjectSpec::RegularFile,
                    2,
                ),
            ]),
            Err(NamespaceError::MissingParent(parent)) if parent == path(&["missing"])
        ));
    }

    #[test]
    fn writer_panic_poisons_every_later_registry_operation() {
        let registry = NamespaceRegistry::new();
        let panic_result = catch_unwind(AssertUnwindSafe(|| {
            let _ = registry.create_object(
                path(&["file"]),
                NamespaceObjectSpec::RegularFile,
                |_| -> Result<(), Infallible> { panic!("simulated backing panic") },
            );
        }));

        assert!(panic_result.is_err());
        assert_eq!(registry.generation(), Err(NamespaceError::LockPoisoned));
        assert_eq!(registry.object_count(), Err(NamespaceError::LockPoisoned));
    }
}
