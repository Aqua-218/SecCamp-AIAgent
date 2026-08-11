//! VM-wide namespace identity, path, generation, and open-count state.

use std::{
    collections::{BTreeMap, HashMap},
    error::Error,
    fmt,
    sync::{RwLock, RwLockReadGuard, RwLockWriteGuard},
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

/// The object kinds accepted by the initial link-free namespace model.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NamespaceObjectKind {
    /// A directory that may own child paths.
    Directory,
    /// A regular file.
    RegularFile,
}

/// The current registry record for one live namespace object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamespaceObject {
    id: ObjectId,
    path: CanonicalPath,
    kind: NamespaceObjectKind,
    open_handle_count: u64,
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

impl NamespaceObject {
    const fn new(id: ObjectId, path: CanonicalPath, kind: NamespaceObjectKind) -> Self {
        Self {
            id,
            path,
            kind,
            open_handle_count: 0,
        }
    }

    /// Returns the session-local object identity.
    #[must_use]
    pub const fn id(&self) -> &ObjectId {
        &self.id
    }

    /// Returns the object's current canonical path.
    #[must_use]
    pub const fn path(&self) -> &CanonicalPath {
        &self.path
    }

    /// Returns whether the object is a directory or regular file.
    #[must_use]
    pub const fn kind(&self) -> NamespaceObjectKind {
        self.kind
    }

    /// Returns the number of live handles registered for this object.
    #[must_use]
    pub const fn open_handle_count(&self) -> u64 {
        self.open_handle_count
    }
}

/// One object path changed by a subtree rename.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamespaceMove {
    object: ObjectId,
    source: CanonicalPath,
    destination: CanonicalPath,
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
    /// Internal path and object indexes no longer describe the same tree.
    InvariantViolation,
}

impl fmt::Display for NamespaceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LockPoisoned => formatter.write_str("namespace registry lock is poisoned"),
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
            _ => None,
        }
    }
}

/// A namespace rejection or a backing operation failure before commit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NamespaceOperationError<E> {
    /// The registry rejected the operation before invoking its executor.
    Namespace(NamespaceError),
    /// The backing executor reported that it did not cross its linearization point.
    Executor(E),
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
            NamespaceObjectKind::Directory,
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
        kind: NamespaceObjectKind,
    ) -> Result<NamespaceObject, NamespaceError> {
        let sequence = self
            .next_object_sequence
            .ok_or(NamespaceError::ObjectIdExhausted)?;
        let object_id = object_id(sequence);
        if self.objects.contains_key(&object_id) {
            return Err(NamespaceError::InvariantViolation);
        }
        self.next_object_sequence = sequence.checked_add(1);
        let object = NamespaceObject::new(object_id, path, kind);
        self.paths.insert(object.path.clone(), object.id.clone());
        self.objects.insert(object.id.clone(), object.clone());
        Ok(object)
    }
}

/// A VM-wide, link-free namespace registry protected by one reader-writer lock.
///
/// Read and write executors run while the relevant namespace guard remains held.
/// An executor error must mean the backing operation did not cross its
/// linearization point. A writer panic poisons the registry so later operations
/// fail closed instead of observing a possibly divergent backing namespace.
/// Executors must not reenter this registry. Filesystem adapters must acquire
/// the namespace guard before the Capability kernel guard everywhere, keeping
/// one global lock order for rename, revoke, and ordinary I/O.
#[derive(Debug)]
pub struct NamespaceRegistry {
    state: RwLock<NamespaceState>,
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
        }
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn from_manifest(
        entries: impl IntoIterator<Item = (CanonicalPath, NamespaceObjectKind)>,
    ) -> Result<Self, NamespaceError> {
        let mut entries = entries.into_iter();
        let Some((root_path, root_kind)) = entries.next() else {
            return Err(NamespaceError::InvalidManifestRoot);
        };
        if !root_path.is_root() || root_kind != NamespaceObjectKind::Directory {
            return Err(NamespaceError::InvalidManifestRoot);
        }

        let mut state = NamespaceState::with_root();
        for (path, kind) in entries {
            state.validate_new_path(&path)?;
            state.allocate_object(path, kind)?;
        }
        Ok(Self {
            state: RwLock::new(state),
        })
    }

    /// Returns the current namespace generation.
    ///
    /// # Errors
    ///
    /// Returns [`NamespaceError::LockPoisoned`] after a writer panic.
    pub fn generation(&self) -> Result<NamespaceGeneration, NamespaceError> {
        Ok(self.read_state()?.generation)
    }

    /// Returns the number of live namespace objects.
    ///
    /// # Errors
    ///
    /// Returns [`NamespaceError::LockPoisoned`] after a writer panic.
    pub fn object_count(&self) -> Result<usize, NamespaceError> {
        Ok(self.read_state()?.objects.len())
    }

    /// Returns a point-in-time copy of an object record.
    ///
    /// This snapshot is for inspection only. Authorization and backing I/O must
    /// use [`Self::with_object`] so a rename cannot invalidate the path.
    ///
    /// # Errors
    ///
    /// Returns [`NamespaceError::LockPoisoned`] after a writer panic.
    pub fn object_snapshot(
        &self,
        object: &ObjectId,
    ) -> Result<Option<NamespaceObject>, NamespaceError> {
        Ok(self.read_state()?.objects.get(object).cloned())
    }

    /// Returns a point-in-time copy of the object at `path`.
    ///
    /// # Errors
    ///
    /// Returns [`NamespaceError::LockPoisoned`] after a writer panic.
    pub fn object_at_path_snapshot(
        &self,
        path: &CanonicalPath,
    ) -> Result<Option<NamespaceObject>, NamespaceError> {
        let state = self.read_state()?;
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
        let state = self.read_state()?;
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
        let state = self.read_state()?;
        let parent = state
            .objects
            .get(parent)
            .ok_or_else(|| NamespaceError::UnknownObject(parent.clone()))?;
        if parent.kind != NamespaceObjectKind::Directory {
            return Err(NamespaceError::ParentNotDirectory(parent.path.clone()).into());
        }
        let child_path = parent
            .path
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
        operation: impl FnOnce(&NamespaceObject, &NamespaceObject, &[&NamespaceObject]) -> Result<T, E>,
    ) -> Result<T, NamespaceOperationError<E>> {
        let state = self.read_state()?;
        let directory = state
            .objects
            .get(directory)
            .ok_or_else(|| NamespaceError::UnknownObject(directory.clone()))?;
        if directory.kind != NamespaceObjectKind::Directory {
            return Err(NamespaceError::ParentNotDirectory(directory.path.clone()).into());
        }

        let parent = match directory.path.parent() {
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
        let child_depth = directory.path.as_segments().len() + 1;
        let mut children = state
            .objects
            .values()
            .filter(|candidate| {
                candidate.path.as_segments().len() == child_depth
                    && candidate.path.is_at_or_below(&directory.path)
            })
            .collect::<Vec<_>>();
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
        let mut state = self.write_state()?;
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
            Ok(value) => Ok(value),
            Err(error) => {
                object_record.open_handle_count -= 1;
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
        let mut state = self.write_state()?;
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

    /// Creates an object and publishes it only after the backing executor succeeds.
    ///
    /// The registry stages a path-independent object identity and returns it only
    /// after `operation` commits. Executor failure leaves that identity unissued.
    ///
    /// # Errors
    ///
    /// Returns an error for an occupied path, invalid parent, exhausted object
    /// identity or generation, poisoned registry, or backing operation failure.
    pub fn create_object<T, E>(
        &self,
        path: CanonicalPath,
        kind: NamespaceObjectKind,
        operation: impl FnOnce(&NamespaceObject) -> Result<T, E>,
    ) -> Result<NamespaceObjectCreation<T>, NamespaceOperationError<E>> {
        let mut state = self.write_state()?;
        state.validate_new_path(&path)?;
        let next_generation = state.next_generation()?;
        let mut next_state = state.clone();
        let object_record = next_state.allocate_object(path, kind)?;
        next_state.generation = next_generation;

        let result = operation(&object_record).map_err(NamespaceOperationError::Executor)?;
        let object_id = object_record.id.clone();
        *state = next_state;
        Ok(NamespaceObjectCreation::new(object_id, result))
    }

    /// Removes an empty, unopened object after the backing executor succeeds.
    ///
    /// # Errors
    ///
    /// Returns an error for root, unknown or non-empty objects, live handles,
    /// exhausted generation, poisoned registry, or backing operation failure.
    pub fn remove_object<T, E>(
        &self,
        object: &ObjectId,
        operation: impl FnOnce(&NamespaceObject) -> Result<T, E>,
    ) -> Result<T, NamespaceOperationError<E>> {
        let mut state = self.write_state()?;
        let object_record = state
            .objects
            .get(object)
            .cloned()
            .ok_or_else(|| NamespaceError::UnknownObject(object.clone()))?;
        if object_record.path.is_root() {
            return Err(NamespaceError::CannotModifyRoot.into());
        }
        if object_record.open_handle_count != 0 {
            return Err(NamespaceError::OpenHandleInSubtree(object.clone()).into());
        }
        if state.objects.values().any(|candidate| {
            candidate.id != object_record.id && candidate.path.is_at_or_below(&object_record.path)
        }) {
            return Err(NamespaceError::DirectoryNotEmpty(object.clone()).into());
        }
        let next_generation = state.next_generation()?;
        let mut next_state = state.clone();
        if next_state.objects.remove(object).is_none()
            || next_state.paths.remove(&object_record.path).is_none()
        {
            return Err(NamespaceError::InvariantViolation.into());
        }
        next_state.generation = next_generation;

        let result = operation(&object_record).map_err(NamespaceOperationError::Executor)?;
        *state = next_state;
        Ok(result)
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
        let mut state = self.write_state()?;
        if source.is_root() {
            return Err(NamespaceError::CannotModifyRoot.into());
        }
        if !state.paths.contains_key(source) {
            return Err(NamespaceError::UnknownPath(source.clone()).into());
        }
        if state.paths.contains_key(&destination) {
            return Err(NamespaceError::PathOccupied(destination).into());
        }
        if destination.is_at_or_below(source) {
            return Err(NamespaceError::DestinationInsideSource.into());
        }
        state.validate_parent(&destination)?;

        let mut moved_objects = Vec::new();
        for object in state
            .objects
            .values()
            .filter(|object| object.path.is_at_or_below(source))
        {
            if object.open_handle_count != 0 {
                return Err(NamespaceError::OpenHandleInSubtree(object.id.clone()).into());
            }
            let Some(rebased_path) = object.path.rebase(source, &destination) else {
                return Err(NamespaceError::InvariantViolation.into());
            };
            moved_objects.push(NamespaceMove {
                object: object.id.clone(),
                source: object.path.clone(),
                destination: rebased_path,
            });
        }

        let next_generation = state.next_generation()?;
        let plan = RenamePlan {
            source: source.clone(),
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
            object.path.clone_from(&movement.destination);
            next_state
                .paths
                .insert(movement.destination.clone(), movement.object.clone());
        }
        next_state.generation = next_generation;

        let result = operation(&plan).map_err(NamespaceOperationError::Executor)?;
        *state = next_state;
        Ok(result)
    }

    fn read_state(&self) -> Result<RwLockReadGuard<'_, NamespaceState>, NamespaceError> {
        self.state.read().map_err(|_| NamespaceError::LockPoisoned)
    }

    fn write_state(&self) -> Result<RwLockWriteGuard<'_, NamespaceState>, NamespaceError> {
        self.state.write().map_err(|_| NamespaceError::LockPoisoned)
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
    };

    use authority_core::path::CanonicalPath;

    use super::{
        NamespaceError, NamespaceGeneration, NamespaceObjectKind, NamespaceOperationError,
        NamespaceRegistry,
    };

    fn path(segments: &[&str]) -> CanonicalPath {
        CanonicalPath::new(segments).expect("test paths must be canonical")
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
            registry.create_object(path(&["file"]), NamespaceObjectKind::RegularFile, |_| {
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
            .create_object(path(&["file"]), NamespaceObjectKind::RegularFile, |_| {
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
            .create_object(path(&["last"]), NamespaceObjectKind::RegularFile, |_| {
                Ok::<_, Infallible>(())
            })
            .expect("the final object ID should remain usable");
        assert_eq!(
            last_object.object().as_str(),
            format!("object-{}", u64::MAX)
        );
        let mut executor_called = false;

        let result =
            registry.create_object(path(&["next"]), NamespaceObjectKind::RegularFile, |_| {
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
            NamespaceRegistry::from_manifest([(
                CanonicalPath::root(),
                NamespaceObjectKind::RegularFile,
            )]),
            Err(NamespaceError::InvalidManifestRoot)
        ));
        assert!(matches!(
            NamespaceRegistry::from_manifest([
                (CanonicalPath::root(), NamespaceObjectKind::Directory),
                (
                    path(&["missing", "child"]),
                    NamespaceObjectKind::RegularFile,
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
                NamespaceObjectKind::RegularFile,
                |_| -> Result<(), Infallible> { panic!("simulated backing panic") },
            );
        }));

        assert!(panic_result.is_err());
        assert_eq!(registry.generation(), Err(NamespaceError::LockPoisoned));
        assert_eq!(registry.object_count(), Err(NamespaceError::LockPoisoned));
    }
}
