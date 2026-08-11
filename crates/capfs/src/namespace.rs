//! VM-wide namespace identity, path, generation, and open-count state.

use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    error::Error,
    fmt,
    sync::{RwLock, RwLockReadGuard, RwLockWriteGuard},
};

use authority_core::{handle::ObjectId, path::CanonicalPath};

/// A monotone version of the shared namespace path mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NamespaceGeneration(u64);

impl NamespaceGeneration {
    /// Returns the initial generation assigned to a registry containing only root.
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
    /// An object identity was already used earlier in this VM session.
    ObjectIdAlreadyIssued(ObjectId),
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
            Self::ObjectIdAlreadyIssued(object) => {
                write!(formatter, "namespace object `{object}` was already issued")
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

impl Error for NamespaceError {}

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
    issued_ids: BTreeSet<ObjectId>,
    generation: NamespaceGeneration,
}

impl NamespaceState {
    fn next_generation(&self) -> Result<NamespaceGeneration, NamespaceError> {
        self.generation
            .checked_next()
            .ok_or(NamespaceError::NamespaceGenerationExhausted)
    }

    fn validate_new_object(
        &self,
        object: &ObjectId,
        path: &CanonicalPath,
    ) -> Result<(), NamespaceError> {
        if self.issued_ids.contains(object) {
            return Err(NamespaceError::ObjectIdAlreadyIssued(object.clone()));
        }
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

    fn insert_object(&mut self, object: NamespaceObject) {
        self.paths.insert(object.path.clone(), object.id.clone());
        self.issued_ids.insert(object.id.clone());
        self.objects.insert(object.id.clone(), object);
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

impl NamespaceRegistry {
    /// Creates a registry with one directory object at the repository root.
    #[must_use]
    pub fn new(root: ObjectId) -> Self {
        let root_object = NamespaceObject::new(
            root.clone(),
            CanonicalPath::root(),
            NamespaceObjectKind::Directory,
        );
        let mut objects = BTreeMap::new();
        objects.insert(root.clone(), root_object);
        let mut paths = HashMap::new();
        paths.insert(CanonicalPath::root(), root.clone());
        let mut issued_ids = BTreeSet::new();
        issued_ids.insert(root);

        Self {
            state: RwLock::new(NamespaceState {
                objects,
                paths,
                issued_ids,
                generation: NamespaceGeneration::initial(),
            }),
        }
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

    /// Registers an object that already exists in a validated backing tree.
    ///
    /// This method is intended for startup import before the registry is exposed
    /// to workloads. Runtime creation must use [`Self::create_object`].
    ///
    /// # Errors
    ///
    /// Returns an error for a reused ID, occupied path, missing directory parent,
    /// exhausted generation, or poisoned registry.
    pub fn register_existing_object(
        &self,
        object: ObjectId,
        path: CanonicalPath,
        kind: NamespaceObjectKind,
    ) -> Result<(), NamespaceError> {
        let mut state = self.write_state()?;
        state.validate_new_object(&object, &path)?;
        let next_generation = state.next_generation()?;
        state.insert_object(NamespaceObject::new(object, path, kind));
        state.generation = next_generation;
        Ok(())
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
    /// # Errors
    ///
    /// Returns an error for a reused ID, occupied path, invalid parent, exhausted
    /// generation, poisoned registry, or backing operation failure.
    pub fn create_object<T, E>(
        &self,
        object: ObjectId,
        path: CanonicalPath,
        kind: NamespaceObjectKind,
        operation: impl FnOnce(&NamespaceObject) -> Result<T, E>,
    ) -> Result<T, NamespaceOperationError<E>> {
        let mut state = self.write_state()?;
        state.validate_new_object(&object, &path)?;
        let next_generation = state.next_generation()?;
        let object_record = NamespaceObject::new(object, path, kind);
        let mut next_state = state.clone();
        next_state.insert_object(object_record.clone());
        next_state.generation = next_generation;

        let result = operation(&object_record).map_err(NamespaceOperationError::Executor)?;
        *state = next_state;
        Ok(result)
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

    use authority_core::{handle::ObjectId, path::CanonicalPath};

    use super::{
        NamespaceError, NamespaceGeneration, NamespaceObjectKind, NamespaceOperationError,
        NamespaceRegistry,
    };

    fn path(segments: &[&str]) -> CanonicalPath {
        CanonicalPath::new(segments).expect("test paths must be canonical")
    }

    #[test]
    fn generation_exhaustion_rejects_before_executor() {
        let registry = NamespaceRegistry::new(ObjectId::new("root"));
        registry
            .state
            .write()
            .expect("test registry must be writable")
            .generation = NamespaceGeneration(u64::MAX);
        let mut executor_called = false;

        let result = registry.create_object(
            ObjectId::new("file"),
            path(&["file"]),
            NamespaceObjectKind::RegularFile,
            |_| {
                executor_called = true;
                Ok::<_, Infallible>(())
            },
        );

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
        let file = ObjectId::new("file");
        let registry = NamespaceRegistry::new(ObjectId::new("root"));
        registry
            .register_existing_object(
                file.clone(),
                path(&["file"]),
                NamespaceObjectKind::RegularFile,
            )
            .expect("test file should register");
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
    fn writer_panic_poisons_every_later_registry_operation() {
        let registry = NamespaceRegistry::new(ObjectId::new("root"));
        let panic_result = catch_unwind(AssertUnwindSafe(|| {
            let _ = registry.create_object(
                ObjectId::new("file"),
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
