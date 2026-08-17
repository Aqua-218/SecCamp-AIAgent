//! Direct-I/O FUSE adapter with per-operation capability reauthorization.

use std::{
    collections::BTreeMap,
    error::Error,
    ffi::OsStr,
    fmt, io,
    num::{NonZeroU64, NonZeroUsize},
    path::Path,
    sync::{
        Arc, OnceLock, RwLock, Weak,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use authority_core::{
    capability::{
        AuthorityBody, AuthorityRequest, CapId, Capability, CapabilityRequest,
        CapabilityRequestSet, SubjectId,
    },
    file::{FileEffect, FileRequest},
    handle::{HandleId, ObjectId, OpenHandle},
    kernel::{
        CapabilityInspectionError, CapabilityKernel, EffectCommitError, EffectExecution,
        RevocationObserver, RevocationObserverError,
    },
    path::{CanonicalPath, path_matches},
    repository::RepoId,
    state::HandleCloseStatus,
    time::MonotonicTime,
};
use fuser::{
    BackgroundSession, BsdFileFlags, Config, Errno, FileAttr, FileHandle, FileType, Filesystem,
    FopenFlags, Generation, INodeNo, KernelConfig, LockOwner, MountOption, Notifier, OpenAccMode,
    OpenFlags, RenameFlags as FuseRenameFlags, ReplyAttr, ReplyCreate, ReplyData, ReplyDirectory,
    ReplyEmpty, ReplyEntry, ReplyOpen, ReplyWrite, Request, SessionACL, TimeOrNow, WriteFlags,
};
use rustix::fs::OFlags;

use crate::{
    backing::{ImportedRepository, ValidatedRepository},
    namespace::{
        NamespaceError, NamespaceExecutorOutcome, NamespaceGeneration, NamespaceObject,
        NamespaceObjectKind, NamespaceObjectSpec, NamespaceOperationError, NamespaceRegistry,
        RenamePlan, SymlinkTarget,
    },
    node::{ForgetOutcome, NodeId, NodeTable, NodeTableError},
    runtime::{
        BackingMetadata, CreationPermissions, MetadataPermissions, MetadataTime, MetadataTimes,
        OpenedBackingFile,
    },
};

/// How long the operating system may answer `LOOKUP` and `GETATTR` from its own
/// caches instead of asking this adapter.
///
/// This is not an authorization window. A revocation invalidates these caches
/// through [`MountCacheInvalidator`] before it returns, so no stale entry can
/// survive one, whatever the value here. What the value bounds is how long a
/// mount may show attributes that another mount on the same repository has
/// since changed through a path this adapter did not observe.
const ATTRIBUTE_TTL: Duration = Duration::from_secs(1);
const NODE_GENERATION: Generation = Generation(0);
const MAX_IO_SIZE: u32 = 1024 * 1024;
const COMMIT_UNKNOWN_EVIDENCE: &[u8] = b"capfs-backing-outcome-unknown";

/// Supplies the session-relative monotonic time used for authorization.
///
/// Implementations must use the same tick origin as the capability validity
/// windows installed in the kernel. `now` must not call back into the
/// filesystem or capability kernel.
pub trait AuthorizationClock: Send + Sync + 'static {
    /// Returns the time attached to the next authorization decision.
    fn now(&self) -> MonotonicTime;
}

impl AuthorizationClock for MonotonicTime {
    fn now(&self) -> MonotonicTime {
        *self
    }
}

/// Identity of one FUSE mount within a capability-kernel session.
///
/// The caller must assign a distinct value to mounts that share one
/// [`CapabilityKernel`]. It namespaces authority-side handle identities.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MountInstanceId(String);

impl MountInstanceId {
    /// Creates an opaque mount identity chosen by the trusted runtime.
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Returns the opaque mount identity.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for MountInstanceId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// The authenticated identity and presented capability fixed for one mount.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MountAuthority {
    mount: MountInstanceId,
    subject: SubjectId,
    capability: CapId,
    repository: RepoId,
}

impl MountAuthority {
    /// Binds one mount to a subject, capability, and repository.
    #[must_use]
    pub const fn new(
        mount: MountInstanceId,
        subject: SubjectId,
        capability: CapId,
        repository: RepoId,
    ) -> Self {
        Self {
            mount,
            subject,
            capability,
            repository,
        }
    }

    /// Returns the mount instance identity.
    #[must_use]
    pub const fn mount(&self) -> &MountInstanceId {
        &self.mount
    }

    /// Returns the transport-authenticated subject.
    #[must_use]
    pub const fn subject(&self) -> &SubjectId {
        &self.subject
    }

    /// Returns the capability presented for filesystem operations.
    #[must_use]
    pub const fn capability(&self) -> &CapId {
        &self.capability
    }

    /// Returns the backing repository identity.
    #[must_use]
    pub const fn repository(&self) -> &RepoId {
        &self.repository
    }
}

/// Failure to construct a capability-enforcing filesystem from imported state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CapabilityFilesystemError {
    /// The imported namespace lock is poisoned.
    Namespace(NamespaceError),
    /// The imported manifest does not contain its required root object.
    MissingNamespaceRoot,
    /// The mount authority names a different repository than the imported root.
    RepositoryMismatch {
        /// Identity assigned when the backing root was imported.
        imported: RepoId,
        /// Identity carried by the mount's presented authority.
        authority: RepoId,
    },
}

impl fmt::Display for CapabilityFilesystemError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Namespace(error) => write!(formatter, "cannot read imported namespace: {error}"),
            Self::MissingNamespaceRoot => {
                formatter.write_str("imported namespace has no repository root object")
            }
            Self::RepositoryMismatch {
                imported,
                authority,
            } => write!(
                formatter,
                "imported repository `{imported}` does not match mount authority repository `{authority}`"
            ),
        }
    }
}

impl Error for CapabilityFilesystemError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Namespace(error) => Some(error),
            Self::MissingNamespaceRoot | Self::RepositoryMismatch { .. } => None,
        }
    }
}

impl From<NamespaceError> for CapabilityFilesystemError {
    fn from(error: NamespaceError) -> Self {
        Self::Namespace(error)
    }
}

#[derive(Debug)]
struct OpenResource {
    node: NodeId,
    object: ObjectId,
    authority_handle: HandleId,
    access: OpenResourceAccess,
    backing: OpenBacking,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OpenResourceAccess {
    File(FileAccess),
    Directory,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FileAccess {
    ReadOnly,
    WriteOnly,
    ReadWrite,
}

impl FileAccess {
    const fn permits_read(self) -> bool {
        matches!(self, Self::ReadOnly | Self::ReadWrite)
    }

    const fn permits_write(self) -> bool {
        matches!(self, Self::WriteOnly | Self::ReadWrite)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileOpenIntent {
    access: FileAccess,
    truncate: bool,
}

impl FileOpenIntent {
    fn from_open_flags(flags: OpenFlags) -> Result<Self, AdapterError> {
        let access = match flags.acc_mode() {
            OpenAccMode::O_RDONLY => FileAccess::ReadOnly,
            OpenAccMode::O_WRONLY => FileAccess::WriteOnly,
            OpenAccMode::O_RDWR => FileAccess::ReadWrite,
        };
        let truncate = supported_open_flags(flags)?.contains(OFlags::TRUNC);
        if truncate && !access.permits_write() {
            return Err(AdapterError::Unsupported);
        }
        Ok(Self { access, truncate })
    }

    const fn needs_writable_backing(self) -> bool {
        self.access.permits_write() || self.truncate
    }

    fn from_create_flags(raw_flags: i32) -> Result<Self, AdapterError> {
        let access_flags = OpenFlags(raw_flags);
        let access = match access_flags.acc_mode() {
            OpenAccMode::O_RDONLY => FileAccess::ReadOnly,
            OpenAccMode::O_WRONLY => FileAccess::WriteOnly,
            OpenAccMode::O_RDWR => FileAccess::ReadWrite,
        };
        let raw_flags = u32::try_from(raw_flags).map_err(|_| AdapterError::InvalidRequest)?;
        let flags = OFlags::from_bits_retain(raw_flags);
        if flags.intersects(OFlags::APPEND) || flags.contains(OFlags::TMPFILE) {
            return Err(AdapterError::Unsupported);
        }

        // FUSE `CREATE` is only reached after the namespace transaction has
        // established that the target does not exist. O_TRUNC therefore has no
        // existing length to change and does not request the Truncate effect.
        Ok(Self {
            access,
            truncate: false,
        })
    }
}

#[derive(Debug)]
enum OpenBacking {
    File(OpenedBackingFile),
    Directory(NamespaceGeneration),
}

/// One metadata dimension accepted by the initial `SETATTR` policy.
///
/// A mode update and a timestamp update need separate Linux syscalls. Keeping
/// them separate means an error cannot report a failed compound update after
/// one dimension has already committed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MetadataUpdate {
    Permissions(MetadataPermissions),
    Timestamps(MetadataTimes),
}

/// The one effectful change accepted from a single FUSE `SETATTR` request.
///
/// `fchmod` and `futimens` have distinct linearization points. The adapter
/// rejects their combination, and combinations with truncation, rather than
/// pretending a multi-syscall request is atomic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SetattrMutation {
    Truncate(u64),
    Metadata(MetadataUpdate),
}

impl OpenBacking {
    const fn kind(&self) -> OpenResourceKind {
        match self {
            Self::File(_) => OpenResourceKind::File,
            Self::Directory(_) => OpenResourceKind::Directory,
        }
    }
}

impl OpenResourceAccess {
    const fn kind(self) -> OpenResourceKind {
        match self {
            Self::File(_) => OpenResourceKind::File,
            Self::Directory => OpenResourceKind::Directory,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OpenResourceKind {
    File,
    Directory,
}

#[derive(Debug)]
struct HandleState {
    next_sequence: Option<u64>,
    resources: BTreeMap<u64, OpenResource>,
}

impl HandleState {
    const fn new() -> Self {
        Self {
            next_sequence: Some(1),
            resources: BTreeMap::new(),
        }
    }

    fn reserve(&mut self) -> Result<u64, AdapterError> {
        let sequence = self.next_sequence.take().ok_or(AdapterError::Internal)?;
        self.next_sequence = sequence.checked_add(1);
        if self.resources.contains_key(&sequence) {
            return Err(AdapterError::Internal);
        }
        Ok(sequence)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AdapterError {
    NotFound,
    AlreadyExists,
    AccessDenied,
    Unsupported,
    IsDirectory,
    NotDirectory,
    DirectoryNotEmpty,
    Busy,
    TryAgain,
    InvalidRequest,
    BadHandle,
    CrossDevice,
    Internal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RemovalTargetKind {
    NonDirectory,
    Directory,
}

impl RemovalTargetKind {
    fn accepts(self, actual: NamespaceObjectKind) -> bool {
        match self {
            Self::NonDirectory => actual != NamespaceObjectKind::Directory,
            Self::Directory => actual == NamespaceObjectKind::Directory,
        }
    }
}

impl AdapterError {
    const fn errno(self) -> Errno {
        match self {
            Self::NotFound => Errno::ENOENT,
            Self::AlreadyExists => Errno::EEXIST,
            Self::AccessDenied => Errno::EACCES,
            Self::Unsupported => Errno::EPERM,
            Self::IsDirectory => Errno::EISDIR,
            Self::NotDirectory => Errno::ENOTDIR,
            Self::DirectoryNotEmpty => Errno::ENOTEMPTY,
            Self::Busy => Errno::EBUSY,
            Self::TryAgain => Errno::EAGAIN,
            Self::InvalidRequest => Errno::EINVAL,
            Self::BadHandle => Errno::EBADF,
            Self::CrossDevice => Errno::EXDEV,
            Self::Internal => Errno::EIO,
        }
    }
}

fn committed_execution<T>(value: T) -> EffectExecution<T, AdapterError> {
    EffectExecution::Committed {
        value,
        receipt: None,
    }
}

const fn failed_before_commit<T>(error: AdapterError) -> EffectExecution<T, AdapterError> {
    EffectExecution::FailedBeforeCommit(error)
}

fn commit_unknown<T>() -> EffectExecution<T, AdapterError> {
    EffectExecution::CommitUnknown {
        evidence: COMMIT_UNKNOWN_EVIDENCE.to_vec(),
    }
}

fn read_only_execution<T>(result: Result<T, AdapterError>) -> EffectExecution<T, AdapterError> {
    match result {
        Ok(value) => committed_execution(value),
        Err(error) => failed_before_commit(error),
    }
}

fn mutation_execution<T>(result: Result<T, AdapterError>) -> EffectExecution<T, AdapterError> {
    match result {
        Ok(value) => committed_execution(value),
        Err(_) => commit_unknown(),
    }
}

struct Entry {
    node: NodeId,
    metadata: BackingMetadata,
}

struct CreatedFile {
    node: NodeId,
    handle: u64,
    metadata: BackingMetadata,
}

/// Result produced after the truncate syscall crossed its linearization point.
#[derive(Clone, Copy)]
enum TruncateCommit {
    Metadata(BackingMetadata),
    MetadataUnavailable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DirectoryEntry {
    node: Option<NodeId>,
    kind: NamespaceObjectKind,
    name: String,
    next_offset: u64,
}

/// A subject-local direct-I/O FUSE view of one validated repository.
///
/// Metadata is visible only for the presented capability's path range and its
/// ancestors. `OPEN` and every `READ` perform final effect authorization while
/// the namespace path remains stable. Successful opens use direct I/O so the
/// kernel page cache cannot bypass a later revocation check.
pub struct CapabilityFilesystem {
    backing: Arc<ValidatedRepository>,
    namespace: Arc<NamespaceRegistry>,
    nodes: Arc<NodeTable>,
    kernel: Arc<CapabilityKernel>,
    authority: MountAuthority,
    clock: Arc<dyn AuthorizationClock>,
    /// Handle table shared by every session thread.
    ///
    /// `READ`, `WRITE`, `GETATTR`, `SETATTR(size)`, and `READDIR` only resolve
    /// an existing entry, so they take the shared guard and no longer serialize
    /// against each other. `OPEN`, `CREATE`, `OPENDIR`, `RELEASE`, and teardown
    /// take the exclusive guard. Reader/writer exclusion against `RELEASE` is
    /// what the previous mutex provided, and the read guard preserves it.
    ///
    /// This lock never orders an operation against revocation. That ordering
    /// belongs to the capability kernel's own state guard, which every
    /// authorization still passes through.
    handles: RwLock<HandleState>,
    fatal: Arc<AtomicBool>,
}

impl fmt::Debug for CapabilityFilesystem {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CapabilityFilesystem")
            .field("backing", &self.backing)
            .field("namespace", &self.namespace)
            .field("nodes", &self.nodes)
            .field("kernel", &self.kernel)
            .field("authority", &self.authority)
            .field("clock", &"<authorization clock>")
            .field("handles", &self.handles)
            .field("fatal", &self.fatal)
            .finish()
    }
}

impl CapabilityFilesystem {
    /// Creates one subject mount from a backing/namespace pair imported together.
    ///
    /// # Errors
    ///
    /// Returns an error if the imported namespace cannot supply its pinned root.
    pub fn new(
        imported: ImportedRepository,
        kernel: Arc<CapabilityKernel>,
        authority: MountAuthority,
        clock: Arc<dyn AuthorizationClock>,
    ) -> Result<Self, CapabilityFilesystemError> {
        if imported.repository() != &authority.repository {
            return Err(CapabilityFilesystemError::RepositoryMismatch {
                imported: imported.repository().clone(),
                authority: authority.repository.clone(),
            });
        }
        let (_repository, backing, namespace) = imported.into_parts();
        let root = namespace
            .object_at_path_snapshot(&CanonicalPath::root())?
            .ok_or(CapabilityFilesystemError::MissingNamespaceRoot)?;
        let nodes = Arc::new(NodeTable::new(authority.subject.clone(), root.id().clone()));

        Ok(Self {
            backing,
            namespace,
            nodes,
            kernel,
            authority,
            clock,
            handles: RwLock::new(HandleState::new()),
            fatal: Arc::new(AtomicBool::new(false)),
        })
    }

    fn lookup_entry(&self, parent: NodeId, name: &str) -> Result<Entry, AdapterError> {
        self.ensure_healthy()?;
        let parent = self
            .nodes
            .resolve(parent)
            .map_err(|error| map_node_lookup_error(&error))?;
        self.namespace
            .with_child(&parent, name, |child| {
                self.with_visible_metadata(child, |metadata| {
                    let binding = self
                        .nodes
                        .remember_lookup(child.id())
                        .map_err(|_| AdapterError::Internal)?;
                    Ok(Entry {
                        node: binding.node(),
                        metadata,
                    })
                })
            })
            .map_err(|error| map_namespace_operation_error(&error))
    }

    fn getattr_entry(&self, node: NodeId, handle: Option<u64>) -> Result<Entry, AdapterError> {
        self.ensure_healthy()?;
        let object = match handle {
            Some(handle) => {
                let handles = self.handles.read().map_err(|_| AdapterError::Internal)?;
                let resource = handles
                    .resources
                    .get(&handle)
                    .ok_or(AdapterError::BadHandle)?;
                if resource.node != node {
                    return Err(AdapterError::BadHandle);
                }
                resource.object.clone()
            }
            None => self
                .nodes
                .resolve(node)
                .map_err(|error| map_node_lookup_error(&error))?,
        };
        self.namespace
            .with_object(&object, |object| {
                self.with_visible_metadata(object, |metadata| Ok(Entry { node, metadata }))
            })
            .map_err(|error| map_namespace_operation_error(&error))
    }

    fn with_visible_metadata<T>(
        &self,
        object: &NamespaceObject,
        operation: impl FnOnce(BackingMetadata) -> Result<T, AdapterError>,
    ) -> Result<T, AdapterError> {
        let now = self.clock.now();
        self.kernel
            .with_active_capability(
                &self.authority.subject,
                &self.authority.capability,
                now,
                |capability| {
                    if !self.capability_may_observe_object(capability, object) {
                        return Err(AdapterError::NotFound);
                    }
                    let metadata = self
                        .backing
                        .runtime_metadata(object)
                        .map_err(|_| AdapterError::Internal)?;
                    operation(metadata)
                },
            )
            .map_err(|error| map_metadata_inspection_error(&error))
    }

    /// Returns whether every name an object answers to is within reach.
    ///
    /// A hard-linked inode is one object with several names, and this adapter
    /// authorizes it on all of them. Showing it through a name whose sibling
    /// name is out of range would advertise something no operation could then
    /// use, so visibility follows the same all-names rule as authorization.
    fn capability_may_observe_object(
        &self,
        capability: &Capability,
        object: &NamespaceObject,
    ) -> bool {
        object
            .paths()
            .all(|path| self.capability_may_observe(capability, path))
    }

    fn capability_may_observe(&self, capability: &Capability, path: &CanonicalPath) -> bool {
        let AuthorityBody::File(authority) = capability.authority() else {
            // capfs is deliberately a repository filesystem adapter. Future
            // authority families must receive their own adapters rather than
            // being treated as filesystem authority by accident.
            return false;
        };
        authority.repository() == &self.authority.repository
            && !authority.effects().is_empty()
            && (path_matches(authority.path(), path)
                || authority.path().path().is_at_or_below(path))
    }

    /// Builds the authorization every name of `object` must independently pass.
    ///
    /// # Why every name
    ///
    /// A hard link gives one inode several paths, and a capability is granted
    /// over paths. If an operation were authorized on only the name the caller
    /// happened to use, then linking a protected file into a directory the
    /// caller controls would hand it the file's contents. Requiring the effect
    /// on *all* current names makes the authority over an aliased inode the
    /// intersection of the authority over its names, so adding a name can never
    /// widen what anyone may do with it.
    fn object_requests(
        &self,
        effects: &[FileEffect],
        object: &NamespaceObject,
    ) -> Result<CapabilityRequestSet, AdapterError> {
        let mut requests = Vec::with_capacity(effects.len() * object.expected_link_count());
        for path in object.paths() {
            for effect in effects {
                requests.push(self.file_request(*effect, path.clone()));
            }
        }
        let mut requests = requests.into_iter();
        let Some(first) = requests.next() else {
            // Both an empty effect list and a path-less object are internal
            // faults; neither may reach the kernel as "nothing to authorize".
            self.mark_fatal();
            return Err(AdapterError::Internal);
        };
        Ok(CapabilityRequestSet::new(first, requests))
    }

    /// Authorizes one effect on every name of an object, then commits.
    fn with_authorized_object<T>(
        &self,
        object: &NamespaceObject,
        effect: FileEffect,
        execute: impl FnOnce() -> EffectExecution<T, AdapterError>,
    ) -> Result<T, AdapterError> {
        let requests = self.object_requests(&[effect], object)?;
        self.kernel
            .authorize_all_and_execute_classified(
                &self.authority.subject,
                &self.authority.capability,
                &requests,
                |_| execute(),
            )
            .map_err(|error| self.map_effect_error(&error))
    }

    /// Authorizes a backing namespace mutation without erasing whether its
    /// linearization point was crossed.
    fn with_authorized_namespace_effect<T>(
        &self,
        object: &NamespaceObject,
        effect: FileEffect,
        execute: impl FnOnce() -> EffectExecution<T, AdapterError>,
    ) -> NamespaceExecutorOutcome<T, AdapterError> {
        let requests = match self.object_requests(&[effect], object) {
            Ok(requests) => requests,
            Err(error) => return NamespaceExecutorOutcome::FailedBeforeCommit(error),
        };
        self.namespace_effect_outcome(self.kernel.authorize_all_and_execute_classified(
            &self.authority.subject,
            &self.authority.capability,
            &requests,
            |_| execute(),
        ))
    }

    /// Preserves the kernel's external commit classification for a namespace
    /// transaction. The registry performs shared quarantine only after it has
    /// published the staged transition for `CommittedWithError`.
    fn namespace_effect_outcome<T>(
        &self,
        result: Result<T, EffectCommitError<AdapterError>>,
    ) -> NamespaceExecutorOutcome<T, AdapterError> {
        match result {
            Ok(value) => NamespaceExecutorOutcome::Committed(value),
            Err(EffectCommitError::CommittedButAudit { .. }) => {
                NamespaceExecutorOutcome::CommittedWithError(AdapterError::Internal)
            }
            Err(
                EffectCommitError::CommitUnknown { .. }
                | EffectCommitError::CommitUnknownAndAudit { .. },
            ) => {
                // The namespace cannot safely choose either staged state. Keep
                // the conservative staged snapshot, quarantine the repository,
                // and require out-of-band reconciliation before any mount can
                // use it. Never relabel an ambiguous external result as a
                // failure before commit.
                self.namespace.mark_in_doubt();
                NamespaceExecutorOutcome::CommittedWithError(AdapterError::Internal)
            }
            Err(error) => NamespaceExecutorOutcome::FailedBeforeCommit(map_effect_error(&error)),
        }
    }

    fn open_file(&self, node: NodeId, flags: OpenFlags) -> Result<u64, AdapterError> {
        let intent = FileOpenIntent::from_open_flags(flags)?;
        self.open_resource(
            node,
            NamespaceObjectKind::RegularFile,
            AdapterError::IsDirectory,
            OpenResourceAccess::File(intent.access),
            |object| self.file_open_requests(intent, object),
            |object| {
                let open = if intent.needs_writable_backing() {
                    self.backing.open_runtime_writable_file(object)
                } else {
                    self.backing.open_runtime_file(object)
                };
                let Ok(file) = open else {
                    return failed_before_commit(AdapterError::Internal);
                };
                if intent.truncate && file.truncate_to(0).is_err() {
                    return commit_unknown();
                }
                committed_execution(OpenBacking::File(file))
            },
        )
    }

    fn open_directory(&self, node: NodeId, flags: OpenFlags) -> Result<u64, AdapterError> {
        let raw_flags = supported_open_flags(flags)?;
        if flags.acc_mode() != OpenAccMode::O_RDONLY || raw_flags.contains(OFlags::TRUNC) {
            return Err(AdapterError::Unsupported);
        }
        let generation = self
            .namespace
            .generation()
            .map_err(|_| AdapterError::Internal)?;
        self.open_resource(
            node,
            NamespaceObjectKind::Directory,
            AdapterError::NotDirectory,
            OpenResourceAccess::Directory,
            |object| self.object_requests(&[FileEffect::ListDirectory], object),
            |_| committed_execution(OpenBacking::Directory(generation)),
        )
    }

    fn open_resource(
        &self,
        node: NodeId,
        expected_kind: NamespaceObjectKind,
        kind_error: AdapterError,
        access: OpenResourceAccess,
        authorization_requests: impl FnOnce(
            &NamespaceObject,
        ) -> Result<CapabilityRequestSet, AdapterError>,
        open_backing: impl FnOnce(&NamespaceObject) -> EffectExecution<OpenBacking, AdapterError>,
    ) -> Result<u64, AdapterError> {
        self.ensure_healthy()?;
        let object = self
            .nodes
            .resolve(node)
            .map_err(|error| map_node_lookup_error(&error))?;
        let mut handles = self.handles.write().map_err(|_| AdapterError::Internal)?;
        let sequence = handles.reserve()?;
        let authority_handle =
            HandleId::new(format!("{}:fuse-handle:{sequence}", self.authority.mount));
        let opened = self
            .namespace
            .open_object_with_commit_outcome(&object, |object| {
                if let Err(error) = self.ensure_healthy() {
                    return NamespaceExecutorOutcome::FailedBeforeCommit(error);
                }
                if object.kind() != expected_kind {
                    return NamespaceExecutorOutcome::FailedBeforeCommit(kind_error);
                }
                if self
                    .kernel
                    .register_open_handle(OpenHandle::new(
                        authority_handle.clone(),
                        self.authority.subject.clone(),
                        object.id().clone(),
                    ))
                    .is_err()
                {
                    return NamespaceExecutorOutcome::FailedBeforeCommit(AdapterError::Internal);
                }

                let requests = match authorization_requests(object) {
                    Ok(requests) => requests,
                    Err(error) => {
                        return self.close_unreturned_authority_handle(
                            &authority_handle,
                            NamespaceExecutorOutcome::FailedBeforeCommit(error),
                        );
                    }
                };
                let outcome = self.namespace_effect_outcome(
                    self.kernel.authorize_all_and_execute_classified(
                        &self.authority.subject,
                        &self.authority.capability,
                        &requests,
                        |_| open_backing(object),
                    ),
                );
                self.close_unreturned_authority_handle(&authority_handle, outcome)
            });
        let backing = opened.map_err(|error| map_namespace_operation_error(&error))?;
        let replaced = handles.resources.insert(
            sequence,
            OpenResource {
                node,
                object,
                authority_handle,
                access,
                backing,
            },
        );
        if replaced.is_some() {
            self.mark_fatal();
            return Err(AdapterError::Internal);
        }
        Ok(sequence)
    }

    fn create_file(
        &self,
        parent: NodeId,
        name: &str,
        mode: u32,
        umask: u32,
        flags: i32,
    ) -> Result<CreatedFile, AdapterError> {
        self.ensure_healthy()?;
        let intent = FileOpenIntent::from_create_flags(flags)?;
        let parent = self
            .nodes
            .resolve(parent)
            .map_err(|error| map_node_lookup_error(&error))?;
        let permissions = CreationPermissions::from_requested_mode(mode, umask);

        // Reserve the public handle before beginning the namespace transaction.
        // A successful CREATE therefore cannot publish an object for which the
        // adapter has no handle identity to return to FUSE.
        let mut handles = self.handles.write().map_err(|_| AdapterError::Internal)?;
        let sequence = handles.reserve()?;
        let authority_handle =
            HandleId::new(format!("{}:fuse-handle:{sequence}", self.authority.mount));
        let created = self.namespace.create_open_child_with_commit_outcome(
            &parent,
            name,
            NamespaceObjectSpec::RegularFile,
            |live_parent, child| {
                if let Err(error) = self.ensure_healthy() {
                    return NamespaceExecutorOutcome::FailedBeforeCommit(error);
                }
                if self
                    .kernel
                    .register_open_handle(OpenHandle::new(
                        authority_handle.clone(),
                        self.authority.subject.clone(),
                        child.id().clone(),
                    ))
                    .is_err()
                {
                    return NamespaceExecutorOutcome::FailedBeforeCommit(AdapterError::Internal);
                }

                let requests =
                    match self.file_creation_requests(FileEffect::CreateFile, intent, child) {
                        Ok(requests) => requests,
                        Err(error) => {
                            return self.close_unreturned_authority_handle(
                                &authority_handle,
                                NamespaceExecutorOutcome::FailedBeforeCommit(error),
                            );
                        }
                    };
                let mut remembered_node = None;
                let result = self.kernel.authorize_all_and_execute_classified(
                    &self.authority.subject,
                    &self.authority.capability,
                    &requests,
                    |_| {
                        // Allocate the LOOKUP reference before touching the
                        // backing file. If allocation fails, no file is created;
                        // if backing creation fails, the reference is removed
                        // before the namespace transaction rolls back.
                        let Ok(binding) = self.nodes.remember_lookup(child.id()) else {
                            return failed_before_commit(AdapterError::Internal);
                        };
                        let node = binding.node();
                        remembered_node = Some(node);
                        if let Ok((backing, metadata)) =
                            self.backing
                                .create_runtime_file(live_parent, child, permissions)
                        {
                            committed_execution((node, backing, metadata))
                        } else {
                            if self.forget_created_lookup(node, child.id()).is_ok() {
                                remembered_node = None;
                            }
                            commit_unknown()
                        }
                    },
                );
                let mut outcome = self.namespace_effect_outcome(result);
                if let Some(node) = remembered_node {
                    outcome = Self::cleanup_unreturned_namespace_outcome(outcome, || {
                        self.forget_created_lookup(node, child.id())
                    });
                }
                self.close_unreturned_authority_handle(&authority_handle, outcome)
            },
        );
        let creation = created.map_err(|error| map_namespace_operation_error(&error))?;
        let (object, (node, backing, metadata)) = creation.into_parts();
        let replaced = handles.resources.insert(
            sequence,
            OpenResource {
                node,
                object,
                authority_handle,
                access: OpenResourceAccess::File(intent.access),
                backing: OpenBacking::File(backing),
            },
        );
        if replaced.is_some() {
            self.mark_fatal();
            return Err(AdapterError::Internal);
        }
        Ok(CreatedFile {
            node,
            handle: sequence,
            metadata,
        })
    }

    fn create_directory(
        &self,
        parent: NodeId,
        name: &str,
        mode: u32,
        umask: u32,
    ) -> Result<Entry, AdapterError> {
        self.ensure_healthy()?;
        let parent = self
            .nodes
            .resolve(parent)
            .map_err(|error| map_node_lookup_error(&error))?;
        let permissions = CreationPermissions::from_requested_mode(mode, umask);
        let created = self.namespace.create_child_with_commit_outcome(
            &parent,
            name,
            NamespaceObjectSpec::Directory,
            |live_parent, child| {
                if let Err(error) = self.ensure_healthy() {
                    return NamespaceExecutorOutcome::FailedBeforeCommit(error);
                }
                let requests = match self.object_requests(&[FileEffect::CreateDirectory], child) {
                    Ok(requests) => requests,
                    Err(error) => {
                        return NamespaceExecutorOutcome::FailedBeforeCommit(error);
                    }
                };
                let mut remembered_node = None;
                let result = self.kernel.authorize_all_and_execute_classified(
                    &self.authority.subject,
                    &self.authority.capability,
                    &requests,
                    |_| {
                        let Ok(binding) = self.nodes.remember_lookup(child.id()) else {
                            return failed_before_commit(AdapterError::Internal);
                        };
                        let node = binding.node();
                        remembered_node = Some(node);
                        if let Ok(metadata) =
                            self.backing
                                .create_runtime_directory(live_parent, child, permissions)
                        {
                            committed_execution(Entry { node, metadata })
                        } else {
                            if self.forget_created_lookup(node, child.id()).is_ok() {
                                remembered_node = None;
                            }
                            commit_unknown()
                        }
                    },
                );
                let mut outcome = self.namespace_effect_outcome(result);
                if let Some(node) = remembered_node {
                    outcome = Self::cleanup_unreturned_namespace_outcome(outcome, || {
                        self.forget_created_lookup(node, child.id())
                    });
                }
                outcome
            },
        );
        created
            .map(|creation| creation.into_parts().1)
            .map_err(|error| map_namespace_operation_error(&error))
    }

    /// Replies with a link body that is proven to resolve inside this mount.
    ///
    /// The operating system resolves symbolic links itself: it asks for the
    /// target and then continues its own path walk, without returning here for
    /// the `..` components. The string handed back is therefore the entire
    /// enforcement boundary, and it is rechecked here rather than trusted from
    /// registration time, because a rename can move the link and change what the
    /// same relative target denotes. A link that would now leave the repository
    /// gets `EXDEV` instead of its body.
    ///
    /// The check runs for every name the link answers to: a hard-linked symlink
    /// can be reached through any of them, and the same body resolves from each
    /// name's own directory.
    fn read_link(&self, node: NodeId) -> Result<String, AdapterError> {
        self.ensure_healthy()?;
        let object = self
            .nodes
            .resolve(node)
            .map_err(|error| map_node_lookup_error(&error))?;
        self.namespace
            .with_object(&object, |object| {
                if object.kind() != NamespaceObjectKind::Symlink {
                    return Err(AdapterError::InvalidRequest);
                }
                let target = object.link_target().ok_or(AdapterError::Internal)?;
                for path in object.paths() {
                    target
                        .resolve_from(path)
                        .map_err(|_| AdapterError::CrossDevice)?;
                }
                self.with_authorized_object(object, FileEffect::ReadLink, || {
                    read_only_execution(
                        self.backing
                            .read_runtime_symlink(object)
                            .map_err(|_| AdapterError::Internal),
                    )
                })
            })
            .map_err(|error| map_namespace_operation_error(&error))
    }

    fn create_symlink(
        &self,
        parent: NodeId,
        name: &str,
        target: &str,
    ) -> Result<Entry, AdapterError> {
        self.ensure_healthy()?;
        let target = SymlinkTarget::new(target).map_err(|_| AdapterError::Unsupported)?;
        let parent = self
            .nodes
            .resolve(parent)
            .map_err(|error| map_node_lookup_error(&error))?;
        // The registry refuses to stage a link whose target leaves the
        // repository, so an escaping target fails before anything is created.
        let created = self.namespace.create_child_with_commit_outcome(
            &parent,
            name,
            NamespaceObjectSpec::Symlink(target.clone()),
            |live_parent, child| {
                if let Err(error) = self.ensure_healthy() {
                    return NamespaceExecutorOutcome::FailedBeforeCommit(error);
                }
                let requests = match self.object_requests(&[FileEffect::CreateSymlink], child) {
                    Ok(requests) => requests,
                    Err(error) => {
                        return NamespaceExecutorOutcome::FailedBeforeCommit(error);
                    }
                };
                let mut remembered_node = None;
                let result = self.kernel.authorize_all_and_execute_classified(
                    &self.authority.subject,
                    &self.authority.capability,
                    &requests,
                    |_| {
                        let Ok(binding) = self.nodes.remember_lookup(child.id()) else {
                            return failed_before_commit(AdapterError::Internal);
                        };
                        let node = binding.node();
                        remembered_node = Some(node);
                        if let Ok(metadata) =
                            self.backing
                                .create_runtime_symlink(live_parent, child, &target)
                        {
                            committed_execution(Entry { node, metadata })
                        } else {
                            if self.forget_created_lookup(node, child.id()).is_ok() {
                                remembered_node = None;
                            }
                            commit_unknown()
                        }
                    },
                );
                let mut outcome = self.namespace_effect_outcome(result);
                if let Some(node) = remembered_node {
                    outcome = Self::cleanup_unreturned_namespace_outcome(outcome, || {
                        self.forget_created_lookup(node, child.id())
                    });
                }
                outcome
            },
        );
        created
            .map(|creation| creation.into_parts().1)
            .map_err(|error| map_namespace_operation_error(&error))
    }

    /// Gives one live inode a second name.
    ///
    /// `CreateHardLink` is required on the new name *and* on every name the
    /// inode already has. Requiring the existing names is what stops a caller
    /// from attaching a file it has no authority over to a directory it
    /// controls; requiring the new one keeps the alias inside its own reach.
    /// Because every later operation is authorized on all names, the link
    /// cannot widen anyone's access to the inode.
    fn create_hard_link(
        &self,
        node: NodeId,
        new_parent: NodeId,
        new_name: &str,
    ) -> Result<Entry, AdapterError> {
        self.ensure_healthy()?;
        let source = self
            .nodes
            .resolve(node)
            .map_err(|error| map_node_lookup_error(&error))?;
        let parent = self
            .nodes
            .resolve(new_parent)
            .map_err(|error| map_node_lookup_error(&error))?;
        self.namespace
            .link_child_with_commit_outcome(
                &parent,
                new_name,
                &source,
                |live_parent, linked, link_path| {
                    if let Err(error) = self.ensure_healthy() {
                        return NamespaceExecutorOutcome::FailedBeforeCommit(error);
                    }
                    let Some(source_path) = linked.paths().find(|path| *path != link_path).cloned()
                    else {
                        return NamespaceExecutorOutcome::FailedBeforeCommit(
                            AdapterError::Internal,
                        );
                    };
                    let requests = match self.object_requests(&[FileEffect::CreateHardLink], linked)
                    {
                        Ok(requests) => requests,
                        Err(error) => {
                            return NamespaceExecutorOutcome::FailedBeforeCommit(error);
                        }
                    };
                    let mut remembered_node = None;
                    let result = self.kernel.authorize_all_and_execute_classified(
                        &self.authority.subject,
                        &self.authority.capability,
                        &requests,
                        |_| {
                            // The inode already has a node identity; LINK adds
                            // one kernel lookup reference to it rather than
                            // introducing a second identity for one inode.
                            let Ok(binding) = self.nodes.remember_lookup(linked.id()) else {
                                return failed_before_commit(AdapterError::Internal);
                            };
                            let node = binding.node();
                            remembered_node = Some(node);
                            if let Ok(metadata) = self.backing.create_runtime_hard_link(
                                linked,
                                &source_path,
                                live_parent,
                                link_path,
                            ) {
                                committed_execution(Entry { node, metadata })
                            } else {
                                if self.forget_lookup_reference(node).is_ok() {
                                    remembered_node = None;
                                }
                                commit_unknown()
                            }
                        },
                    );
                    let mut outcome = self.namespace_effect_outcome(result);
                    if let Some(node) = remembered_node {
                        outcome = Self::cleanup_unreturned_namespace_outcome(outcome, || {
                            self.forget_lookup_reference(node)
                        });
                    }
                    outcome
                },
            )
            .map_err(|error| map_namespace_operation_error(&error))
    }

    fn remove_file(&self, parent: NodeId, name: &str) -> Result<(), AdapterError> {
        self.remove_child(
            parent,
            name,
            RemovalTargetKind::NonDirectory,
            AdapterError::IsDirectory,
            FileEffect::RemoveFile,
        )
    }

    fn remove_directory(&self, parent: NodeId, name: &str) -> Result<(), AdapterError> {
        self.remove_child(
            parent,
            name,
            RemovalTargetKind::Directory,
            AdapterError::NotDirectory,
            FileEffect::RemoveDirectory,
        )
    }

    fn remove_child(
        &self,
        parent: NodeId,
        name: &str,
        expected_kind: RemovalTargetKind,
        kind_error: AdapterError,
        effect: FileEffect,
    ) -> Result<(), AdapterError> {
        self.ensure_healthy()?;
        let parent = self
            .nodes
            .resolve(parent)
            .map_err(|error| map_node_lookup_error(&error))?;
        self.namespace
            .remove_child_with_commit_outcome(&parent, name, |live_parent, child, removed_path| {
                if let Err(error) = self.ensure_healthy() {
                    return NamespaceExecutorOutcome::FailedBeforeCommit(error);
                }
                if !expected_kind.accepts(child.kind()) {
                    return NamespaceExecutorOutcome::FailedBeforeCommit(kind_error);
                }
                self.with_authorized_namespace_effect(child, effect, || {
                    mutation_execution(
                        self.backing
                            .remove_runtime_object(live_parent, child, removed_path)
                            .map_err(|_| AdapterError::Internal),
                    )
                })
            })
            .map_err(|error| map_namespace_operation_error(&error))
    }

    fn rename_entry(
        &self,
        source_parent: NodeId,
        source_name: &str,
        destination_parent: NodeId,
        destination_name: &str,
        flags: FuseRenameFlags,
    ) -> Result<(), AdapterError> {
        self.ensure_healthy()?;
        if !flags
            .difference(FuseRenameFlags::RENAME_NOREPLACE)
            .is_empty()
        {
            return Err(AdapterError::Unsupported);
        }
        let source_parent = self
            .nodes
            .resolve(source_parent)
            .map_err(|error| map_node_lookup_error(&error))?;
        let destination_parent = self
            .nodes
            .resolve(destination_parent)
            .map_err(|error| map_node_lookup_error(&error))?;
        self.namespace
            .rename_child_with_commit_outcome(
                &source_parent,
                source_name,
                &destination_parent,
                destination_name,
                |plan| {
                    if let Err(error) = self.ensure_healthy() {
                        return NamespaceExecutorOutcome::FailedBeforeCommit(error);
                    }
                    let requests = match self.rename_requests(plan) {
                        Ok(requests) => requests,
                        Err(error) => {
                            return NamespaceExecutorOutcome::FailedBeforeCommit(error);
                        }
                    };
                    self.namespace_effect_outcome(self.kernel.authorize_all_and_execute_classified(
                        &self.authority.subject,
                        &self.authority.capability,
                        &requests,
                        |_| {
                            mutation_execution(
                                self.backing
                                    .rename_runtime_subtree(plan)
                                    .map_err(|_| AdapterError::Internal),
                            )
                        },
                    ))
                },
            )
            .map_err(|error| map_namespace_operation_error(&error))
    }

    fn close_failed_authority_handle(
        &self,
        authority_handle: &HandleId,
    ) -> Result<(), AdapterError> {
        if self
            .kernel
            .close_handle(&self.authority.subject, authority_handle)
            == Ok(HandleCloseStatus::Closed)
        {
            Ok(())
        } else {
            self.mark_fatal();
            Err(AdapterError::Internal)
        }
    }

    /// Closes an authority-side handle when no FUSE handle can be returned,
    /// without changing the backing effect's commit classification.
    fn close_unreturned_authority_handle<T>(
        &self,
        authority_handle: &HandleId,
        outcome: NamespaceExecutorOutcome<T, AdapterError>,
    ) -> NamespaceExecutorOutcome<T, AdapterError> {
        Self::cleanup_unreturned_namespace_outcome(outcome, || {
            self.close_failed_authority_handle(authority_handle)
        })
    }

    /// Runs request-local cleanup only when a namespace operation cannot return
    /// its successful value, preserving whether the backing effect committed.
    fn cleanup_unreturned_namespace_outcome<T>(
        outcome: NamespaceExecutorOutcome<T, AdapterError>,
        cleanup: impl FnOnce() -> Result<(), AdapterError>,
    ) -> NamespaceExecutorOutcome<T, AdapterError> {
        match outcome {
            NamespaceExecutorOutcome::Committed(value) => {
                NamespaceExecutorOutcome::Committed(value)
            }
            NamespaceExecutorOutcome::FailedBeforeCommit(error) => {
                let error = cleanup().err().unwrap_or(error);
                NamespaceExecutorOutcome::FailedBeforeCommit(error)
            }
            NamespaceExecutorOutcome::CommittedWithError(error) => {
                let error = cleanup().err().unwrap_or(error);
                NamespaceExecutorOutcome::CommittedWithError(error)
            }
        }
    }

    /// Drops one lookup reference from a node that other references may hold.
    ///
    /// `LINK` adds a reference to an inode the kernel already knows, so undoing
    /// it must not require the node to disappear.
    fn forget_lookup_reference(&self, node: NodeId) -> Result<(), AdapterError> {
        match self.nodes.forget(node, NonZeroU64::MIN) {
            Ok(ForgetOutcome::Removed(_) | ForgetOutcome::Retained(_)) => Ok(()),
            Err(_) => {
                self.mark_fatal();
                Err(AdapterError::Internal)
            }
        }
    }

    fn forget_created_lookup(&self, node: NodeId, object: &ObjectId) -> Result<(), AdapterError> {
        match self.nodes.forget(node, NonZeroU64::MIN) {
            Ok(ForgetOutcome::Removed(removed)) if removed == *object => Ok(()),
            Ok(ForgetOutcome::Removed(_) | ForgetOutcome::Retained(_)) | Err(_) => {
                self.mark_fatal();
                Err(AdapterError::Internal)
            }
        }
    }

    fn read_file(
        &self,
        node: NodeId,
        handle: u64,
        offset: u64,
        size: u32,
    ) -> Result<Vec<u8>, AdapterError> {
        self.ensure_healthy()?;
        if size > MAX_IO_SIZE {
            return Err(AdapterError::InvalidRequest);
        }
        let handles = self.handles.read().map_err(|_| AdapterError::Internal)?;
        let resource = handles
            .resources
            .get(&handle)
            .ok_or(AdapterError::BadHandle)?;
        if resource.node != node {
            return Err(AdapterError::BadHandle);
        }
        let OpenResourceAccess::File(access) = resource.access else {
            return Err(AdapterError::BadHandle);
        };
        if !access.permits_read() {
            return Err(AdapterError::BadHandle);
        }
        let OpenBacking::File(backing) = &resource.backing else {
            return Err(AdapterError::BadHandle);
        };

        self.namespace
            .with_object(&resource.object, |object| {
                self.with_authorized_object(object, FileEffect::ReadData, || {
                    read_only_execution(
                        backing
                            .read_at(offset, size as usize)
                            .map_err(|_| AdapterError::Internal),
                    )
                })
            })
            .map_err(|error| map_namespace_operation_error(&error))
    }

    fn write_file_with_flags(
        &self,
        node: NodeId,
        handle: u64,
        offset: u64,
        bytes: &[u8],
        write_flags: WriteFlags,
    ) -> Result<u32, AdapterError> {
        let kill_set_id = supported_write_flags(write_flags)?;
        self.ensure_healthy()?;
        if bytes.len() > MAX_IO_SIZE as usize {
            return Err(AdapterError::InvalidRequest);
        }
        let handles = self.handles.read().map_err(|_| AdapterError::Internal)?;
        let resource = handles
            .resources
            .get(&handle)
            .ok_or(AdapterError::BadHandle)?;
        if resource.node != node {
            return Err(AdapterError::BadHandle);
        }
        let OpenResourceAccess::File(access) = resource.access else {
            return Err(AdapterError::BadHandle);
        };
        if !access.permits_write() {
            return Err(AdapterError::BadHandle);
        }
        let OpenBacking::File(backing) = &resource.backing else {
            return Err(AdapterError::BadHandle);
        };

        self.namespace
            .with_object_mutation(&resource.object, |object| {
                self.ensure_healthy()?;
                self.with_authorized_object(object, FileEffect::WriteData, || {
                    let write = if kill_set_id {
                        backing.write_at_killing_set_id(offset, bytes)
                    } else {
                        backing.write_at(offset, bytes)
                    };
                    let Ok(written) = write else {
                        return commit_unknown();
                    };
                    match u32::try_from(written) {
                        Ok(written) => committed_execution(written),
                        Err(_) => commit_unknown(),
                    }
                })
            })
            .map_err(|error| map_namespace_operation_error(&error))
    }

    #[cfg(test)]
    fn write_file(
        &self,
        node: NodeId,
        handle: u64,
        offset: u64,
        bytes: &[u8],
    ) -> Result<u32, AdapterError> {
        self.write_file_with_flags(node, handle, offset, bytes, WriteFlags::empty())
    }

    fn truncate_file(
        &self,
        node: NodeId,
        handle: Option<u64>,
        length: u64,
    ) -> Result<BackingMetadata, AdapterError> {
        self.ensure_healthy()?;
        if let Some(handle) = handle {
            let handles = self.handles.read().map_err(|_| AdapterError::Internal)?;
            let resource = handles
                .resources
                .get(&handle)
                .ok_or(AdapterError::BadHandle)?;
            if resource.node != node {
                return Err(AdapterError::BadHandle);
            }
            let OpenResourceAccess::File(access) = resource.access else {
                return Err(AdapterError::BadHandle);
            };
            if !access.permits_write() {
                return Err(AdapterError::BadHandle);
            }
            let OpenBacking::File(backing) = &resource.backing else {
                return Err(AdapterError::BadHandle);
            };
            self.with_authorized_truncate(&resource.object, |object| {
                if backing.truncate_to(length).is_err() {
                    return commit_unknown();
                }
                committed_execution(match self.backing.runtime_metadata(object) {
                    Ok(metadata) => TruncateCommit::Metadata(metadata),
                    Err(_) => TruncateCommit::MetadataUnavailable,
                })
            })
        } else {
            let object = self
                .nodes
                .resolve(node)
                .map_err(|error| map_node_lookup_error(&error))?;
            self.with_authorized_truncate(&object, |object| {
                let Ok(backing) = self.backing.open_runtime_writable_file(object) else {
                    return failed_before_commit(AdapterError::Internal);
                };
                if backing.truncate_to(length).is_err() {
                    return commit_unknown();
                }
                committed_execution(match self.backing.runtime_metadata(object) {
                    Ok(metadata) => TruncateCommit::Metadata(metadata),
                    Err(_) => TruncateCommit::MetadataUnavailable,
                })
            })
        }
    }

    /// Converts a post-syscall metadata observation into the FUSE result.
    fn finish_truncate(&self, commit: TruncateCommit) -> Result<BackingMetadata, AdapterError> {
        match commit {
            TruncateCommit::Metadata(metadata) => Ok(metadata),
            TruncateCommit::MetadataUnavailable => {
                // `ftruncate` was already durably audited as committed. The
                // reply metadata is a later observation, so treating this as a
                // pre-commit executor error would falsify the audit. Quarantine
                // all mounts instead of letting the caller retry an operation
                // that is known to have changed the file.
                self.namespace.mark_in_doubt();
                Err(AdapterError::Internal)
            }
        }
    }

    /// Changes exactly one supported metadata dimension under `SetMetadata`.
    ///
    /// The runtime operation ends at `fchmod` or `futimens`. It intentionally
    /// returns no attributes: fetching reply metadata after that syscall is a
    /// separate, fallible observation and must not turn a committed mutation
    /// into an uncommitted audit outcome.
    fn set_metadata(&self, node: NodeId, update: MetadataUpdate) -> Result<(), AdapterError> {
        self.ensure_healthy()?;
        let object = self
            .nodes
            .resolve(node)
            .map_err(|error| map_node_lookup_error(&error))?;
        self.namespace
            .with_object_mutation(&object, |object| {
                self.ensure_healthy()?;
                self.with_authorized_object(object, FileEffect::SetMetadata, || {
                    mutation_execution(match update {
                        MetadataUpdate::Permissions(permissions) => self
                            .backing
                            .set_runtime_permissions(object, permissions)
                            .map_err(|_| AdapterError::Internal),
                        MetadataUpdate::Timestamps(timestamps) => self
                            .backing
                            .set_runtime_timestamps(object, timestamps)
                            .map_err(|_| AdapterError::Internal),
                    })
                })
            })
            .map_err(|error| map_namespace_operation_error(&error))
    }

    fn with_authorized_truncate(
        &self,
        object: &ObjectId,
        operation: impl FnOnce(&NamespaceObject) -> EffectExecution<TruncateCommit, AdapterError>,
    ) -> Result<BackingMetadata, AdapterError> {
        self.namespace
            .with_object_mutation(object, |object| {
                self.ensure_healthy()?;
                if object.kind() != NamespaceObjectKind::RegularFile {
                    return Err(AdapterError::IsDirectory);
                }
                // The kernel first records the truncate as committed. Only
                // then do we interpret its already-captured reply metadata;
                // an unavailable observation quarantines while the repository
                // mutation gate is still held.
                let commit = self
                    .with_authorized_object(object, FileEffect::Truncate, || operation(object))?;
                self.finish_truncate(commit)
            })
            .map_err(|error| map_namespace_operation_error(&error))
    }

    fn read_directory(
        &self,
        node: NodeId,
        handle: u64,
        offset: u64,
    ) -> Result<Vec<DirectoryEntry>, AdapterError> {
        self.ensure_healthy()?;
        let offset = usize::try_from(offset).map_err(|_| AdapterError::InvalidRequest)?;
        let handles = self.handles.read().map_err(|_| AdapterError::Internal)?;
        let resource = handles
            .resources
            .get(&handle)
            .ok_or(AdapterError::BadHandle)?;
        if resource.node != node
            || resource.access.kind() != OpenResourceKind::Directory
            || resource.backing.kind() != OpenResourceKind::Directory
        {
            return Err(AdapterError::BadHandle);
        }
        let OpenBacking::Directory(generation) = resource.backing else {
            return Err(AdapterError::BadHandle);
        };

        self.namespace
            .with_directory_children_at_generation(
                &resource.object,
                generation,
                |directory, parent, children| {
                    let requests = self.object_requests(&[FileEffect::ListDirectory], directory)?;
                    self.kernel
                        .authorize_all_and_execute_classified(
                            &self.authority.subject,
                            &self.authority.capability,
                            &requests,
                            |capability| {
                                read_only_execution((|| {
                                    let mut entries = Vec::with_capacity(children.len() + 2);
                                    entries.push((
                                        Some(node),
                                        NamespaceObjectKind::Directory,
                                        ".".into(),
                                    ));
                                    entries.push((
                                        self.nodes
                                            .node_for_object(parent.id())
                                            .map_err(|_| AdapterError::Internal)?,
                                        NamespaceObjectKind::Directory,
                                        "..".into(),
                                    ));
                                    for child in children {
                                        if !self.capability_may_observe_object(
                                            capability,
                                            child.object(),
                                        ) {
                                            continue;
                                        }
                                        let name =
                                            child.name().ok_or(AdapterError::Internal)?.to_owned();
                                        entries.push((
                                            self.nodes
                                                .node_for_object(child.object().id())
                                                .map_err(|_| AdapterError::Internal)?,
                                            child.object().kind(),
                                            name,
                                        ));
                                    }
                                    if offset > entries.len() {
                                        return Err(AdapterError::InvalidRequest);
                                    }
                                    entries
                                        .into_iter()
                                        .enumerate()
                                        .skip(offset)
                                        .map(|(index, (node, kind, name))| {
                                            let next_offset = index
                                                .checked_add(1)
                                                .and_then(|value| u64::try_from(value).ok())
                                                .ok_or(AdapterError::Internal)?;
                                            Ok(DirectoryEntry {
                                                node,
                                                kind,
                                                name,
                                                next_offset,
                                            })
                                        })
                                        .collect()
                                })())
                            },
                        )
                        .map_err(|error| self.map_effect_error(&error))
                },
            )
            .map_err(|error| map_namespace_operation_error(&error))
    }

    fn release_file(&self, node: NodeId, handle: u64) -> Result<(), AdapterError> {
        self.release_resource(node, handle, OpenResourceKind::File)
    }

    fn release_directory(&self, node: NodeId, handle: u64) -> Result<(), AdapterError> {
        self.release_resource(node, handle, OpenResourceKind::Directory)
    }

    fn release_resource(
        &self,
        node: NodeId,
        handle: u64,
        expected_kind: OpenResourceKind,
    ) -> Result<(), AdapterError> {
        self.ensure_healthy()?;
        let mut handles = self.handles.write().map_err(|_| AdapterError::Internal)?;
        let resource = handles
            .resources
            .get(&handle)
            .ok_or(AdapterError::BadHandle)?;
        if resource.node != node
            || resource.access.kind() != expected_kind
            || resource.backing.kind() != expected_kind
        {
            return Err(AdapterError::BadHandle);
        }
        let object = resource.object.clone();
        let authority_handle = resource.authority_handle.clone();

        self.namespace
            .close_object(&object, |_| {
                match self
                    .kernel
                    .close_handle(&self.authority.subject, &authority_handle)
                {
                    Ok(HandleCloseStatus::Closed) => Ok(()),
                    Ok(HandleCloseStatus::AlreadyClosed) | Err(_) => Err(AdapterError::Internal),
                }
            })
            .map_err(|error| map_namespace_operation_error(&error))?;
        handles.resources.remove(&handle).ok_or_else(|| {
            self.mark_fatal();
            AdapterError::Internal
        })?;
        Ok(())
    }

    fn file_request(&self, effect: FileEffect, path: CanonicalPath) -> CapabilityRequest {
        CapabilityRequest::new(
            self.clock.now(),
            AuthorityRequest::File(FileRequest::new(
                self.authority.repository.clone(),
                effect,
                path,
            )),
        )
    }

    fn file_open_requests(
        &self,
        intent: FileOpenIntent,
        object: &NamespaceObject,
    ) -> Result<CapabilityRequestSet, AdapterError> {
        let mut effects = Vec::with_capacity(3);
        match intent.access {
            FileAccess::ReadOnly => effects.push(FileEffect::ReadData),
            FileAccess::WriteOnly => effects.push(FileEffect::WriteData),
            FileAccess::ReadWrite => {
                effects.push(FileEffect::ReadData);
                effects.push(FileEffect::WriteData);
            }
        }
        if intent.truncate {
            effects.push(FileEffect::Truncate);
        }
        self.object_requests(&effects, object)
    }

    fn file_creation_requests(
        &self,
        creation_effect: FileEffect,
        intent: FileOpenIntent,
        object: &NamespaceObject,
    ) -> Result<CapabilityRequestSet, AdapterError> {
        let mut effects = Vec::with_capacity(3);
        effects.push(creation_effect);
        match intent.access {
            FileAccess::ReadOnly => effects.push(FileEffect::ReadData),
            FileAccess::WriteOnly => effects.push(FileEffect::WriteData),
            FileAccess::ReadWrite => {
                effects.push(FileEffect::ReadData);
                effects.push(FileEffect::WriteData);
            }
        }
        self.object_requests(&effects, object)
    }

    fn rename_requests(&self, plan: &RenamePlan) -> Result<CapabilityRequestSet, AdapterError> {
        let mut requests = Vec::with_capacity(plan.moved_objects().len().saturating_mul(2));
        for movement in plan.moved_objects() {
            requests.push(self.file_request(FileEffect::Rename, movement.source().clone()));
            requests.push(self.file_request(FileEffect::Rename, movement.destination().clone()));
        }
        let Some(first) = requests.first().cloned() else {
            self.mark_fatal();
            return Err(AdapterError::Internal);
        };
        Ok(CapabilityRequestSet::new(
            first,
            requests.into_iter().skip(1),
        ))
    }

    fn forget_node(&self, node: NodeId, count: u64) {
        let Some(count) = NonZeroU64::new(count) else {
            self.mark_fatal();
            return;
        };
        if self.nodes.forget(node, count).is_err() {
            self.mark_fatal();
        }
    }

    fn cleanup_handles(&self) {
        let Ok(mut handles) = self.handles.write() else {
            self.mark_fatal();
            return;
        };
        let pending = handles
            .resources
            .iter()
            .map(|(handle, resource)| {
                (
                    *handle,
                    resource.object.clone(),
                    resource.authority_handle.clone(),
                )
            })
            .collect::<Vec<_>>();
        for (handle, object, authority_handle) in pending {
            let closed = self.namespace.close_object_for_cleanup(&object, |_| {
                match self
                    .kernel
                    .close_handle(&self.authority.subject, &authority_handle)
                {
                    Ok(HandleCloseStatus::Closed | HandleCloseStatus::AlreadyClosed) => Ok(()),
                    Err(_) => Err(AdapterError::Internal),
                }
            });
            if closed.is_ok() {
                handles.resources.remove(&handle);
            } else {
                self.mark_fatal();
            }
        }
    }

    fn ensure_healthy(&self) -> Result<(), AdapterError> {
        if self.fatal.load(Ordering::Acquire) {
            return Err(AdapterError::Internal);
        }
        self.namespace
            .ensure_operational()
            .map_err(|_| AdapterError::Internal)
    }

    fn mark_fatal(&self) {
        self.fatal.store(true, Ordering::Release);
    }

    fn map_effect_error(&self, error: &EffectCommitError<AdapterError>) -> AdapterError {
        if matches!(
            error,
            EffectCommitError::CommittedButAudit { .. }
                | EffectCommitError::CommitUnknown { .. }
                | EffectCommitError::CommitUnknownAndAudit { .. }
        ) {
            // The backing operation may already exist even though its durable
            // receipt failed or its outcome could not be determined. Quarantine
            // every mount sharing this repository instead of allowing a retry
            // against unresolved backing state.
            self.namespace.mark_in_doubt();
            self.mark_fatal();
        }
        map_effect_error(error)
    }
}

impl Filesystem for CapabilityFilesystem {
    /// Negotiates the FUSE session.
    ///
    /// `FUSE_CACHE_SYMLINKS` must never be added here. `READLINK` revalidates
    /// that a link still resolves inside the repository from the link's current
    /// path, and a cached link body would let the kernel keep following a target
    /// that a rename has since turned into an escape without asking again.
    fn init(&mut self, _request: &Request, config: &mut KernelConfig) -> io::Result<()> {
        config
            .set_max_write(MAX_IO_SIZE)
            .map(|_| ())
            .map_err(|limit| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "FUSE kernel rejected {MAX_IO_SIZE}-byte request bound; maximum is {limit}"
                    ),
                )
            })
    }

    fn destroy(&mut self) {
        self.cleanup_handles();
    }

    fn lookup(&self, _request: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEntry) {
        let Some(parent) = NodeId::new(parent.0) else {
            reply.error(Errno::EIO);
            return;
        };
        let Some(name) = name.to_str() else {
            reply.error(Errno::ENOENT);
            return;
        };
        match self.lookup_entry(parent, name) {
            Ok(entry) => reply.entry(
                &ATTRIBUTE_TTL,
                &file_attr(entry.node, entry.metadata),
                NODE_GENERATION,
            ),
            Err(error) => reply.error(error.errno()),
        }
    }

    fn forget(&self, _request: &Request, node: INodeNo, lookup_count: u64) {
        let Some(node) = NodeId::new(node.0) else {
            self.mark_fatal();
            return;
        };
        self.forget_node(node, lookup_count);
    }

    fn getattr(
        &self,
        _request: &Request,
        node: INodeNo,
        handle: Option<FileHandle>,
        reply: ReplyAttr,
    ) {
        let Some(node) = NodeId::new(node.0) else {
            reply.error(Errno::EIO);
            return;
        };
        match self.getattr_entry(node, handle.map(|value| value.0)) {
            Ok(entry) => reply.attr(&ATTRIBUTE_TTL, &file_attr(entry.node, entry.metadata)),
            Err(error) => reply.error(error.errno()),
        }
    }

    fn setattr(
        &self,
        _request: &Request,
        node: INodeNo,
        mode: Option<u32>,
        uid: Option<u32>,
        gid: Option<u32>,
        size: Option<u64>,
        atime: Option<TimeOrNow>,
        mtime: Option<TimeOrNow>,
        changed_time: Option<SystemTime>,
        handle: Option<FileHandle>,
        created_time: Option<SystemTime>,
        status_change_time: Option<SystemTime>,
        backup_time: Option<SystemTime>,
        flags: Option<BsdFileFlags>,
        reply: ReplyAttr,
    ) {
        let Some(node) = NodeId::new(node.0) else {
            reply.error(Errno::EIO);
            return;
        };
        if uid.is_some()
            || gid.is_some()
            || changed_time.is_some()
            || created_time.is_some()
            || status_change_time.is_some()
            || backup_time.is_some()
            || flags.is_some()
        {
            reply.error(Errno::EPERM);
            return;
        }

        let entry = match supported_setattr_mutation(size, mode, atime, mtime) {
            // `truncate_file` returns the metadata captured immediately after
            // the mutation while the repository gate is still exclusive. Do
            // not fetch attributes a second time after releasing that gate.
            Ok(SetattrMutation::Truncate(size)) => self
                .truncate_file(node, handle.map(|value| value.0), size)
                .map(|metadata| Entry { node, metadata }),
            Ok(SetattrMutation::Metadata(update)) => self
                .set_metadata(node, update)
                .and_then(|()| self.getattr_entry(node, None)),
            Err(error) => Err(error),
        };

        match entry {
            Ok(entry) => reply.attr(&ATTRIBUTE_TTL, &file_attr(entry.node, entry.metadata)),
            Err(error) => reply.error(error.errno()),
        }
    }

    fn mkdir(
        &self,
        _request: &Request,
        parent: INodeNo,
        name: &OsStr,
        mode: u32,
        umask: u32,
        reply: ReplyEntry,
    ) {
        let Some(parent) = NodeId::new(parent.0) else {
            reply.error(Errno::EIO);
            return;
        };
        let Some(name) = name.to_str() else {
            reply.error(Errno::ENOENT);
            return;
        };
        match self.create_directory(parent, name, mode, umask) {
            Ok(entry) => reply.entry(
                &ATTRIBUTE_TTL,
                &file_attr(entry.node, entry.metadata),
                NODE_GENERATION,
            ),
            Err(error) => reply.error(error.errno()),
        }
    }

    fn create(
        &self,
        _request: &Request,
        parent: INodeNo,
        name: &OsStr,
        mode: u32,
        umask: u32,
        flags: i32,
        reply: ReplyCreate,
    ) {
        let Some(parent) = NodeId::new(parent.0) else {
            reply.error(Errno::EIO);
            return;
        };
        let Some(name) = name.to_str() else {
            reply.error(Errno::ENOENT);
            return;
        };
        match self.create_file(parent, name, mode, umask, flags) {
            Ok(created) => reply.created(
                &ATTRIBUTE_TTL,
                &file_attr(created.node, created.metadata),
                NODE_GENERATION,
                FileHandle(created.handle),
                // CREATE always hands back a writable handle.
                WRITABLE_HANDLE_FLAGS,
            ),
            Err(error) => reply.error(error.errno()),
        }
    }

    fn readlink(&self, _request: &Request, node: INodeNo, reply: ReplyData) {
        let Some(node) = NodeId::new(node.0) else {
            reply.error(Errno::EIO);
            return;
        };
        match self.read_link(node) {
            Ok(target) => reply.data(target.as_bytes()),
            Err(error) => reply.error(error.errno()),
        }
    }

    fn symlink(
        &self,
        _request: &Request,
        parent: INodeNo,
        link_name: &OsStr,
        target: &Path,
        reply: ReplyEntry,
    ) {
        let Some(parent) = NodeId::new(parent.0) else {
            reply.error(Errno::EIO);
            return;
        };
        let Some(link_name) = link_name.to_str() else {
            reply.error(Errno::ENOENT);
            return;
        };
        let Some(target) = target.to_str() else {
            // A target the canonical path model cannot represent is refused
            // rather than stored as opaque bytes it could never resolve.
            reply.error(Errno::EPERM);
            return;
        };
        match self.create_symlink(parent, link_name, target) {
            Ok(entry) => reply.entry(
                &ATTRIBUTE_TTL,
                &file_attr(entry.node, entry.metadata),
                NODE_GENERATION,
            ),
            Err(error) => reply.error(error.errno()),
        }
    }

    fn link(
        &self,
        _request: &Request,
        node: INodeNo,
        new_parent: INodeNo,
        new_name: &OsStr,
        reply: ReplyEntry,
    ) {
        let Some(node) = NodeId::new(node.0) else {
            reply.error(Errno::EIO);
            return;
        };
        let Some(new_parent) = NodeId::new(new_parent.0) else {
            reply.error(Errno::EIO);
            return;
        };
        let Some(new_name) = new_name.to_str() else {
            reply.error(Errno::ENOENT);
            return;
        };
        match self.create_hard_link(node, new_parent, new_name) {
            Ok(entry) => reply.entry(
                &ATTRIBUTE_TTL,
                &file_attr(entry.node, entry.metadata),
                NODE_GENERATION,
            ),
            Err(error) => reply.error(error.errno()),
        }
    }

    /// Refuses device, FIFO, and socket creation explicitly.
    ///
    /// The default `Filesystem` implementation answers `ENOSYS`, which tells
    /// the kernel the operation is merely unimplemented. capfs models a closed
    /// object universe of directories, regular files, and symbolic links, so
    /// this is a policy refusal and says so with `EPERM`.
    fn mknod(
        &self,
        _request: &Request,
        _parent: INodeNo,
        _name: &OsStr,
        _mode: u32,
        _umask: u32,
        _rdev: u32,
        reply: ReplyEntry,
    ) {
        reply.error(Errno::EPERM);
    }

    fn unlink(&self, _request: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        let Some(parent) = NodeId::new(parent.0) else {
            reply.error(Errno::EIO);
            return;
        };
        let Some(name) = name.to_str() else {
            reply.error(Errno::ENOENT);
            return;
        };
        match self.remove_file(parent, name) {
            Ok(()) => reply.ok(),
            Err(error) => reply.error(error.errno()),
        }
    }

    fn rmdir(&self, _request: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        let Some(parent) = NodeId::new(parent.0) else {
            reply.error(Errno::EIO);
            return;
        };
        let Some(name) = name.to_str() else {
            reply.error(Errno::ENOENT);
            return;
        };
        match self.remove_directory(parent, name) {
            Ok(()) => reply.ok(),
            Err(error) => reply.error(error.errno()),
        }
    }

    fn rename(
        &self,
        _request: &Request,
        parent: INodeNo,
        name: &OsStr,
        newparent: INodeNo,
        newname: &OsStr,
        flags: FuseRenameFlags,
        reply: ReplyEmpty,
    ) {
        let Some(parent) = NodeId::new(parent.0) else {
            reply.error(Errno::EIO);
            return;
        };
        let Some(newparent) = NodeId::new(newparent.0) else {
            reply.error(Errno::EIO);
            return;
        };
        let Some(name) = name.to_str() else {
            reply.error(Errno::ENOENT);
            return;
        };
        let Some(newname) = newname.to_str() else {
            reply.error(Errno::ENOENT);
            return;
        };
        match self.rename_entry(parent, name, newparent, newname, flags) {
            Ok(()) => reply.ok(),
            Err(error) => reply.error(error.errno()),
        }
    }

    fn open(&self, _request: &Request, node: INodeNo, flags: OpenFlags, reply: ReplyOpen) {
        let Some(node) = NodeId::new(node.0) else {
            reply.error(Errno::EIO);
            return;
        };
        match self.open_file(node, flags) {
            Ok(handle) => reply.opened(FileHandle(handle), handle_cache_mode(flags)),
            Err(error) => reply.error(error.errno()),
        }
    }

    fn opendir(&self, _request: &Request, node: INodeNo, flags: OpenFlags, reply: ReplyOpen) {
        let Some(node) = NodeId::new(node.0) else {
            reply.error(Errno::EIO);
            return;
        };
        match self.open_directory(node, flags) {
            Ok(handle) => reply.opened(FileHandle(handle), FopenFlags::empty()),
            Err(error) => reply.error(error.errno()),
        }
    }

    fn readdir(
        &self,
        _request: &Request,
        node: INodeNo,
        handle: FileHandle,
        offset: u64,
        mut reply: ReplyDirectory,
    ) {
        let Some(node) = NodeId::new(node.0) else {
            reply.error(Errno::EIO);
            return;
        };
        match self.read_directory(node, handle.0, offset) {
            Ok(entries) => {
                for entry in entries {
                    let inode = entry.node.map_or(INodeNo(0), |node| INodeNo(node.as_u64()));
                    if reply.add(
                        inode,
                        entry.next_offset,
                        namespace_file_type(entry.kind),
                        entry.name,
                    ) {
                        break;
                    }
                }
                reply.ok();
            }
            Err(error) => reply.error(error.errno()),
        }
    }

    fn read(
        &self,
        _request: &Request,
        node: INodeNo,
        handle: FileHandle,
        offset: u64,
        size: u32,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        reply: ReplyData,
    ) {
        let Some(node) = NodeId::new(node.0) else {
            reply.error(Errno::EIO);
            return;
        };
        match self.read_file(node, handle.0, offset, size) {
            Ok(bytes) => reply.data(&bytes),
            Err(error) => reply.error(error.errno()),
        }
    }

    fn write(
        &self,
        _request: &Request,
        node: INodeNo,
        handle: FileHandle,
        offset: u64,
        data: &[u8],
        write_flags: WriteFlags,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        reply: ReplyWrite,
    ) {
        let Some(node) = NodeId::new(node.0) else {
            reply.error(Errno::EIO);
            return;
        };
        match self.write_file_with_flags(node, handle.0, offset, data, write_flags) {
            Ok(written) => reply.written(written),
            Err(error) => reply.error(error.errno()),
        }
    }

    fn release(
        &self,
        _request: &Request,
        node: INodeNo,
        handle: FileHandle,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        _flush: bool,
        reply: ReplyEmpty,
    ) {
        let Some(node) = NodeId::new(node.0) else {
            reply.error(Errno::EIO);
            return;
        };
        match self.release_file(node, handle.0) {
            Ok(()) => reply.ok(),
            Err(error) => reply.error(error.errno()),
        }
    }

    fn releasedir(
        &self,
        _request: &Request,
        node: INodeNo,
        handle: FileHandle,
        _flags: OpenFlags,
        reply: ReplyEmpty,
    ) {
        let Some(node) = NodeId::new(node.0) else {
            reply.error(Errno::EIO);
            return;
        };
        match self.release_directory(node, handle.0) {
            Ok(()) => reply.ok(),
            Err(error) => reply.error(error.errno()),
        }
    }
}

/// Discards the operating system's caches for one mount when a capability is
/// revoked.
///
/// The FUSE kernel is allowed to answer `READ`, `LOOKUP`, and `GETATTR` from
/// its own page and attribute caches without consulting this adapter. Those
/// answers were authorized when the cache was filled, so a revocation that only
/// changed capability state would keep being satisfied from them. This observer
/// is what stops that: it is registered with the capability kernel before the
/// mount is spawned, and every revoking transition runs it before returning.
///
/// # Why this is sound
///
/// A FUSE notification is processed inline by the operating system while the
/// write to the FUSE device is still in progress, so once
/// [`Notifier::inval_inode`] returns the cached pages and attributes for that
/// inode are already gone. Every inode this mount has handed out is
/// invalidated, so after the observer returns there is no cached state left
/// that could answer a request. Any read issued after that must come back to
/// this adapter, which reauthorizes it and finds the capability revoked.
///
/// Reads already in flight when the revocation commits are not the concern:
/// they were authorized before it, and the capability kernel's own state guard
/// is what orders them.
///
/// # Failing closed
///
/// If the notifier is missing, the node table cannot be read, or the operating
/// system refuses an invalidation, the mount is marked fatal so every later
/// operation on it fails, and the error is reported to the revoking caller.
/// A cache that cannot be proven empty is treated as populated.
///
/// # Outliving its mount
///
/// The kernel holds registered observers for its own lifetime, which is longer
/// than any one mount's. The state this observer needs is therefore held
/// weakly: once the session is dropped the filesystem goes with it, the weak
/// references stop resolving, and the observer reports success because a mount
/// that no longer exists has no cache left to serve anything from. Holding
/// these strongly would keep the whole mount alive and turn every revoke after
/// an unmount into a propagation failure.
struct MountCacheInvalidator {
    mount: MountInstanceId,
    notifier: OnceLock<Notifier>,
    nodes: Weak<NodeTable>,
    fatal: Weak<AtomicBool>,
}

impl MountCacheInvalidator {
    fn new(mount: MountInstanceId, nodes: &Arc<NodeTable>, fatal: &Arc<AtomicBool>) -> Self {
        Self {
            mount,
            notifier: OnceLock::new(),
            nodes: Arc::downgrade(nodes),
            fatal: Arc::downgrade(fatal),
        }
    }

    /// Supplies the notifier once the session exists.
    ///
    /// Registration happens before the mount is spawned so that no revocation
    /// can commit without this observer running. Between registration and this
    /// call the observer has no notifier and deliberately fails closed.
    fn attach(&self, notifier: Notifier) {
        let _ = self.notifier.set(notifier);
    }

    fn fail(&self, reason: impl Into<String>) -> RevocationObserverError {
        if let Some(fatal) = self.fatal.upgrade() {
            fatal.store(true, Ordering::Release);
        }
        RevocationObserverError::new("capfs mount cache", reason)
    }
}

impl RevocationObserver for MountCacheInvalidator {
    fn discard_cached_decisions(&self) -> Result<(), RevocationObserverError> {
        let Some(nodes) = self.nodes.upgrade() else {
            // The mount is gone, so its caches went with it.
            return Ok(());
        };
        let Some(notifier) = self.notifier.get() else {
            return Err(self.fail(format!(
                "mount {} was revoked before its session could be notified",
                self.mount
            )));
        };
        // Snapshot first. Invalidation can block until the operating system
        // drains an in-flight request from this mount, and that request needs
        // the same table.
        let nodes = nodes
            .live_nodes()
            .map_err(|error| self.fail(format!("mount {} node table: {error}", self.mount)))?;

        for node in nodes {
            // Offset zero with length zero invalidates the whole file and its
            // cached attributes. ENOENT means the kernel already dropped this
            // inode, which is the state being asked for.
            match notifier.inval_inode(INodeNo(node.as_u64()), 0, 0) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(self.fail(format!(
                        "mount {} could not invalidate inode {}: {error}",
                        self.mount,
                        node.as_u64()
                    )));
                }
            }
        }
        Ok(())
    }
}

/// Reply flags for a writable file handle.
///
/// Writable handles stay on direct I/O. A buffered write through FUSE is
/// assembled page by page and has to read a partial page back before it can
/// modify it, which costs more than the round trips it saves. Direct I/O also
/// keeps every write reauthorized individually, which is strictly stronger than
/// what the page cache would give.
const WRITABLE_HANDLE_FLAGS: FopenFlags =
    FopenFlags::FOPEN_DIRECT_IO.union(FopenFlags::FOPEN_NOFLUSH);

/// Chooses whether one open handle uses the operating system's page cache.
///
/// A read-only handle is cached, which is what makes repeated reads cost
/// nothing. A writable handle is not, because buffered FUSE writes are slower
/// than direct ones and because mixing a cached and a direct handle on one
/// inode would let the cached one keep serving content the direct one has
/// already overwritten.
///
/// Neither choice is an authorization decision. A cached handle's reads are
/// reachable again after a revoke because [`MountCacheInvalidator`] discards
/// the cache before the revoke returns, and a direct handle's reads never left
/// this adapter in the first place.
///
/// `FOPEN_KEEP_CACHE` is never set, so a cached handle's pages are dropped at
/// the next `OPEN`. That bounds how long one mount can show content another
/// mount has since rewritten to a single open.
fn handle_cache_mode(flags: OpenFlags) -> FopenFlags {
    let requested = u32::try_from(flags.0).map(OFlags::from_bits_retain);
    match requested {
        Ok(flags) if !flags.intersects(OFlags::WRONLY | OFlags::RDWR) => FopenFlags::empty(),
        // Anything writable, and anything whose flags could not be read back,
        // takes the conservative path.
        _ => WRITABLE_HANDLE_FLAGS,
    }
}

/// Upper bound on session threads per mount.
///
/// One, on measured evidence rather than caution.
///
/// A single thread used to saturate at about four concurrent readers, and
/// raising this removed that plateau. Serving reads from the operating
/// system's page cache removed it far more effectively: a cached read never
/// reaches the session at all, so sixteen concurrent readers now cost the same
/// per operation whether this is one or eight.
///
/// What remained was the cost. Dispatching a request to a thread pool instead
/// of the same warm thread measured about 18% worse on single-client writes,
/// which still round trip because writable handles stay on direct I/O.
///
/// Raising this is worthwhile only for a workload that issues concurrent
/// *writes* or *opens*, which is the case the benchmark does not yet cover.
/// Each thread also holds its own request buffer sized by [`MAX_IO_SIZE`], so
/// threads cost roughly a megabyte of resident memory apiece, per mount, and a
/// host runs one mount per subject.
const MAX_SESSION_THREADS: usize = 1;

/// Returns the session thread count for one mount.
///
/// See [`MAX_SESSION_THREADS`] for why this is currently pinned to one, and
/// what evidence would justify raising it.
fn session_threads() -> usize {
    std::thread::available_parallelism()
        .map_or(1, NonZeroUsize::get)
        .min(MAX_SESSION_THREADS)
}

/// Returns the hardened direct-I/O mount configuration for [`CapabilityFilesystem`].
///
/// The session runs several threads. That is a throughput decision only: every
/// operation still performs its own authorization against the capability
/// kernel's state guard, and concurrent threads change neither the set of
/// authorized operations nor the point at which a revoke excludes them.
#[must_use]
pub fn mount_config() -> Config {
    let mut config = Config::default();
    config.mount_options = vec![
        MountOption::NoDev,
        MountOption::NoSuid,
        MountOption::NoExec,
        MountOption::NoAtime,
        MountOption::FSName("capfs".to_owned()),
        MountOption::Subtype("capfs".to_owned()),
    ];
    config.acl = SessionACL::Owner;
    config.n_threads = Some(session_threads());
    // Each thread needs its own descriptor to read the FUSE device without
    // contending on a shared one.
    config.clone_fd = true;
    config
}

/// Mounts a capability-enforcing filesystem on a background session thread.
///
/// Dropping the returned session unmounts the filesystem.
///
/// # Errors
///
/// Returns an I/O error when the mount configuration, mountpoint, FUSE device,
/// or userspace mount helper rejects the session.
pub fn spawn_mount(
    filesystem: CapabilityFilesystem,
    mountpoint: impl AsRef<Path>,
) -> io::Result<BackgroundSession> {
    // The observer is registered before the mount exists. A revocation can
    // therefore never commit against a live mount that this kernel does not
    // know to invalidate; the worst case is a revocation between registration
    // and `attach`, which fails closed because the notifier is still unset.
    let invalidator = Arc::new(MountCacheInvalidator::new(
        filesystem.authority.mount.clone(),
        &filesystem.nodes,
        &filesystem.fatal,
    ));
    filesystem
        .kernel
        .register_revocation_observer(Arc::clone(&invalidator) as Arc<dyn RevocationObserver>)
        .map_err(|error| {
            io::Error::other(format!(
                "capability kernel rejected the mount observer: {error}"
            ))
        })?;

    let session = fuser::spawn_mount(filesystem, mountpoint, &mount_config())?;
    invalidator.attach(session.notifier());
    Ok(session)
}

fn file_attr(node: NodeId, metadata: BackingMetadata) -> FileAttr {
    FileAttr {
        ino: INodeNo(node.as_u64()),
        size: metadata.size,
        blocks: metadata.blocks,
        atime: metadata.atime,
        mtime: metadata.mtime,
        ctime: metadata.ctime,
        crtime: UNIX_EPOCH,
        kind: namespace_file_type(metadata.kind),
        perm: metadata.permissions,
        nlink: metadata.link_count,
        uid: metadata.uid,
        gid: metadata.gid,
        rdev: 0,
        blksize: metadata.block_size,
        flags: 0,
    }
}

const fn metadata_time(value: TimeOrNow) -> MetadataTime {
    match value {
        TimeOrNow::Now => MetadataTime::Now,
        TimeOrNow::SpecificTime(time) => MetadataTime::Exact(time),
    }
}

fn supported_setattr_mutation(
    size: Option<u64>,
    mode: Option<u32>,
    atime: Option<TimeOrNow>,
    mtime: Option<TimeOrNow>,
) -> Result<SetattrMutation, AdapterError> {
    match (size, mode, atime, mtime) {
        (Some(size), None, None, None) => Ok(SetattrMutation::Truncate(size)),
        (None, Some(mode), None, None) => Ok(SetattrMutation::Metadata(
            MetadataUpdate::Permissions(MetadataPermissions::from_requested_mode(mode)),
        )),
        (None, None, access, modification) if access.is_some() || modification.is_some() => {
            let timestamps =
                MetadataTimes::new(access.map(metadata_time), modification.map(metadata_time))
                    .expect("the match guarantees a non-empty timestamp update");
            Ok(SetattrMutation::Metadata(MetadataUpdate::Timestamps(
                timestamps,
            )))
        }
        _ => Err(AdapterError::Unsupported),
    }
}

const fn namespace_file_type(kind: NamespaceObjectKind) -> FileType {
    match kind {
        NamespaceObjectKind::Directory => FileType::Directory,
        NamespaceObjectKind::RegularFile => FileType::RegularFile,
        NamespaceObjectKind::Symlink => FileType::Symlink,
    }
}

fn supported_open_flags(flags: OpenFlags) -> Result<OFlags, AdapterError> {
    let raw = u32::try_from(flags.0).map_err(|_| AdapterError::InvalidRequest)?;
    let flags = OFlags::from_bits_retain(raw);
    if flags.intersects(OFlags::APPEND | OFlags::CREATE | OFlags::EXCL)
        || flags.contains(OFlags::TMPFILE)
    {
        return Err(AdapterError::Unsupported);
    }
    Ok(flags)
}

/// Validates FUSE write provenance and returns whether set-ID bits must die.
fn supported_write_flags(flags: WriteFlags) -> Result<bool, AdapterError> {
    if flags.contains(WriteFlags::FUSE_WRITE_CACHE) {
        return Err(AdapterError::Unsupported);
    }
    Ok(flags.contains(WriteFlags::FUSE_WRITE_KILL_SUIDGID))
}

const fn map_node_lookup_error(error: &NodeTableError) -> AdapterError {
    match error {
        NodeTableError::UnknownNode(_) => AdapterError::NotFound,
        _ => AdapterError::Internal,
    }
}

const fn map_namespace_operation_error(
    error: &NamespaceOperationError<AdapterError>,
) -> AdapterError {
    match error {
        NamespaceOperationError::Namespace(
            NamespaceError::UnknownObject(_)
            | NamespaceError::UnknownPath(_)
            | NamespaceError::InvalidChildName(_),
        ) => AdapterError::NotFound,
        NamespaceOperationError::Namespace(NamespaceError::PathOccupied(_)) => {
            AdapterError::AlreadyExists
        }
        NamespaceOperationError::Namespace(NamespaceError::ParentNotDirectory(_)) => {
            AdapterError::NotDirectory
        }
        NamespaceOperationError::Namespace(NamespaceError::OpenHandleInSubtree(_)) => {
            AdapterError::Busy
        }
        NamespaceOperationError::Namespace(NamespaceError::DirectoryNotEmpty(_)) => {
            AdapterError::DirectoryNotEmpty
        }
        NamespaceOperationError::Namespace(NamespaceError::DirectoryGenerationChanged {
            ..
        }) => AdapterError::TryAgain,
        NamespaceOperationError::Namespace(NamespaceError::DestinationInsideSource) => {
            AdapterError::InvalidRequest
        }
        // A target that would leave the repository is refused rather than
        // handed to the kernel, which would resolve it outside this mount.
        NamespaceOperationError::Namespace(
            NamespaceError::SymlinkTargetEscapes(_) | NamespaceError::CannotAliasKind { .. },
        ) => AdapterError::CrossDevice,
        NamespaceOperationError::Namespace(NamespaceError::InvalidSymlinkTarget(_)) => {
            AdapterError::Unsupported
        }
        NamespaceOperationError::Namespace(_) => AdapterError::Internal,
        NamespaceOperationError::Executor(error) => *error,
    }
}

const fn map_metadata_inspection_error(
    error: &CapabilityInspectionError<AdapterError>,
) -> AdapterError {
    match error {
        CapabilityInspectionError::NotActive => AdapterError::NotFound,
        CapabilityInspectionError::Inspection(error) => *error,
        CapabilityInspectionError::LockPoisoned => AdapterError::Internal,
    }
}

const fn map_effect_error(error: &EffectCommitError<AdapterError>) -> AdapterError {
    match error {
        EffectCommitError::NotAuthorized => AdapterError::AccessDenied,
        EffectCommitError::Effect(error) => *error,
        // An unknown commit outcome is reported as a failure, which is the only
        // answer that cannot mislead: claiming success would invent a result,
        // and the caller must not retry an operation that may already have
        // taken effect. `map_effect_error` on the filesystem marks the mount
        // fatal for these.
        EffectCommitError::LockPoisoned
        | EffectCommitError::Audit(_)
        | EffectCommitError::CommittedButAudit { .. }
        | EffectCommitError::CommitUnknown { .. }
        | EffectCommitError::CommitUnknownAndAudit { .. } => AdapterError::Internal,
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        num::NonZeroUsize,
        os::unix::fs::PermissionsExt,
        sync::{Arc, Barrier},
        thread,
        time::{Duration, UNIX_EPOCH},
    };

    use authority_core::{
        audit::AttemptOutcome,
        capability::{AuthorityBody, AuthorityRequest, IssuerId, SubjectId},
        file::{FileAuthority, FileEffect, FileEffects},
        kernel::{CapabilityKernel, EffectCommitError},
        path::{CanonicalPath, PathPattern},
        repository::RepoId,
        state::{CapabilityGrant, CapabilityState, StaticAuthorityEnvelope, Subject},
        time::{MonotonicTime, TimeWindow},
    };
    use fuser::{OpenFlags, RenameFlags, TimeOrNow, WriteFlags};
    use rustix::fs::OFlags;
    use tempfile::{TempDir, tempdir};

    use super::{
        AdapterError, CapabilityFilesystem, CapabilityFilesystemError, MetadataUpdate,
        MountAuthority, MountInstanceId, NodeId, OpenBacking, SetattrMutation, TruncateCommit,
        supported_setattr_mutation, supported_write_flags,
    };
    use crate::{
        backing::{ImportedRepository, PreflightLimits},
        namespace::{NamespaceExecutorOutcome, NamespaceObjectKind},
        runtime::{MetadataPermissions, MetadataTime, MetadataTimes},
    };

    fn path(segments: &[&str]) -> CanonicalPath {
        CanonicalPath::new(segments).expect("test path must be canonical")
    }

    fn open_flags(flags: OFlags) -> OpenFlags {
        OpenFlags(i32::try_from(flags.bits()).expect("test open flags must fit i32"))
    }

    #[test]
    fn write_flags_accept_kernel_set_id_cleanup_but_reject_cached_writes() {
        assert_eq!(
            supported_write_flags(WriteFlags::FUSE_WRITE_KILL_SUIDGID),
            Ok(true),
            "ordinary direct writes may require set-ID cleanup"
        );
        assert_eq!(supported_write_flags(WriteFlags::empty()), Ok(false));
        assert_eq!(
            supported_write_flags(
                WriteFlags::FUSE_WRITE_CACHE | WriteFlags::FUSE_WRITE_KILL_SUIDGID,
            ),
            Err(AdapterError::Unsupported),
            "page-cache writes do not carry trustworthy identity or handles"
        );
    }

    fn create_flags(flags: OFlags) -> i32 {
        i32::try_from(flags.bits()).expect("test create flags must fit i32")
    }

    fn test_filesystem() -> (
        TempDir,
        CapabilityFilesystem,
        Arc<CapabilityKernel>,
        authority_core::capability::CapId,
    ) {
        test_filesystem_with_pattern(PathPattern::Prefix(path(&["scoped"])))
    }

    fn test_filesystem_with_pattern(
        authority_path: PathPattern,
    ) -> (
        TempDir,
        CapabilityFilesystem,
        Arc<CapabilityKernel>,
        authority_core::capability::CapId,
    ) {
        test_filesystem_with_effects(
            authority_path,
            FileEffects::from_effects([FileEffect::ReadData, FileEffect::ListDirectory]),
        )
    }

    fn test_filesystem_with_effects(
        authority_path: PathPattern,
        effects: FileEffects,
    ) -> (
        TempDir,
        CapabilityFilesystem,
        Arc<CapabilityKernel>,
        authority_core::capability::CapId,
    ) {
        let directory = tempdir().expect("temporary repository must be creatable");
        fs::create_dir(directory.path().join("scoped"))
            .expect("authorized test directory must be creatable");
        fs::write(directory.path().join("scoped/allowed.txt"), b"capability")
            .expect("authorized test file must be writable");
        fs::write(directory.path().join("hidden.txt"), b"hidden")
            .expect("hidden test file must be writable");
        let imported = ImportedRepository::open(
            RepoId::new("workspace"),
            directory.path(),
            PreflightLimits::new(NonZeroUsize::new(16).expect("limit must be non-zero"), 4),
        )
        .expect("test repository must pass preflight");

        let subject = SubjectId::new("subject");
        let repository = RepoId::new("workspace");
        let validity = TimeWindow::new(MonotonicTime::from_ticks(0), MonotonicTime::from_ticks(10))
            .expect("test validity window must be non-empty");
        let envelope = StaticAuthorityEnvelope::new(
            validity,
            AuthorityBody::File(FileAuthority::new(
                repository.clone(),
                effects,
                PathPattern::Prefix(CanonicalPath::root()),
            )),
        );
        let kernel = Arc::new(CapabilityKernel::new(CapabilityState::new(IssuerId::new(
            "issuer",
        ))));
        kernel
            .register_subject(Subject::new(subject.clone(), envelope))
            .expect("test subject registration must succeed");
        let capability = kernel
            .issue_root(CapabilityGrant::new(
                subject.clone(),
                validity,
                AuthorityBody::File(FileAuthority::new(
                    repository.clone(),
                    effects,
                    authority_path,
                )),
            ))
            .expect("test capability issuance must succeed");
        let authority = MountAuthority::new(
            MountInstanceId::new("test-mount"),
            subject,
            capability.clone(),
            repository,
        );
        let filesystem = CapabilityFilesystem::new(
            imported,
            Arc::clone(&kernel),
            authority,
            Arc::new(MonotonicTime::from_ticks(5)),
        )
        .expect("test filesystem must initialize");
        (directory, filesystem, kernel, capability)
    }

    #[test]
    fn lookup_exposes_only_the_authority_range_and_its_ancestors() {
        let (_directory, filesystem, _kernel, _capability) = test_filesystem();

        let scoped = filesystem
            .lookup_entry(NodeId::ROOT, "scoped")
            .expect("an authority ancestor must remain visible");
        assert_eq!(scoped.metadata.kind, NamespaceObjectKind::Directory);
        let allowed = filesystem
            .lookup_entry(scoped.node, "allowed.txt")
            .expect("a path inside authority must remain visible");
        assert_eq!(allowed.metadata.kind, NamespaceObjectKind::RegularFile);
        assert!(matches!(
            filesystem.lookup_entry(NodeId::ROOT, "hidden.txt"),
            Err(AdapterError::NotFound)
        ));
    }

    #[test]
    fn open_read_and_release_track_both_handle_registries() {
        let (_directory, filesystem, kernel, _capability) = test_filesystem();
        let scoped = filesystem
            .lookup_entry(NodeId::ROOT, "scoped")
            .expect("authorized directory must resolve");
        let allowed = filesystem
            .lookup_entry(scoped.node, "allowed.txt")
            .expect("authorized file must resolve");

        assert_eq!(
            filesystem.open_file(allowed.node, OpenFlags(1)),
            Err(AdapterError::AccessDenied)
        );
        let handle = filesystem
            .open_file(allowed.node, OpenFlags(0))
            .expect("read-only authorized open must succeed");
        let object = filesystem
            .nodes
            .resolve(allowed.node)
            .expect("opened node must stay bound");
        assert_eq!(kernel.object_open_handle_count(&object), Ok(1));
        assert_eq!(
            filesystem
                .namespace
                .object_snapshot(&object)
                .map(|value| value.map(|record| record.open_handle_count())),
            Ok(Some(1))
        );
        assert_eq!(
            filesystem
                .read_file(allowed.node, handle, 3, 4)
                .expect("authorized positioned read must succeed"),
            b"abil"
        );

        filesystem
            .release_file(allowed.node, handle)
            .expect("release must close both handle registries");
        assert_eq!(kernel.object_open_handle_count(&object), Ok(0));
        assert_eq!(
            filesystem
                .namespace
                .object_snapshot(&object)
                .map(|value| value.map(|record| record.open_handle_count())),
            Ok(Some(0))
        );
    }

    // Requirement: CREATE authorizes both installation of the namespace entry
    // and the access mode of the returned FUSE handle. Category: FUSE/create.
    // Risk: critical.
    #[test]
    fn create_file_requires_the_creation_and_handle_access_effects() {
        let (directory, filesystem, _kernel, _capability) = test_filesystem_with_effects(
            PathPattern::Prefix(path(&["scoped"])),
            FileEffects::only(FileEffect::CreateFile),
        );
        let scoped = filesystem
            .lookup_entry(NodeId::ROOT, "scoped")
            .expect("create authority must expose its parent directory");

        assert!(matches!(
            filesystem.create_file(
                scoped.node,
                "created.txt",
                0o666,
                0,
                create_flags(OFlags::WRONLY),
            ),
            Err(AdapterError::AccessDenied)
        ));
        assert!(
            !directory.path().join("scoped/created.txt").exists(),
            "a denied compound CREATE must publish neither a namespace object nor a backing file"
        );
    }

    // Requirement: successful CREATE publishes one lookup reference and one
    // open handle together. Category: FUSE/create. Risk: critical.
    #[test]
    fn create_file_returns_a_writable_handle_for_the_new_namespace_object() {
        let (directory, filesystem, kernel, _capability) = test_filesystem_with_effects(
            PathPattern::Prefix(path(&["scoped"])),
            FileEffects::from_effects([FileEffect::CreateFile, FileEffect::WriteData]),
        );
        let scoped = filesystem
            .lookup_entry(NodeId::ROOT, "scoped")
            .expect("create authority must expose its parent directory");
        let created = filesystem
            .create_file(
                scoped.node,
                "created.txt",
                0o666,
                0o027,
                create_flags(OFlags::WRONLY),
            )
            .expect("CreateFile and WriteData must authorize a writable CREATE");
        let object = filesystem
            .nodes
            .resolve(created.node)
            .expect("a successful CREATE must bind its returned node");

        assert_eq!(created.metadata.permissions, 0o640);
        assert_eq!(kernel.object_open_handle_count(&object), Ok(1));
        assert_eq!(
            filesystem
                .namespace
                .object_snapshot(&object)
                .map(|value| value.map(|record| record.open_handle_count())),
            Ok(Some(1))
        );
        assert_eq!(
            filesystem
                .write_file(created.node, created.handle, 0, b"new content")
                .expect("the returned O_WRONLY handle must remain usable"),
            11
        );
        assert_eq!(
            fs::read(directory.path().join("scoped/created.txt"))
                .expect("the new backing file must be readable in the test"),
            b"new content"
        );
        filesystem
            .release_file(created.node, created.handle)
            .expect("the CREATE handle must release both registries");
        assert_eq!(kernel.object_open_handle_count(&object), Ok(0));
    }

    // Requirement: MKDIR is a separate effect from file creation and publishes
    // only after the hardened backing operation succeeds. Category: FUSE/create.
    // Risk: critical.
    #[test]
    fn create_directory_requires_its_own_effect_and_applies_request_umask() {
        let (directory, filesystem, _kernel, _capability) = test_filesystem_with_effects(
            PathPattern::Prefix(path(&["scoped"])),
            FileEffects::only(FileEffect::CreateDirectory),
        );
        let scoped = filesystem
            .lookup_entry(NodeId::ROOT, "scoped")
            .expect("directory-create authority must expose its parent");
        let created = filesystem
            .create_directory(scoped.node, "created-dir", 0o777, 0o027)
            .expect("CreateDirectory must authorize MKDIR without file-create authority");

        assert_eq!(created.metadata.kind, NamespaceObjectKind::Directory);
        assert_eq!(created.metadata.permissions, 0o750);
        assert!(directory.path().join("scoped/created-dir").is_dir());
        assert!(matches!(
            filesystem.create_file(
                scoped.node,
                "not-a-file.txt",
                0o600,
                0,
                create_flags(OFlags::WRONLY),
            ),
            Err(AdapterError::AccessDenied)
        ));
    }

    #[test]
    fn create_rejects_an_occupied_child_and_a_non_directory_parent() {
        let (_directory, filesystem, _kernel, _capability) = test_filesystem_with_effects(
            PathPattern::Prefix(path(&["scoped"])),
            FileEffects::from_effects([FileEffect::CreateFile, FileEffect::WriteData]),
        );
        let scoped = filesystem
            .lookup_entry(NodeId::ROOT, "scoped")
            .expect("authorized directory must resolve");
        let existing = filesystem
            .lookup_entry(scoped.node, "allowed.txt")
            .expect("authorized file must resolve");

        assert!(matches!(
            filesystem.create_file(
                scoped.node,
                "allowed.txt",
                0o600,
                0,
                create_flags(OFlags::WRONLY),
            ),
            Err(AdapterError::AlreadyExists)
        ));
        assert!(matches!(
            filesystem.create_file(
                existing.node,
                "child.txt",
                0o600,
                0,
                create_flags(OFlags::WRONLY),
            ),
            Err(AdapterError::NotDirectory)
        ));
    }

    // Requirement: UNLINK requires RemoveFile at the child path and must not
    // remove a file while any handle is live. Category: FUSE/remove. Risk: critical.
    #[test]
    fn remove_file_reauthorizes_the_named_child_and_respects_open_handles() {
        let (directory, filesystem, _kernel, _capability) = test_filesystem_with_effects(
            PathPattern::Prefix(path(&["scoped"])),
            FileEffects::only(FileEffect::ReadData),
        );
        let scoped = filesystem
            .lookup_entry(NodeId::ROOT, "scoped")
            .expect("metadata visibility must expose the authorized ancestor");
        assert_eq!(
            filesystem.remove_file(scoped.node, "allowed.txt"),
            Err(AdapterError::AccessDenied)
        );
        assert!(directory.path().join("scoped/allowed.txt").is_file());

        let (directory, filesystem, _kernel, _capability) = test_filesystem_with_effects(
            PathPattern::Prefix(path(&["scoped"])),
            FileEffects::from_effects([FileEffect::ReadData, FileEffect::RemoveFile]),
        );
        let scoped = filesystem
            .lookup_entry(NodeId::ROOT, "scoped")
            .expect("remove authority must expose the parent directory");
        let allowed = filesystem
            .lookup_entry(scoped.node, "allowed.txt")
            .expect("remove authority must expose the target file");
        let handle = filesystem
            .open_file(allowed.node, OpenFlags(0))
            .expect("ReadData must authorize a test open handle");

        assert_eq!(
            filesystem.remove_file(scoped.node, "allowed.txt"),
            Err(AdapterError::Busy),
            "removal must not detach a namespace object while its handle is live"
        );
        filesystem
            .release_file(allowed.node, handle)
            .expect("the test handle must release normally");
        filesystem
            .remove_file(scoped.node, "allowed.txt")
            .expect("RemoveFile must delete a closed regular file");
        assert!(!directory.path().join("scoped/allowed.txt").exists());
    }

    // Requirement: POSIX unlink removes both regular files and symbolic links, while directories
    // remain exclusive to RMDIR. Category: FUSE/remove. Risk: critical.
    #[test]
    fn remove_file_accepts_a_symbolic_link_but_not_a_directory() {
        let (directory, filesystem, _kernel, _capability) = test_filesystem_with_effects(
            PathPattern::Prefix(path(&["scoped"])),
            FileEffects::from_effects([
                FileEffect::CreateDirectory,
                FileEffect::CreateSymlink,
                FileEffect::RemoveFile,
            ]),
        );
        let scoped = filesystem
            .lookup_entry(NodeId::ROOT, "scoped")
            .expect("remove authority must expose the parent directory");
        filesystem
            .create_symlink(scoped.node, "link.txt", "allowed.txt")
            .expect("CreateSymlink must create the test link");

        filesystem
            .remove_file(scoped.node, "link.txt")
            .expect("RemoveFile must unlink a symbolic link without following it");
        assert!(
            fs::symlink_metadata(directory.path().join("scoped/link.txt")).is_err(),
            "the symbolic link name must be removed"
        );
        assert!(directory.path().join("scoped/allowed.txt").is_file());
        filesystem
            .create_directory(scoped.node, "empty", 0o700, 0)
            .expect("CreateDirectory must create an empty comparison directory");
        assert_eq!(
            filesystem.remove_file(scoped.node, "empty"),
            Err(AdapterError::IsDirectory),
            "UNLINK must not remove a directory"
        );
    }

    // Requirement: RMDIR has its own effect and only commits for an empty
    // directory. Category: FUSE/remove. Risk: critical.
    #[test]
    fn remove_directory_requires_remove_directory_and_an_empty_child() {
        let (directory, filesystem, _kernel, _capability) = test_filesystem_with_effects(
            PathPattern::Prefix(path(&["scoped"])),
            FileEffects::from_effects([FileEffect::CreateDirectory, FileEffect::RemoveDirectory]),
        );
        let scoped = filesystem
            .lookup_entry(NodeId::ROOT, "scoped")
            .expect("directory authority must expose its parent");
        filesystem
            .create_directory(scoped.node, "empty", 0o755, 0)
            .expect("CreateDirectory must create an empty test directory");

        filesystem
            .remove_directory(scoped.node, "empty")
            .expect("RemoveDirectory must remove an empty directory");
        assert!(!directory.path().join("scoped/empty").exists());
        assert_eq!(
            filesystem.remove_directory(scoped.node, "allowed.txt"),
            Err(AdapterError::NotDirectory),
            "RMDIR must not silently remove a regular file"
        );
    }

    // Requirement: a subtree rename checks Rename on both the source and
    // destination of every moved object. Category: FUSE/rename. Risk: critical.
    #[test]
    fn rename_authorizes_every_subtree_source_and_destination_path() {
        let (directory, filesystem, kernel, _capability) = test_filesystem_with_effects(
            PathPattern::Prefix(path(&["scoped"])),
            FileEffects::from_effects([
                FileEffect::CreateDirectory,
                FileEffect::CreateFile,
                FileEffect::WriteData,
                FileEffect::Rename,
            ]),
        );
        let scoped = filesystem
            .lookup_entry(NodeId::ROOT, "scoped")
            .expect("rename authority must expose its parent directory");
        let source = filesystem
            .create_directory(scoped.node, "source", 0o755, 0)
            .expect("test source directory must be creatable");
        let child = filesystem
            .create_file(
                source.node,
                "child.txt",
                0o600,
                0,
                create_flags(OFlags::WRONLY),
            )
            .expect("test child file must be creatable");
        filesystem
            .release_file(child.node, child.handle)
            .expect("the test child handle must release before rename");

        filesystem
            .rename_entry(
                scoped.node,
                "source",
                scoped.node,
                "moved",
                RenameFlags::empty(),
            )
            .expect("Rename authority must move a closed subtree without replacement");
        assert!(directory.path().join("scoped/moved/child.txt").is_file());
        assert!(!directory.path().join("scoped/source").exists());

        let record = kernel
            .effect_records()
            .expect("audit records must remain available")
            .pop()
            .expect("successful rename must produce an effect record");
        let requests = record
            .requests()
            .map(|request| match request.authority() {
                AuthorityRequest::File(request) => (request.effect(), request.path().clone()),
                _ => panic!("a capfs rename audit record must contain only file requests"),
            })
            .collect::<Vec<_>>();
        assert_eq!(requests.len(), 4);
        for expected_path in [
            path(&["scoped", "source"]),
            path(&["scoped", "moved"]),
            path(&["scoped", "source", "child.txt"]),
            path(&["scoped", "moved", "child.txt"]),
        ] {
            assert!(
                requests.iter().any(|(effect, request_path)| {
                    *effect == FileEffect::Rename && request_path == &expected_path
                }),
                "rename audit must include `{expected_path:?}`"
            );
        }
    }

    // Requirement: each positioned write checks WriteData at the object's
    // current path and preserves every byte outside the requested range.
    // Category: FUSE/authorization. Risk: critical.
    #[test]
    fn write_uses_a_writable_handle_and_current_path_authorization() {
        let (directory, filesystem, _kernel, _capability) = test_filesystem_with_effects(
            PathPattern::Prefix(path(&["scoped"])),
            FileEffects::only(FileEffect::WriteData),
        );
        let scoped = filesystem
            .lookup_entry(NodeId::ROOT, "scoped")
            .expect("write authority must make its ancestor visible");
        let allowed = filesystem
            .lookup_entry(scoped.node, "allowed.txt")
            .expect("write authority must make its target visible");
        let handle = filesystem
            .open_file(allowed.node, OpenFlags(1))
            .expect("WriteData authority must open an O_WRONLY handle");

        assert_eq!(
            filesystem
                .write_file(allowed.node, handle, 3, b"SAFE")
                .expect("authorized positioned write must succeed"),
            4
        );
        assert_eq!(
            fs::read(directory.path().join("scoped/allowed.txt"))
                .expect("backing content must remain readable in the test"),
            b"capSAFEity"
        );
        assert_eq!(
            filesystem.read_file(allowed.node, handle, 0, 1),
            Err(AdapterError::BadHandle),
            "an O_WRONLY handle must not gain read access from its backing descriptor"
        );
        filesystem
            .release_file(allowed.node, handle)
            .expect("writable handle must release normally");
    }

    // Requirement: revocation after OPEN prevents a later WRITE on the same
    // descriptor. Category: FUSE/revocation. Risk: critical.
    #[test]
    fn every_write_reauthorizes_an_existing_writable_handle() {
        let (directory, filesystem, kernel, capability) = test_filesystem_with_effects(
            PathPattern::Prefix(path(&["scoped"])),
            FileEffects::only(FileEffect::WriteData),
        );
        let scoped = filesystem
            .lookup_entry(NodeId::ROOT, "scoped")
            .expect("authorized directory must resolve");
        let allowed = filesystem
            .lookup_entry(scoped.node, "allowed.txt")
            .expect("authorized file must resolve");
        let handle = filesystem
            .open_file(allowed.node, OpenFlags(1))
            .expect("initial O_WRONLY open must succeed");

        assert_eq!(
            filesystem
                .write_file(allowed.node, handle, 0, b"C")
                .expect("write before revoke must succeed"),
            1
        );
        kernel
            .revoke_held_by(&SubjectId::new("subject"), &capability)
            .expect("test capability must be revocable");
        assert_eq!(
            filesystem.write_file(allowed.node, handle, 1, b"X"),
            Err(AdapterError::AccessDenied)
        );
        assert_eq!(
            fs::read(directory.path().join("scoped/allowed.txt"))
                .expect("test backing file must remain readable"),
            b"Capability"
        );
        filesystem
            .release_file(allowed.node, handle)
            .expect("revocation must not prevent writable handle release");
    }

    // Requirement: a live open handle excludes rename while a positioned write
    // is in flight, and every competing operation has one namespace order.
    // Category: bounded concurrency/security. Risk: critical.
    #[test]
    fn bounded_rename_write_race_keeps_open_handle_exclusive() {
        const OPERATIONS: usize = 32;

        let (directory, filesystem, _kernel, _capability) = test_filesystem_with_effects(
            PathPattern::Prefix(path(&["scoped"])),
            FileEffects::from_effects([FileEffect::WriteData, FileEffect::Rename]),
        );
        let scoped = filesystem
            .lookup_entry(NodeId::ROOT, "scoped")
            .expect("the authorized parent must resolve");
        let allowed = filesystem
            .lookup_entry(scoped.node, "allowed.txt")
            .expect("the authorized file must resolve");
        let handle = filesystem
            .open_file(allowed.node, OpenFlags(1))
            .expect("WriteData authority must open a writable handle");
        let filesystem = Arc::new(filesystem);
        let start = Arc::new(Barrier::new(2));

        let writer_filesystem = Arc::clone(&filesystem);
        let writer_start = Arc::clone(&start);
        let writer = thread::spawn(move || {
            writer_start.wait();
            (0..OPERATIONS)
                .map(|_| writer_filesystem.write_file(allowed.node, handle, 0, b"X"))
                .collect::<Vec<_>>()
        });

        let rename_filesystem = Arc::clone(&filesystem);
        let rename_start = Arc::clone(&start);
        let renamer = thread::spawn(move || {
            rename_start.wait();
            (0..OPERATIONS)
                .map(|_| {
                    rename_filesystem.rename_entry(
                        scoped.node,
                        "allowed.txt",
                        scoped.node,
                        "moved.txt",
                        RenameFlags::RENAME_NOREPLACE,
                    )
                })
                .collect::<Vec<_>>()
        });

        for result in writer.join().expect("writer thread must not panic") {
            assert_eq!(
                result,
                Ok(1),
                "every write must commit while the handle is live"
            );
        }
        for result in renamer.join().expect("rename thread must not panic") {
            assert_eq!(
                result,
                Err(AdapterError::Busy),
                "rename must not reach authorization or backing while an open handle exists"
            );
        }

        filesystem
            .release_file(allowed.node, handle)
            .expect("the live writable handle must close after the race");
        assert_eq!(
            fs::read(directory.path().join("scoped/allowed.txt"))
                .expect("the original backing path must remain readable"),
            b"Xapability"
        );
        assert!(!directory.path().join("scoped/moved.txt").exists());
    }

    // Requirement: O_RDWR requires both effects, not merely a writable
    // backing descriptor. Category: FUSE/least privilege. Risk: critical.
    #[test]
    fn read_write_open_requires_read_and_write_authority() {
        let (_directory, filesystem, _kernel, _capability) = test_filesystem_with_effects(
            PathPattern::Prefix(path(&["scoped"])),
            FileEffects::only(FileEffect::WriteData),
        );
        let scoped = filesystem
            .lookup_entry(NodeId::ROOT, "scoped")
            .expect("write authority must make its ancestor visible");
        let allowed = filesystem
            .lookup_entry(scoped.node, "allowed.txt")
            .expect("write authority must make its target visible");

        assert_eq!(
            filesystem.open_file(allowed.node, OpenFlags(2)),
            Err(AdapterError::AccessDenied)
        );
    }

    // Requirement: an O_RDWR handle uses the compound OPEN authorization but
    // still reauthorizes each later data operation. Category: FUSE/access.
    // Risk: critical.
    #[test]
    fn read_write_handle_serves_both_data_operations() {
        let (directory, filesystem, _kernel, _capability) = test_filesystem_with_effects(
            PathPattern::Prefix(path(&["scoped"])),
            FileEffects::from_effects([FileEffect::ReadData, FileEffect::WriteData]),
        );
        let scoped = filesystem
            .lookup_entry(NodeId::ROOT, "scoped")
            .expect("read/write authority must make its ancestor visible");
        let allowed = filesystem
            .lookup_entry(scoped.node, "allowed.txt")
            .expect("read/write authority must make its target visible");
        let handle = filesystem
            .open_file(allowed.node, OpenFlags(2))
            .expect("both effects must authorize an O_RDWR open");

        assert_eq!(
            filesystem
                .read_file(allowed.node, handle, 0, 3)
                .expect("O_RDWR handle must permit reads"),
            b"cap"
        );
        assert_eq!(
            filesystem
                .write_file(allowed.node, handle, 3, b"SAFE")
                .expect("O_RDWR handle must permit writes"),
            4
        );
        assert_eq!(
            fs::read(directory.path().join("scoped/allowed.txt"))
                .expect("test backing file must remain readable"),
            b"capSAFEity"
        );
        filesystem
            .release_file(allowed.node, handle)
            .expect("O_RDWR handle must release normally");
    }

    // Requirement: O_TRUNC requires both the requested handle access and the
    // separate Truncate effect. Category: FUSE/least privilege. Risk: critical.
    #[test]
    fn truncate_open_requires_explicit_truncate_authority() {
        let (directory, filesystem, _kernel, _capability) = test_filesystem_with_effects(
            PathPattern::Prefix(path(&["scoped"])),
            FileEffects::only(FileEffect::WriteData),
        );
        let scoped = filesystem
            .lookup_entry(NodeId::ROOT, "scoped")
            .expect("write authority must make its ancestor visible");
        let allowed = filesystem
            .lookup_entry(scoped.node, "allowed.txt")
            .expect("write authority must make its target visible");

        assert_eq!(
            filesystem.open_file(allowed.node, open_flags(OFlags::WRONLY | OFlags::TRUNC)),
            Err(AdapterError::AccessDenied)
        );
        assert_eq!(
            fs::read(directory.path().join("scoped/allowed.txt"))
                .expect("denied truncation must leave the backing file unchanged"),
            b"capability"
        );
        assert_eq!(
            filesystem.open_file(allowed.node, open_flags(OFlags::RDONLY | OFlags::TRUNC)),
            Err(AdapterError::Unsupported),
            "a read-only FUSE handle cannot carry a length-changing open intent"
        );
    }

    // Requirement: a successful O_TRUNC is performed under the same guard as
    // its compound authorization. Category: FUSE/authorization. Risk: critical.
    #[test]
    fn truncate_open_changes_length_only_after_compound_authorization() {
        let (directory, filesystem, _kernel, _capability) = test_filesystem_with_effects(
            PathPattern::Prefix(path(&["scoped"])),
            FileEffects::from_effects([FileEffect::WriteData, FileEffect::Truncate]),
        );
        let scoped = filesystem
            .lookup_entry(NodeId::ROOT, "scoped")
            .expect("truncate authority must make its ancestor visible");
        let allowed = filesystem
            .lookup_entry(scoped.node, "allowed.txt")
            .expect("truncate authority must make its target visible");

        let handle = filesystem
            .open_file(allowed.node, open_flags(OFlags::WRONLY | OFlags::TRUNC))
            .expect("WriteData and Truncate must authorize O_TRUNC together");
        assert_eq!(
            fs::read(directory.path().join("scoped/allowed.txt"))
                .expect("truncated backing file must remain readable"),
            b""
        );
        filesystem
            .release_file(allowed.node, handle)
            .expect("truncated handle must release normally");
    }

    // Requirement: SETATTR(size) checks Truncate at the object's current path
    // on every request. Category: FUSE/revocation. Risk: critical.
    #[test]
    fn explicit_size_change_reauthorizes_truncate() {
        let (directory, filesystem, kernel, capability) = test_filesystem_with_effects(
            PathPattern::Prefix(path(&["scoped"])),
            FileEffects::only(FileEffect::Truncate),
        );
        let scoped = filesystem
            .lookup_entry(NodeId::ROOT, "scoped")
            .expect("truncate authority must make its ancestor visible");
        let allowed = filesystem
            .lookup_entry(scoped.node, "allowed.txt")
            .expect("truncate authority must make its target visible");

        let metadata = filesystem
            .truncate_file(allowed.node, None, 4)
            .expect("Truncate authority must allow an explicit size change");
        assert_eq!(metadata.size, 4);
        assert_eq!(
            fs::read(directory.path().join("scoped/allowed.txt"))
                .expect("truncated backing file must remain readable"),
            b"capa"
        );

        kernel
            .revoke_held_by(&SubjectId::new("subject"), &capability)
            .expect("test capability must be revocable");
        assert_eq!(
            filesystem.truncate_file(allowed.node, None, 0),
            Err(AdapterError::AccessDenied)
        );
        assert_eq!(
            fs::read(directory.path().join("scoped/allowed.txt"))
                .expect("revoked truncation must leave the backing file unchanged"),
            b"capa"
        );
    }

    // Requirement: the adapter must not collapse a kernel post-commit audit
    // failure into the pre-commit error consumed by namespace transactions.
    #[test]
    fn namespace_effect_classification_preserves_commit_status() {
        let (_directory, filesystem, _kernel, _capability) = test_filesystem();
        assert_eq!(
            filesystem.namespace_effect_outcome::<()>(Ok(())),
            NamespaceExecutorOutcome::Committed(())
        );
        assert_eq!(
            filesystem
                .namespace_effect_outcome::<()>(Err(EffectCommitError::Effect(AdapterError::Busy))),
            NamespaceExecutorOutcome::FailedBeforeCommit(AdapterError::Busy)
        );
        assert_eq!(
            filesystem.namespace_effect_outcome::<()>(Err(EffectCommitError::CommitUnknown {
                attempt_id: authority_core::audit::AttemptId::from_u64(0),
                evidence: b"test ambiguity".to_vec(),
            })),
            NamespaceExecutorOutcome::CommittedWithError(AdapterError::Internal)
        );
        assert!(filesystem.namespace.is_in_doubt());
    }

    // Requirement: once a backing syscall succeeds but its later outcome is
    // unknown, the attempt is terminally ambiguous and the shared repository
    // rejects an exact retry before another backing invocation.
    #[test]
    fn post_write_failure_is_commit_unknown_and_cannot_be_retried() {
        let (directory, filesystem, kernel, _capability) = test_filesystem_with_effects(
            PathPattern::Prefix(path(&["scoped"])),
            FileEffects::only(FileEffect::WriteData),
        );
        let scoped = filesystem
            .lookup_entry(NodeId::ROOT, "scoped")
            .expect("write authority must expose its parent");
        let allowed = filesystem
            .lookup_entry(scoped.node, "allowed.txt")
            .expect("write authority must expose its target");
        let handle = filesystem
            .open_file(allowed.node, OpenFlags(1))
            .expect("WriteData must authorize the test handle");
        let handles = filesystem
            .handles
            .read()
            .expect("handle table must be readable");
        let resource = handles
            .resources
            .get(&handle)
            .expect("test handle must remain live");
        let OpenBacking::File(backing) = &resource.backing else {
            panic!("test handle must own a regular backing file");
        };

        let first: Result<(), _> =
            filesystem
                .namespace
                .with_object_mutation(&resource.object, |object| {
                    filesystem.with_authorized_object(object, FileEffect::WriteData, || {
                        backing
                            .write_at(0, b"X")
                            .expect("injected backing syscall must succeed");
                        super::commit_unknown()
                    })
                });
        assert!(first.is_err());
        drop(handles);

        assert_eq!(
            fs::read(directory.path().join("scoped/allowed.txt"))
                .expect("committed backing bytes must remain observable"),
            b"Xapability"
        );
        assert!(filesystem.namespace.is_in_doubt());
        assert_eq!(
            kernel
                .attempt_records()
                .expect("effect attempts must remain readable")
                .last()
                .expect("ambiguous write must append an attempt")
                .outcome(),
            AttemptOutcome::CommitUnknown
        );
        let attempts_before_retry = kernel
            .attempt_records()
            .expect("effect attempts must remain readable")
            .len();

        assert_eq!(
            filesystem.write_file(allowed.node, handle, 0, b"Y"),
            Err(AdapterError::Internal)
        );
        assert_eq!(
            kernel
                .attempt_records()
                .expect("effect attempts must remain readable")
                .len(),
            attempts_before_retry,
            "quarantine must reject retry before another authorization or backing call"
        );
        assert_eq!(
            fs::read(directory.path().join("scoped/allowed.txt"))
                .expect("rejected retry must leave committed bytes unchanged"),
            b"Xapability"
        );
    }

    // Requirement: failure to observe reply metadata after a successful
    // ftruncate quarantines the shared repository instead of falsifying the
    // effect as failed-before-commit.
    #[test]
    fn post_truncate_metadata_failure_quarantines_the_repository() {
        let (_directory, filesystem, kernel, _capability) = test_filesystem_with_effects(
            PathPattern::Prefix(path(&["scoped"])),
            FileEffects::only(FileEffect::Truncate),
        );
        let scoped = filesystem
            .lookup_entry(NodeId::ROOT, "scoped")
            .expect("truncate authority must make its ancestor visible");
        let allowed = filesystem
            .lookup_entry(scoped.node, "allowed.txt")
            .expect("truncate authority must make its target visible");
        let object = filesystem
            .nodes
            .resolve(allowed.node)
            .expect("test node must resolve to the truncated object");

        assert_eq!(
            filesystem.with_authorized_truncate(&object, |_| {
                super::committed_execution(TruncateCommit::MetadataUnavailable)
            }),
            Err(AdapterError::Internal)
        );
        assert!(filesystem.namespace.is_in_doubt());
        assert_eq!(
            kernel
                .attempt_records()
                .expect("truncate audit must remain readable")
                .last()
                .expect("truncate must append one audit attempt")
                .outcome(),
            AttemptOutcome::Committed,
            "reply metadata failure must not falsify the committed truncate"
        );
        assert_eq!(filesystem.ensure_healthy(), Err(AdapterError::Internal));
        assert!(matches!(
            filesystem.lookup_entry(NodeId::ROOT, "scoped"),
            Err(AdapterError::Internal)
        ));
    }

    // Requirement: mode and timestamp SETATTR requests require SetMetadata,
    // use one backing syscall per request, and reauthorize after revocation.
    // Category: FUSE/metadata. Risk: critical.
    #[test]
    fn metadata_changes_require_set_metadata_and_reauthorize() {
        let (directory, filesystem, _kernel, _capability) = test_filesystem_with_effects(
            PathPattern::Prefix(path(&["scoped"])),
            FileEffects::only(FileEffect::WriteData),
        );
        let scoped = filesystem
            .lookup_entry(NodeId::ROOT, "scoped")
            .expect("metadata visibility must expose the authorized parent");
        let allowed = filesystem
            .lookup_entry(scoped.node, "allowed.txt")
            .expect("metadata visibility must expose the authorized file");
        let initial_mode = fs::metadata(directory.path().join("scoped/allowed.txt"))
            .expect("test backing metadata must be readable")
            .permissions()
            .mode();

        assert_eq!(
            filesystem.set_metadata(
                allowed.node,
                MetadataUpdate::Permissions(MetadataPermissions::from_requested_mode(0o4750)),
            ),
            Err(AdapterError::AccessDenied)
        );
        assert_eq!(
            fs::metadata(directory.path().join("scoped/allowed.txt"))
                .expect("denied metadata update must leave backing metadata readable")
                .permissions()
                .mode(),
            initial_mode,
            "a denied SetMetadata request must not reach fchmod"
        );

        let (directory, filesystem, kernel, capability) = test_filesystem_with_effects(
            PathPattern::Prefix(path(&["scoped"])),
            FileEffects::only(FileEffect::SetMetadata),
        );
        let scoped = filesystem
            .lookup_entry(NodeId::ROOT, "scoped")
            .expect("metadata visibility must expose the authorized parent");
        let allowed = filesystem
            .lookup_entry(scoped.node, "allowed.txt")
            .expect("metadata visibility must expose the authorized file");
        filesystem
            .set_metadata(
                allowed.node,
                MetadataUpdate::Permissions(MetadataPermissions::from_requested_mode(0o4750)),
            )
            .expect("SetMetadata must authorize an ordinary permission update");
        assert_eq!(
            fs::metadata(directory.path().join("scoped/allowed.txt"))
                .expect("updated backing metadata must remain readable")
                .permissions()
                .mode()
                & 0o7777,
            0o750,
            "set-ID bits must be removed before fchmod"
        );

        let timestamp = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        filesystem
            .set_metadata(
                allowed.node,
                MetadataUpdate::Timestamps(
                    MetadataTimes::new(None, Some(MetadataTime::Exact(timestamp)))
                        .expect("a timestamp update must be non-empty"),
                ),
            )
            .expect("SetMetadata must authorize an exact mtime update");
        let object = filesystem
            .nodes
            .resolve(allowed.node)
            .expect("live node must resolve to its namespace object");
        let metadata = filesystem
            .namespace
            .with_object(&object, |object| {
                filesystem.backing.runtime_metadata(object)
            })
            .expect("updated namespace metadata must remain valid");
        assert_eq!(metadata.mtime, timestamp);

        kernel
            .revoke_held_by(&SubjectId::new("subject"), &capability)
            .expect("test capability must be revocable");
        assert_eq!(
            filesystem.set_metadata(
                allowed.node,
                MetadataUpdate::Permissions(MetadataPermissions::from_requested_mode(0o600)),
            ),
            Err(AdapterError::AccessDenied)
        );
        assert_eq!(
            fs::metadata(directory.path().join("scoped/allowed.txt"))
                .expect("revoked metadata update must leave backing metadata readable")
                .permissions()
                .mode()
                & 0o777,
            0o750
        );
    }

    #[test]
    fn setattr_accepts_one_effectful_dimension_per_request() {
        assert!(matches!(
            supported_setattr_mutation(Some(0), None, None, None),
            Ok(SetattrMutation::Truncate(0))
        ));
        assert!(matches!(
            supported_setattr_mutation(None, Some(0o4755), None, None),
            Ok(SetattrMutation::Metadata(MetadataUpdate::Permissions(_)))
        ));
        assert!(matches!(
            supported_setattr_mutation(None, None, Some(TimeOrNow::Now), None),
            Ok(SetattrMutation::Metadata(MetadataUpdate::Timestamps(_)))
        ));
        assert_eq!(
            supported_setattr_mutation(Some(0), Some(0o600), None, None),
            Err(AdapterError::Unsupported),
            "truncate and chmod have distinct linearization points"
        );
        assert_eq!(
            supported_setattr_mutation(None, Some(0o600), Some(TimeOrNow::Now), None),
            Err(AdapterError::Unsupported),
            "chmod and timestamp changes cannot be represented as one atomic request"
        );
    }

    #[test]
    fn directory_listing_uses_capability_visibility_and_offset_cookies() {
        let (_directory, filesystem, kernel, _capability) = test_filesystem();
        assert_eq!(
            filesystem.open_directory(NodeId::ROOT, OpenFlags(0)),
            Err(AdapterError::AccessDenied),
            "an ancestor's metadata visibility must not imply ListDirectory"
        );
        let scoped = filesystem
            .lookup_entry(NodeId::ROOT, "scoped")
            .expect("authorized directory must resolve");
        let handle = filesystem
            .open_directory(scoped.node, OpenFlags(0))
            .expect("authorized directory must open");
        let object = filesystem
            .nodes
            .resolve(scoped.node)
            .expect("opened directory node must stay bound");
        assert_eq!(kernel.object_open_handle_count(&object), Ok(1));

        let entries = filesystem
            .read_directory(scoped.node, handle, 0)
            .expect("authorized directory listing must succeed");
        assert_eq!(
            entries
                .iter()
                .map(|entry| (entry.name.as_str(), entry.next_offset))
                .collect::<Vec<_>>(),
            [(".", 1), ("..", 2), ("allowed.txt", 3)]
        );
        assert_eq!(
            filesystem
                .read_directory(scoped.node, handle, 2)
                .expect("a returned offset must resume after its entry"),
            entries[2..]
        );
        assert_eq!(
            filesystem
                .read_directory(scoped.node, handle, 3)
                .expect("the final offset must report end of stream"),
            []
        );
        assert_eq!(
            filesystem.read_directory(scoped.node, handle, 4),
            Err(AdapterError::InvalidRequest)
        );

        filesystem
            .release_directory(scoped.node, handle)
            .expect("directory release must close both handle registries");
        assert_eq!(kernel.object_open_handle_count(&object), Ok(0));
        assert_eq!(
            filesystem
                .namespace
                .object_snapshot(&object)
                .map(|value| value.map(|record| record.open_handle_count())),
            Ok(Some(0))
        );
    }

    // Requirement: a directory handle never applies an old cookie to a
    // changed namespace. Category: FUSE/readdir. Risk: high.
    #[test]
    fn directory_listing_requires_restart_after_namespace_mutation() {
        let (_directory, filesystem, _kernel, _capability) = test_filesystem_with_effects(
            PathPattern::Prefix(path(&["scoped"])),
            FileEffects::from_effects([
                FileEffect::ListDirectory,
                FileEffect::CreateFile,
                FileEffect::WriteData,
            ]),
        );
        let scoped = filesystem
            .lookup_entry(NodeId::ROOT, "scoped")
            .expect("directory authority must expose the test directory");
        let directory_handle = filesystem
            .open_directory(scoped.node, OpenFlags(0))
            .expect("ListDirectory must open the initial stream");
        assert!(
            filesystem
                .read_directory(scoped.node, directory_handle, 0)
                .is_ok(),
            "the generation captured at open must list the initial namespace"
        );

        let created = filesystem
            .create_file(
                scoped.node,
                "later.txt",
                0o600,
                0,
                create_flags(OFlags::WRONLY),
            )
            .expect("a capability-authorized creation must advance the namespace generation");
        filesystem
            .release_file(created.node, created.handle)
            .expect("the test creation handle must release normally");
        assert_eq!(
            filesystem.read_directory(scoped.node, directory_handle, 2),
            Err(AdapterError::TryAgain),
            "the caller must restart after the namespace changed"
        );
        filesystem
            .release_directory(scoped.node, directory_handle)
            .expect("a stale directory handle must still release normally");
    }

    #[test]
    fn every_directory_read_reauthorizes_an_existing_handle() {
        let (_directory, filesystem, kernel, capability) = test_filesystem();
        let scoped = filesystem
            .lookup_entry(NodeId::ROOT, "scoped")
            .expect("authorized directory must resolve");
        let handle = filesystem
            .open_directory(scoped.node, OpenFlags(0))
            .expect("initial authorized directory open must succeed");

        assert!(filesystem.read_directory(scoped.node, handle, 0).is_ok());
        kernel
            .revoke_held_by(&SubjectId::new("subject"), &capability)
            .expect("test capability must be revocable");
        assert_eq!(
            filesystem.read_directory(scoped.node, handle, 0),
            Err(AdapterError::AccessDenied)
        );
        filesystem
            .release_directory(scoped.node, handle)
            .expect("revocation must not prevent directory release");
    }

    #[test]
    fn directory_listing_filters_children_outside_exact_visibility() {
        let (_directory, filesystem, _kernel, _capability) =
            test_filesystem_with_pattern(PathPattern::Exact(path(&["scoped"])));
        let scoped = filesystem
            .lookup_entry(NodeId::ROOT, "scoped")
            .expect("exactly authorized directory must resolve");
        let handle = filesystem
            .open_directory(scoped.node, OpenFlags(0))
            .expect("exact ListDirectory authority must open its directory");

        assert_eq!(
            filesystem
                .read_directory(scoped.node, handle, 0)
                .expect("directory listing must apply entry visibility")
                .into_iter()
                .map(|entry| entry.name)
                .collect::<Vec<_>>(),
            [".", ".."]
        );
        filesystem
            .release_directory(scoped.node, handle)
            .expect("exact directory handle must release");
    }

    #[test]
    fn every_read_reauthorizes_an_existing_open_handle() {
        let (_directory, filesystem, kernel, capability) = test_filesystem();
        let scoped = filesystem
            .lookup_entry(NodeId::ROOT, "scoped")
            .expect("authorized directory must resolve");
        let allowed = filesystem
            .lookup_entry(scoped.node, "allowed.txt")
            .expect("authorized file must resolve");
        let handle = filesystem
            .open_file(allowed.node, OpenFlags(0))
            .expect("initial authorized open must succeed");

        assert_eq!(
            filesystem
                .read_file(allowed.node, handle, 0, 10)
                .expect("read before revoke must succeed"),
            b"capability"
        );
        kernel
            .revoke_held_by(&SubjectId::new("subject"), &capability)
            .expect("test capability must be revocable");
        assert_eq!(
            filesystem.read_file(allowed.node, handle, 0, 10),
            Err(AdapterError::AccessDenied)
        );
        filesystem
            .release_file(allowed.node, handle)
            .expect("revocation must not prevent resource release");
    }

    #[test]
    fn malformed_forget_fails_the_mount_closed() {
        let (_directory, filesystem, _kernel, _capability) = test_filesystem();

        filesystem.forget_node(NodeId::ROOT, 0);

        assert!(matches!(
            filesystem.getattr_entry(NodeId::ROOT, None),
            Err(AdapterError::Internal)
        ));
    }

    #[test]
    fn constructor_rejects_a_repository_identity_mismatch() {
        let directory = tempdir().expect("temporary repository must be creatable");
        let imported = ImportedRepository::open(
            RepoId::new("imported-repository"),
            directory.path(),
            PreflightLimits::new(NonZeroUsize::new(4).expect("limit must be non-zero"), 1),
        )
        .expect("empty repository must pass preflight");
        let kernel = Arc::new(CapabilityKernel::new(CapabilityState::new(IssuerId::new(
            "issuer",
        ))));
        let error = CapabilityFilesystem::new(
            imported,
            kernel,
            MountAuthority::new(
                MountInstanceId::new("mismatched-mount"),
                SubjectId::new("subject"),
                authority_core::capability::CapId::new("capability"),
                RepoId::new("authority-repository"),
            ),
            Arc::new(MonotonicTime::from_ticks(0)),
        )
        .expect_err("a capability must not be paired with a different backing repository");

        assert_eq!(
            error,
            CapabilityFilesystemError::RepositoryMismatch {
                imported: RepoId::new("imported-repository"),
                authority: RepoId::new("authority-repository"),
            }
        );
    }
}
