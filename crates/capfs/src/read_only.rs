//! Direct-I/O FUSE adapter with per-operation capability reauthorization.

use std::{
    collections::BTreeMap,
    error::Error,
    ffi::OsStr,
    fmt, io,
    num::NonZeroU64,
    path::Path,
    sync::{
        Arc, Mutex,
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
    kernel::{CapabilityInspectionError, CapabilityKernel, EffectCommitError},
    path::{CanonicalPath, path_matches},
    repository::RepoId,
    state::HandleCloseStatus,
    time::MonotonicTime,
};
use fuser::{
    BackgroundSession, BsdFileFlags, Config, Errno, FileAttr, FileHandle, FileType, Filesystem,
    FopenFlags, Generation, INodeNo, KernelConfig, LockOwner, MountOption, OpenAccMode, OpenFlags,
    RenameFlags as FuseRenameFlags, ReplyAttr, ReplyCreate, ReplyData, ReplyDirectory, ReplyEmpty,
    ReplyEntry, ReplyOpen, ReplyWrite, Request, SessionACL, TimeOrNow, WriteFlags,
};
use rustix::fs::OFlags;

use crate::{
    backing::{ImportedRepository, ValidatedRepository},
    namespace::{
        NamespaceError, NamespaceObject, NamespaceObjectKind, NamespaceOperationError,
        NamespaceRegistry, RenamePlan,
    },
    node::{ForgetOutcome, NodeId, NodeTable, NodeTableError},
    runtime::{
        BackingMetadata, CreationPermissions, MetadataPermissions, MetadataTime, MetadataTimes,
        OpenedBackingFile,
    },
};

const ATTRIBUTE_TTL: Duration = Duration::ZERO;
const NODE_GENERATION: Generation = Generation(0);
const MAX_IO_SIZE: u32 = 1024 * 1024;

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
    Directory,
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
            Self::Directory => OpenResourceKind::Directory,
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
    InvalidRequest,
    BadHandle,
    Internal,
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
            Self::InvalidRequest => Errno::EINVAL,
            Self::BadHandle => Errno::EBADF,
            Self::Internal => Errno::EIO,
        }
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
    nodes: NodeTable,
    kernel: Arc<CapabilityKernel>,
    authority: MountAuthority,
    clock: Arc<dyn AuthorizationClock>,
    handles: Mutex<HandleState>,
    fatal: AtomicBool,
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
        let nodes = NodeTable::new(authority.subject.clone(), root.id().clone());

        Ok(Self {
            backing,
            namespace,
            nodes,
            kernel,
            authority,
            clock,
            handles: Mutex::new(HandleState::new()),
            fatal: AtomicBool::new(false),
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
                let handles = self.handles.lock().map_err(|_| AdapterError::Internal)?;
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
                    if !self.capability_may_observe(capability, object.path()) {
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

    fn capability_may_observe(&self, capability: &Capability, path: &CanonicalPath) -> bool {
        let AuthorityBody::File(authority) = capability.authority();
        authority.repository() == &self.authority.repository
            && !authority.effects().is_empty()
            && (path_matches(authority.path(), path)
                || authority.path().path().is_at_or_below(path))
    }

    fn open_file(&self, node: NodeId, flags: OpenFlags) -> Result<u64, AdapterError> {
        let intent = FileOpenIntent::from_open_flags(flags)?;
        self.open_resource(
            node,
            NamespaceObjectKind::RegularFile,
            AdapterError::IsDirectory,
            OpenResourceAccess::File(intent.access),
            |path| self.file_open_requests(intent, path.clone()),
            |object| {
                let open = if intent.needs_writable_backing() {
                    self.backing.open_runtime_writable_file(object)
                } else {
                    self.backing.open_runtime_file(object)
                };
                let file = open.map_err(|_| AdapterError::Internal)?;
                if intent.truncate {
                    file.truncate_to(0).map_err(|_| AdapterError::Internal)?;
                }
                Ok(OpenBacking::File(file))
            },
        )
    }

    fn open_directory(&self, node: NodeId, flags: OpenFlags) -> Result<u64, AdapterError> {
        let raw_flags = supported_open_flags(flags)?;
        if flags.acc_mode() != OpenAccMode::O_RDONLY || raw_flags.contains(OFlags::TRUNC) {
            return Err(AdapterError::Unsupported);
        }
        self.open_resource(
            node,
            NamespaceObjectKind::Directory,
            AdapterError::NotDirectory,
            OpenResourceAccess::Directory,
            |path| {
                CapabilityRequestSet::one(
                    self.file_request(FileEffect::ListDirectory, path.clone()),
                )
            },
            |_| Ok(OpenBacking::Directory),
        )
    }

    fn open_resource(
        &self,
        node: NodeId,
        expected_kind: NamespaceObjectKind,
        kind_error: AdapterError,
        access: OpenResourceAccess,
        authorization_requests: impl FnOnce(&CanonicalPath) -> CapabilityRequestSet,
        open_backing: impl FnOnce(&NamespaceObject) -> Result<OpenBacking, AdapterError>,
    ) -> Result<u64, AdapterError> {
        self.ensure_healthy()?;
        let object = self
            .nodes
            .resolve(node)
            .map_err(|error| map_node_lookup_error(&error))?;
        let mut handles = self.handles.lock().map_err(|_| AdapterError::Internal)?;
        let sequence = handles.reserve()?;
        let authority_handle =
            HandleId::new(format!("{}:fuse-handle:{sequence}", self.authority.mount));
        let opened = self.namespace.open_object(&object, |object| {
            if object.kind() != expected_kind {
                return Err(kind_error);
            }
            self.kernel
                .register_open_handle(OpenHandle::new(
                    authority_handle.clone(),
                    self.authority.subject.clone(),
                    object.id().clone(),
                ))
                .map_err(|_| AdapterError::Internal)?;

            let requests = authorization_requests(object.path());
            match self.kernel.authorize_all_and_commit(
                &self.authority.subject,
                &self.authority.capability,
                &requests,
                |_| open_backing(object),
            ) {
                Ok(backing) => Ok(backing),
                Err(error) => {
                    self.close_failed_authority_handle(&authority_handle)?;
                    Err(map_effect_error(&error))
                }
            }
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
        let mut handles = self.handles.lock().map_err(|_| AdapterError::Internal)?;
        let sequence = handles.reserve()?;
        let authority_handle =
            HandleId::new(format!("{}:fuse-handle:{sequence}", self.authority.mount));
        let created = self.namespace.create_open_child(
            &parent,
            name,
            NamespaceObjectKind::RegularFile,
            |live_parent, child| {
                self.kernel
                    .register_open_handle(OpenHandle::new(
                        authority_handle.clone(),
                        self.authority.subject.clone(),
                        child.id().clone(),
                    ))
                    .map_err(|_| AdapterError::Internal)?;

                let requests = self.file_creation_requests(
                    FileEffect::CreateFile,
                    intent,
                    child.path().clone(),
                );
                match self.kernel.authorize_all_and_commit(
                    &self.authority.subject,
                    &self.authority.capability,
                    &requests,
                    |_| {
                        // Allocate the LOOKUP reference before touching the
                        // backing file. If allocation fails, no file is created;
                        // if backing creation fails, the reference is removed
                        // before the namespace transaction rolls back.
                        let binding = self
                            .nodes
                            .remember_lookup(child.id())
                            .map_err(|_| AdapterError::Internal)?;
                        let node = binding.node();
                        if let Ok((backing, metadata)) =
                            self.backing
                                .create_runtime_file(live_parent, child, permissions)
                        {
                            Ok((node, backing, metadata))
                        } else {
                            self.forget_created_lookup(node, child.id())?;
                            Err(AdapterError::Internal)
                        }
                    },
                ) {
                    Ok(created) => Ok(created),
                    Err(error) => {
                        self.close_failed_authority_handle(&authority_handle)?;
                        Err(map_effect_error(&error))
                    }
                }
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
        let created = self.namespace.create_child(
            &parent,
            name,
            NamespaceObjectKind::Directory,
            |live_parent, child| {
                let request = self.file_request(FileEffect::CreateDirectory, child.path().clone());
                self.kernel
                    .authorize_and_commit(
                        &self.authority.subject,
                        &self.authority.capability,
                        &request,
                        |_| {
                            let binding = self
                                .nodes
                                .remember_lookup(child.id())
                                .map_err(|_| AdapterError::Internal)?;
                            let node = binding.node();
                            if let Ok(metadata) = self.backing.create_runtime_directory(
                                live_parent,
                                child,
                                permissions,
                            ) {
                                Ok(Entry { node, metadata })
                            } else {
                                self.forget_created_lookup(node, child.id())?;
                                Err(AdapterError::Internal)
                            }
                        },
                    )
                    .map_err(|error| map_effect_error(&error))
            },
        );
        created
            .map(|creation| creation.into_parts().1)
            .map_err(|error| map_namespace_operation_error(&error))
    }

    fn remove_file(&self, parent: NodeId, name: &str) -> Result<(), AdapterError> {
        self.remove_child(
            parent,
            name,
            NamespaceObjectKind::RegularFile,
            AdapterError::IsDirectory,
            FileEffect::RemoveFile,
        )
    }

    fn remove_directory(&self, parent: NodeId, name: &str) -> Result<(), AdapterError> {
        self.remove_child(
            parent,
            name,
            NamespaceObjectKind::Directory,
            AdapterError::NotDirectory,
            FileEffect::RemoveDirectory,
        )
    }

    fn remove_child(
        &self,
        parent: NodeId,
        name: &str,
        expected_kind: NamespaceObjectKind,
        kind_error: AdapterError,
        effect: FileEffect,
    ) -> Result<(), AdapterError> {
        self.ensure_healthy()?;
        let parent = self
            .nodes
            .resolve(parent)
            .map_err(|error| map_node_lookup_error(&error))?;
        self.namespace
            .remove_child(&parent, name, |live_parent, child| {
                if child.kind() != expected_kind {
                    return Err(kind_error);
                }
                let request = self.file_request(effect, child.path().clone());
                self.kernel
                    .authorize_and_commit(
                        &self.authority.subject,
                        &self.authority.capability,
                        &request,
                        |_| {
                            self.backing
                                .remove_runtime_object(live_parent, child)
                                .map_err(|_| AdapterError::Internal)
                        },
                    )
                    .map_err(|error| map_effect_error(&error))
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
            .rename_child(
                &source_parent,
                source_name,
                &destination_parent,
                destination_name,
                |plan| {
                    let requests = self.rename_requests(plan)?;
                    self.kernel
                        .authorize_all_and_commit(
                            &self.authority.subject,
                            &self.authority.capability,
                            &requests,
                            |_| {
                                self.backing
                                    .rename_runtime_subtree(plan)
                                    .map_err(|_| AdapterError::Internal)
                            },
                        )
                        .map_err(|error| map_effect_error(&error))
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
        let handles = self.handles.lock().map_err(|_| AdapterError::Internal)?;
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
                let request = self.file_request(FileEffect::ReadData, object.path().clone());
                self.kernel
                    .authorize_and_commit(
                        &self.authority.subject,
                        &self.authority.capability,
                        &request,
                        |_| {
                            backing
                                .read_at(offset, size as usize)
                                .map_err(|_| AdapterError::Internal)
                        },
                    )
                    .map_err(|error| map_effect_error(&error))
            })
            .map_err(|error| map_namespace_operation_error(&error))
    }

    fn write_file(
        &self,
        node: NodeId,
        handle: u64,
        offset: u64,
        bytes: &[u8],
    ) -> Result<u32, AdapterError> {
        self.ensure_healthy()?;
        if bytes.len() > MAX_IO_SIZE as usize {
            return Err(AdapterError::InvalidRequest);
        }
        let handles = self.handles.lock().map_err(|_| AdapterError::Internal)?;
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
            .with_object(&resource.object, |object| {
                let request = self.file_request(FileEffect::WriteData, object.path().clone());
                self.kernel
                    .authorize_and_commit(
                        &self.authority.subject,
                        &self.authority.capability,
                        &request,
                        |_| {
                            backing
                                .write_at(offset, bytes)
                                .map_err(|_| AdapterError::Internal)
                                .and_then(|written| {
                                    u32::try_from(written).map_err(|_| AdapterError::Internal)
                                })
                        },
                    )
                    .map_err(|error| map_effect_error(&error))
            })
            .map_err(|error| map_namespace_operation_error(&error))
    }

    fn truncate_file(
        &self,
        node: NodeId,
        handle: Option<u64>,
        length: u64,
    ) -> Result<BackingMetadata, AdapterError> {
        self.ensure_healthy()?;
        if let Some(handle) = handle {
            let handles = self.handles.lock().map_err(|_| AdapterError::Internal)?;
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
                backing
                    .truncate_to(length)
                    .map_err(|_| AdapterError::Internal)?;
                self.backing
                    .runtime_metadata(object)
                    .map_err(|_| AdapterError::Internal)
            })
        } else {
            let object = self
                .nodes
                .resolve(node)
                .map_err(|error| map_node_lookup_error(&error))?;
            self.with_authorized_truncate(&object, |object| {
                let backing = self
                    .backing
                    .open_runtime_writable_file(object)
                    .map_err(|_| AdapterError::Internal)?;
                backing
                    .truncate_to(length)
                    .map_err(|_| AdapterError::Internal)?;
                self.backing
                    .runtime_metadata(object)
                    .map_err(|_| AdapterError::Internal)
            })
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
            .with_object(&object, |object| {
                let request = self.file_request(FileEffect::SetMetadata, object.path().clone());
                self.kernel
                    .authorize_and_commit(
                        &self.authority.subject,
                        &self.authority.capability,
                        &request,
                        |_| match update {
                            MetadataUpdate::Permissions(permissions) => self
                                .backing
                                .set_runtime_permissions(object, permissions)
                                .map_err(|_| AdapterError::Internal),
                            MetadataUpdate::Timestamps(timestamps) => self
                                .backing
                                .set_runtime_timestamps(object, timestamps)
                                .map_err(|_| AdapterError::Internal),
                        },
                    )
                    .map_err(|error| map_effect_error(&error))
            })
            .map_err(|error| map_namespace_operation_error(&error))
    }

    fn with_authorized_truncate<T>(
        &self,
        object: &ObjectId,
        operation: impl FnOnce(&NamespaceObject) -> Result<T, AdapterError>,
    ) -> Result<T, AdapterError> {
        self.namespace
            .with_object(object, |object| {
                if object.kind() != NamespaceObjectKind::RegularFile {
                    return Err(AdapterError::IsDirectory);
                }
                let request = self.file_request(FileEffect::Truncate, object.path().clone());
                self.kernel
                    .authorize_and_commit(
                        &self.authority.subject,
                        &self.authority.capability,
                        &request,
                        |_| operation(object),
                    )
                    .map_err(|error| map_effect_error(&error))
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
        let handles = self.handles.lock().map_err(|_| AdapterError::Internal)?;
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

        self.namespace
            .with_directory_children(&resource.object, |directory, parent, children| {
                let request =
                    self.file_request(FileEffect::ListDirectory, directory.path().clone());
                self.kernel
                    .authorize_and_commit(
                        &self.authority.subject,
                        &self.authority.capability,
                        &request,
                        |capability| {
                            let mut entries = Vec::with_capacity(children.len() + 2);
                            entries.push((Some(node), NamespaceObjectKind::Directory, ".".into()));
                            entries.push((
                                self.nodes
                                    .node_for_object(parent.id())
                                    .map_err(|_| AdapterError::Internal)?,
                                NamespaceObjectKind::Directory,
                                "..".into(),
                            ));
                            for child in children {
                                if !self.capability_may_observe(capability, child.path()) {
                                    continue;
                                }
                                let name = child
                                    .path()
                                    .as_segments()
                                    .last()
                                    .cloned()
                                    .ok_or(AdapterError::Internal)?;
                                entries.push((
                                    self.nodes
                                        .node_for_object(child.id())
                                        .map_err(|_| AdapterError::Internal)?,
                                    child.kind(),
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
                        },
                    )
                    .map_err(|error| map_effect_error(&error))
            })
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
        let mut handles = self.handles.lock().map_err(|_| AdapterError::Internal)?;
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
        path: CanonicalPath,
    ) -> CapabilityRequestSet {
        let mut additional = Vec::with_capacity(2);
        let first = match intent.access {
            FileAccess::ReadOnly => self.file_request(FileEffect::ReadData, path.clone()),
            FileAccess::WriteOnly => self.file_request(FileEffect::WriteData, path.clone()),
            FileAccess::ReadWrite => {
                additional.push(self.file_request(FileEffect::WriteData, path.clone()));
                self.file_request(FileEffect::ReadData, path.clone())
            }
        };
        if intent.truncate {
            additional.push(self.file_request(FileEffect::Truncate, path));
        }
        CapabilityRequestSet::new(first, additional)
    }

    fn file_creation_requests(
        &self,
        creation_effect: FileEffect,
        intent: FileOpenIntent,
        path: CanonicalPath,
    ) -> CapabilityRequestSet {
        let mut additional = Vec::with_capacity(2);
        match intent.access {
            FileAccess::ReadOnly => {
                additional.push(self.file_request(FileEffect::ReadData, path.clone()));
            }
            FileAccess::WriteOnly => {
                additional.push(self.file_request(FileEffect::WriteData, path.clone()));
            }
            FileAccess::ReadWrite => {
                additional.push(self.file_request(FileEffect::ReadData, path.clone()));
                additional.push(self.file_request(FileEffect::WriteData, path.clone()));
            }
        }
        CapabilityRequestSet::new(self.file_request(creation_effect, path), additional)
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
        let Ok(mut handles) = self.handles.lock() else {
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
            let closed = self.namespace.close_object(&object, |_| {
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
            Err(AdapterError::Internal)
        } else {
            Ok(())
        }
    }

    fn mark_fatal(&self) {
        self.fatal.store(true, Ordering::Release);
    }
}

impl Filesystem for CapabilityFilesystem {
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

        let mutation = match supported_setattr_mutation(size, mode, atime, mtime) {
            Ok(SetattrMutation::Truncate(size)) => self
                .truncate_file(node, handle.map(|value| value.0), size)
                .map(|_| ()),
            Ok(SetattrMutation::Metadata(update)) => self.set_metadata(node, update),
            Err(error) => Err(error),
        };

        match mutation.and_then(|()| self.getattr_entry(node, None)) {
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
                FopenFlags::FOPEN_DIRECT_IO | FopenFlags::FOPEN_NOFLUSH,
            ),
            Err(error) => reply.error(error.errno()),
        }
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
            Ok(handle) => reply.opened(
                FileHandle(handle),
                FopenFlags::FOPEN_DIRECT_IO | FopenFlags::FOPEN_NOFLUSH,
            ),
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
        if write_flags
            .intersects(WriteFlags::FUSE_WRITE_CACHE | WriteFlags::FUSE_WRITE_KILL_SUIDGID)
        {
            reply.error(Errno::EPERM);
            return;
        }
        match self.write_file(node, handle.0, offset, data) {
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

/// Returns the hardened direct-I/O mount configuration for [`CapabilityFilesystem`].
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
    config.n_threads = Some(1);
    config.clone_fd = false;
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
    fuser::spawn_mount(filesystem, mountpoint, &mount_config())
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
        NamespaceOperationError::Namespace(NamespaceError::DestinationInsideSource) => {
            AdapterError::InvalidRequest
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
        EffectCommitError::LockPoisoned | EffectCommitError::Audit(_) => AdapterError::Internal,
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        num::NonZeroUsize,
        os::unix::fs::PermissionsExt,
        sync::Arc,
        time::{Duration, UNIX_EPOCH},
    };

    use authority_core::{
        capability::{AuthorityBody, AuthorityRequest, IssuerId, SubjectId},
        file::{FileAuthority, FileEffect, FileEffects},
        kernel::CapabilityKernel,
        path::{CanonicalPath, PathPattern},
        repository::RepoId,
        state::{CapabilityGrant, CapabilityState, StaticAuthorityEnvelope, Subject},
        time::{MonotonicTime, TimeWindow},
    };
    use fuser::{OpenFlags, RenameFlags, TimeOrNow};
    use rustix::fs::OFlags;
    use tempfile::{TempDir, tempdir};

    use super::{
        AdapterError, CapabilityFilesystem, CapabilityFilesystemError, MetadataUpdate,
        MountAuthority, MountInstanceId, NodeId, SetattrMutation, supported_setattr_mutation,
    };
    use crate::{
        backing::{ImportedRepository, PreflightLimits},
        namespace::NamespaceObjectKind,
        runtime::{MetadataPermissions, MetadataTime, MetadataTimes},
    };

    fn path(segments: &[&str]) -> CanonicalPath {
        CanonicalPath::new(segments).expect("test path must be canonical")
    }

    fn open_flags(flags: OFlags) -> OpenFlags {
        OpenFlags(i32::try_from(flags.bits()).expect("test open flags must fit i32"))
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
            .revoke(&capability)
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
            .revoke(&capability)
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
            .revoke(&capability)
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
            .revoke(&capability)
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
            .revoke(&capability)
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
