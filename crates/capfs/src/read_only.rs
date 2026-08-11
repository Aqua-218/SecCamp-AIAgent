//! Read-only FUSE adapter with per-operation capability reauthorization.

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
    time::{Duration, UNIX_EPOCH},
};

use authority_core::{
    capability::{
        AuthorityBody, AuthorityRequest, CapId, Capability, CapabilityRequest, SubjectId,
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
    BackgroundSession, Config, Errno, FileAttr, FileHandle, FileType, Filesystem, FopenFlags,
    Generation, INodeNo, KernelConfig, LockOwner, MountOption, OpenAccMode, OpenFlags, ReplyAttr,
    ReplyData, ReplyEmpty, ReplyEntry, ReplyOpen, Request, SessionACL,
};
use rustix::fs::OFlags;

use crate::{
    backing::{ImportedRepository, ValidatedRepository},
    namespace::{
        NamespaceError, NamespaceObject, NamespaceObjectKind, NamespaceOperationError,
        NamespaceRegistry,
    },
    node::{NodeId, NodeTable, NodeTableError},
    runtime::{BackingMetadata, OpenedBackingFile},
};

const ATTRIBUTE_TTL: Duration = Duration::ZERO;
const NODE_GENERATION: Generation = Generation(0);
const MAX_READ_SIZE: u32 = 1024 * 1024;

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

/// Failure to construct a read-only filesystem from imported state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReadOnlyFilesystemError {
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

impl fmt::Display for ReadOnlyFilesystemError {
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

impl Error for ReadOnlyFilesystemError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Namespace(error) => Some(error),
            Self::MissingNamespaceRoot | Self::RepositoryMismatch { .. } => None,
        }
    }
}

impl From<NamespaceError> for ReadOnlyFilesystemError {
    fn from(error: NamespaceError) -> Self {
        Self::Namespace(error)
    }
}

#[derive(Debug)]
struct OpenFile {
    node: NodeId,
    object: ObjectId,
    authority_handle: HandleId,
    backing: OpenedBackingFile,
}

#[derive(Debug)]
struct HandleState {
    next_sequence: Option<u64>,
    files: BTreeMap<u64, OpenFile>,
}

impl HandleState {
    const fn new() -> Self {
        Self {
            next_sequence: Some(1),
            files: BTreeMap::new(),
        }
    }

    fn reserve(&mut self) -> Result<u64, AdapterError> {
        let sequence = self.next_sequence.take().ok_or(AdapterError::Internal)?;
        self.next_sequence = sequence.checked_add(1);
        if self.files.contains_key(&sequence) {
            return Err(AdapterError::Internal);
        }
        Ok(sequence)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AdapterError {
    NotFound,
    AccessDenied,
    ReadOnly,
    IsDirectory,
    InvalidRequest,
    BadHandle,
    Internal,
}

impl AdapterError {
    const fn errno(self) -> Errno {
        match self {
            Self::NotFound => Errno::ENOENT,
            Self::AccessDenied => Errno::EACCES,
            Self::ReadOnly => Errno::EROFS,
            Self::IsDirectory => Errno::EISDIR,
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

/// A subject-local, read-only FUSE view of one validated repository.
///
/// Metadata is visible only for the presented capability's path range and its
/// ancestors. `OPEN` and every `READ` perform final effect authorization while
/// the namespace path remains stable. Successful opens use direct I/O so the
/// kernel page cache cannot bypass a later revocation check.
pub struct ReadOnlyFilesystem {
    backing: ValidatedRepository,
    namespace: NamespaceRegistry,
    nodes: NodeTable,
    kernel: Arc<CapabilityKernel>,
    authority: MountAuthority,
    clock: Arc<dyn AuthorizationClock>,
    handles: Mutex<HandleState>,
    fatal: AtomicBool,
}

impl fmt::Debug for ReadOnlyFilesystem {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReadOnlyFilesystem")
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

impl ReadOnlyFilesystem {
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
    ) -> Result<Self, ReadOnlyFilesystemError> {
        if imported.repository() != &authority.repository {
            return Err(ReadOnlyFilesystemError::RepositoryMismatch {
                imported: imported.repository().clone(),
                authority: authority.repository.clone(),
            });
        }
        let (_repository, backing, namespace) = imported.into_parts();
        let root = namespace
            .object_at_path_snapshot(&CanonicalPath::root())?
            .ok_or(ReadOnlyFilesystemError::MissingNamespaceRoot)?;
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
                let file = handles.files.get(&handle).ok_or(AdapterError::BadHandle)?;
                if file.node != node {
                    return Err(AdapterError::BadHandle);
                }
                file.object.clone()
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
        self.ensure_healthy()?;
        validate_open_flags(flags)?;
        let object = self
            .nodes
            .resolve(node)
            .map_err(|error| map_node_lookup_error(&error))?;
        let mut handles = self.handles.lock().map_err(|_| AdapterError::Internal)?;
        let sequence = handles.reserve()?;
        let authority_handle =
            HandleId::new(format!("{}:fuse-handle:{sequence}", self.authority.mount));
        let opened = self.namespace.open_object(&object, |object| {
            if object.kind() != NamespaceObjectKind::RegularFile {
                return Err(AdapterError::IsDirectory);
            }
            self.kernel
                .register_open_handle(OpenHandle::new(
                    authority_handle.clone(),
                    self.authority.subject.clone(),
                    object.id().clone(),
                ))
                .map_err(|_| AdapterError::Internal)?;

            let request = self.file_request(FileEffect::ReadData, object.path().clone());
            match self.kernel.authorize_and_commit(
                &self.authority.subject,
                &self.authority.capability,
                &request,
                |_| {
                    self.backing
                        .open_runtime_file(object)
                        .map_err(|_| AdapterError::Internal)
                },
            ) {
                Ok(backing) => Ok(backing),
                Err(error) => {
                    if self
                        .kernel
                        .close_handle(&self.authority.subject, &authority_handle)
                        != Ok(HandleCloseStatus::Closed)
                    {
                        self.mark_fatal();
                        return Err(AdapterError::Internal);
                    }
                    Err(map_effect_error(&error))
                }
            }
        });
        let backing = opened.map_err(|error| map_namespace_operation_error(&error))?;
        let replaced = handles.files.insert(
            sequence,
            OpenFile {
                node,
                object,
                authority_handle,
                backing,
            },
        );
        if replaced.is_some() {
            self.mark_fatal();
            return Err(AdapterError::Internal);
        }
        Ok(sequence)
    }

    fn read_file(
        &self,
        node: NodeId,
        handle: u64,
        offset: u64,
        size: u32,
    ) -> Result<Vec<u8>, AdapterError> {
        self.ensure_healthy()?;
        if size > MAX_READ_SIZE {
            return Err(AdapterError::InvalidRequest);
        }
        let handles = self.handles.lock().map_err(|_| AdapterError::Internal)?;
        let file = handles.files.get(&handle).ok_or(AdapterError::BadHandle)?;
        if file.node != node {
            return Err(AdapterError::BadHandle);
        }

        self.namespace
            .with_object(&file.object, |object| {
                let request = self.file_request(FileEffect::ReadData, object.path().clone());
                self.kernel
                    .authorize_and_commit(
                        &self.authority.subject,
                        &self.authority.capability,
                        &request,
                        |_| {
                            file.backing
                                .read_at(offset, size as usize)
                                .map_err(|_| AdapterError::Internal)
                        },
                    )
                    .map_err(|error| map_effect_error(&error))
            })
            .map_err(|error| map_namespace_operation_error(&error))
    }

    fn release_file(&self, node: NodeId, handle: u64) -> Result<(), AdapterError> {
        self.ensure_healthy()?;
        let mut handles = self.handles.lock().map_err(|_| AdapterError::Internal)?;
        let file = handles.files.get(&handle).ok_or(AdapterError::BadHandle)?;
        if file.node != node {
            return Err(AdapterError::BadHandle);
        }
        let object = file.object.clone();
        let authority_handle = file.authority_handle.clone();

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
        handles.files.remove(&handle).ok_or_else(|| {
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
            .files
            .iter()
            .map(|(handle, file)| (*handle, file.object.clone(), file.authority_handle.clone()))
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
                handles.files.remove(&handle);
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

impl Filesystem for ReadOnlyFilesystem {
    fn init(&mut self, _request: &Request, config: &mut KernelConfig) -> io::Result<()> {
        config
            .set_max_write(MAX_READ_SIZE)
            .map(|_| ())
            .map_err(|limit| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("FUSE kernel rejected {MAX_READ_SIZE}-byte request bound; maximum is {limit}"),
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
}

/// Returns the hardened mount configuration for [`ReadOnlyFilesystem`].
#[must_use]
pub fn mount_config() -> Config {
    let mut config = Config::default();
    config.mount_options = vec![
        MountOption::RO,
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

/// Mounts a read-only filesystem on a background session thread.
///
/// Dropping the returned session unmounts the filesystem.
///
/// # Errors
///
/// Returns an I/O error when the mount configuration, mountpoint, FUSE device,
/// or userspace mount helper rejects the session.
pub fn spawn_mount(
    filesystem: ReadOnlyFilesystem,
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
        kind: match metadata.kind {
            NamespaceObjectKind::Directory => FileType::Directory,
            NamespaceObjectKind::RegularFile => FileType::RegularFile,
        },
        perm: metadata.permissions,
        nlink: metadata.link_count,
        uid: metadata.uid,
        gid: metadata.gid,
        rdev: 0,
        blksize: metadata.block_size,
        flags: 0,
    }
}

fn validate_open_flags(flags: OpenFlags) -> Result<(), AdapterError> {
    if flags.acc_mode() != OpenAccMode::O_RDONLY {
        return Err(AdapterError::ReadOnly);
    }
    let raw = u32::try_from(flags.0).map_err(|_| AdapterError::InvalidRequest)?;
    let flags = OFlags::from_bits_retain(raw);
    if flags.intersects(
        OFlags::APPEND | OFlags::CREATE | OFlags::EXCL | OFlags::TRUNC | OFlags::TMPFILE,
    ) {
        return Err(AdapterError::ReadOnly);
    }
    Ok(())
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
            | NamespaceError::InvalidChildName(_)
            | NamespaceError::ParentNotDirectory(_),
        ) => AdapterError::NotFound,
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
    use std::{fs, num::NonZeroUsize, sync::Arc};

    use authority_core::{
        capability::{AuthorityBody, IssuerId, SubjectId},
        file::{FileAuthority, FileEffect, FileEffects},
        kernel::CapabilityKernel,
        path::{CanonicalPath, PathPattern},
        repository::RepoId,
        state::{CapabilityGrant, CapabilityState, StaticAuthorityEnvelope, Subject},
        time::{MonotonicTime, TimeWindow},
    };
    use fuser::OpenFlags;
    use tempfile::{TempDir, tempdir};

    use super::{
        AdapterError, MountAuthority, MountInstanceId, NodeId, ReadOnlyFilesystem,
        ReadOnlyFilesystemError,
    };
    use crate::{
        backing::{ImportedRepository, PreflightLimits},
        namespace::NamespaceObjectKind,
    };

    fn path(segments: &[&str]) -> CanonicalPath {
        CanonicalPath::new(segments).expect("test path must be canonical")
    }

    fn test_filesystem() -> (
        TempDir,
        ReadOnlyFilesystem,
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
                FileEffects::only(FileEffect::ReadData),
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
                    FileEffects::only(FileEffect::ReadData),
                    PathPattern::Prefix(path(&["scoped"])),
                )),
            ))
            .expect("test capability issuance must succeed");
        let authority = MountAuthority::new(
            MountInstanceId::new("test-mount"),
            subject,
            capability.clone(),
            repository,
        );
        let filesystem = ReadOnlyFilesystem::new(
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
            Err(AdapterError::ReadOnly)
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
        let error = ReadOnlyFilesystem::new(
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
            ReadOnlyFilesystemError::RepositoryMismatch {
                imported: RepoId::new("imported-repository"),
                authority: RepoId::new("authority-repository"),
            }
        );
    }
}
