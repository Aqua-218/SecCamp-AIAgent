//! Descriptor-relative runtime access to a validated backing repository.

use std::{
    collections::{HashMap, HashSet},
    error::Error,
    fmt, io,
    os::fd::AsFd,
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use authority_core::path::CanonicalPath;
use rustix::{
    fd::OwnedFd,
    fs::{
        AtFlags, FileType, Mode, OFlags, RenameFlags, ResolveFlags, Statx, StatxFlags,
        StatxTimestamp, Timespec, Timestamps, UTIME_NOW, UTIME_OMIT, fchmod, ftruncate, futimens,
        linkat, mkdirat, openat2, readlinkat, renameat_with, statx, symlinkat, unlinkat,
    },
    io::{fcntl_dupfd_cloexec, pread, pwrite},
};

use crate::{
    backing::ValidatedRepository,
    namespace::{NamespaceObject, NamespaceObjectKind, RenamePlan, SymlinkTarget},
};

const REQUIRED_METADATA: StatxFlags = StatxFlags::BASIC_STATS.union(StatxFlags::MNT_ID);

/// The link count passed for a directory, whose value carries no alias meaning.
///
/// Linux derives a directory's link count from its `.` and `..` entries, so it
/// can never indicate an alias. Directories are excluded from the link-count
/// comparison, and this constant documents the value's irrelevance at each
/// call site instead of leaving a bare number.
const DIRECTORY_LINK_COUNT_UNCHECKED: usize = 0;
const RESOLVE_WITHIN_ROOT: ResolveFlags = ResolveFlags::BENEATH
    .union(ResolveFlags::NO_MAGICLINKS)
    .union(ResolveFlags::NO_SYMLINKS)
    .union(ResolveFlags::NO_XDEV);

/// Permission bits applied to one newly-created backing object.
///
/// Creation never propagates set-ID or sticky bits. The adapter supplies the
/// FUSE request's mode and umask, and this type retains only the effective
/// owner/group/other permission bits. Applying them with `fchmod` makes the
/// result independent of the capfs process's own umask.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub(crate) struct CreationPermissions(Mode);

impl CreationPermissions {
    #[allow(dead_code)]
    pub(crate) fn from_requested_mode(requested_mode: u32, request_umask: u32) -> Self {
        Self(Mode::from_raw_mode(requested_mode & !request_umask & 0o777))
    }

    const fn mode(self) -> Mode {
        self.0
    }
}

/// Ordinary owner/group/other permission bits for a metadata update.
///
/// set-ID and sticky bits are deliberately stripped. Those bits can change
/// execution or deletion semantics and are outside the initial capfs metadata
/// policy even when a caller holds `SetMetadata`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub(crate) struct MetadataPermissions(Mode);

impl MetadataPermissions {
    #[allow(dead_code)]
    pub(crate) fn from_requested_mode(requested_mode: u32) -> Self {
        Self(Mode::from_raw_mode(requested_mode & 0o777))
    }

    const fn mode(self) -> Mode {
        self.0
    }
}

/// One timestamp value accepted by the supported metadata policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub(crate) enum MetadataTime {
    /// Ask the kernel to sample its current realtime clock.
    Now,
    /// Set one exact wall-clock value.
    Exact(SystemTime),
}

/// A non-empty atime/mtime update executed by one `futimens` syscall.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub(crate) struct MetadataTimes {
    access: Option<MetadataTime>,
    modification: Option<MetadataTime>,
}

impl MetadataTimes {
    #[allow(dead_code)]
    pub(crate) fn new(
        access: Option<MetadataTime>,
        modification: Option<MetadataTime>,
    ) -> Option<Self> {
        if access.is_none() && modification.is_none() {
            None
        } else {
            Some(Self {
                access,
                modification,
            })
        }
    }

    #[allow(dead_code)]
    fn to_rustix(self, path: &CanonicalPath) -> Result<Timestamps, RuntimeBackingError> {
        Ok(Timestamps {
            last_access: metadata_time_to_timespec(self.access, path)?,
            last_modification: metadata_time_to_timespec(self.modification, path)?,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct BackingMetadata {
    pub(crate) size: u64,
    pub(crate) blocks: u64,
    pub(crate) atime: SystemTime,
    pub(crate) mtime: SystemTime,
    pub(crate) ctime: SystemTime,
    pub(crate) kind: NamespaceObjectKind,
    pub(crate) permissions: u16,
    pub(crate) link_count: u32,
    pub(crate) uid: u32,
    pub(crate) gid: u32,
    pub(crate) block_size: u32,
}

/// A runtime backing operation rejected before protected data was returned.
#[derive(Debug)]
pub(crate) enum RuntimeBackingError {
    Io {
        operation: &'static str,
        path: PathBuf,
        source: io::Error,
    },
    RequiredMetadataUnavailable(CanonicalPath),
    ObjectKindChanged {
        path: CanonicalPath,
        expected: NamespaceObjectKind,
        actual: Option<NamespaceObjectKind>,
    },
    UnexpectedLinkCount {
        path: CanonicalPath,
        expected: usize,
        actual: u32,
    },
    SymlinkTargetChanged {
        path: CanonicalPath,
    },
    NonUtf8SymlinkTarget {
        path: CanonicalPath,
    },
    NestedMount(CanonicalPath),
    TimestampOutOfRange(CanonicalPath),
    #[allow(dead_code)]
    PathNotDirectChild {
        parent: CanonicalPath,
        child: CanonicalPath,
    },
    InvalidLinkPlan,
    LinkedDifferentInode {
        path: CanonicalPath,
    },
    #[allow(dead_code)]
    InvalidRenamePlan {
        source: CanonicalPath,
        destination: CanonicalPath,
        reason: &'static str,
    },
    #[allow(dead_code)]
    RenameIo {
        source: CanonicalPath,
        destination: CanonicalPath,
        cause: io::Error,
    },
}

impl fmt::Display for RuntimeBackingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io {
                operation,
                path,
                source,
            } => write!(
                formatter,
                "failed to {operation} backing path `{}`: {source}",
                path.display()
            ),
            Self::RequiredMetadataUnavailable(path) => write!(
                formatter,
                "required runtime metadata is unavailable for `{}`",
                DisplayCanonicalPath(path)
            ),
            Self::ObjectKindChanged {
                path,
                expected,
                actual,
            } => write!(
                formatter,
                "backing object `{}` changed kind from {expected:?} to {actual:?}",
                DisplayCanonicalPath(path)
            ),
            Self::UnexpectedLinkCount {
                path,
                expected,
                actual,
            } => write!(
                formatter,
                "backing object `{}` has {actual} names but the namespace records {expected}",
                DisplayCanonicalPath(path)
            ),
            Self::SymlinkTargetChanged { path } => write!(
                formatter,
                "backing symbolic link `{}` no longer has the target the namespace recorded",
                DisplayCanonicalPath(path)
            ),
            Self::NonUtf8SymlinkTarget { path } => write!(
                formatter,
                "backing symbolic link `{}` has a non-UTF-8 target",
                DisplayCanonicalPath(path)
            ),
            Self::NestedMount(path) => write!(
                formatter,
                "backing object `{}` crossed the repository mount boundary",
                DisplayCanonicalPath(path)
            ),
            Self::TimestampOutOfRange(path) => write!(
                formatter,
                "backing object `{}` has a timestamp outside SystemTime range",
                DisplayCanonicalPath(path)
            ),
            Self::PathNotDirectChild { parent, child } => write!(
                formatter,
                "backing path `{}` is not a direct child of `{}`",
                DisplayCanonicalPath(child),
                DisplayCanonicalPath(parent)
            ),
            Self::InvalidLinkPlan => {
                formatter.write_str("a hard link plan named an object with no existing name")
            }
            Self::LinkedDifferentInode { path } => write!(
                formatter,
                "backing hard link `{}` named a different inode than the validated source",
                DisplayCanonicalPath(path)
            ),
            Self::InvalidRenamePlan {
                source,
                destination,
                reason,
            } => write!(
                formatter,
                "invalid backing rename plan from `{}` to `{}`: {reason}",
                DisplayCanonicalPath(source),
                DisplayCanonicalPath(destination)
            ),
            Self::RenameIo {
                source,
                destination,
                cause,
            } => write!(
                formatter,
                "failed to rename backing path `{}` to `{}` without replacement: {cause}",
                DisplayCanonicalPath(source),
                DisplayCanonicalPath(destination)
            ),
        }
    }
}

impl Error for RuntimeBackingError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::RenameIo { cause, .. } => Some(cause),
            _ => None,
        }
    }
}

/// A regular-file descriptor opened beneath one validated repository root.
///
/// The descriptor is never opened with create, append, or truncate semantics.
/// Callers remain responsible for authorizing every read or write while they
/// hold the corresponding capability-kernel guard.
#[derive(Debug)]
pub(crate) struct OpenedBackingFile {
    fd: OwnedFd,
    path: CanonicalPath,
}

impl OpenedBackingFile {
    /// Reads at an explicit offset without changing descriptor state.
    pub(crate) fn read_at(
        &self,
        offset: u64,
        requested_size: usize,
    ) -> Result<Vec<u8>, RuntimeBackingError> {
        let mut bytes = vec![0_u8; requested_size];
        let count = pread(&self.fd, bytes.as_mut_slice(), offset)
            .map_err(|error| runtime_io_error("read", &self.path, error))?;
        bytes.truncate(count);
        Ok(bytes)
    }

    /// Writes at an explicit offset without append or implicit truncation.
    ///
    /// A successful call may report a short write. The caller must return that
    /// exact count and must not retry after dropping its authorization guard.
    pub(crate) fn write_at(&self, offset: u64, bytes: &[u8]) -> Result<usize, RuntimeBackingError> {
        pwrite(&self.fd, bytes, offset)
            .map_err(|error| runtime_io_error("write", &self.path, error))
    }

    /// Changes the file length without following a path or reopening the file.
    ///
    /// Callers must authorize this as an explicit `Truncate` effect. Ordinary
    /// positioned writes deliberately remain a `WriteData` effect, including
    /// when they extend the file past its previous end.
    pub(crate) fn truncate_to(&self, length: u64) -> Result<(), RuntimeBackingError> {
        ftruncate(&self.fd, length).map_err(|error| runtime_io_error("truncate", &self.path, error))
    }
}

#[derive(Debug, Clone, Copy)]
enum RuntimeFileAccess {
    ReadOnly,
    ReadWrite,
}

impl RuntimeFileAccess {
    const fn open_flags(self) -> OFlags {
        match self {
            Self::ReadOnly => OFlags::RDONLY,
            Self::ReadWrite => OFlags::RDWR,
        }
    }

    const fn operation(self) -> &'static str {
        match self {
            Self::ReadOnly => "open for reading",
            Self::ReadWrite => "open for reading and writing",
        }
    }
}

impl ValidatedRepository {
    pub(crate) fn runtime_metadata(
        &self,
        object: &NamespaceObject,
    ) -> Result<BackingMetadata, RuntimeBackingError> {
        let path = object.primary_path();
        let fd = if path.is_root() {
            None
        } else {
            Some(
                openat2(
                    self.as_fd(),
                    path_buf(path),
                    OFlags::PATH | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                    Mode::empty(),
                    RESOLVE_WITHIN_ROOT,
                )
                .map_err(|error| runtime_io_error("open for metadata", path, error))?,
            )
        };
        let metadata = match &fd {
            Some(fd) => metadata_for_fd(fd, path)?,
            None => metadata_for_fd(self.as_fd(), path)?,
        };
        validate_runtime_metadata(self, object, metadata)
    }

    pub(crate) fn open_runtime_file(
        &self,
        object: &NamespaceObject,
    ) -> Result<OpenedBackingFile, RuntimeBackingError> {
        self.open_runtime_file_with_access(object, RuntimeFileAccess::ReadOnly)
    }

    /// Opens a regular file for positioned writes without mutating its length.
    ///
    /// `O_RDWR` lets the adapter serve an `O_RDWR` FUSE handle, but does not
    /// grant logical read access: the adapter must enforce the requested access
    /// mode and reauthorize each `ReadData` or `WriteData` effect separately.
    /// The open never carries `O_APPEND`, `O_CREAT`, or `O_TRUNC`.
    pub(crate) fn open_runtime_writable_file(
        &self,
        object: &NamespaceObject,
    ) -> Result<OpenedBackingFile, RuntimeBackingError> {
        self.open_runtime_file_with_access(object, RuntimeFileAccess::ReadWrite)
    }

    /// Exclusively creates one regular file below a validated live parent.
    ///
    /// The child must be the staged direct child supplied by the namespace
    /// transaction. The parent is opened and validated before `O_EXCL` creation;
    /// the returned descriptor and metadata are validated before the caller can
    /// publish the child. Any post-create failure removes the new entry first.
    #[allow(dead_code)]
    pub(crate) fn create_runtime_file(
        &self,
        parent: &NamespaceObject,
        child: &NamespaceObject,
        permissions: CreationPermissions,
    ) -> Result<(OpenedBackingFile, BackingMetadata), RuntimeBackingError> {
        let child_name =
            validate_creation_objects(parent, child, NamespaceObjectKind::RegularFile)?;
        let parent_fd = self.open_runtime_directory(parent)?;
        let fd = openat2(
            &parent_fd,
            child_name,
            OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::RUSR | Mode::WUSR,
            RESOLVE_WITHIN_ROOT,
        )
        .map_err(|error| runtime_io_error("create regular file", child.primary_path(), error))?;

        let result = (|| {
            fchmod(&fd, permissions.mode()).map_err(|error| {
                runtime_io_error("set creation permissions", child.primary_path(), error)
            })?;
            let metadata = validate_runtime_metadata(
                self,
                child,
                metadata_for_fd(&fd, child.primary_path())?,
            )?;
            Ok((
                OpenedBackingFile {
                    fd,
                    path: child.primary_path().clone(),
                },
                metadata,
            ))
        })();

        rollback_created_entry_on_error(&parent_fd, child, child_name, AtFlags::empty(), result)
    }

    /// Exclusively creates one directory below a validated live parent.
    ///
    /// The directory is opened without following links, assigned its effective
    /// permissions by descriptor, and validated before publication. Any failure
    /// after `mkdirat` removes the empty directory before returning an error.
    #[allow(dead_code)]
    pub(crate) fn create_runtime_directory(
        &self,
        parent: &NamespaceObject,
        child: &NamespaceObject,
        permissions: CreationPermissions,
    ) -> Result<BackingMetadata, RuntimeBackingError> {
        let child_name = validate_creation_objects(parent, child, NamespaceObjectKind::Directory)?;
        let parent_fd = self.open_runtime_directory(parent)?;
        mkdirat(&parent_fd, child_name, Mode::RWXU)
            .map_err(|error| runtime_io_error("create directory", child.primary_path(), error))?;

        let result = (|| {
            let child_fd = openat2(
                &parent_fd,
                child_name,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                Mode::empty(),
                RESOLVE_WITHIN_ROOT,
            )
            .map_err(|error| {
                runtime_io_error("open created directory", child.primary_path(), error)
            })?;
            fchmod(&child_fd, permissions.mode()).map_err(|error| {
                runtime_io_error("set creation permissions", child.primary_path(), error)
            })?;
            validate_runtime_metadata(
                self,
                child,
                metadata_for_fd(&child_fd, child.primary_path())?,
            )
        })();

        rollback_created_entry_on_error(&parent_fd, child, child_name, AtFlags::REMOVEDIR, result)
    }

    /// Removes one validated direct child using its live parent descriptor.
    ///
    /// Every validation happens before `unlinkat`. A successful syscall is the
    /// operation's linearization point and the method performs no fallible work
    /// afterward, so the namespace transaction may publish its staged removal.
    #[allow(dead_code)]
    pub(crate) fn remove_runtime_object(
        &self,
        parent: &NamespaceObject,
        object: &NamespaceObject,
        removed_path: &CanonicalPath,
    ) -> Result<(), RuntimeBackingError> {
        let child_name = direct_child_path_name(parent, removed_path)?;
        let parent_fd = self.open_runtime_directory(parent)?;
        let _validated_object = self.open_and_validate_runtime_child(
            &parent_fd,
            child_name,
            removed_path,
            object.kind(),
            object.expected_link_count(),
        )?;
        let (flags, operation) = match object.kind() {
            NamespaceObjectKind::Directory => (AtFlags::REMOVEDIR, "remove directory"),
            NamespaceObjectKind::RegularFile => (AtFlags::empty(), "remove regular file"),
            NamespaceObjectKind::Symlink => (AtFlags::empty(), "remove symbolic link"),
        };
        unlinkat(&parent_fd, child_name, flags)
            .map_err(|error| runtime_io_error(operation, removed_path, error))
    }

    /// Executes one validated no-replace subtree rename.
    ///
    /// The complete plan, both parent directories, and every moved backing
    /// object are validated before `renameat2`. The `NOREPLACE` syscall is the
    /// final fallible step, which preserves the namespace executor contract:
    /// `Err` means the backing rename did not commit, and `Ok` means it did.
    #[allow(dead_code)]
    pub(crate) fn rename_runtime_subtree(
        &self,
        plan: &RenamePlan,
    ) -> Result<(), RuntimeBackingError> {
        validate_rename_plan(plan)?;
        let source_parent_path = plan
            .source()
            .parent()
            .ok_or_else(|| invalid_rename_plan(plan, "the repository root cannot be renamed"))?;
        let destination_parent_path = plan.destination().parent().ok_or_else(|| {
            invalid_rename_plan(plan, "the repository root cannot be a rename destination")
        })?;
        let source_name = final_name(plan.source())
            .ok_or_else(|| invalid_rename_plan(plan, "the source has no final path segment"))?;
        let destination_name = final_name(plan.destination()).ok_or_else(|| {
            invalid_rename_plan(plan, "the destination has no final path segment")
        })?;

        let source_parent_fd = self.open_runtime_directory_path(&source_parent_path)?;
        let destination_parent_fd = self.open_runtime_directory_path(&destination_parent_path)?;
        for movement in plan.moved_objects() {
            let fd = if movement.source() == plan.source() {
                self.open_and_validate_runtime_child(
                    &source_parent_fd,
                    source_name,
                    movement.source(),
                    movement.kind(),
                    movement.expected_link_count(),
                )?
            } else {
                self.open_and_validate_runtime_path(
                    movement.source(),
                    movement.kind(),
                    movement.expected_link_count(),
                )?
            };
            drop(fd);
        }

        renameat_with(
            &source_parent_fd,
            source_name,
            &destination_parent_fd,
            destination_name,
            RenameFlags::NOREPLACE,
        )
        .map_err(|error| RuntimeBackingError::RenameIo {
            source: plan.source().clone(),
            destination: plan.destination().clone(),
            cause: io::Error::from_raw_os_error(error.raw_os_error()),
        })
    }

    /// Replaces ordinary permission bits on one validated backing object.
    ///
    /// The object descriptor is opened and its kind, mount, and hard-link
    /// invariants are checked before `fchmod`. The syscall is the final fallible
    /// step: success means the metadata effect committed even if a later FUSE
    /// attribute reply must independently fail.
    #[allow(dead_code)]
    pub(crate) fn set_runtime_permissions(
        &self,
        object: &NamespaceObject,
        permissions: MetadataPermissions,
    ) -> Result<(), RuntimeBackingError> {
        let fd = self.open_runtime_metadata_object(object)?;
        fchmod(&fd, permissions.mode())
            .map_err(|error| runtime_io_error("set permissions", object.primary_path(), error))
    }

    /// Replaces atime and/or mtime on one validated backing object.
    ///
    /// Missing fields become `UTIME_OMIT`; `Now` becomes `UTIME_NOW`, allowing
    /// both supported timestamps to commit atomically in one `futimens` call.
    /// Exact-time conversion and all backing validation happen before that
    /// final syscall.
    #[allow(dead_code)]
    pub(crate) fn set_runtime_timestamps(
        &self,
        object: &NamespaceObject,
        times: MetadataTimes,
    ) -> Result<(), RuntimeBackingError> {
        let timestamps = times.to_rustix(object.primary_path())?;
        let fd = self.open_runtime_metadata_object(object)?;
        futimens(&fd, &timestamps)
            .map_err(|error| runtime_io_error("set timestamps", object.primary_path(), error))
    }

    fn open_runtime_file_with_access(
        &self,
        object: &NamespaceObject,
        access: RuntimeFileAccess,
    ) -> Result<OpenedBackingFile, RuntimeBackingError> {
        if object.kind() != NamespaceObjectKind::RegularFile {
            return Err(RuntimeBackingError::ObjectKindChanged {
                path: object.primary_path().clone(),
                expected: NamespaceObjectKind::RegularFile,
                actual: Some(object.kind()),
            });
        }
        let fd = openat2(
            self.as_fd(),
            path_buf(object.primary_path()),
            access.open_flags() | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
            RESOLVE_WITHIN_ROOT,
        )
        .map_err(|error| runtime_io_error(access.operation(), object.primary_path(), error))?;
        let metadata = metadata_for_fd(&fd, object.primary_path())?;
        validate_runtime_metadata(self, object, metadata)?;
        Ok(OpenedBackingFile {
            fd,
            path: object.primary_path().clone(),
        })
    }

    #[allow(dead_code)]
    fn open_runtime_metadata_object(
        &self,
        object: &NamespaceObject,
    ) -> Result<OwnedFd, RuntimeBackingError> {
        match object.kind() {
            NamespaceObjectKind::Directory => self.open_runtime_directory(object),
            NamespaceObjectKind::RegularFile => {
                let file =
                    self.open_runtime_file_with_access(object, RuntimeFileAccess::ReadOnly)?;
                Ok(file.fd)
            }
            // A symbolic link's own metadata is reachable only through an
            // `O_PATH` descriptor: opening it any other way would resolve the
            // target instead of the link.
            NamespaceObjectKind::Symlink => self.open_runtime_symlink(object),
        }
    }

    /// Opens one symbolic link itself, never its target.
    fn open_runtime_symlink(
        &self,
        object: &NamespaceObject,
    ) -> Result<OwnedFd, RuntimeBackingError> {
        if object.kind() != NamespaceObjectKind::Symlink {
            return Err(RuntimeBackingError::ObjectKindChanged {
                path: object.primary_path().clone(),
                expected: NamespaceObjectKind::Symlink,
                actual: Some(object.kind()),
            });
        }
        let fd = openat2(
            self.as_fd(),
            path_buf(object.primary_path()),
            OFlags::PATH | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
            RESOLVE_WITHIN_ROOT,
        )
        .map_err(|error| runtime_io_error("open symbolic link", object.primary_path(), error))?;
        validate_runtime_metadata(self, object, metadata_for_fd(&fd, object.primary_path())?)?;
        Ok(fd)
    }

    /// Reads one symbolic link and confirms the backing agrees with the registry.
    ///
    /// The registry, not the backing tree, owns what a link means: the target it
    /// recorded was validated to stay inside the repository, and it is the value
    /// that gets replied to `READLINK`. Reading the backing link and comparing is
    /// what detects a target rewritten out of band; a mismatch fails closed
    /// rather than serving either value.
    pub(crate) fn read_runtime_symlink(
        &self,
        object: &NamespaceObject,
    ) -> Result<String, RuntimeBackingError> {
        let recorded =
            object
                .link_target()
                .ok_or_else(|| RuntimeBackingError::ObjectKindChanged {
                    path: object.primary_path().clone(),
                    expected: NamespaceObjectKind::Symlink,
                    actual: Some(object.kind()),
                })?;
        let fd = self.open_runtime_symlink(object)?;
        let observed = read_link_body(&fd, object.primary_path())?;
        if observed != recorded.as_str() {
            return Err(RuntimeBackingError::SymlinkTargetChanged {
                path: object.primary_path().clone(),
            });
        }
        Ok(observed)
    }

    /// Exclusively creates one symbolic link below a validated live parent.
    ///
    /// `symlinkat` fails with `EEXIST` rather than replacing anything, and the
    /// created link is reopened without following it and compared against the
    /// target the namespace staged. A failure after creation removes the link
    /// before returning.
    pub(crate) fn create_runtime_symlink(
        &self,
        parent: &NamespaceObject,
        child: &NamespaceObject,
        target: &SymlinkTarget,
    ) -> Result<BackingMetadata, RuntimeBackingError> {
        let child_name = validate_creation_objects(parent, child, NamespaceObjectKind::Symlink)?;
        let parent_fd = self.open_runtime_directory(parent)?;
        symlinkat(target.as_str(), &parent_fd, child_name).map_err(|error| {
            runtime_io_error("create symbolic link", child.primary_path(), error)
        })?;

        let result = (|| {
            let child_fd = openat2(
                &parent_fd,
                child_name,
                OFlags::PATH | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                Mode::empty(),
                RESOLVE_WITHIN_ROOT,
            )
            .map_err(|error| {
                runtime_io_error("open created symbolic link", child.primary_path(), error)
            })?;
            if read_link_body(&child_fd, child.primary_path())? != target.as_str() {
                return Err(RuntimeBackingError::SymlinkTargetChanged {
                    path: child.primary_path().clone(),
                });
            }
            validate_runtime_metadata(
                self,
                child,
                metadata_for_fd(&child_fd, child.primary_path())?,
            )
        })();

        rollback_created_entry_on_error(&parent_fd, child, child_name, AtFlags::empty(), result)
    }

    /// Gives one existing inode an additional name below a validated parent.
    ///
    /// Both names are resolved from descriptors this method opened and
    /// validated, so no intermediate component can be substituted. `linkat`
    /// resolves only the two final components, and it never follows a symbolic
    /// link source: linking a link produces a second name for the link itself.
    ///
    /// The created name is then reopened and required to be the *same inode*
    /// that was validated. That comparison is what closes the window between
    /// validating the source name and using it: if the source was swapped in
    /// between, the new name points at a different inode and is removed again.
    pub(crate) fn create_runtime_hard_link(
        &self,
        source: &NamespaceObject,
        source_path: &CanonicalPath,
        parent: &NamespaceObject,
        link_path: &CanonicalPath,
    ) -> Result<BackingMetadata, RuntimeBackingError> {
        if source.kind() == NamespaceObjectKind::Directory {
            return Err(RuntimeBackingError::ObjectKindChanged {
                path: source_path.clone(),
                expected: NamespaceObjectKind::RegularFile,
                actual: Some(source.kind()),
            });
        }
        let link_name = direct_child_path_name(parent, link_path)?;
        let source_parent_path =
            source_path
                .parent()
                .ok_or_else(|| RuntimeBackingError::PathNotDirectChild {
                    parent: CanonicalPath::root(),
                    child: source_path.clone(),
                })?;
        let source_name =
            final_name(source_path).ok_or_else(|| RuntimeBackingError::PathNotDirectChild {
                parent: source_parent_path.clone(),
                child: source_path.clone(),
            })?;
        let source_parent_fd = self.open_runtime_directory_path(&source_parent_path)?;
        let parent_fd = self.open_runtime_directory(parent)?;

        // The source must still have exactly the names the registry recorded
        // *before* this one is added.
        let existing_names = source
            .expected_link_count()
            .checked_sub(1)
            .ok_or(RuntimeBackingError::InvalidLinkPlan)?;
        let source_fd = openat2(
            &source_parent_fd,
            source_name,
            OFlags::PATH | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
            RESOLVE_WITHIN_ROOT,
        )
        .map_err(|error| runtime_io_error("open hard link source", source_path, error))?;
        let source_metadata = metadata_for_fd(&source_fd, source_path)?;
        validate_runtime_metadata_for(
            self,
            source_path,
            source.kind(),
            existing_names,
            source_metadata,
        )?;

        linkat(
            &source_parent_fd,
            source_name,
            &parent_fd,
            link_name,
            AtFlags::empty(),
        )
        .map_err(|error| runtime_io_error("create hard link", link_path, error))?;

        let result = (|| {
            let link_fd = openat2(
                &parent_fd,
                link_name,
                OFlags::PATH | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                Mode::empty(),
                RESOLVE_WITHIN_ROOT,
            )
            .map_err(|error| runtime_io_error("open created hard link", link_path, error))?;
            let metadata = metadata_for_fd(&link_fd, link_path)?;
            if metadata.stx_ino != source_metadata.stx_ino {
                return Err(RuntimeBackingError::LinkedDifferentInode {
                    path: link_path.clone(),
                });
            }
            validate_runtime_metadata_for(
                self,
                link_path,
                source.kind(),
                source.expected_link_count(),
                metadata,
            )
        })();

        rollback_created_path_on_error(&parent_fd, link_path, link_name, AtFlags::empty(), result)
    }

    fn open_runtime_directory(
        &self,
        object: &NamespaceObject,
    ) -> Result<OwnedFd, RuntimeBackingError> {
        if object.kind() != NamespaceObjectKind::Directory {
            return Err(RuntimeBackingError::ObjectKindChanged {
                path: object.primary_path().clone(),
                expected: NamespaceObjectKind::Directory,
                actual: Some(object.kind()),
            });
        }
        let fd = self.open_runtime_directory_path(object.primary_path())?;
        validate_runtime_metadata(self, object, metadata_for_fd(&fd, object.primary_path())?)?;
        Ok(fd)
    }

    fn open_runtime_directory_path(
        &self,
        path: &CanonicalPath,
    ) -> Result<OwnedFd, RuntimeBackingError> {
        let fd = if path.is_root() {
            fcntl_dupfd_cloexec(self.as_fd(), 0)
                .map_err(|error| runtime_io_error("duplicate root directory", path, error))?
        } else {
            openat2(
                self.as_fd(),
                path_buf(path),
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                Mode::empty(),
                RESOLVE_WITHIN_ROOT,
            )
            .map_err(|error| runtime_io_error("open parent directory", path, error))?
        };
        validate_runtime_metadata_for(
            self,
            path,
            NamespaceObjectKind::Directory,
            DIRECTORY_LINK_COUNT_UNCHECKED,
            metadata_for_fd(&fd, path)?,
        )?;
        Ok(fd)
    }

    #[allow(dead_code)]
    fn open_and_validate_runtime_child(
        &self,
        parent_fd: &OwnedFd,
        child_name: &str,
        child_path: &CanonicalPath,
        expected_kind: NamespaceObjectKind,
        expected_link_count: usize,
    ) -> Result<OwnedFd, RuntimeBackingError> {
        let fd = openat2(
            parent_fd,
            child_name,
            OFlags::PATH | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
            RESOLVE_WITHIN_ROOT,
        )
        .map_err(|error| runtime_io_error("open child for mutation", child_path, error))?;
        validate_runtime_metadata_for(
            self,
            child_path,
            expected_kind,
            expected_link_count,
            metadata_for_fd(&fd, child_path)?,
        )?;
        Ok(fd)
    }

    #[allow(dead_code)]
    fn open_and_validate_runtime_path(
        &self,
        path: &CanonicalPath,
        expected_kind: NamespaceObjectKind,
        expected_link_count: usize,
    ) -> Result<OwnedFd, RuntimeBackingError> {
        let fd = openat2(
            self.as_fd(),
            path_buf(path),
            OFlags::PATH | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
            RESOLVE_WITHIN_ROOT,
        )
        .map_err(|error| runtime_io_error("open rename source", path, error))?;
        validate_runtime_metadata_for(
            self,
            path,
            expected_kind,
            expected_link_count,
            metadata_for_fd(&fd, path)?,
        )?;
        Ok(fd)
    }
}

fn direct_child_name<'a>(
    parent: &NamespaceObject,
    child: &'a NamespaceObject,
) -> Result<&'a str, RuntimeBackingError> {
    direct_child_path_name(parent, child.primary_path())
}

/// Returns the final segment of a path that must be a direct child of `parent`.
///
/// Taking the path rather than the object matters once an inode can have more
/// than one name: a removal or a link names one of them, and using the object's
/// primary path instead would operate on a different name than the request did.
fn direct_child_path_name<'a>(
    parent: &NamespaceObject,
    child: &'a CanonicalPath,
) -> Result<&'a str, RuntimeBackingError> {
    if parent.kind() != NamespaceObjectKind::Directory
        || child.parent().as_ref() != Some(parent.primary_path())
    {
        return Err(RuntimeBackingError::PathNotDirectChild {
            parent: parent.primary_path().clone(),
            child: child.clone(),
        });
    }
    final_name(child).ok_or_else(|| RuntimeBackingError::PathNotDirectChild {
        parent: parent.primary_path().clone(),
        child: child.clone(),
    })
}

/// Reads a link body from an `O_PATH` descriptor of the link itself.
fn read_link_body(fd: &OwnedFd, path: &CanonicalPath) -> Result<String, RuntimeBackingError> {
    let body = readlinkat(fd, "", Vec::new())
        .map_err(|error| runtime_io_error("read symbolic link", path, error))?;
    String::from_utf8(body.into_bytes())
        .map_err(|_| RuntimeBackingError::NonUtf8SymlinkTarget { path: path.clone() })
}

fn final_name(path: &CanonicalPath) -> Option<&str> {
    path.as_segments().last().map(String::as_str)
}

#[allow(dead_code)]
fn invalid_rename_plan(plan: &RenamePlan, reason: &'static str) -> RuntimeBackingError {
    RuntimeBackingError::InvalidRenamePlan {
        source: plan.source().clone(),
        destination: plan.destination().clone(),
        reason,
    }
}

#[allow(dead_code)]
fn validate_rename_plan(plan: &RenamePlan) -> Result<(), RuntimeBackingError> {
    if plan.source().is_root() || plan.destination().is_root() {
        return Err(invalid_rename_plan(
            plan,
            "source and destination must both be below the repository root",
        ));
    }
    if plan.destination().is_at_or_below(plan.source()) {
        return Err(invalid_rename_plan(
            plan,
            "destination must not be inside the source subtree",
        ));
    }
    if plan.moved_objects().is_empty() {
        return Err(invalid_rename_plan(
            plan,
            "the moved-object set must not be empty",
        ));
    }

    let mut objects = HashSet::with_capacity(plan.moved_objects().len());
    let mut sources = HashMap::with_capacity(plan.moved_objects().len());
    let mut destinations = HashSet::with_capacity(plan.moved_objects().len());
    let mut root_movement_count = 0_usize;
    for movement in plan.moved_objects() {
        if !objects.insert(movement.object())
            || sources.insert(movement.source(), movement.kind()).is_some()
            || !destinations.insert(movement.destination())
        {
            return Err(invalid_rename_plan(
                plan,
                "object identities and source/destination paths must be unique",
            ));
        }
        let expected_destination = movement
            .source()
            .rebase(plan.source(), plan.destination())
            .ok_or_else(|| {
                invalid_rename_plan(plan, "every moved source must be inside the source subtree")
            })?;
        if &expected_destination != movement.destination() {
            return Err(invalid_rename_plan(
                plan,
                "every destination must preserve its source-relative suffix",
            ));
        }
        if movement.source() == plan.source() {
            if movement.destination() != plan.destination() {
                return Err(invalid_rename_plan(
                    plan,
                    "the root movement must match the requested destination",
                ));
            }
            root_movement_count += 1;
        }
    }
    if root_movement_count != 1 {
        return Err(invalid_rename_plan(
            plan,
            "the source root must appear exactly once",
        ));
    }
    for movement in plan.moved_objects() {
        if movement.source() == plan.source() {
            continue;
        }
        let parent = movement.source().parent().ok_or_else(|| {
            invalid_rename_plan(plan, "a moved descendant must have a moved parent")
        })?;
        if sources.get(&parent) != Some(&NamespaceObjectKind::Directory) {
            return Err(invalid_rename_plan(
                plan,
                "every moved descendant must have a directory parent in the plan",
            ));
        }
    }
    Ok(())
}

#[allow(dead_code)]
fn validate_creation_objects<'a>(
    parent: &NamespaceObject,
    child: &'a NamespaceObject,
    expected_kind: NamespaceObjectKind,
) -> Result<&'a str, RuntimeBackingError> {
    if child.kind() != expected_kind {
        return Err(RuntimeBackingError::ObjectKindChanged {
            path: child.primary_path().clone(),
            expected: expected_kind,
            actual: Some(child.kind()),
        });
    }
    direct_child_name(parent, child)
}

#[allow(dead_code)]
fn rollback_created_entry_on_error<T>(
    parent_fd: &OwnedFd,
    child: &NamespaceObject,
    child_name: &str,
    flags: AtFlags,
    result: Result<T, RuntimeBackingError>,
) -> Result<T, RuntimeBackingError> {
    rollback_created_path_on_error(parent_fd, child.primary_path(), child_name, flags, result)
}

fn rollback_created_path_on_error<T>(
    parent_fd: &OwnedFd,
    child_path: &CanonicalPath,
    child_name: &str,
    flags: AtFlags,
    result: Result<T, RuntimeBackingError>,
) -> Result<T, RuntimeBackingError> {
    let Err(error) = result else {
        return result;
    };
    if let Err(cleanup_error) = unlinkat(parent_fd, child_name, flags) {
        // Returning would let NamespaceRegistry roll back while an untracked
        // backing entry remains. Panicking under its writer lock poisons the
        // registry so the inconsistent repository fails closed.
        panic!(
            "failed to roll back backing creation `{}` after `{error}`: {}",
            DisplayCanonicalPath(child_path),
            io::Error::from_raw_os_error(cleanup_error.raw_os_error())
        );
    }
    Err(error)
}

fn metadata_for_fd(fd: impl AsFd, path: &CanonicalPath) -> Result<Statx, RuntimeBackingError> {
    let metadata = statx(
        fd,
        "",
        AtFlags::EMPTY_PATH | AtFlags::NO_AUTOMOUNT | AtFlags::SYMLINK_NOFOLLOW,
        REQUIRED_METADATA,
    )
    .map_err(|error| runtime_io_error("inspect metadata", path, error))?;
    let available = StatxFlags::from_bits_retain(metadata.stx_mask);
    if !available.contains(REQUIRED_METADATA) {
        return Err(RuntimeBackingError::RequiredMetadataUnavailable(
            path.clone(),
        ));
    }
    Ok(metadata)
}

fn validate_runtime_metadata(
    repository: &ValidatedRepository,
    object: &NamespaceObject,
    metadata: Statx,
) -> Result<BackingMetadata, RuntimeBackingError> {
    validate_runtime_metadata_for(
        repository,
        object.primary_path(),
        object.kind(),
        object.expected_link_count(),
        metadata,
    )
}

/// Rechecks that the inode behind a path is still the one the namespace records.
///
/// The link-count comparison is what detects a name created outside capfs. It
/// is no longer "exactly one": a hard link made *through* capfs is recorded in
/// the namespace, so the invariant is that the inode has exactly as many names
/// as the registry knows about. A name capfs cannot see would still be caught.
fn validate_runtime_metadata_for(
    repository: &ValidatedRepository,
    path: &CanonicalPath,
    expected_kind: NamespaceObjectKind,
    expected_link_count: usize,
    metadata: Statx,
) -> Result<BackingMetadata, RuntimeBackingError> {
    let actual_kind = namespace_kind(FileType::from_raw_mode(metadata.stx_mode.into()));
    if actual_kind != Some(expected_kind) {
        return Err(RuntimeBackingError::ObjectKindChanged {
            path: path.clone(),
            expected: expected_kind,
            actual: actual_kind,
        });
    }
    if metadata.stx_mnt_id != repository.root_mount_id() {
        return Err(RuntimeBackingError::NestedMount(path.clone()));
    }
    if expected_kind != NamespaceObjectKind::Directory
        && u64::from(metadata.stx_nlink) != expected_link_count as u64
    {
        return Err(RuntimeBackingError::UnexpectedLinkCount {
            path: path.clone(),
            expected: expected_link_count,
            actual: metadata.stx_nlink,
        });
    }

    Ok(BackingMetadata {
        size: metadata.stx_size,
        blocks: metadata.stx_blocks,
        atime: system_time(metadata.stx_atime, path)?,
        mtime: system_time(metadata.stx_mtime, path)?,
        ctime: system_time(metadata.stx_ctime, path)?,
        kind: expected_kind,
        permissions: metadata.stx_mode & 0o7777,
        link_count: metadata.stx_nlink,
        uid: metadata.stx_uid,
        gid: metadata.stx_gid,
        block_size: metadata.stx_blksize,
    })
}

fn system_time(
    timestamp: StatxTimestamp,
    path: &CanonicalPath,
) -> Result<SystemTime, RuntimeBackingError> {
    let nanos = Duration::from_nanos(u64::from(timestamp.tv_nsec));
    let value = if timestamp.tv_sec >= 0 {
        UNIX_EPOCH
            .checked_add(Duration::from_secs(timestamp.tv_sec.unsigned_abs()))
            .and_then(|time| time.checked_add(nanos))
    } else {
        UNIX_EPOCH
            .checked_sub(Duration::from_secs(timestamp.tv_sec.unsigned_abs()))
            .and_then(|time| time.checked_add(nanos))
    };
    value.ok_or_else(|| RuntimeBackingError::TimestampOutOfRange(path.clone()))
}

#[allow(dead_code)]
fn metadata_time_to_timespec(
    update: Option<MetadataTime>,
    path: &CanonicalPath,
) -> Result<Timespec, RuntimeBackingError> {
    match update {
        None => Ok(Timespec {
            tv_sec: 0,
            tv_nsec: UTIME_OMIT,
        }),
        Some(MetadataTime::Now) => Ok(Timespec {
            tv_sec: 0,
            tv_nsec: UTIME_NOW,
        }),
        Some(MetadataTime::Exact(time)) => exact_time_to_timespec(time, path),
    }
}

#[allow(dead_code)]
fn exact_time_to_timespec(
    time: SystemTime,
    path: &CanonicalPath,
) -> Result<Timespec, RuntimeBackingError> {
    match time.duration_since(UNIX_EPOCH) {
        Ok(duration) => Ok(Timespec {
            tv_sec: i64::try_from(duration.as_secs())
                .map_err(|_| RuntimeBackingError::TimestampOutOfRange(path.clone()))?,
            tv_nsec: i64::from(duration.subsec_nanos()),
        }),
        Err(error) => {
            let duration = error.duration();
            let seconds = i64::try_from(duration.as_secs())
                .map_err(|_| RuntimeBackingError::TimestampOutOfRange(path.clone()))?;
            let nanos = duration.subsec_nanos();
            if nanos == 0 {
                Ok(Timespec {
                    tv_sec: -seconds,
                    tv_nsec: 0,
                })
            } else {
                let tv_sec = seconds
                    .checked_add(1)
                    .and_then(i64::checked_neg)
                    .ok_or_else(|| RuntimeBackingError::TimestampOutOfRange(path.clone()))?;
                Ok(Timespec {
                    tv_sec,
                    tv_nsec: 1_000_000_000_i64 - i64::from(nanos),
                })
            }
        }
    }
}

const fn namespace_kind(kind: FileType) -> Option<NamespaceObjectKind> {
    match kind {
        FileType::Directory => Some(NamespaceObjectKind::Directory),
        FileType::RegularFile => Some(NamespaceObjectKind::RegularFile),
        FileType::Symlink => Some(NamespaceObjectKind::Symlink),
        _ => None,
    }
}

fn path_buf(path: &CanonicalPath) -> PathBuf {
    path.as_segments().iter().collect()
}

fn runtime_io_error(
    operation: &'static str,
    path: &CanonicalPath,
    source: rustix::io::Errno,
) -> RuntimeBackingError {
    RuntimeBackingError::Io {
        operation,
        path: diagnostic_path(path),
        source: io::Error::from_raw_os_error(source.raw_os_error()),
    }
}

fn diagnostic_path(path: &CanonicalPath) -> PathBuf {
    if path.is_root() {
        Path::new("/").to_path_buf()
    } else {
        path_buf(path)
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
            write!(formatter, "/{segment}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::{
        convert::Infallible,
        fs,
        num::NonZeroUsize,
        os::unix::fs::{PermissionsExt, symlink},
        path::PathBuf,
        time::{Duration, SystemTime, UNIX_EPOCH},
    };

    use rustix::fs::{AtFlags, Timespec};
    use tempfile::tempdir;

    use super::{
        CreationPermissions, MetadataPermissions, MetadataTime, MetadataTimes, RuntimeBackingError,
        exact_time_to_timespec, rollback_created_entry_on_error,
    };
    use crate::{
        backing::{ImportedRepository, PreflightLimits},
        namespace::{
            NamespaceError, NamespaceObjectKind, NamespaceObjectSpec, NamespaceOperationError,
            SymlinkTarget,
        },
    };
    use authority_core::path::CanonicalPath;
    use authority_core::repository::RepoId;

    fn limits() -> PreflightLimits {
        PreflightLimits::new(NonZeroUsize::new(16).expect("limit must be non-zero"), 4)
    }

    #[test]
    fn runtime_metadata_and_reads_stay_below_the_validated_root() {
        let directory = tempdir().expect("temporary repository must be creatable");
        fs::write(directory.path().join("notes.txt"), b"capability")
            .expect("test file must be writable");
        let imported =
            ImportedRepository::open(RepoId::new("workspace"), directory.path(), limits())
                .expect("link-free repository must validate");
        let (_repository, backing, namespace) = imported.into_parts();
        let path = CanonicalPath::new(["notes.txt"]).expect("test path must be canonical");
        let object = namespace
            .object_at_path_snapshot(&path)
            .expect("namespace must remain readable")
            .expect("manifest file must exist");

        let metadata = backing
            .runtime_metadata(&object)
            .expect("unchanged backing metadata must validate");
        assert_eq!(metadata.kind, NamespaceObjectKind::RegularFile);
        assert_eq!(metadata.size, 10);
        let file = backing
            .open_runtime_file(&object)
            .expect("unchanged regular file must open");
        assert_eq!(
            file.read_at(3, 4)
                .expect("bounded positioned read must work"),
            b"abil"
        );
    }

    #[test]
    fn runtime_positioned_write_preserves_unwritten_file_content() {
        let directory = tempdir().expect("temporary repository must be creatable");
        let file_path = directory.path().join("notes.txt");
        fs::write(&file_path, b"capability").expect("test file must be writable");
        let imported =
            ImportedRepository::open(RepoId::new("workspace"), directory.path(), limits())
                .expect("link-free repository must validate");
        let (_repository, backing, namespace) = imported.into_parts();
        let path = CanonicalPath::new(["notes.txt"]).expect("test path must be canonical");
        let object = namespace
            .object_at_path_snapshot(&path)
            .expect("namespace must remain readable")
            .expect("manifest file must exist");

        let file = backing
            .open_runtime_writable_file(&object)
            .expect("unchanged regular file must open for writing");
        assert_eq!(
            fs::metadata(&file_path)
                .expect("opened file metadata must remain readable")
                .len(),
            10,
            "opening for writes must not truncate the file"
        );
        assert_eq!(
            file.write_at(3, b"SAFE")
                .expect("bounded positioned write must work"),
            4
        );
        drop(file);

        assert_eq!(
            fs::read(file_path).expect("written test file must remain readable"),
            b"capSAFEity"
        );
    }

    #[test]
    fn runtime_read_only_file_rejects_positioned_write_with_path_context() {
        let directory = tempdir().expect("temporary repository must be creatable");
        fs::write(directory.path().join("notes.txt"), b"safe").expect("test file must be writable");
        let imported =
            ImportedRepository::open(RepoId::new("workspace"), directory.path(), limits())
                .expect("link-free repository must validate");
        let (_repository, backing, namespace) = imported.into_parts();
        let path = CanonicalPath::new(["notes.txt"]).expect("test path must be canonical");
        let object = namespace
            .object_at_path_snapshot(&path)
            .expect("namespace must remain readable")
            .expect("manifest file must exist");
        let file = backing
            .open_runtime_file(&object)
            .expect("unchanged regular file must open for reading");

        let error = file
            .write_at(0, b"blocked")
            .expect_err("read-only backing descriptor must reject writes");
        match error {
            RuntimeBackingError::Io {
                operation,
                path,
                source,
            } => {
                assert_eq!(operation, "write");
                assert_eq!(path, PathBuf::from("notes.txt"));
                assert_eq!(
                    source.raw_os_error(),
                    Some(rustix::io::Errno::BADF.raw_os_error())
                );
            }
            other => panic!("expected positioned write I/O error, got {other:?}"),
        }
    }

    #[test]
    fn runtime_writable_file_truncates_by_descriptor() {
        let directory = tempdir().expect("temporary repository must be creatable");
        let file_path = directory.path().join("notes.txt");
        fs::write(&file_path, b"capability").expect("test file must be writable");
        let imported =
            ImportedRepository::open(RepoId::new("workspace"), directory.path(), limits())
                .expect("link-free repository must validate");
        let (_repository, backing, namespace) = imported.into_parts();
        let path = CanonicalPath::new(["notes.txt"]).expect("test path must be canonical");
        let object = namespace
            .object_at_path_snapshot(&path)
            .expect("namespace must remain readable")
            .expect("manifest file must exist");

        let file = backing
            .open_runtime_writable_file(&object)
            .expect("unchanged regular file must open for writing");
        file.truncate_to(3)
            .expect("descriptor-relative truncate must work");
        drop(file);

        assert_eq!(
            fs::read(&file_path).expect("truncated file must remain readable"),
            b"cap"
        );
    }

    #[test]
    fn runtime_read_only_file_rejects_truncate_with_path_context() {
        let directory = tempdir().expect("temporary repository must be creatable");
        fs::write(directory.path().join("notes.txt"), b"safe").expect("test file must be writable");
        let imported =
            ImportedRepository::open(RepoId::new("workspace"), directory.path(), limits())
                .expect("link-free repository must validate");
        let (_repository, backing, namespace) = imported.into_parts();
        let path = CanonicalPath::new(["notes.txt"]).expect("test path must be canonical");
        let object = namespace
            .object_at_path_snapshot(&path)
            .expect("namespace must remain readable")
            .expect("manifest file must exist");
        let file = backing
            .open_runtime_file(&object)
            .expect("unchanged regular file must open for reading");

        let error = file
            .truncate_to(0)
            .expect_err("read-only backing descriptor must reject truncation");
        match error {
            RuntimeBackingError::Io {
                operation,
                path,
                source,
            } => {
                assert_eq!(operation, "truncate");
                assert_eq!(path, PathBuf::from("notes.txt"));
                assert_eq!(
                    source.raw_os_error(),
                    Some(rustix::io::Errno::INVAL.raw_os_error())
                );
            }
            other => panic!("expected truncate I/O error, got {other:?}"),
        }
    }

    #[test]
    fn runtime_create_file_is_exclusive_and_returns_validated_open_file() {
        let directory = tempdir().expect("temporary repository must be creatable");
        fs::create_dir(directory.path().join("src")).expect("parent directory must be creatable");
        let imported =
            ImportedRepository::open(RepoId::new("workspace"), directory.path(), limits())
                .expect("link-free repository must validate");
        let (_repository, backing, namespace) = imported.into_parts();
        let parent_path = CanonicalPath::new(["src"]).expect("test path must be canonical");
        let parent = namespace
            .object_at_path_snapshot(&parent_path)
            .expect("namespace must remain readable")
            .expect("parent must be imported");
        let permissions = CreationPermissions::from_requested_mode(0o1666, 0o027);

        let creation = namespace
            .create_child(
                parent.id(),
                "new.txt",
                NamespaceObjectSpec::RegularFile,
                |live_parent, child| backing.create_runtime_file(live_parent, child, permissions),
            )
            .expect("vacant child must be created");
        let (_object, (file, metadata)) = creation.into_parts();
        assert_eq!(metadata.kind, NamespaceObjectKind::RegularFile);
        assert_eq!(metadata.size, 0);
        assert_eq!(metadata.link_count, 1);
        assert_eq!(metadata.permissions, 0o640);
        assert_eq!(
            file.write_at(0, b"safe")
                .expect("returned descriptor must be writable"),
            4
        );
        drop(file);

        let created_path = directory.path().join("src/new.txt");
        assert_eq!(
            fs::read(&created_path).expect("created file must remain readable"),
            b"safe"
        );
        assert_eq!(
            fs::metadata(&created_path)
                .expect("created metadata must remain readable")
                .permissions()
                .mode()
                & 0o7777,
            0o640,
            "special bits must be stripped and the request umask applied exactly"
        );
    }

    #[test]
    fn runtime_create_directory_is_exclusive_and_returns_validated_metadata() {
        let directory = tempdir().expect("temporary repository must be creatable");
        let imported =
            ImportedRepository::open(RepoId::new("workspace"), directory.path(), limits())
                .expect("empty repository must validate");
        let (_repository, backing, namespace) = imported.into_parts();
        let parent = namespace
            .object_at_path_snapshot(&CanonicalPath::root())
            .expect("namespace must remain readable")
            .expect("root must be imported");
        let creation = namespace
            .create_child(
                parent.id(),
                "private",
                NamespaceObjectSpec::Directory,
                |live_parent, child| {
                    backing.create_runtime_directory(
                        live_parent,
                        child,
                        CreationPermissions::from_requested_mode(0o1777, 0o077),
                    )
                },
            )
            .expect("vacant directory must be created");
        let (_object, metadata) = creation.into_parts();

        assert_eq!(metadata.kind, NamespaceObjectKind::Directory);
        assert_eq!(metadata.permissions, 0o700);
        assert!(directory.path().join("private").is_dir());
        assert_eq!(
            fs::metadata(directory.path().join("private"))
                .expect("created directory metadata must remain readable")
                .permissions()
                .mode()
                & 0o7777,
            0o700
        );
    }

    #[test]
    fn runtime_create_does_not_replace_an_existing_backing_entry() {
        let directory = tempdir().expect("temporary repository must be creatable");
        let imported =
            ImportedRepository::open(RepoId::new("workspace"), directory.path(), limits())
                .expect("empty repository must validate");
        let (_repository, backing, namespace) = imported.into_parts();
        let parent = namespace
            .object_at_path_snapshot(&CanonicalPath::root())
            .expect("namespace must remain readable")
            .expect("root must be imported");
        let child_path = CanonicalPath::new(["occupied"]).expect("test path must be canonical");
        fs::write(directory.path().join("occupied"), b"original")
            .expect("out-of-band test entry must be creatable");

        let error = namespace
            .create_child(
                parent.id(),
                "occupied",
                NamespaceObjectSpec::RegularFile,
                |live_parent, child| {
                    backing.create_runtime_file(
                        live_parent,
                        child,
                        CreationPermissions::from_requested_mode(0o600, 0),
                    )
                },
            )
            .expect_err("exclusive creation must reject an occupied backing name");
        assert!(matches!(
            error,
            NamespaceOperationError::Executor(RuntimeBackingError::Io {
                operation: "create regular file",
                ..
            })
        ));
        assert_eq!(
            fs::read(directory.path().join("occupied"))
                .expect("occupied file must remain readable"),
            b"original"
        );
        assert!(
            namespace
                .object_at_path_snapshot(&child_path)
                .expect("namespace must remain readable")
                .is_none(),
            "failed backing creation must not publish the staged object"
        );
    }

    #[test]
    fn runtime_create_directory_does_not_replace_an_existing_backing_entry() {
        let directory = tempdir().expect("temporary repository must be creatable");
        let imported =
            ImportedRepository::open(RepoId::new("workspace"), directory.path(), limits())
                .expect("empty repository must validate");
        let (_repository, backing, namespace) = imported.into_parts();
        let parent = namespace
            .object_at_path_snapshot(&CanonicalPath::root())
            .expect("namespace must remain readable")
            .expect("root must be imported");
        let child_path = CanonicalPath::new(["occupied"]).expect("test path must be canonical");
        fs::create_dir(directory.path().join("occupied"))
            .expect("out-of-band test directory must be creatable");
        fs::write(directory.path().join("occupied/sentinel"), b"original")
            .expect("out-of-band sentinel must be creatable");

        let error = namespace
            .create_child(
                parent.id(),
                "occupied",
                NamespaceObjectSpec::Directory,
                |live_parent, child| {
                    backing.create_runtime_directory(
                        live_parent,
                        child,
                        CreationPermissions::from_requested_mode(0o700, 0),
                    )
                },
            )
            .expect_err("exclusive directory creation must reject an occupied backing name");
        assert!(matches!(
            error,
            NamespaceOperationError::Executor(RuntimeBackingError::Io {
                operation: "create directory",
                ..
            })
        ));
        assert_eq!(
            fs::read(directory.path().join("occupied/sentinel"))
                .expect("occupied directory must remain untouched"),
            b"original"
        );
        assert!(
            namespace
                .object_at_path_snapshot(&child_path)
                .expect("namespace must remain readable")
                .is_none()
        );
    }

    #[test]
    fn runtime_create_does_not_follow_an_existing_target_symlink() {
        let directory = tempdir().expect("temporary repository must be creatable");
        let outside = tempdir().expect("outside directory must be creatable");
        let outside_file = outside.path().join("secret.txt");
        fs::write(&outside_file, b"secret").expect("outside file must be creatable");
        let imported =
            ImportedRepository::open(RepoId::new("workspace"), directory.path(), limits())
                .expect("empty repository must validate");
        let (_repository, backing, namespace) = imported.into_parts();
        let parent = namespace
            .object_at_path_snapshot(&CanonicalPath::root())
            .expect("namespace must remain readable")
            .expect("root must be imported");
        let child_path = CanonicalPath::new(["new.txt"]).expect("test path must be canonical");
        symlink(&outside_file, directory.path().join("new.txt"))
            .expect("out-of-band target symlink must be creatable");

        let error = namespace
            .create_child(
                parent.id(),
                "new.txt",
                NamespaceObjectSpec::RegularFile,
                |live_parent, child| {
                    backing.create_runtime_file(
                        live_parent,
                        child,
                        CreationPermissions::from_requested_mode(0o600, 0),
                    )
                },
            )
            .expect_err("exclusive creation must reject a target symlink");
        assert!(matches!(
            error,
            NamespaceOperationError::Executor(RuntimeBackingError::Io {
                operation: "create regular file",
                ..
            })
        ));
        assert_eq!(
            fs::read(&outside_file).expect("outside target must remain readable"),
            b"secret"
        );
        assert!(
            fs::symlink_metadata(directory.path().join("new.txt"))
                .expect("target symlink must remain present")
                .file_type()
                .is_symlink()
        );
        assert!(
            namespace
                .object_at_path_snapshot(&child_path)
                .expect("namespace must remain readable")
                .is_none()
        );
    }

    #[test]
    fn post_create_failure_removes_backing_entry_before_namespace_rollback() {
        let directory = tempdir().expect("temporary repository must be creatable");
        let imported =
            ImportedRepository::open(RepoId::new("workspace"), directory.path(), limits())
                .expect("empty repository must validate");
        let (_repository, backing, namespace) = imported.into_parts();
        let parent = namespace
            .object_at_path_snapshot(&CanonicalPath::root())
            .expect("namespace must remain readable")
            .expect("root must be imported");
        let child_path =
            CanonicalPath::new(["rolled-back.txt"]).expect("test path must be canonical");

        let error = namespace
            .create_child(
                parent.id(),
                "rolled-back.txt",
                NamespaceObjectSpec::RegularFile,
                |live_parent, child| {
                    let parent_fd = backing.open_runtime_directory(live_parent)?;
                    fs::write(directory.path().join("rolled-back.txt"), b"uncommitted")
                        .expect("test backing entry must be creatable");
                    rollback_created_entry_on_error(
                        &parent_fd,
                        child,
                        "rolled-back.txt",
                        AtFlags::empty(),
                        Err::<(), _>(RuntimeBackingError::PathNotDirectChild {
                            parent: CanonicalPath::root(),
                            child: child.primary_path().clone(),
                        }),
                    )
                },
            )
            .expect_err("post-create validation failure must abort the transaction");
        assert!(matches!(
            error,
            NamespaceOperationError::Executor(RuntimeBackingError::PathNotDirectChild { .. })
        ));
        assert!(!directory.path().join("rolled-back.txt").exists());
        assert!(
            namespace
                .object_at_path_snapshot(&child_path)
                .expect("namespace must remain readable")
                .is_none()
        );
    }

    #[test]
    fn runtime_create_rejects_a_non_direct_child_before_touching_backing() {
        let directory = tempdir().expect("temporary repository must be creatable");
        fs::create_dir(directory.path().join("left")).expect("left parent must be creatable");
        fs::create_dir(directory.path().join("right")).expect("right parent must be creatable");
        let imported =
            ImportedRepository::open(RepoId::new("workspace"), directory.path(), limits())
                .expect("link-free repository must validate");
        let (_repository, backing, namespace) = imported.into_parts();
        let wrong_parent = namespace
            .object_at_path_snapshot(
                &CanonicalPath::new(["right"]).expect("test path must be canonical"),
            )
            .expect("namespace must remain readable")
            .expect("right parent must be imported");
        let child_path =
            CanonicalPath::new(["left", "new.txt"]).expect("test path must be canonical");

        let error = namespace
            .create_object(
                child_path.clone(),
                NamespaceObjectSpec::RegularFile,
                |child| {
                    backing.create_runtime_file(
                        &wrong_parent,
                        child,
                        CreationPermissions::from_requested_mode(0o600, 0),
                    )
                },
            )
            .expect_err("a mismatched parent must reject creation");
        assert!(matches!(
            error,
            NamespaceOperationError::Executor(RuntimeBackingError::PathNotDirectChild { .. })
        ));
        assert!(!directory.path().join("left/new.txt").exists());
        assert!(!directory.path().join("right/new.txt").exists());
    }

    #[test]
    fn runtime_create_rejects_a_parent_symlink_substituted_after_preflight() {
        let directory = tempdir().expect("temporary repository must be creatable");
        let outside = tempdir().expect("outside directory must be creatable");
        let parent_path = directory.path().join("src");
        fs::create_dir(&parent_path).expect("parent directory must be creatable");
        let imported =
            ImportedRepository::open(RepoId::new("workspace"), directory.path(), limits())
                .expect("initial repository must validate");
        let (_repository, backing, namespace) = imported.into_parts();
        let parent_canonical = CanonicalPath::new(["src"]).expect("test path must be canonical");
        let parent = namespace
            .object_at_path_snapshot(&parent_canonical)
            .expect("namespace must remain readable")
            .expect("parent must be imported");
        fs::remove_dir(&parent_path).expect("test parent must be replaceable");
        symlink(outside.path(), &parent_path).expect("test parent symlink must be creatable");
        let child_path = parent_canonical
            .child("escape.txt")
            .expect("child path must be canonical");

        let error = namespace
            .create_child(
                parent.id(),
                "escape.txt",
                NamespaceObjectSpec::RegularFile,
                |live_parent, child| {
                    backing.create_runtime_file(
                        live_parent,
                        child,
                        CreationPermissions::from_requested_mode(0o600, 0),
                    )
                },
            )
            .expect_err("a substituted parent symlink must reject creation");
        assert!(matches!(
            error,
            NamespaceOperationError::Executor(RuntimeBackingError::Io {
                operation: "open parent directory",
                ..
            })
        ));
        assert!(!outside.path().join("escape.txt").exists());
        assert!(
            namespace
                .object_at_path_snapshot(&child_path)
                .expect("namespace must remain readable")
                .is_none()
        );
    }

    #[test]
    fn runtime_remove_file_commits_backing_and_namespace_together() {
        let directory = tempdir().expect("temporary repository must be creatable");
        fs::write(directory.path().join("obsolete.txt"), b"obsolete")
            .expect("test file must be creatable");
        let imported =
            ImportedRepository::open(RepoId::new("workspace"), directory.path(), limits())
                .expect("link-free repository must validate");
        let (_repository, backing, namespace) = imported.into_parts();
        let root = namespace
            .object_at_path_snapshot(&CanonicalPath::root())
            .expect("namespace must remain readable")
            .expect("root must be imported");
        let removed_path =
            CanonicalPath::new(["obsolete.txt"]).expect("test path must be canonical");

        namespace
            .remove_child(root.id(), "obsolete.txt", |parent, object, removed| {
                backing.remove_runtime_object(parent, object, removed)
            })
            .expect("validated regular file must be removed");

        assert!(!directory.path().join("obsolete.txt").exists());
        assert!(
            namespace
                .object_at_path_snapshot(&removed_path)
                .expect("namespace must remain readable")
                .is_none()
        );
    }

    #[test]
    fn runtime_remove_directory_uses_removedir_without_cross_kind_fallback() {
        let directory = tempdir().expect("temporary repository must be creatable");
        fs::create_dir(directory.path().join("empty")).expect("test directory must be creatable");
        let imported =
            ImportedRepository::open(RepoId::new("workspace"), directory.path(), limits())
                .expect("link-free repository must validate");
        let (_repository, backing, namespace) = imported.into_parts();
        let root = namespace
            .object_at_path_snapshot(&CanonicalPath::root())
            .expect("namespace must remain readable")
            .expect("root must be imported");
        let removed_path = CanonicalPath::new(["empty"]).expect("test path must be canonical");

        namespace
            .remove_child(root.id(), "empty", |parent, object, removed| {
                backing.remove_runtime_object(parent, object, removed)
            })
            .expect("validated empty directory must be removed");

        assert!(!directory.path().join("empty").exists());
        assert!(
            namespace
                .object_at_path_snapshot(&removed_path)
                .expect("namespace must remain readable")
                .is_none()
        );
    }

    #[test]
    fn failed_backing_remove_keeps_namespace_and_directory() {
        let directory = tempdir().expect("temporary repository must be creatable");
        let object_path = directory.path().join("initially-empty");
        fs::create_dir(&object_path).expect("test directory must be creatable");
        let imported =
            ImportedRepository::open(RepoId::new("workspace"), directory.path(), limits())
                .expect("initial repository must validate");
        let (_repository, backing, namespace) = imported.into_parts();
        let root = namespace
            .object_at_path_snapshot(&CanonicalPath::root())
            .expect("namespace must remain readable")
            .expect("root must be imported");
        let canonical =
            CanonicalPath::new(["initially-empty"]).expect("test path must be canonical");
        fs::write(object_path.join("untracked-child"), b"blocks rmdir")
            .expect("out-of-band child must be creatable");

        let error = namespace
            .remove_child(root.id(), "initially-empty", |parent, object, removed| {
                backing.remove_runtime_object(parent, object, removed)
            })
            .expect_err("non-empty backing directory must reject removal");
        assert!(matches!(
            error,
            NamespaceOperationError::Executor(RuntimeBackingError::Io {
                operation: "remove directory",
                ..
            })
        ));
        assert!(object_path.join("untracked-child").exists());
        assert!(
            namespace
                .object_at_path_snapshot(&canonical)
                .expect("namespace must remain readable")
                .is_some(),
            "a failed unlinkat must not publish the staged namespace removal"
        );
    }

    #[test]
    fn runtime_remove_rejects_hard_link_introduced_after_preflight() {
        let directory = tempdir().expect("temporary repository must be creatable");
        let file_path = directory.path().join("kept.txt");
        fs::write(&file_path, b"kept").expect("test file must be creatable");
        let imported =
            ImportedRepository::open(RepoId::new("workspace"), directory.path(), limits())
                .expect("initial repository must validate");
        let (_repository, backing, namespace) = imported.into_parts();
        let root = namespace
            .object_at_path_snapshot(&CanonicalPath::root())
            .expect("namespace must remain readable")
            .expect("root must be imported");
        let canonical = CanonicalPath::new(["kept.txt"]).expect("test path must be canonical");
        fs::hard_link(&file_path, directory.path().join("alias.txt"))
            .expect("out-of-band hard link must be creatable");

        let error = namespace
            .remove_child(root.id(), "kept.txt", |parent, object, removed| {
                backing.remove_runtime_object(parent, object, removed)
            })
            .expect_err("hard-linked file must reject removal");
        assert!(matches!(
            error,
            NamespaceOperationError::Executor(RuntimeBackingError::UnexpectedLinkCount {
                expected: 1,
                actual: 2,
                ..
            })
        ));
        assert!(file_path.exists());
        assert!(directory.path().join("alias.txt").exists());
        assert!(
            namespace
                .object_at_path_snapshot(&canonical)
                .expect("namespace must remain readable")
                .is_some()
        );
    }

    #[test]
    fn runtime_rename_file_is_no_replace_and_updates_the_same_object() {
        let directory = tempdir().expect("temporary repository must be creatable");
        fs::create_dir(directory.path().join("source")).expect("source parent must be creatable");
        fs::create_dir(directory.path().join("destination"))
            .expect("destination parent must be creatable");
        fs::write(directory.path().join("source/item.txt"), b"payload")
            .expect("source file must be creatable");
        let imported =
            ImportedRepository::open(RepoId::new("workspace"), directory.path(), limits())
                .expect("link-free repository must validate");
        let (_repository, backing, namespace) = imported.into_parts();
        let source_parent_path =
            CanonicalPath::new(["source"]).expect("test path must be canonical");
        let destination_parent_path =
            CanonicalPath::new(["destination"]).expect("test path must be canonical");
        let source_path = source_parent_path
            .child("item.txt")
            .expect("source path must be canonical");
        let destination_path = destination_parent_path
            .child("moved.txt")
            .expect("destination path must be canonical");
        let source_parent = namespace
            .object_at_path_snapshot(&source_parent_path)
            .expect("namespace must remain readable")
            .expect("source parent must be imported");
        let destination_parent = namespace
            .object_at_path_snapshot(&destination_parent_path)
            .expect("namespace must remain readable")
            .expect("destination parent must be imported");
        let original_object = namespace
            .object_at_path_snapshot(&source_path)
            .expect("namespace must remain readable")
            .expect("source file must be imported")
            .id()
            .clone();

        namespace
            .rename_child(
                source_parent.id(),
                "item.txt",
                destination_parent.id(),
                "moved.txt",
                |plan| backing.rename_runtime_subtree(plan),
            )
            .expect("validated no-replace rename must commit");

        assert!(!directory.path().join("source/item.txt").exists());
        assert_eq!(
            fs::read(directory.path().join("destination/moved.txt"))
                .expect("renamed file must remain readable"),
            b"payload"
        );
        assert!(
            namespace
                .object_at_path_snapshot(&source_path)
                .expect("namespace must remain readable")
                .is_none()
        );
        assert_eq!(
            namespace
                .object_at_path_snapshot(&destination_path)
                .expect("namespace must remain readable")
                .expect("destination must be published")
                .id(),
            &original_object
        );
    }

    #[test]
    fn runtime_rename_validates_and_moves_every_subtree_object() {
        let directory = tempdir().expect("temporary repository must be creatable");
        fs::create_dir_all(directory.path().join("source/nested"))
            .expect("source subtree must be creatable");
        fs::create_dir(directory.path().join("destination"))
            .expect("destination parent must be creatable");
        fs::write(directory.path().join("source/nested/item.txt"), b"payload")
            .expect("nested file must be creatable");
        let imported =
            ImportedRepository::open(RepoId::new("workspace"), directory.path(), limits())
                .expect("link-free repository must validate");
        let (_repository, backing, namespace) = imported.into_parts();
        let source_parent = namespace
            .object_at_path_snapshot(&CanonicalPath::root())
            .expect("namespace must remain readable")
            .expect("root must be imported");
        let destination_parent_path =
            CanonicalPath::new(["destination"]).expect("test path must be canonical");
        let destination_parent = namespace
            .object_at_path_snapshot(&destination_parent_path)
            .expect("namespace must remain readable")
            .expect("destination parent must be imported");

        namespace
            .rename_child(
                source_parent.id(),
                "source",
                destination_parent.id(),
                "renamed",
                |plan| backing.rename_runtime_subtree(plan),
            )
            .expect("validated subtree rename must commit");

        assert_eq!(
            fs::read(directory.path().join("destination/renamed/nested/item.txt"))
                .expect("renamed descendant must remain readable"),
            b"payload"
        );
        let moved_path = CanonicalPath::new(["destination", "renamed", "nested", "item.txt"])
            .expect("test path must be canonical");
        assert!(
            namespace
                .object_at_path_snapshot(&moved_path)
                .expect("namespace must remain readable")
                .is_some()
        );
    }

    #[test]
    fn failed_no_replace_rename_leaves_backing_and_namespace_unchanged() {
        let directory = tempdir().expect("temporary repository must be creatable");
        fs::create_dir(directory.path().join("source")).expect("source parent must be creatable");
        fs::create_dir(directory.path().join("destination"))
            .expect("destination parent must be creatable");
        fs::write(directory.path().join("source/item.txt"), b"source")
            .expect("source file must be creatable");
        let imported =
            ImportedRepository::open(RepoId::new("workspace"), directory.path(), limits())
                .expect("initial repository must validate");
        let (_repository, backing, namespace) = imported.into_parts();
        let source_parent_path =
            CanonicalPath::new(["source"]).expect("test path must be canonical");
        let destination_parent_path =
            CanonicalPath::new(["destination"]).expect("test path must be canonical");
        let source_path = source_parent_path
            .child("item.txt")
            .expect("source path must be canonical");
        let destination_path = destination_parent_path
            .child("occupied.txt")
            .expect("destination path must be canonical");
        let source_parent = namespace
            .object_at_path_snapshot(&source_parent_path)
            .expect("namespace must remain readable")
            .expect("source parent must be imported");
        let destination_parent = namespace
            .object_at_path_snapshot(&destination_parent_path)
            .expect("namespace must remain readable")
            .expect("destination parent must be imported");
        fs::write(
            directory.path().join("destination/occupied.txt"),
            b"destination",
        )
        .expect("out-of-band destination must be creatable");

        let error = namespace
            .rename_child(
                source_parent.id(),
                "item.txt",
                destination_parent.id(),
                "occupied.txt",
                |plan| backing.rename_runtime_subtree(plan),
            )
            .expect_err("NOREPLACE must reject an occupied backing destination");
        assert!(matches!(
            error,
            NamespaceOperationError::Executor(RuntimeBackingError::RenameIo { .. })
        ));
        assert_eq!(
            fs::read(directory.path().join("source/item.txt"))
                .expect("source must remain readable"),
            b"source"
        );
        assert_eq!(
            fs::read(directory.path().join("destination/occupied.txt"))
                .expect("destination must remain readable"),
            b"destination"
        );
        assert!(
            namespace
                .object_at_path_snapshot(&source_path)
                .expect("namespace must remain readable")
                .is_some()
        );
        assert!(
            namespace
                .object_at_path_snapshot(&destination_path)
                .expect("namespace must remain readable")
                .is_none()
        );
    }

    #[test]
    fn runtime_rename_rejects_descendant_kind_change_before_syscall() {
        let directory = tempdir().expect("temporary repository must be creatable");
        fs::create_dir(directory.path().join("source"))
            .expect("source directory must be creatable");
        fs::write(directory.path().join("source/item.txt"), b"source")
            .expect("source child must be creatable");
        let imported =
            ImportedRepository::open(RepoId::new("workspace"), directory.path(), limits())
                .expect("initial repository must validate");
        let (_repository, backing, namespace) = imported.into_parts();
        let root = namespace
            .object_at_path_snapshot(&CanonicalPath::root())
            .expect("namespace must remain readable")
            .expect("root must be imported");
        fs::remove_file(directory.path().join("source/item.txt"))
            .expect("test child must be replaceable");
        fs::create_dir(directory.path().join("source/item.txt"))
            .expect("replacement directory must be creatable");

        let error = namespace
            .rename_child(root.id(), "source", root.id(), "destination", |plan| {
                backing.rename_runtime_subtree(plan)
            })
            .expect_err("changed descendant kind must reject the entire rename");
        assert!(matches!(
            error,
            NamespaceOperationError::Executor(RuntimeBackingError::ObjectKindChanged {
                expected: NamespaceObjectKind::RegularFile,
                actual: Some(NamespaceObjectKind::Directory),
                ..
            })
        ));
        assert!(directory.path().join("source/item.txt").is_dir());
        assert!(!directory.path().join("destination").exists());
        assert!(
            namespace
                .object_at_path_snapshot(
                    &CanonicalPath::new(["source"]).expect("test path must be canonical")
                )
                .expect("namespace must remain readable")
                .is_some()
        );
    }

    #[test]
    fn runtime_rename_does_not_follow_a_source_symlink() {
        let directory = tempdir().expect("temporary repository must be creatable");
        let outside = tempdir().expect("outside directory must be creatable");
        let outside_file = outside.path().join("secret.txt");
        fs::write(&outside_file, b"secret").expect("outside file must be creatable");
        fs::write(directory.path().join("source.txt"), b"source")
            .expect("source file must be creatable");
        fs::create_dir(directory.path().join("destination"))
            .expect("destination parent must be creatable");
        let imported =
            ImportedRepository::open(RepoId::new("workspace"), directory.path(), limits())
                .expect("initial repository must validate");
        let (_repository, backing, namespace) = imported.into_parts();
        let root = namespace
            .object_at_path_snapshot(&CanonicalPath::root())
            .expect("namespace must remain readable")
            .expect("root must be imported");
        let destination_parent = namespace
            .object_at_path_snapshot(
                &CanonicalPath::new(["destination"]).expect("test path must be canonical"),
            )
            .expect("namespace must remain readable")
            .expect("destination parent must be imported");
        fs::remove_file(directory.path().join("source.txt")).expect("source must be replaceable");
        symlink(&outside_file, directory.path().join("source.txt"))
            .expect("replacement symlink must be creatable");

        let error = namespace
            .rename_child(
                root.id(),
                "source.txt",
                destination_parent.id(),
                "moved.txt",
                |plan| backing.rename_runtime_subtree(plan),
            )
            .expect_err("source symlink must reject rename");
        // The substitution is detected as a kind change: the namespace recorded
        // a regular file and the backing now holds a symbolic link. Symlinks are
        // representable objects now, so the mismatch names what was found.
        assert!(matches!(
            error,
            NamespaceOperationError::Executor(
                RuntimeBackingError::Io { .. }
                    | RuntimeBackingError::ObjectKindChanged {
                        expected: NamespaceObjectKind::RegularFile,
                        actual: None | Some(NamespaceObjectKind::Symlink),
                        ..
                    }
            )
        ));
        assert_eq!(
            fs::read(&outside_file).expect("outside file must remain readable"),
            b"secret"
        );
        assert!(
            fs::symlink_metadata(directory.path().join("source.txt"))
                .expect("source symlink must remain present")
                .file_type()
                .is_symlink()
        );
        assert!(!directory.path().join("destination/moved.txt").exists());
        assert!(
            namespace
                .object_at_path_snapshot(
                    &CanonicalPath::new(["source.txt"]).expect("test path must be canonical")
                )
                .expect("namespace must remain readable")
                .is_some()
        );
    }

    #[test]
    fn runtime_rename_rejects_a_destination_parent_symlink() {
        let directory = tempdir().expect("temporary repository must be creatable");
        let outside = tempdir().expect("outside directory must be creatable");
        fs::create_dir(directory.path().join("source")).expect("source parent must be creatable");
        fs::create_dir(directory.path().join("destination"))
            .expect("destination parent must be creatable");
        fs::write(directory.path().join("source/item.txt"), b"source")
            .expect("source file must be creatable");
        let imported =
            ImportedRepository::open(RepoId::new("workspace"), directory.path(), limits())
                .expect("initial repository must validate");
        let (_repository, backing, namespace) = imported.into_parts();
        let source_parent = namespace
            .object_at_path_snapshot(
                &CanonicalPath::new(["source"]).expect("test path must be canonical"),
            )
            .expect("namespace must remain readable")
            .expect("source parent must be imported");
        let destination_parent = namespace
            .object_at_path_snapshot(
                &CanonicalPath::new(["destination"]).expect("test path must be canonical"),
            )
            .expect("namespace must remain readable")
            .expect("destination parent must be imported");
        fs::remove_dir(directory.path().join("destination"))
            .expect("destination parent must be replaceable");
        symlink(outside.path(), directory.path().join("destination"))
            .expect("replacement parent symlink must be creatable");

        let error = namespace
            .rename_child(
                source_parent.id(),
                "item.txt",
                destination_parent.id(),
                "moved.txt",
                |plan| backing.rename_runtime_subtree(plan),
            )
            .expect_err("destination parent symlink must reject rename");
        assert!(matches!(
            error,
            NamespaceOperationError::Executor(RuntimeBackingError::Io {
                operation: "open parent directory",
                ..
            })
        ));
        assert_eq!(
            fs::read(directory.path().join("source/item.txt"))
                .expect("source must remain readable"),
            b"source"
        );
        assert!(!outside.path().join("moved.txt").exists());
        assert!(
            namespace
                .object_at_path_snapshot(
                    &CanonicalPath::new(["source", "item.txt"])
                        .expect("test path must be canonical")
                )
                .expect("namespace must remain readable")
                .is_some()
        );
    }

    #[test]
    fn runtime_permissions_strip_privileged_bits_and_apply_exact_mode() {
        let directory = tempdir().expect("temporary repository must be creatable");
        let file_path = directory.path().join("file.txt");
        let child_directory_path = directory.path().join("child");
        fs::write(&file_path, b"content").expect("test file must be creatable");
        fs::create_dir(&child_directory_path).expect("test directory must be creatable");
        let imported =
            ImportedRepository::open(RepoId::new("workspace"), directory.path(), limits())
                .expect("link-free repository must validate");
        let (_repository, backing, namespace) = imported.into_parts();
        let file = namespace
            .object_at_path_snapshot(
                &CanonicalPath::new(["file.txt"]).expect("test path must be canonical"),
            )
            .expect("namespace must remain readable")
            .expect("file must be imported");
        let child_directory = namespace
            .object_at_path_snapshot(
                &CanonicalPath::new(["child"]).expect("test path must be canonical"),
            )
            .expect("namespace must remain readable")
            .expect("directory must be imported");

        backing
            .set_runtime_permissions(&file, MetadataPermissions::from_requested_mode(0o7754))
            .expect("file permissions must be mutable by descriptor");
        backing
            .set_runtime_permissions(
                &child_directory,
                MetadataPermissions::from_requested_mode(0o5710),
            )
            .expect("directory permissions must be mutable by descriptor");

        assert_eq!(
            fs::metadata(&file_path)
                .expect("file metadata must remain readable")
                .permissions()
                .mode()
                & 0o7777,
            0o754,
            "set-ID and sticky bits must not reach the backing file"
        );
        assert_eq!(
            fs::metadata(&child_directory_path)
                .expect("directory metadata must remain readable")
                .permissions()
                .mode()
                & 0o7777,
            0o710,
            "set-ID and sticky bits must not reach the backing directory"
        );
    }

    #[test]
    fn runtime_permissions_reject_hard_link_before_metadata_change() {
        let directory = tempdir().expect("temporary repository must be creatable");
        let file_path = directory.path().join("file.txt");
        fs::write(&file_path, b"content").expect("test file must be creatable");
        fs::set_permissions(&file_path, fs::Permissions::from_mode(0o640))
            .expect("initial permissions must be configurable");
        let imported =
            ImportedRepository::open(RepoId::new("workspace"), directory.path(), limits())
                .expect("initial repository must validate");
        let (_repository, backing, namespace) = imported.into_parts();
        let file = namespace
            .object_at_path_snapshot(
                &CanonicalPath::new(["file.txt"]).expect("test path must be canonical"),
            )
            .expect("namespace must remain readable")
            .expect("file must be imported");
        fs::hard_link(&file_path, directory.path().join("alias.txt"))
            .expect("out-of-band hard link must be creatable");

        let error = backing
            .set_runtime_permissions(&file, MetadataPermissions::from_requested_mode(0o600))
            .expect_err("hard-linked file must reject metadata mutation");

        assert!(matches!(
            error,
            RuntimeBackingError::UnexpectedLinkCount {
                expected: 1,
                actual: 2,
                ..
            }
        ));
        assert_eq!(
            fs::metadata(&file_path)
                .expect("file metadata must remain readable")
                .permissions()
                .mode()
                & 0o7777,
            0o640,
            "validation failure must occur before fchmod"
        );
    }

    #[test]
    fn runtime_timestamps_set_exact_values_and_omit_unspecified_fields() {
        let directory = tempdir().expect("temporary repository must be creatable");
        let file_path = directory.path().join("file.txt");
        fs::write(&file_path, b"content").expect("test file must be creatable");
        let imported =
            ImportedRepository::open(RepoId::new("workspace"), directory.path(), limits())
                .expect("link-free repository must validate");
        let (_repository, backing, namespace) = imported.into_parts();
        let file = namespace
            .object_at_path_snapshot(
                &CanonicalPath::new(["file.txt"]).expect("test path must be canonical"),
            )
            .expect("namespace must remain readable")
            .expect("file must be imported");
        let first_access = UNIX_EPOCH + Duration::new(1_700_000_000, 123_456_789);
        let first_modification = UNIX_EPOCH + Duration::new(1_700_000_100, 987_654_321);
        let second_modification = UNIX_EPOCH + Duration::new(1_700_000_200, 111_222_333);

        backing
            .set_runtime_timestamps(
                &file,
                MetadataTimes::new(
                    Some(MetadataTime::Exact(first_access)),
                    Some(MetadataTime::Exact(first_modification)),
                )
                .expect("at least one timestamp is present"),
            )
            .expect("both exact timestamps must commit in one syscall");
        let first_metadata = backing
            .runtime_metadata(&file)
            .expect("updated metadata must remain valid");
        assert_eq!(first_metadata.atime, first_access);
        assert_eq!(first_metadata.mtime, first_modification);

        backing
            .set_runtime_timestamps(
                &file,
                MetadataTimes::new(None, Some(MetadataTime::Exact(second_modification)))
                    .expect("mtime update is non-empty"),
            )
            .expect("mtime-only update must commit");
        let second_metadata = backing
            .runtime_metadata(&file)
            .expect("updated metadata must remain valid");
        assert_eq!(
            second_metadata.atime, first_access,
            "UTIME_OMIT must preserve the unspecified atime"
        );
        assert_eq!(second_metadata.mtime, second_modification);
    }

    #[test]
    fn runtime_timestamps_support_kernel_now_without_changing_omitted_mtime() {
        let directory = tempdir().expect("temporary repository must be creatable");
        fs::write(directory.path().join("file.txt"), b"content")
            .expect("test file must be creatable");
        let imported =
            ImportedRepository::open(RepoId::new("workspace"), directory.path(), limits())
                .expect("link-free repository must validate");
        let (_repository, backing, namespace) = imported.into_parts();
        let file = namespace
            .object_at_path_snapshot(
                &CanonicalPath::new(["file.txt"]).expect("test path must be canonical"),
            )
            .expect("namespace must remain readable")
            .expect("file must be imported");
        let fixed_modification = UNIX_EPOCH + Duration::from_secs(1_600_000_000);
        backing
            .set_runtime_timestamps(
                &file,
                MetadataTimes::new(None, Some(MetadataTime::Exact(fixed_modification)))
                    .expect("mtime update is non-empty"),
            )
            .expect("initial mtime must be configurable");
        let before = SystemTime::now();

        backing
            .set_runtime_timestamps(
                &file,
                MetadataTimes::new(Some(MetadataTime::Now), None)
                    .expect("atime update is non-empty"),
            )
            .expect("kernel-now atime update must commit");
        let after = SystemTime::now();
        let metadata = backing
            .runtime_metadata(&file)
            .expect("updated metadata must remain valid");

        let clock_tolerance = Duration::from_secs(1);
        assert!(
            metadata.atime
                >= before
                    .checked_sub(clock_tolerance)
                    .expect("current time must exceed one second after the epoch")
        );
        assert!(
            metadata.atime
                <= after
                    .checked_add(clock_tolerance)
                    .expect("current time plus one second must be representable")
        );
        assert_eq!(metadata.mtime, fixed_modification);
    }

    #[test]
    fn exact_timestamp_conversion_handles_values_before_unix_epoch() {
        let path = CanonicalPath::new(["file.txt"]).expect("test path must be canonical");

        assert_eq!(
            exact_time_to_timespec(UNIX_EPOCH - Duration::from_nanos(1), &path)
                .expect("one nanosecond before the epoch is representable"),
            Timespec {
                tv_sec: -1,
                tv_nsec: 999_999_999,
            }
        );
        assert!(MetadataTimes::new(None, None).is_none());
    }

    #[test]
    fn runtime_timestamps_reject_a_symlink_before_metadata_change() {
        let directory = tempdir().expect("temporary repository must be creatable");
        let outside = tempdir().expect("outside directory must be creatable");
        let file_path = directory.path().join("file.txt");
        let outside_path = outside.path().join("outside.txt");
        fs::write(&file_path, b"inside").expect("test file must be creatable");
        fs::write(&outside_path, b"outside").expect("outside file must be creatable");
        let imported =
            ImportedRepository::open(RepoId::new("workspace"), directory.path(), limits())
                .expect("initial repository must validate");
        let (_repository, backing, namespace) = imported.into_parts();
        let file = namespace
            .object_at_path_snapshot(
                &CanonicalPath::new(["file.txt"]).expect("test path must be canonical"),
            )
            .expect("namespace must remain readable")
            .expect("file must be imported");
        let outside_before = fs::metadata(&outside_path)
            .expect("outside metadata must be readable")
            .modified()
            .expect("outside mtime must be representable");
        fs::remove_file(&file_path).expect("test file must be replaceable");
        symlink(&outside_path, &file_path).expect("replacement symlink must be creatable");

        let error = backing
            .set_runtime_timestamps(
                &file,
                MetadataTimes::new(None, Some(MetadataTime::Now))
                    .expect("mtime update is non-empty"),
            )
            .expect_err("replacement symlink must reject metadata mutation");

        assert!(matches!(error, RuntimeBackingError::Io { .. }));
        assert_eq!(
            fs::metadata(&outside_path)
                .expect("outside metadata must remain readable")
                .modified()
                .expect("outside mtime must remain representable"),
            outside_before
        );
    }

    #[test]
    fn runtime_open_rejects_a_symlink_substituted_after_preflight() {
        let directory = tempdir().expect("temporary repository must be creatable");
        let file_path = directory.path().join("notes.txt");
        fs::write(&file_path, b"safe").expect("test file must be writable");
        let imported =
            ImportedRepository::open(RepoId::new("workspace"), directory.path(), limits())
                .expect("initial regular file must validate");
        let (_repository, backing, namespace) = imported.into_parts();
        let path = CanonicalPath::new(["notes.txt"]).expect("test path must be canonical");
        let object = namespace
            .object_at_path_snapshot(&path)
            .expect("namespace must remain readable")
            .expect("manifest file must exist");

        fs::remove_file(&file_path).expect("test file must be replaceable");
        symlink("/etc/passwd", &file_path).expect("test symlink must be creatable");

        assert!(matches!(
            backing.open_runtime_file(&object),
            Err(RuntimeBackingError::Io { .. })
        ));
    }

    #[test]
    fn runtime_writable_open_rejects_a_symlink_substituted_after_preflight() {
        let directory = tempdir().expect("temporary repository must be creatable");
        let file_path = directory.path().join("notes.txt");
        fs::write(&file_path, b"safe").expect("test file must be writable");
        let imported =
            ImportedRepository::open(RepoId::new("workspace"), directory.path(), limits())
                .expect("initial regular file must validate");
        let (_repository, backing, namespace) = imported.into_parts();
        let path = CanonicalPath::new(["notes.txt"]).expect("test path must be canonical");
        let object = namespace
            .object_at_path_snapshot(&path)
            .expect("namespace must remain readable")
            .expect("manifest file must exist");

        fs::remove_file(&file_path).expect("test file must be replaceable");
        symlink("/etc/passwd", &file_path).expect("test symlink must be creatable");

        assert!(matches!(
            backing.open_runtime_writable_file(&object),
            Err(RuntimeBackingError::Io { .. })
        ));
    }

    #[test]
    fn runtime_metadata_rejects_a_hard_link_added_after_preflight() {
        let directory = tempdir().expect("temporary repository must be creatable");
        let file_path = directory.path().join("notes.txt");
        fs::write(&file_path, b"safe").expect("test file must be writable");
        let imported =
            ImportedRepository::open(RepoId::new("workspace"), directory.path(), limits())
                .expect("initial regular file must validate");
        let (_repository, backing, namespace) = imported.into_parts();
        let path = CanonicalPath::new(["notes.txt"]).expect("test path must be canonical");
        let object = namespace
            .object_at_path_snapshot(&path)
            .expect("namespace must remain readable")
            .expect("manifest file must exist");

        fs::hard_link(&file_path, directory.path().join("alias.txt"))
            .expect("test hard link must be creatable");

        assert!(matches!(
            backing.runtime_metadata(&object),
            Err(RuntimeBackingError::UnexpectedLinkCount {
                expected: 1,
                actual: 2,
                ..
            })
        ));
    }

    #[test]
    fn runtime_writable_open_rejects_a_hard_link_added_after_preflight() {
        let directory = tempdir().expect("temporary repository must be creatable");
        let file_path = directory.path().join("notes.txt");
        fs::write(&file_path, b"safe").expect("test file must be writable");
        let imported =
            ImportedRepository::open(RepoId::new("workspace"), directory.path(), limits())
                .expect("initial regular file must validate");
        let (_repository, backing, namespace) = imported.into_parts();
        let path = CanonicalPath::new(["notes.txt"]).expect("test path must be canonical");
        let object = namespace
            .object_at_path_snapshot(&path)
            .expect("namespace must remain readable")
            .expect("manifest file must exist");

        fs::hard_link(&file_path, directory.path().join("alias.txt"))
            .expect("test hard link must be creatable");

        assert!(matches!(
            backing.open_runtime_writable_file(&object),
            Err(RuntimeBackingError::UnexpectedLinkCount {
                expected: 1,
                actual: 2,
                ..
            })
        ));
    }

    #[test]
    fn runtime_writable_open_rejects_a_directory_object() {
        let directory = tempdir().expect("temporary repository must be creatable");
        let imported =
            ImportedRepository::open(RepoId::new("workspace"), directory.path(), limits())
                .expect("empty repository must validate");
        let (_repository, backing, namespace) = imported.into_parts();
        let object = namespace
            .object_at_path_snapshot(&CanonicalPath::root())
            .expect("namespace must remain readable")
            .expect("manifest root must exist");

        assert!(matches!(
            backing.open_runtime_writable_file(&object),
            Err(RuntimeBackingError::ObjectKindChanged {
                expected: NamespaceObjectKind::RegularFile,
                actual: Some(NamespaceObjectKind::Directory),
                ..
            })
        ));
    }

    // Requirement: a link created through capfs round-trips, and the registry's
    // record of the target is what a later read is checked against.
    #[test]
    fn runtime_symlink_creation_and_read_agree_with_the_namespace_record() {
        let directory = tempdir().expect("temporary repository must be creatable");
        fs::create_dir(directory.path().join("src")).expect("parent directory must be creatable");
        fs::write(directory.path().join("src/main.rs"), b"fn main() {}")
            .expect("target file must be writable");
        let imported =
            ImportedRepository::open(RepoId::new("workspace"), directory.path(), limits())
                .expect("repository must validate");
        let (_repository, backing, namespace) = imported.into_parts();
        let root = namespace
            .object_at_path_snapshot(&CanonicalPath::root())
            .expect("namespace must remain readable")
            .expect("root must be imported");
        let target = SymlinkTarget::new("src/main.rs").expect("target must be representable");

        let creation = namespace
            .create_child(
                root.id(),
                "entry.rs",
                NamespaceObjectSpec::Symlink(target.clone()),
                |live_parent, child| backing.create_runtime_symlink(live_parent, child, &target),
            )
            .expect("a contained symlink must be creatable");
        let (object, metadata) = creation.into_parts();
        assert_eq!(metadata.kind, NamespaceObjectKind::Symlink);
        assert_eq!(metadata.link_count, 1);
        assert!(
            fs::symlink_metadata(directory.path().join("entry.rs"))
                .expect("the link must exist")
                .file_type()
                .is_symlink()
        );

        let record = namespace
            .object_snapshot(&object)
            .expect("namespace must remain readable")
            .expect("the link must be live");
        assert_eq!(
            backing
                .read_runtime_symlink(&record)
                .expect("an unchanged link must read back"),
            "src/main.rs"
        );

        // A target rewritten outside capfs makes the registry and the backing
        // disagree, and neither value is served.
        fs::remove_file(directory.path().join("entry.rs")).expect("the link must be replaceable");
        symlink("/etc/passwd", directory.path().join("entry.rs"))
            .expect("a replacement link must be creatable");
        assert!(matches!(
            backing.read_runtime_symlink(&record),
            Err(RuntimeBackingError::SymlinkTargetChanged { .. })
        ));
    }

    // Requirement: a second name reaches the same inode, and the namespace's
    // name count is what the runtime validates the inode against afterwards.
    #[test]
    fn runtime_hard_link_creates_a_second_name_for_the_same_inode() {
        let directory = tempdir().expect("temporary repository must be creatable");
        fs::write(directory.path().join("original.txt"), b"shared")
            .expect("test file must be writable");
        let imported =
            ImportedRepository::open(RepoId::new("workspace"), directory.path(), limits())
                .expect("repository must validate");
        let (_repository, backing, namespace) = imported.into_parts();
        let root = namespace
            .object_at_path_snapshot(&CanonicalPath::root())
            .expect("namespace must remain readable")
            .expect("root must be imported");
        let source = namespace
            .object_at_path_snapshot(
                &CanonicalPath::new(["original.txt"]).expect("test path must be canonical"),
            )
            .expect("namespace must remain readable")
            .expect("the file must be imported");

        let metadata = namespace
            .link_child(
                root.id(),
                "alias.txt",
                source.id(),
                |live_parent, linked, link_path| {
                    backing.create_runtime_hard_link(
                        linked,
                        &CanonicalPath::new(["original.txt"]).expect("test path must be canonical"),
                        live_parent,
                        link_path,
                    )
                },
            )
            .expect("a second name must be creatable");
        assert_eq!(metadata.link_count, 2);
        assert_eq!(
            fs::read(directory.path().join("alias.txt")).expect("the alias must be readable"),
            b"shared"
        );

        // Both names now belong to one object, and the runtime accepts the
        // inode only because the registry expects exactly two of them.
        let linked = namespace
            .object_snapshot(source.id())
            .expect("namespace must remain readable")
            .expect("the file must be live");
        assert_eq!(linked.expected_link_count(), 2);
        backing
            .runtime_metadata(&linked)
            .expect("a two-name inode must validate against a two-name record");

        // A third name added outside capfs is still rejected.
        fs::hard_link(
            directory.path().join("original.txt"),
            directory.path().join("smuggled.txt"),
        )
        .expect("out-of-band hard link must be creatable");
        assert!(matches!(
            backing.runtime_metadata(&linked),
            Err(RuntimeBackingError::UnexpectedLinkCount {
                expected: 2,
                actual: 3,
                ..
            })
        ));
    }

    // Requirement: a directory can never gain a second name through capfs.
    #[test]
    fn runtime_hard_link_refuses_a_directory_source() {
        let directory = tempdir().expect("temporary repository must be creatable");
        fs::create_dir(directory.path().join("src")).expect("directory must be creatable");
        let imported =
            ImportedRepository::open(RepoId::new("workspace"), directory.path(), limits())
                .expect("repository must validate");
        let (_repository, _backing, namespace) = imported.into_parts();
        let root = namespace
            .object_at_path_snapshot(&CanonicalPath::root())
            .expect("namespace must remain readable")
            .expect("root must be imported");
        let source = namespace
            .object_at_path_snapshot(
                &CanonicalPath::new(["src"]).expect("test path must be canonical"),
            )
            .expect("namespace must remain readable")
            .expect("the directory must be imported");

        assert!(matches!(
            namespace.link_child(root.id(), "alias", source.id(), |_, _, _| Ok::<
                (),
                Infallible,
            >(())),
            Err(NamespaceOperationError::Namespace(
                NamespaceError::CannotAliasKind { .. }
            ))
        ));
        assert!(!directory.path().join("alias").exists());
    }
}
