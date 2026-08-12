//! Descriptor-relative runtime access to a validated backing repository.

use std::{
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
        AtFlags, FileType, Mode, OFlags, ResolveFlags, Statx, StatxFlags, StatxTimestamp, fchmod,
        ftruncate, mkdirat, openat2, statx, unlinkat,
    },
    io::{fcntl_dupfd_cloexec, pread, pwrite},
};

use crate::{
    backing::ValidatedRepository,
    namespace::{NamespaceObject, NamespaceObjectKind},
};

const REQUIRED_METADATA: StatxFlags = StatxFlags::BASIC_STATS.union(StatxFlags::MNT_ID);
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
    HardLinkAppeared {
        path: CanonicalPath,
        link_count: u32,
    },
    NestedMount(CanonicalPath),
    TimestampOutOfRange(CanonicalPath),
    #[allow(dead_code)]
    CreationPathNotDirectChild {
        parent: CanonicalPath,
        child: CanonicalPath,
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
            Self::HardLinkAppeared { path, link_count } => write!(
                formatter,
                "backing file `{}` now has {link_count} hard links",
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
            Self::CreationPathNotDirectChild { parent, child } => write!(
                formatter,
                "backing creation path `{}` is not a direct child of `{}`",
                DisplayCanonicalPath(child),
                DisplayCanonicalPath(parent)
            ),
        }
    }
}

impl Error for RuntimeBackingError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
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
        let path = object.path();
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
        .map_err(|error| runtime_io_error("create regular file", child.path(), error))?;

        let result = (|| {
            fchmod(&fd, permissions.mode()).map_err(|error| {
                runtime_io_error("set creation permissions", child.path(), error)
            })?;
            let metadata =
                validate_runtime_metadata(self, child, metadata_for_fd(&fd, child.path())?)?;
            Ok((
                OpenedBackingFile {
                    fd,
                    path: child.path().clone(),
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
            .map_err(|error| runtime_io_error("create directory", child.path(), error))?;

        let result = (|| {
            let child_fd = openat2(
                &parent_fd,
                child_name,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                Mode::empty(),
                RESOLVE_WITHIN_ROOT,
            )
            .map_err(|error| runtime_io_error("open created directory", child.path(), error))?;
            fchmod(&child_fd, permissions.mode()).map_err(|error| {
                runtime_io_error("set creation permissions", child.path(), error)
            })?;
            validate_runtime_metadata(self, child, metadata_for_fd(&child_fd, child.path())?)
        })();

        rollback_created_entry_on_error(&parent_fd, child, child_name, AtFlags::REMOVEDIR, result)
    }

    fn open_runtime_file_with_access(
        &self,
        object: &NamespaceObject,
        access: RuntimeFileAccess,
    ) -> Result<OpenedBackingFile, RuntimeBackingError> {
        if object.kind() != NamespaceObjectKind::RegularFile {
            return Err(RuntimeBackingError::ObjectKindChanged {
                path: object.path().clone(),
                expected: NamespaceObjectKind::RegularFile,
                actual: Some(object.kind()),
            });
        }
        let fd = openat2(
            self.as_fd(),
            path_buf(object.path()),
            access.open_flags() | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
            RESOLVE_WITHIN_ROOT,
        )
        .map_err(|error| runtime_io_error(access.operation(), object.path(), error))?;
        let metadata = metadata_for_fd(&fd, object.path())?;
        validate_runtime_metadata(self, object, metadata)?;
        Ok(OpenedBackingFile {
            fd,
            path: object.path().clone(),
        })
    }

    fn open_runtime_directory(
        &self,
        object: &NamespaceObject,
    ) -> Result<OwnedFd, RuntimeBackingError> {
        if object.kind() != NamespaceObjectKind::Directory {
            return Err(RuntimeBackingError::ObjectKindChanged {
                path: object.path().clone(),
                expected: NamespaceObjectKind::Directory,
                actual: Some(object.kind()),
            });
        }
        let fd = if object.path().is_root() {
            fcntl_dupfd_cloexec(self.as_fd(), 0).map_err(|error| {
                runtime_io_error("duplicate root directory", object.path(), error)
            })?
        } else {
            openat2(
                self.as_fd(),
                path_buf(object.path()),
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                Mode::empty(),
                RESOLVE_WITHIN_ROOT,
            )
            .map_err(|error| runtime_io_error("open parent directory", object.path(), error))?
        };
        validate_runtime_metadata(self, object, metadata_for_fd(&fd, object.path())?)?;
        Ok(fd)
    }
}

#[allow(dead_code)]
fn validate_creation_objects<'a>(
    parent: &NamespaceObject,
    child: &'a NamespaceObject,
    expected_kind: NamespaceObjectKind,
) -> Result<&'a str, RuntimeBackingError> {
    if parent.kind() != NamespaceObjectKind::Directory {
        return Err(RuntimeBackingError::ObjectKindChanged {
            path: parent.path().clone(),
            expected: NamespaceObjectKind::Directory,
            actual: Some(parent.kind()),
        });
    }
    if child.kind() != expected_kind {
        return Err(RuntimeBackingError::ObjectKindChanged {
            path: child.path().clone(),
            expected: expected_kind,
            actual: Some(child.kind()),
        });
    }
    if child.path().parent().as_ref() != Some(parent.path()) {
        return Err(RuntimeBackingError::CreationPathNotDirectChild {
            parent: parent.path().clone(),
            child: child.path().clone(),
        });
    }
    child
        .path()
        .as_segments()
        .last()
        .map(String::as_str)
        .ok_or_else(|| RuntimeBackingError::CreationPathNotDirectChild {
            parent: parent.path().clone(),
            child: child.path().clone(),
        })
}

#[allow(dead_code)]
fn rollback_created_entry_on_error<T>(
    parent_fd: &OwnedFd,
    child: &NamespaceObject,
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
            DisplayCanonicalPath(child.path()),
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
    let path = object.path();
    let actual_kind = namespace_kind(FileType::from_raw_mode(metadata.stx_mode.into()));
    if actual_kind != Some(object.kind()) {
        return Err(RuntimeBackingError::ObjectKindChanged {
            path: path.clone(),
            expected: object.kind(),
            actual: actual_kind,
        });
    }
    if metadata.stx_mnt_id != repository.root_mount_id() {
        return Err(RuntimeBackingError::NestedMount(path.clone()));
    }
    if object.kind() == NamespaceObjectKind::RegularFile && metadata.stx_nlink != 1 {
        return Err(RuntimeBackingError::HardLinkAppeared {
            path: path.clone(),
            link_count: metadata.stx_nlink,
        });
    }

    Ok(BackingMetadata {
        size: metadata.stx_size,
        blocks: metadata.stx_blocks,
        atime: system_time(metadata.stx_atime, path)?,
        mtime: system_time(metadata.stx_mtime, path)?,
        ctime: system_time(metadata.stx_ctime, path)?,
        kind: object.kind(),
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

const fn namespace_kind(kind: FileType) -> Option<NamespaceObjectKind> {
    match kind {
        FileType::Directory => Some(NamespaceObjectKind::Directory),
        FileType::RegularFile => Some(NamespaceObjectKind::RegularFile),
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
        fs,
        num::NonZeroUsize,
        os::unix::fs::{PermissionsExt, symlink},
        path::PathBuf,
    };

    use rustix::fs::AtFlags;
    use tempfile::tempdir;

    use super::{CreationPermissions, RuntimeBackingError, rollback_created_entry_on_error};
    use crate::{
        backing::{ImportedRepository, PreflightLimits},
        namespace::{NamespaceObjectKind, NamespaceOperationError},
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
                NamespaceObjectKind::RegularFile,
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
                NamespaceObjectKind::Directory,
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
                NamespaceObjectKind::RegularFile,
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
                NamespaceObjectKind::Directory,
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
                NamespaceObjectKind::RegularFile,
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
                NamespaceObjectKind::RegularFile,
                |live_parent, child| {
                    let parent_fd = backing.open_runtime_directory(live_parent)?;
                    fs::write(directory.path().join("rolled-back.txt"), b"uncommitted")
                        .expect("test backing entry must be creatable");
                    rollback_created_entry_on_error(
                        &parent_fd,
                        child,
                        "rolled-back.txt",
                        AtFlags::empty(),
                        Err::<(), _>(RuntimeBackingError::CreationPathNotDirectChild {
                            parent: CanonicalPath::root(),
                            child: child.path().clone(),
                        }),
                    )
                },
            )
            .expect_err("post-create validation failure must abort the transaction");
        assert!(matches!(
            error,
            NamespaceOperationError::Executor(
                RuntimeBackingError::CreationPathNotDirectChild { .. }
            )
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
                NamespaceObjectKind::RegularFile,
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
            NamespaceOperationError::Executor(
                RuntimeBackingError::CreationPathNotDirectChild { .. }
            )
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
                NamespaceObjectKind::RegularFile,
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
            Err(RuntimeBackingError::HardLinkAppeared { link_count: 2, .. })
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
            Err(RuntimeBackingError::HardLinkAppeared { link_count: 2, .. })
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
}
