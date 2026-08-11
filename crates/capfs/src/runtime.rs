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
        AtFlags, FileType, Mode, OFlags, ResolveFlags, Statx, StatxFlags, StatxTimestamp, openat2,
        statx,
    },
    io::pread,
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

#[derive(Debug)]
pub(crate) struct OpenedBackingFile {
    fd: OwnedFd,
}

impl OpenedBackingFile {
    pub(crate) fn read_at(
        &self,
        offset: u64,
        requested_size: usize,
    ) -> Result<Vec<u8>, RuntimeBackingError> {
        let mut bytes = vec![0_u8; requested_size];
        let count = pread(&self.fd, bytes.as_mut_slice(), offset).map_err(|error| {
            RuntimeBackingError::Io {
                operation: "read",
                path: PathBuf::from("<opened-file>"),
                source: io::Error::from_raw_os_error(error.raw_os_error()),
            }
        })?;
        bytes.truncate(count);
        Ok(bytes)
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
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
            RESOLVE_WITHIN_ROOT,
        )
        .map_err(|error| runtime_io_error("open for reading", object.path(), error))?;
        let metadata = metadata_for_fd(&fd, object.path())?;
        validate_runtime_metadata(self, object, metadata)?;
        Ok(OpenedBackingFile { fd })
    }
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
    use std::{fs, num::NonZeroUsize, os::unix::fs::symlink};

    use tempfile::tempdir;

    use super::RuntimeBackingError;
    use crate::{
        backing::{ImportedRepository, PreflightLimits},
        namespace::NamespaceObjectKind,
    };
    use authority_core::path::CanonicalPath;

    fn limits() -> PreflightLimits {
        PreflightLimits::new(NonZeroUsize::new(16).expect("limit must be non-zero"), 4)
    }

    #[test]
    fn runtime_metadata_and_reads_stay_below_the_validated_root() {
        let directory = tempdir().expect("temporary repository must be creatable");
        fs::write(directory.path().join("notes.txt"), b"capability")
            .expect("test file must be writable");
        let imported = ImportedRepository::open(directory.path(), limits())
            .expect("link-free repository must validate");
        let (backing, namespace) = imported.into_parts();
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
    fn runtime_open_rejects_a_symlink_substituted_after_preflight() {
        let directory = tempdir().expect("temporary repository must be creatable");
        let file_path = directory.path().join("notes.txt");
        fs::write(&file_path, b"safe").expect("test file must be writable");
        let imported = ImportedRepository::open(directory.path(), limits())
            .expect("initial regular file must validate");
        let (backing, namespace) = imported.into_parts();
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
    fn runtime_metadata_rejects_a_hard_link_added_after_preflight() {
        let directory = tempdir().expect("temporary repository must be creatable");
        let file_path = directory.path().join("notes.txt");
        fs::write(&file_path, b"safe").expect("test file must be writable");
        let imported = ImportedRepository::open(directory.path(), limits())
            .expect("initial regular file must validate");
        let (backing, namespace) = imported.into_parts();
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
}
