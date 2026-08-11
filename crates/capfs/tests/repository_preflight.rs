//! Contract tests for link-free repository preflight validation.

#![cfg(target_os = "linux")]

use std::{
    ffi::OsString,
    fs::{self, File, hard_link},
    io::Write,
    num::NonZeroUsize,
    os::unix::{ffi::OsStringExt, fs::symlink, net::UnixListener},
};

use authority_core::path::CanonicalPath;
use capfs::{
    backing::{PreflightLimits, RejectedObjectKind, RepositoryPreflightError, ValidatedRepository},
    namespace::NamespaceObjectKind,
};
use rustix::fs::{Dir, FileType, fstat};
use tempfile::TempDir;

fn limits(max_entries: usize, max_depth: usize) -> PreflightLimits {
    PreflightLimits::new(
        NonZeroUsize::new(max_entries).expect("test entry limits must be nonzero"),
        max_depth,
    )
}

fn path(segments: &[&str]) -> CanonicalPath {
    CanonicalPath::new(segments).expect("test paths must be canonical")
}

fn write_file(path: impl AsRef<std::path::Path>, contents: &[u8]) {
    let mut file = File::create(path).expect("test file should be creatable");
    file.write_all(contents)
        .expect("test file contents should be writable");
}

// Requirement: a regular file cannot be used as the namespace root.
// Category: backing/identity. Risk: high.
#[test]
fn preflight_requires_a_directory_root() {
    let parent = TempDir::new().expect("test parent should be creatable");
    let root = parent.path().join("not-a-directory");
    write_file(&root, b"data");

    assert!(matches!(
        ValidatedRepository::open(&root, limits(1, 0)),
        Err(RepositoryPreflightError::RootNotDirectory(path)) if path == root
    ));
}

// Requirement: a validated root owns a directory fd and returns one stable,
// path-sorted manifest containing only directories and regular files.
// Category: backing/security. Risk: critical.
#[test]
fn preflight_accepts_a_link_free_tree_and_keeps_the_root_fd() {
    let repository = TempDir::new().expect("test repository should be creatable");
    fs::create_dir(repository.path().join("src")).expect("source directory should be creatable");
    write_file(repository.path().join("README.md"), b"readme");
    write_file(repository.path().join("src/lib.rs"), b"pub fn run() {}");

    let validated = ValidatedRepository::open(repository.path(), limits(8, 3))
        .expect("link-free tree should pass preflight");
    let manifest = validated
        .entries()
        .iter()
        .map(|entry| (entry.path().clone(), entry.kind()))
        .collect::<Vec<_>>();

    assert_eq!(
        manifest,
        [
            (CanonicalPath::root(), NamespaceObjectKind::Directory),
            (path(&["README.md"]), NamespaceObjectKind::RegularFile),
            (path(&["src"]), NamespaceObjectKind::Directory),
            (path(&["src", "lib.rs"]), NamespaceObjectKind::RegularFile,),
        ]
    );
    assert_eq!(validated.canonical_root(), repository.path());
    let _root_mount_id = validated.root_mount_id();
    assert_eq!(
        FileType::from_raw_mode(
            fstat(validated.as_fd())
                .expect("root fd should remain valid")
                .st_mode
        ),
        FileType::Directory
    );
    let entries = Dir::read_from(validated.as_fd())
        .expect("root fd should remain readable")
        .filter_map(Result::ok)
        .count();
    assert!(
        entries >= 4,
        "directory stream includes dot entries and repository objects"
    );
}

// Requirement: neither the configured root nor any entry may be a symlink.
// Category: backing/security. Risk: critical.
#[test]
fn preflight_rejects_root_and_entry_symlinks() {
    let parent = TempDir::new().expect("test parent should be creatable");
    let real_root = parent.path().join("real");
    fs::create_dir(&real_root).expect("real root should be creatable");
    let linked_root = parent.path().join("linked");
    symlink(&real_root, &linked_root).expect("root symlink should be creatable");

    assert!(matches!(
        ValidatedRepository::open(&linked_root, limits(4, 2)),
        Err(RepositoryPreflightError::UnsupportedObject {
            kind: RejectedObjectKind::Symlink,
            ..
        })
    ));

    symlink("outside", real_root.join("entry-link")).expect("entry symlink should be creatable");
    assert!(matches!(
        ValidatedRepository::open(&real_root, limits(4, 2)),
        Err(RepositoryPreflightError::UnsupportedObject {
            kind: RejectedObjectKind::Symlink,
            ..
        })
    ));
}

// Requirement: a regular inode must have exactly one path in the initial tree.
// Category: backing/security. Risk: critical.
#[test]
fn preflight_rejects_hard_link_aliases() {
    let repository = TempDir::new().expect("test repository should be creatable");
    let original = repository.path().join("original.rs");
    write_file(&original, b"fn original() {}");
    hard_link(&original, repository.path().join("alias.rs"))
        .expect("hard-link alias should be creatable");

    assert!(matches!(
        ValidatedRepository::open(repository.path(), limits(4, 1)),
        Err(RepositoryPreflightError::HardLink { link_count: 2, .. })
    ));
}

// Requirement: sockets and every other non-file/non-directory object fail
// closed before a manifest is returned. Category: backing/security. Risk: critical.
#[test]
fn preflight_rejects_special_files() {
    let repository = TempDir::new().expect("test repository should be creatable");
    let _socket = UnixListener::bind(repository.path().join("control.sock"))
        .expect("test socket should be bindable");

    assert!(matches!(
        ValidatedRepository::open(repository.path(), limits(4, 1)),
        Err(RepositoryPreflightError::UnsupportedObject {
            kind: RejectedObjectKind::Socket,
            ..
        })
    ));
}

// Requirement: every imported name must fit the same UTF-8 canonical segment
// type used by Authority. Category: backing/identity. Risk: critical.
#[test]
fn preflight_rejects_non_utf8_and_invalid_canonical_names() {
    let non_utf8_repository = TempDir::new().expect("test repository should be creatable");
    let non_utf8 = OsString::from_vec(vec![b'n', b'a', b'm', b'e', 0xff]);
    write_file(non_utf8_repository.path().join(non_utf8), b"data");
    assert!(matches!(
        ValidatedRepository::open(non_utf8_repository.path(), limits(4, 1)),
        Err(RepositoryPreflightError::NonUtf8Name { .. })
    ));

    let wildcard_repository = TempDir::new().expect("test repository should be creatable");
    write_file(wildcard_repository.path().join("*.rs"), b"data");
    assert!(matches!(
        ValidatedRepository::open(wildcard_repository.path(), limits(4, 1)),
        Err(RepositoryPreflightError::InvalidCanonicalPath { .. })
    ));
}

// Requirement: attacker-controlled tree size and depth cannot force unbounded
// manifest memory or recursive stack use. Category: backing/availability. Risk: high.
#[test]
fn preflight_enforces_entry_and_depth_limits() {
    let repository = TempDir::new().expect("test repository should be creatable");
    write_file(repository.path().join("one"), b"1");
    write_file(repository.path().join("two"), b"2");
    assert!(matches!(
        ValidatedRepository::open(repository.path(), limits(2, 1)),
        Err(RepositoryPreflightError::EntryLimitExceeded(_))
    ));

    let deep_repository = TempDir::new().expect("test repository should be creatable");
    fs::create_dir_all(deep_repository.path().join("one/two"))
        .expect("deep directory should be creatable");
    assert!(matches!(
        ValidatedRepository::open(deep_repository.path(), limits(4, 1)),
        Err(RepositoryPreflightError::DepthLimitExceeded { limit: 1, .. })
    ));
}
