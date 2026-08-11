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
    backing::{
        ImportedRepository, PreflightLimits, RejectedObjectKind, RepositoryPreflightError,
        RepositoryStartupError, ValidatedRepository,
    },
    namespace::{NamespaceGeneration, NamespaceObjectKind},
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

// Requirement: startup publishes one complete registry whose stable object IDs
// correspond to the validated manifest order. Category: startup/atomicity. Risk: critical.
#[test]
fn startup_imports_the_complete_manifest_with_registry_assigned_ids() {
    let repository = TempDir::new().expect("test repository should be creatable");
    fs::create_dir(repository.path().join("src")).expect("source directory should be creatable");
    write_file(repository.path().join("README.md"), b"readme");
    write_file(repository.path().join("src/lib.rs"), b"pub fn run() {}");

    let imported = ImportedRepository::open(repository.path(), limits(8, 3))
        .expect("link-free tree should import atomically");
    let expected = [
        (CanonicalPath::root(), NamespaceObjectKind::Directory),
        (path(&["README.md"]), NamespaceObjectKind::RegularFile),
        (path(&["src"]), NamespaceObjectKind::Directory),
        (path(&["src", "lib.rs"]), NamespaceObjectKind::RegularFile),
    ];

    assert_eq!(imported.namespace().object_count(), Ok(expected.len()));
    assert_eq!(
        imported
            .namespace()
            .generation()
            .map(NamespaceGeneration::as_u64),
        Ok(0)
    );
    for (sequence, (object_path, kind)) in expected.iter().enumerate() {
        let object = imported
            .namespace()
            .object_at_path_snapshot(object_path)
            .expect("imported registry should be readable")
            .expect("every manifest path should be imported");
        assert_eq!(object.id().as_str(), format!("object-{sequence}"));
        assert_eq!(object.kind(), *kind);
    }
    assert_eq!(imported.backing().canonical_root(), repository.path());
    assert_eq!(
        FileType::from_raw_mode(
            fstat(imported.backing().as_fd())
                .expect("imported root fd should remain valid")
                .st_mode
        ),
        FileType::Directory
    );
}

// Requirement: an invalid backing tree returns no partially initialized
// namespace owner. Category: startup/atomicity. Risk: critical.
#[test]
fn startup_propagates_preflight_failure_before_namespace_publication() {
    let repository = TempDir::new().expect("test repository should be creatable");
    symlink("outside", repository.path().join("entry-link"))
        .expect("entry symlink should be creatable");

    assert!(matches!(
        ImportedRepository::open(repository.path(), limits(4, 1)),
        Err(RepositoryStartupError::Preflight(
            RepositoryPreflightError::UnsupportedObject {
                kind: RejectedObjectKind::Symlink,
                ..
            }
        ))
    ));
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
