//! Contract tests for repository preflight validation.

#![cfg(target_os = "linux")]

use std::{
    convert::Infallible,
    ffi::OsString,
    fs::{self, File, hard_link},
    io::Write,
    num::NonZeroUsize,
    os::unix::{
        ffi::OsStringExt,
        fs::{MetadataExt, PermissionsExt, symlink},
        net::UnixListener,
    },
};

use authority_core::{path::CanonicalPath, repository::RepoId};
use capfs::{
    backing::{
        ImportedRepository, PreflightLimits, RejectedObjectKind, RepositoryEntry,
        RepositoryPreflightError, RepositoryStartupError, ValidatedRepository,
    },
    namespace::{NamespaceGeneration, NamespaceObjectKind, SymlinkTarget},
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
        .expect("a plain tree should pass preflight");
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

    let repository_id = RepoId::new("workspace");
    let imported = ImportedRepository::open(repository_id.clone(), repository.path(), limits(8, 3))
        .expect("a plain tree should import atomically");
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
    assert_eq!(imported.repository(), &repository_id);
    assert_eq!(
        FileType::from_raw_mode(
            fstat(imported.backing().as_fd())
                .expect("imported root fd should remain valid")
                .st_mode
        ),
        FileType::Directory
    );
}

// Requirement: independently constructed subject mounts for one workspace
// observe one namespace and retain the same anchored backing root. Category:
// mount/identity. Risk: critical.
#[test]
fn cloned_imports_share_the_workspace_state_for_multiple_mounts() {
    let repository = TempDir::new().expect("test repository should be creatable");
    write_file(repository.path().join("existing.txt"), b"existing");
    let first_mount =
        ImportedRepository::open(RepoId::new("workspace"), repository.path(), limits(8, 1))
            .expect("a plain tree should import atomically");
    let second_mount = first_mount.clone();

    let existing_path = path(&["existing.txt"]);
    let existing = first_mount
        .namespace()
        .object_at_path_snapshot(&existing_path)
        .expect("first mount registry must remain readable")
        .expect("manifest file must exist");
    first_mount
        .namespace()
        .open_object(existing.id(), |_| Ok::<_, Infallible>(()))
        .expect("first mount must register its open in the shared registry");

    let observed = second_mount
        .namespace()
        .object_at_path_snapshot(&existing_path)
        .expect("second mount registry must remain readable")
        .expect("second mount must observe the shared object");
    assert_eq!(observed.id(), existing.id());
    assert_eq!(observed.open_handle_count(), 1);
    second_mount
        .namespace()
        .close_object(existing.id(), |_| Ok::<_, Infallible>(()))
        .expect("a second mount must close the shared open count");
    drop(first_mount);
    assert_eq!(
        second_mount.backing().canonical_root(),
        repository.path(),
        "a remaining mount must retain the shared backing root fd"
    );
}

// Requirement: an invalid backing tree returns no partially initialized
// namespace owner. Category: startup/atomicity. Risk: critical.
#[test]
fn startup_propagates_preflight_failure_before_namespace_publication() {
    let repository = TempDir::new().expect("test repository should be creatable");
    symlink("../outside", repository.path().join("entry-link"))
        .expect("entry symlink should be creatable");

    assert!(matches!(
        ImportedRepository::open(RepoId::new("workspace"), repository.path(), limits(4, 1)),
        Err(RepositoryStartupError::Preflight(
            RepositoryPreflightError::EscapingSymlinkTarget { .. }
        ))
    ));
}

// Requirement: the configured root itself must be a real directory, never a
// symlink standing in for one. Category: backing/security. Risk: critical.
#[test]
fn preflight_rejects_a_symlinked_root() {
    let parent = TempDir::new().expect("test parent should be creatable");
    let real_root = parent.path().join("real");
    fs::create_dir(&real_root).expect("real root should be creatable");
    let linked_root = parent.path().join("linked");
    symlink(&real_root, &linked_root).expect("root symlink should be creatable");

    assert!(matches!(
        ValidatedRepository::open(&linked_root, limits(4, 2)),
        Err(RepositoryPreflightError::RootNotDirectory(_))
    ));
}

// Requirement: a symlink whose target stays inside the repository is imported
// with that target; one that leaves is refused for the whole repository.
// Category: backing/security. Risk: critical.
#[test]
fn preflight_imports_contained_symlinks_and_rejects_escaping_ones() {
    let repository = TempDir::new().expect("test repository should be creatable");
    fs::create_dir(repository.path().join("src")).expect("directory should be creatable");
    write_file(repository.path().join("src/main.rs"), b"fn main() {}");
    symlink("src/main.rs", repository.path().join("entry.rs"))
        .expect("relative symlink should be creatable");
    symlink("../main.rs", repository.path().join("src/self.rs"))
        .expect("parent-relative symlink should be creatable");

    let validated = ValidatedRepository::open(repository.path(), limits(8, 2))
        .expect("contained symlinks must import");
    let link = validated
        .entries()
        .iter()
        .find(|entry| entry.path() == &path(&["entry.rs"]))
        .expect("the symlink must appear in the manifest");
    assert_eq!(link.kind(), NamespaceObjectKind::Symlink);
    assert_eq!(
        link.spec().target().map(SymlinkTarget::as_str),
        Some("src/main.rs")
    );

    let absolute = TempDir::new().expect("test repository should be creatable");
    symlink("/etc/passwd", absolute.path().join("absolute"))
        .expect("absolute symlink should be creatable");
    assert!(matches!(
        ValidatedRepository::open(absolute.path(), limits(4, 1)),
        Err(RepositoryPreflightError::UnsupportedSymlinkTarget { .. })
    ));

    let escaping = TempDir::new().expect("test repository should be creatable");
    symlink("../../etc/passwd", escaping.path().join("escape"))
        .expect("escaping symlink should be creatable");
    assert!(matches!(
        ValidatedRepository::open(escaping.path(), limits(4, 1)),
        Err(RepositoryPreflightError::EscapingSymlinkTarget { .. })
    ));
}

// Requirement: an inode may keep several names only when the repository holds
// all of them. Category: backing/security. Risk: critical.
#[test]
fn preflight_imports_complete_hard_link_sets_and_rejects_external_aliases() {
    let repository = TempDir::new().expect("test repository should be creatable");
    let original = repository.path().join("original.rs");
    write_file(&original, b"fn original() {}");
    hard_link(&original, repository.path().join("alias.rs"))
        .expect("hard-link alias should be creatable");

    let validated = ValidatedRepository::open(repository.path(), limits(4, 1))
        .expect("a fully contained alias set must import");
    let inodes = validated
        .entries()
        .iter()
        .filter(|entry| entry.kind() == NamespaceObjectKind::RegularFile)
        .map(RepositoryEntry::inode)
        .collect::<Vec<_>>();
    assert_eq!(inodes.len(), 2);
    assert_eq!(
        inodes.first(),
        inodes.last(),
        "both names must report the same inode so the import groups them"
    );

    let parent = TempDir::new().expect("test parent should be creatable");
    let contained = parent.path().join("repository");
    fs::create_dir(&contained).expect("repository should be creatable");
    let inside = contained.join("inside.rs");
    write_file(&inside, b"fn inside() {}");
    let outside = parent.path().join("outside-alias.rs");
    hard_link(&inside, &outside).expect("out-of-repository alias should be creatable");

    let rejected = ValidatedRepository::open(&contained, limits(4, 1).rejecting_external_aliases())
        .expect_err("the strict policy must refuse an inode named outside the repository");
    match rejected {
        RepositoryPreflightError::ExternalHardLink {
            link_count,
            names_in_repository,
            ..
        } => {
            assert_eq!(link_count, 2);
            assert_eq!(names_in_repository, vec![path(&["inside.rs"])]);
        }
        other => panic!("expected an external hard link rejection, got {other:?}"),
    }
}

// Requirement: the default policy repairs an inode named outside the repository
// by giving the repository its own copy, instead of refusing the whole
// workspace. The outside name keeps the original inode.
// Category: backing/security. Risk: critical.
#[test]
fn preflight_materializes_an_externally_aliased_inode_into_the_repository() {
    let parent = TempDir::new().expect("test parent should be creatable");
    let contained = parent.path().join("repository");
    fs::create_dir(&contained).expect("repository should be creatable");
    let inside = contained.join("inside.rs");
    write_file(&inside, b"fn inside() {}");
    fs::set_permissions(&inside, fs::Permissions::from_mode(0o640))
        .expect("test permissions should be settable");
    // A second repository name for the same inode must survive as an alias of
    // the copy: only the boundary-crossing relationship is broken.
    hard_link(&inside, contained.join("also-inside.rs"))
        .expect("in-repository alias should be creatable");
    let outside = parent.path().join("outside-alias.rs");
    hard_link(&inside, &outside).expect("out-of-repository alias should be creatable");
    let original_inode = fs::metadata(&outside)
        .expect("the outside name should be readable")
        .ino();

    let validated = ValidatedRepository::open(&contained, limits(8, 1))
        .expect("the default policy must repair the repository instead of refusing it");

    let reported = validated.materialized_aliases();
    assert_eq!(reported.len(), 1, "one inode was repaired: {reported:?}");
    assert_eq!(reported[0].path(), &path(&["also-inside.rs"]));
    assert_eq!(reported[0].bytes(), 14, "the copied byte count is reported");
    assert_eq!(reported[0].additional_names(), 1);

    let repaired = fs::metadata(&inside).expect("the repository name should still exist");
    let sibling = fs::metadata(contained.join("also-inside.rs"))
        .expect("the second repository name should still exist");
    assert_eq!(
        repaired.ino(),
        sibling.ino(),
        "names that aliased each other inside the repository must stay aliases"
    );
    assert_eq!(
        repaired.nlink(),
        2,
        "the copy must have exactly its two repository names"
    );
    assert_ne!(
        repaired.ino(),
        original_inode,
        "the repository must no longer share the inode named outside it"
    );
    assert_eq!(
        fs::read(&inside).expect("the copy should be readable"),
        b"fn inside() {}"
    );
    assert_eq!(repaired.permissions().mode() & 0o7777, 0o640);

    let untouched = fs::metadata(&outside).expect("the outside name should still exist");
    assert_eq!(
        untouched.ino(),
        original_inode,
        "the outside name keeps its inode"
    );
    assert_eq!(
        untouched.nlink(),
        1,
        "the outside name is now the inode's only name"
    );
    assert_eq!(
        fs::read(&outside).expect("the outside file should be readable"),
        b"fn inside() {}"
    );

    // The manifest describes the repaired tree, so both repository names group
    // onto one object and the registry accepts them.
    let inodes = validated
        .entries()
        .iter()
        .filter(|entry| entry.kind() == NamespaceObjectKind::RegularFile)
        .map(RepositoryEntry::inode)
        .collect::<Vec<_>>();
    assert_eq!(inodes, vec![repaired.ino(), repaired.ino()]);
    ImportedRepository::from_validated(RepoId::new("workspace"), validated)
        .expect("the repaired manifest must import");
}

// Requirement: repairing an external hard link is bounded, and a refusal
// leaves the tree as it was. Category: backing/resource. Risk: high.
#[test]
fn preflight_refuses_to_copy_more_than_its_budget_allows() {
    let parent = TempDir::new().expect("test parent should be creatable");
    let contained = parent.path().join("repository");
    fs::create_dir(&contained).expect("repository should be creatable");
    let inside = contained.join("large.bin");
    write_file(&inside, &vec![0_u8; 4096]);
    let outside = parent.path().join("outside-alias.bin");
    hard_link(&inside, &outside).expect("out-of-repository alias should be creatable");
    let original_inode = fs::metadata(&inside)
        .expect("the repository name should be readable")
        .ino();

    let error = ValidatedRepository::open(&contained, limits(4, 1).with_external_alias_bytes(1024))
        .expect_err("a copy larger than the budget must be refused");
    assert!(
        matches!(
            error,
            RepositoryPreflightError::MaterializationBudgetExceeded {
                required: 4096,
                remaining: 1024,
                ..
            }
        ),
        "unexpected error: {error:?}"
    );
    assert_eq!(
        fs::metadata(&inside)
            .expect("the repository name should be unchanged")
            .ino(),
        original_inode,
        "a refused repair must not replace the inode"
    );
    assert_eq!(
        fs::read_dir(&contained)
            .expect("the repository should be readable")
            .count(),
        1,
        "a refused repair must not leave a replacement behind"
    );
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
