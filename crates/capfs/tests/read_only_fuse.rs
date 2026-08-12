//! Linux FUSE contract test for read-after-revoke behavior.

#![cfg(target_os = "linux")]

use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    mem::MaybeUninit,
    num::NonZeroUsize,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::Path,
    sync::Arc,
};

use authority_core::{
    capability::{AuthorityBody, CapId, IssuerId, SubjectId},
    file::{FileAuthority, FileEffect, FileEffects},
    kernel::CapabilityKernel,
    path::{CanonicalPath, PathPattern},
    repository::RepoId,
    state::{CapabilityGrant, CapabilityState, StaticAuthorityEnvelope, Subject},
    time::{MonotonicTime, TimeWindow},
};
use capfs::{
    backing::{ImportedRepository, PreflightLimits},
    filesystem::{CapabilityFilesystem, MountAuthority, MountInstanceId, spawn_mount},
};
use fuser::BackgroundSession;
use rustix::fs::{AtFlags, FileType, Mode, OFlags, RawDir, mkdirat, mknodat, open, unlinkat};
use tempfile::tempdir;

type MountedDirectoryView = (
    tempfile::TempDir,
    tempfile::TempDir,
    Arc<CapabilityKernel>,
    SubjectId,
    CapId,
    BackgroundSession,
);

fn mount_directory_view() -> MountedDirectoryView {
    let backing = tempdir().expect("temporary backing directory must be creatable");
    let mountpoint = tempdir().expect("temporary mountpoint must be creatable");
    fs::create_dir(backing.path().join("scoped"))
        .expect("authorized backing directory must be creatable");
    fs::write(backing.path().join("scoped/zeta.txt"), b"zeta")
        .expect("authorized backing file must be writable");
    fs::write(backing.path().join("scoped/alpha.txt"), b"alpha")
        .expect("authorized backing file must be writable");
    fs::write(backing.path().join("hidden.txt"), b"hidden")
        .expect("hidden backing file must be writable");
    let repository = RepoId::new("workspace");
    let imported = ImportedRepository::open(
        repository.clone(),
        backing.path(),
        PreflightLimits::new(NonZeroUsize::new(16).expect("limit must be non-zero"), 2),
    )
    .expect("test backing must pass preflight");

    let subject = SubjectId::new("fuse-directory-subject");
    let validity = TimeWindow::new(MonotonicTime::from_ticks(0), MonotonicTime::from_ticks(10))
        .expect("test validity must be non-empty");
    let kernel = Arc::new(CapabilityKernel::new(CapabilityState::new(IssuerId::new(
        "fuse-directory-session",
    ))));
    let authority = AuthorityBody::File(FileAuthority::new(
        repository.clone(),
        FileEffects::from_effects([
            FileEffect::ListDirectory,
            FileEffect::CreateFile,
            FileEffect::WriteData,
        ]),
        PathPattern::Prefix(CanonicalPath::root()),
    ));
    kernel
        .register_subject(Subject::new(
            subject.clone(),
            StaticAuthorityEnvelope::new(validity, authority),
        ))
        .expect("test subject registration must succeed");
    let capability = kernel
        .issue_root(CapabilityGrant::new(
            subject.clone(),
            validity,
            AuthorityBody::File(FileAuthority::new(
                repository.clone(),
                FileEffects::from_effects([
                    FileEffect::ListDirectory,
                    FileEffect::CreateFile,
                    FileEffect::WriteData,
                ]),
                PathPattern::Prefix(
                    CanonicalPath::new(["scoped"]).expect("test path must be canonical"),
                ),
            )),
        ))
        .expect("test capability issuance must succeed");
    let filesystem = CapabilityFilesystem::new(
        imported,
        Arc::clone(&kernel),
        MountAuthority::new(
            MountInstanceId::new("fuse-directory-integration"),
            subject.clone(),
            capability.clone(),
            repository,
        ),
        Arc::new(MonotonicTime::from_ticks(5)),
    )
    .expect("read-only filesystem must initialize");
    let session = spawn_mount(filesystem, mountpoint.path()).expect("FUSE mount must succeed");

    (backing, mountpoint, kernel, subject, capability, session)
}

// Requirement: direct I/O must route a read on an already-open descriptor back
// through capability authorization after revoke. Category: FUSE/security. Risk: critical.
#[test]
fn mounted_read_only_view_denies_read_after_revoke() {
    if !Path::new("/dev/fuse").exists() {
        eprintln!("skipping FUSE integration test because /dev/fuse is unavailable");
        return;
    }

    let backing = tempdir().expect("temporary backing directory must be creatable");
    let mountpoint = tempdir().expect("temporary mountpoint must be creatable");
    fs::write(backing.path().join("allowed.txt"), b"capability")
        .expect("authorized backing file must be writable");
    fs::write(backing.path().join("hidden.txt"), b"hidden")
        .expect("hidden backing file must be writable");
    let imported = ImportedRepository::open(
        RepoId::new("workspace"),
        backing.path(),
        PreflightLimits::new(NonZeroUsize::new(16).expect("limit must be non-zero"), 2),
    )
    .expect("test backing must pass preflight");

    let subject = SubjectId::new("fuse-subject");
    let repository = RepoId::new("workspace");
    let validity = TimeWindow::new(MonotonicTime::from_ticks(0), MonotonicTime::from_ticks(10))
        .expect("test validity must be non-empty");
    let kernel = Arc::new(CapabilityKernel::new(CapabilityState::new(IssuerId::new(
        "fuse-session",
    ))));
    kernel
        .register_subject(Subject::new(
            subject.clone(),
            StaticAuthorityEnvelope::new(
                validity,
                AuthorityBody::File(FileAuthority::new(
                    repository.clone(),
                    FileEffects::only(FileEffect::ReadData),
                    PathPattern::Prefix(CanonicalPath::root()),
                )),
            ),
        ))
        .expect("test subject registration must succeed");
    let allowed_path = CanonicalPath::new(["allowed.txt"]).expect("test path must be canonical");
    let capability = kernel
        .issue_root(CapabilityGrant::new(
            subject.clone(),
            validity,
            AuthorityBody::File(FileAuthority::new(
                repository.clone(),
                FileEffects::only(FileEffect::ReadData),
                PathPattern::Exact(allowed_path),
            )),
        ))
        .expect("test capability issuance must succeed");
    let filesystem = CapabilityFilesystem::new(
        imported,
        Arc::clone(&kernel),
        MountAuthority::new(
            MountInstanceId::new("fuse-integration"),
            subject.clone(),
            capability.clone(),
            repository,
        ),
        Arc::new(MonotonicTime::from_ticks(5)),
    )
    .expect("read-only filesystem must initialize");
    let session = spawn_mount(filesystem, mountpoint.path()).expect("FUSE mount must succeed");

    assert_eq!(
        fs::metadata(mountpoint.path().join("hidden.txt"))
            .expect_err("a sibling outside authority must be hidden")
            .kind(),
        io::ErrorKind::NotFound
    );
    let mut file =
        File::open(mountpoint.path().join("allowed.txt")).expect("authorized FUSE file must open");
    let mut before_revoke = String::new();
    file.read_to_string(&mut before_revoke)
        .expect("authorized FUSE read must succeed");
    assert_eq!(before_revoke, "capability");

    kernel
        .revoke_held_by(&subject, &capability)
        .expect("test capability must be revocable");
    file.seek(SeekFrom::Start(0))
        .expect("direct-I/O file offset must remain seekable");
    let mut after_revoke = [0_u8; 10];
    assert_eq!(
        file.read(&mut after_revoke)
            .expect_err("an existing descriptor must reauthorize every read")
            .kind(),
        io::ErrorKind::PermissionDenied
    );

    drop(file);
    drop(session);
}

// Requirement: O_TRUNC, WRITE, and SETATTR(size) must all stay behind their
// respective authorization checks. Category: FUSE/security. Risk: critical.
#[test]
fn mounted_view_denies_write_after_revoke() {
    if !Path::new("/dev/fuse").exists() {
        eprintln!("skipping FUSE integration test because /dev/fuse is unavailable");
        return;
    }

    let backing = tempdir().expect("temporary backing directory must be creatable");
    let mountpoint = tempdir().expect("temporary mountpoint must be creatable");
    let backing_file = backing.path().join("allowed.txt");
    fs::write(&backing_file, b"capability").expect("authorized backing file must be writable");
    let repository = RepoId::new("workspace");
    let imported = ImportedRepository::open(
        repository.clone(),
        backing.path(),
        PreflightLimits::new(NonZeroUsize::new(16).expect("limit must be non-zero"), 1),
    )
    .expect("test backing must pass preflight");
    let subject = SubjectId::new("fuse-writer-subject");
    let validity = TimeWindow::new(MonotonicTime::from_ticks(0), MonotonicTime::from_ticks(10))
        .expect("test validity window must be non-empty");
    let kernel = Arc::new(CapabilityKernel::new(CapabilityState::new(IssuerId::new(
        "fuse-writer-session",
    ))));
    kernel
        .register_subject(Subject::new(
            subject.clone(),
            StaticAuthorityEnvelope::new(
                validity,
                AuthorityBody::File(FileAuthority::new(
                    repository.clone(),
                    FileEffects::from_effects([FileEffect::WriteData, FileEffect::Truncate]),
                    PathPattern::Prefix(CanonicalPath::root()),
                )),
            ),
        ))
        .expect("test subject registration must succeed");
    let capability = kernel
        .issue_root(CapabilityGrant::new(
            subject.clone(),
            validity,
            AuthorityBody::File(FileAuthority::new(
                repository.clone(),
                FileEffects::from_effects([FileEffect::WriteData, FileEffect::Truncate]),
                PathPattern::Exact(
                    CanonicalPath::new(["allowed.txt"]).expect("test path must be canonical"),
                ),
            )),
        ))
        .expect("test capability issuance must succeed");
    let filesystem = CapabilityFilesystem::new(
        imported,
        Arc::clone(&kernel),
        MountAuthority::new(
            MountInstanceId::new("fuse-write-integration"),
            subject.clone(),
            capability.clone(),
            repository,
        ),
        Arc::new(MonotonicTime::from_ticks(5)),
    )
    .expect("filesystem must initialize");
    let session = spawn_mount(filesystem, mountpoint.path()).expect("FUSE mount must succeed");

    let mut file = OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(mountpoint.path().join("allowed.txt"))
        .expect("WriteData and Truncate must authorize a FUSE O_TRUNC open");
    assert_eq!(
        fs::read(&backing_file).expect("truncated backing file must remain readable"),
        b""
    );
    file.write_all(b"Capa")
        .expect("authorized FUSE write must succeed");
    assert_eq!(
        fs::read(&backing_file).expect("backing file must remain readable"),
        b"Capa"
    );

    kernel
        .revoke_held_by(&subject, &capability)
        .expect("test capability must be revocable");
    assert_eq!(
        file.write_all(b"!")
            .expect_err("an existing descriptor must reauthorize every write")
            .kind(),
        io::ErrorKind::PermissionDenied
    );
    assert_eq!(
        file.set_len(0)
            .expect_err("an existing descriptor must reauthorize every size change")
            .kind(),
        io::ErrorKind::PermissionDenied
    );
    assert_eq!(
        fs::read(&backing_file).expect("revoked truncation must leave the backing file unchanged"),
        b"Capa"
    );

    drop(file);
    drop(session);
}

// Requirement: FUSE CREATE and MKDIR publish the shared namespace only after
// their separate effects authorize the hardened backing operation. Category:
// FUSE/create. Risk: critical.
#[test]
fn mounted_view_creates_files_and_directories_with_capability_effects() {
    if !Path::new("/dev/fuse").exists() {
        eprintln!("skipping FUSE integration test because /dev/fuse is unavailable");
        return;
    }

    let backing = tempdir().expect("temporary backing directory must be creatable");
    let mountpoint = tempdir().expect("temporary mountpoint must be creatable");
    fs::create_dir(backing.path().join("scoped"))
        .expect("authorized backing directory must be creatable");
    let repository = RepoId::new("workspace");
    let imported = ImportedRepository::open(
        repository.clone(),
        backing.path(),
        PreflightLimits::new(NonZeroUsize::new(16).expect("limit must be non-zero"), 2),
    )
    .expect("test backing must pass preflight");
    let subject = SubjectId::new("fuse-create-subject");
    let validity = TimeWindow::new(MonotonicTime::from_ticks(0), MonotonicTime::from_ticks(10))
        .expect("test validity window must be non-empty");
    let effects = FileEffects::from_effects([
        FileEffect::ListDirectory,
        FileEffect::CreateDirectory,
        FileEffect::CreateFile,
        FileEffect::WriteData,
    ]);
    let kernel = Arc::new(CapabilityKernel::new(CapabilityState::new(IssuerId::new(
        "fuse-create-session",
    ))));
    kernel
        .register_subject(Subject::new(
            subject.clone(),
            StaticAuthorityEnvelope::new(
                validity,
                AuthorityBody::File(FileAuthority::new(
                    repository.clone(),
                    effects,
                    PathPattern::Prefix(CanonicalPath::root()),
                )),
            ),
        ))
        .expect("test subject registration must succeed");
    let capability = kernel
        .issue_root(CapabilityGrant::new(
            subject.clone(),
            validity,
            AuthorityBody::File(FileAuthority::new(
                repository.clone(),
                effects,
                PathPattern::Prefix(
                    CanonicalPath::new(["scoped"]).expect("test path must be canonical"),
                ),
            )),
        ))
        .expect("test capability issuance must succeed");
    let filesystem = CapabilityFilesystem::new(
        imported,
        Arc::clone(&kernel),
        MountAuthority::new(
            MountInstanceId::new("fuse-create-integration"),
            subject.clone(),
            capability.clone(),
            repository,
        ),
        Arc::new(MonotonicTime::from_ticks(5)),
    )
    .expect("filesystem must initialize");
    let session = spawn_mount(filesystem, mountpoint.path()).expect("FUSE mount must succeed");
    let scoped_mount = mountpoint.path().join("scoped");

    fs::create_dir(scoped_mount.join("created-dir"))
        .expect("CreateDirectory must authorize FUSE MKDIR");
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(scoped_mount.join("created.txt"))
        .expect("CreateFile and WriteData must authorize FUSE CREATE");
    file.write_all(b"created through FUSE")
        .expect("the returned CREATE handle must be writable");
    drop(file);

    assert!(backing.path().join("scoped/created-dir").is_dir());
    assert_eq!(
        fs::read(backing.path().join("scoped/created.txt"))
            .expect("the newly created backing file must be readable"),
        b"created through FUSE"
    );
    let scoped_directory = open(
        &scoped_mount,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .expect("ListDirectory must authorize opening the parent before revoke");

    kernel
        .revoke_held_by(&subject, &capability)
        .expect("test capability must be revocable");
    assert_eq!(
        mkdirat(&scoped_directory, "revoked-dir", Mode::RWXU)
            .expect_err("a later MKDIR must reauthorize its creation effect"),
        rustix::io::Errno::ACCESS
    );
    assert!(!backing.path().join("scoped/revoked-dir").exists());

    drop(session);
}

// Requirement: FUSE UNLINK, RMDIR, and no-replace RENAME reach the same
// authorized namespace transaction as their backing syscall. Category:
// FUSE/mutation. Risk: critical.
#[test]
fn mounted_view_removes_and_renames_only_with_live_effects() {
    if !Path::new("/dev/fuse").exists() {
        eprintln!("skipping FUSE integration test because /dev/fuse is unavailable");
        return;
    }

    let backing = tempdir().expect("temporary backing directory must be creatable");
    let mountpoint = tempdir().expect("temporary mountpoint must be creatable");
    let scoped_backing = backing.path().join("scoped");
    fs::create_dir(&scoped_backing).expect("authorized backing directory must be creatable");
    fs::write(scoped_backing.join("old.txt"), b"rename me")
        .expect("test backing file must be writable");
    fs::write(scoped_backing.join("revoked.txt"), b"keep me")
        .expect("revocation test file must be writable");
    fs::create_dir(scoped_backing.join("empty")).expect("test backing directory must be creatable");
    let repository = RepoId::new("workspace");
    let imported = ImportedRepository::open(
        repository.clone(),
        backing.path(),
        PreflightLimits::new(NonZeroUsize::new(16).expect("limit must be non-zero"), 2),
    )
    .expect("test backing must pass preflight");
    let subject = SubjectId::new("fuse-mutation-subject");
    let validity = TimeWindow::new(MonotonicTime::from_ticks(0), MonotonicTime::from_ticks(10))
        .expect("test validity window must be non-empty");
    let effects = FileEffects::from_effects([
        FileEffect::ListDirectory,
        FileEffect::RemoveFile,
        FileEffect::RemoveDirectory,
        FileEffect::Rename,
    ]);
    let kernel = Arc::new(CapabilityKernel::new(CapabilityState::new(IssuerId::new(
        "fuse-mutation-session",
    ))));
    kernel
        .register_subject(Subject::new(
            subject.clone(),
            StaticAuthorityEnvelope::new(
                validity,
                AuthorityBody::File(FileAuthority::new(
                    repository.clone(),
                    effects,
                    PathPattern::Prefix(CanonicalPath::root()),
                )),
            ),
        ))
        .expect("test subject registration must succeed");
    let capability = kernel
        .issue_root(CapabilityGrant::new(
            subject.clone(),
            validity,
            AuthorityBody::File(FileAuthority::new(
                repository.clone(),
                effects,
                PathPattern::Prefix(
                    CanonicalPath::new(["scoped"]).expect("test path must be canonical"),
                ),
            )),
        ))
        .expect("test capability issuance must succeed");
    let filesystem = CapabilityFilesystem::new(
        imported,
        Arc::clone(&kernel),
        MountAuthority::new(
            MountInstanceId::new("fuse-mutation-integration"),
            subject.clone(),
            capability.clone(),
            repository,
        ),
        Arc::new(MonotonicTime::from_ticks(5)),
    )
    .expect("filesystem must initialize");
    let session = spawn_mount(filesystem, mountpoint.path()).expect("FUSE mount must succeed");
    let scoped_mount = mountpoint.path().join("scoped");

    fs::rename(scoped_mount.join("old.txt"), scoped_mount.join("moved.txt"))
        .expect("Rename must authorize both the source and destination");
    assert_eq!(
        fs::read(scoped_backing.join("moved.txt")).expect("renamed file must be readable"),
        b"rename me"
    );
    fs::remove_file(scoped_mount.join("moved.txt")).expect("RemoveFile must authorize FUSE UNLINK");
    fs::remove_dir(scoped_mount.join("empty")).expect("RemoveDirectory must authorize FUSE RMDIR");
    assert!(!scoped_backing.join("moved.txt").exists());
    assert!(!scoped_backing.join("empty").exists());

    let scoped_directory = open(
        &scoped_mount,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .expect("ListDirectory must authorize opening the parent before revoke");
    kernel
        .revoke_held_by(&subject, &capability)
        .expect("test capability must be revocable");
    assert_eq!(
        unlinkat(&scoped_directory, "revoked.txt", AtFlags::empty())
            .expect_err("a revoked capability must not reach FUSE UNLINK"),
        rustix::io::Errno::NOENT
    );
    assert!(scoped_backing.join("revoked.txt").is_file());

    drop(session);
}

// Requirement: FUSE SETATTR(mode) requires SetMetadata even on an existing
// descriptor, and privileged mode bits never reach the backing inode.
// Category: FUSE/metadata. Risk: critical.
#[test]
fn mounted_view_authorizes_metadata_changes_and_rechecks_after_revoke() {
    if !Path::new("/dev/fuse").exists() {
        eprintln!("skipping FUSE integration test because /dev/fuse is unavailable");
        return;
    }

    let backing = tempdir().expect("temporary backing directory must be creatable");
    let mountpoint = tempdir().expect("temporary mountpoint must be creatable");
    let scoped_backing = backing.path().join("scoped");
    fs::create_dir(&scoped_backing).expect("authorized backing directory must be creatable");
    let backing_file = scoped_backing.join("metadata.txt");
    fs::write(&backing_file, b"metadata").expect("test backing file must be writable");
    let repository = RepoId::new("workspace");
    let imported = ImportedRepository::open(
        repository.clone(),
        backing.path(),
        PreflightLimits::new(NonZeroUsize::new(16).expect("limit must be non-zero"), 2),
    )
    .expect("test backing must pass preflight");
    let subject = SubjectId::new("fuse-metadata-subject");
    let validity = TimeWindow::new(MonotonicTime::from_ticks(0), MonotonicTime::from_ticks(10))
        .expect("test validity window must be non-empty");
    let effects = FileEffects::from_effects([
        FileEffect::ListDirectory,
        FileEffect::ReadData,
        FileEffect::SetMetadata,
    ]);
    let kernel = Arc::new(CapabilityKernel::new(CapabilityState::new(IssuerId::new(
        "fuse-metadata-session",
    ))));
    kernel
        .register_subject(Subject::new(
            subject.clone(),
            StaticAuthorityEnvelope::new(
                validity,
                AuthorityBody::File(FileAuthority::new(
                    repository.clone(),
                    effects,
                    PathPattern::Prefix(CanonicalPath::root()),
                )),
            ),
        ))
        .expect("test subject registration must succeed");
    let capability = kernel
        .issue_root(CapabilityGrant::new(
            subject.clone(),
            validity,
            AuthorityBody::File(FileAuthority::new(
                repository.clone(),
                effects,
                PathPattern::Exact(
                    CanonicalPath::new(["scoped", "metadata.txt"])
                        .expect("test path must be canonical"),
                ),
            )),
        ))
        .expect("test capability issuance must succeed");
    let filesystem = CapabilityFilesystem::new(
        imported,
        Arc::clone(&kernel),
        MountAuthority::new(
            MountInstanceId::new("fuse-metadata-integration"),
            subject.clone(),
            capability.clone(),
            repository,
        ),
        Arc::new(MonotonicTime::from_ticks(5)),
    )
    .expect("filesystem must initialize");
    let session = spawn_mount(filesystem, mountpoint.path()).expect("FUSE mount must succeed");

    let file = File::open(mountpoint.path().join("scoped/metadata.txt"))
        .expect("ReadData must authorize opening the FUSE file");
    file.set_permissions(fs::Permissions::from_mode(0o4750))
        .expect("SetMetadata must authorize FUSE chmod");
    assert_eq!(
        fs::metadata(&backing_file)
            .expect("updated backing metadata must remain readable")
            .permissions()
            .mode()
            & 0o7777,
        0o750,
        "set-ID bits must be stripped by the FUSE metadata policy"
    );

    kernel
        .revoke_held_by(&subject, &capability)
        .expect("test capability must be revocable");
    assert_eq!(
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .expect_err("an existing descriptor must reauthorize SETATTR")
            .kind(),
        io::ErrorKind::PermissionDenied
    );
    assert_eq!(
        fs::metadata(&backing_file)
            .expect("revoked metadata update must leave backing metadata readable")
            .permissions()
            .mode()
            & 0o777,
        0o750
    );

    drop(file);
    drop(session);
}

// Requirement: READDIR requires ListDirectory and returns direct visible
// children in canonical-name order. Category: FUSE/security. Risk: critical.
#[test]
fn mounted_directory_view_lists_only_its_authorized_prefix() {
    if !Path::new("/dev/fuse").exists() {
        eprintln!("skipping FUSE integration test because /dev/fuse is unavailable");
        return;
    }
    let (_backing, mountpoint, _kernel, _subject, _capability, session) = mount_directory_view();

    assert_eq!(
        fs::read_dir(mountpoint.path())
            .expect_err("ancestor metadata visibility must not grant ListDirectory")
            .kind(),
        io::ErrorKind::PermissionDenied
    );
    let names = fs::read_dir(mountpoint.path().join("scoped"))
        .expect("authorized directory must be listable")
        .map(|entry| {
            entry
                .expect("authorized directory entry must be readable")
                .file_name()
                .into_string()
                .expect("validated entry names must remain UTF-8")
        })
        .collect::<Vec<_>>();
    assert_eq!(names, ["alpha.txt", "zeta.txt"]);

    drop(session);
}

// Requirement: an existing directory stream reauthorizes each kernel READDIR
// request after revoke. Category: FUSE/security. Risk: critical.
#[test]
fn mounted_directory_stream_denies_readdir_after_revoke() {
    if !Path::new("/dev/fuse").exists() {
        eprintln!("skipping FUSE integration test because /dev/fuse is unavailable");
        return;
    }
    let (_backing, mountpoint, kernel, subject, capability, session) = mount_directory_view();
    let directory = open(
        mountpoint.path().join("scoped"),
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .expect("authorized FUSE directory must open");
    // Forty bytes hold one 32-byte dot entry after any alignment trim, forcing
    // the next iterator step to issue a second getdents/READDIR request.
    let mut buffer = [MaybeUninit::uninit(); 40];
    {
        let mut entries = RawDir::new(&directory, &mut buffer);
        let first = entries
            .next()
            .expect("directory stream must contain its dot entry")
            .expect("first authorized READDIR must succeed");
        assert_eq!(first.file_name().to_bytes(), b".");

        kernel
            .revoke_held_by(&subject, &capability)
            .expect("test capability must be revocable");
        assert_eq!(
            entries
                .next()
                .expect("a second READDIR request must be attempted")
                .expect_err("an existing directory stream must reauthorize after revoke"),
            rustix::io::Errno::ACCESS
        );
    }
    drop(directory);
    drop(session);
}

// Requirement: a directory stream reports EAGAIN after a namespace mutation,
// so the kernel never uses a cookie against a different child set. Category:
// FUSE/readdir. Risk: high.
#[test]
fn mounted_directory_stream_requires_restart_after_namespace_mutation() {
    if !Path::new("/dev/fuse").exists() {
        eprintln!("skipping FUSE integration test because /dev/fuse is unavailable");
        return;
    }
    let (_backing, mountpoint, _kernel, _subject, _capability, session) = mount_directory_view();
    let scoped_mount = mountpoint.path().join("scoped");
    let directory = open(
        &scoped_mount,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .expect("ListDirectory must authorize opening the test directory");
    // Forty bytes hold one 32-byte dot entry after any alignment trim, forcing
    // a second iterator step to send another READDIR request to capfs.
    let mut buffer = [MaybeUninit::uninit(); 40];
    {
        let mut entries = RawDir::new(&directory, &mut buffer);
        let first = entries
            .next()
            .expect("directory stream must contain its dot entry")
            .expect("first authorized READDIR must succeed");
        assert_eq!(first.file_name().to_bytes(), b".");

        let mut created = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(scoped_mount.join("later.txt"))
            .expect("CreateFile and WriteData must mutate the namespace");
        created
            .write_all(b"later")
            .expect("the created FUSE file must be writable");
        drop(created);

        assert_eq!(
            entries
                .next()
                .expect("a second READDIR request must be attempted")
                .expect_err("the old stream must not enumerate after mutation"),
            rustix::io::Errno::AGAIN
        );
    }
    drop(directory);
    drop(session);
}

// Requirement: closing a subject revokes every capability it holds, so it must
// discard the operating system's caches for that subject's mount exactly as an
// explicit revoke does. Without that, a read already served into the page cache
// stays readable after the subject is closed.
// Category: FUSE/security. Risk: critical.
#[test]
fn mounted_view_denies_cached_read_after_subject_close() {
    if !Path::new("/dev/fuse").exists() {
        eprintln!("skipping FUSE integration test because /dev/fuse is unavailable");
        return;
    }

    let backing = tempdir().expect("temporary backing directory must be creatable");
    let mountpoint = tempdir().expect("temporary mountpoint must be creatable");
    fs::write(backing.path().join("allowed.txt"), b"capability")
        .expect("authorized backing file must be writable");
    let repository = RepoId::new("workspace");
    let imported = ImportedRepository::open(
        repository.clone(),
        backing.path(),
        PreflightLimits::new(NonZeroUsize::new(16).expect("limit must be non-zero"), 1),
    )
    .expect("test backing must pass preflight");

    let subject = SubjectId::new("fuse-close-subject");
    let validity = TimeWindow::new(MonotonicTime::from_ticks(0), MonotonicTime::from_ticks(10))
        .expect("test validity must be non-empty");
    let kernel = Arc::new(CapabilityKernel::new(CapabilityState::new(IssuerId::new(
        "fuse-close-session",
    ))));
    kernel
        .register_subject(Subject::new(
            subject.clone(),
            StaticAuthorityEnvelope::new(
                validity,
                AuthorityBody::File(FileAuthority::new(
                    repository.clone(),
                    FileEffects::only(FileEffect::ReadData),
                    PathPattern::Prefix(CanonicalPath::root()),
                )),
            ),
        ))
        .expect("test subject registration must succeed");
    let capability = kernel
        .issue_root(CapabilityGrant::new(
            subject.clone(),
            validity,
            AuthorityBody::File(FileAuthority::new(
                repository.clone(),
                FileEffects::only(FileEffect::ReadData),
                PathPattern::Exact(
                    CanonicalPath::new(["allowed.txt"]).expect("test path must be canonical"),
                ),
            )),
        ))
        .expect("test capability issuance must succeed");
    let filesystem = CapabilityFilesystem::new(
        imported,
        Arc::clone(&kernel),
        MountAuthority::new(
            MountInstanceId::new("fuse-close-integration"),
            subject.clone(),
            capability,
            repository,
        ),
        Arc::new(MonotonicTime::from_ticks(5)),
    )
    .expect("filesystem must initialize");
    let session = spawn_mount(filesystem, mountpoint.path()).expect("FUSE mount must succeed");

    // Read the whole file first. This is the step that fills the operating
    // system's cache; without it the assertion below would pass even if the
    // cache were never invalidated.
    let mut file =
        File::open(mountpoint.path().join("allowed.txt")).expect("authorized FUSE file must open");
    let mut before_close = String::new();
    file.read_to_string(&mut before_close)
        .expect("authorized FUSE read must succeed");
    assert_eq!(before_close, "capability");

    kernel
        .begin_subject_close(&subject)
        .expect("subject close must begin");

    file.seek(SeekFrom::Start(0))
        .expect("file offset must remain seekable");
    let mut after_close = [0_u8; 10];
    assert_eq!(
        file.read(&mut after_close)
            .expect_err("a closed subject must not read from a cache filled before the close")
            .kind(),
        io::ErrorKind::PermissionDenied
    );

    drop(file);
    drop(session);
}

// Requirement: the capability kernel keeps registered observers for its own
// lifetime, which outlasts any single mount. A revoke issued after a mount is
// unmounted must still succeed, because a mount that no longer exists has no
// cache left to invalidate. Category: FUSE/lifecycle. Risk: high.
#[test]
fn revoke_after_unmount_reports_no_propagation_failure() {
    if !Path::new("/dev/fuse").exists() {
        eprintln!("skipping FUSE integration test because /dev/fuse is unavailable");
        return;
    }

    let (_backing, _mountpoint, kernel, subject, first_capability, session) =
        mount_directory_view();

    // A second capability on the same kernel outlives the mount.
    let second_capability = kernel
        .issue_root(CapabilityGrant::new(
            SubjectId::new("fuse-directory-subject"),
            TimeWindow::new(MonotonicTime::from_ticks(0), MonotonicTime::from_ticks(10))
                .expect("test validity must be non-empty"),
            AuthorityBody::File(FileAuthority::new(
                RepoId::new("workspace"),
                FileEffects::only(FileEffect::ListDirectory),
                PathPattern::Prefix(
                    CanonicalPath::new(["scoped"]).expect("test path must be canonical"),
                ),
            )),
        ))
        .expect("second capability issuance must succeed");

    kernel
        .revoke_held_by(&subject, &first_capability)
        .expect("revoking while the mount is live must propagate");

    drop(session);

    // The observer is still registered, but its mount is gone.
    kernel
        .revoke_held_by(&subject, &second_capability)
        .expect("revoking after unmount must not report a propagation failure");
}

// Requirement: read-only handles are cached and writable handles are not, so a
// process holding both on one file must still observe its own writes. If the
// cached handle could keep serving overwritten content, the split cache mode is
// not safe to use. Category: FUSE/coherence. Risk: high.
#[test]
fn cached_read_handle_observes_writes_made_through_a_direct_handle() {
    if !Path::new("/dev/fuse").exists() {
        eprintln!("skipping FUSE integration test because /dev/fuse is unavailable");
        return;
    }

    let backing = tempdir().expect("temporary backing directory must be creatable");
    let mountpoint = tempdir().expect("temporary mountpoint must be creatable");
    fs::write(backing.path().join("shared.txt"), b"aaaaaaaaaa")
        .expect("backing file must be writable");
    let repository = RepoId::new("workspace");
    let imported = ImportedRepository::open(
        repository.clone(),
        backing.path(),
        PreflightLimits::new(NonZeroUsize::new(16).expect("limit must be non-zero"), 1),
    )
    .expect("test backing must pass preflight");

    let subject = SubjectId::new("fuse-coherence-subject");
    let validity = TimeWindow::new(MonotonicTime::from_ticks(0), MonotonicTime::from_ticks(10))
        .expect("test validity must be non-empty");
    let effects = FileEffects::from_effects([FileEffect::ReadData, FileEffect::WriteData]);
    let kernel = Arc::new(CapabilityKernel::new(CapabilityState::new(IssuerId::new(
        "fuse-coherence-session",
    ))));
    kernel
        .register_subject(Subject::new(
            subject.clone(),
            StaticAuthorityEnvelope::new(
                validity,
                AuthorityBody::File(FileAuthority::new(
                    repository.clone(),
                    effects,
                    PathPattern::Prefix(CanonicalPath::root()),
                )),
            ),
        ))
        .expect("test subject registration must succeed");
    let capability = kernel
        .issue_root(CapabilityGrant::new(
            subject.clone(),
            validity,
            AuthorityBody::File(FileAuthority::new(
                repository.clone(),
                effects,
                PathPattern::Prefix(CanonicalPath::root()),
            )),
        ))
        .expect("test capability issuance must succeed");
    let filesystem = CapabilityFilesystem::new(
        imported,
        Arc::clone(&kernel),
        MountAuthority::new(
            MountInstanceId::new("fuse-coherence-integration"),
            subject,
            capability,
            repository,
        ),
        Arc::new(MonotonicTime::from_ticks(5)),
    )
    .expect("filesystem must initialize");
    let session = spawn_mount(filesystem, mountpoint.path()).expect("FUSE mount must succeed");

    let path = mountpoint.path().join("shared.txt");

    // Fill the cached handle's page cache first.
    let mut reader = File::open(&path).expect("read-only handle must open");
    let mut first = String::new();
    reader
        .read_to_string(&mut first)
        .expect("read must succeed");
    assert_eq!(first, "aaaaaaaaaa");

    // Overwrite through a separate writable handle, which is on direct I/O.
    let mut writer = OpenOptions::new()
        .write(true)
        .open(&path)
        .expect("writable handle must open");
    writer.write_all(b"bbbbbbbbbb").expect("write must succeed");
    writer.flush().expect("flush must succeed");
    drop(writer);

    // The already-open cached handle must not keep serving the old content.
    reader.seek(SeekFrom::Start(0)).expect("handle must seek");
    let mut second = String::new();
    reader
        .read_to_string(&mut second)
        .expect("read after the write must succeed");
    assert_eq!(
        second, "bbbbbbbbbb",
        "a cached read handle served content that a direct write handle had already overwritten"
    );

    drop(reader);
    drop(session);
}

/// A mounted view with one capability over `prefix` carrying exactly `effects`.
///
/// The link tests each need a different effect set, and what they are proving is
/// which effect gates which operation, so the effect set is the parameter.
struct ScopedMount {
    backing: tempfile::TempDir,
    mountpoint: tempfile::TempDir,
    session: BackgroundSession,
}

fn mount_with_effects(
    name: &str,
    prefix: &[&str],
    effects: &[FileEffect],
    populate: impl FnOnce(&Path),
) -> ScopedMount {
    let backing = tempdir().expect("temporary backing directory must be creatable");
    let mountpoint = tempdir().expect("temporary mountpoint must be creatable");
    populate(backing.path());
    let repository = RepoId::new("workspace");
    let imported = ImportedRepository::open(
        repository.clone(),
        backing.path(),
        PreflightLimits::new(NonZeroUsize::new(32).expect("limit must be non-zero"), 3),
    )
    .expect("test backing must pass preflight");

    let subject = SubjectId::new(format!("{name}-subject"));
    let validity = TimeWindow::new(MonotonicTime::from_ticks(0), MonotonicTime::from_ticks(10))
        .expect("test validity window must be non-empty");
    let effects = FileEffects::from_effects(effects.iter().copied());
    let kernel = Arc::new(CapabilityKernel::new(CapabilityState::new(IssuerId::new(
        format!("{name}-session"),
    ))));
    kernel
        .register_subject(Subject::new(
            subject.clone(),
            StaticAuthorityEnvelope::new(
                validity,
                AuthorityBody::File(FileAuthority::new(
                    repository.clone(),
                    effects,
                    PathPattern::Prefix(CanonicalPath::root()),
                )),
            ),
        ))
        .expect("test subject registration must succeed");
    let capability = kernel
        .issue_root(CapabilityGrant::new(
            subject.clone(),
            validity,
            AuthorityBody::File(FileAuthority::new(
                repository.clone(),
                effects,
                PathPattern::Prefix(
                    CanonicalPath::new(prefix).expect("test path must be canonical"),
                ),
            )),
        ))
        .expect("test capability issuance must succeed");
    let filesystem = CapabilityFilesystem::new(
        imported,
        Arc::clone(&kernel),
        MountAuthority::new(
            MountInstanceId::new(format!("{name}-integration")),
            subject,
            capability,
            repository,
        ),
        Arc::new(MonotonicTime::from_ticks(5)),
    )
    .expect("filesystem must initialize");
    let session = spawn_mount(filesystem, mountpoint.path()).expect("FUSE mount must succeed");

    ScopedMount {
        backing,
        mountpoint,
        session,
    }
}

// Requirement: a symbolic link is created, read back, and followed through the
// mount, and following it is authorized on the path it resolves to rather than
// on the link's own path. Category: FUSE/links. Risk: critical.
#[test]
fn mounted_view_creates_reads_and_follows_symlinks_inside_its_range() {
    if !Path::new("/dev/fuse").exists() {
        eprintln!("skipping FUSE integration test because /dev/fuse is unavailable");
        return;
    }

    let mount = mount_with_effects(
        "fuse-symlink",
        &["scoped"],
        &[
            FileEffect::ListDirectory,
            FileEffect::ReadData,
            FileEffect::CreateSymlink,
            FileEffect::ReadLink,
        ],
        |backing| {
            fs::create_dir(backing.join("scoped")).expect("scoped directory must be creatable");
            fs::write(backing.join("scoped/target.txt"), b"target contents")
                .expect("target file must be writable");
            fs::write(backing.join("hidden.txt"), b"hidden contents")
                .expect("hidden file must be writable");
        },
    );
    let scoped = mount.mountpoint.path().join("scoped");

    std::os::unix::fs::symlink("target.txt", scoped.join("link.txt"))
        .expect("CreateSymlink must authorize FUSE SYMLINK");
    assert!(
        fs::symlink_metadata(mount.backing.path().join("scoped/link.txt"))
            .expect("the backing link must exist")
            .file_type()
            .is_symlink()
    );
    assert_eq!(
        fs::read_link(scoped.join("link.txt")).expect("ReadLink must authorize FUSE READLINK"),
        Path::new("target.txt")
    );
    assert_eq!(
        fs::read(scoped.join("link.txt")).expect("following the link must reach its target"),
        b"target contents"
    );

    // The link body is stored, but resolution is authorized where it lands: a
    // link inside the authorized prefix that points outside it resolves to a
    // path this capability cannot reach, and the walk stops there.
    std::os::unix::fs::symlink("../hidden.txt", scoped.join("peek.txt"))
        .expect("a link whose target is inside the repository is representable");
    assert_eq!(
        fs::read_link(scoped.join("peek.txt")).expect("its body remains readable"),
        Path::new("../hidden.txt")
    );
    let denied = fs::read(scoped.join("peek.txt"))
        .expect_err("a link must not reach a target the capability does not cover");
    assert!(
        matches!(
            denied.kind(),
            io::ErrorKind::NotFound | io::ErrorKind::PermissionDenied
        ),
        "unexpected error following an out-of-range link: {denied:?}"
    );
    assert_eq!(
        fs::read(mount.backing.path().join("hidden.txt"))
            .expect("the out-of-range file must be untouched"),
        b"hidden contents"
    );

    drop(mount.session);
}

// Requirement: a link body that the mount cannot prove stays inside the
// repository is never stored and never handed to the kernel. Category:
// FUSE/links. Risk: critical.
#[test]
fn mounted_view_refuses_symlink_targets_that_leave_the_repository() {
    if !Path::new("/dev/fuse").exists() {
        eprintln!("skipping FUSE integration test because /dev/fuse is unavailable");
        return;
    }

    let mount = mount_with_effects(
        "fuse-symlink-escape",
        &["scoped"],
        &[
            FileEffect::ListDirectory,
            FileEffect::ReadData,
            FileEffect::CreateSymlink,
            FileEffect::ReadLink,
        ],
        |backing| {
            fs::create_dir(backing.join("scoped")).expect("scoped directory must be creatable");
        },
    );
    let scoped = mount.mountpoint.path().join("scoped");

    let absolute = std::os::unix::fs::symlink("/etc/passwd", scoped.join("absolute"))
        .expect_err("an absolute target must be refused");
    assert_eq!(
        absolute.raw_os_error(),
        Some(rustix::io::Errno::PERM.raw_os_error())
    );

    let escaping = std::os::unix::fs::symlink("../../etc/passwd", scoped.join("escape"))
        .expect_err("a target above the repository root must be refused");
    assert_eq!(
        escaping.raw_os_error(),
        Some(rustix::io::Errno::XDEV.raw_os_error())
    );

    // A `..` after a named component cannot be shown to stay inside, because
    // the named component may itself be a link to a shallower directory.
    let interior = std::os::unix::fs::symlink("a/../../elsewhere", scoped.join("interior"))
        .expect_err("an interior parent component must be refused");
    assert_eq!(
        interior.raw_os_error(),
        Some(rustix::io::Errno::PERM.raw_os_error())
    );

    assert!(!mount.backing.path().join("scoped/absolute").exists());
    assert!(!mount.backing.path().join("scoped/escape").exists());
    assert!(!mount.backing.path().join("scoped/interior").exists());

    drop(mount.session);
}

// Requirement: SYMLINK and READLINK each require their own effect. Category:
// FUSE/links. Risk: critical.
#[test]
fn mounted_view_gates_symlink_creation_and_reading_on_their_own_effects() {
    if !Path::new("/dev/fuse").exists() {
        eprintln!("skipping FUSE integration test because /dev/fuse is unavailable");
        return;
    }

    let populate = |backing: &Path| {
        fs::create_dir(backing.join("scoped")).expect("scoped directory must be creatable");
        fs::write(backing.join("scoped/target.txt"), b"target").expect("file must be writable");
        std::os::unix::fs::symlink("target.txt", backing.join("scoped/existing.txt"))
            .expect("backing link must be creatable");
    };

    let without_create = mount_with_effects(
        "fuse-symlink-nocreate",
        &["scoped"],
        &[
            FileEffect::ListDirectory,
            FileEffect::ReadData,
            FileEffect::ReadLink,
        ],
        populate,
    );
    let scoped = without_create.mountpoint.path().join("scoped");
    let denied = std::os::unix::fs::symlink("target.txt", scoped.join("new.txt"))
        .expect_err("SYMLINK without CreateSymlink must be denied");
    assert_eq!(
        denied.kind(),
        io::ErrorKind::PermissionDenied,
        "unexpected error creating a link without its effect: {denied:?}"
    );
    assert!(
        !without_create
            .backing
            .path()
            .join("scoped/new.txt")
            .exists()
    );
    assert_eq!(
        fs::read_link(scoped.join("existing.txt")).expect("ReadLink must still authorize READLINK"),
        Path::new("target.txt")
    );
    drop(without_create.session);

    let without_readlink = mount_with_effects(
        "fuse-symlink-noread",
        &["scoped"],
        &[
            FileEffect::ListDirectory,
            FileEffect::ReadData,
            FileEffect::CreateSymlink,
        ],
        populate,
    );
    let scoped = without_readlink.mountpoint.path().join("scoped");
    let denied = fs::read_link(scoped.join("existing.txt"))
        .expect_err("READLINK without ReadLink must be denied");
    assert_eq!(
        denied.kind(),
        io::ErrorKind::PermissionDenied,
        "unexpected error reading a link without its effect: {denied:?}"
    );
    drop(without_readlink.session);
}

// Requirement: a hard link needs CreateHardLink on the new name and on every
// name the inode already has, and both names then reach one inode. Category:
// FUSE/links. Risk: critical.
#[test]
fn mounted_view_creates_hard_links_only_within_its_authorized_range() {
    if !Path::new("/dev/fuse").exists() {
        eprintln!("skipping FUSE integration test because /dev/fuse is unavailable");
        return;
    }

    let mount = mount_with_effects(
        "fuse-hardlink",
        &["scoped"],
        &[
            FileEffect::ListDirectory,
            FileEffect::ReadData,
            FileEffect::WriteData,
            FileEffect::CreateHardLink,
        ],
        |backing| {
            fs::create_dir(backing.join("scoped")).expect("scoped directory must be creatable");
            fs::write(backing.join("scoped/original.txt"), b"shared")
                .expect("file must be writable");
            fs::write(backing.join("outside.txt"), b"outside").expect("file must be writable");
        },
    );
    let scoped = mount.mountpoint.path().join("scoped");

    fs::hard_link(scoped.join("original.txt"), scoped.join("alias.txt"))
        .expect("CreateHardLink must authorize FUSE LINK inside the range");
    assert_eq!(
        fs::read(scoped.join("alias.txt")).expect("the second name must read the same inode"),
        b"shared"
    );
    assert_eq!(
        fs::metadata(mount.backing.path().join("scoped/original.txt"))
            .expect("the backing file must be readable")
            .nlink(),
        2,
        "the backing inode must really have two names"
    );

    // A destination outside the authorized prefix fails: the capability covers
    // neither the new name nor, therefore, the resulting alias set.
    let denied = fs::hard_link(
        scoped.join("original.txt"),
        mount.mountpoint.path().join("smuggled.txt"),
    )
    .expect_err("LINK must not place a name outside the authorized range");
    assert!(
        matches!(
            denied.kind(),
            io::ErrorKind::NotFound | io::ErrorKind::PermissionDenied
        ),
        "unexpected error linking outside the range: {denied:?}"
    );
    assert!(!mount.backing.path().join("smuggled.txt").exists());

    drop(mount.session);
}

// Requirement: authority over a hard-linked inode is the intersection of the
// authority over its names. An inode whose other name lies outside the
// capability's range is unreachable through the name inside it, so a link
// cannot be used to widen access. Category: FUSE/links. Risk: critical.
#[test]
fn mounted_view_denies_an_inode_whose_other_name_is_out_of_range() {
    if !Path::new("/dev/fuse").exists() {
        eprintln!("skipping FUSE integration test because /dev/fuse is unavailable");
        return;
    }

    let mount = mount_with_effects(
        "fuse-hardlink-intersection",
        &["scoped"],
        &[FileEffect::ListDirectory, FileEffect::ReadData],
        |backing| {
            fs::create_dir(backing.join("scoped")).expect("scoped directory must be creatable");
            fs::write(backing.join("scoped/plain.txt"), b"plain").expect("file must be writable");
            fs::write(backing.join("secret.txt"), b"secret").expect("file must be writable");
            // The alias exists before the mount does, exactly as it would if it
            // had been created by a capability that covered both names.
            fs::hard_link(backing.join("secret.txt"), backing.join("scoped/alias.txt"))
                .expect("alias must be creatable");
        },
    );
    let scoped = mount.mountpoint.path().join("scoped");

    assert_eq!(
        fs::read(scoped.join("plain.txt")).expect("a single-named file in range stays readable"),
        b"plain",
        "the denial below must come from aliasing, not from the prefix"
    );

    let denied = fs::read(scoped.join("alias.txt"))
        .expect_err("a name whose inode is also named out of range must not be readable");
    assert_eq!(
        denied.kind(),
        io::ErrorKind::NotFound,
        "unexpected error reading an out-of-range alias: {denied:?}"
    );

    let listed = fs::read_dir(&scoped)
        .expect("ListDirectory must authorize the listing")
        .map(|entry| {
            entry
                .expect("directory entries must be readable")
                .file_name()
        })
        .collect::<Vec<_>>();
    assert!(
        listed.iter().any(|name| name == "plain.txt"),
        "the in-range file must still be listed: {listed:?}"
    );
    assert!(
        !listed.iter().any(|name| name == "alias.txt"),
        "an inode with an out-of-range name must not be advertised: {listed:?}"
    );

    drop(mount.session);
}

// Requirement: object kinds outside the modelled universe are refused as policy
// rather than reported as unimplemented. Category: FUSE/links. Risk: high.
#[test]
fn mounted_view_refuses_device_and_fifo_creation_with_eperm() {
    if !Path::new("/dev/fuse").exists() {
        eprintln!("skipping FUSE integration test because /dev/fuse is unavailable");
        return;
    }

    let mount = mount_with_effects(
        "fuse-mknod",
        &["scoped"],
        &[
            FileEffect::ListDirectory,
            FileEffect::CreateFile,
            FileEffect::CreateSymlink,
            FileEffect::CreateHardLink,
        ],
        |backing| {
            fs::create_dir(backing.join("scoped")).expect("scoped directory must be creatable");
        },
    );
    let scoped = open(
        mount.mountpoint.path().join("scoped"),
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .expect("ListDirectory must authorize opening the directory");

    assert_eq!(
        mknodat(&scoped, "pipe", FileType::Fifo, Mode::RUSR | Mode::WUSR, 0)
            .expect_err("FIFO creation must be refused"),
        rustix::io::Errno::PERM
    );
    assert!(!mount.backing.path().join("scoped/pipe").exists());

    drop(mount.session);
}
