//! Linux FUSE contract test for read-after-revoke behavior.

#![cfg(target_os = "linux")]

use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    mem::MaybeUninit,
    num::NonZeroUsize,
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
use rustix::fs::{AtFlags, Mode, OFlags, RawDir, mkdirat, open, unlinkat};
use tempfile::tempdir;

type MountedDirectoryView = (
    tempfile::TempDir,
    tempfile::TempDir,
    Arc<CapabilityKernel>,
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
        FileEffects::only(FileEffect::ListDirectory),
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
                FileEffects::only(FileEffect::ListDirectory),
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
            subject,
            capability.clone(),
            repository,
        ),
        Arc::new(MonotonicTime::from_ticks(5)),
    )
    .expect("read-only filesystem must initialize");
    let session = spawn_mount(filesystem, mountpoint.path()).expect("FUSE mount must succeed");

    (backing, mountpoint, kernel, capability, session)
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
            subject,
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
        .revoke(&capability)
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
            subject,
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
        .revoke(&capability)
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
            subject,
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
        .revoke(&capability)
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
            subject,
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
        .revoke(&capability)
        .expect("test capability must be revocable");
    assert_eq!(
        unlinkat(&scoped_directory, "revoked.txt", AtFlags::empty())
            .expect_err("a revoked capability must not reach FUSE UNLINK"),
        rustix::io::Errno::NOENT
    );
    assert!(scoped_backing.join("revoked.txt").is_file());

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
    let (_backing, mountpoint, _kernel, _capability, session) = mount_directory_view();

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
    let (_backing, mountpoint, kernel, capability, session) = mount_directory_view();
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
            .revoke(&capability)
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
