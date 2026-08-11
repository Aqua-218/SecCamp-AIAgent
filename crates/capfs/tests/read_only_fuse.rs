//! Linux FUSE contract test for read-after-revoke behavior.

#![cfg(target_os = "linux")]

use std::{
    fs::{self, File},
    io::{self, Read, Seek, SeekFrom},
    num::NonZeroUsize,
    path::Path,
    sync::Arc,
};

use authority_core::{
    capability::{AuthorityBody, IssuerId, SubjectId},
    file::{FileAuthority, FileEffect, FileEffects},
    kernel::CapabilityKernel,
    path::{CanonicalPath, PathPattern},
    repository::RepoId,
    state::{CapabilityGrant, CapabilityState, StaticAuthorityEnvelope, Subject},
    time::{MonotonicTime, TimeWindow},
};
use capfs::{
    backing::{ImportedRepository, PreflightLimits},
    read_only::{MountAuthority, MountInstanceId, ReadOnlyFilesystem, spawn_mount},
};
use tempfile::tempdir;

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
    let filesystem = ReadOnlyFilesystem::new(
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
