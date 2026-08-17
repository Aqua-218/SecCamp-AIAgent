//! Privileged integration coverage for the production Linux resource adapter.
//!
//! This target is intentionally ignored in ordinary test runs. The wrapper in
//! `scripts/ci/verify-real-supervisor-resources.sh` runs it in a disposable mount namespace
//! after checking the host prerequisites. It exercises the production composition, rather than
//! the fake event-log resource used by the lifecycle contract tests.

#![cfg(target_os = "linux")]

use std::{
    fs, io,
    num::NonZeroUsize,
    os::fd::OwnedFd,
    os::unix::fs::{FileTypeExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::Arc,
};

use authority_core::{
    capability::{AuthorityBody, CapId, IssuerId, SubjectId},
    durable_audit::DurableAuditLog,
    file::{FileAuthority, FileEffect, FileEffects},
    handle::HandleId,
    path::{CanonicalPath, PathPattern},
    repository::RepoId,
    state::{CapabilityGrant, CapabilityState},
    time::{MonotonicTime, TimeWindow},
};
use capfs::backing::{ImportedRepository, PreflightLimits};
use rustix::{
    fs::statfs,
    net::{
        AddressFamily, SendFlags, SocketAddrUnix, SocketFlags, SocketType, connect, send,
        socket_with,
    },
    process::{getegid, geteuid},
};
use supervisor::{
    CallerResolver, CapfsHostResources, CapfsMountPlan, CapfsRuntimeConfig, CapfsRuntimeManager,
    CapfsUnmountStrategy, ControlFdHandle, LinuxHostConfig, LinuxHostResources, MountHandle,
    ResourceAcquisition, ResourceMutation, RuntimeResources, SubjectCredential,
    SubjectCredentialResolver, WireRequest, WorkloadHandle, WorkloadIsolationConfig,
    WorkloadIsolationLimits,
};
use tempfile::{TempDir, tempdir};

const FUSE_SUPER_MAGIC: u64 = 0x6573_5546;

struct CgroupGuard {
    parent: PathBuf,
    subject: PathBuf,
}

impl Drop for CgroupGuard {
    fn drop(&mut self) {
        // The guard owns exactly one random leaf and deliberately does not recurse. A leftover
        // child makes cleanup visible instead of risking removal of an unrelated cgroup.
        let _ = fs::remove_dir(self.subject.join("occupied-child"));
        let _ = fs::remove_dir(&self.subject);
        let _ = fs::remove_dir(&self.parent);
    }
}

fn filesystem_type(path: &Path) -> io::Result<u64> {
    let filesystem =
        statfs(path).map_err(|error| io::Error::from_raw_os_error(error.raw_os_error()))?;
    u64::try_from(filesystem.f_type)
        .map_err(|_| io::Error::other("filesystem type cannot be represented as u64"))
}

fn socket_client(path: &Path) -> OwnedFd {
    let address = SocketAddrUnix::new(path).expect("control socket path must encode");
    let client = socket_with(
        AddressFamily::UNIX,
        SocketType::SEQPACKET,
        SocketFlags::CLOEXEC,
        None,
    )
    .expect("control client socket must be creatable");
    connect(&client, &address).expect("control client must connect");
    client
}

fn isolation_config() -> WorkloadIsolationConfig {
    WorkloadIsolationConfig::new(
        std::env::current_exe().expect("test executable path must be available"),
        "/",
        "/tmp",
        "/tmp/capfs-old-root",
        "/workspace",
        WorkloadIsolationLimits::new("/tmp", 4 * 1024 * 1024, 64 * 1024 * 1024, 32, 0, 0),
        19,
        "00112233445566778899aabbccddeeff",
    )
}

fn host_config(cgroup_parent: &Path, socket_directory: &Path) -> LinuxHostConfig {
    LinuxHostConfig::new(
        cgroup_parent,
        socket_directory,
        "/bin/true",
        std::iter::empty(),
        isolation_config(),
        SubjectCredential::new(geteuid().as_raw(), getegid().as_raw()),
    )
}

fn imported_repository(repository: &RepoId, backing: &TempDir) -> ImportedRepository {
    fs::write(backing.path().join("allowed.txt"), b"production-adapter")
        .expect("backing file must be writable");
    ImportedRepository::open(
        repository.clone(),
        backing.path(),
        PreflightLimits::new(NonZeroUsize::new(32).expect("limit must be non-zero"), 4),
    )
    .expect("repository must pass the production preflight")
}

fn runtime_config(
    repository: &RepoId,
    imported: ImportedRepository,
    journal: &Path,
    subject: &SubjectId,
    mountpoint: &Path,
) -> CapfsRuntimeConfig {
    let validity = TimeWindow::new(MonotonicTime::from_ticks(0), MonotonicTime::from_ticks(10))
        .expect("test validity must be non-empty");
    let authority = AuthorityBody::File(FileAuthority::new(
        repository.clone(),
        FileEffects::from_effects([FileEffect::ReadData, FileEffect::ListDirectory]),
        PathPattern::Prefix(CanonicalPath::root()),
    ));
    CapfsRuntimeConfig::new(
        CapabilityState::new(IssuerId::new("real-supervisor-resource-session")),
        DurableAuditLog::create(journal).expect("durable audit log must be creatable"),
        imported,
        Arc::new(MonotonicTime::from_ticks(5)),
        CapfsUnmountStrategy::kernel(),
        vec![CapfsMountPlan::new(
            subject.clone(),
            capfs::read_only::MountInstanceId::new("real-supervisor-resource-mount"),
            CapId::new("real-supervisor-resource-root"),
            CapabilityGrant::new(subject.clone(), validity, authority),
            mountpoint,
        )],
    )
}

#[test]
#[ignore = "requires root, cgroup v2, /dev/fuse, and a private mount namespace"]
#[allow(clippy::too_many_lines)] // Keep one observable setup/cleanup transaction in one scenario.
fn real_linux_host_resources_exercises_kernel_side_effects() {
    assert_eq!(
        geteuid().as_raw(),
        0,
        "the real adapter test must run as root"
    );
    assert!(
        fs::symlink_metadata("/dev/fuse")
            .expect("/dev/fuse must be stat-able")
            .file_type()
            .is_char_device(),
        "/dev/fuse must be a character device"
    );
    assert!(
        !fs::read_to_string("/sys/fs/cgroup/cgroup.controllers")
            .expect("cgroup v2 controller file must be readable")
            .is_empty(),
        "the delegated cgroup hierarchy must expose controllers"
    );

    let repository = RepoId::new("workspace");
    let subject = SubjectId::new("real-supervisor-resource");
    let cgroup_parent = std::env::var_os("SUPERVISOR_REAL_RESOURCES_CGROUP_PARENT")
        .map(PathBuf::from)
        .expect("the privileged wrapper must provide an exact cgroup parent");
    assert_eq!(
        cgroup_parent.parent(),
        Some(Path::new("/sys/fs/cgroup")),
        "the wrapper-supplied cgroup parent must be one direct child of the cgroup root"
    );
    let cgroup_path = cgroup_parent.join(subject.as_str());
    assert!(
        !cgroup_parent.exists(),
        "the exact cgroup parent must be unused"
    );
    fs::create_dir(&cgroup_parent).expect("test cgroup parent must be creatable");
    let _cgroup_guard = CgroupGuard {
        parent: cgroup_parent.clone(),
        subject: cgroup_path.clone(),
    };

    let temporary = tempdir().expect("temporary workspace must be creatable");
    let socket_directory = temporary.path().join("control");
    fs::create_dir(&socket_directory).expect("control directory must be creatable");
    fs::set_permissions(&socket_directory, fs::Permissions::from_mode(0o700))
        .expect("control directory must be private");
    let backing = tempdir().expect("backing directory must be creatable");
    let mountpoint = temporary.path().join("mount");
    fs::create_dir(&mountpoint).expect("mountpoint must be creatable");
    let journal = temporary.path().join("authority.wal");

    let host = LinuxHostResources::new(host_config(&cgroup_parent, &socket_directory))
        .expect("production host adapter must validate in the privileged namespace");
    let manager = CapfsRuntimeManager::new(
        host,
        runtime_config(
            &repository,
            imported_repository(&repository, &backing),
            &journal,
            &subject,
            &mountpoint,
        ),
    )
    .expect("production runtime manager must compose");
    let mut supervisor = manager
        .into_supervisor(SubjectCredentialResolver::new())
        .expect("production supervisor must start from a pristine kernel");

    let mount = match supervisor.resources_mut().mount_capfs(&subject) {
        ResourceAcquisition::Acquired(mount) => mount,
        ResourceAcquisition::NoEffect(error)
        | ResourceAcquisition::EffectUnknown(error)
        | ResourceAcquisition::CleanupRequired { error, .. } => {
            panic!("real CapFS mount must complete: {error}")
        }
    };
    assert_eq!(
        filesystem_type(&mountpoint).expect("mounted path must be stat-able"),
        FUSE_SUPER_MAGIC,
        "the adapter must retain a real FUSE mount"
    );
    assert_eq!(supervisor.resources().active_mount_count(), 1);

    let cgroup = match supervisor
        .resources_mut()
        .host_mut()
        .create_cgroup(&subject)
    {
        ResourceAcquisition::Acquired(cgroup) => cgroup,
        ResourceAcquisition::NoEffect(error)
        | ResourceAcquisition::EffectUnknown(error)
        | ResourceAcquisition::CleanupRequired { error, .. } => {
            panic!("real cgroup creation must complete: {error}")
        }
    };
    assert!(
        cgroup_path.is_dir(),
        "the subject cgroup must exist on disk"
    );

    // A child directory makes the first removal fail. The same stable token must then succeed
    // after the observed child is removed, which covers the production retry ownership contract.
    let occupied_child = cgroup_path.join("occupied-child");
    fs::create_dir(&occupied_child).expect("test cgroup child must be creatable");
    assert!(matches!(
        supervisor.resources_mut().host_mut().remove_cgroup(cgroup),
        ResourceMutation::CleanupRequired(_)
    ));
    assert!(
        cgroup_path.is_dir(),
        "failed cgroup cleanup must retain ownership"
    );
    fs::remove_dir(&occupied_child).expect("test cgroup child must be removable");
    assert!(matches!(
        supervisor.resources_mut().host_mut().remove_cgroup(cgroup),
        ResourceMutation::Applied
    ));
    assert!(!cgroup_path.exists(), "cgroup retry must remove the leaf");

    // Recreating the same record gets a fresh token and still leaves the old token idempotent.
    let recreated = match supervisor
        .resources_mut()
        .host_mut()
        .create_cgroup(&subject)
    {
        ResourceAcquisition::Acquired(cgroup) => cgroup,
        ResourceAcquisition::NoEffect(error)
        | ResourceAcquisition::EffectUnknown(error)
        | ResourceAcquisition::CleanupRequired { error, .. } => {
            panic!("record recreation must create a fresh cgroup: {error}")
        }
    };
    assert_ne!(recreated, cgroup);
    assert!(matches!(
        supervisor
            .resources_mut()
            .host_mut()
            .remove_cgroup(recreated),
        ResourceMutation::Applied
    ));

    let control = match supervisor
        .resources_mut()
        .host_mut()
        .open_control_fd(&subject)
    {
        ResourceAcquisition::Acquired(control) => control,
        ResourceAcquisition::NoEffect(error)
        | ResourceAcquisition::EffectUnknown(error)
        | ResourceAcquisition::CleanupRequired { error, .. } => {
            panic!("real control socket must bind: {error}")
        }
    };
    let control_path = supervisor
        .resources()
        .host()
        .control_socket_path(&subject)
        .expect("valid subject must have a control socket path");
    assert!(
        fs::symlink_metadata(&control_path)
            .expect("control socket node must be stat-able")
            .file_type()
            .is_socket(),
        "control socket node must exist"
    );

    let client = socket_client(&control_path);
    let encoded = WireRequest::CloseSubject {
        claimed_subject: SubjectId::new("spoofed-subject"),
    }
    .encode()
    .expect("bounded request must encode");
    send(&client, &encoded, SendFlags::empty()).expect("control client must send a datagram");
    let mut resolver = SubjectCredentialResolver::new();
    let connection = supervisor
        .resources_mut()
        .host_mut()
        .control_listener(&subject)
        .expect("open control descriptor must expose its listener")
        .accept(&mut resolver)
        .expect("control listener must accept the local peer");
    let identity = connection.identity();
    assert_eq!(identity.peer_uid(), geteuid().as_raw());
    assert_eq!(identity.peer_gid(), getegid().as_raw());
    assert_eq!(
        resolver
            .resolve(&identity)
            .expect("peer credential must resolve to the listening subject"),
        subject
    );
    assert_eq!(
        connection
            .receive_request()
            .expect("bounded control datagram must decode"),
        WireRequest::CloseSubject {
            claimed_subject: SubjectId::new("spoofed-subject")
        }
    );
    resolver.release(identity.socket_id());
    drop(connection);
    drop(client);
    assert!(matches!(
        supervisor
            .resources_mut()
            .host_mut()
            .close_control_fd(control),
        ResourceMutation::Applied
    ));
    assert!(
        !control_path.exists(),
        "socket cleanup must remove its node"
    );

    // Handles are bookkeeping at this boundary, but the real adapter still has to grow and
    // release each subject's record without token reuse or cross-subject leakage.
    for index in 0..128 {
        let handle = HandleId::new(format!("real-handle-{index}"));
        assert!(matches!(
            supervisor
                .resources_mut()
                .host_mut()
                .open_handle(&subject, &handle),
            ResourceMutation::Applied
        ));
        assert!(matches!(
            supervisor
                .resources_mut()
                .host_mut()
                .close_handle(&subject, &handle),
            ResourceMutation::Applied
        ));
    }

    assert!(matches!(
        supervisor
            .resources_mut()
            .host_mut()
            .close_control_fd(ControlFdHandle::new(u64::MAX)),
        ResourceMutation::Applied
    ));
    assert!(matches!(
        supervisor
            .resources_mut()
            .host_mut()
            .remove_cgroup(supervisor::CgroupHandle::new(u64::MAX)),
        ResourceMutation::Applied
    ));
    assert!(matches!(
        supervisor.resources_mut().host_mut().start_workload(
            &subject,
            supervisor::CgroupHandle::new(u64::MAX),
            MountHandle::new(u64::MAX),
            &mountpoint,
            ControlFdHandle::new(u64::MAX),
        ),
        ResourceAcquisition::NoEffect(_)
    ));
    assert!(matches!(
        supervisor.resources_mut().host_mut().stop_workload(
            WorkloadHandle::new(u64::MAX),
            supervisor::CgroupHandle::new(u64::MAX),
        ),
        ResourceMutation::Applied
    ));
    assert!(matches!(
        supervisor.resources_mut().unmount_capfs(mount),
        ResourceMutation::Applied
    ));
    assert_ne!(
        filesystem_type(&mountpoint).expect("unmounted path must be stat-able"),
        FUSE_SUPER_MAGIC,
        "unmount must remove the exact FUSE filesystem"
    );
    assert_eq!(supervisor.resources().active_mount_count(), 0);
}
