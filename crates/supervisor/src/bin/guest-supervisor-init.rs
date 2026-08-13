//! Guest-resident composition root for one fixed capability workload.
//!
//! This process is launched only by `guest-control-init` after that PID 1 gate has accepted the
//! session-bound identity bundle. It mounts the session workspace device, constructs the sole
//! guest `CapabilityKernel`, retains the `CapFS` server, and launches exactly one configured
//! workload through `LinuxHostResources`. No host command, credential, or pathname is accepted
//! here after boot.

#![forbid(unsafe_code)]

use std::{
    env,
    ffi::{OsStr, OsString},
    fs,
    num::NonZeroUsize,
    os::fd::{AsRawFd, OwnedFd},
    os::unix::fs::FileTypeExt,
    path::{Component, Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};

use authority_core::{
    capability::{AuthorityBody, CapId, IssuerId, SubjectId},
    durable_audit::DurableAuditLog,
    file::{FileAuthority, FileEffect, FileEffects},
    path::{CanonicalPath, PathPattern},
    repository::RepoId,
    state::{CapabilityGrant, CapabilityState, StaticAuthorityEnvelope, Subject},
    time::{MonotonicTime, TimeWindow},
};
use capfs::{
    backing::{ImportedRepository, PreflightLimits},
    read_only::MountInstanceId,
};
use rustix::{
    fs::{CWD, FileType, Mode, makedev, mknodat, statfs},
    mount::{MountFlags, UnmountFlags, mount, unmount},
    net::{AddressFamily, SocketAddrUnix, SocketFlags, SocketType, connect, socket_with},
    process::{getegid, geteuid},
};
use socket2::{Domain, SockAddr, Socket, Type};
use supervisor::{
    CapfsMountPlan, CapfsRuntimeConfig, CapfsRuntimeManager, CapfsUnmountStrategy,
    DispatchResponse, LinuxHostConfig, LinuxHostResources, RefusalCode, SubjectCredential,
    SubjectCredentialResolver, WireResponse, WorkloadIsolationConfig, WorkloadIsolationLimits,
};

const GUEST_SESSION_ID_ENV: &str = "GUEST_IDENTITY_SESSION_ID";
const GUEST_SUBJECT_ID_ENV: &str = "GUEST_IDENTITY_SUBJECT_ID";
const GUEST_CAPABILITY_ID_ENV: &str = "GUEST_IDENTITY_CAPABILITY_ID";
const CAPFS_LIMIT_ENTRIES: usize = 100_000;
const CAPFS_LIMIT_DEPTH: usize = 64;
const WORKLOAD_TMPFS_BYTES: u64 = 64 * 1024 * 1024;
const WORKLOAD_MEMORY_BYTES: u64 = 256 * 1024 * 1024;
const WORKLOAD_PIDS_MAX: u64 = 32;
const HOST_VSOCK_CID: u32 = 2;
const BROKER_IO_TIMEOUT_SECONDS: u64 = 5;
const DEVICE_DIRECTORY: &str = "/dev";
const PROC_DIRECTORY: &str = "/proc";
const DEVTMPFS_SUPER_MAGIC: i64 = 0x1373;
const TMPFS_SUPER_MAGIC: i64 = 0x0102_1994;
const PROC_SUPER_MAGIC: i64 = 0x9fa0;
const WORKSPACE_DEVICE: &str = "/dev/vdb";
const FUSE_DEVICE: &str = "/dev/fuse";
const FUSE_MAJOR: u32 = 10;
const FUSE_MINOR: u32 = 229;
const CGROUP_READY_TIMEOUT: Duration = Duration::from_secs(5);
const CGROUP_READY_POLL_INTERVAL: Duration = Duration::from_millis(10);

#[derive(Debug)]
struct Config {
    workspace_device: PathBuf,
    runtime_dir: PathBuf,
    cgroup_parent: PathBuf,
    broker_port: u32,
    isolation_launcher: PathBuf,
    workload: PathBuf,
    repository: RepoId,
    effects: FileEffects,
    path: PathPattern,
}

fn main() -> std::process::ExitCode {
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!(
                "guest-supervisor-init: {error}; fixed image arguments: {:?}",
                env::args_os().skip(1).collect::<Vec<_>>()
            );
            std::process::ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let config = parse_config(env::args_os().skip(1))?;
    let identity = GuestIdentity::from_environment()?;
    prepare_device_directory()?;
    prepare_procfs()?;
    prepare_cgroup_hierarchy(&config.cgroup_parent)?;
    prepare_runtime_directory(&config.runtime_dir)?;
    let workspace = config.runtime_dir.join("workspace");
    mount_workspace(&config.workspace_device, &workspace)?;
    let result = run_session(&config, &identity, &workspace);
    if let Err(error) = &result {
        eprintln!("guest-supervisor-init: session failed before workspace cleanup: {error}");
    }
    let unmount_result = unmount(&workspace, UnmountFlags::NOFOLLOW).map_err(|error| {
        format!(
            "unmounting guest workspace {}: {error}",
            workspace.display()
        )
    });
    match (result, unmount_result) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
        (Err(primary), Err(cleanup)) => Err(format!(
            "{primary}; workspace cleanup also failed: {cleanup}"
        )),
    }
}

#[allow(clippy::too_many_lines)]
fn run_session(config: &Config, identity: &GuestIdentity, workspace: &Path) -> Result<(), String> {
    let subject = SubjectId::new(identity.subject.clone());
    let capability = CapId::new(identity.capability.clone());
    let control_directory = config.runtime_dir.join("control");
    let mountpoint = config.runtime_dir.join("capfs");
    let rootfs_mount_target = config.runtime_dir.join("isolated-root");
    fs::create_dir_all(&control_directory)
        .map_err(|error| format!("creating guest control directory: {error}"))?;
    fs::create_dir_all(&mountpoint)
        .map_err(|error| format!("creating guest CapFS mount directory: {error}"))?;
    fs::create_dir_all(&rootfs_mount_target)
        .map_err(|error| format!("creating guest isolation rootfs mount directory: {error}"))?;
    let broker_channel = connect_broker(config.broker_port)?;

    let isolation = WorkloadIsolationConfig::new(
        &config.isolation_launcher,
        "/",
        &rootfs_mount_target,
        rootfs_mount_target.join(".old-root"),
        "/workspace",
        WorkloadIsolationLimits::new(
            "/tmp",
            WORKLOAD_TMPFS_BYTES,
            WORKLOAD_MEMORY_BYTES,
            WORKLOAD_PIDS_MAX,
            geteuid().as_raw(),
            getegid().as_raw(),
        ),
        broker_channel.as_raw_fd(),
        identity.session.clone(),
    );
    let host = LinuxHostResources::new(LinuxHostConfig::new(
        &config.cgroup_parent,
        &control_directory,
        &config.workload,
        std::iter::empty::<OsString>(),
        isolation,
        SubjectCredential::new(geteuid().as_raw(), getegid().as_raw()),
    ))
    .map_err(|error| format!("initializing guest Linux resources: {error}"))?;
    let imported = ImportedRepository::open(
        config.repository.clone(),
        workspace,
        PreflightLimits::new(
            NonZeroUsize::new(CAPFS_LIMIT_ENTRIES).expect("constant is non-zero"),
            CAPFS_LIMIT_DEPTH,
        ),
    )
    .map_err(|error| format!("importing guest workspace: {error}"))?;
    let authority = AuthorityBody::File(FileAuthority::new(
        config.repository.clone(),
        config.effects,
        config.path.clone(),
    ));
    let validity = TimeWindow::new(
        MonotonicTime::from_ticks(0),
        MonotonicTime::from_ticks(u64::MAX),
    )
    .expect("constant validity must be non-empty");
    let plan = CapfsMountPlan::new(
        subject.clone(),
        MountInstanceId::new(identity.subject.clone()),
        capability,
        CapabilityGrant::new(subject.clone(), validity, authority.clone()),
        &mountpoint,
    );
    let audit_path = config.runtime_dir.join("authority.audit");
    let manager = CapfsRuntimeManager::new(
        host,
        CapfsRuntimeConfig::new(
            CapabilityState::new(IssuerId::new(identity.session.clone())),
            DurableAuditLog::create(&audit_path)
                .map_err(|error| format!("creating guest authority audit: {error}"))?,
            imported,
            Arc::new(MonotonicTime::from_ticks(1)),
            CapfsUnmountStrategy::kernel(),
            vec![plan],
        ),
    )
    .map_err(|error| format!("building guest CapFS runtime: {error}"))?;
    let mut supervisor = manager
        .into_supervisor(SubjectCredentialResolver::new())
        .map_err(|error| format!("building guest supervisor: {error}"))?;

    supervisor
        .resources_mut()
        .host_mut()
        .prepare_control_listener(&subject)
        .map_err(|error| format!("reserving bootstrap control listener: {error}"))?;
    let control_path = supervisor
        .resources()
        .host()
        .control_socket_path(&subject)
        .ok_or_else(|| "deriving guest control listener path".to_owned())?;
    let bootstrap = connect_seqpacket(&control_path)?;
    let bootstrap_connection = supervisor.with_resources_and_callers(|resources, callers| {
        resources
            .host_mut()
            .control_listener(&subject)
            .ok_or_else(|| "guest bootstrap listener disappeared".to_owned())?
            .accept(callers)
            .map_err(|error| format!("accepting guest bootstrap channel: {error}"))
    })?;
    supervisor
        .create_subject(
            Subject::new(
                subject.clone(),
                StaticAuthorityEnvelope::new(validity, authority),
            ),
            bootstrap_connection.identity(),
        )
        .map_err(|error| format!("starting guest subject: {error}"))?;
    drop(bootstrap);
    drop(bootstrap_connection);

    let accepted = supervisor.with_resources_and_callers(|resources, callers| {
        resources
            .host_mut()
            .control_listener(&subject)
            .ok_or_else(|| "guest workload control listener disappeared".to_owned())?
            .accept(callers)
            .map_err(|error| format!("accepting isolated workload channel: {error}"))
    })?;
    let connection = accepted.identity();
    supervisor
        .bind_accepted_connection(connection)
        .map_err(|error| format!("binding isolated workload channel: {error}"))?;

    loop {
        let request = accepted
            .receive_request()
            .map_err(|error| format!("receiving workload control request: {error}"))?;
        let response = match supervisor.dispatch_request(&connection, request) {
            Ok(DispatchResponse::SubjectClosed) => WireResponse::SubjectClosed,
            Ok(DispatchResponse::HandleClosed) => WireResponse::HandleClosed,
            Err(_) => WireResponse::Refused(RefusalCode::NotPermitted),
        };
        accepted
            .send_response(response)
            .map_err(|error| format!("sending workload control response: {error}"))?;
        if response == WireResponse::SubjectClosed {
            return Ok(());
        }
    }
}

#[derive(Debug)]
struct GuestIdentity {
    session: String,
    subject: String,
    capability: String,
}

impl GuestIdentity {
    fn from_environment() -> Result<Self, String> {
        Ok(Self {
            session: identity_environment(GUEST_SESSION_ID_ENV)?,
            subject: identity_environment(GUEST_SUBJECT_ID_ENV)?,
            capability: identity_environment(GUEST_CAPABILITY_ID_ENV)?,
        })
    }
}

fn identity_environment(name: &str) -> Result<String, String> {
    let value =
        env::var(name).map_err(|_| format!("required identity environment {name} is absent"))?;
    if value.len() != 32
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(format!(
            "required identity environment {name} was not canonical lower hexadecimal"
        ));
    }
    Ok(value)
}

fn connect_seqpacket(path: &Path) -> Result<OwnedFd, String> {
    let address = SocketAddrUnix::new(path)
        .map_err(|_| format!("encoding bootstrap control path {}", path.display()))?;
    let socket = socket_with(
        AddressFamily::UNIX,
        SocketType::SEQPACKET,
        SocketFlags::CLOEXEC,
        None,
    )
    .map_err(|error| format!("creating guest bootstrap socket: {error}"))?;
    connect(&socket, &address)
        .map_err(|error| format!("connecting guest bootstrap socket: {error}"))?;
    Ok(socket)
}

fn connect_broker(port: u32) -> Result<Socket, String> {
    let broker = Socket::new(Domain::VSOCK, Type::STREAM, None)
        .map_err(|error| format!("creating guest Broker vsock: {error}"))?;
    broker
        .set_read_timeout(Some(std::time::Duration::from_secs(
            BROKER_IO_TIMEOUT_SECONDS,
        )))
        .map_err(|error| format!("setting guest Broker read timeout: {error}"))?;
    broker
        .set_write_timeout(Some(std::time::Duration::from_secs(
            BROKER_IO_TIMEOUT_SECONDS,
        )))
        .map_err(|error| format!("setting guest Broker write timeout: {error}"))?;
    broker
        .connect(&SockAddr::vsock(HOST_VSOCK_CID, port))
        .map_err(|error| format!("connecting guest Broker to host port {port}: {error}"))?;
    broker
        .set_cloexec(false)
        .map_err(|error| format!("preserving guest Broker descriptor for workload: {error}"))?;
    Ok(broker)
}

fn prepare_runtime_directory(path: &Path) -> Result<(), String> {
    require_absolute_lexical_path("runtime directory", path)?;
    let metadata = fs::metadata(path).map_err(|error| {
        format!(
            "inspecting guest runtime directory {}: {error}",
            path.display()
        )
    })?;
    if !metadata.is_dir() {
        return Err(format!(
            "guest runtime directory is not a directory: {}",
            path.display()
        ));
    }
    mount(
        "tmpfs",
        path,
        "tmpfs",
        MountFlags::NOSUID | MountFlags::NODEV | MountFlags::NOEXEC,
        None,
    )
    .map_err(|error| format!("mounting guest runtime tmpfs {}: {error}", path.display()))
}

/// Mounts the private procfs needed by durable audit handles and the isolation launcher.
///
/// The immutable image intentionally has no distribution init system.  Both the durable audit
/// writer and `RuntimeIsolation` use `/proc/self` kernel views to pin trusted descriptors and
/// inspect namespace state, so PID 1 must establish procfs before constructing either component.
/// The isolated workload replaces this mount with its read-only mask before it executes.
fn prepare_procfs() -> Result<(), String> {
    let path = Path::new(PROC_DIRECTORY);
    fs::create_dir_all(path).map_err(|error| {
        format!(
            "creating guest procfs mount directory {}: {error}",
            path.display()
        )
    })?;
    let filesystem = statfs(path).map_err(|error| {
        format!(
            "inspecting guest procfs mount directory {}: {error}",
            path.display()
        )
    })?;
    if filesystem.f_type == PROC_SUPER_MAGIC {
        return Ok(());
    }
    mount(
        "proc",
        path,
        "proc",
        MountFlags::NOSUID | MountFlags::NODEV | MountFlags::NOEXEC,
        None,
    )
    .map_err(|error| format!("mounting guest procfs {}: {error}", path.display()))
}

/// Verifies the guest-owned device namespace before consuming the workspace block device.
///
/// The immutable image deliberately has no host-provided device nodes. `devtmpfs` is the kernel
/// boundary that exposes only the Firecracker devices assigned to this VM, including `/dev/vdb`
/// and `/dev/fuse`; the subsequently isolated workload never receives the raw mount path. Linux
/// may mount it before PID 1, so the check accepts that exact mount rather than remounting it.
fn prepare_device_directory() -> Result<(), String> {
    let path = Path::new(DEVICE_DIRECTORY);
    fs::create_dir_all(path).map_err(|error| {
        format!(
            "creating guest device directory {}: {error}",
            path.display()
        )
    })?;
    let filesystem = statfs(path).map_err(|error| {
        format!(
            "inspecting guest device directory {}: {error}",
            path.display()
        )
    })?;
    if matches!(filesystem.f_type, DEVTMPFS_SUPER_MAGIC | TMPFS_SUPER_MAGIC) {
        return verify_runtime_devices();
    }
    mount(
        "devtmpfs",
        path,
        "devtmpfs",
        MountFlags::NOSUID | MountFlags::NOEXEC,
        None,
    )
    .map_err(|error| format!("mounting guest devtmpfs {}: {error}", path.display()))?;
    let filesystem = statfs(path).map_err(|error| {
        format!(
            "rechecking guest device directory {}: {error}",
            path.display()
        )
    })?;
    if matches!(filesystem.f_type, DEVTMPFS_SUPER_MAGIC | TMPFS_SUPER_MAGIC) {
        verify_runtime_devices()
    } else {
        Err(format!(
            "guest device directory {} is not devtmpfs after mount",
            path.display()
        ))
    }
}

/// Confirms the image receives exactly the block and FUSE device classes required at runtime.
///
/// Linux reports `devtmpfs` as tmpfs through `statfs`, so the filesystem magic alone does not
/// prove that PID 1 can mount the workspace or run `CapFS`. These typed device checks make a
/// missing Firecracker drive or missing kernel FUSE support fail before any authority is created.
fn verify_runtime_devices() -> Result<(), String> {
    let workspace = fs::metadata(WORKSPACE_DEVICE).map_err(|error| {
        format!("inspecting guest workspace device {WORKSPACE_DEVICE}: {error}")
    })?;
    if !workspace.file_type().is_block_device() {
        return Err(format!(
            "guest workspace device {WORKSPACE_DEVICE} is not a block device"
        ));
    }
    ensure_fuse_device()?;
    let fuse = fs::metadata(FUSE_DEVICE)
        .map_err(|error| format!("inspecting guest FUSE device {FUSE_DEVICE}: {error}"))?;
    if !fuse.file_type().is_char_device() {
        return Err(format!(
            "guest FUSE device {FUSE_DEVICE} is not a character device"
        ));
    }
    Ok(())
}

/// Creates the standard FUSE device node when the kernel has not populated it in devtmpfs.
///
/// `/dev/fuse` is the one fixed kernel interface needed by the image-configured `CapFS` server;
/// it is not a host path or a device selected by an untrusted workload. A kernel that lacks the
/// FUSE driver still rejects the later open, so this node never emulates FUSE support.
fn ensure_fuse_device() -> Result<(), String> {
    match fs::symlink_metadata(FUSE_DEVICE) {
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => mknodat(
            CWD,
            FUSE_DEVICE,
            FileType::CharacterDevice,
            Mode::RUSR | Mode::WUSR,
            makedev(FUSE_MAJOR, FUSE_MINOR),
        )
        .map_err(|error| format!("creating guest FUSE device {FUSE_DEVICE}: {error}")),
        Err(error) => Err(format!(
            "inspecting guest FUSE device {FUSE_DEVICE}: {error}"
        )),
    }
}

/// Mounts the cgroup v2 hierarchy that owns all supervisor-created workload leaves.
///
/// `guest-control-init` is the image's PID 1, so no distribution init system mounts cgroupfs on
/// its behalf. Creating it here ensures `LinuxHostResources` cannot silently fall back to a
/// host-like directory when it assigns the isolated workload's memory and PID limits.
fn prepare_cgroup_hierarchy(path: &Path) -> Result<(), String> {
    require_absolute_lexical_path("cgroup parent", path)?;
    fs::create_dir_all(path).map_err(|error| {
        format!(
            "creating guest cgroup mountpoint {}: {error}",
            path.display()
        )
    })?;
    mount(
        "cgroup2",
        path,
        "cgroup2",
        MountFlags::NOSUID | MountFlags::NODEV | MountFlags::NOEXEC,
        None,
    )
    .map_err(|error| {
        format!(
            "mounting guest cgroup v2 hierarchy {}: {error}",
            path.display()
        )
    })?;
    wait_for_cgroup_controllers(path)?;
    enable_cgroup_controllers(path)
}

fn wait_for_cgroup_controllers(path: &Path) -> Result<(), String> {
    let controllers = path.join("cgroup.controllers");
    let deadline = Instant::now() + CGROUP_READY_TIMEOUT;
    loop {
        let available = fs::read_to_string(&controllers).unwrap_or_default();
        if ["memory", "pids"].into_iter().all(|controller| {
            available
                .split_whitespace()
                .any(|available| available == controller)
        }) {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "guest cgroup v2 controllers did not become ready at {} before timeout: {available:?}",
                controllers.display()
            ));
        }
        std::thread::sleep(CGROUP_READY_POLL_INTERVAL);
    }
}

fn enable_cgroup_controllers(path: &Path) -> Result<(), String> {
    let subtree_control = path.join("cgroup.subtree_control");
    fs::write(&subtree_control, "+memory +pids").map_err(|error| {
        format!(
            "enabling guest memory and PID cgroup controllers at {}: {error}",
            subtree_control.display()
        )
    })
}

fn mount_workspace(device: &Path, target: &Path) -> Result<(), String> {
    require_absolute_lexical_path("workspace device", device)?;
    fs::create_dir_all(target)
        .map_err(|error| format!("creating guest workspace mountpoint: {error}"))?;
    mount(
        device,
        target,
        "ext4",
        MountFlags::NOSUID | MountFlags::NODEV,
        None,
    )
    .map_err(|error| {
        format!(
            "mounting guest workspace device {}: {error}",
            device.display()
        )
    })
}

fn parse_config(arguments: impl IntoIterator<Item = OsString>) -> Result<Config, String> {
    let mut arguments = arguments.into_iter();
    let workspace_device = required_path(&mut arguments, "--workspace-device")?;
    let runtime_dir = required_path(&mut arguments, "--runtime-dir")?;
    let cgroup_parent = required_path(&mut arguments, "--cgroup-parent")?;
    let broker_port = required_port(&mut arguments, "--broker-port")?;
    let isolation_launcher = required_path(&mut arguments, "--isolation-launcher")?;
    let workload = required_path(&mut arguments, "--workload")?;
    expect_flag(&mut arguments, "--repository")?;
    let repository = arguments
        .next()
        .ok_or_else(usage)?
        .into_string()
        .map_err(|_| usage())?;
    expect_flag(&mut arguments, "--file-effects")?;
    let effects = parse_file_effects(
        &arguments
            .next()
            .ok_or_else(usage)?
            .into_string()
            .map_err(|_| usage())?,
    )?;
    expect_flag(&mut arguments, "--path-prefix")?;
    let path = parse_path_prefix(
        &arguments
            .next()
            .ok_or_else(usage)?
            .into_string()
            .map_err(|_| usage())?,
    )?;
    if arguments.next().is_some() {
        return Err(usage());
    }
    Ok(Config {
        workspace_device,
        runtime_dir,
        cgroup_parent,
        broker_port,
        isolation_launcher,
        workload,
        repository: RepoId::new(repository),
        effects,
        path,
    })
}

fn required_port(
    arguments: &mut impl Iterator<Item = OsString>,
    flag: &str,
) -> Result<u32, String> {
    expect_flag(arguments, flag)?;
    let port = arguments
        .next()
        .ok_or_else(usage)?
        .into_string()
        .map_err(|_| usage())?
        .parse::<u32>()
        .map_err(|_| usage())?;
    if port == 0 || port == u32::MAX {
        return Err(format!(
            "{flag} must be explicit, non-zero, and non-wildcard"
        ));
    }
    Ok(port)
}

fn parse_file_effects(value: &str) -> Result<FileEffects, String> {
    const EFFECTS: [(&str, FileEffect); 13] = [
        ("read-data", FileEffect::ReadData),
        ("list-directory", FileEffect::ListDirectory),
        ("write-data", FileEffect::WriteData),
        ("truncate", FileEffect::Truncate),
        ("create-file", FileEffect::CreateFile),
        ("create-directory", FileEffect::CreateDirectory),
        ("remove-file", FileEffect::RemoveFile),
        ("remove-directory", FileEffect::RemoveDirectory),
        ("rename", FileEffect::Rename),
        ("set-metadata", FileEffect::SetMetadata),
        ("read-link", FileEffect::ReadLink),
        ("create-symlink", FileEffect::CreateSymlink),
        ("create-hard-link", FileEffect::CreateHardLink),
    ];

    let mut previous = None;
    let mut effects = Vec::new();
    for name in value.split(',') {
        let index = EFFECTS
            .iter()
            .position(|(candidate, _)| *candidate == name)
            .ok_or_else(|| "file effects must use the canonical closed effect names".to_owned())?;
        if previous.is_some_and(|previous| index <= previous) {
            return Err("file effects must be strictly ordered without duplicates".to_owned());
        }
        previous = Some(index);
        effects.push(EFFECTS[index].1);
    }
    let effects = FileEffects::from_effects(effects);
    if effects.is_empty() {
        return Err("file effects cannot be empty".to_owned());
    }
    Ok(effects)
}

fn parse_path_prefix(value: &str) -> Result<PathPattern, String> {
    if value == "/" {
        return Ok(PathPattern::Prefix(CanonicalPath::root()));
    }
    if value.is_empty() || value.starts_with('/') || value.ends_with('/') {
        return Err("path prefix must be / or canonical repository-relative segments".to_owned());
    }
    CanonicalPath::new(value.split('/'))
        .map(PathPattern::Prefix)
        .map_err(|error| format!("invalid path prefix: {error}"))
}

fn required_path(
    arguments: &mut impl Iterator<Item = OsString>,
    flag: &str,
) -> Result<PathBuf, String> {
    expect_flag(arguments, flag)?;
    let path = PathBuf::from(arguments.next().ok_or_else(usage)?);
    require_absolute_lexical_path(flag, &path)?;
    Ok(path)
}

fn expect_flag(
    arguments: &mut impl Iterator<Item = OsString>,
    expected: &str,
) -> Result<(), String> {
    if arguments.next().as_deref() == Some(OsStr::new(expected)) {
        Ok(())
    } else {
        Err(usage())
    }
}

fn require_absolute_lexical_path(label: &str, path: &Path) -> Result<(), String> {
    if path.is_absolute()
        && path
            .components()
            .all(|component| matches!(component, Component::RootDir | Component::Normal(_)))
    {
        Ok(())
    } else {
        Err(format!("{label} must be an absolute lexical path"))
    }
}

fn usage() -> String {
    "usage: guest-supervisor-init --workspace-device <absolute-path> --runtime-dir <absolute-path> --cgroup-parent <absolute-path> --broker-port <1..4294967294> --isolation-launcher <absolute-path> --workload <absolute-path> --repository <repository-id> --file-effects <canonical-comma-list> --path-prefix </|canonical/relative/path>".to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_fixed_guest_runtime_contract() {
        let config = parse_config([
            OsString::from("--workspace-device"),
            OsString::from("/dev/vdb"),
            OsString::from("--runtime-dir"),
            OsString::from("/run/guest-supervisor"),
            OsString::from("--cgroup-parent"),
            OsString::from("/sys/fs/cgroup"),
            OsString::from("--broker-port"),
            OsString::from("18081"),
            OsString::from("--isolation-launcher"),
            OsString::from("/usr/local/libexec/workload-isolation-launcher"),
            OsString::from("--workload"),
            OsString::from("/usr/local/libexec/agent-workload"),
            OsString::from("--repository"),
            OsString::from("workspace"),
            OsString::from("--file-effects"),
            OsString::from("read-data,list-directory,write-data"),
            OsString::from("--path-prefix"),
            OsString::from("src/agent"),
        ])
        .expect("fixed guest runtime configuration must parse");
        assert_eq!(config.workspace_device, PathBuf::from("/dev/vdb"));
        assert_eq!(config.repository, RepoId::new("workspace"));
        assert_eq!(config.broker_port, 18081);
        assert!(config.effects.contains(FileEffect::ReadData));
        assert!(config.effects.contains(FileEffect::ListDirectory));
        assert!(config.effects.contains(FileEffect::WriteData));
        assert!(!config.effects.contains(FileEffect::Rename));
        assert_eq!(
            config.path,
            PathPattern::Prefix(
                CanonicalPath::new(["src", "agent"]).expect("test path prefix must be canonical")
            )
        );
    }

    #[test]
    fn rejects_ambiguous_runtime_paths() {
        let error = parse_config([
            OsString::from("--workspace-device"),
            OsString::from("workspace"),
        ])
        .expect_err("relative device path must be rejected before side effects");
        assert!(error.contains("workspace-device must be an absolute lexical path"));
    }

    #[test]
    fn rejects_noncanonical_guest_authority_policy() {
        assert!(parse_file_effects("write-data,read-data").is_err());
        assert!(parse_file_effects("read-data,read-data").is_err());
        assert!(parse_file_effects("read").is_err());
        assert!(parse_path_prefix("/src").is_err());
        assert!(parse_path_prefix("src/../secret").is_err());
        assert_eq!(
            parse_path_prefix("/").expect("root path prefix must be accepted"),
            PathPattern::Prefix(CanonicalPath::root())
        );
    }
}
