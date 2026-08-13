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
    os::fd::OwnedFd,
    path::{Component, Path, PathBuf},
    sync::Arc,
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
    mount::{MountFlags, UnmountFlags, mount, unmount},
    net::{AddressFamily, SocketAddrUnix, SocketFlags, SocketType, connect, socket_with},
    process::{getegid, geteuid},
};
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

#[derive(Debug)]
struct Config {
    workspace_device: PathBuf,
    runtime_dir: PathBuf,
    cgroup_parent: PathBuf,
    isolation_launcher: PathBuf,
    workload: PathBuf,
    repository: RepoId,
}

fn main() -> std::process::ExitCode {
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("guest-supervisor-init: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let config = parse_config(env::args_os().skip(1))?;
    let identity = GuestIdentity::from_environment()?;
    prepare_runtime_directory(&config.runtime_dir)?;
    let workspace = config.runtime_dir.join("workspace");
    mount_workspace(&config.workspace_device, &workspace)?;
    let result = run_session(&config, &identity, &workspace);
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
        FileEffects::from_effects([
            FileEffect::ReadData,
            FileEffect::ListDirectory,
            FileEffect::WriteData,
            FileEffect::Truncate,
            FileEffect::CreateFile,
            FileEffect::CreateDirectory,
            FileEffect::RemoveFile,
            FileEffect::RemoveDirectory,
            FileEffect::Rename,
            FileEffect::SetMetadata,
            FileEffect::ReadLink,
            FileEffect::CreateSymlink,
            FileEffect::CreateHardLink,
        ]),
        PathPattern::Prefix(CanonicalPath::root()),
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
    let isolation_launcher = required_path(&mut arguments, "--isolation-launcher")?;
    let workload = required_path(&mut arguments, "--workload")?;
    expect_flag(&mut arguments, "--repository")?;
    let repository = arguments
        .next()
        .ok_or_else(usage)?
        .into_string()
        .map_err(|_| usage())?;
    if arguments.next().is_some() {
        return Err(usage());
    }
    Ok(Config {
        workspace_device,
        runtime_dir,
        cgroup_parent,
        isolation_launcher,
        workload,
        repository: RepoId::new(repository),
    })
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
    "usage: guest-supervisor-init --workspace-device <absolute-path> --runtime-dir <absolute-path> --cgroup-parent <absolute-path> --isolation-launcher <absolute-path> --workload <absolute-path> --repository <repository-id>".to_owned()
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
            OsString::from("--isolation-launcher"),
            OsString::from("/usr/local/libexec/workload-isolation-launcher"),
            OsString::from("--workload"),
            OsString::from("/usr/local/libexec/agent-workload"),
            OsString::from("--repository"),
            OsString::from("workspace"),
        ])
        .expect("fixed guest runtime configuration must parse");
        assert_eq!(config.workspace_device, PathBuf::from("/dev/vdb"));
        assert_eq!(config.repository, RepoId::new("workspace"));
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
}
