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
    io::{self, Write},
    num::NonZeroUsize,
    os::fd::{AsRawFd, OwnedFd},
    os::unix::{
        ffi::OsStrExt,
        fs::{FileTypeExt, MetadataExt},
    },
    path::{Component, Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};

use authority_core::{
    capability::{AuthorityBody, CapId, IssuerId, SubjectId},
    durable_audit::DurableAuditLog,
    file::{FileAuthority, FileEffect, FileEffects},
    path::{CanonicalPath, PathPattern},
    policy::{AuthorityPolicyDigest, ROOT_POLICY_ENCODING_VERSION},
    repository::RepoId,
    state::{CapabilityGrant, CapabilityState, StaticAuthorityEnvelope, Subject},
    time::{MonotonicTime, TimeWindow},
};
use capfs::{
    backing::{ImportedRepository, PreflightLimits},
    read_only::MountInstanceId,
};
use rustix::{
    fs::{CWD, FileType, Mode, major, makedev, minor, mknodat, statfs},
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
const GUEST_POLICY_DIGEST_ENV: &str = "GUEST_AUTHORITY_POLICY_DIGEST";
const GUEST_POLICY_ENCODING_VERSION_ENV: &str = "GUEST_AUTHORITY_POLICY_ENCODING_VERSION";
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
const EXT4_SUPER_MAGIC: i64 = 0x0000_ef53;
const CGROUP2_SUPER_MAGIC: i64 = 0x6367_7270;
const WORKSPACE_DEVICE: &str = "/dev/vdb";
const FUSE_DEVICE: &str = "/dev/fuse";
/// The kernel's own list of mountable filesystems, used to prove FUSE is present.
const PROC_FILESYSTEMS: &str = "/proc/filesystems";
const FUSE_MAJOR: u32 = 10;
const FUSE_MINOR: u32 = 229;
const CGROUP_READY_TIMEOUT: Duration = Duration::from_secs(5);
const CGROUP_READY_POLL_INTERVAL: Duration = Duration::from_millis(10);
const SUPERVISOR_READINESS_ENV: &str = "GUEST_SUPERVISOR_READINESS";
const SUPERVISOR_READINESS_REQUIRED: &str = "1";
const SUPERVISOR_READY_MARKER: &[u8; 25] = b"guest-supervisor-ready/v1";
const MOUNTINFO_PATH: &str = "/proc/self/mountinfo";
// Linux statfs(2) mount flag values.  `MountFlags` controls the requested mount; statfs is the
// independent kernel view used to verify that the requested policy actually took effect.
const ST_RDONLY: u64 = 0x0001;
const ST_NOSUID: u64 = 0x0002;
const ST_NODEV: u64 = 0x0004;
const ST_NOEXEC: u64 = 0x0008;
const REQUIRED_PRIVATE_MOUNT_FLAGS: u64 = ST_NOSUID | ST_NODEV | ST_NOEXEC;

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

#[derive(Debug, Clone, PartialEq, Eq)]
struct MountInfo {
    mount_id: u64,
    major: u32,
    minor: u32,
    root: Vec<u8>,
    filesystem_type: Vec<u8>,
    source: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct OwnedMount {
    path: PathBuf,
    mount_id: u64,
}

/// Tracks only mounts created after this process inspected the target.
///
/// The mount ID is retained as an ownership token.  Before rollback we require the exact same
/// mount to still be present; if another actor replaced or stacked a mount, rollback refuses to
/// unmount it.  This prevents an error path from turning an existing mount into an unowned
/// teardown target.
#[derive(Debug, Default)]
struct MountOwnership {
    mounts: Vec<OwnedMount>,
}

impl MountOwnership {
    fn record(&mut self, path: &Path, mount_id: u64) {
        self.mounts.push(OwnedMount {
            path: path.to_owned(),
            mount_id,
        });
    }

    fn forget(&mut self, path: &Path) -> bool {
        let Some(index) = self.mounts.iter().position(|mount| mount.path == path) else {
            return false;
        };
        self.mounts.remove(index);
        true
    }

    fn contains(&self, path: &Path) -> bool {
        self.mounts.iter().any(|mount| mount.path == path)
    }

    #[cfg(test)]
    fn reverse_paths(&self) -> impl Iterator<Item = &Path> {
        self.mounts.iter().rev().map(|mount| mount.path.as_path())
    }

    fn rollback(&mut self) -> Result<(), String> {
        let mut errors = Vec::new();
        while let Some(owned) = self.mounts.pop() {
            let current = match mount_info_for(&owned.path) {
                Ok(current) => current,
                Err(error) => {
                    errors.push(format!(
                        "cannot verify ownership of mount {} during rollback: {error}",
                        owned.path.display()
                    ));
                    continue;
                }
            };
            let Some(current) = current else {
                // A mount that is already gone needs no further cleanup.
                continue;
            };
            if current.mount_id != owned.mount_id {
                errors.push(format!(
                    "refusing to unmount replaced guest mount {} (owned id {}, current id {})",
                    owned.path.display(),
                    owned.mount_id,
                    current.mount_id
                ));
                continue;
            }
            if let Err(error) = unmount(&owned.path, UnmountFlags::NOFOLLOW) {
                errors.push(format!(
                    "unmounting newly-created guest mount {}: {error}",
                    owned.path.display()
                ));
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors.join("; "))
        }
    }
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
    if env::var_os(SUPERVISOR_READINESS_ENV).as_deref()
        != Some(OsStr::new(SUPERVISOR_READINESS_REQUIRED))
    {
        return Err(
            "guest supervisor readiness channel was not inherited from guest-control-init"
                .to_owned(),
        );
    }
    let config = parse_config(env::args_os().skip(1))?;
    let identity = GuestIdentity::from_environment()?;
    let policy = guest_root_policy(&config, identity.policy_digest)?;
    let mut readiness = io::stdout();
    let mut ownership = MountOwnership::default();
    let workspace = config.runtime_dir.join("workspace");
    let result = (|| {
        prepare_device_directory()?;
        prepare_procfs(&mut ownership)?;
        // Ordered after procfs on purpose: the kernel's own filesystem list is the direct answer
        // to whether FUSE exists, and it only becomes readable once procfs is mounted.
        verify_kernel_supports_fuse()?;
        prepare_cgroup_hierarchy(&config.cgroup_parent, &mut ownership)?;
        prepare_runtime_directory(&config.runtime_dir, &mut ownership)?;
        mount_workspace(&config.workspace_device, &workspace, &mut ownership)?;
        run_session(&config, &identity, &policy, &workspace, &mut readiness)
    })();

    match result {
        Ok(()) => {
            let unmount_result = if ownership.contains(&workspace) {
                unmount(&workspace, UnmountFlags::NOFOLLOW).map_err(|error| {
                    format!(
                        "unmounting guest workspace {}: {error}",
                        workspace.display()
                    )
                })
            } else {
                Ok(())
            };
            match unmount_result {
                Ok(()) => {
                    // Only a workspace mounted by this process is cleaned up.  An accepted
                    // pre-existing workspace mount remains owned by its creator.  The other
                    // process-owned procfs/cgroup/tmpfs mounts retain their existing lifetime
                    // until this guest namespace exits.
                    let _ = ownership.forget(&workspace);
                    Ok(())
                }
                Err(cleanup) => match ownership.rollback() {
                    Ok(()) => Err(cleanup),
                    Err(rollback) => {
                        Err(format!("{cleanup}; setup rollback also failed: {rollback}"))
                    }
                },
            }
        }
        Err(primary) => {
            eprintln!(
                "guest-supervisor-init: setup/session failed before workspace cleanup: {primary}"
            );
            match ownership.rollback() {
                Ok(()) => Err(primary),
                Err(rollback) => Err(format!("{primary}; setup rollback also failed: {rollback}")),
            }
        }
    }
}

#[allow(clippy::too_many_lines)]
fn run_session(
    config: &Config,
    identity: &GuestIdentity,
    policy: &GuestRootPolicy,
    workspace: &Path,
    readiness: &mut impl Write,
) -> Result<(), String> {
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
    let plan = CapfsMountPlan::new(
        subject.clone(),
        MountInstanceId::new(identity.subject.clone()),
        capability,
        CapabilityGrant::new(subject.clone(), policy.validity, policy.authority.clone()),
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
                StaticAuthorityEnvelope::new(policy.validity, policy.authority.clone()),
            ),
            bootstrap_connection.identity(),
        )
        .map_err(|error| format!("starting guest subject: {error}"))?;
    let bootstrap_socket_id = bootstrap_connection.identity().socket_id();
    drop(bootstrap);
    drop(bootstrap_connection);
    supervisor.with_resources_and_callers(|_, callers| {
        callers.release(bootstrap_socket_id);
    });

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
    signal_readiness(readiness)?;

    let session_result = (|| {
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
    })();
    drop(accepted);
    supervisor.with_resources_and_callers(|_, callers| {
        callers.release(connection.socket_id());
    });
    session_result
}

fn signal_readiness(writer: &mut impl Write) -> Result<(), String> {
    writer
        .write_all(SUPERVISOR_READY_MARKER)
        .map_err(|error| format!("signaling guest supervisor readiness: {error}"))?;
    writer
        .flush()
        .map_err(|error| format!("flushing guest supervisor readiness: {error}"))
}

#[derive(Debug)]
struct GuestIdentity {
    session: String,
    subject: String,
    capability: String,
    policy_digest: AuthorityPolicyDigest,
}

impl GuestIdentity {
    fn from_environment() -> Result<Self, String> {
        Ok(Self {
            session: identity_environment(GUEST_SESSION_ID_ENV)?,
            subject: identity_environment(GUEST_SUBJECT_ID_ENV)?,
            capability: identity_environment(GUEST_CAPABILITY_ID_ENV)?,
            policy_digest: policy_binding_environment(
                &env::var(GUEST_POLICY_ENCODING_VERSION_ENV).map_err(|_| {
                    format!(
                        "required authority environment {GUEST_POLICY_ENCODING_VERSION_ENV} is absent"
                    )
                })?,
                &env::var(GUEST_POLICY_DIGEST_ENV).map_err(|_| {
                    format!("required authority environment {GUEST_POLICY_DIGEST_ENV} is absent")
                })?,
            )?,
        })
    }
}

#[derive(Debug)]
struct GuestRootPolicy {
    validity: TimeWindow,
    authority: AuthorityBody,
}

fn guest_root_policy(
    config: &Config,
    expected_digest: AuthorityPolicyDigest,
) -> Result<GuestRootPolicy, String> {
    let validity = TimeWindow::new(
        MonotonicTime::from_ticks(0),
        MonotonicTime::from_ticks(u64::MAX),
    )
    .expect("constant validity must be non-empty");
    let authority = AuthorityBody::File(FileAuthority::new(
        config.repository.clone(),
        config.effects,
        config.path.clone(),
    ));
    let actual_digest = AuthorityPolicyDigest::for_root(validity, &authority, false);
    if actual_digest != expected_digest {
        return Err(
            "host authority policy digest does not match the immutable guest root policy"
                .to_owned(),
        );
    }
    Ok(GuestRootPolicy {
        validity,
        authority,
    })
}

fn policy_binding_environment(
    encoding_version: &str,
    digest: &str,
) -> Result<AuthorityPolicyDigest, String> {
    if encoding_version != ROOT_POLICY_ENCODING_VERSION.to_string() {
        return Err(format!(
            "required authority environment {GUEST_POLICY_ENCODING_VERSION_ENV} has an unsupported version"
        ));
    }
    AuthorityPolicyDigest::from_hex(digest).map_err(|_| {
        format!(
            "required authority environment {GUEST_POLICY_DIGEST_ENV} was not canonical lower hexadecimal"
        )
    })
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

fn prepare_runtime_directory(path: &Path, ownership: &mut MountOwnership) -> Result<(), String> {
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
    ensure_filesystem_mount(
        ownership,
        path,
        "guest runtime directory",
        TMPFS_SUPER_MAGIC,
        REQUIRED_PRIVATE_MOUNT_FLAGS,
        true,
        || {
            mount(
                "tmpfs",
                path,
                "tmpfs",
                MountFlags::NOSUID | MountFlags::NODEV | MountFlags::NOEXEC,
                None,
            )
            .map_err(|error| format!("mounting guest runtime tmpfs {}: {error}", path.display()))
        },
    )
}

/// Mounts the private procfs needed by durable audit handles and the isolation launcher.
///
/// The immutable image intentionally has no distribution init system.  Both the durable audit
/// writer and `RuntimeIsolation` use `/proc/self` kernel views to pin trusted descriptors and
/// inspect namespace state, so PID 1 must establish procfs before constructing either component.
/// The isolated workload replaces this mount with its read-only mask before it executes.
fn prepare_procfs(ownership: &mut MountOwnership) -> Result<(), String> {
    let path = Path::new(PROC_DIRECTORY);
    fs::create_dir_all(path).map_err(|error| {
        format!(
            "creating guest procfs mount directory {}: {error}",
            path.display()
        )
    })?;
    ensure_filesystem_mount(
        ownership,
        path,
        "guest procfs",
        PROC_SUPER_MAGIC,
        REQUIRED_PRIVATE_MOUNT_FLAGS,
        false,
        || {
            mount(
                "proc",
                path,
                "proc",
                MountFlags::NOSUID | MountFlags::NODEV | MountFlags::NOEXEC,
                None,
            )
            .map_err(|error| format!("mounting guest procfs {}: {error}", path.display()))
        },
    )?;
    validate_procfs_identity(path)
}

fn validate_procfs_identity(path: &Path) -> Result<(), String> {
    let mount = mount_info_for(path)?
        .ok_or_else(|| format!("guest procfs {} has no mountinfo record", path.display()))?;
    if mount.root != b"/" || mount.filesystem_type != b"proc" || mount.source != b"proc" {
        return Err(format!(
            "guest procfs {} is not a root proc mount (root {:?}, type {:?}, source {:?})",
            path.display(),
            String::from_utf8_lossy(&mount.root),
            String::from_utf8_lossy(&mount.filesystem_type),
            String::from_utf8_lossy(&mount.source)
        ));
    }
    let self_namespace = fs::read_link("/proc/self/ns/pid")
        .map_err(|error| format!("reading current PID namespace identity: {error}"))?;
    let init_namespace = fs::read_link("/proc/1/ns/pid")
        .map_err(|error| format!("reading guest PID 1 namespace identity: {error}"))?;
    if self_namespace != init_namespace {
        return Err(format!(
            "guest procfs exposes PID 1 from a different namespace ({init_namespace:?}) than the supervisor ({self_namespace:?})"
        ));
    }
    Ok(())
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
    let workspace = fs::symlink_metadata(WORKSPACE_DEVICE).map_err(|error| {
        format!("inspecting guest workspace device {WORKSPACE_DEVICE}: {error}")
    })?;
    if workspace.file_type().is_symlink() || !workspace.file_type().is_block_device() {
        return Err(format!(
            "guest workspace device {WORKSPACE_DEVICE} is not a real block device"
        ));
    }
    ensure_fuse_device()?;
    let fuse = fs::symlink_metadata(FUSE_DEVICE)
        .map_err(|error| format!("inspecting guest FUSE device {FUSE_DEVICE}: {error}"))?;
    if fuse.file_type().is_symlink()
        || !fuse.file_type().is_char_device()
        || major(fuse.rdev()) != FUSE_MAJOR
        || minor(fuse.rdev()) != FUSE_MINOR
    {
        return Err(format!(
            "guest FUSE device {FUSE_DEVICE} is not the real {FUSE_MAJOR}:{FUSE_MINOR} character device"
        ));
    }
    Ok(())
}

/// Confirms the running kernel actually carries the FUSE driver.
///
/// `ensure_fuse_device` can always create the `/dev/fuse` node, because a device node is just an
/// inode carrying a major and minor number. On a kernel built without `CONFIG_FUSE_FS` that node
/// is inert: the `CapFS` server's later mount fails with `ENODEV` from deep inside a spawn, and
/// the message names the runtime directory rather than the missing driver. Every guest file
/// operation goes through that mount, so this is not a degraded mode — the session cannot start
/// at all — and the reason should be stated once, here, before any authority exists.
///
/// `/proc/filesystems` is the kernel's own list of what it can mount, which makes it the direct
/// answer rather than an inference from a build flag.
fn verify_kernel_supports_fuse() -> Result<(), String> {
    let filesystems = fs::read_to_string(PROC_FILESYSTEMS).map_err(|error| {
        format!("reading supported guest filesystems from {PROC_FILESYSTEMS}: {error}")
    })?;
    if filesystems
        .lines()
        .any(|line| line.split_whitespace().last() == Some("fuse"))
    {
        return Ok(());
    }
    Err(format!(
        "the guest kernel has no FUSE driver, so the CapFS workspace mount every file operation \
         depends on cannot be created; rebuild or repin the guest kernel with CONFIG_FUSE_FS \
         ({PROC_FILESYSTEMS} lists no fuse entry)"
    ))
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
fn prepare_cgroup_hierarchy(path: &Path, ownership: &mut MountOwnership) -> Result<(), String> {
    require_absolute_lexical_path("cgroup parent", path)?;
    fs::create_dir_all(path).map_err(|error| {
        format!(
            "creating guest cgroup mountpoint {}: {error}",
            path.display()
        )
    })?;
    ensure_filesystem_mount(
        ownership,
        path,
        "guest cgroup v2 hierarchy",
        CGROUP2_SUPER_MAGIC,
        REQUIRED_PRIVATE_MOUNT_FLAGS,
        true,
        || {
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
            })
        },
    )?;
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

fn ensure_filesystem_mount<F>(
    ownership: &mut MountOwnership,
    path: &Path,
    label: &str,
    expected_type: i64,
    required_flags: u64,
    require_read_write: bool,
    mount_action: F,
) -> Result<(), String>
where
    F: FnOnce() -> Result<(), String>,
{
    if mount_info_for(path)?.is_none() {
        mount_action()?;
        let mounted = mount_info_for(path)?.ok_or_else(|| {
            format!(
                "{label} {} is not a mount after mount completed",
                path.display()
            )
        })?;
        // Record before any post-mount validation so every successful mount has an ownership
        // token available to the failure path.
        ownership.record(path, mounted.mount_id);
    }
    let filesystem = statfs(path)
        .map_err(|error| format!("inspecting {label} {} after mount: {error}", path.display()))?;
    let flags = u64::try_from(filesystem.f_flags).map_err(|_| {
        format!(
            "{label} {} reported a negative statfs flag word",
            path.display()
        )
    })?;
    validate_statfs(
        label,
        filesystem.f_type as i64,
        flags,
        expected_type,
        required_flags,
        require_read_write,
    )
    .map_err(|error| {
        format!(
            "{label} {} failed mount validation: {error}",
            path.display()
        )
    })
}

fn validate_statfs(
    label: &str,
    actual_type: i64,
    actual_flags: u64,
    expected_type: i64,
    required_flags: u64,
    require_read_write: bool,
) -> Result<(), String> {
    if actual_type != expected_type {
        return Err(format!(
            "{label} has filesystem type {actual_type:#x}, expected {expected_type:#x}"
        ));
    }
    let missing_flags = required_flags & !actual_flags;
    if missing_flags != 0 {
        return Err(format!(
            "{label} is missing required statfs flags {missing_flags:#x} (reported {actual_flags:#x})"
        ));
    }
    if require_read_write && actual_flags & ST_RDONLY != 0 {
        return Err(format!(
            "{label} is read-only according to statfs flags {actual_flags:#x}"
        ));
    }
    Ok(())
}

fn block_device_numbers(path: &Path) -> Result<(u32, u32), String> {
    let metadata = fs::metadata(path).map_err(|error| {
        format!(
            "inspecting guest workspace device {}: {error}",
            path.display()
        )
    })?;
    if !metadata.file_type().is_block_device() {
        return Err(format!(
            "guest workspace device {} is not a block device",
            path.display()
        ));
    }
    let device = metadata.rdev();
    Ok((major(device), minor(device)))
}

fn mount_info_for(path: &Path) -> Result<Option<MountInfo>, String> {
    let mountinfo = match fs::read(MOUNTINFO_PATH) {
        Ok(mountinfo) => mountinfo,
        // A fresh guest can legitimately have no procfs yet.  In that one case there cannot be
        // an existing /proc mount to mistake for ours; prepare_procfs will mount it and the
        // post-mount ownership lookup will then have a readable mountinfo file.
        Err(error)
            if path == Path::new(PROC_DIRECTORY)
                && error.kind() == std::io::ErrorKind::NotFound =>
        {
            return Ok(None);
        }
        Err(error) => {
            return Err(format!(
                "reading {MOUNTINFO_PATH} for mount ownership: {error}"
            ));
        }
    };
    let expected = path.as_os_str().as_bytes();
    let mut found = None;
    for line in mountinfo
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
    {
        let fields = line
            .split(|byte| *byte == b' ')
            .filter(|field| !field.is_empty())
            .collect::<Vec<_>>();
        let separator = fields
            .iter()
            .position(|field| *field == b"-")
            .ok_or_else(|| "mountinfo record has no filesystem separator".to_owned())?;
        if fields.len() < 6 || separator + 2 >= fields.len() {
            return Err("mountinfo record is incomplete".to_owned());
        }
        if decode_mountinfo_path(fields[4])? != expected {
            continue;
        }
        let mount_id = parse_mountinfo_integer(fields[0], "mount ID")?;
        let (major, minor) = parse_mountinfo_device(fields[2])?;
        let info = MountInfo {
            mount_id,
            major,
            minor,
            root: decode_mountinfo_path(fields[3])?,
            filesystem_type: fields[separator + 1].to_vec(),
            source: fields[separator + 2].to_vec(),
        };
        if found.is_some() {
            return Err(format!(
                "mount point {} has multiple stacked mount records",
                path.display()
            ));
        }
        found = Some(info);
    }
    Ok(found)
}

fn parse_mountinfo_integer(value: &[u8], label: &str) -> Result<u64, String> {
    let value =
        std::str::from_utf8(value).map_err(|_| format!("mountinfo {label} is not UTF-8"))?;
    value
        .parse::<u64>()
        .map_err(|_| format!("mountinfo {label} is not numeric"))
}

fn parse_mountinfo_device(value: &[u8]) -> Result<(u32, u32), String> {
    let Some(separator) = value.iter().position(|byte| *byte == b':') else {
        return Err("mountinfo device has no major/minor separator".to_owned());
    };
    let major = parse_mountinfo_integer(&value[..separator], "device major")?;
    let minor = parse_mountinfo_integer(&value[separator + 1..], "device minor")?;
    let major =
        u32::try_from(major).map_err(|_| "mountinfo device major is too large".to_owned())?;
    let minor =
        u32::try_from(minor).map_err(|_| "mountinfo device minor is too large".to_owned())?;
    Ok((major, minor))
}

fn decode_mountinfo_path(encoded: &[u8]) -> Result<Vec<u8>, String> {
    let mut decoded = Vec::with_capacity(encoded.len());
    let mut index = 0;
    while index < encoded.len() {
        if encoded[index] != b'\\' {
            decoded.push(encoded[index]);
            index += 1;
            continue;
        }
        let Some(octal) = encoded.get(index + 1..index + 4) else {
            return Err("truncated mountinfo escape".to_owned());
        };
        if !octal.iter().all(|byte| (b'0'..=b'7').contains(byte)) {
            return Err("invalid mountinfo escape".to_owned());
        }
        decoded.push((octal[0] - b'0') * 64 + (octal[1] - b'0') * 8 + octal[2] - b'0');
        index += 4;
    }
    Ok(decoded)
}

fn mount_workspace(
    device: &Path,
    target: &Path,
    ownership: &mut MountOwnership,
) -> Result<(), String> {
    require_absolute_lexical_path("workspace device", device)?;
    fs::create_dir_all(target)
        .map_err(|error| format!("creating guest workspace mountpoint: {error}"))?;
    let expected_device = block_device_numbers(device)?;
    ensure_filesystem_mount(
        ownership,
        target,
        "guest workspace",
        EXT4_SUPER_MAGIC,
        ST_NOSUID | ST_NODEV,
        true,
        || {
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
        },
    )?;
    let actual_mount = mount_info_for(target)?.ok_or_else(|| {
        format!(
            "guest workspace {} disappeared while verifying its mount",
            target.display()
        )
    })?;
    if (actual_mount.major, actual_mount.minor) != expected_device {
        return Err(format!(
            "guest workspace {} is backed by device {}:{}, expected {}:{} from {}",
            target.display(),
            actual_mount.major,
            actual_mount.minor,
            expected_device.0,
            expected_device.1,
            device.display()
        ));
    }
    Ok(())
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
    fn readiness_signal_is_one_exact_marker_and_flushes() {
        let mut bytes = Vec::new();
        signal_readiness(&mut bytes).expect("readiness marker must be writable");
        assert_eq!(bytes, SUPERVISOR_READY_MARKER);
    }

    #[test]
    fn readiness_signal_reports_a_closed_channel() {
        struct Closed;

        impl Write for Closed {
            fn write(&mut self, _buffer: &[u8]) -> io::Result<usize> {
                Err(io::Error::new(io::ErrorKind::BrokenPipe, "closed"))
            }

            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }

        let error = signal_readiness(&mut Closed).expect_err("closed readiness must fail");
        assert!(error.contains("signaling guest supervisor readiness"));
    }

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

    #[test]
    fn guest_policy_must_recompute_to_the_host_bound_digest_before_setup() {
        let config = Config {
            workspace_device: PathBuf::from("/dev/vdb"),
            runtime_dir: PathBuf::from("/run/guest-supervisor"),
            cgroup_parent: PathBuf::from("/sys/fs/cgroup"),
            broker_port: 18_081,
            isolation_launcher: PathBuf::from("/usr/local/libexec/workload-isolation-launcher"),
            workload: PathBuf::from("/usr/local/libexec/agent-workload"),
            repository: RepoId::new("workspace"),
            effects: FileEffects::from_effects([
                FileEffect::ReadData,
                FileEffect::ListDirectory,
                FileEffect::WriteData,
            ]),
            path: PathPattern::Prefix(CanonicalPath::root()),
        };
        let validity = TimeWindow::new(
            MonotonicTime::from_ticks(0),
            MonotonicTime::from_ticks(u64::MAX),
        )
        .expect("fixed guest validity");
        let authority = AuthorityBody::File(FileAuthority::new(
            RepoId::new("workspace"),
            config.effects,
            PathPattern::Prefix(CanonicalPath::root()),
        ));
        let expected = AuthorityPolicyDigest::for_root(validity, &authority, false);
        assert!(guest_root_policy(&config, expected).is_ok());

        let foreign = AuthorityPolicyDigest::for_root(validity, &authority, true);
        let error = guest_root_policy(&config, foreign)
            .expect_err("a digest for a delegable host grant must fail closed");
        assert!(error.contains("does not match"));
    }

    #[test]
    fn guest_policy_binding_environment_is_exact_and_versioned() {
        let digest = "a5".repeat(32);
        assert_eq!(
            policy_binding_environment(&ROOT_POLICY_ENCODING_VERSION.to_string(), &digest)
                .expect("canonical policy binding"),
            AuthorityPolicyDigest::from_hex(&digest).expect("canonical test digest")
        );
        assert!(policy_binding_environment("0", &digest).is_err());
        assert!(policy_binding_environment("01", &digest).is_err());
        assert!(
            policy_binding_environment(&ROOT_POLICY_ENCODING_VERSION.to_string(), "A5").is_err()
        );
    }

    #[test]
    fn mount_ownership_exposes_only_reverse_creation_order() {
        let mut ownership = MountOwnership::default();
        ownership.record(Path::new("/proc"), 10);
        ownership.record(Path::new("/run/guest-supervisor"), 11);
        ownership.record(Path::new("/run/guest-supervisor/workspace"), 12);

        let paths = ownership
            .reverse_paths()
            .map(Path::to_owned)
            .collect::<Vec<_>>();
        assert_eq!(
            paths,
            vec![
                PathBuf::from("/run/guest-supervisor/workspace"),
                PathBuf::from("/run/guest-supervisor"),
                PathBuf::from("/proc"),
            ]
        );
        assert!(ownership.forget(Path::new("/run/guest-supervisor")));
        assert!(!ownership.forget(Path::new("/run/guest-supervisor")));
        assert!(ownership.contains(Path::new("/proc")));
        assert!(!ownership.contains(Path::new("/run/guest-supervisor")));
    }

    #[test]
    fn statfs_validation_rejects_type_flag_and_read_only_mismatches() {
        assert!(
            validate_statfs(
                "runtime",
                TMPFS_SUPER_MAGIC,
                REQUIRED_PRIVATE_MOUNT_FLAGS,
                TMPFS_SUPER_MAGIC,
                REQUIRED_PRIVATE_MOUNT_FLAGS,
                true
            )
            .is_ok()
        );
        assert!(
            validate_statfs(
                "runtime",
                PROC_SUPER_MAGIC,
                REQUIRED_PRIVATE_MOUNT_FLAGS,
                TMPFS_SUPER_MAGIC,
                REQUIRED_PRIVATE_MOUNT_FLAGS,
                true
            )
            .expect_err("heterogeneous filesystem must fail")
            .contains("filesystem type")
        );
        assert!(
            validate_statfs(
                "runtime",
                TMPFS_SUPER_MAGIC,
                ST_NOSUID | ST_NODEV,
                TMPFS_SUPER_MAGIC,
                REQUIRED_PRIVATE_MOUNT_FLAGS,
                true
            )
            .expect_err("missing noexec must fail")
            .contains("missing required")
        );
        assert!(
            validate_statfs(
                "workspace",
                EXT4_SUPER_MAGIC,
                ST_NOSUID | ST_NODEV | ST_RDONLY,
                EXT4_SUPER_MAGIC,
                ST_NOSUID | ST_NODEV,
                true
            )
            .expect_err("read-only workspace must fail")
            .contains("read-only")
        );
    }

    #[test]
    fn mountinfo_path_parser_rejects_truncated_and_invalid_escapes() {
        assert_eq!(
            decode_mountinfo_path(br"/run/guest\040supervisor"),
            Ok(b"/run/guest supervisor".to_vec())
        );
        assert!(decode_mountinfo_path(br"/run/guest\04").is_err());
        assert!(decode_mountinfo_path(br"/run/guest\0zz").is_err());
        assert_eq!(parse_mountinfo_device(b"8:16"), Ok((8, 16)));
        assert!(parse_mountinfo_device(b"8/16").is_err());
        assert!(parse_mountinfo_device(b"4294967296:1").is_err());
    }
}
