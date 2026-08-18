//! Opt-in, real-adapter coverage for one complete production session owner.
//!
//! This gate is intentionally ignored by ordinary unit-test runs.  The companion CI wrapper
//! supplies pinned Firecracker/guest artifacts and executes it only on a Linux host with KVM,
//! cgroup-v2, dm-verity, and `AF_VSOCK`.  Nothing in this test replaces Firecracker, the jailer,
//! the filesystem, the guest-control client, or the production Broker listener with a test
//! double.

#![cfg(target_os = "linux")]

use std::{
    fs::{self, File},
    io::{self, Write},
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use authority_core::{
    capability::{AuthorityBody, IssuerId},
    file::{FileAuthority, FileEffect, FileEffects},
    path::{CanonicalPath, PathPattern},
    repository::RepoId,
    time::{MonotonicTime, TimeWindow},
};
use egress_broker::{
    dispatch::PublicDispatchAdapter,
    github::GitHubAdapter,
    public_fetch::{FetchError, PublicResponse},
};
use firecracker_runtime::{
    ApiClient, ApiRequest, CgroupConfig, CgroupVersion, DmVerityConfig, FirecrackerVsockApiClient,
    HostIsolationConfig, HttpMethod, JailerConfig, NamespaceConfig, PinnedArtifact,
    RealCommandRunner, RealFileSystem, Runtime, RuntimeConfig, RuntimeState, SeccompConfig,
    SystemIdentitySource, UnixApiClient, VsockConfig, WorkspaceConfig, WorkspaceImageConfig,
    sha256,
};
use session_orchestrator::{
    BackendError, DurableIdentityLedger, WorkspaceTemplateId,
    authority_backend::AuthorityRootGrant,
    filesystem_factory::{FilesystemFirecrackerFactory, GuestArtifactTemplate, SnapshotTemplate},
    production_runtime::{
        AuthorityAuditMode, PerSessionEgressFactory, PreparedEgressSession,
        ProductionBrokerEndpoint, ProductionBrokerLimits, ProductionDurabilityConfig,
        ProductionFirecrackerConfig, ProductionGuestControlEndpoint, ProductionSessionConfig,
        ProductionSessionRuntime, ProductionSessionRuntimeBuilder, SessionEgressRequest,
    },
    recovery::DurableSessionRecoveryJournal,
    session_owner::{OwnerPollOutcome, OwnerPollRequest, ShutdownReason},
};

const GUEST_MEMORY_MIB: u32 = 256;
const GUEST_CID: u32 = 42;
const GUEST_CONTROL_PORT: u32 = 19_002;
const BROKER_PORT: u32 = 19_001;
const API_TIMEOUT: Duration = Duration::from_secs(10);
const GUEST_READY_TIMEOUT: Duration = Duration::from_secs(50);
const CGROUP_MEMORY_MAX: u64 = 768 * 1024 * 1024;
const CGROUP_CPU_QUOTA: u64 = 100_000;
const CGROUP_CPU_PERIOD: u64 = 100_000;

/// A private temporary directory without adding a package-level test dependency.
struct TemporaryDirectory {
    path: PathBuf,
}

impl TemporaryDirectory {
    fn new() -> Self {
        let parent = std::env::var_os("REAL_SESSION_TEMP_ROOT")
            .map_or_else(|| PathBuf::from("/root"), PathBuf::from);
        let parent_metadata = fs::symlink_metadata(&parent)
            .unwrap_or_else(|error| panic!("real lifecycle temp root is not accessible: {error}"));
        assert!(
            parent_metadata.is_dir() && !parent_metadata.file_type().is_symlink(),
            "real lifecycle temp root must be a non-symlink directory"
        );
        assert_eq!(
            parent_metadata.permissions().mode() & 0o022,
            0,
            "real lifecycle temp root must not be group/world writable"
        );
        // The jailer puts API/vsock sockets below this directory. Keep the component short so
        // the resulting Unix socket paths stay below SUN_LEN even when the wrapper uses a
        // private parent such as `/root/so.XXXXXX`.
        let fixed_name = std::env::var("REAL_SESSION_FIXED_DIRECTORY").ok();
        if let Some(name) = fixed_name.as_deref() {
            assert!(
                !name.is_empty()
                    && name.len() <= 48
                    && name.bytes().all(|byte| byte.is_ascii_lowercase()
                        || byte.is_ascii_digit()
                        || byte == b'-'),
                "REAL_SESSION_FIXED_DIRECTORY must be a bounded lowercase identifier"
            );
        }
        let path = fixed_name.map_or_else(
            || parent.join(format!("s-{}", std::process::id())),
            |name| parent.join(name),
        );
        fs::create_dir_all(&path).unwrap_or_else(|error| {
            panic!("cannot create private real lifecycle staging directory: {error}")
        });
        let metadata = fs::symlink_metadata(&path)
            .expect("real lifecycle staging directory must remain inspectable");
        assert!(
            metadata.is_dir() && !metadata.file_type().is_symlink(),
            "real lifecycle staging path must remain a non-symlink directory"
        );
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
            .expect("real lifecycle staging directory must be private");
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TemporaryDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn required_file(variable: &str) -> PathBuf {
    let value = std::env::var_os(variable).unwrap_or_else(|| panic!("{variable} must be set"));
    let path = PathBuf::from(value);
    assert!(path.is_absolute(), "{variable} must be absolute");
    let metadata = fs::symlink_metadata(&path)
        .unwrap_or_else(|error| panic!("{variable} is not accessible: {error}"));
    assert!(metadata.is_file(), "{variable} must be a regular file");
    assert!(
        !metadata.file_type().is_symlink(),
        "{variable} must not be a symlink"
    );
    path
}

fn pinned(path: &Path) -> PinnedArtifact {
    let bytes = fs::read(path)
        .unwrap_or_else(|error| panic!("cannot read pinned artifact {}: {error}", path.display()));
    PinnedArtifact::new(path, sha256(&bytes))
}

fn root_hash() -> firecracker_runtime::Sha256Digest {
    let value = std::env::var("REAL_SESSION_ROOT_HASH")
        .expect("REAL_SESSION_ROOT_HASH must be set by the real lifecycle wrapper");
    firecracker_runtime::Sha256Digest::from_hex(value.trim())
        .expect("REAL_SESSION_ROOT_HASH must be one 64-character hex digest")
}

fn make_directory(path: &Path, mode: u32) {
    fs::create_dir_all(path)
        .unwrap_or_else(|error| panic!("cannot create {}: {error}", path.display()));
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .unwrap_or_else(|error| panic!("cannot set permissions on {}: {error}", path.display()));
}

fn export_snapshot_if_requested(snapshot_state: &Path, snapshot_memory: &Path) {
    let Some(root) = std::env::var_os("REAL_SESSION_ARTIFACT_EXPORT_ROOT") else {
        return;
    };
    let root = PathBuf::from(root);
    assert!(root.is_absolute(), "artifact export root must be absolute");
    let metadata = fs::symlink_metadata(&root)
        .expect("artifact export root must be created by the trusted wrapper");
    assert!(
        metadata.is_dir()
            && !metadata.file_type().is_symlink()
            && metadata.uid() == rustix::process::geteuid().as_raw()
            && metadata.permissions().mode() & 0o022 == 0,
        "artifact export root must be a secure directory owned by the test identity"
    );
    for (source, name) in [
        (snapshot_state, "snapshot.state"),
        (snapshot_memory, "snapshot.memory"),
    ] {
        let destination = root.join(name);
        let mut input = File::open(source)
            .unwrap_or_else(|error| panic!("cannot open snapshot export source: {error}"));
        let mut output = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&destination)
            .unwrap_or_else(|error| panic!("cannot create snapshot export {name}: {error}"));
        io::copy(&mut input, &mut output)
            .unwrap_or_else(|error| panic!("cannot copy snapshot export {name}: {error}"));
        output
            .sync_all()
            .unwrap_or_else(|error| panic!("cannot sync snapshot export {name}: {error}"));
        fs::set_permissions(&destination, fs::Permissions::from_mode(0o444))
            .unwrap_or_else(|error| panic!("cannot protect snapshot export {name}: {error}"));
    }
}

fn authority_grant() -> AuthorityRootGrant {
    let validity = TimeWindow::new(
        MonotonicTime::from_ticks(0),
        MonotonicTime::from_ticks(u64::MAX),
    )
    .expect("real lifecycle authority window must be non-empty");
    AuthorityRootGrant::new(
        validity,
        AuthorityBody::File(FileAuthority::new(
            RepoId::new("workspace"),
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
        )),
    )
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn runtime_profile(
    root: &Path,
    firecracker: &Path,
    jailer: &Path,
    kernel: &Path,
    rootfs: &Path,
    verity_hash: &Path,
    veritysetup: &Path,
    formatter: &Path,
    seccomp: &Path,
    seccomp_policy: &Path,
    seccomp_compiler: &Path,
    guest_cid: u32,
    broker_port: u32,
    hold_workload_after_probe: bool,
) -> (RuntimeConfig, PathBuf, PathBuf) {
    let jailer_base = root.join("jailer");
    let executable_parent = jailer_base.join("firecracker");
    let template_id = "template";
    let jail_root = executable_parent.join(template_id).join("root");
    for directory in [
        jail_root.join("dev"),
        jail_root.join("run"),
        jail_root.join("workspace"),
        jail_root.join("artifacts"),
        jail_root.join("snapshots"),
    ] {
        make_directory(&directory, 0o755);
    }
    // Firecracker runs as nobody after jailer setup. Give it two pre-created, zero-length
    // snapshot slots rather than making the entire snapshot directory guest-writable.
    for slot in ["state", "memory"] {
        let path = jail_root.join("snapshots").join(slot);
        File::create(&path).unwrap_or_else(|error| {
            panic!(
                "cannot create template snapshot slot {}: {error}",
                path.display()
            )
        });
        fs::set_permissions(&path, fs::Permissions::from_mode(0o666))
            .unwrap_or_else(|error| panic!("cannot make template snapshot slot writable: {error}"));
    }

    let jail_kernel_path = jail_root.join("artifacts/kernel");
    let jail_seccomp_path = jail_root.join("artifacts/seccomp");
    fs::copy(kernel, &jail_kernel_path).expect("template kernel must be copied into the jail");
    fs::copy(seccomp, &jail_seccomp_path).expect("template seccomp must be copied into the jail");
    fs::set_permissions(&jail_kernel_path, fs::Permissions::from_mode(0o644))
        .expect("template kernel must be readable by the jailer");
    fs::set_permissions(&jail_seccomp_path, fs::Permissions::from_mode(0o644))
        .expect("template seccomp must be readable by the jailer");

    let source = root.join("workspace-source");
    make_directory(&source, 0o755);
    let mut marker = File::create(source.join("lifecycle-marker"))
        .expect("real workspace source marker must be creatable");
    marker
        .write_all(b"session-owner-real-lifecycle/v1\n")
        .expect("real workspace source marker must be writable");
    marker
        .sync_all()
        .expect("real workspace source marker must be durable");

    let cgroup_parent = std::env::var_os("REAL_SESSION_CGROUP_PARENT").map_or_else(
        || {
            PathBuf::from(format!(
                "/sys/fs/cgroup/session-owner-real-{}-{}",
                std::process::id(),
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .expect("system clock must be after the Unix epoch")
                    .as_nanos()
            ))
        },
        PathBuf::from,
    );
    fs::create_dir_all(&cgroup_parent).unwrap_or_else(|error| {
        panic!(
            "cannot create production session cgroup parent {}: {error}",
            cgroup_parent.display()
        )
    });
    let cgroup = cgroup_parent.join(template_id);

    let workload_hold = if hold_workload_after_probe {
        " --hold-workload-after-probe"
    } else {
        ""
    };
    let config = RuntimeConfig {
        firecracker: pinned(firecracker),
        kernel: pinned(&jail_kernel_path),
        rootfs: pinned(rootfs),
        verity_hash: pinned(verity_hash),
        veritysetup: pinned(veritysetup),
        dm_verity: DmVerityConfig {
            data_device: rootfs.to_owned(),
            hash_device: verity_hash.to_owned(),
            mapper_name: std::env::var("REAL_SESSION_MAPPER_NAME")
                .unwrap_or_else(|_| format!("session-owner-real-{}", std::process::id())),
            root_hash: root_hash(),
            jailed_device_path: jail_root.join("dev/rootfs"),
        },
        workspace: WorkspaceConfig {
            source,
            clone_root: jail_root.join("workspace"),
            clone_id: template_id.to_owned(),
            image: WorkspaceImageConfig {
                formatter: pinned(formatter),
                size_bytes: 64 * 1024 * 1024,
            },
        },
        jailer: pinned(jailer),
        jailer_config: JailerConfig {
            uid: 65_534,
            gid: 65_534,
            chroot_base_dir: jailer_base,
            cgroup_version: CgroupVersion::V2,
        },
        api_socket: jail_root.join("run/firecracker.sock"),
        isolation: HostIsolationConfig {
            namespaces: NamespaceConfig {
                user: false,
                pid: true,
                mount: true,
                network: false,
                ipc: false,
                uts: false,
            },
            cgroup: CgroupConfig {
                path: cgroup,
                memory_max_bytes: CGROUP_MEMORY_MAX,
                cpu_quota_micros: CGROUP_CPU_QUOTA,
                cpu_period_micros: CGROUP_CPU_PERIOD,
            },
            seccomp: SeccompConfig {
                compiler: pinned(seccomp_compiler),
                filter: pinned(&jail_seccomp_path),
                policy: pinned(seccomp_policy),
                blocked_syscalls: [
                    "bpf",
                    "mount",
                    "perf_event_open",
                    "ptrace",
                    "setns",
                    "unshare",
                ]
                .into_iter()
                .map(str::to_owned)
                .collect(),
            },
        },
        vsock: VsockConfig {
            guest_cid,
            uds_path: jail_root.join("run/vsock.sock"),
        },
        network_devices: Vec::new(),
        vcpu_count: 1,
        memory_mib: GUEST_MEMORY_MIB,
        boot_args: format!(
            "console=ttyS0 reboot=k panic=1 pci=off root=/dev/vda rootfstype=squashfs ro init=/usr/local/libexec/guest-control-init -- --port {GUEST_CONTROL_PORT} --workload /usr/local/libexec/guest-supervisor-init --workspace-device /dev/vdb --runtime-dir /run/guest-supervisor --cgroup-parent /sys/fs/cgroup --broker-port {broker_port} --isolation-launcher /usr/local/libexec/workload-isolation-launcher --workload /usr/local/libexec/agent-workload --repository workspace --file-effects read-data,list-directory,write-data,truncate,create-file,create-directory,remove-file,remove-directory,rename,set-metadata,read-link,create-symlink,create-hard-link --path-prefix /{workload_hold}"
        ),
    };
    (config, cgroup_parent, executable_parent)
}

fn capture_clean_snapshot(root: &Path, config: &RuntimeConfig) -> (PathBuf, PathBuf) {
    config
        .validate()
        .expect("real production template Runtime config must validate before launch");
    let api = UnixApiClient::new(&config.api_socket)
        .expect("template Firecracker API socket path must be valid")
        .with_timeout(API_TIMEOUT)
        .expect("template Firecracker API timeout must be valid");
    let guest = FirecrackerVsockApiClient::new(
        &config.vsock.uds_path,
        config.vsock.guest_cid,
        GUEST_CONTROL_PORT,
    )
    .expect("template guest-control endpoint must be valid");
    let mut runtime = Runtime::new(
        RealCommandRunner::new(),
        RealFileSystem::new(),
        api,
        guest,
        SystemIdentitySource,
    );
    let mut instance = runtime.launch(config).unwrap_or_else(|error| {
        panic!(
            "real template Runtime::launch failed: {error}; staging={}",
            root.display()
        )
    });
    assert_eq!(instance.state(), RuntimeState::WorkloadStopped);
    wait_for_clean_guest_control_listener(config);

    let executable = config
        .firecracker
        .path
        .file_name()
        .expect("validated template Firecracker path must have a filename");
    let jail_root = config
        .jailer_config
        .chroot_base_dir
        .join(executable)
        .join(&config.workspace.clone_id)
        .join("root");
    let state_in_jail = jail_root.join("snapshots/state");
    let memory_in_jail = jail_root.join("snapshots/memory");
    runtime
        .create_snapshot(&mut instance, &state_in_jail, &memory_in_jail)
        .unwrap_or_else(|error| panic!("real clean snapshot capture failed: {error}"));
    assert_eq!(instance.state(), RuntimeState::Snapshotted);

    let state_source = root.join("snapshot-state");
    let memory_source = root.join("snapshot-memory");
    fs::copy(&state_in_jail, &state_source).expect("snapshot state must be copied out of jail");
    fs::copy(&memory_in_jail, &memory_source).expect("snapshot memory must be copied out of jail");
    runtime
        .shutdown(&mut instance, config)
        .unwrap_or_else(|error| panic!("real template Runtime::shutdown failed: {error}"));
    assert_eq!(instance.state(), RuntimeState::Stopped);
    assert!(
        !jail_root.exists(),
        "template jail must be removed after snapshot capture"
    );
    let cgroup = &config.isolation.cgroup.path;
    assert!(!cgroup.exists(), "template cgroup leaf must be removed");
    // Keep the private parent for the following production restore.  The production recovery
    // ledger requires that parent to pre-exist before it reserves a session identity.
    (state_source, memory_source)
}

fn wait_for_clean_guest_control_listener(config: &RuntimeConfig) {
    // Repeated KVM boots on a loaded protected runner can take longer than an
    // individual Firecracker API call. Keep the readiness budget aligned with
    // the production guest-control window while retaining a hard upper bound.
    let deadline = Instant::now() + GUEST_READY_TIMEOUT;
    loop {
        let mut probe = FirecrackerVsockApiClient::new(
            &config.vsock.uds_path,
            config.vsock.guest_cid,
            GUEST_CONTROL_PORT,
        )
        .expect("template guest-control readiness endpoint must be valid");
        let last_error = match probe.request(&ApiRequest {
            method: HttpMethod::Get,
            path: "/pre-session-readiness-probe".to_owned(),
            body: String::new(),
        }) {
            Ok(response) if response.status == 405 => return,
            Ok(response) => format!("unexpected HTTP status {}", response.status),
            Err(error) => error.to_string(),
        };
        assert!(
            Instant::now() < deadline,
            "clean guest-control listener did not become ready before snapshot: {last_error}"
        );
        thread::sleep(Duration::from_millis(50));
    }
}

fn wait_for_completed_guest_effect_probe(
    broker_wal: &Path,
) -> egress_broker::durable::DurableBrokerView {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let observation = match egress_broker::durable::DurableBrokerView::open(broker_wal) {
            Ok(view) if view.requests().is_empty() => {
                "the Broker WAL contains no guest request yet".to_owned()
            }
            Ok(view) if view.requests().len() == 1 => {
                if matches!(
                    view.requests()[0].phase(),
                    egress_broker::durable::DurableRequestPhase::Final(_)
                ) {
                    return view;
                }
                format!(
                    "the guest request is not final yet: {:?}",
                    view.requests()[0].phase()
                )
            }
            Ok(view) => panic!(
                "the guest effect probe produced more than one Broker request: {}",
                view.requests().len()
            ),
            Err(error) => error.to_string(),
        };
        assert!(
            Instant::now() < deadline,
            "guest effect proof did not reach its durable Broker record before the deadline: {observation}"
        );
        thread::sleep(Duration::from_millis(20));
    }
}

fn wait_for_live_completed_guest_effect_probe(
    broker_wal: &Path,
    snapshot_wal: &Path,
) -> egress_broker::durable::DurableBrokerView {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let observation = match fs::copy(broker_wal, snapshot_wal) {
            Ok(_) => match egress_broker::durable::DurableBrokerView::open(snapshot_wal) {
                Ok(view) if view.requests().is_empty() => {
                    "the live Broker WAL snapshot contains no guest request yet".to_owned()
                }
                Ok(view) if view.requests().len() == 1 => {
                    if matches!(
                        view.requests()[0].phase(),
                        egress_broker::durable::DurableRequestPhase::Final(_)
                    ) {
                        return view;
                    }
                    format!(
                        "the live Broker WAL snapshot request is not final yet: {:?}",
                        view.requests()[0].phase()
                    )
                }
                Ok(view) => panic!(
                    "the live guest effect probe produced more than one Broker request: {}",
                    view.requests().len()
                ),
                Err(error) => error.to_string(),
            },
            Err(error) => error.to_string(),
        };
        assert!(
            Instant::now() < deadline,
            "live guest effect proof did not reach a durable Broker record before the deadline: {observation}"
        );
        thread::sleep(Duration::from_millis(20));
    }
}

struct ClosedPublicAdapter;

impl PublicDispatchAdapter for ClosedPublicAdapter {
    fn fetch(
        &self,
        _request: &authority_core::http::HttpFetchRequest,
        _authority: &authority_core::http::HttpFetchAuthority,
    ) -> Result<PublicResponse, FetchError> {
        Err(FetchError::OperationRejected)
    }
}

struct ClosedGitHubAdapter;

impl GitHubAdapter for ClosedGitHubAdapter {
    fn execute(
        &mut self,
        _request_id: egress_protocol::session::BrokerRequestId,
        _request: &authority_core::github::GitHubRequest,
        _authority: &authority_core::github::GitHubAuthority,
        _max_response_bytes: u64,
    ) -> Result<egress_broker::github::GitHubResponse, egress_broker::github::GitHubAdapterError>
    {
        Err(egress_broker::github::GitHubAdapterError::NotAuthorized)
    }
}

struct ClosedEgressFactory;

impl PerSessionEgressFactory for ClosedEgressFactory {
    fn prepare(
        &self,
        request: &SessionEgressRequest,
    ) -> Result<PreparedEgressSession, BackendError> {
        Ok(PreparedEgressSession::new(
            request,
            ClosedPublicAdapter,
            ClosedGitHubAdapter,
            || MonotonicTime::from_ticks(0),
        ))
    }
}

#[allow(clippy::too_many_arguments)]
fn build_real_production_runtime(
    durability_root: &Path,
    template_runtime: RuntimeConfig,
    snapshot_state: &Path,
    snapshot_memory: &Path,
    snapshot_id: u8,
    guest_cid: u32,
    broker_port: u32,
    kernel: &Path,
    seccomp: &Path,
    veritysetup: &Path,
    dmsetup: &Path,
    grant: &AuthorityRootGrant,
) -> (ProductionSessionRuntime, PathBuf) {
    make_directory(durability_root, 0o700);
    let broker_wal_root = durability_root.join("b");
    make_directory(&broker_wal_root, 0o700);
    let factory = FilesystemFirecrackerFactory::with_guest_artifacts(
        session_orchestrator::SnapshotId::new([snapshot_id; session_orchestrator::ID_BYTES]),
        template_runtime.clone(),
        GuestArtifactTemplate::new(pinned(kernel), pinned(seccomp)),
        SnapshotTemplate::new(
            pinned(snapshot_state),
            pinned(snapshot_memory),
            grant.policy_digest(),
        ),
    );
    let config = ProductionSessionConfig::new(
        ProductionDurabilityConfig::new(
            durability_root.join("i"),
            durability_root.join("r"),
            AuthorityAuditMode::CreateNew(durability_root.join("a")),
            &broker_wal_root,
        ),
        IssuerId::new(format!("real-concurrent-{snapshot_id}")),
        ProductionFirecrackerConfig::new(
            template_runtime,
            firecracker_runtime::recovery::RecoveryTools::new(pinned(veritysetup), pinned(dmsetup)),
        ),
        WorkspaceTemplateId::new(format!("real-concurrent-{snapshot_id}")),
        ProductionBrokerEndpoint::new(2, guest_cid, broker_port, 16),
        ProductionGuestControlEndpoint::new(GUEST_CONTROL_PORT),
        ProductionBrokerLimits::new(
            std::num::NonZeroUsize::new(8).unwrap(),
            std::num::NonZeroU64::new(8).unwrap(),
            1024 * 1024,
            std::num::NonZeroUsize::new(1).unwrap(),
            64 * 1024,
            std::num::NonZeroUsize::new(8).unwrap(),
        ),
    );
    let runtime = ProductionSessionRuntimeBuilder::new(config, factory, ClosedEgressFactory)
        .build()
        .unwrap_or_else(|error| panic!("concurrent production runtime build failed: {error}"));
    (runtime, broker_wal_root)
}

fn sole_cgroup_process(path: &Path) -> u32 {
    let body = fs::read_to_string(path.join("cgroup.procs"))
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()));
    let pids = body
        .lines()
        .map(|line| line.parse::<u32>().expect("cgroup PID must be decimal"))
        .collect::<Vec<_>>();
    assert_eq!(
        pids.len(),
        1,
        "one Firecracker task must own {}",
        path.display()
    );
    pids[0]
}

#[test]
#[ignore = "requires root, KVM, cgroup-v2, dm-verity, AF_VSOCK, and two concurrent production guests"]
#[allow(clippy::too_many_lines)]
/// Enforces deploy/README.md "Snapshot provisioning": clones share snapshot-bound CID/ports
/// while distinct jail-backed UDS paths keep both production transports independently live.
fn real_production_two_session_owners_run_concurrently_and_clean_independently() {
    assert_eq!(
        std::env::var("REAL_SESSION_OWNER_LIFECYCLE").as_deref(),
        Ok("1")
    );
    let firecracker = required_file("REAL_SESSION_FIRECRACKER_BIN");
    let jailer = required_file("REAL_SESSION_FIRECRACKER_JAILER");
    let kernel = required_file("REAL_SESSION_KERNEL");
    let rootfs = required_file("REAL_SESSION_ROOTFS");
    let verity_hash = required_file("REAL_SESSION_VERITY_HASH");
    let veritysetup = required_file("REAL_SESSION_VERITYSETUP");
    let dmsetup = required_file("REAL_SESSION_DMSETUP");
    let formatter = required_file("REAL_SESSION_WORKSPACE_FORMATTER");
    let seccomp = required_file("REAL_SESSION_SECCOMP");
    let seccomp_policy = required_file("REAL_SESSION_SECCOMP_POLICY");
    let seccomp_compiler = required_file("REAL_SESSION_SECCOMP_COMPILER");
    let staging = TemporaryDirectory::new();
    let first_root = staging.path().join("a");
    let second_root = staging.path().join("b");
    make_directory(&first_root, 0o700);
    make_directory(&second_root, 0o700);
    let grant = authority_grant();
    let (first_template, cgroup_parent, _) = runtime_profile(
        &first_root,
        &firecracker,
        &jailer,
        &kernel,
        &rootfs,
        &verity_hash,
        &veritysetup,
        &formatter,
        &seccomp,
        &seccomp_policy,
        &seccomp_compiler,
        GUEST_CID,
        BROKER_PORT,
        true,
    );
    let (second_template, second_cgroup_parent, _) = runtime_profile(
        &second_root,
        &firecracker,
        &jailer,
        &kernel,
        &rootfs,
        &verity_hash,
        &veritysetup,
        &formatter,
        &seccomp,
        &seccomp_policy,
        &seccomp_compiler,
        GUEST_CID,
        BROKER_PORT,
        true,
    );
    assert_eq!(cgroup_parent, second_cgroup_parent);
    let (first_state, first_memory) = capture_clean_snapshot(&first_root, &first_template);
    export_snapshot_if_requested(&first_state, &first_memory);
    let (mut first, first_broker_root) = build_real_production_runtime(
        &first_root.join("d"),
        first_template.clone(),
        &first_state,
        &first_memory,
        0xa1,
        GUEST_CID,
        BROKER_PORT,
        &kernel,
        &seccomp,
        &veritysetup,
        &dmsetup,
        &grant,
    );
    let (mut second, second_broker_root) = build_real_production_runtime(
        &second_root.join("d"),
        second_template.clone(),
        &first_state,
        &first_memory,
        0xb2,
        GUEST_CID,
        BROKER_PORT,
        &kernel,
        &seccomp,
        &veritysetup,
        &dmsetup,
        &grant,
    );

    let (first_result, second_result) = thread::scope(|scope| {
        let first_start = scope.spawn(|| first.start(&grant));
        let second_start = scope.spawn(|| second.start(&grant));
        (
            first_start
                .join()
                .expect("first start thread must not panic"),
            second_start
                .join()
                .expect("second start thread must not panic"),
        )
    });
    let first_started =
        first_result.unwrap_or_else(|error| panic!("first concurrent owner failed: {error}"));
    let second_started = second_result.unwrap_or_else(|error| {
        let _ = first.stop();
        panic!("second concurrent owner failed: {error}");
    });
    let first_workspace = first_started.identity().workspace_id().to_string();
    let second_workspace = second_started.identity().workspace_id().to_string();
    assert_ne!(first_workspace, second_workspace);
    let first_cgroup = cgroup_parent.join(&first_workspace);
    let second_cgroup = cgroup_parent.join(&second_workspace);
    let first_firecracker_pid = sole_cgroup_process(&first_cgroup);
    let second_firecracker_pid = sole_cgroup_process(&second_cgroup);
    assert_ne!(first_firecracker_pid, second_firecracker_pid);
    assert!(Path::new(&format!("/proc/{first_firecracker_pid}")).exists());
    assert!(Path::new(&format!("/proc/{second_firecracker_pid}")).exists());

    // Snapshot the fully fsynced WAL while each guest intentionally holds its Broker connection.
    // Opening the live WAL directly would correctly contend with the writer's exclusive lock.
    drop(wait_for_live_completed_guest_effect_probe(
        &first_broker_root.join(format!(
            "{}.wal",
            first_started.identity().broker_session_id()
        )),
        &first_root.join("live-broker-snapshot.wal"),
    ));
    drop(wait_for_live_completed_guest_effect_probe(
        &second_broker_root.join(format!(
            "{}.wal",
            second_started.identity().broker_session_id()
        )),
        &second_root.join("live-broker-snapshot.wal"),
    ));
    assert_eq!(
        first.poll(OwnerPollRequest::Continue).unwrap(),
        OwnerPollOutcome::Running(first_started)
    );
    assert_eq!(
        second.poll(OwnerPollRequest::Continue).unwrap(),
        OwnerPollOutcome::Running(second_started)
    );

    assert_eq!(
        first.stop().unwrap(),
        OwnerPollOutcome::Closed(ShutdownReason::ExternalRequest)
    );
    drop(wait_for_completed_guest_effect_probe(
        &first_broker_root.join(format!(
            "{}.wal",
            first_started.identity().broker_session_id()
        )),
    ));
    assert!(Path::new(&format!("/proc/{second_firecracker_pid}")).exists());
    assert_eq!(
        second.poll(OwnerPollRequest::Continue).unwrap(),
        OwnerPollOutcome::Running(second_started)
    );
    assert_eq!(
        second.stop().unwrap(),
        OwnerPollOutcome::Closed(ShutdownReason::ExternalRequest)
    );
    drop(wait_for_completed_guest_effect_probe(
        &second_broker_root.join(format!(
            "{}.wal",
            second_started.identity().broker_session_id()
        )),
    ));
    assert!(!first_cgroup.exists());
    assert!(!second_cgroup.exists());
    fs::remove_dir(&cgroup_parent)
        .unwrap_or_else(|error| panic!("concurrent cgroup parent retained residue: {error}"));
}

#[test]
#[ignore = "requires root, KVM, cgroup-v2, dm-verity, AF_VSOCK, and pinned production guest artifacts"]
#[allow(clippy::too_many_lines)]
fn real_production_session_owner_runs_ready_poll_stop_and_cleans_every_owned_resource() {
    assert_eq!(
        std::env::var("REAL_SESSION_OWNER_LIFECYCLE").as_deref(),
        Ok("1")
    );

    let firecracker = required_file("REAL_SESSION_FIRECRACKER_BIN");
    let jailer = required_file("REAL_SESSION_FIRECRACKER_JAILER");
    let kernel = required_file("REAL_SESSION_KERNEL");
    let rootfs = required_file("REAL_SESSION_ROOTFS");
    let verity_hash = required_file("REAL_SESSION_VERITY_HASH");
    let veritysetup = required_file("REAL_SESSION_VERITYSETUP");
    let dmsetup = required_file("REAL_SESSION_DMSETUP");
    let formatter = required_file("REAL_SESSION_WORKSPACE_FORMATTER");
    let seccomp = required_file("REAL_SESSION_SECCOMP");
    let seccomp_policy = required_file("REAL_SESSION_SECCOMP_POLICY");
    let seccomp_compiler = required_file("REAL_SESSION_SECCOMP_COMPILER");

    eprintln!("real session-owner phase: preparing template");
    let staging = TemporaryDirectory::new();
    let grant = authority_grant();
    let (template_runtime, _template_cgroup_parent, _executable_parent) = runtime_profile(
        staging.path(),
        &firecracker,
        &jailer,
        &kernel,
        &rootfs,
        &verity_hash,
        &veritysetup,
        &formatter,
        &seccomp,
        &seccomp_policy,
        &seccomp_compiler,
        GUEST_CID,
        BROKER_PORT,
        false,
    );
    let (snapshot_state, snapshot_memory) =
        capture_clean_snapshot(staging.path(), &template_runtime);
    export_snapshot_if_requested(&snapshot_state, &snapshot_memory);
    eprintln!("real session-owner phase: clean snapshot captured");

    let snapshot_id = session_orchestrator::SnapshotId::new([0xa5; session_orchestrator::ID_BYTES]);
    let firecracker_factory = FilesystemFirecrackerFactory::with_guest_artifacts(
        snapshot_id,
        template_runtime.clone(),
        GuestArtifactTemplate::new(pinned(&kernel), pinned(&seccomp)),
        SnapshotTemplate::new(
            pinned(&snapshot_state),
            pinned(&snapshot_memory),
            grant.policy_digest(),
        ),
    );

    let durability_root = staging.path().join("durability");
    make_directory(&durability_root, 0o700);
    let broker_wal_root = durability_root.join("broker-wal");
    make_directory(&broker_wal_root, 0o700);
    let identity_ledger = durability_root.join("identity.ledger");
    let recovery_journal = durability_root.join("session-recovery.wal");
    let authority_wal = durability_root.join("authority.wal");
    let authority_mode = if authority_wal.exists() {
        AuthorityAuditMode::OpenExisting(authority_wal.clone())
    } else {
        AuthorityAuditMode::CreateNew(authority_wal.clone())
    };
    let config = ProductionSessionConfig::new(
        ProductionDurabilityConfig::new(
            &identity_ledger,
            &recovery_journal,
            authority_mode,
            &broker_wal_root,
        ),
        IssuerId::new("real-session-owner-lifecycle"),
        ProductionFirecrackerConfig::new(
            template_runtime.clone(),
            firecracker_runtime::recovery::RecoveryTools::new(
                pinned(&veritysetup),
                pinned(&dmsetup),
            ),
        ),
        WorkspaceTemplateId::new("real-production-workspace"),
        ProductionBrokerEndpoint::new(2, GUEST_CID, BROKER_PORT, 16),
        ProductionGuestControlEndpoint::new(GUEST_CONTROL_PORT),
        ProductionBrokerLimits::new(
            std::num::NonZeroUsize::new(8).expect("non-zero replay capacity"),
            std::num::NonZeroU64::new(8).expect("non-zero request budget"),
            1024 * 1024,
            std::num::NonZeroUsize::new(1).expect("non-zero concurrent budget"),
            64 * 1024,
            std::num::NonZeroUsize::new(8).expect("non-zero connection ceiling"),
        ),
    );

    let mut runtime =
        ProductionSessionRuntimeBuilder::new(config, firecracker_factory, ClosedEgressFactory)
            .build()
            .unwrap_or_else(|error| panic!("production session runtime build failed: {error}"));
    assert_eq!(runtime.state(), session_orchestrator::LifecycleState::Ready);

    eprintln!("real session-owner phase: starting production owner");
    let started = match runtime.start(&grant) {
        Ok(started) => started,
        Err(start_error) => {
            let mut cleanup_results = Vec::new();
            for _ in 0..4 {
                if matches!(
                    runtime.state(),
                    session_orchestrator::LifecycleState::Ready
                        | session_orchestrator::LifecycleState::Closed
                ) {
                    break;
                }
                cleanup_results.push(format!("{:?}", runtime.stop()));
            }
            assert!(
                matches!(
                    runtime.state(),
                    session_orchestrator::LifecycleState::Ready
                        | session_orchestrator::LifecycleState::Closed
                ),
                "production SessionOwner start failed and bounded cleanup did not return to a resource-free state: {start_error}; cleanup={cleanup_results:?}"
            );
            panic!(
                "production SessionOwner start failed after bounded cleanup completed: {start_error}; cleanup={cleanup_results:?}"
            );
        }
    };
    eprintln!("real session-owner phase: production owner running");
    let identity = started.identity();
    let broker_wal = broker_wal_root.join(format!("{}.wal", identity.broker_session_id()));
    if let Some(path) = std::env::var_os("REAL_SESSION_CLEANUP_STATE") {
        fs::write(
            path,
            format!(
                "workspace_id={}\njailer_base={}\ncgroup_parent={}\nmapper_base={}\n",
                identity.workspace_id(),
                template_runtime.jailer_config.chroot_base_dir.display(),
                template_runtime
                    .isolation
                    .cgroup
                    .path
                    .parent()
                    .expect("production cgroup must have a parent")
                    .display(),
                template_runtime.dm_verity.mapper_name,
            ),
        )
        .expect("real lifecycle cleanup state must be durable");
    }
    assert_eq!(
        runtime.state(),
        session_orchestrator::LifecycleState::Running
    );
    assert_eq!(runtime.active_session(), Some(started));

    let polled = runtime
        .poll(OwnerPollRequest::Continue)
        .unwrap_or_else(|error| panic!("production SessionOwner Continue poll failed: {error}"));
    assert_eq!(polled, OwnerPollOutcome::Running(started));
    let guest_effect_proof = wait_for_completed_guest_effect_probe(&broker_wal);
    drop(guest_effect_proof);

    let workspace_id = identity.workspace_id().to_string();
    let executable_parent = template_runtime.jailer_config.chroot_base_dir.join(
        template_runtime
            .firecracker
            .path
            .file_name()
            .expect("Firecracker path must have a filename"),
    );
    let jail_root = executable_parent.join(&workspace_id).join("root");
    let session_cgroup = template_runtime
        .isolation
        .cgroup
        .path
        .parent()
        .expect("session cgroup must have a parent")
        .join(&workspace_id);
    let session_mapper = PathBuf::from("/dev/mapper").join(format!(
        "{}-{workspace_id}",
        template_runtime.dm_verity.mapper_name
    ));
    let workspace_clone = jail_root.join("workspace").join(&workspace_id);
    let workspace_image = jail_root.join("workspace").join("workspace.ext4");
    let api_socket = jail_root.join("run/firecracker.sock");
    let vsock_socket = jail_root.join("run/vsock.sock");

    eprintln!("real session-owner phase: stopping production owner");
    let closed = match runtime.stop() {
        Ok(closed) => closed,
        Err(stop_error) => {
            let mut cleanup_results = Vec::new();
            for _ in 0..4 {
                if runtime.state() == session_orchestrator::LifecycleState::Closed {
                    break;
                }
                cleanup_results.push(format!("{:?}", runtime.stop()));
            }
            assert_eq!(
                runtime.state(),
                session_orchestrator::LifecycleState::Closed,
                "production SessionOwner stop failed and bounded retry did not close it: {stop_error}; cleanup={cleanup_results:?}"
            );
            panic!(
                "production SessionOwner stop needed a retry: {stop_error}; cleanup={cleanup_results:?}"
            );
        }
    };
    eprintln!("real session-owner phase: production owner closed");
    assert_eq!(
        closed,
        OwnerPollOutcome::Closed(ShutdownReason::ExternalRequest)
    );
    assert_eq!(
        runtime.state(),
        session_orchestrator::LifecycleState::Closed
    );
    assert_eq!(runtime.active_session(), None);

    for (label, path) in [
        ("session cgroup", session_cgroup),
        ("dm-verity mapper", session_mapper),
        ("jail root", jail_root),
        ("workspace clone", workspace_clone),
        ("workspace image", workspace_image),
        ("Firecracker API socket", api_socket),
        ("Firecracker vsock socket", vsock_socket),
    ] {
        assert!(
            !path.exists(),
            "{label} must be absent after owner stop: {}",
            path.display()
        );
    }
    let cgroup_parent = template_runtime
        .isolation
        .cgroup
        .path
        .parent()
        .expect("production cgroup must have a parent");
    fs::remove_dir(cgroup_parent)
        .unwrap_or_else(|error| panic!("production cgroup parent must be empty: {error}"));
    assert!(
        !cgroup_parent.exists(),
        "production cgroup parent must be removed after owner stop"
    );

    assert!(
        broker_wal.is_file(),
        "durable Broker WAL must survive cleanup"
    );

    // Drop the owner before reopening its durable writers.  Successful reopen proves the
    // subject/Broker/ledger ownership locks were released rather than merely hidden by Closed.
    drop(runtime);
    let ledger = DurableIdentityLedger::open(&identity_ledger)
        .expect("identity ledger must reopen after owner stop");
    drop(ledger);
    let journal = DurableSessionRecoveryJournal::open(&recovery_journal)
        .expect("session recovery journal must reopen after owner stop");
    drop(journal);
    let authority_view = authority_core::durable_audit::DurableAuditView::open(&authority_wal)
        .expect("authority audit WAL must be readable after owner stop");
    assert!(
        authority_view
            .attempts()
            .iter()
            .all(|attempt| attempt.outcome() != authority_core::audit::AttemptOutcome::Started),
        "authority audit must not retain an unfinished subject operation"
    );
    let broker_view = egress_broker::durable::DurableBrokerView::open(&broker_wal)
        .expect("Broker WAL must be readable after worker join");
    assert_eq!(
        *broker_view.config().session().as_bytes(),
        identity.broker_session_id().as_bytes(),
        "Broker WAL must remain bound to the stopped session identity"
    );
    assert_eq!(broker_view.requests().len(), 1);
}
