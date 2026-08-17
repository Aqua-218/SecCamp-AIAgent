//! Firecracker runtime contract tests.
//!
//! Specification references: `docs/design/runtime-isolation.md` (Firecracker role and
//! snapshot ordering), `docs/design/implementation-plan.md` (Phase 6), and the user
//! Phase 6 completion contract.  The mocks expose observable boundary order so tests
//! remain independent of the implementation's private data structures.

use firecracker_runtime::{
    ApiClient, ApiRequest, ApiResponse, CgroupConfig, CgroupVersion, CommandOutput, CommandRunner,
    CommandSpec, DmVerityConfig, FileSystem, HostIsolationConfig, HttpMethod, IdentityBundle,
    IdentityId, IdentitySource, JailerConfig, MAX_COMMAND_OUTPUT_BYTES, MAX_HTTP_BODY_BYTES,
    MAX_WORKSPACE_BYTES, MAX_WORKSPACE_DEPTH, MIN_WORKSPACE_IMAGE_BYTES, NamespaceConfig,
    PinnedArtifact, ProcessHandle, ProcessOwnership, RealCommandRunner, RealFileSystem, Runtime,
    RuntimeConfig, RuntimeError, RuntimeState, SeccompConfig, Snapshot, VsockConfig,
    WorkspaceConfig, WorkspaceImageConfig, sha256,
};
use std::cell::RefCell;
use std::collections::{HashMap, VecDeque};
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, symlink};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

type Events = Rc<RefCell<Vec<String>>>;

const JAIL_ROOT: &str = "/srv/jailer/firecracker/clone-a/root";
const SNAPSHOT_STATE_PATH: &str = "/srv/jailer/firecracker/clone-a/root/snapshots/state";
const SNAPSHOT_MEMORY_PATH: &str = "/srv/jailer/firecracker/clone-a/root/snapshots/memory";
const SNAPSHOT_STATE_BYTES: &[u8] = b"snapshot-state";
const SNAPSHOT_MEMORY_BYTES: &[u8] = b"snapshot-memory";

static UNIX_API_TEST_LOCK: Mutex<()> = Mutex::new(());

fn read_test_api_request(stream: &mut impl Read) -> Vec<u8> {
    let mut request = Vec::new();
    let mut expected_length = None;
    let mut buffer = [0_u8; 1024];
    loop {
        let count = stream.read(&mut buffer).expect("test API server must read");
        assert!(count > 0, "client closed before completing its request");
        request.extend_from_slice(&buffer[..count]);

        if expected_length.is_none()
            && let Some(header_end) = request.windows(4).position(|window| window == b"\r\n\r\n")
        {
            let headers = String::from_utf8_lossy(&request[..header_end]);
            let content_length = headers
                .lines()
                .find_map(|line| line.strip_prefix("Content-Length: "))
                .and_then(|value| value.parse::<usize>().ok())
                .expect("client must send content length");
            expected_length = Some(header_end + 4 + content_length);
        }
        if expected_length.is_some_and(|length| request.len() >= length) {
            return request;
        }
    }
}

#[derive(Clone)]
struct MockRunner {
    events: Events,
    next_pid: u32,
    stop_failures: VecDeque<bool>,
    run_failures: VecDeque<bool>,
}

impl MockRunner {
    fn new(events: Events) -> Self {
        Self {
            events,
            next_pid: 100,
            stop_failures: VecDeque::new(),
            run_failures: VecDeque::new(),
        }
    }

    fn with_failures(
        events: Events,
        stop_failures: impl IntoIterator<Item = bool>,
        run_failures: impl IntoIterator<Item = bool>,
    ) -> Self {
        Self {
            events,
            next_pid: 100,
            stop_failures: stop_failures.into_iter().collect(),
            run_failures: run_failures.into_iter().collect(),
        }
    }
}

impl CommandRunner for MockRunner {
    fn run(&mut self, command: &CommandSpec) -> Result<CommandOutput, RuntimeError> {
        self.events.borrow_mut().push(format!(
            "command:run:{} {}",
            command.program.display(),
            command.args.join(" ")
        ));
        if self.run_failures.pop_front().unwrap_or(false) {
            return Err(RuntimeError::Command("mock command failure".to_owned()));
        }
        Ok(CommandOutput {
            status: 0,
            stdout: Vec::new(),
            stderr: Vec::new(),
        })
    }

    fn start(&mut self, command: &CommandSpec) -> Result<ProcessHandle, RuntimeError> {
        self.events.borrow_mut().push(format!(
            "command:start:{} {}",
            command.program.display(),
            command.args.join(" ")
        ));
        let process = ProcessHandle { pid: self.next_pid };
        self.next_pid += 1;
        Ok(process)
    }

    fn verify_verity(
        &mut self,
        _veritysetup: &PinnedArtifact,
        _expected: &DmVerityConfig,
    ) -> Result<(), RuntimeError> {
        Ok(())
    }

    fn start_owned(
        &mut self,
        command: &CommandSpec,
        _ownership: &ProcessOwnership,
    ) -> Result<ProcessHandle, RuntimeError> {
        self.start(command)
    }

    fn verify_running(&mut self, _process: ProcessHandle) -> Result<(), RuntimeError> {
        Ok(())
    }

    fn stop(&mut self, process: ProcessHandle) -> Result<(), RuntimeError> {
        self.events
            .borrow_mut()
            .push(format!("command:stop:{}", process.pid));
        if self.stop_failures.pop_front().unwrap_or(false) {
            return Err(RuntimeError::Command("mock stop failure".to_owned()));
        }
        Ok(())
    }
}

#[derive(Clone)]
struct MockFileSystem {
    events: Events,
    artifacts: HashMap<PathBuf, Vec<u8>>,
    fail_clone: bool,
    remove_failures: VecDeque<bool>,
}

impl FileSystem for MockFileSystem {
    fn read(&mut self, path: &Path) -> Result<Vec<u8>, RuntimeError> {
        self.artifacts
            .get(path)
            .cloned()
            .ok_or_else(|| RuntimeError::Io(format!("missing mock artifact {}", path.display())))
    }

    fn bind_block_device(
        &mut self,
        source: &Path,
        jailed_device: &Path,
    ) -> Result<(), RuntimeError> {
        let expected_source = Path::new("/dev/mapper/rootfs-verity");
        let expected_jailed_device = Path::new(JAIL_ROOT).join("dev/rootfs");
        if source != expected_source || jailed_device != expected_jailed_device {
            return Err(RuntimeError::InvalidConfig(format!(
                "unexpected mock block-device bind: {} -> {}",
                source.display(),
                jailed_device.display()
            )));
        }
        self.events.borrow_mut().push(format!(
            "filesystem:bind-device:{}:{}",
            source.display(),
            jailed_device.display()
        ));
        Ok(())
    }

    fn unbind_block_device(
        &mut self,
        source: &Path,
        jailed_device: &Path,
    ) -> Result<(), RuntimeError> {
        let expected_source = Path::new("/dev/mapper/rootfs-verity");
        let expected_jailed_device = Path::new(JAIL_ROOT).join("dev/rootfs");
        if source != expected_source || jailed_device != expected_jailed_device {
            return Err(RuntimeError::InvalidConfig(format!(
                "unexpected mock block-device unbind: {} -> {}",
                source.display(),
                jailed_device.display()
            )));
        }
        self.events.borrow_mut().push(format!(
            "filesystem:unbind-device:{}:{}",
            source.display(),
            jailed_device.display()
        ));
        Ok(())
    }

    fn verify_block_device_binding(
        &mut self,
        source: &Path,
        jailed_device: &Path,
    ) -> Result<(), RuntimeError> {
        let expected_source = Path::new("/dev/mapper/rootfs-verity");
        let expected_jailed_device = Path::new(JAIL_ROOT).join("dev/rootfs");
        if source != expected_source || jailed_device != expected_jailed_device {
            return Err(RuntimeError::InvalidConfig(format!(
                "unexpected mock block-device binding: {} -> {}",
                source.display(),
                jailed_device.display()
            )));
        }
        self.events.borrow_mut().push(format!(
            "filesystem:verify-device:{}:{}",
            source.display(),
            jailed_device.display()
        ));
        Ok(())
    }

    fn clone_workspace(&mut self, source: &Path, destination: &Path) -> Result<(), RuntimeError> {
        self.events.borrow_mut().push(format!(
            "filesystem:clone:{}:{}",
            source.display(),
            destination.display()
        ));
        if self.fail_clone {
            return Err(RuntimeError::Io(
                "mock clone failed after destination preparation".to_owned(),
            ));
        }
        Ok(())
    }

    fn create_workspace_image(
        &mut self,
        workspace: &Path,
        image: &Path,
        size_bytes: u64,
    ) -> Result<(), RuntimeError> {
        self.events.borrow_mut().push(format!(
            "filesystem:image:{}:{}:{size_bytes}",
            workspace.display(),
            image.display()
        ));
        Ok(())
    }

    fn remove_workspace(&mut self, path: &Path) -> Result<(), RuntimeError> {
        self.events
            .borrow_mut()
            .push(format!("filesystem:remove:{}", path.display()));
        if self.remove_failures.pop_front().unwrap_or(false) {
            return Err(RuntimeError::Io("mock remove failure".to_owned()));
        }
        Ok(())
    }
}

struct MockApi {
    events: Events,
    statuses: VecDeque<u16>,
}

impl MockApi {
    fn new(events: Events, statuses: impl IntoIterator<Item = u16>) -> Self {
        Self {
            events,
            statuses: statuses.into_iter().collect(),
        }
    }
}

impl ApiClient for MockApi {
    fn request(&mut self, request: &ApiRequest) -> Result<ApiResponse, RuntimeError> {
        self.events
            .borrow_mut()
            .push(format!("api:{}:{}", request.path, request.body));
        let body = match request.path.as_str() {
            "/actions/inject-identity" => Some("identity-injected"),
            "/actions/start-workload" => Some("workload-started"),
            _ => None,
        }
        .map_or_else(String::new, |acknowledgement| {
            format!("{{\"ack\":\"{acknowledgement}\",{}", &request.body[1..])
        });
        Ok(ApiResponse {
            status: self.statuses.pop_front().unwrap_or(200),
            body,
        })
    }

    fn verify_restore_resources(
        &mut self,
        workspace_path: &Path,
        vsock_uds_path: &Path,
        guest_cid: u32,
    ) -> Result<(), RuntimeError> {
        self.events.borrow_mut().push(format!(
            "api:/vm/config:verify:{}:{}:{guest_cid}",
            workspace_path.display(),
            vsock_uds_path.display()
        ));
        Ok(())
    }
}

struct MockIdentitySource {
    ids: VecDeque<IdentityId>,
}

impl MockIdentitySource {
    fn sequential() -> Self {
        let ids = (1..=15)
            .map(|number| {
                IdentityId::from_hex(&format!("{number:032x}"))
                    .expect("test identity must be non-zero and correctly encoded")
            })
            .collect();
        Self { ids }
    }

    fn from_ids(ids: impl IntoIterator<Item = IdentityId>) -> Self {
        Self {
            ids: ids.into_iter().collect(),
        }
    }
}

impl IdentitySource for MockIdentitySource {
    fn generate(&mut self) -> Result<IdentityId, RuntimeError> {
        self.ids.pop_front().ok_or_else(|| {
            RuntimeError::InvalidIdentity("mock identity source exhausted".to_owned())
        })
    }
}

fn artifact(path: &str, label: &str) -> PinnedArtifact {
    PinnedArtifact::new(PathBuf::from(path), sha256(label.as_bytes()))
}

fn config() -> RuntimeConfig {
    let jail_root = Path::new(JAIL_ROOT);
    let rootfs = artifact("/artifacts/rootfs.img", "rootfs");
    RuntimeConfig {
        firecracker: artifact("/artifacts/firecracker", "firecracker"),
        kernel: artifact(
            jail_root
                .join("artifacts/vmlinux-6.1")
                .to_str()
                .expect("fixture path is UTF-8"),
            "kernel",
        ),
        rootfs: rootfs.clone(),
        verity_hash: artifact("/artifacts/rootfs.verity", "verity-hash"),
        veritysetup: artifact("/usr/sbin/veritysetup", "veritysetup"),
        dm_verity: DmVerityConfig {
            data_device: rootfs.path.clone(),
            hash_device: PathBuf::from("/artifacts/rootfs.verity"),
            mapper_name: "rootfs-verity".to_owned(),
            root_hash: sha256(b"verity-root-hash"),
            jailed_device_path: jail_root.join("dev/rootfs"),
        },
        workspace: WorkspaceConfig {
            source: PathBuf::from("/workspace/source"),
            clone_root: jail_root.join("workspace"),
            clone_id: "clone-a".to_owned(),
            image: WorkspaceImageConfig {
                formatter: artifact("/artifacts/mke2fs", "mke2fs"),
                size_bytes: 64 * 1024 * 1024,
            },
        },
        jailer: artifact("/artifacts/jailer", "jailer"),
        jailer_config: JailerConfig {
            uid: 1000,
            gid: 1000,
            chroot_base_dir: PathBuf::from("/srv/jailer"),
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
                path: PathBuf::from("/sys/fs/cgroup/luna/clone-a"),
                memory_max_bytes: 256 * 1024 * 1024,
                cpu_quota_micros: 100_000,
                cpu_period_micros: 100_000,
            },
            seccomp: SeccompConfig {
                filter: artifact(
                    jail_root
                        .join("artifacts/seccomp.json")
                        .to_str()
                        .expect("fixture path is UTF-8"),
                    "seccomp",
                ),
                blocked_syscalls: [
                    "bpf",
                    "connect",
                    "mount",
                    "perf_event_open",
                    "ptrace",
                    "setns",
                    "socket",
                    "unshare",
                ]
                .into_iter()
                .map(str::to_owned)
                .collect(),
            },
        },
        vsock: VsockConfig {
            guest_cid: 42,
            uds_path: jail_root.join("run/vsock.sock"),
        },
        network_devices: Vec::new(),
        vcpu_count: 2,
        memory_mib: 256,
        boot_args: format!(
            "console=ttyS0 reboot=k panic=1 pci=off init={}",
            firecracker_runtime::REQUIRED_GUEST_INIT
        ),
    }
}

fn filesystem_for(config: &RuntimeConfig, events: Events) -> MockFileSystem {
    let mut artifacts = HashMap::new();
    for (path, bytes) in [
        (&config.firecracker.path, b"firecracker".as_slice()),
        (&config.kernel.path, b"kernel".as_slice()),
        (&config.rootfs.path, b"rootfs".as_slice()),
        (&config.verity_hash.path, b"verity-hash".as_slice()),
        (&config.veritysetup.path, b"veritysetup".as_slice()),
        (&config.workspace.image.formatter.path, b"mke2fs".as_slice()),
        (&config.jailer.path, b"jailer".as_slice()),
        (&config.isolation.seccomp.filter.path, b"seccomp".as_slice()),
        (&PathBuf::from(SNAPSHOT_STATE_PATH), SNAPSHOT_STATE_BYTES),
        (&PathBuf::from(SNAPSHOT_MEMORY_PATH), SNAPSHOT_MEMORY_BYTES),
    ] {
        artifacts.insert(path.clone(), bytes.to_vec());
    }
    MockFileSystem {
        events,
        artifacts,
        fail_clone: false,
        remove_failures: VecDeque::new(),
    }
}

fn runtime(
    config: &RuntimeConfig,
    statuses: impl IntoIterator<Item = u16>,
) -> (
    Runtime<MockRunner, MockFileSystem, MockApi, MockApi, MockIdentitySource>,
    Events,
) {
    let events = Rc::new(RefCell::new(Vec::new()));
    let filesystem = filesystem_for(config, Rc::clone(&events));
    (
        Runtime::new(
            MockRunner::new(Rc::clone(&events)),
            filesystem,
            MockApi::new(Rc::clone(&events), statuses),
            MockApi::new(Rc::clone(&events), std::iter::empty()),
            MockIdentitySource::sequential(),
        ),
        events,
    )
}

fn runtime_with_cleanup_failures(
    config: &RuntimeConfig,
    stop_failures: impl IntoIterator<Item = bool>,
    run_failures: impl IntoIterator<Item = bool>,
    remove_failures: impl IntoIterator<Item = bool>,
) -> (
    Runtime<MockRunner, MockFileSystem, MockApi, MockApi, MockIdentitySource>,
    Events,
) {
    let events = Rc::new(RefCell::new(Vec::new()));
    let mut filesystem = filesystem_for(config, Rc::clone(&events));
    filesystem.remove_failures = remove_failures.into_iter().collect();
    (
        Runtime::new(
            MockRunner::with_failures(Rc::clone(&events), stop_failures, run_failures),
            filesystem,
            MockApi::new(Rc::clone(&events), std::iter::empty()),
            MockApi::new(Rc::clone(&events), std::iter::empty()),
            MockIdentitySource::sequential(),
        ),
        events,
    )
}

fn identity(number: u8) -> IdentityId {
    IdentityId::from_hex(&format!("{number:032x}")).expect("test identity must be valid")
}

fn temporary_workspace(name: &str) -> PathBuf {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock must be after Unix epoch")
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "firecracker-runtime-{name}-{}-{timestamp}",
        std::process::id()
    ));
    fs::create_dir(&path).expect("temporary workspace root must be creatable");
    path
}

#[test]
fn launch_valid_profile_configures_verity_vsock_and_jailer_without_network() {
    // Requirement: Phase 6 must configure rootfs/workspace/vsock and never add virtio-net.
    let config = config();
    let (mut runtime, events) = runtime(&config, std::iter::empty());
    let instance = runtime.launch(&config).expect("valid profile must launch");
    assert_eq!(instance.state(), RuntimeState::WorkloadStopped);
    let events = events.borrow();
    assert!(events[0].starts_with("filesystem:clone:"));
    assert!(events[1].starts_with("filesystem:image:"));
    assert!(events[2].starts_with("command:run:/artifacts/mke2fs -F -q -t ext4 -d"));
    assert!(events[3].starts_with("command:run:/usr/sbin/veritysetup open --readonly"));
    assert!(events[4].starts_with("filesystem:bind-device:"));
    assert!(events[5].starts_with("filesystem:verify-device:"));
    assert!(events[6].contains("--new-pid-ns"));
    assert!(events[6].contains("--uid 1000 --gid 1000 --cgroup-version 2"));
    assert!(events[6].contains("--cgroup memory.max=268435456"));
    assert!(events[6].contains("--cgroup cpu.max=100000 100000"));
    assert!(events[6].contains("--chroot-base-dir /srv/jailer"));
    assert!(!events[6].contains("--new-user-ns"));
    assert!(events.iter().any(|event| event.starts_with("api:/vsock:")));
    assert!(
        events
            .iter()
            .all(|event| !event.contains("network-interface"))
    );
    assert!(events.iter().all(|event| !event.contains("eth0")));
    assert!(events.iter().any(|event| event.contains("/dev/rootfs")));
}

#[test]
fn digest_mismatch_is_rejected_before_any_side_effect() {
    // Requirement: every executable and guest artifact must match its pinned digest.
    let mut config = config();
    config.kernel.digest = sha256(b"unexpected-kernel");
    let (mut runtime, events) = runtime(&config, std::iter::empty());
    let error = runtime
        .launch(&config)
        .expect_err("digest mismatch must fail closed");
    assert!(
        matches!(error, RuntimeError::ArtifactDigestMismatch { label, .. } if label == "kernel")
    );
    assert!(events.borrow().is_empty());
}

#[test]
fn network_device_is_rejected_before_artifact_reads_or_launch() {
    // Requirement: the standard profile has virtio-net disabled and rejects network config.
    let mut config = config();
    config.network_devices.push("eth0".to_owned());
    let (mut runtime, events) = runtime(&config, std::iter::empty());
    assert!(matches!(
        runtime.launch(&config),
        Err(RuntimeError::NetworkDeviceForbidden)
    ));
    assert!(events.borrow().is_empty());
}

#[test]
fn api_error_rolls_back_process_verity_and_workspace_in_reverse_order() {
    // Requirement: partial launch must rollback every completed side effect in reverse order.
    let config = config();
    let (mut runtime, events) = runtime(&config, [200, 503]);
    let error = runtime
        .launch(&config)
        .expect_err("non-success API response must reject launch");
    assert!(matches!(error, RuntimeError::ApiStatus { status: 503, .. }));
    let events = events.borrow();
    assert_eq!(events.len(), 13);
    assert!(events[0].starts_with("filesystem:clone:"));
    assert!(events[1].starts_with("filesystem:image:"));
    assert!(events[2].starts_with("command:run:/artifacts/mke2fs"));
    assert!(events[3].starts_with("command:run:/usr/sbin/veritysetup open"));
    assert!(events[4].starts_with("filesystem:bind-device:"));
    assert!(events[5].starts_with("filesystem:verify-device:"));
    assert!(events[6].starts_with("command:start:"));
    assert!(events[7].starts_with("api:/machine-config:"));
    assert!(events[8].starts_with("api:/boot-source:"));
    assert!(events[9].starts_with("command:stop:"));
    assert!(events[10].starts_with("filesystem:unbind-device:"));
    assert!(events[11].starts_with("command:run:/usr/sbin/veritysetup close"));
    assert!(events[12].starts_with("filesystem:remove:"));
}

#[test]
fn workspace_clone_error_removes_partial_destination_without_starting_vm() {
    // Requirement: a partially prepared clone must be removed before launch returns.
    let config = config();
    let events = Rc::new(RefCell::new(Vec::new()));
    let mut filesystem = filesystem_for(&config, Rc::clone(&events));
    filesystem.fail_clone = true;
    let mut runtime = Runtime::new(
        MockRunner::new(Rc::clone(&events)),
        filesystem,
        MockApi::new(Rc::clone(&events), std::iter::empty()),
        MockApi::new(Rc::clone(&events), std::iter::empty()),
        MockIdentitySource::sequential(),
    );
    let error = runtime
        .launch(&config)
        .expect_err("clone failure must reject launch");
    assert!(matches!(error, RuntimeError::Io(message) if message.contains("mock clone failed")));
    let events = events.borrow();
    assert_eq!(events.len(), 2);
    assert!(events[0].starts_with("filesystem:clone:"));
    assert!(events[1].starts_with("filesystem:remove:"));
}

#[test]
fn snapshot_pauses_vm_before_writing_snapshot_files() {
    let config = config();
    let (mut runtime, events) = runtime(&config, std::iter::empty());
    let mut instance = runtime.launch(&config).expect("baseline VM must launch");

    runtime
        .create_snapshot(&mut instance, SNAPSHOT_STATE_PATH, SNAPSHOT_MEMORY_PATH)
        .expect("pre-session snapshot must succeed");
    assert_eq!(instance.state(), RuntimeState::Snapshotted);

    let events = events.borrow();
    let pause_index = events
        .iter()
        .position(|event| event == r#"api:/vm:{"state":"Paused"}"#)
        .expect("snapshot must pause the VM first");
    let create_index = events
        .iter()
        .position(|event| event.starts_with("api:/snapshot/create:"))
        .expect("snapshot must be written through Firecracker API");
    assert!(pause_index < create_index);
    assert_eq!(
        events[pause_index], r#"api:/vm:{"state":"Paused"}"#,
        "the pause body must request Firecracker's paused state"
    );
}

#[test]
fn snapshot_create_failure_keeps_instance_explicitly_paused() {
    let config = config();
    // launch: machine-config, boot-source, rootfs, workspace, vsock, InstanceStart;
    // create_snapshot: pause succeeds, snapshot/create fails.
    let (mut runtime, events) = runtime(&config, [200, 200, 200, 200, 200, 200, 200, 503]);
    let mut instance = runtime.launch(&config).expect("baseline VM must launch");

    let error = runtime
        .create_snapshot(&mut instance, SNAPSHOT_STATE_PATH, SNAPSHOT_MEMORY_PATH)
        .expect_err("Firecracker snapshot failure must be returned");
    assert!(matches!(
        error,
        RuntimeError::ApiStatus {
            path,
            status: 503,
            ..
        } if path == "/snapshot/create"
    ));
    assert_eq!(instance.state(), RuntimeState::SnapshotPaused);
    assert!(
        events
            .borrow()
            .iter()
            .any(|event| event == r#"api:/vm:{"state":"Paused"}"#)
    );

    runtime
        .shutdown(&mut instance, &config)
        .expect("paused failed snapshot must still be cleanly shut down");
}

#[test]
fn snapshot_pause_failure_enters_unknown_state_and_does_not_create_snapshot() {
    let config = config();
    // launch: machine-config, boot-source, rootfs, workspace, vsock, InstanceStart;
    // create_snapshot: pause is rejected, so snapshot/create must not be attempted.
    let (mut runtime, events) = runtime(&config, [200, 200, 200, 200, 200, 200, 503]);
    let mut instance = runtime.launch(&config).expect("baseline VM must launch");

    let error = runtime
        .create_snapshot(&mut instance, SNAPSHOT_STATE_PATH, SNAPSHOT_MEMORY_PATH)
        .expect_err("Firecracker pause failure must be returned");
    assert!(matches!(
        error,
        RuntimeError::ApiStatus {
            path,
            status: 503,
            ..
        } if path == "/vm"
    ));
    assert_eq!(instance.state(), RuntimeState::SnapshotPauseUnknown);
    assert!(
        events
            .borrow()
            .iter()
            .any(|event| event == r#"api:/vm:{"state":"Paused"}"#)
    );
    assert!(
        !events
            .borrow()
            .iter()
            .any(|event| event.starts_with("api:/snapshot/create:"))
    );

    runtime
        .shutdown(&mut instance, &config)
        .expect("unknown pause state must still be cleanly shut down");
}

fn assert_shutdown_retry(stop_failures: &[bool], run_failures: &[bool], remove_failures: &[bool]) {
    let config = config();
    let (mut runtime, events) = runtime_with_cleanup_failures(
        &config,
        stop_failures.iter().copied(),
        run_failures.iter().copied(),
        remove_failures.iter().copied(),
    );
    let mut instance = runtime.launch(&config).expect("runtime must launch");
    assert!(matches!(
        runtime.shutdown(&mut instance, &config),
        Err(RuntimeError::Cleanup(_))
    ));
    assert_ne!(instance.state(), RuntimeState::Stopped);
    runtime
        .shutdown(&mut instance, &config)
        .expect("pending cleanup must be retryable");
    assert_eq!(instance.state(), RuntimeState::Stopped);
    let completed_event_count = events.borrow().len();
    runtime
        .shutdown(&mut instance, &config)
        .expect("completed shutdown must be idempotent");
    assert_eq!(events.borrow().len(), completed_event_count);
}

#[test]
fn shutdown_retries_each_pending_cleanup_without_repeating_successes() {
    // Every cleanup stage can fail independently; dependent stages wait for its retry.
    assert_shutdown_retry(&[true, false], &[], &[]);
    assert_shutdown_retry(&[false], &[false, false, true], &[]);
    assert_shutdown_retry(&[false], &[false], &[true, false]);
}

#[test]
fn restore_regenerates_all_identities_and_gates_workload_until_injection() {
    // Requirement: restore creates fresh VM/session/request/subject/capability IDs before workload start.
    let config = config();
    let (mut runtime, events) = runtime(&config, std::iter::empty());
    let mut first = runtime.launch(&config).expect("baseline VM must launch");
    let snapshot = runtime
        .create_snapshot(&mut first, SNAPSHOT_STATE_PATH, SNAPSHOT_MEMORY_PATH)
        .expect("pre-session snapshot must succeed");
    runtime
        .shutdown(&mut first, &config)
        .expect("baseline VM must clean up");
    let mut restored = runtime
        .restore(&config, &snapshot)
        .expect("restore must succeed");
    assert_eq!(restored.state(), RuntimeState::IdentityRegenerated);
    let identities = restored
        .identities()
        .expect("restore must expose fresh identities");
    let ids = [
        identities.vm_id,
        identities.session_id,
        identities.request_id,
        identities.subject_id,
        identities.capability_id,
    ];
    assert_eq!(
        ids.iter().collect::<std::collections::HashSet<_>>().len(),
        5
    );
    assert_eq!(
        runtime.start_workload(&mut restored),
        Err(RuntimeError::InvalidState {
            expected: "IdentityInjected".to_owned(),
            actual: "IdentityRegenerated".to_owned(),
        })
    );
    runtime
        .inject_identity(&mut restored)
        .expect("fresh identity injection must succeed");
    runtime
        .start_workload(&mut restored)
        .expect("workload starts only after injection");
    assert_eq!(restored.state(), RuntimeState::Running);
    let events = events.borrow();
    let inject_index = events
        .iter()
        .position(|event| event.starts_with("api:/actions/inject-identity:"))
        .expect("identity injection API event must be present");
    let resume_index = events
        .iter()
        .position(|event| event.starts_with("api:/vm:{\"state\":\"Resumed\"}"))
        .expect("explicit resume API event must be present");
    let start_index = events
        .iter()
        .position(|event| event.starts_with("api:/actions/start-workload:"))
        .expect("workload start API event must be present");
    assert!(resume_index < inject_index && inject_index < start_index);
}

#[test]
fn restore_accepts_exact_host_allocated_identities() {
    let config = config();
    let raw_snapshot = Snapshot::new(
        SNAPSHOT_STATE_PATH,
        SNAPSHOT_MEMORY_PATH,
        config.snapshot_fingerprint(),
        sha256(SNAPSHOT_STATE_BYTES),
        sha256(SNAPSHOT_MEMORY_BYTES),
        Vec::new(),
    );
    let bundle = IdentityBundle::new(
        identity(101),
        identity(102),
        identity(103),
        identity(104),
        identity(105),
    )
    .expect("host identity bundle must validate");
    let (mut runtime, events) = runtime(&config, std::iter::empty());
    let snapshot = runtime
        .verify_snapshot(&config, raw_snapshot)
        .expect("fixture snapshot provenance must verify");
    let restored = runtime
        .restore_with_identities(&config, &snapshot, bundle.clone())
        .expect("host identities must be authoritative during restore");
    assert_eq!(restored.identities(), Some(&bundle));
    assert!(
        events
            .borrow()
            .iter()
            .any(|event| event.starts_with("api:/snapshot/load:"))
    );
}

#[test]
fn restore_rejects_host_identity_reuse_before_side_effects() {
    let config = config();
    let reused = identity(201);
    let raw_snapshot = Snapshot::new(
        SNAPSHOT_STATE_PATH,
        SNAPSHOT_MEMORY_PATH,
        config.snapshot_fingerprint(),
        sha256(SNAPSHOT_STATE_BYTES),
        sha256(SNAPSHOT_MEMORY_BYTES),
        vec![reused],
    );
    let bundle = IdentityBundle {
        vm_id: reused,
        session_id: identity(202),
        request_id: identity(203),
        subject_id: identity(204),
        capability_id: identity(205),
    };
    let (mut runtime, events) = runtime(&config, std::iter::empty());
    let snapshot = runtime
        .verify_snapshot(&config, raw_snapshot)
        .expect("fixture snapshot provenance must verify");
    assert!(matches!(
        runtime.restore_with_identities(&config, &snapshot, bundle),
        Err(RuntimeError::StaleIdentity(_))
    ));
    assert!(events.borrow().is_empty());
}

#[test]
fn stale_identity_is_rejected_and_restored_process_is_rolled_back() {
    // Requirement: an identity copied from snapshot state must never be injected after restore.
    let config = config();
    let stale = IdentityId::from_hex("00000000000000000000000000000001")
        .expect("test identity must be valid");
    let raw_snapshot = Snapshot::new(
        SNAPSHOT_STATE_PATH,
        SNAPSHOT_MEMORY_PATH,
        config.snapshot_fingerprint(),
        sha256(SNAPSHOT_STATE_BYTES),
        sha256(SNAPSHOT_MEMORY_BYTES),
        vec![stale],
    );
    let (mut runtime, events) = runtime(&config, std::iter::empty());
    let snapshot = runtime
        .verify_snapshot(&config, raw_snapshot)
        .expect("fixture snapshot provenance must verify");
    let error = runtime
        .restore(&config, &snapshot)
        .expect_err("stale identity must fail closed");
    assert!(matches!(error, RuntimeError::StaleIdentity(_)));
    let events = events.borrow();
    assert!(
        events
            .iter()
            .any(|event| event.starts_with("api:/snapshot/load:"))
    );
    assert!(
        events
            .iter()
            .any(|event| event.starts_with("command:stop:"))
    );
    assert!(
        events
            .iter()
            .any(|event| event.starts_with("command:run:/usr/sbin/veritysetup close"))
    );
    assert!(
        events
            .iter()
            .any(|event| event.starts_with("filesystem:remove:"))
    );
}

#[test]
fn duplicate_identity_generation_is_rejected_as_stale() {
    // Requirement: all five regenerated identity domains must be distinct.
    let config = config();
    let events = Rc::new(RefCell::new(Vec::new()));
    let filesystem = filesystem_for(&config, Rc::clone(&events));
    let duplicate = IdentityId::from_hex("00000000000000000000000000000001")
        .expect("test identity must be valid");
    let mut runtime = Runtime::new(
        MockRunner::new(Rc::clone(&events)),
        filesystem,
        MockApi::new(Rc::clone(&events), std::iter::empty()),
        MockApi::new(Rc::clone(&events), std::iter::empty()),
        MockIdentitySource::from_ids([duplicate; 5]),
    );
    let raw_snapshot = Snapshot::new(
        SNAPSHOT_STATE_PATH,
        SNAPSHOT_MEMORY_PATH,
        config.snapshot_fingerprint(),
        sha256(SNAPSHOT_STATE_BYTES),
        sha256(SNAPSHOT_MEMORY_BYTES),
        Vec::new(),
    );
    let snapshot = runtime
        .verify_snapshot(&config, raw_snapshot)
        .expect("fixture snapshot provenance must verify");
    let error = runtime
        .restore(&config, &snapshot)
        .expect_err("duplicate IDs must fail closed");
    assert!(matches!(error, RuntimeError::StaleIdentity(_)));
}

#[test]
fn latest_artifact_channel_is_rejected_by_validation() {
    // Requirement: mutable latest paths are never accepted as pinned inputs.
    let mut config = config();
    config.firecracker.path = PathBuf::from("/artifacts/latest/firecracker");
    assert!(
        matches!(config.validate(), Err(RuntimeError::LatestArtifactPath { label }) if label == "firecracker")
    );
}

#[test]
fn boot_args_cannot_bypass_or_duplicate_the_guest_identity_gate() {
    let mut config = config();
    for invalid in [
        "console=ttyS0 reboot=k panic=1 pci=off",
        "console=ttyS0 reboot=k panic=1 pci=off init=/bin/sh",
        "console=ttyS0 reboot=k panic=1 pci=off init=/usr/local/libexec/guest-control-init init=/bin/sh",
        "console=ttyS0 reboot=k panic=1 pci=off init=/usr/local/libexec/guest-control-init rdinit=/bin/sh",
        "console=ttyS0 panic=1 pci=off init=/usr/local/libexec/guest-control-init",
    ] {
        config.boot_args = invalid.to_owned();
        assert!(
            matches!(config.validate(), Err(RuntimeError::InvalidConfig(_))),
            "unsafe boot args must fail: {invalid}"
        );
    }
}

#[test]
fn overlapping_workspace_source_and_clone_paths_are_rejected() {
    // Requirement: clone preparation must not recurse into its own source tree.
    let mut config = config();
    config.workspace.clone_root = PathBuf::from("/workspace/source/clones");
    assert!(matches!(
        config.validate(),
        Err(RuntimeError::InvalidConfig(message)) if message.contains("must not overlap")
    ));
}

#[test]
fn unix_api_client_sends_real_http_over_unix_socket() {
    // Requirement: the production backend must perform an actual Unix API request.
    let _lock = UNIX_API_TEST_LOCK
        .lock()
        .expect("Unix API test lock must not be poisoned");
    let socket = test_socket_path("real-http");
    let _ = fs::remove_file(&socket);
    let listener = UnixListener::bind(&socket).expect("test Unix socket must bind");
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("test API server must accept");
        let request = read_test_api_request(&mut stream);
        assert!(String::from_utf8_lossy(&request).starts_with("PUT /machine-config HTTP/1.1"));
        let response = b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        stream
            .write_all(response)
            .expect("test API server must respond");
    });
    let mut client = firecracker_runtime::UnixApiClient::new(&socket)
        .expect("absolute Unix socket path must validate")
        .with_timeout(Duration::from_secs(1))
        .expect("non-zero timeout must validate");
    let response = client
        .request(&ApiRequest {
            method: HttpMethod::Put,
            path: "/machine-config".to_owned(),
            body: "{}".to_owned(),
        })
        .expect("Unix API request must succeed");
    assert_eq!(response.status, 204);
    server.join().expect("test API server thread must finish");
    fs::remove_file(socket).expect("test Unix socket must be removable");
}

fn request_with_response(name: &str, response: &[u8]) -> Result<ApiResponse, RuntimeError> {
    let _lock = UNIX_API_TEST_LOCK
        .lock()
        .expect("Unix API test lock must not be poisoned");
    let socket = test_socket_path(name);
    let _ = fs::remove_file(&socket);
    let listener = UnixListener::bind(&socket).expect("test Unix socket must bind");
    let response = response.to_vec();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("test API server must accept");
        let _request = read_test_api_request(&mut stream);
        stream
            .write_all(&response)
            .expect("test API server must respond");
    });
    let mut client = firecracker_runtime::UnixApiClient::new(&socket)
        .expect("absolute Unix socket path must validate")
        .with_timeout(Duration::from_secs(1))
        .expect("non-zero timeout must validate");
    let result = client.request(&ApiRequest {
        method: HttpMethod::Get,
        path: "/test".to_owned(),
        body: String::new(),
    });
    server.join().expect("test API server thread must finish");
    fs::remove_file(socket).expect("test Unix socket must be removable");
    result
}

#[test]
fn unix_api_client_accepts_a_bounded_response_body() {
    let response = request_with_response(
        "bounded-body",
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
    )
    .expect("valid bounded response must succeed");
    assert_eq!(response.status, 200);
    assert_eq!(response.body, "ok");
}

#[test]
fn unix_api_client_rejects_oversized_response_before_reading_body() {
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        MAX_HTTP_BODY_BYTES + 1
    );
    let error = request_with_response("oversized-response", response.as_bytes())
        .expect_err("oversized response length must fail closed");
    assert!(matches!(error, RuntimeError::Api(message) if message.contains("body exceeds")));
}

#[test]
fn unix_api_client_rejects_duplicate_content_lengths_and_transfer_encoding() {
    let error = request_with_response(
        "duplicate-content-length",
        b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\nx",
    )
    .expect_err("duplicate content lengths must fail closed");
    assert!(matches!(error, RuntimeError::Api(message) if message.contains("duplicate")));

    let error = request_with_response(
        "transfer-encoding",
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 0\r\n\r\n",
    )
    .expect_err("transfer encoding must fail closed");
    assert!(matches!(error, RuntimeError::Api(message) if message.contains("Transfer-Encoding")));
}

#[test]
fn unix_api_client_rejects_missing_and_malformed_response_framing() {
    let error = request_with_response(
        "missing-content-length",
        b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n",
    )
    .expect_err("body-capable response must declare its length");
    assert!(matches!(error, RuntimeError::Api(message) if message.contains("omitted")));

    let error = request_with_response(
        "malformed-header-name",
        b"HTTP/1.1 200 OK\r\nBad Header: value\r\nContent-Length: 0\r\n\r\n",
    )
    .expect_err("malformed header name must fail closed");
    assert!(matches!(error, RuntimeError::Api(message) if message.contains("header name")));

    let error = request_with_response(
        "malformed-header-value",
        b"HTTP/1.1 200 OK\r\nX-Test: bad\x01value\r\nContent-Length: 0\r\n\r\n",
    )
    .expect_err("malformed header value must fail closed");
    assert!(matches!(error, RuntimeError::Api(message) if message.contains("header value")));
}

#[test]
fn unix_api_client_rejects_unsupported_and_out_of_range_status_lines() {
    let error = request_with_response(
        "unsupported-version",
        b"HTTP/2 200 OK\r\nContent-Length: 0\r\n\r\n",
    )
    .expect_err("unsupported HTTP version must fail closed");
    assert!(
        matches!(&error, RuntimeError::Api(message) if message.contains("HTTP version")),
        "unexpected unsupported-version error: {error:?}"
    );

    let error = request_with_response(
        "out-of-range-status",
        b"HTTP/1.1 600 No\r\nContent-Length: 0\r\n\r\n",
    )
    .expect_err("out-of-range status must fail closed");
    assert!(matches!(error, RuntimeError::Api(message) if message.contains("valid range")));
}

#[test]
fn unix_api_client_rejects_oversized_request_body_before_connecting() {
    let socket = test_socket_path("no-server");
    let mut client = firecracker_runtime::UnixApiClient::new(socket)
        .expect("absolute Unix socket path must validate");
    let error = client
        .request(&ApiRequest {
            method: HttpMethod::Post,
            path: "/test".to_owned(),
            body: "x".repeat(MAX_HTTP_BODY_BYTES + 1),
        })
        .expect_err("oversized request body must fail before connecting");
    assert!(matches!(error, RuntimeError::Api(message) if message.contains("request body")));
}

#[test]
fn real_filesystem_publishes_and_removes_only_owned_complete_clones() {
    let root = temporary_workspace("ownership");
    let source = root.join("source");
    let destination = root.join("clone");
    let outside = root.join("outside");
    fs::create_dir(&source).expect("source directory must be creatable");
    fs::create_dir(&outside).expect("outside directory must be creatable");
    fs::create_dir(source.join("nested")).expect("nested directory must be creatable");
    fs::write(source.join("nested/file"), b"owned").expect("source file must be writable");
    fs::write(outside.join("sentinel"), b"must survive").expect("sentinel must be writable");

    let mut filesystem = RealFileSystem::new();
    filesystem
        .clone_workspace(&source, &destination)
        .expect("complete workspace must publish");
    assert_eq!(
        fs::read(destination.join("nested/file")).expect("published file must be readable"),
        b"owned"
    );

    let saved_clone = root.join("saved-clone");
    fs::rename(&destination, &saved_clone)
        .expect("owned clone must be movable for replacement test");
    symlink(&outside, &destination).expect("replacement symlink must be creatable");
    assert!(filesystem.remove_workspace(&destination).is_err());
    assert_eq!(
        fs::read(outside.join("sentinel")).expect("unowned sentinel must remain"),
        b"must survive"
    );
    fs::remove_file(&destination).expect("replacement symlink must be removable");
    fs::rename(saved_clone, &destination).expect("owned clone must be restorable");
    filesystem
        .remove_workspace(&destination)
        .expect("restored owned clone must be removable");
    assert!(!destination.exists());

    fs::remove_dir_all(root).expect("test workspace must be removable");
}

#[test]
fn real_filesystem_owns_and_removes_the_workspace_block_image_with_its_clone() {
    let root = temporary_workspace("block-image");
    let source = root.join("source");
    let clone = root.join("clone-a");
    let image = root.join("workspace.ext4");
    let non_snapshot_image = root.join("clone-a.ext4");
    fs::create_dir(&source).expect("source directory must be creatable");
    fs::write(source.join("workspace.txt"), b"workspace").expect("source file must be writable");

    let mut filesystem = RealFileSystem::new();
    filesystem
        .clone_workspace(&source, &clone)
        .expect("workspace clone must publish");
    assert!(
        filesystem
            .create_workspace_image(&clone, &non_snapshot_image, MIN_WORKSPACE_IMAGE_BYTES)
            .is_err()
    );
    assert!(!non_snapshot_image.exists());
    filesystem
        .create_workspace_image(&clone, &image, MIN_WORKSPACE_IMAGE_BYTES)
        .expect("owned clone must receive an exact-size block image");

    let metadata = fs::metadata(&image).expect("workspace image must exist");
    assert!(metadata.is_file());
    assert_eq!(metadata.len(), MIN_WORKSPACE_IMAGE_BYTES);
    assert_eq!(metadata.mode() & 0o077, 0);

    filesystem
        .remove_workspace(&clone)
        .expect("owned clone and image must be removable together");
    assert!(!clone.exists());
    assert!(!image.exists());
    fs::remove_dir_all(root).expect("test workspace must be removable");
}

#[test]
fn real_filesystem_rejects_source_aliases_symlinks_hardlinks_and_bounds() {
    let root = temporary_workspace("rejection");
    let source = root.join("source");
    let destination = root.join("clone");
    fs::create_dir(&source).expect("source directory must be creatable");
    fs::write(root.join("outside-file"), b"outside").expect("outside file must be writable");
    symlink(root.join("outside-file"), source.join("symlink"))
        .expect("source symlink must be creatable");
    let mut filesystem = RealFileSystem::new();
    assert!(filesystem.clone_workspace(&source, &destination).is_err());
    assert!(!destination.exists());
    fs::remove_file(source.join("symlink")).expect("source symlink must be removable");

    fs::write(source.join("file"), b"hardlinked").expect("source file must be writable");
    fs::hard_link(source.join("file"), source.join("hardlink"))
        .expect("source hardlink must be creatable");
    assert!(filesystem.clone_workspace(&source, &destination).is_err());
    fs::remove_file(source.join("hardlink")).expect("source hardlink must be removable");
    fs::remove_file(source.join("file")).expect("source file must be removable");

    let nested_destination = source.join("inside-source");
    assert!(
        filesystem
            .clone_workspace(&source, &nested_destination)
            .is_err()
    );

    let mut deep = source.clone();
    for index in 0..=MAX_WORKSPACE_DEPTH {
        deep.push(format!("depth-{index}"));
        fs::create_dir(&deep).expect("bounded-depth source directory must be creatable");
    }
    assert!(filesystem.clone_workspace(&source, &destination).is_err());

    let bytes_source = root.join("bytes-source");
    fs::create_dir(&bytes_source).expect("byte-bound source directory must be creatable");
    let large = bytes_source.join("large");
    let file = fs::File::create(&large).expect("sparse source file must be creatable");
    file.set_len(MAX_WORKSPACE_BYTES + 1)
        .expect("sparse source file must support the bound test");
    let byte_destination = root.join("bytes-clone");
    assert!(
        filesystem
            .clone_workspace(&bytes_source, &byte_destination)
            .is_err()
    );
    assert!(!byte_destination.exists());

    fs::remove_dir_all(root).expect("test workspace must be removable");
}

fn shell_command(script: &str) -> CommandSpec {
    CommandSpec {
        program: PathBuf::from("/bin/sh"),
        args: vec!["-c".to_owned(), script.to_owned()],
        expected_digest: None,
    }
}

fn test_socket_path(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        ".firecracker-runtime-api-{name}-{}",
        std::process::id()
    ))
}

#[test]
fn real_command_runner_captures_normal_output() {
    let mut runner = RealCommandRunner::new();
    let output = runner
        .run(&shell_command("printf stdout; printf stderr >&2"))
        .expect("normal command output must succeed");
    assert_eq!(output.status, 0);
    assert_eq!(output.stdout, b"stdout");
    assert_eq!(output.stderr, b"stderr");
}

#[test]
fn real_command_runner_does_not_inherit_the_host_environment() {
    let mut runner = RealCommandRunner::new();
    let output = runner
        .run(&CommandSpec {
            program: PathBuf::from("/usr/bin/env"),
            args: Vec::new(),
            expected_digest: None,
        })
        .expect("environment probe must run");
    assert_eq!(output.status, 0);
    assert!(
        output.stdout.is_empty(),
        "host credentials and proxy settings must not reach helper processes"
    );
    assert!(output.stderr.is_empty());
}

#[test]
fn real_command_runner_terminates_on_oversized_stdout() {
    let mut runner = RealCommandRunner::new();
    let error = runner
        .run(&CommandSpec {
            program: PathBuf::from("yes"),
            args: Vec::new(),
            expected_digest: None,
        })
        .expect_err("unbounded command output must be rejected");
    assert!(
        matches!(error, RuntimeError::Command(message) if message.contains("stdout") && message.contains(&MAX_COMMAND_OUTPUT_BYTES.to_string()))
    );
}

#[test]
fn real_command_runner_terminates_on_oversized_stderr() {
    let mut runner = RealCommandRunner::new();
    let error = runner
        .run(&shell_command("while :; do printf x >&2; done"))
        .expect_err("unbounded command diagnostics must be rejected");
    assert!(
        matches!(error, RuntimeError::Command(message) if message.contains("stderr") && message.contains(&MAX_COMMAND_OUTPUT_BYTES.to_string()))
    );
}

#[test]
fn real_command_runner_reaps_an_already_exited_owned_child() {
    let mut runner = RealCommandRunner::new();
    let process = runner
        .start(&shell_command("exit 0"))
        .expect("owned child must start");
    std::thread::sleep(Duration::from_millis(20));
    runner
        .stop(process)
        .expect("already-exited owned child must be a successful stop");
}

#[test]
fn real_command_runner_rejects_unowned_pid_without_signalling_it() {
    let mut runner = RealCommandRunner::new();
    let error = runner
        .stop(ProcessHandle {
            pid: std::process::id(),
        })
        .expect_err("unowned PID must be rejected");
    assert!(matches!(error, RuntimeError::Command(message) if message.contains("unknown process")));
}
