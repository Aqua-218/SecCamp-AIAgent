//! Composition tests for the production session adapter types.

use std::{
    collections::VecDeque,
    io,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};

use authority_core::{
    capability::{AuthorityBody, IssuerId, SubjectId as AuthoritySubjectId},
    file::{FileAuthority, FileEffect, FileEffects},
    kernel::CapabilityKernel,
    path::{CanonicalPath, PathPattern},
    repository::RepoId,
    state::{CapabilityState, SubjectStatus},
    time::{MonotonicTime, TimeWindow},
};
use firecracker_runtime::{
    ApiClient, ApiRequest, ApiResponse, CgroupConfig, CgroupVersion, CommandOutput, CommandRunner,
    CommandSpec, DmVerityConfig, FileSystem, HostIsolationConfig, HttpMethod, IdentityId,
    IdentitySource, JailerConfig, NamespaceConfig, PinnedArtifact, ProcessHandle, ProcessOwnership,
    Runtime, RuntimeConfig, RuntimeError, SeccompConfig, Snapshot, VsockConfig, WorkspaceConfig,
    sha256,
};
use session_orchestrator::{
    CleanupStage, CryptographicRandom, EntropyError, LifecycleState, SessionOrchestrator,
    SnapshotDescriptor, SnapshotId, StartStage, SubjectId as OrchestratedSubjectId, VmBackend,
    WorkspaceId, WorkspaceTemplateId,
    authority_backend::{AuthorityCoreBackend, AuthorityRootGrant},
    egress_backend::{BrokerBackend, VsockListenerFactory},
    firecracker_backend::FirecrackerBackendFactory,
    firecracker_workspace::new_firecracker_workspace_adapters,
};

#[derive(Clone, Default)]
struct FsLog {
    reads: Arc<Mutex<Vec<PathBuf>>>,
    clones: Arc<Mutex<Vec<(PathBuf, PathBuf)>>>,
    removals: Arc<Mutex<Vec<PathBuf>>>,
    device_bindings: Arc<Mutex<Vec<(PathBuf, PathBuf)>>>,
}

struct TestFileSystem {
    log: FsLog,
}

impl FileSystem for TestFileSystem {
    fn read(&mut self, path: &Path) -> Result<Vec<u8>, RuntimeError> {
        let jail_root = session_jail_root();
        let allowed = [
            PathBuf::from("/test/firecracker"),
            PathBuf::from("/test/rootfs"),
            PathBuf::from("/test/verity"),
            PathBuf::from("/test/jailer"),
            jail_root.join("artifacts/kernel"),
            jail_root.join("artifacts/seccomp"),
            jail_root.join("snapshots/state"),
            jail_root.join("snapshots/memory"),
        ];
        if !allowed.iter().any(|allowed_path| allowed_path == path) {
            return Err(RuntimeError::Io(format!(
                "test filesystem rejected unexpected read from '{}'",
                path.display()
            )));
        }
        self.log
            .reads
            .lock()
            .expect("filesystem read log must not be poisoned")
            .push(path.to_owned());
        Ok(Vec::new())
    }

    fn verify_block_device_binding(
        &mut self,
        source: &Path,
        jailed_device: &Path,
    ) -> Result<(), RuntimeError> {
        let expected_source = PathBuf::from(format!(
            "/dev/mapper/composition-verity-{}",
            expected_workspace_id()
        ));
        let expected_device = session_jail_root().join("dev/rootfs");
        if source != expected_source || jailed_device != expected_device {
            return Err(RuntimeError::Io(
                "test filesystem rejected inexact jailed block-device binding".to_owned(),
            ));
        }
        self.log
            .device_bindings
            .lock()
            .expect("device-binding log must not be poisoned")
            .push((source.to_owned(), jailed_device.to_owned()));
        Ok(())
    }

    fn clone_workspace(&mut self, source: &Path, destination: &Path) -> Result<(), RuntimeError> {
        let expected_destination = session_jail_root()
            .join("workspace")
            .join(expected_workspace_id().to_string());
        if source != Path::new("/test/source") || destination != expected_destination {
            return Err(RuntimeError::Io(
                "test filesystem rejected inexact workspace clone".to_owned(),
            ));
        }
        self.log
            .clones
            .lock()
            .expect("filesystem log must not be poisoned")
            .push((source.to_owned(), destination.to_owned()));
        Ok(())
    }

    fn remove_workspace(&mut self, path: &Path) -> Result<(), RuntimeError> {
        let expected_path = session_jail_root()
            .join("workspace")
            .join(expected_workspace_id().to_string());
        if path != expected_path {
            return Err(RuntimeError::Io(
                "test filesystem rejected inexact workspace removal".to_owned(),
            ));
        }
        self.log
            .removals
            .lock()
            .expect("filesystem log must not be poisoned")
            .push(path.to_owned());
        Ok(())
    }
}

#[derive(Clone, Default)]
struct RunnerLog {
    stop_attempts: Arc<AtomicUsize>,
    owned_starts: Arc<Mutex<Vec<ProcessOwnership>>>,
    running_verifications: Arc<Mutex<Vec<ProcessHandle>>>,
}

#[derive(Default)]
struct TestRunner {
    next_pid: u32,
    stop_failures: VecDeque<bool>,
    log: RunnerLog,
}

impl CommandRunner for TestRunner {
    fn run(&mut self, _command: &CommandSpec) -> Result<CommandOutput, RuntimeError> {
        Ok(CommandOutput {
            status: 0,
            stdout: Vec::new(),
            stderr: Vec::new(),
        })
    }

    fn start(&mut self, _command: &CommandSpec) -> Result<ProcessHandle, RuntimeError> {
        self.next_pid += 1;
        Ok(ProcessHandle { pid: self.next_pid })
    }

    fn start_owned(
        &mut self,
        command: &CommandSpec,
        ownership: &ProcessOwnership,
    ) -> Result<ProcessHandle, RuntimeError> {
        let workspace = expected_workspace_id().to_string();
        let expected_args = vec![
            "--id".to_owned(),
            workspace.clone(),
            "--exec-file".to_owned(),
            "/test/firecracker".to_owned(),
            "--uid".to_owned(),
            "1000".to_owned(),
            "--gid".to_owned(),
            "1000".to_owned(),
            "--cgroup-version".to_owned(),
            "2".to_owned(),
            "--parent-cgroup".to_owned(),
            "test".to_owned(),
            "--cgroup".to_owned(),
            "memory.max=1".to_owned(),
            "--cgroup".to_owned(),
            "cpu.max=1 1".to_owned(),
            "--chroot-base-dir".to_owned(),
            "/test/jailer".to_owned(),
            "--new-pid-ns".to_owned(),
            "--".to_owned(),
            "--api-sock".to_owned(),
            "/run/firecracker.sock".to_owned(),
            "--seccomp-filter".to_owned(),
            "/artifacts/seccomp".to_owned(),
        ];
        if command.program != Path::new("/test/jailer")
            || command.args != expected_args
            || ownership.cgroup_path.parent() != Some(Path::new("/sys/fs/cgroup/test"))
            || ownership
                .cgroup_path
                .file_name()
                .and_then(|name| name.to_str())
                != Some(workspace.as_str())
            || ownership.firecracker_executable != Path::new("/test/firecracker")
            || ownership.firecracker_digest != sha256(&[])
        {
            return Err(RuntimeError::Command(
                "test runner rejected inexact Firecracker ownership".to_owned(),
            ));
        }
        self.log
            .owned_starts
            .lock()
            .expect("owned-start log must not be poisoned")
            .push(ownership.clone());
        self.start(command)
    }

    fn verify_running(&mut self, process: ProcessHandle) -> Result<(), RuntimeError> {
        if process.pid == 0 || process.pid > self.next_pid {
            return Err(RuntimeError::Command(
                "test runner cannot verify an unknown process".to_owned(),
            ));
        }
        self.log
            .running_verifications
            .lock()
            .expect("running-verification log must not be poisoned")
            .push(process);
        Ok(())
    }

    fn stop(&mut self, _process: ProcessHandle) -> Result<(), RuntimeError> {
        self.log.stop_attempts.fetch_add(1, Ordering::SeqCst);
        if self.stop_failures.pop_front().unwrap_or(false) {
            return Err(RuntimeError::Command(
                "test process stop failure".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Default)]
struct TestApi {
    requests: Arc<Mutex<Vec<ApiRequest>>>,
    failures: Arc<Mutex<VecDeque<bool>>>,
    restore_verifications: Arc<Mutex<Vec<(PathBuf, PathBuf, u32)>>>,
}

impl ApiClient for TestApi {
    fn request(&mut self, request: &ApiRequest) -> Result<ApiResponse, RuntimeError> {
        self.requests
            .lock()
            .expect("API log must not be poisoned")
            .push(request.clone());
        if self
            .failures
            .lock()
            .expect("API failure sequence must not be poisoned")
            .pop_front()
            .unwrap_or(false)
        {
            return Err(RuntimeError::Api("test restore API failure".to_owned()));
        }
        Ok(ApiResponse {
            status: 200,
            body: String::new(),
        })
    }

    fn verify_restore_resources(
        &mut self,
        workspace_path: &Path,
        vsock_uds_path: &Path,
        guest_cid: u32,
    ) -> Result<(), RuntimeError> {
        let expected_workspace = PathBuf::from(format!("/workspace/{}", expected_workspace_id()));
        if workspace_path != expected_workspace
            || vsock_uds_path != Path::new("/run/vsock.sock")
            || guest_cid != 3
        {
            return Err(RuntimeError::StaleSnapshot(
                "test API rejected inexact restored resource binding".to_owned(),
            ));
        }
        self.requests
            .lock()
            .expect("API log must not be poisoned")
            .push(ApiRequest {
                method: HttpMethod::Get,
                path: "/vm/config".to_owned(),
                body: String::new(),
            });
        self.restore_verifications
            .lock()
            .expect("restore-verification log must not be poisoned")
            .push((
                workspace_path.to_owned(),
                vsock_uds_path.to_owned(),
                guest_cid,
            ));
        Ok(())
    }
}

struct UnusedIdentitySource;

impl IdentitySource for UnusedIdentitySource {
    fn generate(&mut self) -> Result<IdentityId, RuntimeError> {
        Err(RuntimeError::InvalidIdentity(
            "composition must use host-allocated identities".to_owned(),
        ))
    }
}

struct SequenceRandom {
    values: VecDeque<[u8; 16]>,
}

impl CryptographicRandom for SequenceRandom {
    fn random_128(&mut self) -> Result<[u8; 16], EntropyError> {
        self.values
            .pop_front()
            .ok_or_else(|| EntropyError::new("test identity sequence exhausted"))
    }
}

#[derive(Clone)]
struct ListenerFactory {
    binds: Arc<AtomicUsize>,
    drops: Arc<AtomicUsize>,
}

struct Listener {
    drops: Arc<AtomicUsize>,
}

impl Drop for Listener {
    fn drop(&mut self) {
        self.drops.fetch_add(1, Ordering::SeqCst);
    }
}

impl VsockListenerFactory for ListenerFactory {
    type Listener = Listener;

    fn bind(&self, _host_cid: u32, _port: u32, _backlog: i32) -> io::Result<Self::Listener> {
        self.binds.fetch_add(1, Ordering::SeqCst);
        Ok(Listener {
            drops: Arc::clone(&self.drops),
        })
    }
}

fn test_broker(
    binds: &Arc<AtomicUsize>,
    drops: &Arc<AtomicUsize>,
) -> BrokerBackend<ListenerFactory> {
    BrokerBackend::new(
        ListenerFactory {
            binds: Arc::clone(binds),
            drops: Arc::clone(drops),
        },
        2,
        3,
        9000,
        16,
    )
    .expect("test broker configuration must be valid")
}

fn cloned_workspace(fs_log: &FsLog) -> PathBuf {
    fs_log
        .clones
        .lock()
        .expect("filesystem log must not be poisoned")[0]
        .1
        .clone()
}

fn assert_workspace_removals(fs_log: &FsLog, expected: &[PathBuf]) {
    assert_eq!(
        fs_log
            .removals
            .lock()
            .expect("filesystem log must not be poisoned")
            .as_slice(),
        expected
    );
}

fn assert_snapshot_reverified(fs_log: &FsLog) {
    let jail_root = session_jail_root();
    let state_path = jail_root.join("snapshots/state");
    let memory_path = jail_root.join("snapshots/memory");
    let reads = fs_log
        .reads
        .lock()
        .expect("filesystem read log must not be poisoned");
    assert_eq!(reads.iter().filter(|path| **path == state_path).count(), 3);
    assert_eq!(reads.iter().filter(|path| **path == memory_path).count(), 3);
}

fn assert_successful_restore_observations(
    fs_log: &FsLog,
    runner_log: &RunnerLog,
    api: &TestApi,
    workspace_id: WorkspaceId,
) {
    assert_eq!(
        fs_log
            .clones
            .lock()
            .expect("filesystem log must not be poisoned")
            .as_slice(),
        [(
            PathBuf::from("/test/source"),
            session_jail_root()
                .join("workspace")
                .join(workspace_id.to_string()),
        )]
    );
    assert_snapshot_reverified(fs_log);
    assert_eq!(
        runner_log
            .owned_starts
            .lock()
            .expect("owned-start log must not be poisoned")
            .len(),
        1
    );
    assert_eq!(
        runner_log
            .running_verifications
            .lock()
            .expect("running-verification log must not be poisoned")
            .as_slice(),
        [
            ProcessHandle { pid: 1 },
            ProcessHandle { pid: 1 },
            ProcessHandle { pid: 1 },
        ]
    );
    assert_eq!(
        api.restore_verifications
            .lock()
            .expect("restore-verification log must not be poisoned")
            .as_slice(),
        [(
            PathBuf::from(format!("/workspace/{workspace_id}")),
            PathBuf::from("/run/vsock.sock"),
            3,
        )]
    );
    assert_eq!(
        fs_log
            .device_bindings
            .lock()
            .expect("device-binding log must not be poisoned")
            .as_slice(),
        [(
            PathBuf::from(format!("/dev/mapper/composition-verity-{workspace_id}")),
            session_jail_root().join("dev/rootfs"),
        )]
    );
    assert!(
        api.requests
            .lock()
            .expect("API log must not be poisoned")
            .iter()
            .any(|request| request.path == "/actions/inject-identity")
    );
}

fn assert_failed_restore_observations(
    fs_log: &FsLog,
    runner_log: &RunnerLog,
    api: &TestApi,
    binds: &AtomicUsize,
    drops: &AtomicUsize,
) {
    assert_eq!(runner_log.stop_attempts.load(Ordering::SeqCst), 2);
    assert_eq!(
        runner_log
            .owned_starts
            .lock()
            .expect("owned-start log must not be poisoned")
            .len(),
        1
    );
    assert_eq!(
        runner_log
            .running_verifications
            .lock()
            .expect("running-verification log must not be poisoned")
            .as_slice(),
        [ProcessHandle { pid: 1 }]
    );
    assert_eq!(binds.load(Ordering::SeqCst), 1);
    assert_eq!(drops.load(Ordering::SeqCst), 1);
    assert_eq!(
        api.requests
            .lock()
            .expect("API log must not be poisoned")
            .iter()
            .filter(|request| request.path == "/snapshot/load")
            .count(),
        1
    );
    assert!(
        api.restore_verifications
            .lock()
            .expect("restore-verification log must not be poisoned")
            .is_empty(),
        "failed snapshot load must not claim restore-resource verification"
    );
    assert_snapshot_reverified(fs_log);
    assert_eq!(
        fs_log
            .device_bindings
            .lock()
            .expect("device-binding log must not be poisoned")
            .len(),
        1
    );
    assert_workspace_removals(fs_log, &[]);
}

fn artifact(path: &str) -> PinnedArtifact {
    PinnedArtifact::new(path, sha256(&[]))
}

fn runtime_config() -> RuntimeConfig {
    let jail_root = Path::new("/test/jailer/firecracker/unbound/root");
    let rootfs = artifact("/test/rootfs");
    RuntimeConfig {
        firecracker: artifact("/test/firecracker"),
        kernel: artifact(
            jail_root
                .join("artifacts/kernel")
                .to_str()
                .expect("test kernel path must be UTF-8"),
        ),
        rootfs: rootfs.clone(),
        verity_hash: artifact("/test/verity"),
        dm_verity: DmVerityConfig {
            data_device: rootfs.path.clone(),
            hash_device: PathBuf::from("/test/verity"),
            mapper_name: "composition-verity".to_owned(),
            root_hash: sha256(b"composition root hash"),
            jailed_device_path: jail_root.join("dev/rootfs"),
        },
        workspace: WorkspaceConfig {
            source: PathBuf::from("/test/source"),
            clone_root: jail_root.join("workspace"),
            clone_id: "unbound".to_owned(),
        },
        jailer: artifact("/test/jailer"),
        jailer_config: JailerConfig {
            uid: 1000,
            gid: 1000,
            chroot_base_dir: PathBuf::from("/test/jailer"),
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
                path: PathBuf::from("/sys/fs/cgroup/test/unbound"),
                memory_max_bytes: 1,
                cpu_quota_micros: 1,
                cpu_period_micros: 1,
            },
            seccomp: SeccompConfig {
                filter: artifact(
                    jail_root
                        .join("artifacts/seccomp")
                        .to_str()
                        .expect("test seccomp path must be UTF-8"),
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
            guest_cid: 3,
            uds_path: jail_root.join("run/vsock.sock"),
        },
        network_devices: Vec::new(),
        vcpu_count: 1,
        memory_mib: 128,
        boot_args: "console=ttyS0".to_owned(),
    }
}

fn expected_workspace_id() -> WorkspaceId {
    WorkspaceId::new([5; 16])
}

fn session_jail_root() -> PathBuf {
    PathBuf::from(format!(
        "/test/jailer/firecracker/{}/root",
        expected_workspace_id()
    ))
}

fn snapshot(config: &RuntimeConfig) -> Snapshot {
    let jail_root = session_jail_root();
    Snapshot::new(
        jail_root.join("snapshots/state"),
        jail_root.join("snapshots/memory"),
        config.snapshot_fingerprint(),
        sha256(&[]),
        sha256(&[]),
        Vec::new(),
    )
}

fn authority_grant() -> AuthorityRootGrant {
    AuthorityRootGrant::new(
        TimeWindow::new(MonotonicTime::from_ticks(1), MonotonicTime::from_ticks(100))
            .expect("test time window must be valid"),
        AuthorityBody::File(FileAuthority::new(
            RepoId::new("repo"),
            FileEffects::only(FileEffect::ReadData),
            PathPattern::Prefix(
                CanonicalPath::new(["src"]).expect("test path pattern must be valid"),
            ),
        )),
    )
}

fn assert_subject_closed(kernel: &CapabilityKernel, subject_id: OrchestratedSubjectId) {
    let subject = AuthoritySubjectId::new(subject_id.to_string());
    assert_eq!(
        kernel
            .subject_status(&subject)
            .expect("Authority Core status lookup must succeed"),
        Some(SubjectStatus::Closed)
    );
}

#[test]
fn production_adapters_preserve_exact_bindings_through_start_and_stop() {
    let fs_log = FsLog::default();
    let template = WorkspaceTemplateId::new("template");
    let (mut workspace, runtime_filesystem) = new_firecracker_workspace_adapters(
        TestFileSystem {
            log: fs_log.clone(),
        },
        template.clone(),
        "/test/source",
        "/test/jailer/firecracker",
    );
    let config = runtime_config();
    let api = TestApi::default();
    let api_observer = api.clone();
    let runner_log = RunnerLog::default();
    let runtime = Runtime::new(
        TestRunner {
            log: runner_log.clone(),
            ..TestRunner::default()
        },
        runtime_filesystem,
        api.clone(),
        api,
        UnusedIdentitySource,
    );
    let snapshot_id = SnapshotId::new([0x90; 16]);
    let snapshot = snapshot(&config);
    let (mut vm, mut workload) =
        FirecrackerBackendFactory::new(runtime, config, snapshot, snapshot_id).into_handles();

    let binds = Arc::new(AtomicUsize::new(0));
    let drops = Arc::new(AtomicUsize::new(0));
    let mut broker = test_broker(&binds, &drops);
    let kernel = Arc::new(CapabilityKernel::new(CapabilityState::new(IssuerId::new(
        "host",
    ))));
    let mut capability = AuthorityCoreBackend::new(Arc::clone(&kernel));
    let mut orchestrator = SessionOrchestrator::new(SequenceRandom {
        values: (1_u8..=7).map(|byte| [byte; 16]).collect(),
    });
    let descriptor = SnapshotDescriptor::clean(snapshot_id);

    let info = orchestrator
        .start_session(
            &descriptor,
            &template,
            &authority_grant(),
            &mut workspace,
            &mut broker,
            &mut vm,
            &mut capability,
            &mut workload,
        )
        .expect("all production adapters must compose");
    let identity = info.identity();
    assert_eq!(binds.load(Ordering::SeqCst), 1);
    assert_eq!(drops.load(Ordering::SeqCst), 0);
    assert_eq!(identity.workspace_id(), expected_workspace_id());
    assert_successful_restore_observations(
        &fs_log,
        &runner_log,
        &api_observer,
        identity.workspace_id(),
    );

    orchestrator
        .stop_session(&mut workspace, &mut broker, &mut vm, &mut capability)
        .expect("composed cleanup must complete");

    assert_eq!(drops.load(Ordering::SeqCst), 1);
    assert_eq!(
        fs_log
            .removals
            .lock()
            .expect("filesystem log must not be poisoned")
            .as_slice(),
        [session_jail_root()
            .join("workspace")
            .join(identity.workspace_id().to_string())]
    );
    assert_subject_closed(&kernel, identity.subject_id());
}

#[test]
fn failed_firecracker_restore_cleanup_is_retried_by_orchestrator_stop() {
    let fs_log = FsLog::default();
    let template = WorkspaceTemplateId::new("template");
    let (mut workspace, runtime_filesystem) = new_firecracker_workspace_adapters(
        TestFileSystem {
            log: fs_log.clone(),
        },
        template.clone(),
        "/test/source",
        "/test/jailer/firecracker",
    );
    let api = TestApi {
        failures: Arc::new(Mutex::new(VecDeque::from([true]))),
        ..TestApi::default()
    };
    let api_observer = api.clone();
    let config = runtime_config();
    let runner_log = RunnerLog::default();
    let runtime = Runtime::new(
        TestRunner {
            stop_failures: VecDeque::from([true, true, false]),
            log: runner_log.clone(),
            ..TestRunner::default()
        },
        runtime_filesystem,
        api.clone(),
        api,
        UnusedIdentitySource,
    );
    let snapshot_id = SnapshotId::new([0x91; 16]);
    let snapshot = snapshot(&config);
    let (mut vm, mut workload) =
        FirecrackerBackendFactory::new(runtime, config, snapshot, snapshot_id).into_handles();

    let binds = Arc::new(AtomicUsize::new(0));
    let drops = Arc::new(AtomicUsize::new(0));
    let mut broker = test_broker(&binds, &drops);
    let kernel = Arc::new(CapabilityKernel::new(CapabilityState::new(IssuerId::new(
        "host",
    ))));
    let mut capability = AuthorityCoreBackend::new(kernel);
    let mut orchestrator = SessionOrchestrator::new(SequenceRandom {
        values: (1_u8..=7).map(|byte| [byte; 16]).collect(),
    });

    let error = orchestrator
        .start_session(
            &SnapshotDescriptor::clean(snapshot_id),
            &template,
            &authority_grant(),
            &mut workspace,
            &mut broker,
            &mut vm,
            &mut capability,
            &mut workload,
        )
        .expect_err("restore and its immediate cleanup must fail");

    assert_eq!(error.stage(), StartStage::VmStart);
    assert!(error.to_string().contains("test restore API failure"));
    assert_eq!(error.rollback_failures().len(), 1);
    assert_eq!(error.rollback_failures()[0].stage(), CleanupStage::VmKill);
    assert_eq!(orchestrator.state(), LifecycleState::Stopping);
    assert_failed_restore_observations(&fs_log, &runner_log, &api_observer, &binds, &drops);
    let cloned_workspace = cloned_workspace(&fs_log);

    orchestrator
        .stop_session(&mut workspace, &mut broker, &mut vm, &mut capability)
        .expect("stop must retry retained Firecracker startup cleanup");

    assert_eq!(orchestrator.state(), LifecycleState::Closed);
    assert_eq!(runner_log.stop_attempts.load(Ordering::SeqCst), 3);
    assert_workspace_removals(&fs_log, &[cloned_workspace]);

    vm.cleanup_failed_start()
        .expect("Runtime must have no pending cleanup after stop");
    assert_eq!(
        runner_log.stop_attempts.load(Ordering::SeqCst),
        3,
        "checking completed cleanup must not retry the process stop"
    );
}
