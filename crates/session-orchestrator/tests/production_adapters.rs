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
    ApiClient, ApiRequest, ApiResponse, CgroupConfig, CommandOutput, CommandRunner, CommandSpec,
    DmVerityConfig, FileSystem, HostIsolationConfig, IdentityId, IdentitySource, NamespaceConfig,
    PinnedArtifact, ProcessHandle, Runtime, RuntimeConfig, RuntimeError, SeccompConfig, Snapshot,
    VsockConfig, WorkspaceConfig, sha256,
};
use session_orchestrator::{
    CleanupStage, CryptographicRandom, EntropyError, LifecycleState, SessionOrchestrator,
    SnapshotDescriptor, SnapshotId, StartStage, SubjectId as OrchestratedSubjectId, VmBackend,
    WorkspaceTemplateId,
    authority_backend::{AuthorityCoreBackend, AuthorityRootGrant},
    egress_backend::{BrokerBackend, VsockListenerFactory},
    firecracker_backend::FirecrackerBackendFactory,
    firecracker_workspace::new_firecracker_workspace_adapters,
};

#[derive(Clone, Default)]
struct FsLog {
    clones: Arc<Mutex<Vec<(PathBuf, PathBuf)>>>,
    removals: Arc<Mutex<Vec<PathBuf>>>,
}

struct TestFileSystem {
    log: FsLog,
}

impl FileSystem for TestFileSystem {
    fn read(&mut self, _path: &Path) -> Result<Vec<u8>, RuntimeError> {
        Ok(Vec::new())
    }

    fn clone_workspace(&mut self, source: &Path, destination: &Path) -> Result<(), RuntimeError> {
        self.log
            .clones
            .lock()
            .expect("filesystem log must not be poisoned")
            .push((source.to_owned(), destination.to_owned()));
        Ok(())
    }

    fn remove_workspace(&mut self, path: &Path) -> Result<(), RuntimeError> {
        self.log
            .removals
            .lock()
            .expect("filesystem log must not be poisoned")
            .push(path.to_owned());
        Ok(())
    }
}

#[derive(Default)]
struct TestRunner {
    next_pid: u32,
    stop_failures: VecDeque<bool>,
    stop_attempts: Arc<AtomicUsize>,
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

    fn stop(&mut self, _process: ProcessHandle) -> Result<(), RuntimeError> {
        self.stop_attempts.fetch_add(1, Ordering::SeqCst);
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

fn artifact(path: &str) -> PinnedArtifact {
    PinnedArtifact::new(path, sha256(&[]))
}

fn runtime_config() -> RuntimeConfig {
    let rootfs = artifact("/test/rootfs");
    RuntimeConfig {
        firecracker: artifact("/test/firecracker"),
        kernel: artifact("/test/kernel"),
        rootfs: rootfs.clone(),
        verity_hash: artifact("/test/verity"),
        dm_verity: DmVerityConfig {
            data_device: rootfs.path.clone(),
            hash_device: PathBuf::from("/test/verity"),
            mapper_name: "composition-verity".to_owned(),
            root_hash: sha256(b"composition root hash"),
        },
        workspace: WorkspaceConfig {
            source: PathBuf::from("/test/source"),
            clone_root: PathBuf::from("/test/clones"),
            clone_id: "unbound".to_owned(),
        },
        jailer: artifact("/test/jailer"),
        api_socket: PathBuf::from("/test/firecracker.sock"),
        isolation: HostIsolationConfig {
            namespaces: NamespaceConfig {
                user: true,
                pid: true,
                mount: true,
                network: true,
                ipc: true,
                uts: true,
            },
            cgroup: CgroupConfig {
                path: PathBuf::from("/test/cgroup"),
                memory_max_bytes: 1,
                cpu_quota_micros: 1,
            },
            seccomp: SeccompConfig {
                filter: artifact("/test/seccomp"),
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
            uds_path: PathBuf::from("/test/vsock.sock"),
        },
        network_devices: Vec::new(),
        vcpu_count: 1,
        memory_mib: 128,
        boot_args: "console=ttyS0".to_owned(),
    }
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
        "/test/clones",
    );
    let config = runtime_config();
    let api = TestApi::default();
    let api_log = Arc::clone(&api.requests);
    let runtime = Runtime::new(
        TestRunner::default(),
        runtime_filesystem,
        api.clone(),
        api,
        UnusedIdentitySource,
    );
    let snapshot_id = SnapshotId::new([0x90; 16]);
    let snapshot = Snapshot::new(
        "/test/snapshot",
        "/test/memory",
        config.snapshot_fingerprint(),
        Vec::new(),
    );
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
    assert_eq!(
        fs_log
            .clones
            .lock()
            .expect("filesystem log must not be poisoned")
            .as_slice(),
        [(
            PathBuf::from("/test/source"),
            PathBuf::from(format!("/test/clones/{}", identity.workspace_id())),
        )]
    );
    assert!(
        api_log
            .lock()
            .expect("API log must not be poisoned")
            .iter()
            .any(|request| request.path == "/actions/inject-identity")
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
        [PathBuf::from(format!(
            "/test/clones/{}",
            identity.workspace_id()
        ))]
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
        "/test/clones",
    );
    let stop_attempts = Arc::new(AtomicUsize::new(0));
    let api = TestApi {
        failures: Arc::new(Mutex::new(VecDeque::from([true]))),
        ..TestApi::default()
    };
    let api_log = Arc::clone(&api.requests);
    let config = runtime_config();
    let runtime = Runtime::new(
        TestRunner {
            next_pid: 0,
            stop_failures: VecDeque::from([true, true, false]),
            stop_attempts: Arc::clone(&stop_attempts),
        },
        runtime_filesystem,
        api.clone(),
        api,
        UnusedIdentitySource,
    );
    let snapshot_id = SnapshotId::new([0x91; 16]);
    let snapshot = Snapshot::new(
        "/test/snapshot",
        "/test/memory",
        config.snapshot_fingerprint(),
        Vec::new(),
    );
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
    assert_eq!(stop_attempts.load(Ordering::SeqCst), 2);
    assert_eq!(binds.load(Ordering::SeqCst), 1);
    assert_eq!(drops.load(Ordering::SeqCst), 1);
    assert_eq!(
        api_log
            .lock()
            .expect("API log must not be poisoned")
            .iter()
            .filter(|request| request.path == "/snapshot/load")
            .count(),
        1
    );
    assert_workspace_removals(&fs_log, &[]);
    let cloned_workspace = cloned_workspace(&fs_log);

    orchestrator
        .stop_session(&mut workspace, &mut broker, &mut vm, &mut capability)
        .expect("stop must retry retained Firecracker startup cleanup");

    assert_eq!(orchestrator.state(), LifecycleState::Closed);
    assert_eq!(stop_attempts.load(Ordering::SeqCst), 3);
    assert_workspace_removals(&fs_log, &[cloned_workspace]);

    vm.cleanup_failed_start()
        .expect("Runtime must have no pending cleanup after stop");
    assert_eq!(
        stop_attempts.load(Ordering::SeqCst),
        3,
        "checking completed cleanup must not retry the process stop"
    );
}
