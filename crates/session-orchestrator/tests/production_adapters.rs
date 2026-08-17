//! Composition tests for the production session adapter types.

use std::{
    collections::VecDeque,
    io::{self, Read, Write},
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant},
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
    WorkspaceImageConfig, sha256,
};
use session_orchestrator::{
    BackendError, BrokerBackend as BrokerBackendTrait, BrokerLease, CapabilityBackend,
    CapabilityLease, CapabilityRevocationBackend, CleanupStage, CryptographicRandom, EntropyError,
    LifecycleState, SessionIdentity, SessionOrchestrator, SnapshotDescriptor, SnapshotId,
    StartStage, SubjectId as OrchestratedSubjectId, VmBackend, WorkspaceId, WorkspaceTemplateId,
    authority_backend::{AuthorityCoreBackend, AuthorityRootGrant},
    egress_backend::{
        BrokerBackend as OwnedBrokerBackend, BrokerCancellation, BrokerConnectionExit,
        BrokerRuntime, BrokerRuntimeFactory, BrokerServiceListener, BrokerStreamShutdown,
        VsockListenerFactory,
    },
    firecracker_backend::{
        FirecrackerBackendFactory, FirecrackerVmBackend, FirecrackerWorkloadBackend,
    },
    firecracker_workspace::{
        FirecrackerFileSystem, FirecrackerWorkspaceBackend, new_firecracker_workspace_adapters,
    },
    session_owner::{
        BrokerRuntimeStatus, BrokerStatusBackend, OwnerPollOutcome, OwnerPollRequest,
        SessionBackends, SessionOwner, ShutdownReason,
    },
};

type LifecycleEvents = Arc<Mutex<Vec<&'static str>>>;

fn record_event(events: &LifecycleEvents, event: &'static str) {
    events
        .lock()
        .expect("lifecycle event log must not be poisoned")
        .push(event);
}

#[derive(Clone, Default)]
struct FsLog {
    reads: Arc<Mutex<Vec<PathBuf>>>,
    clones: Arc<Mutex<Vec<(PathBuf, PathBuf)>>>,
    images: Arc<Mutex<Vec<(PathBuf, PathBuf, u64)>>>,
    removals: Arc<Mutex<Vec<PathBuf>>>,
    device_binds: Arc<Mutex<Vec<(PathBuf, PathBuf)>>>,
    device_bindings: Arc<Mutex<Vec<(PathBuf, PathBuf)>>>,
    device_unbinds: Arc<Mutex<Vec<(PathBuf, PathBuf)>>>,
    lifecycle: LifecycleEvents,
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
            PathBuf::from("/test/mke2fs"),
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

    fn bind_block_device(
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
                "test filesystem rejected inexact jailed block-device bind".to_owned(),
            ));
        }
        self.log
            .device_binds
            .lock()
            .expect("device-bind log must not be poisoned")
            .push((source.to_owned(), jailed_device.to_owned()));
        Ok(())
    }

    fn unbind_block_device(
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
                "test filesystem rejected inexact jailed block-device unbind".to_owned(),
            ));
        }
        self.log
            .device_unbinds
            .lock()
            .expect("device-unbind log must not be poisoned")
            .push((source.to_owned(), jailed_device.to_owned()));
        Ok(())
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

    fn create_workspace_image(
        &mut self,
        workspace: &Path,
        image: &Path,
        size_bytes: u64,
    ) -> Result<(), RuntimeError> {
        let expected_workspace = session_jail_root()
            .join("workspace")
            .join(expected_workspace_id().to_string());
        let expected_image = session_jail_root()
            .join("workspace")
            .join(format!("{}.ext4", expected_workspace_id()));
        if workspace != expected_workspace
            || image != expected_image
            || size_bytes != 64 * 1024 * 1024
        {
            return Err(RuntimeError::Io(
                "test filesystem rejected inexact workspace image".to_owned(),
            ));
        }
        self.log
            .images
            .lock()
            .expect("filesystem image log must not be poisoned")
            .push((workspace.to_owned(), image.to_owned(), size_bytes));
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
        record_event(&self.log.lifecycle, "isolate");
        Ok(())
    }
}

#[derive(Clone, Default)]
struct RunnerLog {
    stop_attempts: Arc<AtomicUsize>,
    owned_starts: Arc<Mutex<Vec<ProcessOwnership>>>,
    running_verifications: Arc<Mutex<Vec<ProcessHandle>>>,
    lifecycle: LifecycleEvents,
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
        record_event(&self.log.lifecycle, "kill");
        Ok(())
    }
}

#[derive(Clone, Default)]
struct TestApi {
    requests: Arc<Mutex<Vec<ApiRequest>>>,
    failures: Arc<Mutex<VecDeque<bool>>>,
    restore_verifications: Arc<Mutex<Vec<(PathBuf, PathBuf, u32)>>>,
    lifecycle: LifecycleEvents,
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
        if request.path == "/actions/inject-identity" {
            record_event(&self.lifecycle, "workload-release");
        }
        let body = match request.path.as_str() {
            "/actions/inject-identity" => Some("identity-injected"),
            "/actions/start-workload" => Some("workload-started"),
            _ => None,
        }
        .map_or_else(String::new, |acknowledgement| {
            format!("{{\"ack\":\"{acknowledgement}\",{}", &request.body[1..])
        });
        Ok(ApiResponse { status: 200, body })
    }

    fn verify_restore_resources(
        &mut self,
        workspace_path: &Path,
        vsock_uds_path: &Path,
        guest_cid: u32,
    ) -> Result<(), RuntimeError> {
        let expected_workspace =
            PathBuf::from(format!("/workspace/{}.ext4", expected_workspace_id()));
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

#[derive(Clone, Default)]
struct BrokerLog {
    binds: Arc<AtomicUsize>,
    drops: Arc<AtomicUsize>,
    shutdowns: Arc<AtomicUsize>,
    builds: Arc<AtomicUsize>,
    starts: Arc<AtomicUsize>,
    exits: Arc<AtomicUsize>,
    exit_requested: Arc<AtomicBool>,
    lifecycle: LifecycleEvents,
}

#[derive(Clone)]
struct ListenerFactory {
    log: BrokerLog,
    accepted: Arc<AtomicBool>,
}

struct Listener {
    log: BrokerLog,
    accepted: Arc<AtomicBool>,
}

impl Drop for Listener {
    fn drop(&mut self) {
        self.log.drops.fetch_add(1, Ordering::SeqCst);
        record_event(&self.log.lifecycle, "broker-worker-exit");
    }
}

struct TestStream {
    log: BrokerLog,
}

impl Read for TestStream {
    fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "test Broker runtime owns stream reads",
        ))
    }
}

impl Write for TestStream {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct TestShutdown {
    log: BrokerLog,
}

impl BrokerStreamShutdown for TestShutdown {
    fn shutdown(&self) -> io::Result<()> {
        self.log.shutdowns.fetch_add(1, Ordering::SeqCst);
        record_event(&self.log.lifecycle, "broker-stream-shutdown");
        Ok(())
    }
}

impl BrokerServiceListener for Listener {
    type Stream = TestStream;
    type Shutdown = TestShutdown;

    fn try_accept_peer(&self) -> io::Result<Option<(u32, Self::Stream)>> {
        Ok((!self.accepted.swap(true, Ordering::SeqCst)).then_some((
            3,
            TestStream {
                log: self.log.clone(),
            },
        )))
    }

    fn shutdown_handle(stream: &Self::Stream) -> io::Result<Self::Shutdown> {
        Ok(TestShutdown {
            log: stream.log.clone(),
        })
    }
}

impl VsockListenerFactory for ListenerFactory {
    type Listener = Listener;

    fn bind(
        &self,
        _identity: &SessionIdentity,
        _host_cid: u32,
        _port: u32,
        _backlog: i32,
    ) -> io::Result<Self::Listener> {
        self.log.binds.fetch_add(1, Ordering::SeqCst);
        record_event(&self.log.lifecycle, "broker-bind");
        Ok(Listener {
            log: self.log.clone(),
            accepted: Arc::clone(&self.accepted),
        })
    }
}

#[derive(Clone, Copy)]
enum RuntimeBehavior {
    WaitForCancellation,
    ExitWhenSignalled,
}

#[derive(Clone)]
struct RuntimeFactory {
    behavior: RuntimeBehavior,
    log: BrokerLog,
}

struct TestBrokerRuntime {
    behavior: RuntimeBehavior,
    log: BrokerLog,
}

impl BrokerRuntime<TestStream> for TestBrokerRuntime {
    fn serve(self, _stream: TestStream, cancellation: &BrokerCancellation) -> BrokerConnectionExit {
        self.log.starts.fetch_add(1, Ordering::SeqCst);
        record_event(&self.log.lifecycle, "broker-runtime-start");
        match self.behavior {
            RuntimeBehavior::WaitForCancellation => {
                while !cancellation.is_cancelled() {
                    thread::park_timeout(Duration::from_millis(1));
                }
                record_event(&self.log.lifecycle, "broker-runtime-cancelled");
                self.log.exits.fetch_add(1, Ordering::SeqCst);
                BrokerConnectionExit::Cancelled
            }
            RuntimeBehavior::ExitWhenSignalled => {
                while !self.log.exit_requested.load(Ordering::SeqCst) {
                    if cancellation.is_cancelled() {
                        record_event(&self.log.lifecycle, "broker-runtime-cancelled");
                        self.log.exits.fetch_add(1, Ordering::SeqCst);
                        return BrokerConnectionExit::Cancelled;
                    }
                    thread::park_timeout(Duration::from_millis(1));
                }
                record_event(&self.log.lifecycle, "broker-runtime-exit");
                self.log.exits.fetch_add(1, Ordering::SeqCst);
                BrokerConnectionExit::EndOfStream
            }
        }
    }
}

impl BrokerRuntimeFactory<TestStream> for RuntimeFactory {
    type Runtime = TestBrokerRuntime;

    fn build(&self, identity: &SessionIdentity) -> Result<Self::Runtime, BackendError> {
        if identity.session_id().as_bytes() != [1; 16]
            || identity.broker_session_id().as_bytes() != [7; 16]
        {
            return Err(BackendError::new(
                "test Broker runtime rejected inexact session identities",
            ));
        }
        self.log.builds.fetch_add(1, Ordering::SeqCst);
        record_event(&self.log.lifecycle, "broker-build");
        Ok(TestBrokerRuntime {
            behavior: self.behavior,
            log: self.log.clone(),
        })
    }
}

type TestBroker = OwnedBrokerBackend<ListenerFactory, RuntimeFactory>;

fn test_broker(log: &BrokerLog, behavior: RuntimeBehavior) -> TestBroker {
    OwnedBrokerBackend::new(
        ListenerFactory {
            log: log.clone(),
            accepted: Arc::new(AtomicBool::new(false)),
        },
        RuntimeFactory {
            behavior,
            log: log.clone(),
        },
        2,
        3,
        9000,
        16,
    )
    .expect("test broker configuration must be valid")
}

struct ObservedBroker {
    inner: TestBroker,
    lifecycle: LifecycleEvents,
}

impl BrokerBackendTrait for ObservedBroker {
    fn establish_broker_session(
        &mut self,
        identity: &SessionIdentity,
    ) -> Result<BrokerLease, BackendError> {
        self.inner.establish_broker_session(identity)
    }

    fn close_broker_session(&mut self, lease: &BrokerLease) -> Result<(), BackendError> {
        self.inner.close_broker_session(lease)?;
        record_event(&self.lifecycle, "broker-joined");
        Ok(())
    }

    fn ensure_broker_session_running(&mut self, lease: &BrokerLease) -> Result<(), BackendError> {
        self.inner.ensure_broker_session_running(lease)?;
        record_event(&self.lifecycle, "broker-ready");
        Ok(())
    }
}

impl BrokerStatusBackend for ObservedBroker {
    fn poll_broker_status(
        &mut self,
        lease: &BrokerLease,
    ) -> Result<BrokerRuntimeStatus, BackendError> {
        let status = BrokerStatusBackend::poll_broker_status(&mut self.inner, lease)?;
        record_event(
            &self.lifecycle,
            match status {
                BrokerRuntimeStatus::Running => "broker-running",
                BrokerRuntimeStatus::Exited => "broker-exited",
            },
        );
        Ok(status)
    }
}

struct ObservedCapability {
    inner: AuthorityCoreBackend,
    lifecycle: LifecycleEvents,
}

impl CapabilityBackend<AuthorityRootGrant> for ObservedCapability {
    fn inject_root_capability(
        &mut self,
        identity: &SessionIdentity,
        grant: &AuthorityRootGrant,
    ) -> Result<CapabilityLease, BackendError> {
        let lease = self.inner.inject_root_capability(identity, grant)?;
        record_event(&self.lifecycle, "capability-injected");
        Ok(lease)
    }
}

impl CapabilityRevocationBackend for ObservedCapability {
    fn revoke_root_capability(&mut self, lease: &CapabilityLease) -> Result<(), BackendError> {
        self.inner.revoke_root_capability(lease)?;
        record_event(&self.lifecycle, "revoke");
        Ok(())
    }
}

/// Waits for a counter that a background thread advances.
///
/// The deadline is deliberately generous. A healthy run leaves this loop as soon as the counter
/// moves, so a wider bound costs a passing test nothing, while a narrow one only adds a way for
/// a loaded machine to fail a correct implementation. Sleeping instead of spinning matters for
/// the same reason: `yield_now` in a tight loop competes for the CPU with the very thread this
/// is waiting for, which is worst exactly when the machine is already busy.
fn wait_for_counter(counter: &AtomicUsize, expected: usize, label: &str) {
    let deadline = Instant::now() + Duration::from_secs(30);
    while counter.load(Ordering::SeqCst) < expected {
        assert!(Instant::now() < deadline, "timed out waiting for {label}");
        thread::sleep(Duration::from_millis(1));
    }
}

fn assert_event_order(events: &LifecycleEvents, expected: &[&'static str]) {
    let events = events
        .lock()
        .expect("lifecycle event log must not be poisoned");
    let mut cursor = 0;
    for expected_event in expected {
        let Some(offset) = events[cursor..]
            .iter()
            .position(|event| event == expected_event)
        else {
            panic!("missing ordered event {expected_event:?} in {events:?}");
        };
        cursor += offset + 1;
    }
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
    assert_eq!(
        fs_log
            .images
            .lock()
            .expect("workspace-image log must not be poisoned")
            .as_slice(),
        [(
            session_jail_root()
                .join("workspace")
                .join(workspace_id.to_string()),
            session_jail_root()
                .join("workspace")
                .join(format!("{workspace_id}.ext4")),
            64 * 1024 * 1024,
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
            PathBuf::from(format!("/workspace/{workspace_id}.ext4")),
            PathBuf::from("/run/vsock.sock"),
            3,
        )]
    );
    assert_eq!(
        fs_log
            .device_binds
            .lock()
            .expect("device-bind log must not be poisoned")
            .as_slice(),
        [(
            PathBuf::from(format!("/dev/mapper/composition-verity-{workspace_id}")),
            session_jail_root().join("dev/rootfs"),
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
    let requests = api.requests.lock().expect("API log must not be poisoned");
    let resume = requests
        .iter()
        .position(|request| request.path == "/vm" && request.body == r#"{"state":"Resumed"}"#)
        .expect("explicit resume request must be present");
    let inject = requests
        .iter()
        .position(|request| request.path == "/actions/inject-identity")
        .expect("identity injection request must be present");
    let start = requests
        .iter()
        .position(|request| request.path == "/actions/start-workload")
        .expect("workload start request must be present");
    assert!(resume < inject && inject < start);
}

fn assert_failed_restore_observations(
    fs_log: &FsLog,
    runner_log: &RunnerLog,
    api: &TestApi,
    broker_log: &BrokerLog,
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
    assert_eq!(broker_log.binds.load(Ordering::SeqCst), 1);
    assert_eq!(broker_log.drops.load(Ordering::SeqCst), 1);
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
            .device_binds
            .lock()
            .expect("device-bind log must not be poisoned")
            .len(),
        1
    );
    assert!(
        fs_log
            .device_unbinds
            .lock()
            .expect("device-unbind log must not be poisoned")
            .is_empty(),
        "a failed process stop must retain the live block-device bind"
    );
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
            image: WorkspaceImageConfig {
                formatter: artifact("/test/mke2fs"),
                size_bytes: 64 * 1024 * 1024,
            },
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

type TestRuntimeFileSystem = FirecrackerFileSystem<TestFileSystem>;
type TestVmBackend =
    FirecrackerVmBackend<TestRunner, TestRuntimeFileSystem, TestApi, TestApi, UnusedIdentitySource>;
type TestWorkloadBackend = FirecrackerWorkloadBackend<
    TestRunner,
    TestRuntimeFileSystem,
    TestApi,
    TestApi,
    UnusedIdentitySource,
>;

struct AdapterStack {
    template: WorkspaceTemplateId,
    workspace: FirecrackerWorkspaceBackend<TestFileSystem>,
    vm: TestVmBackend,
    workload: TestWorkloadBackend,
    fs_log: FsLog,
    runner_log: RunnerLog,
    api: TestApi,
}

fn adapter_stack(lifecycle: &LifecycleEvents, snapshot_id: SnapshotId) -> AdapterStack {
    let fs_log = FsLog {
        lifecycle: Arc::clone(lifecycle),
        ..FsLog::default()
    };
    let template = WorkspaceTemplateId::new("template");
    let (workspace, runtime_filesystem) = new_firecracker_workspace_adapters(
        TestFileSystem {
            log: fs_log.clone(),
        },
        template.clone(),
        "/test/source",
        "/test/jailer/firecracker",
    );
    let api = TestApi {
        lifecycle: Arc::clone(lifecycle),
        ..TestApi::default()
    };
    let runner_log = RunnerLog {
        lifecycle: Arc::clone(lifecycle),
        ..RunnerLog::default()
    };
    let config = runtime_config();
    let runtime = Runtime::new(
        TestRunner {
            log: runner_log.clone(),
            ..TestRunner::default()
        },
        runtime_filesystem,
        api.clone(),
        api.clone(),
        UnusedIdentitySource,
    );
    let snapshot = snapshot(&config);
    let (vm, workload) =
        FirecrackerBackendFactory::new(runtime, config, snapshot, snapshot_id).into_handles();
    AdapterStack {
        template,
        workspace,
        vm,
        workload,
        fs_log,
        runner_log,
        api,
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
fn production_owner_keeps_worker_live_then_cancels_joins_and_closes() {
    let lifecycle = LifecycleEvents::default();
    let snapshot_id = SnapshotId::new([0x90; 16]);
    let stack = adapter_stack(&lifecycle, snapshot_id);
    let fs_log = stack.fs_log.clone();
    let api_observer = stack.api.clone();
    let runner_log = stack.runner_log.clone();

    let broker_log = BrokerLog {
        lifecycle: Arc::clone(&lifecycle),
        ..BrokerLog::default()
    };
    let broker = ObservedBroker {
        inner: test_broker(&broker_log, RuntimeBehavior::WaitForCancellation),
        lifecycle: Arc::clone(&lifecycle),
    };
    let kernel = Arc::new(CapabilityKernel::new(CapabilityState::new(IssuerId::new(
        "host",
    ))));
    let capability = ObservedCapability {
        inner: AuthorityCoreBackend::new(Arc::clone(&kernel)),
        lifecycle: Arc::clone(&lifecycle),
    };
    let orchestrator = SessionOrchestrator::new(SequenceRandom {
        values: (1_u8..=7).map(|byte| [byte; 16]).collect(),
    });
    let mut owner = SessionOwner::new(
        orchestrator,
        SessionBackends::new(
            stack.workspace,
            broker,
            stack.vm,
            capability,
            stack.workload,
        ),
    );
    let descriptor = SnapshotDescriptor::clean(snapshot_id);

    let info = owner
        .start(&descriptor, &stack.template, &authority_grant())
        .expect("all production adapters must compose");
    let identity = info.identity();
    wait_for_counter(&broker_log.starts, 1, "Broker runtime start");
    assert_eq!(broker_log.binds.load(Ordering::SeqCst), 1);
    assert_eq!(broker_log.builds.load(Ordering::SeqCst), 1);
    assert_eq!(broker_log.drops.load(Ordering::SeqCst), 0);
    assert_eq!(identity.workspace_id(), expected_workspace_id());
    assert_successful_restore_observations(
        &fs_log,
        &runner_log,
        &api_observer,
        identity.workspace_id(),
    );
    assert_eq!(
        owner.poll(OwnerPollRequest::Continue),
        Ok(OwnerPollOutcome::Running(info))
    );

    assert_eq!(
        owner.stop().expect("composed cleanup must complete"),
        OwnerPollOutcome::Closed(ShutdownReason::ExternalRequest)
    );

    assert_eq!(owner.state(), LifecycleState::Closed);
    assert_eq!(broker_log.drops.load(Ordering::SeqCst), 1);
    assert_eq!(broker_log.shutdowns.load(Ordering::SeqCst), 1);
    assert_eq!(broker_log.exits.load(Ordering::SeqCst), 1);
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
    assert_event_order(
        &lifecycle,
        &[
            "broker-build",
            "capability-injected",
            "broker-ready",
            "workload-release",
            "broker-running",
            "revoke",
            "kill",
            "broker-stream-shutdown",
            "broker-worker-exit",
            "broker-joined",
            "isolate",
        ],
    );
}

#[test]
fn unexpected_owned_broker_exit_drives_ordered_production_cleanup() {
    let lifecycle = LifecycleEvents::default();
    let snapshot_id = SnapshotId::new([0x92; 16]);
    let stack = adapter_stack(&lifecycle, snapshot_id);
    let fs_log = stack.fs_log.clone();
    let runner_log = stack.runner_log.clone();
    let api_observer = stack.api.clone();
    let broker_log = BrokerLog {
        lifecycle: Arc::clone(&lifecycle),
        ..BrokerLog::default()
    };
    let broker = ObservedBroker {
        inner: test_broker(&broker_log, RuntimeBehavior::ExitWhenSignalled),
        lifecycle: Arc::clone(&lifecycle),
    };
    let kernel = Arc::new(CapabilityKernel::new(CapabilityState::new(IssuerId::new(
        "host",
    ))));
    let capability = ObservedCapability {
        inner: AuthorityCoreBackend::new(Arc::clone(&kernel)),
        lifecycle: Arc::clone(&lifecycle),
    };
    let orchestrator = SessionOrchestrator::new(SequenceRandom {
        values: (1_u8..=7).map(|byte| [byte; 16]).collect(),
    });
    let mut owner = SessionOwner::new(
        orchestrator,
        SessionBackends::new(
            stack.workspace,
            broker,
            stack.vm,
            capability,
            stack.workload,
        ),
    );

    let info = owner
        .start(
            &SnapshotDescriptor::clean(snapshot_id),
            &stack.template,
            &authority_grant(),
        )
        .expect("production composition must start before Broker exit is observed");
    broker_log.exit_requested.store(true, Ordering::SeqCst);
    wait_for_counter(&broker_log.exits, 1, "unexpected Broker exit");
    assert_successful_restore_observations(
        &fs_log,
        &runner_log,
        &api_observer,
        info.identity().workspace_id(),
    );

    assert_eq!(
        owner.poll(OwnerPollRequest::Continue),
        Ok(OwnerPollOutcome::Closed(ShutdownReason::BrokerExited))
    );
    assert_eq!(owner.state(), LifecycleState::Closed);
    assert_eq!(broker_log.binds.load(Ordering::SeqCst), 1);
    assert_eq!(broker_log.builds.load(Ordering::SeqCst), 1);
    assert_eq!(broker_log.starts.load(Ordering::SeqCst), 1);
    assert_eq!(broker_log.drops.load(Ordering::SeqCst), 1);
    assert_eq!(broker_log.shutdowns.load(Ordering::SeqCst), 1);
    assert_subject_closed(&kernel, info.identity().subject_id());
    assert_workspace_removals(
        &fs_log,
        &[session_jail_root()
            .join("workspace")
            .join(info.identity().workspace_id().to_string())],
    );
    assert_event_order(
        &lifecycle,
        &[
            "capability-injected",
            "broker-ready",
            "workload-release",
            "broker-runtime-exit",
            "broker-exited",
            "revoke",
            "kill",
            "broker-stream-shutdown",
            "broker-joined",
            "isolate",
        ],
    );
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

    let broker_log = BrokerLog::default();
    let mut broker = test_broker(&broker_log, RuntimeBehavior::WaitForCancellation);
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
    assert_failed_restore_observations(&fs_log, &runner_log, &api_observer, &broker_log);
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
