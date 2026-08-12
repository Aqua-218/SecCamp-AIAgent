//! Shared Firecracker adapters for the session VM and workload backend traits.
//!
//! The two adapters deliberately share one mutex-protected runtime because the
//! runtime owns both the VM process and the guest control channel. Keeping the
//! lease, configuration, and runtime instance in one state record prevents a
//! VM handle and a workload handle from observing different lifecycle points.

use std::sync::{Arc, Mutex, MutexGuard};

use firecracker_runtime::{
    ApiClient, CommandRunner, FileSystem, IdentitySource, Runtime, RuntimeConfig, RuntimeError,
    RuntimeInstance, RuntimeState, Snapshot,
};

use crate::firecracker_identity::to_firecracker_identity_bundle;
use crate::{
    BackendError, BrokerLease, CapabilityLease, SessionIdentity, SnapshotDescriptor, SnapshotId,
    VmBackend, VmLease, WorkloadBackend, WorkloadLease, WorkspaceLease,
};

type SharedState<C, F, A, G, I> = Arc<Mutex<BackendState<C, F, A, G, I>>>;
type StateGuard<'a, C, F, A, G, I> = MutexGuard<'a, BackendState<C, F, A, G, I>>;

/// VM and workload handles backed by one shared Firecracker runtime.
pub type FirecrackerBackends<C, F, A, G, I> = (
    FirecrackerVmBackend<C, F, A, G, I>,
    FirecrackerWorkloadBackend<C, F, A, G, I>,
);

struct BackendState<C, F, A, G, I> {
    runtime: Runtime<C, F, A, G, I>,
    base_config: RuntimeConfig,
    snapshot: Snapshot,
    snapshot_id: SnapshotId,
    active: Option<ActiveVm>,
    last_closed: Option<VmLease>,
}

struct ActiveVm {
    identity: SessionIdentity,
    lease: VmLease,
    config: RuntimeConfig,
    instance: RuntimeInstance,
}

/// A factory that creates VM and workload adapters sharing one runtime state.
pub struct FirecrackerBackendFactory<C, F, A, G, I>
where
    C: CommandRunner,
    F: FileSystem,
    A: ApiClient,
    G: ApiClient,
    I: IdentitySource,
{
    shared: SharedState<C, F, A, G, I>,
}

impl<C, F, A, G, I> FirecrackerBackendFactory<C, F, A, G, I>
where
    C: CommandRunner,
    F: FileSystem,
    A: ApiClient,
    G: ApiClient,
    I: IdentitySource,
{
    /// Creates a factory around one runtime, immutable base configuration, and snapshot.
    #[must_use]
    pub fn new(
        runtime: Runtime<C, F, A, G, I>,
        base_config: RuntimeConfig,
        snapshot: Snapshot,
        snapshot_id: SnapshotId,
    ) -> Self {
        Self {
            shared: Arc::new(Mutex::new(BackendState {
                runtime,
                base_config,
                snapshot,
                snapshot_id,
                active: None,
                last_closed: None,
            })),
        }
    }

    /// Returns separate VM and workload handles backed by the same state mutex.
    #[must_use]
    pub fn into_handles(self) -> FirecrackerBackends<C, F, A, G, I> {
        let shared = self.shared;
        (
            FirecrackerVmBackend {
                shared: Arc::clone(&shared),
            },
            FirecrackerWorkloadBackend { shared },
        )
    }
}

/// Creates separate VM and workload adapters over one Firecracker runtime.
#[must_use]
pub fn new_firecracker_backends<C, F, A, G, I>(
    runtime: Runtime<C, F, A, G, I>,
    base_config: RuntimeConfig,
    snapshot: Snapshot,
    snapshot_id: SnapshotId,
) -> FirecrackerBackends<C, F, A, G, I>
where
    C: CommandRunner,
    F: FileSystem,
    A: ApiClient,
    G: ApiClient,
    I: IdentitySource,
{
    FirecrackerBackendFactory::new(runtime, base_config, snapshot, snapshot_id).into_handles()
}

/// VM lifecycle adapter backed by the shared Firecracker runtime.
pub struct FirecrackerVmBackend<C, F, A, G, I>
where
    C: CommandRunner,
    F: FileSystem,
    A: ApiClient,
    G: ApiClient,
    I: IdentitySource,
{
    shared: SharedState<C, F, A, G, I>,
}

impl<C, F, A, G, I> VmBackend for FirecrackerVmBackend<C, F, A, G, I>
where
    C: CommandRunner,
    F: FileSystem,
    A: ApiClient,
    G: ApiClient,
    I: IdentitySource,
{
    fn start_vm(
        &mut self,
        snapshot: &SnapshotDescriptor,
        identity: &SessionIdentity,
        workspace: &WorkspaceLease,
        broker: &BrokerLease,
    ) -> Result<VmLease, BackendError> {
        let mut state = lock_state(&self.shared)?;
        if state.active.is_some() {
            return Err(BackendError::new(
                "Firecracker VM backend already has an active VM",
            ));
        }
        state
            .runtime
            .retry_pending_cleanup()
            .map_err(|error| runtime_failure("pending startup cleanup", &error))?;
        if snapshot.snapshot_id() != state.snapshot_id {
            return Err(BackendError::new(
                "snapshot descriptor does not match the configured Firecracker snapshot",
            ));
        }
        verify_workspace_binding(identity, workspace)?;
        verify_broker_binding(identity, broker)?;

        let bundle = to_firecracker_identity_bundle(identity)
            .map_err(|error| runtime_failure("identity conversion", &error))?;
        let mut config = state.base_config.clone();
        let snapshot = state.snapshot.clone();
        config.workspace.clone_id = identity.workspace_id().to_string();
        let instance = state
            .runtime
            .restore_with_identities(&config, &snapshot, bundle)
            .map_err(|error| runtime_failure("snapshot restore", &error))?;
        if instance.state() != RuntimeState::IdentityRegenerated {
            let mut instance = instance;
            let cleanup = state.runtime.shutdown(&mut instance, &config);
            return Err(BackendError::new(format!(
                "Firecracker restore returned unexpected state {:?}; cleanup result: {cleanup:?}",
                instance.state(),
            )));
        }

        let lease = VmLease::new(
            identity.session_id(),
            identity.vm_id(),
            identity.workspace_id(),
            identity.broker_session_id(),
        );
        state.active = Some(ActiveVm {
            identity: *identity,
            lease: lease.clone(),
            config,
            instance,
        });
        state.last_closed = None;
        Ok(lease)
    }

    fn cleanup_failed_start(&mut self) -> Result<(), BackendError> {
        let mut state = lock_state(&self.shared)?;
        if state.active.is_some() {
            return Err(BackendError::new(
                "cannot clean up a failed Firecracker start while a VM is active",
            ));
        }
        state
            .runtime
            .retry_pending_cleanup()
            .map_err(|error| runtime_failure("failed startup cleanup", &error))
    }

    fn kill_vm(&mut self, lease: &VmLease) -> Result<(), BackendError> {
        let mut state = lock_state(&self.shared)?;
        let Some(active_lease) = state.active.as_ref().map(|active| active.lease.clone()) else {
            return match state.last_closed.as_ref() {
                Some(last_closed) if last_closed == lease => Ok(()),
                _ => Err(BackendError::new(
                    "unknown or mismatched Firecracker VM lease",
                )),
            };
        };
        if active_lease != *lease {
            return Err(BackendError::new(
                "Firecracker VM lease does not match the active VM",
            ));
        }

        let BackendState {
            runtime, active, ..
        } = &mut *state;
        let active = active.as_mut().expect("active VM was checked above");
        runtime
            .shutdown(&mut active.instance, &active.config)
            .map_err(|error| runtime_failure("VM shutdown", &error))?;
        let closed_lease = active.lease.clone();
        state.active = None;
        state.last_closed = Some(closed_lease);
        Ok(())
    }
}

/// Workload lifecycle adapter backed by the shared Firecracker runtime.
pub struct FirecrackerWorkloadBackend<C, F, A, G, I>
where
    C: CommandRunner,
    F: FileSystem,
    A: ApiClient,
    G: ApiClient,
    I: IdentitySource,
{
    shared: SharedState<C, F, A, G, I>,
}

impl<C, F, A, G, I> WorkloadBackend for FirecrackerWorkloadBackend<C, F, A, G, I>
where
    C: CommandRunner,
    F: FileSystem,
    A: ApiClient,
    G: ApiClient,
    I: IdentitySource,
{
    fn release_workload(
        &mut self,
        identity: &SessionIdentity,
        vm: &VmLease,
        capability: &CapabilityLease,
    ) -> Result<WorkloadLease, BackendError> {
        let mut state = lock_state(&self.shared)?;
        let active = state.active.as_ref().ok_or_else(|| {
            BackendError::new("cannot release a workload without an active Firecracker VM")
        })?;
        if active.identity != *identity {
            return Err(BackendError::new(
                "session identity does not match the active Firecracker VM",
            ));
        }
        if active.lease != *vm {
            return Err(BackendError::new(
                "VM lease does not match the active Firecracker VM",
            ));
        }
        let expected_capability = CapabilityLease::new(
            identity.session_id(),
            identity.subject_id(),
            identity.capability_id(),
        );
        if *capability != expected_capability {
            return Err(BackendError::new(
                "capability lease does not match the active session identity",
            ));
        }
        let bundle = to_firecracker_identity_bundle(identity)
            .map_err(|error| runtime_failure("identity conversion", &error))?;
        if active.instance.identities() != Some(&bundle) {
            return Err(BackendError::new(
                "runtime identities do not match the exact session identity bundle",
            ));
        }
        let BackendState {
            runtime, active, ..
        } = &mut *state;
        let active = active.as_mut().expect("active VM was checked above");
        runtime
            .inject_identity(&mut active.instance)
            .map_err(|error| runtime_failure("identity injection", &error))?;
        runtime
            .start_workload(&mut active.instance)
            .map_err(|error| runtime_failure("workload start", &error))?;

        let lease = WorkloadLease::new(
            identity.session_id(),
            identity.vm_id(),
            identity.subject_id(),
            identity.capability_id(),
        );
        Ok(lease)
    }
}

fn lock_state<C, F, A, G, I>(
    shared: &SharedState<C, F, A, G, I>,
) -> Result<StateGuard<'_, C, F, A, G, I>, BackendError> {
    shared
        .lock()
        .map_err(|_| BackendError::new("Firecracker backend state mutex is poisoned"))
}

fn verify_workspace_binding(
    identity: &SessionIdentity,
    workspace: &WorkspaceLease,
) -> Result<(), BackendError> {
    if workspace.session_id() != identity.session_id()
        || workspace.workspace_id() != identity.workspace_id()
    {
        return Err(BackendError::new(
            "workspace lease does not match the exact session identity",
        ));
    }
    Ok(())
}

fn verify_broker_binding(
    identity: &SessionIdentity,
    broker: &BrokerLease,
) -> Result<(), BackendError> {
    if broker.session_id() != identity.session_id()
        || broker.broker_session_id() != identity.broker_session_id()
    {
        return Err(BackendError::new(
            "Broker lease does not match the exact session identity",
        ));
    }
    Ok(())
}

fn runtime_failure(operation: &str, error: &RuntimeError) -> BackendError {
    BackendError::new(format!("Firecracker {operation} failed: {error}"))
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::path::{Path, PathBuf};

    use firecracker_runtime::{
        ApiRequest, ApiResponse, CommandOutput, CommandSpec, DmVerityConfig, HostIsolationConfig,
        IdentityId, NamespaceConfig, PinnedArtifact, ProcessHandle, Runtime, SeccompConfig,
        Sha256Digest, VsockConfig, WorkspaceConfig, sha256,
    };

    use super::*;
    use crate::{
        BrokerSessionId, CapabilityId, RequestId, SessionId, SnapshotDescriptor, SnapshotId,
        SubjectId, VmId, WorkspaceId,
    };

    #[derive(Default)]
    struct TestRunner {
        next_pid: u32,
        stop_failures: VecDeque<bool>,
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
            if self.stop_failures.pop_front().unwrap_or(false) {
                return Err(RuntimeError::Command("test stop failure".to_owned()));
            }
            Ok(())
        }
    }

    #[derive(Clone, Default)]
    struct TestFileSystem {
        clones: Arc<Mutex<Vec<PathBuf>>>,
    }

    impl FileSystem for TestFileSystem {
        fn read(&mut self, _path: &Path) -> Result<Vec<u8>, RuntimeError> {
            Ok(Vec::new())
        }

        fn clone_workspace(
            &mut self,
            _source: &Path,
            destination: &Path,
        ) -> Result<(), RuntimeError> {
            self.clones
                .lock()
                .expect("test filesystem mutex must not be poisoned")
                .push(destination.to_owned());
            Ok(())
        }

        fn remove_workspace(&mut self, _path: &Path) -> Result<(), RuntimeError> {
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
                .expect("test API mutex must not be poisoned")
                .push(request.clone());
            if self
                .failures
                .lock()
                .expect("test API failure mutex must not be poisoned")
                .pop_front()
                .unwrap_or(false)
            {
                return Err(RuntimeError::Api("test API failure".to_owned()));
            }
            Ok(ApiResponse {
                status: 200,
                body: String::new(),
            })
        }
    }

    struct TestIdentitySource;

    impl IdentitySource for TestIdentitySource {
        fn generate(&mut self) -> Result<IdentityId, RuntimeError> {
            Err(RuntimeError::InvalidIdentity(
                "restore must use the supplied identity bundle".to_owned(),
            ))
        }
    }

    type TestVmBackend =
        FirecrackerVmBackend<TestRunner, TestFileSystem, TestApi, TestApi, TestIdentitySource>;
    type TestWorkloadBackend = FirecrackerWorkloadBackend<
        TestRunner,
        TestFileSystem,
        TestApi,
        TestApi,
        TestIdentitySource,
    >;
    type TestBackends = (
        TestVmBackend,
        TestWorkloadBackend,
        SessionIdentity,
        Arc<Mutex<Vec<ApiRequest>>>,
        Arc<Mutex<Vec<PathBuf>>>,
    );

    fn artifact(path: &str) -> PinnedArtifact {
        PinnedArtifact::new(path, sha256(&[]))
    }

    fn test_config() -> RuntimeConfig {
        let rootfs = artifact("/test/rootfs");
        RuntimeConfig {
            firecracker: artifact("/test/firecracker"),
            kernel: artifact("/test/kernel"),
            rootfs: rootfs.clone(),
            verity_hash: artifact("/test/verity"),
            dm_verity: DmVerityConfig {
                data_device: rootfs.path.clone(),
                hash_device: PathBuf::from("/test/verity"),
                mapper_name: "test-verity".to_owned(),
                root_hash: sha256(b"test root hash"),
            },
            workspace: WorkspaceConfig {
                source: PathBuf::from("/test/source"),
                clone_root: PathBuf::from("/test/clones"),
                clone_id: "base".to_owned(),
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
                cgroup: firecracker_runtime::CgroupConfig {
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
            memory_mib: 1,
            boot_args: "console=ttyS0".to_owned(),
        }
    }

    fn config_fingerprint(config: &RuntimeConfig) -> Sha256Digest {
        let mut bytes = Vec::new();
        for artifact in [
            &config.firecracker,
            &config.kernel,
            &config.rootfs,
            &config.verity_hash,
            &config.jailer,
            &config.isolation.seccomp.filter,
        ] {
            bytes.extend_from_slice(&artifact.digest.as_bytes());
        }
        bytes.extend_from_slice(&config.dm_verity.root_hash.as_bytes());
        bytes.extend_from_slice(&config.vsock.guest_cid.to_be_bytes());
        sha256(&bytes)
    }

    fn test_identity() -> SessionIdentity {
        SessionIdentity {
            session_id: SessionId::new([1; crate::ID_BYTES]),
            request_id: RequestId::new([2; crate::ID_BYTES]),
            vm_id: VmId::new([3; crate::ID_BYTES]),
            subject_id: SubjectId::new([4; crate::ID_BYTES]),
            workspace_id: WorkspaceId::new([5; crate::ID_BYTES]),
            broker_session_id: BrokerSessionId::new([6; crate::ID_BYTES]),
            capability_id: CapabilityId::new([7; crate::ID_BYTES]),
        }
    }

    fn test_backends(stop_failures: impl IntoIterator<Item = bool>) -> TestBackends {
        test_backends_with_failures(stop_failures, [])
    }

    fn test_backends_with_failures(
        stop_failures: impl IntoIterator<Item = bool>,
        api_failures: impl IntoIterator<Item = bool>,
    ) -> TestBackends {
        let config = test_config();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let failures = Arc::new(Mutex::new(api_failures.into_iter().collect()));
        let clones = Arc::new(Mutex::new(Vec::new()));
        let runtime = Runtime::new(
            TestRunner {
                next_pid: 0,
                stop_failures: stop_failures.into_iter().collect(),
            },
            TestFileSystem {
                clones: Arc::clone(&clones),
            },
            TestApi {
                requests: Arc::clone(&requests),
                failures: Arc::clone(&failures),
            },
            TestApi {
                requests: Arc::clone(&requests),
                failures,
            },
            TestIdentitySource,
        );
        let snapshot = Snapshot::new(
            "/test/snapshot",
            "/test/memory",
            config_fingerprint(&config),
            Vec::new(),
        );
        let (vm, workload) = FirecrackerBackendFactory::new(
            runtime,
            config,
            snapshot,
            SnapshotId::new([9; crate::ID_BYTES]),
        )
        .into_handles();
        (vm, workload, test_identity(), requests, clones)
    }

    fn snapshot_descriptor() -> SnapshotDescriptor {
        SnapshotDescriptor::clean(SnapshotId::new([9; crate::ID_BYTES]))
    }

    #[test]
    fn injects_the_exact_host_identity_bundle_before_workload_start() {
        let (mut vm, mut workload, identity, requests, clones) = test_backends([]);
        let workspace = WorkspaceLease::new(identity.session_id(), identity.workspace_id());
        let broker = BrokerLease::new(identity.session_id(), identity.broker_session_id());
        let vm_lease = vm
            .start_vm(&snapshot_descriptor(), &identity, &workspace, &broker)
            .expect("VM restore should succeed");
        let capability = CapabilityLease::new(
            identity.session_id(),
            identity.subject_id(),
            identity.capability_id(),
        );

        let workload_lease = workload
            .release_workload(&identity, &vm_lease, &capability)
            .expect("workload release should succeed");
        assert_eq!(
            workload_lease,
            WorkloadLease::new(
                identity.session_id(),
                identity.vm_id(),
                identity.subject_id(),
                identity.capability_id(),
            )
        );
        assert_eq!(
            clones
                .lock()
                .expect("test filesystem mutex must not be poisoned")
                .as_slice(),
            [PathBuf::from(
                "/test/clones/05050505050505050505050505050505"
            )]
        );

        let bundle = to_firecracker_identity_bundle(&identity).expect("identity should convert");
        let requests = requests
            .lock()
            .expect("test API mutex must not be poisoned");
        let injection = requests
            .iter()
            .find(|request| request.path == "/actions/inject-identity")
            .expect("identity injection request should be sent");
        assert_eq!(
            injection.body,
            format!(
                "{{\"vm_id\":\"{}\",\"session_id\":\"{}\",\"request_id\":\"{}\",\"subject_id\":\"{}\",\"capability_id\":\"{}\"}}",
                bundle.vm_id.to_hex(),
                bundle.session_id.to_hex(),
                bundle.request_id.to_hex(),
                bundle.subject_id.to_hex(),
                bundle.capability_id.to_hex(),
            )
        );
        assert!(
            requests
                .iter()
                .position(|request| request.path == "/actions/inject-identity")
                < requests
                    .iter()
                    .position(|request| request.path == "/actions/start-workload")
        );
    }

    #[test]
    fn rejects_a_different_snapshot_identity_before_runtime_effects() {
        let (mut vm, _workload, identity, requests, clones) = test_backends([]);
        let workspace = WorkspaceLease::new(identity.session_id(), identity.workspace_id());
        let broker = BrokerLease::new(identity.session_id(), identity.broker_session_id());
        let foreign = SnapshotDescriptor::clean(SnapshotId::new([10; crate::ID_BYTES]));

        assert!(
            vm.start_vm(&foreign, &identity, &workspace, &broker)
                .is_err()
        );
        assert!(
            requests
                .lock()
                .expect("test API mutex must not be poisoned")
                .is_empty()
        );
        assert!(
            clones
                .lock()
                .expect("test filesystem mutex must not be poisoned")
                .is_empty()
        );
    }

    #[test]
    fn retains_a_failed_shutdown_for_exact_retry_and_only_closes_that_lease() {
        let (mut vm, _workload, identity, _requests, _clones) = test_backends([true, false]);
        let workspace = WorkspaceLease::new(identity.session_id(), identity.workspace_id());
        let broker = BrokerLease::new(identity.session_id(), identity.broker_session_id());
        let lease = vm
            .start_vm(&snapshot_descriptor(), &identity, &workspace, &broker)
            .expect("VM restore should succeed");

        assert!(vm.kill_vm(&lease).is_err());
        assert!(vm.kill_vm(&lease).is_ok());
        assert!(vm.kill_vm(&lease).is_ok());

        let unknown = VmLease::new(
            identity.session_id(),
            VmId::new([8; crate::ID_BYTES]),
            identity.workspace_id(),
            identity.broker_session_id(),
        );
        assert!(vm.kill_vm(&unknown).is_err());
    }

    #[test]
    fn failed_start_cleanup_retries_runtime_rollback_before_reporting_success() {
        let (mut vm, _workload, identity, _requests, _clones) =
            test_backends_with_failures([true, true, false], [true]);
        let workspace = WorkspaceLease::new(identity.session_id(), identity.workspace_id());
        let broker = BrokerLease::new(identity.session_id(), identity.broker_session_id());

        assert!(
            vm.start_vm(&snapshot_descriptor(), &identity, &workspace, &broker)
                .is_err()
        );
        assert!(vm.cleanup_failed_start().is_err());
        assert!(vm.cleanup_failed_start().is_ok());
        assert!(
            vm.start_vm(&snapshot_descriptor(), &identity, &workspace, &broker)
                .is_ok()
        );
    }

    #[test]
    fn start_vm_drains_retained_runtime_cleanup_before_a_new_restore() {
        let (mut vm, _workload, identity, _requests, _clones) =
            test_backends_with_failures([true, false], [true]);
        let workspace = WorkspaceLease::new(identity.session_id(), identity.workspace_id());
        let broker = BrokerLease::new(identity.session_id(), identity.broker_session_id());

        assert!(
            vm.start_vm(&snapshot_descriptor(), &identity, &workspace, &broker)
                .is_err()
        );
        assert!(
            vm.start_vm(&snapshot_descriptor(), &identity, &workspace, &broker)
                .is_ok()
        );
    }
}
