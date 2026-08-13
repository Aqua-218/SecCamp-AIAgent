//! Opt-in real Firecracker and `AF_VSOCK` test for the guest identity gate.
//!
//! Run through `scripts/ci/verify-real-guest-control.sh`, which builds a static guest init and
//! a fresh dm-verity rootfs before enabling this ignored test. The test intentionally uses direct
//! Firecracker API setup: it verifies the actual VM/vsock/guest boundary separately from the
//! higher-level jailer and snapshot lifecycle.

use std::{
    env,
    fs::File,
    num::{NonZeroU64, NonZeroUsize},
    os::unix::{fs::FileTypeExt, net::UnixListener},
    path::Path,
    process::{Child, Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use authority_core::{
    capability::{CapId, IssuerId, SubjectId},
    github::{GitHubAuthority, GitHubRequest},
    http::{HttpFetchAuthority, HttpFetchRequest},
    kernel::CapabilityKernel,
    state::CapabilityState,
    time::MonotonicTime,
};
use egress_broker::{
    dispatch::{
        BrokerDispatcher, DispatchContext, PublicDispatchAdapter, default_github_response_cap,
    },
    github::{GitHubAdapter, GitHubAdapterError, GitHubResponse},
    public_fetch::{FetchError, PublicResponse},
    server::{ConnectionCloseReason, ConnectionReport, serve_connection},
};
use egress_protocol::{budget::SessionBudgetLimits, session::BrokerSessionId};
use firecracker_runtime::{
    ApiClient, ApiRequest, FirecrackerVsockApiClient, HttpMethod, IdentityBundle, IdentityId,
    RuntimeError, UnixApiClient, firecracker_guest_port_path,
    guest_control::{GuestControlAction, GuestControlRequest},
};
use tempfile::TempDir;

const GUEST_CID: u32 = 42;
const GUEST_CONTROL_PORT: u32 = 18_080;
const GUEST_BROKER_PORT: u32 = 18_081;
const API_WAIT: Duration = Duration::from_secs(5);

#[derive(Clone, Copy)]
enum GuestWorkload {
    Sleep,
    BrokerProbe,
    RuntimeBrokerProbe,
}

impl GuestWorkload {
    const fn arguments(self) -> &'static str {
        match self {
            Self::Sleep => "sleep 600",
            Self::BrokerProbe => "--port 18081",
            Self::RuntimeBrokerProbe => {
                "-- --workspace-device /dev/vdb --runtime-dir /run/guest-supervisor --cgroup-parent /sys/fs/cgroup --broker-port 18081 --isolation-launcher /usr/local/libexec/workload-isolation-launcher --workload /usr/local/libexec/agent-workload --repository workspace --file-effects read-data,list-directory,write-data --path-prefix /"
            }
        }
    }
}

struct RealFirecracker {
    process: Child,
    directory: TempDir,
    api_socket: std::path::PathBuf,
    serial_log: std::path::PathBuf,
}

impl RealFirecracker {
    fn start(firecracker: &Path) -> Self {
        let directory = tempfile::tempdir().expect("real VM temporary directory must be created");
        let api_socket = directory.path().join("api.sock");
        let log = directory.path().join("firecracker.log");
        let serial_log = directory.path().join("guest-serial.log");
        let process = Command::new(firecracker)
            .arg("--api-sock")
            .arg(&api_socket)
            .arg("--log-path")
            .arg(log)
            .stdin(Stdio::null())
            .stdout(Stdio::from(
                File::create(&serial_log).expect("guest serial log must be creatable"),
            ))
            .stderr(Stdio::null())
            .spawn()
            .expect("real Firecracker must start");
        let deadline = Instant::now() + API_WAIT;
        while !api_socket.exists() {
            assert!(
                Instant::now() < deadline,
                "real Firecracker did not create its API socket before timeout"
            );
            thread::sleep(Duration::from_millis(10));
        }
        Self {
            process,
            directory,
            api_socket,
            serial_log,
        }
    }

    fn api_socket(&self) -> &Path {
        &self.api_socket
    }

    fn vsock_socket(&self) -> std::path::PathBuf {
        self.directory.path().join("vsock.sock")
    }

    fn guest_serial_log(&self) -> String {
        std::fs::read_to_string(&self.serial_log)
            .unwrap_or_else(|error| format!("could not read guest serial log: {error}"))
    }
}

impl Drop for RealFirecracker {
    fn drop(&mut self) {
        let _ = self.process.kill();
        let _ = self.process.wait();
    }
}

fn put(client: &mut UnixApiClient, path: &str, body: String) {
    let response = client
        .request(&ApiRequest {
            method: HttpMethod::Put,
            path: path.to_owned(),
            body,
        })
        .expect("real Firecracker API request must receive a response");
    assert!(
        (200..300).contains(&response.status),
        "Firecracker {path} returned {}: {}",
        response.status,
        response.body
    );
}

fn identity(value: u8) -> IdentityId {
    IdentityId::from_hex(&format!("{value:032x}")).expect("test identity must be valid")
}

fn guest_request() -> GuestControlRequest {
    GuestControlRequest::new(
        identity(1),
        IdentityBundle::new(
            identity(2),
            identity(3),
            identity(4),
            identity(5),
            identity(6),
        )
        .expect("test bundle identities must be distinct"),
    )
    .expect("test challenge must be independent")
}

fn required_path(variable: &str) -> std::path::PathBuf {
    let value = env::var_os(variable).unwrap_or_else(|| panic!("{variable} must be set"));
    let path = std::path::PathBuf::from(value);
    let metadata = std::fs::metadata(&path)
        .unwrap_or_else(|error| panic!("{variable} must name a readable host artifact: {error}"));
    assert!(
        path.is_absolute() && (metadata.is_file() || metadata.file_type().is_block_device()),
        "{variable} must name a regular file or a dm-verity block device"
    );
    path
}

fn wait_for_guest_vsock(vsock: &Path) {
    let deadline = Instant::now() + API_WAIT;
    loop {
        let client = FirecrackerVsockApiClient::new(vsock, GUEST_CID, GUEST_CONTROL_PORT)
            .expect("test guest endpoint must be valid");
        let mut client = client
            .with_timeout(Duration::from_millis(200))
            .expect("test endpoint timeout must be valid");
        let request = guest_request();
        match client.request(&ApiRequest {
            method: HttpMethod::Put,
            path: GuestControlAction::StartWorkload.path().to_owned(),
            body: request.canonical_body(),
        }) {
            Ok(response) if response.status == 409 => return,
            Err(RuntimeError::Io(_) | RuntimeError::Api(_)) if Instant::now() < deadline => {
                thread::sleep(Duration::from_millis(20));
            }
            other => panic!("guest control did not reject pre-injection workload start: {other:?}"),
        }
    }
}

fn configure_and_start_real_vm(
    api: &mut UnixApiClient,
    vm: &RealFirecracker,
    kernel: &Path,
    rootfs: &Path,
    workload: GuestWorkload,
    workspace: Option<&Path>,
) {
    put(
        api,
        "/machine-config",
        r#"{"vcpu_count":1,"mem_size_mib":256}"#.to_owned(),
    );
    put(
        api,
        "/boot-source",
        format!(
            r#"{{"kernel_image_path":"{}","boot_args":"console=ttyS0 reboot=k panic=1 pci=off root=/dev/vda rootfstype=squashfs ro init=/usr/local/libexec/guest-control-init -- --port {GUEST_CONTROL_PORT} --workload /usr/local/libexec/guest-workload {}"}}"#,
            kernel.display(),
            workload.arguments(),
        ),
    );
    put(
        api,
        "/drives/rootfs",
        format!(
            r#"{{"drive_id":"rootfs","path_on_host":"{}","is_root_device":true,"is_read_only":true}}"#,
            rootfs.display()
        ),
    );
    if let Some(workspace) = workspace {
        put(
            api,
            "/drives/workspace",
            format!(
                r#"{{"drive_id":"workspace","path_on_host":"{}","is_root_device":false,"is_read_only":false}}"#,
                workspace.display()
            ),
        );
    }
    let vsock = vm.vsock_socket();
    put(
        api,
        "/vsock",
        format!(
            r#"{{"guest_cid":{GUEST_CID},"uds_path":"{}"}}"#,
            vsock.display()
        ),
    );
    put(
        api,
        "/actions",
        r#"{"action_type":"InstanceStart"}"#.to_owned(),
    );
}

struct NeverPublicAdapter(Arc<AtomicUsize>);

impl PublicDispatchAdapter for NeverPublicAdapter {
    fn fetch(
        &self,
        _request: &HttpFetchRequest,
        _authority: &HttpFetchAuthority,
    ) -> Result<PublicResponse, FetchError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Err(FetchError::OperationRejected)
    }
}

struct NeverGitHubAdapter(Arc<AtomicUsize>);

impl GitHubAdapter for NeverGitHubAdapter {
    fn execute(
        &mut self,
        _request_id: egress_protocol::session::BrokerRequestId,
        _request: &GitHubRequest,
        _authority: &GitHubAuthority,
        _max_response_bytes: u64,
    ) -> Result<GitHubResponse, GitHubAdapterError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Err(GitHubAdapterError::NotAuthorized)
    }
}

fn serve_probe_connection(
    listener: &UnixListener,
    public_calls: Arc<AtomicUsize>,
    github_calls: Arc<AtomicUsize>,
    session: BrokerSessionId,
) -> Result<ConnectionReport, String> {
    let kernel = CapabilityKernel::new(CapabilityState::new(IssuerId::new("real-vsock-test")));
    let mut dispatcher = BrokerDispatcher::new_in_memory(
        kernel,
        NeverPublicAdapter(public_calls),
        NeverGitHubAdapter(github_calls),
        session,
        NonZeroUsize::new(1).expect("fixed replay capacity must be non-zero"),
        SessionBudgetLimits::new(
            NonZeroU64::new(1).expect("fixed request budget must be non-zero"),
            1_024,
            NonZeroUsize::new(1).expect("fixed concurrent budget must be non-zero"),
        ),
        default_github_response_cap(),
    );
    let identity = DispatchContext {
        caller: SubjectId::new("unissued-probe-subject"),
        capability: CapId::new("unissued-probe-capability"),
        now: MonotonicTime::from_ticks(0),
    };
    let deadline = Instant::now() + API_WAIT;
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                let mut ticks = 0_u64;
                let mut clock = || {
                    ticks = ticks
                        .checked_add(1)
                        .expect("test monotonic ticks must not overflow");
                    MonotonicTime::from_ticks(ticks)
                };
                return serve_connection(
                    stream,
                    &mut dispatcher,
                    &identity,
                    &mut clock,
                    NonZeroUsize::new(1).expect("fixed connection request limit must be non-zero"),
                )
                .map_err(|error| format!("serving guest Broker request: {error}"));
            }
            Err(error)
                if error.kind() == std::io::ErrorKind::WouldBlock && Instant::now() < deadline =>
            {
                thread::sleep(Duration::from_millis(10));
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                return Err("guest did not connect to host Broker before timeout".to_owned());
            }
            Err(error) => return Err(format!("accepting guest Broker connection: {error}")),
        }
    }
}

#[test]
#[ignore = "requires KVM, Firecracker, and a guest-control rootfs"]
fn real_firecracker_guest_control_enforces_identity_gate_over_vsock() {
    let firecracker = required_path("REAL_FIRECRACKER_BIN");
    let kernel = required_path("REAL_FIRECRACKER_KERNEL");
    let rootfs = required_path("REAL_FIRECRACKER_ROOTFS");
    let vm = RealFirecracker::start(&firecracker);
    let mut api = UnixApiClient::new(vm.api_socket()).expect("real API path must be valid");
    let vsock = vm.vsock_socket();
    configure_and_start_real_vm(&mut api, &vm, &kernel, &rootfs, GuestWorkload::Sleep, None);

    wait_for_guest_vsock(&vsock);
    let request = guest_request();
    let mut client = FirecrackerVsockApiClient::new(&vsock, GUEST_CID, GUEST_CONTROL_PORT)
        .expect("exact real guest endpoint must be valid");
    let injected = client
        .request(&ApiRequest {
            method: HttpMethod::Put,
            path: GuestControlAction::InjectIdentity.path().to_owned(),
            body: request.canonical_body(),
        })
        .expect("identity injection must reach the real guest");
    assert_eq!(
        injected.body,
        request.canonical_acknowledgement(GuestControlAction::InjectIdentity)
    );
    let started = client
        .request(&ApiRequest {
            method: HttpMethod::Put,
            path: GuestControlAction::StartWorkload.path().to_owned(),
            body: request.canonical_body(),
        })
        .expect("workload release must reach the real guest");
    assert_eq!(
        started.body,
        request.canonical_acknowledgement(GuestControlAction::StartWorkload),
        "guest runtime failed to start; guest serial output:\n{}",
        vm.guest_serial_log(),
    );
    let retried_start = client
        .request(&ApiRequest {
            method: HttpMethod::Put,
            path: GuestControlAction::StartWorkload.path().to_owned(),
            body: request.canonical_body(),
        })
        .expect("a running image-configured workload must keep serving exact start retries");
    assert_eq!(
        retried_start.body,
        request.canonical_acknowledgement(GuestControlAction::StartWorkload)
    );
}

#[test]
#[ignore = "requires KVM, Firecracker, a guest Broker probe rootfs, and a host Unix socket"]
fn real_firecracker_guest_reaches_host_broker_over_vsock() {
    let firecracker = required_path("REAL_FIRECRACKER_BIN");
    let kernel = required_path("REAL_FIRECRACKER_KERNEL");
    let rootfs = required_path("REAL_FIRECRACKER_ROOTFS");
    let public_calls = Arc::new(AtomicUsize::new(0));
    let github_calls = Arc::new(AtomicUsize::new(0));
    let vm = RealFirecracker::start(&firecracker);
    let vsock = vm.vsock_socket();
    let broker_socket = firecracker_guest_port_path(&vsock, GUEST_BROKER_PORT)
        .expect("real Firecracker vsock path must derive one exact guest port socket");
    let listener = UnixListener::bind(&broker_socket)
        .expect("host must bind the exact Firecracker guest Broker socket");
    listener
        .set_nonblocking(true)
        .expect("host Broker listener must become nonblocking");
    let broker = thread::spawn({
        let public_calls = Arc::clone(&public_calls);
        let github_calls = Arc::clone(&github_calls);
        move || {
            serve_probe_connection(
                &listener,
                public_calls,
                github_calls,
                BrokerSessionId::new([7; 16]),
            )
        }
    });

    let mut api = UnixApiClient::new(vm.api_socket()).expect("real API path must be valid");
    configure_and_start_real_vm(
        &mut api,
        &vm,
        &kernel,
        &rootfs,
        GuestWorkload::BrokerProbe,
        None,
    );
    wait_for_guest_vsock(&vsock);
    let request = guest_request();
    let mut client = FirecrackerVsockApiClient::new(&vsock, GUEST_CID, GUEST_CONTROL_PORT)
        .expect("exact real guest endpoint must be valid");
    let injected = client
        .request(&ApiRequest {
            method: HttpMethod::Put,
            path: GuestControlAction::InjectIdentity.path().to_owned(),
            body: request.canonical_body(),
        })
        .expect("identity injection must reach the real guest");
    assert_eq!(
        injected.body,
        request.canonical_acknowledgement(GuestControlAction::InjectIdentity)
    );
    let started = client
        .request(&ApiRequest {
            method: HttpMethod::Put,
            path: GuestControlAction::StartWorkload.path().to_owned(),
            body: request.canonical_body(),
        })
        .expect("guest Broker probe must be released after identity injection");
    assert_eq!(
        started.body,
        request.canonical_acknowledgement(GuestControlAction::StartWorkload),
        "guest runtime failed to start; guest serial output:\n{}",
        vm.guest_serial_log(),
    );

    let report = broker
        .join()
        .expect("host Broker thread must not panic")
        .expect("host Broker must serve the guest probe");
    assert_eq!(report.requests_served(), 1);
    assert_eq!(
        report.close_reason(),
        ConnectionCloseReason::RequestLimitReached
    );
    assert_eq!(public_calls.load(Ordering::SeqCst), 0);
    assert_eq!(github_calls.load(Ordering::SeqCst), 0);
}

#[test]
#[ignore = "requires KVM, Firecracker, a guest capability-runtime rootfs, and a writable workspace image"]
fn real_firecracker_guest_runtime_preserves_the_broker_channel_through_isolation() {
    let firecracker = required_path("REAL_FIRECRACKER_BIN");
    let kernel = required_path("REAL_FIRECRACKER_KERNEL");
    let rootfs = required_path("REAL_FIRECRACKER_ROOTFS");
    let workspace = required_path("REAL_FIRECRACKER_WORKSPACE");
    let public_calls = Arc::new(AtomicUsize::new(0));
    let github_calls = Arc::new(AtomicUsize::new(0));
    let vm = RealFirecracker::start(&firecracker);
    let vsock = vm.vsock_socket();
    let broker_socket = firecracker_guest_port_path(&vsock, GUEST_BROKER_PORT)
        .expect("real Firecracker vsock path must derive one exact guest port socket");
    let listener = UnixListener::bind(&broker_socket)
        .expect("host must bind the exact Firecracker guest Broker socket");
    listener
        .set_nonblocking(true)
        .expect("host Broker listener must become nonblocking");
    let broker = thread::spawn({
        let public_calls = Arc::clone(&public_calls);
        let github_calls = Arc::clone(&github_calls);
        move || {
            // `guest_request` fixes the session identity to 03..03. Matching it here proves the
            // isolated workload uses the host-issued session rather than the probe's legacy ID.
            serve_probe_connection(
                &listener,
                public_calls,
                github_calls,
                BrokerSessionId::new([3; 16]),
            )
        }
    });

    let mut api = UnixApiClient::new(vm.api_socket()).expect("real API path must be valid");
    configure_and_start_real_vm(
        &mut api,
        &vm,
        &kernel,
        &rootfs,
        GuestWorkload::RuntimeBrokerProbe,
        Some(&workspace),
    );
    wait_for_guest_vsock(&vsock);
    let request = guest_request();
    let mut client = FirecrackerVsockApiClient::new(&vsock, GUEST_CID, GUEST_CONTROL_PORT)
        .expect("exact real guest endpoint must be valid");
    let injected = client
        .request(&ApiRequest {
            method: HttpMethod::Put,
            path: GuestControlAction::InjectIdentity.path().to_owned(),
            body: request.canonical_body(),
        })
        .expect("identity injection must reach the real guest");
    assert_eq!(
        injected.body,
        request.canonical_acknowledgement(GuestControlAction::InjectIdentity)
    );
    let started = client
        .request(&ApiRequest {
            method: HttpMethod::Put,
            path: GuestControlAction::StartWorkload.path().to_owned(),
            body: request.canonical_body(),
        })
        .expect("guest runtime must start only after identity injection");
    assert_eq!(
        started.body,
        request.canonical_acknowledgement(GuestControlAction::StartWorkload)
    );

    let report = broker
        .join()
        .expect("host Broker thread must not panic")
        .expect("isolated guest workload must serve one Broker request");
    assert_eq!(report.requests_served(), 1);
    assert_eq!(
        report.close_reason(),
        ConnectionCloseReason::RequestLimitReached
    );
    assert_eq!(public_calls.load(Ordering::SeqCst), 0);
    assert_eq!(github_calls.load(Ordering::SeqCst), 0);
}
