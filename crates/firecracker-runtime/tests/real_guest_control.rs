//! Opt-in real Firecracker and `AF_VSOCK` test for the guest identity gate.
//!
//! Run through `scripts/ci/verify-real-guest-control.sh`, which builds a static guest init and
//! a fresh dm-verity rootfs before enabling this ignored test. The test intentionally uses direct
//! Firecracker API setup: it verifies the actual VM/vsock/guest boundary separately from the
//! higher-level jailer and snapshot lifecycle.

use std::{
    env,
    os::unix::fs::FileTypeExt,
    path::Path,
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use firecracker_runtime::{
    ApiClient, ApiRequest, FirecrackerVsockApiClient, HttpMethod, IdentityBundle, IdentityId,
    RuntimeError, UnixApiClient,
    guest_control::{GuestControlAction, GuestControlRequest},
};
use tempfile::TempDir;

const GUEST_CID: u32 = 42;
const GUEST_CONTROL_PORT: u32 = 18_080;
const API_WAIT: Duration = Duration::from_secs(5);

struct RealFirecracker {
    process: Child,
    directory: TempDir,
    api_socket: std::path::PathBuf,
}

impl RealFirecracker {
    fn start(firecracker: &Path) -> Self {
        let directory = tempfile::tempdir().expect("real VM temporary directory must be created");
        let api_socket = directory.path().join("api.sock");
        let log = directory.path().join("firecracker.log");
        let process = Command::new(firecracker)
            .arg("--api-sock")
            .arg(&api_socket)
            .arg("--log-path")
            .arg(log)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
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
        }
    }

    fn api_socket(&self) -> &Path {
        &self.api_socket
    }

    fn vsock_socket(&self) -> std::path::PathBuf {
        self.directory.path().join("vsock.sock")
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

#[test]
#[ignore = "requires KVM, Firecracker, and a guest-control rootfs"]
fn real_firecracker_guest_control_enforces_identity_gate_over_vsock() {
    let firecracker = required_path("REAL_FIRECRACKER_BIN");
    let kernel = required_path("REAL_FIRECRACKER_KERNEL");
    let rootfs = required_path("REAL_FIRECRACKER_ROOTFS");
    let vm = RealFirecracker::start(&firecracker);
    let mut api = UnixApiClient::new(vm.api_socket()).expect("real API path must be valid");
    put(
        &mut api,
        "/machine-config",
        r#"{"vcpu_count":1,"mem_size_mib":256}"#.to_owned(),
    );
    put(
        &mut api,
        "/boot-source",
        format!(
            r#"{{"kernel_image_path":"{}","boot_args":"console=ttyS0 reboot=k panic=1 pci=off root=/dev/vda rootfstype=squashfs ro init=/usr/local/libexec/guest-control-init -- --port {GUEST_CONTROL_PORT} --workload /usr/local/libexec/guest-workload sleep 600"}}"#,
            kernel.display()
        ),
    );
    put(
        &mut api,
        "/drives/rootfs",
        format!(
            r#"{{"drive_id":"rootfs","path_on_host":"{}","is_root_device":true,"is_read_only":true}}"#,
            rootfs.display()
        ),
    );
    let vsock = vm.vsock_socket();
    put(
        &mut api,
        "/vsock",
        format!(
            r#"{{"guest_cid":{GUEST_CID},"uds_path":"{}"}}"#,
            vsock.display()
        ),
    );
    put(
        &mut api,
        "/actions",
        r#"{"action_type":"InstanceStart"}"#.to_owned(),
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
        .expect("workload release must reach the real guest");
    assert_eq!(
        started.body,
        request.canonical_acknowledgement(GuestControlAction::StartWorkload)
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
