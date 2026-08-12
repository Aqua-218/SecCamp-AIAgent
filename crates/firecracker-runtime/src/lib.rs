//! Firecracker runtime orchestration with pinned artifacts and fail-closed lifecycle rules.
//!
//! Production adapters execute commands, access the filesystem, and speak HTTP over a
//! Unix socket, while the same three boundaries are traits so lifecycle ordering and
//! rollback can be tested without starting a VM. Artifact digests use the audited `sha2`
//! implementation rather than a hand-written cryptographic primitive.

#![warn(clippy::all)]

use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Component, Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use sha2::{Digest, Sha256};

const REQUIRED_BLOCKED_SYSCALLS: [&str; 8] = [
    "bpf",
    "connect",
    "mount",
    "perf_event_open",
    "ptrace",
    "setns",
    "socket",
    "unshare",
];
const HTTP_HEADER_LIMIT: usize = 64 * 1024;
/// Maximum request or response body retained by the Unix API adapter.
pub const MAX_HTTP_BODY_BYTES: usize = 64 * 1024;
/// Maximum number of bytes retained from either command output stream.
pub const MAX_COMMAND_OUTPUT_BYTES: usize = 64 * 1024;
const ID_LENGTH: usize = 16;

/// A SHA-256 digest used to pin every executable and guest artifact.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Sha256Digest([u8; 32]);

impl Sha256Digest {
    /// Parses a lower- or upper-case 64-character hexadecimal digest.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeError::InvalidConfig`] when `value` is not exactly 64
    /// hexadecimal characters.
    pub fn from_hex(value: &str) -> Result<Self, RuntimeError> {
        if value.len() != 64 {
            return Err(RuntimeError::InvalidConfig(
                "SHA-256 digest must contain exactly 64 hexadecimal characters".to_owned(),
            ));
        }
        let mut bytes = [0_u8; 32];
        for (index, slot) in bytes.iter_mut().enumerate() {
            let start = index * 2;
            *slot = u8::from_str_radix(&value[start..start + 2], 16).map_err(|_| {
                RuntimeError::InvalidConfig(
                    "SHA-256 digest contains a non-hex character".to_owned(),
                )
            })?;
        }
        Ok(Self(bytes))
    }

    /// Creates a digest from its raw 32-byte representation.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the raw digest bytes.
    #[must_use]
    pub const fn as_bytes(self) -> [u8; 32] {
        self.0
    }

    /// Returns the canonical lower-case hexadecimal representation.
    #[must_use]
    pub fn to_hex(self) -> String {
        hex_encode(&self.0)
    }

    fn is_zero(self) -> bool {
        self.0.iter().all(|byte| *byte == 0)
    }
}

/// Computes SHA-256 with the `sha2` crate's audited implementation.
#[must_use]
pub fn sha256(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest(Sha256::digest(bytes).into())
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        encoded.push(HEX_DIGITS[usize::from(byte >> 4)] as char);
        encoded.push(HEX_DIGITS[usize::from(byte & 0x0f)] as char);
    }
    encoded
}

/// A path and immutable digest for one boot artifact.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PinnedArtifact {
    /// Absolute host path to the artifact.
    pub path: PathBuf,
    /// Expected SHA-256 digest.
    pub digest: Sha256Digest,
}

impl PinnedArtifact {
    /// Creates a pinned artifact descriptor.
    #[must_use]
    pub fn new(path: impl Into<PathBuf>, digest: Sha256Digest) -> Self {
        Self {
            path: path.into(),
            digest,
        }
    }
}

/// Workspace source and clone destination policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkspaceConfig {
    /// Read-only source workspace used as the clone input.
    pub source: PathBuf,
    /// Directory under which the clone-specific directory is created.
    pub clone_root: PathBuf,
    /// Stable, validated clone identifier used in the destination name.
    pub clone_id: String,
}

impl WorkspaceConfig {
    /// Returns the clone-specific workspace path.
    #[must_use]
    pub fn clone_path(&self) -> PathBuf {
        self.clone_root.join(&self.clone_id)
    }
}

/// dm-verity mapping required for the read-only guest root filesystem.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DmVerityConfig {
    /// Read-only data image, which must equal the pinned rootfs path.
    pub data_device: PathBuf,
    /// Hash image used by dm-verity.
    pub hash_device: PathBuf,
    /// Mapper name created during launch.
    pub mapper_name: String,
    /// Verified dm-verity root hash.
    pub root_hash: Sha256Digest,
}

/// Host-vsock endpoint exposed to the guest through Firecracker's vsock device.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VsockConfig {
    /// Guest context identifier.
    pub guest_cid: u32,
    /// Host Unix-domain socket used by the guest vsock proxy.
    pub uds_path: PathBuf,
}

/// Namespace switches that jailer must create for the Firecracker process.
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(clippy::struct_excessive_bools)] // Each field maps to an independent jailer namespace switch.
pub struct NamespaceConfig {
    /// Create a private user namespace.
    pub user: bool,
    /// Create a private PID namespace.
    pub pid: bool,
    /// Create a private mount namespace.
    pub mount: bool,
    /// Create a private network namespace.
    pub network: bool,
    /// Create a private IPC namespace.
    pub ipc: bool,
    /// Create a private UTS namespace.
    pub uts: bool,
}

/// Cgroup limits and placement for the jailer process.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CgroupConfig {
    /// Absolute cgroup v2 directory.
    pub path: PathBuf,
    /// Maximum memory in bytes.
    pub memory_max_bytes: u64,
    /// Maximum CPU quota in microseconds per period.
    pub cpu_quota_micros: u64,
}

/// Deny-list properties of the host seccomp profile.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SeccompConfig {
    /// Pinned seccomp profile consumed by jailer.
    pub filter: PinnedArtifact,
    /// Syscalls that the profile explicitly denies.
    pub blocked_syscalls: Vec<String>,
}

/// Host-side isolation settings that are checked before any side effect.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostIsolationConfig {
    /// Private namespace configuration.
    pub namespaces: NamespaceConfig,
    /// Cgroup v2 placement and limits.
    pub cgroup: CgroupConfig,
    /// Default-deny seccomp profile description.
    pub seccomp: SeccompConfig,
}

/// A complete pinned Firecracker launch profile.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeConfig {
    /// Pinned Firecracker executable.
    pub firecracker: PinnedArtifact,
    /// Pinned guest kernel.
    pub kernel: PinnedArtifact,
    /// Pinned guest root filesystem image.
    pub rootfs: PinnedArtifact,
    /// Pinned dm-verity hash image.
    pub verity_hash: PinnedArtifact,
    /// Required dm-verity mapping.
    pub dm_verity: DmVerityConfig,
    /// Clone-specific workspace policy.
    pub workspace: WorkspaceConfig,
    /// Jailer executable and API socket paths.
    pub jailer: PinnedArtifact,
    /// Firecracker Unix API socket path.
    pub api_socket: PathBuf,
    /// Host isolation policy.
    pub isolation: HostIsolationConfig,
    /// Firecracker vsock configuration.
    pub vsock: VsockConfig,
    /// Network devices are intentionally unsupported and must remain empty.
    pub network_devices: Vec<String>,
    /// Number of virtual CPUs.
    pub vcpu_count: u32,
    /// Guest memory in MiB.
    pub memory_mib: u32,
    /// Guest kernel command line.
    pub boot_args: String,
}

impl RuntimeConfig {
    /// Validates all static security invariants before filesystem or process changes.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeError::InvalidConfig`] when a pinned path, digest, isolation
    /// setting, namespace switch, resource limit, or lifecycle identifier violates
    /// the fail-closed runtime policy. Returns [`RuntimeError::NetworkDeviceForbidden`]
    /// when a network device is configured.
    pub fn validate(&self) -> Result<(), RuntimeError> {
        validate_artifact("firecracker", &self.firecracker)?;
        validate_artifact("kernel", &self.kernel)?;
        validate_artifact("rootfs", &self.rootfs)?;
        validate_artifact("dm-verity hash image", &self.verity_hash)?;
        validate_artifact("jailer", &self.jailer)?;
        validate_artifact("seccomp filter", &self.isolation.seccomp.filter)?;
        validate_absolute_path("API socket", &self.api_socket)?;
        validate_absolute_path("workspace source", &self.workspace.source)?;
        validate_absolute_path("workspace clone root", &self.workspace.clone_root)?;
        validate_absolute_path("dm-verity hash device", &self.dm_verity.hash_device)?;
        validate_absolute_path("cgroup path", &self.isolation.cgroup.path)?;
        validate_absolute_path("vsock UDS path", &self.vsock.uds_path)?;
        if self.dm_verity.data_device != self.rootfs.path {
            return Err(RuntimeError::InvalidConfig(
                "dm-verity data device must equal the pinned rootfs path".to_owned(),
            ));
        }
        if self.dm_verity.hash_device != self.verity_hash.path {
            return Err(RuntimeError::InvalidConfig(
                "dm-verity hash device must equal the pinned hash image path".to_owned(),
            ));
        }
        if self.dm_verity.root_hash.is_zero() {
            return Err(RuntimeError::InvalidConfig(
                "dm-verity root hash cannot be all zeroes".to_owned(),
            ));
        }
        validate_safe_name("dm-verity mapper name", &self.dm_verity.mapper_name)?;
        validate_safe_name("workspace clone id", &self.workspace.clone_id)?;
        let clone_path = self.workspace.clone_path();
        if self.workspace.source == clone_path
            || clone_path.starts_with(&self.workspace.source)
            || self.workspace.source.starts_with(&clone_path)
        {
            return Err(RuntimeError::InvalidConfig(
                "workspace source and clone paths must not overlap".to_owned(),
            ));
        }
        if self.vsock.guest_cid < 3 {
            return Err(RuntimeError::InvalidConfig(
                "guest CID must be at least 3 and cannot use reserved CID values".to_owned(),
            ));
        }
        if !self.network_devices.is_empty() {
            return Err(RuntimeError::NetworkDeviceForbidden);
        }
        if self.vcpu_count == 0 || self.memory_mib == 0 {
            return Err(RuntimeError::InvalidConfig(
                "vcpu count and memory must both be non-zero".to_owned(),
            ));
        }
        if self.isolation.cgroup.path == Path::new("/") {
            return Err(RuntimeError::InvalidConfig(
                "cgroup path cannot be the host root directory".to_owned(),
            ));
        }
        if self.isolation.cgroup.memory_max_bytes == 0
            || self.isolation.cgroup.cpu_quota_micros == 0
        {
            return Err(RuntimeError::InvalidConfig(
                "cgroup memory and CPU limits must be non-zero".to_owned(),
            ));
        }
        if !(self.isolation.namespaces.user
            && self.isolation.namespaces.pid
            && self.isolation.namespaces.mount
            && self.isolation.namespaces.network
            && self.isolation.namespaces.ipc
            && self.isolation.namespaces.uts)
        {
            return Err(RuntimeError::InvalidConfig(
                "jailer must create private user, PID, mount, network, IPC, and UTS namespaces"
                    .to_owned(),
            ));
        }
        for required in REQUIRED_BLOCKED_SYSCALLS {
            if !self
                .isolation
                .seccomp
                .blocked_syscalls
                .iter()
                .any(|name| name == required)
            {
                return Err(RuntimeError::InvalidConfig(format!(
                    "seccomp profile must block required syscall '{required}'"
                )));
            }
        }
        Ok(())
    }

    fn fingerprint(&self) -> Sha256Digest {
        let mut bytes = Vec::new();
        for artifact in [
            &self.firecracker,
            &self.kernel,
            &self.rootfs,
            &self.verity_hash,
            &self.jailer,
            &self.isolation.seccomp.filter,
        ] {
            bytes.extend_from_slice(&artifact.digest.as_bytes());
        }
        bytes.extend_from_slice(&self.dm_verity.root_hash.as_bytes());
        bytes.extend_from_slice(&self.vsock.guest_cid.to_be_bytes());
        sha256(&bytes)
    }
}

fn validate_artifact(label: &str, artifact: &PinnedArtifact) -> Result<(), RuntimeError> {
    validate_absolute_path(label, &artifact.path)?;
    if artifact.digest.is_zero() {
        return Err(RuntimeError::InvalidConfig(format!(
            "{label} digest cannot be all zeroes"
        )));
    }
    Ok(())
}

fn validate_absolute_path(label: &str, path: &Path) -> Result<(), RuntimeError> {
    if !path.is_absolute() {
        return Err(RuntimeError::InvalidConfig(format!(
            "{label} path must be absolute: {}",
            path.display()
        )));
    }
    if path
        .components()
        .any(|component| component == Component::ParentDir)
    {
        return Err(RuntimeError::InvalidConfig(format!(
            "{label} path cannot contain '..': {}",
            path.display()
        )));
    }
    if path.components().any(|component| {
        matches!(component, Component::Normal(value) if value.to_string_lossy().eq_ignore_ascii_case("latest"))
    }) {
        return Err(RuntimeError::LatestArtifactPath { label: label.to_owned() });
    }
    if path.to_string_lossy().contains('\0') {
        return Err(RuntimeError::InvalidConfig(format!(
            "{label} path contains a NUL byte"
        )));
    }
    Ok(())
}

fn validate_safe_name(label: &str, value: &str) -> Result<(), RuntimeError> {
    if value.is_empty()
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Err(RuntimeError::InvalidConfig(format!(
            "{label} must contain only ASCII letters, digits, '_' or '-'"
        )));
    }
    Ok(())
}

/// A command to execute through the command runner boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommandSpec {
    /// Executable path.
    pub program: PathBuf,
    /// Positional arguments.
    pub args: Vec<String>,
}

impl CommandSpec {
    fn new(program: impl Into<PathBuf>, args: impl IntoIterator<Item = String>) -> Self {
        Self {
            program: program.into(),
            args: args.into_iter().collect(),
        }
    }
}

/// A process identifier returned by a command runner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProcessHandle {
    /// Host process identifier.
    pub pid: u32,
}

/// Captured result of a short command.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommandOutput {
    /// Exit status code.
    pub status: i32,
    /// Standard output.
    pub stdout: Vec<u8>,
    /// Standard error.
    pub stderr: Vec<u8>,
}

/// Boundary for commands that create dm-verity mappings or jailer processes.
pub trait CommandRunner {
    /// Executes a short-lived command and requires a successful exit status.
    ///
    /// # Errors
    ///
    /// Returns an adapter error when the command cannot be started or exits unsuccessfully.
    fn run(&mut self, command: &CommandSpec) -> Result<CommandOutput, RuntimeError>;
    /// Starts a long-lived process and returns a handle for rollback.
    ///
    /// # Errors
    ///
    /// Returns an adapter error when the process cannot be started.
    fn start(&mut self, command: &CommandSpec) -> Result<ProcessHandle, RuntimeError>;
    /// Stops a process created by this runner.
    ///
    /// # Errors
    ///
    /// Returns an adapter error when the process cannot be stopped.
    fn stop(&mut self, process: ProcessHandle) -> Result<(), RuntimeError>;
}

/// Boundary for artifact reads and clone-specific workspace operations.
pub trait FileSystem {
    /// Reads an artifact completely for digest verification.
    ///
    /// # Errors
    ///
    /// Returns an adapter error when the artifact cannot be read.
    fn read(&mut self, path: &Path) -> Result<Vec<u8>, RuntimeError>;
    /// Creates a clone at `destination` from `source`.
    ///
    /// # Errors
    ///
    /// Returns an adapter error when the clone cannot be created.
    fn clone_workspace(&mut self, source: &Path, destination: &Path) -> Result<(), RuntimeError>;
    /// Removes a clone or a dm-verity-related filesystem staging path.
    ///
    /// # Errors
    ///
    /// Returns an adapter error when the path cannot be removed.
    fn remove_workspace(&mut self, path: &Path) -> Result<(), RuntimeError>;
}

/// HTTP method supported by the Unix API client.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HttpMethod {
    /// HTTP GET.
    Get,
    /// HTTP PUT.
    Put,
    /// HTTP POST.
    Post,
    /// HTTP DELETE.
    Delete,
}

impl HttpMethod {
    fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Put => "PUT",
            Self::Post => "POST",
            Self::Delete => "DELETE",
        }
    }
}

/// One request sent to Firecracker's Unix API socket.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApiRequest {
    /// HTTP method.
    pub method: HttpMethod,
    /// Absolute API path.
    pub path: String,
    /// JSON request body.
    pub body: String,
}

/// A response received from the API socket.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApiResponse {
    /// HTTP status code.
    pub status: u16,
    /// Response body.
    pub body: String,
}

/// Boundary for Firecracker or guest-supervisor API calls.
pub trait ApiClient {
    /// Sends one request and returns its status and body.
    ///
    /// # Errors
    ///
    /// Returns an adapter error when the request cannot be sent or decoded.
    fn request(&mut self, request: &ApiRequest) -> Result<ApiResponse, RuntimeError>;
}

/// A production API client speaking HTTP/1.x over a Unix-domain socket.
pub struct UnixApiClient {
    socket: PathBuf,
    timeout: Duration,
}

impl UnixApiClient {
    /// Creates a client for an absolute Unix API socket path.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeError::InvalidConfig`] when `socket` is not an allowed
    /// absolute path.
    pub fn new(socket: impl Into<PathBuf>) -> Result<Self, RuntimeError> {
        let socket = socket.into();
        validate_absolute_path("API socket", &socket)?;
        Ok(Self {
            socket,
            timeout: Duration::from_secs(5),
        })
    }

    /// Sets the bounded read/write timeout used for each API call.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeError::InvalidConfig`] when `timeout` is zero.
    pub fn with_timeout(mut self, timeout: Duration) -> Result<Self, RuntimeError> {
        if timeout.is_zero() {
            return Err(RuntimeError::InvalidConfig(
                "Unix API timeout must be non-zero".to_owned(),
            ));
        }
        self.timeout = timeout;
        Ok(self)
    }

    fn read_response(stream: &mut UnixStream) -> Result<ApiResponse, RuntimeError> {
        let mut headers = Vec::new();
        let mut byte = [0_u8; 1];
        loop {
            stream.read_exact(&mut byte).map_err(RuntimeError::from)?;
            headers.push(byte[0]);
            if headers.len() > HTTP_HEADER_LIMIT {
                return Err(RuntimeError::Api(
                    "HTTP headers exceed safety limit".to_owned(),
                ));
            }
            if headers.ends_with(b"\r\n\r\n") {
                break;
            }
        }
        let header_text = std::str::from_utf8(&headers[..headers.len() - 4]).map_err(|_| {
            RuntimeError::Api("API response headers are not valid UTF-8".to_owned())
        })?;
        let mut lines = header_text.split("\r\n");
        let status_line = lines
            .next()
            .ok_or_else(|| RuntimeError::Api("API response omitted status line".to_owned()))?;
        let status = parse_status_line(status_line)?;
        let mut content_length = None;
        for line in lines {
            let (name, value) = line.split_once(':').ok_or_else(|| {
                RuntimeError::Api("API response header is missing its colon".to_owned())
            })?;
            validate_header_name(name)?;
            validate_header_value(value)?;
            if name.eq_ignore_ascii_case("transfer-encoding") {
                return Err(RuntimeError::Api(
                    "API response must not use Transfer-Encoding".to_owned(),
                ));
            }
            if name.eq_ignore_ascii_case("content-length") {
                if content_length.is_some() {
                    return Err(RuntimeError::Api(
                        "API response contains duplicate Content-Length headers".to_owned(),
                    ));
                }
                let value = value.trim();
                if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
                    return Err(RuntimeError::Api(
                        "API response content length is invalid".to_owned(),
                    ));
                }
                let length = value.parse::<usize>().map_err(|_| {
                    RuntimeError::Api("API response content length is invalid".to_owned())
                })?;
                if length > MAX_HTTP_BODY_BYTES {
                    return Err(RuntimeError::Api(format!(
                        "API response body exceeds {MAX_HTTP_BODY_BYTES}-byte safety limit"
                    )));
                }
                content_length = Some(length);
            }
        }
        let body_is_permitted = !matches!(status, 100..=199 | 204 | 304);
        let length = match (body_is_permitted, content_length) {
            (true, Some(length)) => length,
            (true, None) => {
                return Err(RuntimeError::Api(
                    "API response omitted required Content-Length".to_owned(),
                ));
            }
            (false, Some(length)) => {
                if matches!(status, 100..=199 | 204) && length != 0 {
                    return Err(RuntimeError::Api(
                        "API response declared a body for a bodyless status".to_owned(),
                    ));
                }
                0
            }
            (false, None) => 0,
        };
        let mut body = vec![0_u8; length];
        stream.read_exact(&mut body).map_err(RuntimeError::from)?;
        let body = String::from_utf8(body)
            .map_err(|_| RuntimeError::Api("API response body is not valid UTF-8".to_owned()))?;
        Ok(ApiResponse { status, body })
    }
}

fn parse_status_line(status_line: &str) -> Result<u16, RuntimeError> {
    let (version, rest) = status_line
        .split_once(' ')
        .ok_or_else(|| RuntimeError::Api("API response status line is malformed".to_owned()))?;
    if !matches!(version, "HTTP/1.0" | "HTTP/1.1") {
        return Err(RuntimeError::Api(
            "API response uses an unsupported HTTP version".to_owned(),
        ));
    }
    let (code, reason) = rest
        .split_once(' ')
        .ok_or_else(|| RuntimeError::Api("API response status line is malformed".to_owned()))?;
    if code.len() != 3 || !code.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(RuntimeError::Api(
            "API response status is not a three-digit code".to_owned(),
        ));
    }
    if !reason
        .bytes()
        .all(|byte| byte == b'\t' || (0x20..=0x7e).contains(&byte))
    {
        return Err(RuntimeError::Api(
            "API response status reason is malformed".to_owned(),
        ));
    }
    let status = code
        .parse::<u16>()
        .map_err(|_| RuntimeError::Api("API response status is not numeric".to_owned()))?;
    if !(100..=599).contains(&status) {
        return Err(RuntimeError::Api(
            "API response status is outside the valid range".to_owned(),
        ));
    }
    Ok(status)
}

fn validate_header_name(name: &str) -> Result<(), RuntimeError> {
    if name.is_empty() || !name.bytes().all(is_http_token) {
        return Err(RuntimeError::Api(
            "API response header name is malformed".to_owned(),
        ));
    }
    Ok(())
}

fn validate_header_value(value: &str) -> Result<(), RuntimeError> {
    if !value
        .bytes()
        .all(|byte| byte == b'\t' || (0x20..=0x7e).contains(&byte))
    {
        return Err(RuntimeError::Api(
            "API response header value is malformed".to_owned(),
        ));
    }
    Ok(())
}

fn is_http_token(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

impl ApiClient for UnixApiClient {
    fn request(&mut self, request: &ApiRequest) -> Result<ApiResponse, RuntimeError> {
        if !request.path.starts_with('/')
            || request
                .path
                .chars()
                .any(|character| character.is_ascii_control() || character == ' ')
        {
            return Err(RuntimeError::Api(
                "API path must be an absolute token".to_owned(),
            ));
        }
        let body = request.body.as_bytes();
        if body.len() > MAX_HTTP_BODY_BYTES {
            return Err(RuntimeError::Api(format!(
                "API request body exceeds {MAX_HTTP_BODY_BYTES}-byte safety limit"
            )));
        }
        let mut stream = UnixStream::connect(&self.socket).map_err(RuntimeError::from)?;
        stream
            .set_read_timeout(Some(self.timeout))
            .map_err(RuntimeError::from)?;
        stream
            .set_write_timeout(Some(self.timeout))
            .map_err(RuntimeError::from)?;
        let message = format!(
            "{} {} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
            request.method.as_str(),
            request.path,
            body.len()
        );
        stream
            .write_all(message.as_bytes())
            .map_err(RuntimeError::from)?;
        stream.write_all(body).map_err(RuntimeError::from)?;
        Self::read_response(&mut stream)
    }
}

/// Production command runner backed by `std::process::Command`.
pub struct RealCommandRunner {
    children: HashMap<u32, Child>,
}

impl RealCommandRunner {
    /// Creates an empty process table.
    #[must_use]
    pub fn new() -> Self {
        Self {
            children: HashMap::new(),
        }
    }
}

impl Default for RealCommandRunner {
    fn default() -> Self {
        Self::new()
    }
}

const COMMAND_READ_CHUNK_BYTES: usize = 8 * 1024;

#[derive(Clone, Copy, Debug)]
enum CommandOutputStream {
    Stdout,
    Stderr,
}

impl CommandOutputStream {
    fn name(self) -> &'static str {
        match self {
            Self::Stdout => "stdout",
            Self::Stderr => "stderr",
        }
    }
}

#[derive(Debug)]
enum BoundedReadError {
    LimitExceeded,
    Io(String),
}

#[derive(Debug)]
struct BoundedReadResult {
    bytes: Vec<u8>,
    error: Option<BoundedReadError>,
}

fn read_bounded<R: Read>(mut reader: R) -> BoundedReadResult {
    let mut bytes = Vec::with_capacity(MAX_COMMAND_OUTPUT_BYTES.min(COMMAND_READ_CHUNK_BYTES));
    let mut buffer = [0_u8; COMMAND_READ_CHUNK_BYTES];
    loop {
        let count = match reader.read(&mut buffer) {
            Ok(count) => count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => {
                return BoundedReadResult {
                    bytes,
                    error: Some(BoundedReadError::Io(error.to_string())),
                };
            }
        };
        if count == 0 {
            return BoundedReadResult { bytes, error: None };
        }
        let remaining = MAX_COMMAND_OUTPUT_BYTES.saturating_sub(bytes.len());
        if count > remaining {
            bytes.extend_from_slice(&buffer[..remaining]);
            return BoundedReadResult {
                bytes,
                error: Some(BoundedReadError::LimitExceeded),
            };
        }
        bytes.extend_from_slice(&buffer[..count]);
    }
}

fn spawn_command_reader<R: Read + Send + 'static>(
    stream: CommandOutputStream,
    reader: R,
    sender: mpsc::Sender<(CommandOutputStream, bool)>,
) -> thread::JoinHandle<BoundedReadResult> {
    thread::spawn(move || {
        let result = read_bounded(reader);
        let _ = sender.send((stream, result.error.is_some()));
        result
    })
}

fn monitor_command(
    child: &mut Child,
    receiver: &mpsc::Receiver<(CommandOutputStream, bool)>,
) -> Result<ExitStatus, String> {
    let terminate = loop {
        let mut reader_error = false;
        while let Ok((_stream, has_error)) = receiver.try_recv() {
            reader_error |= has_error;
        }
        if reader_error {
            break true;
        }
        match child.try_wait() {
            Ok(Some(_)) => break false,
            Ok(None) => thread::sleep(Duration::from_millis(1)),
            Err(error) => {
                let _ = child.kill();
                return match child.wait() {
                    Ok(_) => Err(error.to_string()),
                    Err(wait_error) => Err(format!("{error}; reaping child failed: {wait_error}")),
                };
            }
        }
    };
    if terminate {
        let _ = child.kill();
    }
    child.wait().map_err(|error| error.to_string())
}

fn join_command_reader(
    reader: thread::JoinHandle<BoundedReadResult>,
    stream: CommandOutputStream,
) -> Result<BoundedReadResult, RuntimeError> {
    reader
        .join()
        .map_err(|_| RuntimeError::Command(format!("{} reader thread panicked", stream.name())))
}

fn command_output_error(readers: &[BoundedReadResult; 2]) -> Option<String> {
    for (stream, reader) in [
        (CommandOutputStream::Stdout, &readers[0]),
        (CommandOutputStream::Stderr, &readers[1]),
    ] {
        if let Some(error) = &reader.error {
            let message = match error {
                BoundedReadError::LimitExceeded => format!(
                    "{} exceeds {MAX_COMMAND_OUTPUT_BYTES}-byte safety limit",
                    stream.name()
                ),
                BoundedReadError::Io(message) => {
                    format!("{} capture failed: {message}", stream.name())
                }
            };
            return Some(message);
        }
    }
    None
}

impl CommandRunner for RealCommandRunner {
    fn run(&mut self, command: &CommandSpec) -> Result<CommandOutput, RuntimeError> {
        let mut child = Command::new(&command.program)
            .args(&command.args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(RuntimeError::from)?;

        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| RuntimeError::Command("failed to capture command stdout".to_owned()))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| RuntimeError::Command("failed to capture command stderr".to_owned()))?;
        let (sender, receiver) = mpsc::channel();
        let stdout_reader =
            spawn_command_reader(CommandOutputStream::Stdout, stdout, sender.clone());
        let stderr_reader = spawn_command_reader(CommandOutputStream::Stderr, stderr, sender);

        let wait_result = monitor_command(&mut child, &receiver);
        let stdout_result = join_command_reader(stdout_reader, CommandOutputStream::Stdout)?;
        let stderr_result = join_command_reader(stderr_reader, CommandOutputStream::Stderr)?;
        let mut reader_results = [stdout_result, stderr_result];
        let output_error = command_output_error(&reader_results);
        if let Some(message) = output_error {
            return Err(RuntimeError::Command(format!(
                "command {} output failure: {message}",
                command.program.display()
            )));
        }
        let status = wait_result.map_err(|message| {
            RuntimeError::Command(format!(
                "command {} wait failed: {message}",
                command.program.display()
            ))
        })?;
        let status_code = status.code().unwrap_or(-1);
        let stderr = std::mem::take(&mut reader_results[1].bytes);
        if !status.success() {
            return Err(RuntimeError::CommandFailed {
                program: command.program.display().to_string(),
                status: status_code,
                stderr: String::from_utf8_lossy(&stderr).into_owned(),
            });
        }
        Ok(CommandOutput {
            status: status_code,
            stdout: std::mem::take(&mut reader_results[0].bytes),
            stderr,
        })
    }

    fn start(&mut self, command: &CommandSpec) -> Result<ProcessHandle, RuntimeError> {
        let child = Command::new(&command.program)
            .args(&command.args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(RuntimeError::from)?;
        let pid = child.id();
        self.children.insert(pid, child);
        Ok(ProcessHandle { pid })
    }

    fn stop(&mut self, process: ProcessHandle) -> Result<(), RuntimeError> {
        let mut child = self
            .children
            .remove(&process.pid)
            .ok_or_else(|| RuntimeError::Command(format!("unknown process {}", process.pid)))?;
        child.kill().map_err(RuntimeError::from)?;
        child.wait().map_err(RuntimeError::from)?;
        Ok(())
    }
}

/// Production filesystem adapter with symlink-safe recursive workspace copying.
#[derive(Clone, Copy, Debug, Default)]
pub struct RealFileSystem;

impl RealFileSystem {
    /// Creates a filesystem adapter.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    fn copy_entry(source: &Path, destination: &Path) -> Result<(), RuntimeError> {
        let metadata = fs::symlink_metadata(source).map_err(RuntimeError::from)?;
        if metadata.file_type().is_symlink() {
            return Err(RuntimeError::InvalidConfig(format!(
                "workspace contains forbidden symlink: {}",
                source.display()
            )));
        }
        if metadata.is_dir() {
            fs::create_dir(destination).map_err(RuntimeError::from)?;
            for entry in fs::read_dir(source).map_err(RuntimeError::from)? {
                let entry = entry.map_err(RuntimeError::from)?;
                Self::copy_entry(&entry.path(), &destination.join(entry.file_name()))?;
            }
        } else if metadata.is_file() {
            fs::copy(source, destination).map_err(RuntimeError::from)?;
        } else {
            return Err(RuntimeError::InvalidConfig(format!(
                "workspace contains unsupported filesystem object: {}",
                source.display()
            )));
        }
        Ok(())
    }
}

impl FileSystem for RealFileSystem {
    fn read(&mut self, path: &Path) -> Result<Vec<u8>, RuntimeError> {
        fs::read(path).map_err(RuntimeError::from)
    }

    fn clone_workspace(&mut self, source: &Path, destination: &Path) -> Result<(), RuntimeError> {
        if fs::symlink_metadata(destination).is_ok() {
            return Err(RuntimeError::WorkspaceAlreadyExists(
                destination.to_path_buf(),
            ));
        }
        fs::create_dir_all(destination.parent().ok_or_else(|| {
            RuntimeError::InvalidConfig("workspace clone has no parent directory".to_owned())
        })?)
        .map_err(RuntimeError::from)?;
        Self::copy_entry(source, destination)
    }

    fn remove_workspace(&mut self, path: &Path) -> Result<(), RuntimeError> {
        match fs::symlink_metadata(path) {
            Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {
                fs::remove_dir_all(path).map_err(RuntimeError::from)
            }
            Ok(_) => fs::remove_file(path).map_err(RuntimeError::from),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        }
    }
}

/// A 128-bit opaque identity generated after snapshot restore.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct IdentityId([u8; ID_LENGTH]);

impl IdentityId {
    /// Parses a 32-character hexadecimal identity.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeError::InvalidIdentity`] when `value` is not exactly 32
    /// hexadecimal characters or decodes to an all-zero identity.
    pub fn from_hex(value: &str) -> Result<Self, RuntimeError> {
        if value.len() != ID_LENGTH * 2 {
            return Err(RuntimeError::InvalidIdentity(
                "identity must contain exactly 32 hexadecimal characters".to_owned(),
            ));
        }
        let mut bytes = [0_u8; ID_LENGTH];
        for (index, slot) in bytes.iter_mut().enumerate() {
            *slot = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).map_err(|_| {
                RuntimeError::InvalidIdentity("identity contains a non-hex character".to_owned())
            })?;
        }
        if bytes.iter().all(|byte| *byte == 0) {
            return Err(RuntimeError::InvalidIdentity(
                "identity cannot be all zeroes".to_owned(),
            ));
        }
        Ok(Self(bytes))
    }

    /// Returns the identity as lower-case hexadecimal text.
    #[must_use]
    pub fn to_hex(self) -> String {
        hex_encode(&self.0)
    }
}

/// All identities that must be regenerated for every restored VM.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IdentityBundle {
    /// VM identity.
    pub vm_id: IdentityId,
    /// Host broker session identity.
    pub session_id: IdentityId,
    /// Request namespace identity.
    pub request_id: IdentityId,
    /// Subject identity.
    pub subject_id: IdentityId,
    /// Root capability identity.
    pub capability_id: IdentityId,
}

impl IdentityBundle {
    fn generate(source: &mut impl IdentitySource) -> Result<Self, RuntimeError> {
        let ids = [
            source.generate()?,
            source.generate()?,
            source.generate()?,
            source.generate()?,
            source.generate()?,
        ];
        let unique = ids.iter().copied().collect::<HashSet<_>>();
        if unique.len() != ids.len() {
            return Err(RuntimeError::StaleIdentity(
                "identity generator returned duplicate IDs".to_owned(),
            ));
        }
        Ok(Self {
            vm_id: ids[0],
            session_id: ids[1],
            request_id: ids[2],
            subject_id: ids[3],
            capability_id: ids[4],
        })
    }

    fn ids(&self) -> [IdentityId; 5] {
        [
            self.vm_id,
            self.session_id,
            self.request_id,
            self.subject_id,
            self.capability_id,
        ]
    }
}

/// Boundary for post-restore cryptographic identity generation.
pub trait IdentitySource {
    /// Returns one fresh, non-zero identity.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeError::InvalidIdentity`] when a fresh identity cannot be
    /// generated or is all zeroes.
    fn generate(&mut self) -> Result<IdentityId, RuntimeError>;
}

/// Production identity source backed by the host kernel's entropy device.
pub struct SystemIdentitySource;

impl IdentitySource for SystemIdentitySource {
    fn generate(&mut self) -> Result<IdentityId, RuntimeError> {
        let mut bytes = [0_u8; ID_LENGTH];
        File::open("/dev/urandom")
            .map_err(RuntimeError::from)?
            .read_exact(&mut bytes)
            .map_err(RuntimeError::from)?;
        if bytes.iter().all(|byte| *byte == 0) {
            return Err(RuntimeError::InvalidIdentity(
                "kernel entropy returned an all-zero identity".to_owned(),
            ));
        }
        Ok(IdentityId(bytes))
    }
}

/// Snapshot files and the artifact fingerprint from which they were created.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Snapshot {
    /// Firecracker snapshot state path.
    pub snapshot_path: PathBuf,
    /// Firecracker memory file path.
    pub memory_path: PathBuf,
    /// Artifact fingerprint required for restore.
    pub artifact_fingerprint: Sha256Digest,
    forbidden_identities: Vec<IdentityId>,
}

impl Snapshot {
    /// Creates externally persisted snapshot metadata with identities that restore must not reuse.
    #[must_use]
    pub fn new(
        snapshot_path: impl Into<PathBuf>,
        memory_path: impl Into<PathBuf>,
        artifact_fingerprint: Sha256Digest,
        forbidden_identities: Vec<IdentityId>,
    ) -> Self {
        Self {
            snapshot_path: snapshot_path.into(),
            memory_path: memory_path.into(),
            artifact_fingerprint,
            forbidden_identities,
        }
    }
}

/// Lifecycle states that make workload gating observable and auditable.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeState {
    /// Firecracker process and guest are not started.
    New,
    /// VM is booted at the pre-session gate and workload is stopped.
    WorkloadStopped,
    /// A pre-session snapshot has been created.
    Snapshotted,
    /// Snapshot is restored and the workload remains stopped.
    RestoredStopped,
    /// Fresh identities were generated but not injected.
    IdentityRegenerated,
    /// Fresh identities were injected; workload is still stopped.
    IdentityInjected,
    /// Workload start was explicitly requested after identity injection.
    Running,
    /// Process and workspace cleanup completed.
    Stopped,
}

/// A live runtime process and its rollback resources.
#[derive(Debug)]
pub struct RuntimeInstance {
    state: RuntimeState,
    process: ProcessHandle,
    workspace: PathBuf,
    mapper_name: String,
    verity_opened: bool,
    config_fingerprint: Sha256Digest,
    identities: Option<IdentityBundle>,
}

impl RuntimeInstance {
    /// Returns the current lifecycle state.
    #[must_use]
    pub const fn state(&self) -> RuntimeState {
        self.state
    }

    /// Returns the clone-specific workspace path.
    #[must_use]
    pub fn workspace(&self) -> &Path {
        &self.workspace
    }

    /// Returns the dm-verity mapper name owned by this instance.
    #[must_use]
    pub fn mapper_name(&self) -> &str {
        &self.mapper_name
    }

    /// Returns regenerated identities after restore, if present.
    #[must_use]
    pub const fn identities(&self) -> Option<&IdentityBundle> {
        self.identities.as_ref()
    }
}

/// Runtime coordinator parametrized over all side-effecting boundaries.
pub struct Runtime<C, F, A, G, I> {
    command_runner: C,
    filesystem: F,
    api_client: A,
    guest_client: G,
    identity_source: I,
}

impl<C, F, A, G, I> Runtime<C, F, A, G, I>
where
    C: CommandRunner,
    F: FileSystem,
    A: ApiClient,
    G: ApiClient,
    I: IdentitySource,
{
    /// Creates a coordinator using mockable command, filesystem, API, and identity boundaries.
    pub fn new(
        command_runner: C,
        filesystem: F,
        api_client: A,
        guest_client: G,
        identity_source: I,
    ) -> Self {
        Self {
            command_runner,
            filesystem,
            api_client,
            guest_client,
            identity_source,
        }
    }

    /// Launches a pinned pre-session VM with workload execution still gated.
    ///
    /// # Errors
    ///
    /// Returns a validation, artifact, adapter, API, or rollback error when any
    /// launch precondition or lifecycle step fails.
    pub fn launch(&mut self, config: &RuntimeConfig) -> Result<RuntimeInstance, RuntimeError> {
        config.validate()?;
        self.verify_artifacts(config)?;
        let workspace = config.workspace.clone_path();
        if let Err(error) = self
            .filesystem
            .clone_workspace(&config.workspace.source, &workspace)
        {
            let cleanup = self
                .filesystem
                .remove_workspace(&workspace)
                .err()
                .map_or_else(Vec::new, |cleanup_error| vec![cleanup_error.to_string()]);
            return Err(with_cleanup(error, &cleanup));
        }
        let workspace_cloned = true;
        let mut verity_opened = false;
        let mut process = None;

        let result = (|| {
            self.open_verity(config)?;
            verity_opened = true;
            let handle = self.start_jailer(config)?;
            process = Some(handle);
            self.configure_vm(config)?;
            self.api_call(ApiRequest {
                method: HttpMethod::Put,
                path: "/actions".to_owned(),
                body: r#"{"action_type":"InstanceStart"}"#.to_owned(),
            })?;
            Ok(RuntimeInstance {
                state: RuntimeState::WorkloadStopped,
                process: handle,
                workspace: workspace.clone(),
                mapper_name: config.dm_verity.mapper_name.clone(),
                verity_opened: true,
                config_fingerprint: config.fingerprint(),
                identities: None,
            })
        })();
        match result {
            Ok(instance) => Ok(instance),
            Err(error) => {
                let cleanup =
                    self.rollback(process, verity_opened, workspace_cloned, &workspace, config);
                Err(with_cleanup(error, &cleanup))
            }
        }
    }

    /// Creates a snapshot only from a pre-session instance whose workload is stopped.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeError::InvalidState`] when the instance is not at the
    /// pre-session gate, a validation error for unsafe snapshot paths, or an API
    /// error when Firecracker rejects the snapshot request.
    pub fn create_snapshot(
        &mut self,
        instance: &mut RuntimeInstance,
        snapshot_path: impl Into<PathBuf>,
        memory_path: impl Into<PathBuf>,
    ) -> Result<Snapshot, RuntimeError> {
        if instance.state != RuntimeState::WorkloadStopped {
            return Err(RuntimeError::InvalidState {
                expected: "WorkloadStopped".to_owned(),
                actual: format!("{:?}", instance.state),
            });
        }
        let snapshot_path = snapshot_path.into();
        let memory_path = memory_path.into();
        validate_absolute_path("snapshot path", &snapshot_path)?;
        validate_absolute_path("snapshot memory path", &memory_path)?;
        self.api_call(ApiRequest {
            method: HttpMethod::Put,
            path: "/snapshot/create".to_owned(),
            body: format!(
                "{{\"snapshot_type\":\"Full\",\"snapshot_path\":{},\"mem_file_path\":{}}}",
                json_string(&snapshot_path.to_string_lossy()),
                json_string(&memory_path.to_string_lossy())
            ),
        })?;
        instance.state = RuntimeState::Snapshotted;
        Ok(Snapshot::new(
            snapshot_path,
            memory_path,
            instance.config_fingerprint,
            instance
                .identities
                .as_ref()
                .map_or_else(Vec::new, |ids| ids.ids().to_vec()),
        ))
    }

    /// Restores a snapshot, regenerates all identities, and keeps workload execution stopped.
    ///
    /// # Errors
    ///
    /// Returns a validation, stale-snapshot, artifact, identity, adapter, API, or
    /// rollback error when restore cannot complete without violating the lifecycle policy.
    pub fn restore(
        &mut self,
        config: &RuntimeConfig,
        snapshot: &Snapshot,
    ) -> Result<RuntimeInstance, RuntimeError> {
        config.validate()?;
        if config.fingerprint() != snapshot.artifact_fingerprint {
            return Err(RuntimeError::StaleSnapshot(
                "snapshot artifact fingerprint does not match the requested runtime".to_owned(),
            ));
        }
        validate_absolute_path("snapshot path", &snapshot.snapshot_path)?;
        validate_absolute_path("snapshot memory path", &snapshot.memory_path)?;
        self.verify_artifacts(config)?;
        let workspace = config.workspace.clone_path();
        if let Err(error) = self
            .filesystem
            .clone_workspace(&config.workspace.source, &workspace)
        {
            let cleanup = self
                .filesystem
                .remove_workspace(&workspace)
                .err()
                .map_or_else(Vec::new, |cleanup_error| vec![cleanup_error.to_string()]);
            return Err(with_cleanup(error, &cleanup));
        }
        let workspace_cloned = true;
        let mut verity_opened = false;
        let mut process = None;
        let result = (|| {
            self.open_verity(config)?;
            verity_opened = true;
            let handle = self.start_jailer(config)?;
            process = Some(handle);
            self.api_call(ApiRequest {
                method: HttpMethod::Put,
                path: "/snapshot/load".to_owned(),
                body: format!(
                    "{{\"snapshot_path\":{},\"mem_file_path\":{},\"resume_vm\":true}}",
                    json_string(&snapshot.snapshot_path.to_string_lossy()),
                    json_string(&snapshot.memory_path.to_string_lossy())
                ),
            })?;
            let identities = IdentityBundle::generate(&mut self.identity_source)?;
            if identities
                .ids()
                .iter()
                .any(|identity| snapshot.forbidden_identities.contains(identity))
            {
                return Err(RuntimeError::StaleIdentity(
                    "restore generated an identity present in the snapshot".to_owned(),
                ));
            }
            Ok(RuntimeInstance {
                state: RuntimeState::IdentityRegenerated,
                process: handle,
                workspace: workspace.clone(),
                mapper_name: config.dm_verity.mapper_name.clone(),
                verity_opened: true,
                config_fingerprint: config.fingerprint(),
                identities: Some(identities),
            })
        })();
        match result {
            Ok(instance) => Ok(instance),
            Err(error) => {
                let cleanup =
                    self.rollback(process, verity_opened, workspace_cloned, &workspace, config);
                Err(with_cleanup(error, &cleanup))
            }
        }
    }

    /// Injects regenerated identities and leaves the workload stopped.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeError::InvalidState`] or [`RuntimeError::StaleIdentity`] when
    /// identities are not ready, or an API error when injection is rejected.
    pub fn inject_identity(&mut self, instance: &mut RuntimeInstance) -> Result<(), RuntimeError> {
        if instance.state != RuntimeState::IdentityRegenerated {
            return Err(RuntimeError::InvalidState {
                expected: "IdentityRegenerated".to_owned(),
                actual: format!("{:?}", instance.state),
            });
        }
        let identities = instance.identities.as_ref().ok_or_else(|| {
            RuntimeError::StaleIdentity(
                "identity regeneration state has no identity bundle".to_owned(),
            )
        })?;
        self.control_call(ApiRequest {
            method: HttpMethod::Put,
            path: "/actions/inject-identity".to_owned(),
            body: format!(
                "{{\"vm_id\":{},\"session_id\":{},\"request_id\":{},\"subject_id\":{},\"capability_id\":{}}}",
                json_string(&identities.vm_id.to_hex()),
                json_string(&identities.session_id.to_hex()),
                json_string(&identities.request_id.to_hex()),
                json_string(&identities.subject_id.to_hex()),
                json_string(&identities.capability_id.to_hex())
            ),
        })?;
        instance.state = RuntimeState::IdentityInjected;
        Ok(())
    }

    /// Starts workload execution only after identity injection has succeeded.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeError::InvalidState`] when identity injection has not completed,
    /// or an API error when the guest rejects the workload start request.
    pub fn start_workload(&mut self, instance: &mut RuntimeInstance) -> Result<(), RuntimeError> {
        if instance.state != RuntimeState::IdentityInjected {
            return Err(RuntimeError::InvalidState {
                expected: "IdentityInjected".to_owned(),
                actual: format!("{:?}", instance.state),
            });
        }
        self.control_call(ApiRequest {
            method: HttpMethod::Put,
            path: "/actions/start-workload".to_owned(),
            body: "{}".to_owned(),
        })?;
        instance.state = RuntimeState::Running;
        Ok(())
    }

    /// Stops the process, closes dm-verity, and removes the clone-specific workspace.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeError::InvalidState`] for an already stopped instance or
    /// [`RuntimeError::Cleanup`] when one or more shutdown actions fail.
    pub fn shutdown(
        &mut self,
        instance: &mut RuntimeInstance,
        config: &RuntimeConfig,
    ) -> Result<(), RuntimeError> {
        if matches!(instance.state, RuntimeState::Stopped | RuntimeState::New) {
            return Err(RuntimeError::InvalidState {
                expected: "a live runtime instance".to_owned(),
                actual: format!("{:?}", instance.state),
            });
        }
        let mut failures = Vec::new();
        if let Err(error) = self.command_runner.stop(instance.process) {
            failures.push(error.to_string());
        }
        if instance.verity_opened
            && let Err(error) = self.close_verity(config)
        {
            failures.push(error.to_string());
        }
        if let Err(error) = self.filesystem.remove_workspace(&instance.workspace) {
            failures.push(error.to_string());
        }
        if failures.is_empty() {
            instance.state = RuntimeState::Stopped;
            instance.verity_opened = false;
            Ok(())
        } else {
            Err(RuntimeError::Cleanup(failures.join("; ")))
        }
    }

    fn verify_artifacts(&mut self, config: &RuntimeConfig) -> Result<(), RuntimeError> {
        for (label, artifact) in [
            ("firecracker", &config.firecracker),
            ("kernel", &config.kernel),
            ("rootfs", &config.rootfs),
            ("dm-verity hash image", &config.verity_hash),
            ("jailer", &config.jailer),
            ("seccomp filter", &config.isolation.seccomp.filter),
        ] {
            let actual = sha256(&self.filesystem.read(&artifact.path)?);
            if actual != artifact.digest {
                return Err(RuntimeError::ArtifactDigestMismatch {
                    label: label.to_owned(),
                    path: artifact.path.clone(),
                    expected: artifact.digest,
                    actual,
                });
            }
        }
        Ok(())
    }

    fn open_verity(&mut self, config: &RuntimeConfig) -> Result<(), RuntimeError> {
        let command = CommandSpec::new(
            "veritysetup",
            [
                "open".to_owned(),
                "--readonly".to_owned(),
                config.dm_verity.data_device.display().to_string(),
                config.dm_verity.hash_device.display().to_string(),
                config.dm_verity.mapper_name.clone(),
                config.dm_verity.root_hash.to_hex(),
            ],
        );
        self.command_runner.run(&command).map(|_| ())
    }

    fn close_verity(&mut self, config: &RuntimeConfig) -> Result<(), RuntimeError> {
        let command = CommandSpec::new(
            "veritysetup",
            ["close".to_owned(), config.dm_verity.mapper_name.clone()],
        );
        self.command_runner.run(&command).map(|_| ())
    }

    fn start_jailer(&mut self, config: &RuntimeConfig) -> Result<ProcessHandle, RuntimeError> {
        let mut args = vec![
            "--id".to_owned(),
            config.workspace.clone_id.clone(),
            "--exec-file".to_owned(),
            config.firecracker.path.display().to_string(),
            "--api-sock".to_owned(),
            config.api_socket.display().to_string(),
            "--cgroup".to_owned(),
            config.isolation.cgroup.path.display().to_string(),
            "--seccomp-filter".to_owned(),
            config.isolation.seccomp.filter.path.display().to_string(),
        ];
        for flag in [
            "--new-user-ns",
            "--new-pid-ns",
            "--new-mount-ns",
            "--new-net-ns",
            "--new-ipc-ns",
            "--new-uts-ns",
        ] {
            args.push(flag.to_owned());
        }
        self.command_runner
            .start(&CommandSpec::new(&config.jailer.path, args))
    }

    fn configure_vm(&mut self, config: &RuntimeConfig) -> Result<(), RuntimeError> {
        self.api_call(ApiRequest {
            method: HttpMethod::Put,
            path: "/machine-config".to_owned(),
            body: format!(
                "{{\"vcpu_count\":{},\"mem_size_mib\":{}}}",
                config.vcpu_count, config.memory_mib
            ),
        })?;
        self.api_call(ApiRequest {
            method: HttpMethod::Put,
            path: "/boot-source".to_owned(),
            body: format!(
                "{{\"kernel_image_path\":{},\"boot_args\":{}}}",
                json_string(&config.kernel.path.to_string_lossy()),
                json_string(&config.boot_args)
            ),
        })?;
        self.api_call(ApiRequest {
            method: HttpMethod::Put,
            path: "/drives/rootfs".to_owned(),
            body: format!(
                "{{\"drive_id\":\"rootfs\",\"path_on_host\":{},\"is_root_device\":true,\"is_read_only\":true}}",
                json_string(&format!("/dev/mapper/{}", config.dm_verity.mapper_name))
            ),
        })?;
        self.api_call(ApiRequest {
            method: HttpMethod::Put,
            path: "/drives/workspace".to_owned(),
            body: format!(
                "{{\"drive_id\":\"workspace\",\"path_on_host\":{},\"is_root_device\":false,\"is_read_only\":false}}",
                json_string(&config.workspace.clone_path().to_string_lossy())
            ),
        })?;
        self.api_call(ApiRequest {
            method: HttpMethod::Put,
            path: "/vsock".to_owned(),
            body: format!(
                "{{\"guest_cid\":{},\"uds_path\":{}}}",
                config.vsock.guest_cid,
                json_string(&config.vsock.uds_path.to_string_lossy())
            ),
        })
    }

    fn api_call(&mut self, request: ApiRequest) -> Result<(), RuntimeError> {
        let response = self.api_client.request(&request)?;
        if !(200..300).contains(&response.status) {
            return Err(RuntimeError::ApiStatus {
                path: request.path,
                status: response.status,
                body: response.body,
            });
        }
        Ok(())
    }

    fn control_call(&mut self, request: ApiRequest) -> Result<(), RuntimeError> {
        let response = self.guest_client.request(&request)?;
        if !(200..300).contains(&response.status) {
            return Err(RuntimeError::ApiStatus {
                path: request.path,
                status: response.status,
                body: response.body,
            });
        }
        Ok(())
    }

    fn rollback(
        &mut self,
        process: Option<ProcessHandle>,
        verity_opened: bool,
        workspace_cloned: bool,
        workspace: &Path,
        config: &RuntimeConfig,
    ) -> Vec<String> {
        let mut failures = Vec::new();
        if let Some(process) = process
            && let Err(error) = self.command_runner.stop(process)
        {
            failures.push(error.to_string());
        }
        if verity_opened && let Err(error) = self.close_verity(config) {
            failures.push(error.to_string());
        }
        if workspace_cloned && let Err(error) = self.filesystem.remove_workspace(workspace) {
            failures.push(error.to_string());
        }
        failures
    }
}

fn with_cleanup(error: RuntimeError, cleanup: &[String]) -> RuntimeError {
    if cleanup.is_empty() {
        error
    } else {
        RuntimeError::Rollback {
            operation: error.to_string(),
            cleanup: cleanup.join("; "),
        }
    }
}

fn json_string(value: &str) -> String {
    const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut escaped = String::with_capacity(value.len() + 2);
    escaped.push('"');
    for character in value.chars() {
        match character {
            '"' => escaped.push_str("\\\""),
            '\\' => escaped.push_str("\\\\"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            character if character.is_control() => {
                let code = character as u32;
                escaped.push('\\');
                escaped.push('u');
                escaped.push(HEX_DIGITS[((code >> 12) & 0x0f) as usize] as char);
                escaped.push(HEX_DIGITS[((code >> 8) & 0x0f) as usize] as char);
                escaped.push(HEX_DIGITS[((code >> 4) & 0x0f) as usize] as char);
                escaped.push(HEX_DIGITS[(code & 0x0f) as usize] as char);
            }
            character => escaped.push(character),
        }
    }
    escaped.push('"');
    escaped
}

impl From<io::Error> for RuntimeError {
    fn from(error: io::Error) -> Self {
        Self::Io(error.to_string())
    }
}

/// Errors returned by validation, adapters, and lifecycle transitions.
#[derive(Debug, Eq, PartialEq)]
pub enum RuntimeError {
    /// Static configuration violates a security invariant.
    InvalidConfig(String),
    /// A path explicitly names the mutable `latest` artifact channel.
    LatestArtifactPath {
        /// Artifact or configuration label.
        label: String,
    },
    /// A network device was requested in the no-network profile.
    NetworkDeviceForbidden,
    /// A pinned file did not match its expected digest.
    ArtifactDigestMismatch {
        /// Artifact label.
        label: String,
        /// Artifact path.
        path: PathBuf,
        /// Expected digest.
        expected: Sha256Digest,
        /// Observed digest.
        actual: Sha256Digest,
    },
    /// An artifact or socket could not be accessed.
    Io(String),
    /// A command failed before reaching the requested lifecycle point.
    Command(String),
    /// A command returned a non-success status.
    CommandFailed {
        /// Executable path.
        program: String,
        /// Exit status.
        status: i32,
        /// Captured standard error.
        stderr: String,
    },
    /// An API transport or protocol failure occurred.
    Api(String),
    /// An API returned a non-2xx response.
    ApiStatus {
        /// Request path.
        path: String,
        /// HTTP status.
        status: u16,
        /// Response body.
        body: String,
    },
    /// An operation was attempted from the wrong state.
    InvalidState {
        /// Required state.
        expected: String,
        /// Current state.
        actual: String,
    },
    /// A clone destination already exists.
    WorkspaceAlreadyExists(PathBuf),
    /// A restored identity is duplicated or present in snapshot state.
    StaleIdentity(String),
    /// Snapshot metadata does not match the requested artifact set.
    StaleSnapshot(String),
    /// Identity encoding is invalid.
    InvalidIdentity(String),
    /// Cleanup after a failed operation had one or more failures.
    Rollback {
        /// Original operation failure.
        operation: String,
        /// Cleanup failures collected in reverse lifecycle order.
        cleanup: String,
    },
    /// Explicit shutdown cleanup had one or more failures.
    Cleanup(String),
}

impl Display for RuntimeError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidConfig(message) => write!(formatter, "invalid runtime config: {message}"),
            Self::LatestArtifactPath { label } => {
                write!(
                    formatter,
                    "{label} path uses forbidden mutable 'latest' channel"
                )
            }
            Self::NetworkDeviceForbidden => {
                write!(
                    formatter,
                    "network devices are forbidden in the Firecracker profile"
                )
            }
            Self::ArtifactDigestMismatch {
                label,
                path,
                expected,
                actual,
            } => write!(
                formatter,
                "{label} digest mismatch for {}: expected {}, got {}",
                path.display(),
                expected.to_hex(),
                actual.to_hex()
            ),
            Self::Io(message) => write!(formatter, "I/O failure: {message}"),
            Self::Command(message) => write!(formatter, "command failure: {message}"),
            Self::CommandFailed {
                program,
                status,
                stderr,
            } => {
                write!(
                    formatter,
                    "command {program} exited with {status}: {stderr}"
                )
            }
            Self::Api(message) => write!(formatter, "API failure: {message}"),
            Self::ApiStatus { path, status, body } => {
                write!(formatter, "API {path} returned HTTP {status}: {body}")
            }
            Self::InvalidState { expected, actual } => {
                write!(
                    formatter,
                    "invalid lifecycle state: expected {expected}, got {actual}"
                )
            }
            Self::WorkspaceAlreadyExists(path) => {
                write!(
                    formatter,
                    "workspace clone already exists: {}",
                    path.display()
                )
            }
            Self::StaleIdentity(message) => write!(formatter, "stale identity rejected: {message}"),
            Self::StaleSnapshot(message) => write!(formatter, "stale snapshot rejected: {message}"),
            Self::InvalidIdentity(message) => write!(formatter, "invalid identity: {message}"),
            Self::Rollback { operation, cleanup } => {
                write!(formatter, "{operation}; rollback failed: {cleanup}")
            }
            Self::Cleanup(message) => write!(formatter, "shutdown cleanup failed: {message}"),
        }
    }
}

impl Error for RuntimeError {}

#[cfg(test)]
mod tests {
    use super::{Sha256Digest, sha256};

    #[test]
    fn sha256_matches_nist_empty_vector() {
        assert_eq!(
            sha256(b"").to_hex(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn sha256_matches_nist_abc_vector() {
        assert_eq!(
            sha256(b"abc").to_hex(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn digest_parser_rejects_wrong_length_and_accepts_case() {
        assert!(Sha256Digest::from_hex("00").is_err());
        let digest = Sha256Digest::from_hex(
            "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855",
        )
        .expect("NIST digest must parse");
        assert_eq!(
            digest.to_hex(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }
}
