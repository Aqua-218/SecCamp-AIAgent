//! Firecracker runtime orchestration with pinned artifacts and fail-closed lifecycle rules.
//!
//! Production adapters execute commands, access the filesystem, and speak HTTP over a
//! Unix socket, while the same three boundaries are traits so lifecycle ordering and
//! rollback can be tested without starting a VM. Artifact digests use the audited `sha2`
//! implementation rather than a hand-written cryptographic primitive.

#![warn(clippy::all)]

use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::ffi::OsStr;
use std::fmt::{Display, Formatter};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::os::unix::net::UnixStream;
use std::path::{Component, Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use rustix::fs::{CWD, Mode, OFlags, RenameFlags, open, openat, renameat_with, statfs};
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
/// Maximum number of source filesystem entries copied into one workspace.
pub const MAX_WORKSPACE_ENTRIES: usize = 100_000;
/// Maximum source directory depth accepted during workspace cloning.
pub const MAX_WORKSPACE_DEPTH: usize = 64;
/// Maximum aggregate regular-file bytes copied into one workspace.
pub const MAX_WORKSPACE_BYTES: u64 = 1 << 30;
const ID_LENGTH: usize = 16;
const PROCESS_STOP_TIMEOUT: Duration = Duration::from_secs(5);
const CGROUP2_SUPER_MAGIC: i64 = 0x6367_7270;

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
    /// Host path inside the jail root that exposes the opened mapper device.
    pub jailed_device_path: PathBuf,
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
    /// Request a private user namespace (unsupported by the native jailer adapter).
    pub user: bool,
    /// Create a private PID namespace.
    pub pid: bool,
    /// Create a private mount namespace.
    pub mount: bool,
    /// Request creation of a private network namespace (unsupported by the native jailer adapter).
    pub network: bool,
    /// Request a private IPC namespace (unsupported by the native jailer adapter).
    pub ipc: bool,
    /// Request a private UTS namespace (unsupported by the native jailer adapter).
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
    /// CPU scheduling period in microseconds.
    pub cpu_period_micros: u64,
}

/// Cgroup hierarchy version understood by the Firecracker jailer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CgroupVersion {
    /// Unified cgroup v2 hierarchy.
    V2,
}

impl CgroupVersion {
    const fn jailer_value(self) -> &'static str {
        match self {
            Self::V2 => "2",
        }
    }
}

/// Privilege-drop and chroot settings passed to the Firecracker jailer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JailerConfig {
    /// Dedicated non-root POSIX user ID for Firecracker.
    pub uid: u32,
    /// Dedicated non-root POSIX group ID for Firecracker.
    pub gid: u32,
    /// Jailer chroot base directory.
    pub chroot_base_dir: PathBuf,
    /// Explicit cgroup hierarchy version.
    pub cgroup_version: CgroupVersion,
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
    /// Jailer privilege-drop, chroot, and cgroup settings.
    pub jailer_config: JailerConfig,
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
    #[allow(clippy::too_many_lines)] // Each branch validates a distinct security boundary field.
    pub fn validate(&self) -> Result<(), RuntimeError> {
        validate_artifact("firecracker", &self.firecracker)?;
        validate_artifact("kernel", &self.kernel)?;
        validate_artifact("rootfs", &self.rootfs)?;
        validate_artifact("dm-verity hash image", &self.verity_hash)?;
        validate_artifact("jailer", &self.jailer)?;
        validate_artifact("seccomp filter", &self.isolation.seccomp.filter)?;
        validate_absolute_path("API socket", &self.api_socket)?;
        validate_absolute_path("jailer chroot base", &self.jailer_config.chroot_base_dir)?;
        validate_absolute_path("workspace source", &self.workspace.source)?;
        validate_absolute_path("workspace clone root", &self.workspace.clone_root)?;
        validate_absolute_path("dm-verity hash device", &self.dm_verity.hash_device)?;
        validate_absolute_path(
            "jailed dm-verity device",
            &self.dm_verity.jailed_device_path,
        )?;
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
            || self.isolation.cgroup.cpu_period_micros == 0
        {
            return Err(RuntimeError::InvalidConfig(
                "cgroup memory, CPU quota, and CPU period limits must be non-zero".to_owned(),
            ));
        }
        if self.jailer_config.uid == 0 || self.jailer_config.gid == 0 {
            return Err(RuntimeError::InvalidConfig(
                "jailer UID and GID must be dedicated non-root IDs".to_owned(),
            ));
        }
        if !self.isolation.namespaces.pid || !self.isolation.namespaces.mount {
            return Err(RuntimeError::InvalidConfig(
                "jailer requires private PID and mount namespaces".to_owned(),
            ));
        }
        if self.isolation.namespaces.user
            || self.isolation.namespaces.network
            || self.isolation.namespaces.ipc
            || self.isolation.namespaces.uts
        {
            return Err(RuntimeError::InvalidConfig(
                "jailer does not support user, newly-created network, IPC, or UTS namespace switches; use a supported external namespace launcher"
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
        self.cgroup_parent()?;
        self.jail_path("API socket", &self.api_socket)?;
        self.jail_path("kernel", &self.kernel.path)?;
        self.jail_path(
            "jailed dm-verity device",
            &self.dm_verity.jailed_device_path,
        )?;
        self.jail_path("workspace clone", &self.workspace.clone_path())?;
        self.jail_path("seccomp filter", &self.isolation.seccomp.filter.path)?;
        self.jail_path("vsock UDS", &self.vsock.uds_path)?;
        Ok(())
    }

    fn jail_root(&self) -> Result<PathBuf, RuntimeError> {
        let executable_name = self
            .firecracker
            .path
            .file_name()
            .filter(|name| !name.is_empty())
            .ok_or_else(|| {
                RuntimeError::InvalidConfig(
                    "Firecracker executable path has no file name".to_owned(),
                )
            })?;
        Ok(self
            .jailer_config
            .chroot_base_dir
            .join(executable_name)
            .join(&self.workspace.clone_id)
            .join("root"))
    }

    fn jail_path(&self, label: &str, host_path: &Path) -> Result<PathBuf, RuntimeError> {
        jail_relative_path(&self.jail_root()?, label, host_path)
    }

    fn cgroup_parent(&self) -> Result<PathBuf, RuntimeError> {
        let relative = self
            .isolation
            .cgroup
            .path
            .strip_prefix("/sys/fs/cgroup")
            .map_err(|_| {
                RuntimeError::InvalidConfig(
                    "cgroup v2 path must be beneath /sys/fs/cgroup".to_owned(),
                )
            })?;
        if relative.file_name() != Some(OsStr::new(&self.workspace.clone_id)) {
            return Err(RuntimeError::InvalidConfig(
                "cgroup path must end with the workspace clone ID owned by the jailer".to_owned(),
            ));
        }
        let parent = relative
            .parent()
            .unwrap_or_else(|| Path::new(""))
            .to_path_buf();
        if parent.as_os_str().is_empty() {
            return Err(RuntimeError::InvalidConfig(
                "cgroup path must include a non-empty parent beneath /sys/fs/cgroup".to_owned(),
            ));
        }
        for component in parent.components() {
            let Component::Normal(component) = component else {
                return Err(RuntimeError::InvalidConfig(
                    "cgroup parent must be a relative normal path".to_owned(),
                ));
            };
            let component = component.to_str().ok_or_else(|| {
                RuntimeError::InvalidConfig("cgroup parent must be valid UTF-8".to_owned())
            })?;
            validate_safe_name("cgroup parent component", component)?;
        }
        Ok(parent)
    }

    /// Returns the compatibility fingerprint that must be persisted with a snapshot.
    ///
    /// Explicitly session-scoped host paths are normalized to their jail-visible paths because
    /// paused restore binds a fresh workspace and vsock while preserving the guest-visible
    /// resource contract. The clone ID, cgroup leaf, mapper name, and corresponding host paths
    /// are bound separately by [`Self::instance_fingerprint`]. Every non-overridable
    /// restore-relevant field is encoded here.
    #[must_use]
    #[allow(clippy::too_many_lines)] // The encoding deliberately enumerates the full config.
    pub fn snapshot_fingerprint(&self) -> Sha256Digest {
        let mut bytes = Vec::new();
        fingerprint_artifact(&mut bytes, "firecracker", &self.firecracker);
        fingerprint_jail_artifact(&mut bytes, "kernel", self, &self.kernel);
        fingerprint_artifact(&mut bytes, "rootfs", &self.rootfs);
        fingerprint_artifact(&mut bytes, "verity_hash", &self.verity_hash);
        fingerprint_path(
            &mut bytes,
            "dm_verity.data_device",
            &self.dm_verity.data_device,
        );
        fingerprint_path(
            &mut bytes,
            "dm_verity.hash_device",
            &self.dm_verity.hash_device,
        );
        fingerprint_bytes(
            &mut bytes,
            "dm_verity.root_hash",
            &self.dm_verity.root_hash.as_bytes(),
        );
        fingerprint_jail_path(
            &mut bytes,
            "dm_verity.jailed_device_path",
            self,
            &self.dm_verity.jailed_device_path,
        );
        fingerprint_path(&mut bytes, "workspace.source", &self.workspace.source);
        fingerprint_jail_path(
            &mut bytes,
            "workspace.clone_root",
            self,
            &self.workspace.clone_root,
        );
        fingerprint_artifact(&mut bytes, "jailer", &self.jailer);
        fingerprint_bytes(
            &mut bytes,
            "jailer.uid",
            &self.jailer_config.uid.to_be_bytes(),
        );
        fingerprint_bytes(
            &mut bytes,
            "jailer.gid",
            &self.jailer_config.gid.to_be_bytes(),
        );
        fingerprint_path(
            &mut bytes,
            "jailer.chroot_base_dir",
            &self.jailer_config.chroot_base_dir,
        );
        fingerprint_bytes(
            &mut bytes,
            "jailer.cgroup_version",
            self.jailer_config.cgroup_version.jailer_value().as_bytes(),
        );
        fingerprint_jail_path(&mut bytes, "api_socket", self, &self.api_socket);
        for (name, enabled) in [
            ("namespace.user", self.isolation.namespaces.user),
            ("namespace.pid", self.isolation.namespaces.pid),
            ("namespace.mount", self.isolation.namespaces.mount),
            ("namespace.network", self.isolation.namespaces.network),
            ("namespace.ipc", self.isolation.namespaces.ipc),
            ("namespace.uts", self.isolation.namespaces.uts),
        ] {
            fingerprint_bytes(&mut bytes, name, &[u8::from(enabled)]);
        }
        fingerprint_path(
            &mut bytes,
            "cgroup.parent",
            &self
                .cgroup_parent()
                .unwrap_or_else(|_| self.isolation.cgroup.path.clone()),
        );
        fingerprint_bytes(
            &mut bytes,
            "cgroup.memory_max_bytes",
            &self.isolation.cgroup.memory_max_bytes.to_be_bytes(),
        );
        fingerprint_bytes(
            &mut bytes,
            "cgroup.cpu_quota_micros",
            &self.isolation.cgroup.cpu_quota_micros.to_be_bytes(),
        );
        fingerprint_bytes(
            &mut bytes,
            "cgroup.cpu_period_micros",
            &self.isolation.cgroup.cpu_period_micros.to_be_bytes(),
        );
        fingerprint_jail_artifact(
            &mut bytes,
            "seccomp.filter",
            self,
            &self.isolation.seccomp.filter,
        );
        fingerprint_string_set(
            &mut bytes,
            "seccomp.blocked_syscalls",
            &self.isolation.seccomp.blocked_syscalls,
        );
        fingerprint_bytes(
            &mut bytes,
            "vsock.guest_cid",
            &self.vsock.guest_cid.to_be_bytes(),
        );
        fingerprint_string_set(&mut bytes, "network_devices", &self.network_devices);
        fingerprint_bytes(&mut bytes, "vcpu_count", &self.vcpu_count.to_be_bytes());
        fingerprint_bytes(&mut bytes, "memory_mib", &self.memory_mib.to_be_bytes());
        fingerprint_bytes(&mut bytes, "boot_args", self.boot_args.as_bytes());
        sha256(&bytes)
    }

    fn instance_fingerprint(&self) -> Sha256Digest {
        let mut bytes = Vec::new();
        fingerprint_bytes(
            &mut bytes,
            "restore_fingerprint",
            &self.snapshot_fingerprint().as_bytes(),
        );
        fingerprint_bytes(
            &mut bytes,
            "workspace.clone_id",
            self.workspace.clone_id.as_bytes(),
        );
        fingerprint_path(&mut bytes, "vsock.uds_path", &self.vsock.uds_path);
        fingerprint_path(
            &mut bytes,
            "workspace.clone_root",
            &self.workspace.clone_root,
        );
        fingerprint_path(&mut bytes, "api_socket", &self.api_socket);
        fingerprint_path(&mut bytes, "cgroup.path", &self.isolation.cgroup.path);
        fingerprint_path(&mut bytes, "kernel.path", &self.kernel.path);
        fingerprint_path(
            &mut bytes,
            "seccomp.filter.path",
            &self.isolation.seccomp.filter.path,
        );
        fingerprint_path(
            &mut bytes,
            "dm_verity.jailed_device_path",
            &self.dm_verity.jailed_device_path,
        );
        fingerprint_bytes(
            &mut bytes,
            "dm_verity.mapper_name",
            self.dm_verity.mapper_name.as_bytes(),
        );
        sha256(&bytes)
    }
}

fn jail_relative_path(
    jail_root: &Path,
    label: &str,
    host_path: &Path,
) -> Result<PathBuf, RuntimeError> {
    let relative = host_path.strip_prefix(jail_root).map_err(|_| {
        RuntimeError::InvalidConfig(format!(
            "{label} must be provisioned beneath jail root {}: {}",
            jail_root.display(),
            host_path.display()
        ))
    })?;
    if relative.as_os_str().is_empty() {
        return Err(RuntimeError::InvalidConfig(format!(
            "{label} cannot name the jail root itself"
        )));
    }
    Ok(Path::new("/").join(relative))
}

fn fingerprint_bytes(output: &mut Vec<u8>, name: &str, value: &[u8]) {
    output.extend_from_slice(&(name.len() as u64).to_be_bytes());
    output.extend_from_slice(name.as_bytes());
    output.extend_from_slice(&(value.len() as u64).to_be_bytes());
    output.extend_from_slice(value);
}

fn fingerprint_path(output: &mut Vec<u8>, name: &str, path: &Path) {
    fingerprint_bytes(output, name, path.as_os_str().as_bytes());
}

fn fingerprint_artifact(output: &mut Vec<u8>, name: &str, artifact: &PinnedArtifact) {
    fingerprint_path(output, &format!("{name}.path"), &artifact.path);
    fingerprint_bytes(
        output,
        &format!("{name}.digest"),
        &artifact.digest.as_bytes(),
    );
}

fn fingerprint_jail_path(output: &mut Vec<u8>, name: &str, config: &RuntimeConfig, path: &Path) {
    let normalized = config
        .jail_path(name, path)
        .unwrap_or_else(|_| path.to_path_buf());
    fingerprint_path(output, name, &normalized);
}

fn fingerprint_jail_artifact(
    output: &mut Vec<u8>,
    name: &str,
    config: &RuntimeConfig,
    artifact: &PinnedArtifact,
) {
    fingerprint_jail_path(output, &format!("{name}.path"), config, &artifact.path);
    fingerprint_bytes(
        output,
        &format!("{name}.digest"),
        &artifact.digest.as_bytes(),
    );
}

fn fingerprint_string_set(output: &mut Vec<u8>, name: &str, values: &[String]) {
    let mut sorted = values.iter().map(String::as_bytes).collect::<Vec<_>>();
    sorted.sort_unstable();
    fingerprint_bytes(
        output,
        &format!("{name}.count"),
        &(sorted.len() as u64).to_be_bytes(),
    );
    for (index, value) in sorted.into_iter().enumerate() {
        fingerprint_bytes(output, &format!("{name}.{index}"), value);
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

/// Host ownership boundary for one jailer-managed Firecracker process.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessOwnership {
    /// Dedicated cgroup v2 directory that must contain the live Firecracker task.
    pub cgroup_path: PathBuf,
    /// Pinned executable that the owned cgroup must be running.
    pub firecracker_executable: PathBuf,
    /// Pinned digest expected from the executable copied into the jail.
    pub firecracker_digest: Sha256Digest,
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
    /// Starts a jailer and binds the resulting Firecracker task to an observable ownership scope.
    ///
    /// A returned handle retains cleanup ownership even when startup has not produced a live
    /// Firecracker task yet. Callers must use [`Self::verify_running`] before performing VM API
    /// operations. Production adapters must ensure that verification and [`Self::stop`] cover
    /// every task in `ownership`, not just a short-lived launcher.
    ///
    /// # Errors
    ///
    /// Returns an adapter error when the ownership boundary cannot be established.
    fn start_owned(
        &mut self,
        _command: &CommandSpec,
        _ownership: &ProcessOwnership,
    ) -> Result<ProcessHandle, RuntimeError> {
        Err(RuntimeError::Command(
            "command runner does not implement owned Firecracker startup".to_owned(),
        ))
    }
    /// Verifies that the handle still owns a live Firecracker task.
    ///
    /// # Errors
    ///
    /// Returns an adapter error when no owned Firecracker task can be observed.
    fn verify_running(&mut self, _process: ProcessHandle) -> Result<(), RuntimeError> {
        Err(RuntimeError::Command(
            "command runner cannot verify an owned Firecracker task".to_owned(),
        ))
    }
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
    /// Computes a file digest for snapshot provenance checks.
    ///
    /// # Errors
    ///
    /// Returns an adapter error when the file cannot be read completely.
    fn digest(&mut self, path: &Path) -> Result<Sha256Digest, RuntimeError> {
        self.read(path).map(|bytes| sha256(&bytes))
    }
    /// Verifies that a jail-visible block device is the opened host dm-verity device.
    ///
    /// # Errors
    ///
    /// Returns an adapter error when the binding cannot be observed exactly. The default is
    /// fail-closed so a test or production adapter cannot accidentally omit this gate.
    fn verify_block_device_binding(
        &mut self,
        _source: &Path,
        _jailed_device: &Path,
    ) -> Result<(), RuntimeError> {
        Err(RuntimeError::Io(
            "filesystem adapter cannot verify jailed block-device bindings".to_owned(),
        ))
    }
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
    /// HTTP PATCH.
    Patch,
    /// HTTP DELETE.
    Delete,
}

impl HttpMethod {
    fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Put => "PUT",
            Self::Post => "POST",
            Self::Patch => "PATCH",
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
    /// Observes Firecracker's exported VM configuration and verifies restore resource binding.
    ///
    /// # Errors
    ///
    /// Returns an API or stale-snapshot error unless the exported workspace and vsock resources
    /// exactly equal the requested jail-visible values.
    fn verify_restore_resources(
        &mut self,
        workspace_path: &Path,
        vsock_uds_path: &Path,
        guest_cid: u32,
    ) -> Result<(), RuntimeError> {
        let response = self.request(&ApiRequest {
            method: HttpMethod::Get,
            path: "/vm/config".to_owned(),
            body: String::new(),
        })?;
        if !(200..300).contains(&response.status) {
            return Err(RuntimeError::ApiStatus {
                path: "/vm/config".to_owned(),
                status: response.status,
                body: response.body,
            });
        }
        verify_exported_restore_resources(&response.body, workspace_path, vsock_uds_path, guest_cid)
    }
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
    children: HashMap<u32, ManagedChild>,
}

#[derive(Debug)]
enum ManagedChild {
    Direct(Child),
    PendingOwned {
        launcher: Child,
        ownership: ProcessOwnership,
    },
    Isolated {
        launcher: Child,
        ownership: OwnedCgroup,
    },
}

#[derive(Clone, Debug)]
struct OwnedCgroup {
    path: PathBuf,
    identity: ObjectIdentity,
    firecracker_digest: Sha256Digest,
}

impl RealCommandRunner {
    /// Creates an empty process table.
    #[must_use]
    pub fn new() -> Self {
        Self {
            children: HashMap::new(),
        }
    }

    fn retain_unverified_owned_launch(
        &mut self,
        pid: u32,
        launcher: Child,
        requested: &ProcessOwnership,
        observed: Option<OwnedCgroup>,
    ) -> ProcessHandle {
        let managed = match observed {
            Some(ownership) => ManagedChild::Isolated {
                launcher,
                ownership,
            },
            None => ManagedChild::PendingOwned {
                launcher,
                ownership: requested.clone(),
            },
        };
        self.children.insert(pid, managed);
        ProcessHandle { pid }
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

fn spawn_detached(command: &CommandSpec) -> Result<Child, RuntimeError> {
    Command::new(&command.program)
        .args(&command.args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(RuntimeError::from)
}

fn open_owned_cgroup_file(
    ownership: &OwnedCgroup,
    name: &str,
    flags: OFlags,
) -> Result<File, RuntimeError> {
    let directory_fd = open(
        &ownership.path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| RuntimeError::Io(error.to_string()))?;
    let directory = File::from(directory_fd);
    let metadata = directory.metadata().map_err(RuntimeError::from)?;
    if !metadata.is_dir() || ObjectIdentity::from_metadata(&metadata) != ownership.identity {
        return Err(RuntimeError::Command(format!(
            "owned cgroup was replaced: {}",
            ownership.path.display()
        )));
    }
    let file_fd = openat(
        &directory,
        name,
        flags | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| RuntimeError::Io(error.to_string()))?;
    let file = File::from(file_fd);
    if !file.metadata().map_err(RuntimeError::from)?.is_file() {
        return Err(RuntimeError::Command(format!(
            "owned cgroup control is not a regular file: {name}"
        )));
    }
    Ok(file)
}

fn cgroup_tasks(ownership: &OwnedCgroup) -> Result<Vec<u32>, RuntimeError> {
    let file = open_owned_cgroup_file(ownership, "cgroup.procs", OFlags::RDONLY)?;
    let mut contents = Vec::new();
    file.take((MAX_COMMAND_OUTPUT_BYTES + 1) as u64)
        .read_to_end(&mut contents)
        .map_err(RuntimeError::from)?;
    if contents.len() > MAX_COMMAND_OUTPUT_BYTES {
        return Err(RuntimeError::Command(format!(
            "owned cgroup task list exceeds {MAX_COMMAND_OUTPUT_BYTES}-byte safety limit"
        )));
    }
    let contents = std::str::from_utf8(&contents).map_err(|_| {
        RuntimeError::Command("owned cgroup task list is not valid UTF-8".to_owned())
    })?;
    contents
        .lines()
        .map(|line| {
            if line.is_empty() || !line.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err(RuntimeError::Command(
                    "owned cgroup contains a malformed task identifier".to_owned(),
                ));
            }
            let pid = line.parse::<u32>().map_err(|_| {
                RuntimeError::Command("owned cgroup task identifier is out of range".to_owned())
            })?;
            if pid == 0 {
                return Err(RuntimeError::Command(
                    "owned cgroup contains task identifier zero".to_owned(),
                ));
            }
            Ok(pid)
        })
        .collect()
}

fn cgroup_has_firecracker(ownership: &OwnedCgroup, tasks: &[u32]) -> Result<bool, RuntimeError> {
    for pid in tasks {
        let path = PathBuf::from(format!("/proc/{pid}/exe"));
        let file = match File::open(&path) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(RuntimeError::from(error)),
        };
        if digest_reader(file)? == ownership.firecracker_digest {
            return Ok(true);
        }
    }
    Ok(false)
}

fn digest_file(path: &Path) -> Result<Sha256Digest, RuntimeError> {
    digest_reader(File::open(path).map_err(RuntimeError::from)?)
}

fn digest_reader(mut reader: impl Read) -> Result<Sha256Digest, RuntimeError> {
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024];
    loop {
        let count = reader.read(&mut buffer).map_err(RuntimeError::from)?;
        if count == 0 {
            return Ok(Sha256Digest(hasher.finalize().into()));
        }
        hasher.update(&buffer[..count]);
    }
}

fn reap_launcher(launcher: &mut Child, pid: u32) -> Result<(), RuntimeError> {
    match launcher.try_wait() {
        Ok(Some(_)) => Ok(()),
        Ok(None) => {
            if let Err(kill_error) = launcher.kill() {
                return match launcher.try_wait() {
                    Ok(Some(_)) => Ok(()),
                    Ok(None) => Err(RuntimeError::Command(format!(
                        "killing launcher {pid} failed: {kill_error}"
                    ))),
                    Err(wait_error) => Err(RuntimeError::Command(format!(
                        "killing launcher {pid} failed: {kill_error}; checking exit state failed: {wait_error}"
                    ))),
                };
            }
            launcher.wait().map(|_| ()).map_err(|error| {
                RuntimeError::Command(format!("waiting for launcher {pid} failed: {error}"))
            })
        }
        Err(error) => Err(RuntimeError::Command(format!(
            "checking launcher {pid} failed: {error}"
        ))),
    }
}

fn observe_owned_cgroup(ownership: &ProcessOwnership) -> Result<Option<OwnedCgroup>, RuntimeError> {
    match fs::symlink_metadata(&ownership.cgroup_path) {
        Ok(metadata) if !metadata.file_type().is_symlink() && metadata.is_dir() => {
            Ok(Some(OwnedCgroup {
                path: ownership.cgroup_path.clone(),
                identity: ObjectIdentity::from_metadata(&metadata),
                firecracker_digest: ownership.firecracker_digest,
            }))
        }
        Ok(_) => Err(RuntimeError::Command(format!(
            "owned cgroup is not a real directory: {}",
            ownership.cgroup_path.display()
        ))),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(RuntimeError::from(error)),
    }
}

fn stop_pending_owned(
    launcher: &mut Child,
    pid: u32,
    ownership: &ProcessOwnership,
) -> Result<(), RuntimeError> {
    // Once the launcher is reaped it cannot create another cgroup. Observe the exact expected
    // scope afterwards and kill every task if the jailer created it before exiting.
    reap_launcher(launcher, pid)?;
    if let Some(owned_cgroup) = observe_owned_cgroup(ownership)? {
        stop_owned_cgroup(launcher, pid, &owned_cgroup)?;
    }
    Ok(())
}

fn stop_owned_cgroup(
    launcher: &mut Child,
    pid: u32,
    ownership: &OwnedCgroup,
) -> Result<(), RuntimeError> {
    let tasks = cgroup_tasks(ownership)?;
    if !tasks.is_empty() {
        let mut kill = open_owned_cgroup_file(ownership, "cgroup.kill", OFlags::WRONLY)?;
        kill.write_all(b"1").map_err(|error| {
            RuntimeError::Command(format!(
                "killing tasks in owned cgroup {} failed: {error}",
                ownership.path.display()
            ))
        })?;
        let deadline = Instant::now() + PROCESS_STOP_TIMEOUT;
        loop {
            if cgroup_tasks(ownership)?.is_empty() {
                break;
            }
            if Instant::now() >= deadline {
                return Err(RuntimeError::Command(format!(
                    "owned cgroup {} still contains live tasks after kill",
                    ownership.path.display()
                )));
            }
            thread::sleep(Duration::from_millis(1));
        }
    }
    reap_launcher(launcher, pid)?;
    if !cgroup_tasks(ownership)?.is_empty() {
        return Err(RuntimeError::Command(format!(
            "owned cgroup {} gained a live task during cleanup",
            ownership.path.display()
        )));
    }
    let metadata = fs::symlink_metadata(&ownership.path).map_err(RuntimeError::from)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || ObjectIdentity::from_metadata(&metadata) != ownership.identity
    {
        return Err(RuntimeError::Command(format!(
            "owned cgroup was replaced before removal: {}",
            ownership.path.display()
        )));
    }
    if statfs(&ownership.path)
        .map_err(|error| RuntimeError::Io(error.to_string()))?
        .f_type
        == CGROUP2_SUPER_MAGIC
    {
        fs::remove_dir(&ownership.path).map_err(|error| {
            RuntimeError::Command(format!(
                "removing owned cgroup {} failed: {error}",
                ownership.path.display()
            ))
        })?;
    }
    Ok(())
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
        let child = spawn_detached(command)?;
        let pid = child.id();
        self.children.insert(pid, ManagedChild::Direct(child));
        Ok(ProcessHandle { pid })
    }

    #[allow(clippy::too_many_lines)] // Ownership setup and launch observation are one atomic gate.
    fn start_owned(
        &mut self,
        command: &CommandSpec,
        ownership: &ProcessOwnership,
    ) -> Result<ProcessHandle, RuntimeError> {
        validate_absolute_path("owned cgroup", &ownership.cgroup_path)?;
        validate_absolute_path(
            "owned Firecracker executable",
            &ownership.firecracker_executable,
        )?;
        let cgroup_parent = ownership.cgroup_path.parent().ok_or_else(|| {
            RuntimeError::Command("owned cgroup has no parent directory".to_owned())
        })?;
        ensure_directory_path(cgroup_parent, false)?;
        if statfs(cgroup_parent)
            .map_err(|error| RuntimeError::Io(error.to_string()))?
            .f_type
            != CGROUP2_SUPER_MAGIC
        {
            return Err(RuntimeError::Command(format!(
                "owned process scope is not on cgroup v2: {}",
                ownership.cgroup_path.display()
            )));
        }
        let executable_metadata =
            fs::metadata(&ownership.firecracker_executable).map_err(RuntimeError::from)?;
        if !executable_metadata.is_file() {
            return Err(RuntimeError::Command(format!(
                "owned Firecracker executable is not a regular file: {}",
                ownership.firecracker_executable.display()
            )));
        }
        if digest_file(&ownership.firecracker_executable)? != ownership.firecracker_digest {
            return Err(RuntimeError::Command(format!(
                "owned Firecracker executable digest changed before launch: {}",
                ownership.firecracker_executable.display()
            )));
        }
        match fs::symlink_metadata(&ownership.cgroup_path) {
            Ok(_) => {
                return Err(RuntimeError::Command(format!(
                    "owned cgroup already exists before launch: {}",
                    ownership.cgroup_path.display()
                )));
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(RuntimeError::from(error)),
        }
        let mut launcher = spawn_detached(command)?;
        let pid = launcher.id();
        let deadline = Instant::now() + PROCESS_STOP_TIMEOUT;
        let mut observed = None;
        loop {
            match observe_owned_cgroup(ownership) {
                Ok(Some(owned_cgroup)) => {
                    if observed.as_ref().is_some_and(|previous: &OwnedCgroup| {
                        previous.identity != owned_cgroup.identity
                    }) {
                        return Ok(
                            self.retain_unverified_owned_launch(pid, launcher, ownership, observed)
                        );
                    }
                    observed.get_or_insert_with(|| owned_cgroup.clone());
                    let Ok(tasks) = cgroup_tasks(&owned_cgroup) else {
                        return Ok(
                            self.retain_unverified_owned_launch(pid, launcher, ownership, observed)
                        );
                    };
                    match cgroup_has_firecracker(&owned_cgroup, &tasks) {
                        Ok(true) => {
                            self.children.insert(
                                pid,
                                ManagedChild::Isolated {
                                    launcher,
                                    ownership: owned_cgroup,
                                },
                            );
                            return Ok(ProcessHandle { pid });
                        }
                        Ok(false) => {}
                        Err(_) => {
                            return Ok(self.retain_unverified_owned_launch(
                                pid, launcher, ownership, observed,
                            ));
                        }
                    }
                }
                Ok(None) if observed.is_some() => {
                    return Ok(self.retain_unverified_owned_launch(pid, launcher, ownership, None));
                }
                Ok(None) => {}
                Err(_) => {
                    return Ok(
                        self.retain_unverified_owned_launch(pid, launcher, ownership, observed)
                    );
                }
            }
            match launcher.try_wait() {
                Ok(Some(_)) | Err(_) => {
                    return Ok(
                        self.retain_unverified_owned_launch(pid, launcher, ownership, observed)
                    );
                }
                Ok(None) => {}
            }
            if Instant::now() >= deadline {
                return Ok(self.retain_unverified_owned_launch(pid, launcher, ownership, observed));
            }
            thread::sleep(Duration::from_millis(1));
        }
    }

    fn verify_running(&mut self, process: ProcessHandle) -> Result<(), RuntimeError> {
        let managed = self
            .children
            .get_mut(&process.pid)
            .ok_or_else(|| RuntimeError::Command(format!("unknown process {}", process.pid)))?;
        match managed {
            ManagedChild::Direct(child) => match child.try_wait() {
                Ok(None) => Ok(()),
                Ok(Some(status)) => Err(RuntimeError::Command(format!(
                    "process {} exited before its runtime lease was issued with status {status}",
                    process.pid
                ))),
                Err(error) => Err(RuntimeError::Command(format!(
                    "checking process {} failed: {error}",
                    process.pid
                ))),
            },
            ManagedChild::PendingOwned {
                launcher,
                ownership,
            } => {
                let Some(owned_cgroup) = observe_owned_cgroup(ownership)? else {
                    return Err(RuntimeError::Command(format!(
                        "jailer {} has not created owned cgroup {}",
                        process.pid,
                        ownership.cgroup_path.display()
                    )));
                };
                let tasks = cgroup_tasks(&owned_cgroup)?;
                if cgroup_has_firecracker(&owned_cgroup, &tasks)? {
                    return Ok(());
                }
                let launcher_state = match launcher.try_wait() {
                    Ok(Some(status)) => format!("launcher exited with status {status}"),
                    Ok(None) => "launcher is still running".to_owned(),
                    Err(error) => format!("launcher state check failed: {error}"),
                };
                Err(RuntimeError::Command(format!(
                    "owned cgroup {} contains no pinned Firecracker task ({launcher_state})",
                    owned_cgroup.path.display()
                )))
            }
            ManagedChild::Isolated {
                launcher,
                ownership,
            } => {
                let tasks = cgroup_tasks(ownership)?;
                if cgroup_has_firecracker(ownership, &tasks)? {
                    return Ok(());
                }
                let launcher_state = match launcher.try_wait() {
                    Ok(Some(status)) => format!("launcher exited with status {status}"),
                    Ok(None) => "launcher is still running".to_owned(),
                    Err(error) => format!("launcher state check failed: {error}"),
                };
                Err(RuntimeError::Command(format!(
                    "owned cgroup {} contains no pinned Firecracker task ({launcher_state})",
                    ownership.path.display()
                )))
            }
        }
    }

    fn stop(&mut self, process: ProcessHandle) -> Result<(), RuntimeError> {
        let managed = self
            .children
            .get_mut(&process.pid)
            .ok_or_else(|| RuntimeError::Command(format!("unknown process {}", process.pid)))?;
        let result = match managed {
            ManagedChild::Direct(child) => reap_launcher(child, process.pid),
            ManagedChild::PendingOwned {
                launcher,
                ownership,
            } => stop_pending_owned(launcher, process.pid, ownership),
            ManagedChild::Isolated {
                launcher,
                ownership,
            } => stop_owned_cgroup(launcher, process.pid, ownership),
        };
        if result.is_ok() {
            self.children.remove(&process.pid);
        }
        result
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ObjectIdentity {
    device: u64,
    inode: u64,
}

impl ObjectIdentity {
    fn from_metadata(metadata: &fs::Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WorkspaceNodeKind {
    Directory,
    File,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct OwnedWorkspaceNode {
    identity: ObjectIdentity,
    kind: WorkspaceNodeKind,
}

#[derive(Clone, Debug)]
struct WorkspaceOwnership {
    parent: ObjectIdentity,
    root: ObjectIdentity,
    marker: PathBuf,
    marker_token: String,
    nodes: HashMap<PathBuf, OwnedWorkspaceNode>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SourceSnapshot {
    identity: ObjectIdentity,
    kind: WorkspaceNodeKind,
    length: u64,
    modified_seconds: i64,
    modified_nanos: i64,
    links: u64,
}

impl SourceSnapshot {
    fn from_metadata(path: &Path, metadata: &fs::Metadata) -> Result<Self, RuntimeError> {
        let file_type = metadata.file_type();
        let kind = if file_type.is_symlink() {
            return Err(RuntimeError::InvalidConfig(format!(
                "workspace contains forbidden symlink: {}",
                path.display()
            )));
        } else if metadata.is_dir() {
            WorkspaceNodeKind::Directory
        } else if metadata.is_file() {
            if metadata.nlink() > 1 {
                return Err(RuntimeError::InvalidConfig(format!(
                    "workspace contains forbidden hardlink: {}",
                    path.display()
                )));
            }
            WorkspaceNodeKind::File
        } else {
            return Err(RuntimeError::InvalidConfig(format!(
                "workspace contains unsupported filesystem object: {}",
                path.display()
            )));
        };
        Ok(Self {
            identity: ObjectIdentity::from_metadata(metadata),
            kind,
            length: metadata.len(),
            modified_seconds: metadata.mtime(),
            modified_nanos: metadata.mtime_nsec(),
            links: metadata.nlink(),
        })
    }

    fn matches(&self, metadata: &fs::Metadata) -> bool {
        self.identity == ObjectIdentity::from_metadata(metadata)
            && self.kind
                == if metadata.is_dir() {
                    WorkspaceNodeKind::Directory
                } else if metadata.is_file() {
                    WorkspaceNodeKind::File
                } else {
                    return false;
                }
            && self.length == metadata.len()
            && self.modified_seconds == metadata.mtime()
            && self.modified_nanos == metadata.mtime_nsec()
            && self.links == metadata.nlink()
    }
}

fn workspace_error(message: impl Into<String>) -> RuntimeError {
    RuntimeError::InvalidConfig(message.into())
}

fn metadata_at(path: &Path) -> Result<fs::Metadata, RuntimeError> {
    fs::symlink_metadata(path).map_err(RuntimeError::from)
}

fn ensure_directory_path(
    path: &Path,
    create_missing: bool,
) -> Result<ObjectIdentity, RuntimeError> {
    if !path.is_absolute() {
        return Err(workspace_error(format!(
            "workspace path must be absolute: {}",
            path.display()
        )));
    }
    let mut current = PathBuf::from("/");
    for component in path.components() {
        if component == Component::ParentDir {
            return Err(workspace_error(format!(
                "workspace path cannot contain '..': {}",
                path.display()
            )));
        }
        let Component::Normal(name) = component else {
            continue;
        };
        current.push(name);
        match fs::symlink_metadata(&current) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() || !metadata.is_dir() {
                    return Err(workspace_error(format!(
                        "workspace path component is not a real directory: {}",
                        current.display()
                    )));
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound && create_missing => {
                match fs::create_dir(&current) {
                    Ok(()) => {}
                    Err(create_error) if create_error.kind() == io::ErrorKind::AlreadyExists => {}
                    Err(create_error) => return Err(create_error.into()),
                }
                let metadata = metadata_at(&current)?;
                if metadata.file_type().is_symlink() || !metadata.is_dir() {
                    return Err(workspace_error(format!(
                        "workspace path component was replaced: {}",
                        current.display()
                    )));
                }
            }
            Err(error) => return Err(error.into()),
        }
    }
    Ok(ObjectIdentity::from_metadata(&metadata_at(path)?))
}

fn source_snapshot(path: &Path) -> Result<SourceSnapshot, RuntimeError> {
    SourceSnapshot::from_metadata(path, &metadata_at(path)?)
}

fn validate_destination_absence(path: &Path) -> Result<(), RuntimeError> {
    match fs::symlink_metadata(path) {
        Ok(_) => Err(RuntimeError::WorkspaceAlreadyExists(path.to_path_buf())),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn unique_staging_name(destination: &Path) -> PathBuf {
    static STAGING_COUNTER: AtomicU64 = AtomicU64::new(0);
    let counter = STAGING_COUNTER.fetch_add(1, Ordering::Relaxed);
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| {
            u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX)
        });
    let name = destination.file_name().map_or_else(
        || "workspace".to_owned(),
        |value| value.to_string_lossy().into_owned(),
    );
    destination.with_file_name(format!(
        ".{name}.staging-{}-{timestamp}-{counter}",
        std::process::id()
    ))
}

fn sort_workspace_paths(nodes: &HashMap<PathBuf, OwnedWorkspaceNode>) -> Vec<PathBuf> {
    let mut paths = nodes.keys().cloned().collect::<Vec<_>>();
    paths.sort_by_key(|path| std::cmp::Reverse(path.components().count()));
    paths
}

/// Production filesystem adapter with symlink-safe recursive workspace copying.
#[derive(Debug, Default)]
pub struct RealFileSystem {
    owned_workspaces: HashMap<PathBuf, WorkspaceOwnership>,
}

struct CloneContext {
    entries: usize,
    bytes: u64,
    nodes: HashMap<PathBuf, OwnedWorkspaceNode>,
}

struct PreparedClone {
    parent_identity: ObjectIdentity,
    stage: PathBuf,
    stage_identity: ObjectIdentity,
}

impl RealFileSystem {
    /// Creates a filesystem adapter.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn prepare_clone(
        &self,
        source: &Path,
        destination: &Path,
    ) -> Result<PreparedClone, RuntimeError> {
        if !source.is_absolute() || !destination.is_absolute() {
            return Err(workspace_error(
                "workspace source and destination must be absolute",
            ));
        }
        if source
            .components()
            .any(|component| component == Component::ParentDir)
            || destination
                .components()
                .any(|component| component == Component::ParentDir)
        {
            return Err(workspace_error(
                "workspace source and destination cannot contain '..'",
            ));
        }
        if source == destination
            || destination.starts_with(source)
            || source.starts_with(destination)
        {
            return Err(workspace_error(
                "workspace source and destination must not overlap",
            ));
        }
        ensure_directory_path(source, false)?;
        let parent = destination
            .parent()
            .ok_or_else(|| workspace_error("workspace clone has no parent directory"))?;
        let parent_identity = ensure_directory_path(parent, true)?;
        let source_root = source_snapshot(source)?;
        if source_root.kind != WorkspaceNodeKind::Directory {
            return Err(workspace_error("workspace source must be a directory"));
        }
        validate_destination_absence(destination)?;
        if self.owned_workspaces.contains_key(destination) {
            return Err(RuntimeError::WorkspaceAlreadyExists(
                destination.to_path_buf(),
            ));
        }

        let source_canonical = fs::canonicalize(source).map_err(RuntimeError::from)?;
        let parent_canonical = fs::canonicalize(parent).map_err(RuntimeError::from)?;
        let canonical_destination = parent_canonical.join(
            destination
                .file_name()
                .ok_or_else(|| workspace_error("workspace destination has no final component"))?,
        );
        if canonical_destination == source_canonical
            || canonical_destination.starts_with(&source_canonical)
            || source_canonical.starts_with(&canonical_destination)
        {
            return Err(workspace_error(
                "workspace source and destination must not alias or overlap",
            ));
        }

        let stage = loop {
            let candidate = unique_staging_name(destination);
            match fs::create_dir(&candidate) {
                Ok(()) => break candidate,
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        };
        let stage_identity = ObjectIdentity::from_metadata(&metadata_at(&stage)?);
        Ok(PreparedClone {
            parent_identity,
            stage,
            stage_identity,
        })
    }

    fn build_clone(
        source: &Path,
        prepared: &PreparedClone,
    ) -> Result<WorkspaceOwnership, RuntimeError> {
        let mut context = CloneContext {
            entries: 0,
            bytes: 0,
            nodes: HashMap::new(),
        };
        let result = (|| {
            Self::copy_entry(
                source,
                &prepared.stage,
                Path::new("."),
                0,
                true,
                &mut context,
            )?;
            let (marker, marker_token) = Self::create_marker(&prepared.stage, &mut context)?;
            let root_metadata = metadata_at(&prepared.stage)?;
            if ObjectIdentity::from_metadata(&root_metadata) != prepared.stage_identity {
                return Err(workspace_error("staging root was replaced before publish"));
            }
            Ok(WorkspaceOwnership {
                parent: prepared.parent_identity,
                root: prepared.stage_identity,
                marker,
                marker_token,
                nodes: context.nodes.clone(),
            })
        })();
        match result {
            Ok(ownership) => Ok(ownership),
            Err(error) => {
                let cleanup = Self::cleanup_known_tree(
                    &prepared.stage,
                    prepared.stage_identity,
                    &mut context.nodes,
                )
                .err()
                .map_or_else(Vec::new, |cleanup_error| vec![cleanup_error.to_string()]);
                Err(with_cleanup(error, &cleanup))
            }
        }
    }

    fn publish_clone(
        &mut self,
        destination: &Path,
        prepared: PreparedClone,
        ownership: WorkspaceOwnership,
    ) -> Result<(), RuntimeError> {
        let stage = prepared.stage;
        let stage_identity = prepared.stage_identity;
        let mut nodes = ownership.nodes.clone();
        if let Err(error) = validate_destination_absence(destination) {
            let cleanup = Self::cleanup_known_tree(&stage, stage_identity, &mut nodes)
                .err()
                .map_or_else(Vec::new, |cleanup_error| vec![cleanup_error.to_string()]);
            return Err(with_cleanup(error, &cleanup));
        }
        renameat_with(CWD, &stage, CWD, destination, RenameFlags::NOREPLACE).map_err(|error| {
            let cleanup = Self::cleanup_known_tree(&stage, stage_identity, &mut nodes)
                .err()
                .map_or_else(Vec::new, |cleanup_error| vec![cleanup_error.to_string()]);
            with_cleanup(
                workspace_error(format!(
                    "publishing workspace without replacement failed: {error}"
                )),
                &cleanup,
            )
        })?;
        self.owned_workspaces
            .insert(destination.to_path_buf(), ownership);
        let published = match metadata_at(destination) {
            Ok(metadata) => metadata,
            Err(error) => {
                let cleanup = self
                    .remove_workspace(destination)
                    .err()
                    .map_or_else(Vec::new, |cleanup_error| vec![cleanup_error.to_string()]);
                return Err(with_cleanup(error, &cleanup));
            }
        };
        let published_is_owned = self
            .owned_workspaces
            .get(destination)
            .is_some_and(|ownership| ObjectIdentity::from_metadata(&published) == ownership.root);
        if published.file_type().is_symlink() || !published.is_dir() || !published_is_owned {
            let error = workspace_error("workspace destination changed during atomic publish");
            let cleanup = self
                .remove_workspace(destination)
                .err()
                .map_or_else(Vec::new, |cleanup_error| vec![cleanup_error.to_string()]);
            return Err(with_cleanup(error, &cleanup));
        }
        Ok(())
    }

    fn copy_entry(
        source: &Path,
        destination: &Path,
        relative: &Path,
        depth: usize,
        root: bool,
        context: &mut CloneContext,
    ) -> Result<(), RuntimeError> {
        if depth > MAX_WORKSPACE_DEPTH {
            return Err(workspace_error(format!(
                "workspace traversal exceeds {MAX_WORKSPACE_DEPTH}-level depth limit"
            )));
        }
        context.entries = context
            .entries
            .checked_add(1)
            .ok_or_else(|| workspace_error("workspace entry count overflow"))?;
        if context.entries > MAX_WORKSPACE_ENTRIES {
            return Err(workspace_error(format!(
                "workspace contains more than {MAX_WORKSPACE_ENTRIES} entries"
            )));
        }

        let snapshot = source_snapshot(source)?;
        match snapshot.kind {
            WorkspaceNodeKind::Directory => Self::copy_directory(
                source,
                destination,
                relative,
                depth,
                root,
                snapshot,
                context,
            )?,
            WorkspaceNodeKind::File => {
                Self::copy_file(source, destination, relative, snapshot, context)?;
            }
        }
        Ok(())
    }

    fn copy_directory(
        source: &Path,
        destination: &Path,
        relative: &Path,
        depth: usize,
        root: bool,
        snapshot: SourceSnapshot,
        context: &mut CloneContext,
    ) -> Result<(), RuntimeError> {
        if root {
            let destination_metadata = metadata_at(destination)?;
            if destination_metadata.file_type().is_symlink() || !destination_metadata.is_dir() {
                return Err(workspace_error(format!(
                    "staging root is not a real directory: {}",
                    destination.display()
                )));
            }
        } else {
            fs::create_dir(destination).map_err(RuntimeError::from)?;
        }
        context.nodes.insert(
            relative.to_path_buf(),
            OwnedWorkspaceNode {
                identity: ObjectIdentity::from_metadata(&metadata_at(destination)?),
                kind: WorkspaceNodeKind::Directory,
            },
        );
        for entry in fs::read_dir(source).map_err(RuntimeError::from)? {
            let entry = entry.map_err(RuntimeError::from)?;
            let child_relative = if relative == Path::new(".") {
                PathBuf::from(entry.file_name())
            } else {
                relative.join(entry.file_name())
            };
            Self::copy_entry(
                &entry.path(),
                &destination.join(entry.file_name()),
                &child_relative,
                depth + 1,
                false,
                context,
            )?;
        }
        let current = metadata_at(source)?;
        if !snapshot.matches(&current) {
            return Err(workspace_error(format!(
                "workspace source changed while cloning: {}",
                source.display()
            )));
        }
        Ok(())
    }

    fn copy_file(
        source: &Path,
        destination: &Path,
        relative: &Path,
        snapshot: SourceSnapshot,
        context: &mut CloneContext,
    ) -> Result<(), RuntimeError> {
        context.bytes = context
            .bytes
            .checked_add(snapshot.length)
            .ok_or_else(|| workspace_error("workspace byte count overflow"))?;
        if context.bytes > MAX_WORKSPACE_BYTES {
            return Err(workspace_error(format!(
                "workspace exceeds {MAX_WORKSPACE_BYTES}-byte size limit"
            )));
        }
        let mut input = File::open(source).map_err(RuntimeError::from)?;
        let input_metadata = input.metadata().map_err(RuntimeError::from)?;
        if !snapshot.matches(&input_metadata) {
            return Err(workspace_error(format!(
                "workspace source changed before reading: {}",
                source.display()
            )));
        }
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(destination)
            .map_err(RuntimeError::from)?;
        let created_metadata = output.metadata().map_err(RuntimeError::from)?;
        if !created_metadata.is_file() || created_metadata.nlink() != 1 {
            return Err(workspace_error(format!(
                "staged workspace file is not exclusively owned: {}",
                destination.display()
            )));
        }
        let created_identity = ObjectIdentity::from_metadata(&created_metadata);
        context.nodes.insert(
            relative.to_path_buf(),
            OwnedWorkspaceNode {
                identity: created_identity,
                kind: WorkspaceNodeKind::File,
            },
        );
        let copied = io::copy(&mut input, &mut output).map_err(RuntimeError::from)?;
        output.flush().map_err(RuntimeError::from)?;
        output.sync_all().map_err(RuntimeError::from)?;
        if copied != snapshot.length {
            return Err(workspace_error(format!(
                "workspace source changed while reading: {}",
                source.display()
            )));
        }
        let current = metadata_at(source)?;
        if !snapshot.matches(&current) {
            return Err(workspace_error(format!(
                "workspace source changed while cloning: {}",
                source.display()
            )));
        }
        let destination_metadata = metadata_at(destination)?;
        if destination_metadata.file_type().is_symlink()
            || !destination_metadata.is_file()
            || destination_metadata.nlink() != 1
            || destination_metadata.len() != copied
            || ObjectIdentity::from_metadata(&destination_metadata) != created_identity
        {
            return Err(workspace_error(format!(
                "staged workspace file was replaced: {}",
                destination.display()
            )));
        }
        Ok(())
    }

    fn cleanup_known_tree(
        root: &Path,
        root_identity: ObjectIdentity,
        nodes: &mut HashMap<PathBuf, OwnedWorkspaceNode>,
    ) -> Result<(), RuntimeError> {
        let root_metadata = match fs::symlink_metadata(root) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error.into()),
        };
        if root_metadata.file_type().is_symlink()
            || !root_metadata.is_dir()
            || ObjectIdentity::from_metadata(&root_metadata) != root_identity
        {
            return Err(workspace_error(format!(
                "staging path was replaced and will not be removed: {}",
                root.display()
            )));
        }
        for relative in sort_workspace_paths(nodes) {
            if relative == Path::new(".") {
                continue;
            }
            let path = root.join(&relative);
            let metadata = match fs::symlink_metadata(&path) {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    nodes.remove(&relative);
                    continue;
                }
                Err(error) => return Err(error.into()),
            };
            let Some(expected) = nodes.get(&relative) else {
                continue;
            };
            if metadata.file_type().is_symlink()
                || ObjectIdentity::from_metadata(&metadata) != expected.identity
                || (expected.kind == WorkspaceNodeKind::Directory && !metadata.is_dir())
                || (expected.kind == WorkspaceNodeKind::File
                    && (!metadata.is_file() || metadata.nlink() != 1))
            {
                return Err(workspace_error(format!(
                    "owned staging entry was replaced and will not be removed: {}",
                    path.display()
                )));
            }
            let result = if expected.kind == WorkspaceNodeKind::Directory {
                fs::remove_dir(&path)
            } else {
                fs::remove_file(&path)
            };
            match result {
                Ok(()) => {
                    nodes.remove(&relative);
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    nodes.remove(&relative);
                }
                Err(error) => return Err(error.into()),
            }
        }
        let root_metadata = metadata_at(root)?;
        if ObjectIdentity::from_metadata(&root_metadata) != root_identity
            || root_metadata.file_type().is_symlink()
            || !root_metadata.is_dir()
        {
            return Err(workspace_error(format!(
                "staging path was replaced and will not be removed: {}",
                root.display()
            )));
        }
        fs::remove_dir(root).map_err(RuntimeError::from)
    }

    fn create_marker(
        stage: &Path,
        context: &mut CloneContext,
    ) -> Result<(PathBuf, String), RuntimeError> {
        let marker_name = format!(
            ".firecracker-runtime-owner-{}-{}",
            std::process::id(),
            context.entries
        );
        let marker_relative = PathBuf::from(&marker_name);
        let marker_token = format!("{marker_name}:{}", context.bytes);
        let marker_path = stage.join(&marker_relative);
        let mut marker = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&marker_path)
            .map_err(RuntimeError::from)?;
        marker
            .write_all(marker_token.as_bytes())
            .map_err(RuntimeError::from)?;
        marker.sync_all().map_err(RuntimeError::from)?;
        let metadata = metadata_at(&marker_path)?;
        if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.nlink() != 1 {
            return Err(workspace_error("workspace ownership marker was replaced"));
        }
        context.nodes.insert(
            marker_relative.clone(),
            OwnedWorkspaceNode {
                identity: ObjectIdentity::from_metadata(&metadata),
                kind: WorkspaceNodeKind::File,
            },
        );
        Ok((marker_relative, marker_token))
    }

    fn validate_marker(root: &Path, ownership: &WorkspaceOwnership) -> Result<(), RuntimeError> {
        let marker_path = root.join(&ownership.marker);
        let expected = ownership
            .nodes
            .get(&ownership.marker)
            .ok_or_else(|| workspace_error("workspace ownership marker is not recorded"))?;
        let metadata = metadata_at(&marker_path)?;
        if metadata.file_type().is_symlink()
            || !metadata.is_file()
            || metadata.nlink() != 1
            || ObjectIdentity::from_metadata(&metadata) != expected.identity
        {
            return Err(workspace_error(format!(
                "workspace ownership marker was replaced: {}",
                marker_path.display()
            )));
        }
        let file = File::open(&marker_path).map_err(RuntimeError::from)?;
        let opened_metadata = file.metadata().map_err(RuntimeError::from)?;
        if ObjectIdentity::from_metadata(&opened_metadata) != expected.identity {
            return Err(workspace_error(
                "workspace ownership marker changed while opening",
            ));
        }
        let mut contents = Vec::with_capacity(ownership.marker_token.len() + 1);
        file.take((ownership.marker_token.len() + 1) as u64)
            .read_to_end(&mut contents)
            .map_err(RuntimeError::from)?;
        if contents != ownership.marker_token.as_bytes() {
            return Err(workspace_error(
                "workspace ownership marker contents changed",
            ));
        }
        Ok(())
    }

    fn validate_owned_tree(
        root: &Path,
        ownership: &WorkspaceOwnership,
    ) -> Result<(), RuntimeError> {
        let root_metadata = metadata_at(root)?;
        if root_metadata.file_type().is_symlink()
            || !root_metadata.is_dir()
            || ObjectIdentity::from_metadata(&root_metadata) != ownership.root
        {
            return Err(workspace_error(format!(
                "workspace destination was replaced: {}",
                root.display()
            )));
        }
        Self::validate_marker(root, ownership)?;
        for (relative, expected) in &ownership.nodes {
            let path = root.join(relative);
            let metadata = metadata_at(&path)?;
            if metadata.file_type().is_symlink()
                || ObjectIdentity::from_metadata(&metadata) != expected.identity
                || (expected.kind == WorkspaceNodeKind::Directory && !metadata.is_dir())
                || (expected.kind == WorkspaceNodeKind::File
                    && (!metadata.is_file() || metadata.nlink() != 1))
            {
                return Err(workspace_error(format!(
                    "owned workspace entry was replaced: {}",
                    path.display()
                )));
            }
        }
        for (relative, expected) in &ownership.nodes {
            if expected.kind != WorkspaceNodeKind::Directory {
                continue;
            }
            let directory = root.join(relative);
            let before = metadata_at(&directory)?;
            for entry in fs::read_dir(&directory).map_err(RuntimeError::from)? {
                let entry = entry.map_err(RuntimeError::from)?;
                let child = if relative == Path::new(".") {
                    PathBuf::from(entry.file_name())
                } else {
                    relative.join(entry.file_name())
                };
                if !ownership.nodes.contains_key(&child) {
                    return Err(workspace_error(format!(
                        "workspace contains an unowned entry: {}",
                        directory.join(entry.file_name()).display()
                    )));
                }
            }
            let after = metadata_at(&directory)?;
            if ObjectIdentity::from_metadata(&before) != ObjectIdentity::from_metadata(&after) {
                return Err(workspace_error(format!(
                    "workspace directory changed while validating: {}",
                    directory.display()
                )));
            }
        }
        Ok(())
    }
}

impl FileSystem for RealFileSystem {
    fn read(&mut self, path: &Path) -> Result<Vec<u8>, RuntimeError> {
        fs::read(path).map_err(RuntimeError::from)
    }

    fn digest(&mut self, path: &Path) -> Result<Sha256Digest, RuntimeError> {
        digest_file(path)
    }

    fn verify_block_device_binding(
        &mut self,
        source: &Path,
        jailed_device: &Path,
    ) -> Result<(), RuntimeError> {
        validate_absolute_path("opened dm-verity device", source)?;
        validate_absolute_path("jailed dm-verity device", jailed_device)?;
        let jailed_parent = jailed_device.parent().ok_or_else(|| {
            RuntimeError::InvalidConfig("jailed dm-verity device has no parent".to_owned())
        })?;
        ensure_directory_path(jailed_parent, false)?;
        let jailed_link_metadata =
            fs::symlink_metadata(jailed_device).map_err(RuntimeError::from)?;
        if jailed_link_metadata.file_type().is_symlink() {
            return Err(RuntimeError::InvalidConfig(format!(
                "jailed dm-verity device cannot be a symbolic link: {}",
                jailed_device.display()
            )));
        }
        let source_metadata = fs::metadata(source).map_err(RuntimeError::from)?;
        let jailed_metadata = fs::metadata(jailed_device).map_err(RuntimeError::from)?;
        if !source_metadata.file_type().is_block_device()
            || !jailed_metadata.file_type().is_block_device()
            || source_metadata.rdev() != jailed_metadata.rdev()
        {
            return Err(RuntimeError::InvalidConfig(format!(
                "jailed dm-verity device is not the opened mapper {}: {}",
                source.display(),
                jailed_device.display()
            )));
        }
        Ok(())
    }

    fn clone_workspace(&mut self, source: &Path, destination: &Path) -> Result<(), RuntimeError> {
        let prepared = self.prepare_clone(source, destination)?;
        let ownership = Self::build_clone(source, &prepared)?;
        self.publish_clone(destination, prepared, ownership)
    }

    fn remove_workspace(&mut self, path: &Path) -> Result<(), RuntimeError> {
        let Some(ownership) = self.owned_workspaces.get_mut(path) else {
            return match fs::symlink_metadata(path) {
                Ok(_) => Err(workspace_error(format!(
                    "workspace path is not owned by this filesystem instance: {}",
                    path.display()
                ))),
                Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
                Err(error) => Err(error.into()),
            };
        };
        let root_metadata = match fs::symlink_metadata(path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                self.owned_workspaces.remove(path);
                return Ok(());
            }
            Err(error) => return Err(error.into()),
        };
        let parent = path
            .parent()
            .ok_or_else(|| workspace_error("workspace destination has no parent directory"))?;
        let parent_metadata = metadata_at(parent)?;
        if ObjectIdentity::from_metadata(&parent_metadata) != ownership.parent {
            return Err(workspace_error(format!(
                "workspace parent was replaced and will not be modified: {}",
                parent.display()
            )));
        }
        if root_metadata.file_type().is_symlink()
            || !root_metadata.is_dir()
            || ObjectIdentity::from_metadata(&root_metadata) != ownership.root
        {
            return Err(workspace_error(format!(
                "workspace destination was replaced and will not be removed: {}",
                path.display()
            )));
        }
        Self::validate_owned_tree(path, ownership)?;
        for relative in sort_workspace_paths(&ownership.nodes) {
            if relative == Path::new(".") {
                continue;
            }
            let child = path.join(&relative);
            let metadata = match fs::symlink_metadata(&child) {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error.into()),
            };
            let expected = ownership
                .nodes
                .get(&relative)
                .ok_or_else(|| workspace_error("workspace ownership record changed"))?;
            if metadata.file_type().is_symlink()
                || ObjectIdentity::from_metadata(&metadata) != expected.identity
                || (expected.kind == WorkspaceNodeKind::Directory && !metadata.is_dir())
                || (expected.kind == WorkspaceNodeKind::File
                    && (!metadata.is_file() || metadata.nlink() != 1))
            {
                return Err(workspace_error(format!(
                    "workspace entry was replaced and will not be removed: {}",
                    child.display()
                )));
            }
            let result = if expected.kind == WorkspaceNodeKind::Directory {
                fs::remove_dir(&child)
            } else {
                fs::remove_file(&child)
            };
            match result {
                Ok(()) => {
                    ownership.nodes.remove(&relative);
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    ownership.nodes.remove(&relative);
                }
                Err(error) => return Err(error.into()),
            }
        }
        let root_metadata = metadata_at(path)?;
        if ObjectIdentity::from_metadata(&root_metadata) != ownership.root
            || root_metadata.file_type().is_symlink()
            || !root_metadata.is_dir()
        {
            return Err(workspace_error(format!(
                "workspace destination was replaced and will not be removed: {}",
                path.display()
            )));
        }
        fs::remove_dir(path).map_err(RuntimeError::from)?;
        self.owned_workspaces.remove(path);
        Ok(())
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

    fn is_zero(self) -> bool {
        self.0.iter().all(|byte| *byte == 0)
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
    /// Creates a host-allocated identity bundle after validating its domains.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeError::InvalidIdentity`] for an all-zero ID or
    /// [`RuntimeError::StaleIdentity`] when two domains reuse an ID.
    pub fn new(
        vm_id: IdentityId,
        session_id: IdentityId,
        request_id: IdentityId,
        subject_id: IdentityId,
        capability_id: IdentityId,
    ) -> Result<Self, RuntimeError> {
        let bundle = Self {
            vm_id,
            session_id,
            request_id,
            subject_id,
            capability_id,
        };
        bundle.validate(None)?;
        Ok(bundle)
    }

    fn generate(source: &mut impl IdentitySource) -> Result<Self, RuntimeError> {
        let bundle = Self {
            vm_id: source.generate()?,
            session_id: source.generate()?,
            request_id: source.generate()?,
            subject_id: source.generate()?,
            capability_id: source.generate()?,
        };
        bundle.validate(None)?;
        Ok(bundle)
    }

    fn validate(&self, forbidden: Option<&[IdentityId]>) -> Result<(), RuntimeError> {
        let ids = self.ids();
        if ids.iter().any(|identity| identity.is_zero()) {
            return Err(RuntimeError::InvalidIdentity(
                "identity bundle contains an all-zero identity".to_owned(),
            ));
        }
        let unique = ids.iter().copied().collect::<HashSet<_>>();
        if unique.len() != ids.len() {
            return Err(RuntimeError::StaleIdentity(
                "identity bundle contains duplicate IDs".to_owned(),
            ));
        }
        if forbidden.is_some_and(|forbidden| ids.iter().any(|id| forbidden.contains(id))) {
            return Err(RuntimeError::StaleIdentity(
                "identity bundle contains an identity present in the snapshot".to_owned(),
            ));
        }
        Ok(())
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

/// Unverified persisted snapshot manifest.
///
/// This value is never accepted by restore directly. Call [`Runtime::verify_snapshot`] to bind
/// the declared provenance to the current file bytes and obtain a [`VerifiedSnapshot`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Snapshot {
    /// Firecracker snapshot state path.
    pub snapshot_path: PathBuf,
    /// Firecracker memory file path.
    pub memory_path: PathBuf,
    /// Restore-compatibility fingerprint required for restore.
    pub artifact_fingerprint: Sha256Digest,
    /// Expected digest of the Firecracker state file.
    pub snapshot_digest: Sha256Digest,
    /// Expected digest of the guest memory file.
    pub memory_digest: Sha256Digest,
    forbidden_identities: Vec<IdentityId>,
}

impl Snapshot {
    /// Creates externally persisted snapshot metadata with identities that restore must not reuse.
    #[must_use]
    pub fn new(
        snapshot_path: impl Into<PathBuf>,
        memory_path: impl Into<PathBuf>,
        artifact_fingerprint: Sha256Digest,
        snapshot_digest: Sha256Digest,
        memory_digest: Sha256Digest,
        forbidden_identities: Vec<IdentityId>,
    ) -> Self {
        Self {
            snapshot_path: snapshot_path.into(),
            memory_path: memory_path.into(),
            artifact_fingerprint,
            snapshot_digest,
            memory_digest,
            forbidden_identities,
        }
    }
}

/// Snapshot provenance whose declared paths, content digests, and runtime compatibility were
/// verified through the runtime's filesystem boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedSnapshot {
    manifest: Snapshot,
}

impl VerifiedSnapshot {
    /// Returns the verified Firecracker state path.
    #[must_use]
    pub fn snapshot_path(&self) -> &Path {
        &self.manifest.snapshot_path
    }

    /// Returns the verified guest memory path.
    #[must_use]
    pub fn memory_path(&self) -> &Path {
        &self.manifest.memory_path
    }

    /// Returns the verified restore-compatibility fingerprint.
    #[must_use]
    pub const fn artifact_fingerprint(&self) -> Sha256Digest {
        self.manifest.artifact_fingerprint
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
    /// Fresh identities were acknowledged while the restored VM remains paused.
    IdentityAcknowledgedPaused,
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
    process_stopped: bool,
    workspace: PathBuf,
    jail_root: PathBuf,
    workspace_removed: bool,
    mapper_name: String,
    verity_opened: bool,
    restore_fingerprint: Sha256Digest,
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
    pending_cleanup: Option<PendingCleanup>,
}

#[derive(Debug)]
struct PendingCleanup {
    process: Option<ProcessHandle>,
    verity_opened: bool,
    workspace: Option<PathBuf>,
    mapper_name: String,
}

impl PendingCleanup {
    fn is_complete(&self) -> bool {
        self.process.is_none() && !self.verity_opened && self.workspace.is_none()
    }
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
            pending_cleanup: None,
        }
    }

    /// Returns whether cleanup from a failed launch or restore remains pending.
    #[must_use]
    pub const fn has_pending_cleanup(&self) -> bool {
        self.pending_cleanup.is_some()
    }

    /// Retries cleanup retained after a failed launch or restore.
    ///
    /// Cleanup is dependency ordered: a live process prevents dm-verity closure and
    /// an open dm-verity mapping prevents workspace removal. Successfully completed
    /// stages are not repeated on subsequent calls.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeError::Cleanup`] when the first still-pending cleanup stage
    /// fails. The remaining state is retained for another retry.
    pub fn retry_pending_cleanup(&mut self) -> Result<(), RuntimeError> {
        let Some(mut pending) = self.pending_cleanup.take() else {
            return Ok(());
        };
        let failures = self.cleanup_pending(&mut pending);
        if !pending.is_complete() {
            self.pending_cleanup = Some(pending);
        }
        if failures.is_empty() {
            Ok(())
        } else {
            Err(RuntimeError::Cleanup(failures.join("; ")))
        }
    }

    fn ensure_no_pending_cleanup(&self) -> Result<(), RuntimeError> {
        if self.pending_cleanup.is_some() {
            Err(RuntimeError::InvalidState {
                expected: "failed launch cleanup to complete".to_owned(),
                actual: "cleanup pending".to_owned(),
            })
        } else {
            Ok(())
        }
    }

    /// Launches a pinned pre-session VM with workload execution still gated.
    ///
    /// # Errors
    ///
    /// Returns a validation, artifact, adapter, API, or rollback error when any
    /// launch precondition or lifecycle step fails. When rollback also fails,
    /// [`Self::retry_pending_cleanup`] can retry the retained cleanup state.
    pub fn launch(&mut self, config: &RuntimeConfig) -> Result<RuntimeInstance, RuntimeError> {
        self.ensure_no_pending_cleanup()?;
        config.validate()?;
        self.verify_artifacts(config)?;
        let workspace = config.workspace.clone_path();
        if let Err(error) = self
            .filesystem
            .clone_workspace(&config.workspace.source, &workspace)
        {
            let cleanup =
                self.rollback(None, false, true, &workspace, &config.dm_verity.mapper_name);
            return Err(with_cleanup(error, &cleanup));
        }
        let workspace_cloned = true;
        let mut verity_opened = false;
        let mut process = None;

        let result = (|| {
            self.open_verity(config)?;
            verity_opened = true;
            self.verify_verity_binding(config)?;
            let handle = self.start_jailer(config)?;
            process = Some(handle);
            self.command_runner.verify_running(handle)?;
            self.configure_vm(config)?;
            self.api_call(ApiRequest {
                method: HttpMethod::Put,
                path: "/actions".to_owned(),
                body: r#"{"action_type":"InstanceStart"}"#.to_owned(),
            })?;
            self.command_runner.verify_running(handle)?;
            Ok(RuntimeInstance {
                state: RuntimeState::WorkloadStopped,
                process: handle,
                process_stopped: false,
                workspace: workspace.clone(),
                jail_root: config.jail_root()?,
                workspace_removed: false,
                mapper_name: config.dm_verity.mapper_name.clone(),
                verity_opened: true,
                restore_fingerprint: config.snapshot_fingerprint(),
                config_fingerprint: config.instance_fingerprint(),
                identities: None,
            })
        })();
        match result {
            Ok(instance) => Ok(instance),
            Err(error) => {
                let cleanup = self.rollback(
                    process,
                    verity_opened,
                    workspace_cloned,
                    &workspace,
                    &config.dm_verity.mapper_name,
                );
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
    ) -> Result<VerifiedSnapshot, RuntimeError> {
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
        let snapshot_jail_path =
            jail_relative_path(&instance.jail_root, "snapshot path", &snapshot_path)?;
        let memory_jail_path =
            jail_relative_path(&instance.jail_root, "snapshot memory path", &memory_path)?;
        self.api_call(ApiRequest {
            method: HttpMethod::Put,
            path: "/snapshot/create".to_owned(),
            body: format!(
                "{{\"snapshot_type\":\"Full\",\"snapshot_path\":{},\"mem_file_path\":{}}}",
                json_string(&snapshot_jail_path.to_string_lossy()),
                json_string(&memory_jail_path.to_string_lossy())
            ),
        })?;
        let snapshot_digest = self.filesystem.digest(&snapshot_path)?;
        let memory_digest = self.filesystem.digest(&memory_path)?;
        let manifest = Snapshot::new(
            snapshot_path,
            memory_path,
            instance.restore_fingerprint,
            snapshot_digest,
            memory_digest,
            instance
                .identities
                .as_ref()
                .map_or_else(Vec::new, |ids| ids.ids().to_vec()),
        );
        instance.state = RuntimeState::Snapshotted;
        Ok(VerifiedSnapshot { manifest })
    }

    /// Verifies persisted snapshot provenance before it can enter the restore API.
    ///
    /// Verification binds both exact host paths, both file digests, the full runtime
    /// compatibility fingerprint, and the forbidden identity set into a private
    /// [`VerifiedSnapshot`]. Restore repeats the content checks immediately before any side
    /// effect to narrow the filesystem abstraction's unavoidable path-to-open race.
    ///
    /// # Errors
    ///
    /// Returns a validation, stale-snapshot, or digest mismatch error when the manifest does not
    /// identify the exact files and runtime requested.
    pub fn verify_snapshot(
        &mut self,
        config: &RuntimeConfig,
        snapshot: Snapshot,
    ) -> Result<VerifiedSnapshot, RuntimeError> {
        self.verify_snapshot_manifest(config, &snapshot)?;
        Ok(VerifiedSnapshot { manifest: snapshot })
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
        snapshot: &VerifiedSnapshot,
    ) -> Result<RuntimeInstance, RuntimeError> {
        self.restore_generated(config, snapshot)
    }

    fn restore_generated(
        &mut self,
        config: &RuntimeConfig,
        snapshot: &VerifiedSnapshot,
    ) -> Result<RuntimeInstance, RuntimeError> {
        self.ensure_no_pending_cleanup()?;
        config.validate()?;
        self.verify_snapshot_manifest(config, &snapshot.manifest)?;
        let snapshot = &snapshot.manifest;
        validate_absolute_path("snapshot path", &snapshot.snapshot_path)?;
        validate_absolute_path("snapshot memory path", &snapshot.memory_path)?;
        let snapshot_jail_path = config.jail_path("snapshot path", &snapshot.snapshot_path)?;
        let memory_jail_path = config.jail_path("snapshot memory path", &snapshot.memory_path)?;
        self.verify_artifacts(config)?;
        let workspace = config.workspace.clone_path();
        if let Err(error) = self
            .filesystem
            .clone_workspace(&config.workspace.source, &workspace)
        {
            let cleanup =
                self.rollback(None, false, true, &workspace, &config.dm_verity.mapper_name);
            return Err(with_cleanup(error, &cleanup));
        }
        let workspace_cloned = true;
        let mut verity_opened = false;
        let mut process = None;
        let result = (|| {
            self.open_verity(config)?;
            verity_opened = true;
            self.verify_verity_binding(config)?;
            let handle = self.start_jailer(config)?;
            process = Some(handle);
            self.command_runner.verify_running(handle)?;
            self.verify_snapshot_manifest(config, snapshot)?;
            self.api_call(ApiRequest {
                method: HttpMethod::Put,
                path: "/snapshot/load".to_owned(),
                body: format!(
                    "{{\"snapshot_path\":{},\"mem_file_path\":{},\"resume_vm\":false,\"vsock_override\":{{\"uds_path\":{}}}}}",
                    json_string(&snapshot_jail_path.to_string_lossy()),
                    json_string(&memory_jail_path.to_string_lossy()),
                    json_string(&config.jail_path("vsock UDS", &config.vsock.uds_path)?.to_string_lossy())
                ),
            })?;
            self.bind_restored_workspace(config)?;
            self.command_runner.verify_running(handle)?;
            let identities = IdentityBundle::generate(&mut self.identity_source)?;
            identities.validate(Some(&snapshot.forbidden_identities))?;
            Ok(RuntimeInstance {
                state: RuntimeState::IdentityRegenerated,
                process: handle,
                process_stopped: false,
                workspace: workspace.clone(),
                jail_root: config.jail_root()?,
                workspace_removed: false,
                mapper_name: config.dm_verity.mapper_name.clone(),
                verity_opened: true,
                restore_fingerprint: config.snapshot_fingerprint(),
                config_fingerprint: config.instance_fingerprint(),
                identities: Some(identities),
            })
        })();
        match result {
            Ok(instance) => Ok(instance),
            Err(error) => {
                let cleanup = self.rollback(
                    process,
                    verity_opened,
                    workspace_cloned,
                    &workspace,
                    &config.dm_verity.mapper_name,
                );
                Err(with_cleanup(error, &cleanup))
            }
        }
    }

    /// Restores a snapshot using identities allocated and validated by the host.
    ///
    /// # Errors
    ///
    /// Returns a validation, stale-snapshot, stale-identity, adapter, API, or
    /// rollback error when the supplied bundle or restore lifecycle is invalid.
    pub fn restore_with_identities(
        &mut self,
        config: &RuntimeConfig,
        snapshot: &VerifiedSnapshot,
        identities: IdentityBundle,
    ) -> Result<RuntimeInstance, RuntimeError> {
        identities.validate(Some(&snapshot.manifest.forbidden_identities))?;
        self.restore_with_allocated_identities(config, snapshot, identities)
    }

    /// Alias for [`Self::restore_with_identities`] with an explicit bundle name.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::restore_with_identities`].
    pub fn restore_with_identity_bundle(
        &mut self,
        config: &RuntimeConfig,
        snapshot: &VerifiedSnapshot,
        identities: IdentityBundle,
    ) -> Result<RuntimeInstance, RuntimeError> {
        self.restore_with_identities(config, snapshot, identities)
    }

    fn restore_with_allocated_identities(
        &mut self,
        config: &RuntimeConfig,
        snapshot: &VerifiedSnapshot,
        identities: IdentityBundle,
    ) -> Result<RuntimeInstance, RuntimeError> {
        self.ensure_no_pending_cleanup()?;
        config.validate()?;
        self.verify_snapshot_manifest(config, &snapshot.manifest)?;
        let snapshot = &snapshot.manifest;
        validate_absolute_path("snapshot path", &snapshot.snapshot_path)?;
        validate_absolute_path("snapshot memory path", &snapshot.memory_path)?;
        let snapshot_jail_path = config.jail_path("snapshot path", &snapshot.snapshot_path)?;
        let memory_jail_path = config.jail_path("snapshot memory path", &snapshot.memory_path)?;
        self.verify_artifacts(config)?;
        let workspace = config.workspace.clone_path();
        if let Err(error) = self
            .filesystem
            .clone_workspace(&config.workspace.source, &workspace)
        {
            let cleanup =
                self.rollback(None, false, true, &workspace, &config.dm_verity.mapper_name);
            return Err(with_cleanup(error, &cleanup));
        }
        let workspace_cloned = true;
        let mut verity_opened = false;
        let mut process = None;
        let result = (|| {
            self.open_verity(config)?;
            verity_opened = true;
            self.verify_verity_binding(config)?;
            let handle = self.start_jailer(config)?;
            process = Some(handle);
            self.command_runner.verify_running(handle)?;
            self.verify_snapshot_manifest(config, snapshot)?;
            self.api_call(ApiRequest {
                method: HttpMethod::Put,
                path: "/snapshot/load".to_owned(),
                body: format!(
                    "{{\"snapshot_path\":{},\"mem_file_path\":{},\"resume_vm\":false,\"vsock_override\":{{\"uds_path\":{}}}}}",
                    json_string(&snapshot_jail_path.to_string_lossy()),
                    json_string(&memory_jail_path.to_string_lossy()),
                    json_string(&config.jail_path("vsock UDS", &config.vsock.uds_path)?.to_string_lossy())
                ),
            })?;
            self.bind_restored_workspace(config)?;
            self.command_runner.verify_running(handle)?;
            Ok(RuntimeInstance {
                state: RuntimeState::IdentityRegenerated,
                process: handle,
                process_stopped: false,
                workspace: workspace.clone(),
                jail_root: config.jail_root()?,
                workspace_removed: false,
                mapper_name: config.dm_verity.mapper_name.clone(),
                verity_opened: true,
                restore_fingerprint: config.snapshot_fingerprint(),
                config_fingerprint: config.instance_fingerprint(),
                identities: Some(identities),
            })
        })();
        match result {
            Ok(instance) => Ok(instance),
            Err(error) => {
                let cleanup = self.rollback(
                    process,
                    verity_opened,
                    workspace_cloned,
                    &workspace,
                    &config.dm_verity.mapper_name,
                );
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
        if !matches!(
            instance.state,
            RuntimeState::IdentityRegenerated | RuntimeState::IdentityAcknowledgedPaused
        ) {
            return Err(RuntimeError::InvalidState {
                expected: "IdentityRegenerated or IdentityAcknowledgedPaused".to_owned(),
                actual: format!("{:?}", instance.state),
            });
        }
        if instance.state == RuntimeState::IdentityRegenerated {
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
            instance.state = RuntimeState::IdentityAcknowledgedPaused;
        }
        self.api_call(ApiRequest {
            method: HttpMethod::Patch,
            path: "/vm".to_owned(),
            body: r#"{"state":"Resumed"}"#.to_owned(),
        })?;
        self.command_runner.verify_running(instance.process)?;
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
    /// Returns [`RuntimeError::InvalidConfig`] when the cleanup-owning fields do not
    /// match the instance, [`RuntimeError::InvalidState`] for a non-live instance, or
    /// [`RuntimeError::Cleanup`] when one or more shutdown actions fail.
    pub fn shutdown(
        &mut self,
        instance: &mut RuntimeInstance,
        config: &RuntimeConfig,
    ) -> Result<(), RuntimeError> {
        if instance.state == RuntimeState::Stopped {
            return Ok(());
        }
        if config.instance_fingerprint() != instance.config_fingerprint
            || config.dm_verity.mapper_name != instance.mapper_name
            || config.workspace.clone_path() != instance.workspace
        {
            return Err(RuntimeError::InvalidConfig(
                "shutdown config does not match the runtime instance".to_owned(),
            ));
        }
        if instance.state == RuntimeState::New {
            return Err(RuntimeError::InvalidState {
                expected: "a live runtime instance".to_owned(),
                actual: format!("{:?}", instance.state),
            });
        }
        let mut failures = Vec::new();
        if !instance.process_stopped {
            match self.command_runner.stop(instance.process) {
                Ok(()) => instance.process_stopped = true,
                Err(error) => failures.push(error.to_string()),
            }
        }
        if instance.process_stopped && instance.verity_opened {
            match self.close_verity_mapper(&instance.mapper_name) {
                Ok(()) => instance.verity_opened = false,
                Err(error) => failures.push(error.to_string()),
            }
        }
        if instance.process_stopped && !instance.verity_opened && !instance.workspace_removed {
            match self.filesystem.remove_workspace(&instance.workspace) {
                Ok(()) => instance.workspace_removed = true,
                Err(error) => failures.push(error.to_string()),
            }
        }
        if failures.is_empty() {
            instance.state = RuntimeState::Stopped;
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

    fn verify_snapshot_manifest(
        &mut self,
        config: &RuntimeConfig,
        snapshot: &Snapshot,
    ) -> Result<(), RuntimeError> {
        if config.snapshot_fingerprint() != snapshot.artifact_fingerprint {
            return Err(RuntimeError::StaleSnapshot(
                "snapshot compatibility fingerprint does not match the requested runtime"
                    .to_owned(),
            ));
        }
        validate_absolute_path("snapshot path", &snapshot.snapshot_path)?;
        validate_absolute_path("snapshot memory path", &snapshot.memory_path)?;
        config.jail_path("snapshot path", &snapshot.snapshot_path)?;
        config.jail_path("snapshot memory path", &snapshot.memory_path)?;
        for (label, path, expected) in [
            (
                "snapshot state",
                &snapshot.snapshot_path,
                snapshot.snapshot_digest,
            ),
            (
                "snapshot memory",
                &snapshot.memory_path,
                snapshot.memory_digest,
            ),
        ] {
            let actual = self.filesystem.digest(path)?;
            if actual != expected {
                return Err(RuntimeError::SnapshotDigestMismatch {
                    label: label.to_owned(),
                    path: path.clone(),
                    expected,
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

    fn close_verity_mapper(&mut self, mapper_name: &str) -> Result<(), RuntimeError> {
        let command = CommandSpec::new("veritysetup", ["close".to_owned(), mapper_name.to_owned()]);
        self.command_runner.run(&command).map(|_| ())
    }

    fn verify_verity_binding(&mut self, config: &RuntimeConfig) -> Result<(), RuntimeError> {
        self.filesystem.verify_block_device_binding(
            &Path::new("/dev/mapper").join(&config.dm_verity.mapper_name),
            &config.dm_verity.jailed_device_path,
        )
    }

    fn start_jailer(&mut self, config: &RuntimeConfig) -> Result<ProcessHandle, RuntimeError> {
        let command = Self::jailer_command(config)?;
        self.command_runner.start_owned(
            &command,
            &ProcessOwnership {
                cgroup_path: config.isolation.cgroup.path.clone(),
                firecracker_executable: config.firecracker.path.clone(),
                firecracker_digest: config.firecracker.digest,
            },
        )
    }

    fn jailer_command(config: &RuntimeConfig) -> Result<CommandSpec, RuntimeError> {
        let api_socket = config.jail_path("API socket", &config.api_socket)?;
        let seccomp_filter =
            config.jail_path("seccomp filter", &config.isolation.seccomp.filter.path)?;
        let parent_cgroup = config.cgroup_parent()?;
        let args = vec![
            "--id".to_owned(),
            config.workspace.clone_id.clone(),
            "--exec-file".to_owned(),
            config.firecracker.path.display().to_string(),
            "--uid".to_owned(),
            config.jailer_config.uid.to_string(),
            "--gid".to_owned(),
            config.jailer_config.gid.to_string(),
            "--cgroup-version".to_owned(),
            config
                .jailer_config
                .cgroup_version
                .jailer_value()
                .to_owned(),
            "--parent-cgroup".to_owned(),
            parent_cgroup.display().to_string(),
            "--cgroup".to_owned(),
            format!("memory.max={}", config.isolation.cgroup.memory_max_bytes),
            "--cgroup".to_owned(),
            format!(
                "cpu.max={} {}",
                config.isolation.cgroup.cpu_quota_micros, config.isolation.cgroup.cpu_period_micros
            ),
            "--chroot-base-dir".to_owned(),
            config.jailer_config.chroot_base_dir.display().to_string(),
            "--new-pid-ns".to_owned(),
            "--".to_owned(),
            "--api-sock".to_owned(),
            api_socket.display().to_string(),
            "--seccomp-filter".to_owned(),
            seccomp_filter.display().to_string(),
        ];
        Ok(CommandSpec::new(&config.jailer.path, args))
    }

    fn bind_restored_workspace(&mut self, config: &RuntimeConfig) -> Result<(), RuntimeError> {
        let workspace_path = config.jail_path("workspace clone", &config.workspace.clone_path())?;
        let vsock_path = config.jail_path("vsock UDS", &config.vsock.uds_path)?;
        self.api_call(ApiRequest {
            method: HttpMethod::Patch,
            path: "/drives/workspace".to_owned(),
            body: format!(
                "{{\"drive_id\":\"workspace\",\"path_on_host\":{}}}",
                json_string(&workspace_path.to_string_lossy())
            ),
        })?;
        self.api_client.verify_restore_resources(
            &workspace_path,
            &vsock_path,
            config.vsock.guest_cid,
        )
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
                json_string(
                    &config
                        .jail_path("kernel", &config.kernel.path)?
                        .to_string_lossy()
                ),
                json_string(&config.boot_args)
            ),
        })?;
        self.api_call(ApiRequest {
            method: HttpMethod::Put,
            path: "/drives/rootfs".to_owned(),
            body: format!(
                "{{\"drive_id\":\"rootfs\",\"path_on_host\":{},\"is_root_device\":true,\"is_read_only\":true}}",
                json_string(
                    &config
                        .jail_path(
                            "jailed dm-verity device",
                            &config.dm_verity.jailed_device_path,
                        )?
                        .to_string_lossy()
                )
            ),
        })?;
        self.api_call(ApiRequest {
            method: HttpMethod::Put,
            path: "/drives/workspace".to_owned(),
            body: format!(
                "{{\"drive_id\":\"workspace\",\"path_on_host\":{},\"is_root_device\":false,\"is_read_only\":false}}",
                json_string(
                    &config
                        .jail_path("workspace clone", &config.workspace.clone_path())?
                        .to_string_lossy()
                )
            ),
        })?;
        self.api_call(ApiRequest {
            method: HttpMethod::Put,
            path: "/vsock".to_owned(),
            body: format!(
                "{{\"guest_cid\":{},\"uds_path\":{}}}",
                config.vsock.guest_cid,
                json_string(
                    &config
                        .jail_path("vsock UDS", &config.vsock.uds_path)?
                        .to_string_lossy()
                )
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
        mapper_name: &str,
    ) -> Vec<String> {
        debug_assert!(self.pending_cleanup.is_none());
        let mut pending = PendingCleanup {
            process,
            verity_opened,
            workspace: workspace_cloned.then(|| workspace.to_path_buf()),
            mapper_name: mapper_name.to_owned(),
        };
        let failures = self.cleanup_pending(&mut pending);
        if !pending.is_complete() {
            self.pending_cleanup = Some(pending);
        }
        failures
    }

    fn cleanup_pending(&mut self, pending: &mut PendingCleanup) -> Vec<String> {
        if let Some(process) = pending.process {
            match self.command_runner.stop(process) {
                Ok(()) => pending.process = None,
                Err(error) => return vec![error.to_string()],
            }
        }
        if pending.verity_opened {
            match self.close_verity_mapper(&pending.mapper_name) {
                Ok(()) => pending.verity_opened = false,
                Err(error) => return vec![error.to_string()],
            }
        }
        if let Some(workspace) = pending.workspace.as_deref() {
            match self.filesystem.remove_workspace(workspace) {
                Ok(()) => pending.workspace = None,
                Err(error) => return vec![error.to_string()],
            }
        }
        Vec::new()
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

#[derive(Debug)]
enum JsonValue {
    Object(Vec<(String, JsonValue)>),
    Array(Vec<JsonValue>),
    String(String),
    Number(String),
    Simple,
}

impl JsonValue {
    fn member(&self, name: &str) -> Option<&Self> {
        let Self::Object(members) = self else {
            return None;
        };
        members
            .iter()
            .find_map(|(key, value)| (key == name).then_some(value))
    }

    fn string(&self) -> Option<&str> {
        match self {
            Self::String(value) => Some(value),
            _ => None,
        }
    }
}

struct JsonParser<'a> {
    input: &'a str,
    index: usize,
}

impl<'a> JsonParser<'a> {
    fn parse(input: &'a str) -> Result<JsonValue, RuntimeError> {
        let mut parser = Self { input, index: 0 };
        let value = parser.value(0)?;
        parser.whitespace();
        if parser.index != input.len() {
            return Err(RuntimeError::Api(
                "exported VM configuration has trailing JSON data".to_owned(),
            ));
        }
        Ok(value)
    }

    fn value(&mut self, depth: usize) -> Result<JsonValue, RuntimeError> {
        if depth > MAX_WORKSPACE_DEPTH {
            return Err(RuntimeError::Api(
                "exported VM configuration exceeds JSON nesting limit".to_owned(),
            ));
        }
        self.whitespace();
        match self.peek() {
            Some(b'{') => self.object(depth + 1),
            Some(b'[') => self.array(depth + 1),
            Some(b'"') => self.string().map(JsonValue::String),
            Some(b'-' | b'0'..=b'9') => self.number().map(JsonValue::Number),
            Some(b't') => self.literal("true"),
            Some(b'f') => self.literal("false"),
            Some(b'n') => self.literal("null"),
            _ => Err(RuntimeError::Api(
                "exported VM configuration contains invalid JSON".to_owned(),
            )),
        }
    }

    fn object(&mut self, depth: usize) -> Result<JsonValue, RuntimeError> {
        self.expect(b'{')?;
        let mut members = Vec::new();
        self.whitespace();
        if self.take(b'}') {
            return Ok(JsonValue::Object(members));
        }
        loop {
            self.whitespace();
            let key = self.string()?;
            if members.iter().any(|(existing, _)| existing == &key) {
                return Err(RuntimeError::Api(format!(
                    "exported VM configuration contains duplicate JSON key '{key}'"
                )));
            }
            self.whitespace();
            self.expect(b':')?;
            let value = self.value(depth)?;
            members.push((key, value));
            self.whitespace();
            if self.take(b'}') {
                return Ok(JsonValue::Object(members));
            }
            self.expect(b',')?;
        }
    }

    fn array(&mut self, depth: usize) -> Result<JsonValue, RuntimeError> {
        self.expect(b'[')?;
        let mut values = Vec::new();
        self.whitespace();
        if self.take(b']') {
            return Ok(JsonValue::Array(values));
        }
        loop {
            values.push(self.value(depth)?);
            self.whitespace();
            if self.take(b']') {
                return Ok(JsonValue::Array(values));
            }
            self.expect(b',')?;
        }
    }

    fn string(&mut self) -> Result<String, RuntimeError> {
        self.expect(b'"')?;
        let mut output = String::new();
        loop {
            let remainder = self.input.get(self.index..).ok_or_else(|| {
                RuntimeError::Api("exported VM configuration has an unterminated string".to_owned())
            })?;
            let character = remainder.chars().next().ok_or_else(|| {
                RuntimeError::Api("exported VM configuration has an unterminated string".to_owned())
            })?;
            self.index += character.len_utf8();
            match character {
                '"' => return Ok(output),
                '\\' => output.push(self.escape()?),
                character if character.is_control() => {
                    return Err(RuntimeError::Api(
                        "exported VM configuration string contains a control character".to_owned(),
                    ));
                }
                character => output.push(character),
            }
        }
    }

    fn escape(&mut self) -> Result<char, RuntimeError> {
        let byte = self.next().ok_or_else(|| {
            RuntimeError::Api("exported VM configuration has an incomplete escape".to_owned())
        })?;
        match byte {
            b'"' => Ok('"'),
            b'\\' => Ok('\\'),
            b'/' => Ok('/'),
            b'b' => Ok('\u{0008}'),
            b'f' => Ok('\u{000c}'),
            b'n' => Ok('\n'),
            b'r' => Ok('\r'),
            b't' => Ok('\t'),
            b'u' => {
                let value = self.hex_quad()?;
                char::from_u32(u32::from(value)).ok_or_else(|| {
                    RuntimeError::Api(
                        "exported VM configuration contains an unsupported Unicode surrogate"
                            .to_owned(),
                    )
                })
            }
            _ => Err(RuntimeError::Api(
                "exported VM configuration contains an invalid escape".to_owned(),
            )),
        }
    }

    fn hex_quad(&mut self) -> Result<u16, RuntimeError> {
        let mut value = 0_u16;
        for _ in 0..4 {
            let digit = self.next().and_then(|byte| match byte {
                b'0'..=b'9' => Some(u16::from(byte - b'0')),
                b'a'..=b'f' => Some(u16::from(byte - b'a') + 10),
                b'A'..=b'F' => Some(u16::from(byte - b'A') + 10),
                _ => None,
            });
            value = value
                .checked_mul(16)
                .and_then(|value| digit.map(|digit| value + digit))
                .ok_or_else(|| {
                    RuntimeError::Api(
                        "exported VM configuration contains an invalid Unicode escape".to_owned(),
                    )
                })?;
        }
        Ok(value)
    }

    fn number(&mut self) -> Result<String, RuntimeError> {
        let start = self.index;
        while self
            .peek()
            .is_some_and(|byte| matches!(byte, b'-' | b'+' | b'.' | b'e' | b'E' | b'0'..=b'9'))
        {
            self.index += 1;
        }
        let number = &self.input[start..self.index];
        if number.parse::<f64>().is_err() {
            return Err(RuntimeError::Api(
                "exported VM configuration contains an invalid number".to_owned(),
            ));
        }
        Ok(number.to_owned())
    }

    fn literal(&mut self, literal: &str) -> Result<JsonValue, RuntimeError> {
        if self.input[self.index..].starts_with(literal) {
            self.index += literal.len();
            Ok(JsonValue::Simple)
        } else {
            Err(RuntimeError::Api(
                "exported VM configuration contains an invalid literal".to_owned(),
            ))
        }
    }

    fn whitespace(&mut self) {
        while self.peek().is_some_and(|byte| byte.is_ascii_whitespace()) {
            self.index += 1;
        }
    }

    fn expect(&mut self, expected: u8) -> Result<(), RuntimeError> {
        if self.take(expected) {
            Ok(())
        } else {
            Err(RuntimeError::Api(
                "exported VM configuration contains malformed JSON".to_owned(),
            ))
        }
    }

    fn take(&mut self, expected: u8) -> bool {
        if self.peek() == Some(expected) {
            self.index += 1;
            true
        } else {
            false
        }
    }

    fn peek(&self) -> Option<u8> {
        self.input.as_bytes().get(self.index).copied()
    }

    fn next(&mut self) -> Option<u8> {
        let byte = self.peek()?;
        self.index += 1;
        Some(byte)
    }
}

fn verify_exported_restore_resources(
    body: &str,
    workspace_path: &Path,
    vsock_uds_path: &Path,
    guest_cid: u32,
) -> Result<(), RuntimeError> {
    let root = JsonParser::parse(body)?;
    let JsonValue::Array(drives) = root.member("drives").ok_or_else(|| {
        RuntimeError::StaleSnapshot("exported VM config omitted drives".to_owned())
    })?
    else {
        return Err(RuntimeError::StaleSnapshot(
            "exported VM config drives field is not an array".to_owned(),
        ));
    };
    let workspace_matches = drives
        .iter()
        .filter(|drive| drive.member("drive_id").and_then(JsonValue::string) == Some("workspace"))
        .filter(|drive| {
            drive.member("path_on_host").and_then(JsonValue::string)
                == Some(workspace_path.to_string_lossy().as_ref())
        })
        .count();
    if workspace_matches != 1 {
        return Err(RuntimeError::StaleSnapshot(
            "exported VM config does not bind exactly one workspace drive to the requested path"
                .to_owned(),
        ));
    }
    let vsock = root.member("vsock").ok_or_else(|| {
        RuntimeError::StaleSnapshot("exported VM config omitted vsock".to_owned())
    })?;
    let path_matches = vsock.member("uds_path").and_then(JsonValue::string)
        == Some(vsock_uds_path.to_string_lossy().as_ref());
    let cid_matches = vsock.member("guest_cid").and_then(|value| match value {
        JsonValue::Number(number) => number.parse::<u32>().ok(),
        _ => None,
    }) == Some(guest_cid);
    if !path_matches || !cid_matches {
        return Err(RuntimeError::StaleSnapshot(
            "exported VM config does not bind vsock to the requested path and guest CID".to_owned(),
        ));
    }
    Ok(())
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
    /// Snapshot state or memory bytes did not match verified provenance.
    SnapshotDigestMismatch {
        /// Snapshot component label.
        label: String,
        /// Observed component path.
        path: PathBuf,
        /// Provenance digest.
        expected: Sha256Digest,
        /// Observed content digest.
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
    /// Snapshot metadata does not match the requested runtime configuration.
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
            }
            | Self::SnapshotDigestMismatch {
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
    use std::cell::RefCell;
    use std::collections::VecDeque;
    use std::rc::Rc;

    use super::*;

    #[derive(Default)]
    struct CleanupRunner {
        events: Vec<String>,
        stop_failures: VecDeque<bool>,
        close_failures: VecDeque<bool>,
    }

    impl CommandRunner for CleanupRunner {
        fn run(&mut self, command: &CommandSpec) -> Result<CommandOutput, RuntimeError> {
            self.events.push(format!(
                "run:{} {}",
                command.program.display(),
                command.args.join(" ")
            ));
            if self.close_failures.pop_front().unwrap_or(false) {
                Err(RuntimeError::Command("close failed".to_owned()))
            } else {
                Ok(CommandOutput {
                    status: 0,
                    stdout: Vec::new(),
                    stderr: Vec::new(),
                })
            }
        }

        fn start(&mut self, _command: &CommandSpec) -> Result<ProcessHandle, RuntimeError> {
            Err(RuntimeError::Command("unexpected start".to_owned()))
        }

        fn stop(&mut self, process: ProcessHandle) -> Result<(), RuntimeError> {
            self.events.push(format!("stop:{}", process.pid));
            if self.stop_failures.pop_front().unwrap_or(false) {
                Err(RuntimeError::Command("stop failed".to_owned()))
            } else {
                Ok(())
            }
        }
    }

    #[derive(Default)]
    struct CleanupFileSystem {
        events: Vec<String>,
        remove_failures: VecDeque<bool>,
    }

    impl FileSystem for CleanupFileSystem {
        fn read(&mut self, _path: &Path) -> Result<Vec<u8>, RuntimeError> {
            Err(RuntimeError::Io("unexpected read".to_owned()))
        }

        fn clone_workspace(
            &mut self,
            _source: &Path,
            _destination: &Path,
        ) -> Result<(), RuntimeError> {
            Err(RuntimeError::Io("unexpected clone".to_owned()))
        }

        fn remove_workspace(&mut self, path: &Path) -> Result<(), RuntimeError> {
            self.events.push(format!("remove:{}", path.display()));
            if self.remove_failures.pop_front().unwrap_or(false) {
                Err(RuntimeError::Io("remove failed".to_owned()))
            } else {
                Ok(())
            }
        }
    }

    struct UnusedApi;

    impl ApiClient for UnusedApi {
        fn request(&mut self, _request: &ApiRequest) -> Result<ApiResponse, RuntimeError> {
            Err(RuntimeError::Api("unexpected request".to_owned()))
        }
    }

    struct UnusedIdentitySource;

    impl IdentitySource for UnusedIdentitySource {
        fn generate(&mut self) -> Result<IdentityId, RuntimeError> {
            Err(RuntimeError::InvalidIdentity(
                "unexpected generation".to_owned(),
            ))
        }
    }

    fn cleanup_runtime(
        stop_failures: impl IntoIterator<Item = bool>,
        close_failures: impl IntoIterator<Item = bool>,
    ) -> Runtime<CleanupRunner, CleanupFileSystem, UnusedApi, UnusedApi, UnusedIdentitySource> {
        Runtime::new(
            CleanupRunner {
                events: Vec::new(),
                stop_failures: stop_failures.into_iter().collect(),
                close_failures: close_failures.into_iter().collect(),
            },
            CleanupFileSystem::default(),
            UnusedApi,
            UnusedApi,
            UnusedIdentitySource,
        )
    }

    fn test_artifact(path: &str) -> PinnedArtifact {
        PinnedArtifact::new(path, sha256(b"artifact"))
    }

    fn test_config() -> RuntimeConfig {
        let rootfs = test_artifact("/artifacts/rootfs");
        let jail_root = Path::new("/srv/jailer/firecracker/session-a/root");
        RuntimeConfig {
            firecracker: test_artifact("/artifacts/firecracker"),
            kernel: test_artifact(jail_root.join("artifacts/kernel").to_str().unwrap()),
            rootfs: rootfs.clone(),
            verity_hash: test_artifact("/artifacts/verity"),
            dm_verity: DmVerityConfig {
                data_device: rootfs.path,
                hash_device: PathBuf::from("/artifacts/verity"),
                mapper_name: "rootfs-verity".to_owned(),
                root_hash: sha256(b"verity-root"),
                jailed_device_path: jail_root.join("dev/rootfs"),
            },
            workspace: WorkspaceConfig {
                source: PathBuf::from("/workspace/source"),
                clone_root: jail_root.join("workspace"),
                clone_id: "session-a".to_owned(),
            },
            jailer: test_artifact("/artifacts/jailer"),
            jailer_config: JailerConfig {
                uid: 1000,
                gid: 1000,
                chroot_base_dir: PathBuf::from("/srv/jailer"),
                cgroup_version: CgroupVersion::V2,
            },
            api_socket: jail_root.join("run/firecracker.socket"),
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
                    path: PathBuf::from("/sys/fs/cgroup/firecracker/session-a"),
                    memory_max_bytes: 256 * 1024 * 1024,
                    cpu_quota_micros: 100_000,
                    cpu_period_micros: 100_000,
                },
                seccomp: SeccompConfig {
                    filter: test_artifact(jail_root.join("artifacts/seccomp").to_str().unwrap()),
                    blocked_syscalls: REQUIRED_BLOCKED_SYSCALLS
                        .into_iter()
                        .map(str::to_owned)
                        .collect(),
                },
            },
            vsock: VsockConfig {
                guest_cid: 42,
                uds_path: jail_root.join("run/session-a.vsock"),
            },
            network_devices: Vec::new(),
            vcpu_count: 2,
            memory_mib: 256,
            boot_args: "console=ttyS0 reboot=k panic=1 pci=off".to_owned(),
        }
    }

    #[derive(Default)]
    struct LifecycleRunner {
        events: Rc<RefCell<Vec<String>>>,
        next_pid: u32,
    }

    impl CommandRunner for LifecycleRunner {
        fn run(&mut self, command: &CommandSpec) -> Result<CommandOutput, RuntimeError> {
            self.events.borrow_mut().push(format!(
                "command:{} {}",
                command.program.display(),
                command.args.join(" ")
            ));
            Ok(CommandOutput {
                status: 0,
                stdout: Vec::new(),
                stderr: Vec::new(),
            })
        }

        fn start(&mut self, _command: &CommandSpec) -> Result<ProcessHandle, RuntimeError> {
            self.next_pid += 1;
            self.events
                .borrow_mut()
                .push(format!("start:{}", self.next_pid));
            Ok(ProcessHandle { pid: self.next_pid })
        }

        fn start_owned(
            &mut self,
            command: &CommandSpec,
            _ownership: &ProcessOwnership,
        ) -> Result<ProcessHandle, RuntimeError> {
            self.start(command)
        }

        fn verify_running(&mut self, process: ProcessHandle) -> Result<(), RuntimeError> {
            self.events
                .borrow_mut()
                .push(format!("verify:{}", process.pid));
            Ok(())
        }

        fn stop(&mut self, process: ProcessHandle) -> Result<(), RuntimeError> {
            self.events
                .borrow_mut()
                .push(format!("stop:{}", process.pid));
            Ok(())
        }
    }

    #[derive(Default)]
    struct LifecycleFileSystem {
        events: Rc<RefCell<Vec<String>>>,
    }

    impl FileSystem for LifecycleFileSystem {
        fn read(&mut self, _path: &Path) -> Result<Vec<u8>, RuntimeError> {
            Ok(b"artifact".to_vec())
        }

        fn verify_block_device_binding(
            &mut self,
            source: &Path,
            jailed_device: &Path,
        ) -> Result<(), RuntimeError> {
            self.events.borrow_mut().push(format!(
                "verify-device:{}:{}",
                source.display(),
                jailed_device.display()
            ));
            Ok(())
        }

        fn clone_workspace(
            &mut self,
            _source: &Path,
            destination: &Path,
        ) -> Result<(), RuntimeError> {
            self.events
                .borrow_mut()
                .push(format!("clone:{}", destination.display()));
            Ok(())
        }

        fn remove_workspace(&mut self, path: &Path) -> Result<(), RuntimeError> {
            self.events
                .borrow_mut()
                .push(format!("remove:{}", path.display()));
            Ok(())
        }
    }

    struct LifecycleApi {
        label: &'static str,
        events: Rc<RefCell<Vec<String>>>,
        statuses: VecDeque<u16>,
    }

    impl ApiClient for LifecycleApi {
        fn request(&mut self, request: &ApiRequest) -> Result<ApiResponse, RuntimeError> {
            self.events.borrow_mut().push(format!(
                "{}:{:?}:{}:{}",
                self.label, request.method, request.path, request.body
            ));
            Ok(ApiResponse {
                status: self.statuses.pop_front().unwrap_or(204),
                body: String::new(),
            })
        }

        fn verify_restore_resources(
            &mut self,
            workspace_path: &Path,
            vsock_uds_path: &Path,
            guest_cid: u32,
        ) -> Result<(), RuntimeError> {
            self.events.borrow_mut().push(format!(
                "{}:verify-resources:{}:{}:{guest_cid}",
                self.label,
                workspace_path.display(),
                vsock_uds_path.display()
            ));
            Ok(())
        }
    }

    struct SequentialIdentitySource(u8);

    impl IdentitySource for SequentialIdentitySource {
        fn generate(&mut self) -> Result<IdentityId, RuntimeError> {
            self.0 += 1;
            let mut bytes = [0_u8; ID_LENGTH];
            bytes[ID_LENGTH - 1] = self.0;
            Ok(IdentityId(bytes))
        }
    }

    struct SnapshotVerifierFileSystem {
        files: Rc<RefCell<HashMap<PathBuf, Vec<u8>>>>,
    }

    impl FileSystem for SnapshotVerifierFileSystem {
        fn read(&mut self, path: &Path) -> Result<Vec<u8>, RuntimeError> {
            self.files
                .borrow()
                .get(path)
                .cloned()
                .ok_or_else(|| RuntimeError::Io(format!("missing test file {}", path.display())))
        }

        fn clone_workspace(
            &mut self,
            _source: &Path,
            _destination: &Path,
        ) -> Result<(), RuntimeError> {
            Err(RuntimeError::Io("unexpected clone".to_owned()))
        }

        fn remove_workspace(&mut self, _path: &Path) -> Result<(), RuntimeError> {
            Err(RuntimeError::Io("unexpected remove".to_owned()))
        }
    }

    struct LateMutationFileSystem {
        events: Rc<RefCell<Vec<String>>>,
        files: HashMap<PathBuf, Vec<u8>>,
        state_path: PathBuf,
    }

    impl FileSystem for LateMutationFileSystem {
        fn read(&mut self, path: &Path) -> Result<Vec<u8>, RuntimeError> {
            Ok(self
                .files
                .get(path)
                .cloned()
                .unwrap_or_else(|| b"artifact".to_vec()))
        }

        fn verify_block_device_binding(
            &mut self,
            _source: &Path,
            _jailed_device: &Path,
        ) -> Result<(), RuntimeError> {
            Ok(())
        }

        fn clone_workspace(
            &mut self,
            _source: &Path,
            destination: &Path,
        ) -> Result<(), RuntimeError> {
            self.events
                .borrow_mut()
                .push(format!("clone:{}", destination.display()));
            self.files
                .insert(self.state_path.clone(), b"state-v2".to_vec());
            Ok(())
        }

        fn remove_workspace(&mut self, path: &Path) -> Result<(), RuntimeError> {
            self.events
                .borrow_mut()
                .push(format!("remove:{}", path.display()));
            Ok(())
        }
    }

    type LifecycleRuntime = Runtime<
        LifecycleRunner,
        LifecycleFileSystem,
        LifecycleApi,
        LifecycleApi,
        SequentialIdentitySource,
    >;

    fn lifecycle_runtime(
        api_statuses: impl IntoIterator<Item = u16>,
        guest_statuses: impl IntoIterator<Item = u16>,
    ) -> (LifecycleRuntime, Rc<RefCell<Vec<String>>>) {
        let events = Rc::new(RefCell::new(Vec::new()));
        (
            Runtime::new(
                LifecycleRunner {
                    events: Rc::clone(&events),
                    next_pid: 0,
                },
                LifecycleFileSystem {
                    events: Rc::clone(&events),
                },
                LifecycleApi {
                    label: "firecracker",
                    events: Rc::clone(&events),
                    statuses: api_statuses.into_iter().collect(),
                },
                LifecycleApi {
                    label: "guest",
                    events: Rc::clone(&events),
                    statuses: guest_statuses.into_iter().collect(),
                },
                SequentialIdentitySource(0),
            ),
            events,
        )
    }

    fn test_snapshot(config: &RuntimeConfig) -> Snapshot {
        let jail_root = config.jail_root().expect("test jail root must resolve");
        Snapshot::new(
            jail_root.join("snapshots/state"),
            jail_root.join("snapshots/memory"),
            config.snapshot_fingerprint(),
            sha256(b"artifact"),
            sha256(b"artifact"),
            Vec::new(),
        )
    }

    fn fake_owned_process(
        runner: &mut RealCommandRunner,
        cgroup: &Path,
        firecracker_executable: &Path,
    ) -> ProcessHandle {
        let launcher = spawn_detached(&CommandSpec::new(
            "/bin/sh",
            ["-c".to_owned(), "exit 0".to_owned()],
        ))
        .expect("fake launcher must start");
        let process = ProcessHandle { pid: launcher.id() };
        runner.children.insert(
            process.pid,
            ManagedChild::Isolated {
                launcher,
                ownership: OwnedCgroup {
                    path: cgroup.to_owned(),
                    identity: ObjectIdentity::from_metadata(
                        &fs::metadata(cgroup).expect("fake cgroup metadata must resolve"),
                    ),
                    firecracker_digest: digest_file(firecracker_executable)
                        .expect("fake Firecracker executable must be digestible"),
                },
            },
        );
        process
    }

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

    #[test]
    #[allow(clippy::too_many_lines)] // The mutation matrix intentionally names every config field.
    fn snapshot_fingerprint_covers_every_non_overridable_runtime_field() {
        let base = test_config();
        let expected = base.snapshot_fingerprint();
        macro_rules! assert_mutation_changes_fingerprint {
            ($name:literal, $mutation:expr) => {{
                let mut changed = base.clone();
                $mutation(&mut changed);
                assert_ne!(
                    changed.snapshot_fingerprint(),
                    expected,
                    "{} is missing from the snapshot compatibility fingerprint",
                    $name
                );
            }};
        }

        assert_mutation_changes_fingerprint!("firecracker.path", |config: &mut RuntimeConfig| {
            config.firecracker.path.push("changed");
        });
        assert_mutation_changes_fingerprint!("firecracker.digest", |config: &mut RuntimeConfig| {
            config.firecracker.digest = sha256(b"changed-firecracker");
        });
        assert_mutation_changes_fingerprint!("kernel.path", |config: &mut RuntimeConfig| {
            config.kernel.path.push("changed");
        });
        assert_mutation_changes_fingerprint!("kernel.digest", |config: &mut RuntimeConfig| {
            config.kernel.digest = sha256(b"changed-kernel");
        });
        assert_mutation_changes_fingerprint!("rootfs.path", |config: &mut RuntimeConfig| {
            config.rootfs.path.push("changed");
        });
        assert_mutation_changes_fingerprint!("rootfs.digest", |config: &mut RuntimeConfig| {
            config.rootfs.digest = sha256(b"changed-rootfs");
        });
        assert_mutation_changes_fingerprint!("verity_hash.path", |config: &mut RuntimeConfig| {
            config.verity_hash.path.push("changed");
        });
        assert_mutation_changes_fingerprint!("verity_hash.digest", |config: &mut RuntimeConfig| {
            config.verity_hash.digest = sha256(b"changed-verity");
        });
        assert_mutation_changes_fingerprint!(
            "dm_verity.data_device",
            |config: &mut RuntimeConfig| {
                config.dm_verity.data_device.push("changed");
            }
        );
        assert_mutation_changes_fingerprint!(
            "dm_verity.hash_device",
            |config: &mut RuntimeConfig| {
                config.dm_verity.hash_device.push("changed");
            }
        );
        assert_mutation_changes_fingerprint!(
            "dm_verity.root_hash",
            |config: &mut RuntimeConfig| {
                config.dm_verity.root_hash = sha256(b"changed-root-hash");
            }
        );
        assert_mutation_changes_fingerprint!(
            "dm_verity.jailed_device_path",
            |config: &mut RuntimeConfig| {
                config.dm_verity.jailed_device_path.push("changed");
            }
        );
        assert_mutation_changes_fingerprint!("workspace.source", |config: &mut RuntimeConfig| {
            config.workspace.source.push("changed");
        });
        assert_mutation_changes_fingerprint!(
            "workspace.clone_root",
            |config: &mut RuntimeConfig| {
                config.workspace.clone_root.push("changed");
            }
        );
        assert_mutation_changes_fingerprint!("jailer.path", |config: &mut RuntimeConfig| {
            config.jailer.path.push("changed");
        });
        assert_mutation_changes_fingerprint!("jailer.digest", |config: &mut RuntimeConfig| {
            config.jailer.digest = sha256(b"changed-jailer");
        });
        assert_mutation_changes_fingerprint!("jailer.uid", |config: &mut RuntimeConfig| {
            config.jailer_config.uid += 1;
        });
        assert_mutation_changes_fingerprint!("jailer.gid", |config: &mut RuntimeConfig| {
            config.jailer_config.gid += 1;
        });
        assert_mutation_changes_fingerprint!(
            "jailer.chroot_base_dir",
            |config: &mut RuntimeConfig| {
                config.jailer_config.chroot_base_dir.push("changed");
            }
        );
        assert_mutation_changes_fingerprint!("api_socket", |config: &mut RuntimeConfig| {
            config.api_socket.push("changed");
        });
        assert_mutation_changes_fingerprint!("namespace.user", |config: &mut RuntimeConfig| {
            config.isolation.namespaces.user = true;
        });
        assert_mutation_changes_fingerprint!("namespace.pid", |config: &mut RuntimeConfig| {
            config.isolation.namespaces.pid = false;
        });
        assert_mutation_changes_fingerprint!("namespace.mount", |config: &mut RuntimeConfig| {
            config.isolation.namespaces.mount = false;
        });
        assert_mutation_changes_fingerprint!("namespace.network", |config: &mut RuntimeConfig| {
            config.isolation.namespaces.network = true;
        });
        assert_mutation_changes_fingerprint!("namespace.ipc", |config: &mut RuntimeConfig| {
            config.isolation.namespaces.ipc = true;
        });
        assert_mutation_changes_fingerprint!("namespace.uts", |config: &mut RuntimeConfig| {
            config.isolation.namespaces.uts = true;
        });
        assert_mutation_changes_fingerprint!("cgroup.path", |config: &mut RuntimeConfig| {
            config.isolation.cgroup.path.push("changed");
        });
        assert_mutation_changes_fingerprint!(
            "cgroup.memory_max_bytes",
            |config: &mut RuntimeConfig| {
                config.isolation.cgroup.memory_max_bytes += 1;
            }
        );
        assert_mutation_changes_fingerprint!(
            "cgroup.cpu_quota_micros",
            |config: &mut RuntimeConfig| {
                config.isolation.cgroup.cpu_quota_micros += 1;
            }
        );
        assert_mutation_changes_fingerprint!(
            "cgroup.cpu_period_micros",
            |config: &mut RuntimeConfig| {
                config.isolation.cgroup.cpu_period_micros += 1;
            }
        );
        assert_mutation_changes_fingerprint!(
            "seccomp.filter.path",
            |config: &mut RuntimeConfig| {
                config.isolation.seccomp.filter.path.push("changed");
            }
        );
        assert_mutation_changes_fingerprint!(
            "seccomp.filter.digest",
            |config: &mut RuntimeConfig| {
                config.isolation.seccomp.filter.digest = sha256(b"changed-seccomp");
            }
        );
        assert_mutation_changes_fingerprint!(
            "seccomp.blocked_syscalls",
            |config: &mut RuntimeConfig| {
                config
                    .isolation
                    .seccomp
                    .blocked_syscalls
                    .push("clone3".to_owned());
            }
        );
        assert_mutation_changes_fingerprint!("vsock.guest_cid", |config: &mut RuntimeConfig| {
            config.vsock.guest_cid += 1;
        });
        assert_mutation_changes_fingerprint!("network_devices", |config: &mut RuntimeConfig| {
            config.network_devices.push("eth0".to_owned());
        });
        assert_mutation_changes_fingerprint!("vcpu_count", |config: &mut RuntimeConfig| {
            config.vcpu_count += 1;
        });
        assert_mutation_changes_fingerprint!("memory_mib", |config: &mut RuntimeConfig| {
            config.memory_mib += 1;
        });
        assert_mutation_changes_fingerprint!("boot_args", |config: &mut RuntimeConfig| {
            config.boot_args.push_str(" quiet");
        });
    }

    #[test]
    fn snapshot_fingerprint_allows_only_explicit_session_resource_overrides() {
        let base = test_config();
        let mut session = base.clone();
        session.workspace.clone_id = "session-b".to_owned();
        let jail_root = Path::new("/srv/jailer/firecracker/session-b/root");
        session.kernel.path = jail_root.join("artifacts/kernel");
        session.workspace.clone_root = jail_root.join("workspace");
        session.api_socket = jail_root.join("run/firecracker.socket");
        session.isolation.cgroup.path = PathBuf::from("/sys/fs/cgroup/firecracker/session-b");
        session.isolation.seccomp.filter.path = jail_root.join("artifacts/seccomp");
        session.vsock.uds_path = jail_root.join("run/session-b.vsock");
        session.dm_verity.mapper_name = "rootfs-verity-session-b".to_owned();
        session.dm_verity.jailed_device_path = jail_root.join("dev/rootfs");

        assert_eq!(session.snapshot_fingerprint(), base.snapshot_fingerprint());
        assert_ne!(session.instance_fingerprint(), base.instance_fingerprint());
    }

    #[test]
    fn jailer_command_matches_supported_v2_chroot_contract_exactly() {
        let config = test_config();

        let command = LifecycleRuntime::jailer_command(&config)
            .expect("valid jailer configuration must produce an argv");

        assert_eq!(command.program, Path::new("/artifacts/jailer"));
        assert_eq!(
            command.args,
            [
                "--id",
                "session-a",
                "--exec-file",
                "/artifacts/firecracker",
                "--uid",
                "1000",
                "--gid",
                "1000",
                "--cgroup-version",
                "2",
                "--parent-cgroup",
                "firecracker",
                "--cgroup",
                "memory.max=268435456",
                "--cgroup",
                "cpu.max=100000 100000",
                "--chroot-base-dir",
                "/srv/jailer",
                "--new-pid-ns",
                "--",
                "--api-sock",
                "/run/firecracker.socket",
                "--seccomp-filter",
                "/artifacts/seccomp",
            ]
            .map(str::to_owned)
        );
    }

    #[test]
    fn snapshot_verifier_rejects_byte_mismatch_and_rechecks_before_restore() {
        let config = test_config();
        let jail_root = config.jail_root().expect("test jail root must resolve");
        let state_path = jail_root.join("snapshots/state");
        let memory_path = jail_root.join("snapshots/memory");
        let files = Rc::new(RefCell::new(HashMap::from([
            (state_path.clone(), b"state-v1".to_vec()),
            (memory_path.clone(), b"memory-v1".to_vec()),
        ])));
        let mut runtime = Runtime::new(
            CleanupRunner::default(),
            SnapshotVerifierFileSystem {
                files: Rc::clone(&files),
            },
            UnusedApi,
            UnusedApi,
            UnusedIdentitySource,
        );
        let manifest = Snapshot::new(
            &state_path,
            &memory_path,
            config.snapshot_fingerprint(),
            sha256(b"state-v1"),
            sha256(b"memory-v1"),
            Vec::new(),
        );
        let verified = runtime
            .verify_snapshot(&config, manifest)
            .expect("matching snapshot bytes must verify");
        files
            .borrow_mut()
            .insert(state_path.clone(), b"state-v2".to_vec());

        assert!(matches!(
            runtime.restore(&config, &verified),
            Err(RuntimeError::SnapshotDigestMismatch { label, path, .. })
                if label == "snapshot state" && path == state_path
        ));
        assert!(runtime.command_runner.events.is_empty());
    }

    #[test]
    fn restore_rechecks_snapshot_after_workspace_preparation_before_api_use() {
        let config = test_config();
        let jail_root = config.jail_root().expect("test jail root must resolve");
        let state_path = jail_root.join("snapshots/state");
        let memory_path = jail_root.join("snapshots/memory");
        let events = Rc::new(RefCell::new(Vec::new()));
        let files = HashMap::from([
            (state_path.clone(), b"state-v1".to_vec()),
            (memory_path.clone(), b"memory-v1".to_vec()),
        ]);
        let mut runtime = Runtime::new(
            LifecycleRunner {
                events: Rc::clone(&events),
                next_pid: 0,
            },
            LateMutationFileSystem {
                events: Rc::clone(&events),
                files,
                state_path: state_path.clone(),
            },
            LifecycleApi {
                label: "firecracker",
                events: Rc::clone(&events),
                statuses: VecDeque::new(),
            },
            LifecycleApi {
                label: "guest",
                events: Rc::clone(&events),
                statuses: VecDeque::new(),
            },
            SequentialIdentitySource(0),
        );
        let manifest = Snapshot::new(
            &state_path,
            &memory_path,
            config.snapshot_fingerprint(),
            sha256(b"state-v1"),
            sha256(b"memory-v1"),
            Vec::new(),
        );
        let verified = runtime
            .verify_snapshot(&config, manifest)
            .expect("initial snapshot bytes must verify");

        let error = runtime
            .restore(&config, &verified)
            .expect_err("late snapshot replacement must fail before Firecracker reads it");

        assert!(matches!(
            error,
            RuntimeError::SnapshotDigestMismatch { label, path, .. }
                if label == "snapshot state" && path == state_path
        ));
        assert!(
            events
                .borrow()
                .iter()
                .all(|event| !event.contains("firecracker:Put:/snapshot/load:"))
        );
    }

    #[test]
    fn snapshot_verifier_rejects_path_mismatch_even_when_bytes_match() {
        let config = test_config();
        let jail_root = config.jail_root().expect("test jail root must resolve");
        let state_path = jail_root.join("snapshots/state");
        let memory_path = jail_root.join("snapshots/memory");
        let files = Rc::new(RefCell::new(HashMap::from([
            (state_path.clone(), b"state".to_vec()),
            (memory_path.clone(), b"memory".to_vec()),
            (PathBuf::from("/outside/state"), b"state".to_vec()),
        ])));
        let mut runtime = Runtime::new(
            CleanupRunner::default(),
            SnapshotVerifierFileSystem { files },
            UnusedApi,
            UnusedApi,
            UnusedIdentitySource,
        );
        let manifest = Snapshot::new(
            "/outside/state",
            memory_path,
            config.snapshot_fingerprint(),
            sha256(b"state"),
            sha256(b"memory"),
            Vec::new(),
        );

        assert!(matches!(
            runtime.verify_snapshot(&config, manifest),
            Err(RuntimeError::InvalidConfig(message))
                if message.contains("snapshot path must be provisioned beneath jail root")
        ));
        assert!(runtime.command_runner.events.is_empty());
    }

    #[test]
    fn restore_binds_workspace_and_vsock_while_paused_before_issuing_instance() {
        let config = test_config();
        let (mut runtime, events) = lifecycle_runtime([], []);
        let snapshot = runtime
            .verify_snapshot(&config, test_snapshot(&config))
            .expect("test snapshot provenance must verify");

        let instance = runtime
            .restore(&config, &snapshot)
            .expect("paused restore with explicit resource binding must succeed");
        assert_eq!(instance.state(), RuntimeState::IdentityRegenerated);

        let events = events.borrow();
        let load = events
            .iter()
            .position(|event| event.contains("firecracker:Put:/snapshot/load:"))
            .expect("restore must load the snapshot");
        assert!(events[load].contains("\"resume_vm\":false"));
        assert!(
            events[load].contains("\"vsock_override\":{\"uds_path\":\"/run/session-a.vsock\"}")
        );
        let workspace = events
            .iter()
            .position(|event| event.contains("firecracker:Patch:/drives/workspace:"))
            .expect("restore must bind the fresh workspace through Firecracker");
        assert!(events[workspace].contains("\"path_on_host\":\"/workspace/session-a\""));
        let verifies = events
            .iter()
            .enumerate()
            .filter_map(|(index, event)| (event == "verify:1").then_some(index))
            .collect::<Vec<_>>();
        assert_eq!(
            verifies.len(),
            2,
            "restore must verify process ownership before API use and before returning"
        );
        let resources = events
            .iter()
            .position(|event| {
                event == "firecracker:verify-resources:/workspace/session-a:/run/session-a.vsock:42"
            })
            .expect("restore must observe the exact Firecracker device bindings");
        assert!(
            verifies[0] < load
                && load < workspace
                && workspace < resources
                && resources < verifies[1]
        );
        assert!(events.iter().all(|event| !event.contains(":/vm:")));
    }

    #[test]
    fn exported_vm_config_verifier_requires_exact_unique_resource_bindings() {
        let valid = r#"{
            "drives":[
                {"drive_id":"rootfs","path_on_host":"/dev/rootfs"},
                {"drive_id":"workspace","path_on_host":"/workspace/session-a"}
            ],
            "vsock":{"guest_cid":42,"uds_path":"/run/session-a.vsock"},
            "machine-config":{"vcpu_count":2}
        }"#;
        verify_exported_restore_resources(
            valid,
            Path::new("/workspace/session-a"),
            Path::new("/run/session-a.vsock"),
            42,
        )
        .expect("exact exported resource bindings must verify");

        let wrong_workspace = valid.replace("/workspace/session-a", "/workspace/stale");
        assert!(matches!(
            verify_exported_restore_resources(
                &wrong_workspace,
                Path::new("/workspace/session-a"),
                Path::new("/run/session-a.vsock"),
                42,
            ),
            Err(RuntimeError::StaleSnapshot(message)) if message.contains("workspace")
        ));
        let wrong_vsock = valid.replace("\"guest_cid\":42", "\"guest_cid\":43");
        assert!(matches!(
            verify_exported_restore_resources(
                &wrong_vsock,
                Path::new("/workspace/session-a"),
                Path::new("/run/session-a.vsock"),
                42,
            ),
            Err(RuntimeError::StaleSnapshot(message)) if message.contains("vsock")
        ));
        let duplicate_key = valid.replace("\"drives\":[", "\"drives\":[],\"drives\":[");
        assert!(matches!(
            verify_exported_restore_resources(
                &duplicate_key,
                Path::new("/workspace/session-a"),
                Path::new("/run/session-a.vsock"),
                42,
            ),
            Err(RuntimeError::Api(message)) if message.contains("duplicate JSON key")
        ));
    }

    #[test]
    fn identity_acknowledgement_precedes_explicit_resume_and_workload_start() {
        let config = test_config();
        let (mut runtime, events) = lifecycle_runtime([], []);
        let snapshot = runtime
            .verify_snapshot(&config, test_snapshot(&config))
            .expect("test snapshot provenance must verify");
        let mut instance = runtime
            .restore(&config, &snapshot)
            .expect("restore must remain paused");

        runtime
            .inject_identity(&mut instance)
            .expect("identity acknowledgement and resume must succeed");
        assert_eq!(instance.state(), RuntimeState::IdentityInjected);
        runtime
            .start_workload(&mut instance)
            .expect("workload may start after the gate");
        assert_eq!(instance.state(), RuntimeState::Running);

        let events = events.borrow();
        let inject = events
            .iter()
            .position(|event| event.contains("guest:Put:/actions/inject-identity:"))
            .expect("identity injection must be acknowledged");
        let resume = events
            .iter()
            .position(|event| event.contains("firecracker:Patch:/vm:"))
            .expect("Firecracker must be explicitly resumed");
        let start = events
            .iter()
            .position(|event| event.contains("guest:Put:/actions/start-workload:"))
            .expect("workload start must be separately acknowledged");
        assert!(inject < resume && resume < start);
    }

    #[test]
    fn failed_resume_keeps_acknowledged_identity_gate_retryable_without_reinjection() {
        let config = test_config();
        let (mut runtime, events) = lifecycle_runtime([204, 204, 503, 204], []);
        let snapshot = runtime
            .verify_snapshot(&config, test_snapshot(&config))
            .expect("test snapshot provenance must verify");
        let mut instance = runtime
            .restore(&config, &snapshot)
            .expect("restore must remain paused");

        assert!(matches!(
            runtime.inject_identity(&mut instance),
            Err(RuntimeError::ApiStatus {
                path,
                status: 503,
                ..
            }) if path == "/vm"
        ));
        assert_eq!(instance.state(), RuntimeState::IdentityAcknowledgedPaused);
        assert!(matches!(
            runtime.start_workload(&mut instance),
            Err(RuntimeError::InvalidState { .. })
        ));

        runtime
            .inject_identity(&mut instance)
            .expect("resume may be retried without sending identity twice");
        assert_eq!(instance.state(), RuntimeState::IdentityInjected);
        let events = events.borrow();
        assert_eq!(
            events
                .iter()
                .filter(|event| event.contains("/actions/inject-identity"))
                .count(),
            1
        );
        assert_eq!(
            events
                .iter()
                .filter(|event| event.contains("firecracker:Patch:/vm:"))
                .count(),
            2
        );
    }

    #[test]
    fn workspace_rebind_rejection_rolls_back_without_issuing_an_instance() {
        let config = test_config();
        let (mut runtime, events) = lifecycle_runtime([204, 409], []);
        let snapshot = runtime
            .verify_snapshot(&config, test_snapshot(&config))
            .expect("test snapshot provenance must verify");

        assert!(matches!(
            runtime.restore(&config, &snapshot),
            Err(RuntimeError::ApiStatus {
                path,
                status: 409,
                ..
            }) if path == "/drives/workspace"
        ));
        let events = events.borrow();
        let stop = events
            .iter()
            .position(|event| event == "stop:1")
            .expect("failed resource binding must stop the owned task");
        let close = events
            .iter()
            .position(|event| event.contains("veritysetup close"))
            .expect("failed resource binding must close dm-verity");
        let remove = events
            .iter()
            .position(|event| {
                event.contains("remove:/srv/jailer/firecracker/session-a/root/workspace/session-a")
            })
            .expect("failed resource binding must remove the fresh workspace");
        assert!(stop < close && close < remove);
    }

    #[test]
    fn pending_cleanup_keeps_verity_and_workspace_when_process_stop_fails() {
        let mut runtime = cleanup_runtime([true, false], std::iter::empty());

        let failures = runtime.rollback(
            Some(ProcessHandle { pid: 42 }),
            true,
            true,
            Path::new("/workspace/session"),
            "session-root",
        );
        assert!(failures[0].contains("stop failed"));
        assert_eq!(runtime.command_runner.events, ["stop:42"]);
        assert!(runtime.filesystem.events.is_empty());
        assert!(runtime.has_pending_cleanup());

        runtime
            .retry_pending_cleanup()
            .expect("retained cleanup must be retryable");
        assert_eq!(
            runtime.command_runner.events,
            ["stop:42", "stop:42", "run:veritysetup close session-root"]
        );
        assert_eq!(runtime.filesystem.events, ["remove:/workspace/session"]);
        assert!(!runtime.has_pending_cleanup());
    }

    #[test]
    fn pending_cleanup_keeps_workspace_when_verity_close_fails() {
        let mut runtime = cleanup_runtime(std::iter::empty(), [true, false]);

        let failures = runtime.rollback(
            Some(ProcessHandle { pid: 42 }),
            true,
            true,
            Path::new("/workspace/session"),
            "session-root",
        );
        assert!(failures[0].contains("close failed"));
        assert_eq!(
            runtime.command_runner.events,
            ["stop:42", "run:veritysetup close session-root"]
        );
        assert!(runtime.filesystem.events.is_empty());
        assert!(runtime.has_pending_cleanup());

        runtime
            .retry_pending_cleanup()
            .expect("retained cleanup must be retryable");
        assert_eq!(
            runtime.command_runner.events,
            [
                "stop:42",
                "run:veritysetup close session-root",
                "run:veritysetup close session-root"
            ]
        );
        assert_eq!(runtime.filesystem.events, ["remove:/workspace/session"]);
        assert!(!runtime.has_pending_cleanup());
    }

    #[test]
    fn owned_process_verification_tracks_cgroup_task_after_launcher_exit() {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("test clock must be after the Unix epoch")
            .as_nanos();
        let cgroup = std::env::temp_dir().join(format!(
            "firecracker-runtime-owned-cgroup-{}-{suffix}",
            std::process::id()
        ));
        fs::create_dir(&cgroup).expect("fake cgroup directory must be creatable");
        fs::write(cgroup.join("cgroup.procs"), b"")
            .expect("fake cgroup task file must be creatable");
        let current_executable = std::env::current_exe().expect("test executable must resolve");
        let mut runner = RealCommandRunner::new();
        let process = fake_owned_process(&mut runner, &cgroup, &current_executable);
        thread::sleep(Duration::from_millis(20));
        fs::write(
            cgroup.join("cgroup.procs"),
            format!("{}\n", std::process::id()),
        )
        .expect("fake cgroup must expose the owned Firecracker task");

        runner
            .verify_running(process)
            .expect("an exited launcher must not hide the live owned cgroup task");

        fs::write(cgroup.join("cgroup.procs"), b"").expect("fake cgroup task must be removable");
        runner
            .stop(process)
            .expect("empty owned cgroup and exited launcher must clean up");
        fs::remove_file(cgroup.join("cgroup.procs"))
            .expect("fake cgroup task file must be removable");
        fs::remove_dir(cgroup).expect("fake cgroup directory must be removable");
    }

    #[test]
    fn owned_process_start_rejects_a_fake_cgroup_before_launch() {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("test clock must be after the Unix epoch")
            .as_nanos();
        let cgroup = std::env::temp_dir().join(format!(
            "firecracker-runtime-non-cgroup-{}-{suffix}",
            std::process::id()
        ));
        fs::create_dir(&cgroup).expect("fake cgroup directory must be creatable");
        let mut runner = RealCommandRunner::new();

        assert!(matches!(
            runner.start_owned(
                &CommandSpec::new("/bin/sh", ["-c".to_owned(), "exit 0".to_owned()]),
                &ProcessOwnership {
                    cgroup_path: cgroup.clone(),
                    firecracker_executable: PathBuf::from("/bin/sh"),
                    firecracker_digest: digest_file(Path::new("/bin/sh"))
                        .expect("test shell must be digestible"),
                }
            ),
            Err(RuntimeError::Command(message)) if message.contains("not on cgroup v2")
        ));
        assert!(runner.children.is_empty());
        fs::remove_dir(cgroup).expect("fake cgroup directory must be removable");
    }

    #[test]
    fn owned_process_verification_rejects_exited_launcher_without_firecracker_task() {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("test clock must be after the Unix epoch")
            .as_nanos();
        let cgroup = std::env::temp_dir().join(format!(
            "firecracker-runtime-empty-cgroup-{}-{suffix}",
            std::process::id()
        ));
        fs::create_dir(&cgroup).expect("fake cgroup directory must be creatable");
        fs::write(cgroup.join("cgroup.procs"), b"")
            .expect("fake cgroup task file must be creatable");
        let mut runner = RealCommandRunner::new();
        let process = fake_owned_process(&mut runner, &cgroup, Path::new("/bin/sh"));
        thread::sleep(Duration::from_millis(20));

        assert!(matches!(
            runner.verify_running(process),
            Err(RuntimeError::Command(message))
                if message.contains("contains no pinned Firecracker task")
        ));
        runner
            .stop(process)
            .expect("empty owned cgroup and exited launcher must clean up");
        fs::remove_file(cgroup.join("cgroup.procs"))
            .expect("fake cgroup task file must be removable");
        fs::remove_dir(cgroup).expect("fake cgroup directory must be removable");
    }

    #[test]
    fn owned_process_stop_does_not_accept_exited_launcher_while_cgroup_task_remains() {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("test clock must be after the Unix epoch")
            .as_nanos();
        let cgroup = std::env::temp_dir().join(format!(
            "firecracker-runtime-live-cgroup-{}-{suffix}",
            std::process::id()
        ));
        fs::create_dir(&cgroup).expect("fake cgroup directory must be creatable");
        fs::write(
            cgroup.join("cgroup.procs"),
            format!("{}\n", std::process::id()),
        )
        .expect("fake cgroup task file must be creatable");
        let current_executable = std::env::current_exe().expect("test executable must resolve");
        let mut runner = RealCommandRunner::new();
        let process = fake_owned_process(&mut runner, &cgroup, &current_executable);
        thread::sleep(Duration::from_millis(20));

        assert!(runner.stop(process).is_err());
        assert!(
            runner.children.contains_key(&process.pid),
            "failed cgroup termination must retain ownership for cleanup retry"
        );

        fs::write(cgroup.join("cgroup.procs"), b"").expect("fake cgroup task must be removable");
        runner
            .stop(process)
            .expect("cleanup must finish only after no live task remains");
        fs::remove_file(cgroup.join("cgroup.procs"))
            .expect("fake cgroup task file must be removable");
        fs::remove_dir(cgroup).expect("fake cgroup directory must be removable");
    }
}
