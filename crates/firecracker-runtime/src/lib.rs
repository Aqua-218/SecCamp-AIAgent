//! Firecracker runtime orchestration with pinned artifacts and fail-closed lifecycle rules.
//!
//! Production adapters execute commands, access the filesystem, and speak HTTP over a
//! Unix socket, while the same three boundaries are traits so lifecycle ordering and
//! rollback can be tested without starting a VM. Artifact digests use the audited `sha2`
//! implementation rather than a hand-written cryptographic primitive.

#![warn(clippy::all)]

/// Canonical request and acknowledgement encoding for the host-to-guest control channel.
pub mod guest_control;
pub mod recovery;

use authority_core::policy::AuthorityPolicyDigest;
use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::ffi::OsStr;
use std::fmt::{Display, Formatter};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::mem::MaybeUninit;
use std::os::fd::AsFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::{Component, Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use rustix::fs::{
    AtFlags, CWD, Gid, Mode, OFlags, RawDir, RenameFlags, Uid, fchown, fcntl_getfl, fcntl_setfl,
    open, openat, renameat_with, statfs, unlinkat,
};
use rustix::mount::{UnmountFlags, mount_bind, unmount};
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
/// Maximum bytes read into memory from any pinned executable or boot artifact.
pub const MAX_ARTIFACT_BYTES: u64 = 64 * 1024 * 1024;
/// Maximum bytes hashed from one persisted snapshot state or memory file.
///
/// This is deliberately larger than the maximum supported guest memory and workspace image, but
/// finite so a misconfigured FIFO/device or unexpectedly huge file cannot pin the session owner.
pub const MAX_SNAPSHOT_FILE_BYTES: u64 = 64 * 1024 * 1024 * 1024;
const MAX_BOOT_ARGS_BYTES: usize = 4 * 1024;
/// Guest PID 1 required by the identity gate.
pub const REQUIRED_GUEST_INIT: &str = "/usr/local/libexec/guest-control-init";
/// Maximum number of source filesystem entries copied into one workspace.
pub const MAX_WORKSPACE_ENTRIES: usize = 100_000;
/// Maximum source directory depth accepted during workspace cloning.
pub const MAX_WORKSPACE_DEPTH: usize = 64;
/// Maximum aggregate regular-file bytes copied into one workspace.
pub const MAX_WORKSPACE_BYTES: u64 = 1 << 30;
/// Maximum number of concurrently retained direct or owned child processes.
///
/// Pending and isolated ownership records consume the same admission budget
/// until a successful [`CommandRunner::stop`] releases their table entry.
pub const MAX_MANAGED_CHILDREN: usize = 256;
/// Smallest raw ext4 image accepted for a cloned guest workspace.
pub const MIN_WORKSPACE_IMAGE_BYTES: u64 = 16 * 1024 * 1024;
/// Largest sparse raw ext4 image a session may provision.
pub const MAX_WORKSPACE_IMAGE_BYTES: u64 = 16 * 1024 * 1024 * 1024;
const WORKSPACE_IMAGE_BLOCK_BYTES: u64 = 4096;
const WORKSPACE_IMAGE_FILE_SUFFIX: &str = ".ext4";
const ID_LENGTH: usize = 16;
const COMMAND_TIMEOUT: Duration = Duration::from_secs(30);
const PROCESS_STOP_TIMEOUT: Duration = Duration::from_secs(5);
const PROCESS_POLL_INTERVAL: Duration = Duration::from_millis(1);
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

/// Pinned formatter and capacity policy for one writable workspace block device.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkspaceImageConfig {
    /// Pinned `mke2fs` executable used to create the ext4 filesystem.
    pub formatter: PinnedArtifact,
    /// Exact sparse raw-image capacity exposed to the guest.
    pub size_bytes: u64,
}

/// Workspace source, clone destination, and raw block-device policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkspaceConfig {
    /// Read-only source workspace used as the clone input.
    pub source: PathBuf,
    /// Directory under which the clone-specific directory is created.
    pub clone_root: PathBuf,
    /// Stable, validated clone identifier used in the destination name.
    pub clone_id: String,
    /// Formatter and capacity policy for the guest-visible ext4 block device.
    pub image: WorkspaceImageConfig,
}

impl WorkspaceConfig {
    /// Returns the clone-specific workspace path.
    #[must_use]
    pub fn clone_path(&self) -> PathBuf {
        self.clone_root.join(&self.clone_id)
    }

    /// Returns the guest workspace's session-owned raw ext4 image path.
    #[must_use]
    pub fn image_path(&self) -> PathBuf {
        self.clone_root
            .join(format!("{}{}", self.clone_id, WORKSPACE_IMAGE_FILE_SUFFIX))
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

/// Returns the host Unix socket path for a guest-initiated Firecracker vsock port.
///
/// Firecracker forwards a guest connection to host CID 2 and port `P` to the
/// socket whose filename is `<vsock_uds_path>_P`. The base path remains
/// session-owned configuration; this helper only derives the fixed port suffix
/// and never opens or removes a socket.
///
/// # Errors
///
/// Returns [`RuntimeError::InvalidConfig`] if the UDS path is not absolute and
/// safe to compose, or the port is wildcard or zero.
pub fn firecracker_guest_port_path(
    vsock_uds_path: impl AsRef<Path>,
    port: u32,
) -> Result<PathBuf, RuntimeError> {
    let vsock_uds_path = vsock_uds_path.as_ref();
    validate_absolute_path("Firecracker vsock UDS", vsock_uds_path)?;
    if port == 0 || port == u32::MAX {
        return Err(RuntimeError::InvalidConfig(
            "Firecracker guest port must be explicit and non-zero".to_owned(),
        ));
    }
    let file_name = vsock_uds_path.file_name().ok_or_else(|| {
        RuntimeError::InvalidConfig("Firecracker vsock UDS path must name a socket file".to_owned())
    })?;
    if file_name.is_empty() {
        return Err(RuntimeError::InvalidConfig(
            "Firecracker vsock UDS path must name a non-empty socket file".to_owned(),
        ));
    }
    let mut derived_name = file_name.to_os_string();
    derived_name.push("_");
    derived_name.push(port.to_string());
    Ok(vsock_uds_path.with_file_name(derived_name))
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
    /// Pinned `veritysetup` executable used for mapping open and close.
    pub veritysetup: PinnedArtifact,
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
        validate_artifact("veritysetup", &self.veritysetup)?;
        validate_artifact("workspace image formatter", &self.workspace.image.formatter)?;
        validate_artifact("jailer", &self.jailer)?;
        validate_artifact("seccomp filter", &self.isolation.seccomp.filter)?;
        validate_boot_args(&self.boot_args)?;
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
        let image_path = self.workspace.image_path();
        if self.workspace.source == clone_path
            || self.workspace.source == image_path
            || clone_path.starts_with(&self.workspace.source)
            || image_path.starts_with(&self.workspace.source)
            || self.workspace.source.starts_with(&clone_path)
            || self.workspace.source.starts_with(&image_path)
        {
            return Err(RuntimeError::InvalidConfig(
                "workspace source, clone, and image paths must not overlap".to_owned(),
            ));
        }
        if self.workspace.image.size_bytes < MIN_WORKSPACE_IMAGE_BYTES
            || self.workspace.image.size_bytes > MAX_WORKSPACE_IMAGE_BYTES
            || !self
                .workspace
                .image
                .size_bytes
                .is_multiple_of(WORKSPACE_IMAGE_BLOCK_BYTES)
        {
            return Err(RuntimeError::InvalidConfig(format!(
                "workspace image size must be between {MIN_WORKSPACE_IMAGE_BYTES} and {MAX_WORKSPACE_IMAGE_BYTES} bytes and divisible by {WORKSPACE_IMAGE_BLOCK_BYTES}"
            )));
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
        self.jail_path("workspace block image", &self.workspace.image_path())?;
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
            validate_cgroup_component(component)?;
        }
        Ok(parent)
    }

    /// Returns the compatibility fingerprint that must be persisted with a snapshot.
    ///
    /// Explicitly session-scoped host paths are normalized to their jail-visible paths because
    /// paused restore binds a fresh workspace and vsock while preserving the guest-visible
    /// resource contract. The clone ID, cgroup leaf, mapper name, and corresponding host paths
    /// are bound separately by the internal instance fingerprint. Every non-overridable
    /// restore-relevant field is encoded here.
    #[must_use]
    #[allow(clippy::too_many_lines)] // The encoding deliberately enumerates the full config.
    pub fn snapshot_fingerprint(&self) -> Sha256Digest {
        let mut bytes = Vec::new();
        fingerprint_artifact(&mut bytes, "firecracker", &self.firecracker);
        fingerprint_jail_artifact(&mut bytes, "kernel", self, &self.kernel);
        fingerprint_artifact(&mut bytes, "rootfs", &self.rootfs);
        fingerprint_artifact(&mut bytes, "verity_hash", &self.verity_hash);
        fingerprint_artifact(&mut bytes, "veritysetup", &self.veritysetup);
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
        fingerprint_artifact(
            &mut bytes,
            "workspace.image.formatter",
            &self.workspace.image.formatter,
        );
        fingerprint_bytes(
            &mut bytes,
            "workspace.image.size_bytes",
            &self.workspace.image.size_bytes.to_be_bytes(),
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

fn validate_boot_args(boot_args: &str) -> Result<(), RuntimeError> {
    if boot_args.is_empty()
        || boot_args.len() > MAX_BOOT_ARGS_BYTES
        || !boot_args.is_ascii()
        || boot_args.contains('\0')
    {
        return Err(RuntimeError::InvalidConfig(format!(
            "boot args must be non-empty ASCII within {MAX_BOOT_ARGS_BYTES} bytes"
        )));
    }
    let mut init_count = 0_usize;
    let mut has_pci_off = false;
    let mut has_reboot_k = false;
    let mut has_panic_one = false;
    for token in boot_args.split_ascii_whitespace() {
        if let Some(init) = token.strip_prefix("init=") {
            init_count += 1;
            if init != REQUIRED_GUEST_INIT {
                return Err(RuntimeError::InvalidConfig(format!(
                    "guest init must be exactly {REQUIRED_GUEST_INIT}"
                )));
            }
        }
        if token.starts_with("rdinit=") {
            return Err(RuntimeError::InvalidConfig(
                "rdinit may not bypass the guest identity gate".to_owned(),
            ));
        }
        has_pci_off |= token == "pci=off";
        has_reboot_k |= token == "reboot=k";
        has_panic_one |= token == "panic=1";
    }
    if init_count != 1 {
        return Err(RuntimeError::InvalidConfig(
            "boot args must contain exactly one guest-control init".to_owned(),
        ));
    }
    if !(has_pci_off && has_reboot_k && has_panic_one) {
        return Err(RuntimeError::InvalidConfig(
            "boot args must require pci=off, reboot=k, and panic=1".to_owned(),
        ));
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

/// Validates one existing cgroup v2 directory name in the parent of a session leaf.
///
/// This is deliberately looser than [`validate_safe_name`]: every systemd-managed cgroup a host
/// would nest sessions under is named `user.slice`, `system.slice`, or `init.scope`, so rejecting
/// `.` would reject the standard hierarchy. Traversal is still impossible because the caller only
/// passes [`Component::Normal`] components, and `.`, `..`, and leading dots are rejected here so a
/// component can never be a relative reference or a hidden name.
fn validate_cgroup_component(value: &str) -> Result<(), RuntimeError> {
    if value.is_empty()
        || value.starts_with('.')
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
    {
        return Err(RuntimeError::InvalidConfig(format!(
            "cgroup parent component must be a non-hidden name of ASCII letters, digits, '_', '-' or '.': {value}"
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
    /// Digest required from the exact executable bytes used by the production runner.
    ///
    /// When present, the production runner copies the opened, no-follow source into a sealed
    /// executable memfd and executes that descriptor. The source path therefore cannot be swapped
    /// between verification and `execve`.
    pub expected_digest: Option<Sha256Digest>,
}

impl CommandSpec {
    fn new(program: impl Into<PathBuf>, args: impl IntoIterator<Item = String>) -> Self {
        Self {
            program: program.into(),
            args: args.into_iter().collect(),
            expected_digest: None,
        }
    }

    fn pinned(artifact: &PinnedArtifact, args: impl IntoIterator<Item = String>) -> Self {
        Self {
            program: artifact.path.clone(),
            args: args.into_iter().collect(),
            expected_digest: Some(artifact.digest),
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
    /// Verifies that the live dm-verity mapper is bound to the requested immutable inputs.
    ///
    /// Production implementations must query the kernel-backed mapper through a pinned helper and
    /// reject a foreign mapper name, data device, hash device, root hash, algorithm, block sizes,
    /// mode, or verification status. The default is deliberately fail-closed so a new adapter
    /// cannot silently omit this post-open check.
    ///
    /// # Errors
    ///
    /// Returns an adapter error when the live mapper does not match `expected` exactly.
    fn verify_verity(
        &mut self,
        _veritysetup: &PinnedArtifact,
        _expected: &DmVerityConfig,
    ) -> Result<(), RuntimeError> {
        Err(RuntimeError::Command(
            "command runner does not implement live dm-verity verification".to_owned(),
        ))
    }
    /// Opens the expected dm-verity mapping.
    ///
    /// The default command retains the explicit `--readonly` request used by the mock boundary.
    /// Production `veritysetup` versions differ here: dm-verity mappings are intrinsically
    /// read-only, while some packaged `veritysetup` releases reject that optional flag.  The real
    /// runner therefore supplies the same read-only kernel primitive without relying on the
    /// version-specific spelling.
    ///
    /// # Errors
    ///
    /// Returns an adapter error when the mapping command cannot be started or exits unsuccessfully.
    fn open_verity(
        &mut self,
        veritysetup: &PinnedArtifact,
        expected: &DmVerityConfig,
    ) -> Result<(), RuntimeError> {
        self.run(&CommandSpec::pinned(
            veritysetup,
            [
                "open".to_owned(),
                "--readonly".to_owned(),
                expected.data_device.display().to_string(),
                expected.mapper_name.clone(),
                expected.hash_device.display().to_string(),
                expected.root_hash.to_hex(),
            ],
        ))
        .map(|_| ())
    }
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
    /// Registers the exact jailer root and its instance parent for rollback ownership.
    ///
    /// This boundary is intentionally separate from [`Self::prepare_jailer_resources`]: the
    /// runtime must establish the cleanup identity before a later resource-transfer operation
    /// can fail.  A production adapter records stable object identities and refuses replacements;
    /// test doubles that do not create a jail tree may retain the default no-op.
    ///
    /// # Errors
    ///
    /// Returns an adapter error when the root or its parent cannot be verified as an owned real
    /// directory.
    fn register_jailer_root(&mut self, _jail_root: &Path) -> Result<(), RuntimeError> {
        Ok(())
    }
    /// Transfers ownership of the exact workspace image and jailed root-device binding to the
    /// dedicated non-root jailer identity before Firecracker is exec'd.
    ///
    /// The default is a compatibility no-op for non-production test doubles.  The production
    /// filesystem adapter must verify its ownership records and perform this operation on opened
    /// descriptors, never on an untrusted path.
    ///
    /// # Errors
    ///
    /// Returns an adapter error when ownership cannot be transferred safely.
    fn prepare_jailer_resources(
        &mut self,
        _workspace: &Path,
        _jailed_device: &Path,
        _jail_root: &Path,
        _uid: u32,
        _gid: u32,
    ) -> Result<(), RuntimeError> {
        Ok(())
    }
    /// Removes the exact jailer root after all process, mount, and workspace resources are gone.
    ///
    /// The production adapter must retain the root identity from launch preparation and refuse
    /// to follow replacements.  The default keeps existing lifecycle test doubles source
    /// compatible; they do not create a real jail tree.
    ///
    /// # Errors
    ///
    /// Returns an adapter error when the owned jail cannot be removed safely.
    fn remove_jail(&mut self, _jail_root: &Path) -> Result<(), RuntimeError> {
        Ok(())
    }
    /// Bind-mounts a verified host block device at an owner-owned path inside the jail.
    ///
    /// # Errors
    ///
    /// Returns an adapter error when the source is not a block device, the target cannot be
    /// exclusively created, or the mount cannot be observed as the exact source device.
    fn bind_block_device(
        &mut self,
        _source: &Path,
        _jailed_device: &Path,
    ) -> Result<(), RuntimeError> {
        Err(RuntimeError::Io(
            "filesystem adapter cannot bind a jailed block device".to_owned(),
        ))
    }
    /// Unmounts and removes a block-device target created by [`Self::bind_block_device`].
    ///
    /// # Errors
    ///
    /// Returns an adapter error when the exact owned mount or its covered target cannot be
    /// observed and released safely.
    fn unbind_block_device(
        &mut self,
        _source: &Path,
        _jailed_device: &Path,
    ) -> Result<(), RuntimeError> {
        Err(RuntimeError::Io(
            "filesystem adapter cannot unbind a jailed block device".to_owned(),
        ))
    }
    /// Creates a clone at `destination` from `source`.
    ///
    /// # Errors
    ///
    /// Returns an adapter error when the clone cannot be created.
    fn clone_workspace(&mut self, source: &Path, destination: &Path) -> Result<(), RuntimeError>;
    /// Creates a sparse, exclusively-owned raw image adjacent to an existing workspace clone.
    ///
    /// The image remains owned by `workspace` and is removed together with it. The caller runs
    /// the separately pinned formatter only after this method returns successfully.
    ///
    /// # Errors
    ///
    /// Returns an adapter error when the clone is not owned, the image path is unsafe or already
    /// present, or the exact-size regular file cannot be durably created.
    fn create_workspace_image(
        &mut self,
        _workspace: &Path,
        _image: &Path,
        _size_bytes: u64,
    ) -> Result<(), RuntimeError> {
        Err(RuntimeError::Io(
            "filesystem adapter cannot create a workspace block image".to_owned(),
        ))
    }
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

/// Raw transport boundary for Firecracker or guest-supervisor API calls.
///
/// Guest lifecycle authorization is not delegated to this trait: [`Runtime`] validates the
/// challenge and all five identity fields in each guest acknowledgement before changing state.
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

    /// Returns the exact Unix socket used for Firecracker API requests.
    #[must_use]
    pub fn socket_path(&self) -> &Path {
        &self.socket
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
        validate_api_request(request)?;
        let mut stream = UnixStream::connect(&self.socket).map_err(RuntimeError::from)?;
        stream
            .set_read_timeout(Some(self.timeout))
            .map_err(RuntimeError::from)?;
        stream
            .set_write_timeout(Some(self.timeout))
            .map_err(RuntimeError::from)?;
        request_over_stream(&mut stream, request)
    }
}

/// Production guest-control client over Firecracker's host-initiated vsock UDS protocol.
///
/// The UDS path and guest CID are the exact values exported and verified from Firecracker's VM
/// configuration. The explicit guest port selects the guest supervisor listener; no factory can
/// substitute another in-process [`ApiClient`].
pub struct FirecrackerVsockApiClient {
    uds_path: PathBuf,
    guest_cid: u32,
    guest_port: u32,
    timeout: Duration,
}

impl FirecrackerVsockApiClient {
    /// Seals one exact Firecracker vsock device and guest supervisor port.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeError::InvalidConfig`] for a non-absolute UDS path, reserved guest CID,
    /// zero guest port, or the wildcard port value.
    pub fn new(
        uds_path: impl Into<PathBuf>,
        guest_cid: u32,
        guest_port: u32,
    ) -> Result<Self, RuntimeError> {
        let uds_path = uds_path.into();
        validate_absolute_path("guest-control vsock UDS", &uds_path)?;
        if guest_cid < 3 {
            return Err(RuntimeError::InvalidConfig(
                "guest-control CID must be at least 3".to_owned(),
            ));
        }
        if guest_port == 0 || guest_port == u32::MAX {
            return Err(RuntimeError::InvalidConfig(
                "guest-control vsock port must be explicit, non-zero, and non-wildcard".to_owned(),
            ));
        }
        Ok(Self {
            uds_path,
            guest_cid,
            guest_port,
            timeout: Duration::from_secs(5),
        })
    }

    /// Returns the exact Firecracker UDS path.
    #[must_use]
    pub fn uds_path(&self) -> &Path {
        &self.uds_path
    }

    /// Returns the guest CID bound by Firecracker's exported VM configuration.
    #[must_use]
    pub const fn guest_cid(&self) -> u32 {
        self.guest_cid
    }

    /// Returns the fixed guest supervisor port.
    #[must_use]
    pub const fn guest_port(&self) -> u32 {
        self.guest_port
    }

    /// Sets the bounded handshake and HTTP timeout used for each control call.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeError::InvalidConfig`] when `timeout` is zero.
    pub fn with_timeout(mut self, timeout: Duration) -> Result<Self, RuntimeError> {
        if timeout.is_zero() {
            return Err(RuntimeError::InvalidConfig(
                "guest-control timeout must be non-zero".to_owned(),
            ));
        }
        self.timeout = timeout;
        Ok(self)
    }

    fn connect(&self) -> Result<UnixStream, RuntimeError> {
        const HANDSHAKE_LIMIT: usize = 64;
        let mut stream = UnixStream::connect(&self.uds_path).map_err(RuntimeError::from)?;
        stream
            .set_read_timeout(Some(self.timeout))
            .map_err(RuntimeError::from)?;
        stream
            .set_write_timeout(Some(self.timeout))
            .map_err(RuntimeError::from)?;
        writeln!(stream, "CONNECT {}", self.guest_port).map_err(RuntimeError::from)?;
        stream.flush().map_err(RuntimeError::from)?;

        let mut acknowledgement = Vec::new();
        let mut byte = [0_u8; 1];
        loop {
            stream.read_exact(&mut byte).map_err(RuntimeError::from)?;
            acknowledgement.push(byte[0]);
            if acknowledgement.len() > HANDSHAKE_LIMIT {
                return Err(RuntimeError::Api(
                    "Firecracker vsock acknowledgement exceeds safety limit".to_owned(),
                ));
            }
            if byte[0] == b'\n' {
                break;
            }
        }
        let acknowledgement = std::str::from_utf8(&acknowledgement).map_err(|_| {
            RuntimeError::Api("Firecracker vsock acknowledgement is not UTF-8".to_owned())
        })?;
        let assigned_port = acknowledgement
            .strip_prefix("OK ")
            .and_then(|value| value.strip_suffix('\n'))
            .filter(|value| !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()))
            .and_then(|value| value.parse::<u32>().ok())
            .filter(|port| *port != 0 && *port != u32::MAX)
            .ok_or_else(|| {
                RuntimeError::Api(
                    "Firecracker vsock returned an invalid connection acknowledgement".to_owned(),
                )
            })?;
        let _ = assigned_port;
        Ok(stream)
    }
}

impl ApiClient for FirecrackerVsockApiClient {
    fn request(&mut self, request: &ApiRequest) -> Result<ApiResponse, RuntimeError> {
        validate_api_request(request)?;
        let mut stream = self.connect()?;
        request_over_stream(&mut stream, request)
    }
}

fn validate_api_request(request: &ApiRequest) -> Result<(), RuntimeError> {
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
    Ok(())
}

fn request_over_stream(
    stream: &mut UnixStream,
    request: &ApiRequest,
) -> Result<ApiResponse, RuntimeError> {
    validate_api_request(request)?;
    let body = request.body.as_bytes();
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
    UnixApiClient::read_response(stream)
}

/// Production command runner backed by `std::process::Command`.
pub struct RealCommandRunner {
    children: HashMap<u32, ManagedChild>,
    command_timeout: Duration,
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
            command_timeout: COMMAND_TIMEOUT,
        }
    }

    #[cfg(test)]
    fn with_command_timeout(command_timeout: Duration) -> Self {
        Self {
            children: HashMap::new(),
            command_timeout,
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

    fn ensure_child_capacity(&self) -> Result<(), RuntimeError> {
        if self.children.len() >= MAX_MANAGED_CHILDREN {
            Err(RuntimeError::Command(format!(
                "managed child limit of {MAX_MANAGED_CHILDREN} was reached"
            )))
        } else {
            Ok(())
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
    DeadlineExceeded,
    Io(String),
}

#[derive(Debug)]
struct BoundedReadResult {
    bytes: Vec<u8>,
    error: Option<BoundedReadError>,
}

fn read_bounded<R: Read>(mut reader: R, deadline: Instant) -> BoundedReadResult {
    let mut bytes = Vec::with_capacity(MAX_COMMAND_OUTPUT_BYTES.min(COMMAND_READ_CHUNK_BYTES));
    let mut buffer = [0_u8; COMMAND_READ_CHUNK_BYTES];
    loop {
        if Instant::now() >= deadline {
            return BoundedReadResult {
                bytes,
                error: Some(BoundedReadError::DeadlineExceeded),
            };
        }
        let count = match reader.read(&mut buffer) {
            Ok(count) => count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(PROCESS_POLL_INTERVAL);
                continue;
            }
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
    deadline: Instant,
    sender: mpsc::Sender<(CommandOutputStream, bool)>,
) -> io::Result<thread::JoinHandle<BoundedReadResult>> {
    thread::Builder::new()
        .name(format!("command-{}-reader", stream.name()))
        .spawn(move || {
            let result = read_bounded(reader, deadline);
            let _ = sender.send((stream, result.error.is_some()));
            result
        })
}

fn set_nonblocking(stream: impl AsFd) -> Result<(), RuntimeError> {
    let flags = fcntl_getfl(&stream).map_err(|error| RuntimeError::Io(error.to_string()))?;
    fcntl_setfl(&stream, flags | OFlags::NONBLOCK)
        .map_err(|error| RuntimeError::Io(error.to_string()))
}

unsafe extern "C" {
    #[link_name = "kill"]
    fn kill_process(process: i32, signal: i32) -> i32;
}

fn signal_process_group(pid: u32) -> Result<(), RuntimeError> {
    const SIGKILL: i32 = 9;
    const ESRCH: i32 = 3;
    let process_group = i32::try_from(pid).map_err(|_| {
        RuntimeError::Command(format!("process identifier {pid} exceeds platform range"))
    })?;
    // SAFETY: `kill` takes two plain integers. The negative, validated child PID names the
    // process group created for this child, and SIGKILL requires no borrowed memory.
    if unsafe { kill_process(-process_group, SIGKILL) } == 0 {
        return Ok(());
    }
    let error = io::Error::last_os_error();
    if error.raw_os_error() == Some(ESRCH) {
        Ok(())
    } else {
        Err(RuntimeError::Command(format!(
            "killing process group {pid} failed: {error}"
        )))
    }
}

fn reap_child_until(
    child: &mut Child,
    pid: u32,
    deadline: Instant,
) -> Result<ExitStatus, RuntimeError> {
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status),
            Ok(None) if Instant::now() < deadline => thread::sleep(PROCESS_POLL_INTERVAL),
            Ok(None) => {
                return Err(RuntimeError::Command(format!(
                    "process {pid} did not exit before the cleanup deadline"
                )));
            }
            Err(error) => {
                return Err(RuntimeError::Command(format!(
                    "checking process {pid} during cleanup failed: {error}"
                )));
            }
        }
    }
}

fn stop_process_group_until(
    child: &mut Child,
    pid: u32,
    deadline: Instant,
) -> Result<ExitStatus, RuntimeError> {
    let group_result = signal_process_group(pid);
    match child.try_wait() {
        Ok(Some(status)) => {
            group_result?;
            return Ok(status);
        }
        Ok(None) => {
            if let Err(kill_error) = child.kill()
                && group_result.is_err()
            {
                return Err(RuntimeError::Command(format!(
                    "stopping process {pid} failed: {kill_error}; {}",
                    group_result.expect_err("checked as an error")
                )));
            }
        }
        Err(error) => {
            return Err(RuntimeError::Command(format!(
                "checking process {pid} before termination failed: {error}"
            )));
        }
    }
    let status = reap_child_until(child, pid, deadline)?;
    group_result?;
    Ok(status)
}

#[cold]
fn abort_cleanup(_context: &str, _error: &RuntimeError) -> ! {
    // Diagnostics must not turn fail-stop into an unbounded write to an inherited stderr pipe.
    std::process::abort();
}

struct CommandChild {
    child: Child,
    cleanup_required: bool,
}

impl CommandChild {
    fn new(child: Child) -> Self {
        Self {
            child,
            cleanup_required: true,
        }
    }
}

impl Drop for CommandChild {
    fn drop(&mut self) {
        if !self.cleanup_required {
            return;
        }
        let pid = self.child.id();
        if let Err(error) =
            stop_process_group_until(&mut self.child, pid, Instant::now() + PROCESS_STOP_TIMEOUT)
        {
            abort_cleanup("dropping an active command", &error);
        }
    }
}

fn monitor_command(
    child: &mut Child,
    receiver: &mpsc::Receiver<(CommandOutputStream, bool)>,
    deadline: Instant,
) -> Result<ExitStatus, String> {
    let pid = child.id();
    loop {
        let mut reader_error = false;
        while let Ok((_stream, has_error)) = receiver.try_recv() {
            reader_error |= has_error;
        }
        if reader_error {
            return stop_process_group_until(child, pid, Instant::now() + PROCESS_STOP_TIMEOUT)
                .map_err(|error| {
                    abort_cleanup("stopping a command after capture failure", &error)
                });
        }
        if Instant::now() >= deadline {
            stop_process_group_until(child, pid, Instant::now() + PROCESS_STOP_TIMEOUT)
                .unwrap_or_else(|error| abort_cleanup("stopping a command after timeout", &error));
            return Err("execution deadline exceeded".to_owned());
        }
        match child.try_wait() {
            // `try_wait` reaps the child.  Its PID/PGID can be reused immediately after this
            // branch, so signalling the old process group here could kill an unrelated group.
            // Descendants are stopped only while the unreaped leader still pins the identifier.
            Ok(Some(status)) => return Ok(status),
            Ok(None) => thread::sleep(PROCESS_POLL_INTERVAL),
            Err(error) => {
                stop_process_group_until(child, pid, Instant::now() + PROCESS_STOP_TIMEOUT)
                    .unwrap_or_else(|cleanup_error| {
                        abort_cleanup("stopping a command after wait failure", &cleanup_error)
                    });
                return Err(error.to_string());
            }
        }
    }
}

fn join_command_reader(
    reader: thread::JoinHandle<BoundedReadResult>,
    stream: CommandOutputStream,
    deadline: Instant,
) -> Result<BoundedReadResult, RuntimeError> {
    while !reader.is_finished() {
        if Instant::now() >= deadline {
            abort_cleanup(
                "waiting for a command output reader",
                &RuntimeError::Command(format!(
                    "{} reader did not stop before the cleanup deadline",
                    stream.name()
                )),
            );
        }
        thread::sleep(PROCESS_POLL_INTERVAL);
    }
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
                BoundedReadError::DeadlineExceeded => {
                    format!("{} capture exceeded the command deadline", stream.name())
                }
                BoundedReadError::Io(message) => {
                    format!("{} capture failed: {message}", stream.name())
                }
            };
            return Some(message);
        }
    }
    None
}

fn seal_command_executable(
    command: &CommandSpec,
) -> Result<Option<recovery::SealedExecutable>, RuntimeError> {
    command
        .expected_digest
        .map(|digest| {
            recovery::SealedExecutable::load(
                "pinned command executable",
                &PinnedArtifact::new(&command.program, digest),
            )
        })
        .transpose()
}

fn spawn_detached(command: &CommandSpec) -> Result<Child, RuntimeError> {
    let sealed = seal_command_executable(command)?;
    let program = sealed.as_ref().map_or(
        command.program.as_path(),
        recovery::SealedExecutable::program,
    );
    let mut process = Command::new(program);
    process
        .args(&command.args)
        // Host credentials belong to the Broker process. Firecracker, jailer,
        // filesystem formatters, and device-mapper helpers receive no ambient
        // environment from the daemon.
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .process_group(0);
    process.spawn().map_err(RuntimeError::from)
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

fn digest_bounded_regular_file(
    path: &Path,
    maximum_bytes: u64,
) -> Result<Sha256Digest, RuntimeError> {
    let descriptor = open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|error| RuntimeError::Io(error.to_string()))?;
    let mut file = File::from(descriptor);
    let metadata = file.metadata().map_err(RuntimeError::from)?;
    if !metadata.is_file() || metadata.nlink() != 1 {
        return Err(RuntimeError::InvalidConfig(format!(
            "digest input must be a singly-linked regular file: {}",
            path.display()
        )));
    }
    if metadata.len() > maximum_bytes {
        return Err(RuntimeError::InvalidConfig(format!(
            "digest input exceeds {maximum_bytes}-byte safety limit: {}",
            path.display()
        )));
    }

    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024];
    let mut total = 0_u64;
    loop {
        let count = file.read(&mut buffer).map_err(RuntimeError::from)?;
        if count == 0 {
            return Ok(Sha256Digest(hasher.finalize().into()));
        }
        total = total.checked_add(count as u64).ok_or_else(|| {
            RuntimeError::InvalidConfig("digest input length overflow".to_owned())
        })?;
        if total > maximum_bytes {
            return Err(RuntimeError::InvalidConfig(format!(
                "digest input grew beyond {maximum_bytes}-byte safety limit: {}",
                path.display()
            )));
        }
        hasher.update(&buffer[..count]);
    }
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

fn reap_launcher_until(
    launcher: &mut Child,
    pid: u32,
    deadline: Instant,
) -> Result<(), RuntimeError> {
    match launcher.try_wait() {
        // Once `try_wait` has reaped the launcher, `pid` may already identify an unrelated
        // process group.  Never signal by the stale numeric identifier in this branch.
        Ok(Some(_)) => Ok(()),
        Ok(None) => stop_process_group_until(launcher, pid, deadline).map(|_| ()),
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
    deadline: Instant,
) -> Result<(), RuntimeError> {
    // Once the launcher is reaped it cannot create another cgroup. Observe the exact expected
    // scope afterwards and kill every task if the jailer created it before exiting.
    reap_launcher_until(launcher, pid, deadline)?;
    if let Some(owned_cgroup) = observe_owned_cgroup(ownership)? {
        stop_owned_cgroup(launcher, pid, &owned_cgroup, deadline)?;
    }
    Ok(())
}

fn stop_owned_cgroup(
    launcher: &mut Child,
    pid: u32,
    ownership: &OwnedCgroup,
    deadline: Instant,
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
            thread::sleep(PROCESS_POLL_INTERVAL);
        }
    }
    reap_launcher_until(launcher, pid, deadline)?;
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

fn stop_managed_child(
    managed: &mut ManagedChild,
    pid: u32,
    deadline: Instant,
) -> Result<(), RuntimeError> {
    match managed {
        ManagedChild::Direct(child) => reap_launcher_until(child, pid, deadline),
        ManagedChild::PendingOwned {
            launcher,
            ownership,
        } => stop_pending_owned(launcher, pid, ownership, deadline),
        ManagedChild::Isolated {
            launcher,
            ownership,
        } => stop_owned_cgroup(launcher, pid, ownership, deadline),
    }
}

impl CommandRunner for RealCommandRunner {
    fn run(&mut self, command: &CommandSpec) -> Result<CommandOutput, RuntimeError> {
        let deadline = Instant::now() + self.command_timeout;
        let sealed = seal_command_executable(command)?;
        let program = sealed.as_ref().map_or(
            command.program.as_path(),
            recovery::SealedExecutable::program,
        );
        let mut process = Command::new(program);
        process
            .args(&command.args)
            // In particular, never inherit EGRESS_GITHUB_TOKEN or proxy
            // configuration into privileged host-side helper processes.
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .process_group(0);
        let mut command_child = CommandChild::new(process.spawn().map_err(RuntimeError::from)?);
        let child = &mut command_child.child;
        let pid = child.id();

        let Some(stdout) = child.stdout.take() else {
            return Err(RuntimeError::Command(
                "failed to capture command stdout".to_owned(),
            ));
        };
        let Some(stderr) = child.stderr.take() else {
            return Err(RuntimeError::Command(
                "failed to capture command stderr".to_owned(),
            ));
        };
        set_nonblocking(&stdout).and_then(|()| set_nonblocking(&stderr))?;
        let (sender, receiver) = mpsc::channel();
        let stdout_reader = spawn_command_reader(
            CommandOutputStream::Stdout,
            stdout,
            deadline,
            sender.clone(),
        )
        .map_err(RuntimeError::from)?;
        let stderr_reader =
            match spawn_command_reader(CommandOutputStream::Stderr, stderr, deadline, sender) {
                Ok(reader) => reader,
                Err(error) => {
                    stop_process_group_until(child, pid, Instant::now() + PROCESS_STOP_TIMEOUT)
                        .unwrap_or_else(|cleanup_error| {
                            abort_cleanup("recovering command reader setup", &cleanup_error)
                        });
                    command_child.cleanup_required = false;
                    join_command_reader(
                        stdout_reader,
                        CommandOutputStream::Stdout,
                        Instant::now() + PROCESS_STOP_TIMEOUT,
                    )?;
                    return Err(RuntimeError::from(error));
                }
            };

        let wait_result = monitor_command(child, &receiver, deadline);
        command_child.cleanup_required = false;
        let reader_cleanup_deadline = Instant::now() + PROCESS_STOP_TIMEOUT;
        let stdout_result = join_command_reader(
            stdout_reader,
            CommandOutputStream::Stdout,
            reader_cleanup_deadline,
        );
        let stderr_result = join_command_reader(
            stderr_reader,
            CommandOutputStream::Stderr,
            reader_cleanup_deadline,
        );
        let stdout_result = stdout_result?;
        let stderr_result = stderr_result?;
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
        self.ensure_child_capacity()?;
        let child = spawn_detached(command)?;
        let pid = child.id();
        self.children.insert(pid, ManagedChild::Direct(child));
        Ok(ProcessHandle { pid })
    }

    fn verify_verity(
        &mut self,
        veritysetup: &PinnedArtifact,
        expected: &DmVerityConfig,
    ) -> Result<(), RuntimeError> {
        let output = self.run(&CommandSpec::pinned(
            veritysetup,
            ["status".to_owned(), expected.mapper_name.clone()],
        ))?;
        recovery::validate_live_verity_status(&output.stdout, expected)
    }

    fn open_verity(
        &mut self,
        veritysetup: &PinnedArtifact,
        expected: &DmVerityConfig,
    ) -> Result<(), RuntimeError> {
        // dm-verity is a read-only target by definition.  The `--readonly` spelling is accepted
        // by some util-linux/cryptsetup builds but rejected by the veritysetup package shipped on
        // the supported host image, so do not make the kernel primitive depend on that optional
        // CLI flag.  `verify_verity` immediately below checks the resulting target is readonly.
        self.run(&CommandSpec::pinned(
            veritysetup,
            [
                "open".to_owned(),
                expected.data_device.display().to_string(),
                expected.mapper_name.clone(),
                expected.hash_device.display().to_string(),
                expected.root_hash.to_hex(),
            ],
        ))
        .map(|_| ())
    }

    #[allow(clippy::too_many_lines)] // Ownership setup and launch observation are one atomic gate.
    fn start_owned(
        &mut self,
        command: &CommandSpec,
        ownership: &ProcessOwnership,
    ) -> Result<ProcessHandle, RuntimeError> {
        self.ensure_child_capacity()?;
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
        let result =
            stop_managed_child(managed, process.pid, Instant::now() + PROCESS_STOP_TIMEOUT);
        if result.is_ok() {
            self.children.remove(&process.pid);
        }
        result
    }
}

impl Drop for RealCommandRunner {
    fn drop(&mut self) {
        let mut first_failure = None;
        for (&pid, managed) in &mut self.children {
            if let Err(error) =
                stop_managed_child(managed, pid, Instant::now() + PROCESS_STOP_TIMEOUT)
            {
                first_failure.get_or_insert(error);
            }
        }
        if let Some(error) = first_failure {
            abort_cleanup("dropping a command runner with owned processes", &error);
        }
        self.children.clear();
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

#[derive(Clone, Copy, Debug)]
struct WorkspaceImageOwnership {
    parent: ObjectIdentity,
    image: ObjectIdentity,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BlockDeviceBindingState {
    Mounted,
    Unmounted,
}

#[derive(Clone, Copy, Debug)]
struct BlockDeviceBinding {
    source: ObjectIdentity,
    target: ObjectIdentity,
    parent: ObjectIdentity,
    state: BlockDeviceBindingState,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct JailOwnership {
    root: ObjectIdentity,
    parent: ObjectIdentity,
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

#[allow(clippy::too_many_lines)] // Descriptor-relative cleanup keeps identity checks adjacent to each unlink.
fn remove_jail_tree(
    root: &Path,
    root_identity: ObjectIdentity,
    parent_identity: ObjectIdentity,
) -> Result<(), RuntimeError> {
    #[allow(clippy::too_many_lines)] // Recursive descriptor cleanup revalidates each entry before removal.
    fn remove_directory(
        directory: &File,
        root_device: u64,
        depth: usize,
        entries: &mut usize,
    ) -> Result<(), RuntimeError> {
        if depth > MAX_WORKSPACE_DEPTH {
            return Err(workspace_error(format!(
                "jailer root exceeds the maximum cleanup depth of {MAX_WORKSPACE_DEPTH}"
            )));
        }
        let scan = File::from(
            openat(
                directory,
                ".",
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                Mode::empty(),
            )
            .map_err(|error| RuntimeError::Io(error.to_string()))?,
        );
        let mut buffer = [MaybeUninit::uninit(); 8192];
        let mut iterator = RawDir::new(&scan, &mut buffer);
        while let Some(entry) = iterator.next() {
            let entry = entry.map_err(|error| RuntimeError::Io(error.to_string()))?;
            let bytes = entry.file_name().to_bytes();
            if matches!(bytes, b"." | b"..") {
                continue;
            }
            let name = OsStr::from_bytes(bytes);
            *entries = entries
                .checked_add(1)
                .ok_or_else(|| workspace_error("jailer root cleanup entry count overflow"))?;
            if *entries > MAX_WORKSPACE_ENTRIES {
                return Err(workspace_error(format!(
                    "jailer root exceeds the maximum cleanup entry count of {MAX_WORKSPACE_ENTRIES}"
                )));
            }
            let child = File::from(
                openat(
                    &scan,
                    name,
                    OFlags::PATH | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                    Mode::empty(),
                )
                .map_err(|error| RuntimeError::Io(error.to_string()))?,
            );
            let metadata = child.metadata().map_err(RuntimeError::from)?;
            let identity = ObjectIdentity::from_metadata(&metadata);
            if metadata.is_dir() {
                if metadata.dev() != root_device {
                    return Err(workspace_error(format!(
                        "jailer root cleanup encountered a mounted descendant: {}",
                        name.to_string_lossy()
                    )));
                }
                let child_directory = File::from(
                    openat(
                        &scan,
                        name,
                        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                        Mode::empty(),
                    )
                    .map_err(|error| RuntimeError::Io(error.to_string()))?,
                );
                let child_metadata = child_directory.metadata().map_err(RuntimeError::from)?;
                if !child_metadata.is_dir()
                    || ObjectIdentity::from_metadata(&child_metadata) != identity
                {
                    return Err(workspace_error(format!(
                        "jailer root directory changed before recursive cleanup: {}",
                        name.to_string_lossy()
                    )));
                }
                remove_directory(&child_directory, root_device, depth + 1, entries)?;
                let current = File::from(
                    openat(
                        &scan,
                        name,
                        OFlags::PATH | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                        Mode::empty(),
                    )
                    .map_err(|error| RuntimeError::Io(error.to_string()))?,
                );
                let current_metadata = current.metadata().map_err(RuntimeError::from)?;
                if !current_metadata.is_dir()
                    || ObjectIdentity::from_metadata(&current_metadata) != identity
                {
                    return Err(workspace_error(format!(
                        "jailer root directory changed before removal: {}",
                        name.to_string_lossy()
                    )));
                }
                unlinkat(&scan, name, AtFlags::REMOVEDIR)
                    .map_err(|error| RuntimeError::Io(error.to_string()))?;
            } else {
                let current = File::from(
                    openat(
                        &scan,
                        name,
                        OFlags::PATH | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                        Mode::empty(),
                    )
                    .map_err(|error| RuntimeError::Io(error.to_string()))?,
                );
                let current_metadata = current.metadata().map_err(RuntimeError::from)?;
                if current_metadata.is_dir()
                    || ObjectIdentity::from_metadata(&current_metadata) != identity
                {
                    return Err(workspace_error(format!(
                        "jailer root entry changed before removal: {}",
                        name.to_string_lossy()
                    )));
                }
                unlinkat(&scan, name, AtFlags::empty())
                    .map_err(|error| RuntimeError::Io(error.to_string()))?;
            }
        }
        Ok(())
    }

    let parent = root
        .parent()
        .ok_or_else(|| workspace_error("jailer root has no parent directory"))?;
    let parent_file = File::from(
        open(
            parent,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(|error| RuntimeError::Io(error.to_string()))?,
    );
    let observed_parent = parent_file.metadata().map_err(RuntimeError::from)?;
    if !observed_parent.is_dir()
        || ObjectIdentity::from_metadata(&observed_parent) != parent_identity
    {
        return Err(workspace_error(format!(
            "jailer root parent changed before cleanup: {}",
            parent.display()
        )));
    }
    let name = root
        .file_name()
        .ok_or_else(|| workspace_error("jailer root has no final component"))?;
    let root_file = File::from(
        openat(
            &parent_file,
            name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(|error| RuntimeError::Io(error.to_string()))?,
    );
    let metadata = root_file.metadata().map_err(RuntimeError::from)?;
    if !metadata.is_dir()
        || metadata.dev() != observed_parent.dev()
        || ObjectIdentity::from_metadata(&metadata) != root_identity
    {
        return Err(workspace_error(format!(
            "jailer root was replaced or mounted before cleanup: {}",
            root.display()
        )));
    }
    let mut entries = 0;
    remove_directory(&root_file, metadata.dev(), 0, &mut entries)?;
    let current = File::from(
        openat(
            &parent_file,
            name,
            OFlags::PATH | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(|error| RuntimeError::Io(error.to_string()))?,
    );
    let current_metadata = current.metadata().map_err(RuntimeError::from)?;
    if !current_metadata.is_dir()
        || ObjectIdentity::from_metadata(&current_metadata) != root_identity
    {
        return Err(workspace_error(format!(
            "jailer root changed during cleanup: {}",
            root.display()
        )));
    }
    unlinkat(&parent_file, name, AtFlags::REMOVEDIR)
        .map_err(|error| RuntimeError::Io(error.to_string()))
}

/// Production filesystem adapter with symlink-safe recursive workspace copying.
#[derive(Debug, Default)]
pub struct RealFileSystem {
    owned_workspaces: HashMap<PathBuf, WorkspaceOwnership>,
    owned_workspace_images: HashMap<PathBuf, WorkspaceImageOwnership>,
    block_devices: HashMap<PathBuf, BlockDeviceBinding>,
    owned_jails: HashMap<PathBuf, JailOwnership>,
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

fn prepare_block_device_bind_target(
    jailed_device: &Path,
) -> Result<(ObjectIdentity, ObjectIdentity), RuntimeError> {
    let parent = jailed_device.parent().ok_or_else(|| {
        RuntimeError::InvalidConfig("jailed dm-verity device has no parent".to_owned())
    })?;
    let parent_identity = ensure_directory_path(parent, false)?;
    validate_destination_absence(jailed_device)?;
    let target = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(jailed_device)
        .map_err(RuntimeError::from)?;
    target.sync_all().map_err(RuntimeError::from)?;
    let target_metadata = metadata_at(jailed_device)?;
    if target_metadata.file_type().is_symlink()
        || !target_metadata.is_file()
        || target_metadata.nlink() != 1
        || target_metadata.mode() & 0o077 != 0
    {
        return Err(workspace_error(format!(
            "jailed dm-verity mount target is not an exclusive owner-only regular file: {}",
            jailed_device.display()
        )));
    }
    Ok((
        parent_identity,
        ObjectIdentity::from_metadata(&target_metadata),
    ))
}

impl RealFileSystem {
    /// Creates a filesystem adapter.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn transfer_opened_ownership(
        path: &Path,
        flags: OFlags,
        uid: u32,
        gid: u32,
    ) -> Result<(), RuntimeError> {
        let descriptor = open(
            path,
            flags | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(|error| RuntimeError::Io(error.to_string()))?;
        let file = File::from(descriptor);
        fchown(&file, Some(Uid::from_raw(uid)), Some(Gid::from_raw(gid)))
            .map_err(|error| RuntimeError::Io(error.to_string()))
    }

    fn workspace_image_path(workspace: &Path) -> Result<PathBuf, RuntimeError> {
        let parent = workspace
            .parent()
            .ok_or_else(|| workspace_error("workspace clone has no parent directory"))?;
        let name = workspace
            .file_name()
            .ok_or_else(|| workspace_error("workspace clone has no final component"))?;
        Ok(parent.join(format!(
            "{}{WORKSPACE_IMAGE_FILE_SUFFIX}",
            name.to_string_lossy()
        )))
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

    fn remove_owned_workspace_image(&mut self, workspace: &Path) -> Result<(), RuntimeError> {
        let Some(ownership) = self.owned_workspace_images.get(workspace).copied() else {
            return Ok(());
        };
        let image = workspace
            .parent()
            .ok_or_else(|| workspace_error("workspace clone has no parent directory"))?
            .join(format!(
                "{}{}",
                workspace
                    .file_name()
                    .ok_or_else(|| workspace_error("workspace clone has no final component"))?
                    .to_string_lossy(),
                WORKSPACE_IMAGE_FILE_SUFFIX
            ));
        let parent = image
            .parent()
            .ok_or_else(|| workspace_error("workspace image has no parent directory"))?;
        let parent_metadata = metadata_at(parent)?;
        if ObjectIdentity::from_metadata(&parent_metadata) != ownership.parent {
            return Err(workspace_error(format!(
                "workspace image parent was replaced and will not be modified: {}",
                parent.display()
            )));
        }
        let metadata = match fs::symlink_metadata(&image) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                self.owned_workspace_images.remove(workspace);
                return Ok(());
            }
            Err(error) => return Err(error.into()),
        };
        if metadata.file_type().is_symlink()
            || !metadata.is_file()
            || metadata.nlink() != 1
            || ObjectIdentity::from_metadata(&metadata) != ownership.image
        {
            return Err(workspace_error(format!(
                "workspace image was replaced and will not be removed: {}",
                image.display()
            )));
        }
        fs::remove_file(&image).map_err(RuntimeError::from)?;
        self.owned_workspace_images.remove(workspace);
        Ok(())
    }
}

impl FileSystem for RealFileSystem {
    fn read(&mut self, path: &Path) -> Result<Vec<u8>, RuntimeError> {
        let descriptor = open(
            path,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(|error| RuntimeError::Io(error.to_string()))?;
        let file = File::from(descriptor);
        let metadata = file.metadata().map_err(RuntimeError::from)?;
        if !metadata.is_file() {
            return Err(RuntimeError::InvalidConfig(format!(
                "pinned artifact is not a regular file: {}",
                path.display()
            )));
        }
        if metadata.len() > MAX_ARTIFACT_BYTES {
            return Err(RuntimeError::InvalidConfig(format!(
                "pinned artifact exceeds {MAX_ARTIFACT_BYTES}-byte safety limit: {}",
                path.display()
            )));
        }
        let capacity = usize::try_from(metadata.len()).map_err(|_| {
            RuntimeError::InvalidConfig("pinned artifact length does not fit host size".to_owned())
        })?;
        let mut bytes = Vec::with_capacity(capacity);
        file.take(MAX_ARTIFACT_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(RuntimeError::from)?;
        if bytes.len() as u64 > MAX_ARTIFACT_BYTES {
            return Err(RuntimeError::InvalidConfig(format!(
                "pinned artifact grew beyond {MAX_ARTIFACT_BYTES}-byte safety limit: {}",
                path.display()
            )));
        }
        Ok(bytes)
    }

    fn digest(&mut self, path: &Path) -> Result<Sha256Digest, RuntimeError> {
        digest_bounded_regular_file(path, MAX_SNAPSHOT_FILE_BYTES)
    }

    fn register_jailer_root(&mut self, jail_root: &Path) -> Result<(), RuntimeError> {
        let root_metadata = metadata_at(jail_root)?;
        if root_metadata.file_type().is_symlink() || !root_metadata.is_dir() {
            return Err(workspace_error(format!(
                "jailer root is not a real directory: {}",
                jail_root.display()
            )));
        }
        let parent = jail_root.parent().ok_or_else(|| {
            workspace_error("jailer root has no ownership-tracked parent directory")
        })?;
        let parent_metadata = metadata_at(parent)?;
        if parent_metadata.file_type().is_symlink() || !parent_metadata.is_dir() {
            return Err(workspace_error(format!(
                "jailer root parent is not a real directory: {}",
                parent.display()
            )));
        }
        let ownership = JailOwnership {
            root: ObjectIdentity::from_metadata(&root_metadata),
            parent: ObjectIdentity::from_metadata(&parent_metadata),
        };
        if let Some(previous) = self.owned_jails.get(jail_root) {
            if *previous != ownership {
                return Err(workspace_error(format!(
                    "jailer root ownership changed before launch: {}",
                    jail_root.display()
                )));
            }
        } else {
            self.owned_jails.insert(jail_root.to_path_buf(), ownership);
        }
        Ok(())
    }

    fn prepare_jailer_resources(
        &mut self,
        workspace: &Path,
        jailed_device: &Path,
        jail_root: &Path,
        uid: u32,
        gid: u32,
    ) -> Result<(), RuntimeError> {
        if uid == 0 || gid == 0 {
            return Err(RuntimeError::InvalidConfig(
                "jailer resource owner must be a dedicated non-root identity".to_owned(),
            ));
        }
        let jail_ownership = self.owned_jails.get(jail_root).copied().ok_or_else(|| {
            workspace_error(format!(
                "jailer resource preparation requires a registered jailer root: {}",
                jail_root.display()
            ))
        })?;
        let root_metadata = metadata_at(jail_root)?;
        let parent = jail_root.parent().ok_or_else(|| {
            workspace_error("jailer root has no ownership-tracked parent directory")
        })?;
        let parent_metadata = metadata_at(parent)?;
        if root_metadata.file_type().is_symlink()
            || !root_metadata.is_dir()
            || ObjectIdentity::from_metadata(&root_metadata) != jail_ownership.root
            || parent_metadata.file_type().is_symlink()
            || !parent_metadata.is_dir()
            || ObjectIdentity::from_metadata(&parent_metadata) != jail_ownership.parent
        {
            return Err(workspace_error(format!(
                "jailer root or parent changed before resource preparation: {}",
                jail_root.display()
            )));
        }
        let ownership = self.owned_workspaces.get(workspace).ok_or_else(|| {
            workspace_error(format!(
                "jailer resource preparation requires an owned workspace: {}",
                workspace.display()
            ))
        })?;
        Self::validate_owned_tree(workspace, ownership)?;
        let image = Self::workspace_image_path(workspace)?;
        let image_ownership = self
            .owned_workspace_images
            .get(workspace)
            .copied()
            .ok_or_else(|| {
                workspace_error(format!(
                    "jailer resource preparation requires an owned workspace image: {}",
                    image.display()
                ))
            })?;
        let image_metadata = metadata_at(&image)?;
        if image_metadata.file_type().is_symlink()
            || !image_metadata.is_file()
            || image_metadata.nlink() != 1
            || ObjectIdentity::from_metadata(&image_metadata) != image_ownership.image
        {
            return Err(workspace_error(format!(
                "workspace image was replaced before jailer ownership transfer: {}",
                image.display()
            )));
        }
        Self::transfer_opened_ownership(&image, OFlags::RDWR, uid, gid)?;

        let binding = self
            .block_devices
            .get(jailed_device)
            .copied()
            .ok_or_else(|| {
                workspace_error(format!(
                    "jailer resource preparation requires an owned block-device bind: {}",
                    jailed_device.display()
                ))
            })?;
        if binding.state != BlockDeviceBindingState::Mounted {
            return Err(workspace_error(format!(
                "jailer resource block-device bind is not mounted: {}",
                jailed_device.display()
            )));
        }
        let device_metadata = fs::metadata(jailed_device).map_err(RuntimeError::from)?;
        if !device_metadata.file_type().is_block_device()
            || ObjectIdentity::from_metadata(&device_metadata) != binding.source
        {
            return Err(workspace_error(format!(
                "jailed block-device bind changed before jailer ownership transfer: {}",
                jailed_device.display()
            )));
        }
        Self::transfer_opened_ownership(jailed_device, OFlags::RDONLY, uid, gid)
    }

    fn remove_jail(&mut self, jail_root: &Path) -> Result<(), RuntimeError> {
        let Some(ownership) = self.owned_jails.get(jail_root).copied() else {
            return match fs::symlink_metadata(jail_root) {
                Ok(_) => Err(workspace_error(format!(
                    "jailer root is not owned by this filesystem instance: {}",
                    jail_root.display()
                ))),
                Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
                Err(error) => Err(error.into()),
            };
        };
        match fs::symlink_metadata(jail_root) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink()
                    || !metadata.is_dir()
                    || ObjectIdentity::from_metadata(&metadata) != ownership.root
                {
                    return Err(workspace_error(format!(
                        "jailer root was replaced before cleanup: {}",
                        jail_root.display()
                    )));
                }
                remove_jail_tree(jail_root, ownership.root, ownership.parent)?;
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        let parent = jail_root
            .parent()
            .ok_or_else(|| workspace_error("jailer root has no parent directory"))?;
        let parent_metadata = metadata_at(parent)?;
        if parent_metadata.file_type().is_symlink()
            || !parent_metadata.is_dir()
            || ObjectIdentity::from_metadata(&parent_metadata) != ownership.parent
        {
            return Err(workspace_error(format!(
                "jailer root parent was replaced before cleanup: {}",
                parent.display()
            )));
        }
        fs::remove_dir(parent).map_err(|error| {
            RuntimeError::Io(format!(
                "removing empty jailer instance directory {} failed: {error}",
                parent.display()
            ))
        })?;
        self.owned_jails.remove(jail_root);
        Ok(())
    }

    fn bind_block_device(
        &mut self,
        source: &Path,
        jailed_device: &Path,
    ) -> Result<(), RuntimeError> {
        validate_absolute_path("opened dm-verity device", source)?;
        validate_absolute_path("jailed dm-verity device", jailed_device)?;
        let source_metadata = fs::metadata(source).map_err(RuntimeError::from)?;
        if !source_metadata.file_type().is_block_device() {
            return Err(RuntimeError::InvalidConfig(format!(
                "opened dm-verity source is not a block device: {}",
                source.display()
            )));
        }
        if self.block_devices.contains_key(jailed_device) {
            return Err(RuntimeError::WorkspaceAlreadyExists(
                jailed_device.to_path_buf(),
            ));
        }
        let (parent_identity, target_identity) = prepare_block_device_bind_target(jailed_device)?;
        if let Err(error) = mount_bind(source, jailed_device) {
            let cleanup = match metadata_at(jailed_device) {
                Ok(metadata)
                    if !metadata.file_type().is_symlink()
                        && metadata.is_file()
                        && metadata.nlink() == 1
                        && ObjectIdentity::from_metadata(&metadata) == target_identity =>
                {
                    fs::remove_file(jailed_device).map_err(RuntimeError::from)
                }
                Ok(_) => Err(workspace_error(
                    "jailed dm-verity mount target changed while binding",
                )),
                Err(cleanup_error) => Err(cleanup_error),
            };
            return match cleanup {
                Ok(()) => Err(RuntimeError::from(io::Error::from(error))),
                Err(cleanup_error) => Err(RuntimeError::Rollback {
                    operation: error.to_string(),
                    cleanup: cleanup_error.to_string(),
                }),
            };
        }
        let mounted_metadata = fs::metadata(jailed_device).map_err(RuntimeError::from)?;
        if mounted_metadata.file_type().is_symlink()
            || !mounted_metadata.file_type().is_block_device()
            || mounted_metadata.rdev() != source_metadata.rdev()
            || ObjectIdentity::from_metadata(&mounted_metadata)
                != ObjectIdentity::from_metadata(&source_metadata)
        {
            let operation = workspace_error(format!(
                "jailed dm-verity mount does not expose the exact source device: {}",
                jailed_device.display()
            ));
            let cleanup = unmount(jailed_device, UnmountFlags::NOFOLLOW)
                .map_err(|error| RuntimeError::from(io::Error::from(error)))
                .and_then(|()| {
                    let metadata = metadata_at(jailed_device)?;
                    if metadata.file_type().is_symlink()
                        || !metadata.is_file()
                        || metadata.nlink() != 1
                        || ObjectIdentity::from_metadata(&metadata) != target_identity
                    {
                        return Err(workspace_error(
                            "jailed dm-verity target changed after bind-mount rollback",
                        ));
                    }
                    fs::remove_file(jailed_device).map_err(RuntimeError::from)
                });
            return match cleanup {
                Ok(()) => Err(operation),
                Err(cleanup_error) => Err(RuntimeError::Rollback {
                    operation: operation.to_string(),
                    cleanup: cleanup_error.to_string(),
                }),
            };
        }
        self.block_devices.insert(
            jailed_device.to_path_buf(),
            BlockDeviceBinding {
                source: ObjectIdentity::from_metadata(&source_metadata),
                target: target_identity,
                parent: parent_identity,
                state: BlockDeviceBindingState::Mounted,
            },
        );
        Ok(())
    }

    fn unbind_block_device(
        &mut self,
        source: &Path,
        jailed_device: &Path,
    ) -> Result<(), RuntimeError> {
        let Some(binding) = self.block_devices.get(jailed_device).copied() else {
            return Err(workspace_error(format!(
                "jailed dm-verity device is not owned by this filesystem instance: {}",
                jailed_device.display()
            )));
        };
        let parent = jailed_device.parent().ok_or_else(|| {
            RuntimeError::InvalidConfig("jailed dm-verity device has no parent".to_owned())
        })?;
        let parent_metadata = metadata_at(parent)?;
        if ObjectIdentity::from_metadata(&parent_metadata) != binding.parent {
            return Err(workspace_error(format!(
                "jailed dm-verity mount parent was replaced and will not be modified: {}",
                parent.display()
            )));
        }
        if binding.state == BlockDeviceBindingState::Mounted {
            let source_metadata = fs::metadata(source).map_err(RuntimeError::from)?;
            let mounted_metadata = fs::metadata(jailed_device).map_err(RuntimeError::from)?;
            if !source_metadata.file_type().is_block_device()
                || !mounted_metadata.file_type().is_block_device()
                || ObjectIdentity::from_metadata(&source_metadata) != binding.source
                || ObjectIdentity::from_metadata(&mounted_metadata) != binding.source
                || source_metadata.rdev() != mounted_metadata.rdev()
            {
                return Err(workspace_error(
                    "jailed dm-verity mount no longer exposes the exact owned source device",
                ));
            }
            unmount(jailed_device, UnmountFlags::NOFOLLOW)
                .map_err(|error| RuntimeError::from(io::Error::from(error)))?;
            let Some(binding) = self.block_devices.get_mut(jailed_device) else {
                return Err(workspace_error(
                    "jailed dm-verity binding disappeared after unmount",
                ));
            };
            binding.state = BlockDeviceBindingState::Unmounted;
        }
        let target_metadata = metadata_at(jailed_device)?;
        if target_metadata.file_type().is_symlink()
            || !target_metadata.is_file()
            || target_metadata.nlink() != 1
            || ObjectIdentity::from_metadata(&target_metadata) != binding.target
        {
            return Err(workspace_error(format!(
                "jailed dm-verity target was replaced and will not be removed: {}",
                jailed_device.display()
            )));
        }
        fs::remove_file(jailed_device).map_err(RuntimeError::from)?;
        self.block_devices.remove(jailed_device);
        Ok(())
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

    fn create_workspace_image(
        &mut self,
        workspace: &Path,
        image: &Path,
        size_bytes: u64,
    ) -> Result<(), RuntimeError> {
        let ownership = self.owned_workspaces.get(workspace).ok_or_else(|| {
            workspace_error(format!(
                "workspace image requires an owned clone: {}",
                workspace.display()
            ))
        })?;
        Self::validate_owned_tree(workspace, ownership)?;
        let parent = workspace
            .parent()
            .ok_or_else(|| workspace_error("workspace clone has no parent directory"))?;
        if image.parent() != Some(parent) {
            return Err(workspace_error(format!(
                "workspace image must be adjacent to its clone: {}",
                image.display()
            )));
        }
        let parent_metadata = metadata_at(parent)?;
        if ObjectIdentity::from_metadata(&parent_metadata) != ownership.parent {
            return Err(workspace_error(format!(
                "workspace image parent was replaced: {}",
                parent.display()
            )));
        }
        validate_destination_absence(image)?;
        if self.owned_workspace_images.contains_key(workspace) {
            return Err(RuntimeError::WorkspaceAlreadyExists(image.to_path_buf()));
        }
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(image)
            .map_err(RuntimeError::from)?;
        file.set_len(size_bytes).map_err(RuntimeError::from)?;
        file.sync_all().map_err(RuntimeError::from)?;
        let metadata = metadata_at(image)?;
        if metadata.file_type().is_symlink()
            || !metadata.is_file()
            || metadata.nlink() != 1
            || metadata.len() != size_bytes
            || metadata.mode() & 0o077 != 0
        {
            return Err(workspace_error(format!(
                "workspace image is not an exclusive owner-only regular file: {}",
                image.display()
            )));
        }
        self.owned_workspace_images.insert(
            workspace.to_path_buf(),
            WorkspaceImageOwnership {
                parent: ownership.parent,
                image: ObjectIdentity::from_metadata(&metadata),
            },
        );
        Ok(())
    }

    fn remove_workspace(&mut self, path: &Path) -> Result<(), RuntimeError> {
        let Some(ownership) = self.owned_workspaces.get(path) else {
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
                self.remove_owned_workspace_image(path)?;
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
        self.remove_owned_workspace_image(path)?;
        let ownership = self
            .owned_workspaces
            .get_mut(path)
            .ok_or_else(|| workspace_error("workspace ownership disappeared during cleanup"))?;
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

    /// Returns a challenge bound to one fresh host-allocated identity bundle.
    ///
    /// The default is a domain-separated digest of all five already-fresh identities, so
    /// callers that restore host-supplied identities do not silently allocate a sixth identity.
    /// Production overrides this with independent kernel entropy.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeError::StaleIdentity`] only if no distinct non-zero challenge can be
    /// derived within the bounded counter space.
    fn guest_control_challenge(
        &mut self,
        identities: &IdentityBundle,
    ) -> Result<IdentityId, RuntimeError> {
        derive_guest_control_challenge(identities)
    }
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

    fn guest_control_challenge(
        &mut self,
        identities: &IdentityBundle,
    ) -> Result<IdentityId, RuntimeError> {
        for _ in 0..16 {
            let challenge = self.generate()?;
            if !identities.ids().contains(&challenge) {
                return Ok(challenge);
            }
        }
        Err(RuntimeError::StaleIdentity(
            "kernel entropy repeatedly reused a session identity for the guest-control challenge"
                .to_owned(),
        ))
    }
}

fn derive_guest_control_challenge(identities: &IdentityBundle) -> Result<IdentityId, RuntimeError> {
    let mut transcript = Vec::with_capacity(32 + ID_LENGTH * 5 + 1);
    transcript.extend_from_slice(b"firecracker-guest-control-v1\0");
    for identity in identities.ids() {
        transcript.extend_from_slice(&identity.0);
    }
    for counter in 0_u8..=u8::MAX {
        transcript.push(counter);
        let digest = sha256(&transcript).as_bytes();
        transcript.pop();
        let mut bytes = [0_u8; ID_LENGTH];
        bytes.copy_from_slice(&digest[..ID_LENGTH]);
        let challenge = IdentityId(bytes);
        if !challenge.is_zero() && !identities.ids().contains(&challenge) {
            return Ok(challenge);
        }
    }
    Err(RuntimeError::StaleIdentity(
        "could not derive a distinct guest-control challenge".to_owned(),
    ))
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
    /// Guest root-policy digest sealed into the snapshot image, when the
    /// manifest was created by a policy-aware provisioning boundary.
    policy_digest: Option<AuthorityPolicyDigest>,
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
            policy_digest: None,
            forbidden_identities,
        }
    }

    /// Creates snapshot metadata bound to the guest root policy baked into the image.
    #[must_use]
    pub fn new_bound(
        snapshot_path: impl Into<PathBuf>,
        memory_path: impl Into<PathBuf>,
        artifact_fingerprint: Sha256Digest,
        snapshot_digest: Sha256Digest,
        memory_digest: Sha256Digest,
        policy_digest: AuthorityPolicyDigest,
        forbidden_identities: Vec<IdentityId>,
    ) -> Self {
        Self {
            snapshot_path: snapshot_path.into(),
            memory_path: memory_path.into(),
            artifact_fingerprint,
            snapshot_digest,
            memory_digest,
            policy_digest: Some(policy_digest),
            forbidden_identities,
        }
    }

    /// Returns the root-policy digest sealed into the snapshot image.
    #[must_use]
    pub const fn policy_digest(&self) -> Option<AuthorityPolicyDigest> {
        self.policy_digest
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

    /// Returns the verified manifest's guest root-policy digest, if present.
    #[must_use]
    pub const fn policy_digest(&self) -> Option<AuthorityPolicyDigest> {
        self.manifest.policy_digest
    }
}

/// Lifecycle states that make workload gating observable and auditable.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeState {
    /// Firecracker process and guest are not started.
    New,
    /// VM is booted at the pre-session gate and workload is stopped.
    WorkloadStopped,
    /// The VM was paused successfully and the snapshot files are being written.
    ///
    /// This state is deliberately distinct from [`Self::WorkloadStopped`]: the latter means
    /// that the guest workload gate is closed while the VM is running, whereas this state means
    /// that Firecracker acknowledged the pause request.  A failed snapshot write leaves the
    /// instance here so callers cannot accidentally treat it as an unpaused pre-session VM.
    SnapshotPaused,
    /// A snapshot pause request failed after it was sent and the VM state is therefore unknown.
    ///
    /// The runtime fails closed from this state: another snapshot or workload operation is not
    /// permitted.  [`Runtime::shutdown`] remains available so the process can be terminated
    /// without relying on the VM's unknown state.
    SnapshotPauseUnknown,
    /// A pre-session snapshot has been created.
    Snapshotted,
    /// Snapshot is restored and the workload remains stopped.
    RestoredStopped,
    /// Fresh identities were generated but not injected.
    IdentityRegenerated,
    /// The VM resumed but the guest supervisor has not acknowledged the exact identity bundle.
    IdentityResumedAwaitingAck,
    /// Fresh identities were injected; workload is still stopped.
    IdentityInjected,
    /// Workload start was explicitly requested after identity injection.
    Running,
    /// Process and workspace cleanup completed.
    Stopped,
}

/// A live runtime process and its rollback resources.
#[derive(Debug)]
#[allow(clippy::struct_excessive_bools)] // Cleanup flags independently record each owned resource.
pub struct RuntimeInstance {
    state: RuntimeState,
    process: ProcessHandle,
    process_stopped: bool,
    workspace: PathBuf,
    jail_root: PathBuf,
    workspace_removed: bool,
    jail_removed: bool,
    mapper_name: String,
    verity_opened: bool,
    block_device_state: BlockDeviceState,
    restore_fingerprint: Sha256Digest,
    config_fingerprint: Sha256Digest,
    identities: Option<IdentityBundle>,
    guest_control_challenge: Option<IdentityId>,
    guest_policy_digest: Option<AuthorityPolicyDigest>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BlockDeviceState {
    Bound,
    Unbound,
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

    /// Returns the authority policy digest bound to guest-control v2, if any.
    #[must_use]
    pub const fn policy_digest(&self) -> Option<AuthorityPolicyDigest> {
        self.guest_policy_digest
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
    // `Drop` cannot add adapter bounds that are absent from this public generic type. The only
    // constructor seals the correctly monomorphized cleanup routine without changing its API.
    drop_cleanup: fn(&mut Self),
}

impl<C, F, A, G, I> Drop for Runtime<C, F, A, G, I> {
    fn drop(&mut self) {
        (self.drop_cleanup)(self);
    }
}

#[derive(Debug)]
struct PendingCleanup {
    process: Option<ProcessHandle>,
    block_device: Option<(PathBuf, PathBuf)>,
    verity_opened: bool,
    workspace: Option<PathBuf>,
    jail_root: Option<PathBuf>,
    mapper_name: String,
    veritysetup: PinnedArtifact,
}

#[derive(Clone, Copy)]
struct RollbackResources<'a> {
    process: Option<ProcessHandle>,
    verity_opened: bool,
    block_device_bound: bool,
    workspace_cloned: bool,
    workspace: &'a Path,
    jail_root: Option<&'a Path>,
    mapper_name: &'a str,
    veritysetup: &'a PinnedArtifact,
    jailed_device: &'a Path,
}

impl PendingCleanup {
    fn is_complete(&self) -> bool {
        self.process.is_none()
            && self.block_device.is_none()
            && !self.verity_opened
            && self.workspace.is_none()
            && self.jail_root.is_none()
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
            drop_cleanup: Self::cleanup_before_drop,
        }
    }

    fn cleanup_before_drop(&mut self) {
        let Some(mut pending) = self.pending_cleanup.take() else {
            return;
        };
        let failures = self.cleanup_pending(&mut pending);
        if !pending.is_complete() {
            let error = RuntimeError::Cleanup(if failures.is_empty() {
                "owned runtime resources remained after drop cleanup".to_owned()
            } else {
                failures.join("; ")
            });
            abort_cleanup("dropping a runtime with pending cleanup", &error);
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
    #[allow(clippy::too_many_lines)] // Launch ordering and rollback ownership form one atomic gate.
    pub fn launch(&mut self, config: &RuntimeConfig) -> Result<RuntimeInstance, RuntimeError> {
        self.ensure_no_pending_cleanup()?;
        config.validate()?;
        self.verify_artifacts(config)?;
        let jail_root = config.jail_root()?;
        let workspace = config.workspace.clone_path();
        if let Err(error) = self
            .filesystem
            .clone_workspace(&config.workspace.source, &workspace)
        {
            let cleanup = self.rollback(RollbackResources {
                process: None,
                verity_opened: false,
                block_device_bound: false,
                workspace_cloned: true,
                workspace: &workspace,
                jail_root: None,
                mapper_name: &config.dm_verity.mapper_name,
                jailed_device: &config.dm_verity.jailed_device_path,
                veritysetup: &config.veritysetup,
            });
            return Err(with_cleanup(error, &cleanup));
        }
        if let Err(error) = self.create_workspace_block_image(config, &workspace) {
            let cleanup = self.rollback(RollbackResources {
                process: None,
                verity_opened: false,
                block_device_bound: false,
                workspace_cloned: true,
                workspace: &workspace,
                jail_root: None,
                mapper_name: &config.dm_verity.mapper_name,
                jailed_device: &config.dm_verity.jailed_device_path,
                veritysetup: &config.veritysetup,
            });
            return Err(with_cleanup(error, &cleanup));
        }
        let workspace_cloned = true;
        let mut verity_opened = false;
        let mut block_device_bound = false;
        let mut process = None;
        let mut jail_root_prepared = false;

        let result = (|| {
            self.filesystem.register_jailer_root(&jail_root)?;
            jail_root_prepared = true;
            self.open_verity_mapping(config)?;
            verity_opened = true;
            self.verify_open_verity(config)?;
            self.bind_verity_device(config)?;
            block_device_bound = true;
            self.verify_verity_binding(config)?;
            self.filesystem.prepare_jailer_resources(
                &workspace,
                &config.dm_verity.jailed_device_path,
                &jail_root,
                config.jailer_config.uid,
                config.jailer_config.gid,
            )?;
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
                jail_removed: false,
                mapper_name: config.dm_verity.mapper_name.clone(),
                verity_opened: true,
                block_device_state: BlockDeviceState::Bound,
                restore_fingerprint: config.snapshot_fingerprint(),
                config_fingerprint: config.instance_fingerprint(),
                identities: None,
                guest_control_challenge: None,
                guest_policy_digest: None,
            })
        })();
        match result {
            Ok(instance) => Ok(instance),
            Err(error) => {
                let cleanup = self.rollback(RollbackResources {
                    process,
                    verity_opened,
                    block_device_bound,
                    workspace_cloned,
                    workspace: &workspace,
                    jail_root: jail_root_prepared.then_some(jail_root.as_path()),
                    mapper_name: &config.dm_verity.mapper_name,
                    jailed_device: &config.dm_verity.jailed_device_path,
                    veritysetup: &config.veritysetup,
                });
                Err(with_cleanup(error, &cleanup))
            }
        }
    }

    /// Pauses and creates a snapshot only from a pre-session instance whose workload is stopped.
    ///
    /// Firecracker keeps the VM paused after a successful snapshot.  If snapshot creation or
    /// provenance hashing fails, the instance remains [`RuntimeState::SnapshotPaused`] so callers
    /// must shut it down rather than accidentally reusing a partially captured VM.  If the pause
    /// request itself fails, the state is [`RuntimeState::SnapshotPauseUnknown`] because a lost
    /// response may have raced with Firecracker applying the transition.
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
        if let Err(error) = self.api_call(ApiRequest {
            method: HttpMethod::Patch,
            path: "/vm".to_owned(),
            body: r#"{"state":"Paused"}"#.to_owned(),
        }) {
            // A transport failure is ambiguous: Firecracker may have applied the pause before
            // the response was lost.  Keep an explicit unknown state instead of reporting the
            // instance as the ordinary (running-VM, workload-gated) pre-session state.
            instance.state = RuntimeState::SnapshotPauseUnknown;
            return Err(error);
        }
        instance.state = RuntimeState::SnapshotPaused;
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

    #[allow(clippy::too_many_lines)] // Restore sequencing and rollback ownership form one gate.
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
        let jail_root = config.jail_root()?;
        let workspace = config.workspace.clone_path();
        if let Err(error) = self
            .filesystem
            .clone_workspace(&config.workspace.source, &workspace)
        {
            let cleanup = self.rollback(RollbackResources {
                process: None,
                verity_opened: false,
                block_device_bound: false,
                workspace_cloned: true,
                workspace: &workspace,
                jail_root: None,
                mapper_name: &config.dm_verity.mapper_name,
                jailed_device: &config.dm_verity.jailed_device_path,
                veritysetup: &config.veritysetup,
            });
            return Err(with_cleanup(error, &cleanup));
        }
        if let Err(error) = self.create_workspace_block_image(config, &workspace) {
            let cleanup = self.rollback(RollbackResources {
                process: None,
                verity_opened: false,
                block_device_bound: false,
                workspace_cloned: true,
                workspace: &workspace,
                jail_root: None,
                mapper_name: &config.dm_verity.mapper_name,
                jailed_device: &config.dm_verity.jailed_device_path,
                veritysetup: &config.veritysetup,
            });
            return Err(with_cleanup(error, &cleanup));
        }
        let workspace_cloned = true;
        let mut verity_opened = false;
        let mut block_device_bound = false;
        let mut process = None;
        let mut jail_root_prepared = false;
        let result = (|| {
            self.filesystem.register_jailer_root(&jail_root)?;
            jail_root_prepared = true;
            self.open_verity_mapping(config)?;
            verity_opened = true;
            self.verify_open_verity(config)?;
            self.bind_verity_device(config)?;
            block_device_bound = true;
            self.verify_verity_binding(config)?;
            self.filesystem.prepare_jailer_resources(
                &workspace,
                &config.dm_verity.jailed_device_path,
                &jail_root,
                config.jailer_config.uid,
                config.jailer_config.gid,
            )?;
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
                jail_removed: false,
                mapper_name: config.dm_verity.mapper_name.clone(),
                verity_opened: true,
                block_device_state: BlockDeviceState::Bound,
                restore_fingerprint: config.snapshot_fingerprint(),
                config_fingerprint: config.instance_fingerprint(),
                identities: Some(identities),
                guest_control_challenge: None,
                guest_policy_digest: None,
            })
        })();
        match result {
            Ok(instance) => Ok(instance),
            Err(error) => {
                let cleanup = self.rollback(RollbackResources {
                    process,
                    verity_opened,
                    block_device_bound,
                    workspace_cloned,
                    workspace: &workspace,
                    jail_root: jail_root_prepared.then_some(jail_root.as_path()),
                    mapper_name: &config.dm_verity.mapper_name,
                    jailed_device: &config.dm_verity.jailed_device_path,
                    veritysetup: &config.veritysetup,
                });
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

    #[allow(clippy::too_many_lines)] // Restore sequencing and rollback ownership form one gate.
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
        let jail_root = config.jail_root()?;
        let workspace = config.workspace.clone_path();
        if let Err(error) = self
            .filesystem
            .clone_workspace(&config.workspace.source, &workspace)
        {
            let cleanup = self.rollback(RollbackResources {
                process: None,
                verity_opened: false,
                block_device_bound: false,
                workspace_cloned: true,
                workspace: &workspace,
                jail_root: None,
                mapper_name: &config.dm_verity.mapper_name,
                jailed_device: &config.dm_verity.jailed_device_path,
                veritysetup: &config.veritysetup,
            });
            return Err(with_cleanup(error, &cleanup));
        }
        if let Err(error) = self.create_workspace_block_image(config, &workspace) {
            let cleanup = self.rollback(RollbackResources {
                process: None,
                verity_opened: false,
                block_device_bound: false,
                workspace_cloned: true,
                workspace: &workspace,
                jail_root: None,
                mapper_name: &config.dm_verity.mapper_name,
                jailed_device: &config.dm_verity.jailed_device_path,
                veritysetup: &config.veritysetup,
            });
            return Err(with_cleanup(error, &cleanup));
        }
        let workspace_cloned = true;
        let mut verity_opened = false;
        let mut block_device_bound = false;
        let mut process = None;
        let mut jail_root_prepared = false;
        let result = (|| {
            self.filesystem.register_jailer_root(&jail_root)?;
            jail_root_prepared = true;
            self.open_verity_mapping(config)?;
            verity_opened = true;
            self.verify_open_verity(config)?;
            self.bind_verity_device(config)?;
            block_device_bound = true;
            self.verify_verity_binding(config)?;
            self.filesystem.prepare_jailer_resources(
                &workspace,
                &config.dm_verity.jailed_device_path,
                &jail_root,
                config.jailer_config.uid,
                config.jailer_config.gid,
            )?;
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
                jail_removed: false,
                mapper_name: config.dm_verity.mapper_name.clone(),
                verity_opened: true,
                block_device_state: BlockDeviceState::Bound,
                restore_fingerprint: config.snapshot_fingerprint(),
                config_fingerprint: config.instance_fingerprint(),
                identities: Some(identities),
                guest_control_challenge: None,
                guest_policy_digest: None,
            })
        })();
        match result {
            Ok(instance) => Ok(instance),
            Err(error) => {
                let cleanup = self.rollback(RollbackResources {
                    process,
                    verity_opened,
                    block_device_bound,
                    workspace_cloned,
                    workspace: &workspace,
                    jail_root: jail_root_prepared.then_some(jail_root.as_path()),
                    mapper_name: &config.dm_verity.mapper_name,
                    jailed_device: &config.dm_verity.jailed_device_path,
                    veritysetup: &config.veritysetup,
                });
                Err(with_cleanup(error, &cleanup))
            }
        }
    }

    /// Injects regenerated identities and leaves the workload stopped.
    ///
    /// The runtime explicitly resumes the guest supervisor while its workload remains gated, then
    /// sends the bundle over the exact Firecracker vsock endpoint. The guest must return a
    /// canonical acknowledgement containing `identity-injected`, the challenge, and the exact VM,
    /// session, request, subject, and capability IDs, in this field order: `ack`, `challenge`,
    /// `vm_id`, `session_id`, `request_id`, `subject_id`, `capability_id`. A successful HTTP status
    /// without that complete acknowledgement leaves the workload gate closed.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeError::InvalidState`] or [`RuntimeError::StaleIdentity`] when
    /// identities are not ready, or an API error when injection is rejected.
    pub fn inject_identity(&mut self, instance: &mut RuntimeInstance) -> Result<(), RuntimeError> {
        if instance.guest_policy_digest.is_some() {
            return Err(RuntimeError::PolicyDigestRequired);
        }
        if !matches!(
            instance.state,
            RuntimeState::IdentityRegenerated | RuntimeState::IdentityResumedAwaitingAck
        ) {
            return Err(RuntimeError::InvalidState {
                expected: "IdentityRegenerated or IdentityResumedAwaitingAck".to_owned(),
                actual: format!("{:?}", instance.state),
            });
        }
        if instance.state == RuntimeState::IdentityRegenerated {
            let identities = instance.identities.clone().ok_or_else(|| {
                RuntimeError::StaleIdentity(
                    "identity regeneration state has no identity bundle".to_owned(),
                )
            })?;
            self.guest_control_challenge(instance, &identities)?;
            self.api_call(ApiRequest {
                method: HttpMethod::Patch,
                path: "/vm".to_owned(),
                body: r#"{"state":"Resumed"}"#.to_owned(),
            })?;
            instance.state = RuntimeState::IdentityResumedAwaitingAck;
        }
        self.command_runner.verify_running(instance.process)?;
        let identities = instance.identities.clone().ok_or_else(|| {
            RuntimeError::StaleIdentity("resumed VM has no identity bundle".to_owned())
        })?;
        let challenge = instance.guest_control_challenge.ok_or_else(|| {
            RuntimeError::StaleIdentity("resumed VM has no guest-control challenge".to_owned())
        })?;
        let request =
            guest_control::GuestControlRequest::new(challenge, identities).map_err(|error| {
                RuntimeError::StaleIdentity(format!("invalid guest-control request: {error}"))
            })?;
        self.control_call_with_identity_ack(
            ApiRequest {
                method: HttpMethod::Put,
                path: guest_control::GuestControlAction::InjectIdentity
                    .path()
                    .to_owned(),
                body: request.canonical_body(),
            },
            &request.canonical_acknowledgement(guest_control::GuestControlAction::InjectIdentity),
        )?;
        instance.state = RuntimeState::IdentityInjected;
        Ok(())
    }

    /// Injects regenerated identities while binding the guest to one authority policy digest.
    ///
    /// The digest is retained on the runtime instance before any resumable control call. A
    /// retry after a lost response must therefore use the exact same digest; a different digest
    /// cannot replace the request already associated with the restored VM.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeError::InvalidState`], [`RuntimeError::PolicyDigestMismatch`], or an API
    /// error when the bound injection is not accepted.
    pub fn inject_identity_bound(
        &mut self,
        instance: &mut RuntimeInstance,
        policy_digest: AuthorityPolicyDigest,
    ) -> Result<(), RuntimeError> {
        if !matches!(
            instance.state,
            RuntimeState::IdentityRegenerated | RuntimeState::IdentityResumedAwaitingAck
        ) {
            return Err(RuntimeError::InvalidState {
                expected: "IdentityRegenerated or IdentityResumedAwaitingAck".to_owned(),
                actual: format!("{:?}", instance.state),
            });
        }
        if let Some(existing) = instance.guest_policy_digest {
            if existing != policy_digest {
                return Err(RuntimeError::PolicyDigestMismatch {
                    expected: existing,
                    actual: policy_digest,
                });
            }
        } else {
            instance.guest_policy_digest = Some(policy_digest);
        }
        if instance.state == RuntimeState::IdentityRegenerated {
            let identities = instance.identities.clone().ok_or_else(|| {
                RuntimeError::StaleIdentity(
                    "identity regeneration state has no identity bundle".to_owned(),
                )
            })?;
            self.guest_control_challenge(instance, &identities)?;
            self.api_call(ApiRequest {
                method: HttpMethod::Patch,
                path: "/vm".to_owned(),
                body: r#"{"state":"Resumed"}"#.to_owned(),
            })?;
            instance.state = RuntimeState::IdentityResumedAwaitingAck;
        }
        self.command_runner.verify_running(instance.process)?;
        let identities = instance.identities.clone().ok_or_else(|| {
            RuntimeError::StaleIdentity("resumed VM has no identity bundle".to_owned())
        })?;
        let challenge = instance.guest_control_challenge.ok_or_else(|| {
            RuntimeError::StaleIdentity("resumed VM has no guest-control challenge".to_owned())
        })?;
        let request =
            guest_control::GuestControlRequest::new_bound(challenge, identities, policy_digest)
                .map_err(|error| {
                    RuntimeError::StaleIdentity(format!("invalid guest-control request: {error}"))
                })?;
        self.control_call_with_identity_ack(
            ApiRequest {
                method: HttpMethod::Put,
                path: guest_control::GuestControlAction::InjectIdentityBound
                    .path()
                    .to_owned(),
                body: request.canonical_bound_body(),
            },
            &request.canonical_bound_acknowledgement(
                guest_control::GuestControlAction::InjectIdentityBound,
            ),
        )?;
        instance.state = RuntimeState::IdentityInjected;
        Ok(())
    }

    /// Starts workload execution only after identity injection has succeeded.
    ///
    /// The guest must return the same challenge and five identities with a canonical
    /// `workload-started` acknowledgement. The runtime does not enter [`RuntimeState::Running`]
    /// on an unbound or replayed response.
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
        let identities = instance.identities.clone().ok_or_else(|| {
            RuntimeError::StaleIdentity("identity-injected state has no identity bundle".to_owned())
        })?;
        let challenge = instance.guest_control_challenge.ok_or_else(|| {
            RuntimeError::StaleIdentity(
                "identity-injected state has no guest-control challenge".to_owned(),
            )
        })?;
        let (action, body, acknowledgement) = if let Some(policy_digest) =
            instance.guest_policy_digest
        {
            let request =
                guest_control::GuestControlRequest::new_bound(challenge, identities, policy_digest)
                    .map_err(|error| {
                        RuntimeError::StaleIdentity(format!(
                            "invalid guest-control request: {error}"
                        ))
                    })?;
            (
                guest_control::GuestControlAction::StartWorkloadBound,
                request.canonical_bound_body(),
                request.canonical_bound_acknowledgement(
                    guest_control::GuestControlAction::StartWorkloadBound,
                ),
            )
        } else {
            let request = guest_control::GuestControlRequest::new(challenge, identities).map_err(
                |error| {
                    RuntimeError::StaleIdentity(format!("invalid guest-control request: {error}"))
                },
            )?;
            (
                guest_control::GuestControlAction::StartWorkload,
                request.canonical_body(),
                request.canonical_acknowledgement(guest_control::GuestControlAction::StartWorkload),
            )
        };
        self.control_call_with_identity_ack(
            ApiRequest {
                method: HttpMethod::Put,
                path: action.path().to_owned(),
                body,
            },
            &acknowledgement,
        )?;
        instance.state = RuntimeState::Running;
        Ok(())
    }

    /// Stops the process, unbinds and closes dm-verity, and removes the clone-specific workspace.
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
        if instance.process_stopped && instance.block_device_state == BlockDeviceState::Bound {
            match self.filesystem.unbind_block_device(
                &Path::new("/dev/mapper").join(&instance.mapper_name),
                &config.dm_verity.jailed_device_path,
            ) {
                Ok(()) => instance.block_device_state = BlockDeviceState::Unbound,
                Err(error) => failures.push(error.to_string()),
            }
        }
        if instance.process_stopped
            && instance.block_device_state == BlockDeviceState::Unbound
            && instance.verity_opened
        {
            match self.close_verity_mapper(&config.veritysetup, &instance.mapper_name) {
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
        if instance.process_stopped
            && !instance.verity_opened
            && instance.workspace_removed
            && !instance.jail_removed
        {
            match self.filesystem.remove_jail(&instance.jail_root) {
                Ok(()) => instance.jail_removed = true,
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
            ("veritysetup", &config.veritysetup),
            (
                "workspace image formatter",
                &config.workspace.image.formatter,
            ),
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

    fn create_workspace_block_image(
        &mut self,
        config: &RuntimeConfig,
        workspace: &Path,
    ) -> Result<(), RuntimeError> {
        let image = config.workspace.image_path();
        self.filesystem.create_workspace_image(
            workspace,
            &image,
            config.workspace.image.size_bytes,
        )?;
        self.command_runner.run(&CommandSpec::pinned(
            &config.workspace.image.formatter,
            [
                "-F".to_owned(),
                "-q".to_owned(),
                "-t".to_owned(),
                "ext4".to_owned(),
                "-d".to_owned(),
                workspace.display().to_string(),
                image.display().to_string(),
            ],
        ))?;
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

    fn open_verity_mapping(&mut self, config: &RuntimeConfig) -> Result<(), RuntimeError> {
        self.command_runner
            .open_verity(&config.veritysetup, &config.dm_verity)
    }

    fn verify_open_verity(&mut self, config: &RuntimeConfig) -> Result<(), RuntimeError> {
        self.command_runner
            .verify_verity(&config.veritysetup, &config.dm_verity)
    }

    fn close_verity_mapper(
        &mut self,
        veritysetup: &PinnedArtifact,
        mapper_name: &str,
    ) -> Result<(), RuntimeError> {
        let command =
            CommandSpec::pinned(veritysetup, ["close".to_owned(), mapper_name.to_owned()]);
        self.command_runner.run(&command).map(|_| ())
    }

    fn bind_verity_device(&mut self, config: &RuntimeConfig) -> Result<(), RuntimeError> {
        self.filesystem.bind_block_device(
            &Path::new("/dev/mapper").join(&config.dm_verity.mapper_name),
            &config.dm_verity.jailed_device_path,
        )
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
        Ok(CommandSpec::pinned(&config.jailer, args))
    }

    fn bind_restored_workspace(&mut self, config: &RuntimeConfig) -> Result<(), RuntimeError> {
        let workspace_path =
            config.jail_path("workspace block image", &config.workspace.image_path())?;
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
                        .jail_path("workspace block image", &config.workspace.image_path())?
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

    fn guest_control_challenge(
        &mut self,
        instance: &mut RuntimeInstance,
        identities: &IdentityBundle,
    ) -> Result<IdentityId, RuntimeError> {
        if let Some(challenge) = instance.guest_control_challenge {
            return Ok(challenge);
        }
        let challenge = self.identity_source.guest_control_challenge(identities)?;
        if challenge.is_zero() {
            return Err(RuntimeError::InvalidIdentity(
                "guest-control challenge cannot be all zeroes".to_owned(),
            ));
        }
        if identities.ids().contains(&challenge) {
            return Err(RuntimeError::StaleIdentity(
                "guest-control challenge reused a session identity".to_owned(),
            ));
        }
        instance.guest_control_challenge = Some(challenge);
        Ok(challenge)
    }

    fn control_call_with_identity_ack(
        &mut self,
        request: ApiRequest,
        expected_ack: &str,
    ) -> Result<(), RuntimeError> {
        let response = self.guest_client.request(&request)?;
        if !(200..300).contains(&response.status) {
            return Err(RuntimeError::ApiStatus {
                path: request.path,
                status: response.status,
                body: response.body,
            });
        }
        if response.body.as_bytes() != expected_ack.as_bytes() {
            return Err(RuntimeError::StaleIdentity(format!(
                "guest control response for {} did not acknowledge the exact challenge and identity bundle",
                request.path
            )));
        }
        Ok(())
    }

    fn rollback(&mut self, resources: RollbackResources<'_>) -> Vec<String> {
        debug_assert!(self.pending_cleanup.is_none());
        let mut pending = PendingCleanup {
            process: resources.process,
            block_device: resources.block_device_bound.then(|| {
                (
                    Path::new("/dev/mapper").join(resources.mapper_name),
                    resources.jailed_device.to_path_buf(),
                )
            }),
            verity_opened: resources.verity_opened,
            workspace: resources
                .workspace_cloned
                .then(|| resources.workspace.to_path_buf()),
            jail_root: resources.jail_root.map(Path::to_path_buf),
            mapper_name: resources.mapper_name.to_owned(),
            veritysetup: resources.veritysetup.clone(),
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
        if let Some((source, jailed_device)) = pending.block_device.as_ref() {
            match self.filesystem.unbind_block_device(source, jailed_device) {
                Ok(()) => pending.block_device = None,
                Err(error) => return vec![error.to_string()],
            }
        }
        if pending.verity_opened {
            match self.close_verity_mapper(&pending.veritysetup, &pending.mapper_name) {
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
        if let Some(jail_root) = pending.jail_root.as_deref() {
            match self.filesystem.remove_jail(jail_root) {
                Ok(()) => pending.jail_root = None,
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
    /// A bound policy digest was changed or an already-bound instance was sent through v1.
    PolicyDigestMismatch {
        /// Digest retained by the runtime instance.
        expected: AuthorityPolicyDigest,
        /// Digest supplied by the caller.
        actual: AuthorityPolicyDigest,
    },
    /// A v1 identity injection was attempted for an instance that requires v2 binding.
    PolicyDigestRequired,
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
            Self::PolicyDigestMismatch { expected, actual } => write!(
                formatter,
                "guest policy digest mismatch: expected {expected}, got {actual}"
            ),
            Self::PolicyDigestRequired => write!(
                formatter,
                "bound guest identity injection requires the policy digest"
            ),
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
    use std::os::unix::net::UnixListener;
    use std::os::unix::process::ExitStatusExt;
    use std::rc::Rc;

    use super::*;

    #[test]
    fn production_snapshot_digest_rejects_symlinks_and_oversized_files() {
        let directory = unique_test_path("snapshot-digest-boundary");
        fs::create_dir(&directory).expect("digest test directory");
        let target = directory.join("target");
        fs::write(&target, b"snapshot").expect("digest target");
        let link = directory.join("link");
        std::os::unix::fs::symlink(&target, &link).expect("digest symlink");
        let oversized = directory.join("oversized");
        File::create(&oversized)
            .and_then(|file| file.set_len(MAX_SNAPSHOT_FILE_BYTES + 1))
            .expect("sparse oversized fixture");

        let mut filesystem = RealFileSystem::new();
        assert!(filesystem.digest(&link).is_err());
        assert!(filesystem.digest(&oversized).is_err());
        assert_eq!(filesystem.digest(&target), Ok(sha256(b"snapshot")));

        fs::remove_file(link).expect("remove symlink");
        fs::remove_file(oversized).expect("remove sparse fixture");
        fs::remove_file(target).expect("remove target");
        fs::remove_dir(directory).expect("remove fixture directory");
    }

    #[test]
    fn jail_cleanup_unlinks_symlink_without_following_external_target() {
        let directory = unique_test_path("jail-cleanup-symlink");
        let parent = directory.join("instance");
        let root = parent.join("root");
        let external = directory.join("external");
        fs::create_dir_all(&root).expect("jail cleanup root");
        fs::create_dir(&external).expect("external target");
        fs::write(external.join("sentinel"), b"must survive").expect("external sentinel");
        std::os::unix::fs::symlink(&external, root.join("escape")).expect("jail symlink fixture");

        let root_identity = ObjectIdentity::from_metadata(
            &fs::metadata(&root).expect("root metadata must resolve"),
        );
        let parent_identity = ObjectIdentity::from_metadata(
            &fs::metadata(&parent).expect("parent metadata must resolve"),
        );
        remove_jail_tree(&root, root_identity, parent_identity)
            .expect("owned jail cleanup must remove the root");

        assert!(!root.exists());
        assert!(external.join("sentinel").exists());
        fs::remove_file(external.join("sentinel")).expect("external sentinel cleanup");
        fs::remove_dir(external).expect("external target cleanup");
        fs::remove_dir(parent).expect("instance parent cleanup");
        fs::remove_dir(directory).expect("fixture cleanup");
    }

    #[test]
    fn cgroup_parent_components_accept_the_standard_systemd_hierarchy() {
        for accepted in [
            "user.slice",
            "system.slice",
            "init.scope",
            "session-runtime",
        ] {
            validate_cgroup_component(accepted)
                .unwrap_or_else(|error| panic!("{accepted} must be an acceptable parent: {error}"));
        }
        for rejected in [
            "",
            ".",
            "..",
            ".hidden",
            "with space",
            "with/slash",
            "tab\t",
        ] {
            assert!(
                validate_cgroup_component(rejected).is_err(),
                "{rejected:?} must not be an acceptable cgroup parent component"
            );
        }
    }

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

        fn verify_verity(
            &mut self,
            _veritysetup: &PinnedArtifact,
            _expected: &DmVerityConfig,
        ) -> Result<(), RuntimeError> {
            Ok(())
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
            veritysetup: test_artifact("/usr/sbin/veritysetup"),
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
                image: WorkspaceImageConfig {
                    formatter: test_artifact("/artifacts/mke2fs"),
                    size_bytes: 64 * 1024 * 1024,
                },
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
            boot_args: format!("console=ttyS0 reboot=k panic=1 pci=off init={REQUIRED_GUEST_INIT}"),
        }
    }

    #[test]
    fn verity_open_uses_the_action_specific_argument_order() {
        let config = test_config();
        let mut runtime = cleanup_runtime([], []);

        runtime
            .open_verity_mapping(&config)
            .expect("the mock command runner must accept dm-verity setup");

        assert_eq!(
            runtime.command_runner.events,
            [format!(
                "run:/usr/sbin/veritysetup open --readonly {} {} {} {}",
                config.dm_verity.data_device.display(),
                config.dm_verity.mapper_name,
                config.dm_verity.hash_device.display(),
                config.dm_verity.root_hash.to_hex()
            )]
        );
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
        fail_prepare: bool,
    }

    impl FileSystem for LifecycleFileSystem {
        fn read(&mut self, _path: &Path) -> Result<Vec<u8>, RuntimeError> {
            Ok(b"artifact".to_vec())
        }

        fn register_jailer_root(&mut self, jail_root: &Path) -> Result<(), RuntimeError> {
            self.events
                .borrow_mut()
                .push(format!("register-jail:{}", jail_root.display()));
            Ok(())
        }

        fn prepare_jailer_resources(
            &mut self,
            _workspace: &Path,
            _jailed_device: &Path,
            _jail_root: &Path,
            _uid: u32,
            _gid: u32,
        ) -> Result<(), RuntimeError> {
            self.events.borrow_mut().push("prepare-jail".to_owned());
            if self.fail_prepare {
                Err(RuntimeError::Io(
                    "injected jailer resource preparation failure".to_owned(),
                ))
            } else {
                Ok(())
            }
        }

        fn remove_jail(&mut self, jail_root: &Path) -> Result<(), RuntimeError> {
            self.events
                .borrow_mut()
                .push(format!("remove-jail:{}", jail_root.display()));
            Ok(())
        }

        fn bind_block_device(
            &mut self,
            source: &Path,
            jailed_device: &Path,
        ) -> Result<(), RuntimeError> {
            self.events.borrow_mut().push(format!(
                "bind-device:{}:{}",
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
            self.events.borrow_mut().push(format!(
                "unbind-device:{}:{}",
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

        fn create_workspace_image(
            &mut self,
            _workspace: &Path,
            image: &Path,
            size_bytes: u64,
        ) -> Result<(), RuntimeError> {
            self.events
                .borrow_mut()
                .push(format!("image:{}:{size_bytes}", image.display()));
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
        response_bodies: VecDeque<String>,
    }

    impl ApiClient for LifecycleApi {
        fn request(&mut self, request: &ApiRequest) -> Result<ApiResponse, RuntimeError> {
            self.events.borrow_mut().push(format!(
                "{}:{:?}:{}:{}",
                self.label, request.method, request.path, request.body
            ));
            let body = self.response_bodies.pop_front().unwrap_or_else(|| {
                let acknowledgement = match request.path.as_str() {
                    "/actions/inject-identity" => Some("identity-injected"),
                    "/actions/start-workload" => Some("workload-started"),
                    _ => None,
                };
                acknowledgement.map_or_else(String::new, |acknowledgement| {
                    format!(
                        "{{\"ack\":{},{}",
                        json_string(acknowledgement),
                        &request.body[1..]
                    )
                })
            });
            Ok(ApiResponse {
                status: self.statuses.pop_front().unwrap_or(204),
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

        fn bind_block_device(
            &mut self,
            _source: &Path,
            _jailed_device: &Path,
        ) -> Result<(), RuntimeError> {
            Ok(())
        }

        fn unbind_block_device(
            &mut self,
            _source: &Path,
            _jailed_device: &Path,
        ) -> Result<(), RuntimeError> {
            Ok(())
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

        fn create_workspace_image(
            &mut self,
            _workspace: &Path,
            image: &Path,
            size_bytes: u64,
        ) -> Result<(), RuntimeError> {
            self.events
                .borrow_mut()
                .push(format!("image:{}:{size_bytes}", image.display()));
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
                    fail_prepare: false,
                },
                LifecycleApi {
                    label: "firecracker",
                    events: Rc::clone(&events),
                    statuses: api_statuses.into_iter().collect(),
                    response_bodies: VecDeque::new(),
                },
                LifecycleApi {
                    label: "guest",
                    events: Rc::clone(&events),
                    statuses: guest_statuses.into_iter().collect(),
                    response_bodies: VecDeque::new(),
                },
                SequentialIdentitySource(0),
            ),
            events,
        )
    }

    #[test]
    fn jail_resource_preparation_failure_rolls_back_registered_root() {
        let config = test_config();
        let (mut runtime, events) = lifecycle_runtime([], []);
        runtime.filesystem.fail_prepare = true;

        let error = runtime
            .launch(&config)
            .expect_err("injected jailer resource failure must reject launch");
        assert!(matches!(
            error,
            RuntimeError::Io(message) if message.contains("injected jailer resource preparation failure")
        ));
        assert!(!runtime.has_pending_cleanup());

        let events = events.borrow();
        let registered = events
            .iter()
            .position(|event| event.starts_with("register-jail:"))
            .expect("launch must register the jail root before resource preparation");
        let prepared = events
            .iter()
            .position(|event| event == "prepare-jail")
            .expect("launch must reach the injected preparation failure");
        let removed = events
            .iter()
            .position(|event| event.starts_with("remove-jail:"))
            .expect("failed preparation must remove the registered jail root");
        assert!(registered < prepared && prepared < removed);
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
        assert_mutation_changes_fingerprint!("veritysetup.path", |config: &mut RuntimeConfig| {
            config.veritysetup.path.push("changed");
        });
        assert_mutation_changes_fingerprint!("veritysetup.digest", |config: &mut RuntimeConfig| {
            config.veritysetup.digest = sha256(b"changed-veritysetup");
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
        assert_mutation_changes_fingerprint!(
            "workspace.image.formatter.path",
            |config: &mut RuntimeConfig| {
                config.workspace.image.formatter.path.push("changed");
            }
        );
        assert_mutation_changes_fingerprint!(
            "workspace.image.formatter.digest",
            |config: &mut RuntimeConfig| {
                config.workspace.image.formatter.digest = sha256(b"changed-workspace-formatter");
            }
        );
        assert_mutation_changes_fingerprint!(
            "workspace.image.size_bytes",
            |config: &mut RuntimeConfig| {
                config.workspace.image.size_bytes += WORKSPACE_IMAGE_BLOCK_BYTES;
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
                response_bodies: VecDeque::new(),
            },
            LifecycleApi {
                label: "guest",
                events: Rc::clone(&events),
                statuses: VecDeque::new(),
                response_bodies: VecDeque::new(),
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
        assert!(events[workspace].contains("\"path_on_host\":\"/workspace/session-a.ext4\""));
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
                event == "firecracker:verify-resources:/workspace/session-a.ext4:/run/session-a.vsock:42"
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
                {"drive_id":"workspace","path_on_host":"/workspace/session-a.ext4"}
            ],
            "vsock":{"guest_cid":42,"uds_path":"/run/session-a.vsock"},
            "machine-config":{"vcpu_count":2}
        }"#;
        verify_exported_restore_resources(
            valid,
            Path::new("/workspace/session-a.ext4"),
            Path::new("/run/session-a.vsock"),
            42,
        )
        .expect("exact exported resource bindings must verify");

        let wrong_workspace = valid.replace("/workspace/session-a.ext4", "/workspace/stale.ext4");
        assert!(matches!(
            verify_exported_restore_resources(
                &wrong_workspace,
                Path::new("/workspace/session-a.ext4"),
                Path::new("/run/session-a.vsock"),
                42,
            ),
            Err(RuntimeError::StaleSnapshot(message)) if message.contains("workspace")
        ));
        let wrong_vsock = valid.replace("\"guest_cid\":42", "\"guest_cid\":43");
        assert!(matches!(
            verify_exported_restore_resources(
                &wrong_vsock,
                Path::new("/workspace/session-a.ext4"),
                Path::new("/run/session-a.vsock"),
                42,
            ),
            Err(RuntimeError::StaleSnapshot(message)) if message.contains("vsock")
        ));
        let duplicate_key = valid.replace("\"drives\":[", "\"drives\":[],\"drives\":[");
        assert!(matches!(
            verify_exported_restore_resources(
                &duplicate_key,
                Path::new("/workspace/session-a.ext4"),
                Path::new("/run/session-a.vsock"),
                42,
            ),
            Err(RuntimeError::Api(message)) if message.contains("duplicate JSON key")
        ));
    }

    #[test]
    fn firecracker_vsock_client_uses_exact_uds_port_and_bounded_handshake() {
        let socket = std::env::temp_dir().join(format!(
            "firecracker-vsock-api-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock must follow epoch")
                .as_nanos()
        ));
        let listener = UnixListener::bind(&socket).expect("test UDS must bind");
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("client must connect");
            let mut connect = [0_u8; 14];
            stream
                .read_exact(&mut connect)
                .expect("CONNECT handshake must arrive");
            assert_eq!(&connect, b"CONNECT 19002\n");
            stream
                .write_all(b"OK 1073741824\n")
                .expect("ACK must write");

            let mut request = Vec::new();
            let mut byte = [0_u8; 1];
            while !request.ends_with(b"\r\n\r\n") {
                stream
                    .read_exact(&mut byte)
                    .expect("HTTP headers must arrive");
                request.push(byte[0]);
            }
            let headers = String::from_utf8(request).expect("headers must be UTF-8");
            assert!(headers.starts_with("PUT /actions/inject-identity HTTP/1.1\r\n"));
            assert!(headers.contains("Content-Length: 2\r\n"));
            let mut body = [0_u8; 2];
            stream.read_exact(&mut body).expect("HTTP body must arrive");
            assert_eq!(&body, b"{}");
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}")
                .expect("HTTP response must write");
        });
        let mut client = FirecrackerVsockApiClient::new(&socket, 42, 19_002)
            .expect("exact endpoint must construct");
        let response = client
            .request(&ApiRequest {
                method: HttpMethod::Put,
                path: "/actions/inject-identity".to_owned(),
                body: "{}".to_owned(),
            })
            .expect("handshake and HTTP request must succeed");

        assert_eq!(
            response,
            ApiResponse {
                status: 200,
                body: "{}".to_owned()
            }
        );
        server.join().expect("server fixture must finish");
        fs::remove_file(socket).expect("test UDS must be removable");
    }

    #[test]
    fn firecracker_vsock_client_rejects_foreign_or_malformed_endpoint_ack() {
        let socket = std::env::temp_dir().join(format!(
            "firecracker-vsock-bad-ack-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock must follow epoch")
                .as_nanos()
        ));
        let listener = UnixListener::bind(&socket).expect("test UDS must bind");
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("client must connect");
            let mut connect = [0_u8; 14];
            stream
                .read_exact(&mut connect)
                .expect("CONNECT handshake must arrive");
            assert_eq!(&connect, b"CONNECT 19002\n");
            stream.write_all(b"OK 0\n").expect("bad ACK must write");
        });
        let mut client = FirecrackerVsockApiClient::new(&socket, 42, 19_002)
            .expect("exact endpoint must construct");

        assert!(matches!(
            client.request(&ApiRequest {
                method: HttpMethod::Put,
                path: "/actions/inject-identity".to_owned(),
                body: "{}".to_owned(),
            }),
            Err(RuntimeError::Api(message))
                if message.contains("invalid connection acknowledgement")
        ));
        server.join().expect("server fixture must finish");
        fs::remove_file(socket).expect("test UDS must be removable");
    }

    #[test]
    fn explicit_resume_precedes_identity_acknowledgement_and_workload_start() {
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
            .expect("resume and identity acknowledgement must succeed");
        assert_eq!(instance.state(), RuntimeState::IdentityInjected);
        runtime
            .start_workload(&mut instance)
            .expect("workload may start after the gate");
        assert_eq!(instance.state(), RuntimeState::Running);

        let events = events.borrow();
        let resume = events
            .iter()
            .position(|event| event.contains("firecracker:Patch:/vm:"))
            .expect("Firecracker must be explicitly resumed");
        let inject = events
            .iter()
            .position(|event| event.contains("guest:Put:/actions/inject-identity:"))
            .expect("the resumed guest must acknowledge the exact identity bundle");
        let start = events
            .iter()
            .position(|event| event.contains("guest:Put:/actions/start-workload:"))
            .expect("workload start must be separately acknowledged");
        assert!(resume < inject && inject < start);
    }

    #[test]
    fn bound_identity_retry_retains_the_exact_digest_and_uses_v2_paths() {
        let config = test_config();
        let (mut runtime, events) = lifecycle_runtime([], []);
        let snapshot = runtime
            .verify_snapshot(&config, test_snapshot(&config))
            .expect("test snapshot provenance must verify");
        let mut instance = runtime
            .restore(&config, &snapshot)
            .expect("restore must remain paused");
        let digest = AuthorityPolicyDigest::from_hex(&"22".repeat(32))
            .expect("test policy digest must be canonical");
        let changed_digest = AuthorityPolicyDigest::from_hex(&"33".repeat(32))
            .expect("changed test policy digest must be canonical");
        let identities = instance.identities().expect("restore identities").clone();
        let challenge = derive_guest_control_challenge(&identities)
            .expect("test challenge must derive independently");
        let request = guest_control::GuestControlRequest::new_bound(challenge, identities, digest)
            .expect("bound request must be valid");
        runtime
            .guest_client
            .response_bodies
            .push_back(String::new());
        assert!(matches!(
            runtime.inject_identity_bound(&mut instance, digest),
            Err(RuntimeError::StaleIdentity(message))
                if message.contains("exact challenge and identity bundle")
        ));
        assert_eq!(instance.state(), RuntimeState::IdentityResumedAwaitingAck);
        assert_eq!(instance.policy_digest(), Some(digest));
        runtime
            .guest_client
            .response_bodies
            .push_back(request.canonical_bound_acknowledgement(
                guest_control::GuestControlAction::InjectIdentityBound,
            ));
        assert!(matches!(
            runtime.inject_identity_bound(&mut instance, changed_digest),
            Err(RuntimeError::PolicyDigestMismatch { expected, actual })
                if expected == digest && actual == changed_digest
        ));
        runtime
            .inject_identity_bound(&mut instance, digest)
            .expect("exact digest retry must be accepted");
        let started = guest_control::GuestControlRequest::new_bound(
            challenge,
            instance.identities().expect("identity bundle").clone(),
            digest,
        )
        .expect("bound start request must be valid");
        runtime
            .guest_client
            .response_bodies
            .push_back(started.canonical_bound_acknowledgement(
                guest_control::GuestControlAction::StartWorkloadBound,
            ));
        runtime
            .start_workload(&mut instance)
            .expect("bound workload start must use the retained digest");
        assert_eq!(instance.state(), RuntimeState::Running);
        let events = events.borrow();
        assert!(
            events
                .iter()
                .any(|event| event.contains("guest:Put:/actions/inject-identity-v2:"))
        );
        assert!(
            events
                .iter()
                .any(|event| event.contains("guest:Put:/actions/start-workload-v2:"))
        );
    }

    #[test]
    fn opaque_success_cannot_release_a_restored_vm() {
        let config = test_config();
        let (mut runtime, events) = lifecycle_runtime([], []);
        runtime
            .guest_client
            .response_bodies
            .push_back(String::new());
        let snapshot = runtime
            .verify_snapshot(&config, test_snapshot(&config))
            .expect("test snapshot provenance must verify");
        let mut instance = runtime
            .restore(&config, &snapshot)
            .expect("restore must remain paused");

        assert!(matches!(
            runtime.inject_identity(&mut instance),
            Err(RuntimeError::StaleIdentity(message))
                if message.contains("exact challenge and identity bundle")
        ));
        assert_eq!(instance.state(), RuntimeState::IdentityResumedAwaitingAck);
        let events = events.borrow();
        assert!(
            events
                .iter()
                .any(|event| event.contains("firecracker:Patch:/vm:"))
        );
    }

    #[test]
    fn guest_ack_with_a_wrong_nonce_or_identity_fails_closed() {
        for mismatch in ["nonce", "session"] {
            let config = test_config();
            let (mut runtime, events) = lifecycle_runtime([], []);
            let snapshot = runtime
                .verify_snapshot(&config, test_snapshot(&config))
                .expect("test snapshot provenance must verify");
            let mut instance = runtime
                .restore(&config, &snapshot)
                .expect("restore must remain paused");
            let identities = instance
                .identities()
                .expect("restore must allocate identities")
                .clone();
            let challenge =
                derive_guest_control_challenge(&identities).expect("challenge fixture must derive");
            let response = if mismatch == "nonce" {
                let mut wrong_challenge = challenge;
                wrong_challenge.0[0] ^= 1;
                guest_control::GuestControlRequest::new(wrong_challenge, identities.clone())
                    .expect("wrong challenge remains independent from test identities")
                    .canonical_acknowledgement(guest_control::GuestControlAction::InjectIdentity)
            } else {
                let mut wrong_identities = identities.clone();
                wrong_identities.session_id =
                    IdentityId::from_hex("00000000000000000000000000000007")
                        .expect("wrong identity fixture must be valid");
                guest_control::GuestControlRequest::new(challenge, wrong_identities)
                    .expect("wrong test identity remains distinct")
                    .canonical_acknowledgement(guest_control::GuestControlAction::InjectIdentity)
            };
            runtime.guest_client.response_bodies.push_back(response);

            assert!(matches!(
                runtime.inject_identity(&mut instance),
                Err(RuntimeError::StaleIdentity(message))
                    if message.contains("exact challenge and identity bundle")
            ));
            assert_eq!(instance.state(), RuntimeState::IdentityResumedAwaitingAck);
            let events = events.borrow();
            assert!(
                events
                    .iter()
                    .any(|event| event.contains("firecracker:Patch:/vm:"))
            );
        }
    }

    #[test]
    fn workload_is_not_marked_running_without_session_bound_ack() {
        let config = test_config();
        let (mut runtime, _) = lifecycle_runtime([], []);
        let snapshot = runtime
            .verify_snapshot(&config, test_snapshot(&config))
            .expect("test snapshot provenance must verify");
        let mut instance = runtime
            .restore(&config, &snapshot)
            .expect("restore must remain paused");
        runtime
            .inject_identity(&mut instance)
            .expect("identity proof and explicit resume must succeed");
        runtime
            .guest_client
            .response_bodies
            .push_back(String::new());

        assert!(matches!(
            runtime.start_workload(&mut instance),
            Err(RuntimeError::StaleIdentity(message))
                if message.contains("exact challenge and identity bundle")
        ));
        assert_eq!(instance.state(), RuntimeState::IdentityInjected);
    }

    #[test]
    fn failed_resume_keeps_identity_gate_retryable_without_injection() {
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
        assert_eq!(instance.state(), RuntimeState::IdentityRegenerated);
        assert!(matches!(
            runtime.start_workload(&mut instance),
            Err(RuntimeError::InvalidState { .. })
        ));

        runtime
            .inject_identity(&mut instance)
            .expect("resume may be retried before sending identity");
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
        let veritysetup = test_artifact("/usr/sbin/veritysetup");

        let failures = runtime.rollback(RollbackResources {
            process: Some(ProcessHandle { pid: 42 }),
            verity_opened: true,
            block_device_bound: false,
            workspace_cloned: true,
            workspace: Path::new("/workspace/session"),
            jail_root: None,
            mapper_name: "session-root",
            jailed_device: Path::new("/jail/dev/rootfs"),
            veritysetup: &veritysetup,
        });
        assert!(failures[0].contains("stop failed"));
        assert_eq!(runtime.command_runner.events, ["stop:42"]);
        assert!(runtime.filesystem.events.is_empty());
        assert!(runtime.has_pending_cleanup());

        runtime
            .retry_pending_cleanup()
            .expect("retained cleanup must be retryable");
        assert_eq!(
            runtime.command_runner.events,
            [
                "stop:42",
                "stop:42",
                "run:/usr/sbin/veritysetup close session-root"
            ]
        );
        assert_eq!(runtime.filesystem.events, ["remove:/workspace/session"]);
        assert!(!runtime.has_pending_cleanup());
    }

    #[test]
    fn pending_cleanup_keeps_workspace_when_verity_close_fails() {
        let mut runtime = cleanup_runtime(std::iter::empty(), [true, false]);
        let veritysetup = test_artifact("/usr/sbin/veritysetup");

        let failures = runtime.rollback(RollbackResources {
            process: Some(ProcessHandle { pid: 42 }),
            verity_opened: true,
            block_device_bound: false,
            workspace_cloned: true,
            workspace: Path::new("/workspace/session"),
            jail_root: None,
            mapper_name: "session-root",
            jailed_device: Path::new("/jail/dev/rootfs"),
            veritysetup: &veritysetup,
        });
        assert!(failures[0].contains("close failed"));
        assert_eq!(
            runtime.command_runner.events,
            ["stop:42", "run:/usr/sbin/veritysetup close session-root"]
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
                "run:/usr/sbin/veritysetup close session-root",
                "run:/usr/sbin/veritysetup close session-root"
            ]
        );
        assert_eq!(runtime.filesystem.events, ["remove:/workspace/session"]);
        assert!(!runtime.has_pending_cleanup());
    }

    #[test]
    fn pinned_command_rejects_source_replacement_before_execution() {
        let directory = unique_test_path("pinned-command-replacement");
        fs::create_dir(&directory).expect("test directory must be creatable");
        let executable = directory.join("tool");
        fs::copy("/bin/true", &executable).expect("true executable must be copyable");
        let digest = digest_file(&executable).expect("copied executable must be digestible");
        let command = CommandSpec::pinned(&PinnedArtifact::new(&executable, digest), []);
        fs::copy("/bin/false", &executable).expect("source path must be replaceable");

        let error = RealCommandRunner::new()
            .run(&command)
            .expect_err("replaced pinned command must not execute");
        assert!(matches!(error, RuntimeError::ArtifactDigestMismatch { .. }));
        fs::remove_dir_all(directory).expect("test directory must be removable");
    }

    #[test]
    fn sealed_command_executes_opened_bytes_after_source_replacement() {
        let directory = unique_test_path("sealed-command-replacement");
        fs::create_dir(&directory).expect("test directory must be creatable");
        let executable = directory.join("tool");
        fs::copy("/bin/true", &executable).expect("true executable must be copyable");
        let digest = digest_file(&executable).expect("copied executable must be digestible");
        let command = CommandSpec::pinned(&PinnedArtifact::new(&executable, digest), []);
        let sealed = seal_command_executable(&command)
            .expect("pinned executable must seal")
            .expect("pinned command must produce a retained descriptor");
        fs::copy("/bin/false", &executable).expect("source path must be replaceable");

        RealCommandRunner::new()
            .run(&CommandSpec::new(sealed.program(), []))
            .expect("the exact opened true bytes must execute");
        fs::remove_dir_all(directory).expect("test directory must be removable");
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

    fn unique_test_path(label: &str) -> PathBuf {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("test clock must be after the Unix epoch")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "firecracker-runtime-{label}-{}-{suffix}",
            std::process::id()
        ))
    }

    fn assert_process_reaped(pid: u32) {
        assert!(
            !Path::new(&format!("/proc/{pid}")).exists(),
            "owned child {pid} must be killed and reaped before its runner is dropped"
        );
    }

    fn assert_process_gone(pid: u32) {
        let deadline = Instant::now() + Duration::from_secs(1);
        while Path::new(&format!("/proc/{pid}")).exists() && Instant::now() < deadline {
            thread::sleep(PROCESS_POLL_INTERVAL);
        }
        assert!(
            !Path::new(&format!("/proc/{pid}")).exists(),
            "command descendant {pid} must be killed with its process group"
        );
    }

    #[test]
    fn command_deadline_kills_and_reaps_a_hung_process_group() {
        let pid_file = unique_test_path("hung-command-pid");
        let script = format!(
            "/bin/sleep 30 & descendant=$!; printf '%s %s' \"$$\" \"$descendant\" > {}; wait",
            pid_file.display()
        );
        let mut runner = RealCommandRunner::with_command_timeout(Duration::from_millis(50));
        let started = Instant::now();

        let error = runner
            .run(&CommandSpec::new("/bin/sh", ["-c".to_owned(), script]))
            .expect_err("a command exceeding its deadline must fail");

        assert!(error.to_string().contains("deadline"));
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "command timeout and reader shutdown must remain bounded"
        );
        let pids = fs::read_to_string(&pid_file)
            .expect("hung command must publish its PID before the deadline")
            .split_ascii_whitespace()
            .map(str::parse::<u32>)
            .collect::<Result<Vec<_>, _>>()
            .expect("published command PIDs must be valid");
        assert_eq!(pids.len(), 2);
        assert_process_reaped(pids[0]);
        assert_process_gone(pids[1]);
        fs::remove_file(pid_file).expect("hung command PID fixture must be removable");
    }

    #[test]
    fn command_runner_drop_kills_and_reaps_direct_child() {
        let mut runner = RealCommandRunner::new();
        let process = runner
            .start(&CommandSpec::new("/bin/sleep", ["30".to_owned()]))
            .expect("direct child must start");
        assert!(Path::new(&format!("/proc/{}", process.pid)).exists());

        drop(runner);

        assert_process_reaped(process.pid);
    }

    #[test]
    fn command_runner_drop_kills_and_reaps_owned_child() {
        let cgroup = unique_test_path("drop-owned-cgroup");
        fs::create_dir(&cgroup).expect("fake cgroup directory must be creatable");
        fs::write(cgroup.join("cgroup.procs"), b"")
            .expect("fake cgroup task file must be creatable");
        let mut runner = RealCommandRunner::new();
        let launcher = spawn_detached(&CommandSpec::new("/bin/sleep", ["30".to_owned()]))
            .expect("owned launcher must start");
        let pid = launcher.id();
        runner.children.insert(
            pid,
            ManagedChild::Isolated {
                launcher,
                ownership: OwnedCgroup {
                    path: cgroup.clone(),
                    identity: ObjectIdentity::from_metadata(
                        &fs::metadata(&cgroup).expect("fake cgroup metadata must resolve"),
                    ),
                    firecracker_digest: digest_file(Path::new("/bin/sleep"))
                        .expect("test executable must be digestible"),
                },
            },
        );

        drop(runner);

        assert_process_reaped(pid);
        fs::remove_file(cgroup.join("cgroup.procs"))
            .expect("fake cgroup task file must be removable");
        fs::remove_dir(cgroup).expect("fake cgroup directory must be removable");
    }

    #[test]
    fn command_runner_child_admission_is_bounded_and_recovers_after_stop() {
        let mut runner = RealCommandRunner::new();
        let mut direct_children = Vec::with_capacity(MAX_MANAGED_CHILDREN - 2);
        for _ in 0..(MAX_MANAGED_CHILDREN - 2) {
            let child = spawn_detached(&CommandSpec::new("/bin/true", Vec::<String>::new()))
                .expect("capacity fixture child must start");
            let process = ProcessHandle { pid: child.id() };
            runner
                .children
                .insert(process.pid, ManagedChild::Direct(child));
            direct_children.push(process);
        }

        let pending_ownership = ProcessOwnership {
            cgroup_path: unique_test_path("capacity-pending-cgroup"),
            firecracker_executable: PathBuf::from("/bin/true"),
            firecracker_digest: digest_file(Path::new("/bin/true"))
                .expect("test executable must be digestible"),
        };
        let pending_launcher = spawn_detached(&CommandSpec::new("/bin/sleep", ["30".to_owned()]))
            .expect("pending ownership fixture child must start");
        let pending = ProcessHandle {
            pid: pending_launcher.id(),
        };
        runner.children.insert(
            pending.pid,
            ManagedChild::PendingOwned {
                launcher: pending_launcher,
                ownership: pending_ownership,
            },
        );

        let isolated_cgroup = unique_test_path("capacity-isolated-cgroup");
        fs::create_dir(&isolated_cgroup).expect("fake cgroup directory must be creatable");
        fs::write(isolated_cgroup.join("cgroup.procs"), b"")
            .expect("fake cgroup task file must be creatable");
        let isolated = fake_owned_process(&mut runner, &isolated_cgroup, Path::new("/bin/true"));
        assert_eq!(runner.children.len(), MAX_MANAGED_CHILDREN);

        let marker = unique_test_path("capacity-marker");
        let command = CommandSpec::new(
            "/bin/sh",
            ["-c".to_owned(), format!("touch {}", marker.display())],
        );
        let error = runner
            .start(&command)
            .expect_err("direct admission must fail at the child limit");
        assert!(
            error
                .to_string()
                .contains("managed child limit of 256 was reached")
        );
        assert!(
            !marker.exists(),
            "the direct command must not spawn before capacity admission"
        );

        let error = runner
            .start_owned(
                &command,
                &ProcessOwnership {
                    cgroup_path: PathBuf::from("relative-cgroup"),
                    firecracker_executable: PathBuf::from("relative-firecracker"),
                    firecracker_digest: sha256(b"unused"),
                },
            )
            .expect_err("owned admission must share the child limit");
        assert!(
            error
                .to_string()
                .contains("managed child limit of 256 was reached")
        );
        assert!(
            !marker.exists(),
            "the owned command must not validate or spawn before capacity admission"
        );
        assert_eq!(runner.children.len(), MAX_MANAGED_CHILDREN);

        runner
            .stop(pending)
            .expect("stopping a pending launcher without a cgroup must release capacity");
        runner
            .stop(isolated)
            .expect("stopping an isolated launcher with no tasks must release capacity");
        assert_eq!(runner.children.len(), MAX_MANAGED_CHILDREN - 2);

        let recovered = runner
            .start(&CommandSpec::new("/bin/sleep", ["30".to_owned()]))
            .expect("a successful stop must make one child slot available");
        assert_eq!(runner.children.len(), MAX_MANAGED_CHILDREN - 1);
        runner
            .stop(recovered)
            .expect("the recovered direct child must be stoppable");
        assert_eq!(runner.children.len(), MAX_MANAGED_CHILDREN - 2);

        for process in direct_children {
            runner
                .stop(process)
                .expect("capacity fixture child must be reaped");
        }
        assert!(runner.children.is_empty());
        fs::remove_file(isolated_cgroup.join("cgroup.procs"))
            .expect("fake cgroup task file must be removable");
        fs::remove_dir(isolated_cgroup).expect("fake cgroup directory must be removable");
        assert!(!marker.exists());
    }

    #[test]
    fn runtime_drop_aborts_if_owned_process_cleanup_fails() {
        const CHILD_MARKER: &str = "FIRECRACKER_RUNTIME_DROP_ABORT_CHILD";
        if std::env::var_os(CHILD_MARKER).is_some() {
            let mut runtime = cleanup_runtime([true], std::iter::empty());
            runtime.pending_cleanup = Some(PendingCleanup {
                process: Some(ProcessHandle { pid: 42 }),
                block_device: None,
                verity_opened: true,
                workspace: Some(PathBuf::from("/workspace/session")),
                jail_root: None,
                mapper_name: "session-root".to_owned(),
                veritysetup: test_artifact("/usr/sbin/veritysetup"),
            });
            drop(runtime);
            panic!("runtime drop must fail-stop while an owned process may remain live");
        }

        let output = Command::new(std::env::current_exe().expect("test executable must resolve"))
            .args([
                "--exact",
                "tests::runtime_drop_aborts_if_owned_process_cleanup_fails",
                "--nocapture",
            ])
            .env(CHILD_MARKER, "1")
            .output()
            .expect("drop failure subprocess must start");

        assert_eq!(output.status.signal(), Some(6));
    }
}
