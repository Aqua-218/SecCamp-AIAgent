//! Validated policy types for the isolation transaction.

use std::{
    os::fd::RawFd,
    path::{Component, Path, PathBuf},
};

use crate::{IsolationError, SeccompPolicy};

const MAX_TMPFS_BYTES: u64 = 1 << 30;
const MAX_CGROUP_NAME_BYTES: usize = 255;
const MIN_LANDLOCK_ABI: u32 = 3;

/// A bind-mounted, read-only root filesystem.
#[derive(Clone, Debug)]
pub struct RootfsConfig {
    pub(crate) source: PathBuf,
    pub(crate) mount_target: PathBuf,
    pub(crate) old_root: PathBuf,
}

impl RootfsConfig {
    /// Creates a root filesystem mount description.
    pub fn new(
        source: impl Into<PathBuf>,
        mount_target: impl Into<PathBuf>,
        old_root: impl Into<PathBuf>,
    ) -> Self {
        Self {
            source: source.into(),
            mount_target: mount_target.into(),
            old_root: old_root.into(),
        }
    }
}

/// A source directory that is exposed at a workload path.
#[derive(Clone, Debug)]
pub struct BindMountConfig {
    pub(crate) source: PathBuf,
    pub(crate) target: PathBuf,
}

impl BindMountConfig {
    /// Creates a bind mount description.
    pub fn new(source: impl Into<PathBuf>, target: impl Into<PathBuf>) -> Self {
        Self {
            source: source.into(),
            target: target.into(),
        }
    }
}

/// An already-connected, kernel-authenticated control channel kept for the workload.
///
/// The launcher must create this `AF_UNIX` `SOCK_SEQPACKET` descriptor before namespace setup.
/// Keeping a single fixed descriptor lets the workload exchange canonical supervisor messages
/// through ordinary `read` and `write` calls while seccomp continues to deny socket creation and
/// connection syscalls.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ControlChannelConfig {
    fd: RawFd,
}

impl ControlChannelConfig {
    /// The only descriptor number an isolated workload may inherit for supervisor control.
    pub const WORKLOAD_FD: RawFd = 3;

    /// Describes the fixed inherited control descriptor.
    ///
    /// # Errors
    ///
    /// Returns [`IsolationError::InvalidConfig`] unless `fd` is the fixed descriptor reserved for
    /// the supervisor control channel.
    pub fn new(fd: RawFd) -> Result<Self, IsolationError> {
        if fd != Self::WORKLOAD_FD {
            return Err(InvalidConfig::message(
                "the supervisor control channel must use descriptor 3",
            ));
        }
        Ok(Self { fd })
    }

    /// Returns the reserved descriptor that the workload inherits.
    #[must_use]
    pub const fn fd(self) -> RawFd {
        self.fd
    }
}

/// A bounded writable tmpfs mount.
#[derive(Clone, Debug)]
pub struct TmpfsConfig {
    pub(crate) target: PathBuf,
    pub(crate) size_bytes: u64,
}

impl TmpfsConfig {
    /// Creates a tmpfs description with a byte limit.
    pub fn new(target: impl Into<PathBuf>, size_bytes: u64) -> Self {
        Self {
            target: target.into(),
            size_bytes,
        }
    }
}

/// A cgroup v2 policy for the workload.
#[derive(Clone, Debug)]
pub struct CgroupConfig {
    pub(crate) root: PathBuf,
    pub(crate) name: String,
    pub(crate) memory_max_bytes: u64,
    pub(crate) pids_max: u64,
}

impl CgroupConfig {
    /// Creates a cgroup v2 policy.
    pub fn new(
        root: impl Into<PathBuf>,
        name: impl Into<String>,
        memory_max_bytes: u64,
        pids_max: u64,
    ) -> Self {
        Self {
            root: root.into(),
            name: name.into(),
            memory_max_bytes,
            pids_max,
        }
    }
}

/// Static Landlock file envelopes.
#[derive(Clone, Debug)]
pub struct LandlockConfig {
    pub(crate) required_abi: u32,
    pub(crate) read_only_paths: Vec<PathBuf>,
    pub(crate) writable_paths: Vec<PathBuf>,
}

impl LandlockConfig {
    /// Creates a Landlock policy.
    pub fn new<I, J, P, Q>(required_abi: u32, read_only_paths: I, writable_paths: J) -> Self
    where
        I: IntoIterator<Item = P>,
        J: IntoIterator<Item = Q>,
        P: Into<PathBuf>,
        Q: Into<PathBuf>,
    {
        Self {
            required_abi,
            read_only_paths: read_only_paths.into_iter().map(Into::into).collect(),
            writable_paths: writable_paths.into_iter().map(Into::into).collect(),
        }
    }
}

/// The host UID/GID mapped to workload UID/GID zero.
#[derive(Clone, Copy, Debug)]
pub struct IdentityMap {
    pub(crate) host_uid: u32,
    pub(crate) host_gid: u32,
}

impl IdentityMap {
    /// Creates a single-entry UID/GID map.
    pub const fn new(uid: u32, gid: u32) -> Self {
        Self {
            host_uid: uid,
            host_gid: gid,
        }
    }
}

/// Complete isolation policy consumed by [`crate::apply`].
#[derive(Clone, Debug)]
pub struct IsolationConfig {
    pub(crate) rootfs: RootfsConfig,
    pub(crate) workspace: BindMountConfig,
    pub(crate) tmpfs: TmpfsConfig,
    pub(crate) cgroup: CgroupConfig,
    pub(crate) landlock: LandlockConfig,
    pub(crate) seccomp: SeccompPolicy,
    pub(crate) identity: IdentityMap,
    pub(crate) control_channel: Option<ControlChannelConfig>,
}

impl IsolationConfig {
    /// Creates a complete isolation policy.
    pub fn new(
        rootfs: RootfsConfig,
        workspace: BindMountConfig,
        tmpfs: TmpfsConfig,
        cgroup: CgroupConfig,
        landlock: LandlockConfig,
        seccomp: SeccompPolicy,
        identity: IdentityMap,
    ) -> Self {
        Self {
            rootfs,
            workspace,
            tmpfs,
            cgroup,
            landlock,
            seccomp,
            identity,
            control_channel: None,
        }
    }

    /// Retains the fixed preconnected supervisor control channel across isolation and `exec`.
    #[must_use]
    pub fn with_control_channel(mut self, control_channel: ControlChannelConfig) -> Self {
        self.control_channel = Some(control_channel);
        self
    }

    /// Validates all paths, limits, and policy combinations without side effects.
    pub fn validate(&self) -> Result<(), IsolationError> {
        validate_rootfs(&self.rootfs)?;
        validate_bind_mount(&self.workspace)?;
        validate_absolute_clean_path(&self.tmpfs.target, "tmpfs target")?;
        if self.tmpfs.target == Path::new("/") {
            return Err(InvalidConfig::message(
                "tmpfs target must not be the root path",
            ));
        }
        if self.tmpfs.size_bytes == 0 || self.tmpfs.size_bytes > MAX_TMPFS_BYTES {
            return Err(InvalidConfig::message(
                "tmpfs size must be between 1 byte and 1 GiB",
            ));
        }
        validate_cgroup(&self.cgroup)?;
        validate_landlock(&self.landlock)?;
        self.seccomp.validate_for_platform()?;
        if self.workspace.target.starts_with(&self.rootfs.mount_target)
            || self.tmpfs.target.starts_with(&self.rootfs.mount_target)
        {
            return Err(InvalidConfig::message(
                "workload mount targets must not be inside the rootfs staging mount",
            ));
        }
        if self
            .landlock
            .writable_paths
            .iter()
            .any(|path| !path.starts_with(&self.workspace.target))
        {
            return Err(InvalidConfig::message(
                "Landlock writable paths must be inside the workspace target",
            ));
        }
        if self.workspace.target == self.tmpfs.target
            || self.workspace.target == Path::new("/proc")
            || self.workspace.target == Path::new("/dev")
            || self.tmpfs.target == Path::new("/proc")
            || self.tmpfs.target == Path::new("/dev")
        {
            return Err(InvalidConfig::message(
                "workspace, tmpfs, /proc, and /dev mount targets must be distinct",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::ControlChannelConfig;

    #[test]
    fn refuses_control_channel_descriptors_other_than_the_reserved_fd() {
        assert!(ControlChannelConfig::new(2).is_err());
        assert!(ControlChannelConfig::new(4).is_err());
        assert_eq!(
            ControlChannelConfig::new(ControlChannelConfig::WORKLOAD_FD)
                .expect("the reserved descriptor must be accepted")
                .fd(),
            ControlChannelConfig::WORKLOAD_FD
        );
    }
}

fn validate_rootfs(config: &RootfsConfig) -> Result<(), IsolationError> {
    validate_absolute_clean_path(&config.source, "rootfs source")?;
    validate_absolute_clean_path(&config.mount_target, "rootfs mount target")?;
    validate_absolute_clean_path(&config.old_root, "old root path")?;
    if config.mount_target == Path::new("/") {
        return Err(InvalidConfig::message(
            "rootfs mount target must not be root",
        ));
    }
    if !config.old_root.starts_with(&config.mount_target) || config.old_root == config.mount_target
    {
        return Err(InvalidConfig::message(
            "old root must be a distinct child of the rootfs mount target",
        ));
    }
    Ok(())
}

fn validate_bind_mount(config: &BindMountConfig) -> Result<(), IsolationError> {
    validate_absolute_clean_path(&config.source, "workspace source")?;
    validate_absolute_clean_path(&config.target, "workspace target")?;
    if config.target == Path::new("/") {
        return Err(InvalidConfig::message("workspace target must not be root"));
    }
    Ok(())
}

fn validate_cgroup(config: &CgroupConfig) -> Result<(), IsolationError> {
    validate_absolute_clean_path(&config.root, "cgroup root")?;
    if config.root == Path::new("/") {
        return Err(InvalidConfig::message(
            "cgroup root must not be the host root directory",
        ));
    }
    if config.name.is_empty()
        || config.name.len() > MAX_CGROUP_NAME_BYTES
        || config.name == "."
        || config.name == ".."
        || !config
            .name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(InvalidConfig::message(
            "cgroup name must be a non-empty safe component",
        ));
    }
    if config.memory_max_bytes == 0 || config.pids_max == 0 {
        return Err(InvalidConfig::message(
            "cgroup memory and process limits must be positive",
        ));
    }
    Ok(())
}

fn validate_landlock(config: &LandlockConfig) -> Result<(), IsolationError> {
    if config.required_abi < MIN_LANDLOCK_ABI {
        return Err(InvalidConfig::message(
            "Landlock ABI 3 is required for truncate and refer enforcement",
        ));
    }
    if config.read_only_paths.is_empty() || config.writable_paths.is_empty() {
        return Err(InvalidConfig::message(
            "Landlock requires at least one read-only and one writable path",
        ));
    }
    for path in config
        .read_only_paths
        .iter()
        .chain(config.writable_paths.iter())
    {
        validate_absolute_clean_path(path, "Landlock path")?;
    }
    Ok(())
}

fn validate_absolute_clean_path(path: &Path, label: &str) -> Result<(), IsolationError> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err(InvalidConfig::message(format!(
            "{label} must be absolute and free of dot components"
        )));
    }
    Ok(())
}

struct InvalidConfig;

impl InvalidConfig {
    fn message(message: impl Into<String>) -> IsolationError {
        IsolationError::InvalidConfig(message.into())
    }
}
