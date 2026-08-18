//! Crash recovery for session-scoped Firecracker host resources.
//!
//! Recovery never relies on a persisted PID. A validated runtime configuration
//! seals the cgroup, dm-verity mapping, and jail subtree that belong to one
//! random session identity. The recovery driver advances exactly one dependency
//! stage per call so an external durable journal can commit each completed
//! physical effect before the next one begins.

use std::{
    ffi::{OsStr, OsString},
    fs::{self, File},
    io::{Read, Seek, SeekFrom, Write},
    mem::MaybeUninit,
    os::unix::{
        ffi::OsStrExt,
        fs::{FileTypeExt, MetadataExt},
        io::AsRawFd,
    },
    path::{Component, Path, PathBuf},
    thread,
    time::{Duration, Instant},
};

use rustix::{
    fs::{
        AtFlags, MemfdFlags, Mode, OFlags, RawDir, ResolveFlags, SealFlags, fchmod,
        fcntl_add_seals, fcntl_get_seals, fstatfs, major, memfd_create, minor, open, openat,
        openat2, unlinkat,
    },
    io::Errno,
    mount::{UnmountFlags, unmount},
};

use super::{
    CGROUP2_SUPER_MAGIC, COMMAND_TIMEOUT, CommandRunner, CommandSpec, DmVerityConfig,
    MAX_COMMAND_OUTPUT_BYTES, MAX_WORKSPACE_DEPTH, PROCESS_POLL_INTERVAL, RealCommandRunner,
    RuntimeConfig, RuntimeError, Sha256Digest,
};

const RECOVERY_TIMEOUT: Duration = COMMAND_TIMEOUT;
const RECOVERY_REMOVAL_BUDGET: usize = if cfg!(test) { 8 } else { 4096 };
/// Deepest jail subtree recovery will descend before refusing to continue.
///
/// Descent is not charged against the removal budget: a chain of directories is walked to its
/// bottom before the first entry can be unlinked, and `open_descendant_directory` reopens from the
/// root each step, so an unbounded chain costs quadratic work and an unbounded frame stack. A
/// guest writes into its workspace, so the depth of the tree recovery has to walk is guest-chosen.
/// The workspace itself is only ever built to [`MAX_WORKSPACE_DEPTH`], so anything deeper is
/// outside what this host created and is refused rather than walked.
const MAX_RECOVERY_DEPTH: usize = MAX_WORKSPACE_DEPTH;
const MAX_RECOVERY_TOOL_BYTES: u64 = 64 * 1024 * 1024;
const RESOLVE_NO_LINKS: ResolveFlags = ResolveFlags::NO_MAGICLINKS.union(ResolveFlags::NO_SYMLINKS);
const RESOLVE_CHILD: ResolveFlags = ResolveFlags::BENEATH
    .union(ResolveFlags::NO_MAGICLINKS)
    .union(ResolveFlags::NO_SYMLINKS)
    .union(ResolveFlags::NO_XDEV);

/// Exact host resources derived from one validated session runtime configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionResourceOwnership {
    config_fingerprint: Sha256Digest,
    cgroup_parent: PathBuf,
    cgroup_parent_seal: Option<ParentSeal>,
    cgroup_leaf: OsString,
    jail_parent: PathBuf,
    jail_parent_seal: ParentSeal,
    jail_leaf: OsString,
    jail_root: PathBuf,
    jailed_device: PathBuf,
    workspace: PathBuf,
    mapper_name: String,
    data_device: PathBuf,
    hash_device: PathBuf,
    root_hash: Sha256Digest,
}

impl SessionResourceOwnership {
    /// Seals the exact recoverable resources for `config`.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeError`] when the configuration is invalid or a resource
    /// path does not have the exact session-leaf shape recovery requires.
    pub fn from_runtime_config(config: &RuntimeConfig) -> Result<Self, RuntimeError> {
        config.validate()?;
        let cgroup_path = &config.isolation.cgroup.path;
        let cgroup_parent = cgroup_path.parent().ok_or_else(|| {
            RuntimeError::InvalidConfig("session cgroup has no parent directory".to_owned())
        })?;
        let cgroup_leaf = cgroup_path.file_name().ok_or_else(|| {
            RuntimeError::InvalidConfig("session cgroup has no leaf name".to_owned())
        })?;
        if cgroup_leaf != OsStr::new(&config.workspace.clone_id) {
            return Err(RuntimeError::InvalidConfig(
                "session cgroup leaf does not equal the workspace clone identity".to_owned(),
            ));
        }

        let jail_root = config.jail_root()?;
        let jail_leaf_path = jail_root.parent().ok_or_else(|| {
            RuntimeError::InvalidConfig("session jail root has no owned leaf".to_owned())
        })?;
        let jail_parent = jail_leaf_path.parent().ok_or_else(|| {
            RuntimeError::InvalidConfig("session jail leaf has no parent directory".to_owned())
        })?;
        let jail_leaf = jail_leaf_path.file_name().ok_or_else(|| {
            RuntimeError::InvalidConfig("session jail has no leaf name".to_owned())
        })?;
        if jail_leaf != OsStr::new(&config.workspace.clone_id) {
            return Err(RuntimeError::InvalidConfig(
                "session jail leaf does not equal the workspace clone identity".to_owned(),
            ));
        }

        let cgroup_parent_seal = ParentSeal::capture_optional(cgroup_parent)?;
        let jail_parent_seal = ParentSeal::capture(jail_parent)?;
        // A systemd unit cgroup is ephemeral and may be removed atomically with a killed worker.
        // The full cgroup path remains bound by the runtime fingerprint; the durable ownership
        // fingerprint seals the persistent jail ancestor that encloses the remaining resources.
        let config_fingerprint =
            recovery_fingerprint(config.instance_fingerprint(), [&jail_parent_seal]);
        Ok(Self {
            config_fingerprint,
            cgroup_parent: cgroup_parent.to_path_buf(),
            cgroup_parent_seal,
            cgroup_leaf: cgroup_leaf.to_os_string(),
            jail_parent: jail_parent.to_path_buf(),
            jail_parent_seal,
            jail_leaf: jail_leaf.to_os_string(),
            jail_root,
            jailed_device: config.dm_verity.jailed_device_path.clone(),
            workspace: config.workspace.clone_path(),
            mapper_name: config.dm_verity.mapper_name.clone(),
            data_device: config.dm_verity.data_device.clone(),
            hash_device: config.dm_verity.hash_device.clone(),
            root_hash: config.dm_verity.root_hash,
        })
    }

    /// Returns the exact session configuration fingerprint persisted by the owner.
    #[must_use]
    pub const fn config_fingerprint(&self) -> Sha256Digest {
        self.config_fingerprint
    }

    /// Returns the exact session cgroup path.
    #[must_use]
    pub fn cgroup_path(&self) -> PathBuf {
        self.cgroup_parent.join(&self.cgroup_leaf)
    }

    /// Returns the exact session jail subtree removed last.
    #[must_use]
    pub fn jail_path(&self) -> PathBuf {
        self.jail_parent.join(&self.jail_leaf)
    }

    /// Returns the jail root inside the exact session subtree.
    #[must_use]
    pub fn jail_root(&self) -> &Path {
        &self.jail_root
    }

    /// Returns the exact session workspace path.
    #[must_use]
    pub fn workspace(&self) -> &Path {
        &self.workspace
    }

    /// Returns the exact dm-verity mapper name.
    #[must_use]
    pub fn mapper_name(&self) -> &str {
        &self.mapper_name
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ParentSeal {
    expected_parent: PathBuf,
    ancestor_identity: super::ObjectIdentity,
    mount_id: u64,
    owner: u32,
    mode: u32,
}

impl ParentSeal {
    fn capture(expected_parent: &Path) -> Result<Self, RuntimeError> {
        Self::capture_optional(expected_parent)?.ok_or_else(|| {
            RuntimeError::InvalidConfig(format!(
                "recovery parent must be pre-existing: {}",
                expected_parent.display()
            ))
        })
    }

    fn capture_optional(expected_parent: &Path) -> Result<Option<Self>, RuntimeError> {
        validate_absolute_normal_path(expected_parent)?;
        let Some(directory) = open_absolute_directory_optional(expected_parent)? else {
            return Ok(None);
        };
        let metadata = directory.metadata().map_err(RuntimeError::from)?;
        validate_trusted_parent_metadata(expected_parent, &metadata)?;
        Ok(Some(Self {
            expected_parent: expected_parent.to_path_buf(),
            ancestor_identity: super::ObjectIdentity::from_metadata(&metadata),
            mount_id: descriptor_mount_id(&directory)?,
            owner: metadata.uid(),
            mode: metadata.mode(),
        }))
    }

    fn open_verified_parent(&self) -> Result<File, RuntimeError> {
        let ancestor =
            open_absolute_directory_optional(&self.expected_parent)?.ok_or_else(|| {
                RuntimeError::Io(format!(
                    "sealed recovery parent is unavailable: {}",
                    self.expected_parent.display()
                ))
            })?;
        let metadata = ancestor.metadata().map_err(RuntimeError::from)?;
        validate_trusted_parent_metadata(&self.expected_parent, &metadata)?;
        let observed = super::ObjectIdentity::from_metadata(&metadata);
        if observed != self.ancestor_identity
            || descriptor_mount_id(&ancestor)? != self.mount_id
            || metadata.uid() != self.owner
            || metadata.mode() != self.mode
        {
            return Err(RuntimeError::Command(format!(
                "sealed recovery parent was replaced: {}",
                self.expected_parent.display()
            )));
        }
        ancestor.try_clone().map_err(RuntimeError::from)
    }
}

fn recovery_fingerprint<'a>(
    runtime_fingerprint: Sha256Digest,
    seals: impl IntoIterator<Item = &'a ParentSeal>,
) -> Sha256Digest {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"firecracker-recovery-ownership-v3\0");
    bytes.extend_from_slice(&runtime_fingerprint.as_bytes());
    for seal in seals {
        append_fingerprint_field(&mut bytes, seal.expected_parent.as_os_str().as_bytes());
        bytes.extend_from_slice(&seal.ancestor_identity.device.to_be_bytes());
        bytes.extend_from_slice(&seal.ancestor_identity.inode.to_be_bytes());
        bytes.extend_from_slice(&seal.mount_id.to_be_bytes());
        bytes.extend_from_slice(&seal.owner.to_be_bytes());
        bytes.extend_from_slice(&seal.mode.to_be_bytes());
    }
    super::sha256(&bytes)
}

fn append_fingerprint_field(output: &mut Vec<u8>, value: &[u8]) {
    output.extend_from_slice(&(value.len() as u64).to_be_bytes());
    output.extend_from_slice(value);
}

fn validate_trusted_parent_metadata(
    path: &Path,
    metadata: &fs::Metadata,
) -> Result<(), RuntimeError> {
    const GROUP_OR_OTHER_WRITE: u32 = 0o022;
    let effective_uid = effective_uid()?;
    let trusted_owner = metadata.uid() == 0 || metadata.uid() == effective_uid;
    if !trusted_owner || metadata.mode() & GROUP_OR_OTHER_WRITE != 0 {
        return Err(RuntimeError::InvalidConfig(format!(
            "recovery ancestor is not owned and protected by root/euid: {}",
            path.display()
        )));
    }
    Ok(())
}

fn effective_uid() -> Result<u32, RuntimeError> {
    let status = fs::read_to_string("/proc/self/status").map_err(RuntimeError::from)?;
    status
        .lines()
        .find_map(|line| line.strip_prefix("Uid:"))
        .and_then(|uids| uids.split_ascii_whitespace().nth(1))
        .ok_or_else(|| RuntimeError::Io("/proc/self/status omitted effective uid".to_owned()))?
        .parse::<u32>()
        .map_err(|_| RuntimeError::Io("/proc/self/status has invalid effective uid".to_owned()))
}

fn descriptor_mount_id(file: &File) -> Result<u64, RuntimeError> {
    let path = PathBuf::from(format!("/proc/self/fdinfo/{}", file.as_raw_fd()));
    let text = fs::read_to_string(path).map_err(RuntimeError::from)?;
    text.lines()
        .find_map(|line| line.strip_prefix("mnt_id:").map(str::trim))
        .ok_or_else(|| RuntimeError::Io("descriptor fdinfo omitted mnt_id".to_owned()))?
        .parse::<u64>()
        .map_err(|_| RuntimeError::Io("descriptor fdinfo contains invalid mnt_id".to_owned()))
}

fn validate_absolute_normal_path(path: &Path) -> Result<(), RuntimeError> {
    if !path.is_absolute()
        || path
            .strip_prefix("/")
            .map_err(|_| RuntimeError::InvalidConfig("path is not absolute".to_owned()))?
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(RuntimeError::InvalidConfig(format!(
            "recovery path is not absolute and lexical: {}",
            path.display()
        )));
    }
    Ok(())
}

/// Durable stage immediately before or after one recovery effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryStage {
    /// Session identities are reserved; no host cleanup has been acknowledged.
    IdentityReserved,
    /// The exact session cgroup is empty and removed.
    CgroupEmpty,
    /// Factory-owned mounts and provisioning artifacts are released.
    ProvisioningReleased,
    /// The exact dm-verity mapping is absent.
    MapperClosed,
    /// The exact session jail subtree is absent.
    JailRemoved,
    /// Every host recovery obligation is complete.
    Complete,
}

/// Mandatory recovery for resources created by the session provisioner.
pub trait ProvisioningRecovery {
    /// Releases only provisioning resources for `ownership`.
    ///
    /// The operation must be idempotent. It runs after process cleanup and
    /// before mapper and jail cleanup.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeError`] while any exact provisioning resource remains.
    fn release_provisioning(
        &mut self,
        ownership: &SessionResourceOwnership,
    ) -> Result<(), RuntimeError>;
}

/// Physical boundary used by the one-stage recovery driver.
pub trait FirecrackerRecoveryBackend {
    /// Kills every task in the exact cgroup, waits for emptiness, and removes it.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeError`] while the exact cgroup cannot be verified empty and absent.
    fn recover_cgroup(&mut self, ownership: &SessionResourceOwnership) -> Result<(), RuntimeError>;

    /// Verifies and unmounts its exact jailed bind, then closes the exact dm-verity mapping, or
    /// observes both absent.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeError`] when the mapper is foreign, ambiguous, or cannot be closed.
    fn recover_mapper(&mut self, ownership: &SessionResourceOwnership) -> Result<(), RuntimeError>;

    /// Removes the exact jail subtree without following links or mount crossings.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeError`] while the exact jail cannot be verified and removed.
    fn recover_jail(&mut self, ownership: &SessionResourceOwnership) -> Result<(), RuntimeError>;
}

/// A stage-bound recovery error that never advances durable progress.
#[derive(Debug, Eq, PartialEq)]
pub struct RecoveryError {
    pending_stage: RecoveryStage,
    source: Box<RuntimeError>,
}

impl RecoveryError {
    /// Returns the durable stage that must be retried.
    #[must_use]
    pub const fn pending_stage(&self) -> RecoveryStage {
        self.pending_stage
    }

    /// Returns the underlying platform failure.
    #[must_use]
    pub const fn source_error(&self) -> &RuntimeError {
        &self.source
    }
}

impl std::fmt::Display for RecoveryError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "Firecracker recovery remains at {:?}: {}",
            self.pending_stage, self.source
        )
    }
}

impl std::error::Error for RecoveryError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.source.as_ref())
    }
}

/// Advances Firecracker resource cleanup exactly one durable stage at a time.
pub struct FirecrackerRecovery<B> {
    backend: B,
}

/// Opaque in-process transition state reconstructed from one durable journal record.
#[derive(Debug, Eq, PartialEq)]
pub struct RecoveryProgress {
    expected_fingerprint: Sha256Digest,
    stage: RecoveryStage,
}

impl RecoveryProgress {
    /// Returns the durable stage represented by this transition token.
    #[must_use]
    pub const fn stage(&self) -> RecoveryStage {
        self.stage
    }
}

impl<B> FirecrackerRecovery<B>
where
    B: FirecrackerRecoveryBackend,
{
    /// Creates a recovery driver around one physical backend.
    #[must_use]
    pub const fn new(backend: B) -> Self {
        Self { backend }
    }

    /// Returns the physical backend after all ownership has been transferred out.
    #[must_use]
    pub fn into_inner(self) -> B {
        self.backend
    }

    /// Reconstructs an opaque transition token from an incomplete durable journal record.
    ///
    /// # Errors
    ///
    /// Returns [`RecoveryError`] when the journal fingerprint is foreign or the
    /// record already claims completion and therefore has no physical successor.
    pub fn begin(
        ownership: &SessionResourceOwnership,
        expected_fingerprint: Sha256Digest,
        durable_stage: RecoveryStage,
    ) -> Result<RecoveryProgress, RecoveryError> {
        if ownership.config_fingerprint() != expected_fingerprint {
            return Err(RecoveryError {
                pending_stage: durable_stage,
                source: Box::new(RuntimeError::InvalidConfig(
                    "recovery journal fingerprint does not match resource ownership".to_owned(),
                )),
            });
        }
        if durable_stage == RecoveryStage::Complete {
            return Err(RecoveryError {
                pending_stage: durable_stage,
                source: Box::new(RuntimeError::InvalidState {
                    expected: "an incomplete durable recovery stage".to_owned(),
                    actual: "complete".to_owned(),
                }),
            });
        }
        Ok(RecoveryProgress {
            expected_fingerprint,
            stage: durable_stage,
        })
    }

    /// Performs at most one physical recovery effect.
    ///
    /// The returned stage is safe for a caller to persist before invoking this
    /// method again. A failure returns the unchanged input stage.
    ///
    /// # Errors
    ///
    /// Returns [`RecoveryError`] without advancing when an exact resource cannot
    /// be verified or released.
    #[allow(clippy::needless_pass_by_value)] // Linear token consumption prevents effect chaining.
    pub fn recover_next<P>(
        &mut self,
        ownership: &SessionResourceOwnership,
        progress: RecoveryProgress,
        provisioning: &mut P,
    ) -> Result<RecoveryStage, RecoveryError>
    where
        P: ProvisioningRecovery,
    {
        let RecoveryProgress {
            expected_fingerprint,
            stage,
        } = progress;
        if ownership.config_fingerprint() != expected_fingerprint {
            return Err(RecoveryError {
                pending_stage: stage,
                source: Box::new(RuntimeError::InvalidConfig(
                    "recovery journal fingerprint does not match resource ownership".to_owned(),
                )),
            });
        }
        let result = match stage {
            RecoveryStage::IdentityReserved => self
                .backend
                .recover_cgroup(ownership)
                .map(|()| RecoveryStage::CgroupEmpty),
            RecoveryStage::CgroupEmpty => provisioning
                .release_provisioning(ownership)
                .map(|()| RecoveryStage::ProvisioningReleased),
            RecoveryStage::ProvisioningReleased => self
                .backend
                .recover_mapper(ownership)
                .map(|()| RecoveryStage::MapperClosed),
            RecoveryStage::MapperClosed => self
                .backend
                .recover_jail(ownership)
                .map(|()| RecoveryStage::JailRemoved),
            RecoveryStage::JailRemoved => Ok(RecoveryStage::Complete),
            RecoveryStage::Complete => unreachable!("complete progress cannot be constructed"),
        };
        let advanced = result.map_err(|source| RecoveryError {
            pending_stage: stage,
            source: Box::new(source),
        })?;
        Ok(advanced)
    }
}

/// Pinned host tools used only for dm-verity recovery.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryTools {
    veritysetup: super::PinnedArtifact,
    dmsetup: super::PinnedArtifact,
}

impl RecoveryTools {
    /// Creates the mandatory pinned recovery tool set.
    ///
    /// Validation and digest verification happen before the tools are used.
    #[must_use]
    pub const fn new(veritysetup: super::PinnedArtifact, dmsetup: super::PinnedArtifact) -> Self {
        Self {
            veritysetup,
            dmsetup,
        }
    }
}

/// Linux recovery backend for cgroup v2, dm-verity, and jail resources.
pub struct LinuxFirecrackerRecovery {
    runner: RealCommandRunner,
    deadline: Duration,
    tools: RecoveryTools,
    sealed_tools: Option<SealedRecoveryTools>,
}

impl LinuxFirecrackerRecovery {
    /// Creates a production backend with bounded command and cgroup waits.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeError`] unless both tool descriptors are statically safe.
    /// Tool bytes are opened, digested, and sealed only when a live mapper is observed.
    pub fn new(tools: RecoveryTools) -> Result<Self, RuntimeError> {
        super::validate_artifact("veritysetup recovery tool", &tools.veritysetup)?;
        super::validate_artifact("dmsetup recovery tool", &tools.dmsetup)?;
        Ok(Self {
            runner: RealCommandRunner::new(),
            deadline: RECOVERY_TIMEOUT,
            tools,
            sealed_tools: None,
        })
    }

    fn sealed_tools(&mut self) -> Result<&SealedRecoveryTools, RuntimeError> {
        if self.sealed_tools.is_none() {
            self.sealed_tools = Some(SealedRecoveryTools::load(&self.tools)?);
        }
        self.sealed_tools
            .as_ref()
            .ok_or_else(|| RuntimeError::Io("recovery tools were not retained".to_owned()))
    }
}

impl FirecrackerRecoveryBackend for LinuxFirecrackerRecovery {
    fn recover_cgroup(&mut self, ownership: &SessionResourceOwnership) -> Result<(), RuntimeError> {
        recover_cgroup(ownership, self.deadline)
    }

    fn recover_mapper(&mut self, ownership: &SessionResourceOwnership) -> Result<(), RuntimeError> {
        let mapper = find_kernel_mapper(&ownership.mapper_name)?;
        recover_jailed_device_binding(ownership, mapper.as_ref(), self.deadline)?;
        let Some(mapper) = mapper else {
            return Ok(());
        };
        let tools = self.sealed_tools()?.paths();
        recover_mapper(&mut self.runner, &tools, ownership, &mapper)
    }

    fn recover_jail(&mut self, ownership: &SessionResourceOwnership) -> Result<(), RuntimeError> {
        recover_jail(ownership)
    }
}

fn recover_jailed_device_binding(
    ownership: &SessionResourceOwnership,
    mapper: Option<&KernelMapperIdentity>,
    timeout: Duration,
) -> Result<(), RuntimeError> {
    let jail_parent = ownership.jail_parent_seal.open_verified_parent()?;
    let relative = ownership
        .jailed_device
        .strip_prefix(&ownership.jail_parent)
        .map_err(|_| {
            RuntimeError::InvalidConfig(
                "jailed recovery device is outside its sealed jail parent".to_owned(),
            )
        })?;
    let relative_parent = relative.parent().ok_or_else(|| {
        RuntimeError::InvalidConfig("jailed recovery device has no relative parent".to_owned())
    })?;
    let leaf = relative.file_name().ok_or_else(|| {
        RuntimeError::InvalidConfig("jailed recovery device has no leaf".to_owned())
    })?;
    let device_parent = match openat2(
        &jail_parent,
        relative_parent,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
        RESOLVE_CHILD,
    ) {
        Ok(directory) => File::from(directory),
        Err(Errno::NOENT) => return Ok(()),
        Err(error) => return Err(RuntimeError::Io(error.to_string())),
    };
    let target = match openat2(
        &device_parent,
        leaf,
        OFlags::PATH | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
        ResolveFlags::BENEATH.union(RESOLVE_NO_LINKS),
    ) {
        Ok(target) => File::from(target),
        Err(Errno::NOENT) => return Ok(()),
        Err(error) => return Err(RuntimeError::Io(error.to_string())),
    };
    let metadata = target.metadata().map_err(RuntimeError::from)?;
    if metadata.file_type().is_block_device() {
        let mapper = mapper.ok_or_else(|| {
            RuntimeError::Command(
                "jailed recovery device remains mounted after its mapper disappeared".to_owned(),
            )
        })?;
        let parent_mount_id = descriptor_mount_id(&device_parent)?;
        let target_mount_id = descriptor_mount_id(&target)?;
        let target_identity = super::ObjectIdentity::from_metadata(&metadata);
        if major(metadata.rdev()) != mapper.major
            || minor(metadata.rdev()) != mapper.minor
            || target_mount_id == parent_mount_id
        {
            return Err(RuntimeError::Command(
                "jailed recovery device is not the exact mapper bind mount".to_owned(),
            ));
        }
        // An O_PATH descriptor on the mountpoint itself keeps a non-lazy
        // unmount busy. Retain only the sealed identity values across umount.
        drop(target);
        unmount_jailed_mapper_with_retry(
            &device_parent,
            leaf,
            &ownership.jailed_device,
            mapper,
            target_identity,
            target_mount_id,
            timeout,
        )?;
        let unmounted = File::from(
            openat2(
                &device_parent,
                leaf,
                OFlags::PATH | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                Mode::empty(),
                ResolveFlags::BENEATH.union(RESOLVE_NO_LINKS),
            )
            .map_err(|error| RuntimeError::Io(error.to_string()))?,
        );
        let unmounted_metadata = unmounted.metadata().map_err(RuntimeError::from)?;
        if !unmounted_metadata.is_file()
            || unmounted_metadata.file_type().is_symlink()
            || unmounted_metadata.nlink() != 1
            || descriptor_mount_id(&unmounted)? != descriptor_mount_id(&device_parent)?
        {
            return Err(RuntimeError::Command(
                "jailed recovery target changed after exact bind unmount".to_owned(),
            ));
        }
    } else if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.nlink() != 1
        || descriptor_mount_id(&target)? != descriptor_mount_id(&device_parent)?
    {
        return Err(RuntimeError::Command(
            "jailed recovery target has an unexpected type or mount identity".to_owned(),
        ));
    }
    Ok(())
}

fn unmount_jailed_mapper_with_retry(
    device_parent: &File,
    leaf: &OsStr,
    jailed_device: &Path,
    mapper: &KernelMapperIdentity,
    target_identity: super::ObjectIdentity,
    target_mount_id: u64,
    timeout: Duration,
) -> Result<(), RuntimeError> {
    let deadline = Instant::now() + timeout;
    loop {
        match unmount(jailed_device, UnmountFlags::NOFOLLOW) {
            Ok(()) => return Ok(()),
            Err(Errno::BUSY) if Instant::now() < deadline => {
                let current = File::from(
                    openat2(
                        device_parent,
                        leaf,
                        OFlags::PATH | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                        Mode::empty(),
                        ResolveFlags::BENEATH.union(RESOLVE_NO_LINKS),
                    )
                    .map_err(|error| RuntimeError::Io(error.to_string()))?,
                );
                let metadata = current.metadata().map_err(RuntimeError::from)?;
                if !metadata.file_type().is_block_device()
                    || major(metadata.rdev()) != mapper.major
                    || minor(metadata.rdev()) != mapper.minor
                    || super::ObjectIdentity::from_metadata(&metadata) != target_identity
                    || descriptor_mount_id(&current)? != target_mount_id
                {
                    return Err(RuntimeError::Command(
                        "jailed recovery mapper bind changed while unmount was busy".to_owned(),
                    ));
                }
                drop(current);
                thread::sleep(PROCESS_POLL_INTERVAL);
            }
            Err(error) => return Err(RuntimeError::Io(error.to_string())),
        }
    }
}

struct SealedRecoveryTools {
    veritysetup: SealedExecutable,
    dmsetup: SealedExecutable,
}

impl SealedRecoveryTools {
    fn load(tools: &RecoveryTools) -> Result<Self, RuntimeError> {
        Ok(Self {
            veritysetup: SealedExecutable::load("veritysetup recovery tool", &tools.veritysetup)?,
            dmsetup: SealedExecutable::load("dmsetup recovery tool", &tools.dmsetup)?,
        })
    }

    fn paths(&self) -> SealedToolPaths {
        SealedToolPaths {
            veritysetup: self.veritysetup.program.clone(),
            dmsetup: self.dmsetup.program.clone(),
        }
    }
}

pub(crate) struct SealedExecutable {
    file: File,
    program: PathBuf,
}

impl SealedExecutable {
    pub(crate) fn load(
        label: &str,
        artifact: &super::PinnedArtifact,
    ) -> Result<Self, RuntimeError> {
        let mut source = File::from(
            open(
                &artifact.path,
                OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                Mode::empty(),
            )
            .map_err(|error| RuntimeError::Io(error.to_string()))?,
        );
        let metadata = source.metadata().map_err(RuntimeError::from)?;
        let effective_uid = effective_uid()?;
        if !metadata.is_file()
            || !(metadata.uid() == 0 || metadata.uid() == effective_uid)
            || metadata.mode() & 0o022 != 0
            || metadata.mode() & 0o111 == 0
            || metadata.len() == 0
            || metadata.len() > MAX_RECOVERY_TOOL_BYTES
        {
            return Err(RuntimeError::InvalidConfig(format!(
                "{label} must be a root/euid-owned, non-group/world-writable executable regular file"
            )));
        }
        let mut sealed = File::from(
            memfd_create(
                "firecracker-recovery-tool",
                MemfdFlags::ALLOW_SEALING | MemfdFlags::CLOEXEC,
            )
            .map_err(|error| RuntimeError::Io(error.to_string()))?,
        );
        fchmod(&sealed, Mode::RUSR | Mode::XUSR)
            .map_err(|error| RuntimeError::Io(error.to_string()))?;
        let copied = std::io::copy(
            &mut Read::by_ref(&mut source).take(MAX_RECOVERY_TOOL_BYTES + 1),
            &mut sealed,
        )
        .map_err(RuntimeError::from)?;
        if copied > MAX_RECOVERY_TOOL_BYTES {
            return Err(RuntimeError::InvalidConfig(format!(
                "{label} exceeds the recovery executable size limit"
            )));
        }
        sealed
            .seek(SeekFrom::Start(0))
            .map_err(RuntimeError::from)?;
        let observed = super::digest_reader(sealed.try_clone().map_err(RuntimeError::from)?)?;
        if observed != artifact.digest {
            return Err(RuntimeError::ArtifactDigestMismatch {
                label: label.to_owned(),
                path: artifact.path.clone(),
                expected: artifact.digest,
                actual: observed,
            });
        }
        let seals = SealFlags::WRITE | SealFlags::GROW | SealFlags::SHRINK | SealFlags::SEAL;
        fcntl_add_seals(&sealed, seals).map_err(|error| RuntimeError::Io(error.to_string()))?;
        if !fcntl_get_seals(&sealed)
            .map_err(|error| RuntimeError::Io(error.to_string()))?
            .contains(seals)
        {
            return Err(RuntimeError::Io(
                "recovery executable memfd did not retain every required seal".to_owned(),
            ));
        }
        let program = PathBuf::from(format!("/proc/self/fd/{}", sealed.as_raw_fd()));
        Ok(Self {
            file: sealed,
            program,
        })
    }

    pub(crate) fn program(&self) -> &Path {
        &self.program
    }

    /// Allows a sealed helper to remain executable after a deliberate child UID transition.
    ///
    /// The bytes are already immutable and digest-verified. Read/execute permission for other
    /// UIDs is needed only because the memfd remains owned by the unprivileged session daemon
    /// while the narrowly marked veritysetup child changes to UID/GID 0 before `execve`.
    pub(crate) fn allow_uid_transition_execution(&self) -> Result<(), RuntimeError> {
        fchmod(
            &self.file,
            Mode::RUSR | Mode::XUSR | Mode::RGRP | Mode::XGRP | Mode::ROTH | Mode::XOTH,
        )
        .map_err(|error| RuntimeError::Io(error.to_string()))
    }
}

struct SealedToolPaths {
    veritysetup: PathBuf,
    dmsetup: PathBuf,
}

fn open_absolute_directory_optional(path: &Path) -> Result<Option<File>, RuntimeError> {
    validate_absolute_normal_path(path)?;
    let relative = path.strip_prefix("/").map_err(|_| {
        RuntimeError::InvalidConfig(format!(
            "recovery directory is not beneath the host root: {}",
            path.display()
        ))
    })?;
    let root = open(
        "/",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| RuntimeError::Io(error.to_string()))?;
    if relative.as_os_str().is_empty() {
        return Ok(Some(File::from(root)));
    }
    let directory = match openat2(
        &root,
        relative,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::BENEATH.union(RESOLVE_NO_LINKS),
    ) {
        Ok(directory) => directory,
        Err(Errno::NOENT) => return Ok(None),
        Err(error) => return Err(RuntimeError::Io(error.to_string())),
    };
    Ok(Some(File::from(directory)))
}

fn open_optional_child_directory(
    parent: &File,
    leaf: &OsStr,
) -> Result<Option<File>, RuntimeError> {
    match openat2(
        parent,
        leaf,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
        RESOLVE_CHILD,
    ) {
        Ok(directory) => Ok(Some(File::from(directory))),
        Err(Errno::NOENT) => Ok(None),
        Err(error) => Err(RuntimeError::Io(error.to_string())),
    }
}

fn recover_cgroup(
    ownership: &SessionResourceOwnership,
    timeout: Duration,
) -> Result<(), RuntimeError> {
    let Some(parent_seal) = &ownership.cgroup_parent_seal else {
        return if open_absolute_directory_optional(&ownership.cgroup_parent)?.is_none() {
            Ok(())
        } else {
            Err(RuntimeError::Command(format!(
                "absent recovery cgroup parent appeared after ownership capture: {}",
                ownership.cgroup_parent.display()
            )))
        };
    };
    let parent = parent_seal.open_verified_parent()?;
    let Some(directory) = open_optional_child_directory(&parent, &ownership.cgroup_leaf)? else {
        return Ok(());
    };
    if fstatfs(&directory)
        .map_err(|error| RuntimeError::Io(error.to_string()))?
        .f_type
        != CGROUP2_SUPER_MAGIC
    {
        return Err(RuntimeError::Command(format!(
            "recovery cgroup is not on cgroup v2: {}",
            ownership.cgroup_path().display()
        )));
    }
    let mut kill = File::from(
        openat(
            &directory,
            "cgroup.kill",
            OFlags::WRONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(|error| RuntimeError::Io(error.to_string()))?,
    );
    kill.write_all(b"1").map_err(RuntimeError::from)?;
    let deadline = Instant::now() + timeout;
    loop {
        if !read_cgroup_populated(&directory)? {
            break;
        }
        if Instant::now() >= deadline {
            return Err(RuntimeError::Command(format!(
                "recovery cgroup did not become empty before deadline: {}",
                ownership.cgroup_path().display()
            )));
        }
        thread::sleep(PROCESS_POLL_INTERVAL);
    }
    if !remove_cgroup_descendants(&directory)? {
        return Err(RuntimeError::Cleanup(
            "recovery removed a bounded cgroup descendant batch; retry required".to_owned(),
        ));
    }
    let current =
        open_optional_child_directory(&parent, &ownership.cgroup_leaf)?.ok_or_else(|| {
            RuntimeError::Command(
                "recovery cgroup disappeared during identity validation".to_owned(),
            )
        })?;
    if super::ObjectIdentity::from_metadata(&directory.metadata().map_err(RuntimeError::from)?)
        != super::ObjectIdentity::from_metadata(&current.metadata().map_err(RuntimeError::from)?)
    {
        return Err(RuntimeError::Command(
            "recovery cgroup path changed before removal".to_owned(),
        ));
    }
    unlinkat(&parent, &ownership.cgroup_leaf, AtFlags::REMOVEDIR)
        .map_err(|error| RuntimeError::Io(error.to_string()))?;
    Ok(())
}

fn remove_cgroup_descendants(directory: &File) -> Result<bool, RuntimeError> {
    remove_directory_tree(directory, false, RECOVERY_REMOVAL_BUDGET)
}

fn next_directory_entry(
    directory: &File,
    include_non_directories: bool,
) -> Result<Option<(OsString, fs::Metadata)>, RuntimeError> {
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
        let name = OsStr::from_bytes(bytes).to_os_string();
        let descriptor = match openat2(
            directory,
            &name,
            OFlags::PATH | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
            RESOLVE_CHILD,
        ) {
            Ok(descriptor) => descriptor,
            Err(Errno::NOENT) => continue,
            Err(error) => return Err(RuntimeError::Io(error.to_string())),
        };
        let metadata = File::from(descriptor)
            .metadata()
            .map_err(RuntimeError::from)?;
        if include_non_directories || metadata.is_dir() {
            return Ok(Some((name, metadata)));
        }
    }
    Ok(None)
}

fn read_cgroup_populated(directory: &File) -> Result<bool, RuntimeError> {
    let file = File::from(
        openat(
            directory,
            "cgroup.events",
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(|error| RuntimeError::Io(error.to_string()))?,
    );
    let mut bytes = Vec::new();
    file.take((MAX_COMMAND_OUTPUT_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(RuntimeError::from)?;
    if bytes.len() > MAX_COMMAND_OUTPUT_BYTES {
        return Err(RuntimeError::Command(
            "recovery cgroup events exceed the safety limit".to_owned(),
        ));
    }
    parse_cgroup_events(&bytes)
}

fn parse_cgroup_events(bytes: &[u8]) -> Result<bool, RuntimeError> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| RuntimeError::Command("recovery cgroup events are not UTF-8".to_owned()))?;
    let populated = text.lines().find_map(|line| {
        let mut fields = line.split_ascii_whitespace();
        (fields.next() == Some("populated")).then(|| (fields.next(), fields.next()))
    });
    match populated {
        Some((Some("0"), None)) => Ok(false),
        Some((Some("1"), None)) => Ok(true),
        _ => Err(RuntimeError::Command(
            "recovery cgroup.events omitted a canonical populated value".to_owned(),
        )),
    }
}

fn recover_mapper(
    runner: &mut RealCommandRunner,
    tools: &SealedToolPaths,
    ownership: &SessionResourceOwnership,
    mapper: &KernelMapperIdentity,
) -> Result<(), RuntimeError> {
    validate_dmsetup_info(runner, &tools.dmsetup, ownership, mapper)?;
    let status = runner.run(&CommandSpec::new(
        tools.veritysetup.clone(),
        ["status".to_owned(), ownership.mapper_name.clone()],
    ))?;
    validate_verity_status(&status.stdout, ownership)?;
    let table = runner.run(&CommandSpec::new(
        tools.dmsetup.clone(),
        [
            "-j".to_owned(),
            mapper.major.to_string(),
            "-m".to_owned(),
            mapper.minor.to_string(),
            "table".to_owned(),
            "--showkeys".to_owned(),
        ],
    ))?;
    validate_verity_table(&table.stdout, ownership)?;
    let current = find_kernel_mapper(&ownership.mapper_name)?.ok_or_else(|| {
        RuntimeError::Command("recovery mapper disappeared before exact close".to_owned())
    })?;
    if current != *mapper {
        return Err(RuntimeError::Command(
            "recovery mapper UUID/devno/readonly changed before close".to_owned(),
        ));
    }
    runner.run(&CommandSpec::new(
        tools.dmsetup.clone(),
        ["-u".to_owned(), mapper.uuid.clone(), "remove".to_owned()],
    ))?;
    if find_kernel_mapper(&ownership.mapper_name)?.is_some() {
        return Err(RuntimeError::Command(
            "recovery mapper still exists after exact UUID close".to_owned(),
        ));
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct KernelMapperIdentity {
    name: String,
    uuid: String,
    major: u32,
    minor: u32,
    readonly: bool,
}

fn find_kernel_mapper(name: &str) -> Result<Option<KernelMapperIdentity>, RuntimeError> {
    let entries = fs::read_dir("/sys/class/block").map_err(RuntimeError::from)?;
    for entry in entries {
        let entry = entry.map_err(RuntimeError::from)?;
        let block_name = entry.file_name();
        let block_name = block_name.as_bytes();
        if !block_name.starts_with(b"dm-") || !block_name[3..].iter().all(u8::is_ascii_digit) {
            continue;
        }
        let path = entry.path();
        let observed_name = read_kernel_attribute(&path.join("dm/name"))?;
        if observed_name != name {
            continue;
        }
        let uuid = read_kernel_attribute(&path.join("dm/uuid"))?;
        if !uuid.starts_with("CRYPT-VERITY-")
            || uuid.len() > 256
            || !uuid
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        {
            return Err(RuntimeError::Command(
                "kernel mapper has no canonical CRYPT-VERITY UUID".to_owned(),
            ));
        }
        let (major, minor) = parse_device_number(&read_kernel_attribute(&path.join("dev"))?)?;
        let readonly = match read_kernel_attribute(&path.join("ro"))?.as_str() {
            "1" => true,
            "0" => false,
            _ => {
                return Err(RuntimeError::Command(
                    "kernel mapper has a non-canonical read-only flag".to_owned(),
                ));
            }
        };
        return Ok(Some(KernelMapperIdentity {
            name: observed_name,
            uuid,
            major,
            minor,
            readonly,
        }));
    }
    Ok(None)
}

fn read_kernel_attribute(path: &Path) -> Result<String, RuntimeError> {
    let bytes = fs::read(path).map_err(RuntimeError::from)?;
    if bytes.len() > 4096 {
        return Err(RuntimeError::Command(format!(
            "kernel mapper attribute is oversized: {}",
            path.display()
        )));
    }
    let value = std::str::from_utf8(&bytes)
        .map_err(|_| RuntimeError::Command("kernel mapper attribute is not UTF-8".to_owned()))?;
    Ok(value.trim_end_matches('\n').to_owned())
}

fn parse_device_number(value: &str) -> Result<(u32, u32), RuntimeError> {
    let (major, minor) = value.split_once(':').ok_or_else(|| {
        RuntimeError::Command("device number omitted the major/minor separator".to_owned())
    })?;
    if major.is_empty()
        || minor.is_empty()
        || !major.bytes().all(|byte| byte.is_ascii_digit())
        || !minor.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(RuntimeError::Command(
            "device number is not canonical decimal major:minor".to_owned(),
        ));
    }
    Ok((
        major
            .parse()
            .map_err(|_| RuntimeError::Command("device major number is out of range".to_owned()))?,
        minor
            .parse()
            .map_err(|_| RuntimeError::Command("device minor number is out of range".to_owned()))?,
    ))
}

fn validate_dmsetup_info(
    runner: &mut RealCommandRunner,
    dmsetup: &Path,
    ownership: &SessionResourceOwnership,
    mapper: &KernelMapperIdentity,
) -> Result<(), RuntimeError> {
    let info = runner.run(&CommandSpec::new(
        dmsetup,
        [
            "-j".to_owned(),
            mapper.major.to_string(),
            "-m".to_owned(),
            mapper.minor.to_string(),
            "info".to_owned(),
            "-c".to_owned(),
            "--noheadings".to_owned(),
            "--separator".to_owned(),
            "|".to_owned(),
            "-o".to_owned(),
            "name,uuid,major,minor,readonly,segments".to_owned(),
        ],
    ))?;
    let text = std::str::from_utf8(&info.stdout)
        .map_err(|_| RuntimeError::Command("dmsetup info is not UTF-8".to_owned()))?;
    let lines = text.lines().collect::<Vec<_>>();
    if lines.len() != 1 {
        return Err(RuntimeError::Command(
            "dmsetup info did not return exactly one mapper".to_owned(),
        ));
    }
    let fields = lines[0].split('|').map(str::trim).collect::<Vec<_>>();
    let readonly = fields.get(4).copied();
    if fields.len() != 6
        || fields[0] != ownership.mapper_name
        || fields[1] != mapper.uuid
        || fields[2] != mapper.major.to_string()
        || fields[3] != mapper.minor.to_string()
        // dmsetup's column renderer emits `Read-only` on current releases;
        // older releases use `read-only` or the numeric form. Accept only
        // those three documented true spellings, never a case-folded or
        // prefix match.
        || !dmsetup_reports_readonly(readonly)
        || fields[5] != "1"
        || !mapper.readonly
    {
        return Err(RuntimeError::Command(format!(
            "dmsetup info does not match exact kernel mapper identity: expected name={} uuid={} device={}:{} readonly=true segments=1, observed={fields:?}, sysfs_readonly={}",
            ownership.mapper_name, mapper.uuid, mapper.major, mapper.minor, mapper.readonly,
        )));
    }
    Ok(())
}

fn dmsetup_reports_readonly(value: Option<&str>) -> bool {
    matches!(value, Some("Read-only" | "read-only" | "1"))
}

fn validate_verity_status(
    output: &[u8],
    ownership: &SessionResourceOwnership,
) -> Result<(), RuntimeError> {
    validate_verity_status_fields(
        output,
        &ownership.mapper_name,
        &ownership.data_device,
        &ownership.hash_device,
        ownership.root_hash,
    )
}

pub(crate) fn validate_live_verity_status(
    output: &[u8],
    expected: &DmVerityConfig,
) -> Result<(), RuntimeError> {
    validate_verity_status_fields(
        output,
        &expected.mapper_name,
        &expected.data_device,
        &expected.hash_device,
        expected.root_hash,
    )
}

fn validate_verity_status_fields(
    output: &[u8],
    mapper_name: &str,
    data_device: &Path,
    hash_device: &Path,
    root_hash: Sha256Digest,
) -> Result<(), RuntimeError> {
    let output = std::str::from_utf8(output)
        .map_err(|_| RuntimeError::Command("verity status is not valid UTF-8".to_owned()))?;
    let mut lines = output.lines();
    let header = lines.next().ok_or_else(|| {
        RuntimeError::Command("verity status omitted the active mapper header".to_owned())
    })?;
    let expected_header = format!("/dev/mapper/{mapper_name} is active.");
    let expected_in_use_header = format!("/dev/mapper/{mapper_name} is active and is in use.");
    if !matches!(header, value if value == expected_header || value == expected_in_use_header) {
        return Err(RuntimeError::Command(format!(
            "verity status does not bind exact mapper {mapper_name}"
        )));
    }
    let fields = lines.collect::<Vec<_>>();
    let expected = [
        ("type", "VERITY".to_owned()),
        ("status", "verified".to_owned()),
        ("hash type", "1".to_owned()),
        ("data block", "4096".to_owned()),
        ("hash block", "4096".to_owned()),
        ("hash name", "sha256".to_owned()),
        ("root hash", root_hash.to_hex()),
        ("mode", "readonly".to_owned()),
    ];
    for (key, value) in expected {
        let observed = fields
            .iter()
            .filter_map(|line| {
                let (candidate, value) = line.trim().split_once(':')?;
                (candidate == key).then(|| value.trim())
            })
            .collect::<Vec<_>>();
        if observed.len() != 1
            || if key == "root hash" {
                !observed[0].eq_ignore_ascii_case(&value)
            } else {
                observed[0] != value
            }
        {
            return Err(RuntimeError::Command(format!(
                "verity status does not bind exact {key}: expected {value}, observed {observed:?}"
            )));
        }
    }
    validate_status_device(&fields, "data", data_device)?;
    validate_status_device(&fields, "hash", hash_device)?;
    Ok(())
}

fn validate_status_device(
    fields: &[&str],
    prefix: &str,
    expected: &Path,
) -> Result<(), RuntimeError> {
    let device_key = format!("{prefix} device");
    let device = unique_status_value(fields, &device_key)?;
    if device == expected.to_string_lossy() {
        return Ok(());
    }

    let loop_key = format!("{prefix} loop");
    let loop_path = unique_status_value(fields, &loop_key)?;
    let loop_device = device.strip_prefix("/dev/loop").is_some_and(|suffix| {
        !suffix.is_empty() && suffix.bytes().all(|byte| byte.is_ascii_digit())
    });
    if loop_device && loop_path == expected.to_string_lossy() {
        Ok(())
    } else {
        Err(RuntimeError::Command(format!(
            "verity status does not bind exact {prefix} input {}",
            expected.display()
        )))
    }
}

fn unique_status_value<'a>(fields: &[&'a str], key: &str) -> Result<&'a str, RuntimeError> {
    let observed = fields
        .iter()
        .filter_map(|line| {
            let (candidate, value) = line.trim().split_once(':')?;
            (candidate == key).then(|| value.trim())
        })
        .collect::<Vec<_>>();
    if observed.len() == 1 {
        Ok(observed[0])
    } else {
        Err(RuntimeError::Command(format!(
            "verity status must contain exactly one {key} field, observed {observed:?}"
        )))
    }
}

fn validate_verity_table(
    output: &[u8],
    ownership: &SessionResourceOwnership,
) -> Result<(), RuntimeError> {
    let output = std::str::from_utf8(output)
        .map_err(|_| RuntimeError::Command("dm-verity table is not valid UTF-8".to_owned()))?;
    let mut lines = output.lines();
    let line = lines.next().ok_or_else(|| {
        RuntimeError::Command("dm-verity table omitted the mapping target".to_owned())
    })?;
    if lines.next().is_some() {
        return Err(RuntimeError::Command(
            "dm-verity mapper contains more than one target".to_owned(),
        ));
    }
    let fields: Vec<_> = line.split_ascii_whitespace().collect();
    validate_verity_table_fields(&fields, ownership.root_hash)?;
    validate_table_device(fields[4], &ownership.data_device)?;
    validate_table_device(fields[5], &ownership.hash_device)?;
    Ok(())
}

fn validate_verity_table_fields(
    fields: &[&str],
    root_hash: Sha256Digest,
) -> Result<(), RuntimeError> {
    if fields.len() != 13
        || fields[0] != "0"
        || fields[2] != "verity"
        || fields[3] != "1"
        || fields[6] != "4096"
        || fields[7] != "4096"
        || fields[10] != "sha256"
        || !fields[11].eq_ignore_ascii_case(&root_hash.to_hex())
        || !canonical_positive_decimal(fields[1])
        || !canonical_positive_decimal(fields[8])
        || !canonical_positive_decimal(fields[9])
        || !(fields[12] == "-"
            || fields[12].len() <= 512
                && fields[12].len().is_multiple_of(2)
                && fields[12].bytes().all(|byte| byte.is_ascii_hexdigit()))
    {
        return Err(RuntimeError::Command(
            "device mapper target is not the exact safe dm-verity table".to_owned(),
        ));
    }
    parse_device_number(fields[4])?;
    parse_device_number(fields[5])?;
    let sectors = fields[1]
        .parse::<u64>()
        .map_err(|_| RuntimeError::Command("verity target length is out of range".to_owned()))?;
    let data_blocks = fields[8]
        .parse::<u64>()
        .map_err(|_| RuntimeError::Command("verity data block count is out of range".to_owned()))?;
    let expected_sectors = data_blocks.checked_mul(8).ok_or_else(|| {
        RuntimeError::Command("verity target extent arithmetic overflowed".to_owned())
    })?;
    if sectors != expected_sectors {
        return Err(RuntimeError::Command(
            "verity target extent does not cover the exact data block count".to_owned(),
        ));
    }
    Ok(())
}

fn canonical_positive_decimal(value: &str) -> bool {
    !value.is_empty()
        && value != "0"
        && !value.starts_with('0')
        && value.bytes().all(|byte| byte.is_ascii_digit())
}

fn validate_table_device(value: &str, expected_path: &Path) -> Result<(), RuntimeError> {
    let (expected_major, expected_minor) = parse_device_number(value)?;
    let expected = File::from(
        open(
            expected_path,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(|error| RuntimeError::Io(error.to_string()))?,
    );
    let metadata = expected.metadata().map_err(RuntimeError::from)?;
    if metadata.file_type().is_block_device() {
        if major(metadata.rdev()) == expected_major && minor(metadata.rdev()) == expected_minor {
            return Ok(());
        }
        return Err(RuntimeError::Command(format!(
            "dm-verity table device {value} does not match configured block device {}",
            expected_path.display()
        )));
    }
    if !metadata.is_file() {
        return Err(RuntimeError::Command(format!(
            "dm-verity source is neither a regular nor block file: {}",
            expected_path.display()
        )));
    }
    let backing_attribute = PathBuf::from(format!(
        "/sys/dev/block/{expected_major}:{expected_minor}/loop/backing_file"
    ));
    let backing = read_kernel_attribute(&backing_attribute)?;
    if backing.is_empty() || backing.ends_with(" (deleted)") {
        return Err(RuntimeError::Command(
            "dm-verity loop device has no stable backing file".to_owned(),
        ));
    }
    let backing_path = if backing.starts_with('/') {
        PathBuf::from(backing)
    } else {
        Path::new("/").join(backing)
    };
    let observed = File::from(
        open(
            &backing_path,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(|error| RuntimeError::Io(error.to_string()))?,
    );
    if super::ObjectIdentity::from_metadata(&metadata)
        != super::ObjectIdentity::from_metadata(&observed.metadata().map_err(RuntimeError::from)?)
    {
        return Err(RuntimeError::Command(format!(
            "dm-verity loop device does not bind configured source {}",
            expected_path.display()
        )));
    }
    Ok(())
}

fn recover_jail(ownership: &SessionResourceOwnership) -> Result<(), RuntimeError> {
    let parent = ownership.jail_parent_seal.open_verified_parent()?;
    let Some(directory) = open_optional_child_directory(&parent, &ownership.jail_leaf)? else {
        return Ok(());
    };
    let identity =
        super::ObjectIdentity::from_metadata(&directory.metadata().map_err(RuntimeError::from)?);
    if !remove_directory_contents(&directory)? {
        return Err(RuntimeError::Cleanup(
            "recovery removed a bounded jail entry batch; retry required".to_owned(),
        ));
    }
    let current =
        open_optional_child_directory(&parent, &ownership.jail_leaf)?.ok_or_else(|| {
            RuntimeError::Command("recovery jail disappeared during identity validation".to_owned())
        })?;
    if super::ObjectIdentity::from_metadata(&current.metadata().map_err(RuntimeError::from)?)
        != identity
    {
        return Err(RuntimeError::Command(
            "recovery jail path changed before removal".to_owned(),
        ));
    }
    unlinkat(&parent, &ownership.jail_leaf, AtFlags::REMOVEDIR)
        .map_err(|error| RuntimeError::Io(error.to_string()))?;
    Ok(())
}

fn remove_directory_contents(directory: &File) -> Result<bool, RuntimeError> {
    remove_directory_tree(directory, true, RECOVERY_REMOVAL_BUDGET)
}

struct RemovalFrame {
    relative_path: PathBuf,
    identity: super::ObjectIdentity,
}

fn remove_directory_tree(
    root: &File,
    remove_non_directories: bool,
    budget: usize,
) -> Result<bool, RuntimeError> {
    let mut remaining = budget;
    let mut stack = vec![RemovalFrame {
        relative_path: PathBuf::new(),
        identity: super::ObjectIdentity::from_metadata(
            &root.metadata().map_err(RuntimeError::from)?,
        ),
    }];
    loop {
        let Some(frame) = stack.last() else {
            return Ok(true);
        };
        let directory = open_descendant_directory(root, &frame.relative_path)?;
        if let Some((name, metadata)) = next_removable_entry(&directory, remove_non_directories)? {
            if metadata.is_dir() {
                if stack.len() > MAX_RECOVERY_DEPTH {
                    return Err(RuntimeError::Command(format!(
                        "recovery subtree exceeds the {MAX_RECOVERY_DEPTH}-level depth limit"
                    )));
                }
                let child_path = frame.relative_path.join(&name);
                let child = open_descendant_directory(root, &child_path)?;
                let identity = super::ObjectIdentity::from_metadata(
                    &child.metadata().map_err(RuntimeError::from)?,
                );
                stack.push(RemovalFrame {
                    relative_path: child_path,
                    identity,
                });
                continue;
            }
            if remaining == 0 {
                return Ok(false);
            }
            unlinkat(&directory, &name, AtFlags::empty())
                .map_err(|error| RuntimeError::Io(error.to_string()))?;
            remaining -= 1;
            continue;
        }
        if stack.len() == 1 {
            return Ok(true);
        }
        if remaining == 0 {
            return Ok(false);
        }
        let frame = stack.pop().expect("non-root removal frame exists");
        let parent_path = frame
            .relative_path
            .parent()
            .ok_or_else(|| RuntimeError::Command("child recovery path has no parent".to_owned()))?;
        let name = frame
            .relative_path
            .file_name()
            .ok_or_else(|| RuntimeError::Command("child recovery path has no name".to_owned()))?;
        let parent = open_descendant_directory(root, parent_path)?;
        let current = open_optional_child_directory(&parent, name)?.ok_or_else(|| {
            RuntimeError::Command("recovery directory disappeared before removal".to_owned())
        })?;
        if super::ObjectIdentity::from_metadata(&current.metadata().map_err(RuntimeError::from)?)
            != frame.identity
        {
            return Err(RuntimeError::Command(
                "recovery directory changed before removal".to_owned(),
            ));
        }
        unlinkat(&parent, name, AtFlags::REMOVEDIR)
            .map_err(|error| RuntimeError::Io(error.to_string()))?;
        remaining -= 1;
    }
}

fn open_descendant_directory(root: &File, relative_path: &Path) -> Result<File, RuntimeError> {
    let mut directory = root.try_clone().map_err(RuntimeError::from)?;
    for component in relative_path.components() {
        let Component::Normal(name) = component else {
            return Err(RuntimeError::InvalidConfig(
                "recovery descendant path is not lexical".to_owned(),
            ));
        };
        directory = File::from(
            openat2(
                &directory,
                name,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
                Mode::empty(),
                RESOLVE_CHILD,
            )
            .map_err(|error| RuntimeError::Io(error.to_string()))?,
        );
    }
    Ok(directory)
}

fn next_removable_entry(
    directory: &File,
    include_non_directories: bool,
) -> Result<Option<(OsString, fs::Metadata)>, RuntimeError> {
    next_directory_entry(directory, include_non_directories)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        os::unix::fs::symlink,
        os::unix::fs::{MetadataExt, PermissionsExt},
        sync::atomic::{AtomicU64, Ordering},
    };

    static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn dmsetup_readonly_parser_accepts_only_explicit_true_spellings() {
        for accepted in ["Read-only", "read-only", "1"] {
            assert!(dmsetup_reports_readonly(Some(accepted)));
        }
        for rejected in ["Read-write", "read-write", "0", "READ-ONLY", "true", ""] {
            assert!(!dmsetup_reports_readonly(Some(rejected)));
        }
        assert!(!dmsetup_reports_readonly(None));
    }

    fn temp_directory(label: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "firecracker-recovery-{label}-{}-{}",
            std::process::id(),
            TEMP_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).expect("create isolated test directory");
        path
    }

    #[derive(Default)]
    struct FakeBackend {
        events: Vec<&'static str>,
        fail: Option<&'static str>,
    }

    impl FirecrackerRecoveryBackend for FakeBackend {
        fn recover_cgroup(
            &mut self,
            _ownership: &SessionResourceOwnership,
        ) -> Result<(), RuntimeError> {
            self.events.push("cgroup");
            fail_if(self.fail, "cgroup")
        }

        fn recover_mapper(
            &mut self,
            _ownership: &SessionResourceOwnership,
        ) -> Result<(), RuntimeError> {
            self.events.push("mapper");
            fail_if(self.fail, "mapper")
        }

        fn recover_jail(
            &mut self,
            _ownership: &SessionResourceOwnership,
        ) -> Result<(), RuntimeError> {
            self.events.push("jail");
            fail_if(self.fail, "jail")
        }
    }

    #[derive(Default)]
    struct FakeProvisioning {
        events: Vec<&'static str>,
        fail: bool,
    }

    impl ProvisioningRecovery for FakeProvisioning {
        fn release_provisioning(
            &mut self,
            _ownership: &SessionResourceOwnership,
        ) -> Result<(), RuntimeError> {
            self.events.push("provisioning");
            if self.fail {
                Err(RuntimeError::Cleanup("provisioning failed".to_owned()))
            } else {
                Ok(())
            }
        }
    }

    fn fail_if(failure: Option<&str>, stage: &str) -> Result<(), RuntimeError> {
        if failure == Some(stage) {
            Err(RuntimeError::Cleanup(format!("{stage} failed")))
        } else {
            Ok(())
        }
    }

    fn ownership() -> SessionResourceOwnership {
        let parent_seal = ParentSeal::capture(Path::new("/")).expect("seal test parent");
        SessionResourceOwnership {
            config_fingerprint: Sha256Digest::from_bytes([1; 32]),
            cgroup_parent: PathBuf::from("/sys/fs/cgroup/luna"),
            cgroup_parent_seal: Some(parent_seal.clone()),
            cgroup_leaf: OsString::from("session-a"),
            jail_parent: PathBuf::from("/srv/jailer/firecracker"),
            jail_parent_seal: parent_seal,
            jail_leaf: OsString::from("session-a"),
            jail_root: PathBuf::from("/srv/jailer/firecracker/session-a/root"),
            jailed_device: PathBuf::from("/srv/jailer/firecracker/session-a/root/dev/rootfs"),
            workspace: PathBuf::from("/srv/jailer/firecracker/session-a/root/workspace/session-a"),
            mapper_name: "root-session-a".to_owned(),
            data_device: PathBuf::from("/srv/images/root"),
            hash_device: PathBuf::from("/srv/images/root.verity"),
            root_hash: Sha256Digest::from_bytes([2; 32]),
        }
    }

    #[test]
    fn driver_advances_one_dependency_stage_per_call() {
        let mut recovery = FirecrackerRecovery::new(FakeBackend::default());
        let mut provisioning = FakeProvisioning::default();
        let ownership = ownership();
        let mut durable_stage = RecoveryStage::IdentityReserved;
        for expected in [
            RecoveryStage::CgroupEmpty,
            RecoveryStage::ProvisioningReleased,
            RecoveryStage::MapperClosed,
            RecoveryStage::JailRemoved,
            RecoveryStage::Complete,
        ] {
            let progress = FirecrackerRecovery::<FakeBackend>::begin(
                &ownership,
                ownership.config_fingerprint(),
                durable_stage,
            )
            .expect("reconstruct checkpoint-bound progress");
            let stage = recovery
                .recover_next(&ownership, progress, &mut provisioning)
                .expect("one recovery stage must advance");
            assert_eq!(stage, expected);
            durable_stage = stage;
        }
        assert_eq!(recovery.into_inner().events, ["cgroup", "mapper", "jail"]);
        assert_eq!(provisioning.events, ["provisioning"]);
    }

    #[test]
    fn failure_retains_the_exact_pending_stage() {
        let mut recovery = FirecrackerRecovery::new(FakeBackend {
            events: Vec::new(),
            fail: Some("mapper"),
        });
        let mut provisioning = FakeProvisioning::default();
        let ownership = ownership();
        let progress = FirecrackerRecovery::<FakeBackend>::begin(
            &ownership,
            ownership.config_fingerprint(),
            RecoveryStage::ProvisioningReleased,
        )
        .expect("begin mapper recovery");
        let error = recovery
            .recover_next(&ownership, progress, &mut provisioning)
            .expect_err("mapper failure must not advance");
        assert_eq!(error.pending_stage(), RecoveryStage::ProvisioningReleased);
        assert_eq!(recovery.into_inner().events, ["mapper"]);
        assert!(provisioning.events.is_empty());
    }

    #[test]
    fn complete_cannot_be_supplied_as_a_recovery_input() {
        let ownership = ownership();
        let error = FirecrackerRecovery::<FakeBackend>::begin(
            &ownership,
            ownership.config_fingerprint(),
            RecoveryStage::Complete,
        )
        .expect_err("complete must not be accepted as a pending effect");
        assert_eq!(error.pending_stage(), RecoveryStage::Complete);
    }

    #[test]
    fn mismatched_journal_fingerprint_cannot_execute_or_skip_a_stage() {
        let error = FirecrackerRecovery::<FakeBackend>::begin(
            &ownership(),
            Sha256Digest::from_bytes([9; 32]),
            RecoveryStage::MapperClosed,
        )
        .expect_err("foreign durable identity must fail closed");
        assert_eq!(error.pending_stage(), RecoveryStage::MapperClosed);
    }

    #[test]
    fn cgroup_events_requires_the_recursive_population_bit() {
        assert!(parse_cgroup_events(b"populated 1\nfrozen 0\n").expect("canonical events"));
        assert!(!parse_cgroup_events(b"populated 0\nfrozen 0\n").expect("canonical events"));
        assert!(parse_cgroup_events(b"populated 2\n").is_err());
        assert!(parse_cgroup_events(b"frozen 0\n").is_err());
    }

    #[test]
    fn verity_status_requires_exact_devices_type_and_mode() {
        let ownership = ownership();
        let good = format!(
            "/dev/mapper/root-session-a is active.\n  type: VERITY\n  status: verified\n  hash type: 1\n  data block: 4096\n  hash block: 4096\n  hash name: sha256\n  root hash: {}\n  data device: /srv/images/root\n  hash device: /srv/images/root.verity\n  mode: readonly\n",
            ownership.root_hash.to_hex()
        );
        assert!(validate_verity_status(good.as_bytes(), &ownership).is_ok());
        let loop_backed = format!(
            "/dev/mapper/root-session-a is active.\n  type: VERITY\n  status: verified\n  hash type: 1\n  data block: 4096\n  hash block: 4096\n  hash name: sha256\n  root hash: {}\n  data device: /dev/loop21\n  data loop: /srv/images/root\n  hash device: /dev/loop20\n  hash loop: /srv/images/root.verity\n  mode: readonly\n",
            ownership.root_hash.to_hex()
        );
        assert!(validate_verity_status(loop_backed.as_bytes(), &ownership).is_ok());
        let foreign_loop =
            loop_backed.replace("data loop: /srv/images/root", "data loop: /tmp/foreign");
        assert!(validate_verity_status(foreign_loop.as_bytes(), &ownership).is_err());
        let foreign = b"type: VERITY\ndata device: /srv/images/root\nhash device: /srv/images/root.verity\nmode: readwrite\n";
        assert!(validate_verity_status(foreign, &ownership).is_err());
    }

    #[test]
    fn verity_table_requires_exact_root_digest_and_single_target() {
        let ownership = ownership();
        let good = format!(
            "0 1024 verity 1 8:1 8:2 4096 4096 128 1 sha256 {} -\n",
            ownership.root_hash.to_hex()
        );
        let fields = good.split_ascii_whitespace().collect::<Vec<_>>();
        assert!(validate_verity_table_fields(&fields, ownership.root_hash).is_ok());
        let foreign = "0 1024 verity 1 8:1 8:2 4096 4096 128 1 sha256 deadbeef -\n";
        let fields = foreign.split_ascii_whitespace().collect::<Vec<_>>();
        assert!(validate_verity_table_fields(&fields, ownership.root_hash).is_err());
        let unsafe_option = format!("{} 1 ignore_corruption", good.trim_end());
        let fields = unsafe_option.split_ascii_whitespace().collect::<Vec<_>>();
        assert!(validate_verity_table_fields(&fields, ownership.root_hash).is_err());
    }

    #[test]
    fn absolute_directory_open_accepts_root_but_rejects_unsafe_paths() {
        assert!(
            open_absolute_directory_optional(Path::new("/"))
                .expect("root is an anchor")
                .is_some()
        );
        assert!(open_absolute_directory_optional(Path::new("/tmp/../tmp")).is_err());
        assert!(open_absolute_directory_optional(Path::new("relative")).is_err());
    }

    #[test]
    fn sealed_parent_must_exist_and_retain_mount_and_object_identity() {
        let base = temp_directory("parent-seal");
        let missing = base.join("parent");
        assert!(ParentSeal::capture(&missing).is_err());
        assert_eq!(
            ParentSeal::capture_optional(&missing).expect("optional missing parent"),
            None
        );
        fs::create_dir(&missing).expect("create expected parent");
        let exact_seal = ParentSeal::capture(&missing).expect("capture exact parent");
        assert!(exact_seal.open_verified_parent().is_ok());
        fs::rename(&missing, base.join("retained-old-parent")).expect("retain old inode");
        fs::create_dir(&missing).expect("replace sealed parent");
        assert!(exact_seal.open_verified_parent().is_err());
        fs::remove_dir_all(base).expect("remove test tree");
    }

    #[test]
    fn absent_cgroup_parent_is_complete_unless_it_reappears() {
        let base = temp_directory("absent-cgroup-parent");
        let parent = base.join("retired-worker-unit");
        let mut ownership = ownership();
        ownership.cgroup_parent = parent.clone();
        ownership.cgroup_parent_seal = None;
        ownership.cgroup_leaf = OsString::from("retired-firecracker");

        recover_cgroup(&ownership, Duration::from_millis(10))
            .expect("a child cannot survive an absent cgroup parent");
        fs::create_dir(&parent).expect("recreate parent after capture");
        assert!(matches!(
            recover_cgroup(&ownership, Duration::from_millis(10)),
            Err(RuntimeError::Command(message)) if message.contains("appeared")
        ));

        fs::remove_dir_all(base).expect("remove test tree");
    }

    #[test]
    fn absent_leaf_is_success_only_beneath_a_verified_parent() {
        let base = temp_directory("absent-leaf");
        let mut ownership = ownership();
        ownership.jail_parent = base.clone();
        ownership.jail_parent_seal = ParentSeal::capture(&base).expect("seal parent");
        ownership.jail_leaf = OsString::from("absent-session");
        assert!(recover_jail(&ownership).is_ok());

        let retained = base.with_extension("retained");
        fs::rename(&base, &retained).expect("retain sealed parent inode");
        fs::create_dir(&base).expect("replace sealed parent");
        assert!(recover_jail(&ownership).is_err());
        fs::remove_dir_all(base).expect("remove test tree");
        fs::remove_dir_all(retained).expect("remove retained parent");
    }

    #[test]
    fn recovery_fingerprint_binds_stable_parent_seals() {
        let first = temp_directory("fingerprint-one");
        let second = temp_directory("fingerprint-two");
        let first_seal = ParentSeal::capture(&first).expect("seal first");
        let second_seal = ParentSeal::capture(&second).expect("seal second");
        let runtime = Sha256Digest::from_bytes([4; 32]);
        assert_ne!(
            recovery_fingerprint(runtime, [&first_seal]),
            recovery_fingerprint(runtime, [&second_seal])
        );
        fs::remove_dir_all(first).expect("remove first");
        fs::remove_dir_all(second).expect("remove second");
    }

    #[test]
    fn recovery_tools_are_lazy_when_the_kernel_mapper_is_absent() {
        let missing = PathBuf::from("/definitely/missing/recovery-tool");
        let tools = RecoveryTools::new(
            super::super::PinnedArtifact::new(missing.clone(), Sha256Digest::from_bytes([7; 32])),
            super::super::PinnedArtifact::new(missing, Sha256Digest::from_bytes([8; 32])),
        );
        let mut backend =
            LinuxFirecrackerRecovery::new(tools).expect("static descriptors are safe");
        let mut ownership = ownership();
        ownership.mapper_name = format!("absent-recovery-mapper-{}", std::process::id());
        backend
            .recover_mapper(&ownership)
            .expect("absent kernel mapper must not open tools");
        assert!(backend.sealed_tools.is_none());
    }

    #[test]
    fn sealed_executable_runs_the_opened_bytes_after_source_path_replacement() {
        let base = temp_directory("sealed-tool");
        let source = base.join("tool");
        fs::copy("/bin/true", &source).expect("copy true executable");
        fs::set_permissions(&source, fs::Permissions::from_mode(0o500))
            .expect("protect executable");
        let digest = super::super::digest_file(&source).expect("digest true executable");
        let executable = SealedExecutable::load(
            "test recovery tool",
            &super::super::PinnedArtifact::new(&source, digest),
        )
        .expect("seal opened executable");
        fs::rename(&source, base.join("retained-original")).expect("retain original inode");
        fs::copy("/bin/false", &source).expect("replace source path bytes");
        let mut runner = RealCommandRunner::new();
        runner
            .run(&CommandSpec::new(&executable.program, []))
            .expect("sealed original true executable must run");
        fs::remove_dir_all(base).expect("remove test tree");
    }

    #[test]
    fn sealed_executable_can_be_executed_after_a_uid_transition_without_unsealing() {
        let base = temp_directory("sealed-tool-uid-transition");
        let source = base.join("tool");
        fs::copy("/bin/true", &source).expect("copy true executable");
        fs::set_permissions(&source, fs::Permissions::from_mode(0o500))
            .expect("protect executable");
        let digest = super::super::digest_file(&source).expect("digest true executable");
        let executable = SealedExecutable::load(
            "test recovery tool",
            &super::super::PinnedArtifact::new(&source, digest),
        )
        .expect("seal opened executable");

        assert_eq!(
            executable.file.metadata().expect("memfd metadata").mode() & 0o777,
            0o500
        );
        executable
            .allow_uid_transition_execution()
            .expect("grant read and execute across the UID transition");
        assert_eq!(
            executable.file.metadata().expect("memfd metadata").mode() & 0o777,
            0o555
        );
        let required = SealFlags::WRITE | SealFlags::GROW | SealFlags::SHRINK | SealFlags::SEAL;
        assert!(
            fcntl_get_seals(&executable.file)
                .expect("read retained seals")
                .contains(required)
        );

        fs::remove_dir_all(base).expect("remove test tree");
    }

    #[test]
    fn verity_table_rejects_extent_mismatch_and_optional_policy_flags() {
        let root = Sha256Digest::from_bytes([2; 32]);
        let digest = root.to_hex();
        let extent_mismatch = format!("0 1023 verity 1 8:1 8:2 4096 4096 128 1 sha256 {digest} -");
        assert!(
            validate_verity_table_fields(
                &extent_mismatch.split_ascii_whitespace().collect::<Vec<_>>(),
                root
            )
            .is_err()
        );
        let unsafe_option = format!(
            "0 1024 verity 1 8:1 8:2 4096 4096 128 1 sha256 {digest} - 1 ignore_corruption"
        );
        assert!(
            validate_verity_table_fields(
                &unsafe_option.split_ascii_whitespace().collect::<Vec<_>>(),
                root
            )
            .is_err()
        );
    }

    #[test]
    fn jail_symlink_is_unlinked_without_touching_its_external_target() {
        let base = temp_directory("symlink");
        let jail = base.join("jail");
        let external = base.join("external");
        fs::create_dir(&jail).expect("create jail");
        fs::write(&external, b"preserve").expect("create external target");
        symlink(&external, jail.join("link")).expect("create jail symlink");
        let directory = File::open(&jail).expect("open jail");
        assert!(remove_directory_contents(&directory).expect("remove symlink"));
        assert_eq!(fs::read(&external).expect("external survives"), b"preserve");
        fs::remove_dir_all(base).expect("remove test tree");
    }

    #[test]
    fn iterative_removal_makes_bounded_progress_across_wide_and_deep_trees() {
        let base = temp_directory("bounded-removal");
        for index in 0..(RECOVERY_REMOVAL_BUDGET + 3) {
            fs::write(base.join(format!("file-{index}")), b"x").expect("create entry");
        }
        let directory = File::open(&base).expect("open tree");
        assert!(!remove_directory_contents(&directory).expect("first bounded batch"));
        assert!(remove_directory_contents(&directory).expect("second bounded batch"));

        let mut cursor = base.clone();
        for index in 0..(RECOVERY_REMOVAL_BUDGET * 3) {
            cursor.push(format!("d{index}"));
            fs::create_dir(&cursor).expect("create deep directory");
        }
        let mut attempts = 0;
        while !remove_directory_contents(&directory).expect("deep bounded batch") {
            attempts += 1;
            assert!(attempts < 64, "bounded cleanup must make forward progress");
        }
        fs::remove_dir_all(base).expect("remove test tree");
    }

    #[test]
    fn removal_refuses_a_subtree_deeper_than_this_host_could_have_built() {
        let base = temp_directory("depth-limit");
        let mut cursor = base.clone();
        for index in 0..MAX_RECOVERY_DEPTH {
            cursor.push(format!("d{index}"));
            fs::create_dir(&cursor).expect("create directory at the depth limit");
        }
        let directory = File::open(&base).expect("open tree");
        let mut attempts = 0;
        while !remove_directory_contents(&directory).expect("a tree at the limit is removable") {
            attempts += 1;
            assert!(attempts < 256, "bounded cleanup must make forward progress");
        }

        let mut cursor = base.clone();
        for index in 0..=MAX_RECOVERY_DEPTH {
            cursor.push(format!("d{index}"));
            fs::create_dir(&cursor).expect("create directory past the depth limit");
        }
        let error = remove_directory_contents(&directory)
            .expect_err("a subtree deeper than the limit must not be walked");
        assert!(
            error.to_string().contains("depth limit"),
            "unexpected failure: {error}"
        );
        fs::remove_dir_all(base).expect("remove test tree");
    }

    #[test]
    fn cgroup_descendant_cleanup_removes_directories_bottom_up() {
        let base = temp_directory("cgroup-descendants");
        fs::write(base.join("control-file"), b"kernel-owned").expect("create control fixture");
        let mut cursor = base.clone();
        for index in 0..(RECOVERY_REMOVAL_BUDGET + 2) {
            cursor.push(format!("child-{index}"));
            fs::create_dir(&cursor).expect("create descendant");
        }
        let directory = File::open(&base).expect("open cgroup fixture");
        assert!(!remove_cgroup_descendants(&directory).expect("first bounded batch"));
        assert!(remove_cgroup_descendants(&directory).expect("second bounded batch"));
        assert!(base.join("control-file").exists());
        fs::remove_dir_all(base).expect("remove test tree");
    }
}
