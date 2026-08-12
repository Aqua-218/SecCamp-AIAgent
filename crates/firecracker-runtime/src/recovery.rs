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
    io::{Read, Write},
    mem::MaybeUninit,
    os::unix::{
        ffi::OsStrExt,
        fs::{FileTypeExt, MetadataExt},
    },
    path::{Component, Path, PathBuf},
    thread,
    time::{Duration, Instant},
};

use rustix::{
    fs::{AtFlags, Mode, OFlags, RawDir, ResolveFlags, fstatfs, open, openat, openat2, unlinkat},
    io::Errno,
};

use super::{
    CGROUP2_SUPER_MAGIC, COMMAND_TIMEOUT, CommandRunner, CommandSpec, MAX_COMMAND_OUTPUT_BYTES,
    MAX_WORKSPACE_DEPTH, MAX_WORKSPACE_ENTRIES, PROCESS_POLL_INTERVAL, RealCommandRunner,
    RuntimeConfig, RuntimeError, Sha256Digest,
};

const RECOVERY_TIMEOUT: Duration = COMMAND_TIMEOUT;
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
    cgroup_leaf: OsString,
    jail_parent: PathBuf,
    jail_leaf: OsString,
    jail_root: PathBuf,
    workspace: PathBuf,
    mapper_name: String,
    mapper_path: PathBuf,
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

        Ok(Self {
            config_fingerprint: config.instance_fingerprint(),
            cgroup_parent: cgroup_parent.to_path_buf(),
            cgroup_leaf: cgroup_leaf.to_os_string(),
            jail_parent: jail_parent.to_path_buf(),
            jail_leaf: jail_leaf.to_os_string(),
            jail_root,
            workspace: config.workspace.clone_path(),
            mapper_name: config.dm_verity.mapper_name.clone(),
            mapper_path: Path::new("/dev/mapper").join(&config.dm_verity.mapper_name),
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

/// Durable stage immediately before or after one recovery effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryStage {
    /// Session identities are reserved; no host cleanup has been acknowledged.
    IdentityReserved,
    /// The exact session cgroup is empty and removed.
    CgroupEmpty,
    /// The exact dm-verity mapping is absent.
    MapperClosed,
    /// Factory-owned mounts and provisioning artifacts are released.
    ProvisioningReleased,
    /// The exact session jail subtree is absent.
    JailRemoved,
    /// Every host recovery obligation is complete.
    Complete,
}

/// Mandatory recovery for resources created by the session provisioner.
pub trait ProvisioningRecovery {
    /// Releases only provisioning resources for `ownership`.
    ///
    /// The operation must be idempotent. It runs after process and mapper
    /// cleanup and before the jail subtree is removed.
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

    /// Verifies and closes the exact dm-verity mapping, or observes it absent.
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

    /// Performs at most one physical recovery effect.
    ///
    /// The returned stage is safe for a caller to persist before invoking this
    /// method again. A failure returns the unchanged input stage.
    ///
    /// # Errors
    ///
    /// Returns [`RecoveryError`] without advancing when an exact resource cannot
    /// be verified or released.
    pub fn recover_next<P>(
        &mut self,
        ownership: &SessionResourceOwnership,
        stage: RecoveryStage,
        provisioning: &mut P,
    ) -> Result<RecoveryStage, RecoveryError>
    where
        P: ProvisioningRecovery,
    {
        let result = match stage {
            RecoveryStage::IdentityReserved => self
                .backend
                .recover_cgroup(ownership)
                .map(|()| RecoveryStage::CgroupEmpty),
            RecoveryStage::CgroupEmpty => self
                .backend
                .recover_mapper(ownership)
                .map(|()| RecoveryStage::MapperClosed),
            RecoveryStage::MapperClosed => provisioning
                .release_provisioning(ownership)
                .map(|()| RecoveryStage::ProvisioningReleased),
            RecoveryStage::ProvisioningReleased => self
                .backend
                .recover_jail(ownership)
                .map(|()| RecoveryStage::JailRemoved),
            RecoveryStage::JailRemoved | RecoveryStage::Complete => Ok(RecoveryStage::Complete),
        };
        result.map_err(|source| RecoveryError {
            pending_stage: stage,
            source: Box::new(source),
        })
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
}

impl LinuxFirecrackerRecovery {
    /// Creates a production backend with bounded command and cgroup waits.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeError`] unless both tools are absolute, immutable-name,
    /// non-zero-digest artifacts whose bytes match their pinned digests.
    pub fn new(tools: RecoveryTools) -> Result<Self, RuntimeError> {
        super::validate_artifact("veritysetup recovery tool", &tools.veritysetup)?;
        super::validate_artifact("dmsetup recovery tool", &tools.dmsetup)?;
        verify_recovery_tools(&tools)?;
        Ok(Self {
            runner: RealCommandRunner::new(),
            deadline: RECOVERY_TIMEOUT,
            tools,
        })
    }
}

impl FirecrackerRecoveryBackend for LinuxFirecrackerRecovery {
    fn recover_cgroup(&mut self, ownership: &SessionResourceOwnership) -> Result<(), RuntimeError> {
        recover_cgroup(ownership, self.deadline)
    }

    fn recover_mapper(&mut self, ownership: &SessionResourceOwnership) -> Result<(), RuntimeError> {
        verify_recovery_tools(&self.tools)?;
        recover_mapper(&mut self.runner, &self.tools, ownership)
    }

    fn recover_jail(&mut self, ownership: &SessionResourceOwnership) -> Result<(), RuntimeError> {
        recover_jail(ownership)
    }
}

fn verify_recovery_tools(tools: &RecoveryTools) -> Result<(), RuntimeError> {
    for (label, tool) in [
        ("veritysetup recovery tool", &tools.veritysetup),
        ("dmsetup recovery tool", &tools.dmsetup),
    ] {
        let observed = super::digest_file(&tool.path)?;
        if observed != tool.digest {
            return Err(RuntimeError::ArtifactDigestMismatch {
                label: label.to_owned(),
                path: tool.path.clone(),
                expected: tool.digest,
                actual: observed,
            });
        }
    }
    Ok(())
}

fn open_absolute_directory_optional(path: &Path) -> Result<Option<File>, RuntimeError> {
    if !path.is_absolute() || path == Path::new("/") {
        return Err(RuntimeError::InvalidConfig(format!(
            "recovery directory must be an absolute non-root path: {}",
            path.display()
        )));
    }
    let relative = path.strip_prefix("/").map_err(|_| {
        RuntimeError::InvalidConfig(format!(
            "recovery directory is not beneath the host root: {}",
            path.display()
        ))
    })?;
    if relative
        .components()
        .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(RuntimeError::InvalidConfig(format!(
            "recovery directory contains a non-normal component: {}",
            path.display()
        )));
    }
    let root = open(
        "/",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| RuntimeError::Io(error.to_string()))?;
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
    let Some(parent) = open_absolute_directory_optional(&ownership.cgroup_parent)? else {
        return Ok(());
    };
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
    if !read_cgroup_tasks(&directory)?.is_empty() {
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
    }
    let deadline = Instant::now() + timeout;
    loop {
        if read_cgroup_tasks(&directory)?.is_empty() {
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

fn read_cgroup_tasks(directory: &File) -> Result<Vec<u32>, RuntimeError> {
    let file = File::from(
        openat(
            directory,
            "cgroup.procs",
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
            "recovery cgroup task list exceeds the safety limit".to_owned(),
        ));
    }
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| RuntimeError::Command("recovery cgroup task list is not UTF-8".to_owned()))?;
    text.lines()
        .map(|line| {
            if line.is_empty() || !line.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err(RuntimeError::Command(
                    "recovery cgroup contains a malformed task identifier".to_owned(),
                ));
            }
            let pid = line.parse::<u32>().map_err(|_| {
                RuntimeError::Command("recovery cgroup task identifier is out of range".to_owned())
            })?;
            if pid == 0 {
                return Err(RuntimeError::Command(
                    "recovery cgroup contains the reserved zero task identifier".to_owned(),
                ));
            }
            Ok(pid)
        })
        .collect()
}

fn recover_mapper(
    runner: &mut RealCommandRunner,
    tools: &RecoveryTools,
    ownership: &SessionResourceOwnership,
) -> Result<(), RuntimeError> {
    let mapper_metadata = match fs::metadata(&ownership.mapper_path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    if !mapper_metadata.file_type().is_block_device() {
        return Err(RuntimeError::Command(format!(
            "recovery mapper is not a block device: {}",
            ownership.mapper_path.display()
        )));
    }
    let status = runner.run(&CommandSpec::new(
        tools.veritysetup.path.clone(),
        ["status".to_owned(), ownership.mapper_name.clone()],
    ))?;
    validate_verity_status(&status.stdout, ownership)?;
    let table = runner.run(&CommandSpec::new(
        tools.dmsetup.path.clone(),
        [
            "table".to_owned(),
            ownership.mapper_name.clone(),
            "--showkeys".to_owned(),
        ],
    ))?;
    validate_verity_table(&table.stdout, ownership)?;
    runner.run(&CommandSpec::new(
        tools.veritysetup.path.clone(),
        [
            "verify".to_owned(),
            ownership.data_device.display().to_string(),
            ownership.hash_device.display().to_string(),
            ownership.root_hash.to_hex(),
        ],
    ))?;
    let current = fs::metadata(&ownership.mapper_path).map_err(RuntimeError::from)?;
    if !current.file_type().is_block_device() || current.rdev() != mapper_metadata.rdev() {
        return Err(RuntimeError::Command(
            "recovery mapper changed during exact verification".to_owned(),
        ));
    }
    runner.run(&CommandSpec::new(
        tools.veritysetup.path.clone(),
        ["close".to_owned(), ownership.mapper_name.clone()],
    ))?;
    match fs::metadata(&ownership.mapper_path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Ok(_) => Err(RuntimeError::Command(
            "recovery mapper still exists after close".to_owned(),
        )),
        Err(error) => Err(error.into()),
    }
}

fn validate_verity_status(
    output: &[u8],
    ownership: &SessionResourceOwnership,
) -> Result<(), RuntimeError> {
    let output = std::str::from_utf8(output)
        .map_err(|_| RuntimeError::Command("verity status is not valid UTF-8".to_owned()))?;
    let expected = [
        ("type", "VERITY".to_owned()),
        ("data device", ownership.data_device.display().to_string()),
        ("hash device", ownership.hash_device.display().to_string()),
        ("mode", "readonly".to_owned()),
    ];
    for (key, value) in expected {
        let observed = output.lines().find_map(|line| {
            let (candidate, value) = line.trim().split_once(':')?;
            (candidate == key).then(|| value.trim())
        });
        if observed != Some(value.as_str()) {
            return Err(RuntimeError::Command(format!(
                "verity status does not bind exact {key}: expected {value}, observed {observed:?}"
            )));
        }
    }
    Ok(())
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
    if fields.len() < 13 || fields[2] != "verity" {
        return Err(RuntimeError::Command(
            "device mapper target is not an exact dm-verity table".to_owned(),
        ));
    }
    if fields[10] != "sha256" || !fields[11].eq_ignore_ascii_case(&ownership.root_hash.to_hex()) {
        return Err(RuntimeError::Command(format!(
            "dm-verity table root digest does not match the trusted session digest: {}",
            fields[11]
        )));
    }
    Ok(())
}

fn recover_jail(ownership: &SessionResourceOwnership) -> Result<(), RuntimeError> {
    let Some(parent) = open_absolute_directory_optional(&ownership.jail_parent)? else {
        return Ok(());
    };
    let Some(directory) = open_optional_child_directory(&parent, &ownership.jail_leaf)? else {
        return Ok(());
    };
    let identity =
        super::ObjectIdentity::from_metadata(&directory.metadata().map_err(RuntimeError::from)?);
    let mut entries = 0_usize;
    remove_directory_contents(&directory, 0, &mut entries)?;
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

fn remove_directory_contents(
    directory: &File,
    depth: usize,
    entries: &mut usize,
) -> Result<(), RuntimeError> {
    if depth > MAX_WORKSPACE_DEPTH {
        return Err(RuntimeError::Command(
            "recovery jail exceeds the maximum directory depth".to_owned(),
        ));
    }
    let names = {
        let mut buffer = [MaybeUninit::uninit(); 8192];
        let mut names = Vec::new();
        let mut iterator = RawDir::new(directory, &mut buffer);
        while let Some(entry) = iterator.next() {
            let entry = entry.map_err(|error| RuntimeError::Io(error.to_string()))?;
            let bytes = entry.file_name().to_bytes();
            if matches!(bytes, b"." | b"..") {
                continue;
            }
            *entries = entries.checked_add(1).ok_or_else(|| {
                RuntimeError::Command("recovery jail entry count overflowed".to_owned())
            })?;
            if *entries > MAX_WORKSPACE_ENTRIES {
                return Err(RuntimeError::Command(
                    "recovery jail exceeds the maximum entry count".to_owned(),
                ));
            }
            names.push(OsStr::from_bytes(bytes).to_os_string());
        }
        names
    };

    for name in names {
        let descriptor = openat2(
            directory,
            &name,
            OFlags::PATH | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
            RESOLVE_CHILD,
        )
        .map_err(|error| RuntimeError::Io(error.to_string()))?;
        let metadata = File::from(descriptor)
            .metadata()
            .map_err(RuntimeError::from)?;
        if metadata.file_type().is_symlink() {
            return Err(RuntimeError::Command(
                "recovery jail contains a symbolic link".to_owned(),
            ));
        }
        if metadata.is_dir() {
            let child = File::from(
                openat2(
                    directory,
                    &name,
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
                    Mode::empty(),
                    RESOLVE_CHILD,
                )
                .map_err(|error| RuntimeError::Io(error.to_string()))?,
            );
            remove_directory_contents(&child, depth + 1, entries)?;
            unlinkat(directory, &name, AtFlags::REMOVEDIR)
                .map_err(|error| RuntimeError::Io(error.to_string()))?;
        } else {
            unlinkat(directory, &name, AtFlags::empty())
                .map_err(|error| RuntimeError::Io(error.to_string()))?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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
        SessionResourceOwnership {
            config_fingerprint: Sha256Digest::from_bytes([1; 32]),
            cgroup_parent: PathBuf::from("/sys/fs/cgroup/luna"),
            cgroup_leaf: OsString::from("session-a"),
            jail_parent: PathBuf::from("/srv/jailer/firecracker"),
            jail_leaf: OsString::from("session-a"),
            jail_root: PathBuf::from("/srv/jailer/firecracker/session-a/root"),
            workspace: PathBuf::from("/srv/jailer/firecracker/session-a/root/workspace/session-a"),
            mapper_name: "root-session-a".to_owned(),
            mapper_path: PathBuf::from("/dev/mapper/root-session-a"),
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
        let mut stage = RecoveryStage::IdentityReserved;
        for expected in [
            RecoveryStage::CgroupEmpty,
            RecoveryStage::MapperClosed,
            RecoveryStage::ProvisioningReleased,
            RecoveryStage::JailRemoved,
            RecoveryStage::Complete,
        ] {
            stage = recovery
                .recover_next(&ownership, stage, &mut provisioning)
                .expect("one recovery stage must advance");
            assert_eq!(stage, expected);
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
        let error = recovery
            .recover_next(&ownership(), RecoveryStage::CgroupEmpty, &mut provisioning)
            .expect_err("mapper failure must not advance");
        assert_eq!(error.pending_stage(), RecoveryStage::CgroupEmpty);
        assert_eq!(recovery.into_inner().events, ["mapper"]);
        assert!(provisioning.events.is_empty());
    }

    #[test]
    fn complete_is_an_idempotent_noop() {
        let mut recovery = FirecrackerRecovery::new(FakeBackend::default());
        let mut provisioning = FakeProvisioning::default();
        assert_eq!(
            recovery
                .recover_next(&ownership(), RecoveryStage::Complete, &mut provisioning)
                .expect("complete recovery must remain complete"),
            RecoveryStage::Complete
        );
        assert!(recovery.into_inner().events.is_empty());
        assert!(provisioning.events.is_empty());
    }

    #[test]
    fn verity_status_requires_exact_devices_type_and_mode() {
        let ownership = ownership();
        let good = b"/dev/mapper/root-session-a is active.\n  type: VERITY\n  data device: /srv/images/root\n  hash device: /srv/images/root.verity\n  mode: readonly\n";
        assert!(validate_verity_status(good, &ownership).is_ok());
        let foreign = b"type: VERITY\ndata device: /srv/images/foreign\nhash device: /srv/images/root.verity\nmode: readonly\n";
        assert!(validate_verity_status(foreign, &ownership).is_err());
    }

    #[test]
    fn verity_table_requires_exact_root_digest_and_single_target() {
        let ownership = ownership();
        let good = format!(
            "0 1024 verity 1 8:1 8:2 4096 4096 128 1 sha256 {} -\n",
            ownership.root_hash.to_hex()
        );
        assert!(validate_verity_table(good.as_bytes(), &ownership).is_ok());
        let foreign = "0 1024 verity 1 8:1 8:2 4096 4096 128 1 sha256 deadbeef -\n";
        assert!(validate_verity_table(foreign.as_bytes(), &ownership).is_err());
        let multiple = format!("{good}{good}");
        assert!(validate_verity_table(multiple.as_bytes(), &ownership).is_err());
    }

    #[test]
    fn absolute_directory_open_rejects_root_and_parent_components() {
        assert!(open_absolute_directory_optional(Path::new("/")).is_err());
        assert!(open_absolute_directory_optional(Path::new("/tmp/../tmp")).is_err());
        assert!(open_absolute_directory_optional(Path::new("relative")).is_err());
    }
}
