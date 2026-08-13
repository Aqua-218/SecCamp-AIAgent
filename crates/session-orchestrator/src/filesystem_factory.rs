//! Concrete, digest-pinned provisioning of one Firecracker session jail.
//!
//! [`FilesystemFirecrackerFactory`] copies only immutable template artifacts into the jail that
//! the workspace backend already created for a durably reserved session identity. It deliberately
//! does not create a VM, mount a mapper, or remove the jail: those effects belong to the runtime
//! and its dependency-ordered recovery driver.

use std::{
    fs::{self, File, OpenOptions},
    io::{self, Write as _},
    os::unix::fs::{MetadataExt as _, OpenOptionsExt as _},
    path::{Component, Path, PathBuf},
};

use firecracker_runtime::{
    FileSystem as _, PinnedArtifact, RealFileSystem, RuntimeConfig, Snapshot,
};

use crate::{
    BackendError, SnapshotId,
    production_runtime::{
        PerSessionFirecrackerFactory, PreparedFirecrackerSession,
        SessionFirecrackerRecoveryRequest, SessionFirecrackerRequest,
    },
};

const KERNEL_RELATIVE_PATH: &str = "artifacts/kernel";
const SECCOMP_RELATIVE_PATH: &str = "artifacts/seccomp";
const SNAPSHOT_STATE_RELATIVE_PATH: &str = "snapshots/state";
const SNAPSHOT_MEMORY_RELATIVE_PATH: &str = "snapshots/memory";
const API_SOCKET_RELATIVE_PATH: &str = "run/firecracker.sock";
const VSOCK_SOCKET_RELATIVE_PATH: &str = "run/vsock.sock";
const JAILED_ROOTFS_RELATIVE_PATH: &str = "dev/rootfs";
const WORKSPACE_RELATIVE_PATH: &str = "workspace";

/// Immutable source files for one clean Firecracker snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SnapshotTemplate {
    state: PinnedArtifact,
    memory: PinnedArtifact,
}

impl SnapshotTemplate {
    /// Creates the two immutable files that comprise a full Firecracker snapshot.
    #[must_use]
    pub const fn new(state: PinnedArtifact, memory: PinnedArtifact) -> Self {
        Self { state, memory }
    }

    /// Returns the pinned state-file source.
    #[must_use]
    pub const fn state(&self) -> &PinnedArtifact {
        &self.state
    }

    /// Returns the pinned guest-memory source.
    #[must_use]
    pub const fn memory(&self) -> &PinnedArtifact {
        &self.memory
    }
}

/// Filesystem-backed provisioner for a single clean snapshot template.
///
/// `template_runtime` names the immutable kernel and seccomp files that are copied into every
/// session jail. Its snapshot fingerprint is the compatibility contract for `snapshot_template`.
/// The runtime rechecks all copied bytes immediately before restore.
pub struct FilesystemFirecrackerFactory {
    snapshot_id: SnapshotId,
    template_runtime: RuntimeConfig,
    snapshot_template: SnapshotTemplate,
}

impl FilesystemFirecrackerFactory {
    /// Binds a trusted snapshot identity to one immutable runtime and snapshot template.
    #[must_use]
    pub const fn new(
        snapshot_id: SnapshotId,
        template_runtime: RuntimeConfig,
        snapshot_template: SnapshotTemplate,
    ) -> Self {
        Self {
            snapshot_id,
            template_runtime,
            snapshot_template,
        }
    }

    fn validate_template(&self) -> Result<(), BackendError> {
        self.template_runtime
            .validate()
            .map_err(runtime_error("template runtime configuration"))?;
        validate_pinned_file("snapshot state", self.snapshot_template.state())?;
        validate_pinned_file("snapshot memory", self.snapshot_template.memory())?;
        Ok(())
    }

    fn validate_session_config(
        &self,
        config: &RuntimeConfig,
        identity: crate::SessionIdentity,
    ) -> Result<PathBuf, BackendError> {
        config
            .validate()
            .map_err(runtime_error("session runtime configuration"))?;
        if config.workspace.clone_id != identity.workspace_id().to_string() {
            return Err(BackendError::new(
                "session runtime clone ID is not bound to the requested workspace identity",
            ));
        }
        if config.snapshot_fingerprint() != self.template_runtime.snapshot_fingerprint() {
            return Err(BackendError::new(
                "session runtime is not compatible with the factory snapshot template",
            ));
        }
        if config.kernel.digest != self.template_runtime.kernel.digest
            || config.isolation.seccomp.filter.digest
                != self.template_runtime.isolation.seccomp.filter.digest
        {
            return Err(BackendError::new(
                "session runtime kernel or seccomp digest differs from the factory template",
            ));
        }

        let jail_root = session_jail_root(config)?;
        let expected = |relative: &str| jail_root.join(relative);
        for (label, actual, expected) in [
            (
                "kernel",
                &config.kernel.path,
                expected(KERNEL_RELATIVE_PATH),
            ),
            (
                "seccomp filter",
                &config.isolation.seccomp.filter.path,
                expected(SECCOMP_RELATIVE_PATH),
            ),
            (
                "API socket",
                &config.api_socket,
                expected(API_SOCKET_RELATIVE_PATH),
            ),
            (
                "vsock socket",
                &config.vsock.uds_path,
                expected(VSOCK_SOCKET_RELATIVE_PATH),
            ),
            (
                "jailed dm-verity device",
                &config.dm_verity.jailed_device_path,
                expected(JAILED_ROOTFS_RELATIVE_PATH),
            ),
            (
                "workspace clone root",
                &config.workspace.clone_root,
                expected(WORKSPACE_RELATIVE_PATH),
            ),
        ] {
            if actual != &expected {
                return Err(BackendError::new(format!(
                    "session {label} path is not the canonical jail location: {}",
                    actual.display()
                )));
            }
        }
        Ok(jail_root)
    }

    fn validate_request(
        &self,
        request: &SessionFirecrackerRequest,
    ) -> Result<PathBuf, BackendError> {
        self.validate_template()?;
        if request.snapshot_id() != self.snapshot_id {
            return Err(BackendError::new(
                "session request uses a snapshot ID different from this factory",
            ));
        }
        if request.guest_control_port() == 0 || request.guest_control_port() == u32::MAX {
            return Err(BackendError::new(
                "guest-control port must be explicit, non-zero, and non-wildcard",
            ));
        }
        let jail_root =
            self.validate_session_config(request.runtime_config(), request.identity())?;
        if request.snapshot_path() != jail_root.join(SNAPSHOT_STATE_RELATIVE_PATH)
            || request.memory_path() != jail_root.join(SNAPSHOT_MEMORY_RELATIVE_PATH)
        {
            return Err(BackendError::new(
                "session snapshot paths are not the canonical locations beneath its jail",
            ));
        }
        Ok(jail_root)
    }

    fn provision_layout(config: &RuntimeConfig, jail_root: &Path) -> Result<(), BackendError> {
        let chroot_base = &config.jailer_config.chroot_base_dir;
        let executable_parent = chroot_base.join(
            config
                .firecracker
                .path
                .file_name()
                .ok_or_else(|| BackendError::new("Firecracker executable has no filename"))?,
        );
        let effective_uid = effective_uid()?;
        validate_secure_directory("jailer chroot base", chroot_base, None)?;
        validate_secure_directory("Firecracker jail parent", &executable_parent, None)?;
        validate_secure_directory("session jail root", jail_root, Some(effective_uid))?;

        let workspace_root = jail_root.join(WORKSPACE_RELATIVE_PATH);
        validate_secure_directory(
            "session workspace root",
            &workspace_root,
            Some(effective_uid),
        )?;
        let workspace = config.workspace.clone_path();
        validate_existing_directory_beneath(
            "session workspace clone",
            jail_root,
            &workspace,
            Some(effective_uid),
        )?;

        for directory in [
            jail_root.join("artifacts"),
            jail_root.join("snapshots"),
            jail_root.join("run"),
            jail_root.join("dev"),
        ] {
            ensure_secure_directory_beneath(jail_root, &directory, effective_uid)?;
        }
        for path in [
            &config.api_socket,
            &config.vsock.uds_path,
            &config.dm_verity.jailed_device_path,
        ] {
            require_absent(path)?;
        }
        Ok(())
    }

    fn copy_template_files(
        &self,
        request: &SessionFirecrackerRequest,
    ) -> Result<Snapshot, BackendError> {
        let config = request.runtime_config();
        copy_pinned_file(
            "guest kernel",
            &self.template_runtime.kernel,
            &config.kernel.path,
        )?;
        copy_pinned_file(
            "seccomp filter",
            &self.template_runtime.isolation.seccomp.filter,
            &config.isolation.seccomp.filter.path,
        )?;
        copy_pinned_file(
            "snapshot state",
            self.snapshot_template.state(),
            request.snapshot_path(),
        )?;
        copy_pinned_file(
            "snapshot memory",
            self.snapshot_template.memory(),
            request.memory_path(),
        )?;
        Ok(Snapshot::new(
            request.snapshot_path(),
            request.memory_path(),
            config.snapshot_fingerprint(),
            self.snapshot_template.state().digest,
            self.snapshot_template.memory().digest,
            Vec::new(),
        ))
    }
}

impl PerSessionFirecrackerFactory for FilesystemFirecrackerFactory {
    fn snapshot_id(&self) -> SnapshotId {
        self.snapshot_id
    }

    fn prepare(
        &mut self,
        request: &SessionFirecrackerRequest,
    ) -> Result<PreparedFirecrackerSession, BackendError> {
        let jail_root = self.validate_request(request)?;
        Self::provision_layout(request.runtime_config(), &jail_root)?;
        let snapshot = self.copy_template_files(request)?;
        PreparedFirecrackerSession::verify(
            request,
            request.runtime_config().clone(),
            snapshot,
            self.snapshot_id,
        )
        .map_err(|error| {
            BackendError::new(format!("prepared session verification failed: {error}"))
        })
    }

    fn recover_provisioning(
        &mut self,
        request: &SessionFirecrackerRecoveryRequest,
    ) -> Result<(), BackendError> {
        self.validate_template()?;
        let _ = self.validate_session_config(request.runtime_config(), request.identity())?;
        // This factory owns no process, mapper, mount, or descriptor after `prepare` returns.
        // Its regular files remain inside the sealed session jail so the recovery driver's later
        // `JailRemoved` stage releases them atomically with every other jail-owned path.
        Ok(())
    }
}

fn runtime_error(
    context: &'static str,
) -> impl FnOnce(firecracker_runtime::RuntimeError) -> BackendError {
    move |error| BackendError::new(format!("invalid {context}: {error}"))
}

fn validate_pinned_file(label: &str, artifact: &PinnedArtifact) -> Result<(), BackendError> {
    if !artifact.path.is_absolute()
        || artifact
            .path
            .components()
            .any(|component| matches!(component, Component::ParentDir | Component::Prefix(_)))
    {
        return Err(BackendError::new(format!(
            "{label} source path must be absolute and contain no parent traversal: {}",
            artifact.path.display()
        )));
    }
    if artifact.digest.as_bytes() == [0; 32] {
        return Err(BackendError::new(format!(
            "{label} source digest cannot be all zeroes"
        )));
    }
    Ok(())
}

fn session_jail_root(config: &RuntimeConfig) -> Result<PathBuf, BackendError> {
    let executable = config
        .firecracker
        .path
        .file_name()
        .filter(|name| !name.is_empty())
        .ok_or_else(|| BackendError::new("Firecracker executable has no filename"))?;
    Ok(config
        .jailer_config
        .chroot_base_dir
        .join(executable)
        .join(&config.workspace.clone_id)
        .join("root"))
}

fn effective_uid() -> Result<u32, BackendError> {
    let status = fs::read_to_string("/proc/self/status")
        .map_err(|error| BackendError::new(format!("cannot read effective UID: {error}")))?;
    status
        .lines()
        .find_map(|line| line.strip_prefix("Uid:"))
        .and_then(|uids| uids.split_ascii_whitespace().nth(1))
        .and_then(|uid| uid.parse::<u32>().ok())
        .ok_or_else(|| BackendError::new("cannot parse effective UID from /proc/self/status"))
}

fn validate_secure_directory(
    label: &str,
    path: &Path,
    expected_owner: Option<u32>,
) -> Result<(), BackendError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| BackendError::new(format!("cannot inspect {label}: {error}")))?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.mode() & 0o022 != 0
        || expected_owner.is_some_and(|owner| metadata.uid() != owner)
    {
        return Err(BackendError::new(format!(
            "{label} must be a secure non-symlink directory owned by the session service: {}",
            path.display()
        )));
    }
    Ok(())
}

fn validate_existing_directory_beneath(
    label: &str,
    root: &Path,
    path: &Path,
    expected_owner: Option<u32>,
) -> Result<(), BackendError> {
    let relative = path.strip_prefix(root).map_err(|_| {
        BackendError::new(format!(
            "{label} is outside the session jail root: {}",
            path.display()
        ))
    })?;
    if relative.as_os_str().is_empty()
        || relative
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(BackendError::new(format!(
            "{label} is not a normal descendant of the session jail root: {}",
            path.display()
        )));
    }
    validate_secure_directory(label, path, expected_owner)
}

fn ensure_secure_directory_beneath(
    root: &Path,
    path: &Path,
    effective_uid: u32,
) -> Result<(), BackendError> {
    let relative = path.strip_prefix(root).map_err(|_| {
        BackendError::new(format!(
            "factory directory is outside the session jail root: {}",
            path.display()
        ))
    })?;
    if relative.as_os_str().is_empty()
        || relative
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(BackendError::new(format!(
            "factory directory is not a normal session-jail descendant: {}",
            path.display()
        )));
    }

    let mut current = root.to_path_buf();
    for component in relative.components() {
        let Component::Normal(component) = component else {
            return Err(BackendError::new(
                "factory directory has an invalid component",
            ));
        };
        current.push(component);
        match fs::symlink_metadata(&current) {
            Ok(_) => validate_secure_directory("factory directory", &current, Some(effective_uid))?,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                fs::create_dir(&current).map_err(|error| {
                    BackendError::new(format!(
                        "cannot create factory directory {}: {error}",
                        current.display()
                    ))
                })?;
                validate_secure_directory(
                    "created factory directory",
                    &current,
                    Some(effective_uid),
                )?;
            }
            Err(error) => {
                return Err(BackendError::new(format!(
                    "cannot inspect factory directory {}: {error}",
                    current.display()
                )));
            }
        }
    }
    Ok(())
}

fn require_absent(path: &Path) -> Result<(), BackendError> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Ok(_) => Err(BackendError::new(format!(
            "session runtime path already exists and is not factory-owned: {}",
            path.display()
        ))),
        Err(error) => Err(BackendError::new(format!(
            "cannot inspect session runtime path {}: {error}",
            path.display()
        ))),
    }
}

#[allow(clippy::too_many_lines)] // Every copy phase checks one ownership or digest invariant.
fn copy_pinned_file(
    label: &str,
    source: &PinnedArtifact,
    destination: &Path,
) -> Result<(), BackendError> {
    validate_pinned_file(label, source)?;
    if source.path == destination {
        return Err(BackendError::new(format!(
            "{label} source and session destination must differ: {}",
            destination.display()
        )));
    }
    let source_metadata = fs::symlink_metadata(&source.path).map_err(|error| {
        BackendError::new(format!(
            "cannot inspect {label} source {}: {error}",
            source.path.display()
        ))
    })?;
    if source_metadata.file_type().is_symlink()
        || !source_metadata.is_file()
        || source_metadata.nlink() == 0
    {
        return Err(BackendError::new(format!(
            "{label} source must be a real regular file: {}",
            source.path.display()
        )));
    }
    let source_identity = FileIdentity::from_metadata(&source_metadata);
    let mut digester = RealFileSystem::new();
    let source_digest = digester.digest(&source.path).map_err(|error| {
        BackendError::new(format!(
            "cannot digest {label} source {}: {error}",
            source.path.display()
        ))
    })?;
    if source_digest != source.digest {
        return Err(BackendError::new(format!(
            "{label} source digest does not match its pinned descriptor: {}",
            source.path.display()
        )));
    }

    let mut input = File::open(&source.path).map_err(|error| {
        BackendError::new(format!(
            "cannot open {label} source {}: {error}",
            source.path.display()
        ))
    })?;
    let opened_metadata = input.metadata().map_err(|error| {
        BackendError::new(format!(
            "cannot inspect opened {label} source {}: {error}",
            source.path.display()
        ))
    })?;
    if !opened_metadata.is_file()
        || FileIdentity::from_metadata(&opened_metadata) != source_identity
    {
        return Err(BackendError::new(format!(
            "{label} source changed before it could be copied: {}",
            source.path.display()
        )));
    }

    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o644)
        .open(destination)
        .map_err(|error| {
            BackendError::new(format!(
                "cannot create exclusive {label} destination {}: {error}",
                destination.display()
            ))
        })?;
    let destination_identity = output
        .metadata()
        .map(|metadata| FileIdentity::from_metadata(&metadata))
        .map_err(|error| {
            BackendError::new(format!(
                "cannot inspect created {label} destination {}: {error}",
                destination.display()
            ))
        })?;
    let copy_result = (|| {
        io::copy(&mut input, &mut output).map_err(|error| {
            BackendError::new(format!(
                "cannot copy {label} into {}: {error}",
                destination.display()
            ))
        })?;
        output.flush().map_err(|error| {
            BackendError::new(format!(
                "cannot flush {label} destination {}: {error}",
                destination.display()
            ))
        })?;
        output.sync_all().map_err(|error| {
            BackendError::new(format!(
                "cannot sync {label} destination {}: {error}",
                destination.display()
            ))
        })?;
        drop(output);
        let destination_metadata = fs::symlink_metadata(destination).map_err(|error| {
            BackendError::new(format!(
                "cannot inspect copied {label} destination {}: {error}",
                destination.display()
            ))
        })?;
        if destination_metadata.file_type().is_symlink()
            || !destination_metadata.is_file()
            || destination_metadata.nlink() != 1
            || FileIdentity::from_metadata(&destination_metadata) != destination_identity
        {
            return Err(BackendError::new(format!(
                "{label} destination was replaced while copying: {}",
                destination.display()
            )));
        }
        let destination_digest = digester.digest(destination).map_err(|error| {
            BackendError::new(format!(
                "cannot digest copied {label} destination {}: {error}",
                destination.display()
            ))
        })?;
        if destination_digest != source.digest {
            return Err(BackendError::new(format!(
                "copied {label} destination digest does not match the pinned source: {}",
                destination.display()
            )));
        }
        let current_source = fs::symlink_metadata(&source.path).map_err(|error| {
            BackendError::new(format!(
                "cannot re-check {label} source {}: {error}",
                source.path.display()
            ))
        })?;
        if current_source.file_type().is_symlink()
            || FileIdentity::from_metadata(&current_source) != source_identity
        {
            return Err(BackendError::new(format!(
                "{label} source changed while copying: {}",
                source.path.display()
            )));
        }
        Ok(())
    })();
    if let Err(error) = copy_result {
        let _ = remove_owned_file(destination, destination_identity);
        return Err(error);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FileIdentity {
    device: u64,
    inode: u64,
}

impl FileIdentity {
    fn from_metadata(metadata: &fs::Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
        }
    }
}

fn remove_owned_file(path: &Path, expected: FileIdentity) -> Result<(), BackendError> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        BackendError::new(format!(
            "cannot inspect failed-copy destination {}: {error}",
            path.display()
        ))
    })?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.nlink() != 1
        || FileIdentity::from_metadata(&metadata) != expected
    {
        return Err(BackendError::new(format!(
            "failed-copy destination changed and will not be removed: {}",
            path.display()
        )));
    }
    fs::remove_file(path).map_err(|error| {
        BackendError::new(format!(
            "cannot remove failed-copy destination {}: {error}",
            path.display()
        ))
    })
}
