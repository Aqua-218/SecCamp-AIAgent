//! Real Linux implementation of the host operations surrounding a `CapFS` mount.
//!
//! [`CapfsHostResources`](crate::capfs_resources::CapfsHostResources) is the boundary where the
//! supervisor stops describing a lifecycle and something actually happens on the host. This module
//! is that something: a cgroup v2 leaf per subject, a `SOCK_SEQPACKET` control socket per subject,
//! a workload process confined to the leaf, and handle bookkeeping that keeps the shutdown order
//! enforceable.
//!
//! Handles deliberately have no OS object here. A subject's files are reached through its `CapFS`
//! mount, so the descriptors live in the guest; what the host must know is only *which* handle
//! identities a subject still holds, so that a close cannot be skipped or replayed.

use std::{
    collections::{BTreeMap, BTreeSet, btree_map::Entry},
    error::Error,
    ffi::{OsStr, OsString},
    fmt, fs,
    io::{self, Read, Write},
    os::unix::{fs::PermissionsExt, net::UnixListener},
    path::{Component, Path, PathBuf},
    process::{Child, Command, Stdio},
    thread::sleep,
    time::{Duration, Instant},
};

use authority_core::{capability::SubjectId, handle::HandleId};
use rustix::net::sockopt::socket_peercred;

use crate::{
    capfs_resources::CapfsHostResources,
    control_socket::{ControlSocketError, SubjectControlListener, SubjectCredential},
    supervisor::{
        CgroupHandle, ControlFdHandle, MountHandle, ResourceAcquisition, ResourceMutation,
        WorkloadHandle,
    },
};

/// How long a stopped workload is given to leave its cgroup before stop reports failure.
const WORKLOAD_STOP_TIMEOUT: Duration = Duration::from_secs(10);
const WORKLOAD_POLL_INTERVAL: Duration = Duration::from_millis(10);
const WORKLOAD_START_TIMEOUT: Duration = Duration::from_secs(10);
const ISOLATED_WORKLOAD_CGROUP: &str = "workload";
const START_GATE_READY: &[u8; 5] = b"ready";
const START_GATE_RELEASE: [u8; 1] = [1];
const START_GATE_ISOLATED: &[u8; 8] = b"isolated";

/// Environment variable carrying the subject's `CapFS` mount point to its workload.
pub const WORKLOAD_MOUNTPOINT_ENV: &str = "CAPFS_MOUNTPOINT";
/// Environment variable carrying the subject identity to its workload.
pub const WORKLOAD_SUBJECT_ENV: &str = "SUPERVISOR_SUBJECT";

/// Immutable process and filesystem limits for every isolated workload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkloadIsolationLimits {
    tmpfs_target: PathBuf,
    tmpfs_size_bytes: u64,
    memory_max_bytes: u64,
    pids_max: u64,
    user_id: u32,
    group_id: u32,
}

impl WorkloadIsolationLimits {
    /// Creates the explicit limits the fixed isolation launcher receives.
    #[must_use]
    pub fn new(
        tmpfs_target: impl Into<PathBuf>,
        tmpfs_size_bytes: u64,
        memory_max_bytes: u64,
        pids_max: u64,
        user_id: u32,
        group_id: u32,
    ) -> Self {
        Self {
            tmpfs_target: tmpfs_target.into(),
            tmpfs_size_bytes,
            memory_max_bytes,
            pids_max,
            user_id,
            group_id,
        }
    }
}

/// Fixed inputs for the expendable `workload-isolation-launcher` process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkloadIsolationConfig {
    launcher: PathBuf,
    rootfs_source: PathBuf,
    rootfs_mount_target: PathBuf,
    old_root: PathBuf,
    workspace_target: PathBuf,
    limits: WorkloadIsolationLimits,
}

impl WorkloadIsolationConfig {
    /// Creates one complete static isolation policy for a guest supervisor.
    #[must_use]
    pub fn new(
        launcher: impl Into<PathBuf>,
        rootfs_source: impl Into<PathBuf>,
        rootfs_mount_target: impl Into<PathBuf>,
        old_root: impl Into<PathBuf>,
        workspace_target: impl Into<PathBuf>,
        limits: WorkloadIsolationLimits,
    ) -> Self {
        Self {
            launcher: launcher.into(),
            rootfs_source: rootfs_source.into(),
            rootfs_mount_target: rootfs_mount_target.into(),
            old_root: old_root.into(),
            workspace_target: workspace_target.into(),
            limits,
        }
    }

    fn launcher_arguments(&self, launch: &IsolatedWorkloadLaunch<'_>) -> Vec<OsString> {
        let mut arguments = Vec::with_capacity(42 + launch.workload_arguments.len());
        append_argument(&mut arguments, "--rootfs-source", &self.rootfs_source);
        append_argument(
            &mut arguments,
            "--rootfs-mount-target",
            &self.rootfs_mount_target,
        );
        append_argument(&mut arguments, "--old-root", &self.old_root);
        append_argument(
            &mut arguments,
            "--workspace-source",
            launch.workspace_source,
        );
        append_argument(&mut arguments, "--workspace-target", &self.workspace_target);
        append_argument(&mut arguments, "--tmpfs-target", &self.limits.tmpfs_target);
        append_argument(
            &mut arguments,
            "--tmpfs-size-bytes",
            self.limits.tmpfs_size_bytes.to_string(),
        );
        append_argument(&mut arguments, "--cgroup-root", launch.cgroup_root);
        append_argument(&mut arguments, "--cgroup-name", ISOLATED_WORKLOAD_CGROUP);
        append_argument(
            &mut arguments,
            "--memory-max-bytes",
            self.limits.memory_max_bytes.to_string(),
        );
        append_argument(
            &mut arguments,
            "--pids-max",
            self.limits.pids_max.to_string(),
        );
        append_argument(
            &mut arguments,
            "--host-uid",
            self.limits.user_id.to_string(),
        );
        append_argument(
            &mut arguments,
            "--host-gid",
            self.limits.group_id.to_string(),
        );
        append_argument(&mut arguments, "--start-gate", launch.start_gate);
        append_argument(&mut arguments, "--control-socket", launch.control_path);
        append_argument(&mut arguments, "--landlock-read-only", "/");
        append_argument(
            &mut arguments,
            "--landlock-writable",
            &self.workspace_target,
        );
        append_argument(
            &mut arguments,
            "--env",
            format!("{WORKLOAD_SUBJECT_ENV}={}", launch.subject.as_str()),
        );
        append_argument(
            &mut arguments,
            "--env",
            format!(
                "{WORKLOAD_MOUNTPOINT_ENV}={}",
                self.workspace_target.display()
            ),
        );
        append_argument(&mut arguments, "--program", launch.workload_program);
        arguments.push(OsString::from("--"));
        arguments.extend_from_slice(launch.workload_arguments);
        arguments
    }
}

struct IsolatedWorkloadLaunch<'a> {
    workspace_source: &'a Path,
    cgroup_root: &'a Path,
    start_gate: &'a Path,
    subject: &'a SubjectId,
    control_path: &'a Path,
    workload_program: &'a Path,
    workload_arguments: &'a [OsString],
}

fn append_argument(arguments: &mut Vec<OsString>, flag: &str, value: impl AsRef<OsStr>) {
    arguments.push(OsString::from(flag));
    arguments.push(value.as_ref().to_owned());
}

/// Static host configuration shared by every subject in one session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxHostConfig {
    cgroup_parent: PathBuf,
    control_socket_directory: PathBuf,
    workload_program: PathBuf,
    workload_arguments: Vec<OsString>,
    isolation: WorkloadIsolationConfig,
    workload_credential: SubjectCredential,
}

impl LinuxHostConfig {
    /// Describes where subject resources are created and what a workload runs.
    ///
    /// `cgroup_parent` must be an existing cgroup v2 directory the supervisor may create leaves
    /// in. `control_socket_directory` must be an existing directory the supervisor owns. The
    /// workload always runs through `isolation`; this adapter has no direct-spawn mode.
    #[must_use]
    pub fn new(
        cgroup_parent: impl Into<PathBuf>,
        control_socket_directory: impl Into<PathBuf>,
        workload_program: impl Into<PathBuf>,
        workload_arguments: impl IntoIterator<Item = OsString>,
        isolation: WorkloadIsolationConfig,
        workload_credential: SubjectCredential,
    ) -> Self {
        Self {
            cgroup_parent: cgroup_parent.into(),
            control_socket_directory: control_socket_directory.into(),
            workload_program: workload_program.into(),
            workload_arguments: workload_arguments.into_iter().collect(),
            isolation,
            workload_credential,
        }
    }
}

/// A failure in the Linux host adapter.
#[derive(Debug)]
pub enum LinuxHostError {
    /// A configured path is not an absolute, lexical path the supervisor may own.
    InvalidPath(PathBuf),
    /// A subject identity cannot name a filesystem object.
    InvalidSubjectName(SubjectId),
    /// A configured directory does not exist or is not a directory.
    MissingDirectory(PathBuf),
    /// The guest supervisor lacks the privilege required to own workload isolation resources.
    SupervisorNotRoot,
    /// An operating-system operation failed.
    Io {
        /// What the adapter was doing.
        action: &'static str,
        /// Failure reported by the operating system.
        source: io::Error,
    },
    /// The control socket could not be created or released.
    ControlSocket(ControlSocketError),
    /// A token was presented that this adapter never issued, or issued for another subject.
    ForeignToken(&'static str),
    /// The subject already owns a resource of this kind.
    AlreadyOwned(&'static str),
    /// A workload did not leave its cgroup within the stop timeout.
    WorkloadStopTimeout(SubjectId),
    /// A handle identity was opened twice or closed without being open.
    HandleState {
        /// What went wrong with the handle identity.
        reason: &'static str,
        /// Handle identity involved.
        handle: HandleId,
    },
    /// A root-owned child did not complete the start-gate handshake.
    StartGate(String),
}

impl fmt::Display for LinuxHostError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPath(path) => write!(
                formatter,
                "host path must be absolute and lexical: {}",
                path.display()
            ),
            Self::InvalidSubjectName(subject) => write!(
                formatter,
                "subject `{}` cannot name a host resource",
                subject.as_str()
            ),
            Self::MissingDirectory(path) => write!(
                formatter,
                "host directory must already exist: {}",
                path.display()
            ),
            Self::SupervisorNotRoot => {
                formatter.write_str("guest supervisor must run as root to own isolation resources")
            }
            Self::Io { action, source } => write!(formatter, "{action} failed: {source}"),
            Self::ControlSocket(error) => error.fmt(formatter),
            Self::ForeignToken(kind) => {
                write!(formatter, "{kind} token was not issued for this subject")
            }
            Self::AlreadyOwned(kind) => write!(formatter, "subject already owns its {kind}"),
            Self::WorkloadStopTimeout(subject) => write!(
                formatter,
                "workload for `{}` did not leave its cgroup within {} seconds",
                subject.as_str(),
                WORKLOAD_STOP_TIMEOUT.as_secs()
            ),
            Self::HandleState { reason, handle } => {
                write!(formatter, "handle `{}` {reason}", handle.as_str())
            }
            Self::StartGate(message) => write!(formatter, "workload start gate failed: {message}"),
        }
    }
}

impl Error for LinuxHostError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::ControlSocket(error) => Some(error),
            _ => None,
        }
    }
}

fn io_error(action: &'static str, source: io::Error) -> LinuxHostError {
    LinuxHostError::Io { action, source }
}

/// A subject name that is safe to use as a single filesystem component.
///
/// A subject identity is host-assigned, but it reaches this module as a string, and one `/` or
/// `..` in it would place a cgroup or socket outside the directory the supervisor owns.
fn resource_name(subject: &SubjectId) -> Result<&str, LinuxHostError> {
    let name = subject.as_str();
    let safe = !name.is_empty()
        && name.len() <= 128
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
        && !name.starts_with('.');
    if safe {
        Ok(name)
    } else {
        Err(LinuxHostError::InvalidSubjectName(subject.clone()))
    }
}

fn validate_owned_directory(path: &Path) -> Result<(), LinuxHostError> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::ParentDir | Component::CurDir))
    {
        return Err(LinuxHostError::InvalidPath(path.to_path_buf()));
    }
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| LinuxHostError::MissingDirectory(path.to_owned()))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(LinuxHostError::MissingDirectory(path.to_owned()));
    }
    if metadata.permissions().mode() & 0o022 != 0 {
        return Err(LinuxHostError::InvalidPath(path.to_owned()));
    }
    Ok(())
}

fn validate_absolute_lexical_path(path: &Path) -> Result<(), LinuxHostError> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::ParentDir | Component::CurDir))
    {
        return Err(LinuxHostError::InvalidPath(path.to_path_buf()));
    }
    Ok(())
}

fn validate_executable(path: &Path) -> Result<(), LinuxHostError> {
    validate_absolute_lexical_path(path)?;
    let metadata = fs::symlink_metadata(path)
        .map_err(|source| io_error("inspecting workload isolation launcher", source))?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.permissions().mode() & 0o111 == 0
    {
        return Err(LinuxHostError::InvalidPath(path.to_path_buf()));
    }
    Ok(())
}

fn validate_isolation_config(config: &WorkloadIsolationConfig) -> Result<(), LinuxHostError> {
    validate_executable(&config.launcher)?;
    for path in [
        &config.rootfs_source,
        &config.rootfs_mount_target,
        &config.old_root,
        &config.workspace_target,
        &config.limits.tmpfs_target,
    ] {
        validate_absolute_lexical_path(path)?;
    }
    if config.limits.tmpfs_size_bytes == 0
        || config.limits.tmpfs_size_bytes > (1_u64 << 30)
        || config.limits.memory_max_bytes == 0
        || config.limits.pids_max == 0
    {
        return Err(LinuxHostError::StartGate(
            "isolation limits must be positive and tmpfs must not exceed 1 GiB".to_owned(),
        ));
    }
    Ok(())
}

struct SubjectCgroup {
    subject: SubjectId,
    path: PathBuf,
}

struct SubjectControl {
    subject: SubjectId,
    listener: SubjectControlListener,
    bootstrap_reserved: bool,
}

struct SubjectWorkload {
    subject: SubjectId,
    cgroup: CgroupHandle,
    child: Child,
    start_gate: Option<WorkloadStartGate>,
}

/// Parent-owned gate that prevents an expendable launcher from entering isolation too early.
struct WorkloadStartGate {
    listener: UnixListener,
    path: PathBuf,
}

impl WorkloadStartGate {
    fn bind(directory: &Path, subject: &SubjectId) -> Result<Self, LinuxHostError> {
        let name = resource_name(subject)?;
        let path = directory.join(format!("{name}.start-gate.sock"));
        let listener = UnixListener::bind(&path)
            .map_err(|source| io_error("binding workload start gate", source))?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
            .map_err(|source| io_error("restricting workload start gate", source))?;
        listener
            .set_nonblocking(true)
            .map_err(|source| io_error("making workload start gate nonblocking", source))?;
        Ok(Self { listener, path })
    }

    fn release(&self) -> Result<(), LinuxHostError> {
        let deadline = Instant::now() + WORKLOAD_START_TIMEOUT;
        loop {
            match self.listener.accept() {
                Ok((mut stream, _)) => {
                    let peer = socket_peercred(&stream)
                        .map_err(|error| LinuxHostError::StartGate(error.to_string()))?;
                    if peer.uid.as_raw() != 0 || peer.gid.as_raw() != 0 {
                        return Err(LinuxHostError::StartGate(
                            "start-gate peer is not the root-owned launcher".to_owned(),
                        ));
                    }
                    stream
                        .set_read_timeout(Some(WORKLOAD_START_TIMEOUT))
                        .map_err(|source| {
                            io_error("setting workload start-gate read timeout", source)
                        })?;
                    let mut ready = [0_u8; START_GATE_READY.len()];
                    stream.read_exact(&mut ready).map_err(|source| {
                        io_error("reading workload start-gate readiness", source)
                    })?;
                    if ready != *START_GATE_READY {
                        return Err(LinuxHostError::StartGate(
                            "start-gate peer sent an invalid readiness marker".to_owned(),
                        ));
                    }
                    stream
                        .write_all(&START_GATE_RELEASE)
                        .map_err(|source| io_error("releasing workload start gate", source))?;
                    let mut isolated = [0_u8; START_GATE_ISOLATED.len()];
                    stream.read_exact(&mut isolated).map_err(|source| {
                        io_error("reading isolated workload startup attestation", source)
                    })?;
                    if isolated != *START_GATE_ISOLATED {
                        return Err(LinuxHostError::StartGate(
                            "launcher sent an invalid isolation attestation".to_owned(),
                        ));
                    }
                    return Ok(());
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    if Instant::now() >= deadline {
                        return Err(LinuxHostError::StartGate(format!(
                            "root-owned launcher did not connect within {} seconds",
                            WORKLOAD_START_TIMEOUT.as_secs()
                        )));
                    }
                    sleep(WORKLOAD_POLL_INTERVAL);
                }
                Err(source) => return Err(io_error("accepting workload start gate", source)),
            }
        }
    }

    fn remove(&self) -> Result<(), LinuxHostError> {
        match fs::remove_file(&self.path) {
            Ok(()) => Ok(()),
            Err(source) if source.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(source) => Err(io_error("removing workload start gate", source)),
        }
    }
}

/// Real Linux host resources for one session's subjects.
pub struct LinuxHostResources {
    config: LinuxHostConfig,
    next_token: u64,
    cgroups: BTreeMap<CgroupHandle, SubjectCgroup>,
    controls: BTreeMap<ControlFdHandle, SubjectControl>,
    workloads: BTreeMap<WorkloadHandle, SubjectWorkload>,
    handles: BTreeMap<SubjectId, BTreeSet<HandleId>>,
}

impl fmt::Debug for LinuxHostResources {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LinuxHostResources")
            .field("config", &self.config)
            .field("cgroups", &self.cgroups.len())
            .field("controls", &self.controls.len())
            .field("workloads", &self.workloads.len())
            .finish_non_exhaustive()
    }
}

impl LinuxHostResources {
    /// Validates the static host configuration and returns an adapter that owns nothing yet.
    ///
    /// # Errors
    ///
    /// Returns [`LinuxHostError`] when the cgroup parent or control-socket directory is not an
    /// existing, absolute, non-symlink directory.
    pub fn new(config: LinuxHostConfig) -> Result<Self, LinuxHostError> {
        if rustix::process::geteuid().as_raw() != 0 {
            return Err(LinuxHostError::SupervisorNotRoot);
        }
        validate_owned_directory(&config.cgroup_parent)?;
        validate_owned_directory(&config.control_socket_directory)?;
        validate_absolute_lexical_path(&config.workload_program)?;
        validate_isolation_config(&config.isolation)?;
        Ok(Self {
            config,
            next_token: 0,
            cgroups: BTreeMap::new(),
            controls: BTreeMap::new(),
            workloads: BTreeMap::new(),
            handles: BTreeMap::new(),
        })
    }

    /// Returns the control socket path a subject's workload connects to.
    #[must_use]
    pub fn control_socket_path(&self, subject: &SubjectId) -> Option<PathBuf> {
        let name = resource_name(subject).ok()?;
        Some(
            self.config
                .control_socket_directory
                .join(format!("{name}.sock")),
        )
    }

    /// Returns the listener that owns a subject's accepted control connections.
    ///
    /// The caller accepts on this listener to bind a connection to the subject before any request
    /// byte is read. Returns `None` once the control descriptor has been closed.
    pub fn control_listener(&mut self, subject: &SubjectId) -> Option<&mut SubjectControlListener> {
        self.controls
            .values_mut()
            .find(|control| control.subject == *subject)
            .map(|control| &mut control.listener)
    }

    /// Reserves the subject's control listener before the setup transaction begins.
    ///
    /// A guest bootstrap connection must be accepted before
    /// [`crate::Supervisor::create_subject`] can use that kernel-authenticated identity. The
    /// subsequent setup transaction adopts this exact listener through `open_control_fd`; callers
    /// must therefore invoke this only immediately before creating the same subject.
    pub fn prepare_control_listener(
        &mut self,
        subject: &SubjectId,
    ) -> Result<ControlFdHandle, LinuxHostError> {
        match self.create_control_listener(subject, true) {
            ResourceAcquisition::Acquired(handle) => Ok(handle),
            ResourceAcquisition::NoEffect(error) | ResourceAcquisition::EffectUnknown(error) => {
                Err(error)
            }
            ResourceAcquisition::CleanupRequired { resource, error } => {
                let cleanup = self.close_control_fd(resource);
                Err(match cleanup {
                    ResourceMutation::Applied => error,
                    ResourceMutation::NoEffect(cleanup_error)
                    | ResourceMutation::CleanupRequired(cleanup_error)
                    | ResourceMutation::EffectUnknown(cleanup_error) => {
                        LinuxHostError::StartGate(format!(
                            "control listener setup failed ({error}); cleanup also failed ({cleanup_error})"
                        ))
                    }
                })
            }
        }
    }

    fn create_control_listener(
        &mut self,
        subject: &SubjectId,
        bootstrap_reserved: bool,
    ) -> ResourceAcquisition<ControlFdHandle, LinuxHostError> {
        if self
            .controls
            .values()
            .any(|owned| owned.subject == *subject)
        {
            return ResourceAcquisition::NoEffect(LinuxHostError::AlreadyOwned(
                "control descriptor",
            ));
        }
        let Some(path) = self.control_socket_path(subject) else {
            return ResourceAcquisition::NoEffect(LinuxHostError::InvalidSubjectName(
                subject.clone(),
            ));
        };
        let listener = match SubjectControlListener::bind(
            &path,
            subject.clone(),
            self.config.workload_credential,
            8,
        ) {
            Ok(listener) => listener,
            Err(error) => {
                return ResourceAcquisition::NoEffect(LinuxHostError::ControlSocket(error));
            }
        };
        let handle = ControlFdHandle::new(self.issue_token());
        self.controls.insert(
            handle,
            SubjectControl {
                subject: subject.clone(),
                listener,
                bootstrap_reserved,
            },
        );
        ResourceAcquisition::Acquired(handle)
    }

    fn issue_token(&mut self) -> u64 {
        let token = self.next_token;
        // A 64-bit counter cannot wrap within a session; saturating keeps the type total without
        // inventing a reuse path, and a saturated token would collide loudly on insert.
        self.next_token = self.next_token.saturating_add(1);
        token
    }

    fn cgroup_path(&self, handle: CgroupHandle) -> Option<&SubjectCgroup> {
        self.cgroups.get(&handle)
    }

    fn wait_for_empty_cgroup(path: &Path, subject: &SubjectId) -> Result<(), LinuxHostError> {
        let deadline = Instant::now() + WORKLOAD_STOP_TIMEOUT;
        loop {
            if !cgroup_populated(path)? {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(LinuxHostError::WorkloadStopTimeout(subject.clone()));
            }
            sleep(WORKLOAD_POLL_INTERVAL);
        }
    }
}

fn cgroup_populated(path: &Path) -> Result<bool, LinuxHostError> {
    let events = fs::read_to_string(path.join("cgroup.events"))
        .map_err(|error| io_error("reading cgroup.events", error))?;
    events
        .lines()
        .find_map(|line| line.strip_prefix("populated "))
        .map(|value| value.trim() == "1")
        .ok_or_else(|| {
            io_error(
                "reading cgroup.events",
                io::Error::other("cgroup.events omitted the populated key"),
            )
        })
}

impl CapfsHostResources for LinuxHostResources {
    type Error = LinuxHostError;

    fn create_cgroup(
        &mut self,
        subject: &SubjectId,
    ) -> ResourceAcquisition<CgroupHandle, Self::Error> {
        if self.cgroups.values().any(|owned| owned.subject == *subject) {
            return ResourceAcquisition::NoEffect(LinuxHostError::AlreadyOwned("cgroup"));
        }
        let name = match resource_name(subject) {
            Ok(name) => name,
            Err(error) => return ResourceAcquisition::NoEffect(error),
        };
        let path = self.config.cgroup_parent.join(name);
        // `create_dir` rather than `create_dir_all`: an existing leaf is another owner's cgroup,
        // and adopting it would put two subjects in one resource.
        if let Err(error) = fs::create_dir(&path) {
            return ResourceAcquisition::NoEffect(io_error("creating the subject cgroup", error));
        }
        let handle = CgroupHandle::new(self.issue_token());
        self.cgroups.insert(
            handle,
            SubjectCgroup {
                subject: subject.clone(),
                path,
            },
        );
        ResourceAcquisition::Acquired(handle)
    }

    fn remove_cgroup(&mut self, cgroup: CgroupHandle) -> ResourceMutation<Self::Error> {
        let Some(owned) = self.cgroups.remove(&cgroup) else {
            // Removal is idempotent, so a token this adapter no longer holds is already removed.
            return ResourceMutation::Applied;
        };
        match fs::remove_dir(&owned.path) {
            Ok(()) => ResourceMutation::Applied,
            Err(error) if error.kind() == io::ErrorKind::NotFound => ResourceMutation::Applied,
            Err(error) => {
                // The directory still exists, so the caller must retry rather than forget it.
                self.cgroups.insert(cgroup, owned);
                ResourceMutation::CleanupRequired(io_error("removing the subject cgroup", error))
            }
        }
    }

    fn open_control_fd(
        &mut self,
        subject: &SubjectId,
    ) -> ResourceAcquisition<ControlFdHandle, Self::Error> {
        if let Some((handle, owned)) = self
            .controls
            .iter_mut()
            .find(|(_, owned)| owned.subject == *subject)
        {
            if owned.bootstrap_reserved {
                owned.bootstrap_reserved = false;
                return ResourceAcquisition::Acquired(*handle);
            }
            return ResourceAcquisition::NoEffect(LinuxHostError::AlreadyOwned(
                "control descriptor",
            ));
        }
        self.create_control_listener(subject, false)
    }

    fn close_control_fd(&mut self, control: ControlFdHandle) -> ResourceMutation<Self::Error> {
        let Some(owned) = self.controls.remove(&control) else {
            return ResourceMutation::Applied;
        };
        let path = owned.listener.path().to_path_buf();
        // The socket is closed before its name is removed, so no peer can connect to a listener
        // that is no longer bound to a subject.
        drop(owned);
        match fs::remove_file(&path) {
            Ok(()) => ResourceMutation::Applied,
            Err(error) if error.kind() == io::ErrorKind::NotFound => ResourceMutation::Applied,
            Err(error) => {
                ResourceMutation::CleanupRequired(io_error("removing the control socket", error))
            }
        }
    }

    #[allow(clippy::too_many_lines)]
    fn start_workload(
        &mut self,
        subject: &SubjectId,
        cgroup: CgroupHandle,
        _mount: MountHandle,
        mountpoint: &Path,
        control: ControlFdHandle,
    ) -> ResourceAcquisition<WorkloadHandle, Self::Error> {
        let Some(owned_cgroup) = self.cgroup_path(cgroup) else {
            return ResourceAcquisition::NoEffect(LinuxHostError::ForeignToken("cgroup"));
        };
        if owned_cgroup.subject != *subject {
            return ResourceAcquisition::NoEffect(LinuxHostError::ForeignToken("cgroup"));
        }
        let cgroup_path = owned_cgroup.path.clone();
        let Some(owned_control) = self.controls.get(&control) else {
            return ResourceAcquisition::NoEffect(LinuxHostError::ForeignToken(
                "control descriptor",
            ));
        };
        if owned_control.subject != *subject {
            return ResourceAcquisition::NoEffect(LinuxHostError::ForeignToken(
                "control descriptor",
            ));
        }
        let control_path = owned_control.listener.path().to_path_buf();
        if self
            .workloads
            .values()
            .any(|owned| owned.subject == *subject)
        {
            return ResourceAcquisition::NoEffect(LinuxHostError::AlreadyOwned("workload"));
        }

        let start_gate =
            match WorkloadStartGate::bind(&self.config.control_socket_directory, subject) {
                Ok(start_gate) => start_gate,
                Err(error) => return ResourceAcquisition::NoEffect(error),
            };

        let launch = IsolatedWorkloadLaunch {
            workspace_source: mountpoint,
            cgroup_root: &cgroup_path,
            start_gate: &start_gate.path,
            subject,
            control_path: &control_path,
            workload_program: &self.config.workload_program,
            workload_arguments: &self.config.workload_arguments,
        };
        let launcher_arguments = self.config.isolation.launcher_arguments(&launch);

        let mut command = Command::new(&self.config.isolation.launcher);
        command
            .args(launcher_arguments)
            .env_clear()
            .current_dir("/")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let child = match command.spawn() {
            Ok(child) => child,
            Err(error) => {
                let gate_cleanup = start_gate.remove();
                if let Err(gate_error) = gate_cleanup {
                    return ResourceAcquisition::EffectUnknown(gate_error);
                }
                return ResourceAcquisition::NoEffect(io_error("spawning the workload", error));
            }
        };

        // The child exists before it is confined. This window is why confinement failure returns
        // `CleanupRequired` rather than `NoEffect`: the process is real and must be stopped even
        // though it never became a supervised workload.
        let handle = WorkloadHandle::new(self.issue_token());
        self.workloads.insert(
            handle,
            SubjectWorkload {
                subject: subject.clone(),
                cgroup,
                child,
                start_gate: Some(start_gate),
            },
        );
        let release = self
            .workloads
            .get(&handle)
            .and_then(|owned| owned.start_gate.as_ref())
            .ok_or_else(|| LinuxHostError::StartGate("start gate disappeared".to_owned()))
            .and_then(WorkloadStartGate::release);
        if let Err(error) = release {
            return ResourceAcquisition::CleanupRequired {
                resource: handle,
                error,
            };
        }
        match cgroup_populated(&cgroup_path) {
            Ok(true) => {
                let Some(start_gate) = self
                    .workloads
                    .get_mut(&handle)
                    .and_then(|owned| owned.start_gate.take())
                else {
                    return ResourceAcquisition::CleanupRequired {
                        resource: handle,
                        error: LinuxHostError::StartGate("start gate disappeared".to_owned()),
                    };
                };
                match start_gate.remove() {
                    Ok(()) => ResourceAcquisition::Acquired(handle),
                    Err(error) => {
                        self.workloads
                            .get_mut(&handle)
                            .expect("issued workload token must remain live")
                            .start_gate = Some(start_gate);
                        ResourceAcquisition::CleanupRequired {
                            resource: handle,
                            error,
                        }
                    }
                }
            }
            Ok(false) => ResourceAcquisition::CleanupRequired {
                resource: handle,
                error: LinuxHostError::StartGate(
                    "isolated workload did not populate its delegated cgroup".to_owned(),
                ),
            },
            Err(error) => ResourceAcquisition::CleanupRequired {
                resource: handle,
                error,
            },
        }
    }

    fn stop_workload(
        &mut self,
        workload: WorkloadHandle,
        cgroup: CgroupHandle,
    ) -> ResourceMutation<Self::Error> {
        let Some(mut owned) = self.workloads.remove(&workload) else {
            return ResourceMutation::Applied;
        };
        if owned.cgroup != cgroup {
            self.workloads.insert(workload, owned);
            return ResourceMutation::NoEffect(LinuxHostError::ForeignToken("cgroup"));
        }
        let Some(path) = self.cgroup_path(cgroup).map(|entry| entry.path.clone()) else {
            self.workloads.insert(workload, owned);
            return ResourceMutation::NoEffect(LinuxHostError::ForeignToken("cgroup"));
        };
        // `cgroup.kill` stops the whole subtree at once, so a workload cannot outlive the stop by
        // forking. Killing the recorded PID alone would miss every descendant.
        if let Err(error) = fs::write(path.join("cgroup.kill"), "1") {
            self.workloads.insert(workload, owned);
            return ResourceMutation::CleanupRequired(io_error(
                "killing the workload cgroup",
                error,
            ));
        }
        if let Err(error) = Self::wait_for_empty_cgroup(&path, &owned.subject) {
            self.workloads.insert(workload, owned);
            return ResourceMutation::CleanupRequired(error);
        }
        if let Some(start_gate) = owned.start_gate.take()
            && let Err(error) = start_gate.remove()
        {
            self.workloads.insert(workload, owned);
            return ResourceMutation::CleanupRequired(error);
        }
        // Reaping is what releases the zombie the supervisor created; the cgroup being empty is
        // not enough on its own.
        match owned.child.wait() {
            Ok(_) => ResourceMutation::Applied,
            Err(error) => {
                ResourceMutation::CleanupRequired(io_error("reaping the workload", error))
            }
        }
    }

    fn open_handle(
        &mut self,
        subject: &SubjectId,
        handle: &HandleId,
    ) -> ResourceMutation<Self::Error> {
        match self.handles.entry(subject.clone()) {
            Entry::Occupied(mut owned) => {
                if owned.get().contains(handle) {
                    return ResourceMutation::NoEffect(LinuxHostError::HandleState {
                        reason: "is already open for this subject",
                        handle: handle.clone(),
                    });
                }
                owned.get_mut().insert(handle.clone());
            }
            Entry::Vacant(slot) => {
                slot.insert(BTreeSet::from([handle.clone()]));
            }
        }
        ResourceMutation::Applied
    }

    fn close_handle(
        &mut self,
        subject: &SubjectId,
        handle: &HandleId,
    ) -> ResourceMutation<Self::Error> {
        // Close is idempotent by contract, so a handle this adapter does not hold is already
        // closed rather than an error.
        if let Some(open) = self.handles.get_mut(subject) {
            open.remove(handle);
            if open.is_empty() {
                self.handles.remove(subject);
            }
        }
        ResourceMutation::Applied
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn unique(label: &str) -> String {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        format!(
            "supervisor-host-{label}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        )
    }

    struct Fixture {
        cgroup_parent: PathBuf,
        socket_directory: PathBuf,
    }

    fn test_isolation_config() -> WorkloadIsolationConfig {
        WorkloadIsolationConfig::new(
            std::env::current_exe().expect("test executable path must resolve"),
            "/",
            "/mnt/rootfs",
            "/mnt/rootfs/.old-root",
            "/workspace",
            WorkloadIsolationLimits::new("/tmp", 1024 * 1024, 1024 * 1024, 8, 1000, 1000),
        )
    }

    impl Fixture {
        /// Returns a fixture, or `None` on a host without a writable cgroup v2 hierarchy.
        fn new(label: &str) -> Option<Self> {
            let cgroup_parent = Path::new("/sys/fs/cgroup").join(unique(label));
            if fs::create_dir(&cgroup_parent).is_err() {
                return None;
            }
            let socket_directory = std::env::temp_dir().join(unique(label));
            fs::create_dir(&socket_directory).expect("socket directory must be creatable");
            Some(Self {
                cgroup_parent,
                socket_directory,
            })
        }

        fn config(&self, program: &str, arguments: &[&str]) -> LinuxHostConfig {
            LinuxHostConfig::new(
                &self.cgroup_parent,
                &self.socket_directory,
                program,
                arguments.iter().map(|argument| OsString::from(*argument)),
                test_isolation_config(),
                SubjectCredential::new(
                    rustix::process::geteuid().as_raw(),
                    rustix::process::getegid().as_raw(),
                ),
            )
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            drop(fs::remove_dir_all(&self.socket_directory));
            drop(fs::remove_dir(&self.cgroup_parent));
        }
    }

    #[test]
    fn isolation_launcher_arguments_bind_each_dynamic_resource() {
        let config = Fixture::new("arguments")
            .expect("test fixture must be creatable")
            .config("/usr/local/libexec/guest-workload", &["--fixed"]);
        let subject = SubjectId::new("subject-a");
        let launch = IsolatedWorkloadLaunch {
            workspace_source: Path::new("/run/capfs/subject-a"),
            cgroup_root: Path::new("/sys/fs/cgroup/subject-a"),
            start_gate: Path::new("/run/supervisor/subject-a.start-gate.sock"),
            subject: &subject,
            control_path: Path::new("/run/supervisor/subject-a.sock"),
            workload_program: &config.workload_program,
            workload_arguments: &config.workload_arguments,
        };
        let arguments = config.isolation.launcher_arguments(&launch);
        assert!(arguments.windows(2).any(|pair| {
            pair == [
                OsString::from("--workspace-source"),
                OsString::from("/run/capfs/subject-a"),
            ]
        }));
        assert!(arguments.windows(2).any(|pair| {
            pair == [
                OsString::from("--cgroup-root"),
                OsString::from("/sys/fs/cgroup/subject-a"),
            ]
        }));
        assert!(arguments.windows(2).any(|pair| {
            pair == [
                OsString::from("--start-gate"),
                OsString::from("/run/supervisor/subject-a.start-gate.sock"),
            ]
        }));
        assert!(arguments.windows(2).any(|pair| {
            pair == [
                OsString::from("--control-socket"),
                OsString::from("/run/supervisor/subject-a.sock"),
            ]
        }));
        assert_eq!(arguments.last(), Some(&OsString::from("--fixed")));
    }

    #[test]
    fn one_subject_owns_at_most_one_cgroup_and_control_socket() {
        let Some(fixture) = Fixture::new("exclusive") else {
            return;
        };
        let mut host = LinuxHostResources::new(fixture.config("/bin/true", &[]))
            .expect("validated host config must build");
        let subject = SubjectId::new("subject-a");

        let ResourceAcquisition::Acquired(cgroup) = host.create_cgroup(&subject) else {
            panic!("first cgroup must be created");
        };
        assert!(matches!(
            host.create_cgroup(&subject),
            ResourceAcquisition::NoEffect(LinuxHostError::AlreadyOwned("cgroup"))
        ));
        let ResourceAcquisition::Acquired(control) = host.open_control_fd(&subject) else {
            panic!("first control socket must bind");
        };
        assert!(matches!(
            host.open_control_fd(&subject),
            ResourceAcquisition::NoEffect(LinuxHostError::AlreadyOwned("control descriptor"))
        ));

        assert!(matches!(
            host.close_control_fd(control),
            ResourceMutation::Applied
        ));
        assert!(
            matches!(host.close_control_fd(control), ResourceMutation::Applied),
            "closing a released descriptor must stay idempotent"
        );
        assert!(matches!(
            host.remove_cgroup(cgroup),
            ResourceMutation::Applied
        ));
        assert!(matches!(
            host.remove_cgroup(cgroup),
            ResourceMutation::Applied
        ));
    }

    #[test]
    fn a_workload_cannot_borrow_another_subjects_tokens() {
        let Some(fixture) = Fixture::new("foreign") else {
            return;
        };
        let mut host = LinuxHostResources::new(fixture.config("/bin/true", &[]))
            .expect("validated host config must build");
        let owner = SubjectId::new("subject-a");
        let other = SubjectId::new("subject-b");

        let ResourceAcquisition::Acquired(cgroup) = host.create_cgroup(&owner) else {
            panic!("cgroup creation must succeed");
        };
        let ResourceAcquisition::Acquired(control) = host.open_control_fd(&owner) else {
            panic!("control socket must bind");
        };

        assert!(matches!(
            host.start_workload(
                &other,
                cgroup,
                MountHandle::new(1),
                &fixture.socket_directory,
                control,
            ),
            ResourceAcquisition::NoEffect(LinuxHostError::ForeignToken("cgroup"))
        ));

        drop(host.close_control_fd(control));
        drop(host.remove_cgroup(cgroup));
    }

    #[test]
    fn subject_names_that_could_escape_their_directory_are_refused() {
        let Some(fixture) = Fixture::new("names") else {
            return;
        };
        let mut host = LinuxHostResources::new(fixture.config("/bin/true", &[]))
            .expect("validated host config must build");

        for name in ["../escape", "with/slash", "", ".hidden", "with space"] {
            let subject = SubjectId::new(name);
            assert!(
                matches!(
                    host.create_cgroup(&subject),
                    ResourceAcquisition::NoEffect(LinuxHostError::InvalidSubjectName(_))
                ),
                "{name:?} must not name a host resource"
            );
        }
    }

    #[test]
    fn handles_are_tracked_per_subject_and_close_is_idempotent() {
        let Some(fixture) = Fixture::new("handles") else {
            return;
        };
        let mut host = LinuxHostResources::new(fixture.config("/bin/true", &[]))
            .expect("validated host config must build");
        let subject = SubjectId::new("subject-a");
        let handle = HandleId::new("handle-1");

        assert!(matches!(
            host.open_handle(&subject, &handle),
            ResourceMutation::Applied
        ));
        assert!(matches!(
            host.open_handle(&subject, &handle),
            ResourceMutation::NoEffect(LinuxHostError::HandleState { .. })
        ));
        assert!(matches!(
            host.close_handle(&subject, &handle),
            ResourceMutation::Applied
        ));
        assert!(matches!(
            host.close_handle(&subject, &handle),
            ResourceMutation::Applied
        ));
        assert!(matches!(
            host.open_handle(&subject, &handle),
            ResourceMutation::Applied
        ));
    }

    #[test]
    fn host_config_requires_existing_owned_directories() {
        let missing = std::env::temp_dir().join(unique("missing"));
        let config = LinuxHostConfig::new(
            &missing,
            std::env::temp_dir(),
            "/bin/true",
            [],
            test_isolation_config(),
            SubjectCredential::new(0, 0),
        );
        assert!(matches!(
            LinuxHostResources::new(config),
            Err(LinuxHostError::MissingDirectory(_))
        ));

        let relative = LinuxHostConfig::new(
            "relative/cgroup",
            std::env::temp_dir(),
            "/bin/true",
            [],
            test_isolation_config(),
            SubjectCredential::new(0, 0),
        );
        assert!(matches!(
            LinuxHostResources::new(relative),
            Err(LinuxHostError::InvalidPath(_))
        ));
    }
}
