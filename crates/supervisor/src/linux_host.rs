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
    ffi::OsString,
    fmt, fs, io,
    path::{Component, Path, PathBuf},
    process::{Child, Command, Stdio},
    thread::sleep,
    time::{Duration, Instant},
};

use authority_core::{capability::SubjectId, handle::HandleId};

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

/// Environment variable carrying the subject's `CapFS` mount point to its workload.
pub const WORKLOAD_MOUNTPOINT_ENV: &str = "CAPFS_MOUNTPOINT";
/// Environment variable carrying the subject's control socket path to its workload.
pub const WORKLOAD_CONTROL_SOCKET_ENV: &str = "SUPERVISOR_CONTROL_SOCKET";
/// Environment variable carrying the subject identity to its workload.
pub const WORKLOAD_SUBJECT_ENV: &str = "SUPERVISOR_SUBJECT";

/// Static host configuration shared by every subject in one session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxHostConfig {
    cgroup_parent: PathBuf,
    control_socket_directory: PathBuf,
    workload_program: PathBuf,
    workload_arguments: Vec<OsString>,
    workload_credential: SubjectCredential,
}

impl LinuxHostConfig {
    /// Describes where subject resources are created and what a workload runs.
    ///
    /// `cgroup_parent` must be an existing cgroup v2 directory the supervisor may create leaves
    /// in. `control_socket_directory` must be an existing directory the supervisor owns.
    #[must_use]
    pub fn new(
        cgroup_parent: impl Into<PathBuf>,
        control_socket_directory: impl Into<PathBuf>,
        workload_program: impl Into<PathBuf>,
        workload_arguments: impl IntoIterator<Item = OsString>,
        workload_credential: SubjectCredential,
    ) -> Self {
        Self {
            cgroup_parent: cgroup_parent.into(),
            control_socket_directory: control_socket_directory.into(),
            workload_program: workload_program.into(),
            workload_arguments: workload_arguments.into_iter().collect(),
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
    Ok(())
}

struct SubjectCgroup {
    subject: SubjectId,
    path: PathBuf,
}

struct SubjectControl {
    subject: SubjectId,
    listener: SubjectControlListener,
}

struct SubjectWorkload {
    subject: SubjectId,
    cgroup: CgroupHandle,
    child: Child,
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
        validate_owned_directory(&config.cgroup_parent)?;
        validate_owned_directory(&config.control_socket_directory)?;
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
            },
        );
        ResourceAcquisition::Acquired(handle)
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

        let mut command = Command::new(&self.config.workload_program);
        command
            .args(&self.config.workload_arguments)
            .env_clear()
            .env(WORKLOAD_SUBJECT_ENV, subject.as_str())
            .env(WORKLOAD_MOUNTPOINT_ENV, mountpoint)
            .env(WORKLOAD_CONTROL_SOCKET_ENV, &control_path)
            .current_dir(mountpoint)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let child = match command.spawn() {
            Ok(child) => child,
            Err(error) => {
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
            },
        );
        let pid = self
            .workloads
            .get(&handle)
            .map_or(0, |owned| owned.child.id());
        if let Err(error) = fs::write(cgroup_path.join("cgroup.procs"), pid.to_string()) {
            return ResourceAcquisition::CleanupRequired {
                resource: handle,
                error: io_error("moving the workload into its cgroup", error),
            };
        }
        match cgroup_populated(&cgroup_path) {
            Ok(true) => ResourceAcquisition::Acquired(handle),
            // The workload exited before confinement could be observed. Its exit is not proof
            // that it did nothing, so the caller still owns a workload it must stop.
            Ok(false) => ResourceAcquisition::CleanupRequired {
                resource: handle,
                error: io_error(
                    "confirming the workload joined its cgroup",
                    io::Error::other("the cgroup is empty immediately after the move"),
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
    fn a_confined_workload_is_stopped_with_every_descendant() {
        let Some(fixture) = Fixture::new("workload") else {
            return;
        };
        let mut host =
            LinuxHostResources::new(fixture.config("/bin/sh", &["-c", "sleep 300 & wait"]))
                .expect("validated host config must build");
        let subject = SubjectId::new("subject-a");

        let ResourceAcquisition::Acquired(cgroup) = host.create_cgroup(&subject) else {
            panic!("cgroup creation must succeed");
        };
        let ResourceAcquisition::Acquired(control) = host.open_control_fd(&subject) else {
            panic!("control socket must bind");
        };
        let mountpoint = fixture.socket_directory.clone();
        let ResourceAcquisition::Acquired(workload) =
            host.start_workload(&subject, cgroup, MountHandle::new(1), &mountpoint, control)
        else {
            panic!("workload must start inside its cgroup");
        };

        let procs = fs::read_to_string(fixture.cgroup_parent.join("subject-a/cgroup.procs"))
            .expect("cgroup.procs must be readable");
        assert!(
            procs.lines().count() >= 1,
            "the workload must be confined before start returns"
        );

        assert!(matches!(
            host.stop_workload(workload, cgroup),
            ResourceMutation::Applied
        ));
        assert!(
            !cgroup_populated(&fixture.cgroup_parent.join("subject-a"))
                .expect("cgroup must remain readable"),
            "cgroup.kill must take the whole subtree, not just the recorded PID"
        );
        assert!(matches!(
            host.close_control_fd(control),
            ResourceMutation::Applied
        ));
        assert!(matches!(
            host.remove_cgroup(cgroup),
            ResourceMutation::Applied
        ));
        assert!(!fixture.cgroup_parent.join("subject-a").exists());
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
            SubjectCredential::new(0, 0),
        );
        assert!(matches!(
            LinuxHostResources::new(relative),
            Err(LinuxHostError::InvalidPath(_))
        ));
    }
}
