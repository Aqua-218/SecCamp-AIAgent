//! Linux syscall backend for the isolation transaction.

#[cfg(target_os = "linux")]
mod implementation {
    use std::{
        ffi::CString,
        fs, io,
        num::NonZeroU32,
        os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
        os::unix::ffi::OsStrExt,
        os::unix::fs::MetadataExt,
        path::{Path, PathBuf},
    };

    use crate::backend::{ChildStartupNotifier, private::OperationPermit};
    use crate::{
        BackendError, BindMountConfig, CapabilityReport, CgroupConfig, ControlChannelConfig,
        EgressChannelConfig, IdentityMap, IsolatedChildProcess, IsolationBackend, IsolationConfig,
        IsolationStep, LandlockConfig, NamespaceIdentity, NamespacePreparation, PidNamespaceChild,
        SeccompPolicy, SpawnOutcome,
    };

    const LANDLOCK_CREATE_RULESET_VERSION: libc::c_uint = 1;
    const LANDLOCK_RULE_TYPE_PATH_BENEATH: libc::c_uint = 1;
    const LANDLOCK_ACCESS_FS_EXECUTE: u64 = 1 << 0;
    const LANDLOCK_ACCESS_FS_WRITE_FILE: u64 = 1 << 1;
    const LANDLOCK_ACCESS_FS_READ_FILE: u64 = 1 << 2;
    const LANDLOCK_ACCESS_FS_READ_DIR: u64 = 1 << 3;
    const LANDLOCK_ACCESS_FS_REMOVE_DIR: u64 = 1 << 4;
    const LANDLOCK_ACCESS_FS_REMOVE_FILE: u64 = 1 << 5;
    const LANDLOCK_ACCESS_FS_MAKE_CHAR: u64 = 1 << 6;
    const LANDLOCK_ACCESS_FS_MAKE_DIR: u64 = 1 << 7;
    const LANDLOCK_ACCESS_FS_MAKE_REG: u64 = 1 << 8;
    const LANDLOCK_ACCESS_FS_MAKE_SOCK: u64 = 1 << 9;
    const LANDLOCK_ACCESS_FS_MAKE_FIFO: u64 = 1 << 10;
    const LANDLOCK_ACCESS_FS_MAKE_BLOCK: u64 = 1 << 11;
    const LANDLOCK_ACCESS_FS_MAKE_SYM: u64 = 1 << 12;
    const LANDLOCK_ACCESS_FS_REFER: u64 = 1 << 13;
    const LANDLOCK_ACCESS_FS_TRUNCATE: u64 = 1 << 14;
    const LANDLOCK_ALL_ACCESS: u64 = LANDLOCK_ACCESS_FS_EXECUTE
        | LANDLOCK_ACCESS_FS_WRITE_FILE
        | LANDLOCK_ACCESS_FS_READ_FILE
        | LANDLOCK_ACCESS_FS_READ_DIR
        | LANDLOCK_ACCESS_FS_REMOVE_DIR
        | LANDLOCK_ACCESS_FS_REMOVE_FILE
        | LANDLOCK_ACCESS_FS_MAKE_CHAR
        | LANDLOCK_ACCESS_FS_MAKE_DIR
        | LANDLOCK_ACCESS_FS_MAKE_REG
        | LANDLOCK_ACCESS_FS_MAKE_SOCK
        | LANDLOCK_ACCESS_FS_MAKE_FIFO
        | LANDLOCK_ACCESS_FS_MAKE_BLOCK
        | LANDLOCK_ACCESS_FS_MAKE_SYM
        | LANDLOCK_ACCESS_FS_REFER
        | LANDLOCK_ACCESS_FS_TRUNCATE;
    const LANDLOCK_READ_ONLY_ACCESS: u64 =
        LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR;
    const LANDLOCK_WORKSPACE_ACCESS: u64 = LANDLOCK_READ_ONLY_ACCESS
        | LANDLOCK_ACCESS_FS_WRITE_FILE
        | LANDLOCK_ACCESS_FS_REMOVE_DIR
        | LANDLOCK_ACCESS_FS_REMOVE_FILE
        | LANDLOCK_ACCESS_FS_MAKE_DIR
        | LANDLOCK_ACCESS_FS_MAKE_REG
        | LANDLOCK_ACCESS_FS_REFER
        | LANDLOCK_ACCESS_FS_TRUNCATE;
    const SECCOMP_DATA_NR_OFFSET: u32 = 0;
    const SECCOMP_DATA_ARCH_OFFSET: u32 = 4;
    const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
    const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
    const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
    const BPF_LD: u16 = 0x00;
    const BPF_W: u16 = 0x00;
    const BPF_ABS: u16 = 0x20;
    const BPF_JMP: u16 = 0x05;
    const BPF_JEQ: u16 = 0x10;
    const BPF_JSET: u16 = 0x40;
    const BPF_K: u16 = 0x00;
    const BPF_STMT: u16 = 0x06;
    const AUDIT_ARCH_X86_64: u32 = 0xc000_003e;
    const SECCOMP_DATA_MMAP_FLAGS_OFFSET: u32 = 16 + (3 * 8);
    const MAP_SHARED_FLAG: u32 = libc::MAP_SHARED as u32;
    const CAPABILITY_VERSION_3: u32 = 0x2008_0522;
    const CURRENT_PID_NAMESPACE: &str = "/proc/self/ns/pid";
    const PID_NAMESPACE_FOR_CHILDREN: &str = "/proc/self/ns/pid_for_children";
    const FIRST_NONSTANDARD_FD: RawFd = 3;
    const NULL_DEVICE_MAJOR: libc::c_uint = 1;
    const NULL_DEVICE_MINOR: libc::c_uint = 3;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct PidNamespaceObservation {
        current: NamespaceIdentity,
        for_children: NamespaceIdentity,
    }

    #[derive(Debug)]
    struct StartupPipe {
        reader: OwnedFd,
        writer: OwnedFd,
    }

    #[derive(Debug)]
    struct PinnedWorkspaceSource {
        descriptor: OwnedFd,
        device: u64,
        inode: u64,
    }

    impl PinnedWorkspaceSource {
        fn proc_path(&self) -> PathBuf {
            PathBuf::from(format!("/proc/self/fd/{}", self.descriptor.as_raw_fd()))
        }
    }

    #[repr(C)]
    struct LandlockRulesetAttr {
        handled_access_fs: u64,
    }

    #[repr(C)]
    struct LandlockPathBeneathAttr {
        allowed_access: u64,
        parent_fd: libc::c_int,
    }

    #[repr(C)]
    struct CapabilityHeader {
        version: u32,
        pid: libc::pid_t,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct CapabilityData {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }

    #[repr(C)]
    struct SockFilter {
        code: u16,
        jump_true: u8,
        jump_false: u8,
        constant: u32,
    }

    #[repr(C)]
    struct SockFprog {
        length: u16,
        filter: *mut SockFilter,
    }

    /// Linux syscall backend. It must be used in a child process before the workload is execed.
    pub struct LinuxBackend {
        previous_cgroup: Option<PathBuf>,
        created_cgroup: Option<PathBuf>,
        rootfs_pivoted: bool,
        max_capability_index: Option<libc::c_int>,
        prepared_pid_namespaces: Option<(NamespaceIdentity, NamespaceIdentity)>,
        startup_notifier_fd: Option<RawFd>,
        expected_parent_pid: Option<libc::pid_t>,
        workspace_source: Option<PinnedWorkspaceSource>,
        child_entry_failure: Option<BackendError>,
    }

    impl LinuxBackend {
        /// Creates a backend with no process-global state changed.
        pub const fn new() -> Self {
            Self {
                previous_cgroup: None,
                created_cgroup: None,
                rootfs_pivoted: false,
                max_capability_index: None,
                prepared_pid_namespaces: None,
                startup_notifier_fd: None,
                expected_parent_pid: None,
                workspace_source: None,
                child_entry_failure: None,
            }
        }
    }

    impl Default for LinuxBackend {
        fn default() -> Self {
            Self::new()
        }
    }

    #[allow(private_bounds, private_interfaces)]
    impl IsolationBackend for LinuxBackend {
        fn detect_capabilities(&mut self, config: &IsolationConfig) -> CapabilityReport {
            let mut report = CapabilityReport {
                namespaces_available: true,
                cgroup_v2_available: false,
                landlock_abi: query_landlock_abi(),
                seccomp_available: false,
                reasons: Vec::new(),
            };
            self.max_capability_index = query_max_capability_index();
            if self.max_capability_index.is_none() {
                report
                    .reasons
                    .push("kernel capability limit could not be queried".to_owned());
            }
            if !user_namespace_is_permitted() {
                report.namespaces_available = false;
                report
                    .reasons
                    .push("user namespaces are disabled by the host".to_owned());
            }
            if !close_range_is_available() {
                report.reasons.push(
                    "close_range is unavailable; inherited descriptors cannot be closed completely"
                        .to_owned(),
                );
            }
            if !pidfd_open_is_available() {
                report.reasons.push(
                    "pidfd_open is unavailable; isolation child ownership cannot be established"
                        .to_owned(),
                );
            }
            let controllers = config.cgroup.root.join("cgroup.controllers");
            let controllers = fs::read_to_string(&controllers);
            let required_controllers = controllers.as_ref().is_ok_and(|value| {
                value
                    .split_whitespace()
                    .any(|controller| controller == "memory")
                    && value
                        .split_whitespace()
                        .any(|controller| controller == "pids")
            });
            let control_files = ["memory.max", "pids.max", "cgroup.procs"];
            let control_files = control_files
                .iter()
                .map(|name| {
                    let path = config.cgroup.root.join(name);
                    (*name, path.is_file() && access_path(&path, libc::W_OK))
                })
                .collect::<Vec<_>>();
            let controls_available = control_files.iter().all(|(_, available)| *available);
            let root_writable = access_path(&config.cgroup.root, libc::W_OK | libc::X_OK);
            report.cgroup_v2_available =
                required_controllers && root_writable && controls_available;
            if !report.cgroup_v2_available {
                let controller_status = controllers.as_ref().map_or_else(
                    |error| format!("unreadable ({error})"),
                    |value| value.trim().to_owned(),
                );
                let control_status = control_files
                    .iter()
                    .map(|(name, available)| format!("{name}={available}"))
                    .collect::<Vec<_>>()
                    .join(", ");
                let kernel_cgroup_status = fs::read_to_string("/proc/cgroups").map_or_else(
                    |error| format!("unreadable ({error})"),
                    |value| value.trim().replace('\n', "; "),
                );
                report
                    .reasons
                    .push(format!(
                        "configured cgroup v2 root or required control files are absent or not writable: controllers={controller_status:?}, root_writable={root_writable}, controls={control_status}, kernel_cgroups={kernel_cgroup_status:?}"
                    ));
            }
            report.seccomp_available = seccomp_is_available();
            if !report.seccomp_available {
                report
                    .reasons
                    .push("seccomp filter mode is unavailable".to_owned());
            }
            match report.landlock_abi {
                Some(abi) if abi >= config.landlock.required_abi => {}
                Some(abi) => report.reasons.push(format!(
                    "Landlock ABI {abi} is below required ABI {}",
                    config.landlock.required_abi
                )),
                None => report
                    .reasons
                    .push("Landlock ABI could not be queried".to_owned()),
            }
            report
        }

        fn prepare_namespaces(
            &mut self,
            _permit: OperationPermit,
            _config: &IsolationConfig,
        ) -> Result<NamespacePreparation, BackendError> {
            if self.prepared_pid_namespaces.is_some() {
                return Err(BackendError::new(
                    IsolationStep::Namespaces,
                    "namespace preparation already has an unconsumed child handoff",
                    None,
                ));
            }
            let preparation = prepare_namespaces(IsolationStep::Namespaces)?;
            self.prepared_pid_namespaces = Some((preparation.parent(), preparation.child()));
            Ok(preparation)
        }

        fn spawn_isolated<T, F>(
            &mut self,
            _permit: OperationPermit,
            preparation: NamespacePreparation,
            child_entry: F,
        ) -> Result<SpawnOutcome<T>, BackendError>
        where
            F: FnOnce(&mut Self, NamespacePreparation, ChildStartupNotifier) -> T,
        {
            self.spawn_isolated_impl(preparation, child_entry)
        }

        fn verify_pid_namespace_child(
            &mut self,
            _permit: OperationPermit,
            preparation: NamespacePreparation,
        ) -> Result<PidNamespaceChild, BackendError> {
            if let Some(error) = self.child_entry_failure.take() {
                return Err(error);
            }
            verify_pid_namespace_child_entry(IsolationStep::Namespaces, preparation)
        }

        fn apply_step(
            &mut self,
            _permit: OperationPermit,
            step: IsolationStep,
            config: &IsolationConfig,
        ) -> Result<(), BackendError> {
            match step {
                IsolationStep::Namespaces => Err(BackendError::new(
                    step,
                    "namespace setup requires the explicit prepare and child handoff API",
                    None,
                )),
                IsolationStep::IdentityMap => self.install_identity_map(step, config.identity),
                IsolationStep::CgroupV2 => self.configure_cgroup(step, &config.cgroup),
                IsolationStep::ReadOnlyRootfs => self.mount_rootfs(step, config),
                IsolationStep::Workspace => self.mount_workspace(step, &config.workspace),
                IsolationStep::LimitedTmpfs => {
                    mount_tmpfs(step, &config.tmpfs.target, config.tmpfs.size_bytes)
                }
                IsolationStep::MaskProc => mask_mount(step, Path::new("/proc")),
                IsolationStep::MaskDevices => mask_mount(step, Path::new("/dev")),
                IsolationStep::CloseInheritedFileDescriptors => {
                    let notifier_fd = self.startup_notifier_fd.ok_or_else(|| {
                        BackendError::new(
                            step,
                            "child startup notifier was not registered before descriptor closure",
                            None,
                        )
                    })?;
                    if let Some(control_channel) = config.control_channel {
                        validate_control_channel(step, control_channel)?;
                    }
                    if let Some(egress_channel) = config.egress_channel {
                        validate_egress_channel(step, egress_channel)?;
                    }
                    close_inherited_fds(
                        step,
                        notifier_fd,
                        config.control_channel,
                        config.egress_channel,
                    )
                }
                IsolationStep::Landlock => install_landlock(step, &config.landlock),
                IsolationStep::DropCapabilities => self.drop_capabilities(step),
                IsolationStep::NoNewPrivs => set_no_new_privs(step),
                IsolationStep::Seccomp => {
                    self.verify_parent_lifecycle(step)?;
                    install_seccomp(step, &config.seccomp)
                }
            }
        }

        fn rollback_step(
            &mut self,
            _permit: OperationPermit,
            step: IsolationStep,
            config: &IsolationConfig,
        ) -> Result<(), BackendError> {
            match step {
                IsolationStep::CgroupV2 => self.rollback_cgroup(step),
                IsolationStep::Workspace => unmount_path(step, &config.workspace.target),
                IsolationStep::LimitedTmpfs => unmount_path(step, &config.tmpfs.target),
                IsolationStep::MaskProc => unmount_path(step, Path::new("/proc")),
                IsolationStep::MaskDevices => unmount_path(step, Path::new("/dev")),
                IsolationStep::ReadOnlyRootfs if self.rootfs_pivoted => Err(BackendError::new(
                    step,
                    "root pivot is irreversible; terminate the child instead of retrying",
                    None,
                )),
                IsolationStep::Namespaces
                | IsolationStep::IdentityMap
                | IsolationStep::ReadOnlyRootfs
                | IsolationStep::CloseInheritedFileDescriptors
                | IsolationStep::Landlock
                | IsolationStep::DropCapabilities
                | IsolationStep::NoNewPrivs
                | IsolationStep::Seccomp => Err(BackendError::new(
                    step,
                    "kernel state cannot be safely rolled back in the current process",
                    None,
                )),
            }
        }
    }

    impl LinuxBackend {
        fn spawn_isolated_impl<T, F>(
            &mut self,
            preparation: NamespacePreparation,
            child_entry: F,
        ) -> Result<SpawnOutcome<T>, BackendError>
        where
            F: FnOnce(&mut Self, NamespacePreparation, ChildStartupNotifier) -> T,
        {
            self.consume_prepared_namespace_handoff(&preparation)?;
            let previous_signal_mask = block_all_signals(IsolationStep::Namespaces)?;
            let fork_resources = (|| {
                if !process_is_single_threaded(IsolationStep::Namespaces)? {
                    return Err(BackendError::new(
                        IsolationStep::Namespaces,
                        "PID namespace handoff requires a single-threaded launcher process",
                        None,
                    ));
                }
                Ok::<_, BackendError>((
                    create_startup_pipe(IsolationStep::Namespaces)?,
                    open_null_device(IsolationStep::Namespaces)?,
                ))
            })();
            let (startup_pipe, null_device) = match fork_resources {
                Ok(resources) => resources,
                Err(error) => {
                    if let Err(restore_error) =
                        restore_signal_mask(IsolationStep::Namespaces, &previous_signal_mask)
                    {
                        return Err(combine_errors(&error, &restore_error));
                    }
                    return Err(error);
                }
            };
            let child_namespace = preparation.child();
            let launcher_pid = current_pid();
            // SAFETY: Namespace preparation can succeed only for a single-threaded
            // launcher. Signals are blocked across fork so inherited handlers
            // cannot execute before the child replaces their process-global state.
            let fork_result = unsafe { libc::fork() };
            match fork_result {
                -1 => {
                    let fork_error = last_error(
                        IsolationStep::Namespaces,
                        "fork prepared PID namespace child",
                    );
                    if let Err(restore_error) =
                        restore_signal_mask(IsolationStep::Namespaces, &previous_signal_mask)
                    {
                        return Err(combine_errors(&fork_error, &restore_error));
                    }
                    Err(fork_error)
                }
                0 => {
                    drop(startup_pipe.reader);
                    let notifier_fd = startup_pipe.writer.as_raw_fd();
                    self.expected_parent_pid = Some(launcher_pid);
                    self.startup_notifier_fd = Some(notifier_fd);
                    let lifecycle_result = configure_child_lifecycle(
                        IsolationStep::Namespaces,
                        launcher_pid,
                        notifier_fd,
                    );
                    let descriptor_result = install_sanitized_standard_descriptors(
                        IsolationStep::Namespaces,
                        &null_device,
                    );
                    drop(null_device);
                    self.child_entry_failure = combine_results(lifecycle_result, descriptor_result);
                    let notifier = ChildStartupNotifier::from_fd(startup_pipe.writer);
                    // This process is PID 1 in the prepared namespace. The fixed
                    // seccomp contract denies every process-creation syscall, so
                    // it cannot acquire descendants that need a reaper. Its
                    // ancestor launcher owns termination and reap through pidfd.
                    Ok(SpawnOutcome::Child(child_entry(
                        self,
                        preparation,
                        notifier,
                    )))
                }
                child_pid => {
                    let raw_child_pid = child_pid;
                    self.expected_parent_pid = None;
                    self.startup_notifier_fd = None;
                    drop(startup_pipe.writer);
                    drop(null_device);
                    if let Err(error) =
                        restore_signal_mask(IsolationStep::Namespaces, &previous_signal_mask)
                    {
                        return Err(cleanup_failed_spawn(child_pid, error));
                    }
                    let child_pid = u32::try_from(child_pid)
                        .ok()
                        .and_then(NonZeroU32::new)
                        .ok_or_else(|| {
                            cleanup_failed_spawn(
                                raw_child_pid,
                                BackendError::new(
                                    IsolationStep::Namespaces,
                                    "fork returned an invalid child PID",
                                    None,
                                ),
                            )
                        })?;
                    let pidfd = open_pidfd(IsolationStep::Namespaces, child_pid)
                        .map_err(|error| cleanup_failed_spawn(raw_child_pid, error))?;
                    Ok(SpawnOutcome::Parent(IsolatedChildProcess::from_spawn(
                        child_pid,
                        child_namespace,
                        pidfd,
                        startup_pipe.reader,
                    )))
                }
            }
        }

        fn consume_prepared_namespace_handoff(
            &mut self,
            preparation: &NamespacePreparation,
        ) -> Result<(), BackendError> {
            let expected_namespaces = self.prepared_pid_namespaces.take().ok_or_else(|| {
                BackendError::new(
                    IsolationStep::Namespaces,
                    "PID namespace handoff has no matching backend preparation",
                    None,
                )
            })?;
            if expected_namespaces != (preparation.parent(), preparation.child()) {
                return Err(BackendError::new(
                    IsolationStep::Namespaces,
                    "PID namespace handoff token does not match backend preparation",
                    None,
                ));
            }
            Ok(())
        }

        fn install_identity_map(
            &self,
            step: IsolationStep,
            identity: IdentityMap,
        ) -> Result<(), BackendError> {
            install_identity_map(step, identity)?;
            // Linux clears PDEATHSIG when effective or filesystem credentials
            // change. Re-arm only after both mapped credentials are final and
            // reject a launcher that vanished during the cleared interval.
            self.verify_parent_lifecycle(step)
        }

        fn verify_parent_lifecycle(&self, step: IsolationStep) -> Result<(), BackendError> {
            let expected_parent_pid = self.expected_parent_pid.ok_or_else(|| {
                BackendError::new(
                    step,
                    "expected launcher PID was not retained in the isolation child",
                    None,
                )
            })?;
            let notifier_fd = self.startup_notifier_fd.ok_or_else(|| {
                BackendError::new(
                    step,
                    "startup notifier was not retained for parent-liveness verification",
                    None,
                )
            })?;
            arm_and_verify_parent_lifecycle(step, expected_parent_pid, notifier_fd)
        }

        fn configure_cgroup(
            &mut self,
            step: IsolationStep,
            config: &CgroupConfig,
        ) -> Result<(), BackendError> {
            self.previous_cgroup = Some(current_cgroup_path(step, &config.root)?);
            let path = config.root.join(&config.name);
            fs::create_dir(&path).map_err(|error| io_error(step, "create cgroup", &error))?;
            self.created_cgroup = Some(path.clone());
            let result = (|| {
                write_text(
                    step,
                    &path.join("memory.max"),
                    &config.memory_max_bytes.to_string(),
                )?;
                write_text(step, &path.join("pids.max"), &config.pids_max.to_string())?;
                write_text(step, &path.join("cgroup.procs"), &current_pid().to_string())?;
                Ok::<(), BackendError>(())
            })();
            if let Err(error) = result {
                if let Err(cleanup_error) = fs::remove_dir(&path) {
                    return Err(BackendError::new(
                        step,
                        format!(
                            "{error}; failed to remove partially configured cgroup: {cleanup_error}"
                        ),
                        cleanup_error.raw_os_error(),
                    ));
                }
                self.created_cgroup = None;
                self.previous_cgroup = None;
                return Err(error);
            }
            Ok(())
        }

        fn rollback_cgroup(&mut self, step: IsolationStep) -> Result<(), BackendError> {
            let previous = self.previous_cgroup.as_ref().ok_or_else(|| {
                BackendError::new(step, "previous cgroup membership was not recorded", None)
            })?;
            let created = self.created_cgroup.as_ref().ok_or_else(|| {
                BackendError::new(step, "created cgroup path was not recorded", None)
            })?;
            write_text(
                step,
                &previous.join("cgroup.procs"),
                &current_pid().to_string(),
            )?;
            fs::remove_dir(created).map_err(|error| io_error(step, "remove cgroup", &error))?;
            self.previous_cgroup = None;
            self.created_cgroup = None;
            Ok(())
        }

        fn mount_rootfs(
            &mut self,
            step: IsolationStep,
            config: &IsolationConfig,
        ) -> Result<(), BackendError> {
            let rootfs = &config.rootfs;
            make_mounts_private(step)?;
            let workspace_source = pin_workspace_source(step, &config.workspace.source)?;
            let setup_result = (|| {
                mount_call(
                    step,
                    Some(&rootfs.source),
                    &rootfs.mount_target,
                    None,
                    libc::MS_BIND,
                    None,
                )?;
                fs::create_dir_all(&rootfs.old_root)
                    .map_err(|error| io_error(step, "create old-root directory", &error))?;
                create_rootfs_mount_targets(step, config)?;
                stage_workspace_mount(
                    step,
                    &rootfs.mount_target,
                    &config.workspace.target,
                    &workspace_source,
                )?;
                Ok::<(), BackendError>(())
            })();
            if let Err(error) = setup_result {
                if let Err(cleanup_error) = unmount_path(step, &rootfs.mount_target) {
                    return Err(BackendError::new(
                        step,
                        format!(
                            "{error}; failed to unmount partial rootfs staging mount: {}",
                            cleanup_error.message
                        ),
                        cleanup_error.errno,
                    ));
                }
                return Err(error);
            }
            let result = mount_call(
                step,
                None,
                &rootfs.mount_target,
                None,
                libc::MS_BIND
                    | libc::MS_REMOUNT
                    | libc::MS_RDONLY
                    | libc::MS_NOSUID
                    | libc::MS_NODEV,
                None,
            );
            if result.is_err() {
                if let Err(cleanup_error) = unmount_path(step, &rootfs.mount_target) {
                    return Err(BackendError::new(
                        step,
                        format!(
                            "rootfs remount failed; failed to unmount partial rootfs staging mount: {}",
                            cleanup_error.message
                        ),
                        cleanup_error.errno,
                    ));
                }
                return result;
            }
            let result = (|| {
                pivot_root(step, &rootfs.mount_target, &rootfs.old_root)?;
                self.rootfs_pivoted = true;
                change_directory(step, Path::new("/"))?;
                let old_root_after_pivot =
                    old_root_after_pivot(&rootfs.mount_target, &rootfs.old_root).ok_or_else(
                        || BackendError::new(step, "old-root path was not beneath rootfs", None),
                    )?;
                unmount_path(step, &old_root_after_pivot)?;
                fs::remove_dir(&old_root_after_pivot).map_err(|error| {
                    io_error(step, "remove detached old-root directory", &error)
                })?;
                Ok::<(), BackendError>(())
            })();
            if let Err(error) = &result
                && self.rootfs_pivoted
            {
                return Err(BackendError::new(
                    step,
                    format!(
                        "root pivot completed but rootfs finalization failed: {}; terminate the child",
                        error.message
                    ),
                    error.errno,
                ));
            }
            if result.is_ok() {
                self.workspace_source = Some(workspace_source);
            }
            result
        }

        fn mount_workspace(
            &mut self,
            step: IsolationStep,
            config: &BindMountConfig,
        ) -> Result<(), BackendError> {
            let source = self.workspace_source.as_ref().ok_or_else(|| {
                BackendError::new(
                    step,
                    "workspace source was not pinned before rootfs pivot",
                    None,
                )
            })?;
            verify_pinned_workspace_mount(step, source, &config.target)?;
            let result = mount_call(
                step,
                None,
                &config.target,
                None,
                libc::MS_BIND
                    | libc::MS_REMOUNT
                    | libc::MS_NOSUID
                    | libc::MS_NODEV
                    | libc::MS_NOEXEC,
                None,
            );
            if result.is_err()
                && let Err(cleanup_error) = unmount_path(step, &config.target)
            {
                return Err(BackendError::new(
                    step,
                    format!(
                        "workspace remount failed; failed to unmount partial workspace mount: {}",
                        cleanup_error.message
                    ),
                    cleanup_error.errno,
                ));
            }
            if result.is_ok() {
                self.workspace_source = None;
            }
            result
        }

        fn drop_capabilities(&self, step: IsolationStep) -> Result<(), BackendError> {
            let max_capability_index = self.max_capability_index.ok_or_else(|| {
                BackendError::new(step, "kernel capability limit was not detected", None)
            })?;
            drop_capabilities(step, max_capability_index)
        }
    }

    fn prepare_namespaces(step: IsolationStep) -> Result<NamespacePreparation, BackendError> {
        let before = observe_pid_namespaces(step)?;
        let flags = libc::CLONE_NEWUSER
            | libc::CLONE_NEWNS
            | libc::CLONE_NEWPID
            | libc::CLONE_NEWNET
            | libc::CLONE_NEWIPC
            | libc::CLONE_NEWUTS
            | libc::CLONE_NEWCGROUP;
        // SAFETY: `flags` is a fixed allowlisted set and no pointer crosses the FFI boundary.
        let result = unsafe { libc::unshare(flags) };
        if result == -1 {
            return Err(last_error(step, "unshare required namespaces"));
        }

        let prepared = observe_pid_namespaces(step)?;
        if prepared.current != before.current {
            return Err(BackendError::new(
                step,
                "PID namespace preparation unexpectedly moved the calling process; terminate it",
                None,
            ));
        }
        if prepared.for_children == prepared.current {
            return Err(BackendError::new(
                step,
                "PID namespace preparation did not create a distinct namespace for the next child; terminate the process",
                None,
            ));
        }

        Ok(NamespacePreparation::attest(
            prepared.current,
            prepared.for_children,
        ))
    }

    // Consuming the preparation token prevents a caller from verifying it twice.
    #[allow(clippy::needless_pass_by_value)]
    fn verify_pid_namespace_child_entry(
        step: IsolationStep,
        preparation: NamespacePreparation,
    ) -> Result<PidNamespaceChild, BackendError> {
        validate_pid_namespace_child_entry(step, &preparation, observe_pid_namespaces(step)?)?;
        let child_namespace = preparation.child();
        Ok(PidNamespaceChild::attest(child_namespace))
    }

    fn validate_pid_namespace_child_entry(
        step: IsolationStep,
        preparation: &NamespacePreparation,
        observed: PidNamespaceObservation,
    ) -> Result<(), BackendError> {
        if observed.current == preparation.parent() {
            return Err(BackendError::new(
                step,
                "PID namespace is prepared only for the next child, but no child handoff occurred; refusing to report namespace isolation complete",
                None,
            ));
        }
        if observed.current != preparation.child() {
            return Err(BackendError::new(
                step,
                "workload child entered an unexpected PID namespace; refusing to report namespace isolation complete",
                None,
            ));
        }
        if observed.for_children != observed.current {
            return Err(BackendError::new(
                step,
                "workload child has a different pending PID namespace for descendants; refusing to report namespace isolation complete",
                None,
            ));
        }
        Ok(())
    }

    fn make_mounts_private(step: IsolationStep) -> Result<(), BackendError> {
        mount_call(
            step,
            None,
            Path::new("/"),
            None,
            libc::MS_REC | libc::MS_PRIVATE,
            None,
        )
    }

    fn install_identity_map(
        step: IsolationStep,
        identity: IdentityMap,
    ) -> Result<(), BackendError> {
        write_text(step, Path::new("/proc/self/setgroups"), "deny")?;
        write_text(
            step,
            Path::new("/proc/self/uid_map"),
            &format!("0 {} 1\n", identity.host_uid),
        )?;
        write_text(
            step,
            Path::new("/proc/self/gid_map"),
            &format!("0 {} 1\n", identity.host_gid),
        )?;
        // SAFETY: The arguments are scalar IDs in the newly-created user namespace.
        let gid_result = unsafe { libc::setresgid(0, 0, 0) };
        if gid_result == -1 {
            return Err(last_error(step, "set mapped GID"));
        }
        // SAFETY: The arguments are scalar IDs in the newly-created user namespace.
        let uid_result = unsafe { libc::setresuid(0, 0, 0) };
        if uid_result == -1 {
            return Err(last_error(step, "set mapped UID"));
        }
        Ok(())
    }

    fn pin_workspace_source(
        step: IsolationStep,
        source: &Path,
    ) -> Result<PinnedWorkspaceSource, BackendError> {
        let source = c_path(step, source)?;
        // O_PATH pins the exact directory object without granting a data IO
        // channel. O_NOFOLLOW prevents a final symlink from changing which host
        // tree is exposed after validation.
        // SAFETY: the path is NUL-terminated and successful open returns one fd.
        let descriptor = unsafe {
            libc::open(
                source.as_ptr(),
                libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        if descriptor == -1 {
            return Err(last_error(step, "pin workspace source before rootfs pivot"));
        }
        // SAFETY: successful open returned one owned descriptor.
        let descriptor = unsafe { OwnedFd::from_raw_fd(descriptor) };
        let identity = descriptor_identity(step, &descriptor, "inspect pinned workspace source")?;
        Ok(PinnedWorkspaceSource {
            descriptor,
            device: identity.0,
            inode: identity.1,
        })
    }

    fn stage_workspace_mount(
        step: IsolationStep,
        rootfs_target: &Path,
        workspace_target: &Path,
        source: &PinnedWorkspaceSource,
    ) -> Result<(), BackendError> {
        let workspace_target = rootfs_path(rootfs_target, workspace_target).ok_or_else(|| {
            BackendError::new(step, "workspace target escaped the staged rootfs", None)
        })?;
        mount_call(
            step,
            Some(&source.proc_path()),
            &workspace_target,
            None,
            libc::MS_BIND,
            None,
        )
    }

    fn create_rootfs_mount_targets(
        step: IsolationStep,
        config: &IsolationConfig,
    ) -> Result<(), BackendError> {
        for target in [
            &config.workspace.target,
            &config.tmpfs.target,
            Path::new("/proc"),
            Path::new("/dev"),
        ] {
            let target = rootfs_path(&config.rootfs.mount_target, target).ok_or_else(|| {
                BackendError::new(step, "mount target escaped the staged rootfs", None)
            })?;
            fs::create_dir_all(target)
                .map_err(|error| io_error(step, "create rootfs mount directory", &error))?;
        }
        Ok(())
    }

    fn verify_pinned_workspace_mount(
        step: IsolationStep,
        source: &PinnedWorkspaceSource,
        target: &Path,
    ) -> Result<(), BackendError> {
        let current_source = descriptor_identity(
            step,
            &source.descriptor,
            "reinspect pinned workspace source",
        )?;
        if current_source != (source.device, source.inode) {
            return Err(BackendError::new(
                step,
                "pinned workspace descriptor identity changed before finalization",
                None,
            ));
        }
        let target_metadata = fs::metadata(target)
            .map_err(|error| io_error(step, "inspect staged workspace mount", &error))?;
        if (target_metadata.dev(), target_metadata.ino()) != current_source {
            return Err(BackendError::new(
                step,
                "workspace mount did not resolve to the source pinned before rootfs pivot",
                None,
            ));
        }
        Ok(())
    }

    fn descriptor_identity(
        step: IsolationStep,
        descriptor: &OwnedFd,
        action: &'static str,
    ) -> Result<(u64, u64), BackendError> {
        let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
        // SAFETY: metadata is writable and the descriptor remains live.
        if unsafe { libc::fstat(descriptor.as_raw_fd(), metadata.as_mut_ptr()) } == -1 {
            return Err(last_error(step, action));
        }
        // SAFETY: successful fstat initialized the complete structure.
        let metadata = unsafe { metadata.assume_init() };
        Ok((metadata.st_dev, metadata.st_ino))
    }

    fn mount_tmpfs(
        step: IsolationStep,
        target: &Path,
        size_bytes: u64,
    ) -> Result<(), BackendError> {
        let data = CString::new(format!("size={size_bytes}"))
            .map_err(|_| BackendError::new(step, "tmpfs size contains a NUL byte", None))?;
        mount_call(
            step,
            Some(Path::new("tmpfs")),
            target,
            Some(Path::new("tmpfs")),
            libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
            Some(&data),
        )
    }

    fn mask_mount(step: IsolationStep, target: &Path) -> Result<(), BackendError> {
        let data = CString::new("size=4096")
            .map_err(|_| BackendError::new(step, "mask size contains a NUL byte", None))?;
        mount_call(
            step,
            Some(Path::new("tmpfs")),
            target,
            Some(Path::new("tmpfs")),
            libc::MS_RDONLY | libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
            Some(&data),
        )
    }

    fn create_startup_pipe(step: IsolationStep) -> Result<StartupPipe, BackendError> {
        let mut descriptors = [-1; 2];
        // SAFETY: `descriptors` contains storage for exactly two returned fds.
        let result = unsafe { libc::pipe2(descriptors.as_mut_ptr(), libc::O_CLOEXEC) };
        if result == -1 {
            return Err(last_error(step, "create close-on-exec child startup pipe"));
        }
        // SAFETY: successful `pipe2` returns ownership of both descriptors.
        let reader = unsafe { OwnedFd::from_raw_fd(descriptors[0]) };
        // SAFETY: successful `pipe2` returns ownership of both descriptors.
        let writer = unsafe { OwnedFd::from_raw_fd(descriptors[1]) };
        Ok(StartupPipe {
            reader: ensure_nonstandard_fd(step, reader, "normalize startup pipe reader")?,
            writer: ensure_nonstandard_fd(step, writer, "normalize startup pipe writer")?,
        })
    }

    fn open_null_device(step: IsolationStep) -> Result<OwnedFd, BackendError> {
        let path = c"/dev/null";
        // SAFETY: the path is a static C string and the flags create an owned fd.
        let descriptor = unsafe {
            libc::open(
                path.as_ptr(),
                libc::O_RDWR | libc::O_CLOEXEC | libc::O_NOCTTY | libc::O_NOFOLLOW,
            )
        };
        if descriptor == -1 {
            return Err(last_error(
                step,
                "open trusted /dev/null for standard descriptors",
            ));
        }
        // SAFETY: successful `open` returns one owned descriptor.
        let descriptor = unsafe { OwnedFd::from_raw_fd(descriptor) };
        let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
        // SAFETY: `metadata` is writable and the owned descriptor remains live.
        let result = unsafe { libc::fstat(descriptor.as_raw_fd(), metadata.as_mut_ptr()) };
        if result == -1 {
            return Err(last_error(step, "inspect /dev/null device identity"));
        }
        // SAFETY: successful `fstat` initialized the complete structure.
        let metadata = unsafe { metadata.assume_init() };
        if metadata.st_mode & libc::S_IFMT != libc::S_IFCHR
            || libc::major(metadata.st_rdev) != NULL_DEVICE_MAJOR
            || libc::minor(metadata.st_rdev) != NULL_DEVICE_MINOR
        {
            return Err(BackendError::new(
                step,
                "/dev/null was not the kernel null character device (major 1, minor 3)",
                None,
            ));
        }
        ensure_nonstandard_fd(step, descriptor, "normalize /dev/null descriptor")
    }

    fn ensure_nonstandard_fd(
        step: IsolationStep,
        descriptor: OwnedFd,
        action: &'static str,
    ) -> Result<OwnedFd, BackendError> {
        if descriptor.as_raw_fd() >= FIRST_NONSTANDARD_FD {
            return Ok(descriptor);
        }
        // SAFETY: `descriptor` is live and F_DUPFD_CLOEXEC returns a new owned fd.
        let duplicated = unsafe {
            libc::fcntl(
                descriptor.as_raw_fd(),
                libc::F_DUPFD_CLOEXEC,
                FIRST_NONSTANDARD_FD,
            )
        };
        if duplicated == -1 {
            return Err(last_error(step, action));
        }
        // SAFETY: successful F_DUPFD_CLOEXEC transfers ownership of the new fd.
        Ok(unsafe { OwnedFd::from_raw_fd(duplicated) })
    }

    fn install_sanitized_standard_descriptors(
        step: IsolationStep,
        null_device: &OwnedFd,
    ) -> Result<(), BackendError> {
        for target in 0..FIRST_NONSTANDARD_FD {
            loop {
                // CLOEXEC prevents even the harmless placeholder from becoming
                // an implicit workload channel after its eventual exec.
                // SAFETY: the source is live, differs from every target, and
                // dup3 atomically replaces each inherited standard descriptor.
                let result =
                    unsafe { libc::dup3(null_device.as_raw_fd(), target, libc::O_CLOEXEC) };
                if result == target {
                    break;
                }
                if result == -1 && errno() == libc::EINTR {
                    continue;
                }
                return Err(last_error(
                    step,
                    "replace inherited standard descriptor with /dev/null",
                ));
            }
        }
        Ok(())
    }

    fn block_all_signals(step: IsolationStep) -> Result<libc::sigset_t, BackendError> {
        // SAFETY: sigset_t is a plain C value initialized by sigfillset.
        let mut all_signals = unsafe { std::mem::zeroed::<libc::sigset_t>() };
        // SAFETY: `all_signals` points to writable sigset storage.
        if unsafe { libc::sigfillset(&raw mut all_signals) } == -1 {
            return Err(last_error(step, "construct the fork signal mask"));
        }
        // SAFETY: the previous mask points to writable storage and this process
        // has already been proven single-threaded.
        let mut previous = unsafe { std::mem::zeroed::<libc::sigset_t>() };
        let result = unsafe {
            libc::pthread_sigmask(libc::SIG_SETMASK, &raw const all_signals, &raw mut previous)
        };
        if result != 0 {
            return Err(BackendError::new(
                step,
                "block signals across PID namespace fork",
                Some(result),
            ));
        }
        Ok(previous)
    }

    fn restore_signal_mask(
        step: IsolationStep,
        previous: &libc::sigset_t,
    ) -> Result<(), BackendError> {
        // SAFETY: `previous` was initialized by pthread_sigmask in this thread.
        let result =
            unsafe { libc::pthread_sigmask(libc::SIG_SETMASK, previous, std::ptr::null_mut()) };
        if result == 0 {
            Ok(())
        } else {
            Err(BackendError::new(
                step,
                "restore launcher signal mask after PID namespace fork",
                Some(result),
            ))
        }
    }

    fn configure_child_lifecycle(
        step: IsolationStep,
        expected_parent_pid: libc::pid_t,
        notifier_fd: RawFd,
    ) -> Result<(), BackendError> {
        // If the launcher disappears before readiness, either PDEATHSIG or the
        // startup pipe's default SIGPIPE disposition terminates this child.
        arm_parent_death_signal(step)?;
        reset_signal_dispositions(step)?;
        // SAFETY: sigset_t is initialized before it is installed.
        let mut empty_mask = unsafe { std::mem::zeroed::<libc::sigset_t>() };
        // SAFETY: `empty_mask` points to writable sigset storage.
        if unsafe { libc::sigemptyset(&raw mut empty_mask) } == -1 {
            return Err(last_error(step, "construct empty child signal mask"));
        }
        // SAFETY: the child is single-threaded and the mask is initialized.
        let result = unsafe {
            libc::pthread_sigmask(
                libc::SIG_SETMASK,
                &raw const empty_mask,
                std::ptr::null_mut(),
            )
        };
        if result != 0 {
            return Err(BackendError::new(
                step,
                "clear inherited child signal mask",
                Some(result),
            ));
        }
        arm_and_verify_parent_lifecycle(step, expected_parent_pid, notifier_fd)
    }

    fn arm_and_verify_parent_lifecycle(
        step: IsolationStep,
        expected_parent_pid: libc::pid_t,
        notifier_fd: RawFd,
    ) -> Result<(), BackendError> {
        arm_parent_death_signal(step)?;
        let mut parent_death_signal = 0;
        // SAFETY: PR_GET_PDEATHSIG writes one scalar signal number.
        if unsafe {
            libc::prctl(
                libc::PR_GET_PDEATHSIG,
                &raw mut parent_death_signal,
                0,
                0,
                0,
            )
        } == -1
        {
            return Err(last_error(step, "verify child parent-death termination"));
        }
        if parent_death_signal != libc::SIGKILL {
            return Err(BackendError::new(
                step,
                "parent-death signal was not SIGKILL after lifecycle re-arm",
                None,
            ));
        }

        // A PID-namespace init sees an out-of-namespace parent as PID zero. If
        // the parent is visible, require its exact pre-fork PID; in both cases
        // the one-owner startup pipe detects death in the PR_SET race window.
        // SAFETY: getppid has no pointer arguments.
        let observed_parent_pid = unsafe { libc::getppid() };
        if observed_parent_pid != 0 && observed_parent_pid != expected_parent_pid {
            return Err(BackendError::new(
                step,
                "isolation child was reparented before lifecycle verification",
                None,
            ));
        }
        verify_startup_reader_alive(step, notifier_fd)
    }

    fn arm_parent_death_signal(step: IsolationStep) -> Result<(), BackendError> {
        // SAFETY: PR_SET_PDEATHSIG accepts a scalar signal number.
        if unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) } == -1 {
            Err(last_error(step, "arm child parent-death termination"))
        } else {
            Ok(())
        }
    }

    fn verify_startup_reader_alive(
        step: IsolationStep,
        notifier_fd: RawFd,
    ) -> Result<(), BackendError> {
        let mut descriptor = libc::pollfd {
            fd: notifier_fd,
            events: libc::POLLOUT,
            revents: 0,
        };
        loop {
            // SAFETY: descriptor points to one initialized pollfd and timeout
            // zero makes this a nonblocking liveness observation.
            let result = unsafe { libc::poll(&raw mut descriptor, 1, 0) };
            if result == -1 && errno() == libc::EINTR {
                continue;
            }
            if result == -1 {
                return Err(last_error(step, "poll child startup notifier"));
            }
            let terminal = libc::POLLERR | libc::POLLHUP | libc::POLLNVAL;
            if result == 0
                || descriptor.revents & terminal != 0
                || descriptor.revents & libc::POLLOUT == 0
            {
                return Err(BackendError::new(
                    step,
                    "launcher closed the child startup channel before readiness",
                    None,
                ));
            }
            return Ok(());
        }
    }

    fn reset_signal_dispositions(step: IsolationStep) -> Result<(), BackendError> {
        let first_glibc_reserved_signal = libc::SIGRTMIN() - 2;
        for signal in 1..=libc::SIGRTMAX() {
            if signal == libc::SIGKILL || signal == libc::SIGSTOP {
                continue;
            }
            // SAFETY: zero is a valid base for sigaction before its mask is initialized.
            let mut action = unsafe { std::mem::zeroed::<libc::sigaction>() };
            action.sa_sigaction = libc::SIG_DFL;
            // SAFETY: the action mask points to writable sigset storage.
            if unsafe { libc::sigemptyset(&raw mut action.sa_mask) } == -1 {
                return Err(last_error(
                    step,
                    "construct default child signal disposition",
                ));
            }
            // SAFETY: `action` is initialized and the signal range is kernel-defined.
            let result =
                unsafe { libc::sigaction(signal, &raw const action, std::ptr::null_mut()) };
            if result == 0 {
                continue;
            }
            let error = errno();
            if error == libc::EINVAL
                && (signal == first_glibc_reserved_signal
                    || signal == first_glibc_reserved_signal + 1)
            {
                continue;
            }
            return Err(BackendError::new(
                step,
                format!("reset inherited disposition for signal {signal}"),
                Some(error),
            ));
        }
        Ok(())
    }

    fn validate_control_channel(
        step: IsolationStep,
        control_channel: ControlChannelConfig,
    ) -> Result<(), BackendError> {
        let descriptor = control_channel.fd();
        if descriptor < FIRST_NONSTANDARD_FD {
            return Err(BackendError::new(
                step,
                "supervisor control channel overlapped a standard descriptor",
                None,
            ));
        }
        if descriptor_has_cloexec(step, descriptor)? {
            return Err(BackendError::new(
                step,
                "supervisor control channel was close-on-exec",
                None,
            ));
        }
        let mut socket_type = 0_i32;
        let mut socket_type_length = libc::socklen_t::try_from(std::mem::size_of_val(&socket_type))
            .map_err(|_| {
                BackendError::new(step, "socket type length did not fit socklen_t", None)
            })?;
        // SAFETY: the descriptor is supplied by the trusted launcher; the output pointer and
        // length point to writable storage of exactly the advertised size.
        let socket_type_result = unsafe {
            libc::getsockopt(
                descriptor,
                libc::SOL_SOCKET,
                libc::SO_TYPE,
                (&raw mut socket_type).cast::<libc::c_void>(),
                &raw mut socket_type_length,
            )
        };
        if socket_type_result == -1 {
            return Err(last_error(step, "inspect supervisor control socket type"));
        }
        if socket_type != libc::SOCK_SEQPACKET {
            return Err(BackendError::new(
                step,
                "supervisor control channel was not a Unix seqpacket socket",
                None,
            ));
        }

        let mut peer: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
        let mut peer_length =
            libc::socklen_t::try_from(std::mem::size_of_val(&peer)).map_err(|_| {
                BackendError::new(step, "socket peer length did not fit socklen_t", None)
            })?;
        // SAFETY: `peer` and `peer_length` are writable buffers accepted by getpeername.
        let peer_result = unsafe {
            libc::getpeername(
                descriptor,
                (&raw mut peer).cast::<libc::sockaddr>(),
                &raw mut peer_length,
            )
        };
        if peer_result == -1 {
            return Err(last_error(
                step,
                "verify supervisor control socket is connected",
            ));
        }
        if i32::from(peer.ss_family) != libc::AF_UNIX {
            return Err(BackendError::new(
                step,
                "supervisor control channel peer was not Unix-domain",
                None,
            ));
        }
        Ok(())
    }

    fn validate_egress_channel(
        step: IsolationStep,
        egress_channel: EgressChannelConfig,
    ) -> Result<(), BackendError> {
        let descriptor = egress_channel.fd();
        if descriptor < FIRST_NONSTANDARD_FD {
            return Err(BackendError::new(
                step,
                "egress Broker channel overlapped a standard descriptor",
                None,
            ));
        }
        if descriptor_has_cloexec(step, descriptor)? {
            return Err(BackendError::new(
                step,
                "egress Broker channel was close-on-exec",
                None,
            ));
        }
        let mut socket_type = 0_i32;
        let mut socket_type_length = libc::socklen_t::try_from(std::mem::size_of_val(&socket_type))
            .map_err(|_| {
                BackendError::new(step, "socket type length did not fit socklen_t", None)
            })?;
        // SAFETY: the descriptor is supplied by the trusted guest supervisor; the output pointer
        // and length point to writable storage of exactly the advertised size.
        let socket_type_result = unsafe {
            libc::getsockopt(
                descriptor,
                libc::SOL_SOCKET,
                libc::SO_TYPE,
                (&raw mut socket_type).cast::<libc::c_void>(),
                &raw mut socket_type_length,
            )
        };
        if socket_type_result == -1 {
            return Err(last_error(step, "inspect egress Broker socket type"));
        }
        if socket_type != libc::SOCK_STREAM {
            return Err(BackendError::new(
                step,
                "egress Broker channel was not a stream socket",
                None,
            ));
        }

        let mut peer: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
        let mut peer_length =
            libc::socklen_t::try_from(std::mem::size_of_val(&peer)).map_err(|_| {
                BackendError::new(step, "socket peer length did not fit socklen_t", None)
            })?;
        // SAFETY: `peer` and `peer_length` are writable buffers accepted by getpeername.
        let peer_result = unsafe {
            libc::getpeername(
                descriptor,
                (&raw mut peer).cast::<libc::sockaddr>(),
                &raw mut peer_length,
            )
        };
        if peer_result == -1 {
            return Err(last_error(
                step,
                "verify egress Broker channel is connected",
            ));
        }
        if i32::from(peer.ss_family) != libc::AF_VSOCK {
            return Err(BackendError::new(
                step,
                "egress Broker channel peer was not vsock",
                None,
            ));
        }
        Ok(())
    }

    fn close_inherited_fds(
        step: IsolationStep,
        preserved_notifier_fd: RawFd,
        control_channel: Option<ControlChannelConfig>,
        egress_channel: Option<EgressChannelConfig>,
    ) -> Result<(), BackendError> {
        if preserved_notifier_fd < FIRST_NONSTANDARD_FD {
            return Err(BackendError::new(
                step,
                "child startup notifier overlapped a standard descriptor",
                None,
            ));
        }
        if !descriptor_has_cloexec(step, preserved_notifier_fd)? {
            return Err(BackendError::new(
                step,
                "child startup notifier was not close-on-exec",
                None,
            ));
        }
        let mut preserved = vec![preserved_notifier_fd.cast_unsigned()];
        for descriptor in [
            control_channel.map(ControlChannelConfig::fd),
            egress_channel.map(EgressChannelConfig::fd),
        ]
        .into_iter()
        .flatten()
        {
            if descriptor == preserved_notifier_fd {
                return Err(BackendError::new(
                    step,
                    "preserved workload channel overlapped the startup notifier",
                    None,
                ));
            }
            preserved.push(descriptor.cast_unsigned());
        }
        preserved.sort_unstable();
        if preserved.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(BackendError::new(
                step,
                "preserved workload channels overlapped one descriptor",
                None,
            ));
        }
        let mut first = FIRST_NONSTANDARD_FD.cast_unsigned();
        for descriptor in preserved {
            if descriptor > first {
                close_fd_range(step, first, descriptor - 1)?;
            }
            first = descriptor.checked_add(1).ok_or_else(|| {
                BackendError::new(step, "preserved descriptor exceeded the valid range", None)
            })?;
        }
        close_fd_range(step, first, u32::MAX)?;
        Ok(())
    }

    fn close_fd_range(step: IsolationStep, first: u32, last: u32) -> Result<(), BackendError> {
        // SAFETY: the range excludes the separately-owned notifier and uses no pointer.
        let result = unsafe { libc::syscall(libc::SYS_close_range, first, last, 0_u32) };
        if result == 0 {
            return Ok(());
        }
        if errno() == libc::ENOSYS {
            return Err(BackendError::new(
                step,
                "close_range is unavailable; refusing an incomplete descriptor sweep",
                Some(libc::ENOSYS),
            ));
        }
        Err(last_error(step, "close inherited file descriptor range"))
    }

    fn descriptor_has_cloexec(
        step: IsolationStep,
        descriptor: RawFd,
    ) -> Result<bool, BackendError> {
        loop {
            // SAFETY: F_GETFD reads flags from a scalar descriptor.
            let flags = unsafe { libc::fcntl(descriptor, libc::F_GETFD) };
            if flags >= 0 {
                return Ok(flags & libc::FD_CLOEXEC != 0);
            }
            if errno() == libc::EINTR {
                continue;
            }
            return Err(last_error(step, "inspect descriptor close-on-exec flag"));
        }
    }

    fn open_pidfd(step: IsolationStep, child_pid: NonZeroU32) -> Result<OwnedFd, BackendError> {
        let child_pid = libc::pid_t::try_from(child_pid.get()).map_err(|_| {
            BackendError::new(step, "child PID did not fit the pidfd_open ABI", None)
        })?;
        // SAFETY: pidfd_open accepts only the scalar child PID and zero flags.
        let descriptor = unsafe { libc::syscall(libc::SYS_pidfd_open, child_pid, 0_u32) };
        if descriptor == -1 {
            return Err(last_error(step, "open isolation child pidfd"));
        }
        let descriptor = RawFd::try_from(descriptor).map_err(|_| {
            BackendError::new(step, "pidfd_open returned an invalid descriptor", None)
        })?;
        // SAFETY: successful pidfd_open returns one owned descriptor.
        let descriptor = unsafe { OwnedFd::from_raw_fd(descriptor) };
        let descriptor = ensure_nonstandard_fd(step, descriptor, "normalize isolation pidfd")?;
        if !descriptor_has_cloexec(step, descriptor.as_raw_fd())? {
            return Err(BackendError::new(
                step,
                "pidfd_open returned a descriptor without close-on-exec",
                None,
            ));
        }
        Ok(descriptor)
    }

    fn close_range_is_available() -> bool {
        // Reversed bounds are side-effect free and return EINVAL on kernels that
        // implement close_range, while older kernels return ENOSYS.
        // SAFETY: no valid descriptor range is supplied.
        let result = unsafe { libc::syscall(libc::SYS_close_range, 1_u32, 0_u32, 0_u32) };
        result == 0 || (result == -1 && errno() == libc::EINVAL)
    }

    fn pidfd_open_is_available() -> bool {
        // An invalid PID makes this a side-effect-free availability probe.
        // SAFETY: the syscall receives an invalid scalar PID and zero flags.
        let result = unsafe { libc::syscall(libc::SYS_pidfd_open, -1_i32, 0_u32) };
        if result >= 0 {
            if let Ok(descriptor) = RawFd::try_from(result) {
                // SAFETY: an unexpectedly successful probe returned an owned fd.
                drop(unsafe { OwnedFd::from_raw_fd(descriptor) });
            }
            true
        } else {
            matches!(errno(), libc::EINVAL | libc::ESRCH)
        }
    }

    fn combine_results(
        first: Result<(), BackendError>,
        second: Result<(), BackendError>,
    ) -> Option<BackendError> {
        match (first, second) {
            (Ok(()), Ok(())) => None,
            (Err(error), Ok(())) | (Ok(()), Err(error)) => Some(error),
            (Err(primary), Err(secondary)) => Some(combine_errors(&primary, &secondary)),
        }
    }

    fn combine_errors(primary: &BackendError, secondary: &BackendError) -> BackendError {
        BackendError::new(
            primary.step,
            format!(
                "{}; additional failure during {}: {}",
                primary.message, secondary.step, secondary.message
            ),
            primary.errno.or(secondary.errno),
        )
    }

    fn cleanup_failed_spawn(child_pid: libc::pid_t, original: BackendError) -> BackendError {
        match kill_and_reap_direct_child(child_pid) {
            Ok(()) => original,
            Err(cleanup_error) => combine_errors(&original, &cleanup_error),
        }
    }

    fn kill_and_reap_direct_child(child_pid: libc::pid_t) -> Result<(), BackendError> {
        loop {
            // SAFETY: `child_pid` came directly from fork and cannot be reused
            // until this launcher reaps it.
            let result = unsafe { libc::kill(child_pid, libc::SIGKILL) };
            if result == 0 || (result == -1 && errno() == libc::ESRCH) {
                break;
            }
            if errno() == libc::EINTR {
                continue;
            }
            return Err(last_error(
                IsolationStep::Namespaces,
                "kill child after isolation spawn ownership failure",
            ));
        }
        loop {
            let mut status = 0;
            // SAFETY: the PID names this launcher's direct, unreaped child and
            // `status` points to writable storage.
            let result = unsafe { libc::waitpid(child_pid, &raw mut status, 0) };
            if result == child_pid {
                return Ok(());
            }
            if result == -1 && errno() == libc::EINTR {
                continue;
            }
            return Err(last_error(
                IsolationStep::Namespaces,
                "reap child after isolation spawn ownership failure",
            ));
        }
    }

    fn install_landlock(step: IsolationStep, config: &LandlockConfig) -> Result<(), BackendError> {
        let attr = LandlockRulesetAttr {
            handled_access_fs: LANDLOCK_ALL_ACCESS,
        };
        let ruleset_fd = syscall_fd(
            step,
            libc::SYS_landlock_create_ruleset,
            (&raw const attr).cast(),
            std::mem::size_of::<LandlockRulesetAttr>(),
            0,
        )?;
        if let Err(error) = set_no_new_privs(step) {
            let _ = close_fd(ruleset_fd);
            return Err(error);
        }
        let rule_result = (|| {
            for path in &config.read_only_paths {
                add_landlock_rule(step, ruleset_fd, path, LANDLOCK_READ_ONLY_ACCESS)?;
            }
            for path in &config.writable_paths {
                add_landlock_rule(step, ruleset_fd, path, LANDLOCK_WORKSPACE_ACCESS)?;
            }
            Ok::<(), BackendError>(())
        })();
        if let Err(error) = rule_result {
            let _ = close_fd(ruleset_fd);
            return Err(error);
        }
        // SAFETY: The fd is owned by this function and the ruleset is immutable after restrict.
        let result = unsafe { libc::syscall(libc::SYS_landlock_restrict_self, ruleset_fd, 0_u32) };
        let close_result = close_fd(ruleset_fd);
        if result == -1 {
            return Err(last_error(step, "restrict process with Landlock ruleset"));
        }
        close_result
    }

    fn add_landlock_rule(
        step: IsolationStep,
        ruleset_fd: RawFd,
        path: &Path,
        allowed_access: u64,
    ) -> Result<(), BackendError> {
        let path = c_path(step, path)?;
        // SAFETY: O_PATH opens only the named path; no data is read through the descriptor.
        let parent_fd = unsafe { libc::open(path.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
        if parent_fd == -1 {
            return Err(last_error(step, "open Landlock rule path"));
        }
        let rule = LandlockPathBeneathAttr {
            allowed_access,
            parent_fd,
        };
        // SAFETY: `rule` lives across the syscall and contains only a live fd and scalar rights.
        let result = unsafe {
            libc::syscall(
                libc::SYS_landlock_add_rule,
                ruleset_fd,
                LANDLOCK_RULE_TYPE_PATH_BENEATH,
                (&raw const rule).cast::<libc::c_void>(),
                0_u32,
            )
        };
        let close_result = close_fd(parent_fd);
        if result == -1 {
            return Err(last_error(step, "add Landlock path rule"));
        }
        close_result
    }

    fn drop_capabilities(
        step: IsolationStep,
        max_capability_index: libc::c_int,
    ) -> Result<(), BackendError> {
        // Clear ambient capabilities first so a later failure cannot leave an ambient privilege
        // path behind while this transaction is being aborted.
        // SAFETY: This prctl operation takes no pointer and clears ambient capabilities.
        let ambient_result = unsafe {
            libc::prctl(
                libc::PR_CAP_AMBIENT,
                libc::PR_CAP_AMBIENT_CLEAR_ALL,
                0,
                0,
                0,
            )
        };
        if ambient_result == -1 && errno() != libc::EINVAL {
            return Err(last_error(step, "clear ambient capabilities"));
        }

        // Drop the bounding set before clearing the effective set so no future exec can regain it.
        for capability in 0..=max_capability_index {
            // SAFETY: The prctl arguments are scalar capability numbers.
            let capability = libc::c_ulong::from(capability.cast_unsigned());
            let result = unsafe { libc::prctl(libc::PR_CAPBSET_DROP, capability, 0, 0, 0) };
            if result == -1 && errno() != libc::EINVAL {
                return Err(last_error(step, "drop capability from bounding set"));
            }
        }
        // SAFETY: Both structures are valid, initialized capability ABI values.
        let header = CapabilityHeader {
            version: CAPABILITY_VERSION_3,
            pid: 0,
        };
        let data = [
            CapabilityData {
                effective: 0,
                permitted: 0,
                inheritable: 0,
            },
            CapabilityData {
                effective: 0,
                permitted: 0,
                inheritable: 0,
            },
        ];
        // SAFETY: The pointers reference stack values for the duration of the syscall.
        let result = unsafe {
            libc::syscall(
                libc::SYS_capset,
                (&raw const header).cast::<libc::c_void>(),
                data.as_ptr().cast::<libc::c_void>(),
            )
        };
        if result == -1 {
            return Err(last_error(
                step,
                "clear effective and permitted capabilities",
            ));
        }
        Ok(())
    }

    fn set_no_new_privs(step: IsolationStep) -> Result<(), BackendError> {
        // SAFETY: The operation uses only scalar prctl arguments and is idempotent.
        let result = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
        if result == -1 {
            Err(last_error(step, "set no_new_privs"))
        } else {
            Ok(())
        }
    }

    fn install_seccomp(step: IsolationStep, policy: &SeccompPolicy) -> Result<(), BackendError> {
        policy
            .validate_for_platform()
            .map_err(|error| BackendError::new(step, error.to_string(), None))?;
        let mut filters = compile_filter(step, policy)?;
        let mut program = SockFprog {
            length: u16::try_from(filters.len()).map_err(|_| {
                BackendError::new(step, "seccomp filter exceeds the BPF length limit", None)
            })?,
            filter: filters.as_mut_ptr(),
        };
        // SAFETY: no_new_privs is set; the filter buffer remains alive for the syscall.
        let result = unsafe {
            libc::prctl(
                libc::PR_SET_SECCOMP,
                libc::c_ulong::from(libc::SECCOMP_MODE_FILTER),
                (&raw mut program).cast::<libc::c_void>() as libc::c_ulong,
                0,
                0,
            )
        };
        if result == -1 {
            Err(last_error(step, "install default-deny seccomp filter"))
        } else {
            Ok(())
        }
    }

    fn compile_filter(
        step: IsolationStep,
        policy: &SeccompPolicy,
    ) -> Result<Vec<SockFilter>, BackendError> {
        let architecture = if cfg!(target_arch = "x86_64") {
            AUDIT_ARCH_X86_64
        } else {
            return Err(BackendError::new(
                step,
                "seccomp architecture is not verified for this target",
                None,
            ));
        };
        let mut filters = vec![
            statement(BPF_LD | BPF_W | BPF_ABS, SECCOMP_DATA_ARCH_OFFSET),
            jump(BPF_JMP | BPF_JEQ | BPF_K, architecture, 1, 0),
            statement(BPF_STMT, SECCOMP_RET_KILL_PROCESS),
            statement(BPF_LD | BPF_W | BPF_ABS, SECCOMP_DATA_NR_OFFSET),
        ];
        let syscall_count = policy.allowed_syscalls().len();
        let has_mmap_guard = policy.allows(crate::Syscall::Mmap);
        let comparison_start = filters.len();
        let guard_start = comparison_start + syscall_count;
        let allow_index = guard_start + if has_mmap_guard { 2 } else { 0 };
        let deny_index = allow_index + 1;
        for (index, syscall) in policy.allowed_syscalls().iter().enumerate() {
            let number = syscall.number().ok_or_else(|| {
                BackendError::new(step, format!("unsupported syscall '{syscall}'"), None)
            })?;
            let comparison_index = comparison_start + index;
            let true_target = if *syscall == crate::Syscall::Mmap {
                guard_start
            } else {
                allow_index
            };
            let jump_true = u8::try_from(true_target - (comparison_index + 1)).map_err(|_| {
                BackendError::new(step, "seccomp allowlist is too large for classic BPF", None)
            })?;
            let false_target = if index == syscall_count - 1 {
                deny_index
            } else {
                comparison_index + 1
            };
            let jump_false = u8::try_from(false_target - (comparison_index + 1)).map_err(|_| {
                BackendError::new(step, "seccomp allowlist is too large for classic BPF", None)
            })?;
            filters.push(jump(
                BPF_JMP | BPF_JEQ | BPF_K,
                number.cast_unsigned(),
                jump_true,
                jump_false,
            ));
        }
        if has_mmap_guard {
            filters.push(statement(
                BPF_LD | BPF_W | BPF_ABS,
                SECCOMP_DATA_MMAP_FLAGS_OFFSET,
            ));
            filters.push(jump(BPF_JMP | BPF_JSET | BPF_K, MAP_SHARED_FLAG, 1, 0));
        }
        filters.push(statement(BPF_STMT, SECCOMP_RET_ALLOW));
        filters.push(statement(BPF_STMT, SECCOMP_RET_ERRNO | libc::EPERM as u32));
        Ok(filters)
    }

    const fn statement(code: u16, constant: u32) -> SockFilter {
        SockFilter {
            code,
            jump_true: 0,
            jump_false: 0,
            constant,
        }
    }

    const fn jump(code: u16, constant: u32, jump_true: u8, jump_false: u8) -> SockFilter {
        SockFilter {
            code,
            jump_true,
            jump_false,
            constant,
        }
    }

    fn mount_call(
        step: IsolationStep,
        source: Option<&Path>,
        target: &Path,
        filesystem: Option<&Path>,
        flags: libc::c_ulong,
        data: Option<&CString>,
    ) -> Result<(), BackendError> {
        let source = source.map(|path| c_path(step, path)).transpose()?;
        let target = c_path(step, target)?;
        let filesystem = filesystem.map(|path| c_path(step, path)).transpose()?;
        let source_ptr = source
            .as_ref()
            .map_or(std::ptr::null(), |path| path.as_ptr());
        let filesystem_ptr = filesystem
            .as_ref()
            .map_or(std::ptr::null(), |path| path.as_ptr());
        let data_ptr: *const libc::c_char = data.map_or(std::ptr::null(), |value| value.as_ptr());
        // SAFETY: All pointers refer to NUL-terminated strings alive during the call.
        let result = unsafe {
            libc::mount(
                source_ptr,
                target.as_ptr(),
                filesystem_ptr,
                flags,
                data_ptr.cast::<libc::c_void>(),
            )
        };
        if result == -1 {
            Err(last_error(step, "mount filesystem"))
        } else {
            Ok(())
        }
    }

    fn pivot_root(
        step: IsolationStep,
        new_root: &Path,
        old_root: &Path,
    ) -> Result<(), BackendError> {
        let new_root = c_path(step, new_root)?;
        let old_root = c_path(step, old_root)?;
        // SAFETY: Both paths are validated absolute paths and remain alive for the syscall.
        let result =
            unsafe { libc::syscall(libc::SYS_pivot_root, new_root.as_ptr(), old_root.as_ptr()) };
        if result == -1 {
            Err(last_error(step, "pivot into read-only rootfs"))
        } else {
            Ok(())
        }
    }

    fn unmount_path(step: IsolationStep, path: &Path) -> Result<(), BackendError> {
        let path = c_path(step, path)?;
        // SAFETY: The path pointer is valid for the duration of the syscall.
        let result = unsafe { libc::umount2(path.as_ptr(), libc::MNT_DETACH) };
        if result == -1 {
            Err(last_error(step, "unmount path"))
        } else {
            Ok(())
        }
    }

    fn change_directory(step: IsolationStep, path: &Path) -> Result<(), BackendError> {
        let path = c_path(step, path)?;
        // SAFETY: The path pointer is valid for the duration of the syscall.
        let result = unsafe { libc::chdir(path.as_ptr()) };
        if result == -1 {
            Err(last_error(step, "change working directory"))
        } else {
            Ok(())
        }
    }

    fn write_text(step: IsolationStep, path: &Path, value: &str) -> Result<(), BackendError> {
        fs::write(path, value).map_err(|error| io_error(step, "write kernel control file", &error))
    }

    fn current_cgroup_path(
        step: IsolationStep,
        cgroup_root: &Path,
    ) -> Result<PathBuf, BackendError> {
        let content = fs::read_to_string("/proc/self/cgroup")
            .map_err(|error| io_error(step, "read current cgroup membership", &error))?;
        let path = content
            .lines()
            .find_map(|line| line.strip_prefix("0::"))
            .ok_or_else(|| BackendError::new(step, "unified cgroup membership is missing", None))?;
        Ok(cgroup_root.join(path.trim_start_matches('/')))
    }

    fn rootfs_path(rootfs_target: &Path, target: &Path) -> Option<PathBuf> {
        let relative = target.strip_prefix("/").ok()?;
        Some(rootfs_target.join(relative))
    }

    fn old_root_after_pivot(rootfs_target: &Path, old_root: &Path) -> Option<PathBuf> {
        let relative = old_root.strip_prefix(rootfs_target).ok()?;
        Some(Path::new("/").join(relative))
    }

    fn c_path(step: IsolationStep, path: &Path) -> Result<CString, BackendError> {
        CString::new(path.as_os_str().as_bytes())
            .map_err(|_| BackendError::new(step, "path contains an embedded NUL byte", None))
    }

    fn syscall_fd(
        step: IsolationStep,
        number: libc::c_long,
        first: *const libc::c_void,
        second: usize,
        third: usize,
    ) -> Result<RawFd, BackendError> {
        // SAFETY: The caller supplies a live pointer and exact ABI-sized arguments.
        let result = unsafe { libc::syscall(number, first, second, third) };
        if result == -1 {
            Err(last_error(step, "create Landlock ruleset"))
        } else {
            RawFd::try_from(result).map_err(|_| {
                BackendError::new(step, "kernel returned an invalid file descriptor", None)
            })
        }
    }

    fn close_fd(fd: RawFd) -> Result<(), BackendError> {
        // SAFETY: `fd` was returned by the kernel and is owned by the caller.
        let result = unsafe { libc::close(fd) };
        if result == -1 {
            Err(last_error(
                IsolationStep::Landlock,
                "close Landlock descriptor",
            ))
        } else {
            Ok(())
        }
    }

    fn query_landlock_abi() -> Option<u32> {
        // SAFETY: VERSION query intentionally passes a null attribute and zero size.
        let result = unsafe {
            libc::syscall(
                libc::SYS_landlock_create_ruleset,
                std::ptr::null::<libc::c_void>(),
                0_usize,
                LANDLOCK_CREATE_RULESET_VERSION,
            )
        };
        result.try_into().ok()
    }

    fn query_max_capability_index() -> Option<libc::c_int> {
        let value = fs::read_to_string("/proc/sys/kernel/cap_last_cap").ok()?;
        let value = value.trim().parse::<u32>().ok()?;
        let value = libc::c_int::try_from(value).ok()?;
        (value <= 63).then_some(value)
    }

    fn seccomp_is_available() -> bool {
        // SAFETY: This query has no pointer or mutable process effect.
        let result = unsafe { libc::prctl(libc::PR_GET_SECCOMP, 0, 0, 0, 0) };
        result >= 0 && result != libc::SECCOMP_MODE_STRICT.cast_signed()
    }

    fn user_namespace_is_permitted() -> bool {
        let namespace_limit = fs::read_to_string("/proc/sys/user/max_user_namespaces")
            .ok()
            .and_then(|value| value.trim().parse::<u64>().ok());
        if namespace_limit == Some(0) {
            return false;
        }

        // Root may create a user namespace even when the unprivileged toggle is absent.
        // SAFETY: The query reads only the effective UID.
        let effective_uid = unsafe { libc::geteuid() };
        if effective_uid == 0 {
            return true;
        }
        fs::read_to_string("/proc/sys/kernel/unprivileged_userns_clone")
            .map(|value| value.trim() == "1")
            .unwrap_or(false)
    }

    fn access_path(path: &Path, mode: libc::c_int) -> bool {
        let Ok(path) = CString::new(path.as_os_str().as_bytes()) else {
            return false;
        };
        // SAFETY: The path pointer is valid for the duration of the access query.
        unsafe { libc::access(path.as_ptr(), mode) == 0 }
    }

    fn observe_pid_namespaces(
        step: IsolationStep,
    ) -> Result<PidNamespaceObservation, BackendError> {
        Ok(PidNamespaceObservation {
            current: namespace_identity(step, Path::new(CURRENT_PID_NAMESPACE))?,
            for_children: namespace_identity(step, Path::new(PID_NAMESPACE_FOR_CHILDREN))?,
        })
    }

    fn process_is_single_threaded(step: IsolationStep) -> Result<bool, BackendError> {
        let mut tasks = fs::read_dir("/proc/self/task")
            .map_err(|error| io_error(step, "inspect launcher thread count", &error))?;
        let Some(first_task) = tasks.next() else {
            return Err(BackendError::new(
                step,
                "launcher task directory contained no threads",
                None,
            ));
        };
        first_task.map_err(|error| io_error(step, "inspect launcher thread entry", &error))?;
        match tasks.next() {
            None => Ok(true),
            Some(Ok(_)) => Ok(false),
            Some(Err(error)) => Err(io_error(step, "inspect launcher thread entry", &error)),
        }
    }

    fn namespace_identity(
        step: IsolationStep,
        path: &Path,
    ) -> Result<NamespaceIdentity, BackendError> {
        let metadata = fs::metadata(path)
            .map_err(|error| io_error(step, "observe PID namespace identity", &error))?;
        Ok(NamespaceIdentity::from_kernel(
            metadata.dev(),
            metadata.ino(),
        ))
    }

    fn errno() -> i32 {
        // SAFETY: libc exposes the calling thread's errno cell.
        unsafe { *libc::__errno_location() }
    }

    fn current_pid() -> libc::pid_t {
        // SAFETY: `getpid` has no pointer arguments and cannot violate memory safety.
        unsafe { libc::getpid() }
    }

    fn last_error(step: IsolationStep, action: &str) -> BackendError {
        let error = io::Error::last_os_error();
        let errno = error.raw_os_error();
        BackendError::new(step, action, errno)
    }

    fn io_error(step: IsolationStep, action: &str, error: &io::Error) -> BackendError {
        BackendError::new(step, action, error.raw_os_error())
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn seccomp_filter_denies_every_non_allowlisted_syscall() {
            let policy = SeccompPolicy::default();
            let filter = compile_filter(IsolationStep::Seccomp, &policy)
                .expect("default policy must compile");
            let last_comparison = 3 + policy.allowed_syscalls().len();
            let guard_start = last_comparison + 1;
            assert_eq!(filter[1].jump_true, 1);
            assert_eq!(filter[1].jump_false, 0);
            assert_eq!(filter[2].constant, SECCOMP_RET_KILL_PROCESS);
            assert_eq!(filter[last_comparison].jump_false, 3);
            assert_eq!(filter[guard_start].constant, SECCOMP_DATA_MMAP_FLAGS_OFFSET);
            assert_eq!(filter[guard_start + 1].code, BPF_JMP | BPF_JSET | BPF_K);
            assert_eq!(filter[guard_start + 1].jump_true, 1);
            assert_eq!(filter[guard_start + 1].jump_false, 0);
            assert_eq!(filter[guard_start + 2].constant, SECCOMP_RET_ALLOW);
            assert_eq!(
                filter[guard_start + 3].constant,
                SECCOMP_RET_ERRNO | libc::EPERM as u32
            );
        }

        #[test]
        fn seccomp_filter_without_mmap_reaches_errno_for_unknown_syscalls() {
            let policy = SeccompPolicy::new([crate::Syscall::Read]).expect("read is safe");
            let filter = compile_filter(IsolationStep::Seccomp, &policy)
                .expect("single syscall policy must compile");

            assert_eq!(filter.len(), 7);
            assert_eq!(filter[4].jump_true, 0);
            assert_eq!(filter[4].jump_false, 1);
            assert_eq!(filter[5].constant, SECCOMP_RET_ALLOW);
            assert_eq!(filter[6].constant, SECCOMP_RET_ERRNO | libc::EPERM as u32);
        }

        #[test]
        fn landlock_workspace_rights_do_not_include_special_file_creation() {
            let special_file_creation = LANDLOCK_ACCESS_FS_MAKE_CHAR
                | LANDLOCK_ACCESS_FS_MAKE_SOCK
                | LANDLOCK_ACCESS_FS_MAKE_FIFO
                | LANDLOCK_ACCESS_FS_MAKE_BLOCK
                | LANDLOCK_ACCESS_FS_MAKE_SYM;

            assert_eq!(
                LANDLOCK_ALL_ACCESS & LANDLOCK_ACCESS_FS_TRUNCATE,
                LANDLOCK_ACCESS_FS_TRUNCATE
            );
            assert_eq!(
                LANDLOCK_WORKSPACE_ACCESS & special_file_creation,
                0,
                "workspace must not create devices, sockets, FIFOs, or symlinks"
            );
            assert_ne!(
                LANDLOCK_WORKSPACE_ACCESS & LANDLOCK_ACCESS_FS_REFER,
                0,
                "workspace rename enforcement requires REFER to be handled and allowed"
            );
        }

        #[test]
        fn workspace_source_pin_survives_path_rename() {
            let nonce = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("test clock must follow the Unix epoch")
                .as_nanos();
            let root = std::env::temp_dir().join(format!(
                "runtime-isolation-workspace-pin-{}-{nonce}",
                std::process::id()
            ));
            let original = root.join("original");
            let renamed = root.join("renamed");
            fs::create_dir_all(&original).expect("test workspace must be created");

            let pinned = pin_workspace_source(IsolationStep::ReadOnlyRootfs, &original)
                .expect("workspace source must be pinned");
            fs::rename(&original, &renamed).expect("test workspace must be renamed");
            let through_descriptor = fs::metadata(pinned.proc_path())
                .expect("pinned workspace must remain reachable through its descriptor");

            assert_eq!(
                (through_descriptor.dev(), through_descriptor.ino()),
                (pinned.device, pinned.inode)
            );
            drop(pinned);
            fs::remove_dir(&renamed).expect("renamed test workspace must be removed");
            fs::remove_dir(&root).expect("test workspace root must be removed");
        }

        #[test]
        fn startup_reader_liveness_rejects_a_closed_parent_endpoint() {
            let pipe = create_startup_pipe(IsolationStep::Namespaces)
                .expect("test startup pipe must be created");
            verify_startup_reader_alive(IsolationStep::Namespaces, pipe.writer.as_raw_fd())
                .expect("a live reader must keep the startup writer usable");

            drop(pipe.reader);
            let error =
                verify_startup_reader_alive(IsolationStep::Namespaces, pipe.writer.as_raw_fd())
                    .expect_err("a closed parent endpoint must fail lifecycle verification");
            assert!(error.message.contains("closed the child startup channel"));
        }

        #[test]
        fn gated_credential_transition_rearms_parent_death_signal() {
            // SAFETY: geteuid has no pointer arguments.
            if unsafe { libc::geteuid() } != 0
                || !process_is_single_threaded(IsolationStep::Namespaces)
                    .expect("the credential test must inspect its thread count")
            {
                return;
            }
            let pipe = create_startup_pipe(IsolationStep::Namespaces)
                .expect("credential test startup pipe must be created");
            let parent_pid = current_pid();
            // SAFETY: the child performs only isolated lifecycle operations and
            // exits without returning into the Rust test harness.
            let child_pid = unsafe { libc::fork() };
            assert_ne!(child_pid, -1, "credential test fork must succeed");
            if child_pid == 0 {
                drop(pipe.reader);
                let writer_fd = pipe.writer.as_raw_fd();
                let result = (|| {
                    configure_child_lifecycle(IsolationStep::Namespaces, parent_pid, writer_fd)?;
                    // SAFETY: the expendable root child intentionally changes to
                    // the conventional nobody credential for this regression test.
                    if unsafe { libc::setresgid(65534, 65534, 65534) } == -1 {
                        return Err(last_error(
                            IsolationStep::IdentityMap,
                            "change regression-test GID",
                        ));
                    }
                    // SAFETY: the child still has UID zero until this final change.
                    if unsafe { libc::setresuid(65534, 65534, 65534) } == -1 {
                        return Err(last_error(
                            IsolationStep::IdentityMap,
                            "change regression-test UID",
                        ));
                    }
                    let mut cleared_signal = libc::SIGKILL;
                    // SAFETY: PR_GET_PDEATHSIG writes one scalar signal number.
                    if unsafe {
                        libc::prctl(libc::PR_GET_PDEATHSIG, &raw mut cleared_signal, 0, 0, 0)
                    } == -1
                        || cleared_signal != 0
                    {
                        return Err(BackendError::new(
                            IsolationStep::IdentityMap,
                            "credential transition did not clear the parent-death signal",
                            None,
                        ));
                    }
                    arm_and_verify_parent_lifecycle(
                        IsolationStep::IdentityMap,
                        parent_pid,
                        writer_fd,
                    )
                })();
                // SAFETY: the fork child must never return into the test harness.
                unsafe { libc::_exit(i32::from(result.is_err())) }
            }

            drop(pipe.writer);
            let mut status = 0;
            // SAFETY: the PID is this process's direct, unreaped child.
            assert_eq!(
                unsafe { libc::waitpid(child_pid, &raw mut status, 0) },
                child_pid
            );
            assert!(libc::WIFEXITED(status));
            assert_eq!(libc::WEXITSTATUS(status), 0);
        }

        #[test]
        fn pid_namespace_identity_is_observable_without_privilege() {
            let observation = observe_pid_namespaces(IsolationStep::Namespaces)
                .expect("procfs namespace links must be observable");

            assert_ne!(observation.current.inode(), 0);
            assert_ne!(observation.for_children.inode(), 0);
            assert_eq!(
                observation.current,
                namespace_identity(IsolationStep::Namespaces, Path::new(CURRENT_PID_NAMESPACE))
                    .expect("current PID namespace must remain observable")
            );
        }

        #[test]
        fn pid_namespace_verification_rejects_missing_child_handoff() {
            let parent = NamespaceIdentity::from_kernel(4, 10);
            let child = NamespaceIdentity::from_kernel(4, 11);
            let error = validate_pid_namespace_child_entry(
                IsolationStep::Namespaces,
                &NamespacePreparation::attest(parent, child),
                PidNamespaceObservation {
                    current: parent,
                    for_children: child,
                },
            )
            .expect_err("the namespace-preparing parent must not pass child verification");

            assert!(error.message.contains("no child handoff occurred"));
        }

        #[test]
        fn pid_namespace_verification_accepts_the_expected_child() {
            let parent = NamespaceIdentity::from_kernel(4, 10);
            let child = NamespaceIdentity::from_kernel(4, 11);

            validate_pid_namespace_child_entry(
                IsolationStep::Namespaces,
                &NamespacePreparation::attest(parent, child),
                PidNamespaceObservation {
                    current: child,
                    for_children: child,
                },
            )
            .expect("the expected PID namespace child must pass verification");
        }

        #[test]
        fn pid_namespace_verification_rejects_a_nested_pending_namespace() {
            let parent = NamespaceIdentity::from_kernel(4, 10);
            let child = NamespaceIdentity::from_kernel(4, 11);
            let nested = NamespaceIdentity::from_kernel(4, 12);
            let error = validate_pid_namespace_child_entry(
                IsolationStep::Namespaces,
                &NamespacePreparation::attest(parent, child),
                PidNamespaceObservation {
                    current: child,
                    for_children: nested,
                },
            )
            .expect_err("a second pending PID namespace must fail verification");

            assert!(error.message.contains("different pending PID namespace"));
        }

        #[test]
        fn fork_rejects_a_handoff_not_owned_by_the_backend() {
            let mut backend = LinuxBackend::new();
            let preparation = NamespacePreparation::attest(
                NamespaceIdentity::from_kernel(4, 10),
                NamespaceIdentity::from_kernel(4, 11),
            );

            let error = backend
                .spawn_isolated_impl(
                    preparation,
                    |_child_backend, _child_preparation, _notifier| (),
                )
                .expect_err("an unattested direct handoff must fail before fork");

            assert!(error.message.contains("no matching backend preparation"));
        }

        #[test]
        fn fork_rejects_a_multithreaded_launcher() {
            let (ready_sender, ready_receiver) = std::sync::mpsc::sync_channel(0);
            let (release_sender, release_receiver) = std::sync::mpsc::sync_channel(0);
            let extra_thread = std::thread::spawn(move || {
                ready_sender
                    .send(())
                    .expect("the test must announce its extra thread");
                release_receiver
                    .recv()
                    .expect("the test must release its extra thread");
            });
            ready_receiver
                .recv()
                .expect("the extra thread must become live");

            let parent_namespace = NamespaceIdentity::from_kernel(4, 10);
            let child_namespace = NamespaceIdentity::from_kernel(4, 11);
            let preparation = NamespacePreparation::attest(parent_namespace, child_namespace);
            let mut backend = LinuxBackend::new();
            backend.prepared_pid_namespaces = Some((parent_namespace, child_namespace));
            let result: Result<SpawnOutcome<()>, BackendError> = backend.spawn_isolated_impl(
                preparation,
                |_child_backend, _child_preparation, _notifier| unreachable!("fork must not occur"),
            );

            release_sender
                .send(())
                .expect("the test must release its extra thread");
            extra_thread.join().expect("the extra thread must exit");
            let error = result.expect_err("a multithreaded launcher must fail before fork");
            assert!(error.message.contains("single-threaded launcher"));
        }

        #[test]
        fn control_descriptors_are_cloexec_and_do_not_overlap_standard_io() {
            let pipe = create_startup_pipe(IsolationStep::Namespaces)
                .expect("startup pipe creation must not require privilege");
            let null_device = open_null_device(IsolationStep::Namespaces)
                .expect("opening the kernel null device must not require privilege");

            for descriptor in [
                pipe.reader.as_raw_fd(),
                pipe.writer.as_raw_fd(),
                null_device.as_raw_fd(),
            ] {
                assert!(descriptor >= FIRST_NONSTANDARD_FD);
                assert!(
                    descriptor_has_cloexec(IsolationStep::Namespaces, descriptor)
                        .expect("control descriptor flags must be observable")
                );
            }
        }

        #[test]
        fn descriptor_sweep_rejects_a_standard_notifier() {
            let error = close_inherited_fds(
                IsolationStep::CloseInheritedFileDescriptors,
                libc::STDERR_FILENO,
                None,
                None,
            )
            .expect_err("a notifier may never overlap inherited standard IO");

            assert!(error.message.contains("overlapped a standard descriptor"));
        }

        #[test]
        fn required_process_descriptor_syscalls_are_available() {
            assert!(
                close_range_is_available(),
                "complete descriptor closure requires close_range"
            );
            assert!(
                pidfd_open_is_available(),
                "race-free child ownership requires pidfd_open"
            );
        }

        #[test]
        fn gated_fork_sanitizes_child_lifecycle_and_owns_it_by_pidfd() {
            if !process_is_single_threaded(IsolationStep::Namespaces)
                .expect("the fork test must inspect its thread count")
            {
                // Rust's parallel test harness is multi-threaded. The production
                // prepare call cannot succeed in that state, so exercise the real
                // fork only when this test itself runs single-threaded.
                return;
            }
            let leaked_descriptor = open_null_device(IsolationStep::Namespaces)
                .expect("the fork test must create an inherited descriptor");
            let leaked_fd = leaked_descriptor.as_raw_fd();
            let observed = observe_pid_namespaces(IsolationStep::Namespaces)
                .expect("the fork test must observe its current PID namespace");
            assert_eq!(observed.current, observed.for_children);
            let child_namespace = observed.current;
            let parent_namespace = NamespaceIdentity::from_kernel(
                child_namespace.device(),
                child_namespace.inode() ^ 1,
            );
            let preparation = NamespacePreparation::attest(parent_namespace, child_namespace);
            let mut backend = LinuxBackend::new();
            backend.prepared_pid_namespaces = Some((parent_namespace, child_namespace));

            let outcome: Result<SpawnOutcome<()>, BackendError> = backend.spawn_isolated_impl(
                preparation,
                move |child_backend, _child_preparation, _notifier| {
                    let Some(notifier_fd) = child_backend.startup_notifier_fd else {
                        // SAFETY: the fork child must never return into the test harness.
                        unsafe { libc::_exit(1) }
                    };
                    let setup_is_safe = child_signal_state_is_reset()
                        && standard_descriptors_are_sanitized()
                        && descriptor_has_cloexec(IsolationStep::Namespaces, notifier_fd)
                            .unwrap_or(false)
                        && close_inherited_fds(
                            IsolationStep::CloseInheritedFileDescriptors,
                            notifier_fd,
                            None,
                            None,
                        )
                        .is_ok()
                        && descriptor_is_closed(leaked_fd)
                        && !descriptor_is_closed(notifier_fd);
                    // The child must not return into the Rust test harness after fork.
                    unsafe {
                        libc::_exit(i32::from(!setup_is_safe));
                    }
                },
            );

            let outcome = match outcome {
                Ok(outcome) => outcome,
                Err(error) => panic!("fork must succeed for the isolated fork test: {error}"),
            };
            let SpawnOutcome::Parent(mut child) = outcome else {
                // The child branch exits in the continuation and cannot reach this assertion.
                panic!("only the fork parent may return to the test harness");
            };

            assert!(
                descriptor_has_cloexec(
                    IsolationStep::Namespaces,
                    child
                        .pidfd()
                        .expect("the parent must own a pidfd")
                        .as_raw_fd(),
                )
                .expect("pidfd flags must be observable")
            );
            assert!(matches!(
                child.wait_for_startup(),
                Err(crate::backend::ChildProcessError::StartupChannelClosed)
            ));
            assert!(matches!(
                child.wait(),
                Err(crate::backend::ChildProcessError::AlreadyReaped)
            ));
            assert_eq!(child.pid_namespace(), child_namespace);
        }

        fn descriptor_is_closed(descriptor: RawFd) -> bool {
            // SAFETY: F_GETFD only inspects the scalar descriptor.
            let result = unsafe { libc::fcntl(descriptor, libc::F_GETFD) };
            result == -1 && errno() == libc::EBADF
        }

        fn standard_descriptors_are_sanitized() -> bool {
            (libc::STDIN_FILENO..=libc::STDERR_FILENO).all(|descriptor| {
                descriptor_has_cloexec(IsolationStep::Namespaces, descriptor).unwrap_or(false)
                    && descriptor_is_null_device(descriptor)
            })
        }

        fn descriptor_is_null_device(descriptor: RawFd) -> bool {
            let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
            // SAFETY: `metadata` is writable and fstat does not consume the fd.
            if unsafe { libc::fstat(descriptor, metadata.as_mut_ptr()) } == -1 {
                return false;
            }
            // SAFETY: successful fstat initialized the complete structure.
            let metadata = unsafe { metadata.assume_init() };
            metadata.st_mode & libc::S_IFMT == libc::S_IFCHR
                && libc::major(metadata.st_rdev) == NULL_DEVICE_MAJOR
                && libc::minor(metadata.st_rdev) == NULL_DEVICE_MINOR
        }

        fn child_signal_state_is_reset() -> bool {
            // SAFETY: the structures are writable outputs for signal-state queries.
            let mut action = unsafe { std::mem::zeroed::<libc::sigaction>() };
            // SAFETY: a null new action queries the current disposition.
            if unsafe { libc::sigaction(libc::SIGPIPE, std::ptr::null(), &raw mut action) } == -1
                || action.sa_sigaction != libc::SIG_DFL
            {
                return false;
            }
            // SAFETY: the mask is a writable query output; a null input leaves it unchanged.
            let mut mask = unsafe { std::mem::zeroed::<libc::sigset_t>() };
            if unsafe { libc::pthread_sigmask(libc::SIG_SETMASK, std::ptr::null(), &raw mut mask) }
                != 0
            {
                return false;
            }
            // SAFETY: `mask` was initialized by pthread_sigmask.
            if unsafe { libc::sigismember(&raw const mask, libc::SIGTERM) } != 0 {
                return false;
            }
            let mut parent_death_signal = 0;
            // SAFETY: PR_GET_PDEATHSIG writes one signal number to the supplied pointer.
            unsafe {
                libc::prctl(
                    libc::PR_GET_PDEATHSIG,
                    &raw mut parent_death_signal,
                    0,
                    0,
                    0,
                ) == 0
                    && parent_death_signal == libc::SIGKILL
            }
        }
    }
}

#[cfg(target_os = "linux")]
pub use implementation::LinuxBackend;

#[cfg(not(target_os = "linux"))]
mod unsupported {
    use crate::backend::private::OperationPermit;
    use crate::{BackendError, CapabilityReport, IsolationBackend, IsolationConfig, IsolationStep};

    /// Unsupported-platform backend that reports prerequisites without attempting mutation.
    pub struct LinuxBackend;

    impl LinuxBackend {
        /// Creates an unsupported-platform backend.
        pub const fn new() -> Self {
            Self
        }
    }

    impl Default for LinuxBackend {
        fn default() -> Self {
            Self::new()
        }
    }

    #[allow(private_bounds, private_interfaces)]
    impl IsolationBackend for LinuxBackend {
        fn detect_capabilities(&mut self, _config: &IsolationConfig) -> CapabilityReport {
            CapabilityReport::unavailable(["runtime isolation requires Linux"])
        }

        fn apply_step(
            &mut self,
            _permit: OperationPermit,
            step: IsolationStep,
            _config: &IsolationConfig,
        ) -> Result<(), BackendError> {
            Err(BackendError::new(
                step,
                "runtime isolation requires Linux",
                None,
            ))
        }

        fn rollback_step(
            &mut self,
            _permit: OperationPermit,
            step: IsolationStep,
            _config: &IsolationConfig,
        ) -> Result<(), BackendError> {
            Err(BackendError::new(
                step,
                "runtime isolation requires Linux",
                None,
            ))
        }
    }
}

#[cfg(not(target_os = "linux"))]
pub use unsupported::LinuxBackend;
