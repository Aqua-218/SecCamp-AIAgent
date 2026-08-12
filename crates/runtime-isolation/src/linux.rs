//! Linux syscall backend for the isolation transaction.

#[cfg(target_os = "linux")]
mod implementation {
    use std::{
        ffi::CString,
        fs, io,
        os::fd::RawFd,
        os::unix::ffi::OsStrExt,
        os::unix::fs::MetadataExt,
        path::{Path, PathBuf},
    };

    use crate::{
        BackendError, BindMountConfig, CapabilityReport, CgroupConfig, IdentityMap,
        IsolationBackend, IsolationConfig, IsolationStep, LandlockConfig, SeccompPolicy,
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

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct NamespaceIdentity {
        device: u64,
        inode: u64,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct PidNamespaceObservation {
        current: NamespaceIdentity,
        for_children: NamespaceIdentity,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct PidNamespaceHandoff {
        parent: NamespaceIdentity,
        child: NamespaceIdentity,
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
    }

    impl LinuxBackend {
        /// Creates a backend with no process-global state changed.
        pub const fn new() -> Self {
            Self {
                previous_cgroup: None,
                created_cgroup: None,
                rootfs_pivoted: false,
                max_capability_index: None,
            }
        }
    }

    impl Default for LinuxBackend {
        fn default() -> Self {
            Self::new()
        }
    }

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
            let controllers = config.cgroup.root.join("cgroup.controllers");
            let required_controllers = fs::read_to_string(&controllers)
                .map(|value| {
                    value
                        .split_whitespace()
                        .any(|controller| controller == "memory")
                        && value
                            .split_whitespace()
                            .any(|controller| controller == "pids")
                })
                .unwrap_or(false);
            let control_files = ["memory.max", "pids.max", "cgroup.procs"];
            let controls_available = control_files.iter().all(|name| {
                let path = config.cgroup.root.join(name);
                path.is_file() && access_path(&path, libc::W_OK)
            });
            report.cgroup_v2_available = required_controllers
                && access_path(&config.cgroup.root, libc::W_OK | libc::X_OK)
                && controls_available;
            if !report.cgroup_v2_available {
                report
                    .reasons
                    .push(
                        "configured cgroup v2 root or required control files are absent or not writable"
                            .to_owned(),
                    );
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

        fn apply_step(
            &mut self,
            step: IsolationStep,
            config: &IsolationConfig,
        ) -> Result<(), BackendError> {
            match step {
                IsolationStep::Namespaces => create_namespaces(step),
                IsolationStep::IdentityMap => install_identity_map(step, config.identity),
                IsolationStep::CgroupV2 => self.configure_cgroup(step, &config.cgroup),
                IsolationStep::ReadOnlyRootfs => self.mount_rootfs(step, config),
                IsolationStep::Workspace => mount_workspace(step, &config.workspace),
                IsolationStep::LimitedTmpfs => {
                    mount_tmpfs(step, &config.tmpfs.target, config.tmpfs.size_bytes)
                }
                IsolationStep::MaskProc => mask_mount(step, Path::new("/proc")),
                IsolationStep::MaskDevices => mask_mount(step, Path::new("/dev")),
                IsolationStep::CloseInheritedFileDescriptors => close_inherited_fds(step),
                IsolationStep::Landlock => install_landlock(step, &config.landlock),
                IsolationStep::DropCapabilities => self.drop_capabilities(step),
                IsolationStep::NoNewPrivs => set_no_new_privs(step),
                IsolationStep::Seccomp => install_seccomp(step, &config.seccomp),
            }
        }

        fn rollback_step(
            &mut self,
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
                for target in [
                    &config.workspace.target,
                    &config.tmpfs.target,
                    Path::new("/proc"),
                    Path::new("/dev"),
                ] {
                    let target = rootfs_path(&rootfs.mount_target, target).ok_or_else(|| {
                        BackendError::new(step, "mount target escaped the staged rootfs", None)
                    })?;
                    fs::create_dir_all(target)
                        .map_err(|error| io_error(step, "create rootfs mount directory", &error))?;
                }
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
            result
        }

        fn drop_capabilities(&self, step: IsolationStep) -> Result<(), BackendError> {
            let max_capability_index = self.max_capability_index.ok_or_else(|| {
                BackendError::new(step, "kernel capability limit was not detected", None)
            })?;
            drop_capabilities(step, max_capability_index)
        }
    }

    fn create_namespaces(step: IsolationStep) -> Result<(), BackendError> {
        let handoff = prepare_namespaces(step)?;
        verify_pid_namespace_child_entry(step, handoff)
    }

    fn prepare_namespaces(step: IsolationStep) -> Result<PidNamespaceHandoff, BackendError> {
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

        Ok(PidNamespaceHandoff {
            parent: prepared.current,
            child: prepared.for_children,
        })
    }

    fn verify_pid_namespace_child_entry(
        step: IsolationStep,
        handoff: PidNamespaceHandoff,
    ) -> Result<(), BackendError> {
        validate_pid_namespace_child_entry(step, handoff, observe_pid_namespaces(step)?)
    }

    fn validate_pid_namespace_child_entry(
        step: IsolationStep,
        handoff: PidNamespaceHandoff,
        observed: PidNamespaceObservation,
    ) -> Result<(), BackendError> {
        if observed.current == handoff.parent {
            return Err(BackendError::new(
                step,
                "PID namespace is prepared only for the next child, but no child handoff occurred; refusing to report namespace isolation complete",
                None,
            ));
        }
        if observed.current != handoff.child {
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

    fn mount_workspace(step: IsolationStep, config: &BindMountConfig) -> Result<(), BackendError> {
        mount_call(
            step,
            Some(&config.source),
            &config.target,
            None,
            libc::MS_BIND,
            None,
        )?;
        let result = mount_call(
            step,
            None,
            &config.target,
            None,
            libc::MS_BIND | libc::MS_REMOUNT | libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
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
        result
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

    fn close_inherited_fds(step: IsolationStep) -> Result<(), BackendError> {
        // SAFETY: The range excludes stdin/stdout/stderr and uses no user pointer.
        let result = unsafe { libc::syscall(libc::SYS_close_range, 3_u32, u32::MAX, 0_u32) };
        if result == 0 {
            return Ok(());
        }
        if errno() != libc::ENOSYS {
            return Err(last_error(step, "close inherited file descriptors"));
        }
        let mut limits = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: `limits` is a valid writable rlimit structure.
        let limit_result = unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &raw mut limits) };
        if limit_result == -1 {
            return Err(last_error(step, "query file descriptor limit"));
        }
        let upper = limits.rlim_cur.min(1_048_576) as RawFd;
        for fd in 3..upper {
            // SAFETY: Each descriptor is a scalar selected from the process table.
            let close_result = unsafe { libc::close(fd) };
            if close_result == -1 && errno() != libc::EBADF {
                return Err(last_error(step, "close inherited file descriptor"));
            }
        }
        Ok(())
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

    fn namespace_identity(
        step: IsolationStep,
        path: &Path,
    ) -> Result<NamespaceIdentity, BackendError> {
        let metadata = fs::metadata(path)
            .map_err(|error| io_error(step, "observe PID namespace identity", &error))?;
        Ok(NamespaceIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
        })
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
        fn pid_namespace_identity_is_observable_without_privilege() {
            let observation = observe_pid_namespaces(IsolationStep::Namespaces)
                .expect("procfs namespace links must be observable");

            assert_ne!(observation.current.inode, 0);
            assert_ne!(observation.for_children.inode, 0);
            assert_eq!(
                observation.current,
                namespace_identity(IsolationStep::Namespaces, Path::new(CURRENT_PID_NAMESPACE))
                    .expect("current PID namespace must remain observable")
            );
        }

        #[test]
        fn pid_namespace_verification_rejects_missing_child_handoff() {
            let parent = NamespaceIdentity {
                device: 4,
                inode: 10,
            };
            let child = NamespaceIdentity {
                device: 4,
                inode: 11,
            };
            let error = validate_pid_namespace_child_entry(
                IsolationStep::Namespaces,
                PidNamespaceHandoff { parent, child },
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
            let parent = NamespaceIdentity {
                device: 4,
                inode: 10,
            };
            let child = NamespaceIdentity {
                device: 4,
                inode: 11,
            };

            validate_pid_namespace_child_entry(
                IsolationStep::Namespaces,
                PidNamespaceHandoff { parent, child },
                PidNamespaceObservation {
                    current: child,
                    for_children: child,
                },
            )
            .expect("the expected PID namespace child must pass verification");
        }

        #[test]
        fn pid_namespace_verification_rejects_a_nested_pending_namespace() {
            let parent = NamespaceIdentity {
                device: 4,
                inode: 10,
            };
            let child = NamespaceIdentity {
                device: 4,
                inode: 11,
            };
            let nested = NamespaceIdentity {
                device: 4,
                inode: 12,
            };
            let error = validate_pid_namespace_child_entry(
                IsolationStep::Namespaces,
                PidNamespaceHandoff { parent, child },
                PidNamespaceObservation {
                    current: child,
                    for_children: nested,
                },
            )
            .expect_err("a second pending PID namespace must fail verification");

            assert!(error.message.contains("different pending PID namespace"));
        }
    }
}

#[cfg(target_os = "linux")]
pub use implementation::LinuxBackend;

#[cfg(not(target_os = "linux"))]
mod unsupported {
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

    impl IsolationBackend for LinuxBackend {
        fn detect_capabilities(&mut self, _config: &IsolationConfig) -> CapabilityReport {
            CapabilityReport::unavailable(["runtime isolation requires Linux"])
        }

        fn apply_step(
            &mut self,
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
