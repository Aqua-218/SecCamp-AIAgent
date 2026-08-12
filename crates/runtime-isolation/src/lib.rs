//! Ordered Linux process isolation for untrusted workloads.
//!
//! The public API deliberately separates policy validation and orchestration
//! from privileged operations. [`LinuxBackend`] is the production backend;
//! [`IsolationBackend`] can be implemented by a test double without executing
//! privileged syscalls.

#![deny(unsafe_op_in_unsafe_fn)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::must_use_candidate)]

mod backend;
mod config;
mod linux;
mod syscall;

pub use backend::{
    BackendError, CapabilityReport, IsolationBackend, IsolationError, IsolationReceipt,
    IsolationStep, RuntimeIsolation, apply,
};
pub use config::{
    BindMountConfig, CgroupConfig, IdentityMap, IsolationConfig, LandlockConfig, RootfsConfig,
    TmpfsConfig,
};
pub use linux::LinuxBackend;
pub use syscall::{SeccompPolicy, Syscall};

#[cfg(test)]
mod tests {
    use super::{
        BackendError, BindMountConfig, CapabilityReport, CgroupConfig, IdentityMap,
        IsolationBackend, IsolationConfig, IsolationError, IsolationReceipt, IsolationStep,
        LandlockConfig, RootfsConfig, RuntimeIsolation, SeccompPolicy, Syscall, TmpfsConfig, apply,
    };

    struct MockBackend {
        calls: Vec<IsolationStep>,
        rollbacks: Vec<IsolationStep>,
        fail_at: Option<IsolationStep>,
        report: CapabilityReport,
    }

    impl MockBackend {
        fn new() -> Self {
            Self {
                calls: Vec::new(),
                rollbacks: Vec::new(),
                fail_at: None,
                report: CapabilityReport::supported(3),
            }
        }
    }

    impl IsolationBackend for MockBackend {
        fn detect_capabilities(&mut self, _config: &IsolationConfig) -> CapabilityReport {
            self.report.clone()
        }

        fn apply_step(
            &mut self,
            step: IsolationStep,
            _config: &IsolationConfig,
        ) -> Result<(), BackendError> {
            self.calls.push(step);
            if self.fail_at == Some(step) {
                return Err(BackendError::new(step, "injected failure", None));
            }
            Ok(())
        }

        fn rollback_step(
            &mut self,
            step: IsolationStep,
            _config: &IsolationConfig,
        ) -> Result<(), BackendError> {
            self.rollbacks.push(step);
            Ok(())
        }
    }

    fn test_config() -> IsolationConfig {
        let rootfs = RootfsConfig::new(
            "/var/lib/luna/rootfs",
            "/mnt/luna-rootfs",
            "/mnt/luna-rootfs/.old_root",
        );
        let workspace = BindMountConfig::new("/run/luna/capfs", "/workspace");
        let tmpfs = TmpfsConfig::new("/tmp", 8 * 1024 * 1024);
        let cgroup = CgroupConfig::new("/sys/fs/cgroup", "luna-test", 64 * 1024 * 1024, 64);
        let landlock = LandlockConfig::new(3, ["/"], ["/workspace"]);
        let seccomp = SeccompPolicy::default();
        IsolationConfig::new(
            rootfs,
            workspace,
            tmpfs,
            cgroup,
            landlock,
            seccomp,
            IdentityMap::new(1000, 1000),
        )
    }

    #[test]
    fn successful_apply_enforces_the_security_order() {
        let mut backend = MockBackend::new();
        let receipt = apply(&mut backend, &test_config()).expect("mock isolation must succeed");
        let expected = vec![
            IsolationStep::Namespaces,
            IsolationStep::IdentityMap,
            IsolationStep::CgroupV2,
            IsolationStep::ReadOnlyRootfs,
            IsolationStep::Workspace,
            IsolationStep::LimitedTmpfs,
            IsolationStep::MaskProc,
            IsolationStep::MaskDevices,
            IsolationStep::CloseInheritedFileDescriptors,
            IsolationStep::Landlock,
            IsolationStep::DropCapabilities,
            IsolationStep::NoNewPrivs,
            IsolationStep::Seccomp,
        ];
        assert_eq!(receipt.steps(), expected.as_slice());
        assert_eq!(backend.calls, expected);
        assert!(backend.rollbacks.is_empty());
    }

    #[test]
    fn a_failed_step_rolls_back_every_completed_step_in_reverse_order() {
        let mut backend = MockBackend::new();
        backend.fail_at = Some(IsolationStep::Landlock);

        let error = RuntimeIsolation::apply_transaction(&mut backend, &test_config())
            .expect_err("failure must propagate");
        assert!(matches!(
            error,
            IsolationError::TerminationRequired {
                failures,
                ..
            } if failures.is_empty()
        ));
        assert_eq!(
            backend.rollbacks,
            vec![
                IsolationStep::CloseInheritedFileDescriptors,
                IsolationStep::MaskDevices,
                IsolationStep::MaskProc,
                IsolationStep::LimitedTmpfs,
                IsolationStep::Workspace,
                IsolationStep::ReadOnlyRootfs,
                IsolationStep::CgroupV2,
                IsolationStep::IdentityMap,
                IsolationStep::Namespaces,
            ]
        );
    }

    #[test]
    fn insufficient_capabilities_are_reported_before_any_mutation() {
        let mut backend = MockBackend::new();
        backend.report = CapabilityReport::unavailable(vec!["cgroup v2 is not writable"]);

        let error = apply(&mut backend, &test_config()).expect_err("unsupported host must fail");
        assert!(matches!(error, IsolationError::CapabilityUnavailable(_)));
        assert!(backend.calls.is_empty());
    }

    #[test]
    fn a_kernel_with_an_older_landlock_abi_is_rejected() {
        let mut backend = MockBackend::new();
        backend.report = CapabilityReport::supported(2);

        let error = apply(&mut backend, &test_config()).expect_err("ABI downgrade must fail");
        assert!(matches!(error, IsolationError::CapabilityUnavailable(_)));
        assert!(backend.calls.is_empty());
    }

    #[test]
    fn malformed_paths_and_unbounded_tmpfs_are_rejected_before_backend_calls() {
        let rootfs = RootfsConfig::new(
            "relative/rootfs",
            "/mnt/luna-rootfs",
            "/mnt/luna-rootfs/.old_root",
        );
        let workspace = BindMountConfig::new("/run/luna/capfs", "/workspace");
        let tmpfs = TmpfsConfig::new("/tmp", 0);
        let cgroup = CgroupConfig::new("/sys/fs/cgroup", "luna-test", 64 * 1024 * 1024, 64);
        let landlock = LandlockConfig::new(3, ["/"], ["/workspace"]);
        let config = IsolationConfig::new(
            rootfs,
            workspace,
            tmpfs,
            cgroup,
            landlock,
            SeccompPolicy::default(),
            IdentityMap::new(1000, 1000),
        );
        let mut backend = MockBackend::new();

        let error = apply(&mut backend, &config).expect_err("invalid config must fail");
        assert!(matches!(error, IsolationError::InvalidConfig(_)));
        assert!(backend.calls.is_empty());
    }

    #[test]
    fn forbidden_network_and_namespace_syscalls_are_rejected_from_allowlist() {
        for syscall in [
            Syscall::Socket,
            Syscall::Connect,
            Syscall::IoUringSetup,
            Syscall::IoUringEnter,
            Syscall::IoUringRegister,
            Syscall::Mount,
            Syscall::OpenTree,
            Syscall::MoveMount,
            Syscall::Fsopen,
            Syscall::Fsconfig,
            Syscall::Fsmount,
            Syscall::Fspick,
            Syscall::MountSetattr,
            Syscall::Unshare,
            Syscall::Clone,
            Syscall::Clone3,
            Syscall::Ptrace,
            Syscall::Bpf,
            Syscall::PerfEventOpen,
            Syscall::ProcessVmReadv,
            Syscall::ProcessVmWritev,
            Syscall::Userfaultfd,
            Syscall::OpenByHandleAt,
        ] {
            let error = SeccompPolicy::new([syscall]).expect_err("forbidden syscall must fail");
            assert!(error.to_string().contains("forbidden"));
        }
    }

    #[test]
    fn writable_landlock_paths_cannot_escape_the_workspace() {
        let config = IsolationConfig::new(
            RootfsConfig::new(
                "/var/lib/luna/rootfs",
                "/mnt/luna-rootfs",
                "/mnt/luna-rootfs/.old_root",
            ),
            BindMountConfig::new("/run/luna/capfs", "/workspace"),
            TmpfsConfig::new("/tmp", 8 * 1024 * 1024),
            CgroupConfig::new("/sys/fs/cgroup", "luna-test", 64 * 1024 * 1024, 64),
            LandlockConfig::new(3, ["/"], ["/"]),
            SeccompPolicy::default(),
            IdentityMap::new(1000, 1000),
        );
        let mut backend = MockBackend::new();

        let error = apply(&mut backend, &config).expect_err("root-wide writes must be rejected");
        assert!(matches!(error, IsolationError::InvalidConfig(_)));
        assert!(backend.calls.is_empty());
    }

    #[test]
    fn empty_allowlist_is_rejected_instead_of_installing_an_unstartable_filter() {
        let error = SeccompPolicy::new(std::iter::empty::<Syscall>())
            .expect_err("empty seccomp policy must fail closed");
        assert!(error.to_string().contains("must not be empty"));
    }

    #[test]
    fn receipt_is_immutable_after_success() {
        let mut backend = MockBackend::new();
        let receipt: IsolationReceipt = apply(&mut backend, &test_config()).expect("success");
        assert_eq!(receipt.steps().len(), 13);
        assert_eq!(receipt.steps()[0], IsolationStep::Namespaces);
    }
}
