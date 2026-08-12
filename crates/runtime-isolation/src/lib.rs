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
    BackendError, CapabilityReport, IsolatedChildProcess, IsolationBackend, IsolationError,
    IsolationReceipt, IsolationStep, NamespaceIdentity, NamespacePreparation, PidNamespaceChild,
    RuntimeIsolation, SpawnOutcome, apply, spawn_isolated,
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
        IsolatedChildProcess, IsolationBackend, IsolationConfig, IsolationError, IsolationReceipt,
        IsolationStep, LandlockConfig, NamespaceIdentity, NamespacePreparation, PidNamespaceChild,
        RootfsConfig, RuntimeIsolation, SeccompPolicy, SpawnOutcome, Syscall, TmpfsConfig, apply,
        spawn_isolated,
    };

    use std::{cell::Cell, num::NonZeroU32};

    #[derive(Clone, Copy)]
    enum MockSpawnRole {
        Parent,
        Child,
        Reject,
    }

    #[derive(Debug, Eq, PartialEq)]
    enum MockEvent {
        PrepareNamespaces,
        SpawnParent,
        SpawnChild,
        SpawnRejected,
        VerifyChild,
        Apply(IsolationStep),
    }

    struct MockBackend {
        events: Vec<MockEvent>,
        calls: Vec<IsolationStep>,
        rollbacks: Vec<IsolationStep>,
        fail_at: Option<IsolationStep>,
        report: CapabilityReport,
        spawn_role: MockSpawnRole,
        namespace_prepares: usize,
        child_verifications: usize,
        fail_child_verification: bool,
    }

    impl MockBackend {
        fn new() -> Self {
            Self {
                events: Vec::new(),
                calls: Vec::new(),
                rollbacks: Vec::new(),
                fail_at: None,
                report: CapabilityReport::supported(3),
                spawn_role: MockSpawnRole::Child,
                namespace_prepares: 0,
                child_verifications: 0,
                fail_child_verification: false,
            }
        }
    }

    impl IsolationBackend for MockBackend {
        fn detect_capabilities(&mut self, _config: &IsolationConfig) -> CapabilityReport {
            self.report.clone()
        }

        fn prepare_namespaces(
            &mut self,
            _config: &IsolationConfig,
        ) -> Result<NamespacePreparation, BackendError> {
            self.events.push(MockEvent::PrepareNamespaces);
            self.namespace_prepares += 1;
            Ok(NamespacePreparation::attest(
                NamespaceIdentity::from_kernel(4, 10),
                NamespaceIdentity::from_kernel(4, 11),
            ))
        }

        fn spawn_isolated<T, F>(
            &mut self,
            preparation: NamespacePreparation,
            child_entry: F,
        ) -> Result<SpawnOutcome<T>, BackendError>
        where
            F: FnOnce(&mut Self, NamespacePreparation) -> T,
        {
            match self.spawn_role {
                MockSpawnRole::Parent => {
                    self.events.push(MockEvent::SpawnParent);
                    Ok(SpawnOutcome::Parent(IsolatedChildProcess::attest(
                        NonZeroU32::new(42).expect("mock child PID is positive"),
                        preparation.child(),
                    )))
                }
                MockSpawnRole::Child => {
                    self.events.push(MockEvent::SpawnChild);
                    let child_result = child_entry(self, preparation);
                    Ok(SpawnOutcome::Child(child_result))
                }
                MockSpawnRole::Reject => {
                    self.events.push(MockEvent::SpawnRejected);
                    Err(BackendError::new(
                        IsolationStep::Namespaces,
                        "injected missing child handoff",
                        None,
                    ))
                }
            }
        }

        fn verify_pid_namespace_child(
            &mut self,
            preparation: NamespacePreparation,
        ) -> Result<PidNamespaceChild, BackendError> {
            self.events.push(MockEvent::VerifyChild);
            self.child_verifications += 1;
            if self.fail_child_verification {
                return Err(BackendError::new(
                    IsolationStep::Namespaces,
                    "injected child namespace mismatch",
                    None,
                ));
            }
            Ok(PidNamespaceChild::attest(preparation.child()))
        }

        fn apply_step(
            &mut self,
            step: IsolationStep,
            _config: &IsolationConfig,
        ) -> Result<(), BackendError> {
            if step == IsolationStep::Namespaces {
                return Err(BackendError::new(
                    step,
                    "namespace setup must use the explicit handoff API",
                    None,
                ));
            }
            self.events.push(MockEvent::Apply(step));
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
    fn successful_child_spawn_enforces_the_security_order() {
        let mut backend = MockBackend::new();
        let outcome = spawn_isolated(&mut backend, &test_config(), |receipt| receipt)
            .expect("mock child isolation must succeed");
        let SpawnOutcome::Child(receipt) = outcome else {
            panic!("child-role mock must return the child outcome");
        };
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
        assert_eq!(
            receipt.pid_namespace(),
            NamespaceIdentity::from_kernel(4, 11)
        );
        assert_eq!(backend.calls, expected[1..]);
        assert_eq!(backend.namespace_prepares, 1);
        assert_eq!(backend.child_verifications, 1);
        assert!(backend.rollbacks.is_empty());
        let mut expected_events = vec![
            MockEvent::PrepareNamespaces,
            MockEvent::SpawnChild,
            MockEvent::VerifyChild,
        ];
        expected_events.extend(expected[1..].iter().copied().map(MockEvent::Apply));
        assert_eq!(backend.events, expected_events);
    }

    #[test]
    fn parent_spawn_returns_only_child_process_ownership() {
        let mut backend = MockBackend::new();
        backend.spawn_role = MockSpawnRole::Parent;
        let workload_called = Cell::new(false);

        let outcome = spawn_isolated(&mut backend, &test_config(), |_| {
            workload_called.set(true);
        })
        .expect("mock parent spawn must succeed");
        let SpawnOutcome::Parent(child) = outcome else {
            panic!("parent-role mock must return the parent outcome");
        };

        assert_eq!(child.pid(), NonZeroU32::new(42).expect("positive PID"));
        assert_eq!(child.pid_namespace(), NamespaceIdentity::from_kernel(4, 11));
        assert!(!workload_called.get());
        assert_eq!(backend.namespace_prepares, 1);
        assert_eq!(backend.child_verifications, 0);
        assert!(backend.calls.is_empty());
        assert_eq!(
            backend.events,
            vec![MockEvent::PrepareNamespaces, MockEvent::SpawnParent]
        );
    }

    #[test]
    fn legacy_apply_rejects_before_namespace_preparation() {
        let mut backend = MockBackend::new();

        let error = apply(&mut backend, &test_config())
            .expect_err("legacy in-process apply must require explicit handoff");

        assert!(matches!(error, IsolationError::ChildHandoffRequired));
        assert_eq!(backend.namespace_prepares, 0);
        assert_eq!(backend.child_verifications, 0);
        assert!(backend.calls.is_empty());
        assert!(backend.events.is_empty());
    }

    #[test]
    fn missing_child_handoff_never_creates_a_receipt() {
        let mut backend = MockBackend::new();
        backend.spawn_role = MockSpawnRole::Reject;

        let error =
            RuntimeIsolation::spawn_isolated_transaction(&mut backend, &test_config(), |_| ())
                .expect_err("missing child handoff must fail closed");

        assert!(matches!(
            error,
            IsolationError::TerminationRequired {
                original,
                failures,
            } if original.message.contains("missing child handoff") && failures.is_empty()
        ));
        assert_eq!(backend.namespace_prepares, 1);
        assert_eq!(backend.child_verifications, 0);
        assert!(backend.calls.is_empty());
        assert_eq!(
            backend.events,
            vec![MockEvent::PrepareNamespaces, MockEvent::SpawnRejected]
        );
    }

    #[test]
    fn unverified_child_cannot_execute_remaining_steps_or_receive_a_receipt() {
        let mut backend = MockBackend::new();
        backend.fail_child_verification = true;

        let error =
            RuntimeIsolation::spawn_isolated_transaction(&mut backend, &test_config(), |_| ())
                .expect_err("PID namespace mismatch must fail before child setup");

        assert!(matches!(
            error,
            IsolationError::TerminationRequired { original, .. }
                if original.message.contains("child namespace mismatch")
        ));
        assert_eq!(backend.namespace_prepares, 1);
        assert_eq!(backend.child_verifications, 1);
        assert!(backend.calls.is_empty());
        assert_eq!(backend.rollbacks, vec![IsolationStep::Namespaces]);
        assert_eq!(
            backend.events,
            vec![
                MockEvent::PrepareNamespaces,
                MockEvent::SpawnChild,
                MockEvent::VerifyChild,
            ]
        );
    }

    #[test]
    fn a_failed_step_rolls_back_every_completed_step_in_reverse_order() {
        let mut backend = MockBackend::new();
        backend.fail_at = Some(IsolationStep::Landlock);

        let error =
            RuntimeIsolation::spawn_isolated_transaction(&mut backend, &test_config(), |_| ())
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
        let outcome: SpawnOutcome<IsolationReceipt> =
            spawn_isolated(&mut backend, &test_config(), |receipt| receipt).expect("success");
        let SpawnOutcome::Child(receipt) = outcome else {
            panic!("child-role mock must return a receipt only in the child");
        };
        assert_eq!(receipt.steps().len(), 13);
        assert_eq!(receipt.steps()[0], IsolationStep::Namespaces);
    }
}
