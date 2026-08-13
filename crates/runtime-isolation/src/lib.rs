//! Ordered Linux process isolation for untrusted workloads.
//!
//! The public API deliberately separates policy validation and orchestration
//! from privileged operations. [`LinuxBackend`] is the only production backend;
//! [`IsolationBackend`] is sealed so downstream safe code cannot forge kernel
//! isolation attestations or directly invoke process-global setup operations.

#![deny(unsafe_op_in_unsafe_fn)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::must_use_candidate)]

mod backend;
mod config;
mod linux;
mod syscall;

pub use backend::{
    BackendError, CapabilityReport, ChildExit, ChildProcessError, ChildStartupFailure,
    ChildStartupReady, ChildStartupStatus, IsolatedChildProcess, IsolationBackend, IsolationError,
    IsolationReceipt, IsolationStep, NamespaceIdentity, NamespacePreparation, PidNamespaceChild,
    RuntimeIsolation, SpawnOutcome, apply, spawn_isolated,
};
pub use config::{
    BindMountConfig, CgroupConfig, ControlChannelConfig, IdentityMap, IsolationConfig,
    LandlockConfig, RootfsConfig, TmpfsConfig,
};
pub use linux::LinuxBackend;
pub use syscall::{SeccompPolicy, Syscall};

#[cfg(test)]
mod tests {
    use crate::backend::{ChildStartupNotifier, private::OperationPermit};

    use super::{
        BackendError, BindMountConfig, CapabilityReport, CgroupConfig, IdentityMap,
        IsolatedChildProcess, IsolationBackend, IsolationConfig, IsolationError, IsolationReceipt,
        IsolationStep, LandlockConfig, NamespaceIdentity, NamespacePreparation, PidNamespaceChild,
        RootfsConfig, RuntimeIsolation, SeccompPolicy, SpawnOutcome, Syscall, TmpfsConfig, apply,
        spawn_isolated,
    };

    use std::{
        cell::Cell,
        fs::File,
        io::Read,
        num::NonZeroU32,
        os::fd::{FromRawFd, OwnedFd},
    };

    const STARTUP_MESSAGE_LEN: usize = 32;

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
        fail_errno: Option<i32>,
        rollback_fail_at: Option<IsolationStep>,
        report: CapabilityReport,
        spawn_role: MockSpawnRole,
        namespace_prepares: usize,
        child_verifications: usize,
        fail_child_verification: bool,
        startup_messages: Vec<[u8; STARTUP_MESSAGE_LEN]>,
    }

    impl MockBackend {
        fn new() -> Self {
            Self {
                events: Vec::new(),
                calls: Vec::new(),
                rollbacks: Vec::new(),
                fail_at: None,
                fail_errno: None,
                rollback_fail_at: None,
                report: CapabilityReport::supported(3),
                spawn_role: MockSpawnRole::Child,
                namespace_prepares: 0,
                child_verifications: 0,
                fail_child_verification: false,
                startup_messages: Vec::new(),
            }
        }
    }

    #[allow(private_bounds, private_interfaces)]
    impl IsolationBackend for MockBackend {
        fn detect_capabilities(&mut self, _config: &IsolationConfig) -> CapabilityReport {
            self.report.clone()
        }

        fn prepare_namespaces(
            &mut self,
            _permit: OperationPermit,
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
            _permit: OperationPermit,
            preparation: NamespacePreparation,
            child_entry: F,
        ) -> Result<SpawnOutcome<T>, BackendError>
        where
            F: FnOnce(&mut Self, NamespacePreparation, ChildStartupNotifier) -> T,
        {
            match self.spawn_role {
                MockSpawnRole::Parent => {
                    self.events.push(MockEvent::SpawnParent);
                    Ok(SpawnOutcome::Parent(
                        IsolatedChildProcess::unattested_for_test(
                            NonZeroU32::new(42).expect("mock child PID is positive"),
                            preparation.child(),
                        ),
                    ))
                }
                MockSpawnRole::Child => {
                    self.events.push(MockEvent::SpawnChild);
                    let (reader, writer) = startup_pipe();
                    let child_result =
                        child_entry(self, preparation, ChildStartupNotifier::from_fd(writer));
                    self.startup_messages.push(read_startup_message(reader));
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
            _permit: OperationPermit,
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
            _permit: OperationPermit,
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
                return Err(BackendError::new(step, "injected failure", self.fail_errno));
            }
            Ok(())
        }

        fn rollback_step(
            &mut self,
            _permit: OperationPermit,
            step: IsolationStep,
            _config: &IsolationConfig,
        ) -> Result<(), BackendError> {
            self.rollbacks.push(step);
            if self.rollback_fail_at == Some(step) {
                return Err(BackendError::new(
                    step,
                    "injected rollback failure",
                    Some(libc::EBUSY),
                ));
            }
            Ok(())
        }
    }

    fn startup_pipe() -> (OwnedFd, OwnedFd) {
        let mut descriptors = [-1; 2];
        // SAFETY: the array contains storage for exactly two returned descriptors.
        let result = unsafe { libc::pipe2(descriptors.as_mut_ptr(), libc::O_CLOEXEC) };
        assert_eq!(result, 0, "mock startup pipe creation must succeed");
        // SAFETY: successful pipe2 returns ownership of both descriptors.
        let reader = unsafe { OwnedFd::from_raw_fd(descriptors[0]) };
        // SAFETY: successful pipe2 returns ownership of both descriptors.
        let writer = unsafe { OwnedFd::from_raw_fd(descriptors[1]) };
        (reader, writer)
    }

    fn read_startup_message(reader: OwnedFd) -> [u8; STARTUP_MESSAGE_LEN] {
        let mut reader = File::from(reader);
        let mut message = [0_u8; STARTUP_MESSAGE_LEN];
        reader
            .read_exact(&mut message)
            .expect("mock child must emit one complete startup message");
        message
    }

    fn assert_ready_message(message: &[u8; STARTUP_MESSAGE_LEN], namespace: NamespaceIdentity) {
        assert_common_startup_header(message, 1, 12, 0);
        assert_eq!(read_i32(message, 8), i32::MIN);
        assert_eq!(read_u64(message, 12), namespace.device());
        assert_eq!(read_u64(message, 20), namespace.inode());
        assert_eq!(read_u32(message, 28), 0);
    }

    fn assert_failure_message(
        message: &[u8; STARTUP_MESSAGE_LEN],
        step_code: u8,
        errno: Option<i32>,
        rollback_failure_count: u32,
    ) {
        assert_common_startup_header(message, 2, step_code, 1);
        assert_eq!(read_i32(message, 8), errno.unwrap_or(i32::MIN));
        assert_eq!(read_u64(message, 12), 0);
        assert_eq!(read_u64(message, 20), 0);
        assert_eq!(read_u32(message, 28), rollback_failure_count);
    }

    fn assert_common_startup_header(
        message: &[u8; STARTUP_MESSAGE_LEN],
        kind: u8,
        step_code: u8,
        flags: u8,
    ) {
        assert_eq!(&message[..4], b"LISO");
        assert_eq!(message[4], 1);
        assert_eq!(message[5], kind);
        assert_eq!(message[6], step_code);
        assert_eq!(message[7], flags);
    }

    fn read_i32(message: &[u8; STARTUP_MESSAGE_LEN], offset: usize) -> i32 {
        i32::from_le_bytes(
            message[offset..offset + 4]
                .try_into()
                .expect("fixed-width i32 startup field"),
        )
    }

    fn read_u32(message: &[u8; STARTUP_MESSAGE_LEN], offset: usize) -> u32 {
        u32::from_le_bytes(
            message[offset..offset + 4]
                .try_into()
                .expect("fixed-width u32 startup field"),
        )
    }

    fn read_u64(message: &[u8; STARTUP_MESSAGE_LEN], offset: usize) -> u64 {
        u64::from_le_bytes(
            message[offset..offset + 8]
                .try_into()
                .expect("fixed-width u64 startup field"),
        )
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
        assert_eq!(backend.startup_messages.len(), 1);
        assert_ready_message(
            &backend.startup_messages[0],
            NamespaceIdentity::from_kernel(4, 11),
        );
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
        assert!(backend.startup_messages.is_empty());
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
        assert!(backend.startup_messages.is_empty());
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
        assert_eq!(backend.startup_messages.len(), 1);
        assert_failure_message(&backend.startup_messages[0], 0, None, 0);
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
        assert_eq!(backend.startup_messages.len(), 1);
        assert_failure_message(&backend.startup_messages[0], 9, None, 0);
    }

    #[test]
    fn child_failure_message_preserves_errno_and_rollback_failure_count() {
        let mut backend = MockBackend::new();
        backend.fail_at = Some(IsolationStep::Landlock);
        backend.fail_errno = Some(libc::EACCES);
        backend.rollback_fail_at = Some(IsolationStep::Workspace);

        let error =
            RuntimeIsolation::spawn_isolated_transaction(&mut backend, &test_config(), |_| ())
                .expect_err("child isolation failure must propagate");

        assert!(matches!(
            error,
            IsolationError::TerminationRequired {
                original,
                failures,
            } if original.errno == Some(libc::EACCES)
                && failures.len() == 1
                && failures[0].step == IsolationStep::Workspace
                && failures[0].errno == Some(libc::EBUSY)
        ));
        assert_eq!(backend.startup_messages.len(), 1);
        assert_failure_message(&backend.startup_messages[0], 9, Some(libc::EACCES), 1);
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
