//! Contract tests for `session-orchestrator`.
//!
//! Specification references: `docs/session-orchestrator/contracts.md` and
//! `docs/design/runtime-isolation.md`. These tests cover the startup state
//! machine, reverse-order rollback, identity freshness, lease binding, and
//! retryable stop cleanup. All external systems are deterministic mocks.

use std::{cell::RefCell, path::PathBuf, rc::Rc};

use session_orchestrator::{
    BackendError, BrokerBackend, BrokerLease, CapabilityBackend, CapabilityLease,
    CapabilityRevocationBackend, CleanupStage, CryptographicRandom, EntropyError, IdentityKind,
    IdentityLedger, LedgerError, LifecycleState, SessionId, SessionInfo, SessionOrchestrator,
    SnapshotDescriptor, SnapshotId, SnapshotIdentity, StartFailure, StartStage, StopError,
    VmBackend, VmLease, WorkloadBackend, WorkloadLease, WorkspaceBackend, WorkspaceId,
    WorkspaceLease, WorkspaceTemplateId,
};

#[derive(Clone, Default)]
struct CallLog(Rc<RefCell<Vec<&'static str>>>);

impl CallLog {
    fn push(&self, call: &'static str) {
        self.0.borrow_mut().push(call);
    }

    fn values(&self) -> Vec<&'static str> {
        self.0.borrow().clone()
    }
}

#[derive(Debug)]
struct SequenceRandom {
    values: Vec<[u8; 16]>,
    next: usize,
}

impl SequenceRandom {
    fn new(values: Vec<[u8; 16]>) -> Self {
        Self { values, next: 0 }
    }
}

impl CryptographicRandom for SequenceRandom {
    fn random_128(&mut self) -> Result<[u8; 16], EntropyError> {
        let value = self
            .values
            .get(self.next)
            .copied()
            .ok_or_else(|| EntropyError::new("test entropy sequence exhausted"))?;
        self.next += 1;
        Ok(value)
    }
}

struct FailingLedger {
    error: LedgerError,
}

impl IdentityLedger for FailingLedger {
    fn reserve_batch(
        &mut self,
        _identities: &[(IdentityKind, [u8; 16])],
    ) -> Result<(), LedgerError> {
        Err(self.error.clone())
    }
}

fn identity_values(start: u8, count: usize) -> Vec<[u8; 16]> {
    (0..count)
        .map(|offset| {
            [start.wrapping_add(u8::try_from(offset).expect("test offset fits in u8")); 16]
        })
        .collect()
}

fn snapshot() -> SnapshotDescriptor {
    SnapshotDescriptor::clean(SnapshotId::new([0xA0; 16]))
}

fn template() -> WorkspaceTemplateId {
    WorkspaceTemplateId::new("workspace-template")
}

#[derive(Default)]
struct MockWorkspace {
    log: CallLog,
    fail_clone: bool,
    fail_isolate: bool,
    foreign_session: Option<SessionId>,
}

impl WorkspaceBackend for MockWorkspace {
    fn clone_workspace(
        &mut self,
        identity: &session_orchestrator::SessionIdentity,
        _template: &WorkspaceTemplateId,
    ) -> Result<WorkspaceLease, BackendError> {
        self.log.push("workspace.clone");
        if self.fail_clone {
            return Err(BackendError::new("workspace clone failed"));
        }
        Ok(WorkspaceLease::new(
            self.foreign_session.unwrap_or(identity.session_id()),
            identity.workspace_id(),
        ))
    }

    fn isolate_workspace(&mut self, _lease: &WorkspaceLease) -> Result<(), BackendError> {
        self.log.push("workspace.isolate");
        if self.fail_isolate {
            return Err(BackendError::new("workspace isolation failed"));
        }
        Ok(())
    }
}

#[derive(Default)]
struct MockBroker {
    log: CallLog,
    fail_establish: bool,
    fail_running_check: bool,
    fail_close: bool,
    foreign_session: Option<SessionId>,
}

impl BrokerBackend for MockBroker {
    fn establish_broker_session(
        &mut self,
        identity: &session_orchestrator::SessionIdentity,
    ) -> Result<BrokerLease, BackendError> {
        self.log.push("broker.establish");
        if self.fail_establish {
            return Err(BackendError::new("Broker session establishment failed"));
        }
        Ok(BrokerLease::new(
            self.foreign_session.unwrap_or(identity.session_id()),
            identity.broker_session_id(),
        ))
    }

    fn ensure_broker_session_running(&mut self, _lease: &BrokerLease) -> Result<(), BackendError> {
        self.log.push("broker.ensure-running");
        if self.fail_running_check {
            Err(BackendError::new(
                "Broker service exited before workload release",
            ))
        } else {
            Ok(())
        }
    }

    fn close_broker_session(&mut self, _lease: &BrokerLease) -> Result<(), BackendError> {
        self.log.push("broker.close");
        if self.fail_close {
            return Err(BackendError::new("Broker session close failed"));
        }
        Ok(())
    }
}

#[derive(Default)]
struct MockVm {
    log: CallLog,
    fail_start: bool,
    fail_kill: bool,
    foreign_session: Option<SessionId>,
    foreign_workspace: Option<WorkspaceId>,
}

impl VmBackend for MockVm {
    fn start_vm(
        &mut self,
        _snapshot: &SnapshotDescriptor,
        identity: &session_orchestrator::SessionIdentity,
        _workspace: &WorkspaceLease,
        _broker: &BrokerLease,
    ) -> Result<VmLease, BackendError> {
        self.log.push("vm.start");
        if self.fail_start {
            return Err(BackendError::new("Firecracker start failed"));
        }
        Ok(VmLease::new(
            self.foreign_session.unwrap_or(identity.session_id()),
            identity.vm_id(),
            self.foreign_workspace.unwrap_or(identity.workspace_id()),
            identity.broker_session_id(),
        ))
    }

    fn kill_vm(&mut self, _lease: &VmLease) -> Result<(), BackendError> {
        self.log.push("vm.kill");
        if self.fail_kill {
            return Err(BackendError::new("Firecracker kill failed"));
        }
        Ok(())
    }
}

#[derive(Default)]
struct MockCapability {
    log: CallLog,
    fail_inject: bool,
    fail_revoke: bool,
    foreign_session: Option<SessionId>,
}

impl CapabilityRevocationBackend for MockCapability {
    fn revoke_root_capability(&mut self, _lease: &CapabilityLease) -> Result<(), BackendError> {
        self.log.push("capability.revoke");
        if self.fail_revoke {
            return Err(BackendError::new("capability revoke failed"));
        }
        Ok(())
    }
}

impl CapabilityBackend<u64> for MockCapability {
    fn inject_root_capability(
        &mut self,
        identity: &session_orchestrator::SessionIdentity,
        _grant: &u64,
    ) -> Result<CapabilityLease, BackendError> {
        self.log.push("capability.inject");
        if self.fail_inject {
            return Err(BackendError::new("root capability injection failed"));
        }
        Ok(CapabilityLease::new(
            self.foreign_session.unwrap_or(identity.session_id()),
            identity.subject_id(),
            identity.capability_id(),
        ))
    }
}

#[derive(Default)]
struct MockWorkload {
    log: CallLog,
    fail_release: bool,
    foreign_session: Option<SessionId>,
}

impl WorkloadBackend for MockWorkload {
    fn release_workload(
        &mut self,
        identity: &session_orchestrator::SessionIdentity,
        _vm: &VmLease,
        _capability: &CapabilityLease,
    ) -> Result<WorkloadLease, BackendError> {
        self.log.push("workload.release");
        if self.fail_release {
            return Err(BackendError::new("workload release failed"));
        }
        Ok(WorkloadLease::new(
            self.foreign_session.unwrap_or(identity.session_id()),
            identity.vm_id(),
            identity.subject_id(),
            identity.capability_id(),
        ))
    }
}

fn start_with(
    random: SequenceRandom,
    workspace: &mut MockWorkspace,
    broker: &mut MockBroker,
    vm: &mut MockVm,
    capability: &mut MockCapability,
    workload: &mut MockWorkload,
) -> Result<(SessionOrchestrator<SequenceRandom>, SessionInfo), StartFailure> {
    let mut orchestrator = SessionOrchestrator::new(random);
    let result = orchestrator.start_session(
        &snapshot(),
        &template(),
        &7_u64,
        workspace,
        broker,
        vm,
        capability,
        workload,
    );
    result
        .map(|info| (orchestrator, info))
        .map_err(|error| error.failure().clone())
}

// Requirement: one session commits workspace, Broker, VM, root capability,
// and workload in the documented order. Category: normal/state transition.
// Risk: critical.
#[test]
fn startup_and_stop_follow_the_linearized_lifecycle_order() {
    let log = CallLog::default();
    let mut workspace = MockWorkspace {
        log: log.clone(),
        ..MockWorkspace::default()
    };
    let mut broker = MockBroker {
        log: log.clone(),
        ..MockBroker::default()
    };
    let mut vm = MockVm {
        log: log.clone(),
        ..MockVm::default()
    };
    let mut capability = MockCapability {
        log: log.clone(),
        ..MockCapability::default()
    };
    let mut workload = MockWorkload {
        log: log.clone(),
        ..MockWorkload::default()
    };
    let (mut orchestrator, info) = start_with(
        SequenceRandom::new(identity_values(1, 7)),
        &mut workspace,
        &mut broker,
        &mut vm,
        &mut capability,
        &mut workload,
    )
    .expect("normal startup must commit");

    assert_eq!(orchestrator.state(), LifecycleState::Running);
    assert_eq!(orchestrator.active_session(), Some(info));
    assert_ne!(
        info.identity().session_id().as_bytes(),
        info.identity().vm_id().as_bytes()
    );
    assert_eq!(
        log.values(),
        vec![
            "workspace.clone",
            "broker.establish",
            "vm.start",
            "capability.inject",
            "broker.ensure-running",
            "workload.release"
        ]
    );

    orchestrator
        .stop_session(&mut workspace, &mut broker, &mut vm, &mut capability)
        .expect("normal stop must commit");
    assert_eq!(orchestrator.state(), LifecycleState::Closed);
    assert!(orchestrator.active_session().is_none());
    assert!(matches!(
        orchestrator.stop_session(&mut workspace, &mut broker, &mut vm, &mut capability),
        Err(StopError::InvalidState(LifecycleState::Closed))
    ));
    assert_eq!(
        log.values(),
        vec![
            "workspace.clone",
            "broker.establish",
            "vm.start",
            "capability.inject",
            "broker.ensure-running",
            "workload.release",
            "capability.revoke",
            "vm.kill",
            "broker.close",
            "workspace.isolate"
        ]
    );
}

// Requirement: each startup failure rolls back every committed dependency in
// reverse order. Category: error/rollback. Risk: critical.
#[test]
fn workspace_failure_has_no_downstream_side_effect() {
    let log = CallLog::default();
    let mut workspace = MockWorkspace {
        log: log.clone(),
        fail_clone: true,
        ..MockWorkspace::default()
    };
    let mut broker = MockBroker {
        log: log.clone(),
        ..MockBroker::default()
    };
    let mut vm = MockVm {
        log: log.clone(),
        ..MockVm::default()
    };
    let mut capability = MockCapability {
        log: log.clone(),
        ..MockCapability::default()
    };
    let mut workload = MockWorkload {
        log: log.clone(),
        ..MockWorkload::default()
    };

    let error = start_with(
        SequenceRandom::new(identity_values(10, 7)),
        &mut workspace,
        &mut broker,
        &mut vm,
        &mut capability,
        &mut workload,
    )
    .expect_err("workspace failure must reject startup");
    assert!(matches!(error, StartFailure::Backend(_)));
    assert_eq!(log.values(), vec!["workspace.clone"]);
}

// Requirement: Broker failure isolates an already-cloned workspace. Category:
// error/rollback. Risk: critical.
#[test]
fn broker_failure_rolls_back_workspace() {
    let log = CallLog::default();
    let mut workspace = MockWorkspace {
        log: log.clone(),
        ..MockWorkspace::default()
    };
    let mut broker = MockBroker {
        log: log.clone(),
        fail_establish: true,
        ..MockBroker::default()
    };
    let mut vm = MockVm {
        log: log.clone(),
        ..MockVm::default()
    };
    let mut capability = MockCapability {
        log: log.clone(),
        ..MockCapability::default()
    };
    let mut workload = MockWorkload {
        log: log.clone(),
        ..MockWorkload::default()
    };

    let error = start_with(
        SequenceRandom::new(identity_values(20, 7)),
        &mut workspace,
        &mut broker,
        &mut vm,
        &mut capability,
        &mut workload,
    )
    .expect_err("Broker failure must reject startup");
    assert!(matches!(error, StartFailure::Backend(_)));
    assert_eq!(
        log.values(),
        vec!["workspace.clone", "broker.establish", "workspace.isolate"]
    );
}

// Requirement: Firecracker failure closes Broker before isolating workspace.
// Category: error/rollback. Risk: critical.
#[test]
fn vm_failure_rolls_back_broker_then_workspace() {
    let log = CallLog::default();
    let mut workspace = MockWorkspace {
        log: log.clone(),
        ..MockWorkspace::default()
    };
    let mut broker = MockBroker {
        log: log.clone(),
        ..MockBroker::default()
    };
    let mut vm = MockVm {
        log: log.clone(),
        fail_start: true,
        ..MockVm::default()
    };
    let mut capability = MockCapability {
        log: log.clone(),
        ..MockCapability::default()
    };
    let mut workload = MockWorkload {
        log: log.clone(),
        ..MockWorkload::default()
    };

    let error = start_with(
        SequenceRandom::new(identity_values(30, 7)),
        &mut workspace,
        &mut broker,
        &mut vm,
        &mut capability,
        &mut workload,
    )
    .expect_err("VM failure must reject startup");
    assert!(matches!(error, StartFailure::Backend(_)));
    assert_eq!(
        log.values(),
        vec![
            "workspace.clone",
            "broker.establish",
            "vm.start",
            "broker.close",
            "workspace.isolate"
        ]
    );
}

// Requirement: root capability failure kills VM before closing the Broker and
// isolating workspace. Category: error/rollback. Risk: critical.
#[test]
fn capability_failure_rolls_back_vm_broker_and_workspace() {
    let log = CallLog::default();
    let mut workspace = MockWorkspace {
        log: log.clone(),
        ..MockWorkspace::default()
    };
    let mut broker = MockBroker {
        log: log.clone(),
        ..MockBroker::default()
    };
    let mut vm = MockVm {
        log: log.clone(),
        ..MockVm::default()
    };
    let mut capability = MockCapability {
        log: log.clone(),
        fail_inject: true,
        ..MockCapability::default()
    };
    let mut workload = MockWorkload {
        log: log.clone(),
        ..MockWorkload::default()
    };

    let error = start_with(
        SequenceRandom::new(identity_values(40, 7)),
        &mut workspace,
        &mut broker,
        &mut vm,
        &mut capability,
        &mut workload,
    )
    .expect_err("capability failure must reject startup");
    assert!(matches!(error, StartFailure::Backend(_)));
    assert_eq!(
        log.values(),
        vec![
            "workspace.clone",
            "broker.establish",
            "vm.start",
            "capability.inject",
            "vm.kill",
            "broker.close",
            "workspace.isolate"
        ]
    );
}

// Requirement: a Broker worker that exits during paused-VM startup is detected
// after capability injection and before workload code can run.
// Category: integration/lifecycle. Risk: critical.
#[test]
fn broker_exit_before_workload_release_fails_closed() {
    let log = CallLog::default();
    let mut workspace = MockWorkspace {
        log: log.clone(),
        ..MockWorkspace::default()
    };
    let mut broker = MockBroker {
        log: log.clone(),
        fail_running_check: true,
        ..MockBroker::default()
    };
    let mut vm = MockVm {
        log: log.clone(),
        ..MockVm::default()
    };
    let mut capability = MockCapability {
        log: log.clone(),
        ..MockCapability::default()
    };
    let mut workload = MockWorkload {
        log: log.clone(),
        ..MockWorkload::default()
    };

    let error = start_with(
        SequenceRandom::new(identity_values(45, 7)),
        &mut workspace,
        &mut broker,
        &mut vm,
        &mut capability,
        &mut workload,
    )
    .expect_err("an exited Broker must reject workload release");

    assert!(matches!(error, StartFailure::Backend(_)));
    assert_eq!(
        log.values(),
        vec![
            "workspace.clone",
            "broker.establish",
            "vm.start",
            "capability.inject",
            "broker.ensure-running",
            "capability.revoke",
            "vm.kill",
            "broker.close",
            "workspace.isolate",
        ]
    );
}

// Requirement: workload failure revokes the root before killing its VM.
// Category: error/rollback. Risk: critical.
#[test]
fn workload_failure_revokes_then_kills_all_resources() {
    let log = CallLog::default();
    let mut workspace = MockWorkspace {
        log: log.clone(),
        ..MockWorkspace::default()
    };
    let mut broker = MockBroker {
        log: log.clone(),
        ..MockBroker::default()
    };
    let mut vm = MockVm {
        log: log.clone(),
        ..MockVm::default()
    };
    let mut capability = MockCapability {
        log: log.clone(),
        ..MockCapability::default()
    };
    let mut workload = MockWorkload {
        log: log.clone(),
        fail_release: true,
        ..MockWorkload::default()
    };

    let error = start_with(
        SequenceRandom::new(identity_values(50, 7)),
        &mut workspace,
        &mut broker,
        &mut vm,
        &mut capability,
        &mut workload,
    )
    .expect_err("workload failure must reject startup");
    assert!(matches!(error, StartFailure::Backend(_)));
    assert_eq!(
        log.values(),
        vec![
            "workspace.clone",
            "broker.establish",
            "vm.start",
            "capability.inject",
            "broker.ensure-running",
            "workload.release",
            "capability.revoke",
            "vm.kill",
            "broker.close",
            "workspace.isolate"
        ]
    );
}

// Requirement: rollback failures remain visible to the caller. Category:
// error reporting. Risk: high.
#[test]
fn rollback_failure_is_reported_without_claiming_success() {
    let log = CallLog::default();
    let mut workspace = MockWorkspace {
        log: log.clone(),
        fail_isolate: true,
        ..MockWorkspace::default()
    };
    let mut broker = MockBroker {
        log: log.clone(),
        fail_establish: true,
        ..MockBroker::default()
    };
    let mut vm = MockVm {
        log: log.clone(),
        ..MockVm::default()
    };
    let mut capability = MockCapability {
        log: log.clone(),
        ..MockCapability::default()
    };
    let mut workload = MockWorkload {
        log: log.clone(),
        ..MockWorkload::default()
    };

    let mut orchestrator = SessionOrchestrator::new(SequenceRandom::new(identity_values(60, 7)));
    let error = orchestrator
        .start_session(
            &snapshot(),
            &template(),
            &7_u64,
            &mut workspace,
            &mut broker,
            &mut vm,
            &mut capability,
            &mut workload,
        )
        .expect_err("startup and rollback failure must be reported");
    assert_eq!(error.stage(), StartStage::BrokerEstablishment);
    assert_eq!(error.rollback_failures().len(), 1);
    assert_eq!(
        error.rollback_failures()[0].stage(),
        CleanupStage::WorkspaceIsolation
    );
    assert_eq!(orchestrator.state(), LifecycleState::Stopping);
}

#[test]
fn startup_rollback_failure_is_retained_for_stop_retry() {
    let log = CallLog::default();
    let mut workspace = MockWorkspace {
        log: log.clone(),
        fail_isolate: true,
        ..MockWorkspace::default()
    };
    let mut broker = MockBroker {
        log: log.clone(),
        fail_establish: true,
        ..MockBroker::default()
    };
    let mut vm = MockVm {
        log: log.clone(),
        ..MockVm::default()
    };
    let mut capability = MockCapability {
        log: log.clone(),
        ..MockCapability::default()
    };
    let mut workload = MockWorkload {
        log: log.clone(),
        ..MockWorkload::default()
    };
    let mut orchestrator = SessionOrchestrator::new(SequenceRandom::new(identity_values(63, 7)));

    let error = orchestrator
        .start_session(
            &snapshot(),
            &template(),
            &7_u64,
            &mut workspace,
            &mut broker,
            &mut vm,
            &mut capability,
            &mut workload,
        )
        .expect_err("rollback failure must leave a retryable session");
    assert_eq!(
        error.rollback_failures()[0].stage(),
        CleanupStage::WorkspaceIsolation
    );
    assert_eq!(orchestrator.state(), LifecycleState::Stopping);
    assert!(orchestrator.active_session().is_none());

    let before = log.values();
    let second_start = orchestrator.start_session(
        &snapshot(),
        &template(),
        &7_u64,
        &mut workspace,
        &mut broker,
        &mut vm,
        &mut capability,
        &mut workload,
    );
    assert!(matches!(
        second_start,
        Err(error) if error.failure() == &StartFailure::InvalidState(LifecycleState::Stopping)
    ));
    assert_eq!(log.values(), before);

    workspace.fail_isolate = false;
    orchestrator
        .stop_session(&mut workspace, &mut broker, &mut vm, &mut capability)
        .expect("retained startup cleanup must be retryable");
    assert_eq!(orchestrator.state(), LifecycleState::Closed);
    assert_eq!(
        log.values(),
        vec![
            "workspace.clone",
            "broker.establish",
            "workspace.isolate",
            "workspace.isolate"
        ]
    );
}

// Requirement: a workspace clone whose lease fails validation is never left on the host.
// Category: failure containment. Risk: high.
#[test]
fn foreign_workspace_lease_isolates_the_clone_before_returning() {
    let log = CallLog::default();
    let mut workspace = MockWorkspace {
        log: log.clone(),
        foreign_session: Some(SessionId::new([0xAA; 16])),
        ..MockWorkspace::default()
    };
    let mut broker = MockBroker {
        log: log.clone(),
        ..MockBroker::default()
    };
    let mut vm = MockVm {
        log: log.clone(),
        ..MockVm::default()
    };
    let mut capability = MockCapability {
        log: log.clone(),
        ..MockCapability::default()
    };
    let mut workload = MockWorkload {
        log: log.clone(),
        ..MockWorkload::default()
    };
    let mut orchestrator = SessionOrchestrator::new(SequenceRandom::new(identity_values(80, 7)));

    let error = orchestrator
        .start_session(
            &snapshot(),
            &template(),
            &7_u64,
            &mut workspace,
            &mut broker,
            &mut vm,
            &mut capability,
            &mut workload,
        )
        .expect_err("a lease bound to another session must not start a session");

    assert_eq!(error.stage(), StartStage::WorkspaceClone);
    assert!(matches!(
        error.failure(),
        StartFailure::CrossSessionLease { .. }
    ));
    assert!(
        error.rollback_failures().is_empty(),
        "isolation succeeded, so nothing is outstanding"
    );
    assert_eq!(
        log.values(),
        vec!["workspace.clone", "workspace.isolate"],
        "the clone must be released and no later backend touched"
    );
    assert_eq!(orchestrator.state(), LifecycleState::Ready);
}

// Requirement: workspace isolation never runs while a live VM kill has failed.
// Category: failure containment. Risk: critical.
#[test]
fn rollback_keeps_workspace_bound_when_vm_kill_fails() {
    let log = CallLog::default();
    let mut workspace = MockWorkspace {
        log: log.clone(),
        ..MockWorkspace::default()
    };
    let mut broker = MockBroker {
        log: log.clone(),
        ..MockBroker::default()
    };
    let mut vm = MockVm {
        log: log.clone(),
        fail_kill: true,
        ..MockVm::default()
    };
    let mut capability = MockCapability {
        log: log.clone(),
        ..MockCapability::default()
    };
    let mut workload = MockWorkload {
        log: log.clone(),
        fail_release: true,
        ..MockWorkload::default()
    };
    let mut orchestrator = SessionOrchestrator::new(SequenceRandom::new(identity_values(65, 7)));

    let error = orchestrator
        .start_session(
            &snapshot(),
            &template(),
            &7_u64,
            &mut workspace,
            &mut broker,
            &mut vm,
            &mut capability,
            &mut workload,
        )
        .expect_err("failed VM kill must keep startup unresolved");
    assert_eq!(error.stage(), StartStage::WorkloadRelease);
    assert_eq!(error.rollback_failures()[0].stage(), CleanupStage::VmKill);
    assert_eq!(orchestrator.state(), LifecycleState::Stopping);
    assert_eq!(
        log.values(),
        vec![
            "workspace.clone",
            "broker.establish",
            "vm.start",
            "capability.inject",
            "broker.ensure-running",
            "workload.release",
            "capability.revoke",
            "vm.kill",
            "broker.close"
        ]
    );
}

// Requirement: a snapshot cannot carry session-scoped identities into a new
// session. Category: security/state boundary. Risk: critical.
#[test]
fn snapshot_with_inherited_identity_is_rejected_before_backend_calls() {
    let log = CallLog::default();
    let mut workspace = MockWorkspace {
        log: log.clone(),
        ..MockWorkspace::default()
    };
    let mut broker = MockBroker {
        log: log.clone(),
        ..MockBroker::default()
    };
    let mut vm = MockVm {
        log: log.clone(),
        ..MockVm::default()
    };
    let mut capability = MockCapability {
        log: log.clone(),
        ..MockCapability::default()
    };
    let mut workload = MockWorkload {
        log: log.clone(),
        ..MockWorkload::default()
    };
    let dirty_snapshot = SnapshotDescriptor::with_inherited_ids(
        SnapshotId::new([0xA1; 16]),
        [SnapshotIdentity::new(IdentityKind::Session, [0x01; 16])],
    );
    let mut orchestrator = SessionOrchestrator::new(SequenceRandom::new(identity_values(70, 7)));

    let error = orchestrator
        .start_session(
            &dirty_snapshot,
            &template(),
            &7_u64,
            &mut workspace,
            &mut broker,
            &mut vm,
            &mut capability,
            &mut workload,
        )
        .expect_err("dirty snapshot must be rejected");
    assert!(matches!(
        error.failure(),
        StartFailure::SnapshotContainsSessionIdentity {
            kind: IdentityKind::Session,
            ..
        }
    ));
    assert_eq!(orchestrator.state(), LifecycleState::Ready);
    assert!(log.values().is_empty());
}

// Requirement: a cryptographic identity returned again after restore is never
// rebound. Category: security/replay. Risk: critical.
#[test]
fn snapshot_restore_rejects_reused_session_identity() {
    let mut values = identity_values(80, 7);
    values.extend(identity_values(80, 7));
    let mut orchestrator = SessionOrchestrator::new(SequenceRandom::new(values));
    let mut workspace = MockWorkspace::default();
    let mut broker = MockBroker::default();
    let mut vm = MockVm::default();
    let mut capability = MockCapability::default();
    let mut workload = MockWorkload::default();

    orchestrator
        .start_session(
            &snapshot(),
            &template(),
            &7_u64,
            &mut workspace,
            &mut broker,
            &mut vm,
            &mut capability,
            &mut workload,
        )
        .expect("first restore must start");
    orchestrator
        .stop_session(&mut workspace, &mut broker, &mut vm, &mut capability)
        .expect("first session must stop");
    let error = orchestrator
        .start_session(
            &snapshot(),
            &template(),
            &7_u64,
            &mut workspace,
            &mut broker,
            &mut vm,
            &mut capability,
            &mut workload,
        )
        .expect_err("reused identity must reject second restore");
    assert!(matches!(
        error.failure(),
        StartFailure::IdentityReused(IdentityKind::Session)
    ));
    assert_eq!(orchestrator.state(), LifecycleState::Closed);
}

// Requirement: a second active session cannot share this orchestrator's
// resources. Category: state transition. Risk: critical.
#[test]
fn active_session_rejects_a_second_start() {
    let log = CallLog::default();
    let mut workspace = MockWorkspace {
        log: log.clone(),
        ..MockWorkspace::default()
    };
    let mut broker = MockBroker {
        log: log.clone(),
        ..MockBroker::default()
    };
    let mut vm = MockVm {
        log: log.clone(),
        ..MockVm::default()
    };
    let mut capability = MockCapability {
        log: log.clone(),
        ..MockCapability::default()
    };
    let mut workload = MockWorkload {
        log: log.clone(),
        ..MockWorkload::default()
    };
    let mut orchestrator = SessionOrchestrator::new(SequenceRandom::new(identity_values(90, 14)));
    orchestrator
        .start_session(
            &snapshot(),
            &template(),
            &7_u64,
            &mut workspace,
            &mut broker,
            &mut vm,
            &mut capability,
            &mut workload,
        )
        .expect("first session must start");
    let before = log.values();
    let error = orchestrator
        .start_session(
            &snapshot(),
            &template(),
            &7_u64,
            &mut workspace,
            &mut broker,
            &mut vm,
            &mut capability,
            &mut workload,
        )
        .expect_err("active session must reject a second start");
    assert!(matches!(
        error.failure(),
        StartFailure::InvalidState(LifecycleState::Running)
    ));
    assert_eq!(log.values(), before);
}

// Requirement: a Broker lease from another session is rejected before VM
// startup. Category: security/authorization boundary. Risk: critical.
#[test]
fn foreign_broker_session_cannot_be_attached_to_workspace() {
    let log = CallLog::default();
    let mut workspace = MockWorkspace {
        log: log.clone(),
        ..MockWorkspace::default()
    };
    let mut broker = MockBroker {
        log: log.clone(),
        foreign_session: Some(SessionId::new([0xEE; 16])),
        ..MockBroker::default()
    };
    let mut vm = MockVm {
        log: log.clone(),
        ..MockVm::default()
    };
    let mut capability = MockCapability {
        log: log.clone(),
        ..MockCapability::default()
    };
    let mut workload = MockWorkload {
        log: log.clone(),
        ..MockWorkload::default()
    };
    let mut orchestrator = SessionOrchestrator::new(SequenceRandom::new(identity_values(100, 7)));

    let error = orchestrator
        .start_session(
            &snapshot(),
            &template(),
            &7_u64,
            &mut workspace,
            &mut broker,
            &mut vm,
            &mut capability,
            &mut workload,
        )
        .expect_err("foreign Broker lease must be rejected");
    assert!(matches!(
        error.failure(),
        StartFailure::CrossSessionLease {
            resource: session_orchestrator::ResourceKind::Broker,
            ..
        }
    ));
    assert_eq!(
        log.values(),
        vec![
            "workspace.clone",
            "broker.establish",
            "broker.close",
            "workspace.isolate"
        ]
    );
}

// Requirement: a VM bound to another workspace cannot be released as this
// session's VM. Category: security/resource binding. Risk: critical.
#[test]
fn foreign_workspace_binding_is_rejected_before_capability_injection() {
    let log = CallLog::default();
    let mut workspace = MockWorkspace {
        log: log.clone(),
        ..MockWorkspace::default()
    };
    let mut broker = MockBroker {
        log: log.clone(),
        ..MockBroker::default()
    };
    let mut vm = MockVm {
        log: log.clone(),
        foreign_workspace: Some(WorkspaceId::new([0xEF; 16])),
        ..MockVm::default()
    };
    let mut capability = MockCapability {
        log: log.clone(),
        ..MockCapability::default()
    };
    let mut workload = MockWorkload {
        log: log.clone(),
        ..MockWorkload::default()
    };
    let mut orchestrator = SessionOrchestrator::new(SequenceRandom::new(identity_values(110, 7)));

    let error = orchestrator
        .start_session(
            &snapshot(),
            &template(),
            &7_u64,
            &mut workspace,
            &mut broker,
            &mut vm,
            &mut capability,
            &mut workload,
        )
        .expect_err("foreign workspace binding must be rejected");
    assert!(matches!(
        error.failure(),
        StartFailure::LeaseIdentityMismatch(session_orchestrator::ResourceKind::Vm)
    ));
    assert_eq!(
        log.values(),
        vec![
            "workspace.clone",
            "broker.establish",
            "vm.start",
            "vm.kill",
            "broker.close",
            "workspace.isolate"
        ]
    );
}

// Requirement: stop continues containment cleanup after a revoke failure and
// retries only the unfinished step. Category: failure recovery. Risk: critical.
#[test]
fn stop_remains_stopping_and_retries_failed_revoke() {
    let log = CallLog::default();
    let mut workspace = MockWorkspace {
        log: log.clone(),
        ..MockWorkspace::default()
    };
    let mut broker = MockBroker {
        log: log.clone(),
        ..MockBroker::default()
    };
    let mut vm = MockVm {
        log: log.clone(),
        ..MockVm::default()
    };
    let mut capability = MockCapability {
        log: log.clone(),
        fail_revoke: true,
        ..MockCapability::default()
    };
    let mut workload = MockWorkload {
        log: log.clone(),
        ..MockWorkload::default()
    };
    let mut orchestrator = SessionOrchestrator::new(SequenceRandom::new(identity_values(120, 7)));
    orchestrator
        .start_session(
            &snapshot(),
            &template(),
            &7_u64,
            &mut workspace,
            &mut broker,
            &mut vm,
            &mut capability,
            &mut workload,
        )
        .expect("session must start before stop test");

    let error = orchestrator
        .stop_session(&mut workspace, &mut broker, &mut vm, &mut capability)
        .expect_err("revoke failure must keep stop incomplete");
    assert!(matches!(error, StopError::Cleanup(_)));
    assert_eq!(orchestrator.state(), LifecycleState::Stopping);
    assert_eq!(
        log.values(),
        vec![
            "workspace.clone",
            "broker.establish",
            "vm.start",
            "capability.inject",
            "broker.ensure-running",
            "workload.release",
            "capability.revoke",
            "vm.kill",
            "broker.close",
            "workspace.isolate"
        ]
    );

    capability.fail_revoke = false;
    orchestrator
        .stop_session(&mut workspace, &mut broker, &mut vm, &mut capability)
        .expect("retry must finish the failed revoke");
    assert_eq!(orchestrator.state(), LifecycleState::Closed);
    assert_eq!(
        log.values(),
        vec![
            "workspace.clone",
            "broker.establish",
            "vm.start",
            "capability.inject",
            "broker.ensure-running",
            "workload.release",
            "capability.revoke",
            "vm.kill",
            "broker.close",
            "workspace.isolate",
            "capability.revoke"
        ]
    );
}

// Requirement: typed IDs are fixed-width and display without truncation.
// Category: boundary/identity. Risk: medium.
#[test]
fn generated_identity_summary_contains_distinct_fixed_width_ids() {
    let mut workspace = MockWorkspace::default();
    let mut broker = MockBroker::default();
    let mut vm = MockVm::default();
    let mut capability = MockCapability::default();
    let mut workload = MockWorkload::default();
    let (_, info) = start_with(
        SequenceRandom::new(identity_values(140, 7)),
        &mut workspace,
        &mut broker,
        &mut vm,
        &mut capability,
        &mut workload,
    )
    .expect("session must start");
    let identity = info.identity();
    let values = [
        identity.session_id().as_bytes(),
        identity.request_id().as_bytes(),
        identity.vm_id().as_bytes(),
        identity.subject_id().as_bytes(),
        identity.workspace_id().as_bytes(),
        identity.capability_id().as_bytes(),
        identity.broker_session_id().as_bytes(),
    ];
    for value in values {
        assert_eq!(value.len(), 16);
        assert_ne!(value, [0; 16]);
    }
    for (index, left) in values.iter().enumerate() {
        assert!(values[index + 1..].iter().all(|right| left != right));
    }
    assert_eq!(identity.session_id().to_string().len(), 32);
}

#[test]
fn ledger_write_or_sync_failure_keeps_ready_without_backend_effects() {
    for error in [
        LedgerError::WriteFailed {
            path: PathBuf::from("mock-ledger"),
            message: "injected write failure".into(),
        },
        LedgerError::SyncFailed {
            path: PathBuf::from("mock-ledger"),
            message: "injected sync failure".into(),
        },
    ] {
        let log = CallLog::default();
        let mut workspace = MockWorkspace {
            log: log.clone(),
            ..MockWorkspace::default()
        };
        let mut broker = MockBroker {
            log: log.clone(),
            ..MockBroker::default()
        };
        let mut vm = MockVm {
            log: log.clone(),
            ..MockVm::default()
        };
        let mut capability = MockCapability {
            log: log.clone(),
            ..MockCapability::default()
        };
        let mut workload = MockWorkload {
            log: log.clone(),
            ..MockWorkload::default()
        };
        let mut orchestrator = SessionOrchestrator::with_ledger(
            SequenceRandom::new(identity_values(200, 7)),
            FailingLedger { error },
        );
        let error = orchestrator
            .start_session(
                &snapshot(),
                &template(),
                &7_u64,
                &mut workspace,
                &mut broker,
                &mut vm,
                &mut capability,
                &mut workload,
            )
            .expect_err("ledger failure must reject startup");
        assert!(matches!(error.failure(), StartFailure::Ledger(_)));
        assert_eq!(orchestrator.state(), LifecycleState::Ready);
        assert!(log.values().is_empty());
    }
}
