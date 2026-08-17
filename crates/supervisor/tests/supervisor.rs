#![allow(missing_docs)]

use std::{error::Error, fmt, sync::Arc};

use authority_core::{
    capability::{AuthorityBody, IssuerId, SubjectId},
    file::{FileAuthority, FileEffect, FileEffects},
    handle::{HandleId, ObjectId},
    kernel::CapabilityKernel,
    path::{CanonicalPath, PathPattern},
    repository::RepoId,
    state::{CapabilityGrant, CapabilityState, StaticAuthorityEnvelope, Subject},
    time::{MonotonicTime, TimeWindow},
};
use supervisor::{
    CgroupHandle, CleanupStep, ConnectionIdentity, ControlFdHandle, MountHandle,
    ResourceAcquisition, ResourceMutation, RuntimeResources, SetupStep, StaticCallerResolver,
    SubjectLifecycle, Supervisor, SupervisorCapacity, SupervisorError, SupervisorLimits,
    SupervisorLimitsError, WorkloadHandle,
};

#[derive(Debug, Clone, PartialEq, Eq)]
struct FakeError(&'static str);

impl fmt::Display for FakeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.0)
    }
}

impl Error for FakeError {}

#[derive(Debug, Default)]
struct FakeResources {
    events: Vec<&'static str>,
    failures: Vec<&'static str>,
    next_token: u64,
    mutate_authority_during_start: Option<Arc<CapabilityKernel>>,
}

impl FakeResources {
    fn fail_once(&mut self, operation: &'static str) {
        self.failures.push(operation);
    }

    fn record(&mut self, operation: &'static str) -> Result<(), FakeError> {
        self.events.push(operation);
        if let Some(index) = self
            .failures
            .iter()
            .position(|failure| *failure == operation)
        {
            self.failures.remove(index);
            Err(FakeError(operation))
        } else {
            Ok(())
        }
    }

    fn token(&mut self) -> u64 {
        self.next_token += 1;
        self.next_token
    }
}

impl RuntimeResources for FakeResources {
    type Error = FakeError;

    fn create_cgroup(
        &mut self,
        _subject: &SubjectId,
    ) -> ResourceAcquisition<CgroupHandle, Self::Error> {
        match self.record("create_cgroup") {
            Ok(()) => ResourceAcquisition::Acquired(CgroupHandle::new(self.token())),
            Err(error) => ResourceAcquisition::NoEffect(error),
        }
    }

    fn remove_cgroup(&mut self, _cgroup: CgroupHandle) -> ResourceMutation<Self::Error> {
        match self.record("remove_cgroup") {
            Ok(()) => ResourceMutation::Applied,
            Err(error) => ResourceMutation::CleanupRequired(error),
        }
    }

    fn mount_capfs(
        &mut self,
        _subject: &SubjectId,
    ) -> ResourceAcquisition<MountHandle, Self::Error> {
        match self.record("mount") {
            Ok(()) => ResourceAcquisition::Acquired(MountHandle::new(self.token())),
            Err(error) => ResourceAcquisition::NoEffect(error),
        }
    }

    fn unmount_capfs(&mut self, _mount: MountHandle) -> ResourceMutation<Self::Error> {
        match self.record("unmount") {
            Ok(()) => ResourceMutation::Applied,
            Err(error) => ResourceMutation::CleanupRequired(error),
        }
    }

    fn open_control_fd(
        &mut self,
        _subject: &SubjectId,
    ) -> ResourceAcquisition<ControlFdHandle, Self::Error> {
        match self.record("open_control") {
            Ok(()) => ResourceAcquisition::Acquired(ControlFdHandle::new(self.token())),
            Err(error) => ResourceAcquisition::NoEffect(error),
        }
    }

    fn close_control_fd(&mut self, _control: ControlFdHandle) -> ResourceMutation<Self::Error> {
        match self.record("close_control") {
            Ok(()) => ResourceMutation::Applied,
            Err(error) => ResourceMutation::CleanupRequired(error),
        }
    }

    fn start_workload(
        &mut self,
        subject: &SubjectId,
        _cgroup: CgroupHandle,
        _mount: MountHandle,
        _control: ControlFdHandle,
    ) -> ResourceAcquisition<WorkloadHandle, Self::Error> {
        match self.record("start_workload") {
            Ok(()) => {
                if let Some(kernel) = self.mutate_authority_during_start.take() {
                    CapabilityKernel::begin_subject_close(&kernel, subject)
                        .expect("concurrent test mutation must be accepted");
                }
                ResourceAcquisition::Acquired(WorkloadHandle::new(self.token()))
            }
            Err(error) => ResourceAcquisition::NoEffect(error),
        }
    }

    fn stop_workload(
        &mut self,
        _workload: WorkloadHandle,
        _cgroup: CgroupHandle,
    ) -> ResourceMutation<Self::Error> {
        match self.record("stop_workload") {
            Ok(()) => ResourceMutation::Applied,
            Err(error) => ResourceMutation::CleanupRequired(error),
        }
    }

    fn open_handle(
        &mut self,
        _subject: &SubjectId,
        _handle: &HandleId,
    ) -> ResourceMutation<Self::Error> {
        match self.record("open_handle") {
            Ok(()) => ResourceMutation::Applied,
            Err(error) => ResourceMutation::NoEffect(error),
        }
    }

    fn close_handle(
        &mut self,
        _subject: &SubjectId,
        _handle: &HandleId,
    ) -> ResourceMutation<Self::Error> {
        match self.record("close_handle") {
            Ok(()) => ResourceMutation::Applied,
            Err(error) => ResourceMutation::CleanupRequired(error),
        }
    }
}

fn time(ticks: u64) -> MonotonicTime {
    MonotonicTime::from_ticks(ticks)
}

fn window(not_before: u64, expires_at: u64) -> TimeWindow {
    TimeWindow::new(time(not_before), time(expires_at)).expect("test window must be non-empty")
}

fn authority() -> AuthorityBody {
    AuthorityBody::File(FileAuthority::new(
        RepoId::new("workspace"),
        FileEffects::only(FileEffect::ReadData),
        PathPattern::Prefix(CanonicalPath::root()),
    ))
}

fn root_subject() -> SubjectId {
    SubjectId::new("subject-root")
}

fn root_envelope() -> StaticAuthorityEnvelope {
    StaticAuthorityEnvelope::new(window(0, 100), authority())
}

fn root_grant() -> CapabilityGrant {
    CapabilityGrant::new(root_subject(), window(1, 99), authority()).with_delegable(true)
}

fn child_subject() -> SubjectId {
    SubjectId::new("subject-child")
}

fn child_envelope() -> StaticAuthorityEnvelope {
    StaticAuthorityEnvelope::new(window(10, 90), authority())
}

fn new_supervisor() -> (
    Supervisor<CapabilityKernel, FakeResources, StaticCallerResolver>,
    ConnectionIdentity,
) {
    let identity = ConnectionIdentity::new(1, 101, 1000, 1000);
    let mut callers = StaticCallerResolver::new();
    callers
        .bind(identity, root_subject())
        .expect("caller binding must be unique");
    let kernel = CapabilityKernel::new(CapabilityState::new(IssuerId::new("session")));
    let resources = FakeResources::default();
    let mut supervisor = Supervisor::new(kernel, resources, callers)
        .expect("pristine kernel must initialize supervisor");
    supervisor
        .create_subject(Subject::new(root_subject(), root_envelope()), identity)
        .expect("subject setup must succeed");
    (supervisor, identity)
}

fn assert_cleanup_steps<KE, RE, CE>(error: &SupervisorError<KE, RE, CE>, expected: &[CleanupStep]) {
    let SupervisorError::CleanupFailed { failures, .. } = error else {
        panic!("expected CleanupFailed");
    };
    assert_eq!(
        failures
            .iter()
            .map(|failure| failure.step)
            .collect::<Vec<_>>(),
        expected,
    );
}

#[test]
fn normal_setup_root_handle_and_shutdown_follow_required_order() {
    let (mut supervisor, identity) = new_supervisor();
    let root_capability = supervisor
        .issue_root(&root_subject(), root_grant())
        .expect("root issuance must succeed");
    assert!(root_capability.as_str().starts_with("session:"));

    supervisor
        .open_handle(
            &identity,
            HandleId::new("handle-1"),
            ObjectId::new("object-1"),
        )
        .expect("handle setup must succeed");
    supervisor
        .shutdown_subject(&root_subject())
        .expect("shutdown must complete");

    assert_eq!(
        supervisor
            .lifecycle(&root_subject())
            .expect("closed subject record must remain queryable"),
        SubjectLifecycle::Closed
    );
    assert_eq!(
        supervisor.resources().events,
        vec![
            "create_cgroup",
            "mount",
            "open_control",
            "start_workload",
            "open_handle",
            "stop_workload",
            "close_control",
            "close_handle",
            "unmount",
            "remove_cgroup",
        ]
    );
}

#[test]
fn root_derive_and_revoke_use_typed_authority_kernel_transitions() {
    let root_identity = ConnectionIdentity::new(1, 101, 1000, 1000);
    let child_identity = ConnectionIdentity::new(2, 102, 1000, 1000);
    let mut callers = StaticCallerResolver::new();
    callers
        .bind(root_identity, root_subject())
        .expect("root caller binding must be unique");
    callers
        .bind(child_identity, child_subject())
        .expect("child caller binding must be unique");
    let kernel = CapabilityKernel::new(CapabilityState::new(IssuerId::new("session")));
    let resources = FakeResources::default();
    let mut supervisor = Supervisor::new(kernel, resources, callers)
        .expect("pristine kernel must initialize supervisor");
    supervisor
        .create_subject(Subject::new(root_subject(), root_envelope()), root_identity)
        .expect("root setup must succeed");
    supervisor
        .create_subject(
            Subject::new(child_subject(), child_envelope()).with_parent(root_subject()),
            child_identity,
        )
        .expect("child setup must succeed");

    let root = supervisor
        .issue_root(&root_subject(), root_grant())
        .expect("root issuance must succeed");
    let child = supervisor
        .derive(
            &root_identity,
            &root,
            CapabilityGrant::new(child_subject(), window(20, 80), authority()),
            time(30),
        )
        .expect("narrow child derivation must succeed");
    assert!(matches!(
        supervisor.revoke(&child_identity, &root),
        Err(SupervisorError::Kernel(
            authority_core::kernel::CapabilityKernelError::StateTransition(
                authority_core::state::CapabilityStateError::CapabilityNotHeld { .. }
            )
        ))
    ));
    assert_eq!(
        supervisor
            .revoke(&root_identity, &root)
            .expect("root revoke must succeed"),
        authority_core::state::RevocationStatus::NewlyRevoked
    );
    assert_eq!(
        supervisor
            .revoke(&root_identity, &root)
            .expect("repeated revoke must succeed"),
        authority_core::state::RevocationStatus::AlreadyRevoked
    );
    assert!(!child.as_str().is_empty());
}

#[test]
fn request_subject_spoof_is_ignored_in_favor_of_connection_identity() {
    let (mut supervisor, identity) = new_supervisor();
    let handle = HandleId::new("handle-1");
    supervisor
        .open_handle(&identity, handle.clone(), ObjectId::new("object-1"))
        .expect("handle setup must succeed");
    let request = supervisor::WireRequest::CloseHandle {
        claimed_subject: SubjectId::new("attacker-selected-subject"),
        handle,
    }
    .encode()
    .expect("request must encode");

    assert_eq!(
        supervisor
            .dispatch_wire(&identity, &request)
            .expect("caller handle close must succeed"),
        supervisor::DispatchResponse::HandleClosed
    );
    assert_eq!(
        supervisor
            .lifecycle(&root_subject())
            .expect("running subject record must remain queryable"),
        SubjectLifecycle::Running
    );
}

#[test]
fn authenticated_foreign_subject_cannot_close_another_subjects_handle() {
    let root_identity = ConnectionIdentity::new(4, 104, 1000, 1000);
    let child_identity = ConnectionIdentity::new(5, 105, 1000, 1000);
    let mut callers = StaticCallerResolver::new();
    callers
        .bind(root_identity, root_subject())
        .expect("root caller binding must be unique");
    callers
        .bind(child_identity, child_subject())
        .expect("child caller binding must be unique");
    let kernel = CapabilityKernel::new(CapabilityState::new(IssuerId::new("session")));
    let resources = FakeResources::default();
    let mut supervisor = Supervisor::new(kernel, resources, callers)
        .expect("pristine kernel must initialize supervisor");
    supervisor
        .create_subject(Subject::new(root_subject(), root_envelope()), root_identity)
        .expect("root setup must succeed");
    supervisor
        .create_subject(
            Subject::new(child_subject(), child_envelope()).with_parent(root_subject()),
            child_identity,
        )
        .expect("child setup must succeed");

    let handle = HandleId::new("root-owned-handle");
    supervisor
        .open_handle(&root_identity, handle.clone(), ObjectId::new("object-1"))
        .expect("root handle setup must succeed");

    let before_events = supervisor.resources().events.clone();
    let request = supervisor::WireRequest::CloseHandle {
        claimed_subject: root_subject(),
        handle,
    }
    .encode()
    .expect("request must encode");
    assert!(matches!(
        supervisor.dispatch_wire(&child_identity, &request),
        Err(SupervisorError::HandleNotOwned { .. })
    ));
    assert_eq!(
        supervisor.resources().events,
        before_events,
        "ownership rejection must happen before the runtime adapter is called"
    );
}

#[test]
fn close_subject_claim_cannot_close_a_foreign_subject() {
    let root_identity = ConnectionIdentity::new(6, 106, 1000, 1000);
    let child_identity = ConnectionIdentity::new(7, 107, 1000, 1000);
    let mut callers = StaticCallerResolver::new();
    callers
        .bind(root_identity, root_subject())
        .expect("root caller binding must be unique");
    callers
        .bind(child_identity, child_subject())
        .expect("child caller binding must be unique");
    let kernel = CapabilityKernel::new(CapabilityState::new(IssuerId::new("session")));
    let resources = FakeResources::default();
    let mut supervisor = Supervisor::new(kernel, resources, callers)
        .expect("pristine kernel must initialize supervisor");
    supervisor
        .create_subject(Subject::new(root_subject(), root_envelope()), root_identity)
        .expect("root setup must succeed");
    supervisor
        .create_subject(
            Subject::new(child_subject(), child_envelope()).with_parent(root_subject()),
            child_identity,
        )
        .expect("child setup must succeed");

    let request = supervisor::WireRequest::CloseSubject {
        claimed_subject: root_subject(),
    }
    .encode()
    .expect("request must encode");
    assert_eq!(
        supervisor
            .dispatch_wire(&child_identity, &request)
            .expect("the caller's own subject must close"),
        supervisor::DispatchResponse::SubjectClosed
    );
    assert_eq!(
        supervisor
            .lifecycle(&child_subject())
            .expect("closed child record must remain queryable"),
        SubjectLifecycle::Closed
    );
    assert_eq!(
        supervisor
            .lifecycle(&root_subject())
            .expect("foreign subject must remain queryable"),
        SubjectLifecycle::Running,
        "claimed subject data must never select the shutdown target"
    );
}

#[test]
fn partial_setup_rolls_back_already_acquired_resources() {
    let identity = ConnectionIdentity::new(2, 102, 1000, 1000);
    let mut callers = StaticCallerResolver::new();
    callers
        .bind(identity, SubjectId::new("subject-partial"))
        .expect("caller binding must be unique");
    let kernel = CapabilityKernel::new(CapabilityState::new(IssuerId::new("session")));
    let mut resources = FakeResources::default();
    resources.fail_once("mount");
    let mut supervisor = Supervisor::new(kernel, resources, callers)
        .expect("pristine kernel must initialize supervisor");
    let subject = SubjectId::new("subject-partial");

    let error = supervisor
        .create_subject(Subject::new(subject.clone(), root_envelope()), identity)
        .expect_err("mount failure must reject setup");
    assert!(matches!(
        error,
        SupervisorError::SetupFailed {
            step: SetupStep::Mount,
            rollback,
            ..
        } if rollback.is_empty()
    ));
    assert_eq!(
        supervisor.resources().events,
        vec!["create_cgroup", "mount", "remove_cgroup"]
    );
    assert!(matches!(
        supervisor.lifecycle(&subject),
        Err(SupervisorError::UnknownSubject(_))
    ));
}

#[test]
fn clean_setup_rollback_permanently_reserves_subject_id() {
    let identity = ConnectionIdentity::new(20, 120, 1000, 1000);
    let subject = SubjectId::new("rollback-reserved-subject");
    let mut callers = StaticCallerResolver::new();
    callers
        .bind(identity, subject.clone())
        .expect("caller binding must be unique");
    let mut resources = FakeResources::default();
    resources.fail_once("mount");
    let mut supervisor = Supervisor::new(
        CapabilityKernel::new(CapabilityState::new(IssuerId::new("session"))),
        resources,
        callers,
    )
    .expect("pristine kernel must initialize supervisor");

    supervisor
        .create_subject(Subject::new(subject.clone(), root_envelope()), identity)
        .expect_err("the first setup must fail before authority registration");
    let events_after_rollback = supervisor.resources().events.clone();

    assert!(matches!(
        supervisor.create_subject(Subject::new(subject.clone(), root_envelope()), identity),
        Err(SupervisorError::DuplicateSubject(duplicate)) if duplicate == subject
    ));
    assert_eq!(
        supervisor.resources().events,
        events_after_rollback,
        "a permanently reserved subject ID must not reach the adapter again"
    );
}

#[test]
fn register_to_start_authority_mutation_fails_closed_and_rolls_back_resources() {
    let identity = ConnectionIdentity::new(21, 121, 1000, 1000);
    let subject = SubjectId::new("authority-start-race");
    let mut callers = StaticCallerResolver::new();
    callers
        .bind(identity, subject.clone())
        .expect("caller binding must be unique");
    let kernel = Arc::new(CapabilityKernel::new(CapabilityState::new(IssuerId::new(
        "session",
    ))));
    let resources = FakeResources {
        mutate_authority_during_start: Some(Arc::clone(&kernel)),
        ..FakeResources::default()
    };
    let mut supervisor = Supervisor::new(kernel.clone(), resources, callers)
        .expect("pristine shared kernel must initialize supervisor");

    let error = supervisor
        .create_subject(Subject::new(subject.clone(), root_envelope()), identity)
        .expect_err("authority mutation during workload start must fail closed");
    assert!(matches!(
        error,
        SupervisorError::SetupFailed {
            step: SetupStep::StartWorkload,
            primary: supervisor::OperationFailure::Invariant(
                "authority subject changed during workload start"
            ),
            rollback,
            ..
        } if rollback.is_empty()
    ));
    assert!(matches!(
        supervisor.lifecycle(&subject),
        Err(SupervisorError::UnknownSubject(_))
    ));
    assert_eq!(
        supervisor.resources().events,
        vec![
            "create_cgroup",
            "mount",
            "open_control",
            "start_workload",
            "stop_workload",
            "close_control",
            "unmount",
            "remove_cgroup",
        ],
        "a concurrent authority mutation must not publish a running resource record"
    );
    assert_eq!(
        CapabilityKernel::subject_status(&kernel, &subject)
            .expect("shared kernel status must remain readable"),
        Some(authority_core::state::SubjectStatus::Closed)
    );
}

#[test]
fn setup_rollback_retains_prerequisites_when_control_close_fails() {
    let identity = ConnectionIdentity::new(3, 103, 1000, 1000);
    let mut callers = StaticCallerResolver::new();
    let subject = SubjectId::new("subject-rollback");
    callers
        .bind(identity, subject.clone())
        .expect("caller binding must be unique");
    let kernel = CapabilityKernel::new(CapabilityState::new(IssuerId::new("session")));
    let mut resources = FakeResources::default();
    resources.fail_once("start_workload");
    resources.fail_once("close_control");
    let mut supervisor = Supervisor::new(kernel, resources, callers)
        .expect("pristine kernel must initialize supervisor");

    let error = supervisor
        .create_subject(Subject::new(subject.clone(), root_envelope()), identity)
        .expect_err("workload startup failure must trigger rollback");
    assert!(matches!(
        error,
        SupervisorError::SetupFailed {
            rollback,
            ..
        } if rollback.iter().any(|failure| failure.step == CleanupStep::CloseControlFd)
    ));
    assert_eq!(
        supervisor
            .lifecycle(&subject)
            .expect("incomplete rollback must retain the subject"),
        SubjectLifecycle::Closing
    );
    assert_eq!(
        supervisor.resources().events,
        vec![
            "create_cgroup",
            "mount",
            "open_control",
            "start_workload",
            "close_control"
        ]
    );

    supervisor
        .shutdown_subject(&subject)
        .expect("retry must finish retained rollback");
    assert_eq!(
        supervisor
            .lifecycle(&subject)
            .expect("closed subject record must remain queryable"),
        SubjectLifecycle::Closed
    );
    assert_eq!(
        supervisor.resources().events,
        vec![
            "create_cgroup",
            "mount",
            "open_control",
            "start_workload",
            "close_control",
            "close_control",
            "unmount",
            "remove_cgroup"
        ]
    );
}

#[test]
fn cleanup_failure_keeps_subject_closing_and_blocks_new_requests() {
    let (mut supervisor, identity) = new_supervisor();
    supervisor.resources_mut().fail_once("unmount");

    let error = supervisor
        .shutdown_subject(&root_subject())
        .expect_err("unmount failure must not report closed");
    assert!(matches!(error, SupervisorError::CleanupFailed { .. }));
    assert_eq!(
        supervisor
            .lifecycle(&root_subject())
            .expect("closing subject record must remain queryable"),
        SubjectLifecycle::Closing
    );
    let request = supervisor::WireRequest::CloseSubject {
        claimed_subject: root_subject(),
    }
    .encode()
    .expect("request must encode");
    assert!(matches!(
        supervisor.dispatch_wire(&identity, &request),
        Err(SupervisorError::SubjectClosing(_))
    ));

    supervisor
        .shutdown_subject(&root_subject())
        .expect("retry after transient cleanup failure must complete");
    assert_eq!(
        supervisor
            .lifecycle(&root_subject())
            .expect("closed subject record must remain queryable"),
        SubjectLifecycle::Closed
    );
}

#[test]
fn stop_workload_failure_is_retained_and_retried_before_mount_cleanup() {
    let (mut supervisor, _) = new_supervisor();
    supervisor.resources_mut().fail_once("stop_workload");

    let error = supervisor
        .shutdown_subject(&root_subject())
        .expect_err("workload stop failure must remain fail-closed");
    assert_cleanup_steps(&error, &[CleanupStep::StopWorkload]);
    assert_eq!(
        supervisor
            .lifecycle(&root_subject())
            .expect("closing subject must remain tracked"),
        SubjectLifecycle::Closing
    );
    assert_eq!(
        supervisor.resources().events,
        vec![
            "create_cgroup",
            "mount",
            "open_control",
            "start_workload",
            "stop_workload",
            "close_control"
        ],
        "mount and cgroup cleanup must wait for workload stop"
    );

    supervisor
        .shutdown_subject(&root_subject())
        .expect("retry must stop workload before releasing prerequisites");
    assert_eq!(
        supervisor.resources().events,
        vec![
            "create_cgroup",
            "mount",
            "open_control",
            "start_workload",
            "stop_workload",
            "close_control",
            "stop_workload",
            "unmount",
            "remove_cgroup",
        ]
    );
}

#[test]
fn remove_cgroup_failure_is_retained_after_mount_cleanup_and_retried() {
    let (mut supervisor, _) = new_supervisor();
    supervisor.resources_mut().fail_once("remove_cgroup");

    let error = supervisor
        .shutdown_subject(&root_subject())
        .expect_err("cgroup removal failure must remain fail-closed");
    assert_cleanup_steps(&error, &[CleanupStep::RemoveCgroup]);
    assert_eq!(
        supervisor.resources().events,
        vec![
            "create_cgroup",
            "mount",
            "open_control",
            "start_workload",
            "stop_workload",
            "close_control",
            "unmount",
            "remove_cgroup",
        ]
    );

    supervisor
        .shutdown_subject(&root_subject())
        .expect("retry must remove the retained cgroup");
    assert_eq!(supervisor.resources().events.last(), Some(&"remove_cgroup"));
    assert_eq!(
        supervisor
            .lifecycle(&root_subject())
            .expect("closed subject must remain queryable"),
        SubjectLifecycle::Closed
    );
}

#[test]
fn close_handle_failure_is_retained_and_retried_before_unmount() {
    let (mut supervisor, identity) = new_supervisor();
    let handle = HandleId::new("close-retry-handle");
    supervisor
        .open_handle(&identity, handle, ObjectId::new("object-1"))
        .expect("handle setup must succeed");
    supervisor.resources_mut().fail_once("close_handle");

    let error = supervisor
        .shutdown_subject(&root_subject())
        .expect_err("runtime handle close failure must remain fail-closed");
    assert_cleanup_steps(&error, &[CleanupStep::CloseHandle]);
    assert_eq!(
        supervisor.resources().events,
        vec![
            "create_cgroup",
            "mount",
            "open_control",
            "start_workload",
            "open_handle",
            "stop_workload",
            "close_control",
            "close_handle",
        ]
    );

    supervisor
        .shutdown_subject(&root_subject())
        .expect("retry must close the retained runtime handle");
    assert_eq!(
        supervisor
            .lifecycle(&root_subject())
            .expect("closed subject must remain queryable"),
        SubjectLifecycle::Closed
    );
    assert_eq!(
        supervisor.resources().events,
        vec![
            "create_cgroup",
            "mount",
            "open_control",
            "start_workload",
            "open_handle",
            "stop_workload",
            "close_control",
            "close_handle",
            "close_handle",
            "unmount",
            "remove_cgroup",
        ]
    );
}

#[test]
fn simultaneous_cleanup_failures_are_all_retained_for_one_retry_matrix() {
    let (mut supervisor, identity) = new_supervisor();
    supervisor
        .open_handle(
            &identity,
            HandleId::new("multi-failure-handle"),
            ObjectId::new("object-1"),
        )
        .expect("handle setup must succeed");
    supervisor.resources_mut().fail_once("stop_workload");
    supervisor.resources_mut().fail_once("close_control");
    supervisor.resources_mut().fail_once("close_handle");

    let error = supervisor
        .shutdown_subject(&root_subject())
        .expect_err("simultaneous cleanup failures must be reported together");
    assert_cleanup_steps(
        &error,
        &[
            CleanupStep::StopWorkload,
            CleanupStep::CloseControlFd,
            CleanupStep::CloseHandle,
        ],
    );
    assert_eq!(
        supervisor
            .lifecycle(&root_subject())
            .expect("failed cleanup must remain tracked"),
        SubjectLifecycle::Closing
    );

    supervisor
        .shutdown_subject(&root_subject())
        .expect("the retry matrix must converge after transient failures are consumed");
    assert_eq!(
        supervisor
            .lifecycle(&root_subject())
            .expect("closed subject must remain queryable"),
        SubjectLifecycle::Closed
    );
}

#[test]
fn stale_handle_and_post_close_requests_are_rejected() {
    let (mut supervisor, identity) = new_supervisor();
    let handle = HandleId::new("handle-1");
    supervisor
        .open_handle(&identity, handle.clone(), ObjectId::new("object-1"))
        .expect("handle setup must succeed");
    supervisor
        .close_handle(&identity, &handle)
        .expect("first close must succeed");
    assert!(matches!(
        supervisor.close_handle(&identity, &handle),
        Err(SupervisorError::StaleHandle(_))
    ));

    supervisor
        .shutdown_subject(&root_subject())
        .expect("shutdown must complete");
    let request = supervisor::WireRequest::CloseSubject {
        claimed_subject: root_subject(),
    }
    .encode()
    .expect("request must encode");
    assert!(matches!(
        supervisor.dispatch_wire(&identity, &request),
        Err(SupervisorError::SubjectClosed(_))
    ));
}

#[test]
fn closed_handle_id_cannot_be_reused() {
    let (mut supervisor, identity) = new_supervisor();
    let handle = HandleId::new("handle-never-reuse");
    supervisor
        .open_handle(&identity, handle.clone(), ObjectId::new("object-1"))
        .expect("handle setup must succeed");
    supervisor
        .close_handle(&identity, &handle)
        .expect("handle close must succeed");

    let before = supervisor.resources().events.len();
    assert!(matches!(
        supervisor.open_handle(&identity, handle, ObjectId::new("object-2")),
        Err(SupervisorError::StaleHandle(_))
    ));
    assert_eq!(supervisor.resources().events.len(), before);
}

// Requirement: revocation is gated on the connection like every other authority operation.
// Category: unit/security. Risk: high.
#[test]
fn revoke_requires_a_bound_running_connection() {
    let root_identity = ConnectionIdentity::new(1, 101, 1000, 1000);
    let mut callers = StaticCallerResolver::new();
    callers
        .bind(root_identity, root_subject())
        .expect("root caller binding must be unique");
    let kernel = CapabilityKernel::new(CapabilityState::new(IssuerId::new("session")));
    let mut supervisor = Supervisor::new(kernel, FakeResources::default(), callers)
        .expect("pristine kernel must initialize supervisor");
    supervisor
        .create_subject(Subject::new(root_subject(), root_envelope()), root_identity)
        .expect("root setup must succeed");
    let root = supervisor
        .issue_root(&root_subject(), root_grant())
        .expect("root issuance must succeed");

    let unbound = ConnectionIdentity::new(9, 109, 1000, 1000);
    assert!(
        supervisor.revoke(&unbound, &root).is_err(),
        "an unbound connection must not revoke"
    );

    supervisor
        .shutdown_subject(&root_subject())
        .expect("clean shutdown must succeed");
    assert!(
        supervisor.revoke(&root_identity, &root).is_err(),
        "a subject that is no longer running must not revoke"
    );
}

#[test]
fn a_second_connection_bound_to_one_subject_cannot_act_as_it() {
    // The resolver maps both connections to the same subject, so only the record's own
    // `connection` separates the channel that created the subject from a later one.
    let created = ConnectionIdentity::new(1, 101, 1000, 1000);
    let extra = ConnectionIdentity::new(2, 102, 1000, 1000);
    let mut callers = StaticCallerResolver::new();
    callers
        .bind(created, root_subject())
        .expect("first binding must be unique");
    callers
        .bind(extra, root_subject())
        .expect("second binding must be unique");
    let mut supervisor = Supervisor::new(
        CapabilityKernel::new(CapabilityState::new(IssuerId::new("session"))),
        FakeResources::default(),
        callers,
    )
    .expect("pristine kernel must initialize supervisor");
    supervisor
        .create_subject(Subject::new(root_subject(), root_envelope()), created)
        .expect("subject setup must succeed");

    assert!(matches!(
        supervisor.open_handle(&extra, HandleId::new("handle-1"), ObjectId::new("object-1")),
        Err(SupervisorError::ConnectionNotBoundToSubject { subject, identity })
            if subject == root_subject() && identity == extra
    ));
    assert!(
        supervisor
            .resources()
            .events
            .iter()
            .all(|event| *event != "open_handle"),
        "a foreign channel must be refused before the adapter is reached"
    );
}

#[test]
fn an_unbound_connection_reaches_no_authority_operation() {
    let (mut supervisor, _) = new_supervisor();
    let unbound = ConnectionIdentity::new(9, 909, 1000, 1000);
    let request = supervisor::WireRequest::CloseSubject {
        claimed_subject: root_subject(),
    }
    .encode()
    .expect("request must encode");

    assert!(matches!(
        supervisor.dispatch_wire(&unbound, &request),
        Err(SupervisorError::Caller(_))
    ));
    assert!(matches!(
        supervisor.open_handle(
            &unbound,
            HandleId::new("handle-1"),
            ObjectId::new("object-1")
        ),
        Err(SupervisorError::Caller(_))
    ));
    assert!(matches!(
        supervisor.derive(
            &unbound,
            &authority_core::capability::CapId::new("session:0"),
            CapabilityGrant::new(child_subject(), window(20, 80), authority()),
            time(30),
        ),
        Err(SupervisorError::Caller(_))
    ));
    assert_eq!(
        supervisor
            .lifecycle(&root_subject())
            .expect("the subject record must remain queryable"),
        SubjectLifecycle::Running,
        "a caller that cannot be resolved must change nothing"
    );
}

#[test]
fn issue_root_refuses_a_grant_naming_another_subject() {
    let (supervisor, _) = new_supervisor();

    assert!(matches!(
        supervisor.issue_root(
            &root_subject(),
            CapabilityGrant::new(child_subject(), window(1, 99), authority()),
        ),
        Err(SupervisorError::GrantSubjectMismatch { requested, granted })
            if requested == root_subject() && granted == child_subject()
    ));
}

#[test]
fn the_same_subject_id_cannot_be_created_twice() {
    let created = ConnectionIdentity::new(1, 101, 1000, 1000);
    let second = ConnectionIdentity::new(2, 102, 1000, 1000);
    let mut callers = StaticCallerResolver::new();
    callers
        .bind(created, root_subject())
        .expect("first binding must be unique");
    callers
        .bind(second, root_subject())
        .expect("second binding must be unique");
    let mut supervisor = Supervisor::new(
        CapabilityKernel::new(CapabilityState::new(IssuerId::new("session"))),
        FakeResources::default(),
        callers,
    )
    .expect("pristine kernel must initialize supervisor");
    supervisor
        .create_subject(Subject::new(root_subject(), root_envelope()), created)
        .expect("first setup must succeed");
    let after_first = supervisor.resources().events.clone();

    assert!(matches!(
        supervisor.create_subject(Subject::new(root_subject(), root_envelope()), second),
        Err(SupervisorError::DuplicateSubject(subject)) if subject == root_subject()
    ));
    assert_eq!(
        supervisor.resources().events,
        after_first,
        "a duplicate subject must be refused before any resource is acquired"
    );
}

#[test]
fn a_child_cannot_be_created_under_a_parent_that_is_not_running() {
    let root_identity = ConnectionIdentity::new(1, 101, 1000, 1000);
    let child_identity = ConnectionIdentity::new(2, 102, 1000, 1000);
    let mut callers = StaticCallerResolver::new();
    callers
        .bind(root_identity, root_subject())
        .expect("root binding must be unique");
    callers
        .bind(child_identity, child_subject())
        .expect("child binding must be unique");
    let mut supervisor = Supervisor::new(
        CapabilityKernel::new(CapabilityState::new(IssuerId::new("session"))),
        FakeResources::default(),
        callers,
    )
    .expect("pristine kernel must initialize supervisor");
    supervisor
        .create_subject(Subject::new(root_subject(), root_envelope()), root_identity)
        .expect("root setup must succeed");
    supervisor
        .shutdown_subject(&root_subject())
        .expect("shutdown must complete");
    assert_eq!(
        supervisor
            .lifecycle(&root_subject())
            .expect("the closed subject record must remain queryable"),
        SubjectLifecycle::Closed
    );
    let after_shutdown = supervisor.resources().events.clone();

    let error = supervisor
        .create_subject(
            Subject::new(child_subject(), child_envelope()).with_parent(root_subject()),
            child_identity,
        )
        .expect_err("a closed parent must not accept a new child");

    assert!(
        matches!(&error, SupervisorError::SubjectClosed(subject) if *subject == root_subject()),
        "unexpected parent gate failure: {error:?}"
    );
    assert!(
        supervisor.lifecycle(&child_subject()).is_err(),
        "a refused child must leave no record behind"
    );
    assert_eq!(
        supervisor.resources().events,
        after_shutdown,
        "the parent gate must run before any child resource is acquired"
    );
}

#[test]
fn derive_requires_a_running_caller_and_a_capability_it_holds() {
    let root_identity = ConnectionIdentity::new(1, 101, 1000, 1000);
    let child_identity = ConnectionIdentity::new(2, 102, 1000, 1000);
    let mut callers = StaticCallerResolver::new();
    callers
        .bind(root_identity, root_subject())
        .expect("root binding must be unique");
    callers
        .bind(child_identity, child_subject())
        .expect("child binding must be unique");
    let mut supervisor = Supervisor::new(
        CapabilityKernel::new(CapabilityState::new(IssuerId::new("session"))),
        FakeResources::default(),
        callers,
    )
    .expect("pristine kernel must initialize supervisor");
    supervisor
        .create_subject(Subject::new(root_subject(), root_envelope()), root_identity)
        .expect("root setup must succeed");
    supervisor
        .create_subject(
            Subject::new(child_subject(), child_envelope()).with_parent(root_subject()),
            child_identity,
        )
        .expect("child setup must succeed");
    let root = supervisor
        .issue_root(&root_subject(), root_grant())
        .expect("root issuance must succeed");

    // A caller that does not hold the parent capability cannot derive from it.
    assert!(matches!(
        supervisor.derive(
            &child_identity,
            &root,
            CapabilityGrant::new(child_subject(), window(20, 80), authority()),
            time(30),
        ),
        Err(SupervisorError::Kernel(_))
    ));

    // A closed caller cannot derive at all, even from a capability it held.
    supervisor
        .shutdown_subject(&root_subject())
        .expect("shutdown must complete");
    assert!(matches!(
        supervisor.derive(
            &root_identity,
            &root,
            CapabilityGrant::new(root_subject(), window(20, 80), authority()),
            time(30),
        ),
        Err(SupervisorError::SubjectClosed(subject)) if subject == root_subject()
    ));
}

#[test]
fn zero_registry_capacity_is_rejected_during_supervisor_construction() {
    let callers = StaticCallerResolver::new();
    let result = Supervisor::new_with_limits(
        CapabilityKernel::new(CapabilityState::new(IssuerId::new("session"))),
        FakeResources::default(),
        callers,
        SupervisorLimits::new(0, 1),
    );
    assert!(matches!(
        result,
        Err(SupervisorError::InvalidLimits(SupervisorLimitsError::Zero(
            SupervisorCapacity::Subjects
        )))
    ));
}

#[test]
fn subject_capacity_exhaustion_happens_before_the_resource_adapter() {
    let root_identity = ConnectionIdentity::new(30, 130, 1000, 1000);
    let extra_identity = ConnectionIdentity::new(31, 131, 1000, 1000);
    let extra_subject = SubjectId::new("capacity-subject");
    let mut callers = StaticCallerResolver::new();
    callers
        .bind(root_identity, root_subject())
        .expect("root binding must be unique");
    callers
        .bind(extra_identity, extra_subject.clone())
        .expect("extra binding must be unique");
    let mut supervisor = Supervisor::new_with_limits(
        CapabilityKernel::new(CapabilityState::new(IssuerId::new("session"))),
        FakeResources::default(),
        callers,
        SupervisorLimits::new(1, 8),
    )
    .expect("positive limits must construct");
    supervisor
        .create_subject(Subject::new(root_subject(), root_envelope()), root_identity)
        .expect("the single subject slot must be usable");
    let before = supervisor.resources().events.clone();

    assert!(matches!(
        supervisor.create_subject(Subject::new(extra_subject, root_envelope()), extra_identity),
        Err(SupervisorError::CapacityExceeded(
            SupervisorCapacity::Subjects
        ))
    ));
    assert_eq!(supervisor.issued_subject_count(), 1);
    assert_eq!(supervisor.resources().events, before);
}

#[test]
fn clean_rollback_consumes_subject_capacity_permanently() {
    let first_identity = ConnectionIdentity::new(32, 132, 1000, 1000);
    let second_identity = ConnectionIdentity::new(33, 133, 1000, 1000);
    let first_subject = SubjectId::new("capacity-rollback-first");
    let second_subject = SubjectId::new("capacity-rollback-second");
    let mut callers = StaticCallerResolver::new();
    callers
        .bind(first_identity, first_subject.clone())
        .expect("first binding must be unique");
    callers
        .bind(second_identity, second_subject.clone())
        .expect("second binding must be unique");
    let mut resources = FakeResources::default();
    resources.fail_once("mount");
    let mut supervisor = Supervisor::new_with_limits(
        CapabilityKernel::new(CapabilityState::new(IssuerId::new("session"))),
        resources,
        callers,
        SupervisorLimits::new(1, 8),
    )
    .expect("positive limits must construct");
    supervisor
        .create_subject(Subject::new(first_subject, root_envelope()), first_identity)
        .expect_err("first setup must fail cleanly");
    let before = supervisor.resources().events.clone();

    assert!(matches!(
        supervisor.create_subject(
            Subject::new(second_subject, root_envelope()),
            second_identity
        ),
        Err(SupervisorError::CapacityExceeded(
            SupervisorCapacity::Subjects
        ))
    ));
    assert_eq!(supervisor.issued_subject_count(), 1);
    assert_eq!(supervisor.resources().events, before);
}

#[test]
fn issued_handle_capacity_remains_exhausted_after_close_before_adapter_call() {
    let identity = ConnectionIdentity::new(34, 134, 1000, 1000);
    let mut callers = StaticCallerResolver::new();
    callers
        .bind(identity, root_subject())
        .expect("caller binding must be unique");
    let mut supervisor = Supervisor::new_with_limits(
        CapabilityKernel::new(CapabilityState::new(IssuerId::new("session"))),
        FakeResources::default(),
        callers,
        SupervisorLimits::new(1, 1),
    )
    .expect("positive limits must construct");
    supervisor
        .create_subject(Subject::new(root_subject(), root_envelope()), identity)
        .expect("subject setup must succeed");
    let first = HandleId::new("capacity-handle-first");
    supervisor
        .open_handle(&identity, first.clone(), ObjectId::new("object-1"))
        .expect("the single handle slot must be usable");
    supervisor
        .close_handle(&identity, &first)
        .expect("closing a handle must not release its identity reservation");
    let before = supervisor.resources().events.clone();

    assert!(matches!(
        supervisor.open_handle(
            &identity,
            HandleId::new("capacity-handle-second"),
            ObjectId::new("object-2"),
        ),
        Err(SupervisorError::CapacityExceeded(
            SupervisorCapacity::IssuedHandles
        ))
    ));
    assert_eq!(supervisor.issued_handle_count(), 1);
    assert_eq!(supervisor.resources().events, before);
}
