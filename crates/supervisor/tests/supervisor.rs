#![allow(missing_docs)]

use std::{error::Error, fmt};

use authority_core::{
    capability::{AuthorityBody, IssuerId, SubjectId},
    file::{FileAuthority, FileEffect, FileEffects},
    handle::{HandleId, ObjectId, OpenHandle},
    kernel::CapabilityKernel,
    path::{CanonicalPath, PathPattern},
    repository::RepoId,
    state::{CapabilityGrant, CapabilityState, StaticAuthorityEnvelope, Subject},
    time::{MonotonicTime, TimeWindow},
};
use supervisor::{
    CgroupHandle, CleanupStep, ConnectionIdentity, ControlFdHandle, MountHandle, RuntimeResources,
    SetupStep, StaticCallerResolver, SubjectLifecycle, Supervisor, SupervisorError, WorkloadHandle,
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

    fn create_cgroup(&mut self, _subject: &SubjectId) -> Result<CgroupHandle, Self::Error> {
        self.record("create_cgroup")?;
        Ok(CgroupHandle::new(self.token()))
    }

    fn remove_cgroup(&mut self, _cgroup: CgroupHandle) -> Result<(), Self::Error> {
        self.record("remove_cgroup")
    }

    fn mount_capfs(&mut self, _subject: &SubjectId) -> Result<MountHandle, Self::Error> {
        self.record("mount")?;
        Ok(MountHandle::new(self.token()))
    }

    fn unmount_capfs(&mut self, _mount: MountHandle) -> Result<(), Self::Error> {
        self.record("unmount")
    }

    fn open_control_fd(&mut self, _subject: &SubjectId) -> Result<ControlFdHandle, Self::Error> {
        self.record("open_control")?;
        Ok(ControlFdHandle::new(self.token()))
    }

    fn close_control_fd(&mut self, _control: ControlFdHandle) -> Result<(), Self::Error> {
        self.record("close_control")
    }

    fn start_workload(
        &mut self,
        _subject: &SubjectId,
        _cgroup: CgroupHandle,
        _mount: MountHandle,
        _control: ControlFdHandle,
    ) -> Result<WorkloadHandle, Self::Error> {
        self.record("start_workload")?;
        Ok(WorkloadHandle::new(self.token()))
    }

    fn stop_workload(
        &mut self,
        _workload: WorkloadHandle,
        _cgroup: CgroupHandle,
    ) -> Result<(), Self::Error> {
        self.record("stop_workload")
    }

    fn open_handle(&mut self, _subject: &SubjectId, _handle: &HandleId) -> Result<(), Self::Error> {
        self.record("open_handle")
    }

    fn close_handle(
        &mut self,
        _subject: &SubjectId,
        _handle: &HandleId,
    ) -> Result<(), Self::Error> {
        self.record("close_handle")
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
    let mut supervisor = Supervisor::new(kernel, resources, callers);
    supervisor
        .create_subject(Subject::new(root_subject(), root_envelope()), identity)
        .expect("subject setup must succeed");
    (supervisor, identity)
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
    let mut supervisor = Supervisor::new(kernel, resources, callers);
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
    let mut supervisor = Supervisor::new(kernel, resources, callers);
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
    assert!(matches!(
        supervisor.close_handle(&child_identity, &handle),
        Err(SupervisorError::HandleNotOwned { .. })
    ));
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
    let mut supervisor = Supervisor::new(kernel, resources, callers);
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
    let mut supervisor = Supervisor::new(kernel, resources, callers);

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

#[test]
fn failed_handle_registration_retains_runtime_cleanup_and_reserves_id() {
    let identity = ConnectionIdentity::new(6, 106, 1000, 1000);
    let mut callers = StaticCallerResolver::new();
    callers
        .bind(identity, root_subject())
        .expect("caller binding must be unique");
    let handle = HandleId::new("already-issued");
    let foreign = SubjectId::new("subject-foreign");
    let kernel = CapabilityKernel::new(CapabilityState::new(IssuerId::new("session")));
    kernel
        .register_subject(Subject::new(foreign.clone(), root_envelope()))
        .expect("foreign subject setup must succeed");
    kernel
        .register_open_handle(OpenHandle::new(
            handle.clone(),
            foreign,
            ObjectId::new("foreign-object"),
        ))
        .expect("foreign handle setup must succeed");
    let mut resources = FakeResources::default();
    resources.fail_once("close_handle");
    let mut supervisor = Supervisor::new(kernel, resources, callers);
    supervisor
        .create_subject(Subject::new(root_subject(), root_envelope()), identity)
        .expect("target subject setup must succeed");

    let error = supervisor
        .open_handle(&identity, handle.clone(), ObjectId::new("target-object"))
        .expect_err("authority duplicate must reject registration");
    assert!(matches!(
        error,
        SupervisorError::SetupFailed {
            rollback,
            ..
        } if rollback.iter().any(|failure| failure.step == CleanupStep::CloseHandle)
    ));
    let before = supervisor.resources().events.len();
    assert!(matches!(
        supervisor.open_handle(&identity, handle.clone(), ObjectId::new("retry-object")),
        Err(SupervisorError::StaleHandle(_))
    ));
    assert_eq!(supervisor.resources().events.len(), before);

    supervisor
        .shutdown_subject(&root_subject())
        .expect("shutdown must retry the pending runtime close");
    assert_eq!(
        supervisor.resources().events[before..],
        [
            "stop_workload",
            "close_control",
            "close_handle",
            "unmount",
            "remove_cgroup"
        ]
    );
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
    let mut supervisor = Supervisor::new(kernel, FakeResources::default(), callers);
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
