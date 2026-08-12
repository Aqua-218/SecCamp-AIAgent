//! Contract tests for synchronized effect authorization and state transitions.
//!
//! Specification: `docs/design/state-and-revocation.md`, section
//! "Commit versus revoke". Coverage: final authorization, executor invocation,
//! transition error propagation, ancestor revocation, and pre-commit failures.
//! Related concurrency model: `authorization_kernel_loom.rs`.

use std::{
    cell::Cell,
    convert::Infallible,
    error::Error,
    fmt,
    sync::{Arc, Barrier, mpsc},
    thread,
    time::Duration,
};

use authority_core::{
    audit::AttemptOutcome,
    capability::{
        AuthorityBody, AuthorityRequest, CapId, CapabilityRequest, CapabilityRequestSet, IssuerId,
        SubjectId,
    },
    file::{FileAuthority, FileEffect, FileEffects, FileRequest},
    handle::{HandleId, ObjectId, OpenHandle},
    kernel::{
        CapabilityInspectionError, CapabilityKernel, CapabilityKernelError, EffectCommitError,
    },
    path::{CanonicalPath, PathPattern},
    repository::RepoId,
    state::{
        AuthorizationEpoch, CapabilityGrant, CapabilityState, CapabilityStateError,
        HandleCloseStatus, RevocationStatus, StaticAuthorityEnvelope, Subject, SubjectCloseStatus,
        SubjectFinishStatus, SubjectStatus,
    },
    time::{MonotonicTime, TimeWindow},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ExecutorFailure;

impl fmt::Display for ExecutorFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("backing operation was rejected")
    }
}

impl Error for ExecutorFailure {}

fn time(ticks: u64) -> MonotonicTime {
    MonotonicTime::from_ticks(ticks)
}

fn window(not_before: u64, expires_at: u64) -> TimeWindow {
    TimeWindow::new(time(not_before), time(expires_at))
        .expect("test bounds must form a non-empty time window")
}

fn path(segments: &[&str]) -> CanonicalPath {
    CanonicalPath::new(segments).expect("test paths must contain valid segments")
}

fn authority(effects: impl IntoIterator<Item = FileEffect>, pattern: PathPattern) -> AuthorityBody {
    AuthorityBody::File(FileAuthority::new(
        RepoId::new("workspace"),
        FileEffects::from_effects(effects),
        pattern,
    ))
}

fn root_subject_id() -> SubjectId {
    SubjectId::new("subject-root")
}

fn child_subject_id() -> SubjectId {
    SubjectId::new("subject-child")
}

fn root_envelope() -> StaticAuthorityEnvelope {
    StaticAuthorityEnvelope::new(
        window(0, 100),
        authority(
            [FileEffect::ReadData, FileEffect::WriteData],
            PathPattern::Prefix(CanonicalPath::root()),
        ),
    )
}

fn child_envelope() -> StaticAuthorityEnvelope {
    StaticAuthorityEnvelope::new(
        window(10, 90),
        authority([FileEffect::ReadData], PathPattern::Prefix(path(&["src"]))),
    )
}

fn root_grant() -> CapabilityGrant {
    CapabilityGrant::new(
        root_subject_id(),
        window(10, 90),
        authority(
            [FileEffect::ReadData, FileEffect::WriteData],
            PathPattern::Prefix(CanonicalPath::root()),
        ),
    )
    .with_delegable(true)
}

fn child_grant() -> CapabilityGrant {
    CapabilityGrant::new(
        child_subject_id(),
        window(20, 80),
        authority([FileEffect::ReadData], PathPattern::Prefix(path(&["src"]))),
    )
}

fn read_request(ticks: u64, segments: &[&str]) -> CapabilityRequest {
    file_request(ticks, FileEffect::ReadData, segments)
}

fn file_request(ticks: u64, effect: FileEffect, segments: &[&str]) -> CapabilityRequest {
    CapabilityRequest::new(
        time(ticks),
        AuthorityRequest::File(FileRequest::new(
            RepoId::new("workspace"),
            effect,
            path(segments),
        )),
    )
}

fn kernel_with_root() -> (CapabilityKernel, CapId) {
    let kernel = CapabilityKernel::new(CapabilityState::new(IssuerId::new("session-issuer")));
    kernel
        .register_subject(Subject::new(root_subject_id(), root_envelope()))
        .expect("root subject registration must succeed");
    kernel
        .register_subject(
            Subject::new(child_subject_id(), child_envelope()).with_parent(root_subject_id()),
        )
        .expect("child subject registration must succeed");
    let root_id = kernel
        .issue_root(root_grant())
        .expect("root issuance must succeed");
    (kernel, root_id)
}

// Requirement: exclusive kernel transitions retain the sequential state's
// exact typed errors. Category: state/error. Risk: high.
#[test]
fn transition_errors_retain_their_typed_state_source() {
    let kernel = CapabilityKernel::new(CapabilityState::new(IssuerId::new("session-issuer")));
    let missing_subject = SubjectId::new("subject-missing");

    let error = kernel
        .issue_root(CapabilityGrant::new(
            missing_subject.clone(),
            window(10, 20),
            authority(
                [FileEffect::ReadData],
                PathPattern::Prefix(CanonicalPath::root()),
            ),
        ))
        .expect_err("an unregistered subject must not receive a root capability");

    assert_eq!(
        error,
        CapabilityKernelError::StateTransition(CapabilityStateError::UnknownSubject(
            missing_subject
        ))
    );
    assert_eq!(
        error.to_string(),
        "target subject `subject-missing` is not registered"
    );
    assert_eq!(
        error.source().map(ToString::to_string),
        Some("target subject `subject-missing` is not registered".to_owned())
    );
}

// Requirement: registration, issuance, and Derive remain available through
// the exclusive kernel boundary. Category: normal/state. Risk: critical.
#[test]
fn kernel_derives_and_commits_with_the_exact_authorizing_capability() {
    let (kernel, root_id) = kernel_with_root();
    let child_id = kernel
        .derive(&root_subject_id(), &root_id, child_grant(), time(30))
        .expect("a narrower child must be derivable");

    let committed_id = kernel
        .authorize_and_commit(
            &child_subject_id(),
            &child_id,
            &read_request(30, &["src", "main.rs"]),
            |capability| Ok::<_, Infallible>(capability.metadata().id().clone()),
        )
        .expect("the child must authorize a read inside its scope");

    assert_eq!(committed_id, child_id);
}

// Requirement: one external operation with multiple authority boundaries is
// authorized and audited atomically. Category: authorization/audit. Risk: critical.
#[test]
fn compound_commit_requires_every_request_and_records_the_complete_set() {
    let (kernel, root_id) = kernel_with_root();
    let read = read_request(30, &["src", "main.rs"]);
    let write = file_request(30, FileEffect::WriteData, &["src", "main.rs"]);
    let requests = CapabilityRequestSet::new(read.clone(), [write.clone()]);

    kernel
        .authorize_all_and_commit(&root_subject_id(), &root_id, &requests, |_| {
            Ok::<_, Infallible>(())
        })
        .expect("the root capability must authorize both requested effects");

    let attempts = kernel
        .attempt_records()
        .expect("the audit trail must remain readable");
    let effects = kernel
        .effect_records()
        .expect("the audit trail must remain readable");
    assert_eq!(attempts.len(), 1);
    assert_eq!(effects.len(), 1);
    assert_eq!(attempts[0].requests().collect::<Vec<_>>(), [&read, &write]);
    assert_eq!(effects[0].requests().collect::<Vec<_>>(), [&read, &write]);
}

// Requirement: metadata policy may inspect only an active capability held by
// the transport-authenticated caller. Category: authorization/security. Risk: critical.
#[test]
fn active_capability_inspection_preserves_subject_and_lifecycle_binding() {
    let (kernel, root_id) = kernel_with_root();

    let inspected_id = kernel
        .with_active_capability(&root_subject_id(), &root_id, time(30), |capability| {
            Ok::<_, Infallible>(capability.metadata().id().clone())
        })
        .expect("the owner must inspect its active capability");
    assert_eq!(inspected_id, root_id);
    assert_eq!(
        kernel.with_active_capability(&child_subject_id(), &root_id, time(30), |_| Ok::<
            _,
            Infallible,
        >(()),),
        Err(CapabilityInspectionError::NotActive)
    );

    kernel
        .revoke(&root_id)
        .expect("the active root capability must be revocable");
    assert_eq!(
        kernel.with_active_capability(&root_subject_id(), &root_id, time(30), |_| Ok::<
            _,
            Infallible,
        >(()),),
        Err(CapabilityInspectionError::NotActive)
    );
    assert!(
        kernel
            .attempt_records()
            .expect("audit records must remain readable")
            .is_empty(),
        "metadata inspection must not fabricate an external effect attempt"
    );
}

// Requirement: revoke cannot complete while an earlier authority inspection
// still relies on the capability. Category: concurrency/security. Risk: critical.
#[test]
fn revoke_waits_for_active_capability_inspection() {
    let (kernel, root_id) = kernel_with_root();
    let kernel = Arc::new(kernel);
    let inspection_started = Arc::new(Barrier::new(2));
    let release_inspection = Arc::new(Barrier::new(2));
    let (revoke_started_tx, revoke_started_rx) = mpsc::channel();
    let (revoke_finished_tx, revoke_finished_rx) = mpsc::channel();

    thread::scope(|scope| {
        let inspecting_kernel = Arc::clone(&kernel);
        let inspecting_id = root_id.clone();
        let inspecting_started = Arc::clone(&inspection_started);
        let inspecting_release = Arc::clone(&release_inspection);
        let inspection = scope.spawn(move || {
            inspecting_kernel.with_active_capability(
                &root_subject_id(),
                &inspecting_id,
                time(30),
                |_| {
                    inspecting_started.wait();
                    inspecting_release.wait();
                    Ok::<_, Infallible>(())
                },
            )
        });

        inspection_started.wait();
        let revoking_kernel = Arc::clone(&kernel);
        let revoking_id = root_id.clone();
        let revoke = scope.spawn(move || {
            revoke_started_tx
                .send(())
                .expect("the test observer must remain connected");
            let result = revoking_kernel.revoke(&revoking_id);
            revoke_finished_tx
                .send(())
                .expect("the test observer must remain connected");
            result
        });

        revoke_started_rx
            .recv()
            .expect("the revoke thread must begin");
        assert_eq!(
            revoke_finished_rx.recv_timeout(Duration::from_millis(50)),
            Err(mpsc::RecvTimeoutError::Timeout),
            "revoke must wait for the shared inspection guard"
        );
        release_inspection.wait();

        assert_eq!(
            inspection.join().expect("inspection thread must not panic"),
            Ok(())
        );
        assert_eq!(
            revoke.join().expect("revoke thread must not panic"),
            Ok(RevocationStatus::NewlyRevoked)
        );
        revoke_finished_rx
            .recv()
            .expect("revoke must finish after inspection releases its guard");
    });
}

// Requirement: a failed final check must not invoke the effect executor.
// Category: authorization decision table/security. Risk: critical.
#[test]
fn denied_effects_never_invoke_the_executor() {
    let (kernel, root_id) = kernel_with_root();
    let executor_calls = Cell::new(0_u8);
    let forged_id = CapId::new("forged-capability");
    let cases = [
        (
            child_subject_id(),
            root_id.clone(),
            read_request(30, &["src", "main.rs"]),
        ),
        (
            root_subject_id(),
            forged_id,
            read_request(30, &["src", "main.rs"]),
        ),
        (
            root_subject_id(),
            root_id.clone(),
            read_request(90, &["src", "main.rs"]),
        ),
        (
            root_subject_id(),
            root_id.clone(),
            file_request(30, FileEffect::Rename, &["src", "main.rs"]),
        ),
    ];

    for (caller, capability_id, request) in cases {
        let result = kernel.authorize_and_commit(&caller, &capability_id, &request, |_| {
            executor_calls.set(executor_calls.get() + 1);
            Ok::<_, Infallible>(())
        });

        assert_eq!(result, Err(EffectCommitError::NotAuthorized));
    }
    assert_eq!(executor_calls.get(), 0);
}

// Requirement: executor failures remain distinguishable from authorization
// failures and release shared access. Category: error/state. Risk: critical.
#[test]
fn pre_commit_effect_failure_is_reported_and_releases_the_guard() {
    let (kernel, root_id) = kernel_with_root();

    let error = kernel
        .authorize_and_commit(
            &root_subject_id(),
            &root_id,
            &read_request(30, &["src", "main.rs"]),
            |_| Err::<(), _>(ExecutorFailure),
        )
        .expect_err("the executor failure must be propagated");

    assert_eq!(error, EffectCommitError::Effect(ExecutorFailure));
    assert_eq!(
        error.to_string(),
        "effect failed before its linearization point: backing operation was rejected"
    );
    assert_eq!(
        error.source().map(ToString::to_string),
        Some("backing operation was rejected".to_owned())
    );
    assert_eq!(kernel.revoke(&root_id), Ok(RevocationStatus::NewlyRevoked));
}

// Requirement: once ancestor revoke returns, a descendant cannot start an
// effect based only on that authority. Category: state/security. Risk: critical.
#[test]
fn ancestor_revoke_prevents_every_later_executor_call() {
    let (kernel, root_id) = kernel_with_root();
    let child_id = kernel
        .derive(&root_subject_id(), &root_id, child_grant(), time(30))
        .expect("child derivation must succeed before revoke");
    let executor_calls = Cell::new(0_u8);

    assert_eq!(
        kernel.authorization_epoch(),
        Ok(AuthorizationEpoch::default())
    );
    assert_eq!(kernel.revoke(&root_id), Ok(RevocationStatus::NewlyRevoked));
    assert_eq!(
        kernel.authorization_epoch().map(AuthorizationEpoch::as_u64),
        Ok(1)
    );
    let result = kernel.authorize_and_commit(
        &child_subject_id(),
        &child_id,
        &read_request(30, &["src", "main.rs"]),
        |_| {
            executor_calls.set(executor_calls.get() + 1);
            Ok::<_, Infallible>(())
        },
    );

    assert_eq!(result, Err(EffectCommitError::NotAuthorized));
    assert_eq!(executor_calls.get(), 0);
    assert_eq!(
        kernel.revoke(&root_id),
        Ok(RevocationStatus::AlreadyRevoked)
    );
    assert_eq!(
        kernel.authorization_epoch().map(AuthorizationEpoch::as_u64),
        Ok(1)
    );
}

// Requirement: the synchronized lifecycle API blocks authorization before it
// reports that shutdown has begun. Category: lifecycle/security. Risk: critical.
#[test]
fn subject_close_blocks_later_executor_calls() {
    let (kernel, root_id) = kernel_with_root();
    let executor_calls = Cell::new(0_u8);

    assert_eq!(
        kernel.begin_subject_close(&root_subject_id()),
        Ok(SubjectCloseStatus::Started)
    );
    assert_eq!(
        kernel.subject_status(&root_subject_id()),
        Ok(Some(SubjectStatus::Closing))
    );
    let result = kernel.authorize_and_commit(
        &root_subject_id(),
        &root_id,
        &read_request(30, &["src", "main.rs"]),
        |_| {
            executor_calls.set(executor_calls.get() + 1);
            Ok::<_, Infallible>(())
        },
    );

    assert_eq!(result, Err(EffectCommitError::NotAuthorized));
    assert_eq!(executor_calls.get(), 0);
    assert_eq!(
        kernel.finish_subject_close(&root_subject_id()),
        Ok(SubjectFinishStatus::Closed)
    );
}

// Requirement: the synchronized handle API preserves object counts, rejects
// foreign close, and keeps stale IDs closed. Category: state/security. Risk: high.
#[test]
fn kernel_tracks_live_handles_without_reusing_ids() {
    let (kernel, _) = kernel_with_root();
    let handle_id = HandleId::new("handle-1");
    let object_id = ObjectId::new("object-1");
    let handle = OpenHandle::new(handle_id.clone(), root_subject_id(), object_id.clone());

    assert_eq!(kernel.register_open_handle(handle.clone()), Ok(()));
    assert_eq!(kernel.open_handle(&handle_id), Ok(Some(handle)));
    assert_eq!(kernel.object_open_handle_count(&object_id), Ok(1));
    assert_eq!(
        kernel.close_handle(&child_subject_id(), &handle_id),
        Err(CapabilityKernelError::StateTransition(
            CapabilityStateError::HandleNotOwned {
                caller: child_subject_id(),
                handle: handle_id.clone(),
            }
        ))
    );
    assert_eq!(kernel.object_open_handle_count(&object_id), Ok(1));
    assert_eq!(
        kernel.close_handle(&root_subject_id(), &handle_id),
        Ok(HandleCloseStatus::Closed)
    );
    assert_eq!(kernel.open_handle(&handle_id), Ok(None));
    assert_eq!(kernel.object_open_handle_count(&object_id), Ok(0));
    assert_eq!(
        kernel.close_handle(&root_subject_id(), &handle_id),
        Ok(HandleCloseStatus::AlreadyClosed)
    );
}

// Requirement: every checked request is an attempt, while only a successful
// executor creates an effect record. Category: audit/security. Risk: critical.
#[test]
fn audit_distinguishes_denied_failed_and_committed_attempts() {
    let (kernel, root_id) = kernel_with_root();
    let denied_request = file_request(30, FileEffect::Rename, &["src", "main.rs"]);
    let failed_request = read_request(30, &["src", "failed.rs"]);
    let committed_request = read_request(30, &["src", "committed.rs"]);

    assert_eq!(
        kernel.authorize_and_commit(&root_subject_id(), &root_id, &denied_request, |_| Ok::<
            _,
            Infallible,
        >(
            ()
        ),),
        Err(EffectCommitError::NotAuthorized)
    );
    assert_eq!(
        kernel.authorize_and_commit(&root_subject_id(), &root_id, &failed_request, |_| Err::<
            (),
            _,
        >(
            ExecutorFailure
        ),),
        Err(EffectCommitError::Effect(ExecutorFailure))
    );
    kernel
        .authorize_and_commit(&root_subject_id(), &root_id, &committed_request, |_| {
            Ok::<_, Infallible>(())
        })
        .expect("the final request must commit");

    let attempts = kernel
        .attempt_records()
        .expect("the audit trail must remain readable");
    assert_eq!(attempts.len(), 3);
    assert_eq!(attempts[0].id().as_u64(), 0);
    assert_eq!(attempts[0].outcome(), AttemptOutcome::Denied);
    assert_eq!(attempts[0].request(), &denied_request);
    assert_eq!(attempts[1].id().as_u64(), 1);
    assert_eq!(attempts[1].outcome(), AttemptOutcome::FailedBeforeCommit);
    assert_eq!(attempts[1].request(), &failed_request);
    assert_eq!(attempts[2].id().as_u64(), 2);
    assert_eq!(attempts[2].outcome(), AttemptOutcome::Committed);
    assert_eq!(attempts[2].request(), &committed_request);
    assert_eq!(
        attempts[2].authorization_epoch(),
        AuthorizationEpoch::default()
    );

    let effects = kernel
        .effect_records()
        .expect("the effect trail must remain readable");
    assert_eq!(effects.len(), 1);
    assert_eq!(effects[0].attempt_id(), attempts[2].id());
    assert_eq!(effects[0].caller(), &root_subject_id());
    assert_eq!(effects[0].capability_id(), &root_id);
    assert_eq!(effects[0].request(), &committed_request);
}
