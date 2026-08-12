//! Loom models for the effect-commit and revoke synchronization boundary.
//!
//! Specification: `docs/design/verification.md`, revoke/commit row. Coverage:
//! bounded interleavings for direct and ancestor revoke, compound requests,
//! two concurrent effects, and a negative control that releases shared access
//! immediately after authorization.
//! Run with: `RUSTFLAGS='--cfg loom' cargo test --test authorization_kernel_loom`.

#![cfg(loom)]

use std::convert::Infallible;

use authority_core::{
    audit::AttemptOutcome,
    capability::{
        AuthorityBody, AuthorityRequest, CapId, CapabilityRequest, CapabilityRequestSet, IssuerId,
        SubjectId,
    },
    file::{FileAuthority, FileEffect, FileEffects, FileRequest},
    handle::{HandleId, ObjectId, OpenHandle},
    kernel::{CapabilityKernel, CapabilityKernelError, EffectCommitError, EffectExecution},
    path::{CanonicalPath, PathPattern},
    repository::RepoId,
    state::{
        AuthorizationEpoch, CapabilityGrant, CapabilityState, CapabilityStateError,
        HandleCloseStatus, RevocationStatus, StaticAuthorityEnvelope, Subject, SubjectCloseStatus,
        SubjectFinishStatus,
    },
    time::{MonotonicTime, TimeWindow},
};
use loom::{
    sync::{
        Arc, RwLock,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread,
};

fn time(ticks: u64) -> MonotonicTime {
    MonotonicTime::from_ticks(ticks)
}

fn window(not_before: u64, expires_at: u64) -> TimeWindow {
    TimeWindow::new(time(not_before), time(expires_at))
        .expect("model bounds must form a non-empty time window")
}

fn subject_id() -> SubjectId {
    SubjectId::new("subject-root")
}

fn authority() -> AuthorityBody {
    AuthorityBody::File(FileAuthority::new(
        RepoId::new("workspace"),
        FileEffects::from_effects([FileEffect::ReadData, FileEffect::WriteData]),
        PathPattern::Prefix(CanonicalPath::root()),
    ))
}

fn request() -> CapabilityRequest {
    CapabilityRequest::new(
        time(50),
        AuthorityRequest::File(FileRequest::new(
            RepoId::new("workspace"),
            FileEffect::ReadData,
            CanonicalPath::new(["src", "main.rs"]).expect("model path must contain valid segments"),
        )),
    )
}

fn write_request() -> CapabilityRequest {
    CapabilityRequest::new(
        time(50),
        AuthorityRequest::File(FileRequest::new(
            RepoId::new("workspace"),
            FileEffect::WriteData,
            CanonicalPath::new(["src", "main.rs"]).expect("model path must contain valid segments"),
        )),
    )
}

fn initialized_state() -> (CapabilityState, CapId) {
    let mut state = CapabilityState::new(IssuerId::new("model-issuer"));
    let envelope = StaticAuthorityEnvelope::new(window(0, 100), authority());
    state
        .register_subject(Subject::new(subject_id(), envelope))
        .expect("model subject registration must succeed");
    let capability_id = state
        .issue_root(CapabilityGrant::new(
            subject_id(),
            window(0, 100),
            authority(),
        ))
        .expect("model root issuance must succeed");
    (state, capability_id)
}

fn child_subject_id() -> SubjectId {
    SubjectId::new("subject-child")
}

fn initialized_delegated_state() -> (CapabilityState, CapId, CapId) {
    let mut state = CapabilityState::new(IssuerId::new("model-issuer"));
    let envelope = StaticAuthorityEnvelope::new(window(0, 100), authority());
    state
        .register_subject(Subject::new(subject_id(), envelope.clone()))
        .expect("model root subject registration must succeed");
    state
        .register_subject(Subject::new(child_subject_id(), envelope).with_parent(subject_id()))
        .expect("model child subject registration must succeed");
    let root_id = state
        .issue_root(
            CapabilityGrant::new(subject_id(), window(0, 100), authority()).with_delegable(true),
        )
        .expect("model root issuance must succeed");
    let child_id = state
        .derive(
            &subject_id(),
            &root_id,
            CapabilityGrant::new(child_subject_id(), window(0, 100), authority()),
            time(50),
        )
        .expect("model child derivation must succeed");
    (state, root_id, child_id)
}

// This intentionally broken control proves that the model contains the TOCTOU
// schedule the production guard is intended to eliminate.
struct CheckThenCommitKernel {
    state: RwLock<CapabilityState>,
}

impl CheckThenCommitKernel {
    fn new(state: CapabilityState) -> Self {
        Self {
            state: RwLock::new(state),
        }
    }

    fn authorize_then_commit(
        &self,
        caller: &SubjectId,
        capability_id: &CapId,
        request: &CapabilityRequest,
        commit: impl FnOnce(),
    ) -> bool {
        let state = self
            .state
            .read()
            .expect("the negative-control lock must remain healthy");
        let authorized = state.authorizes(caller, capability_id, request);
        drop(state);

        if !authorized {
            return false;
        }
        thread::yield_now();
        commit();
        true
    }

    fn revoke(&self, capability_id: &CapId) {
        self.state
            .write()
            .expect("the negative-control lock must remain healthy")
            .revoke(capability_id)
            .expect("the model capability must exist");
    }
}

// Requirement: production shared/exclusive locking admits only two orders:
// commit before revoke returns, or authorization denial after revoke.
// Category: bounded concurrency/security. Risk: critical.
#[test]
fn guarded_commit_never_crosses_a_completed_revoke() {
    loom::model(|| {
        let (state, capability_id) = initialized_state();
        let kernel = Arc::new(CapabilityKernel::new(state));
        let revoke_returned = Arc::new(AtomicBool::new(false));

        let effect_kernel = Arc::clone(&kernel);
        let effect_capability_id = capability_id.clone();
        let effect_revoke_returned = Arc::clone(&revoke_returned);
        let effect = thread::spawn(move || {
            effect_kernel.authorize_and_execute_classified(
                &subject_id(),
                &effect_capability_id,
                &request(),
                |_| {
                    thread::yield_now();
                    assert!(
                        !effect_revoke_returned.load(Ordering::Acquire),
                        "effect committed after revoke returned"
                    );
                    EffectExecution::<_, Infallible>::Committed {
                        value: (),
                        receipt: None,
                    }
                },
            )
        });

        let revoke_kernel = Arc::clone(&kernel);
        let revoke_capability_id = capability_id;
        let revoke_finished = Arc::clone(&revoke_returned);
        let revoke = thread::spawn(move || {
            assert_eq!(
                revoke_kernel.revoke_held_by(&subject_id(), &revoke_capability_id),
                Ok(RevocationStatus::NewlyRevoked)
            );
            revoke_finished.store(true, Ordering::Release);
        });

        let effect_result = effect.join().expect("the effect thread must not panic");
        revoke.join().expect("the revoke thread must not panic");
        assert!(matches!(
            effect_result,
            Ok(()) | Err(EffectCommitError::NotAuthorized)
        ));
        let attempts = kernel
            .attempt_records()
            .expect("the model audit trail must remain readable");
        let effects = kernel
            .effect_records()
            .expect("the model effect trail must remain readable");
        assert_eq!(attempts.len(), 1);
        match effect_result {
            Ok(()) => {
                assert_eq!(attempts[0].outcome(), AttemptOutcome::Committed);
                assert_eq!(
                    attempts[0].authorization_epoch(),
                    AuthorizationEpoch::default()
                );
                assert_eq!(effects.len(), 1);
            }
            Err(EffectCommitError::NotAuthorized) => {
                assert_eq!(attempts[0].outcome(), AttemptOutcome::Denied);
                assert_eq!(attempts[0].authorization_epoch().as_u64(), 1);
                assert!(effects.is_empty());
            }
            Err(error) => panic!("the model returned an unexpected effect error: {error}"),
        }
    });
}

// Requirement: revoking a root uses the same exclusion boundary for a child
// effect as direct revocation. Category: bounded concurrency/security. Risk: critical.
#[test]
fn guarded_descendant_commit_never_crosses_completed_ancestor_revoke() {
    loom::model(|| {
        let (state, root_id, child_id) = initialized_delegated_state();
        let kernel = Arc::new(CapabilityKernel::new(state));
        let revoke_returned = Arc::new(AtomicBool::new(false));

        let effect_kernel = Arc::clone(&kernel);
        let effect_revoke_returned = Arc::clone(&revoke_returned);
        let effect = thread::spawn(move || {
            effect_kernel.authorize_and_execute_classified(
                &child_subject_id(),
                &child_id,
                &request(),
                |_| {
                    thread::yield_now();
                    assert!(
                        !effect_revoke_returned.load(Ordering::Acquire),
                        "descendant effect committed after ancestor revoke returned"
                    );
                    EffectExecution::<_, Infallible>::Committed {
                        value: (),
                        receipt: None,
                    }
                },
            )
        });

        let revoke_kernel = Arc::clone(&kernel);
        let revoke_finished = Arc::clone(&revoke_returned);
        let revoke = thread::spawn(move || {
            assert_eq!(
                revoke_kernel.revoke_held_by(&subject_id(), &root_id),
                Ok(RevocationStatus::NewlyRevoked)
            );
            revoke_finished.store(true, Ordering::Release);
        });

        let effect_result = effect.join().expect("the effect thread must not panic");
        revoke.join().expect("the revoke thread must not panic");
        assert!(matches!(
            effect_result,
            Ok(()) | Err(EffectCommitError::NotAuthorized)
        ));
        assert_eq!(
            kernel
                .effect_records()
                .expect("the model effect trail must remain readable")
                .len(),
            usize::from(effect_result.is_ok())
        );
    });
}

fn check_compound_commit_against_revoke(revoke_ancestor: bool) {
    loom::model(move || {
        let (state, ancestor_id, capability_id) = initialized_delegated_state();
        let revoke_id = if revoke_ancestor {
            ancestor_id
        } else {
            capability_id.clone()
        };
        let revoke_subject = if revoke_ancestor {
            subject_id()
        } else {
            child_subject_id()
        };
        let kernel = Arc::new(CapabilityKernel::new(state));
        let revoke_returned = Arc::new(AtomicBool::new(false));
        let executor_entries = Arc::new(AtomicUsize::new(0));
        let executor_steps = Arc::new(AtomicUsize::new(0));
        let expected_requests = [request(), write_request()];
        let requests =
            CapabilityRequestSet::new(expected_requests[0].clone(), [expected_requests[1].clone()]);

        let effect_kernel = Arc::clone(&kernel);
        let effect_revoke_returned = Arc::clone(&revoke_returned);
        let effect_executor_entries = Arc::clone(&executor_entries);
        let effect_executor_steps = Arc::clone(&executor_steps);
        let effect = thread::spawn(move || {
            effect_kernel.authorize_all_and_execute_classified(
                &child_subject_id(),
                &capability_id,
                &requests,
                |_| {
                    effect_executor_entries.fetch_add(1, Ordering::AcqRel);
                    assert!(
                        !effect_revoke_returned.load(Ordering::Acquire),
                        "compound executor entered after revoke returned"
                    );

                    effect_executor_steps.fetch_add(1, Ordering::AcqRel);
                    thread::yield_now();
                    assert!(
                        !effect_revoke_returned.load(Ordering::Acquire),
                        "revoke returned between compound executor steps"
                    );
                    effect_executor_steps.fetch_add(1, Ordering::AcqRel);
                    EffectExecution::<_, Infallible>::Committed {
                        value: (),
                        receipt: None,
                    }
                },
            )
        });

        let revoke_kernel = Arc::clone(&kernel);
        let revoke_finished = Arc::clone(&revoke_returned);
        let revoke = thread::spawn(move || {
            assert_eq!(
                revoke_kernel.revoke_held_by(&revoke_subject, &revoke_id),
                Ok(RevocationStatus::NewlyRevoked)
            );
            revoke_finished.store(true, Ordering::Release);
        });

        let effect_result = effect.join().expect("the effect thread must not panic");
        revoke.join().expect("the revoke thread must not panic");

        let attempts = kernel
            .attempt_records()
            .expect("the model audit trail must remain readable");
        let effects = kernel
            .effect_records()
            .expect("the model effect trail must remain readable");
        assert_eq!(attempts.len(), 1);
        assert_eq!(
            attempts[0].requests().collect::<Vec<_>>(),
            expected_requests.iter().collect::<Vec<_>>()
        );

        match effect_result {
            Ok(()) => {
                assert_eq!(executor_entries.load(Ordering::Acquire), 1);
                assert_eq!(executor_steps.load(Ordering::Acquire), 2);
                assert_eq!(attempts[0].outcome(), AttemptOutcome::Committed);
                assert_eq!(effects.len(), 1);
                assert_eq!(
                    effects[0].requests().collect::<Vec<_>>(),
                    expected_requests.iter().collect::<Vec<_>>()
                );
            }
            Err(EffectCommitError::NotAuthorized) => {
                assert_eq!(executor_entries.load(Ordering::Acquire), 0);
                assert_eq!(executor_steps.load(Ordering::Acquire), 0);
                assert_eq!(attempts[0].outcome(), AttemptOutcome::Denied);
                assert!(effects.is_empty());
            }
            Err(error) => panic!("the model returned an unexpected effect error: {error}"),
        }
    });
}

// Requirement: a compound operation is either fully guarded before direct
// revoke or denied without entering its executor. Category: bounded
// concurrency/security. Risk: critical.
#[test]
fn compound_commit_never_partially_crosses_completed_direct_revoke() {
    check_compound_commit_against_revoke(false);
}

// Requirement: ancestor revoke applies the same all-or-deny boundary to a
// descendant's compound operation. Category: bounded concurrency/security.
// Risk: critical.
#[test]
fn compound_commit_never_partially_crosses_completed_ancestor_revoke() {
    check_compound_commit_against_revoke(true);
}

// Requirement: every effect already holding shared access may commit before
// revoke, while every later effect is denied. Category: bounded concurrency/security.
// Risk: critical.
#[test]
fn two_guarded_effects_remain_consistent_with_one_revoke_order() {
    let mut model = loom::model::Builder::new();
    // Three threads plus audit bookkeeping produce many equivalent schedules.
    // Two preemptions still cover both effects before revoke, revoke before
    // both effects, and one effect on each side of revoke.
    model.preemption_bound = Some(2);
    model.check(|| {
        let (state, capability_id) = initialized_state();
        let kernel = Arc::new(CapabilityKernel::new(state));
        let revoke_returned = Arc::new(AtomicBool::new(false));
        let executor_calls = Arc::new(AtomicUsize::new(0));

        let spawn_effect = |kernel: &Arc<CapabilityKernel>,
                            revoke_returned: &Arc<AtomicBool>,
                            executor_calls: &Arc<AtomicUsize>| {
            let effect_kernel = Arc::clone(kernel);
            let effect_revoke_returned = Arc::clone(revoke_returned);
            let effect_calls = Arc::clone(executor_calls);
            let effect_capability_id = capability_id.clone();
            thread::spawn(move || {
                effect_kernel.authorize_and_execute_classified(
                    &subject_id(),
                    &effect_capability_id,
                    &request(),
                    |_| {
                        assert!(
                            !effect_revoke_returned.load(Ordering::Acquire),
                            "effect committed after revoke returned"
                        );
                        effect_calls.fetch_add(1, Ordering::AcqRel);
                        EffectExecution::<_, Infallible>::Committed {
                            value: (),
                            receipt: None,
                        }
                    },
                )
            })
        };

        let first_effect = spawn_effect(&kernel, &revoke_returned, &executor_calls);
        let second_effect = spawn_effect(&kernel, &revoke_returned, &executor_calls);
        let revoke_kernel = Arc::clone(&kernel);
        let revoke_finished = Arc::clone(&revoke_returned);
        let revoke = thread::spawn(move || {
            assert_eq!(
                revoke_kernel.revoke_held_by(&subject_id(), &capability_id),
                Ok(RevocationStatus::NewlyRevoked)
            );
            revoke_finished.store(true, Ordering::Release);
        });

        let first_result = first_effect
            .join()
            .expect("the first effect thread must not panic");
        let second_result = second_effect
            .join()
            .expect("the second effect thread must not panic");
        revoke.join().expect("the revoke thread must not panic");
        assert!(matches!(
            first_result,
            Ok(()) | Err(EffectCommitError::NotAuthorized)
        ));
        assert!(matches!(
            second_result,
            Ok(()) | Err(EffectCommitError::NotAuthorized)
        ));

        let committed = usize::from(first_result.is_ok()) + usize::from(second_result.is_ok());
        assert_eq!(executor_calls.load(Ordering::Acquire), committed);
        let attempts = kernel
            .attempt_records()
            .expect("the model audit trail must remain readable");
        let effects = kernel
            .effect_records()
            .expect("the model effect trail must remain readable");
        assert_eq!(attempts.len(), 2);
        assert_eq!(
            attempts
                .iter()
                .filter(|attempt| attempt.outcome() == AttemptOutcome::Committed)
                .count(),
            committed
        );
        assert_eq!(effects.len(), committed);
    });
}

// Requirement: open-handle registration and subject shutdown have one
// linearization order; a closing subject cannot retain a handle that was
// registered after shutdown returned. Category: bounded concurrency/security.
// Risk: critical.
#[test]
fn open_handle_registration_and_shutdown_are_linearized() {
    let mut model = loom::model::Builder::new();
    model.preemption_bound = Some(2);
    model.check(|| {
        let (state, _) = initialized_state();
        let kernel = Arc::new(CapabilityKernel::new(state));
        let handle_id = HandleId::new("loom-handle");
        let handle = OpenHandle::new(
            handle_id.clone(),
            subject_id(),
            ObjectId::new("loom-object"),
        );

        let register_kernel = Arc::clone(&kernel);
        let register_handle = handle.clone();
        let register = thread::spawn(move || register_kernel.register_open_handle(register_handle));
        let close_kernel = Arc::clone(&kernel);
        let close = thread::spawn(move || close_kernel.begin_subject_close(&subject_id()));

        let register_result = register
            .join()
            .expect("handle registration thread must not panic");
        let close_result = close
            .join()
            .expect("subject shutdown thread must not panic");
        assert!(matches!(
            close_result,
            Ok(SubjectCloseStatus::Started | SubjectCloseStatus::AlreadyClosing)
        ));
        assert!(matches!(
            register_result,
            Ok(())
                | Err(CapabilityKernelError::StateTransition(
                    CapabilityStateError::SubjectNotRunning(_)
                ))
        ));

        let has_live_handle = kernel
            .open_handle(&handle_id)
            .expect("handle lookup must remain readable")
            .is_some();
        if has_live_handle {
            assert_eq!(
                kernel.finish_subject_close(&subject_id()),
                Err(CapabilityKernelError::StateTransition(
                    CapabilityStateError::SubjectHasOpenHandles(subject_id()),
                ))
            );
            assert_eq!(
                kernel.close_handle(&subject_id(), &handle_id),
                Ok(HandleCloseStatus::Closed)
            );
        }
        assert_eq!(
            kernel.finish_subject_close(&subject_id()),
            Ok(SubjectFinishStatus::Closed)
        );
        assert_eq!(
            kernel.open_handle(&handle_id),
            Ok(None),
            "a closed subject must not retain a live handle"
        );
    });
}

// Requirement: two distinct revokes are both monotone and a descendant
// effect is ordered before both completed revokes or denied after the first
// one. Category: bounded concurrency/security. Risk: critical.
#[test]
fn multiple_direct_and_ancestor_revokes_preserve_effect_order() {
    let mut model = loom::model::Builder::new();
    model.preemption_bound = Some(2);
    model.check(|| {
        let (state, root_id, child_id) = initialized_delegated_state();
        let kernel = Arc::new(CapabilityKernel::new(state));
        let completed_revokes = Arc::new(AtomicUsize::new(0));

        let effect_kernel = Arc::clone(&kernel);
        let effect_child_id = child_id.clone();
        let effect_completed_revokes = Arc::clone(&completed_revokes);
        let effect = thread::spawn(move || {
            effect_kernel.authorize_and_execute_classified(
                &child_subject_id(),
                &effect_child_id,
                &request(),
                |_| {
                    assert_eq!(
                        effect_completed_revokes.load(Ordering::Acquire),
                        0,
                        "an effect cannot commit after either revoke returned"
                    );
                    EffectExecution::<_, Infallible>::Committed {
                        value: (),
                        receipt: None,
                    }
                },
            )
        });

        let child_revoke_kernel = Arc::clone(&kernel);
        let child_revoke_completed = Arc::clone(&completed_revokes);
        let child_revoke_id = child_id.clone();
        let child_revoke = thread::spawn(move || {
            let result = child_revoke_kernel.revoke_held_by(&child_subject_id(), &child_revoke_id);
            assert_eq!(result, Ok(RevocationStatus::NewlyRevoked));
            child_revoke_completed.fetch_add(1, Ordering::AcqRel);
        });

        let root_revoke_kernel = Arc::clone(&kernel);
        let root_revoke_completed = Arc::clone(&completed_revokes);
        let root_revoke = thread::spawn(move || {
            let result = root_revoke_kernel.revoke_held_by(&subject_id(), &root_id);
            assert_eq!(result, Ok(RevocationStatus::NewlyRevoked));
            root_revoke_completed.fetch_add(1, Ordering::AcqRel);
        });

        let effect_result = effect.join().expect("effect thread must not panic");
        child_revoke
            .join()
            .expect("child revoke thread must not panic");
        root_revoke
            .join()
            .expect("root revoke thread must not panic");
        assert!(matches!(
            effect_result,
            Ok(()) | Err(EffectCommitError::NotAuthorized)
        ));
        assert_eq!(completed_revokes.load(Ordering::Acquire), 2);
        assert_eq!(
            kernel
                .authorization_epoch()
                .expect("epoch must be readable")
                .as_u64(),
            2
        );
        let attempts = kernel
            .attempt_records()
            .expect("audit records must remain readable");
        assert_eq!(attempts.len(), 1);
        assert_eq!(
            attempts[0].outcome(),
            if effect_result.is_ok() {
                AttemptOutcome::Committed
            } else {
                AttemptOutcome::Denied
            }
        );
    });
}

// Requirement: the negative control must expose an authorization/commit gap.
// Category: mutation/negative control. Risk: critical.
#[test]
#[should_panic(expected = "negative control committed after revoke returned")]
fn unlocked_negative_control_admits_a_post_revoke_commit() {
    loom::model(|| {
        let (state, capability_id) = initialized_state();
        let kernel = Arc::new(CheckThenCommitKernel::new(state));
        let revoke_returned = Arc::new(AtomicBool::new(false));

        let effect_kernel = Arc::clone(&kernel);
        let effect_capability_id = capability_id.clone();
        let effect_revoke_returned = Arc::clone(&revoke_returned);
        let effect = thread::spawn(move || {
            effect_kernel.authorize_then_commit(
                &subject_id(),
                &effect_capability_id,
                &request(),
                || {
                    assert!(
                        !effect_revoke_returned.load(Ordering::Acquire),
                        "negative control committed after revoke returned"
                    );
                },
            );
        });

        let revoke_kernel = Arc::clone(&kernel);
        let revoke_finished = Arc::clone(&revoke_returned);
        let revoke = thread::spawn(move || {
            revoke_kernel.revoke(&capability_id);
            revoke_finished.store(true, Ordering::Release);
        });

        effect.join().expect("the effect thread must not panic");
        revoke.join().expect("the revoke thread must not panic");
    });
}
