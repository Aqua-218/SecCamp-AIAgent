//! Loom models for the effect-commit and revoke synchronization boundary.
//!
//! Specification: `docs/design/verification.md`, revoke/commit row. Coverage:
//! every bounded interleaving of one effect and one revoke, plus a negative
//! control that releases shared access immediately after authorization.
//! Run with: `RUSTFLAGS='--cfg loom' cargo test --test authorization_kernel_loom`.

#![cfg(loom)]

use std::convert::Infallible;

use authority_core::{
    capability::{AuthorityBody, AuthorityRequest, CapId, CapabilityRequest, IssuerId, SubjectId},
    file::{FileAuthority, FileEffect, FileEffects, FileRequest},
    kernel::{CapabilityKernel, EffectCommitError},
    path::{CanonicalPath, PathPattern},
    repository::RepoId,
    state::{CapabilityGrant, CapabilityState, RevocationStatus, StaticAuthorityEnvelope, Subject},
    time::{MonotonicTime, TimeWindow},
};
use loom::{
    sync::{
        Arc, RwLock,
        atomic::{AtomicBool, Ordering},
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
        FileEffects::only(FileEffect::ReadData),
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
            effect_kernel.authorize_and_commit(
                &subject_id(),
                &effect_capability_id,
                &request(),
                |_| {
                    thread::yield_now();
                    assert!(
                        !effect_revoke_returned.load(Ordering::Acquire),
                        "effect committed after revoke returned"
                    );
                    Ok::<_, Infallible>(())
                },
            )
        });

        let revoke_kernel = Arc::clone(&kernel);
        let revoke_capability_id = capability_id;
        let revoke_finished = Arc::clone(&revoke_returned);
        let revoke = thread::spawn(move || {
            assert_eq!(
                revoke_kernel.revoke(&revoke_capability_id),
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
