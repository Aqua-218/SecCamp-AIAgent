//! Durable audit contract tests.
//!
//! Specification: `docs/authority-core/audit-records.md`, durable WAL and
//! receipt contract. Coverage: persistence across reopen, incomplete external
//! effect windows, sequence continuation, and kernel integration.

use std::{
    fs,
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
};

use authority_core::{
    audit::{AttemptId, AttemptOutcome, AuditError},
    capability::{AuthorityBody, AuthorityRequest, CapId, CapabilityRequest, IssuerId, SubjectId},
    durable_audit::{CommitReceipt, DurableAuditError, DurableAuditLog},
    file::{FileAuthority, FileEffect, FileEffects, FileRequest},
    kernel::{CapabilityKernel, EffectCommitError},
    path::{CanonicalPath, PathPattern},
    repository::RepoId,
    state::{
        AuthorizationEpoch, CapabilityGrant, CapabilityState, StaticAuthorityEnvelope, Subject,
    },
    time::{MonotonicTime, TimeWindow},
};

static NEXT_PATH: AtomicU64 = AtomicU64::new(0);

struct TestJournal {
    path: std::path::PathBuf,
}

impl TestJournal {
    fn new() -> Self {
        let serial = NEXT_PATH.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "authority-core-durable-integration-{}-{serial}.wal",
            std::process::id()
        ));
        let _ = fs::remove_file(&path);
        Self { path }
    }
}

impl Drop for TestJournal {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

fn time(ticks: u64) -> MonotonicTime {
    MonotonicTime::from_ticks(ticks)
}

fn window(not_before: u64, expires_at: u64) -> TimeWindow {
    TimeWindow::new(time(not_before), time(expires_at))
        .expect("test bounds must form a non-empty time window")
}

fn request() -> CapabilityRequest {
    CapabilityRequest::new(
        time(10),
        AuthorityRequest::File(FileRequest::new(
            RepoId::new("workspace"),
            FileEffect::ReadData,
            CanonicalPath::new(["src", "main.rs"]).expect("test path must be valid"),
        )),
    )
}

fn authority() -> AuthorityBody {
    AuthorityBody::File(FileAuthority::new(
        RepoId::new("workspace"),
        FileEffects::only(FileEffect::ReadData),
        PathPattern::Prefix(CanonicalPath::root()),
    ))
}

fn initial_state() -> CapabilityState {
    let mut state = CapabilityState::new(IssuerId::new("durable-issuer"));
    state
        .register_subject(Subject::new(
            SubjectId::new("subject"),
            StaticAuthorityEnvelope::new(window(0, 20), authority()),
        ))
        .expect("test subject must register");
    state
}

fn issue_root(kernel: &CapabilityKernel) -> CapId {
    kernel
        .issue_root(CapabilityGrant::new(
            SubjectId::new("subject"),
            window(0, 20),
            authority(),
        ))
        .expect("test root capability must issue")
}

#[test]
fn kernel_durable_audit_survives_reopen_and_continues_attempt_ids() {
    let journal = TestJournal::new();
    let backend = DurableAuditLog::create(&journal.path).expect("journal creation must sync");
    let kernel = CapabilityKernel::try_new_with_durable_audit(initial_state(), backend)
        .expect("a healthy backend must construct a kernel");
    let capability_id = issue_root(&kernel);
    kernel
        .authorize_and_commit(
            &SubjectId::new("subject"),
            &capability_id,
            &request(),
            |_| Ok::<_, std::convert::Infallible>(()),
        )
        .expect("authorized effect must commit");
    drop(kernel);

    let reopened = DurableAuditLog::open(&journal.path).expect("durable records must reopen");
    let records = reopened
        .attempts()
        .expect("reopened records must be readable");
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].attempt_id(), AttemptId::from_u64(0));
    assert_eq!(records[0].outcome(), AttemptOutcome::Committed);
    assert_eq!(
        records[0]
            .receipt()
            .expect("commit receipt must persist")
            .attempt_id(),
        AttemptId::from_u64(0)
    );

    let next_kernel = CapabilityKernel::try_new_with_durable_audit(initial_state(), reopened)
        .expect("reopened backend must construct a new kernel");
    let next_capability_id = issue_root(&next_kernel);
    next_kernel
        .authorize_and_commit(
            &SubjectId::new("subject"),
            &next_capability_id,
            &request(),
            |_| Ok::<_, std::convert::Infallible>(()),
        )
        .expect("the reopened session must accept a new effect");
    let records = next_kernel
        .attempt_records()
        .expect("in-memory audit must remain readable");
    assert_eq!(records[0].id(), AttemptId::from_u64(1));
}

#[test]
fn durable_kernel_preserves_external_root_identity_and_skips_it_sequentially() {
    let journal = TestJournal::new();
    let backend = DurableAuditLog::create(&journal.path).expect("journal creation must sync");
    let kernel = CapabilityKernel::try_new_with_durable_audit(initial_state(), backend)
        .expect("a healthy backend must construct a kernel");
    let external_id = CapId::new("durable-issuer:0");
    let issued_id = kernel
        .issue_root_with_id(
            external_id.clone(),
            CapabilityGrant::new(SubjectId::new("subject"), window(0, 20), authority()),
        )
        .expect("the durable kernel must accept the host identity");
    assert_eq!(issued_id, external_id);
    assert_eq!(issue_root(&kernel).as_str(), "durable-issuer:1");

    kernel
        .authorize_and_commit(&SubjectId::new("subject"), &external_id, &request(), |_| {
            Ok::<_, std::convert::Infallible>(())
        })
        .expect("the exact external identity must authorize normally");
    let attempts = kernel
        .attempt_records()
        .expect("the durable audit trail must remain readable");
    assert_eq!(attempts.len(), 1);
    assert_eq!(attempts[0].capability_id(), &external_id);
}

#[test]
fn durable_wal_preserves_unknown_completion_after_crash_window() {
    let journal = TestJournal::new();
    let backend = DurableAuditLog::create(&journal.path).expect("journal creation must sync");
    let requests = authority_core::capability::CapabilityRequestSet::one(request());
    backend
        .begin_attempt(
            AttemptId::from_u64(0),
            &SubjectId::new("subject"),
            &CapId::new("capability"),
            &requests,
            AuthorizationEpoch::default(),
        )
        .expect("attempt start must be synced before external work");
    drop(backend);

    let reopened = DurableAuditLog::open(&journal.path).expect("the synced start must reopen");
    let attempts = reopened
        .attempts()
        .expect("recovered attempts must be readable");
    assert_eq!(attempts[0].outcome(), AttemptOutcome::Started);
    assert!(attempts[0].receipt().is_none());

    reopened
        .finish_attempt(
            AttemptId::from_u64(0),
            AttemptOutcome::Committed,
            Some(&CommitReceipt::new(
                AttemptId::from_u64(0),
                b"reconciled-provider-receipt".to_vec(),
            )),
        )
        .expect("an explicit reconciliation receipt may close the started attempt");
    assert_eq!(
        reopened.attempts().expect("records must remain readable")[0].outcome(),
        AttemptOutcome::Committed
    );
}

#[test]
fn terminal_receipt_failure_reports_possible_external_commit() {
    let journal = TestJournal::new();
    let backend = DurableAuditLog::create(&journal.path).expect("journal creation must sync");
    let kernel = CapabilityKernel::try_new_with_durable_audit(initial_state(), backend)
        .expect("a healthy backend must construct a kernel");
    let capability_id = issue_root(&kernel);
    let result = kernel.authorize_and_commit_with_receipt(
        &SubjectId::new("subject"),
        &capability_id,
        &request(),
        |_| Ok::<_, std::convert::Infallible>(((), vec![0_u8; 8 * 1024 * 1024])),
    );

    assert!(matches!(
        result,
        Err(EffectCommitError::CommittedButAudit(AuditError::Durable(
            DurableAuditError::RecordTooLarge(_)
        )))
    ));
    assert_eq!(
        kernel
            .attempt_records()
            .expect("the in-memory audit must remain readable")[0]
            .outcome(),
        AttemptOutcome::Started,
        "receipt failure must remain visibly unresolved rather than false success"
    );
}

#[test]
fn pre_executor_journal_replay_fails_closed_without_invoking_executor() {
    let journal = TestJournal::new();
    let backend = DurableAuditLog::create(&journal.path).expect("journal creation must sync");
    let kernel = CapabilityKernel::try_new_with_durable_audit(initial_state(), backend.clone())
        .expect("a healthy backend must construct a kernel");
    let requests = authority_core::capability::CapabilityRequestSet::one(request());
    backend
        .begin_attempt(
            AttemptId::from_u64(0),
            &SubjectId::new("other-subject"),
            &CapId::new("other-capability"),
            &requests,
            AuthorizationEpoch::default(),
        )
        .expect("the replay fixture start must be durable");
    let capability_id = issue_root(&kernel);
    let executor_called = AtomicBool::new(false);

    let result = kernel.authorize_and_commit(
        &SubjectId::new("subject"),
        &capability_id,
        &request(),
        |_| {
            executor_called.store(true, Ordering::Release);
            Ok::<_, std::convert::Infallible>(())
        },
    );

    assert!(matches!(
        result,
        Err(EffectCommitError::Audit(AuditError::Durable(
            DurableAuditError::ReplayDetected { .. }
        )))
    ));
    assert!(!executor_called.load(Ordering::Acquire));
}
