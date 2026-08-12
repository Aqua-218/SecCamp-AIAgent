//! Append-only authorization-attempt and committed-effect audit records.

use std::{error::Error, fmt};

#[cfg(loom)]
use loom::sync::{
    Arc, Mutex,
    atomic::{AtomicU8, Ordering},
};
#[cfg(not(loom))]
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicU8, Ordering},
};

use crate::{
    capability::{CapId, CapabilityRequest, CapabilityRequestSet, SubjectId},
    durable_audit::{CommitReceipt, CommitUnknownEvidence, DurableAuditError, DurableAuditLog},
    state::AuthorizationEpoch,
};

const OUTCOME_STARTED: u8 = 0;
const OUTCOME_DENIED: u8 = 1;
const OUTCOME_FAILED_BEFORE_COMMIT: u8 = 2;
const OUTCOME_COMMITTED: u8 = 3;
const OUTCOME_COMMIT_UNKNOWN: u8 = 4;

/// Monotone identity for one authorization attempt in a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AttemptId(u64);

impl AttemptId {
    /// Creates an attempt identity from a recovered session-local sequence.
    #[must_use]
    pub const fn from_u64(value: u64) -> Self {
        Self(value)
    }

    /// Returns the numeric session-local identity.
    #[must_use]
    pub const fn as_u64(self) -> u64 {
        self.0
    }
}

/// Current terminal state of an authorization attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AttemptOutcome {
    /// The attempt was recorded but did not reach a terminal state.
    Started,
    /// Final authorization rejected the request before executor invocation.
    Denied,
    /// The executor failed before its documented linearization point.
    FailedBeforeCommit,
    /// The executor reached its documented linearization point.
    Committed,
    /// The executor may have crossed its linearization point, but completion could not be proven.
    CommitUnknown,
}

impl AttemptOutcome {
    const fn code(self) -> u8 {
        match self {
            Self::Started => OUTCOME_STARTED,
            Self::Denied => OUTCOME_DENIED,
            Self::FailedBeforeCommit => OUTCOME_FAILED_BEFORE_COMMIT,
            Self::Committed => OUTCOME_COMMITTED,
            Self::CommitUnknown => OUTCOME_COMMIT_UNKNOWN,
        }
    }

    const fn from_code(code: u8) -> Self {
        match code {
            OUTCOME_DENIED => Self::Denied,
            OUTCOME_FAILED_BEFORE_COMMIT => Self::FailedBeforeCommit,
            OUTCOME_COMMITTED => Self::Committed,
            OUTCOME_COMMIT_UNKNOWN => Self::CommitUnknown,
            _ => Self::Started,
        }
    }
}

/// Snapshot of one authorization attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttemptRecord {
    id: AttemptId,
    caller: SubjectId,
    capability_id: CapId,
    request: CapabilityRequest,
    additional_requests: Vec<CapabilityRequest>,
    authorization_epoch: AuthorizationEpoch,
    outcome: AttemptOutcome,
}

impl AttemptRecord {
    /// Returns the monotone attempt identity.
    #[must_use]
    pub const fn id(&self) -> AttemptId {
        self.id
    }

    /// Returns the authenticated subject that made the attempt.
    #[must_use]
    pub const fn caller(&self) -> &SubjectId {
        &self.caller
    }

    /// Returns the capability identity presented by the caller.
    #[must_use]
    pub const fn capability_id(&self) -> &CapId {
        &self.capability_id
    }

    /// Returns the exact request checked by final authorization.
    #[must_use]
    pub const fn request(&self) -> &CapabilityRequest {
        &self.request
    }

    /// Returns every request that was required for this external operation.
    ///
    /// The first item is also available through [`Self::request`] for
    /// single-request compatibility.
    #[must_use]
    pub fn requests(&self) -> impl DoubleEndedIterator<Item = &CapabilityRequest> {
        std::iter::once(&self.request).chain(self.additional_requests.iter())
    }

    /// Returns the authorization epoch observed during the final check.
    #[must_use]
    pub const fn authorization_epoch(&self) -> AuthorizationEpoch {
        self.authorization_epoch
    }

    /// Returns the attempt's current or terminal outcome.
    #[must_use]
    pub const fn outcome(&self) -> AttemptOutcome {
        self.outcome
    }
}

/// Snapshot of one effect that reached its documented linearization point.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectRecord {
    attempt_id: AttemptId,
    caller: SubjectId,
    capability_id: CapId,
    request: CapabilityRequest,
    additional_requests: Vec<CapabilityRequest>,
    authorization_epoch: AuthorizationEpoch,
}

impl EffectRecord {
    /// Returns the attempt that authorized this effect.
    #[must_use]
    pub const fn attempt_id(&self) -> AttemptId {
        self.attempt_id
    }

    /// Returns the authenticated subject that committed the effect.
    #[must_use]
    pub const fn caller(&self) -> &SubjectId {
        &self.caller
    }

    /// Returns the exact capability identity used for authorization.
    #[must_use]
    pub const fn capability_id(&self) -> &CapId {
        &self.capability_id
    }

    /// Returns the committed typed request.
    #[must_use]
    pub const fn request(&self) -> &CapabilityRequest {
        &self.request
    }

    /// Returns every request that authorized this committed external effect.
    ///
    /// The first item is also available through [`Self::request`] for
    /// single-request compatibility.
    #[must_use]
    pub fn requests(&self) -> impl DoubleEndedIterator<Item = &CapabilityRequest> {
        std::iter::once(&self.request).chain(self.additional_requests.iter())
    }

    /// Returns the authorization epoch observed during commit.
    #[must_use]
    pub const fn authorization_epoch(&self) -> AuthorizationEpoch {
        self.authorization_epoch
    }
}

/// A failure that prevents reliable audit recording.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditError {
    /// An internal audit writer panicked while holding the record lock.
    LockPoisoned,
    /// The session-local attempt identity sequence cannot advance.
    AttemptIdExhausted,
    /// The durable backend rejected or could not persist the journal update.
    Durable(DurableAuditError),
}

impl fmt::Display for AuditError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LockPoisoned => formatter.write_str("authorization audit lock is poisoned"),
            Self::AttemptIdExhausted => {
                formatter.write_str("session-local attempt ID sequence is exhausted")
            }
            Self::Durable(error) => error.fmt(formatter),
        }
    }
}

impl Error for AuditError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Durable(error) => Some(error),
            Self::LockPoisoned | Self::AttemptIdExhausted => None,
        }
    }
}

impl From<DurableAuditError> for AuditError {
    fn from(error: DurableAuditError) -> Self {
        Self::Durable(error)
    }
}

#[derive(Debug)]
struct AttemptJournal {
    id: AttemptId,
    caller: SubjectId,
    capability_id: CapId,
    request: CapabilityRequest,
    additional_requests: Vec<CapabilityRequest>,
    authorization_epoch: AuthorizationEpoch,
    outcome: AtomicU8,
}

impl AttemptJournal {
    fn snapshot(&self) -> AttemptRecord {
        AttemptRecord {
            id: self.id,
            caller: self.caller.clone(),
            capability_id: self.capability_id.clone(),
            request: self.request.clone(),
            additional_requests: self.additional_requests.clone(),
            authorization_epoch: self.authorization_epoch,
            outcome: AttemptOutcome::from_code(self.outcome.load(Ordering::Acquire)),
        }
    }

    fn effect_snapshot(&self) -> Option<EffectRecord> {
        (self.outcome.load(Ordering::Acquire) == OUTCOME_COMMITTED).then(|| EffectRecord {
            attempt_id: self.id,
            caller: self.caller.clone(),
            capability_id: self.capability_id.clone(),
            request: self.request.clone(),
            additional_requests: self.additional_requests.clone(),
            authorization_epoch: self.authorization_epoch,
        })
    }

    fn finish(&self, outcome: AttemptOutcome) {
        debug_assert_ne!(outcome, AttemptOutcome::Started);
        self.outcome.store(outcome.code(), Ordering::Release);
    }
}

#[derive(Debug)]
struct AuditState {
    next_attempt_sequence: Option<u64>,
    attempts: Vec<Arc<AttemptJournal>>,
}

/// In-memory append-only journal for authorization attempts.
///
/// Each attempt is appended before final authorization. Its outcome is a
/// single atomic transition, so recording a committed effect cannot fail after
/// the external executor has crossed its linearization point.
#[derive(Debug)]
pub(crate) struct AuditTrail {
    state: Mutex<AuditState>,
    backend: Option<Arc<DurableAuditLog>>,
}

impl AuditTrail {
    pub(crate) fn new() -> Self {
        Self {
            state: Mutex::new(AuditState {
                next_attempt_sequence: Some(0),
                attempts: Vec::new(),
            }),
            backend: None,
        }
    }

    pub(crate) fn new_with_backend(backend: Arc<DurableAuditLog>) -> Result<Self, AuditError> {
        let next_attempt_sequence = backend.next_attempt_sequence()?;
        Ok(Self {
            state: Mutex::new(AuditState {
                next_attempt_sequence,
                attempts: Vec::new(),
            }),
            backend: Some(backend),
        })
    }

    #[cfg(test)]
    pub(crate) fn start_attempt(
        &self,
        caller: SubjectId,
        capability_id: CapId,
        request: CapabilityRequest,
        authorization_epoch: AuthorizationEpoch,
    ) -> Result<AttemptGuard, AuditError> {
        self.start_request_set(
            caller,
            capability_id,
            &CapabilityRequestSet::one(request),
            authorization_epoch,
        )
    }

    /// Records a non-empty set of requests before their shared final check.
    pub(crate) fn start_request_set(
        &self,
        caller: SubjectId,
        capability_id: CapId,
        requests: &CapabilityRequestSet,
        authorization_epoch: AuthorizationEpoch,
    ) -> Result<AttemptGuard, AuditError> {
        let mut state = self.state.lock().map_err(|_| AuditError::LockPoisoned)?;
        let sequence = state
            .next_attempt_sequence
            .take()
            .ok_or(AuditError::AttemptIdExhausted)?;
        state.next_attempt_sequence = sequence.checked_add(1);
        if let Some(backend) = &self.backend
            && let Err(error) = backend.begin_attempt(
                AttemptId::from_u64(sequence),
                &caller,
                &capability_id,
                requests,
                authorization_epoch,
            )
        {
            state.next_attempt_sequence = Some(sequence);
            return Err(AuditError::Durable(error));
        }
        let journal = Arc::new(AttemptJournal {
            id: AttemptId(sequence),
            caller,
            capability_id,
            request: requests.first().clone(),
            additional_requests: requests.additional().to_vec(),
            authorization_epoch,
            outcome: AtomicU8::new(OUTCOME_STARTED),
        });
        state.attempts.push(Arc::clone(&journal));
        Ok(AttemptGuard {
            journal,
            backend: self.backend.clone(),
        })
    }

    pub(crate) fn attempts(&self) -> Result<Vec<AttemptRecord>, AuditError> {
        let state = self.state.lock().map_err(|_| AuditError::LockPoisoned)?;
        Ok(state
            .attempts
            .iter()
            .map(|attempt| attempt.snapshot())
            .collect())
    }

    pub(crate) fn effects(&self) -> Result<Vec<EffectRecord>, AuditError> {
        let state = self.state.lock().map_err(|_| AuditError::LockPoisoned)?;
        Ok(state
            .attempts
            .iter()
            .filter_map(|attempt| attempt.effect_snapshot())
            .collect())
    }
}

pub(crate) struct AttemptGuard {
    journal: Arc<AttemptJournal>,
    backend: Option<Arc<DurableAuditLog>>,
}

impl AttemptGuard {
    pub(crate) fn id(&self) -> AttemptId {
        self.journal.id
    }

    pub(crate) fn deny(self) -> Result<(), AuditError> {
        self.finish(AttemptOutcome::Denied, None, None)
    }

    pub(crate) fn fail_before_commit(self) -> Result<(), AuditError> {
        self.finish(AttemptOutcome::FailedBeforeCommit, None, None)
    }

    #[cfg(test)]
    pub(crate) fn commit(self) -> Result<(), AuditError> {
        let receipt = CommitReceipt::kernel_success(self.journal.id);
        self.commit_with_receipt(&receipt)
    }

    pub(crate) fn commit_with_receipt(self, receipt: &CommitReceipt) -> Result<(), AuditError> {
        self.finish(AttemptOutcome::Committed, Some(receipt), None)
    }

    #[allow(dead_code)] // The kernel's bounded ambiguous-result callback wires this terminal path.
    pub(crate) fn commit_unknown(self, evidence: impl Into<Vec<u8>>) -> Result<(), AuditError> {
        let evidence = CommitUnknownEvidence::new(self.journal.id, evidence)?;
        self.finish(AttemptOutcome::CommitUnknown, None, Some(&evidence))
    }

    fn finish(
        self,
        outcome: AttemptOutcome,
        receipt: Option<&CommitReceipt>,
        commit_unknown_evidence: Option<&CommitUnknownEvidence>,
    ) -> Result<(), AuditError> {
        if let Some(backend) = &self.backend {
            backend.finish_attempt(self.journal.id, outcome, receipt, commit_unknown_evidence)?;
        }
        self.journal.finish(outcome);
        Ok(())
    }
}

#[cfg(all(test, not(loom)))]
mod tests {
    use super::{AttemptOutcome, AuditError, AuditTrail};
    use crate::{
        capability::{AuthorityRequest, CapId, CapabilityRequest, SubjectId},
        file::{FileEffect, FileRequest},
        path::CanonicalPath,
        repository::RepoId,
        state::AuthorizationEpoch,
        time::MonotonicTime,
    };

    fn request() -> CapabilityRequest {
        CapabilityRequest::new(
            MonotonicTime::from_ticks(10),
            AuthorityRequest::File(FileRequest::new(
                RepoId::new("workspace"),
                FileEffect::ReadData,
                CanonicalPath::root(),
            )),
        )
    }

    fn start(trail: &AuditTrail, sequence: u64) -> super::AttemptGuard {
        trail
            .start_attempt(
                SubjectId::new(format!("subject-{sequence}")),
                CapId::new(format!("capability-{sequence}")),
                request(),
                AuthorizationEpoch::default(),
            )
            .expect("the fixed audit sequence must remain available")
    }

    #[test]
    fn effect_snapshots_include_only_committed_attempts() {
        let trail = AuditTrail::new();
        start(&trail, 0).deny().expect("denial must be recorded");
        start(&trail, 1)
            .fail_before_commit()
            .expect("pre-commit failure must be recorded");
        start(&trail, 2).commit().expect("commit must be recorded");
        start(&trail, 3)
            .commit_unknown(b"provider-timeout-after-send")
            .expect("commit-unknown must be recorded");

        let attempts = trail
            .attempts()
            .expect("the audit lock must remain healthy");
        assert_eq!(attempts.len(), 4);
        assert_eq!(attempts[0].outcome(), AttemptOutcome::Denied);
        assert_eq!(attempts[1].outcome(), AttemptOutcome::FailedBeforeCommit);
        assert_eq!(attempts[2].outcome(), AttemptOutcome::Committed);
        assert_eq!(attempts[3].outcome(), AttemptOutcome::CommitUnknown);
        let effects = trail.effects().expect("the audit lock must remain healthy");
        assert_eq!(effects.len(), 1);
        assert_eq!(effects[0].attempt_id(), attempts[2].id());
    }

    #[test]
    fn exhausted_attempt_ids_fail_before_record_creation() {
        let trail = AuditTrail::new();
        trail
            .state
            .lock()
            .expect("the audit lock must remain healthy")
            .next_attempt_sequence = None;

        assert!(matches!(
            trail.start_attempt(
                SubjectId::new("subject"),
                CapId::new("capability"),
                request(),
                AuthorizationEpoch::default(),
            ),
            Err(AuditError::AttemptIdExhausted)
        ));
        assert!(
            trail
                .attempts()
                .expect("the audit lock must remain healthy")
                .is_empty()
        );
    }

    #[test]
    fn empty_commit_unknown_evidence_leaves_attempt_non_terminal() {
        let trail = AuditTrail::new();
        let attempt = start(&trail, 0);

        assert!(matches!(
            attempt.commit_unknown(Vec::new()),
            Err(AuditError::Durable(
                crate::durable_audit::DurableAuditError::InvalidRecord(message)
            )) if message == "CommitUnknown evidence cannot be empty"
        ));
        let attempts = trail
            .attempts()
            .expect("rejected evidence must leave the audit readable");
        assert_eq!(attempts[0].outcome(), AttemptOutcome::Started);
        assert!(
            trail
                .effects()
                .expect("rejected evidence must not poison effects")
                .is_empty()
        );
    }

    #[test]
    fn poisoned_audit_lock_rejects_new_attempts() {
        let trail = AuditTrail::new();
        let poisoned = &trail;
        std::thread::scope(|scope| {
            scope
                .spawn(|| {
                    let _guard = poisoned
                        .state
                        .lock()
                        .expect("test audit lock must initially be healthy");
                    panic!("poison in-memory audit lock");
                })
                .join()
                .expect_err("the fixture thread must panic");
        });

        assert_eq!(
            trail.attempts(),
            Err(AuditError::LockPoisoned),
            "a poisoned audit lock must not expose partial records"
        );
    }
}
