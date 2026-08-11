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
    capability::{CapId, CapabilityRequest, SubjectId},
    state::AuthorizationEpoch,
};

const OUTCOME_STARTED: u8 = 0;
const OUTCOME_DENIED: u8 = 1;
const OUTCOME_FAILED_BEFORE_COMMIT: u8 = 2;
const OUTCOME_COMMITTED: u8 = 3;

/// Monotone identity for one authorization attempt in a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AttemptId(u64);

impl AttemptId {
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
}

impl AttemptOutcome {
    const fn code(self) -> u8 {
        match self {
            Self::Started => OUTCOME_STARTED,
            Self::Denied => OUTCOME_DENIED,
            Self::FailedBeforeCommit => OUTCOME_FAILED_BEFORE_COMMIT,
            Self::Committed => OUTCOME_COMMITTED,
        }
    }

    const fn from_code(code: u8) -> Self {
        match code {
            OUTCOME_DENIED => Self::Denied,
            OUTCOME_FAILED_BEFORE_COMMIT => Self::FailedBeforeCommit,
            OUTCOME_COMMITTED => Self::Committed,
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

    /// Returns the authorization epoch observed during commit.
    #[must_use]
    pub const fn authorization_epoch(&self) -> AuthorizationEpoch {
        self.authorization_epoch
    }
}

/// A failure that prevents reliable audit recording.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditError {
    /// An internal audit writer panicked while holding the record lock.
    LockPoisoned,
    /// The session-local attempt identity sequence cannot advance.
    AttemptIdExhausted,
}

impl fmt::Display for AuditError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LockPoisoned => formatter.write_str("authorization audit lock is poisoned"),
            Self::AttemptIdExhausted => {
                formatter.write_str("session-local attempt ID sequence is exhausted")
            }
        }
    }
}

impl Error for AuditError {}

#[derive(Debug)]
struct AttemptJournal {
    id: AttemptId,
    caller: SubjectId,
    capability_id: CapId,
    request: CapabilityRequest,
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
}

impl AuditTrail {
    pub(crate) fn new() -> Self {
        Self {
            state: Mutex::new(AuditState {
                next_attempt_sequence: Some(0),
                attempts: Vec::new(),
            }),
        }
    }

    pub(crate) fn start_attempt(
        &self,
        caller: SubjectId,
        capability_id: CapId,
        request: CapabilityRequest,
        authorization_epoch: AuthorizationEpoch,
    ) -> Result<AttemptGuard, AuditError> {
        let mut state = self.state.lock().map_err(|_| AuditError::LockPoisoned)?;
        let sequence = state
            .next_attempt_sequence
            .take()
            .ok_or(AuditError::AttemptIdExhausted)?;
        state.next_attempt_sequence = sequence.checked_add(1);
        let journal = Arc::new(AttemptJournal {
            id: AttemptId(sequence),
            caller,
            capability_id,
            request,
            authorization_epoch,
            outcome: AtomicU8::new(OUTCOME_STARTED),
        });
        state.attempts.push(Arc::clone(&journal));
        Ok(AttemptGuard { journal })
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
}

impl AttemptGuard {
    pub(crate) fn deny(self) {
        self.journal.finish(AttemptOutcome::Denied);
    }

    pub(crate) fn fail_before_commit(self) {
        self.journal.finish(AttemptOutcome::FailedBeforeCommit);
    }

    pub(crate) fn commit(self) {
        self.journal.finish(AttemptOutcome::Committed);
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
        start(&trail, 0).deny();
        start(&trail, 1).fail_before_commit();
        start(&trail, 2).commit();

        let attempts = trail
            .attempts()
            .expect("the audit lock must remain healthy");
        assert_eq!(attempts.len(), 3);
        assert_eq!(attempts[0].outcome(), AttemptOutcome::Denied);
        assert_eq!(attempts[1].outcome(), AttemptOutcome::FailedBeforeCommit);
        assert_eq!(attempts[2].outcome(), AttemptOutcome::Committed);
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
}
