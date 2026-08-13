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
    durable_audit::{
        CommitReceipt, CommitUnknownEvidence, DurableAttempt, DurableAttemptMetadata,
        DurableAuditError, DurableAuditLog, ReconciledCommit,
    },
    state::AuthorizationEpoch,
};

/// Evidence recorded when recovery closes an attempt whose process stopped mid-effect.
const RECOVERED_ATTEMPT_EVIDENCE: &[u8] =
    b"authority-core recovery closed an attempt left started by an unclean shutdown";

const OUTCOME_STARTED: u8 = 0;
const OUTCOME_DENIED: u8 = 1;
const OUTCOME_FAILED_BEFORE_COMMIT: u8 = 2;
const OUTCOME_COMMITTED: u8 = 3;
const OUTCOME_COMMIT_UNKNOWN: u8 = 4;

/// What one journal recovery inherited and had to reconcile.
///
/// Prior attempts are never re-authorized. They stay in the journal as history belonging to an
/// earlier capability-state instance, and the attempts that were still `Started` are closed as
/// `CommitUnknown` so the journal holds no attempt whose fate is silently undetermined.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditRecovery {
    state_instance: u64,
    inherited_attempts: usize,
    reconciled: Vec<AttemptId>,
}

impl AuditRecovery {
    /// Returns the capability-state instance every new attempt is recorded under.
    #[must_use]
    pub const fn state_instance(&self) -> u64 {
        self.state_instance
    }

    /// Returns how many attempts the journal already held.
    #[must_use]
    pub const fn inherited_attempts(&self) -> usize {
        self.inherited_attempts
    }

    /// Returns the prior attempts closed as `CommitUnknown` by this recovery.
    #[must_use]
    pub fn reconciled(&self) -> &[AttemptId] {
        &self.reconciled
    }
}

/// Resolves whether an attempt whose commit was unknown actually landed.
///
/// Implemented by the adapter that owns the external boundary, because only it can ask the
/// provider. The decoded metadata carries the typed request, so an implementation identifies the
/// operation from the audit record itself rather than from separate bookkeeping that could drift.
pub trait CommitReconciler {
    /// Adapter-specific failure type.
    type Error: Error + Send + Sync + 'static;

    /// Returns the provider's verdict, or `None` while the outcome stays unknown.
    ///
    /// Returning `None` is the honest answer when the provider cannot say. It leaves the record
    /// unresolved rather than guessing, and the attempt can be reconciled again later.
    ///
    /// # Errors
    ///
    /// Returns the adapter error when the provider could not be consulted at all.
    fn resolve(
        &mut self,
        attempt: &DurableAttempt,
        metadata: &DurableAttemptMetadata,
    ) -> Result<Option<ReconciledCommit>, Self::Error>;
}

/// What one reconciliation pass resolved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReconciliationSummary {
    committed: Vec<AttemptId>,
    not_committed: Vec<AttemptId>,
    still_unknown: Vec<AttemptId>,
}

impl ReconciliationSummary {
    /// Returns the attempts a provider confirmed as committed.
    #[must_use]
    pub fn committed(&self) -> &[AttemptId] {
        &self.committed
    }

    /// Returns the attempts a provider confirmed never landed.
    #[must_use]
    pub fn not_committed(&self) -> &[AttemptId] {
        &self.not_committed
    }

    /// Returns the attempts whose outcome the provider still cannot determine.
    #[must_use]
    pub fn still_unknown(&self) -> &[AttemptId] {
        &self.still_unknown
    }
}

/// Failure while reconciling unknown commits against their providers.
#[derive(Debug)]
pub enum ReconciliationError {
    /// The journal could not be read or appended to.
    Durable(DurableAuditError),
    /// A provider adapter failed while being consulted.
    ///
    /// Carries the attempt so an operator knows which record is still open.
    Provider {
        /// Attempt whose provider could not be consulted.
        attempt: AttemptId,
        /// Adapter failure.
        source: Box<dyn Error + Send + Sync>,
    },
}

impl fmt::Display for ReconciliationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Durable(error) => error.fmt(formatter),
            Self::Provider { attempt, source } => write!(
                formatter,
                "provider could not be consulted for attempt {}: {source}",
                attempt.as_u64()
            ),
        }
    }
}

impl Error for ReconciliationError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Durable(error) => Some(error),
            Self::Provider { source, .. } => Some(source.as_ref()),
        }
    }
}

/// Asks a provider about every unresolved `CommitUnknown` attempt and records what it says.
///
/// Recovery leaves `CommitUnknown` records behind on purpose: the host genuinely could not tell.
/// This is the second half of that story, and it is separate because only an adapter that can
/// reach the provider can finish it. Verdicts append to the journal; nothing already written is
/// rewritten.
///
/// # Errors
///
/// Returns [`ReconciliationError`] on the first journal failure, or when an adapter reports it
/// could not consult its provider. Verdicts recorded before the failure stay durable.
pub fn reconcile_unknown_commits<R>(
    log: &DurableAuditLog,
    reconciler: &mut R,
) -> Result<ReconciliationSummary, ReconciliationError>
where
    R: CommitReconciler,
{
    let attempts = log.attempts().map_err(ReconciliationError::Durable)?;
    let mut summary = ReconciliationSummary {
        committed: Vec::new(),
        not_committed: Vec::new(),
        still_unknown: Vec::new(),
    };
    for attempt in attempts {
        if attempt.outcome() != AttemptOutcome::CommitUnknown || attempt.reconciliation().is_some()
        {
            continue;
        }
        let metadata = attempt.metadata().map_err(ReconciliationError::Durable)?;
        let verdict = reconciler.resolve(&attempt, &metadata).map_err(|error| {
            ReconciliationError::Provider {
                attempt: attempt.attempt_id(),
                source: Box::new(error),
            }
        })?;
        let Some(verdict) = verdict else {
            summary.still_unknown.push(attempt.attempt_id());
            continue;
        };
        log.reconcile_attempt(attempt.attempt_id(), &verdict)
            .map_err(ReconciliationError::Durable)?;
        match verdict {
            ReconciledCommit::Committed(_) => summary.committed.push(attempt.attempt_id()),
            ReconciledCommit::NotCommitted => summary.not_committed.push(attempt.attempt_id()),
        }
    }
    Ok(summary)
}

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
    /// Recovery found attempts from a prior capability-state instance.
    ///
    /// The audit WAL does not persist the [`crate::state::CapabilityState`]
    /// transitions that authorized these attempts. Even terminal outcomes
    /// therefore cannot be attached to a caller-supplied operational state
    /// without risking capability identity reuse. A [`DurableAuditLog`] with
    /// any prior attempt is inspection-only until full state recovery exists.
    StateRecoveryRequired {
        /// Exact prior attempt identities, sorted in ascending order.
        attempts: Vec<AttemptId>,
    },
}

impl fmt::Display for AuditError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LockPoisoned => formatter.write_str("authorization audit lock is poisoned"),
            Self::AttemptIdExhausted => {
                formatter.write_str("session-local attempt ID sequence is exhausted")
            }
            Self::Durable(error) => error.fmt(formatter),
            Self::StateRecoveryRequired { attempts } => {
                formatter.write_str(
                    "durable audit contains prior attempts but operational capability-state recovery is unsupported (attempt IDs: [",
                )?;
                for (index, attempt) in attempts.iter().enumerate() {
                    if index != 0 {
                        formatter.write_str(", ")?;
                    }
                    write!(formatter, "{}", attempt.as_u64())?;
                }
                formatter.write_str("])")
            }
        }
    }
}

impl Error for AuditError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Durable(error) => Some(error),
            Self::LockPoisoned | Self::AttemptIdExhausted | Self::StateRecoveryRequired { .. } => {
                None
            }
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
    state_instance: u64,
}

impl AuditTrail {
    pub(crate) fn new() -> Self {
        Self {
            state: Mutex::new(AuditState {
                next_attempt_sequence: Some(0),
                attempts: Vec::new(),
            }),
            backend: None,
            state_instance: 0,
        }
    }

    pub(crate) fn new_with_backend(backend: Arc<DurableAuditLog>) -> Result<Self, AuditError> {
        let mut recovered_attempts = backend
            .attempts()?
            .into_iter()
            .map(|attempt| attempt.attempt_id())
            .collect::<Vec<_>>();
        recovered_attempts.sort_unstable();
        if !recovered_attempts.is_empty() {
            return Err(AuditError::StateRecoveryRequired {
                attempts: recovered_attempts,
            });
        }
        let next_attempt_sequence = backend.next_attempt_sequence()?;
        Ok(Self {
            state: Mutex::new(AuditState {
                next_attempt_sequence,
                attempts: Vec::new(),
            }),
            backend: Some(backend),
            state_instance: 0,
        })
    }

    /// Attaches a fresh capability state to a journal that already holds attempts.
    ///
    /// Reconciliation happens before the trail is usable: every prior attempt still recorded as
    /// `Started` is durably finished as `CommitUnknown`, because a process that stopped between
    /// authorization and its terminal record cannot know whether the external effect landed. The
    /// new instance then appends under its own state instance, so the prior instance's `CapId` and
    /// `SubjectId` values can never be confused with this one's.
    pub(crate) fn recover_with_backend(
        backend: Arc<DurableAuditLog>,
    ) -> Result<(Self, AuditRecovery), AuditError> {
        let inherited = backend.attempts()?;
        let state_instance = backend
            .next_attempt_sequence()?
            .ok_or(AuditError::AttemptIdExhausted)?;
        let mut reconciled = Vec::new();
        for attempt in &inherited {
            if attempt.outcome() != AttemptOutcome::Started {
                continue;
            }
            let evidence =
                CommitUnknownEvidence::new(attempt.attempt_id(), RECOVERED_ATTEMPT_EVIDENCE)
                    .map_err(AuditError::Durable)?;
            backend
                .finish_attempt(
                    attempt.attempt_id(),
                    AttemptOutcome::CommitUnknown,
                    None,
                    Some(&evidence),
                )
                .map_err(AuditError::Durable)?;
            reconciled.push(attempt.attempt_id());
        }
        // Reconciliation consumes sequences, so the usable range is read after it completes.
        let next_attempt_sequence = backend.next_attempt_sequence()?;
        let trail = Self {
            state: Mutex::new(AuditState {
                next_attempt_sequence,
                attempts: Vec::new(),
            }),
            backend: Some(backend),
            state_instance,
        };
        Ok((
            trail,
            AuditRecovery {
                state_instance,
                inherited_attempts: inherited.len(),
                reconciled,
            },
        ))
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
                self.state_instance,
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
    use std::{
        error::Error,
        fs,
        path::PathBuf,
        sync::{
            Arc,
            atomic::{AtomicU64, Ordering},
        },
    };

    use super::{AttemptOutcome, AuditError, AuditTrail};
    use crate::{
        capability::{AuthorityRequest, CapId, CapabilityRequest, CapabilityRequestSet, SubjectId},
        durable_audit::{CommitReceipt, CommitUnknownEvidence, DurableAuditLog},
        file::{FileEffect, FileRequest},
        path::CanonicalPath,
        repository::RepoId,
        state::AuthorizationEpoch,
        time::MonotonicTime,
    };

    static NEXT_JOURNAL: AtomicU64 = AtomicU64::new(0);

    struct TestJournal {
        directory: PathBuf,
        path: PathBuf,
    }

    impl TestJournal {
        fn new() -> Self {
            let serial = NEXT_JOURNAL.fetch_add(1, Ordering::Relaxed);
            let directory = std::env::temp_dir().join(format!(
                "authority-core-audit-recovery-{}-{serial}",
                std::process::id()
            ));
            let _ = fs::remove_dir_all(&directory);
            fs::create_dir(&directory).expect("test journal directory must be creatable");
            let path = directory.join("audit.wal");
            Self { directory, path }
        }
    }

    impl Drop for TestJournal {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.directory);
        }
    }

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

    fn begin_durable(log: &DurableAuditLog, attempt: super::AttemptId) {
        log.begin_attempt(
            0,
            attempt,
            &SubjectId::new(format!("subject-{}", attempt.as_u64())),
            &CapId::new(format!("capability-{}", attempt.as_u64())),
            &CapabilityRequestSet::one(request()),
            AuthorizationEpoch::default(),
        )
        .expect("test attempt start must be durable");
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
    fn empty_durable_backend_is_the_only_operational_recovery() {
        let journal = TestJournal::new();
        let backend = Arc::new(
            DurableAuditLog::create(&journal.path).expect("empty test WAL must be creatable"),
        );

        let trail = AuditTrail::new_with_backend(backend)
            .expect("an empty WAL has no missing capability-state history");

        assert!(
            trail
                .attempts()
                .expect("fresh durable audit must remain readable")
                .is_empty()
        );
        assert_eq!(start(&trail, 0).id(), super::AttemptId::from_u64(0));
    }

    #[test]
    fn recovery_closes_dangling_attempts_and_leaves_terminal_history_alone() {
        let journal = TestJournal::new();
        let backend =
            Arc::new(DurableAuditLog::create(&journal.path).expect("test WAL must be creatable"));

        let committed = super::AttemptId::from_u64(0);
        begin_durable(&backend, committed);
        let receipt = CommitReceipt::kernel_success(committed);
        backend
            .finish_attempt(committed, AttemptOutcome::Committed, Some(&receipt), None)
            .expect("committed outcome must be durable");
        let dangling = super::AttemptId::from_u64(1);
        begin_durable(&backend, dangling);
        let second_dangling = super::AttemptId::from_u64(2);
        begin_durable(&backend, second_dangling);
        drop(backend);

        let reopened = Arc::new(
            DurableAuditLog::open(&journal.path).expect("a crashed WAL must reopen for recovery"),
        );
        let (trail, recovery) = AuditTrail::recover_with_backend(reopened)
            .expect("prior attempts must not block a fresh capability state");

        assert_eq!(recovery.inherited_attempts(), 3);
        assert_eq!(recovery.reconciled(), &[dangling, second_dangling]);
        assert_eq!(recovery.state_instance(), 3);

        let durable = trail
            .backend
            .as_ref()
            .expect("recovered trail keeps its backend")
            .attempts()
            .expect("recovered WAL must remain readable");
        assert_eq!(durable[0].outcome(), AttemptOutcome::Committed);
        for closed in &durable[1..] {
            assert_eq!(closed.outcome(), AttemptOutcome::CommitUnknown);
            assert_eq!(
                closed
                    .commit_unknown_evidence()
                    .expect("a reconciled attempt records why its fate is unknown")
                    .token(),
                super::RECOVERED_ATTEMPT_EVIDENCE
            );
        }
        assert!(
            trail
                .attempts()
                .expect("recovered trail must expose no operational attempt")
                .is_empty(),
            "prior attempts are history, never live state"
        );
    }

    #[test]
    fn recovered_attempts_are_recorded_under_a_fresh_state_instance() {
        let journal = TestJournal::new();
        let backend =
            Arc::new(DurableAuditLog::create(&journal.path).expect("test WAL must be creatable"));
        let first = super::AttemptId::from_u64(0);
        begin_durable(&backend, first);
        backend
            .finish_attempt(first, AttemptOutcome::Denied, None, None)
            .expect("denied outcome must be durable");
        let first_metadata = backend
            .attempts()
            .expect("WAL must be readable")
            .first()
            .expect("one attempt exists")
            .metadata()
            .expect("a durable attempt must decode");
        drop(backend);

        let reopened =
            Arc::new(DurableAuditLog::open(&journal.path).expect("reopen for recovery must work"));
        let (trail, recovery) =
            AuditTrail::recover_with_backend(reopened).expect("recovery must succeed");
        let guard = start(&trail, 0);
        let next = guard.id();
        guard.deny().expect("denial must be recorded");

        assert_eq!(next, super::AttemptId::from_u64(1));
        let attempts = trail
            .backend
            .as_ref()
            .expect("recovered trail keeps its backend")
            .attempts()
            .expect("WAL must be readable");
        let new_metadata = attempts
            .iter()
            .find(|attempt| attempt.attempt_id() == next)
            .expect("the new attempt is durable")
            .metadata()
            .expect("a durable attempt must decode");
        assert_eq!(first_metadata.state_instance(), 0);
        assert_eq!(
            new_metadata.state_instance(),
            recovery.state_instance(),
            "a fresh capability state must not write under the crashed instance"
        );
        assert_ne!(
            new_metadata.state_instance(),
            first_metadata.state_instance()
        );
        assert_eq!(new_metadata.caller().as_str(), "subject-0");
    }

    #[test]
    fn every_recovered_attempt_requires_state_recovery_with_exact_sorted_ids() {
        let journal = TestJournal::new();
        let backend =
            Arc::new(DurableAuditLog::create(&journal.path).expect("test WAL must be creatable"));

        let denied = super::AttemptId::from_u64(0);
        begin_durable(&backend, denied);
        backend
            .finish_attempt(denied, AttemptOutcome::Denied, None, None)
            .expect("denied outcome must be durable");

        let failed = super::AttemptId::from_u64(1);
        begin_durable(&backend, failed);
        backend
            .finish_attempt(failed, AttemptOutcome::FailedBeforeCommit, None, None)
            .expect("pre-commit failure must be durable");

        let committed = super::AttemptId::from_u64(2);
        begin_durable(&backend, committed);
        let receipt = CommitReceipt::kernel_success(committed);
        backend
            .finish_attempt(committed, AttemptOutcome::Committed, Some(&receipt), None)
            .expect("committed outcome must be durable");

        let unknown = super::AttemptId::from_u64(3);
        begin_durable(&backend, unknown);
        let evidence = CommitUnknownEvidence::new(unknown, b"provider-timeout")
            .expect("fixed ambiguity evidence must be valid");
        backend
            .finish_attempt(
                unknown,
                AttemptOutcome::CommitUnknown,
                None,
                Some(&evidence),
            )
            .expect("commit-unknown outcome must be durable");

        let started = super::AttemptId::from_u64(4);
        begin_durable(&backend, started);

        let error = AuditTrail::new_with_backend(backend)
            .expect_err("every prior attempt must block operational state recovery");
        assert_eq!(
            error,
            AuditError::StateRecoveryRequired {
                attempts: vec![denied, failed, committed, unknown, started],
            }
        );
        assert_eq!(
            error.to_string(),
            "durable audit contains prior attempts but operational capability-state recovery is unsupported (attempt IDs: [0, 1, 2, 3, 4])"
        );
        assert!(error.source().is_none());
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
    #[derive(Default)]
    struct ScriptedReconciler {
        verdicts: Vec<Option<super::ReconciledCommit>>,
        seen: Vec<(super::AttemptId, String)>,
        fail_at: Option<usize>,
        calls: usize,
    }

    #[derive(Debug)]
    struct ProviderUnreachable;

    impl std::fmt::Display for ProviderUnreachable {
        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("provider unreachable")
        }
    }

    impl std::error::Error for ProviderUnreachable {}

    impl super::CommitReconciler for ScriptedReconciler {
        type Error = ProviderUnreachable;

        fn resolve(
            &mut self,
            attempt: &super::DurableAttempt,
            metadata: &super::DurableAttemptMetadata,
        ) -> Result<Option<super::ReconciledCommit>, Self::Error> {
            let index = self.calls;
            self.calls += 1;
            if self.fail_at == Some(index) {
                return Err(ProviderUnreachable);
            }
            self.seen
                .push((attempt.attempt_id(), metadata.caller().as_str().to_owned()));
            Ok(self.verdicts.get(index).cloned().flatten())
        }
    }

    fn unknown_attempt(backend: &DurableAuditLog, id: super::AttemptId) {
        begin_durable(backend, id);
        let evidence = CommitUnknownEvidence::new(id, b"provider-timeout")
            .expect("test evidence must be valid");
        backend
            .finish_attempt(id, AttemptOutcome::CommitUnknown, None, Some(&evidence))
            .expect("commit-unknown outcome must be durable");
    }

    #[test]
    fn reconciliation_records_each_verdict_without_rewriting_the_ambiguity() {
        let journal = TestJournal::new();
        let backend = DurableAuditLog::create(&journal.path).expect("test WAL must be creatable");
        let committed = super::AttemptId::from_u64(0);
        let missed = super::AttemptId::from_u64(1);
        let open = super::AttemptId::from_u64(2);
        unknown_attempt(&backend, committed);
        unknown_attempt(&backend, missed);
        unknown_attempt(&backend, open);

        let mut reconciler = ScriptedReconciler {
            verdicts: vec![
                Some(super::ReconciledCommit::Committed(CommitReceipt::new(
                    committed,
                    b"provider-accepted-1".to_vec(),
                ))),
                Some(super::ReconciledCommit::NotCommitted),
                None,
            ],
            ..ScriptedReconciler::default()
        };
        let summary = super::reconcile_unknown_commits(&backend, &mut reconciler)
            .expect("reconciliation must complete");

        assert_eq!(summary.committed(), &[committed]);
        assert_eq!(summary.not_committed(), &[missed]);
        assert_eq!(summary.still_unknown(), &[open]);
        assert_eq!(
            reconciler.seen,
            vec![
                (committed, "subject-0".to_owned()),
                (missed, "subject-1".to_owned()),
                (open, "subject-2".to_owned()),
            ],
            "each verdict must be decided from the record's own decoded metadata"
        );
        drop(backend);

        let reopened = DurableAuditLog::open(&journal.path).expect("a reconciled WAL must reopen");
        let attempts = reopened.attempts().expect("WAL must be readable");
        for attempt in &attempts {
            assert_eq!(
                attempt.outcome(),
                AttemptOutcome::CommitUnknown,
                "a verdict must not rewrite the terminal record"
            );
            assert!(
                attempt.commit_unknown_evidence().is_some(),
                "the original ambiguity evidence must survive reconciliation"
            );
        }
        assert!(matches!(
            attempts[0].reconciliation(),
            Some(super::ReconciledCommit::Committed(receipt))
                if receipt.token() == b"provider-accepted-1"
        ));
        assert_eq!(
            attempts[1].reconciliation(),
            Some(&super::ReconciledCommit::NotCommitted)
        );
        assert_eq!(attempts[2].reconciliation(), None);
    }

    #[test]
    fn an_attempt_is_reconciled_at_most_once_and_only_when_unknown() {
        let journal = TestJournal::new();
        let backend = DurableAuditLog::create(&journal.path).expect("test WAL must be creatable");
        let unknown = super::AttemptId::from_u64(0);
        unknown_attempt(&backend, unknown);
        let denied = super::AttemptId::from_u64(1);
        begin_durable(&backend, denied);
        backend
            .finish_attempt(denied, AttemptOutcome::Denied, None, None)
            .expect("denied outcome must be durable");

        backend
            .reconcile_attempt(unknown, &super::ReconciledCommit::NotCommitted)
            .expect("first verdict must be durable");
        assert!(
            backend
                .reconcile_attempt(unknown, &super::ReconciledCommit::NotCommitted)
                .is_err(),
            "a second verdict would let a later reader pick which one to believe"
        );
        assert!(
            backend
                .reconcile_attempt(denied, &super::ReconciledCommit::NotCommitted)
                .is_err(),
            "an attempt that was never ambiguous has nothing to reconcile"
        );
        assert!(
            backend
                .reconcile_attempt(
                    unknown,
                    &super::ReconciledCommit::Committed(CommitReceipt::new(
                        super::AttemptId::from_u64(9),
                        b"foreign".to_vec(),
                    )),
                )
                .is_err(),
            "a receipt for another attempt must not attach here"
        );
    }

    #[test]
    fn a_provider_failure_keeps_the_verdicts_already_recorded() {
        let journal = TestJournal::new();
        let backend = DurableAuditLog::create(&journal.path).expect("test WAL must be creatable");
        let first = super::AttemptId::from_u64(0);
        let second = super::AttemptId::from_u64(1);
        unknown_attempt(&backend, first);
        unknown_attempt(&backend, second);

        let mut reconciler = ScriptedReconciler {
            verdicts: vec![Some(super::ReconciledCommit::NotCommitted), None],
            fail_at: Some(1),
            ..ScriptedReconciler::default()
        };
        let error = super::reconcile_unknown_commits(&backend, &mut reconciler)
            .expect_err("an unreachable provider must surface");

        assert!(matches!(
            error,
            super::ReconciliationError::Provider { attempt, .. } if attempt == second
        ));
        let attempts = backend.attempts().expect("WAL must be readable");
        assert_eq!(
            attempts[0].reconciliation(),
            Some(&super::ReconciledCommit::NotCommitted),
            "a verdict recorded before the failure stays durable"
        );
        assert_eq!(attempts[1].reconciliation(), None);
    }
}
