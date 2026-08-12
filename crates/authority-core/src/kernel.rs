//! Concurrent authorization boundary for effect commit and revocation.

use std::{error::Error, fmt};

#[cfg(loom)]
use loom::sync::Arc;
#[cfg(not(loom))]
use std::sync::Arc;

#[cfg(loom)]
use loom::sync::RwLock;
#[cfg(not(loom))]
use std::sync::RwLock;

use crate::{
    audit::{AttemptId, AttemptRecord, AuditError, AuditTrail, EffectRecord},
    capability::{CapId, Capability, CapabilityRequest, CapabilityRequestSet, SubjectId},
    durable_audit::{
        CommitReceipt, DurableAuditError, DurableAuditLog, MAX_COMMIT_UNKNOWN_EVIDENCE_BYTES,
    },
    handle::{HandleId, ObjectId, OpenHandle},
    state::{
        AuthorizationEpoch, CapabilityGrant, CapabilityState, CapabilityStateError,
        HandleCloseStatus, RevocationStatus, Subject, SubjectCloseStatus, SubjectFinishStatus,
        SubjectStatus,
    },
    time::MonotonicTime,
};

/// A failed synchronized state transition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CapabilityKernelError {
    /// A writer panicked while it held the capability-state lock.
    LockPoisoned,
    /// The sequential state machine rejected the requested transition.
    StateTransition(CapabilityStateError),
    /// The capability is revoked, but a registered observer could not confirm
    /// that it discarded the decisions the revocation invalidates.
    ///
    /// Authorization inside this kernel already fails closed. This reports that
    /// state *outside* the kernel — a kernel-side filesystem cache, a mount, a
    /// remote decision cache — may still be able to satisfy a request the
    /// revocation was meant to stop. The caller must treat the affected
    /// component as compromised rather than retrying.
    RevocationNotPropagated(RevocationObserverError),
}

impl fmt::Display for CapabilityKernelError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LockPoisoned => formatter.write_str("capability kernel state lock is poisoned"),
            Self::StateTransition(error) => error.fmt(formatter),
            Self::RevocationNotPropagated(error) => write!(
                formatter,
                "capability was revoked but the revocation was not propagated: {error}"
            ),
        }
    }
}

impl Error for CapabilityKernelError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::LockPoisoned => None,
            Self::StateTransition(error) => Some(error),
            Self::RevocationNotPropagated(error) => Some(error),
        }
    }
}

/// A registered observer that could not discard its cached decisions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevocationObserverError {
    observer: &'static str,
    reason: String,
}

impl RevocationObserverError {
    /// Records which observer failed and why.
    #[must_use]
    pub fn new(observer: &'static str, reason: impl Into<String>) -> Self {
        Self {
            observer,
            reason: reason.into(),
        }
    }

    /// Returns the failing observer's static name.
    #[must_use]
    pub const fn observer(&self) -> &'static str {
        self.observer
    }

    /// Returns the observer's description of the failure.
    #[must_use]
    pub fn reason(&self) -> &str {
        &self.reason
    }
}

impl fmt::Display for RevocationObserverError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.observer, self.reason)
    }
}

impl Error for RevocationObserverError {}

/// Discards decisions cached outside the kernel when a revocation commits.
///
/// The kernel's own authorization fails closed the moment a revocation takes
/// the state lock. Components that cache an authorization result somewhere the
/// kernel cannot reach — most importantly a Linux kernel page or attribute
/// cache populated through a FUSE mount — need to be told, or a revoked
/// capability keeps being satisfied from that cache.
///
/// # Ordering
///
/// Observers run after the state transition has committed and after the state
/// lock has been released, and before the revoking call returns. That is what
/// makes the guarantee stated on [`CapabilityKernel::revoke_held_by`] — that later
/// attempts recheck against the revoked state once the call returns — hold for
/// cached decisions as well as for kernel state.
///
/// Releasing the lock first is required, not incidental. An observer that
/// invalidates a FUSE cache blocks until the operating system has finished
/// that invalidation, and the operating system may first need to drain an
/// in-flight request from that same mount. That request needs shared state
/// access to be denied. Holding exclusive access across the observer would
/// therefore deadlock the revocation against the request it is trying to stop.
///
/// # Implementation requirements
///
/// An observer must not re-enter a transition on the kernel that is notifying
/// it, must return only after its discard has taken effect, and must report an
/// error rather than returning if it cannot confirm that.
pub trait RevocationObserver: Send + Sync {
    /// Discards every decision this observer has cached.
    ///
    /// The revoked capability is deliberately not supplied. Deciding which
    /// cached entries a single revocation can still satisfy requires the
    /// derivation graph, and an observer that guessed wrong would leave a
    /// live cache entry behind. Discarding everything cannot.
    ///
    /// # Errors
    ///
    /// Returns [`RevocationObserverError`] when the discard cannot be
    /// confirmed. The caller treats that as a compromised component.
    fn discard_cached_decisions(&self) -> Result<(), RevocationObserverError>;
}

impl From<CapabilityStateError> for CapabilityKernelError {
    fn from(error: CapabilityStateError) -> Self {
        Self::StateTransition(error)
    }
}

/// A failed authorization or effect attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EffectCommitError<E> {
    /// The capability-state lock cannot be trusted after a writer panic.
    LockPoisoned,
    /// The supplied capability did not authorize the request at commit time.
    NotAuthorized,
    /// The effect executor failed before reaching its linearization point.
    Effect(E),
    /// The attempt could not be recorded before executor invocation.
    Audit(AuditError),
    /// The executor returned success, but the terminal durable receipt could
    /// not be persisted. The external effect may already exist; callers must
    /// resolve this with the provider's idempotency or reconciliation path.
    CommittedButAudit {
        /// Identity durably allocated before executor invocation.
        attempt_id: AttemptId,
        /// Exact receipt returned by the executor for reconciliation.
        receipt: CommitReceipt,
        /// Terminal audit persistence failure.
        source: AuditError,
    },
    /// The executor crossed a boundary whose external result cannot be
    /// determined. The durable audit records this as `CommitUnknown`, never as
    /// a committed effect.
    CommitUnknown {
        /// Identity durably allocated before executor invocation.
        attempt_id: AttemptId,
        /// Exact bounded evidence returned by the executor.
        evidence: Vec<u8>,
    },
    /// The external result is unknown and its terminal evidence could not be
    /// persisted. Recovery must treat the original started attempt as
    /// unresolved and must not infer either success or failure.
    CommitUnknownAndAudit {
        /// Identity durably allocated before executor invocation.
        attempt_id: AttemptId,
        /// Exact evidence returned by the executor after its size check.
        evidence: Vec<u8>,
        /// Evidence validation or terminal audit persistence failure.
        source: AuditError,
    },
}

impl<E: fmt::Display> fmt::Display for EffectCommitError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LockPoisoned => formatter.write_str("capability kernel state lock is poisoned"),
            Self::NotAuthorized => formatter.write_str("capability does not authorize this effect"),
            Self::Effect(error) => {
                write!(
                    formatter,
                    "effect failed before its linearization point: {error}"
                )
            }
            Self::Audit(error) => error.fmt(formatter),
            Self::CommittedButAudit {
                attempt_id, source, ..
            } => write!(
                formatter,
                "effect attempt {} may be committed but its audit receipt failed: {source}",
                attempt_id.as_u64()
            ),
            Self::CommitUnknown { attempt_id, .. } => write!(
                formatter,
                "effect attempt {} completion is unknown and requires reconciliation",
                attempt_id.as_u64()
            ),
            Self::CommitUnknownAndAudit {
                attempt_id, source, ..
            } => write!(
                formatter,
                "effect attempt {} completion is unknown and its evidence could not be persisted: {source}",
                attempt_id.as_u64()
            ),
        }
    }
}

impl<E: Error + 'static> Error for EffectCommitError<E> {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Effect(error) => Some(error),
            Self::Audit(error) => Some(error),
            Self::CommittedButAudit { source, .. } | Self::CommitUnknownAndAudit { source, .. } => {
                Some(source)
            }
            Self::LockPoisoned | Self::NotAuthorized | Self::CommitUnknown { .. } => None,
        }
    }
}

/// The executor's typed observation at its external linearization boundary.
///
/// Unlike `Result`, this type cannot collapse an ambiguous provider outcome
/// into either pre-commit failure or committed success. `CommitUnknown`
/// evidence is appended to the durable attempt but never creates an
/// [`EffectRecord`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EffectExecution<T, E> {
    /// The operation failed before its documented linearization point.
    FailedBeforeCommit(E),
    /// The operation reached its documented linearization point.
    Committed {
        /// Successful adapter value.
        value: T,
        /// Optional provider acceptance token persisted in the commit receipt.
        receipt: Option<Vec<u8>>,
    },
    /// The provider may or may not have accepted the operation.
    CommitUnknown {
        /// Non-empty bounded evidence used by the reconciliation path.
        evidence: Vec<u8>,
    },
}

/// A failed inspection of active capability authority.
///
/// Inspection does not represent an external effect and therefore does not
/// append an audit attempt. Callers must still use
/// [`CapabilityKernel::authorize_and_execute_classified`] before reading or
/// mutating protected data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CapabilityInspectionError<E> {
    /// The capability-state lock cannot be trusted after a writer panic.
    LockPoisoned,
    /// The supplied capability is not active and held by the caller.
    NotActive,
    /// The inspection callback rejected the capability authority.
    Inspection(E),
}

impl<E: fmt::Display> fmt::Display for CapabilityInspectionError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LockPoisoned => formatter.write_str("capability kernel state lock is poisoned"),
            Self::NotActive => formatter.write_str("capability is not active for this subject"),
            Self::Inspection(error) => write!(formatter, "capability inspection failed: {error}"),
        }
    }
}

impl<E: Error + 'static> Error for CapabilityInspectionError<E> {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Inspection(error) => Some(error),
            Self::LockPoisoned | Self::NotActive => None,
        }
    }
}

/// Serializes capability transitions with effect authorization and commit.
///
/// Effect attempts hold shared access from their final authorization check
/// through the executor's linearization point. Revocation and every other
/// state transition require exclusive access, so a completed revoke cannot be
/// followed by an effect that relied only on the revoked capability.
pub struct CapabilityKernel {
    state: RwLock<CapabilityState>,
    audit: AuditTrail,
    revocation_observers: RwLock<Vec<Arc<dyn RevocationObserver>>>,
}

impl fmt::Debug for CapabilityKernel {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let observers = self
            .revocation_observers
            .read()
            .map_or(0, |observers| observers.len());
        formatter
            .debug_struct("CapabilityKernel")
            .field("state", &self.state)
            .field("audit", &self.audit)
            .field("revocation_observers", &observers)
            .finish()
    }
}

impl CapabilityKernel {
    /// Wraps initialized sequential state in the concurrent boundary.
    #[must_use]
    pub fn new(state: CapabilityState) -> Self {
        Self {
            state: RwLock::new(state),
            audit: AuditTrail::new(),
            revocation_observers: RwLock::new(Vec::new()),
        }
    }

    /// Creates a kernel whose attempt journal is backed by the supplied WAL.
    ///
    /// Only an empty, exclusively owned WAL can back a new operational kernel.
    /// A WAL containing any prior attempt remains available through its
    /// read-only recovery view, but cannot be attached to caller-supplied
    /// capability state until full capability-state recovery exists.
    ///
    /// # Errors
    ///
    /// Returns [`AuditError`] if the backend cannot be inspected safely or if
    /// it contains attempts from a prior capability-state instance.
    pub fn try_new_with_durable_audit(
        state: CapabilityState,
        backend: DurableAuditLog,
    ) -> Result<Self, AuditError> {
        Ok(Self {
            state: RwLock::new(state),
            audit: AuditTrail::new_with_backend(Arc::new(backend))?,
            revocation_observers: RwLock::new(Vec::new()),
        })
    }

    /// Registers an observer notified by every revoking transition.
    ///
    /// Register before issuing the capabilities whose decisions the observer
    /// caches. A revocation that commits before registration cannot be
    /// propagated to it.
    ///
    /// # Errors
    ///
    /// Returns [`CapabilityKernelError::LockPoisoned`] if a writer previously
    /// panicked while mutating the observer list.
    pub fn register_revocation_observer(
        &self,
        observer: Arc<dyn RevocationObserver>,
    ) -> Result<(), CapabilityKernelError> {
        self.revocation_observers
            .write()
            .map_err(|_| CapabilityKernelError::LockPoisoned)?
            .push(observer);
        Ok(())
    }

    /// Runs every observer with no state lock held.
    ///
    /// The caller must have released exclusive state access first. See
    /// [`RevocationObserver`] for why that ordering is required rather than
    /// convenient. Every observer runs even after one fails, so a single
    /// failing mount cannot leave the others holding stale caches; the first
    /// failure is what the caller sees.
    fn propagate_revocation(&self) -> Result<(), CapabilityKernelError> {
        let observers = self
            .revocation_observers
            .read()
            .map_err(|_| CapabilityKernelError::LockPoisoned)?
            .clone();

        let mut first_failure = None;
        for observer in observers {
            if let Err(error) = observer.discard_cached_decisions()
                && first_failure.is_none()
            {
                first_failure = Some(error);
            }
        }
        first_failure.map_or(Ok(()), |error| {
            Err(CapabilityKernelError::RevocationNotPropagated(error))
        })
    }

    /// Registers a subject while holding exclusive state access.
    ///
    /// # Errors
    ///
    /// Returns [`CapabilityKernelError::LockPoisoned`] if a writer previously
    /// panicked, or wraps the sequential registration error.
    pub fn register_subject(&self, subject: Subject) -> Result<(), CapabilityKernelError> {
        self.with_state_mut(|state| state.register_subject(subject))
    }

    /// Issues a root capability while holding exclusive state access.
    ///
    /// # Errors
    ///
    /// Returns [`CapabilityKernelError::LockPoisoned`] if a writer previously
    /// panicked, or wraps the sequential issuance error.
    pub fn issue_root(&self, grant: CapabilityGrant) -> Result<CapId, CapabilityKernelError> {
        self.with_state_mut(|state| state.issue_root(grant))
    }

    /// Issues a root capability with a trusted host-allocated identity while
    /// holding exclusive state access.
    ///
    /// The transition uses the same subject/envelope validation and permanent
    /// identity reservation as [`CapabilityState::issue_root_with_id`].
    ///
    /// # Errors
    ///
    /// Returns [`CapabilityKernelError::LockPoisoned`] if a writer previously
    /// panicked, or wraps the sequential issuance error.
    pub fn issue_root_with_id(
        &self,
        capability_id: CapId,
        grant: CapabilityGrant,
    ) -> Result<CapId, CapabilityKernelError> {
        self.with_state_mut(|state| state.issue_root_with_id(capability_id, grant))
    }

    /// Derives a capability while holding exclusive state access.
    ///
    /// # Errors
    ///
    /// Returns [`CapabilityKernelError::LockPoisoned`] if a writer previously
    /// panicked, or wraps the sequential derivation error.
    pub fn derive(
        &self,
        caller: &SubjectId,
        parent_id: &CapId,
        grant: CapabilityGrant,
        now: MonotonicTime,
    ) -> Result<CapId, CapabilityKernelError> {
        self.with_state_mut(|state| state.derive(caller, parent_id, grant, now))
    }

    /// Revokes a capability for an in-crate test of the trusted state transition.
    ///
    /// The exclusive lock waits for every already-authorized effect to reach
    /// its linearization point. Once this method returns, later effect attempts
    /// recheck authorization against the revoked state.
    ///
    /// # Errors
    ///
    /// Returns [`CapabilityKernelError::LockPoisoned`] if a writer previously
    /// panicked, or wraps the sequential revocation error.
    #[cfg(test)]
    pub(crate) fn revoke(
        &self,
        capability: &CapId,
    ) -> Result<RevocationStatus, CapabilityKernelError> {
        let status = self.with_state_mut(|state| state.revoke(capability))?;
        // The state lock is released here. Observers run before this returns,
        // so a decision cached outside the kernel cannot outlive the call
        // either. See `RevocationObserver` for why the lock must be released
        // first.
        if status == RevocationStatus::NewlyRevoked {
            self.propagate_revocation()?;
        }
        Ok(status)
    }

    /// Revokes a capability only when `caller` currently holds it.
    ///
    /// The holder check and revocation are one exclusive state transition, so
    /// a transport-authenticated subject cannot race an ownership change or
    /// revoke another subject's predictable capability identity.
    ///
    /// # Errors
    ///
    /// Returns propagation errors after a committed revocation, or a typed state
    /// error when the capability is unknown or not held by `caller`.
    pub fn revoke_held_by(
        &self,
        caller: &SubjectId,
        capability: &CapId,
    ) -> Result<RevocationStatus, CapabilityKernelError> {
        let status = self.with_state_mut(|state| state.revoke_held_by(caller, capability))?;
        if status == RevocationStatus::NewlyRevoked {
            self.propagate_revocation()?;
        }
        Ok(status)
    }

    /// Returns the current version for authorization-dependent caches.
    ///
    /// # Errors
    ///
    /// Returns [`CapabilityKernelError::LockPoisoned`] if a writer previously
    /// panicked while mutating the capability state.
    pub fn authorization_epoch(&self) -> Result<AuthorizationEpoch, CapabilityKernelError> {
        let state = self
            .state
            .read()
            .map_err(|_| CapabilityKernelError::LockPoisoned)?;
        Ok(state.authorization_epoch())
    }

    /// Returns the lifecycle status of a registered subject.
    ///
    /// # Errors
    ///
    /// Returns [`CapabilityKernelError::LockPoisoned`] if a writer previously
    /// panicked while mutating the capability state.
    pub fn subject_status(
        &self,
        subject: &SubjectId,
    ) -> Result<Option<SubjectStatus>, CapabilityKernelError> {
        let state = self
            .state
            .read()
            .map_err(|_| CapabilityKernelError::LockPoisoned)?;
        Ok(state.subject_status(subject))
    }

    /// Begins subject shutdown under exclusive state access.
    ///
    /// # Errors
    ///
    /// Returns [`CapabilityKernelError::LockPoisoned`] if a writer previously
    /// panicked, or wraps the sequential lifecycle error.
    pub fn begin_subject_close(
        &self,
        subject: &SubjectId,
    ) -> Result<SubjectCloseStatus, CapabilityKernelError> {
        let status = self.with_state_mut(|state| state.begin_subject_close(subject))?;
        // Closing a subject revokes every capability it holds, so it carries
        // the same propagation obligation as an explicit revoke.
        if status == SubjectCloseStatus::Started {
            self.propagate_revocation()?;
        }
        Ok(status)
    }

    /// Marks external teardown for a closing subject as complete.
    ///
    /// # Errors
    ///
    /// Returns [`CapabilityKernelError::LockPoisoned`] if a writer previously
    /// panicked, or wraps the sequential lifecycle error.
    pub fn finish_subject_close(
        &self,
        subject: &SubjectId,
    ) -> Result<SubjectFinishStatus, CapabilityKernelError> {
        self.with_state_mut(|state| state.finish_subject_close(subject))
    }

    /// Registers a live handle under exclusive state access.
    ///
    /// # Errors
    ///
    /// Returns [`CapabilityKernelError::LockPoisoned`] if a writer previously
    /// panicked, or wraps the sequential handle-registration error.
    pub fn register_open_handle(&self, handle: OpenHandle) -> Result<(), CapabilityKernelError> {
        self.with_state_mut(|state| state.register_open_handle(handle))
    }

    /// Closes a handle under exclusive state access.
    ///
    /// # Errors
    ///
    /// Returns [`CapabilityKernelError::LockPoisoned`] if a writer previously
    /// panicked, or wraps the sequential close error.
    pub fn close_handle(
        &self,
        caller: &SubjectId,
        handle: &HandleId,
    ) -> Result<HandleCloseStatus, CapabilityKernelError> {
        self.with_state_mut(|state| state.close_handle(caller, handle))
    }

    /// Returns a copy of one live handle record.
    ///
    /// # Errors
    ///
    /// Returns [`CapabilityKernelError::LockPoisoned`] if a writer previously
    /// panicked while mutating the capability state.
    pub fn open_handle(
        &self,
        handle: &HandleId,
    ) -> Result<Option<OpenHandle>, CapabilityKernelError> {
        let state = self
            .state
            .read()
            .map_err(|_| CapabilityKernelError::LockPoisoned)?;
        Ok(state.open_handle(handle).cloned())
    }

    /// Returns the number of live handles for one namespace object.
    ///
    /// # Errors
    ///
    /// Returns [`CapabilityKernelError::LockPoisoned`] if a writer previously
    /// panicked while mutating the capability state.
    pub fn object_open_handle_count(
        &self,
        object: &ObjectId,
    ) -> Result<usize, CapabilityKernelError> {
        let state = self
            .state
            .read()
            .map_err(|_| CapabilityKernelError::LockPoisoned)?;
        Ok(state.object_open_handle_count(object))
    }

    /// Returns whether no permanent authority identity has been issued yet.
    ///
    /// An adapter with an empty local manifest must establish this before it
    /// assumes ownership of the kernel; otherwise it could forget tombstones
    /// retained by a previously attached adapter and attempt identity reuse.
    ///
    /// # Errors
    ///
    /// Returns [`CapabilityKernelError::LockPoisoned`] if the state lock was
    /// poisoned by an earlier writer panic.
    pub fn is_pristine(&self) -> Result<bool, CapabilityKernelError> {
        self.state
            .read()
            .map_err(|_| CapabilityKernelError::LockPoisoned)
            .map(|state| state.is_pristine())
    }

    /// Returns snapshots of all authorization attempts in start order.
    ///
    /// # Errors
    ///
    /// Returns [`AuditError::LockPoisoned`] if an internal audit writer
    /// panicked while appending an attempt.
    pub fn attempt_records(&self) -> Result<Vec<AttemptRecord>, AuditError> {
        self.audit.attempts()
    }

    /// Returns committed-effect snapshots in their attempt start order.
    ///
    /// Attempts denied by final authorization and executor failures are not
    /// effect records.
    ///
    /// # Errors
    ///
    /// Returns [`AuditError::LockPoisoned`] if an internal audit writer
    /// panicked while appending an attempt.
    pub fn effect_records(&self) -> Result<Vec<EffectRecord>, AuditError> {
        self.audit.effects()
    }

    /// Inspects authority metadata while the capability remains active.
    ///
    /// The callback runs while a shared state guard is held. Revocation and
    /// subject shutdown wait for it to return, so a successful inspection is
    /// linearized before every later exclusive transition. The callback must
    /// not re-enter this kernel.
    ///
    /// This method is for policy-derived metadata decisions only. It does not
    /// record an effect attempt; protected external effects must pass through
    /// [`Self::authorize_and_execute_classified`].
    ///
    /// # Errors
    ///
    /// Returns [`CapabilityInspectionError::LockPoisoned`] if capability state
    /// cannot be trusted, [`CapabilityInspectionError::NotActive`] without
    /// invoking the callback when the capability is inactive or not held by
    /// the caller, or [`CapabilityInspectionError::Inspection`] when the
    /// callback rejects the authority.
    pub fn with_active_capability<T, E>(
        &self,
        caller: &SubjectId,
        capability_id: &CapId,
        now: MonotonicTime,
        inspect: impl FnOnce(&Capability) -> Result<T, E>,
    ) -> Result<T, CapabilityInspectionError<E>> {
        let state = self
            .state
            .read()
            .map_err(|_| CapabilityInspectionError::LockPoisoned)?;
        let capability = state
            .active_capability(caller, capability_id, now)
            .ok_or(CapabilityInspectionError::NotActive)?;

        inspect(capability).map_err(CapabilityInspectionError::Inspection)
    }

    /// Reauthorizes one request and preserves an executor's explicit
    /// pre-commit, committed, or commit-unknown classification.
    ///
    /// The executor runs while a shared state guard is held, so a revocation
    /// that returns cannot race an already-authorized effect past this call.
    /// The executor must not re-enter this kernel: an exclusive transition
    /// would deadlock while the shared guard remains held. Its classification
    /// must describe the outcome at the provider's documented linearization
    /// point.
    ///
    /// # Errors
    ///
    /// Returns [`EffectCommitError::LockPoisoned`] when state cannot be
    /// trusted, [`EffectCommitError::NotAuthorized`] without invoking the
    /// executor when the final check fails, and [`EffectCommitError::Effect`]
    /// only for an explicit [`EffectExecution::FailedBeforeCommit`]. Returns
    /// [`EffectCommitError::CommitUnknown`] only after unknown evidence is
    /// durably terminal. Returns
    /// [`EffectCommitError::CommitUnknownAndAudit`] when that terminal write
    /// fails.
    pub fn authorize_and_execute_classified<T, E>(
        &self,
        caller: &SubjectId,
        capability_id: &CapId,
        request: &CapabilityRequest,
        execute: impl FnOnce(&Capability) -> EffectExecution<T, E>,
    ) -> Result<T, EffectCommitError<E>> {
        self.authorize_all_and_execute_classified(
            caller,
            capability_id,
            &CapabilityRequestSet::one(request.clone()),
            execute,
        )
    }

    /// Reauthorizes a non-empty request set and preserves the executor's
    /// explicit external-outcome classification.
    ///
    /// One shared state guard covers every final request check and the entire
    /// executor call, making the compound operation one revocation boundary.
    /// The executor has the same non-reentrancy and truthful-classification
    /// obligations as [`Self::authorize_and_execute_classified`].
    ///
    /// # Errors
    ///
    /// Returns the same typed authorization, audit, and execution failures as
    /// [`Self::authorize_and_execute_classified`].
    pub fn authorize_all_and_execute_classified<T, E>(
        &self,
        caller: &SubjectId,
        capability_id: &CapId,
        requests: &CapabilityRequestSet,
        execute: impl FnOnce(&Capability) -> EffectExecution<T, E>,
    ) -> Result<T, EffectCommitError<E>> {
        self.authorize_all_and_commit_inner(caller, capability_id, requests, execute)
    }

    fn authorize_all_and_commit_inner<T, E>(
        &self,
        caller: &SubjectId,
        capability_id: &CapId,
        requests: &CapabilityRequestSet,
        commit_to_linearization: impl FnOnce(&Capability) -> EffectExecution<T, E>,
    ) -> Result<T, EffectCommitError<E>> {
        let state = self
            .state
            .read()
            .map_err(|_| EffectCommitError::LockPoisoned)?;

        let attempt = self
            .audit
            .start_request_set(
                caller.clone(),
                capability_id.clone(),
                requests,
                state.authorization_epoch(),
            )
            .map_err(EffectCommitError::Audit)?;

        if !requests
            .iter()
            .all(|request| state.authorizes(caller, capability_id, request))
        {
            let audit_result = attempt.deny();
            drop(state);
            return match audit_result {
                Ok(()) => Err(EffectCommitError::NotAuthorized),
                Err(error) => Err(EffectCommitError::Audit(error)),
            };
        }

        // Passing a reference tied to the read guard keeps shared access alive
        // for the entire executor call, rather than only for the check above.
        let Some(capability) = state.capability(capability_id) else {
            // Public transitions keep authorization and capability lookup in
            // sync. Preserve a terminal audit outcome if internal state is
            // ever inconsistent instead of leaving the attempt as started.
            let audit_result = attempt.deny();
            drop(state);
            return match audit_result {
                Ok(()) => Err(EffectCommitError::NotAuthorized),
                Err(error) => Err(EffectCommitError::Audit(error)),
            };
        };
        let attempt_id = attempt.id();
        let result = commit_to_linearization(capability);
        match result {
            EffectExecution::Committed { value, receipt } => {
                let receipt = receipt.map_or_else(
                    || CommitReceipt::kernel_success(attempt_id),
                    |token| CommitReceipt::new(attempt_id, token),
                );
                let audit_result = attempt.commit_with_receipt(&receipt);
                drop(state);
                match audit_result {
                    Ok(()) => Ok(value),
                    Err(source) => Err(EffectCommitError::CommittedButAudit {
                        attempt_id,
                        receipt,
                        source,
                    }),
                }
            }
            EffectExecution::FailedBeforeCommit(error) => {
                let audit_result = attempt.fail_before_commit();
                drop(state);
                match audit_result {
                    Ok(()) => Err(EffectCommitError::Effect(error)),
                    Err(audit_error) => Err(EffectCommitError::Audit(audit_error)),
                }
            }
            EffectExecution::CommitUnknown { evidence } => {
                if let Err(source) = validate_commit_unknown_evidence(&evidence) {
                    drop(state);
                    return Err(EffectCommitError::CommitUnknownAndAudit {
                        attempt_id,
                        evidence,
                        source,
                    });
                }
                // The retained bytes are the exact bounded executor evidence;
                // only the copy passed to the consuming audit guard is cloned.
                let audit_result = attempt.commit_unknown(evidence.clone());
                drop(state);
                match audit_result {
                    Ok(()) => Err(EffectCommitError::CommitUnknown {
                        attempt_id,
                        evidence,
                    }),
                    Err(source) => Err(EffectCommitError::CommitUnknownAndAudit {
                        attempt_id,
                        evidence,
                        source,
                    }),
                }
            }
        }
    }

    fn with_state_mut<T>(
        &self,
        transition: impl FnOnce(&mut CapabilityState) -> Result<T, CapabilityStateError>,
    ) -> Result<T, CapabilityKernelError> {
        let mut state = self
            .state
            .write()
            .map_err(|_| CapabilityKernelError::LockPoisoned)?;
        transition(&mut state).map_err(CapabilityKernelError::from)
    }
}

fn validate_commit_unknown_evidence(evidence: &[u8]) -> Result<(), AuditError> {
    if evidence.is_empty() {
        return Err(AuditError::Durable(DurableAuditError::InvalidRecord(
            "CommitUnknown evidence cannot be empty".to_owned(),
        )));
    }
    if evidence.len() > MAX_COMMIT_UNKNOWN_EVIDENCE_BYTES {
        return Err(AuditError::Durable(DurableAuditError::RecordTooLarge(
            evidence.len(),
        )));
    }
    Ok(())
}

#[cfg(all(test, not(loom)))]
mod tests {
    use std::{
        convert::Infallible,
        error::Error,
        fs,
        path::{Path, PathBuf},
        sync::atomic::{AtomicU64, Ordering},
        thread,
    };

    use super::{CapabilityKernel, CapabilityKernelError, EffectCommitError, EffectExecution};
    use crate::{
        audit::{AttemptId, AttemptOutcome, AuditError},
        capability::{AuthorityBody, AuthorityRequest, CapabilityRequest, IssuerId, SubjectId},
        durable_audit::{DurableAuditError, DurableAuditLog, MAX_COMMIT_UNKNOWN_EVIDENCE_BYTES},
        file::{FileAuthority, FileEffect, FileEffects, FileRequest},
        path::{CanonicalPath, PathPattern},
        repository::RepoId,
        state::{
            CapabilityGrant, CapabilityState, RevocationStatus, StaticAuthorityEnvelope, Subject,
        },
        time::{MonotonicTime, TimeWindow},
    };

    static NEXT_TEST_DIRECTORY: AtomicU64 = AtomicU64::new(0);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let serial = NEXT_TEST_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "authority-kernel-errors-{}-{serial}",
                std::process::id()
            ));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir(&path).expect("create kernel test directory");
            Self(path)
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn empty_envelope() -> StaticAuthorityEnvelope {
        StaticAuthorityEnvelope::new(
            TimeWindow::new(MonotonicTime::from_ticks(0), MonotonicTime::from_ticks(1))
                .expect("fixed test bounds must form a non-empty window"),
            AuthorityBody::File(FileAuthority::new(
                RepoId::new("workspace"),
                FileEffects::empty(),
                PathPattern::Prefix(CanonicalPath::root()),
            )),
        )
    }

    fn read_authority() -> AuthorityBody {
        AuthorityBody::File(FileAuthority::new(
            RepoId::new("workspace"),
            FileEffects::only(FileEffect::ReadData),
            PathPattern::Prefix(CanonicalPath::root()),
        ))
    }

    // Requirement: a writer panic makes every later transition fail closed.
    // Category: error/state boundary. Risk: critical.
    #[test]
    fn poisoned_state_lock_rejects_later_transitions() {
        let kernel = CapabilityKernel::new(CapabilityState::new(IssuerId::new("issuer")));

        thread::scope(|scope| {
            let writer = scope.spawn(|| {
                let _state = kernel
                    .state
                    .write()
                    .expect("fresh capability state must not be poisoned");
                panic!("poison the exclusive state guard");
            });
            assert!(writer.join().is_err());
        });

        assert_eq!(
            kernel.register_subject(Subject::new(SubjectId::new("subject"), empty_envelope())),
            Err(CapabilityKernelError::LockPoisoned)
        );
    }

    // Requirement: the public effect boundary requires an explicit commit
    // classification, while raw host revocation remains test-only and
    // crate-private. Category: authorization/API boundary. Risk: critical.
    #[test]
    fn classified_execution_records_pre_commit_failure_before_test_only_raw_revoke() {
        let kernel = CapabilityKernel::new(CapabilityState::new(IssuerId::new("issuer")));
        let subject = SubjectId::new("subject");
        let validity = TimeWindow::new(MonotonicTime::from_ticks(0), MonotonicTime::from_ticks(10))
            .expect("fixed test bounds must form a non-empty window");
        kernel
            .register_subject(Subject::new(
                subject.clone(),
                StaticAuthorityEnvelope::new(validity, read_authority()),
            ))
            .expect("subject registration must succeed");
        let capability = kernel
            .issue_root(CapabilityGrant::new(
                subject.clone(),
                validity,
                read_authority(),
            ))
            .expect("root capability issuance must succeed");
        let request = CapabilityRequest::new(
            MonotonicTime::from_ticks(1),
            AuthorityRequest::File(FileRequest::new(
                RepoId::new("workspace"),
                FileEffect::ReadData,
                CanonicalPath::root(),
            )),
        );

        let result =
            kernel.authorize_and_execute_classified(&subject, &capability, &request, |_| {
                EffectExecution::<(), _>::FailedBeforeCommit("backing read rejected")
            });

        assert_eq!(
            result,
            Err(EffectCommitError::Effect("backing read rejected"))
        );
        assert_eq!(
            kernel
                .attempt_records()
                .expect("audit attempts must remain readable")[0]
                .outcome(),
            AttemptOutcome::FailedBeforeCommit
        );
        assert!(
            kernel
                .effect_records()
                .expect("effect records must remain readable")
                .is_empty()
        );
        assert_eq!(
            kernel
                .revoke(&capability)
                .expect("trusted raw test revocation must succeed"),
            RevocationStatus::NewlyRevoked
        );
    }

    #[test]
    fn classified_commit_unknown_retains_attempt_and_exact_evidence() {
        let (kernel, subject, capability, request) = authorized_kernel();
        let evidence = b"provider-timeout-after-request-write".to_vec();

        let result =
            kernel.authorize_and_execute_classified(&subject, &capability, &request, |_| {
                EffectExecution::<(), Infallible>::CommitUnknown {
                    evidence: evidence.clone(),
                }
            });

        assert_eq!(
            result,
            Err(EffectCommitError::CommitUnknown {
                attempt_id: AttemptId::from_u64(0),
                evidence: evidence.clone(),
            })
        );
        let error = result.expect_err("commit completion must remain unknown");
        assert!(error.source().is_none());
        assert!(error.to_string().contains("effect attempt 0 completion"));
    }

    #[test]
    fn oversized_commit_unknown_retains_exact_evidence_and_started_attempt() {
        let (kernel, subject, capability, request) = authorized_kernel();
        let oversized = vec![0x5a; MAX_COMMIT_UNKNOWN_EVIDENCE_BYTES + 1];

        let result =
            kernel.authorize_and_execute_classified(&subject, &capability, &request, |_| {
                EffectExecution::<(), Infallible>::CommitUnknown {
                    evidence: oversized.clone(),
                }
            });

        assert!(matches!(
            result,
            Err(EffectCommitError::CommitUnknownAndAudit {
                attempt_id,
                evidence,
                source: AuditError::Durable(DurableAuditError::RecordTooLarge(length)),
            }) if attempt_id == AttemptId::from_u64(0)
                && evidence == oversized
                && length == MAX_COMMIT_UNKNOWN_EVIDENCE_BYTES + 1
        ));
        assert_eq!(
            kernel
                .attempt_records()
                .expect("invalid evidence must leave audit readable")[0]
                .outcome(),
            AttemptOutcome::Started
        );
    }

    #[test]
    fn committed_audit_failure_retains_attempt_and_exact_receipt() {
        let directory = TestDirectory::new();
        let journal = directory.0.join("audit.wal");
        let moved = directory.0.join("moved.wal");
        let (kernel, subject, capability, request) = durable_authorized_kernel(&journal);
        let token = b"provider-accepted-request-7".to_vec();

        let result =
            kernel.authorize_and_execute_classified(&subject, &capability, &request, |_| {
                replace_journal_path(&journal, &moved);
                EffectExecution::<(), Infallible>::Committed {
                    value: (),
                    receipt: Some(token.clone()),
                }
            });

        match result.expect_err("swapped WAL path must fail the terminal receipt") {
            EffectCommitError::CommittedButAudit {
                attempt_id,
                receipt,
                source,
            } => {
                assert_eq!(attempt_id, AttemptId::from_u64(0));
                assert_eq!(receipt.attempt_id(), attempt_id);
                assert_eq!(receipt.token(), token);
                assert!(matches!(
                    source,
                    AuditError::Durable(DurableAuditError::PathIdentityChanged)
                ));
            }
            other => panic!("unexpected committed audit error: {other:?}"),
        }
        assert_eq!(
            kernel
                .attempt_records()
                .expect("failed terminal receipt must leave audit readable")[0]
                .outcome(),
            AttemptOutcome::Started
        );
    }

    #[test]
    fn commit_unknown_audit_failure_retains_attempt_and_exact_evidence() {
        let directory = TestDirectory::new();
        let journal = directory.0.join("audit.wal");
        let moved = directory.0.join("moved.wal");
        let (kernel, subject, capability, request) = durable_authorized_kernel(&journal);
        let evidence = b"provider-timeout-after-request-write".to_vec();

        let result =
            kernel.authorize_and_execute_classified(&subject, &capability, &request, |_| {
                replace_journal_path(&journal, &moved);
                EffectExecution::<(), Infallible>::CommitUnknown {
                    evidence: evidence.clone(),
                }
            });

        match result.expect_err("swapped WAL path must fail terminal evidence") {
            EffectCommitError::CommitUnknownAndAudit {
                attempt_id,
                evidence: retained,
                source,
            } => {
                assert_eq!(attempt_id, AttemptId::from_u64(0));
                assert_eq!(retained, evidence);
                assert!(matches!(
                    source,
                    AuditError::Durable(DurableAuditError::PathIdentityChanged)
                ));
            }
            other => panic!("unexpected unknown audit error: {other:?}"),
        }
        assert_eq!(
            kernel
                .attempt_records()
                .expect("failed terminal evidence must leave audit readable")[0]
                .outcome(),
            AttemptOutcome::Started
        );
    }

    fn authorized_kernel() -> (
        CapabilityKernel,
        SubjectId,
        crate::capability::CapId,
        CapabilityRequest,
    ) {
        let kernel = CapabilityKernel::new(CapabilityState::new(IssuerId::new("issuer")));
        let subject = SubjectId::new("subject");
        let validity = TimeWindow::new(MonotonicTime::from_ticks(0), MonotonicTime::from_ticks(10))
            .expect("fixed test bounds must form a non-empty window");
        kernel
            .register_subject(Subject::new(
                subject.clone(),
                StaticAuthorityEnvelope::new(validity, read_authority()),
            ))
            .expect("subject registration must succeed");
        let capability = kernel
            .issue_root(CapabilityGrant::new(
                subject.clone(),
                validity,
                read_authority(),
            ))
            .expect("root capability issuance must succeed");
        let request = CapabilityRequest::new(
            MonotonicTime::from_ticks(1),
            AuthorityRequest::File(FileRequest::new(
                RepoId::new("workspace"),
                FileEffect::ReadData,
                CanonicalPath::root(),
            )),
        );
        (kernel, subject, capability, request)
    }

    fn durable_authorized_kernel(
        journal: &Path,
    ) -> (
        CapabilityKernel,
        SubjectId,
        crate::capability::CapId,
        CapabilityRequest,
    ) {
        let backend = DurableAuditLog::create(journal).expect("create durable kernel WAL");
        let state = CapabilityState::new(IssuerId::new("issuer"));
        let kernel = CapabilityKernel::try_new_with_durable_audit(state, backend)
            .expect("construct durable kernel");
        let subject = SubjectId::new("subject");
        let validity = TimeWindow::new(MonotonicTime::from_ticks(0), MonotonicTime::from_ticks(10))
            .expect("fixed test bounds must form a non-empty window");
        kernel
            .register_subject(Subject::new(
                subject.clone(),
                StaticAuthorityEnvelope::new(validity, read_authority()),
            ))
            .expect("subject registration must succeed");
        let capability = kernel
            .issue_root(CapabilityGrant::new(
                subject.clone(),
                validity,
                read_authority(),
            ))
            .expect("root capability issuance must succeed");
        let request = CapabilityRequest::new(
            MonotonicTime::from_ticks(1),
            AuthorityRequest::File(FileRequest::new(
                RepoId::new("workspace"),
                FileEffect::ReadData,
                CanonicalPath::root(),
            )),
        );
        (kernel, subject, capability, request)
    }

    fn replace_journal_path(journal: &Path, moved: &Path) {
        fs::rename(journal, moved).expect("move locked journal inode");
        fs::copy(moved, journal).expect("replace journal pathname");
    }
}
