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
    audit::{AttemptRecord, AuditError, AuditTrail, EffectRecord},
    capability::{CapId, Capability, CapabilityRequest, CapabilityRequestSet, SubjectId},
    durable_audit::{CommitReceipt, DurableAuditLog},
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
}

impl fmt::Display for CapabilityKernelError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LockPoisoned => formatter.write_str("capability kernel state lock is poisoned"),
            Self::StateTransition(error) => error.fmt(formatter),
        }
    }
}

impl Error for CapabilityKernelError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::LockPoisoned => None,
            Self::StateTransition(error) => Some(error),
        }
    }
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
    CommittedButAudit(AuditError),
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
            Self::CommittedButAudit(error) => write!(
                formatter,
                "effect may be committed but its audit receipt failed: {error}"
            ),
        }
    }
}

impl<E: Error + 'static> Error for EffectCommitError<E> {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Effect(error) => Some(error),
            Self::Audit(error) | Self::CommittedButAudit(error) => Some(error),
            Self::LockPoisoned | Self::NotAuthorized => None,
        }
    }
}

/// A failed inspection of active capability authority.
///
/// Inspection does not represent an external effect and therefore does not
/// append an audit attempt. Callers must still use [`CapabilityKernel::authorize_and_commit`]
/// before reading or mutating protected data.
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
#[derive(Debug)]
pub struct CapabilityKernel {
    state: RwLock<CapabilityState>,
    audit: AuditTrail,
}

impl CapabilityKernel {
    /// Wraps initialized sequential state in the concurrent boundary.
    #[must_use]
    pub fn new(state: CapabilityState) -> Self {
        Self {
            state: RwLock::new(state),
            audit: AuditTrail::new(),
        }
    }

    /// Creates a kernel whose attempt journal is backed by the supplied WAL.
    ///
    /// The WAL's recovered attempt sequence is used, so reopening a session
    /// cannot reuse a prior attempt identity. Callers should use this
    /// constructor when terminal audit receipts must survive process restart.
    ///
    /// # Errors
    ///
    /// Returns [`AuditError`] if the backend cannot be inspected safely.
    pub fn try_new_with_durable_audit(
        state: CapabilityState,
        backend: DurableAuditLog,
    ) -> Result<Self, AuditError> {
        Ok(Self {
            state: RwLock::new(state),
            audit: AuditTrail::new_with_backend(Arc::new(backend))?,
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

    /// Revokes a capability while holding exclusive state access.
    ///
    /// The exclusive lock waits for every already-authorized effect to reach
    /// its linearization point. Once this method returns, later effect attempts
    /// recheck authorization against the revoked state.
    ///
    /// # Errors
    ///
    /// Returns [`CapabilityKernelError::LockPoisoned`] if a writer previously
    /// panicked, or wraps the sequential revocation error.
    pub fn revoke(&self, capability: &CapId) -> Result<RevocationStatus, CapabilityKernelError> {
        self.with_state_mut(|state| state.revoke(capability))
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
        self.with_state_mut(|state| state.begin_subject_close(subject))
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
    /// [`Self::authorize_and_commit`].
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

    /// Reauthorizes an effect and executes it through its linearization point.
    ///
    /// The executor runs while a shared state guard is held. It must return
    /// only after the external effect has either reached its documented
    /// linearization point or failed without committing. It must not re-enter
    /// this kernel, because attempting an exclusive transition while retaining
    /// shared access can deadlock.
    ///
    /// # Errors
    ///
    /// Returns [`EffectCommitError::LockPoisoned`] if a writer previously
    /// panicked, [`EffectCommitError::NotAuthorized`] without invoking the
    /// executor when the final check fails, or [`EffectCommitError::Effect`]
    /// when the executor reports a pre-commit failure.
    pub fn authorize_and_commit<T, E>(
        &self,
        caller: &SubjectId,
        capability_id: &CapId,
        request: &CapabilityRequest,
        commit_to_linearization: impl FnOnce(&Capability) -> Result<T, E>,
    ) -> Result<T, EffectCommitError<E>> {
        self.authorize_all_and_commit(
            caller,
            capability_id,
            &CapabilityRequestSet::one(request.clone()),
            commit_to_linearization,
        )
    }

    /// Reauthorizes one request and persists an adapter-provided commit
    /// receipt with the terminal durable audit record.
    ///
    /// # Errors
    ///
    /// Returns [`EffectCommitError::CommittedButAudit`] if the executor
    /// succeeds but the terminal receipt cannot be persisted.
    pub fn authorize_and_commit_with_receipt<T, E>(
        &self,
        caller: &SubjectId,
        capability_id: &CapId,
        request: &CapabilityRequest,
        commit_to_linearization: impl FnOnce(&Capability) -> Result<(T, Vec<u8>), E>,
    ) -> Result<T, EffectCommitError<E>> {
        self.authorize_all_and_commit_with_receipt(
            caller,
            capability_id,
            &CapabilityRequestSet::one(request.clone()),
            commit_to_linearization,
        )
    }

    /// Reauthorizes every request in one non-empty external operation and
    /// executes it through its linearization point.
    ///
    /// The kernel holds one shared state guard across all final checks and the
    /// executor. A revoke that returns therefore excludes the whole compound
    /// operation, not merely its first request. One audit attempt records the
    /// complete request set and becomes a committed effect only when the
    /// executor reaches its documented linearization point.
    ///
    /// The executor must not re-enter this kernel. It must return an error
    /// unless the operation either failed before its linearization point or
    /// reached that point for the whole request set.
    ///
    /// # Errors
    ///
    /// Returns [`EffectCommitError::LockPoisoned`] if a writer previously
    /// panicked, [`EffectCommitError::NotAuthorized`] without invoking the
    /// executor when any request is denied, or [`EffectCommitError::Effect`]
    /// when the executor reports a pre-commit failure.
    pub fn authorize_all_and_commit<T, E>(
        &self,
        caller: &SubjectId,
        capability_id: &CapId,
        requests: &CapabilityRequestSet,
        commit_to_linearization: impl FnOnce(&Capability) -> Result<T, E>,
    ) -> Result<T, EffectCommitError<E>> {
        self.authorize_all_and_commit_inner(caller, capability_id, requests, |capability| {
            commit_to_linearization(capability).map(|value| (value, None))
        })
    }

    /// Reauthorizes every request and accepts an adapter-provided commit
    /// receipt from the executor.
    ///
    /// The returned token is persisted with the terminal WAL record. This is
    /// the preferred entry point for external providers with an idempotency
    /// or acceptance identifier. A provider token is only meaningful if the
    /// executor returns it after its documented linearization point.
    ///
    /// # Errors
    ///
    /// Returns [`EffectCommitError::CommittedButAudit`] when the executor
    /// succeeded but the receipt could not be durably recorded; that result
    /// means the external effect may already exist and needs reconciliation.
    pub fn authorize_all_and_commit_with_receipt<T, E>(
        &self,
        caller: &SubjectId,
        capability_id: &CapId,
        requests: &CapabilityRequestSet,
        commit_to_linearization: impl FnOnce(&Capability) -> Result<(T, Vec<u8>), E>,
    ) -> Result<T, EffectCommitError<E>> {
        self.authorize_all_and_commit_inner(caller, capability_id, requests, |capability| {
            commit_to_linearization(capability).map(|(value, token)| (value, Some(token)))
        })
    }

    fn authorize_all_and_commit_inner<T, E>(
        &self,
        caller: &SubjectId,
        capability_id: &CapId,
        requests: &CapabilityRequestSet,
        commit_to_linearization: impl FnOnce(&Capability) -> Result<(T, Option<Vec<u8>>), E>,
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
            Ok((value, receipt)) => {
                let receipt = receipt.map_or_else(
                    || CommitReceipt::kernel_success(attempt_id),
                    |token| CommitReceipt::new(attempt_id, token),
                );
                let audit_result = attempt.commit_with_receipt(&receipt);
                drop(state);
                match audit_result {
                    Ok(()) => Ok(value),
                    Err(error) => Err(EffectCommitError::CommittedButAudit(error)),
                }
            }
            Err(error) => {
                let audit_result = attempt.fail_before_commit();
                drop(state);
                match audit_result {
                    Ok(()) => Err(EffectCommitError::Effect(error)),
                    Err(audit_error) => Err(EffectCommitError::Audit(audit_error)),
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

#[cfg(all(test, not(loom)))]
mod tests {
    use std::thread;

    use super::{CapabilityKernel, CapabilityKernelError};
    use crate::{
        capability::{AuthorityBody, IssuerId, SubjectId},
        file::{FileAuthority, FileEffects},
        path::{CanonicalPath, PathPattern},
        repository::RepoId,
        state::{CapabilityState, StaticAuthorityEnvelope, Subject},
        time::{MonotonicTime, TimeWindow},
    };

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
}
