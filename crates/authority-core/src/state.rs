//! Sequential capability issuance, delegation, holding, and revocation state.

use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt,
};

use crate::{
    capability::{
        AuthorityBody, CapId, Capability, CapabilityMetadata, CapabilityRequest, IssuerId,
        SubjectId, authority_body_below, capability_matches,
    },
    handle::{HandleId, ObjectId, OpenHandle},
    time::{MonotonicTime, TimeWindow},
};

/// The immutable authority ceiling assigned to one subject.
///
/// Capability issuance may narrow this envelope but can never expand it. The
/// envelope intentionally excludes identity and delegation metadata because
/// those fields are checked by [`CapabilityState`] as transition policy.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct StaticAuthorityEnvelope {
    validity: TimeWindow,
    authority: AuthorityBody,
}

impl StaticAuthorityEnvelope {
    /// Creates a static authority ceiling from validated authority fields.
    #[must_use]
    pub const fn new(validity: TimeWindow, authority: AuthorityBody) -> Self {
        Self {
            validity,
            authority,
        }
    }

    /// Returns the maximum validity window assigned to the subject.
    #[must_use]
    pub const fn validity(&self) -> TimeWindow {
        self.validity
    }

    /// Returns the maximum typed authority assigned to the subject.
    #[must_use]
    pub const fn authority(&self) -> &AuthorityBody {
        &self.authority
    }

    /// Returns whether the supplied authority fields stay within this envelope.
    #[must_use]
    pub fn contains(&self, validity: TimeWindow, authority: &AuthorityBody) -> bool {
        validity.is_subset_of(self.validity) && authority_body_below(authority, &self.authority)
    }
}

/// A registered subject and its immutable authority ceiling.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Subject {
    id: SubjectId,
    parent: Option<SubjectId>,
    envelope: StaticAuthorityEnvelope,
}

/// Lifecycle state for a registered subject.
///
/// Registration publishes a fully initialized [`Subject`] as running. Closing
/// immediately blocks new authorization and capability issuance; the external
/// supervisor may then stop resources before marking the subject closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SubjectStatus {
    /// The subject may receive and exercise capabilities.
    Running,
    /// New authority use is blocked while external resources are torn down.
    Closing,
    /// Teardown completed and the subject cannot become running again.
    Closed,
}

/// Reports the result of beginning subject shutdown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubjectCloseStatus {
    /// The subject changed from running to closing.
    Started,
    /// The subject was already closing.
    AlreadyClosing,
    /// The subject had already completed shutdown.
    AlreadyClosed,
}

/// Reports the result of completing subject shutdown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubjectFinishStatus {
    /// The subject changed from closing to closed.
    Closed,
    /// The subject was already closed.
    AlreadyClosed,
}

/// Reports whether closing a handle changed the live-handle registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandleCloseStatus {
    /// The handle was live and is now closed.
    Closed,
    /// The handle identity was issued previously and was already closed.
    AlreadyClosed,
}

impl Subject {
    /// Creates a root subject without a parent.
    #[must_use]
    pub const fn new(id: SubjectId, envelope: StaticAuthorityEnvelope) -> Self {
        Self {
            id,
            parent: None,
            envelope,
        }
    }

    /// Records the already-registered parent of this subject.
    #[must_use]
    pub fn with_parent(mut self, parent: SubjectId) -> Self {
        self.parent = Some(parent);
        self
    }

    /// Returns the subject identity.
    #[must_use]
    pub const fn id(&self) -> &SubjectId {
        &self.id
    }

    /// Returns the parent subject, if this is not a root subject.
    #[must_use]
    pub const fn parent(&self) -> Option<&SubjectId> {
        self.parent.as_ref()
    }

    /// Returns the subject's immutable authority ceiling.
    #[must_use]
    pub const fn envelope(&self) -> &StaticAuthorityEnvelope {
        &self.envelope
    }
}

/// Authority fields requested for a new capability.
///
/// The request cannot choose identity metadata. [`CapabilityState`] assigns the
/// capability ID, issuer, and parent link only after every transition check has
/// succeeded.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CapabilityGrant {
    subject: SubjectId,
    validity: TimeWindow,
    authority: AuthorityBody,
    delegable: bool,
}

impl CapabilityGrant {
    /// Creates a non-delegable capability grant.
    #[must_use]
    pub const fn new(subject: SubjectId, validity: TimeWindow, authority: AuthorityBody) -> Self {
        Self {
            subject,
            validity,
            authority,
            delegable: false,
        }
    }

    /// Sets whether a successfully issued capability may derive children.
    #[must_use]
    pub const fn with_delegable(mut self, delegable: bool) -> Self {
        self.delegable = delegable;
        self
    }

    /// Returns the subject that will hold the new capability.
    #[must_use]
    pub const fn subject(&self) -> &SubjectId {
        &self.subject
    }

    /// Returns the proposed validity window.
    #[must_use]
    pub const fn validity(&self) -> TimeWindow {
        self.validity
    }

    /// Returns the proposed typed authority.
    #[must_use]
    pub const fn authority(&self) -> &AuthorityBody {
        &self.authority
    }

    /// Returns whether the proposed capability may derive children.
    #[must_use]
    pub const fn is_delegable(&self) -> bool {
        self.delegable
    }
}

/// Reports whether a revoke transition changed the state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevocationStatus {
    /// The capability became directly revoked in this transition.
    NewlyRevoked,
    /// The capability was already directly revoked.
    AlreadyRevoked,
}

/// Monotone version for cached authorization decisions.
///
/// A newly effective revocation advances this value. Cache users must include
/// the observed epoch in their key and discard entries after it changes.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AuthorizationEpoch(u64);

impl AuthorizationEpoch {
    /// Returns the numeric session-local epoch.
    #[must_use]
    pub const fn as_u64(self) -> u64 {
        self.0
    }

    const fn checked_next(self) -> Option<Self> {
        match self.0.checked_add(1) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }
}

/// A rejected subject-registration or capability-state transition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CapabilityStateError {
    /// A subject with this identity is already registered.
    DuplicateSubject(SubjectId),
    /// A new subject refers to a parent that is not registered.
    UnknownParentSubject(SubjectId),
    /// A capability grant names a subject that is not registered.
    UnknownSubject(SubjectId),
    /// A transition requires a subject that is still running.
    SubjectNotRunning(SubjectId),
    /// Shutdown completion was requested before shutdown began.
    SubjectNotClosing(SubjectId),
    /// Shutdown completion was requested while the subject still owns handles.
    SubjectHasOpenHandles(SubjectId),
    /// A handle identity was already used earlier in this session.
    HandleIdAlreadyIssued(HandleId),
    /// A transition refers to a handle identity never issued in this session.
    UnknownHandle(HandleId),
    /// A transition refers to a capability that was never issued.
    UnknownCapability(CapId),
    /// The caller does not hold the requested parent capability.
    ParentNotHeld {
        /// The authenticated caller.
        caller: SubjectId,
        /// The requested parent capability.
        parent: CapId,
    },
    /// The parent or one of its ancestors is expired, not yet valid, or revoked.
    ParentChainInactive(CapId),
    /// The parent does not permit further delegation.
    ParentNotDelegable(CapId),
    /// The proposed authority is not contained by the parent capability.
    GrantExceedsParent(CapId),
    /// The proposed authority is not contained by the target subject's envelope.
    GrantExceedsEnvelope(SubjectId),
    /// The session-local capability ID sequence has no remaining values.
    CapabilityIdExhausted,
    /// The authorization epoch cannot advance without wrapping.
    AuthorizationEpochExhausted,
}

impl fmt::Display for CapabilityStateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateSubject(subject) => {
                write!(formatter, "subject `{subject}` is already registered")
            }
            Self::UnknownParentSubject(subject) => {
                write!(formatter, "parent subject `{subject}` is not registered")
            }
            Self::UnknownSubject(subject) => {
                write!(formatter, "target subject `{subject}` is not registered")
            }
            Self::SubjectNotRunning(subject) => {
                write!(formatter, "subject `{subject}` is not running")
            }
            Self::SubjectNotClosing(subject) => {
                write!(formatter, "subject `{subject}` is not closing")
            }
            Self::SubjectHasOpenHandles(subject) => {
                write!(formatter, "subject `{subject}` still has open handles")
            }
            Self::HandleIdAlreadyIssued(handle) => {
                write!(formatter, "handle `{handle}` was already issued")
            }
            Self::UnknownHandle(handle) => {
                write!(formatter, "handle `{handle}` was not issued by this state")
            }
            Self::UnknownCapability(capability) => {
                write!(
                    formatter,
                    "capability `{capability}` was not issued by this state"
                )
            }
            Self::ParentNotHeld { caller, parent } => write!(
                formatter,
                "subject `{caller}` does not hold parent capability `{parent}`"
            ),
            Self::ParentChainInactive(parent) => write!(
                formatter,
                "parent capability `{parent}` or one of its ancestors is inactive"
            ),
            Self::ParentNotDelegable(parent) => {
                write!(formatter, "parent capability `{parent}` is not delegable")
            }
            Self::GrantExceedsParent(parent) => write!(
                formatter,
                "requested capability authority exceeds parent `{parent}`"
            ),
            Self::GrantExceedsEnvelope(subject) => write!(
                formatter,
                "requested capability authority exceeds subject `{subject}` envelope"
            ),
            Self::CapabilityIdExhausted => {
                formatter.write_str("session-local capability ID sequence is exhausted")
            }
            Self::AuthorizationEpochExhausted => {
                formatter.write_str("session-local authorization epoch is exhausted")
            }
        }
    }
}

impl Error for CapabilityStateError {}

/// Session-local sequential state for capability issuance and revocation.
///
/// This type deliberately has no internal synchronization. A later
/// authorization guard will serialize it with effect commit and revoke; this
/// layer defines the deterministic transition rules that guard must protect.
#[derive(Debug)]
pub struct CapabilityState {
    issuer: IssuerId,
    next_capability_sequence: Option<u64>,
    subjects: BTreeMap<SubjectId, Subject>,
    subject_statuses: BTreeMap<SubjectId, SubjectStatus>,
    capabilities: BTreeMap<CapId, Capability>,
    held: BTreeMap<SubjectId, BTreeSet<CapId>>,
    revoked: BTreeSet<CapId>,
    issued_ids: BTreeSet<CapId>,
    authorization_epoch: AuthorizationEpoch,
    open_handles: BTreeMap<HandleId, OpenHandle>,
    issued_handle_ids: BTreeSet<HandleId>,
}

impl CapabilityState {
    /// Creates empty state for one session-local capability issuer.
    #[must_use]
    pub const fn new(issuer: IssuerId) -> Self {
        Self {
            issuer,
            next_capability_sequence: Some(0),
            subjects: BTreeMap::new(),
            subject_statuses: BTreeMap::new(),
            capabilities: BTreeMap::new(),
            held: BTreeMap::new(),
            revoked: BTreeSet::new(),
            issued_ids: BTreeSet::new(),
            authorization_epoch: AuthorizationEpoch(0),
            open_handles: BTreeMap::new(),
            issued_handle_ids: BTreeSet::new(),
        }
    }

    /// Returns the issuer assigned to every capability created by this state.
    #[must_use]
    pub const fn issuer(&self) -> &IssuerId {
        &self.issuer
    }

    /// Returns the version of the current authorization state.
    #[must_use]
    pub const fn authorization_epoch(&self) -> AuthorizationEpoch {
        self.authorization_epoch
    }

    /// Registers a subject before capabilities may be issued to it.
    ///
    /// # Errors
    ///
    /// Returns [`CapabilityStateError::DuplicateSubject`] if the identity is
    /// already present, or [`CapabilityStateError::UnknownParentSubject`] if a
    /// parent link does not resolve to an existing subject.
    pub fn register_subject(&mut self, subject: Subject) -> Result<(), CapabilityStateError> {
        if self.subjects.contains_key(subject.id()) {
            return Err(CapabilityStateError::DuplicateSubject(subject.id().clone()));
        }
        if let Some(parent) = subject.parent()
            && !self.subjects.contains_key(parent)
        {
            return Err(CapabilityStateError::UnknownParentSubject(parent.clone()));
        }
        if let Some(parent) = subject.parent() {
            self.ensure_subject_running(parent)?;
        }

        let subject_id = subject.id().clone();
        self.held.insert(subject_id.clone(), BTreeSet::new());
        self.subject_statuses
            .insert(subject_id.clone(), SubjectStatus::Running);
        self.subjects.insert(subject_id, subject);
        Ok(())
    }

    /// Returns a registered subject.
    #[must_use]
    pub fn subject(&self, subject: &SubjectId) -> Option<&Subject> {
        self.subjects.get(subject)
    }

    /// Returns the lifecycle status of a registered subject.
    #[must_use]
    pub fn subject_status(&self, subject: &SubjectId) -> Option<SubjectStatus> {
        self.subject_statuses.get(subject).copied()
    }

    /// Returns a live open-handle record.
    #[must_use]
    pub fn open_handle(&self, handle: &HandleId) -> Option<&OpenHandle> {
        self.open_handles.get(handle)
    }

    /// Returns the number of live handles owned by a subject.
    #[must_use]
    pub fn subject_open_handle_count(&self, subject: &SubjectId) -> usize {
        self.open_handles
            .values()
            .filter(|handle| handle.subject() == subject)
            .count()
    }

    /// Returns the number of live handles referring to a namespace object.
    #[must_use]
    pub fn object_open_handle_count(&self, object: &ObjectId) -> usize {
        self.open_handles
            .values()
            .filter(|handle| handle.object() == object)
            .count()
    }

    /// Records a newly opened handle without caching its authorization.
    ///
    /// Handle identities remain reserved after close, preventing a delayed
    /// request from being rebound to a different live handle.
    ///
    /// # Errors
    ///
    /// Returns an error when the owner is unknown or not running, or when the
    /// handle identity has ever been issued in this session.
    pub fn register_open_handle(&mut self, handle: OpenHandle) -> Result<(), CapabilityStateError> {
        self.ensure_subject_running(handle.subject())?;
        if self.issued_handle_ids.contains(handle.id()) {
            return Err(CapabilityStateError::HandleIdAlreadyIssued(
                handle.id().clone(),
            ));
        }

        self.issued_handle_ids.insert(handle.id().clone());
        self.open_handles.insert(handle.id().clone(), handle);
        Ok(())
    }

    /// Removes a live handle while retaining its identity as permanently used.
    ///
    /// # Errors
    ///
    /// Returns [`CapabilityStateError::UnknownHandle`] when the identity was
    /// never issued in this session.
    pub fn close_handle(
        &mut self,
        handle: &HandleId,
    ) -> Result<HandleCloseStatus, CapabilityStateError> {
        if self.open_handles.remove(handle).is_some() {
            return Ok(HandleCloseStatus::Closed);
        }
        if self.issued_handle_ids.contains(handle) {
            Ok(HandleCloseStatus::AlreadyClosed)
        } else {
            Err(CapabilityStateError::UnknownHandle(handle.clone()))
        }
    }

    /// Returns an issued capability, including one that is now revoked.
    #[must_use]
    pub fn capability(&self, capability: &CapId) -> Option<&Capability> {
        self.capabilities.get(capability)
    }

    /// Returns whether `subject` currently holds `capability`.
    #[must_use]
    pub fn is_held_by(&self, subject: &SubjectId, capability: &CapId) -> bool {
        self.held
            .get(subject)
            .is_some_and(|capabilities| capabilities.contains(capability))
    }

    /// Returns whether this capability was directly revoked.
    #[must_use]
    pub fn is_revoked(&self, capability: &CapId) -> bool {
        self.revoked.contains(capability)
    }

    /// Issues a root capability inside the target subject's static envelope.
    ///
    /// The state assigns a fresh ID and records no parent link. Rejected grants
    /// leave the capability sequence, issued-ID set, and held set unchanged.
    ///
    /// # Errors
    ///
    /// Returns an error if the target subject is unknown, the grant exceeds its
    /// envelope, or the session-local ID sequence is exhausted.
    pub fn issue_root(&mut self, grant: CapabilityGrant) -> Result<CapId, CapabilityStateError> {
        self.validate_envelope(&grant)?;
        self.issue(grant, None)
    }

    /// Derives a capability from a held, active, delegable parent.
    ///
    /// The caller identity must come from the trusted transport boundary rather
    /// than request payload. The state supplies the fresh child ID, issuer, and
    /// exact parent link only after all checks succeed.
    ///
    /// # Errors
    ///
    /// Returns an error unless the parent exists, is held by `caller`, has an
    /// active ancestor chain at `now`, permits delegation, contains the grant,
    /// and the target subject's static envelope also contains the grant.
    pub fn derive(
        &mut self,
        caller: &SubjectId,
        parent_id: &CapId,
        grant: CapabilityGrant,
        now: MonotonicTime,
    ) -> Result<CapId, CapabilityStateError> {
        self.ensure_subject_running(caller)?;
        let parent = self
            .capabilities
            .get(parent_id)
            .ok_or_else(|| CapabilityStateError::UnknownCapability(parent_id.clone()))?;

        if parent.metadata().subject() != caller || !self.is_held_by(caller, parent_id) {
            return Err(CapabilityStateError::ParentNotHeld {
                caller: caller.clone(),
                parent: parent_id.clone(),
            });
        }
        if !self.is_effectively_active(parent_id, now) {
            return Err(CapabilityStateError::ParentChainInactive(parent_id.clone()));
        }
        if !parent.metadata().is_delegable() {
            return Err(CapabilityStateError::ParentNotDelegable(parent_id.clone()));
        }
        if !grant.validity().is_subset_of(parent.validity())
            || !authority_body_below(grant.authority(), parent.authority())
        {
            return Err(CapabilityStateError::GrantExceedsParent(parent_id.clone()));
        }

        self.validate_envelope(&grant)?;
        self.issue(grant, Some(parent_id.clone()))
    }

    /// Directly revokes an issued capability.
    ///
    /// Descendants remain recorded but become effectively inactive because
    /// authorization and derivation walk every ancestor link.
    ///
    /// # Errors
    ///
    /// Returns [`CapabilityStateError::UnknownCapability`] for an ID that this
    /// session never issued.
    pub fn revoke(&mut self, capability: &CapId) -> Result<RevocationStatus, CapabilityStateError> {
        if !self.capabilities.contains_key(capability) {
            return Err(CapabilityStateError::UnknownCapability(capability.clone()));
        }

        if self.revoked.contains(capability) {
            return Ok(RevocationStatus::AlreadyRevoked);
        }

        let next_epoch = self
            .authorization_epoch
            .checked_next()
            .ok_or(CapabilityStateError::AuthorizationEpochExhausted)?;
        self.revoked.insert(capability.clone());
        self.authorization_epoch = next_epoch;
        Ok(RevocationStatus::NewlyRevoked)
    }

    /// Begins monotone shutdown and revokes every capability held by a subject.
    ///
    /// The transition from running to closing advances the authorization epoch
    /// exactly once, even when the subject holds no capabilities. Existing
    /// records remain available for audit and descendant capabilities become
    /// inactive through their revoked ancestor chain.
    ///
    /// # Errors
    ///
    /// Returns [`CapabilityStateError::UnknownSubject`] for an unregistered
    /// identity, or [`CapabilityStateError::AuthorizationEpochExhausted`] if
    /// the transition cannot invalidate cached decisions without wrapping.
    pub fn begin_subject_close(
        &mut self,
        subject: &SubjectId,
    ) -> Result<SubjectCloseStatus, CapabilityStateError> {
        match self.subject_status(subject) {
            None => return Err(CapabilityStateError::UnknownSubject(subject.clone())),
            Some(SubjectStatus::Closing) => return Ok(SubjectCloseStatus::AlreadyClosing),
            Some(SubjectStatus::Closed) => return Ok(SubjectCloseStatus::AlreadyClosed),
            Some(SubjectStatus::Running) => {}
        }

        let next_epoch = self.next_authorization_epoch()?;
        if let Some(capabilities) = self.held.get(subject) {
            self.revoked.extend(capabilities.iter().cloned());
        }
        self.subject_statuses
            .insert(subject.clone(), SubjectStatus::Closing);
        self.authorization_epoch = next_epoch;
        Ok(SubjectCloseStatus::Started)
    }

    /// Marks a closing subject as fully torn down.
    ///
    /// # Errors
    ///
    /// Returns [`CapabilityStateError::UnknownSubject`] for an unregistered
    /// identity or [`CapabilityStateError::SubjectNotClosing`] when shutdown
    /// has not begun.
    pub fn finish_subject_close(
        &mut self,
        subject: &SubjectId,
    ) -> Result<SubjectFinishStatus, CapabilityStateError> {
        match self.subject_status(subject) {
            None => Err(CapabilityStateError::UnknownSubject(subject.clone())),
            Some(SubjectStatus::Running) => {
                Err(CapabilityStateError::SubjectNotClosing(subject.clone()))
            }
            Some(SubjectStatus::Closing) => {
                if self.subject_open_handle_count(subject) != 0 {
                    return Err(CapabilityStateError::SubjectHasOpenHandles(subject.clone()));
                }
                self.subject_statuses
                    .insert(subject.clone(), SubjectStatus::Closed);
                Ok(SubjectFinishStatus::Closed)
            }
            Some(SubjectStatus::Closed) => Ok(SubjectFinishStatus::AlreadyClosed),
        }
    }

    /// Returns whether this capability and every ancestor are active at `now`.
    #[must_use]
    pub fn is_effectively_active(&self, capability: &CapId, now: MonotonicTime) -> bool {
        let mut current = Some(capability.clone());
        let mut visited = BTreeSet::new();

        while let Some(current_id) = current {
            // A cycle cannot be constructed through the public API. Treating a
            // corrupt cycle as inactive preserves fail-closed behavior.
            if !visited.insert(current_id.clone()) {
                return false;
            }
            let Some(current_capability) = self.capabilities.get(&current_id) else {
                return false;
            };
            if self.revoked.contains(&current_id) || !current_capability.validity().contains(now) {
                return false;
            }
            current = current_capability.metadata().parent().cloned();
        }

        true
    }

    /// Returns whether one held capability authorizes a request for `caller`.
    ///
    /// Unknown, copied, expired, or transitively revoked capability IDs all
    /// produce `false`; callers cannot bypass subject binding by presenting an
    /// ID held by another subject.
    #[must_use]
    pub fn authorizes(
        &self,
        caller: &SubjectId,
        capability_id: &CapId,
        request: &CapabilityRequest,
    ) -> bool {
        if self.subject_status(caller) != Some(SubjectStatus::Running) {
            return false;
        }
        let Some(capability) = self.capabilities.get(capability_id) else {
            return false;
        };

        capability.metadata().subject() == caller
            && self.is_held_by(caller, capability_id)
            && self.is_effectively_active(capability_id, request.time())
            && capability_matches(capability, request)
    }

    fn validate_envelope(&self, grant: &CapabilityGrant) -> Result<(), CapabilityStateError> {
        self.ensure_subject_running(grant.subject())?;
        let subject = self
            .subjects
            .get(grant.subject())
            .ok_or_else(|| CapabilityStateError::UnknownSubject(grant.subject().clone()))?;

        if subject
            .envelope()
            .contains(grant.validity(), grant.authority())
        {
            Ok(())
        } else {
            Err(CapabilityStateError::GrantExceedsEnvelope(
                grant.subject().clone(),
            ))
        }
    }

    fn ensure_subject_running(&self, subject: &SubjectId) -> Result<(), CapabilityStateError> {
        match self.subject_status(subject) {
            None => Err(CapabilityStateError::UnknownSubject(subject.clone())),
            Some(SubjectStatus::Running) => Ok(()),
            Some(SubjectStatus::Closing | SubjectStatus::Closed) => {
                Err(CapabilityStateError::SubjectNotRunning(subject.clone()))
            }
        }
    }

    fn next_authorization_epoch(&self) -> Result<AuthorizationEpoch, CapabilityStateError> {
        self.authorization_epoch
            .checked_next()
            .ok_or(CapabilityStateError::AuthorizationEpochExhausted)
    }

    fn issue(
        &mut self,
        grant: CapabilityGrant,
        parent: Option<CapId>,
    ) -> Result<CapId, CapabilityStateError> {
        let capability_id = self.allocate_capability_id()?;
        let mut metadata = CapabilityMetadata::new(
            capability_id.clone(),
            grant.subject.clone(),
            self.issuer.clone(),
        )
        .with_delegable(grant.delegable);
        if let Some(parent) = parent {
            metadata = metadata.with_parent(parent);
        }

        let capability = Capability::new(metadata, grant.validity, grant.authority);
        let subject_id = capability.metadata().subject().clone();

        self.issued_ids.insert(capability_id.clone());
        self.held
            .entry(subject_id)
            .or_default()
            .insert(capability_id.clone());
        self.capabilities.insert(capability_id.clone(), capability);

        Ok(capability_id)
    }

    fn allocate_capability_id(&mut self) -> Result<CapId, CapabilityStateError> {
        let sequence = self
            .next_capability_sequence
            .take()
            .ok_or(CapabilityStateError::CapabilityIdExhausted)?;
        self.next_capability_sequence = sequence.checked_add(1);

        let capability_id = CapId::new(format!("{}:{sequence}", self.issuer));
        if self.issued_ids.contains(&capability_id) {
            // The issuer and sequence form a session-local injective key. This
            // branch protects fail-closed behavior if that invariant changes.
            self.next_capability_sequence = None;
            return Err(CapabilityStateError::CapabilityIdExhausted);
        }

        Ok(capability_id)
    }
}

#[cfg(test)]
mod tests {
    use super::{AuthorizationEpoch, CapabilityState, CapabilityStateError};
    use crate::capability::IssuerId;

    // Requirement: the final u64 sequence value is usable exactly once and no
    // wrapped ID can be issued. Category: numeric boundary. Risk: critical.
    #[test]
    fn capability_id_allocation_stops_after_the_u64_maximum() {
        let mut state = CapabilityState::new(IssuerId::new("session-issuer"));
        state.next_capability_sequence = Some(u64::MAX);

        let final_id = state
            .allocate_capability_id()
            .expect("the maximum sequence value must remain available");

        assert_eq!(final_id.as_str(), "session-issuer:18446744073709551615");
        assert_eq!(
            state.allocate_capability_id(),
            Err(CapabilityStateError::CapabilityIdExhausted)
        );
    }

    // Requirement: an authorization epoch must never wrap to a stale value.
    // Category: numeric boundary. Risk: critical.
    #[test]
    fn authorization_epoch_stops_before_wraparound() {
        let mut state = CapabilityState::new(IssuerId::new("session-issuer"));
        state.authorization_epoch = AuthorizationEpoch(u64::MAX);

        assert_eq!(
            state.authorization_epoch.checked_next(),
            None,
            "the maximum epoch must not wrap"
        );
        assert_eq!(
            CapabilityStateError::AuthorizationEpochExhausted.to_string(),
            "session-local authorization epoch is exhausted"
        );
    }
}
