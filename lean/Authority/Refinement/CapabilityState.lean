import Authority.Refinement.Observation

/-!
# Capability-State Observation Refinement

An executable, proof-carrying checker for versioned logical events over
`CapabilityState`. Its soundness theorems concern only supplied and checked
Lean data. In particular, an audit or observer-error label is not proof that a
Rust process emitted that event.
-/

namespace Authority.Refinement.CapabilityState

abbrev ModelState := Authority.CapabilityState

/-- Operations covered by this refinement checker. -/
inductive Command where
  | registerSubject (subject : Subject)
  | issueRootWithId (capabilityId : CapId) (grant : CapabilityGrant)
  | allocateRoot (grant : CapabilityGrant)
  | derive (caller : SubjectId) (parentId : CapId) (grant : CapabilityGrant)
      (now : MonotonicTime)
  | revoke (capabilityId : CapId)
  | beginSubjectClose (subject : SubjectId)
  | finishSubjectClose (subject : SubjectId)
  | registerHandle (handle : OpenHandle)
  | closeHandle (caller : SubjectId) (handleId : HandleId)
  | effectAttempt (caller : SubjectId) (capabilityId : CapId)
      (request : CapabilityRequest)

/-- Executably distinguished rejection explanations. -/
inductive RejectionReason where
  | duplicateSubject
  | unknownParentSubject
  | invalidCapabilityId
  | capabilityAlreadyIssued
  | unknownCapability
  | parentNotHeld
  | parentChainInactive
  | parentNotDelegable
  | grantExceedsParent
  | grantExceedsEnvelope
  | capabilityIdExhausted
  | authorizationEpochExhausted
  | unknownSubject
  | subjectNotRunning
  | subjectNotClosing
  | subjectHasOpenHandles (handleId : HandleId)
  | handleAlreadyIssued
  | unknownHandle
  | handleNotOwned
  | notAuthorized
  deriving Repr, BEq, DecidableEq

/-- Audit phase reported by an event producer; the checker proves no occurrence claim. -/
inductive AuditFailurePhase where
  | start
  | denialTerminal
  | precommitTerminal
  | committedTerminal
  deriving Repr, BEq, DecidableEq

/-- Observable call outcomes, including errors returned after a committed transition. -/
inductive Outcome where
  | accepted
  | rejectedNoEffect (reason : RejectionReason)
  | effectFailedBeforeCommit
  | allocatorExhausted
  | revocationCommittedButPropagationError
  | auditFailure (phase : AuditFailurePhase)

/-- One versioned command/outcome observation. -/
structure Event where
  schemaVersion : Nat
  command : Command
  outcome : Outcome

/-- Grant checks that precede sequential root-ID allocation. -/
structure RootGrantReady (state : ModelState) (grant : CapabilityGrant) where
  targetSubject : Subject
  targetLookup : state.subjects grant.subject = some targetSubject
  targetRunning : state.subjectStatuses grant.subject = some .running
  grantInsideEnvelope :
    targetSubject.envelope.contains grant.validity grant.authority = true

/-- Derivation checks that precede sequential child-ID allocation. -/
structure DeriveReady (state : ModelState) (caller : SubjectId)
    (parentId : CapId) (grant : CapabilityGrant) (now : MonotonicTime) where
  callerRunning : state.subjectStatuses caller = some .running
  parentCapability : Capability
  parentLookup : state.capabilities parentId = some parentCapability
  parentBoundToCaller : parentCapability.metadata.subject = caller
  parentHeld : state.HeldBy caller parentId
  parentActive : state.EffectivelyActive parentId now
  parentDelegable : parentCapability.metadata.delegable = true
  grantBelowParent :
    timeWindowBelow grant.validity parentCapability.validity = true ∧
      authorityBodyBelow grant.authority parentCapability.authority = true
  targetSubject : Subject
  targetLookup : state.subjects grant.subject = some targetSubject
  targetRunning : state.subjectStatuses grant.subject = some .running
  grantInsideEnvelope :
    targetSubject.envelope.contains grant.validity grant.authority = true

/-- A first allocator error occurs only after all command-specific checks pass. -/
inductive FirstAllocationExhaustion : Command → ModelState → Prop
  | root {state : ModelState} {grant : CapabilityGrant} :
      RootGrantReady state grant →
      Authority.CapabilityState.MayExhaustAllocator state →
      FirstAllocationExhaustion (.allocateRoot grant) state
  | derived {state : ModelState} {caller : SubjectId} {parentId : CapId}
      {grant : CapabilityGrant} {now : MonotonicTime} :
      DeriveReady state caller parentId grant now →
      Authority.CapabilityState.MayExhaustAllocator state →
      FirstAllocationExhaustion (.derive caller parentId grant now) state

/-- Forget command validation while retaining the state-changing scan evidence. -/
theorem FirstAllocationExhaustion.scanEvidence {command : Command}
    {state : ModelState} (failure : FirstAllocationExhaustion command state) :
    Authority.CapabilityState.MayExhaustAllocator state := by
  cases failure with
  | root _ exhausted => exact exhausted
  | derived _ exhausted => exact exhausted

/-- State already committed when revocation propagation subsequently reports an error. -/
inductive PropagationFailure : Command → ModelState → ModelState → Prop
  | revoke {state : ModelState} {capabilityId : CapId}
      (issued : state.WasIssued capabilityId)
      (unrevoked : state.revoked capabilityId = false)
      (canIncrement : CanIncrementU64 state.authorizationEpoch) :
      PropagationFailure (.revoke capabilityId) state (state.revoke capabilityId)
  | beginClose {state : ModelState} {subject : SubjectId}
      (running : state.subjectStatuses subject = some .running)
      (canIncrement : CanIncrementU64 state.authorizationEpoch) :
      PropagationFailure (.beginSubjectClose subject) state
        (state.beginSubjectClose subject)

/-- Propagation errors retain the already-committed state transition. -/
theorem PropagationFailure.toSteps {command : Command} {before after : ModelState}
    (failure : PropagationFailure command before after) :
    Authority.CapabilityState.Steps before after := by
  cases failure with
  | revoke issued unrevoked canIncrement =>
      exact .tail (.refl _) (.revoke issued unrevoked canIncrement)
  | beginClose running canIncrement =>
      exact .tail (.refl _) (.beginClose running canIncrement)

/-- Accepted labels are tied to exact constructors of the existing state machine. -/
inductive Accepted : Command → ModelState → ModelState → Prop
  | registerSubject {state : ModelState} {subject : Subject}
      (allowed : Authority.CapabilityState.MayRegisterSubject state subject) :
      Accepted (.registerSubject subject) state (state.registerSubject subject)
  | issueRootWithId {state : ModelState} {capabilityId : CapId}
      {grant : CapabilityGrant}
      (allowed : Authority.CapabilityState.MayIssueRoot state capabilityId grant) :
      Accepted (.issueRootWithId capabilityId grant)
        state (state.issue capabilityId none grant)
  | allocateRoot {state : ModelState} {grant : CapabilityGrant}
      (allowed : Authority.CapabilityState.MayAllocateRoot state grant) :
      Accepted (.allocateRoot grant) state
        (state.allocateRoot grant allowed.allocation.selectedSequence)
  | derive {state : ModelState} {caller : SubjectId} {parentId : CapId}
      {grant : CapabilityGrant} {now : MonotonicTime}
      (allowed : Authority.CapabilityState.MayAllocateDerived
        state caller parentId grant now) :
      Accepted (.derive caller parentId grant now) state
        (state.allocateDerived parentId grant allowed.allocation.selectedSequence)
  | revoke {state : ModelState} {capabilityId : CapId}
      (issued : state.WasIssued capabilityId)
      (unrevoked : state.revoked capabilityId = false)
      (canIncrement : CanIncrementU64 state.authorizationEpoch) :
      Accepted (.revoke capabilityId) state (state.revoke capabilityId)
  | revokeAlready {state : ModelState} {capabilityId : CapId}
      (issued : state.WasIssued capabilityId)
      (revoked : state.revoked capabilityId = true) :
      Accepted (.revoke capabilityId) state state
  | beginClose {state : ModelState} {subject : SubjectId}
      (running : state.subjectStatuses subject = some .running)
      (canIncrement : CanIncrementU64 state.authorizationEpoch) :
      Accepted (.beginSubjectClose subject) state (state.beginSubjectClose subject)
  | beginCloseAlreadyClosing {state : ModelState} {subject : SubjectId}
      (closing : state.subjectStatuses subject = some .closing) :
      Accepted (.beginSubjectClose subject) state state
  | beginCloseAlreadyClosed {state : ModelState} {subject : SubjectId}
      (closed : state.subjectStatuses subject = some .closed) :
      Accepted (.beginSubjectClose subject) state state
  | finishClose {state : ModelState} {subject : SubjectId}
      (closing : state.subjectStatuses subject = some .closing)
      (noLiveHandles : ∀ handleId handle,
        state.openHandles handleId = some handle → handle.subject ≠ subject) :
      Accepted (.finishSubjectClose subject) state (state.finishSubjectClose subject)
  | finishCloseAlreadyClosed {state : ModelState} {subject : SubjectId}
      (closed : state.subjectStatuses subject = some .closed) :
      Accepted (.finishSubjectClose subject) state state
  | registerHandle {state : ModelState} {handle : OpenHandle}
      (running : state.subjectStatuses handle.subject = some .running)
      (fresh : state.issuedHandleOwners handle.id = none) :
      Accepted (.registerHandle handle) state (state.registerOpenHandle handle)
  | closeHandle {state : ModelState} {caller : SubjectId} {handleId : HandleId}
      (owned : state.MayCloseHandle caller handleId) :
      Accepted (.closeHandle caller handleId) state (state.closeHandle handleId)
  | effect {state : ModelState} {caller : SubjectId} {capabilityId : CapId}
      {request : CapabilityRequest}
      (authorized : state.Authorizes caller capabilityId request) :
      Accepted (.effectAttempt caller capabilityId request) state state

/-- Every accepted label forward-simulates to existing abstract steps. -/
theorem Accepted.toSteps {command : Command} {before after : ModelState}
    (accepted : Accepted command before after) :
    Authority.CapabilityState.Steps before after := by
  cases accepted with
  | registerSubject allowed => exact .tail (.refl _) (.registerSubject allowed)
  | issueRootWithId allowed => exact .tail (.refl _) (.issueRoot allowed)
  | allocateRoot allowed => exact .tail (.refl _) (.issueAllocatedRoot allowed)
  | derive allowed => exact .tail (.refl _) (.derive allowed)
  | revoke issued unrevoked canIncrement =>
      exact .tail (.refl _) (.revoke issued unrevoked canIncrement)
  | revokeAlready issued revoked =>
      exact .tail (.refl _) (.successfulNoop (.revokeAlready issued revoked))
  | beginClose running canIncrement =>
      exact .tail (.refl _) (.beginClose running canIncrement)
  | beginCloseAlreadyClosing closing =>
      exact .tail (.refl _)
        (.successfulNoop (.beginCloseAlreadyClosing closing))
  | beginCloseAlreadyClosed closed =>
      exact .tail (.refl _) (.successfulNoop (.beginCloseAlreadyClosed closed))
  | finishClose closing noLiveHandles =>
      exact .tail (.refl _) (.finishClose closing noLiveHandles)
  | finishCloseAlreadyClosed closed =>
      exact .tail (.refl _) (.successfulNoop (.finishCloseAlreadyClosed closed))
  | registerHandle running fresh =>
      exact .tail (.refl _) (.registerHandle running fresh)
  | closeHandle owned => exact .tail (.refl _) (.closeHandle owned)
  | effect => exact .refl _

/--
Proof-carrying evidence for each named no-state-effect cause. This validates the
reported cause in the supplied state; it does not attest that Rust evaluated
overlapping causes in any particular order or emitted the report.
-/
inductive Rejected : Command → RejectionReason → ModelState → Prop
  | duplicateSubject {state : ModelState} {subject : Subject}
      (existing : state.subjects subject.id ≠ none) :
      Rejected (.registerSubject subject) .duplicateSubject state
  | unknownParentSubject {state : ModelState} {subject : Subject}
      {parent : SubjectId} (parentLink : subject.parent = some parent)
      (unknown : state.subjects parent = none) :
      Rejected (.registerSubject subject) .unknownParentSubject state
  | parentSubjectNotRunning {state : ModelState} {subject : Subject}
      {parent : SubjectId} (parentLink : subject.parent = some parent)
      (known : state.subjects parent ≠ none)
      (notRunning : state.subjectStatuses parent ≠ some .running) :
      Rejected (.registerSubject subject) .subjectNotRunning state
  | invalidCapabilityId {state : ModelState} {capabilityId : CapId}
      {grant : CapabilityGrant} (invalid : capabilityId.value = "") :
      Rejected (.issueRootWithId capabilityId grant) .invalidCapabilityId state
  | capabilityAlreadyIssued {state : ModelState} {capabilityId : CapId}
      {grant : CapabilityGrant} (issued : state.WasIssued capabilityId) :
      Rejected (.issueRootWithId capabilityId grant) .capabilityAlreadyIssued state
  | rootUnknownSubject {state : ModelState} {capabilityId : CapId}
      {grant : CapabilityGrant}
      (unknown : state.subjectStatuses grant.subject = none) :
      Rejected (.issueRootWithId capabilityId grant) .unknownSubject state
  | rootSubjectNotRunning {state : ModelState} {capabilityId : CapId}
      {grant : CapabilityGrant}
      (notRunning : state.subjectStatuses grant.subject = some .closing ∨
        state.subjectStatuses grant.subject = some .closed) :
      Rejected (.issueRootWithId capabilityId grant) .subjectNotRunning state
  | rootExceedsEnvelope {state : ModelState} {capabilityId : CapId}
      {grant : CapabilityGrant} {subject : Subject}
      (lookup : state.subjects grant.subject = some subject)
      (outside : subject.envelope.contains grant.validity grant.authority = false) :
      Rejected (.issueRootWithId capabilityId grant) .grantExceedsEnvelope state
  | allocateRootUnknownSubject {state : ModelState} {grant : CapabilityGrant}
      (unknown : state.subjectStatuses grant.subject = none) :
      Rejected (.allocateRoot grant) .unknownSubject state
  | allocateRootSubjectNotRunning {state : ModelState} {grant : CapabilityGrant}
      (notRunning : state.subjectStatuses grant.subject = some .closing ∨
        state.subjectStatuses grant.subject = some .closed) :
      Rejected (.allocateRoot grant) .subjectNotRunning state
  | allocateRootExceedsEnvelope {state : ModelState} {grant : CapabilityGrant}
      {subject : Subject} (running : state.subjectStatuses grant.subject = some .running)
      (lookup : state.subjects grant.subject = some subject)
      (outside : subject.envelope.contains grant.validity grant.authority = false) :
      Rejected (.allocateRoot grant) .grantExceedsEnvelope state
  | allocateRootAlreadyExhausted {state : ModelState} {grant : CapabilityGrant}
      (ready : RootGrantReady state grant)
      (exhausted : state.capabilityIdsExhausted = true) :
      Rejected (.allocateRoot grant) .capabilityIdExhausted state
  | deriveUnknownCaller {state : ModelState} {caller : SubjectId}
      {parentId : CapId} {grant : CapabilityGrant} {now : MonotonicTime}
      (unknown : state.subjectStatuses caller = none) :
      Rejected (.derive caller parentId grant now) .unknownSubject state
  | deriveCallerNotRunning {state : ModelState} {caller : SubjectId}
      {parentId : CapId} {grant : CapabilityGrant} {now : MonotonicTime}
      (notRunning : state.subjectStatuses caller = some .closing ∨
        state.subjectStatuses caller = some .closed) :
      Rejected (.derive caller parentId grant now) .subjectNotRunning state
  | deriveUnknownParent {state : ModelState} {caller : SubjectId}
      {parentId : CapId} {grant : CapabilityGrant} {now : MonotonicTime}
      (unknown : state.capabilities parentId = none) :
      Rejected (.derive caller parentId grant now) .unknownCapability state
  | deriveParentNotHeld {state : ModelState} {caller : SubjectId}
      {parentId : CapId} {grant : CapabilityGrant} {now : MonotonicTime}
      {parent : Capability} (lookup : state.capabilities parentId = some parent)
      (notHeld : parent.metadata.subject ≠ caller ∨ ¬ state.HeldBy caller parentId) :
      Rejected (.derive caller parentId grant now) .parentNotHeld state
  | deriveParentInactive {state : ModelState} {caller : SubjectId}
      {parentId : CapId} {grant : CapabilityGrant} {now : MonotonicTime}
      (inactive : ¬ state.EffectivelyActive parentId now) :
      Rejected (.derive caller parentId grant now) .parentChainInactive state
  | deriveParentNotDelegable {state : ModelState} {caller : SubjectId}
      {parentId : CapId} {grant : CapabilityGrant} {now : MonotonicTime}
      {parent : Capability} (lookup : state.capabilities parentId = some parent)
      (notDelegable : parent.metadata.delegable = false) :
      Rejected (.derive caller parentId grant now) .parentNotDelegable state
  | deriveExceedsParent {state : ModelState} {caller : SubjectId}
      {parentId : CapId} {grant : CapabilityGrant} {now : MonotonicTime}
      {parent : Capability} (lookup : state.capabilities parentId = some parent)
      (outside : timeWindowBelow grant.validity parent.validity = false ∨
        authorityBodyBelow grant.authority parent.authority = false) :
      Rejected (.derive caller parentId grant now) .grantExceedsParent state
  | deriveUnknownTarget {state : ModelState} {caller : SubjectId}
      {parentId : CapId} {grant : CapabilityGrant} {now : MonotonicTime}
      (unknown : state.subjectStatuses grant.subject = none) :
      Rejected (.derive caller parentId grant now) .unknownSubject state
  | deriveTargetNotRunning {state : ModelState} {caller : SubjectId}
      {parentId : CapId} {grant : CapabilityGrant} {now : MonotonicTime}
      (notRunning : state.subjectStatuses grant.subject = some .closing ∨
        state.subjectStatuses grant.subject = some .closed) :
      Rejected (.derive caller parentId grant now) .subjectNotRunning state
  | deriveExceedsEnvelope {state : ModelState} {caller : SubjectId}
      {parentId : CapId} {grant : CapabilityGrant} {now : MonotonicTime}
      {subject : Subject} (lookup : state.subjects grant.subject = some subject)
      (outside : subject.envelope.contains grant.validity grant.authority = false) :
      Rejected (.derive caller parentId grant now) .grantExceedsEnvelope state
  | deriveAlreadyExhausted {state : ModelState} {caller : SubjectId}
      {parentId : CapId} {grant : CapabilityGrant} {now : MonotonicTime}
      (ready : DeriveReady state caller parentId grant now)
      (exhausted : state.capabilityIdsExhausted = true) :
      Rejected (.derive caller parentId grant now) .capabilityIdExhausted state
  | unknownRevoke {state : ModelState} {capabilityId : CapId}
      (unknown : state.capabilities capabilityId = none) :
      Rejected (.revoke capabilityId) .unknownCapability state
  | revokeEpochExhausted {state : ModelState} {capabilityId : CapId}
      (exhausted : state.authorizationEpoch = u64Maximum) :
      Rejected (.revoke capabilityId) .authorizationEpochExhausted state
  | beginCloseUnknown {state : ModelState} {subject : SubjectId}
      (unknown : state.subjectStatuses subject = none) :
      Rejected (.beginSubjectClose subject) .unknownSubject state
  | beginCloseEpochExhausted {state : ModelState} {subject : SubjectId}
      (exhausted : state.authorizationEpoch = u64Maximum) :
      Rejected (.beginSubjectClose subject) .authorizationEpochExhausted state
  | finishCloseUnknown {state : ModelState} {subject : SubjectId}
      (unknown : state.subjectStatuses subject = none) :
      Rejected (.finishSubjectClose subject) .unknownSubject state
  | finishCloseNotClosing {state : ModelState} {subject : SubjectId}
      (running : state.subjectStatuses subject = some .running) :
      Rejected (.finishSubjectClose subject) .subjectNotClosing state
  | finishCloseHasHandle {state : ModelState} {subject : SubjectId}
      {handleId : HandleId} {handle : OpenHandle}
      (lookup : state.openHandles handleId = some handle)
      (owned : handle.subject = subject) :
      Rejected (.finishSubjectClose subject) (.subjectHasOpenHandles handleId) state
  | registerHandleUnknownSubject {state : ModelState} {handle : OpenHandle}
      (unknown : state.subjectStatuses handle.subject = none) :
      Rejected (.registerHandle handle) .unknownSubject state
  | registerHandleSubjectNotRunning {state : ModelState} {handle : OpenHandle}
      (notRunning : state.subjectStatuses handle.subject = some .closing ∨
        state.subjectStatuses handle.subject = some .closed) :
      Rejected (.registerHandle handle) .subjectNotRunning state
  | handleAlreadyIssued {state : ModelState} {handle : OpenHandle} {owner : SubjectId}
      (issued : state.issuedHandleOwners handle.id = some owner) :
      Rejected (.registerHandle handle) .handleAlreadyIssued state
  | closeUnknownHandle {state : ModelState} {caller : SubjectId} {handleId : HandleId}
      (unknown : state.issuedHandleOwners handleId = none) :
      Rejected (.closeHandle caller handleId) .unknownHandle state
  | closeHandleNotOwned {state : ModelState} {caller owner : SubjectId}
      {handleId : HandleId} (lookup : state.issuedHandleOwners handleId = some owner)
      (different : owner ≠ caller) :
      Rejected (.closeHandle caller handleId) .handleNotOwned state
  | effectNotAuthorized {state : ModelState} {caller : SubjectId}
      {capabilityId : CapId} {request : CapabilityRequest}
      (denied : ¬ state.Authorizes caller capabilityId request) :
      Rejected (.effectAttempt caller capabilityId request) .notAuthorized state

/-- Outcome-specific evidence supplied for checks that require global map facts. -/
def Event.ValidOutcome (event : Event) (before after : ModelState) : Prop :=
  match event.outcome with
    | .accepted => Accepted event.command before after
    | .rejectedNoEffect reason =>
        after = before ∧ Rejected event.command reason before
    | .effectFailedBeforeCommit =>
        after = before ∧
          ∃ caller capabilityId request,
            event.command = .effectAttempt caller capabilityId request ∧
              before.Authorizes caller capabilityId request
    | .allocatorExhausted =>
        after = before.exhaustAllocator ∧
          FirstAllocationExhaustion event.command before
    | .revocationCommittedButPropagationError =>
        PropagationFailure event.command before after
    | .auditFailure phase =>
        after = before ∧
          ∃ caller capabilityId request,
            event.command = .effectAttempt caller capabilityId request ∧
              match phase with
              | .start => True
              | .denialTerminal => ¬ before.Authorizes caller capabilityId request
              | .precommitTerminal => before.Authorizes caller capabilityId request
              | .committedTerminal => before.Authorizes caller capabilityId request

/-- A checked event's exact logical meaning at the capability-state projection. -/
def Event.Valid (event : Event) (before after : ModelState) : Prop :=
  event.schemaVersion = observationSchemaVersion ∧
    event.ValidOutcome before after

/-- Proof-carrying candidate for facts not enumerable from total functional maps. -/
structure EventCandidate (before : ModelState) (event : Event) where
  after : ModelState
  outcomeValid : event.ValidOutcome before after

/-- Proof-bearing result of the executable event checker. -/
structure CheckedEvent (before : ModelState) (event : Event) where
  after : ModelState
  valid : event.Valid before after

/-- Proof-bearing result of the accepted-command sub-checker. -/
structure AcceptedResult (command : Command) (before : ModelState) where
  after : ModelState
  accepted : Accepted command before after

/-- Accept proof-carrying evidence for every command in the closed inventory. -/
def checkAccepted (state : ModelState) (command : Command)
    (candidate : AcceptedResult command state) : Option (AcceptedResult command state) := by
  cases command <;> exact some candidate

/-- Every result returned by the accepted-command checker has exact step evidence. -/
theorem checkAccepted_sound {state : ModelState} {command : Command}
    {candidate checked : AcceptedResult command state}
    (_result : checkAccepted state command candidate = some checked) :
    Authority.CapabilityState.Steps state checked.after :=
  checked.accepted.toSteps

/-- Check a closed command/outcome candidate after executable schema validation. -/
def checkEvent (before : ModelState) (event : Event)
    (candidate : EventCandidate before event) : Option (CheckedEvent before event) :=
  if version : event.schemaVersion = observationSchemaVersion then
    match event.outcome with
    | .accepted => some ⟨candidate.after, version, candidate.outcomeValid⟩
    | .rejectedNoEffect _ => some ⟨candidate.after, version, candidate.outcomeValid⟩
    | .effectFailedBeforeCommit => some ⟨candidate.after, version, candidate.outcomeValid⟩
    | .allocatorExhausted => some ⟨candidate.after, version, candidate.outcomeValid⟩
    | .revocationCommittedButPropagationError =>
        some ⟨candidate.after, version, candidate.outcomeValid⟩
    | .auditFailure _ => some ⟨candidate.after, version, candidate.outcomeValid⟩
  else
    none

/-- The checker proves only the validity predicate stored in checked data. -/
theorem checkEvent_sound {before : ModelState} {event : Event}
    {candidate : EventCandidate before event}
    {checked : CheckedEvent before event}
    (_accepted : checkEvent before event candidate = some checked) :
    event.Valid before checked.after :=
  checked.valid

/-- Every checked event forward-simulates to existing finite abstract execution. -/
theorem CheckedEvent.forwardSimulation {before : ModelState} {event : Event}
    (checked : CheckedEvent before event) :
    Authority.CapabilityState.Steps before checked.after := by
  rcases checked with ⟨after, checkedValid⟩
  change Authority.CapabilityState.Steps before after
  rcases checkedValid with ⟨_, validOutcome⟩
  cases outcomeEq : event.outcome with
  | accepted =>
      simp only [Event.ValidOutcome, outcomeEq] at validOutcome
      exact validOutcome.toSteps
  | rejectedNoEffect =>
      simp only [Event.ValidOutcome, outcomeEq] at validOutcome
      change after = before ∧ _ at validOutcome
      rw [validOutcome.1]
      exact .refl before
  | effectFailedBeforeCommit =>
      simp only [Event.ValidOutcome, outcomeEq] at validOutcome
      change after = before ∧ _ at validOutcome
      rw [validOutcome.1]
      exact .refl before
  | allocatorExhausted =>
      simp only [Event.ValidOutcome, outcomeEq] at validOutcome
      rcases validOutcome with ⟨afterEq, failure⟩
      subst after
      exact .tail (.refl before) (.allocatorExhausted failure.scanEvidence)
  | revocationCommittedButPropagationError =>
      simp only [Event.ValidOutcome, outcomeEq] at validOutcome
      exact validOutcome.toSteps
  | auditFailure =>
      simp only [Event.ValidOutcome, outcomeEq] at validOutcome
      change after = before ∧ _ at validOutcome
      rw [validOutcome.1]
      exact .refl before

/-- A successful checker result is an existing capability-state execution. -/
theorem checkEvent_forwardSimulation {before : ModelState} {event : Event}
    {candidate : EventCandidate before event}
    {checked : CheckedEvent before event}
    (_accepted : checkEvent before event candidate = some checked) :
    Authority.CapabilityState.Steps before checked.after :=
  checked.forwardSimulation

/-- Concatenate two finite executions of the existing abstract machine. -/
theorem steps_trans {first middle last : ModelState}
    (firstSteps : Authority.CapabilityState.Steps first middle)
    (remainingSteps : Authority.CapabilityState.Steps middle last) :
    Authority.CapabilityState.Steps first last := by
  induction remainingSteps with
  | refl => exact firstSteps
  | tail _ transition inductionHypothesis =>
      exact .tail inductionHypothesis transition

/-- A checked finite trace contains its exact final state and simulation proof. -/
structure CheckedTrace (before : ModelState) where
  after : ModelState
  simulation : Authority.CapabilityState.Steps before after

/-- Dependent trace input keeps every candidate aligned with the prior result state. -/
inductive TraceInput : ModelState → Type
  | nil (state : ModelState) : TraceInput state
  | cons {state : ModelState} (event : Event)
      (candidate : EventCandidate state event)
      (remaining : TraceInput candidate.after) : TraceInput state

/-- Check every version in a closed, proof-carrying event trace. -/
def checkTrace : {before : ModelState} → TraceInput before →
    Option (CheckedTrace before)
  | before, .nil _ => some ⟨before, .refl before⟩
  | _, .cons event candidate remaining =>
      if version : event.schemaVersion = observationSchemaVersion then
        let checked : CheckedEvent _ event :=
          ⟨candidate.after, version, candidate.outcomeValid⟩
        match checkTrace remaining with
        | none => none
        | some rest =>
            some ⟨rest.after,
              steps_trans checked.forwardSimulation rest.simulation⟩
      else
        none

/-- Successful trace checking forward-simulates to existing abstract `Steps`. -/
theorem checkTrace_sound {before : ModelState} {input : TraceInput before}
    {checked : CheckedTrace before}
    (_accepted : checkTrace input = some checked) :
    Authority.CapabilityState.Steps before checked.after :=
  checked.simulation

/-- A validated initial snapshot paired with a checked event trace. -/
structure CheckedObservation (snapshot : StateSnapshot) where
  initialDenotation : snapshot.Denotes snapshot.model
  trace : CheckedTrace snapshot.model

/-- Validate the initial observation before checking its event sequence. -/
def checkObservedTrace (snapshot : StateSnapshot)
    (input : TraceInput snapshot.model) : Option (CheckedObservation snapshot) :=
  if valid : snapshot.validate = true then
    match checkTrace input with
    | none => none
    | some trace => some ⟨StateSnapshot.validate_sound valid, trace⟩
  else
    none

/-- Observation checking proves denotation and simulation only for supplied data. -/
theorem checkObservedTrace_sound {snapshot : StateSnapshot}
    {input : TraceInput snapshot.model} {checked : CheckedObservation snapshot}
    (_accepted : checkObservedTrace snapshot input = some checked) :
    snapshot.Denotes snapshot.model ∧
      Authority.CapabilityState.Steps snapshot.model checked.trace.after :=
  ⟨checked.initialDenotation, checked.trace.simulation⟩

/-- Checked traces preserve the complete structural invariant. -/
theorem CheckedTrace.preserves_structuralWellFormed {before : ModelState}
    (checked : CheckedTrace before)
    (wellFormed : before.StructuralWellFormed) :
    checked.after.StructuralWellFormed :=
  checked.simulation.preserve_structuralWellFormed wellFormed

/-- Checked traces preserve both modeled Rust-width counters. -/
theorem CheckedTrace.preserves_countersRepresentable {before : ModelState}
    (checked : CheckedTrace before)
    (representable : before.CountersRepresentable) :
    checked.after.CountersRepresentable :=
  checked.simulation.preserve_countersRepresentable representable

/-- Checked traces never decrease the authorization epoch. -/
theorem CheckedTrace.authorizationEpoch_monotone {before : ModelState}
    (checked : CheckedTrace before) :
    before.authorizationEpoch ≤ checked.after.authorizationEpoch :=
  checked.simulation.epoch_monotone

/-- Checked traces preserve the non-amplifying capability graph. -/
theorem CheckedTrace.preserves_graphWellFormed {before : ModelState}
    (checked : CheckedTrace before) (wellFormed : before.GraphWellFormed) :
    checked.after.GraphWellFormed :=
  checked.simulation.graphWellFormed wellFormed

/-- The versioned observation used for the first failed root-ID scan. -/
def firstRootExhaustionEvent (grant : CapabilityGrant) : Event where
  schemaVersion := observationSchemaVersion
  command := .allocateRoot grant
  outcome := .allocatorExhausted

/-- Package exact validation and scan evidence for the first exhaustion error. -/
def firstRootExhaustionCandidate {state : ModelState} {grant : CapabilityGrant}
    (ready : RootGrantReady state grant)
    (scan : Authority.CapabilityState.MayExhaustAllocator state) :
    EventCandidate state (firstRootExhaustionEvent grant) :=
  ⟨state.exhaustAllocator, by
    change state.exhaustAllocator = state.exhaustAllocator ∧
      FirstAllocationExhaustion (.allocateRoot grant) state
    exact ⟨rfl, .root ready scan⟩⟩

/-- A first state-changing exhaustion observation is accepted, not dropped. -/
theorem first_allocator_exhaustion_checked {state : ModelState}
    {grant : CapabilityGrant} (ready : RootGrantReady state grant)
    (scan : Authority.CapabilityState.MayExhaustAllocator state) :
    ∃ checked,
      checkEvent state (firstRootExhaustionEvent grant)
          (firstRootExhaustionCandidate ready scan) = some checked ∧
        checked.after = state.exhaustAllocator := by
  have checkedValid : (firstRootExhaustionEvent grant).Valid
      state state.exhaustAllocator := by
    refine ⟨rfl, ?_⟩
    change state.exhaustAllocator = state.exhaustAllocator ∧
      FirstAllocationExhaustion (.allocateRoot grant) state
    exact ⟨rfl, .root ready scan⟩
  refine ⟨⟨state.exhaustAllocator, checkedValid⟩, ?_, rfl⟩
  simp [checkEvent, firstRootExhaustionEvent, observationSchemaVersion,
    firstRootExhaustionCandidate]

/-- The accepted first exhaustion observation takes the explicit abstract step. -/
theorem first_allocator_exhaustion_forwardSimulation {state : ModelState}
    {grant : CapabilityGrant} (ready : RootGrantReady state grant)
    (scan : Authority.CapabilityState.MayExhaustAllocator state) :
    Authority.CapabilityState.Steps state state.exhaustAllocator := by
  have failure : FirstAllocationExhaustion (.allocateRoot grant) state :=
    .root ready scan
  exact .tail (.refl state) (.allocatorExhausted failure.scanEvidence)

private def witnessSubject : SubjectId := ⟨"checked-subject"⟩
private def witnessHandleId : HandleId := ⟨"checked-handle"⟩
private def witnessObject : ObjectId := ⟨"checked-object"⟩

private def witnessEnvelope : StaticAuthorityEnvelope where
  validity := {
    notBefore := { ticks := 0 }
    expiresAt := { ticks := 1 }
    isValid := by decide }
  authority := .file {
    repository := { value := "checked-repository" }
    effects := FileEffects.empty
    path := .exact CanonicalPath.root }

private def witnessSubjectRecord : Subject where
  id := witnessSubject
  parent := none
  envelope := witnessEnvelope

private def witnessRegistrationAllowed :
    (Authority.CapabilityState.empty ⟨"checked-issuer"⟩).MayRegisterSubject
      witnessSubjectRecord := by
  constructor
  · rfl
  · rfl
  · intro capabilityId
    rfl
  · intro parentId parentLookup
    simp [witnessSubjectRecord] at parentLookup

private def witnessHandle : OpenHandle where
  id := witnessHandleId
  subject := witnessSubject
  object := witnessObject

private def witnessState : ModelState :=
  (Authority.CapabilityState.empty ⟨"checked-issuer"⟩).registerSubject
    witnessSubjectRecord

/-- The concrete trace begins in a reachable, structurally well-formed state. -/
theorem witnessState_structuralWellFormed : witnessState.StructuralWellFormed := by
  exact witnessRegistrationAllowed.preserves_structuralWellFormed
    (Authority.CapabilityState.empty_structuralWellFormed ⟨"checked-issuer"⟩)

private def acceptedWitnessEvent : Event where
  schemaVersion := observationSchemaVersion
  command := .registerHandle witnessHandle
  outcome := .accepted

private def rejectedWitnessEvent : Event where
  schemaVersion := observationSchemaVersion
  command := .registerHandle witnessHandle
  outcome := .rejectedNoEffect .handleAlreadyIssued

private def witnessAfter : ModelState :=
  witnessState.registerOpenHandle witnessHandle

private def acceptedWitnessCandidate :
    EventCandidate witnessState acceptedWitnessEvent :=
  ⟨witnessAfter, by
    exact .registerHandle
      (by simp [witnessState, witnessHandle, witnessSubject,
        witnessSubjectRecord, Authority.CapabilityState.registerSubject,
        Authority.CapabilityState.empty, replace])
      (by rfl)⟩

private def rejectedWitnessCandidate :
    EventCandidate witnessAfter rejectedWitnessEvent :=
  ⟨witnessAfter, by
    refine ⟨rfl, ?_⟩
    exact .handleAlreadyIssued (owner := witnessSubject) (by
      simp [witnessAfter, witnessHandle,
        Authority.CapabilityState.registerOpenHandle])⟩

private def acceptedRejectedTrace : TraceInput witnessState :=
  .cons acceptedWitnessEvent acceptedWitnessCandidate
    (.cons rejectedWitnessEvent rejectedWitnessCandidate (.nil witnessAfter))

/-- A concrete accepted event is recognized and registers its exact handle. -/
theorem accepted_event_witness :
    ∃ checked,
      checkEvent witnessState acceptedWitnessEvent acceptedWitnessCandidate =
        some checked ∧
        checked.after = witnessAfter := by
  simp [checkEvent, acceptedWitnessCandidate, acceptedWitnessEvent, witnessState,
    witnessHandle, witnessHandleId, witnessSubject, Authority.CapabilityState.empty,
    replace, observationSchemaVersion]

/-- A concrete accepted-then-rejected trace preserves the accepted final state. -/
theorem accepted_rejected_trace_witness :
    ∃ checked,
      checkTrace acceptedRejectedTrace = some checked ∧
      checked.after = witnessAfter := by
  simp [checkTrace, acceptedRejectedTrace, checkEvent, acceptedWitnessCandidate,
    rejectedWitnessCandidate, acceptedWitnessEvent, rejectedWitnessEvent,
    witnessState, witnessAfter, witnessHandle, witnessHandleId, witnessSubject,
    Authority.CapabilityState.empty, replace, observationSchemaVersion,
    Authority.CapabilityState.registerOpenHandle]

private def exhaustionGrant : CapabilityGrant where
  subject := witnessSubject
  validity := witnessEnvelope.validity
  authority := witnessEnvelope.authority
  delegable := false

private def finalSequentialId : CapId :=
  witnessState.sequentialCapabilityId u64Maximum

private def exhaustionState : ModelState :=
  { witnessState.issue finalSequentialId none exhaustionGrant with
    nextCapabilitySequence := u64Maximum
    capabilityIdsExhausted := false }

private def exhaustionReady : RootGrantReady exhaustionState exhaustionGrant := by
  refine {
    targetSubject := witnessSubjectRecord
    targetLookup := ?_
    targetRunning := ?_
    grantInsideEnvelope := ?_ }
  · simp [exhaustionState, witnessState, witnessSubjectRecord,
      exhaustionGrant, Authority.CapabilityState.issue,
      Authority.CapabilityState.registerSubject, replace]
  · simp [exhaustionState, witnessState, witnessSubjectRecord,
      exhaustionGrant, Authority.CapabilityState.issue,
      Authority.CapabilityState.registerSubject, replace]
  · exact StaticAuthorityEnvelope.contains_self witnessEnvelope

private def exhaustionScan :
    Authority.CapabilityState.MayExhaustAllocator exhaustionState := by
  refine {
    allocatorAvailable := rfl
    cursorRepresentable := by simp [exhaustionState, FitsU64]
    everyRemainingIssued := ?_ }
  intro sequence atOrAfter fits
  have atMaximum : sequence = u64Maximum :=
    Nat.le_antisymm fits atOrAfter
  subst sequence
  refine ⟨exhaustionState.capabilityFromGrant finalSequentialId none exhaustionGrant, ?_⟩
  simp [exhaustionState, finalSequentialId, Authority.CapabilityState.issue,
    Authority.CapabilityState.capabilityFromGrant,
    Authority.CapabilityState.sequentialCapabilityId]

/-- The first-exhaustion checker path is concretely inhabited. -/
theorem concrete_first_allocator_exhaustion_witness :
    ∃ checked,
      checkEvent exhaustionState (firstRootExhaustionEvent exhaustionGrant)
          (firstRootExhaustionCandidate exhaustionReady exhaustionScan) = some checked ∧
        checked.after = exhaustionState.exhaustAllocator :=
  first_allocator_exhaustion_checked exhaustionReady exhaustionScan

end Authority.Refinement.CapabilityState
