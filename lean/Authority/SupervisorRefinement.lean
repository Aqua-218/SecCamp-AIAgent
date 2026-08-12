import Authority.Integration

/-!
# Conditional Supervisor Refinement

This module gives a forward, single-subject abstraction of the supervisor's
multi-stage setup, handle-open, and shutdown ownership protocol.  It relates
local resource ownership to `IntegratedHandleState` managed handles, but is a
conditional model: an adapter must establish the modeled preconditions at its
linearization points.  These theorems do not prove the Rust source code.
-/

namespace Authority
namespace SupervisorRefinement

/-- Locally visible lifecycle for the selected supervised subject. -/
inductive Lifecycle where
  | creating
  | running
  | closing
  | cleanupBlocked
  | closed
  deriving Repr, BEq, DecidableEq

/-- Local knowledge about one cleanup resource. -/
inductive ResourceOwnership where
  | none
  | owned
  | unresolved
  deriving Repr, BEq, DecidableEq

/-- Result of a setup-side resource acquisition that returned an error. -/
inductive ResourceAcquisition where
  | noEffect
  | cleanupRequired
  | effectUnknown
  deriving Repr, BEq, DecidableEq

/-- Result of a cleanup mutation that returned an error. -/
inductive ResourceMutation where
  | noEffect
  | cleanupRequired
  | effectUnknown
  deriving Repr, BEq, DecidableEq

/-- External resource selected by a setup or cleanup operation. -/
inductive ResourceKind where
  | cgroup
  | mount
  | control
  | workload
  deriving Repr, BEq, DecidableEq

/-- Successful supervisor linearization labels. -/
inductive Success where
  | reserveSubject
  | acquireCgroup
  | acquireMount
  | acquireControl
  | registerSubject
  | startWorkload
  | publishSubject
  | openRuntimeHandle
  | registerManagedHandle
  | beginShutdown
  | stopWorkload
  | closeControl
  | closeRuntimeHandle
  | unmount
  | removeCgroup
  | finishShutdown
  deriving Repr, BEq, DecidableEq

/-- Failure labels retain the stage at which a state-changing call returned `Err`. -/
inductive Failure where
  | setupBeforeRegistration (outcome : ResourceAcquisition)
  | setupAfterRegistration
  | handleRegistration
  | handleRegistrationCleanup
  | handleRegistrationUnknown
  | beginShutdown
  | cleanupWorkload (outcome : ResourceMutation)
  | cleanupControl (outcome : ResourceMutation)
  | cleanupHandle (outcome : ResourceMutation)
  | cleanupUnmount (outcome : ResourceMutation)
  | cleanupCgroup (outcome : ResourceMutation)
  | finishShutdown
  deriving Repr, BEq, DecidableEq

/-- A mutation target is known even when the call's effect is not. -/
def ResourceMutation.Addressable : ResourceMutation → Prop
  | .noEffect => True
  | .cleanupRequired => True
  | .effectUnknown => True

/-- A cleanup mutation error is retry-addressable because its token remains owned. -/
def Failure.Addressable : Failure → Prop
  | .cleanupWorkload outcome
  | .cleanupControl outcome
  | .cleanupHandle outcome
  | .cleanupUnmount outcome
  | .cleanupCgroup outcome => outcome.Addressable
  | _ => False

/-- Every modeled transition records whether the caller observes success or error. -/
inductive ResultLabel where
  | ok (operation : Success)
  | error (failure : Failure)
  deriving Repr, BEq, DecidableEq

/-- One selected subject's supervisor-local and integrated ownership state. -/
structure State where
  integrated : IntegratedHandleState
  subject : Subject
  known : Bool
  lifecycle : Lifecycle
  authorityRegistered : Bool
  ownsCgroup : ResourceOwnership
  ownsMount : ResourceOwnership
  ownsControl : ResourceOwnership
  ownsWorkload : ResourceOwnership
  runtimeHandles : List HandleId
  authorityHandles : List HandleId
  pendingOpen : Option OpenHandle
  issuedSubjects : SubjectId → Bool
  issuedHandles : HandleId → Bool

namespace State

/-- The selected subject owns one local runtime descriptor. -/
def RuntimeOwns (state : State) (handleId : HandleId) : Prop :=
  handleId ∈ state.runtimeHandles

/-- The selected subject tracks one Authority-live managed handle. -/
def AuthorityOwns (state : State) (handleId : HandleId) : Prop :=
  handleId ∈ state.authorityHandles

/-- Exported coupling between local ownership and the integrated managed scope. -/
structure Invariant (state : State) : Prop where
  integratedWellFormed : state.integrated.WellFormed
  knownSubjectIssued : state.known = true →
    state.issuedSubjects state.subject.id = true
  registeredSubjectExact : state.authorityRegistered = true →
    state.integrated.authority.subjects state.subject.id = some state.subject
  authoritySubjectIssued :
    state.integrated.authority.subjects state.subject.id = some state.subject →
      state.issuedSubjects state.subject.id = true
  selectedManagedHandleIssued : ∀ handleId,
    state.integrated.managedHandles handleId = true →
    state.integrated.authority.issuedHandleOwners handleId = some state.subject.id →
      state.issuedHandles handleId = true
  runtimeHandlesNodup : state.runtimeHandles.Nodup
  authorityHandlesNodup : state.authorityHandles.Nodup
  runtimeHandleIssued : ∀ handleId,
    state.RuntimeOwns handleId → state.issuedHandles handleId = true
  authorityHandleSound : ∀ handleId,
    state.AuthorityOwns handleId →
      ∃ handle,
        state.integrated.authority.openHandles handleId = some handle ∧
        handle.subject = state.subject.id ∧
        state.integrated.managedHandles handleId = true
  authorityHandleRuntimeOwned : ∀ handleId,
    state.AuthorityOwns handleId → state.RuntimeOwns handleId
  pendingRuntimeOwned : ∀ handle,
    state.pendingOpen = some handle → state.RuntimeOwns handle.id
  pendingHandleIssued : ∀ handle,
    state.pendingOpen = some handle → state.issuedHandles handle.id = true

/-- Change only lifecycle and non-handle cleanup flags. -/
def updateCleanupFlags (state : State) (nextLifecycle : Lifecycle)
    (nextCgroup nextMount nextControl nextWorkload : ResourceOwnership) : State :=
  { state with
    lifecycle := nextLifecycle
    ownsCgroup := nextCgroup
    ownsMount := nextMount
    ownsControl := nextControl
    ownsWorkload := nextWorkload }

/-- Refinement facts ignore lifecycle and non-handle resource ownership flags. -/
theorem Invariant.updateCleanupFlags {state : State} (invariant : state.Invariant)
    (nextLifecycle : Lifecycle)
    (nextCgroup nextMount nextControl nextWorkload : ResourceOwnership) :
    (updateCleanupFlags state nextLifecycle nextCgroup nextMount nextControl
      nextWorkload).Invariant := by
  constructor
  · exact invariant.integratedWellFormed
  · exact invariant.knownSubjectIssued
  · exact invariant.registeredSubjectExact
  · exact invariant.authoritySubjectIssued
  · exact invariant.selectedManagedHandleIssued
  · exact invariant.runtimeHandlesNodup
  · exact invariant.authorityHandlesNodup
  · exact invariant.runtimeHandleIssued
  · exact invariant.authorityHandleSound
  · exact invariant.authorityHandleRuntimeOwned
  · exact invariant.pendingRuntimeOwned
  · exact invariant.pendingHandleIssued

/-- Concrete empty supervisor paired with concrete integrated initialization. -/
def initial (issuer : IssuerId) (subjectId : SubjectId) : State where
  integrated := IntegratedHandleState.initial issuer
  subject := IntegratedHandleState.startupSubject subjectId
  known := false
  lifecycle := .creating
  authorityRegistered := false
  ownsCgroup := .none
  ownsMount := .none
  ownsControl := .none
  ownsWorkload := .none
  runtimeHandles := []
  authorityHandles := []
  pendingOpen := none
  issuedSubjects := fun _ => false
  issuedHandles := fun _ => false

/-- Concrete empty supervisor initialization satisfies the refinement invariant. -/
theorem initial_invariant (issuer : IssuerId) (subjectId : SubjectId) :
    (initial issuer subjectId).Invariant := by
  constructor
  · exact IntegratedHandleState.initial_wellFormed issuer
  · simp [initial]
  · simp [initial]
  · simp [initial, IntegratedHandleState.initial,
      IntegratedHandleState.initializeClosed, CapabilityState.empty]
  · simp [initial, IntegratedHandleState.initial,
      IntegratedHandleState.initializeClosed]
  · simp [initial]
  · simp [initial]
  · simp [initial, RuntimeOwns]
  · simp [initial, AuthorityOwns]
  · simp [initial, AuthorityOwns]
  · simp [initial]
  · simp [initial]

/-- Reserve the subject identity before acquiring external resources. -/
def reserveSubject (state : State) : State :=
  { state with
    known := true
    lifecycle := .creating
    issuedSubjects := replace state.issuedSubjects state.subject.id true }

/-- Acquire the subject cgroup during setup. -/
def acquireCgroup (state : State) : State := { state with ownsCgroup := .owned }

/-- Acquire the capability-filesystem mount during setup. -/
def acquireMount (state : State) : State := { state with ownsMount := .owned }

/-- Acquire the authenticated control descriptor during setup. -/
def acquireControl (state : State) : State := { state with ownsControl := .owned }

/-- Mirror a successful Authority subject registration. -/
def registerSubject (state : State) : State :=
  { state with
    integrated := state.integrated.withAuthority
      (state.integrated.authority.registerSubject state.subject)
    authorityRegistered := true }

/-- Record a successfully started workload. -/
def startWorkload (state : State) : State := { state with ownsWorkload := .owned }

/-- Publish the selected subject as locally running. -/
def publishRunning (state : State) : State := { state with lifecycle := .running }

/-- Fail setup after Authority registration while retaining cleanup ownership. -/
def failRegisteredCreate (state : State) : State :=
  { state with lifecycle := .closing }

/-- Update one external cleanup resource without laundering any other token. -/
def setResource (state : State) (resource : ResourceKind)
    (ownership : ResourceOwnership) : State :=
  match resource with
  | .cgroup => { state with ownsCgroup := ownership }
  | .mount => { state with ownsMount := ownership }
  | .control => { state with ownsControl := ownership }
  | .workload => { state with ownsWorkload := ownership }

/-- Record an error-returning acquisition according to its Rust-side evidence. -/
def failAcquisition (state : State) (resource : ResourceKind)
    (outcome : ResourceAcquisition) : State :=
  match outcome with
  | .noEffect => state
  | .cleanupRequired =>
      { state.setResource resource .owned with lifecycle := .closing }
  | .effectUnknown =>
      { state.setResource resource .unresolved with lifecycle := .cleanupBlocked }

/-- Acquisition-error bookkeeping never releases permanent local tombstones. -/
theorem failAcquisition_preserves_issued (state : State) (resource : ResourceKind)
    (outcome : ResourceAcquisition) :
    (state.failAcquisition resource outcome).issuedSubjects = state.issuedSubjects ∧
      (state.failAcquisition resource outcome).issuedHandles = state.issuedHandles := by
  cases resource <;> cases outcome <;> exact ⟨rfl, rfl⟩

theorem failAcquisition_preserves_allocator (state : State)
    (resource : ResourceKind) (outcome : ResourceAcquisition) :
    (state.failAcquisition resource outcome).integrated.authority.nextCapabilitySequence =
        state.integrated.authority.nextCapabilitySequence ∧
      (state.failAcquisition resource outcome).integrated.authority.capabilityIdsExhausted =
        state.integrated.authority.capabilityIdsExhausted := by
  cases resource <;> cases outcome <;> exact ⟨rfl, rfl⟩

/-- Reserve and open one runtime descriptor before Authority registration. -/
def beginOpen (state : State) (handle : OpenHandle) : State :=
  { state with
    runtimeHandles := handle.id :: state.runtimeHandles
    pendingOpen := some handle
    issuedHandles := replace state.issuedHandles handle.id true }

/-- Publish one successfully registered managed handle locally and integrally. -/
def commitOpen (state : State) (handle : OpenHandle)
    (object : NamespaceObject) : State :=
  { state with
    integrated := state.integrated.openHandle handle object
    authorityHandles := handle.id :: state.authorityHandles
    pendingOpen := none }

/-- Registration failure with successful compensation releases the runtime descriptor. -/
def failOpenClean (state : State) (handle : OpenHandle) : State :=
  { state with
    integrated := state.integrated.failOpenAfterRegistration handle
    runtimeHandles := state.runtimeHandles.erase handle.id
    pendingOpen := none }

/-- Registration and compensation failure retains runtime cleanup ownership. -/
def failOpenRetained (state : State) (handle : OpenHandle) : State :=
  { state with
    integrated := state.integrated.failOpenAfterRegistration handle
    lifecycle := .closing
    pendingOpen := none }

/-- Unknown compensation retains the known descriptor for cleanup retry. -/
def failOpenUnknown (state : State) (handle : OpenHandle) : State :=
  { state with
    integrated := state.integrated.failOpenAfterRegistration handle
    lifecycle := .closing
    pendingOpen := none }

end State

/-- Multi-stage subject creation, including error returns that retain state. -/
inductive CreateStep : State → ResultLabel → State → Prop
  | reserve {state : State} :
      state.lifecycle = .creating →
      state.known = false →
      state.issuedSubjects state.subject.id = false →
      CreateStep state (.ok .reserveSubject) state.reserveSubject
  | acquireCgroup {state : State} :
      state.known = true → state.lifecycle = .creating →
      state.ownsCgroup = .none →
      CreateStep state (.ok .acquireCgroup) state.acquireCgroup
  | acquireMount {state : State} :
      state.known = true → state.lifecycle = .creating →
      state.ownsCgroup = .owned → state.ownsMount = .none →
      CreateStep state (.ok .acquireMount) state.acquireMount
  | acquireControl {state : State} :
      state.known = true → state.lifecycle = .creating →
      state.ownsMount = .owned → state.ownsControl = .none →
      CreateStep state (.ok .acquireControl) state.acquireControl
  | registerSubject {state : State} :
      state.known = true → state.lifecycle = .creating →
      state.authorityRegistered = false →
      (allowed : state.integrated.authority.MayRegisterSubject state.subject) →
      CreateStep state (.ok .registerSubject) state.registerSubject
  | startWorkload {state : State} :
      state.known = true → state.lifecycle = .creating →
      state.ownsCgroup = .owned → state.ownsMount = .owned →
      state.ownsControl = .owned → state.ownsWorkload = .none →
      state.authorityRegistered = true →
      CreateStep state (.ok .startWorkload) state.startWorkload
  | publish {state : State} :
      state.known = true → state.lifecycle = .creating →
      state.authorityRegistered = true →
      state.ownsCgroup = .owned → state.ownsMount = .owned →
      state.ownsControl = .owned → state.ownsWorkload = .owned →
      state.pendingOpen = none →
      state.integrated.authority.subjectStatuses state.subject.id = some .running →
      CreateStep state (.ok .publishSubject) state.publishRunning
  | acquisitionFailed {state : State} {resource : ResourceKind}
      {outcome : ResourceAcquisition} :
      state.lifecycle = .creating → state.authorityRegistered = false →
      CreateStep state (.error (.setupBeforeRegistration outcome))
        (state.failAcquisition resource outcome)
  | failAfterRegistration {state : State} :
      state.known = true → state.lifecycle = .creating →
      state.authorityRegistered = true →
      CreateStep state (.error .setupAfterRegistration)
        state.failRegisteredCreate

/-- Authority registration is a genuine integrated Authority-only transition. -/
theorem registerSubject_integratedStep {state : State}
    (allowed : state.integrated.authority.MayRegisterSubject state.subject) :
    IntegratedHandleState.Step state.integrated state.registerSubject.integrated := by
  apply IntegratedHandleState.Step.authorityOnly
    (CapabilityState.Step.registerSubject allowed)
  intro handleId _managed
  rfl

/-- Every accepted creation stage preserves the supervisor refinement invariant. -/
theorem CreateStep.preserves_invariant {before after : State}
    {result : ResultLabel} (transition : CreateStep before result after)
    (invariant : before.Invariant) : after.Invariant := by
  cases transition with
  | reserve creating unknown fresh =>
      constructor
      · exact invariant.integratedWellFormed
      · intro _known
        simp [State.reserveSubject]
      · simpa [State.reserveSubject] using invariant.registeredSubjectExact
      · intro subjectLookup
        simp [State.reserveSubject]
      · simpa [State.reserveSubject] using invariant.selectedManagedHandleIssued
      · simpa [State.reserveSubject] using invariant.runtimeHandlesNodup
      · simpa [State.reserveSubject] using invariant.authorityHandlesNodup
      · simpa [State.reserveSubject, State.RuntimeOwns] using invariant.runtimeHandleIssued
      · simpa [State.reserveSubject, State.AuthorityOwns] using invariant.authorityHandleSound
      · simpa [State.reserveSubject, State.AuthorityOwns,
          State.RuntimeOwns] using invariant.authorityHandleRuntimeOwned
      · simpa [State.reserveSubject, State.RuntimeOwns] using invariant.pendingRuntimeOwned
      · simpa [State.reserveSubject] using invariant.pendingHandleIssued
  | acquireCgroup known creating _free =>
      constructor
      · exact invariant.integratedWellFormed
      · simpa [State.acquireCgroup] using invariant.knownSubjectIssued
      · simpa [State.acquireCgroup] using invariant.registeredSubjectExact
      · simpa [State.acquireCgroup] using invariant.authoritySubjectIssued
      · simpa [State.acquireCgroup] using invariant.selectedManagedHandleIssued
      · simpa [State.acquireCgroup] using invariant.runtimeHandlesNodup
      · simpa [State.acquireCgroup] using invariant.authorityHandlesNodup
      · simpa [State.acquireCgroup] using invariant.runtimeHandleIssued
      · simpa [State.acquireCgroup] using invariant.authorityHandleSound
      · simpa [State.acquireCgroup] using invariant.authorityHandleRuntimeOwned
      · simpa [State.acquireCgroup] using invariant.pendingRuntimeOwned
      · simpa [State.acquireCgroup] using invariant.pendingHandleIssued
  | acquireMount known creating _cgroup _free =>
      constructor <;> try simpa [State.acquireMount] using invariant.integratedWellFormed
      · simpa [State.acquireMount] using invariant.knownSubjectIssued
      · simpa [State.acquireMount] using invariant.registeredSubjectExact
      · simpa [State.acquireMount] using invariant.authoritySubjectIssued
      · simpa [State.acquireMount] using invariant.selectedManagedHandleIssued
      · simpa [State.acquireMount] using invariant.runtimeHandlesNodup
      · simpa [State.acquireMount] using invariant.authorityHandlesNodup
      · simpa [State.acquireMount] using invariant.runtimeHandleIssued
      · simpa [State.acquireMount] using invariant.authorityHandleSound
      · simpa [State.acquireMount] using invariant.authorityHandleRuntimeOwned
      · simpa [State.acquireMount] using invariant.pendingRuntimeOwned
      · simpa [State.acquireMount] using invariant.pendingHandleIssued
  | acquireControl known creating _mount _free =>
      constructor
      · exact invariant.integratedWellFormed
      · simpa [State.acquireControl] using invariant.knownSubjectIssued
      · simpa [State.acquireControl] using invariant.registeredSubjectExact
      · simpa [State.acquireControl] using invariant.authoritySubjectIssued
      · simpa [State.acquireControl] using invariant.selectedManagedHandleIssued
      · simpa [State.acquireControl] using invariant.runtimeHandlesNodup
      · simpa [State.acquireControl] using invariant.authorityHandlesNodup
      · simpa [State.acquireControl] using invariant.runtimeHandleIssued
      · simpa [State.acquireControl] using invariant.authorityHandleSound
      · simpa [State.acquireControl] using invariant.authorityHandleRuntimeOwned
      · simpa [State.acquireControl] using invariant.pendingRuntimeOwned
      · simpa [State.acquireControl] using invariant.pendingHandleIssued
  | registerSubject known creating unregistered allowed =>
      have integratedTransition := registerSubject_integratedStep allowed
      constructor
      · exact integratedTransition.preserves_wellFormed invariant.integratedWellFormed
      · simpa [State.registerSubject] using invariant.knownSubjectIssued
      · intro _registered
        exact CapabilityState.registerSubject_stores_exact_record
          before.integrated.authority before.subject
      · intro _lookup
        exact invariant.knownSubjectIssued known
      · intro handleId managed owner
        exact invariant.selectedManagedHandleIssued handleId managed owner
      · simpa [State.registerSubject] using invariant.runtimeHandlesNodup
      · simpa [State.registerSubject] using invariant.authorityHandlesNodup
      · simpa [State.registerSubject] using invariant.runtimeHandleIssued
      · intro handleId owned
        rcases invariant.authorityHandleSound handleId owned with
          ⟨handle, handleLookup, subjectMatches, managed⟩
        exact ⟨handle, by simpa [State.registerSubject,
          IntegratedHandleState.withAuthority,
          CapabilityState.registerSubject] using handleLookup,
          subjectMatches, managed⟩
      · simpa [State.registerSubject] using invariant.authorityHandleRuntimeOwned
      · simpa [State.registerSubject] using invariant.pendingRuntimeOwned
      · simpa [State.registerSubject] using invariant.pendingHandleIssued
  | startWorkload known creating cgroup mount control _free registered =>
      constructor
      · exact invariant.integratedWellFormed
      · simpa [State.startWorkload] using invariant.knownSubjectIssued
      · simpa [State.startWorkload] using invariant.registeredSubjectExact
      · simpa [State.startWorkload] using invariant.authoritySubjectIssued
      · simpa [State.startWorkload] using invariant.selectedManagedHandleIssued
      · simpa [State.startWorkload] using invariant.runtimeHandlesNodup
      · simpa [State.startWorkload] using invariant.authorityHandlesNodup
      · simpa [State.startWorkload] using invariant.runtimeHandleIssued
      · simpa [State.startWorkload] using invariant.authorityHandleSound
      · simpa [State.startWorkload] using invariant.authorityHandleRuntimeOwned
      · simpa [State.startWorkload] using invariant.pendingRuntimeOwned
      · simpa [State.startWorkload] using invariant.pendingHandleIssued
  | publish known creating registered cgroup mount control workload pending running =>
      constructor
      · exact invariant.integratedWellFormed
      · simpa [State.publishRunning] using invariant.knownSubjectIssued
      · simpa [State.publishRunning] using invariant.registeredSubjectExact
      · simpa [State.publishRunning] using invariant.authoritySubjectIssued
      · simpa [State.publishRunning] using invariant.selectedManagedHandleIssued
      · simpa [State.publishRunning] using invariant.runtimeHandlesNodup
      · simpa [State.publishRunning] using invariant.authorityHandlesNodup
      · simpa [State.publishRunning] using invariant.runtimeHandleIssued
      · simpa [State.publishRunning] using invariant.authorityHandleSound
      · simpa [State.publishRunning] using invariant.authorityHandleRuntimeOwned
      · simpa [State.publishRunning] using invariant.pendingRuntimeOwned
      · simpa [State.publishRunning] using invariant.pendingHandleIssued
  | acquisitionFailed creating unregistered =>
      rename_i resource outcome
      cases resource <;> cases outcome
      · exact invariant
      · simpa [State.failAcquisition, State.setResource] using
          invariant.updateCleanupFlags .closing .owned before.ownsMount
            before.ownsControl before.ownsWorkload
      · simpa [State.failAcquisition, State.setResource] using
          invariant.updateCleanupFlags .cleanupBlocked .unresolved before.ownsMount
            before.ownsControl before.ownsWorkload
      · exact invariant
      · simpa [State.failAcquisition, State.setResource] using
          invariant.updateCleanupFlags .closing before.ownsCgroup .owned
            before.ownsControl before.ownsWorkload
      · simpa [State.failAcquisition, State.setResource] using
          invariant.updateCleanupFlags .cleanupBlocked before.ownsCgroup .unresolved
            before.ownsControl before.ownsWorkload
      · exact invariant
      · simpa [State.failAcquisition, State.setResource] using
          invariant.updateCleanupFlags .closing before.ownsCgroup before.ownsMount
            .owned before.ownsWorkload
      · simpa [State.failAcquisition, State.setResource] using
          invariant.updateCleanupFlags .cleanupBlocked before.ownsCgroup
            before.ownsMount .unresolved before.ownsWorkload
      · exact invariant
      · simpa [State.failAcquisition, State.setResource] using
          invariant.updateCleanupFlags .closing before.ownsCgroup before.ownsMount
            before.ownsControl .owned
      · simpa [State.failAcquisition, State.setResource] using
          invariant.updateCleanupFlags .cleanupBlocked before.ownsCgroup
            before.ownsMount before.ownsControl .unresolved
  | failAfterRegistration known creating registered =>
      constructor
      · exact invariant.integratedWellFormed
      · simpa [State.failRegisteredCreate] using invariant.knownSubjectIssued
      · simpa [State.failRegisteredCreate] using invariant.registeredSubjectExact
      · simpa [State.failRegisteredCreate] using invariant.authoritySubjectIssued
      · simpa [State.failRegisteredCreate] using invariant.selectedManagedHandleIssued
      · simpa [State.failRegisteredCreate] using invariant.runtimeHandlesNodup
      · simpa [State.failRegisteredCreate] using invariant.authorityHandlesNodup
      · simpa [State.failRegisteredCreate] using invariant.runtimeHandleIssued
      · simpa [State.failRegisteredCreate] using invariant.authorityHandleSound
      · simpa [State.failRegisteredCreate] using invariant.authorityHandleRuntimeOwned
      · simpa [State.failRegisteredCreate] using invariant.pendingRuntimeOwned
      · simpa [State.failRegisteredCreate] using invariant.pendingHandleIssued

/-- A registered create failure is an error-labeled state change retaining ownership. -/
theorem failed_registered_create_reserves_subject {state : State}
    (invariant : state.Invariant) (known : state.known = true)
    (creating : state.lifecycle = .creating)
    (registered : state.authorityRegistered = true) :
    CreateStep state (.error .setupAfterRegistration) state.failRegisteredCreate ∧
      state.failRegisteredCreate.lifecycle = .closing ∧
      state.failRegisteredCreate.issuedSubjects state.subject.id = true := by
  exact ⟨CreateStep.failAfterRegistration known creating registered, rfl,
    invariant.knownSubjectIssued known⟩

/-- Multi-stage runtime handle open, including both compensation outcomes. -/
inductive OpenStep : State → ResultLabel → State → Prop
  | openRuntime {state : State} {handle : OpenHandle} :
      state.known = true → state.lifecycle = .running →
      state.pendingOpen = none →
      handle.subject = state.subject.id →
      state.issuedHandles handle.id = false →
      OpenStep state (.ok .openRuntimeHandle) (state.beginOpen handle)
  | registerManaged {state : State} {handle : OpenHandle} :
      state.known = true → state.lifecycle = .running →
      state.pendingOpen = some handle →
      handle.subject = state.subject.id →
      handle.id ∉ state.authorityHandles →
      (allowed : state.integrated.MayOpen handle) →
      OpenStep state (.ok .registerManagedHandle)
        (state.commitOpen handle allowed.object)
  | registrationFailedClean {state : State} {handle : OpenHandle} :
      state.known = true → state.lifecycle = .running →
      state.pendingOpen = some handle →
      handle.subject = state.subject.id →
      handle.id ∉ state.authorityHandles →
      (allowed : state.integrated.MayFailOpenAfterRegistration handle) →
      OpenStep state (.error .handleRegistration) (state.failOpenClean handle)
  | registrationFailedRetained {state : State} {handle : OpenHandle} :
      state.known = true → state.lifecycle = .running →
      state.pendingOpen = some handle →
      handle.subject = state.subject.id →
      handle.id ∉ state.authorityHandles →
      (allowed : state.integrated.MayFailOpenAfterRegistration handle) →
      OpenStep state (.error .handleRegistrationCleanup)
        (state.failOpenRetained handle)
  | registrationFailedUnknown {state : State} {handle : OpenHandle} :
      state.known = true → state.lifecycle = .running →
      state.pendingOpen = some handle →
      handle.subject = state.subject.id →
      handle.id ∉ state.authorityHandles →
      (allowed : state.integrated.MayFailOpenAfterRegistration handle) →
      OpenStep state (.error .handleRegistrationUnknown)
        (state.failOpenUnknown handle)

/-- Every accepted open stage preserves scoped managed-handle refinement. -/
theorem OpenStep.preserves_invariant {before after : State}
    {result : ResultLabel} (transition : OpenStep before result after)
    (invariant : before.Invariant) : after.Invariant := by
  cases transition with
  | openRuntime known running noPending subjectMatches fresh =>
      rename_i handle
      have notRuntime : handle.id ∉ before.runtimeHandles := by
        intro runtimeOwned
        have issued := invariant.runtimeHandleIssued handle.id runtimeOwned
        rw [fresh] at issued
        cases issued
      constructor
      · exact invariant.integratedWellFormed
      · simpa [State.beginOpen] using invariant.knownSubjectIssued
      · simpa [State.beginOpen] using invariant.registeredSubjectExact
      · simpa [State.beginOpen] using invariant.authoritySubjectIssued
      · intro handleId managed owner
        by_cases sameId : handleId = handle.id
        · subst handleId
          simp [State.beginOpen]
        · have oldIssued := invariant.selectedManagedHandleIssued handleId managed owner
          simpa [State.beginOpen, replace, sameId] using oldIssued
      · simp [State.beginOpen]
        exact ⟨notRuntime, invariant.runtimeHandlesNodup⟩
      · simpa [State.beginOpen] using invariant.authorityHandlesNodup
      · intro handleId runtimeOwned
        simp [State.beginOpen, State.RuntimeOwns] at runtimeOwned
        rcases runtimeOwned with sameId | oldOwned
        · subst handleId
          simp [State.beginOpen]
        · have oldIssued := invariant.runtimeHandleIssued handleId oldOwned
          by_cases sameId : handleId = handle.id
          · subst handleId
            exact False.elim (notRuntime oldOwned)
          · simpa [State.beginOpen, replace, sameId] using oldIssued
      · simpa [State.beginOpen, State.AuthorityOwns] using
          invariant.authorityHandleSound
      · intro handleId authorityOwned
        exact List.mem_cons_of_mem handle.id
          (invariant.authorityHandleRuntimeOwned handleId authorityOwned)
      · intro pendingHandle pendingLookup
        have exactHandle : pendingHandle = handle := by
          simpa [State.beginOpen] using Option.some.inj pendingLookup.symm
        subst pendingHandle
        simp [State.beginOpen, State.RuntimeOwns]
      · intro pendingHandle pendingLookup
        have exactHandle : pendingHandle = handle := by
          simpa [State.beginOpen] using Option.some.inj pendingLookup.symm
        subst pendingHandle
        simp [State.beginOpen]
  | registerManaged known running pending subjectMatches notAuthority allowed =>
      rename_i handle
      have integratedAfter := IntegratedHandleState.openHandle_preserves_wellFormed
        invariant.integratedWellFormed allowed
      have runtimeOwned := invariant.pendingRuntimeOwned handle pending
      have issued := invariant.pendingHandleIssued handle pending
      constructor
      · exact integratedAfter
      · simpa [State.commitOpen] using invariant.knownSubjectIssued
      · simpa [State.commitOpen, IntegratedHandleState.openHandle,
          CapabilityState.registerOpenHandle] using invariant.registeredSubjectExact
      · simpa [State.commitOpen, IntegratedHandleState.openHandle,
          CapabilityState.registerOpenHandle] using invariant.authoritySubjectIssued
      · intro handleId managed owner
        by_cases sameId : handleId = handle.id
        · subst handleId
          exact issued
        · have oldManaged : before.integrated.managedHandles handleId = true := by
            simpa [State.commitOpen, IntegratedHandleState.openHandle,
              replace, sameId] using managed
          have oldOwner : before.integrated.authority.issuedHandleOwners handleId =
              some before.subject.id := by
            simpa [State.commitOpen, IntegratedHandleState.openHandle,
              CapabilityState.registerOpenHandle, replace, sameId] using owner
          exact invariant.selectedManagedHandleIssued handleId oldManaged oldOwner
      · simpa [State.commitOpen] using invariant.runtimeHandlesNodup
      · simp [State.commitOpen]
        exact ⟨notAuthority, invariant.authorityHandlesNodup⟩
      · simpa [State.commitOpen] using invariant.runtimeHandleIssued
      · intro handleId authorityOwned
        simp [State.commitOpen, State.AuthorityOwns] at authorityOwned
        rcases authorityOwned with sameId | oldOwned
        · subst handleId
          exact ⟨handle,
            CapabilityState.registerOpenHandle_stores_exact_record
              before.integrated.authority handle,
            subjectMatches, by simp [State.commitOpen,
              IntegratedHandleState.openHandle]⟩
        · rcases invariant.authorityHandleSound handleId oldOwned with
            ⟨oldHandle, oldLookup, oldSubject, oldManaged⟩
          have differentId : handleId ≠ handle.id := by
            intro sameId
            subst handleId
            exact notAuthority oldOwned
          exact ⟨oldHandle, by simpa [State.commitOpen,
            IntegratedHandleState.openHandle,
            CapabilityState.registerOpenHandle, replace, differentId] using oldLookup,
            oldSubject, by simpa [State.commitOpen,
              IntegratedHandleState.openHandle, replace, differentId] using oldManaged⟩
      · intro handleId authorityOwned
        simp [State.commitOpen, State.AuthorityOwns] at authorityOwned
        rcases authorityOwned with sameId | oldOwned
        · subst handleId
          exact runtimeOwned
        · exact invariant.authorityHandleRuntimeOwned handleId oldOwned
      · simp [State.commitOpen]
      · simp [State.commitOpen]
  | registrationFailedClean known running pending subjectMatches notAuthority allowed =>
      rename_i handle
      have integratedAfter :=
        IntegratedHandleState.failOpenAfterRegistration_preserves_wellFormed
          invariant.integratedWellFormed allowed
      have liveExact :=
        IntegratedHandleState.failOpenAfterRegistration_openHandles
          invariant.integratedWellFormed allowed
      have issued := invariant.pendingHandleIssued handle pending
      constructor
      · exact integratedAfter
      · simpa [State.failOpenClean] using invariant.knownSubjectIssued
      · simpa [State.failOpenClean,
          IntegratedHandleState.failOpenAfterRegistration,
          CapabilityState.closeHandle, CapabilityState.registerOpenHandle] using
          invariant.registeredSubjectExact
      · simpa [State.failOpenClean,
          IntegratedHandleState.failOpenAfterRegistration,
          CapabilityState.closeHandle, CapabilityState.registerOpenHandle] using
          invariant.authoritySubjectIssued
      · intro handleId managed owner
        by_cases sameId : handleId = handle.id
        · subst handleId
          exact issued
        · have oldManaged : before.integrated.managedHandles handleId = true := by
            simpa [State.failOpenClean,
              IntegratedHandleState.failOpenAfterRegistration, replace, sameId] using managed
          have oldOwner : before.integrated.authority.issuedHandleOwners handleId =
              some before.subject.id := by
            simpa [State.failOpenClean,
              IntegratedHandleState.failOpenAfterRegistration,
              CapabilityState.closeHandle, CapabilityState.registerOpenHandle,
              replace, sameId] using owner
          exact invariant.selectedManagedHandleIssued handleId oldManaged oldOwner
      · simpa [State.failOpenClean] using invariant.runtimeHandlesNodup.erase handle.id
      · simpa [State.failOpenClean] using invariant.authorityHandlesNodup
      · intro handleId runtimeOwned
        have oldOwned : before.RuntimeOwns handleId :=
          List.mem_of_mem_erase (by simpa [State.failOpenClean,
            State.RuntimeOwns] using runtimeOwned)
        exact invariant.runtimeHandleIssued handleId oldOwned
      · intro handleId authorityOwned
        rcases invariant.authorityHandleSound handleId authorityOwned with
          ⟨oldHandle, oldLookup, oldSubject, oldManaged⟩
        have differentId : handleId ≠ handle.id := by
          intro sameId
          subst handleId
          exact notAuthority authorityOwned
        exact ⟨oldHandle, by simpa [State.failOpenClean, liveExact] using oldLookup,
          oldSubject, by simpa [State.failOpenClean,
            IntegratedHandleState.failOpenAfterRegistration, replace,
            differentId] using oldManaged⟩
      · intro handleId authorityOwned
        have oldRuntime := invariant.authorityHandleRuntimeOwned handleId authorityOwned
        have differentId : handleId ≠ handle.id := by
          intro sameId
          subst handleId
          exact notAuthority authorityOwned
        exact (List.mem_erase_of_ne differentId).2 oldRuntime
      · simp [State.failOpenClean]
      · simp [State.failOpenClean]
  | registrationFailedRetained known running pending subjectMatches notAuthority allowed =>
      rename_i handle
      have integratedAfter :=
        IntegratedHandleState.failOpenAfterRegistration_preserves_wellFormed
          invariant.integratedWellFormed allowed
      have liveExact :=
        IntegratedHandleState.failOpenAfterRegistration_openHandles
          invariant.integratedWellFormed allowed
      have issued := invariant.pendingHandleIssued handle pending
      constructor
      · exact integratedAfter
      · simpa [State.failOpenRetained] using invariant.knownSubjectIssued
      · simpa [State.failOpenRetained,
          IntegratedHandleState.failOpenAfterRegistration,
          CapabilityState.closeHandle, CapabilityState.registerOpenHandle] using
          invariant.registeredSubjectExact
      · simpa [State.failOpenRetained,
          IntegratedHandleState.failOpenAfterRegistration,
          CapabilityState.closeHandle, CapabilityState.registerOpenHandle] using
          invariant.authoritySubjectIssued
      · intro handleId managed owner
        by_cases sameId : handleId = handle.id
        · subst handleId
          exact issued
        · have oldManaged : before.integrated.managedHandles handleId = true := by
            simpa [State.failOpenRetained,
              IntegratedHandleState.failOpenAfterRegistration, replace, sameId] using managed
          have oldOwner : before.integrated.authority.issuedHandleOwners handleId =
              some before.subject.id := by
            simpa [State.failOpenRetained,
              IntegratedHandleState.failOpenAfterRegistration,
              CapabilityState.closeHandle, CapabilityState.registerOpenHandle,
              replace, sameId] using owner
          exact invariant.selectedManagedHandleIssued handleId oldManaged oldOwner
      · simpa [State.failOpenRetained] using invariant.runtimeHandlesNodup
      · simpa [State.failOpenRetained] using invariant.authorityHandlesNodup
      · simpa [State.failOpenRetained] using invariant.runtimeHandleIssued
      · intro handleId authorityOwned
        rcases invariant.authorityHandleSound handleId authorityOwned with
          ⟨oldHandle, oldLookup, oldSubject, oldManaged⟩
        have differentId : handleId ≠ handle.id := by
          intro sameId
          subst handleId
          exact notAuthority authorityOwned
        exact ⟨oldHandle, by simpa [State.failOpenRetained, liveExact] using oldLookup,
          oldSubject, by simpa [State.failOpenRetained,
            IntegratedHandleState.failOpenAfterRegistration, replace,
            differentId] using oldManaged⟩
      · simpa [State.failOpenRetained] using invariant.authorityHandleRuntimeOwned
      · simp [State.failOpenRetained]
      · simp [State.failOpenRetained]
  | registrationFailedUnknown known running pending subjectMatches notAuthority allowed =>
      rename_i handle
      have integratedAfter :=
        IntegratedHandleState.failOpenAfterRegistration_preserves_wellFormed
          invariant.integratedWellFormed allowed
      have liveExact :=
        IntegratedHandleState.failOpenAfterRegistration_openHandles
          invariant.integratedWellFormed allowed
      have issued := invariant.pendingHandleIssued handle pending
      constructor
      · exact integratedAfter
      · simpa [State.failOpenUnknown] using invariant.knownSubjectIssued
      · simpa [State.failOpenUnknown,
          IntegratedHandleState.failOpenAfterRegistration,
          CapabilityState.closeHandle, CapabilityState.registerOpenHandle] using
          invariant.registeredSubjectExact
      · simpa [State.failOpenUnknown,
          IntegratedHandleState.failOpenAfterRegistration,
          CapabilityState.closeHandle, CapabilityState.registerOpenHandle] using
          invariant.authoritySubjectIssued
      · intro handleId managed owner
        by_cases sameId : handleId = handle.id
        · subst handleId
          exact issued
        · have oldManaged : before.integrated.managedHandles handleId = true := by
            simpa [State.failOpenUnknown,
              IntegratedHandleState.failOpenAfterRegistration, replace, sameId] using managed
          have oldOwner : before.integrated.authority.issuedHandleOwners handleId =
              some before.subject.id := by
            simpa [State.failOpenUnknown,
              IntegratedHandleState.failOpenAfterRegistration,
              CapabilityState.closeHandle, CapabilityState.registerOpenHandle,
              replace, sameId] using owner
          exact invariant.selectedManagedHandleIssued handleId oldManaged oldOwner
      · simpa [State.failOpenUnknown] using invariant.runtimeHandlesNodup
      · simpa [State.failOpenUnknown] using invariant.authorityHandlesNodup
      · simpa [State.failOpenUnknown] using invariant.runtimeHandleIssued
      · intro handleId authorityOwned
        rcases invariant.authorityHandleSound handleId authorityOwned with
          ⟨oldHandle, oldLookup, oldSubject, oldManaged⟩
        have differentId : handleId ≠ handle.id := by
          intro sameId
          subst handleId
          exact notAuthority authorityOwned
        exact ⟨oldHandle, by simpa [State.failOpenUnknown, liveExact] using oldLookup,
          oldSubject, by simpa [State.failOpenUnknown,
            IntegratedHandleState.failOpenAfterRegistration, replace,
            differentId] using oldManaged⟩
      · simpa [State.failOpenUnknown] using invariant.authorityHandleRuntimeOwned
      · simp [State.failOpenUnknown]
      · simp [State.failOpenUnknown]

/-- Successful managed registration is exactly one atomic integrated open. -/
theorem commitOpen_integratedStep {state : State} {handle : OpenHandle}
    (allowed : state.integrated.MayOpen handle) :
    IntegratedHandleState.Step state.integrated
      (state.commitOpen handle allowed.object).integrated := by
  simpa [State.commitOpen] using IntegratedHandleState.Step.openAtomic allowed

/-- Either registration-failure outcome refines the same consuming error step. -/
theorem failOpen_integratedStep {state : State} {handle : OpenHandle}
    (allowed : state.integrated.MayFailOpenAfterRegistration handle) :
    IntegratedHandleState.Step state.integrated
      (state.failOpenRetained handle).integrated := by
  simpa [State.failOpenRetained] using
    IntegratedHandleState.Step.failedOpenAfterRegistration allowed

/-- Unknown compensation still consumes the integrated handle identity. -/
theorem failOpenUnknown_integratedStep {state : State} {handle : OpenHandle}
    (allowed : state.integrated.MayFailOpenAfterRegistration handle) :
    IntegratedHandleState.Step state.integrated
      (state.failOpenUnknown handle).integrated := by
  simpa [State.failOpenUnknown] using
    IntegratedHandleState.Step.failedOpenAfterRegistration allowed

/-- Retained cleanup ownership is fail-closed for later open requests. -/
theorem failOpenRetained_blocks_open {state : State} {handle : OpenHandle} :
    ¬ ∃ result after, OpenStep (state.failOpenRetained handle) result after := by
  rintro ⟨result, after, transition⟩
  cases transition <;> simp [State.failOpenRetained] at *

/-- Retained compensation ambiguity blocks later opens until cleanup completes. -/
theorem failOpenUnknown_blocks_open {state : State} {handle : OpenHandle} :
    ¬ ∃ result after, OpenStep (state.failOpenUnknown handle) result after := by
  rintro ⟨result, after, transition⟩
  cases transition <;> simp [State.failOpenUnknown] at *

/-- Cleanup-required compensation retains an addressable runtime descriptor. -/
theorem failOpenRetained_owns_cleanup {state : State} {handle : OpenHandle}
    (invariant : state.Invariant) (pending : state.pendingOpen = some handle) :
    (state.failOpenRetained handle).lifecycle = .closing ∧
      (state.failOpenRetained handle).RuntimeOwns handle.id := by
  exact ⟨rfl, by simpa [State.failOpenRetained] using
    invariant.pendingRuntimeOwned handle pending⟩

/-- Unknown compensation retains an addressable descriptor for cleanup retry. -/
theorem failOpenUnknown_owns_retryable_cleanup {state : State}
    {handle : OpenHandle} (invariant : state.Invariant)
    (pending : state.pendingOpen = some handle) :
    (state.failOpenUnknown handle).lifecycle = .closing ∧
      (state.failOpenUnknown handle).RuntimeOwns handle.id := by
  exact ⟨rfl, by simpa [State.failOpenUnknown] using
    invariant.pendingRuntimeOwned handle pending⟩

/-- Both registration failure outcomes reserve the local and integrated tombstone. -/
theorem failed_open_reserves_handle (state : State) (handle : OpenHandle) :
    let clean := state.failOpenClean handle
    let retained := state.failOpenRetained handle
    clean.issuedHandles handle.id = state.issuedHandles handle.id ∧
      retained.issuedHandles handle.id = state.issuedHandles handle.id ∧
      clean.integrated.managedHandles handle.id = true ∧
      retained.integrated.managedHandles handle.id = true ∧
      clean.integrated.authority.issuedHandleOwners handle.id = some handle.subject ∧
      retained.integrated.authority.issuedHandleOwners handle.id = some handle.subject ∧
      clean.integrated.authority.openHandles handle.id = none ∧
      retained.integrated.authority.openHandles handle.id = none := by
  simp [State.failOpenClean, State.failOpenRetained,
    IntegratedHandleState.failOpenAfterRegistration,
    CapabilityState.closeHandle, CapabilityState.registerOpenHandle]

namespace State

/-- Begin registered shutdown by revoking Authority before resource cleanup. -/
def beginRegisteredShutdown (state : State) : State :=
  { state with
    integrated := state.integrated.withAuthority
      (state.integrated.authority.beginSubjectClose state.subject.id)
    lifecycle := .closing }

/-- A rejected begin-close still leaves the local record fail-closed. -/
def rejectBeginShutdown (state : State) : State :=
  { state with lifecycle := .closing }

/-- An unregistered retained setup record enters cleanup without Authority mutation. -/
def beginUnregisteredShutdown (state : State) : State :=
  { state with lifecycle := .closing }

/-- Release the workload ownership token. -/
def stopWorkload (state : State) : State := { state with ownsWorkload := .none }

/-- Release the control descriptor ownership token. -/
def closeControl (state : State) : State := { state with ownsControl := .none }

/-- Release a runtime-only descriptor after failed Authority registration. -/
def closeRuntimeOnly (state : State) (handleId : HandleId) : State :=
  { state with runtimeHandles := state.runtimeHandles.erase handleId }

/-- Close one locally tracked managed handle in both models. -/
def closeManaged (state : State) (handleId : HandleId)
    (handle : OpenHandle) (object : NamespaceObject) : State :=
  { state with
    integrated := state.integrated.closeHandle handleId handle object
    runtimeHandles := state.runtimeHandles.erase handleId
    authorityHandles := state.authorityHandles.erase handleId }

/-- Release the mount only after its cleanup gate was established. -/
def unmount (state : State) : State := { state with ownsMount := .none }

/-- Release the cgroup only after workload and mount cleanup. -/
def removeCgroup (state : State) : State := { state with ownsCgroup := .none }

/-- Record a cleanup error while retaining its known target token for retry. -/
def failMutation (state : State) (_resource : ResourceKind)
    (outcome : ResourceMutation) : State :=
  match outcome with
  | .noEffect => state
  | .cleanupRequired => state
  | .effectUnknown => { state with lifecycle := .closing }

/-- A descriptor mutation with unknown effect retains its known token for retry. -/
def failHandleMutation (state : State) (outcome : ResourceMutation) : State :=
  match outcome with
  | .noEffect => state
  | .cleanupRequired => state
  | .effectUnknown => { state with lifecycle := .closing }

/-- Cleanup error bookkeeping preserves owned tokens and scoped refinement. -/
theorem Invariant.failMutation {state : State} (invariant : state.Invariant)
    (resource : ResourceKind) (outcome : ResourceMutation) :
    (state.failMutation resource outcome).Invariant := by
  cases outcome
  · exact invariant
  · exact invariant
  · simpa [failMutation] using (invariant.updateCleanupFlags
      .closing state.ownsCgroup state.ownsMount state.ownsControl
        state.ownsWorkload)

/-- Descriptor effect uncertainty changes lifecycle, not scoped refinement facts. -/
theorem Invariant.failHandleMutation {state : State} (invariant : state.Invariant)
    (outcome : ResourceMutation) : (state.failHandleMutation outcome).Invariant := by
  cases outcome
  · exact invariant
  · exact invariant
  · simpa [failHandleMutation] using invariant.updateCleanupFlags
      .closing state.ownsCgroup state.ownsMount state.ownsControl
        state.ownsWorkload

/-- Error bookkeeping leaves both permanent local tombstone maps unchanged. -/
theorem failMutation_preserves_issued (state : State) (resource : ResourceKind)
    (outcome : ResourceMutation) :
    (state.failMutation resource outcome).issuedSubjects = state.issuedSubjects ∧
      (state.failMutation resource outcome).issuedHandles = state.issuedHandles := by
  cases resource <;> cases outcome <;> exact ⟨rfl, rfl⟩

theorem failHandleMutation_preserves_issued (state : State)
    (outcome : ResourceMutation) :
    (state.failHandleMutation outcome).issuedSubjects = state.issuedSubjects ∧
      (state.failHandleMutation outcome).issuedHandles = state.issuedHandles := by
  cases outcome <;> exact ⟨rfl, rfl⟩

theorem failMutation_preserves_allocator (state : State) (resource : ResourceKind)
    (outcome : ResourceMutation) :
    (state.failMutation resource outcome).integrated.authority.nextCapabilitySequence =
        state.integrated.authority.nextCapabilitySequence ∧
      (state.failMutation resource outcome).integrated.authority.capabilityIdsExhausted =
        state.integrated.authority.capabilityIdsExhausted := by
  cases resource <;> cases outcome <;> exact ⟨rfl, rfl⟩

theorem failHandleMutation_preserves_allocator (state : State)
    (outcome : ResourceMutation) :
    (state.failHandleMutation outcome).integrated.authority.nextCapabilitySequence =
        state.integrated.authority.nextCapabilitySequence ∧
      (state.failHandleMutation outcome).integrated.authority.capabilityIdsExhausted =
        state.integrated.authority.capabilityIdsExhausted := by
  cases outcome <;> exact ⟨rfl, rfl⟩

/-- Finish a registered Authority shutdown after all ownership is released. -/
def finishRegisteredShutdown (state : State) : State :=
  { state with
    integrated := state.integrated.withAuthority
      (state.integrated.authority.finishSubjectClose state.subject.id)
    lifecycle := .closed
    authorityRegistered := false }

/-- Finish cleanup for a record that never reached Authority registration. -/
def finishUnregisteredShutdown (state : State) : State :=
  { state with lifecycle := .closed }

/-- Non-dependent ownership key used by cleanup retry theorems. -/
inductive Asset where
  | cgroup
  | mount
  | control
  | workload
  | runtimeHandle (handleId : HandleId)
  | authorityHandle (handleId : HandleId)
  deriving Repr, DecidableEq

/-- The selected subject currently owns the named cleanup asset. -/
def OwnsAsset (state : State) : Asset → Prop
  | .cgroup => state.ownsCgroup = .owned
  | .mount => state.ownsMount = .owned
  | .control => state.ownsControl = .owned
  | .workload => state.ownsWorkload = .owned
  | .runtimeHandle handleId => state.RuntimeOwns handleId
  | .authorityHandle handleId => state.AuthorityOwns handleId

/-- Resource-error bookkeeping never invents an addressable asset. -/
theorem failMutation_ownsAsset_monotone (state : State) (resource : ResourceKind)
    (outcome : ResourceMutation) (asset : Asset) :
    (state.failMutation resource outcome).OwnsAsset asset → state.OwnsAsset asset := by
  cases resource <;> cases outcome <;> cases asset <;>
    simp [failMutation, setResource, OwnsAsset, RuntimeOwns, AuthorityOwns]

/-- Descriptor-error bookkeeping never invents an addressable asset. -/
theorem failHandleMutation_ownsAsset_monotone (state : State)
    (outcome : ResourceMutation) (asset : Asset) :
    (state.failHandleMutation outcome).OwnsAsset asset → state.OwnsAsset asset := by
  cases outcome <;> cases asset <;>
    simp [failHandleMutation, OwnsAsset, RuntimeOwns, AuthorityOwns]

end State

/-- Cleanup-only transitions preserve ownership of every unreleased asset. -/
inductive CleanupStep : State → ResultLabel → State → Prop
  | beginRegistered {state : State} :
      state.known = true → state.lifecycle ≠ .closed →
      state.lifecycle ≠ .cleanupBlocked →
      state.authorityRegistered = true →
      state.integrated.authority.subjectStatuses state.subject.id = some .running →
      CanIncrementU64 state.integrated.authority.authorizationEpoch →
      CleanupStep state (.ok .beginShutdown) state.beginRegisteredShutdown
  | beginRejected {state : State} :
      state.known = true → state.lifecycle ≠ .closed →
      state.lifecycle ≠ .cleanupBlocked →
      CleanupStep state (.error .beginShutdown) state.rejectBeginShutdown
  | beginUnregistered {state : State} :
      state.known = true → state.lifecycle ≠ .closed →
      state.lifecycle ≠ .cleanupBlocked →
      state.authorityRegistered = false →
      CleanupStep state (.ok .beginShutdown) state.beginUnregisteredShutdown
  | stopWorkload {state : State} :
      state.lifecycle = .closing → state.ownsWorkload = .owned →
      CleanupStep state (.ok .stopWorkload) state.stopWorkload
  | stopWorkloadFailed {state : State} {outcome : ResourceMutation} :
      state.lifecycle = .closing → state.ownsWorkload = .owned →
      CleanupStep state (.error (.cleanupWorkload outcome))
        (state.failMutation .workload outcome)
  | closeControl {state : State} :
      state.lifecycle = .closing → state.ownsControl = .owned →
      CleanupStep state (.ok .closeControl) state.closeControl
  | closeControlFailed {state : State} {outcome : ResourceMutation} :
      state.lifecycle = .closing → state.ownsControl = .owned →
      CleanupStep state (.error (.cleanupControl outcome))
        (state.failMutation .control outcome)
  | closeRuntimeOnly {state : State} {handleId : HandleId} :
      state.lifecycle = .closing → state.RuntimeOwns handleId →
      ¬ state.AuthorityOwns handleId →
      state.pendingOpen = none →
      CleanupStep state (.ok .closeRuntimeHandle)
        (state.closeRuntimeOnly handleId)
  | closeManaged {state : State} {handleId : HandleId} :
      state.lifecycle = .closing → state.RuntimeOwns handleId →
      state.AuthorityOwns handleId →
      state.pendingOpen = none →
      (allowed : state.integrated.MayClose state.subject.id handleId) →
      CleanupStep state (.ok .closeRuntimeHandle)
        (state.closeManaged handleId allowed.handle allowed.object)
  | closeHandleFailed {state : State} {handleId : HandleId}
      {outcome : ResourceMutation} :
      state.lifecycle = .closing → state.RuntimeOwns handleId →
      CleanupStep state (.error (.cleanupHandle outcome))
        (state.failHandleMutation outcome)
  | unmount {state : State} :
      state.lifecycle = .closing → state.ownsMount = .owned →
      state.ownsWorkload = .none → state.ownsControl = .none →
      state.runtimeHandles = [] →
      CleanupStep state (.ok .unmount) state.unmount
  | unmountFailed {state : State} {outcome : ResourceMutation} :
      state.lifecycle = .closing → state.ownsMount = .owned →
      CleanupStep state (.error (.cleanupUnmount outcome))
        (state.failMutation .mount outcome)
  | removeCgroup {state : State} :
      state.lifecycle = .closing → state.ownsCgroup = .owned →
      state.ownsWorkload = .none → state.ownsMount = .none →
      CleanupStep state (.ok .removeCgroup) state.removeCgroup
  | removeCgroupFailed {state : State} {outcome : ResourceMutation} :
      state.lifecycle = .closing → state.ownsCgroup = .owned →
      CleanupStep state (.error (.cleanupCgroup outcome))
        (state.failMutation .cgroup outcome)
  | finishRegistered {state : State} :
      state.lifecycle = .closing → state.authorityRegistered = true →
      state.ownsCgroup = .none → state.ownsMount = .none →
      state.ownsControl = .none → state.ownsWorkload = .none →
      state.runtimeHandles = [] → state.authorityHandles = [] →
      state.pendingOpen = none →
      state.integrated.authority.subjectStatuses state.subject.id = some .closing →
      (∀ handleId handle,
        state.integrated.authority.openHandles handleId = some handle →
          handle.subject ≠ state.subject.id) →
      CleanupStep state (.ok .finishShutdown) state.finishRegisteredShutdown
  | finishRejected {state : State} :
      state.lifecycle = .closing →
      CleanupStep state (.error .finishShutdown) state
  | finishUnregistered {state : State} :
      state.lifecycle = .closing → state.authorityRegistered = false →
      state.ownsCgroup = .none → state.ownsMount = .none →
      state.ownsControl = .none → state.ownsWorkload = .none →
      state.runtimeHandles = [] → state.authorityHandles = [] →
      state.pendingOpen = none →
      CleanupStep state (.ok .finishShutdown) state.finishUnregisteredShutdown

/-- Tokenless acquisition ambiguity requires reconciliation outside modeled cleanup. -/
theorem cleanupBlocked_is_terminal {state : State}
    (blocked : state.lifecycle = .cleanupBlocked) :
    ¬ ∃ result after, CleanupStep state result after := by
  rintro ⟨result, after, transition⟩
  cases transition <;> simp_all

/-- A partial-open mutation with a known descriptor can immediately resume cleanup. -/
theorem failOpenUnknown_cleanup_retriable {state : State} {handle : OpenHandle}
    (invariant : state.Invariant) (pending : state.pendingOpen = some handle)
    (notAuthority : ¬ state.AuthorityOwns handle.id) :
    CleanupStep (state.failOpenUnknown handle) (.ok .closeRuntimeHandle)
      ((state.failOpenUnknown handle).closeRuntimeOnly handle.id) := by
  apply CleanupStep.closeRuntimeOnly
  · rfl
  · simpa [State.failOpenUnknown] using
      invariant.pendingRuntimeOwned handle pending
  · simpa [State.failOpenUnknown] using notAuthority
  · rfl

/-- Cleanup-required acquisition failure retains an addressable token. -/
theorem acquisition_cleanupRequired_retains (state : State)
    (resource : ResourceKind) :
    (state.failAcquisition resource .cleanupRequired).lifecycle = .closing ∧
      match resource with
      | .cgroup => (state.failAcquisition resource .cleanupRequired).ownsCgroup = .owned
      | .mount => (state.failAcquisition resource .cleanupRequired).ownsMount = .owned
      | .control => (state.failAcquisition resource .cleanupRequired).ownsControl = .owned
      | .workload => (state.failAcquisition resource .cleanupRequired).ownsWorkload = .owned := by
  cases resource <;> simp [State.failAcquisition, State.setResource]

/-- Unknown acquisition effect is represented, never silently dropped. -/
theorem acquisition_effectUnknown_blocks (state : State)
    (resource : ResourceKind) :
    (state.failAcquisition resource .effectUnknown).lifecycle = .cleanupBlocked ∧
      match resource with
      | .cgroup =>
          (state.failAcquisition resource .effectUnknown).ownsCgroup = .unresolved
      | .mount =>
          (state.failAcquisition resource .effectUnknown).ownsMount = .unresolved
      | .control =>
          (state.failAcquisition resource .effectUnknown).ownsControl = .unresolved
      | .workload =>
          (state.failAcquisition resource .effectUnknown).ownsWorkload = .unresolved := by
  cases resource <;> simp [State.failAcquisition, State.setResource]

/-- Registered begin-close refines the Authority-only integrated transition. -/
theorem beginRegisteredShutdown_integratedStep {state : State}
    (running : state.integrated.authority.subjectStatuses state.subject.id =
      some .running)
    (canIncrement : CanIncrementU64 state.integrated.authority.authorizationEpoch) :
    IntegratedHandleState.Step state.integrated
      state.beginRegisteredShutdown.integrated := by
  apply IntegratedHandleState.Step.authorityOnly
    (CapabilityState.Step.beginClose running canIncrement)
  intro handleId _managed
  rfl

/-- Registered finish-close refines the Authority-only integrated transition. -/
theorem finishRegisteredShutdown_integratedStep {state : State}
    (closing : state.integrated.authority.subjectStatuses state.subject.id =
      some .closing)
    (noSubjectHandles : ∀ handleId handle,
      state.integrated.authority.openHandles handleId = some handle →
        handle.subject ≠ state.subject.id) :
    IntegratedHandleState.Step state.integrated
      state.finishRegisteredShutdown.integrated := by
  apply IntegratedHandleState.Step.authorityOnly
    (CapabilityState.Step.finishClose closing noSubjectHandles)
  intro handleId _managed
  rfl

/-- Managed local cleanup is exactly one atomic integrated close. -/
theorem closeManaged_integratedStep {state : State} {handleId : HandleId}
    (allowed : state.integrated.MayClose state.subject.id handleId) :
    IntegratedHandleState.Step state.integrated
      (state.closeManaged handleId allowed.handle allowed.object).integrated := by
  simpa [State.closeManaged] using IntegratedHandleState.Step.closeAtomic allowed

/-- Cleanup retries never acquire an asset absent before the cleanup step. -/
theorem CleanupStep.ownership_monotone {before after : State}
    {result : ResultLabel} (transition : CleanupStep before result after) :
    ∀ asset, after.OwnsAsset asset → before.OwnsAsset asset := by
  cases transition with
  | stopWorkloadFailed closing owned =>
      intro asset
      exact State.failMutation_ownsAsset_monotone before .workload _ asset
  | closeControlFailed closing owned =>
      intro asset
      exact State.failMutation_ownsAsset_monotone before .control _ asset
  | closeHandleFailed closing owned =>
      intro asset
      exact State.failHandleMutation_ownsAsset_monotone before _ asset
  | unmountFailed closing owned =>
      intro asset
      exact State.failMutation_ownsAsset_monotone before .mount _ asset
  | removeCgroupFailed closing owned =>
      intro asset
      exact State.failMutation_ownsAsset_monotone before .cgroup _ asset
  | closeRuntimeOnly closing runtimeOwned notAuthority noPending =>
      intro asset afterOwned
      cases asset <;> simp_all [State.OwnsAsset, State.RuntimeOwns,
        State.AuthorityOwns, State.closeRuntimeOnly]
      exact List.mem_of_mem_erase afterOwned
  | closeManaged closing runtimeOwned authorityOwned noPending allowed =>
      intro asset afterOwned
      cases asset <;> simp_all [State.OwnsAsset, State.RuntimeOwns,
        State.AuthorityOwns, State.closeManaged]
      all_goals exact List.mem_of_mem_erase afterOwned
  | _ =>
      intro asset afterOwned
      cases asset <;> simp [State.OwnsAsset, State.RuntimeOwns,
        State.AuthorityOwns, State.beginRegisteredShutdown,
        State.rejectBeginShutdown, State.beginUnregisteredShutdown,
        State.stopWorkload, State.closeControl, State.unmount,
        State.removeCgroup, State.finishRegisteredShutdown,
        State.finishUnregisteredShutdown] at afterOwned ⊢ <;> assumption

/-- Cleanup cannot release permanent subject or handle tombstones. -/
theorem CleanupStep.preserves_issued {before after : State}
    {result : ResultLabel} (transition : CleanupStep before result after) :
    after.issuedSubjects = before.issuedSubjects ∧
      after.issuedHandles = before.issuedHandles := by
  cases transition with
  | stopWorkloadFailed => exact State.failMutation_preserves_issued before .workload _
  | closeControlFailed => exact State.failMutation_preserves_issued before .control _
  | closeHandleFailed => exact State.failHandleMutation_preserves_issued before _
  | unmountFailed => exact State.failMutation_preserves_issued before .mount _
  | removeCgroupFailed => exact State.failMutation_preserves_issued before .cgroup _
  | _ => exact ⟨rfl, rfl⟩

/-- Every error-returning cleanup stage can be retried from its returned state. -/
theorem CleanupStep.error_retriable {before after : State} {failure : Failure}
    (transition : CleanupStep before (.error failure) after)
    (addressable : failure.Addressable) :
    CleanupStep after (.error failure) after := by
  cases transition with
  | beginRejected known notClosed notBlocked =>
      apply CleanupStep.beginRejected
      · simpa [State.rejectBeginShutdown] using known
      · simp [State.rejectBeginShutdown]
      · simp [State.rejectBeginShutdown]
  | stopWorkloadFailed closing owned =>
      rename_i outcome
      cases outcome
      · exact CleanupStep.stopWorkloadFailed closing owned
      · exact CleanupStep.stopWorkloadFailed closing owned
      · apply CleanupStep.stopWorkloadFailed
        · simp [State.failMutation]
        · simpa [State.failMutation] using owned
  | closeControlFailed closing owned =>
      rename_i outcome
      cases outcome
      · exact CleanupStep.closeControlFailed closing owned
      · exact CleanupStep.closeControlFailed closing owned
      · apply CleanupStep.closeControlFailed
        · simp [State.failMutation]
        · simpa [State.failMutation] using owned
  | closeHandleFailed closing owned =>
      rename_i handleId outcome
      cases outcome
      · exact CleanupStep.closeHandleFailed closing owned
      · exact CleanupStep.closeHandleFailed closing owned
      · apply CleanupStep.closeHandleFailed
        · simp [State.failHandleMutation]
        · simpa [State.failHandleMutation] using owned
  | unmountFailed closing owned =>
      rename_i outcome
      cases outcome
      · exact CleanupStep.unmountFailed closing owned
      · exact CleanupStep.unmountFailed closing owned
      · apply CleanupStep.unmountFailed
        · simp [State.failMutation]
        · simpa [State.failMutation] using owned
  | removeCgroupFailed closing owned =>
      rename_i outcome
      cases outcome
      · exact CleanupStep.removeCgroupFailed closing owned
      · exact CleanupStep.removeCgroupFailed closing owned
      · apply CleanupStep.removeCgroupFailed
        · simp [State.failMutation]
        · simpa [State.failMutation] using owned
  | finishRejected closing =>
      exact CleanupStep.finishRejected closing

/-- Error returns preserve every cleanup token for the retrying owner. -/
theorem CleanupStep.error_preserves_ownership {before after : State}
    {failure : Failure} (transition : CleanupStep before (.error failure) after)
    (addressable : failure.Addressable) :
    ∀ asset, before.OwnsAsset asset ↔ after.OwnsAsset asset := by
  cases transition with
  | beginRejected => intro asset; rfl
  | stopWorkloadFailed closing owned =>
      rename_i outcome
      cases outcome
      · intro asset; rfl
      · intro asset; rfl
      · intro asset
        cases asset <;> simp [State.failMutation, State.OwnsAsset,
          State.RuntimeOwns, State.AuthorityOwns]
  | closeControlFailed closing owned =>
      rename_i outcome
      cases outcome
      · intro asset; rfl
      · intro asset; rfl
      · intro asset
        cases asset <;> simp [State.failMutation, State.OwnsAsset,
          State.RuntimeOwns, State.AuthorityOwns]
  | closeHandleFailed closing owned =>
      rename_i handleId outcome
      cases outcome
      · intro asset; rfl
      · intro asset; rfl
      · intro asset
        cases asset <;> simp [State.failHandleMutation, State.OwnsAsset,
          State.RuntimeOwns, State.AuthorityOwns]
  | unmountFailed closing owned =>
      rename_i outcome
      cases outcome
      · intro asset; rfl
      · intro asset; rfl
      · intro asset
        cases asset <;> simp [State.failMutation, State.OwnsAsset,
          State.RuntimeOwns, State.AuthorityOwns]
  | removeCgroupFailed closing owned =>
      rename_i outcome
      cases outcome
      · intro asset; rfl
      · intro asset; rfl
      · intro asset
        cases asset <;> simp [State.failMutation, State.OwnsAsset,
          State.RuntimeOwns, State.AuthorityOwns]
  | finishRejected => intro asset; rfl

/-- Every cleanup-only transition preserves the conditional refinement invariant. -/
theorem CleanupStep.preserves_invariant {before after : State}
    {result : ResultLabel} (transition : CleanupStep before result after)
    (invariant : before.Invariant) : after.Invariant := by
  cases transition with
  | beginRegistered known notClosed notBlocked registered running canIncrement =>
      have integratedTransition :=
        beginRegisteredShutdown_integratedStep running canIncrement
      constructor
      · exact integratedTransition.preserves_wellFormed
          invariant.integratedWellFormed
      · simpa [State.beginRegisteredShutdown] using invariant.knownSubjectIssued
      · simpa [State.beginRegisteredShutdown, IntegratedHandleState.withAuthority,
          CapabilityState.beginSubjectClose] using invariant.registeredSubjectExact
      · simpa [State.beginRegisteredShutdown, IntegratedHandleState.withAuthority,
          CapabilityState.beginSubjectClose] using invariant.authoritySubjectIssued
      · simpa [State.beginRegisteredShutdown, IntegratedHandleState.withAuthority,
          CapabilityState.beginSubjectClose] using
          invariant.selectedManagedHandleIssued
      · simpa [State.beginRegisteredShutdown] using invariant.runtimeHandlesNodup
      · simpa [State.beginRegisteredShutdown] using invariant.authorityHandlesNodup
      · simpa [State.beginRegisteredShutdown] using invariant.runtimeHandleIssued
      · simpa [State.beginRegisteredShutdown, IntegratedHandleState.withAuthority,
          CapabilityState.beginSubjectClose] using invariant.authorityHandleSound
      · simpa [State.beginRegisteredShutdown] using
          invariant.authorityHandleRuntimeOwned
      · simpa [State.beginRegisteredShutdown] using invariant.pendingRuntimeOwned
      · simpa [State.beginRegisteredShutdown] using invariant.pendingHandleIssued
  | beginRejected known notClosed notBlocked =>
      simpa [State.rejectBeginShutdown] using invariant.updateCleanupFlags
        .closing before.ownsCgroup before.ownsMount before.ownsControl
          before.ownsWorkload
  | beginUnregistered known notClosed notBlocked unregistered =>
      simpa [State.beginUnregisteredShutdown] using invariant.updateCleanupFlags
        .closing before.ownsCgroup before.ownsMount before.ownsControl
          before.ownsWorkload
  | stopWorkload closing owned =>
      simpa [State.stopWorkload] using invariant.updateCleanupFlags
        before.lifecycle before.ownsCgroup before.ownsMount before.ownsControl .none
  | stopWorkloadFailed closing owned =>
      rename_i outcome
      exact invariant.failMutation .workload outcome
  | closeControl closing owned =>
      simpa [State.closeControl] using invariant.updateCleanupFlags
        before.lifecycle before.ownsCgroup before.ownsMount .none before.ownsWorkload
  | closeControlFailed closing owned =>
      rename_i outcome
      exact invariant.failMutation .control outcome
  | closeRuntimeOnly closing runtimeOwned notAuthority noPending =>
      rename_i handleId
      constructor
      · exact invariant.integratedWellFormed
      · simpa [State.closeRuntimeOnly] using invariant.knownSubjectIssued
      · simpa [State.closeRuntimeOnly] using invariant.registeredSubjectExact
      · simpa [State.closeRuntimeOnly] using invariant.authoritySubjectIssued
      · simpa [State.closeRuntimeOnly] using invariant.selectedManagedHandleIssued
      · simpa [State.closeRuntimeOnly] using
          invariant.runtimeHandlesNodup.erase handleId
      · simpa [State.closeRuntimeOnly] using invariant.authorityHandlesNodup
      · intro queriedId remaining
        exact invariant.runtimeHandleIssued queriedId
          (List.mem_of_mem_erase (by simpa [State.closeRuntimeOnly,
            State.RuntimeOwns] using remaining))
      · simpa [State.closeRuntimeOnly] using invariant.authorityHandleSound
      · intro queriedId authorityOwned
        have oldRuntime := invariant.authorityHandleRuntimeOwned queriedId authorityOwned
        have different : queriedId ≠ handleId := by
          intro same
          subst queriedId
          exact notAuthority authorityOwned
        exact (List.mem_erase_of_ne different).2 oldRuntime
      · simp [State.closeRuntimeOnly, noPending]
      · simp [State.closeRuntimeOnly, noPending]
  | closeManaged closing runtimeOwned authorityOwned noPending allowed =>
      rename_i handleId
      constructor
      · exact IntegratedHandleState.closeHandle_preserves_wellFormed
          invariant.integratedWellFormed allowed
      · simpa [State.closeManaged] using invariant.knownSubjectIssued
      · simpa [State.closeManaged, IntegratedHandleState.closeHandle,
          CapabilityState.closeHandle] using invariant.registeredSubjectExact
      · simpa [State.closeManaged, IntegratedHandleState.closeHandle,
          CapabilityState.closeHandle] using invariant.authoritySubjectIssued
      · simpa [State.closeManaged, IntegratedHandleState.closeHandle,
          CapabilityState.closeHandle] using
          invariant.selectedManagedHandleIssued
      · simpa [State.closeManaged] using invariant.runtimeHandlesNodup.erase handleId
      · simpa [State.closeManaged] using
          invariant.authorityHandlesNodup.erase handleId
      · intro queriedId remaining
        exact invariant.runtimeHandleIssued queriedId
          (List.mem_of_mem_erase (by simpa [State.closeManaged,
            State.RuntimeOwns] using remaining))
      · intro queriedId remaining
        have oldAuthority : before.AuthorityOwns queriedId :=
          List.mem_of_mem_erase (by simpa [State.closeManaged,
            State.AuthorityOwns] using remaining)
        rcases invariant.authorityHandleSound queriedId oldAuthority with
          ⟨queriedHandle, oldLookup, subjectMatches, managed⟩
        have different : queriedId ≠ handleId := by
          intro same
          subst queriedId
          exact invariant.authorityHandlesNodup.not_mem_erase
            (by simpa [State.closeManaged, State.AuthorityOwns] using remaining)
        exact ⟨queriedHandle, by simpa [State.closeManaged,
          IntegratedHandleState.closeHandle, CapabilityState.closeHandle,
          replace, different] using oldLookup, subjectMatches, managed⟩
      · intro queriedId remaining
        have oldAuthority : before.AuthorityOwns queriedId :=
          List.mem_of_mem_erase (by simpa [State.closeManaged,
            State.AuthorityOwns] using remaining)
        have oldRuntime := invariant.authorityHandleRuntimeOwned queriedId oldAuthority
        have different : queriedId ≠ handleId := by
          intro same
          subst queriedId
          exact invariant.authorityHandlesNodup.not_mem_erase
            (by simpa [State.closeManaged, State.AuthorityOwns] using remaining)
        exact (List.mem_erase_of_ne different).2 oldRuntime
      · simp [State.closeManaged, noPending]
      · simp [State.closeManaged, noPending]
  | closeHandleFailed closing runtimeOwned =>
      rename_i handleId outcome
      exact invariant.failHandleMutation outcome
  | unmount closing owned noWorkload noControl noHandles =>
      simpa [State.unmount] using invariant.updateCleanupFlags
        before.lifecycle before.ownsCgroup .none before.ownsControl before.ownsWorkload
  | unmountFailed closing owned =>
      rename_i outcome
      exact invariant.failMutation .mount outcome
  | removeCgroup closing owned noWorkload noMount =>
      simpa [State.removeCgroup] using invariant.updateCleanupFlags
        before.lifecycle .none before.ownsMount before.ownsControl before.ownsWorkload
  | removeCgroupFailed closing owned =>
      rename_i outcome
      exact invariant.failMutation .cgroup outcome
  | finishRegistered closing registered noCgroup noMount noControl noWorkload
      noRuntime noAuthority noPending authorityClosing noSubjectHandles =>
      have integratedTransition :=
        finishRegisteredShutdown_integratedStep authorityClosing noSubjectHandles
      constructor
      · exact integratedTransition.preserves_wellFormed
          invariant.integratedWellFormed
      · simpa [State.finishRegisteredShutdown] using invariant.knownSubjectIssued
      · simp [State.finishRegisteredShutdown]
      · simpa [State.finishRegisteredShutdown, IntegratedHandleState.withAuthority,
          CapabilityState.finishSubjectClose] using invariant.authoritySubjectIssued
      · simpa [State.finishRegisteredShutdown, IntegratedHandleState.withAuthority,
          CapabilityState.finishSubjectClose] using
          invariant.selectedManagedHandleIssued
      · simpa [State.finishRegisteredShutdown] using invariant.runtimeHandlesNodup
      · simpa [State.finishRegisteredShutdown] using invariant.authorityHandlesNodup
      · simpa [State.finishRegisteredShutdown] using invariant.runtimeHandleIssued
      · simpa [State.finishRegisteredShutdown, IntegratedHandleState.withAuthority,
          CapabilityState.finishSubjectClose] using invariant.authorityHandleSound
      · simpa [State.finishRegisteredShutdown] using
          invariant.authorityHandleRuntimeOwned
      · simpa [State.finishRegisteredShutdown] using invariant.pendingRuntimeOwned
      · simpa [State.finishRegisteredShutdown] using invariant.pendingHandleIssued
  | finishRejected closing => exact invariant
  | finishUnregistered closing unregistered noCgroup noMount noControl noWorkload
      noRuntime noAuthority noPending =>
      simpa [State.finishUnregisteredShutdown] using invariant.updateCleanupFlags
        .closed before.ownsCgroup before.ownsMount before.ownsControl
          before.ownsWorkload

/-- Complete supervisor transition relation with result-bearing labels. -/
inductive Step : State → ResultLabel → State → Prop
  | create {before after : State} {result : ResultLabel} :
      CreateStep before result after → Step before result after
  | opening {before after : State} {result : ResultLabel} :
      OpenStep before result after → Step before result after
  | cleanup {before after : State} {result : ResultLabel} :
      CleanupStep before result after → Step before result after

/-- One supervisor transition preserves the full scoped refinement invariant. -/
theorem Step.preserves_invariant {before after : State} {result : ResultLabel}
    (transition : Step before result after) (invariant : before.Invariant) :
    after.Invariant := by
  cases transition with
  | create createTransition =>
      exact createTransition.preserves_invariant invariant
  | opening openTransition =>
      exact openTransition.preserves_invariant invariant
  | cleanup cleanupTransition =>
      exact cleanupTransition.preserves_invariant invariant

/-- `cleanupBlocked` is terminal for the complete modeled supervisor relation. -/
theorem Step.cleanupBlocked_terminal {state : State}
    (blocked : state.lifecycle = .cleanupBlocked) :
    ¬ ∃ result after, Step state result after := by
  rintro ⟨result, after, transition⟩
  cases transition with
  | create createTransition => cases createTransition <;> simp_all
  | opening openTransition => cases openTransition <;> simp_all
  | cleanup cleanupTransition =>
      exact cleanupBlocked_is_terminal blocked ⟨result, after, cleanupTransition⟩

/-- Local subject and handle tombstones only grow. -/
def TombstonesExtend (before after : State) : Prop :=
  (∀ subjectId, before.issuedSubjects subjectId = true →
    after.issuedSubjects subjectId = true) ∧
  (∀ handleId, before.issuedHandles handleId = true →
    after.issuedHandles handleId = true)

/-- Every creation stage preserves all previously issued identities. -/
theorem CreateStep.tombstones_extend {before after : State}
    {result : ResultLabel} (transition : CreateStep before result after) :
    TombstonesExtend before after := by
  cases transition with
  | acquisitionFailed creating unregistered =>
      rename_i resource outcome
      have preserved := State.failAcquisition_preserves_issued before resource outcome
      exact ⟨fun identity issued => by rw [preserved.1]; exact issued,
        fun identity issued => by rw [preserved.2]; exact issued⟩
  | _ =>
      constructor <;> intro identity issued <;>
        simp_all [TombstonesExtend, State.reserveSubject, State.acquireCgroup,
          State.acquireMount, State.acquireControl, State.registerSubject,
          State.startWorkload, State.publishRunning, State.failRegisteredCreate,
          replace]

/-- Every open stage preserves all tombstones, including failed registrations. -/
theorem OpenStep.tombstones_extend {before after : State}
    {result : ResultLabel} (transition : OpenStep before result after) :
    TombstonesExtend before after := by
  cases transition <;> constructor <;> intro identity issued <;>
    simp_all [TombstonesExtend, State.beginOpen, State.commitOpen,
      State.failOpenClean, State.failOpenRetained, State.failOpenUnknown, replace]

/-- Cleanup never removes a subject or handle tombstone. -/
theorem CleanupStep.tombstones_extend {before after : State}
    {result : ResultLabel} (transition : CleanupStep before result after) :
    TombstonesExtend before after := by
  have preserved := transition.preserves_issued
  constructor
  · intro subjectId issued
    rw [preserved.1]
    exact issued
  · intro handleId issued
    rw [preserved.2]
    exact issued

/-- Every complete supervisor transition permanently preserves issued identities. -/
theorem Step.tombstones_extend {before after : State} {result : ResultLabel}
    (transition : Step before result after) : TombstonesExtend before after := by
  cases transition with
  | create createTransition => exact createTransition.tombstones_extend
  | opening openTransition => exact openTransition.tombstones_extend
  | cleanup cleanupTransition => exact cleanupTransition.tombstones_extend

/-- Supervisor operations do not consume the Authority capability allocator. -/
theorem Step.preserves_allocator_state {before after : State}
    {result : ResultLabel} (transition : Step before result after) :
    after.integrated.authority.nextCapabilitySequence =
        before.integrated.authority.nextCapabilitySequence ∧
      after.integrated.authority.capabilityIdsExhausted =
        before.integrated.authority.capabilityIdsExhausted := by
  cases transition with
  | create createTransition =>
      cases createTransition with
      | acquisitionFailed creating unregistered =>
          rename_i resource outcome
          exact State.failAcquisition_preserves_allocator before resource outcome
      | _ => exact ⟨rfl, rfl⟩
  | opening openTransition => cases openTransition <;> exact ⟨rfl, rfl⟩
  | cleanup cleanupTransition =>
      cases cleanupTransition with
      | stopWorkloadFailed =>
          exact State.failMutation_preserves_allocator before .workload _
      | closeControlFailed =>
          exact State.failMutation_preserves_allocator before .control _
      | closeHandleFailed =>
          exact State.failHandleMutation_preserves_allocator before _
      | unmountFailed =>
          exact State.failMutation_preserves_allocator before .mount _
      | removeCgroupFailed =>
          exact State.failMutation_preserves_allocator before .cgroup _
      | _ => exact ⟨rfl, rfl⟩

/-- An arbitrary finite supervisor execution hides intermediate result labels. -/
inductive Steps : State → State → Prop
  | refl (state : State) : Steps state state
  | tail {first middle last : State} {result : ResultLabel} :
      Steps first middle → Step middle result last → Steps first last

/-- Concatenate two arbitrary finite supervisor executions. -/
theorem Steps.trans {first middle last : State}
    (earlier : Steps first middle) (later : Steps middle last) : Steps first last := by
  induction later with
  | refl => exact earlier
  | tail _ transition inductionHypothesis =>
      exact Steps.tail inductionHypothesis transition

/-- The scoped refinement invariant survives every finite supervisor execution. -/
theorem Steps.preserves_invariant {before after : State}
    (transitions : Steps before after) (invariant : before.Invariant) :
    after.Invariant := by
  induction transitions with
  | refl => exact invariant
  | tail _ transition inductionHypothesis =>
      exact transition.preserves_invariant inductionHypothesis

/-- Permanent subject and handle tombstones survive every finite execution. -/
theorem Steps.tombstones_extend {before after : State}
    (transitions : Steps before after) : TombstonesExtend before after := by
  induction transitions with
  | refl => exact ⟨fun _ issued => issued, fun _ issued => issued⟩
  | tail _ transition inductionHypothesis =>
      rcases inductionHypothesis with ⟨subjectsEarlier, handlesEarlier⟩
      rcases transition.tombstones_extend with ⟨subjectsLast, handlesLast⟩
      exact ⟨fun subjectId issued => subjectsLast subjectId
          (subjectsEarlier subjectId issued),
        fun handleId issued => handlesLast handleId
          (handlesEarlier handleId issued)⟩

/-- No finite supervisor execution consumes or exhausts the capability allocator. -/
theorem Steps.preserves_allocator_state {before after : State}
    (transitions : Steps before after) :
    after.integrated.authority.nextCapabilitySequence =
        before.integrated.authority.nextCapabilitySequence ∧
      after.integrated.authority.capabilityIdsExhausted =
        before.integrated.authority.capabilityIdsExhausted := by
  induction transitions with
  | refl => exact ⟨rfl, rfl⟩
  | tail _ transition inductionHypothesis =>
      exact ⟨transition.preserves_allocator_state.1.trans inductionHypothesis.1,
        transition.preserves_allocator_state.2.trans inductionHypothesis.2⟩

/-- A cleanly compensated failed open cannot make its reserved ID reusable. -/
theorem failed_open_clean_tombstone_persists {state : State}
    {handle : OpenHandle} (invariant : state.Invariant)
    (pending : state.pendingOpen = some handle) {after : State}
    (suffix : Steps (state.failOpenClean handle) after) :
    after.issuedHandles handle.id = true := by
  have issued := invariant.pendingHandleIssued handle pending
  exact suffix.tombstones_extend.2 handle.id (by
    simpa [State.failOpenClean] using issued)

/-- A cleanup-retaining failed open cannot make its reserved ID reusable. -/
theorem failed_open_retained_tombstone_persists {state : State}
    {handle : OpenHandle} (invariant : state.Invariant)
    (pending : state.pendingOpen = some handle) {after : State}
    (suffix : Steps (state.failOpenRetained handle) after) :
    after.issuedHandles handle.id = true := by
  have issued := invariant.pendingHandleIssued handle pending
  exact suffix.tombstones_extend.2 handle.id (by
    simpa [State.failOpenRetained] using issued)

/-- Retryable unknown compensation keeps the consumed handle permanent. -/
theorem failed_open_unknown_tombstone_persists {state : State}
    {handle : OpenHandle} (invariant : state.Invariant)
    (pending : state.pendingOpen = some handle) {after : State}
    (suffix : Steps (state.failOpenUnknown handle) after) :
    after.issuedHandles handle.id = true := by
  have issued := invariant.pendingHandleIssued handle pending
  exact suffix.tombstones_extend.2 handle.id (by
    simpa [State.failOpenUnknown] using issued)

/-- Supervisor reachability begins only from the concrete paired initial state. -/
def Reachable (state : State) : Prop :=
  ∃ issuer subjectId, Steps (State.initial issuer subjectId) state

/-- Concrete initialization is constructively reachable. -/
theorem initial_reachable (issuer : IssuerId) (subjectId : SubjectId) :
    Reachable (State.initial issuer subjectId) :=
  ⟨issuer, subjectId, Steps.refl _⟩

/-- Every supervisor-reachable state exports scoped exactness and counter bounds. -/
theorem Reachable.invariant {state : State} (reachable : Reachable state) :
    state.Invariant := by
  rcases reachable with ⟨issuer, subjectId, transitions⟩
  exact transitions.preserves_invariant (State.initial_invariant issuer subjectId)

/-- Reachability is closed under any finite suffix, not merely one transition. -/
theorem Reachable.steps {before after : State} (reachable : Reachable before)
    (transitions : Steps before after) : Reachable after := by
  rcases reachable with ⟨issuer, subjectId, earlier⟩
  exact ⟨issuer, subjectId, earlier.trans transitions⟩

/-- Reachable states expose both Authority and namespace machine-counter bounds. -/
theorem Reachable.countersRepresentable {state : State}
    (reachable : Reachable state) :
    state.integrated.authority.CountersRepresentable ∧
      state.integrated.namespaceState.CountersRepresentable :=
  ⟨reachable.invariant.integratedWellFormed.authorityCountersRepresentable,
    reachable.invariant.integratedWellFormed.namespaceCountersRepresentable⟩

/-- Reachability keeps the Authority allocator cursor representable by `u64`. -/
theorem Reachable.allocatorCursorValid {state : State}
    (reachable : Reachable state) :
    FitsU64 state.integrated.authority.nextCapabilitySequence :=
  reachable.countersRepresentable.1.2

/-- Concrete supervisor reachability leaves the capability allocator unused. -/
theorem Reachable.allocatorUnused {state : State} (reachable : Reachable state) :
    state.integrated.authority.nextCapabilitySequence = 0 ∧
      state.integrated.authority.capabilityIdsExhausted = false := by
  rcases reachable with ⟨issuer, subjectId, transitions⟩
  have preserved := transitions.preserves_allocator_state
  simpa [State.initial, IntegratedHandleState.initial,
    IntegratedHandleState.initializeClosed, CapabilityState.empty] using preserved

namespace State

/-- Concrete setup failure that retains an addressable cgroup cleanup token. -/
def cleanupRequiredInitial (issuer : IssuerId) (subjectId : SubjectId) : State :=
  (initial issuer subjectId).reserveSubject.failAcquisition .cgroup .cleanupRequired

/-- Concrete setup failure whose cgroup effect requires external reconciliation. -/
def effectUnknownInitial (issuer : IssuerId) (subjectId : SubjectId) : State :=
  (initial issuer subjectId).reserveSubject.failAcquisition .cgroup .effectUnknown

/-- Concrete supervisor state immediately after Authority registration. -/
def registeredInitial (issuer : IssuerId) (subjectId : SubjectId) : State :=
  registerSubject (acquireControl
    (acquireMount (acquireCgroup (reserveSubject (initial issuer subjectId)))))

/-- Concrete supervisor state after all successful create stages. -/
def runningInitial (issuer : IssuerId) (subjectId : SubjectId) : State :=
  publishRunning (startWorkload (registeredInitial issuer subjectId))

/-- Concrete registered setup failure retaining cleanup ownership. -/
def failedRegisteredInitial (issuer : IssuerId) (subjectId : SubjectId) : State :=
  failRegisteredCreate (registeredInitial issuer subjectId)

/-- Concrete successfully opened supervisor state. -/
def openedInitial (issuer : IssuerId) (subjectId : SubjectId)
    (handleId : HandleId) : State :=
  let handle := IntegratedHandleState.startupRootHandle subjectId handleId
  commitOpen (beginOpen (runningInitial issuer subjectId) handle) handle
    (NamespaceState.rootObject (NamespaceState.allocatedObjectId 0))

/-- Concrete shutdown completion after releasing all local resources. -/
def closedInitial (issuer : IssuerId) (subjectId : SubjectId) : State :=
  finishRegisteredShutdown (removeCgroup (unmount (closeControl
    (stopWorkload (beginRegisteredShutdown (runningInitial issuer subjectId))))))

end State

/-- Both partial-acquisition error outcomes occur in ordinary finite executions. -/
theorem acquisitionFailureStates_reachable (issuer : IssuerId)
    (subjectId : SubjectId) :
    Reachable (State.cleanupRequiredInitial issuer subjectId) ∧
      Reachable (State.effectUnknownInitial issuer subjectId) := by
  let initial := State.initial issuer subjectId
  let reserved := initial.reserveSubject
  have reserveStep : Step initial (.ok .reserveSubject) reserved :=
    .create (CreateStep.reserve (by rfl) (by rfl) (by rfl))
  have setupPrefix : Steps initial reserved :=
    Steps.tail (Steps.refl initial) reserveStep
  constructor
  · apply (initial_reachable issuer subjectId).steps
    simpa [initial, reserved, State.cleanupRequiredInitial] using
      (Steps.tail setupPrefix
        (Step.create (CreateStep.acquisitionFailed
          (state := reserved) (resource := .cgroup)
          (outcome := .cleanupRequired) (by rfl) (by rfl))))
  · apply (initial_reachable issuer subjectId).steps
    simpa [initial, reserved, State.effectUnknownInitial] using
      (Steps.tail setupPrefix
        (Step.create (CreateStep.acquisitionFailed
          (state := reserved) (resource := .cgroup)
          (outcome := .effectUnknown) (by rfl) (by rfl))))

/-- The concrete unknown-effect setup witness is terminal and still invariant. -/
theorem effectUnknownInitial_terminal (issuer : IssuerId) (subjectId : SubjectId) :
    Reachable (State.effectUnknownInitial issuer subjectId) ∧
      (State.effectUnknownInitial issuer subjectId).Invariant ∧
      ¬ ∃ result after,
        CleanupStep (State.effectUnknownInitial issuer subjectId) result after := by
  have reachable := (acquisitionFailureStates_reachable issuer subjectId).2
  exact ⟨reachable, reachable.invariant,
    cleanupBlocked_is_terminal (by
      simp [State.effectUnknownInitial, State.failAcquisition,
        State.setResource])⟩

/-- Concrete empty setup admits the full successful create execution. -/
theorem runningInitial_steps (issuer : IssuerId) (subjectId : SubjectId) :
    Steps (State.initial issuer subjectId) (State.runningInitial issuer subjectId) := by
  let s0 := State.initial issuer subjectId
  let s1 := s0.reserveSubject
  let s2 := s1.acquireCgroup
  let s3 := s2.acquireMount
  let s4 := s3.acquireControl
  let s5 := s4.registerSubject
  let s6 := s5.startWorkload
  let s7 := s6.publishRunning
  have registerAllowed : s4.integrated.authority.MayRegisterSubject s4.subject := by
    simpa [s4, s3, s2, s1, s0, State.acquireControl, State.acquireMount,
      State.acquireCgroup, State.reserveSubject, State.initial] using
      IntegratedHandleState.initialMayRegisterSubject issuer subjectId
  have t1 : Steps s0 s1 := Steps.tail (Steps.refl s0)
    (.create (CreateStep.reserve (by rfl) (by rfl) (by rfl)))
  have t2 : Steps s0 s2 := Steps.tail t1
    (.create (CreateStep.acquireCgroup (by rfl) (by rfl) (by rfl)))
  have t3 : Steps s0 s3 := Steps.tail t2
    (.create (CreateStep.acquireMount (by rfl) (by rfl) (by rfl) (by rfl)))
  have t4 : Steps s0 s4 := Steps.tail t3
    (.create (CreateStep.acquireControl (by rfl) (by rfl) (by rfl) (by rfl)))
  have t5 : Steps s0 s5 := Steps.tail t4
    (.create (CreateStep.registerSubject (by rfl) (by rfl) (by rfl)
      registerAllowed))
  have t6 : Steps s0 s6 := Steps.tail t5
    (.create (CreateStep.startWorkload (by rfl) (by rfl) (by rfl)
      (by rfl) (by rfl) (by rfl) (by rfl)))
  have runningStatus : s6.integrated.authority.subjectStatuses s6.subject.id =
      some .running := by
    simpa [s6, s5, State.startWorkload, State.registerSubject,
      IntegratedHandleState.withAuthority] using
      CapabilityState.registerSubject_starts_running s4.integrated.authority
        s4.subject
  have t7 : Steps s0 s7 := Steps.tail t6
    (.create (CreateStep.publish (by rfl) (by rfl) (by rfl) (by rfl)
      (by rfl) (by rfl) (by rfl) (by rfl) runningStatus))
  simpa [s0, s1, s2, s3, s4, s5, s6, s7,
    State.runningInitial] using t7

/-- A fully running concrete supervisor is ordinarily reachable and well formed. -/
theorem runningInitial_reachable (issuer : IssuerId) (subjectId : SubjectId) :
    Reachable (State.runningInitial issuer subjectId) :=
  (initial_reachable issuer subjectId).steps (runningInitial_steps issuer subjectId)

/-- A registered create failure is concretely reachable through an error result. -/
theorem failedRegisteredInitial_reachable (issuer : IssuerId)
    (subjectId : SubjectId) : Reachable (State.failedRegisteredInitial issuer subjectId) := by
  let registered := State.registeredInitial issuer subjectId
  have createPrefix : Steps (State.initial issuer subjectId) registered := by
    let s0 := State.initial issuer subjectId
    let s1 := s0.reserveSubject
    let s2 := s1.acquireCgroup
    let s3 := s2.acquireMount
    let s4 := s3.acquireControl
    have allowed : s4.integrated.authority.MayRegisterSubject s4.subject := by
      simpa [s4, s3, s2, s1, s0, State.acquireControl, State.acquireMount,
        State.acquireCgroup, State.reserveSubject, State.initial] using
        IntegratedHandleState.initialMayRegisterSubject issuer subjectId
    have t1 : Steps s0 s1 := Steps.tail (Steps.refl s0)
      (.create (CreateStep.reserve (by rfl) (by rfl) (by rfl)))
    have t2 : Steps s0 s2 := Steps.tail t1
      (.create (CreateStep.acquireCgroup (by rfl) (by rfl) (by rfl)))
    have t3 : Steps s0 s3 := Steps.tail t2
      (.create (CreateStep.acquireMount (by rfl) (by rfl) (by rfl) (by rfl)))
    have t4 : Steps s0 s4 := Steps.tail t3
      (.create (CreateStep.acquireControl (by rfl) (by rfl) (by rfl) (by rfl)))
    simpa [registered, State.registeredInitial, s4, s3, s2, s1, s0] using
      (Steps.tail t4
        (Step.create (CreateStep.registerSubject (by rfl) (by rfl) (by rfl)
          allowed)))
  apply (initial_reachable issuer subjectId).steps
  apply Steps.tail createPrefix
  simpa [registered, State.failedRegisteredInitial] using
    (Step.create (CreateStep.failAfterRegistration (state := registered)
      (by rfl) (by rfl) (by rfl)))

/-- Every suffix after registered setup failure retains the subject tombstone. -/
theorem failedRegisteredInitial_subject_tombstone_persists
    (issuer : IssuerId) (subjectId : SubjectId) {after : State}
    (suffix : Steps (State.failedRegisteredInitial issuer subjectId) after) :
    after.issuedSubjects subjectId = true := by
  have initiallyIssued :
      (State.failedRegisteredInitial issuer subjectId).issuedSubjects subjectId = true := by
    simp [State.failedRegisteredInitial, State.registeredInitial,
      State.failRegisteredCreate,
      State.registerSubject, State.acquireControl, State.acquireMount,
      State.acquireCgroup, State.reserveSubject, State.initial,
      IntegratedHandleState.startupSubject]
  exact suffix.tombstones_extend.1 subjectId initiallyIssued

/-- The concrete running state admits one successful two-stage managed open. -/
theorem openedInitial_reachable (issuer : IssuerId) (subjectId : SubjectId)
    (handleId : HandleId) : Reachable (State.openedInitial issuer subjectId handleId) := by
  let running := State.runningInitial issuer subjectId
  let handle := IntegratedHandleState.startupRootHandle subjectId handleId
  let begun := running.beginOpen handle
  have mayOpen : begun.integrated.MayOpen handle := by
    simpa [begun, running, State.runningInitial, State.beginOpen,
      State.publishRunning, State.startWorkload, State.registerSubject,
      State.acquireControl, State.acquireMount, State.acquireCgroup,
      State.reserveSubject, State.initial, IntegratedHandleState.readyInitial] using
      IntegratedHandleState.readyInitialMayOpen issuer subjectId handleId
  have exactObject : mayOpen.object =
      NamespaceState.rootObject (NamespaceState.allocatedObjectId 0) := by
    have rootLookup : begun.integrated.namespaceState.objects handle.object =
        some (NamespaceState.rootObject (NamespaceState.allocatedObjectId 0)) := by
      simp [begun, running, handle, State.beginOpen, State.runningInitial,
        State.registeredInitial, State.publishRunning, State.startWorkload,
        State.registerSubject, State.acquireControl, State.acquireMount,
        State.acquireCgroup, State.reserveSubject, State.initial,
        IntegratedHandleState.withAuthority, IntegratedHandleState.initial,
        IntegratedHandleState.initializeClosed,
        IntegratedHandleState.startupRootHandle, NamespaceState.runtimeInitial,
        NamespaceState.withRoot, replace]
    exact Option.some.inj (mayOpen.objectLookup.symm.trans rootLookup)
  have began : Step running (.ok .openRuntimeHandle) begun :=
    Step.opening (OpenStep.openRuntime
      (by simp [running, State.runningInitial, State.registeredInitial,
        State.publishRunning, State.startWorkload, State.registerSubject,
        State.acquireControl, State.acquireMount, State.acquireCgroup,
        State.reserveSubject, State.initial])
      (by simp [running, State.runningInitial, State.publishRunning])
      (by simp [running, State.runningInitial, State.registeredInitial,
        State.publishRunning, State.startWorkload, State.registerSubject,
        State.acquireControl, State.acquireMount, State.acquireCgroup,
        State.reserveSubject, State.initial])
      (by simp [handle, running, State.runningInitial, State.registeredInitial,
        State.publishRunning, State.startWorkload, State.registerSubject,
        State.acquireControl, State.acquireMount, State.acquireCgroup,
        State.reserveSubject, State.initial,
        IntegratedHandleState.startupRootHandle,
        IntegratedHandleState.startupSubject])
      (by simp [running, State.runningInitial, State.registeredInitial,
        State.publishRunning, State.startWorkload, State.registerSubject,
        State.acquireControl, State.acquireMount, State.acquireCgroup,
        State.reserveSubject, State.initial]))
  have committed : Step begun (.ok .registerManagedHandle)
      (State.openedInitial issuer subjectId handleId) := by
    simpa [State.openedInitial, running, handle, begun, exactObject] using
      (Step.opening (OpenStep.registerManaged
        (state := begun) (handle := handle)
        (by simp [begun, running, State.beginOpen, State.runningInitial,
          State.registeredInitial, State.publishRunning, State.startWorkload,
          State.registerSubject, State.acquireControl, State.acquireMount,
          State.acquireCgroup, State.reserveSubject, State.initial])
        (by simp [begun, running, State.beginOpen, State.runningInitial,
          State.publishRunning])
        (by simp [begun, State.beginOpen])
        (by simp [begun, handle, running, State.beginOpen,
          State.runningInitial, State.registeredInitial, State.publishRunning,
          State.startWorkload, State.registerSubject, State.acquireControl,
          State.acquireMount, State.acquireCgroup, State.reserveSubject,
          State.initial, IntegratedHandleState.startupRootHandle,
          IntegratedHandleState.startupSubject])
        (by simp [begun, running, State.beginOpen, State.runningInitial,
          State.registeredInitial, State.publishRunning, State.startWorkload,
          State.registerSubject, State.acquireControl, State.acquireMount,
          State.acquireCgroup, State.reserveSubject, State.initial]) mayOpen))
  exact (runningInitial_reachable issuer subjectId).steps
    (Steps.tail (Steps.tail (Steps.refl running) began) committed)

/-- The concrete running state can complete ordered shutdown with no handles. -/
theorem closedInitial_reachable (issuer : IssuerId) (subjectId : SubjectId) :
    Reachable (State.closedInitial issuer subjectId) := by
  let running := State.runningInitial issuer subjectId
  let closing := running.beginRegisteredShutdown
  let stopped := closing.stopWorkload
  let controlClosed := stopped.closeControl
  let unmounted := controlClosed.unmount
  let cgroupRemoved := unmounted.removeCgroup
  have canIncrement : CanIncrementU64
      running.integrated.authority.authorizationEpoch := by
    simpa [running, State.runningInitial, State.registeredInitial,
      State.publishRunning, State.startWorkload, State.registerSubject,
      State.acquireControl, State.acquireMount, State.acquireCgroup,
      State.reserveSubject, State.initial, IntegratedHandleState.withAuthority,
      IntegratedHandleState.initial, IntegratedHandleState.initializeClosed,
      CapabilityState.registerSubject, CapabilityState.empty,
      CanIncrementU64] using (show 0 < u64Maximum by decide)
  have runningStatus : running.integrated.authority.subjectStatuses
      running.subject.id = some .running := by
    simpa [running, State.runningInitial, State.registeredInitial,
      State.publishRunning, State.startWorkload, State.registerSubject,
      IntegratedHandleState.withAuthority] using
      CapabilityState.registerSubject_starts_running
        (State.acquireControl (State.acquireMount (State.acquireCgroup
          (State.reserveSubject (State.initial issuer subjectId))))).integrated.authority
        (State.acquireControl (State.acquireMount (State.acquireCgroup
          (State.reserveSubject (State.initial issuer subjectId))))).subject
  have beginStep : Step running (.ok .beginShutdown) closing :=
    .cleanup (CleanupStep.beginRegistered
      (by simp [running, State.runningInitial, State.registeredInitial,
        State.publishRunning, State.startWorkload, State.registerSubject,
        State.acquireControl, State.acquireMount, State.acquireCgroup,
        State.reserveSubject, State.initial])
      (by simp [running, State.runningInitial, State.publishRunning])
      (by simp [running, State.runningInitial, State.publishRunning])
      (by simp [running, State.runningInitial, State.registeredInitial,
        State.publishRunning, State.startWorkload, State.registerSubject])
      runningStatus canIncrement)
  have stopStep : Step closing (.ok .stopWorkload) stopped :=
    .cleanup (CleanupStep.stopWorkload
      (by simp [closing, State.beginRegisteredShutdown])
      (by simp [closing, running, State.beginRegisteredShutdown,
        State.runningInitial, State.registeredInitial, State.publishRunning,
        State.startWorkload, State.registerSubject, State.acquireControl,
        State.acquireMount, State.acquireCgroup, State.reserveSubject,
        State.initial]))
  have controlStep : Step stopped (.ok .closeControl) controlClosed :=
    .cleanup (CleanupStep.closeControl
      (by simp [stopped, closing, State.stopWorkload,
        State.beginRegisteredShutdown])
      (by simp [stopped, closing, running, State.stopWorkload,
        State.beginRegisteredShutdown, State.runningInitial,
        State.registeredInitial, State.publishRunning, State.startWorkload,
        State.registerSubject, State.acquireControl, State.acquireMount,
        State.acquireCgroup, State.reserveSubject, State.initial]))
  have unmountStep : Step controlClosed (.ok .unmount) unmounted :=
    .cleanup (CleanupStep.unmount
      (by simp [controlClosed, stopped, closing, State.closeControl,
        State.stopWorkload, State.beginRegisteredShutdown])
      (by simp [controlClosed, stopped, closing, running, State.closeControl,
        State.stopWorkload, State.beginRegisteredShutdown,
        State.runningInitial, State.registeredInitial, State.publishRunning,
        State.startWorkload, State.registerSubject, State.acquireControl,
        State.acquireMount, State.acquireCgroup, State.reserveSubject,
        State.initial])
      (by simp [controlClosed, stopped, State.closeControl, State.stopWorkload])
      (by simp [controlClosed, State.closeControl])
      (by simp [controlClosed, stopped, closing, running, State.closeControl,
        State.stopWorkload, State.beginRegisteredShutdown,
        State.runningInitial, State.registeredInitial, State.publishRunning,
        State.startWorkload, State.registerSubject, State.acquireControl,
        State.acquireMount, State.acquireCgroup, State.reserveSubject,
        State.initial]))
  have cgroupStep : Step unmounted (.ok .removeCgroup) cgroupRemoved :=
    .cleanup (CleanupStep.removeCgroup
      (by simp [unmounted, controlClosed, stopped, closing, State.unmount,
        State.closeControl, State.stopWorkload, State.beginRegisteredShutdown])
      (by simp [unmounted, controlClosed, stopped, closing, running,
        State.unmount, State.closeControl, State.stopWorkload,
        State.beginRegisteredShutdown, State.runningInitial,
        State.registeredInitial, State.publishRunning, State.startWorkload,
        State.registerSubject, State.acquireControl, State.acquireMount,
        State.acquireCgroup, State.reserveSubject, State.initial])
      (by simp [unmounted, controlClosed, stopped, State.unmount,
        State.closeControl, State.stopWorkload])
      (by simp [unmounted, State.unmount]))
  have authorityClosing : cgroupRemoved.integrated.authority.subjectStatuses
      cgroupRemoved.subject.id = some .closing := by
    simpa [cgroupRemoved, unmounted, controlClosed, stopped, closing,
      State.removeCgroup, State.unmount, State.closeControl,
      State.stopWorkload, State.beginRegisteredShutdown,
      IntegratedHandleState.withAuthority] using
      CapabilityState.beginSubjectClose_sets_closing
        running.integrated.authority running.subject.id
  have noHandles : ∀ queriedId queriedHandle,
      cgroupRemoved.integrated.authority.openHandles queriedId = some queriedHandle →
        queriedHandle.subject ≠ cgroupRemoved.subject.id := by
    intro queriedId queriedHandle lookup
    simp [cgroupRemoved, unmounted, controlClosed, stopped, closing, running,
      State.removeCgroup, State.unmount, State.closeControl,
      State.stopWorkload, State.beginRegisteredShutdown,
      State.runningInitial, State.registeredInitial, State.publishRunning,
      State.startWorkload, State.registerSubject, State.acquireControl,
      State.acquireMount, State.acquireCgroup, State.reserveSubject,
      State.initial, IntegratedHandleState.withAuthority,
      IntegratedHandleState.initial, IntegratedHandleState.initializeClosed,
      CapabilityState.beginSubjectClose, CapabilityState.registerSubject,
      CapabilityState.empty] at lookup
  have finishStep : Step cgroupRemoved (.ok .finishShutdown)
      (State.closedInitial issuer subjectId) := by
    simpa [State.closedInitial, running, closing, stopped, controlClosed,
      unmounted, cgroupRemoved] using
      (Step.cleanup (CleanupStep.finishRegistered
        (state := cgroupRemoved)
        (by simp [cgroupRemoved, unmounted, controlClosed, stopped, closing,
          State.removeCgroup, State.unmount, State.closeControl,
          State.stopWorkload, State.beginRegisteredShutdown])
        (by simp [cgroupRemoved, unmounted, controlClosed, stopped, closing,
          running, State.removeCgroup, State.unmount, State.closeControl,
          State.stopWorkload, State.beginRegisteredShutdown,
          State.runningInitial, State.registeredInitial, State.publishRunning,
          State.startWorkload, State.registerSubject])
        (by simp [cgroupRemoved, State.removeCgroup])
        (by simp [cgroupRemoved, unmounted, State.removeCgroup, State.unmount])
        (by simp [cgroupRemoved, unmounted, controlClosed, State.removeCgroup,
          State.unmount, State.closeControl])
        (by simp [cgroupRemoved, unmounted, controlClosed, stopped,
          State.removeCgroup, State.unmount, State.closeControl,
          State.stopWorkload])
        (by simp [cgroupRemoved, unmounted, controlClosed, stopped, closing,
          running, State.removeCgroup, State.unmount, State.closeControl,
          State.stopWorkload, State.beginRegisteredShutdown,
          State.runningInitial, State.registeredInitial, State.publishRunning,
          State.startWorkload, State.registerSubject, State.acquireControl,
          State.acquireMount, State.acquireCgroup, State.reserveSubject,
          State.initial])
        (by simp [cgroupRemoved, unmounted, controlClosed, stopped, closing,
          running, State.removeCgroup, State.unmount, State.closeControl,
          State.stopWorkload, State.beginRegisteredShutdown,
          State.runningInitial, State.registeredInitial, State.publishRunning,
          State.startWorkload, State.registerSubject, State.acquireControl,
          State.acquireMount, State.acquireCgroup, State.reserveSubject,
          State.initial])
        (by simp [cgroupRemoved, unmounted, controlClosed, stopped, closing,
          running, State.removeCgroup, State.unmount, State.closeControl,
          State.stopWorkload, State.beginRegisteredShutdown,
          State.runningInitial, State.registeredInitial, State.publishRunning,
          State.startWorkload, State.registerSubject, State.acquireControl,
          State.acquireMount, State.acquireCgroup, State.reserveSubject,
          State.initial]) authorityClosing noHandles))
  have shutdown : Steps running (State.closedInitial issuer subjectId) :=
    Steps.tail (Steps.tail (Steps.tail (Steps.tail (Steps.tail
      (Steps.tail (Steps.refl running) beginStep) stopStep) controlStep)
      unmountStep) cgroupStep) finishStep
  exact (runningInitial_reachable issuer subjectId).steps shutdown

/-- Reachability is non-vacuous at setup, live operation, and terminal cleanup. -/
theorem concrete_reachability_nonempty (issuer : IssuerId) (subjectId : SubjectId)
    (handleId : HandleId) :
    Reachable (State.runningInitial issuer subjectId) ∧
      Reachable (State.openedInitial issuer subjectId handleId) ∧
      Reachable (State.closedInitial issuer subjectId) :=
  ⟨runningInitial_reachable issuer subjectId,
    openedInitial_reachable issuer subjectId handleId,
    closedInitial_reachable issuer subjectId⟩

end SupervisorRefinement
end Authority
