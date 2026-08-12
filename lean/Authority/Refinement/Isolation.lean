import Authority.Isolation

/-!
# Runtime-Isolation Platform Refinement

Kernel namespace observations are checked before they are related to the pure
coordinator model. Facts about the actual process namespace require an explicit
observation-source accuracy proposition; no theorem assumes kernel or adapter
honesty implicitly.
-/

namespace Authority

namespace Isolation

namespace Refinement

/-- Stable kernel identity of one namespace inode. -/
structure NamespaceIdentity where
  device : Nat
  inode : Nat
  deriving Repr, BEq, DecidableEq

/-- Checkable preparation and child-process PID namespace observations. -/
structure PidNamespaceObservation where
  preparedParent : NamespaceIdentity
  preparedChild : NamespaceIdentity
  observedCurrent : NamespaceIdentity
  observedForChildren : NamespaceIdentity
  deriving Repr, BEq, DecidableEq

/--
All child-side namespace handles must identify the prepared child namespace,
which must remain distinct from the preparing parent's namespace.
-/
def PidNamespaceObservation.IdentitiesMatch
    (observation : PidNamespaceObservation) : Prop :=
  observation.preparedParent ≠ observation.preparedChild ∧
    observation.observedCurrent = observation.preparedChild ∧
    observation.observedForChildren = observation.preparedChild ∧
    observation.observedCurrent = observation.observedForChildren ∧
    observation.observedCurrent ≠ observation.preparedParent ∧
    observation.observedForChildren ≠ observation.preparedParent

/-- Exact namespace identity matching is decidable from captured kernel identities. -/
instance (observation : PidNamespaceObservation) : Decidable observation.IdentitiesMatch := by
  unfold PidNamespaceObservation.IdentitiesMatch
  infer_instance

/-- Executable checker for exact parent/prepared-child/current/for-children identity relations. -/
def PidNamespaceObservation.checks (observation : PidNamespaceObservation) : Bool :=
  decide observation.IdentitiesMatch

/-- The executable checker accepts exactly the complete identity relation. -/
theorem PidNamespaceObservation.checks_eq_true_iff
    (observation : PidNamespaceObservation) :
    observation.checks = true ↔ observation.IdentitiesMatch := by
  simp only [PidNamespaceObservation.checks, decide_eq_true_eq]

/-- Actual platform state relevant to the workload child's PID namespace. -/
structure NamespacePlatformState where
  current : NamespaceIdentity
  forChildren : NamespaceIdentity
  deriving Repr, BEq, DecidableEq

/-- Exact safety premises needed before recording PID-child entry in the model. -/
structure PidNamespaceSafetyPremises (observation : PidNamespaceObservation)
    (platform : NamespacePlatformState) : Prop where
  preparedNamespacesDistinct : observation.preparedParent ≠ observation.preparedChild
  currentIsPreparedChild : platform.current = observation.preparedChild
  forChildrenIsPreparedChild : platform.forChildren = observation.preparedChild
  currentMatchesForChildren : platform.current = platform.forChildren
  currentIsNotPreparingParent : platform.current ≠ observation.preparedParent
  forChildrenIsNotPreparingParent : platform.forChildren ≠ observation.preparedParent

/--
External assumption that the namespace observation source reported both actual
child-side namespace handles exactly. This is an input proposition, not an
OS-honesty claim.
-/
def ExternalNamespaceObservationSourceAccurate
    (observation : PidNamespaceObservation) (platform : NamespacePlatformState) : Prop :=
  platform.current = observation.observedCurrent ∧
    platform.forChildren = observation.observedForChildren

/-- A checked observation places the actual process in the prepared child namespace. -/
theorem PidNamespaceObservation.checked_implies_child_current
    {observation : PidNamespaceObservation} {platform : NamespacePlatformState}
    (checked : observation.checks = true)
    (sourceAccurate : ExternalNamespaceObservationSourceAccurate observation platform) :
    PidNamespaceSafetyPremises observation platform := by
  have identitiesMatch : observation.IdentitiesMatch := by
    simpa only [PidNamespaceObservation.checks, decide_eq_true_eq] using checked
  exact ⟨identitiesMatch.1,
    sourceAccurate.1.trans identitiesMatch.2.1,
    sourceAccurate.2.trans identitiesMatch.2.2.1,
    sourceAccurate.1.trans
      (identitiesMatch.2.2.2.1.trans sourceAccurate.2.symm),
    fun currentIsParent =>
      identitiesMatch.2.2.2.2.1 (sourceAccurate.1.symm.trans currentIsParent),
    fun forChildrenIsParent =>
      identitiesMatch.2.2.2.2.2
        (sourceAccurate.2.symm.trans forChildrenIsParent)⟩

/-- Coordinator state immediately after namespace preparation, before child verification. -/
def preparedNamespaceState : State :=
  State.initial.beginApply.recordNamespaceCreated

/-- Coordinator state after verified entry into the prepared child namespace. -/
def enteredChildNamespaceState : State :=
  preparedNamespaceState.recordPidChildEntered

/-- The explicit child-entry handoff is one accepted isolation-model transition. -/
theorem prepared_to_entered_child_step :
    Step preparedNamespaceState enteredChildNamespaceState := by
  exact Step.pidChildEntered rfl rfl rfl rfl

/-- States reachable after namespace preparation through isolation-model transitions. -/
def Reachable (state : State) : Prop :=
  Steps preparedNamespaceState state

/-- Namespace preparation is the initial state of the refinement slice. -/
theorem preparedNamespaceState_reachable : Reachable preparedNamespaceState :=
  Steps.refl preparedNamespaceState

/-- A verified child entry remains reachable in the pure coordinator model. -/
theorem enteredChildNamespaceState_reachable : Reachable enteredChildNamespaceState :=
  Steps.tail preparedNamespaceState_reachable prepared_to_entered_child_step

/-- Child entry records both preparation and current-child completion premises. -/
theorem enteredChildNamespaceState_safety :
    enteredChildNamespaceState.namespaceCreated = true ∧
      enteredChildNamespaceState.pidChildEntered = true ∧
      enteredChildNamespaceState.NamespaceStatusValid := by
  simp [enteredChildNamespaceState, preparedNamespaceState,
    State.initial, State.beginApply, State.recordNamespaceCreated,
    State.recordPidChildEntered, State.NamespaceStatusValid]

/-- Typed terminal classes for failures in the child-startup handshake. -/
inductive StartupFailure where
  | childVerification
  | parentStartup
  | notification
  deriving Repr, BEq, DecidableEq

/-- Security-relevant events exposed by the pure child-startup protocol. -/
inductive StartupEvent where
  | childVerified
  | isolationCompleted
  | childVerificationFailed
  | parentStartupFailed
  | notificationFailed
  | mustTerminate
  | parentKillRequired
  | successReceiptDelivered
  deriving Repr, BEq, DecidableEq

/--
A typed startup trace distinguishes parent-visible success from each failure
boundary. A locally constructed receipt is not parent-visible until notification
succeeds, so notification failure has no successful parent receipt.
-/
inductive StartupTrace where
  | success (receipt : Receipt)
  | failure (failure : StartupFailure)

/-- Ordered security events for one typed startup trace. -/
def StartupTrace.events : StartupTrace → List StartupEvent
  | .success _ => [.childVerified, .isolationCompleted, .successReceiptDelivered]
  | .failure .childVerification =>
      [.childVerificationFailed, .mustTerminate, .parentKillRequired]
  | .failure .parentStartup =>
      [.parentStartupFailed, .parentKillRequired]
  | .failure .notification =>
      [.childVerified, .isolationCompleted, .notificationFailed,
        .mustTerminate, .parentKillRequired]

/-- The receipt made visible to the parent after a completed startup handshake. -/
def StartupTrace.parentReceipt : StartupTrace → Option Receipt
  | .success receipt => some receipt
  | .failure _ => none

/-- Whether the child-side protocol must terminate instead of running a workload. -/
def StartupTrace.mustTerminate : StartupTrace → Bool
  | .success _ => false
  | .failure .childVerification => true
  | .failure .parentStartup => false
  | .failure .notification => true

/-- Whether the parent must enforce termination and reap its still-owned child. -/
def StartupTrace.parentKillRequired : StartupTrace → Bool
  | .success _ => false
  | .failure _ => true

/-- Concrete trace for failure to verify the child's namespace identities. -/
def childVerificationFailureTrace : StartupTrace :=
  .failure .childVerification

/-- Concrete trace for failure while the parent awaits or validates startup. -/
def parentStartupFailureTrace : StartupTrace :=
  .failure .parentStartup

/-- Concrete trace for failure to notify the parent after child verification. -/
def notificationFailureTrace : StartupTrace :=
  .failure .notification

/-- No typed failure can expose a successful startup receipt to the parent. -/
theorem StartupTrace.failure_has_no_success_receipt (failure : StartupFailure) :
    (StartupTrace.failure failure).parentReceipt = none := by
  rfl

/-- Failure traces never contain the successful receipt-delivery event. -/
theorem StartupTrace.failure_events_have_no_success_receipt
    (failure : StartupFailure) :
    StartupEvent.successReceiptDelivered ∉ (StartupTrace.failure failure).events := by
  cases failure <;> simp [StartupTrace.events]

/-- Every typed startup failure retains the parent's termination-and-reap obligation. -/
theorem StartupTrace.failure_requires_parent_kill (failure : StartupFailure) :
    (StartupTrace.failure failure).parentKillRequired = true := by
  rfl

/-- Every failure trace records the parent's termination-and-reap obligation. -/
theorem StartupTrace.failure_events_require_parent_kill
    (failure : StartupFailure) :
    StartupEvent.parentKillRequired ∈ (StartupTrace.failure failure).events := by
  cases failure <;> simp [StartupTrace.events]

/-- Child namespace verification failure is an explicit fail-stop boundary. -/
theorem StartupTrace.child_verification_requires_termination :
    childVerificationFailureTrace.mustTerminate = true := by
  rfl

/-- Child verification failure exposes no receipt and retains both cleanup duties. -/
theorem StartupTrace.child_verification_failure_obligations :
    childVerificationFailureTrace.parentReceipt = none ∧
      childVerificationFailureTrace.mustTerminate = true ∧
      childVerificationFailureTrace.parentKillRequired = true := by
  constructor
  · rfl
  · constructor <;> rfl

/-- Child verification failure records termination before parent cleanup. -/
theorem StartupTrace.child_verification_events_require_termination :
    StartupEvent.mustTerminate ∈ childVerificationFailureTrace.events := by
  simp [childVerificationFailureTrace, StartupTrace.events]

/-- Parent startup failure exposes no receipt and leaves parent cleanup mandatory. -/
theorem StartupTrace.parent_startup_failure_obligations :
    parentStartupFailureTrace.parentReceipt = none ∧
      parentStartupFailureTrace.parentKillRequired = true := by
  constructor <;> rfl

/-- Notification failure cannot fall through into the isolated workload. -/
theorem StartupTrace.notification_failure_requires_termination :
    notificationFailureTrace.mustTerminate = true := by
  rfl

/-- Notification failure exposes no receipt and retains both cleanup duties. -/
theorem StartupTrace.notification_failure_obligations :
    notificationFailureTrace.parentReceipt = none ∧
      notificationFailureTrace.mustTerminate = true ∧
      notificationFailureTrace.parentKillRequired = true := by
  constructor
  · rfl
  · constructor <;> rfl

/-- Notification failure records termination before parent cleanup. -/
theorem StartupTrace.notification_failure_events_require_termination :
    StartupEvent.mustTerminate ∈ notificationFailureTrace.events := by
  simp [notificationFailureTrace, StartupTrace.events]

/-!
## Rust-shaped startup and ownership observations

These observations mirror the fields that the Linux backend validates before
writing a ready message and before releasing its owned direct child.
-/

/-- Parent-visible observations from the concrete Linux readiness boundary. -/
structure RustReadyObservation where
  completedStepCode : Nat
  expectedFinalStepCode : Nat
  namespaceMatchesPreparation : Bool
  parentDeathSignal : Nat
  killSignal : Nat
  startupReaderAlive : Bool
  sourcePinnedBeforePivot : Bool
  mountedSourceMatchesPin : Bool
  deriving Repr, BEq, DecidableEq

/-- Executable checker for the exact Rust readiness contract. -/
def RustReadyObservation.checks (observation : RustReadyObservation) : Bool :=
  observation.completedStepCode == observation.expectedFinalStepCode &&
    observation.namespaceMatchesPreparation &&
    observation.parentDeathSignal == observation.killSignal &&
    observation.startupReaderAlive && observation.sourcePinnedBeforePivot &&
    observation.mountedSourceMatchesPin

/-- Translation from checked Rust fields to the abstract lifecycle evidence. -/
def RustReadyObservation.toEvidence
    (observation : RustReadyObservation) : ChildReadyEvidence where
  parentDeathSignalIsKill := observation.parentDeathSignal == observation.killSignal
  startupReaderAlive := observation.startupReaderAlive
  sourcePinnedBeforePivot := observation.sourcePinnedBeforePivot
  mountedSourceMatchesPin := observation.mountedSourceMatchesPin

/-- Rust readiness cannot be accepted without every kernel evidence bit. -/
theorem RustReadyObservation.checked_evidence
    {observation : RustReadyObservation}
    (checked : observation.checks = true) :
    observation.toEvidence.checks = true := by
  simp [RustReadyObservation.checks] at checked
  simp [RustReadyObservation.toEvidence, ChildReadyEvidence.checks,
    checked.1.1.1.2, checked.1.1.2, checked.1.2, checked.2]

/-- A checked Rust observation admits the concrete starting-to-ready transition. -/
theorem RustReadyObservation.checked_refines_child_ready
    {observation : RustReadyObservation}
    (checked : observation.checks = true) :
    ChildLifecycleStep .starting .ready :=
  ChildLifecycleStep.ready observation.toEvidence
    (RustReadyObservation.checked_evidence checked)

/-- Rust parent-side observations after a shutdown or Drop attempt. -/
structure RustOwnedChildObservation where
  terminationRequested : Bool
  childExited : Bool
  waitObserved : Bool
  deriving Repr, BEq, DecidableEq

/-- Ownership may be released only after termination, exit, and wait evidence. -/
def RustOwnedChildObservation.checksRelease
    (observation : RustOwnedChildObservation) : Bool :=
  observation.terminationRequested && observation.childExited && observation.waitObserved

/-- Checked release evidence is non-vacuous and includes the observed reap. -/
theorem RustOwnedChildObservation.checked_release_complete
    {observation : RustOwnedChildObservation}
    (checked : observation.checksRelease = true) :
    observation.terminationRequested = true ∧
      observation.childExited = true ∧ observation.waitObserved = true := by
  simp [RustOwnedChildObservation.checksRelease] at checked
  exact ⟨checked.1.1, checked.1.2, checked.2⟩

/-- Checked Rust release evidence refines the kill-and-reap lifecycle trace. -/
theorem RustOwnedChildObservation.checked_refines_drop_reap
    {observation : RustOwnedChildObservation}
    (checked : observation.checksRelease = true) :
    ChildLifecycleSteps .ready .reaped := by
  have evidence := RustOwnedChildObservation.checked_release_complete checked
  exact ChildLifecycle.drop_kill_reap_trace
    observation.terminationRequested observation.childExited observation.waitObserved
    evidence.1 evidence.2.1 evidence.2.2

/-- Checked parent-death cleanup uses the same concrete kill-and-wait evidence. -/
theorem RustOwnedChildObservation.checked_refines_parent_death_reap
    {observation : RustOwnedChildObservation}
    (checked : observation.checksRelease = true) :
    ChildLifecycleSteps .ready .reaped := by
  have evidence := RustOwnedChildObservation.checked_release_complete checked
  exact ChildLifecycle.parentDeath_kill_reap_trace
    observation.terminationRequested observation.childExited observation.waitObserved
    evidence.1 evidence.2.1 evidence.2.2

/-- Startup failure cleanup starts before readiness and still requires kill and wait evidence. -/
theorem RustOwnedChildObservation.checked_refines_startup_failure_reap
    {observation : RustOwnedChildObservation}
    (checked : observation.checksRelease = true) :
    ChildLifecycleSteps .starting .reaped := by
  have evidence := RustOwnedChildObservation.checked_release_complete checked
  exact .tail
    (.tail (.tail (.refl .starting) .startupFailure)
      (.signalExit observation.terminationRequested observation.childExited
        evidence.1 evidence.2.1))
    (.reap observation.waitObserved evidence.2.2)

/-- Concrete ready witness using Rust's final seccomp code and SIGKILL value. -/
def validRustReadyObservation : RustReadyObservation where
  completedStepCode := 12
  expectedFinalStepCode := 12
  namespaceMatchesPreparation := true
  parentDeathSignal := 9
  killSignal := 9
  startupReaderAlive := true
  sourcePinnedBeforePivot := true
  mountedSourceMatchesPin := true

theorem validRustReadyObservation_checks : validRustReadyObservation.checks = true := by
  native_decide

/-- A credential transition that cleared PDEATHSIG cannot produce readiness. -/
def clearedParentDeathObservation : RustReadyObservation :=
  { validRustReadyObservation with parentDeathSignal := 0 }

theorem clearedParentDeathObservation_rejected :
    clearedParentDeathObservation.checks = false := by
  native_decide

/-- Resolving the workspace to an unpinned post-pivot source cannot produce readiness. -/
def postPivotWorkspaceMismatchObservation : RustReadyObservation :=
  { validRustReadyObservation with mountedSourceMatchesPin := false }

theorem postPivotWorkspaceMismatchObservation_rejected :
    postPivotWorkspaceMismatchObservation.checks = false := by
  native_decide

/-- A termination signal without a wait observation cannot release ownership. -/
def unreapedRustChildObservation : RustOwnedChildObservation where
  terminationRequested := true
  childExited := true
  waitObserved := false

theorem unreapedRustChildObservation_rejected :
    unreapedRustChildObservation.checksRelease = false := by
  native_decide

/-- Child verification failure is recorded after namespace preparation. -/
def childVerificationFailureState : State :=
  preparedNamespaceState.applyFailure .namespaces

/-- Verification failure after namespace creation is a reachable model transition. -/
theorem prepared_to_child_verification_failure_step :
    Step preparedNamespaceState childVerificationFailureState := by
  exact Step.applyFailure rfl rfl

/-- The pure failure state remains reachable without admitting a successful handoff. -/
theorem childVerificationFailureState_reachable :
    Reachable childVerificationFailureState :=
  Steps.tail preparedNamespaceState_reachable
    prepared_to_child_verification_failure_step

/-- The modeled verification failure has no receipt and requires termination. -/
theorem childVerificationFailureState_obligations :
    childVerificationFailureState.receipt = none ∧
      childVerificationFailureState.mustTerminate = true := by
  simp [childVerificationFailureState, preparedNamespaceState, State.initial,
    State.beginApply, State.recordNamespaceCreated, State.applyFailure,
    ApplyStage.irreversible]

/-- Checked platform observation together with its corresponding model transition. -/
def PidNamespaceObservation.Refines (observation : PidNamespaceObservation)
    (platform : NamespacePlatformState) : Prop :=
  PidNamespaceSafetyPremises observation platform ∧
    Step preparedNamespaceState enteredChildNamespaceState

/-- A checked, accurately sourced namespace observation refines PID-child entry. -/
theorem PidNamespaceObservation.checked_refines
    {observation : PidNamespaceObservation} {platform : NamespacePlatformState}
    (checked : observation.checks = true)
    (sourceAccurate : ExternalNamespaceObservationSourceAccurate observation platform) :
    observation.Refines platform := by
  exact ⟨observation.checked_implies_child_current checked sourceAccurate,
    prepared_to_entered_child_step⟩

/-- Concrete valid child-current namespace observation. -/
def validPidNamespaceObservation : PidNamespaceObservation where
  preparedParent := ⟨1, 100⟩
  preparedChild := ⟨1, 101⟩
  observedCurrent := ⟨1, 101⟩
  observedForChildren := ⟨1, 101⟩

/-- The valid child-current observation is executable and accepted. -/
theorem validPidNamespaceObservation_checks : validPidNamespaceObservation.checks = true := by
  native_decide

/-- Concrete invalid observation taken from the preparing parent process. -/
def parentCurrentNamespaceObservation : PidNamespaceObservation where
  preparedParent := ⟨1, 100⟩
  preparedChild := ⟨1, 101⟩
  observedCurrent := ⟨1, 100⟩
  observedForChildren := ⟨1, 101⟩

/-- Observing the parent's current namespace cannot prove child entry. -/
theorem parentCurrentNamespaceObservation_rejected :
    parentCurrentNamespaceObservation.checks = false := by
  native_decide

/-- Concrete invalid observation of a third namespace in both child handles. -/
def unexpectedChildNamespaceObservation : PidNamespaceObservation where
  preparedParent := ⟨1, 100⟩
  preparedChild := ⟨1, 101⟩
  observedCurrent := ⟨1, 102⟩
  observedForChildren := ⟨1, 102⟩

/-- Matching child handles cannot substitute a namespace other than the prepared child. -/
theorem unexpectedChildNamespaceObservation_rejected :
    unexpectedChildNamespaceObservation.checks = false := by
  native_decide

/-- Concrete invalid preparation that aliases the parent and child namespaces. -/
def aliasedPreparedNamespaceObservation : PidNamespaceObservation where
  preparedParent := ⟨1, 100⟩
  preparedChild := ⟨1, 100⟩
  observedCurrent := ⟨1, 100⟩
  observedForChildren := ⟨1, 100⟩

/-- A preparation that did not create a distinct child namespace is rejected. -/
theorem aliasedPreparedNamespaceObservation_rejected :
    aliasedPreparedNamespaceObservation.checks = false := by
  native_decide

/-- Concrete invalid observation whose child handles name different namespaces. -/
def divergentChildNamespaceObservation : PidNamespaceObservation where
  preparedParent := ⟨1, 100⟩
  preparedChild := ⟨1, 101⟩
  observedCurrent := ⟨1, 101⟩
  observedForChildren := ⟨1, 102⟩

/-- A nested or pending `for_children` namespace cannot prove exact child entry. -/
theorem divergentChildNamespaceObservation_rejected :
    divergentChildNamespaceObservation.checks = false := by
  native_decide

/-- Concrete actual namespace state matching the accepted observation. -/
def validNamespacePlatformState : NamespacePlatformState where
  current := validPidNamespaceObservation.preparedChild
  forChildren := validPidNamespaceObservation.preparedChild

/-- The external accuracy premise is constructively satisfiable for the valid witness. -/
theorem validNamespaceObservation_source_accurate :
    ExternalNamespaceObservationSourceAccurate
      validPidNamespaceObservation validNamespacePlatformState := by
  constructor <;> rfl

/-- The valid witness refines an actual modeled PID-child entry. -/
theorem validPidNamespaceObservation_refines :
    validPidNamespaceObservation.Refines validNamespacePlatformState :=
  validPidNamespaceObservation.checked_refines
    validPidNamespaceObservation_checks validNamespaceObservation_source_accurate

end Refinement

end Isolation

end Authority
