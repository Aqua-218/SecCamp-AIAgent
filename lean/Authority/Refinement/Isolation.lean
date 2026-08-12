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

/-- Checkable preparation and current-process PID namespace observation. -/
structure PidNamespaceObservation where
  preparedParent : NamespaceIdentity
  preparedChild : NamespaceIdentity
  observedCurrent : NamespaceIdentity
  deriving Repr, BEq, DecidableEq

/--
The prepared namespaces must differ, and the current process must be in the
prepared child namespace rather than the preparing parent's namespace.
-/
def PidNamespaceObservation.checks (observation : PidNamespaceObservation) : Bool :=
  decide (observation.preparedParent ≠ observation.preparedChild) &&
    decide (observation.observedCurrent = observation.preparedChild) &&
    decide (observation.observedCurrent ≠ observation.preparedParent)

/-- Actual platform state relevant to the workload child's PID namespace. -/
structure NamespacePlatformState where
  current : NamespaceIdentity
  deriving Repr, BEq, DecidableEq

/-- Exact safety premises needed before recording PID-child entry in the model. -/
structure PidNamespaceSafetyPremises (observation : PidNamespaceObservation)
    (platform : NamespacePlatformState) : Prop where
  preparedNamespacesDistinct : observation.preparedParent ≠ observation.preparedChild
  currentIsPreparedChild : platform.current = observation.preparedChild
  currentIsNotPreparingParent : platform.current ≠ observation.preparedParent

/--
External assumption that the namespace observation source reported the actual
current namespace exactly. This is an input proposition, not an OS-honesty claim.
-/
def ExternalNamespaceObservationSourceAccurate
    (observation : PidNamespaceObservation) (platform : NamespacePlatformState) : Prop :=
  platform.current = observation.observedCurrent

/-- A checked observation places the actual process in the prepared child namespace. -/
theorem PidNamespaceObservation.checked_implies_child_current
    {observation : PidNamespaceObservation} {platform : NamespacePlatformState}
    (checked : observation.checks = true)
    (sourceAccurate : ExternalNamespaceObservationSourceAccurate observation platform) :
    PidNamespaceSafetyPremises observation platform := by
  simp only [PidNamespaceObservation.checks, Bool.and_eq_true,
    decide_eq_true_eq] at checked
  exact ⟨checked.1.1, sourceAccurate.trans checked.1.2,
    sourceAccurate ▸ checked.2⟩

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

/-- Child entry records both preparation and current-child completion premises. -/
theorem enteredChildNamespaceState_safety :
    enteredChildNamespaceState.namespaceCreated = true ∧
      enteredChildNamespaceState.pidChildEntered = true ∧
      enteredChildNamespaceState.NamespaceStatusValid := by
  simp [enteredChildNamespaceState, preparedNamespaceState,
    State.initial, State.beginApply, State.recordNamespaceCreated,
    State.recordPidChildEntered, State.NamespaceStatusValid]

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

/-- The valid child-current observation is executable and accepted. -/
theorem validPidNamespaceObservation_checks : validPidNamespaceObservation.checks = true := by
  native_decide

/-- Concrete invalid observation taken from the preparing parent process. -/
def parentCurrentNamespaceObservation : PidNamespaceObservation where
  preparedParent := ⟨1, 100⟩
  preparedChild := ⟨1, 101⟩
  observedCurrent := ⟨1, 100⟩

/-- Observing the parent's current namespace cannot prove child entry. -/
theorem parentCurrentNamespaceObservation_rejected :
    parentCurrentNamespaceObservation.checks = false := by
  native_decide

/-- Concrete invalid preparation that aliases the parent and child namespaces. -/
def aliasedPreparedNamespaceObservation : PidNamespaceObservation where
  preparedParent := ⟨1, 100⟩
  preparedChild := ⟨1, 100⟩
  observedCurrent := ⟨1, 100⟩

/-- A preparation that did not create a distinct child namespace is rejected. -/
theorem aliasedPreparedNamespaceObservation_rejected :
    aliasedPreparedNamespaceObservation.checks = false := by
  native_decide

/-- Concrete actual namespace state matching the accepted observation. -/
def validNamespacePlatformState : NamespacePlatformState where
  current := validPidNamespaceObservation.preparedChild

/-- The external accuracy premise is constructively satisfiable for the valid witness. -/
theorem validNamespaceObservation_source_accurate :
    ExternalNamespaceObservationSourceAccurate
      validPidNamespaceObservation validNamespacePlatformState := by
  rfl

/-- The valid witness refines an actual modeled PID-child entry. -/
theorem validPidNamespaceObservation_refines :
    validPidNamespaceObservation.Refines validNamespacePlatformState :=
  validPidNamespaceObservation.checked_refines
    validPidNamespaceObservation_checks validNamespaceObservation_source_accurate

end Refinement

end Isolation

end Authority
