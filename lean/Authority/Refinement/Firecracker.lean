import Authority.Firecracker

/-!
# Firecracker Platform Refinement

Executable host observations are related to the pure Firecracker lifecycle and
cleanup models. Every theorem about actual platform state takes an explicit
observation-source accuracy proposition; the model does not assume that the OS,
Firecracker, or an adapter reports truthfully.
-/

namespace Authority

namespace Firecracker

namespace Refinement

/-- Stable identity of the cgroup directory owned by one runtime instance. -/
structure OwnedCgroupId where
  device : Nat
  inode : Nat
  deriving Repr, BEq, DecidableEq

/-- Platform state relevant after stopping the owned Firecracker process scope. -/
structure CgroupPlatformState where
  cgroup : OwnedCgroupId
  liveTasks : List Nat
  deriving Repr, BEq, DecidableEq

/-- Checkable result returned by the process-stop observation boundary. -/
structure ProcessStopObservation where
  expectedOwnedCgroup : OwnedCgroupId
  stopReturnedSuccess : Bool
  observed : CgroupPlatformState
  deriving Repr, BEq, DecidableEq

/-- The stop result is accepted only for the owned cgroup with no remaining task. -/
def ProcessStopObservation.checks (observation : ProcessStopObservation) : Bool :=
  observation.stopReturnedSuccess &&
    decide (observation.observed.cgroup = observation.expectedOwnedCgroup) &&
    observation.observed.liveTasks.isEmpty

/-- Concrete platform premise required before the model records process stop. -/
def ProcessStopSafetyPremises (owned : OwnedCgroupId)
    (platform : CgroupPlatformState) : Prop :=
  platform.cgroup = owned ∧ platform.liveTasks = []

/--
External assumption that the cgroup observation source reported the supplied
platform state exactly. This proposition is an input, not an OS-honesty claim.
-/
def ExternalCgroupObservationSourceAccurate
    (observation : ProcessStopObservation) (platform : CgroupPlatformState) : Prop :=
  platform = observation.observed

/-- A checked successful stop has no live task in the actual owned cgroup. -/
theorem ProcessStopObservation.checked_implies_no_live_task
    {observation : ProcessStopObservation} {platform : CgroupPlatformState}
    (checked : observation.checks = true)
    (sourceAccurate : ExternalCgroupObservationSourceAccurate observation platform) :
    ProcessStopSafetyPremises observation.expectedOwnedCgroup platform := by
  simp only [ProcessStopObservation.checks, Bool.and_eq_true,
    decide_eq_true_eq, List.isEmpty_iff] at checked
  subst platform
  exact ⟨checked.1.2, checked.2⟩

/-- Checked process stop refines the model's successful stop transition. -/
def ProcessStopObservation.RefinesCleanup (observation : ProcessStopObservation)
    (platform : CgroupPlatformState) (before : CleanupState) : Prop :=
  ProcessStopSafetyPremises observation.expectedOwnedCgroup platform ∧
    CleanupStep before before.stopProcess

/-- A checked, accurately sourced process stop refines a cleanup step. -/
theorem ProcessStopObservation.checked_refines_cleanup
    {observation : ProcessStopObservation} {platform : CgroupPlatformState}
    {before : CleanupState} (checked : observation.checks = true)
    (sourceAccurate : ExternalCgroupObservationSourceAccurate observation platform) :
    observation.RefinesCleanup platform before := by
  exact ⟨observation.checked_implies_no_live_task checked sourceAccurate,
    CleanupStep.stopProcess⟩

/-- Concrete accepted stop observation. -/
def validProcessStopObservation : ProcessStopObservation where
  expectedOwnedCgroup := ⟨1, 7⟩
  stopReturnedSuccess := true
  observed := ⟨⟨1, 7⟩, []⟩

/-- The accepted stop observation is executable and non-vacuous. -/
theorem validProcessStopObservation_checks : validProcessStopObservation.checks = true := by
  native_decide

/-- Concrete rejected stop observation with a remaining live task. -/
def liveTaskProcessStopObservation : ProcessStopObservation where
  expectedOwnedCgroup := ⟨1, 7⟩
  stopReturnedSuccess := true
  observed := ⟨⟨1, 7⟩, [42]⟩

/-- A successful return cannot pass the checker while the cgroup reports a live task. -/
theorem liveTaskProcessStopObservation_rejected :
    liveTaskProcessStopObservation.checks = false := by
  native_decide

/-- Concrete actual cgroup state matching the accepted stop observation. -/
def validCgroupPlatformState : CgroupPlatformState :=
  validProcessStopObservation.observed

/-- The external cgroup accuracy premise is satisfiable for the accepted witness. -/
theorem validCgroupObservation_source_accurate :
    ExternalCgroupObservationSourceAccurate
      validProcessStopObservation validCgroupPlatformState := by
  rfl

/-- The accepted stop witness refines the cleanup model from its live state. -/
theorem validProcessStopObservation_refines :
    validProcessStopObservation.RefinesCleanup
      validCgroupPlatformState CleanupState.live :=
  validProcessStopObservation.checked_refines_cleanup
    validProcessStopObservation_checks validCgroupObservation_source_accurate

/-- Workspace device identity that paused restore must bind before identity acknowledgement. -/
structure WorkspaceDeviceBinding where
  driveId : String
  root : Isolation.HostPath
  cloneId : String
  deriving Repr, DecidableEq

/-- Vsock identity that paused restore must bind before identity acknowledgement. -/
structure VsockBinding where
  cid : Nat
  socket : Isolation.HostPath
  deriving Repr, DecidableEq

/-- Workspace binding required by one runtime configuration. -/
def expectedWorkspaceBinding (config : RuntimeConfig) : WorkspaceDeviceBinding where
  driveId := "workspace"
  root := config.workspaceRoot
  cloneId := config.workspaceCloneId

/-- Vsock binding required by one runtime configuration. -/
def expectedVsockBinding (config : RuntimeConfig) : VsockBinding where
  cid := config.vsockCid
  socket := config.vsockSocket

/-- Actual platform state relevant to a paused restore refinement. -/
structure RestorePlatformState where
  loadedSnapshot : Option FingerprintPayload
  paused : Bool
  workspace : Option WorkspaceDeviceBinding
  vsock : Option VsockBinding
  acknowledgedIdentities : Option IdentityBundle
  deriving DecidableEq

/-- Checkable platform observation collected after paused restore and guest acknowledgement. -/
structure RestoreObservation where
  loadReturnedSuccess : Bool
  resumeRequested : Bool
  observed : RestorePlatformState
  identities : IdentityBundle
  deriving DecidableEq

private def allGuestIdentityKinds : List GuestIdentityKind :=
  [.vm, .session, .request, .subject, .capability]

private theorem guestIdentityKind_mem_all (kind : GuestIdentityKind) :
    kind ∈ allGuestIdentityKinds := by
  cases kind <;> simp [allGuestIdentityKinds]

/-- Executable form of the identity bundle contract used by restore observations. -/
def identityBundleChecks (bundle : IdentityBundle) (forbidden : List Nat) : Bool :=
  allGuestIdentityKinds.all (fun kind => bundle.forKind kind != 0) &&
    allGuestIdentityKinds.all (fun kind => !forbidden.contains (bundle.forKind kind)) &&
    allGuestIdentityKinds.all (fun first =>
      allGuestIdentityKinds.all (fun second =>
        decide (bundle.forKind first = bundle.forKind second → first = second)))

/-- The executable identity check entails the pure model's identity premise. -/
theorem identityBundleChecks_sound {bundle : IdentityBundle} {forbidden : List Nat}
    (checked : identityBundleChecks bundle forbidden = true) :
    bundle.Valid forbidden := by
  simp only [identityBundleChecks, Bool.and_eq_true, List.all_eq_true,
    bne_iff_ne, Bool.not_eq_true, List.contains_eq_mem, decide_eq_true_eq]
    at checked
  refine ⟨?_, ?_, ?_⟩
  · intro kind
    exact checked.1.1 kind (guestIdentityKind_mem_all kind)
  · intro first second equal
    exact checked.2 first (guestIdentityKind_mem_all first)
      second (guestIdentityKind_mem_all second) equal
  · intro kind
    simpa using checked.1.2 kind (guestIdentityKind_mem_all kind)

/-- Exact executable checks for paused load, rebound devices, and identity acknowledgement. -/
def RestoreObservation.checks (config : RuntimeConfig) (snapshot : Snapshot)
    (observation : RestoreObservation) : Bool :=
  observation.loadReturnedSuccess && !observation.resumeRequested &&
    decide (snapshot.fingerprint = config.fingerprintPayload) &&
    decide (observation.observed.loadedSnapshot = some snapshot.fingerprint) &&
    decide (observation.observed.paused = true) &&
    decide (observation.observed.workspace = some (expectedWorkspaceBinding config)) &&
    decide (observation.observed.vsock = some (expectedVsockBinding config)) &&
    decide (observation.observed.acknowledgedIdentities = some observation.identities) &&
    identityBundleChecks observation.identities snapshot.forbiddenIdentities

/-- Concrete platform premises needed to interpret a restore observation. -/
structure RestoreSafetyPremises (config : RuntimeConfig) (snapshot : Snapshot)
    (identities : IdentityBundle) (platform : RestorePlatformState) : Prop where
  snapshotCompatible : snapshot.fingerprint = config.fingerprintPayload
  loadedPaused : platform.loadedSnapshot = some snapshot.fingerprint ∧ platform.paused = true
  workspaceBound : platform.workspace = some (expectedWorkspaceBinding config)
  vsockBound : platform.vsock = some (expectedVsockBinding config)
  identityAcknowledged : platform.acknowledgedIdentities = some identities
  identitiesValid : identities.Valid snapshot.forbiddenIdentities

/--
External assumption that the restore observation source reported the supplied
platform state exactly. It is deliberately required by every platform theorem.
-/
def ExternalRestoreObservationSourceAccurate (observation : RestoreObservation)
    (platform : RestorePlatformState) : Prop :=
  platform = observation.observed

/-- Checked restore data plus source accuracy entails every platform safety premise. -/
theorem RestoreObservation.checked_implies_platform_premises
    {config : RuntimeConfig} {snapshot : Snapshot} {observation : RestoreObservation}
    {platform : RestorePlatformState} (checked : observation.checks config snapshot = true)
    (sourceAccurate : ExternalRestoreObservationSourceAccurate observation platform) :
    RestoreSafetyPremises config snapshot observation.identities platform := by
  simp only [RestoreObservation.checks, Bool.and_eq_true, Bool.not_eq_true,
    decide_eq_true_eq] at checked
  rcases checked with
    ⟨⟨⟨⟨⟨⟨⟨⟨loadSucceeded, noResume⟩, compatible⟩, loaded⟩, paused⟩,
      workspace⟩, vsock⟩, acknowledged⟩, identitiesValid⟩
  subst platform
  exact ⟨compatible, ⟨loaded, paused⟩, workspace, vsock, acknowledged,
    identityBundleChecks_sound identitiesValid⟩

/-- Model state reached after the complete paused-restore identity acknowledgement path. -/
def acknowledgedRestoreState (snapshot : Snapshot) (identities : IdentityBundle) : State :=
  ((State.restore snapshot).markGuestGate identities).markIdentityAcknowledged

/-- A checked restore observation constructs the corresponding model execution. -/
theorem RestoreObservation.checked_steps
    {config : RuntimeConfig} {snapshot : Snapshot} {observation : RestoreObservation}
    (checked : observation.checks config snapshot = true) :
    Steps (State.launched config)
      (acknowledgedRestoreState snapshot observation.identities) := by
  simp only [RestoreObservation.checks, Bool.and_eq_true, Bool.not_eq_true,
    decide_eq_true_eq] at checked
  rcases checked with
    ⟨⟨⟨⟨⟨⟨⟨⟨loadSucceeded, noResume⟩, compatible⟩, loaded⟩, paused⟩,
      workspace⟩, vsock⟩, acknowledged⟩, identitiesValid⟩
  let launched := State.launched config
  let snapshotted := launched.markSnapshotted
  let restored := State.restore snapshot
  let gated := restored.markGuestGate observation.identities
  let acknowledged := gated.markIdentityAcknowledged
  have snapshotStep : Step launched snapshotted := Step.snapshot rfl
  have restoreStep : Step snapshotted restored := by
    apply Step.restore
    · rfl
    · exact compatible
  have regenerateStep : Step restored gated := by
    apply Step.regenerate
    · rfl
    · simpa [restored, State.restore] using
        identityBundleChecks_sound identitiesValid
  have acknowledgeStep : Step gated acknowledged := Step.acknowledge rfl rfl
  have toSnapshot : Steps launched snapshotted :=
    Steps.tail (Steps.refl launched) snapshotStep
  have toRestore : Steps launched restored := Steps.tail toSnapshot restoreStep
  have toGate : Steps launched gated := Steps.tail toRestore regenerateStep
  have toAcknowledgement : Steps launched acknowledged :=
    Steps.tail toGate acknowledgeStep
  simpa [launched, acknowledged, gated, restored, acknowledgedRestoreState]
    using toAcknowledgement

/-- Checked restore plus valid configuration yields launched-origin reachability. -/
theorem RestoreObservation.checked_reachable
    {config : RuntimeConfig} {snapshot : Snapshot} {observation : RestoreObservation}
    (valid : config.Valid) (checked : observation.checks config snapshot = true) :
    (acknowledgedRestoreState snapshot observation.identities).Reachable config :=
  ⟨valid, observation.checked_steps checked⟩

/-- Full refinement combines external platform premises with model reachability. -/
def RestoreObservation.Refines (config : RuntimeConfig) (snapshot : Snapshot)
    (observation : RestoreObservation) (platform : RestorePlatformState) : Prop :=
  RestoreSafetyPremises config snapshot observation.identities platform ∧
    (acknowledgedRestoreState snapshot observation.identities).Reachable config

/-- A checked, accurately sourced restore observation refines the Firecracker model. -/
theorem RestoreObservation.checked_refines
    {config : RuntimeConfig} {snapshot : Snapshot} {observation : RestoreObservation}
    {platform : RestorePlatformState} (valid : config.Valid)
    (checked : observation.checks config snapshot = true)
    (sourceAccurate : ExternalRestoreObservationSourceAccurate observation platform) :
    observation.Refines config snapshot platform :=
  ⟨observation.checked_implies_platform_premises checked sourceAccurate,
    observation.checked_reachable valid checked⟩

/-- Concrete valid paused restore observation. -/
def validRestoreObservation : RestoreObservation where
  loadReturnedSuccess := true
  resumeRequested := false
  observed :=
    { loadedSnapshot := some (createInternalSnapshot validRuntimeConfigWitness).fingerprint
      paused := true
      workspace := some (expectedWorkspaceBinding validRuntimeConfigWitness)
      vsock := some (expectedVsockBinding validRuntimeConfigWitness)
      acknowledgedIdentities := some freshIdentityWitness }
  identities := freshIdentityWitness

/-- The complete paused restore observation is executable and accepted. -/
theorem validRestoreObservation_checks :
    validRestoreObservation.checks validRuntimeConfigWitness
      (createInternalSnapshot validRuntimeConfigWitness) = true := by
  native_decide

/-- Concrete invalid restore observation that lacks identity acknowledgement. -/
def missingIdentityAckRestoreObservation : RestoreObservation :=
  { validRestoreObservation with
    observed := { validRestoreObservation.observed with acknowledgedIdentities := none } }

/-- Paused load and bindings alone cannot bypass identity acknowledgement. -/
theorem missingIdentityAckRestoreObservation_rejected :
    missingIdentityAckRestoreObservation.checks validRuntimeConfigWitness
      (createInternalSnapshot validRuntimeConfigWitness) = false := by
  native_decide

/-- Concrete invalid restore observation whose VM is already resumed. -/
def resumedRestoreObservation : RestoreObservation :=
  { validRestoreObservation with
    observed := { validRestoreObservation.observed with paused := false } }

/-- A resumed observation cannot be interpreted as a paused restore. -/
theorem resumedRestoreObservation_rejected :
    resumedRestoreObservation.checks validRuntimeConfigWitness
      (createInternalSnapshot validRuntimeConfigWitness) = false := by
  native_decide

/-- Concrete invalid restore observation with no observed vsock binding. -/
def missingVsockRestoreObservation : RestoreObservation :=
  { validRestoreObservation with
    observed := { validRestoreObservation.observed with vsock := none } }

/-- Identity acknowledgement cannot compensate for a missing restored vsock binding. -/
theorem missingVsockRestoreObservation_rejected :
    missingVsockRestoreObservation.checks validRuntimeConfigWitness
      (createInternalSnapshot validRuntimeConfigWitness) = false := by
  native_decide

/-- Concrete actual restore state matching the accepted observation. -/
def validRestorePlatformState : RestorePlatformState :=
  validRestoreObservation.observed

/-- The external restore accuracy premise is satisfiable for the accepted witness. -/
theorem validRestoreObservation_source_accurate :
    ExternalRestoreObservationSourceAccurate
      validRestoreObservation validRestorePlatformState := by
  rfl

/-- The accepted paused-restore witness reaches identity acknowledgement in the model. -/
theorem validRestoreObservation_refines :
    validRestoreObservation.Refines validRuntimeConfigWitness
      (createInternalSnapshot validRuntimeConfigWitness) validRestorePlatformState :=
  validRestoreObservation.checked_refines validRuntimeConfigWitness_valid
    validRestoreObservation_checks validRestoreObservation_source_accurate

end Refinement

end Firecracker

end Authority
