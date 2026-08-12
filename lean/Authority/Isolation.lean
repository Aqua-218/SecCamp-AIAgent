import Authority.State

/-!
# Runtime Isolation Coordinator

Pure configuration and coordinator model for the runtime-isolation crate. The
model proves preflight, apply ordering, receipt, and rollback trace properties.
Successful backend returns refining real kernel isolation remain an explicit
platform obligation.
-/

namespace Authority

namespace Isolation

/-- Lexical host path used by preflight validation. -/
structure HostPath where
  absolute : Bool
  components : List String
  deriving Repr, DecidableEq

/-- The host root path. -/
def HostPath.root : HostPath where
  absolute := true
  components := []

/-- Absolute path with no current- or parent-directory component. -/
def HostPath.CleanAbsolute (path : HostPath) : Prop :=
  path.absolute = true ∧ "." ∉ path.components ∧ ".." ∉ path.components

/-- Component-prefix containment, matching lexical `Path::starts_with`. -/
def HostPath.AtOrBelow (path parent : HostPath) : Prop :=
  parent.components <+: path.components

/-- Exact safe-component grammar for a Linux cgroup leaf name. -/
def CgroupNameValid (name : String) : Prop :=
  name ≠ "" ∧ name.length ≤ 255 ∧ name ≠ "." ∧ name ≠ ".." ∧
    ∀ character, character ∈ name.toList →
      character.isAlphanum = true ∨ character = '.' ∨
        character = '_' ∨ character = '-'

/-- Exact immutable isolation policy relevant to pure preflight. -/
structure Config where
  rootfsSource : HostPath
  rootfsMount : HostPath
  oldRoot : HostPath
  workspaceSource : HostPath
  workspaceTarget : HostPath
  tmpfsTarget : HostPath
  tmpfsBytes : Nat
  cgroupRoot : HostPath
  cgroupName : String
  memoryMaxBytes : Nat
  pidsMax : Nat
  landlockRequiredAbi : Nat
  landlockReadOnly : List HostPath
  landlockWritable : List HostPath
  seccompPlatformValid : Bool

/-- One GiB, the inclusive tmpfs ceiling used by the Rust validator. -/
def maximumTmpfsBytes : Nat := 1073741824

/-- Complete side-effect-free configuration contract. -/
structure Config.Valid (config : Config) : Prop where
  rootfsSourceClean : config.rootfsSource.CleanAbsolute
  rootfsMountClean : config.rootfsMount.CleanAbsolute
  oldRootClean : config.oldRoot.CleanAbsolute
  workspaceSourceClean : config.workspaceSource.CleanAbsolute
  workspaceTargetClean : config.workspaceTarget.CleanAbsolute
  tmpfsTargetClean : config.tmpfsTarget.CleanAbsolute
  cgroupRootClean : config.cgroupRoot.CleanAbsolute
  rootfsMountNotRoot : config.rootfsMount ≠ HostPath.root
  oldRootBelowMount : config.oldRoot.AtOrBelow config.rootfsMount
  oldRootDistinct : config.oldRoot ≠ config.rootfsMount
  workspaceNotRoot : config.workspaceTarget ≠ HostPath.root
  tmpfsNotRoot : config.tmpfsTarget ≠ HostPath.root
  cgroupNotRoot : config.cgroupRoot ≠ HostPath.root
  tmpfsPositive : 0 < config.tmpfsBytes
  tmpfsBounded : config.tmpfsBytes ≤ maximumTmpfsBytes
  cgroupNameValid : CgroupNameValid config.cgroupName
  memoryPositive : 0 < config.memoryMaxBytes
  pidsPositive : 0 < config.pidsMax
  landlockAbiSupported : 3 ≤ config.landlockRequiredAbi
  readOnlyNonempty : config.landlockReadOnly ≠ []
  writableNonempty : config.landlockWritable ≠ []
  readOnlyClean : ∀ path, path ∈ config.landlockReadOnly → path.CleanAbsolute
  writableClean : ∀ path, path ∈ config.landlockWritable → path.CleanAbsolute
  writableInsideWorkspace : ∀ path, path ∈ config.landlockWritable →
    path.AtOrBelow config.workspaceTarget
  workspaceOutsideStaging :
    ¬ config.workspaceTarget.AtOrBelow config.rootfsMount
  tmpfsOutsideStaging : ¬ config.tmpfsTarget.AtOrBelow config.rootfsMount
  workspaceTmpfsDistinct : config.workspaceTarget ≠ config.tmpfsTarget
  workspaceNotProc : config.workspaceTarget.components ≠ ["proc"]
  workspaceNotDev : config.workspaceTarget.components ≠ ["dev"]
  tmpfsNotProc : config.tmpfsTarget.components ≠ ["proc"]
  tmpfsNotDev : config.tmpfsTarget.components ≠ ["dev"]
  seccompValid : config.seccompPlatformValid = true

/-- Runtime capabilities detected before any isolation mutation. -/
structure CapabilityReport where
  namespacesAvailable : Bool
  cgroupV2Available : Bool
  seccompAvailable : Bool
  landlockAbi : Option Nat
  reasons : List String

/-- Exact fail-closed host capability conjunction. -/
def CapabilityReport.Sufficient (report : CapabilityReport) (config : Config) : Prop :=
  report.namespacesAvailable = true ∧ report.cgroupV2Available = true ∧
    report.seccompAvailable = true ∧ report.reasons = [] ∧
    ∃ abi, report.landlockAbi = some abi ∧ config.landlockRequiredAbi ≤ abi

/-- Configuration validity directly exposes every immutable resource ceiling. -/
theorem Config.Valid.resource_limits {config : Config} (valid : config.Valid) :
    0 < config.tmpfsBytes ∧ config.tmpfsBytes ≤ maximumTmpfsBytes ∧
    0 < config.memoryMaxBytes ∧ 0 < config.pidsMax :=
  ⟨valid.tmpfsPositive, valid.tmpfsBounded, valid.memoryPositive, valid.pidsPositive⟩

/-- A valid configuration permits writes only inside the workspace target. -/
theorem Config.Valid.every_writable_path_inside_workspace {config : Config}
    (valid : config.Valid) {path : HostPath}
    (writable : path ∈ config.landlockWritable) :
    path.AtOrBelow config.workspaceTarget :=
  valid.writableInsideWorkspace path writable

/-- The thirteen coordinator stages in their only accepted order. -/
inductive ApplyStage where
  | namespaces
  | identityMap
  | cgroupV2
  | readOnlyRootfs
  | workspace
  | limitedTmpfs
  | maskProc
  | maskDevices
  | closeInheritedFileDescriptors
  | landlock
  | dropCapabilities
  | noNewPrivs
  | seccomp
  deriving Repr, BEq, DecidableEq

/-- Required apply plan. -/
def requiredStages : List ApplyStage :=
  [.namespaces, .identityMap, .cgroupV2, .readOnlyRootfs, .workspace,
    .limitedTmpfs, .maskProc, .maskDevices, .closeInheritedFileDescriptors,
    .landlock, .dropCapabilities, .noNewPrivs, .seccomp]

/-- Linux stages whose process state cannot be restored in place. -/
def ApplyStage.irreversible : ApplyStage → Bool
  | .namespaces | .identityMap | .readOnlyRootfs |
      .closeInheritedFileDescriptors | .landlock | .dropCapabilities |
      .noNewPrivs | .seccomp => true
  | .cgroupV2 | .workspace | .limitedTmpfs | .maskProc | .maskDevices => false

/-- Receipt exists only after every coordinator stage returned success. -/
structure Receipt where
  stages : List ApplyStage
  complete : stages = requiredStages

/-- Observable coordinator phases. -/
inductive Phase where
  | preflight
  | applying
  | rollingBack
  | succeeded
  | failed
  deriving Repr, BEq, DecidableEq

/-- Coordinator state including complete apply and rollback call traces. -/
structure State where
  phase : Phase
  completed : List ApplyStage
  remaining : List ApplyStage
  applyTrace : List ApplyStage
  rollbackPending : List ApplyStage
  rollbackTrace : List ApplyStage
  rollbackFailures : List ApplyStage
  receipt : Option Receipt
  mustTerminate : Bool

/-- State before side-effect-free validation and capability detection. -/
def State.initial : State where
  phase := .preflight
  completed := []
  remaining := requiredStages
  applyTrace := []
  rollbackPending := []
  rollbackTrace := []
  rollbackFailures := []
  receipt := none
  mustTerminate := false

/-- Enter apply only after configuration and capability preflight succeed. -/
def State.beginApply (state : State) : State := { state with phase := .applying }

/-- Record one successful backend stage. -/
def State.applySuccess (state : State) (stage : ApplyStage)
    (remaining : List ApplyStage) : State :=
  { state with
    completed := state.completed ++ [stage]
    remaining := remaining
    applyTrace := state.applyTrace ++ [stage] }

/-- Stop applying and prepare reverse-prefix rollback after one failure. -/
def State.applyFailure (state : State) (stage : ApplyStage) : State :=
  { state with
    phase := if state.completed = [] then .failed else .rollingBack
    applyTrace := state.applyTrace ++ [stage]
    rollbackPending := state.completed.reverse
    mustTerminate := state.mustTerminate || state.completed.any ApplyStage.irreversible }

/-- Record one rollback attempt and whether that attempt failed. -/
def State.recordRollback (state : State) (stage : ApplyStage)
    (remaining : List ApplyStage) (failed : Bool) : State :=
  { state with
    phase := if remaining = [] then .failed else .rollingBack
    rollbackPending := remaining
    rollbackTrace := state.rollbackTrace ++ [stage]
    rollbackFailures := if failed then state.rollbackFailures ++ [stage]
      else state.rollbackFailures }

/-- Exact coordinator-shape invariant. -/
def State.WellFormed (state : State) : Prop :=
  state.completed ++ state.remaining = requiredStages ∧
  match state.phase with
  | .preflight =>
      state.completed = [] ∧ state.remaining = requiredStages ∧
      state.applyTrace = [] ∧ state.rollbackTrace = [] ∧
        state.rollbackPending = [] ∧ state.receipt = none
  | .applying =>
      state.applyTrace = state.completed ∧ state.rollbackTrace = [] ∧
        state.rollbackPending = [] ∧ state.receipt = none
  | .rollingBack =>
      state.rollbackTrace ++ state.rollbackPending = state.completed.reverse ∧
        state.rollbackPending ≠ [] ∧ state.receipt = none
  | .succeeded =>
      state.completed = requiredStages ∧ state.remaining = [] ∧
        state.applyTrace = requiredStages ∧
        ∃ receipt, state.receipt = some receipt ∧ receipt.stages = requiredStages
  | .failed =>
      state.rollbackPending = [] ∧ state.receipt = none ∧
        state.rollbackTrace = state.completed.reverse

/-- Initial coordinator shape is valid. -/
theorem State.initial_wellFormed : State.initial.WellFormed := by
  simp [State.initial, State.WellFormed]

/-- Accepted coordinator transitions. Failed preflight makes no transition. -/
inductive Step : State → State → Prop
  | beginApply {state : State} {config : Config} {report : CapabilityReport} :
      state.phase = .preflight → config.Valid → report.Sufficient config →
      Step state state.beginApply
  | applySuccess {state : State} {stage : ApplyStage}
      {remaining : List ApplyStage} :
      state.phase = .applying → state.remaining = stage :: remaining →
      Step state (state.applySuccess stage remaining)
  | applyFailure {state : State} {stage : ApplyStage}
      {remaining : List ApplyStage} :
      state.phase = .applying → state.remaining = stage :: remaining →
      Step state (state.applyFailure stage)
  | rollback {state : State} {stage : ApplyStage}
      {remaining : List ApplyStage} {failed : Bool} :
      state.phase = .rollingBack → state.rollbackPending = stage :: remaining →
      Step state (state.recordRollback stage remaining failed)
  | finish {state : State} :
      state.phase = .applying → state.remaining = [] →
      (complete : state.completed = requiredStages) →
      Step state {
        state with
        phase := .succeeded
        receipt := some { stages := state.completed, complete := complete } }

/-- Every accepted coordinator transition preserves exact plan and trace shape. -/
theorem Step.preserves_wellFormed {before after : State}
    (transition : Step before after) (wellFormed : before.WellFormed) :
    after.WellFormed := by
  cases transition with
  | beginApply phase valid sufficient =>
      rw [State.WellFormed, phase] at wellFormed
      rcases wellFormed with ⟨plan, completed, remaining, applyTrace,
        rollbackTrace, noRollback, noReceipt⟩
      simp [State.beginApply, State.WellFormed, plan, completed, remaining,
        applyTrace, rollbackTrace, noRollback, noReceipt, State.initial]
  | applySuccess phase nextStage =>
      rw [State.WellFormed, phase] at wellFormed
      rcases wellFormed with ⟨plan, traceMatches, rollbackTrace,
        noRollback, noReceipt⟩
      constructor
      · rw [State.applySuccess, nextStage] at *
        simpa [List.append_assoc] using plan
      · simp [State.applySuccess, phase, traceMatches, rollbackTrace, noRollback,
          noReceipt]
  | applyFailure phase nextStage =>
      rw [State.WellFormed, phase] at wellFormed
      rcases wellFormed with ⟨plan, traceMatches, rollbackTrace,
        noRollback, noReceipt⟩
      constructor
      · exact plan
      · by_cases noCompleted : before.completed = []
        · simp [State.applyFailure, noCompleted, noReceipt, rollbackTrace]
        · have reverseNonempty : before.completed.reverse ≠ [] := by
            simpa using noCompleted
          simp [State.applyFailure, noCompleted, rollbackTrace, reverseNonempty,
            noReceipt]
  | rollback phase pending =>
      rw [State.WellFormed, phase] at wellFormed
      rcases wellFormed with ⟨plan, rollbackPartition, pendingNonempty, noReceipt⟩
      constructor
      · exact plan
      · rename_i stage remaining failed
        by_cases noRemaining : remaining = []
        · have partitionAfter : before.rollbackTrace ++ [stage] =
              before.completed.reverse := by
            rw [← rollbackPartition, pending, noRemaining]
          simp [State.recordRollback, noRemaining, noReceipt, partitionAfter]
        · have partitionAfter :
              (before.rollbackTrace ++ [stage]) ++ remaining =
                before.completed.reverse := by
            rw [← rollbackPartition, pending]
            simp [List.append_assoc]
          simp [State.recordRollback, noRemaining, partitionAfter, noReceipt]
  | finish phase noRemaining complete =>
      rw [State.WellFormed, phase] at wellFormed
      rcases wellFormed with ⟨plan, traceMatches, rollbackTrace,
        noRollback, noReceipt⟩
      constructor
      · exact plan
      · simp [State.WellFormed, complete, noRemaining, traceMatches]

/-- A rolling-back state attempts exactly the successful prefix in reverse order. -/
theorem State.rollback_partition {state : State} (wellFormed : state.WellFormed)
    (rollingBack : state.phase = .rollingBack) :
    state.rollbackTrace ++ state.rollbackPending = state.completed.reverse := by
  rw [State.WellFormed, rollingBack] at wellFormed
  exact wellFormed.2.1

/-- A success receipt cannot coexist with rollback. -/
theorem State.receipt_excludes_rollback {state : State}
    (wellFormed : state.WellFormed) {receipt : Receipt}
    (receiptLookup : state.receipt = some receipt) :
    state.phase = .succeeded := by
  cases phase : state.phase with
  | preflight =>
      rw [State.WellFormed, phase] at wellFormed
      rw [wellFormed.2.2.2.2.2.2] at receiptLookup
      cases receiptLookup
  | applying =>
      rw [State.WellFormed, phase] at wellFormed
      rw [wellFormed.2.2.2.2] at receiptLookup
      cases receiptLookup
  | rollingBack =>
      rw [State.WellFormed, phase] at wellFormed
      rw [wellFormed.2.2.2] at receiptLookup
      cases receiptLookup
  | succeeded => rfl
  | failed =>
      rw [State.WellFormed, phase] at wellFormed
      rw [wellFormed.2.2.1] at receiptLookup
      cases receiptLookup

/-- Every successful state exposes the complete required stage list. -/
theorem State.success_receipt_exact {state : State} (wellFormed : state.WellFormed)
    (succeeded : state.phase = .succeeded) :
    ∃ receipt, state.receipt = some receipt ∧ receipt.stages = requiredStages := by
  rw [State.WellFormed, succeeded] at wellFormed
  exact wellFormed.2.2.2.2

/-- A terminal failure retains the complete reverse-prefix rollback trace. -/
theorem State.failed_rollback_complete {state : State} (wellFormed : state.WellFormed)
    (failed : state.phase = .failed) :
    state.rollbackTrace = state.completed.reverse := by
  rw [State.WellFormed, failed] at wellFormed
  exact wellFormed.2.2.2

/-- Failure after any irreversible Linux stage requires terminating the child. -/
theorem State.applyFailure_marks_mustTerminate {state : State}
    (failedStage : ApplyStage)
    (irreversibleCompleted : ∃ stage,
      stage ∈ state.completed ∧ stage.irreversible = true) :
    (state.applyFailure failedStage).mustTerminate = true := by
  simp [State.applyFailure, List.any_eq_true, irreversibleCompleted]

/-- Once required, child termination cannot be cleared by a coordinator step. -/
theorem Step.mustTerminate_monotone {before after : State}
    (transition : Step before after)
    (required : before.mustTerminate = true) : after.mustTerminate = true := by
  cases transition with
  | beginApply | applySuccess | rollback | finish => exact required
  | applyFailure => simp [State.applyFailure, required]

/-- Arbitrary finite isolation execution. -/
inductive Steps : State → State → Prop
  | refl (state : State) : Steps state state
  | tail {first middle last : State} :
      Steps first middle → Step middle last → Steps first last

/-- Child-termination obligation persists across arbitrary retries and finishes. -/
theorem Steps.mustTerminate_monotone {before after : State}
    (transitions : Steps before after)
    (required : before.mustTerminate = true) : after.mustTerminate = true := by
  induction transitions with
  | refl => exact required
  | tail _ transition inductionHypothesis =>
      exact transition.mustTerminate_monotone inductionHypothesis

/-- Exact coordinator shape is inductive across arbitrary finite execution. -/
theorem Steps.preserves_wellFormed {before after : State}
    (transitions : Steps before after) (wellFormed : before.WellFormed) :
    after.WellFormed := by
  induction transitions with
  | refl => exact wellFormed
  | tail _ transition inductionHypothesis =>
      exact transition.preserves_wellFormed inductionHypothesis

end Isolation

end Authority
