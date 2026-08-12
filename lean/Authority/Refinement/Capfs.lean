import Authority.Audit
import Authority.Integration

/-!
# Capability Filesystem Commit Refinement

This module gives the Rust CapFS adapter a failure-aware abstract machine. It
separates the staged namespace from the externally visible backing view,
records repository-wide quarantine, preserves unresolved attempts across
restart, and admits only destruction-time handle cleanup while quarantined.

The observation checker is proof carrying: schema validation is executable,
while the candidate supplies the exact successful integrated execution that
the Rust event claims to have staged.
-/

namespace Authority.Refinement.Capfs

/-- Which backing snapshot may be visible after an indeterminate syscall. -/
inductive UnknownBacking where
  | before
  | staged
  deriving Repr, BEq, DecidableEq

/-- Rust's externally reported effect classifications at the CapFS boundary. -/
inductive RustOutcome where
  | committed
  | failedBeforeCommit
  | committedButAudit (attemptId : AttemptId)
  | commitUnknown (attemptId : AttemptId) (backing : UnknownBacking)
  deriving Repr, DecidableEq

/-- Repository state that must survive mount cloning and process restart. -/
structure State where
  integrated : IntegratedHandleState
  /-- Last backing namespace known or recovered by the host adapter. -/
  backingNamespace : NamespaceState
  /-- Durable attempts without a reconciled terminal outcome. -/
  unresolvedAttempts : List AttemptId

namespace State

/-- The admission state is stored in the shared integrated repository record. -/
def repositoryHealth (state : State) : RepositoryHealth :=
  state.integrated.repositoryHealth

/-- Healthy repositories expose exactly the namespace observed in backing. -/
def Aligned (state : State) : Prop :=
  state.integrated.namespaceState = state.backingNamespace

/-- Lift a reconciled integrated snapshot into the CapFS machine. -/
def ofIntegrated (integrated : IntegratedHandleState) : State where
  integrated := integrated
  backingNamespace := integrated.namespaceState
  unresolvedAttempts := []

/-- Replace only the shared repository admission state. -/
def withHealth (state : State) (health : RepositoryHealth) : State :=
  { state with
    integrated := { state.integrated with repositoryHealth := health } }

/-- A known commit publishes the staged namespace to both logical views. -/
def publish (_state : State) (staged : IntegratedHandleState)
    (health : RepositoryHealth) (unresolved : List AttemptId) : State where
  integrated := { staged with repositoryHealth := health }
  backingNamespace := staged.namespaceState
  unresolvedAttempts := unresolved

/-- An unknown commit retains the old registry and quarantines either backing view. -/
def publishUnknown (state : State) (staged : IntegratedHandleState)
    (attemptId : AttemptId) (backing : UnknownBacking) : State where
  integrated := { state.integrated with repositoryHealth := .inDoubt }
  backingNamespace := match backing with
    | .before => state.backingNamespace
    | .staged => staged.namespaceState
  unresolvedAttempts := attemptId :: state.unresolvedAttempts

/-- Destruction cleanup changes handle accounting but never clears quarantine. -/
def cleanupClose (state : State) (handleId : HandleId)
    (handle : OpenHandle) (object : NamespaceObject) : State :=
  let integrated := { state.integrated.closeHandle handleId handle object with
    repositoryHealth := .inDoubt }
  { integrated
    backingNamespace := integrated.namespaceState
    unresolvedAttempts := state.unresolvedAttempts }

/-- A crash records the durable started attempt before any recovery scan. -/
def crashStarted (state : State) (attemptId : AttemptId) : State :=
  { (state.withHealth .inDoubt) with
    unresolvedAttempts := attemptId :: state.unresolvedAttempts }

/-- Recovered health is operational exactly when no durable ambiguity remains. -/
def recoveredHealth : List AttemptId → RepositoryHealth
  | [] => .operational
  | _ :: _ => .inDoubt

/-- Restart imports the backing manifest but preserves durable ambiguity. -/
def restart (state : State) (recoveredNamespace : NamespaceState) : State where
  integrated := {
    state.integrated with
      namespaceState := recoveredNamespace
      repositoryHealth := recoveredHealth state.unresolvedAttempts }
  backingNamespace := recoveredNamespace
  unresolvedAttempts := state.unresolvedAttempts

/-- Restart always realigns the imported registry with the recovered backing view. -/
theorem restart_aligned (state : State) (recoveredNamespace : NamespaceState) :
    (state.restart recoveredNamespace).Aligned := rfl

end State

/-- A staged effect is an existing finite integrated execution admitted while healthy. -/
structure ProposedEffect (before : State) (staged : IntegratedHandleState) : Prop where
  operational : before.repositoryHealth = .operational
  noUnresolved : before.unresolvedAttempts = []
  execution : IntegratedHandleState.Steps before.integrated staged

/-- A staged effect cannot silently change shared repository health. -/
theorem ProposedEffect.staged_operational {before : State}
    {staged : IntegratedHandleState} (proposed : ProposedEffect before staged) :
    staged.repositoryHealth = .operational := by
  rw [proposed.execution.preserve_repositoryHealth]
  exact proposed.operational

/-- All ordinary executor outcomes require admission from an operational repository. -/
inductive OrdinaryStep : State → State → Prop
  | committed {before : State} {staged : IntegratedHandleState}
      (proposed : ProposedEffect before staged) :
      OrdinaryStep before
        (before.publish staged .operational before.unresolvedAttempts)
  | failedBeforeCommit {before : State} {staged : IntegratedHandleState}
      (proposed : ProposedEffect before staged) :
      OrdinaryStep before before
  | committedButAudit {before : State} {staged : IntegratedHandleState}
      {attemptId : AttemptId} (proposed : ProposedEffect before staged) :
      OrdinaryStep before
        (before.publish staged .inDoubt
          (attemptId :: before.unresolvedAttempts))
  | commitUnknown {before : State} {staged : IntegratedHandleState}
      {attemptId : AttemptId} {backing : UnknownBacking}
      (proposed : ProposedEffect before staged) :
      OrdinaryStep before
        (before.publishUnknown staged attemptId backing)

/-- Reconciliation evidence binds every unresolved attempt to its own receipt. -/
structure ReconciliationEvidence (state : State) : Type where
  receipts : AttemptId → Option CommitReceipt
  verified : ∀ attemptId, attemptId ∈ state.unresolvedAttempts →
    ∃ receipt, receipts attemptId = some receipt ∧ receipt.attemptId = attemptId

/-- Verified reconciliation adopts backing as authoritative and clears quarantine. -/
def reconcile (state : State) (_evidence : ReconciliationEvidence state) : State where
  integrated := {
    state.integrated with
      namespaceState := state.backingNamespace
      repositoryHealth := .operational }
  backingNamespace := state.backingNamespace
  unresolvedAttempts := []

/-- Complete CapFS transitions distinguish ordinary effects from lifecycle repair. -/
inductive Step : State → State → Prop
  | ordinary {before after : State} : OrdinaryStep before after → Step before after
  | cleanupClose {before : State} {caller : SubjectId} {handleId : HandleId}
      (quarantined : before.repositoryHealth = .inDoubt)
      (allowed : before.integrated.MayClose caller handleId) :
      Step before
        (before.cleanupClose handleId allowed.handle allowed.object)
  | crashStarted {before : State} {attemptId : AttemptId} :
      Step before (before.crashStarted attemptId)
  | restart {before : State} {recoveredNamespace : NamespaceState} :
      Step before (before.restart recoveredNamespace)
  | reconcile {before : State} (evidence : ReconciliationEvidence before) :
      Step before (Capfs.reconcile before evidence)

/-- Finite failure-aware executions. -/
inductive Steps : State → State → Prop
  | refl (state : State) : Steps state state
  | tail {first middle last : State} :
      Steps first middle → Step middle last → Steps first last

/-- A known post-commit audit error publishes staged state before quarantine. -/
theorem committedButAudit_quarantines_and_publishes {before : State}
    {staged : IntegratedHandleState} {attemptId : AttemptId}
    (proposed : ProposedEffect before staged) :
    let after := before.publish staged .inDoubt
      (attemptId :: before.unresolvedAttempts)
    OrdinaryStep before after ∧
      after.repositoryHealth = .inDoubt ∧
      after.integrated.namespaceState = staged.namespaceState ∧
      after.backingNamespace = staged.namespaceState ∧
      attemptId ∈ after.unresolvedAttempts := by
  exact ⟨OrdinaryStep.committedButAudit proposed, rfl, rfl, rfl,
    by simp [State.publish]⟩

/-- An indeterminate effect always quarantines and retains its durable identity. -/
theorem commitUnknown_quarantines {before : State}
    {staged : IntegratedHandleState} {attemptId : AttemptId}
    {backing : UnknownBacking} (proposed : ProposedEffect before staged) :
    let after := before.publishUnknown staged attemptId backing
    OrdinaryStep before after ∧
      after.repositoryHealth = .inDoubt ∧
      attemptId ∈ after.unresolvedAttempts := by
  exact ⟨OrdinaryStep.commitUnknown proposed, rfl,
    by simp [State.publishUnknown]⟩

/-- Quarantine prevents every ordinary executor outcome from being admitted. -/
theorem inDoubt_noOrdinaryStep {before after : State}
    (quarantined : before.repositoryHealth = .inDoubt) :
    ¬ OrdinaryStep before after := by
  intro transition
  cases transition with
  | committed proposed | failedBeforeCommit proposed |
      committedButAudit proposed | commitUnknown proposed =>
      have impossible := quarantined.symm.trans proposed.operational
      cases impossible

/-- Cleanup of an already-issued handle remains available during quarantine. -/
theorem cleanupClose_allowedInDoubt {before : State} {caller : SubjectId}
    {handleId : HandleId} (quarantined : before.repositoryHealth = .inDoubt)
    (allowed : before.integrated.MayClose caller handleId) :
    ∃ after,
      Step before after ∧ after.repositoryHealth = .inDoubt := by
  let after := before.cleanupClose handleId allowed.handle allowed.object
  exact ⟨after, .cleanupClose quarantined allowed, rfl⟩

/-- A nonempty recovered attempt set can never restart as operational. -/
theorem restart_unresolved_notOperational {state : State}
    (unresolved : state.unresolvedAttempts ≠ [])
    (recoveredNamespace : NamespaceState) :
    (state.restart recoveredNamespace).repositoryHealth ≠ .operational := by
  cases attempts : state.unresolvedAttempts with
  | nil => exact False.elim (unresolved attempts)
  | cons attempt remaining =>
      simp [State.restart, State.repositoryHealth, State.recoveredHealth, attempts]

/-- The crash-start transition itself immediately quarantines the repository. -/
theorem crashStarted_quarantines (state : State) (attemptId : AttemptId) :
    (state.crashStarted attemptId).repositoryHealth = .inDoubt ∧
      attemptId ∈ (state.crashStarted attemptId).unresolvedAttempts := by
  exact ⟨rfl, by simp [State.crashStarted]⟩

/-- A restorable CapFS snapshot has no ambiguity and exact backing alignment. -/
structure Restorable (state : State) : Prop where
  integrated : state.integrated.Restorable
  aligned : state.Aligned
  noUnresolved : state.unresolvedAttempts = []

/-- Startup includes both concrete empty state and explicitly reconciled imports. -/
inductive Start : State → Prop
  | runtime (issuer : IssuerId) :
      Start (State.ofIntegrated (IntegratedHandleState.initial issuer))
  | restored {state : State} : Restorable state → Start state

/-- Reachability starts only from concrete runtime or reconciled restore evidence. -/
def Reachable (state : State) : Prop :=
  ∃ initial, Start initial ∧ Steps initial state

/-- Every reconciled restorable snapshot is an admitted reachable start. -/
theorem reconciled_restorable_reachable {state : State}
    (restorable : Restorable state) : Reachable state :=
  ⟨state, .restored restorable, .refl state⟩

/-- Observation schema version shared with the Rust-shaped event stream. -/
def observationSchemaVersion : Nat := 1

/-- Closed Rust namespace-operation vocabulary at the CapFS boundary. -/
inductive RustOperation where
  | hardLink (objectId : ObjectId) (alias : CanonicalPath)
  | unlinkName (objectId : ObjectId) (alias newPrimary : CanonicalPath)
  | createSymlink (objectId : ObjectId) (path target : CanonicalPath)
  deriving DecidableEq

/-- Versioned Rust-shaped outcome without embedding abstract state. -/
structure Observation where
  schemaVersion : Nat
  operation : RustOperation
  outcome : RustOutcome
  deriving DecidableEq

/-- Exact abstract result selected by one typed Rust outcome. -/
def outcomeState (before : State) (staged : IntegratedHandleState) :
    RustOutcome → State
  | .committed =>
      before.publish staged .operational before.unresolvedAttempts
  | .failedBeforeCommit => before
  | .committedButAudit attemptId =>
      before.publish staged .inDoubt (attemptId :: before.unresolvedAttempts)
  | .commitUnknown attemptId backing =>
      before.publishUnknown staged attemptId backing

/--
Concrete operation evidence fixes the only integrated step that a Rust label may
claim. In particular, a generic finite `ProposedEffect` cannot stand in for a
hard-link, unlink, or symlink publication.
-/
inductive OperationEffect (before : State) :
    RustOperation → IntegratedHandleState → Prop
  | hardLink {objectId : ObjectId} {alias : CanonicalPath}
      (allowed : before.integrated.namespaceState.MayAddHardLink objectId alias) :
      OperationEffect before (.hardLink objectId alias)
        (before.integrated.addHardLink objectId allowed.object alias)
  | unlinkName {objectId : ObjectId} {alias : CanonicalPath}
      (allowed : before.integrated.namespaceState.MayUnlinkName objectId alias) :
      OperationEffect before (.unlinkName objectId alias allowed.newPrimary)
        (before.integrated.unlinkName objectId allowed.object alias
          allowed.newPrimary allowed.remaining)
  | createSymlink {object : NamespaceObject}
      (allowed : before.integrated.namespaceState.MayCreateSymlink object) :
      OperationEffect before (.createSymlink object.id object.path allowed.target)
        (before.integrated.createSymlink object)

/-- Concrete operation evidence is exactly one corresponding integrated step. -/
theorem OperationEffect.integratedStep {before : State}
    {operation : RustOperation} {staged : IntegratedHandleState}
    (effect : OperationEffect before operation staged) :
    IntegratedHandleState.Step before.integrated staged := by
  cases effect with
  | hardLink allowed => exact .hardLinkAtomic allowed
  | unlinkName allowed => exact .unlinkNameAtomic allowed
  | createSymlink allowed => exact .createSymlinkAtomic allowed

/-- An operation-specific step supplies the ordinary staging proof when healthy. -/
def OperationEffect.proposed {before : State} {operation : RustOperation}
    {staged : IntegratedHandleState}
    (effect : OperationEffect before operation staged)
    (operational : before.repositoryHealth = .operational)
    (noUnresolved : before.unresolvedAttempts = []) :
    ProposedEffect before staged := {
  operational
  noUnresolved
  execution := .tail (.refl before.integrated) effect.integratedStep }

/-- Proof-carrying candidate binds a Rust label to its one concrete transition. -/
structure Candidate (before : State) (observation : Observation) where
  staged : IntegratedHandleState
  operational : before.repositoryHealth = .operational
  noUnresolved : before.unresolvedAttempts = []
  effect : OperationEffect before observation.operation staged

/-- Successful observation checking returns its exact abstract state. -/
structure CheckedObservation (before : State) (observation : Observation) where
  after : State
  staged : IntegratedHandleState
  effect : OperationEffect before observation.operation staged
  proposed : ProposedEffect before staged
  exactOutcome : after = outcomeState before staged observation.outcome

/-- Check the executable schema boundary before accepting proof-carrying state evidence. -/
def checkObservation (before : State) (observation : Observation)
    (candidate : Candidate before observation) :
    Option (CheckedObservation before observation) :=
  if _version : observation.schemaVersion = observationSchemaVersion then
    some {
      after := outcomeState before candidate.staged observation.outcome
      staged := candidate.staged
      effect := candidate.effect
      proposed := candidate.effect.proposed candidate.operational
        candidate.noUnresolved
      exactOutcome := rfl }
  else
    none

/-- Every checked Rust outcome takes exactly one typed ordinary abstract step. -/
theorem CheckedObservation.forwardSimulation {before : State}
    {observation : Observation}
    (checked : CheckedObservation before observation) :
    Step before checked.after := by
  rw [checked.exactOutcome]
  cases observation.outcome with
  | committed =>
      simpa [outcomeState] using Step.ordinary
        (OrdinaryStep.committed checked.proposed)
  | failedBeforeCommit =>
      simpa [outcomeState] using Step.ordinary
        (OrdinaryStep.failedBeforeCommit checked.proposed)
  | committedButAudit attemptId =>
      simpa [outcomeState] using Step.ordinary
        (OrdinaryStep.committedButAudit
          (attemptId := attemptId) checked.proposed)
  | commitUnknown attemptId backing =>
      simpa [outcomeState] using Step.ordinary
        (OrdinaryStep.commitUnknown
          (attemptId := attemptId) (backing := backing) checked.proposed)

/-- A successful checker result forward-simulates to a finite CapFS execution. -/
theorem rustNamespaceOutcome_refines_step {before : State}
    {observation : Observation} {candidate : Candidate before observation}
    {checked : CheckedObservation before observation}
    (_accepted : checkObservation before observation candidate = some checked) :
    Steps before checked.after :=
  .tail (.refl before) checked.forwardSimulation

/-- A hard-link effect determines the exact no-replace integrated transition. -/
theorem OperationEffect.hardLink_exact {before : State}
    {staged : IntegratedHandleState} {objectId : ObjectId}
    {alias : CanonicalPath}
    (effect : OperationEffect before (.hardLink objectId alias) staged) :
    ∃ allowed : before.integrated.namespaceState.MayAddHardLink objectId alias,
      staged = before.integrated.addHardLink objectId allowed.object alias := by
  cases effect with
  | hardLink allowed => exact ⟨allowed, rfl⟩

/-- Every accepted hard-link label contains its exact no-replace evidence. -/
theorem CheckedObservation.hardLink_precondition {before : State}
    {observation : Observation} (checked : CheckedObservation before observation)
    {objectId : ObjectId} {alias : CanonicalPath}
    (label : observation.operation = .hardLink objectId alias) :
    ∃ allowed : before.integrated.namespaceState.MayAddHardLink objectId alias,
      checked.staged = before.integrated.addHardLink objectId allowed.object alias := by
  have effect : OperationEffect before (.hardLink objectId alias) checked.staged := by
    simpa [label] using checked.effect
  exact effect.hardLink_exact

private def aliasPrimary : CanonicalPath :=
  { segments := ["primary"]
    isValid := by decide }

private def aliasSecondary : CanonicalPath :=
  { segments := ["secondary"]
    isValid := by decide }

private def symlinkName : CanonicalPath :=
  { segments := ["shortcut"]
    isValid := by decide }

private def symlinkTarget : CanonicalPath :=
  { segments := ["target"]
    isValid := by decide }

private def aliasObject : NamespaceObject := {
  id := ⟨"alias-object"⟩
  path := aliasPrimary
  kind := .regularFile
  openHandleCount := 0
  aliases := [aliasPrimary, aliasSecondary]
  symlinkTarget := none }

private theorem aliasPrimary_ne_aliasSecondary :
    aliasPrimary ≠ aliasSecondary := by
  intro samePath
  have sameSegments := congrArg CanonicalPath.segments samePath
  simp [aliasPrimary, aliasSecondary] at sameSegments

private def aliasNamespace : NamespaceState where
  objects := replace (fun _ => none) aliasObject.id (some aliasObject)
  paths := replace
    (replace (fun _ => none) aliasPrimary (some aliasObject.id))
    aliasSecondary (some aliasObject.id)
  issuedObjects := replace (fun _ => false) aliasObject.id true
  nextObjectSequence := none
  generation := 0

/-- Two distinct names concretely inhabit the finite alias-set model. -/
theorem concrete_alias_witness :
    ∃ object : NamespaceObject,
      object.aliases = [aliasPrimary, aliasSecondary] ∧
      object.ShapeWellFormed := by
  refine ⟨aliasObject, rfl, ?_⟩
  simp [aliasObject, NamespaceObject.ShapeWellFormed,
    NamespaceObject.AliasesWellFormed, NamespaceObject.TargetWellFormed,
    aliasPrimary, aliasSecondary]

/-- The exact two-name index has a concrete alias-well-formed state witness. -/
theorem concrete_alias_state_witness : aliasNamespace.AliasWellFormed := by
  refine ⟨?_, ?_, ?_, ?_, ?_⟩
  · intro objectId object objectLookup
    by_cases sameId : objectId = aliasObject.id
    · subst objectId
      simp [aliasNamespace, replace] at objectLookup
      subst object
      rfl
    · simp [aliasNamespace, replace, sameId] at objectLookup
  · intro objectId object objectLookup
    by_cases sameId : objectId = aliasObject.id
    · subst objectId
      simp [aliasNamespace, replace] at objectLookup
      subst object
      simp [aliasObject, NamespaceObject.ShapeWellFormed,
        NamespaceObject.AliasesWellFormed, NamespaceObject.TargetWellFormed,
        aliasPrimary, aliasSecondary]
    · simp [aliasNamespace, replace, sameId] at objectLookup
  · intro objectId object path objectLookup aliasMember
    by_cases sameId : objectId = aliasObject.id
    · subst objectId
      simp [aliasNamespace, replace] at objectLookup
      subst object
      simp only [aliasObject, List.mem_cons, List.mem_singleton] at aliasMember
      rcases aliasMember with primary | secondary
      · subst path
        simp [aliasNamespace, replace, aliasPrimary_ne_aliasSecondary]
      · rcases secondary with secondary | impossible
        · subst path
          simp [aliasNamespace, replace]
        · contradiction
    · simp [aliasNamespace, replace, sameId] at objectLookup
  · intro path objectId pathLookup
    by_cases secondary : path = aliasSecondary
    · subst path
      simp [aliasNamespace, replace] at pathLookup
      subst objectId
      exact ⟨aliasObject, by simp [aliasNamespace, replace], by simp [aliasObject]⟩
    · by_cases primary : path = aliasPrimary
      · subst path
        simp [aliasNamespace, replace, aliasPrimary_ne_aliasSecondary] at pathLookup
        subst objectId
        exact ⟨aliasObject, by simp [aliasNamespace, replace], by simp [aliasObject]⟩
      · simp [aliasNamespace, replace, secondary, primary] at pathLookup
  · intro objectId object objectLookup
    by_cases sameId : objectId = aliasObject.id
    · subst objectId
      simp [aliasNamespace, replace]
    · simp [aliasNamespace, replace, sameId] at objectLookup

/-- A contained symbolic-link target concretely inhabits the kind/target invariant. -/
theorem concrete_symlink_witness :
    ∃ object : NamespaceObject,
      object.kind = .symlink ∧
      object.symlinkTarget = some symlinkTarget ∧
      object.ShapeWellFormed := by
  let object : NamespaceObject := {
    id := ⟨"symlink-object"⟩
    path := symlinkName
    kind := .symlink
    openHandleCount := 0
    aliases := [symlinkName]
    symlinkTarget := some symlinkTarget }
  refine ⟨object, rfl, rfl, ?_⟩
  simp [object, NamespaceObject.ShapeWellFormed,
    NamespaceObject.AliasesWellFormed, NamespaceObject.TargetWellFormed]

private def traceRootId : ObjectId := ⟨"trace-root"⟩

private def traceObject : NamespaceObject := {
  id := NamespaceState.allocatedObjectId 1
  path := symlinkName
  kind := .symlink
  openHandleCount := 0
  aliases := [symlinkName]
  symlinkTarget := some symlinkTarget }

private def traceInitial : NamespaceState := NamespaceState.withRoot traceRootId

private theorem traceObjectId_ne_rootId : traceObject.id ≠ traceRootId := by
  native_decide

private theorem symlinkName_ne_root : symlinkName ≠ CanonicalPath.root := by
  intro equality
  have segments := congrArg CanonicalPath.segments equality
  simp [symlinkName, CanonicalPath.root] at segments

private theorem aliasSecondary_ne_root :
    aliasSecondary ≠ CanonicalPath.root := by
  intro equality
  have segments := congrArg CanonicalPath.segments equality
  simp [aliasSecondary, CanonicalPath.root] at segments

private theorem aliasSecondary_ne_symlinkName :
    aliasSecondary ≠ symlinkName := by
  intro equality
  have segments := congrArg CanonicalPath.segments equality
  simp [aliasSecondary, symlinkName] at segments

private def traceMayCreate : traceInitial.MayCreate traceObject := by
  refine {
    allocationSequence := 1
    cursorExpected := rfl
    sequenceRepresentable := by simp [FitsU64, u64Maximum]
    objectIdAllocated := rfl
    generationCanIncrement := by simp [CanIncrementU64, traceInitial,
      NamespaceState.withRoot, u64Maximum]
    objectIdFresh := ?_
    objectAbsent := ?_
    pathAbsent := ?_
    startsClosed := rfl
    parentId := traceRootId
    parent := NamespaceState.rootObject traceRootId
    parentLookup := ?_
    parentPathLookup := ?_
    parentIsDirectory := rfl
    directChild := ?_ }
  · simp [traceInitial, NamespaceState.withRoot, replace,
      traceObjectId_ne_rootId]
  · simp [traceInitial, NamespaceState.withRoot, replace,
      traceObjectId_ne_rootId]
  · simp [traceInitial, traceObject, NamespaceState.withRoot, replace,
      symlinkName_ne_root]
  · simp [traceInitial, NamespaceState.withRoot, replace]
  · simp [traceInitial, NamespaceState.withRoot,
      NamespaceState.rootObject, replace]
  · exact ⟨"shortcut", by rfl⟩

private def traceMayCreateSymlink :
    traceInitial.MayCreateSymlink traceObject := {
  complete := NamespaceState.withRoot_completeWellFormed traceRootId
  creation := traceMayCreate
  kindIsSymlink := rfl
  aliasesSingleton := rfl
  target := symlinkTarget
  targetStored := rfl }

private def traceCreated : NamespaceState := traceInitial.createSymlink traceObject

private theorem traceCreated_complete : traceCreated.CompleteWellFormed :=
  NamespaceState.createSymlink_preserves_completeWellFormed traceMayCreateSymlink

private def traceMayLink :
    traceCreated.MayAddHardLink traceObject.id aliasSecondary := by
  refine {
    generationCanIncrement := by simp [traceCreated, traceInitial,
      NamespaceState.createSymlink, NamespaceState.create, CanIncrementU64,
      NamespaceState.withRoot, u64Maximum]
    complete := traceCreated_complete
    object := traceObject
    objectLookup := ?_
    sourceIsNotDirectory := by simp [traceObject]
    aliasAbsent := ?_
    aliasNotRoot := aliasSecondary_ne_root
    parentId := traceRootId
    parent := NamespaceState.rootObject traceRootId
    parentLookup := ?_
    parentPathLookup := ?_
    parentIsDirectory := rfl
    directChild := ?_ }
  · exact NamespaceState.create_stores_object traceInitial traceObject
  · simp [traceCreated, traceInitial, NamespaceState.createSymlink,
      NamespaceState.create, NamespaceState.withRoot, replace,
      traceObject, aliasSecondary_ne_symlinkName, aliasSecondary_ne_root]
  · simp [traceCreated, traceInitial, NamespaceState.createSymlink,
      NamespaceState.create, NamespaceState.withRoot, replace,
      traceObjectId_ne_rootId.symm]
  · simp [traceCreated, traceInitial, NamespaceState.createSymlink,
      NamespaceState.create, NamespaceState.withRoot,
      NamespaceState.rootObject, replace, traceObject, symlinkName_ne_root,
      symlinkName_ne_root.symm]
  · exact ⟨"secondary", by rfl⟩

private def traceLinked : NamespaceState :=
  traceCreated.addHardLink traceObject.id traceObject aliasSecondary

private theorem traceLinked_complete : traceLinked.CompleteWellFormed :=
  NamespaceState.addHardLink_preserves_completeWellFormed traceMayLink

private def traceMayUnlink :
    traceLinked.MayUnlinkName traceObject.id symlinkName := by
  refine {
    generationCanIncrement := by simp [traceLinked, traceCreated, traceInitial,
      NamespaceState.addHardLink, NamespaceState.createSymlink,
      NamespaceState.create, NamespaceState.withRoot, CanIncrementU64, u64Maximum]
    complete := traceLinked_complete
    object := NamespaceState.withAddedAlias traceObject aliasSecondary
    objectLookup := ?_
    sourceIsNotDirectory := by simp [NamespaceState.withAddedAlias, traceObject]
    noOpenHandles := rfl
    aliasIndexed := ?_
    newPrimary := aliasSecondary
    remaining := []
    partition := by simp [NamespaceState.withAddedAlias, traceObject]
    newPrimaryIndexed := ?_
    newPrimaryNotRoot := aliasSecondary_ne_root
    parentId := traceRootId
    parent := NamespaceState.rootObject traceRootId
    parentLookup := ?_
    parentPathLookup := ?_
    parentIsDirectory := rfl
    directChild := ?_ }
  · exact NamespaceState.addHardLink_stores_object traceCreated traceObject.id
      traceObject aliasSecondary
  · have oldPath := NamespaceState.create_stores_path traceInitial traceObject
    simpa [traceLinked, NamespaceState.addHardLink, replace, symlinkName,
      aliasSecondary] using oldPath
  · exact NamespaceState.addHardLink_stores_path traceCreated traceObject.id
      traceObject aliasSecondary
  · simp [traceLinked, traceCreated, traceInitial,
      NamespaceState.addHardLink, NamespaceState.createSymlink,
      NamespaceState.create, NamespaceState.withRoot, replace,
      traceObjectId_ne_rootId.symm]
  · simp [traceLinked, traceCreated, traceInitial,
      NamespaceState.addHardLink, NamespaceState.createSymlink,
      NamespaceState.create, NamespaceState.withRoot,
      NamespaceState.rootObject, replace, traceObject, aliasSecondary_ne_root,
      aliasSecondary_ne_root.symm, symlinkName_ne_root,
      symlinkName_ne_root.symm]
  · exact ⟨"secondary", by rfl⟩

private def traceFinal : NamespaceState :=
  traceLinked.unlinkName traceObject.id
    (NamespaceState.withAddedAlias traceObject aliasSecondary)
    symlinkName aliasSecondary []

/--
A concrete finite execution creates a symlink, adds a second hard-link name,
then unlinks its primary name. The surviving representative and target are exact.
-/
theorem concrete_multiAlias_symlink_trace :
    NamespaceState.CompleteSteps traceInitial traceFinal ∧
      traceLinked.paths symlinkName = some traceObject.id ∧
      traceLinked.paths aliasSecondary = some traceObject.id ∧
      traceFinal.paths symlinkName = none ∧
      traceFinal.objects traceObject.id = some
        (NamespaceState.withRemainingAliases
          (NamespaceState.withAddedAlias traceObject aliasSecondary)
          aliasSecondary []) ∧
      (NamespaceState.withRemainingAliases
        (NamespaceState.withAddedAlias traceObject aliasSecondary)
        aliasSecondary []).symlinkTarget = some symlinkTarget := by
  have created : NamespaceState.CompleteSteps traceInitial traceCreated :=
    .tail (.refl traceInitial) (.createSymlink traceMayCreateSymlink)
  have linked : NamespaceState.CompleteSteps traceInitial traceLinked :=
    .tail created (.addHardLink traceMayLink)
  have unlinked : NamespaceState.CompleteSteps traceInitial traceFinal :=
    .tail linked (.unlinkName traceMayUnlink)
  refine ⟨unlinked, ?_, ?_, ?_, ?_, ?_⟩
  · have oldPath := NamespaceState.create_stores_path traceInitial traceObject
    simpa [traceLinked, NamespaceState.addHardLink, replace, symlinkName,
      aliasSecondary] using oldPath
  · exact NamespaceState.addHardLink_stores_path traceCreated traceObject.id
      traceObject aliasSecondary
  · exact NamespaceState.unlinkName_clears_path traceLinked traceObject.id
      (NamespaceState.withAddedAlias traceObject aliasSecondary) symlinkName
      aliasSecondary []
  · exact NamespaceState.unlinkName_stores_object traceLinked traceObject.id
      (NamespaceState.withAddedAlias traceObject aliasSecondary) symlinkName
      aliasSecondary []
  · rfl

private def unknownWitnessState : State :=
  State.ofIntegrated (IntegratedHandleState.initial ⟨"capfs-issuer"⟩)

private def unknownWitnessProposed :
    ProposedEffect unknownWitnessState unknownWitnessState.integrated := {
  operational := rfl
  noUnresolved := rfl
  execution := .refl unknownWitnessState.integrated }

/-- A concrete indeterminate syscall retains a durable attempt and quarantines. -/
theorem concrete_commitUnknown_witness :
    ∃ after,
      OrdinaryStep unknownWitnessState after ∧
      after.repositoryHealth = .inDoubt ∧
      (⟨0⟩ : AttemptId) ∈ after.unresolvedAttempts := by
  exact ⟨unknownWitnessState.publishUnknown unknownWitnessState.integrated ⟨0⟩
      .staged,
    .commitUnknown unknownWitnessProposed,
    rfl, by simp [State.publishUnknown]⟩

end Authority.Refinement.Capfs
