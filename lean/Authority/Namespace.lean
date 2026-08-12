import Authority.State

/-!
# Capability Filesystem Namespace

An abstract link-free namespace with reciprocal object/path indexes, monotone
object identity reservation, generation tracking, and open-handle exclusion.
FUSE and host-filesystem calls refine this sequential specification.
-/

namespace Authority

/-- Canonical paths are equal exactly when their validated segment lists are equal. -/
instance : DecidableEq CanonicalPath := fun first second => by
  cases first
  cases second
  simp only [CanonicalPath.mk.injEq]
  infer_instance

/-- Object kinds accepted by the link-free namespace. -/
inductive NamespaceObjectKind where
  | directory
  | regularFile
  deriving Repr, BEq, DecidableEq

/-- Current record for one live namespace object. -/
structure NamespaceObject where
  id : ObjectId
  path : CanonicalPath
  kind : NamespaceObjectKind
  openHandleCount : Nat
  deriving DecidableEq

/-- VM-wide namespace state before synchronization and backing operations. -/
structure NamespaceState where
  objects : ObjectId → Option NamespaceObject
  paths : CanonicalPath → Option ObjectId
  issuedObjects : ObjectId → Bool
  generation : Nat

namespace NamespaceState

/-- `parent` is the immediate canonical parent of `child`. -/
def DirectParent (parent child : CanonicalPath) : Prop :=
  ∃ segment, child.segments = parent.segments ++ [segment]

/-- `child` lies strictly below `ancestor` in the canonical path tree. -/
def ProperDescendant (child ancestor : CanonicalPath) : Prop :=
  ∃ suffix, suffix ≠ [] ∧ child.segments = ancestor.segments ++ suffix

/-- Empty abstract state; a concrete adapter may separately install its root. -/
def empty : NamespaceState where
  objects := fun _ => none
  paths := fun _ => none
  issuedObjects := fun _ => false
  generation := 0

/-- The closed directory record installed at namespace initialization. -/
def rootObject (rootId : ObjectId) : NamespaceObject where
  id := rootId
  path := CanonicalPath.root
  kind := .directory
  openHandleCount := 0

/-- Initial namespace containing exactly one closed directory root. -/
def withRoot (rootId : ObjectId) : NamespaceState :=
  { objects := replace (fun _ => none) rootId (some (rootObject rootId))
    paths := replace (fun _ => none) CanonicalPath.root (some rootId)
    issuedObjects := replace (fun _ => false) rootId true
    generation := 0 }

/-- Both indexes describe the same live objects and canonical paths. -/
structure WellFormed (state : NamespaceState) : Prop where
  objectToPath : ∀ objectId object,
    state.objects objectId = some object →
      object.id = objectId ∧ state.paths object.path = some objectId
  pathToObject : ∀ path objectId,
    state.paths path = some objectId →
      ∃ object, state.objects objectId = some object ∧ object.path = path
  liveWasIssued : ∀ objectId object,
    state.objects objectId = some object → state.issuedObjects objectId = true

/-- The singleton root namespace satisfies all reciprocal-index invariants. -/
theorem withRoot_wellFormed (rootId : ObjectId) : (withRoot rootId).WellFormed := by
  constructor
  · intro objectId object objectLookup
    by_cases sameId : objectId = rootId
    · subst objectId
      simp [withRoot, replace] at objectLookup
      subst object
      exact ⟨rfl, by simp [withRoot, rootObject, replace]⟩
    · simp [withRoot, replace, sameId] at objectLookup
  · intro path objectId pathLookup
    by_cases samePath : path = CanonicalPath.root
    · subst path
      simp [withRoot, replace] at pathLookup
      subst objectId
      exact ⟨rootObject rootId, by simp [withRoot, replace], by simp [rootObject]⟩
    · simp [withRoot, replace, samePath] at pathLookup
  · intro objectId object objectLookup
    by_cases sameId : objectId = rootId
    · subst objectId
      simp [withRoot, replace]
    · simp [withRoot, replace, sameId] at objectLookup

/-- A well-formed namespace maps one object identity to only one current path. -/
theorem WellFormed.object_path_unique {state : NamespaceState}
    (_wellFormed : state.WellFormed) {objectId : ObjectId}
    {first second : NamespaceObject}
    (firstLookup : state.objects objectId = some first)
    (secondLookup : state.objects objectId = some second) : first.path = second.path := by
  have sameObject : first = second := Option.some.inj
    (firstLookup.symm.trans secondLookup)
  exact congrArg NamespaceObject.path sameObject

/-- A well-formed namespace maps one path to only one object identity. -/
theorem WellFormed.path_object_unique {state : NamespaceState}
    (_wellFormed : state.WellFormed) {path : CanonicalPath}
    {first second : ObjectId}
    (firstLookup : state.paths path = some first)
    (secondLookup : state.paths path = some second) : first = second := by
  exact Option.some.inj (firstLookup.symm.trans secondLookup)

/-- Preconditions for publishing a fresh namespace object. -/
structure MayCreate (state : NamespaceState) (object : NamespaceObject) where
  objectIdFresh : state.issuedObjects object.id = false
  objectAbsent : state.objects object.id = none
  pathAbsent : state.paths object.path = none
  startsClosed : object.openHandleCount = 0
  parentId : ObjectId
  parent : NamespaceObject
  parentLookup : state.objects parentId = some parent
  parentPathLookup : state.paths parent.path = some parentId
  parentIsDirectory : parent.kind = .directory
  directChild : DirectParent parent.path object.path

/-- Recover the created identity indexed by creation evidence. -/
def MayCreate.objectId {state : NamespaceState} {object : NamespaceObject}
    (_ : MayCreate state object) : ObjectId := object.id

/-- Atomically publish reciprocal object and path indexes. -/
def create (state : NamespaceState) (object : NamespaceObject) : NamespaceState :=
  { objects := replace state.objects object.id (some object)
    paths := replace state.paths object.path (some object.id)
    issuedObjects := replace state.issuedObjects object.id true
    generation := state.generation + 1 }

/-- Creation stores the complete object record. -/
theorem create_stores_object (state : NamespaceState) (object : NamespaceObject) :
    (state.create object).objects object.id = some object := by
  simp [create]

/-- Creation installs the reciprocal path index. -/
theorem create_stores_path (state : NamespaceState) (object : NamespaceObject) :
    (state.create object).paths object.path = some object.id := by
  simp [create]

/-- Creation permanently reserves the fresh object identity. -/
theorem create_reserves_identity (state : NamespaceState) (object : NamespaceObject) :
    (state.create object).issuedObjects object.id = true := by
  simp [create]

/-- Creation preserves reciprocal-index well-formedness. -/
theorem create_preserves_wellFormed {state : NamespaceState}
    {object : NamespaceObject} (wellFormed : state.WellFormed)
    (allowed : MayCreate state object) : (state.create object).WellFormed := by
  constructor
  · intro queriedId queriedObject queriedLookup
    by_cases sameId : queriedId = object.id
    · subst queriedId
      have exactObject : queriedObject = object := Option.some.inj
        (queriedLookup.symm.trans (create_stores_object state object))
      subst queriedObject
      exact ⟨rfl, create_stores_path state object⟩
    · have oldLookup : state.objects queriedId = some queriedObject := by
        simpa [create, replace, sameId] using queriedLookup
      rcases wellFormed.objectToPath queriedId queriedObject oldLookup with
        ⟨identityMatches, oldPathLookup⟩
      refine ⟨identityMatches, ?_⟩
      by_cases samePath : queriedObject.path = object.path
      · have pathWasAbsent := allowed.pathAbsent
        rw [← samePath, oldPathLookup] at pathWasAbsent
        cases pathWasAbsent
      · simp [create, replace, samePath]
        exact oldPathLookup
  · intro queriedPath queriedId queriedLookup
    by_cases samePath : queriedPath = object.path
    · subst queriedPath
      have exactId : queriedId = object.id := Option.some.inj
        (queriedLookup.symm.trans (create_stores_path state object))
      subst queriedId
      exact ⟨object, create_stores_object state object, rfl⟩
    · have oldLookup : state.paths queriedPath = some queriedId := by
        simpa [create, replace, samePath] using queriedLookup
      rcases wellFormed.pathToObject queriedPath queriedId oldLookup with
        ⟨oldObject, objectLookup, pathMatches⟩
      refine ⟨oldObject, ?_, pathMatches⟩
      have differentId : queriedId ≠ object.id := by
        intro sameId
        subst queriedId
        have identityWasAbsent := allowed.objectAbsent
        rw [objectLookup] at identityWasAbsent
        cases identityWasAbsent
      simpa [create, replace, differentId] using objectLookup
  · intro queriedId queriedObject queriedLookup
    by_cases sameId : queriedId = object.id
    · subst queriedId
      exact create_reserves_identity state object
    · have oldLookup : state.objects queriedId = some queriedObject := by
        simpa [create, replace, sameId] using queriedLookup
      have oldIssued := wellFormed.liveWasIssued queriedId queriedObject oldLookup
      simpa [create, replace, sameId] using oldIssued

/-- Preconditions for removing one live, unopened object. -/
structure MayRemove (state : NamespaceState) (objectId : ObjectId) where
  object : NamespaceObject
  objectLookup : state.objects objectId = some object
  identityMatches : object.id = objectId
  pathLookup : state.paths object.path = some objectId
  noOpenHandles : object.openHandleCount = 0
  notRoot : object.path ≠ CanonicalPath.root
  directoryEmpty : object.kind = .directory →
    ∀ childId child, state.objects childId = some child →
      ¬ ProperDescendant child.path object.path

/-- Remove a live object while retaining its identity reservation. -/
def remove (state : NamespaceState) (objectId : ObjectId)
    (object : NamespaceObject) : NamespaceState :=
  { state with
    objects := replace state.objects objectId none
    paths := replace state.paths object.path none
    generation := state.generation + 1 }

/-- Removal clears the live object index. -/
theorem remove_clears_object (state : NamespaceState)
    (objectId : ObjectId) (object : NamespaceObject) :
    (state.remove objectId object).objects objectId = none := by
  simp [remove]

/-- Removal clears the object's former path. -/
theorem remove_clears_path (state : NamespaceState)
    (objectId : ObjectId) (object : NamespaceObject) :
    (state.remove objectId object).paths object.path = none := by
  simp [remove]

/-- Removal never releases an issued object identity. -/
theorem remove_preserves_identity_reservation (state : NamespaceState)
    (objectId : ObjectId) (object : NamespaceObject) :
    (state.remove objectId object).issuedObjects = state.issuedObjects := by
  rfl

/-- Removing an unopened live object preserves reciprocal-index consistency. -/
theorem remove_preserves_wellFormed {state : NamespaceState}
    {objectId : ObjectId} (wellFormed : state.WellFormed)
    (allowed : MayRemove state objectId) :
    (state.remove objectId allowed.object).WellFormed := by
  constructor
  · intro queriedId queriedObject queriedLookup
    have differentId : queriedId ≠ objectId := by
      intro sameId
      subst queriedId
      simp [remove] at queriedLookup
    have oldLookup : state.objects queriedId = some queriedObject := by
      simpa [remove, replace, differentId] using queriedLookup
    rcases wellFormed.objectToPath queriedId queriedObject oldLookup with
      ⟨identityMatches, oldPathLookup⟩
    refine ⟨identityMatches, ?_⟩
    have differentPath : queriedObject.path ≠ allowed.object.path := by
      intro samePath
      have sameOwner := Option.some.inj
        (oldPathLookup.symm.trans (samePath ▸ allowed.pathLookup))
      exact differentId sameOwner
    simpa [remove, replace, differentPath] using oldPathLookup
  · intro queriedPath queriedId queriedLookup
    have differentPath : queriedPath ≠ allowed.object.path := by
      intro samePath
      subst queriedPath
      simp [remove] at queriedLookup
    have oldPathLookup : state.paths queriedPath = some queriedId := by
      simpa [remove, replace, differentPath] using queriedLookup
    rcases wellFormed.pathToObject queriedPath queriedId oldPathLookup with
      ⟨queriedObject, oldObjectLookup, pathMatches⟩
    have differentId : queriedId ≠ objectId := by
      intro sameId
      subst queriedId
      have sameObject := Option.some.inj
        (oldObjectLookup.symm.trans allowed.objectLookup)
      have samePath := congrArg NamespaceObject.path sameObject
      exact differentPath (pathMatches.symm.trans samePath)
    exact ⟨queriedObject,
      by simpa [remove, replace, differentId] using oldObjectLookup, pathMatches⟩
  · intro queriedId queriedObject queriedLookup
    have differentId : queriedId ≠ objectId := by
      intro sameId
      subst queriedId
      simp [remove] at queriedLookup
    exact wellFormed.liveWasIssued queriedId queriedObject
      (by simpa [remove, replace, differentId] using queriedLookup)

/-- A reversible transformation of the complete canonical path space. -/
structure PathRenaming where
  forward : CanonicalPath → CanonicalPath
  inverse : CanonicalPath → CanonicalPath
  inverseForward : ∀ path, inverse (forward path) = path
  forwardInverse : ∀ path, forward (inverse path) = path
  preservesRoot : forward CanonicalPath.root = CanonicalPath.root

namespace PathRenaming

/-- A reversible path transformation is injective. -/
theorem forward_injective (pathMapping : PathRenaming) :
    ∀ {first second}, pathMapping.forward first = pathMapping.forward second →
      first = second := by
  intro first second sameDestination
  have := congrArg pathMapping.inverse sameDestination
  simpa [pathMapping.inverseForward] using this

end PathRenaming

/-- Safety preconditions for a global reversible path transaction. -/
structure MayRename (state : NamespaceState) (_pathMapping : PathRenaming) : Prop where
  allHandlesClosed : ∀ objectId object,
    state.objects objectId = some object → object.openHandleCount = 0

/-- Rename every live path through one reversible transformation. -/
def renamePaths (state : NamespaceState) (pathMapping : PathRenaming) : NamespaceState :=
  { state with
    objects := fun objectId => (state.objects objectId).map
      (fun object => { object with path := pathMapping.forward object.path })
    paths := fun path => state.paths (pathMapping.inverse path)
    generation := state.generation + 1 }

/-- Rename never changes object identity, kind, or open-handle count. -/
theorem rename_preserves_object_fields {state : NamespaceState}
    {pathMapping : PathRenaming} {objectId : ObjectId} {object : NamespaceObject}
    (lookup : state.objects objectId = some object) :
    (state.renamePaths pathMapping).objects objectId = some {
      object with path := pathMapping.forward object.path
    } := by
  simp [renamePaths, lookup]

/-- Reciprocal indexes remain well formed under every reversible path rename. -/
theorem rename_preserves_wellFormed {state : NamespaceState}
    (wellFormed : state.WellFormed) (pathMapping : PathRenaming) :
    (state.renamePaths pathMapping).WellFormed := by
  constructor
  · intro objectId renamedObject renamedLookup
    simp only [renamePaths] at renamedLookup
    cases oldLookup : state.objects objectId with
    | none => simp [oldLookup] at renamedLookup
    | some oldObject =>
        simp [oldLookup] at renamedLookup
        subst renamedObject
        rcases wellFormed.objectToPath objectId oldObject oldLookup with
          ⟨identityMatches, oldPathLookup⟩
        refine ⟨identityMatches, ?_⟩
        simp [renamePaths, pathMapping.inverseForward, oldPathLookup]
  · intro renamedPath objectId renamedLookup
    have oldPathLookup : state.paths (pathMapping.inverse renamedPath) = some objectId :=
      renamedLookup
    rcases wellFormed.pathToObject (pathMapping.inverse renamedPath) objectId oldPathLookup with
      ⟨oldObject, objectLookup, pathMatches⟩
    refine ⟨{ oldObject with path := pathMapping.forward oldObject.path }, ?_, ?_⟩
    · exact rename_preserves_object_fields objectLookup
    · rw [pathMatches, pathMapping.forwardInverse]
  · intro objectId renamedObject renamedLookup
    simp only [renamePaths] at renamedLookup
    cases oldLookup : state.objects objectId with
    | none => simp [oldLookup] at renamedLookup
    | some oldObject =>
        exact wellFormed.liveWasIssued objectId oldObject oldLookup

/-- Open one live object without changing its canonical path or generation. -/
def withOpenHandleCount (object : NamespaceObject) (count : Nat) : NamespaceObject :=
  { object with openHandleCount := count }

/-- Open one live object without changing its canonical path or generation. -/
def openObject (state : NamespaceState) (objectId : ObjectId)
    (object : NamespaceObject) : NamespaceState :=
  let openedObject := withOpenHandleCount object (object.openHandleCount + 1)
  { state with objects := replace state.objects objectId (some openedObject) }

/-- Close one live object handle without changing its path or generation. -/
def closeObject (state : NamespaceState) (objectId : ObjectId)
    (object : NamespaceObject) : NamespaceState :=
  let closedObject := withOpenHandleCount object (object.openHandleCount - 1)
  { state with objects := replace state.objects objectId (some closedObject) }

/-- Open increments only the selected object's live-handle count. -/
theorem openObject_increments_count (state : NamespaceState)
    (objectId : ObjectId) (object : NamespaceObject) :
    (state.openObject objectId object).objects objectId =
      some (withOpenHandleCount object (object.openHandleCount + 1)) := by
  simp [openObject]

/-- Close decrements only the selected object's live-handle count. -/
theorem closeObject_decrements_count (state : NamespaceState)
    (objectId : ObjectId) (object : NamespaceObject) :
    (state.closeObject objectId object).objects objectId =
      some (withOpenHandleCount object (object.openHandleCount - 1)) := by
  simp [closeObject]

/-- Creation cannot revoke an identity that was already reserved. -/
theorem create_preserves_issued_identity (state : NamespaceState)
    (object : NamespaceObject) {queriedId : ObjectId}
    (issuedBefore : state.issuedObjects queriedId = true) :
    (state.create object).issuedObjects queriedId = true := by
  by_cases sameId : queriedId = object.id
  · subst queriedId
    exact create_reserves_identity state object
  · simpa [create, replace, sameId] using issuedBefore

/-- Opening a correctly indexed live object preserves index consistency. -/
theorem openObject_preserves_wellFormed {state : NamespaceState}
    {objectId : ObjectId} {object : NamespaceObject}
    (wellFormed : state.WellFormed)
    (objectLookup : state.objects objectId = some object) :
    (state.openObject objectId object).WellFormed := by
  constructor
  · intro queriedId queriedObject queriedLookup
    by_cases sameId : queriedId = objectId
    · subst queriedId
      have exactObject : queriedObject =
          withOpenHandleCount object (object.openHandleCount + 1) := Option.some.inj
        (queriedLookup.symm.trans (openObject_increments_count state objectId object))
      subst queriedObject
      rcases wellFormed.objectToPath objectId object objectLookup with
        ⟨identityMatches, pathLookup⟩
      exact ⟨identityMatches, pathLookup⟩
    · exact wellFormed.objectToPath queriedId queriedObject
        (by simpa [openObject, replace, sameId] using queriedLookup)
  · intro path queriedId pathLookup
    rcases wellFormed.pathToObject path queriedId pathLookup with
      ⟨queriedObject, oldLookup, pathMatches⟩
    by_cases sameId : queriedId = objectId
    · subst queriedId
      have exactObject : queriedObject = object := Option.some.inj
        (oldLookup.symm.trans objectLookup)
      subst queriedObject
      exact ⟨withOpenHandleCount object (object.openHandleCount + 1),
        openObject_increments_count state objectId object, pathMatches⟩
    · exact ⟨queriedObject,
        by simpa [openObject, replace, sameId] using oldLookup, pathMatches⟩
  · intro queriedId queriedObject queriedLookup
    by_cases sameId : queriedId = objectId
    · subst queriedId
      exact wellFormed.liveWasIssued objectId object objectLookup
    · exact wellFormed.liveWasIssued queriedId queriedObject
        (by simpa [openObject, replace, sameId] using queriedLookup)

/-- Closing a correctly indexed live object preserves index consistency. -/
theorem closeObject_preserves_wellFormed {state : NamespaceState}
    {objectId : ObjectId} {object : NamespaceObject}
    (wellFormed : state.WellFormed)
    (objectLookup : state.objects objectId = some object) :
    (state.closeObject objectId object).WellFormed := by
  constructor
  · intro queriedId queriedObject queriedLookup
    by_cases sameId : queriedId = objectId
    · subst queriedId
      have exactObject : queriedObject =
          withOpenHandleCount object (object.openHandleCount - 1) := Option.some.inj
        (queriedLookup.symm.trans (closeObject_decrements_count state objectId object))
      subst queriedObject
      rcases wellFormed.objectToPath objectId object objectLookup with
        ⟨identityMatches, pathLookup⟩
      exact ⟨identityMatches, pathLookup⟩
    · exact wellFormed.objectToPath queriedId queriedObject
        (by simpa [closeObject, replace, sameId] using queriedLookup)
  · intro path queriedId pathLookup
    rcases wellFormed.pathToObject path queriedId pathLookup with
      ⟨queriedObject, oldLookup, pathMatches⟩
    by_cases sameId : queriedId = objectId
    · subst queriedId
      have exactObject : queriedObject = object := Option.some.inj
        (oldLookup.symm.trans objectLookup)
      subst queriedObject
      exact ⟨withOpenHandleCount object (object.openHandleCount - 1),
        closeObject_decrements_count state objectId object, pathMatches⟩
    · exact ⟨queriedObject,
        by simpa [closeObject, replace, sameId] using oldLookup, pathMatches⟩
  · intro queriedId queriedObject queriedLookup
    by_cases sameId : queriedId = objectId
    · subst queriedId
      exact wellFormed.liveWasIssued objectId object objectLookup
    · exact wellFormed.liveWasIssued queriedId queriedObject
        (by simpa [closeObject, replace, sameId] using queriedLookup)

/-- Namespace-mutating steps and handle-count steps. -/
inductive Step : NamespaceState → NamespaceState → Prop
  | create {state : NamespaceState} {object : NamespaceObject} :
      MayCreate state object → Step state (state.create object)
  | remove {state : NamespaceState} {objectId : ObjectId} :
      (allowed : MayRemove state objectId) →
      Step state (state.remove objectId allowed.object)
  | renamePaths {state : NamespaceState} {pathMapping : PathRenaming} :
      MayRename state pathMapping → Step state (state.renamePaths pathMapping)
  | openObject {state : NamespaceState} {objectId : ObjectId}
      {object : NamespaceObject} :
      state.objects objectId = some object →
      Step state (state.openObject objectId object)
  | closeObject {state : NamespaceState} {objectId : ObjectId}
      {object : NamespaceObject} :
      state.objects objectId = some object → 0 < object.openHandleCount →
      Step state (state.closeObject objectId object)

/-- Namespace generation never decreases. -/
theorem Step.generation_monotone {before after : NamespaceState}
    (transition : Step before after) : before.generation ≤ after.generation := by
  cases transition with
  | create => exact Nat.le_succ _
  | remove => exact Nat.le_succ _
  | renamePaths => exact Nat.le_succ _
  | openObject => exact Nat.le_refl _
  | closeObject => exact Nat.le_refl _

/-- Issued object identities are never released by any accepted transition. -/
theorem Step.issued_identity_monotone {before after : NamespaceState}
    (transition : Step before after) {objectId : ObjectId}
    (issuedBefore : before.issuedObjects objectId = true) :
    after.issuedObjects objectId = true := by
  cases transition with
  | create allowed =>
      exact create_preserves_issued_identity _ _ issuedBefore
  | remove => exact issuedBefore
  | renamePaths => exact issuedBefore
  | openObject => exact issuedBefore
  | closeObject => exact issuedBefore

/-- Every accepted namespace step preserves reciprocal-index well-formedness. -/
theorem Step.preserves_wellFormed {before after : NamespaceState}
    (transition : Step before after) (wellFormed : before.WellFormed) :
    after.WellFormed := by
  cases transition with
  | create allowed => exact create_preserves_wellFormed wellFormed allowed
  | remove allowed => exact remove_preserves_wellFormed wellFormed allowed
  | renamePaths _ => exact rename_preserves_wellFormed wellFormed _
  | openObject objectLookup =>
      exact openObject_preserves_wellFormed wellFormed objectLookup
  | closeObject objectLookup _ =>
      exact closeObject_preserves_wellFormed wellFormed objectLookup

/-- Reflexive-transitive closure of accepted namespace transitions. -/
inductive Steps : NamespaceState → NamespaceState → Prop
  | refl (state : NamespaceState) : Steps state state
  | tail {first middle last : NamespaceState} :
      Steps first middle → Step middle last → Steps first last

/-- Reciprocal indexes remain consistent after any finite accepted execution. -/
theorem Steps.preserve_wellFormed {before after : NamespaceState}
    (transitions : Steps before after) (wellFormed : before.WellFormed) :
    after.WellFormed := by
  induction transitions with
  | refl => exact wellFormed
  | tail _ transition inductionHypothesis =>
      exact transition.preserves_wellFormed inductionHypothesis

/-- Namespace generation never decreases during any finite execution. -/
theorem Steps.generation_monotone {before after : NamespaceState}
    (transitions : Steps before after) : before.generation ≤ after.generation := by
  induction transitions with
  | refl => exact Nat.le_refl _
  | tail _ transition inductionHypothesis =>
      exact Nat.le_trans inductionHypothesis transition.generation_monotone

/-- Once issued, an object identity remains reserved after any finite execution. -/
theorem Steps.issued_identity_monotone {before after : NamespaceState}
    (transitions : Steps before after) {objectId : ObjectId}
    (issuedBefore : before.issuedObjects objectId = true) :
    after.issuedObjects objectId = true := by
  induction transitions with
  | refl => exact issuedBefore
  | tail _ transition inductionHypothesis =>
      exact transition.issued_identity_monotone inductionHypothesis

end NamespaceState

end Authority
