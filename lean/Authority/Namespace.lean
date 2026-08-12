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

/-- `path` is the selected subtree root or lies below it. -/
def AtOrBelow (path subtreeRoot : CanonicalPath) : Prop :=
  ∃ suffix, path.segments = subtreeRoot.segments ++ suffix

/-- Every immediate child is a proper descendant of its parent. -/
theorem directParent_implies_properDescendant {parent child : CanonicalPath}
    (directParent : DirectParent parent child) : ProperDescendant child parent := by
  rcases directParent with ⟨segment, pathEquality⟩
  exact ⟨[segment], by simp, pathEquality⟩

/-- A canonical path cannot be its own immediate parent. -/
theorem directParent_irrefl (path : CanonicalPath) : ¬ DirectParent path path := by
  rintro ⟨segment, pathEquality⟩
  have lengthEquality := congrArg List.length pathEquality
  simp at lengthEquality

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

/-- The reciprocal indexes describe one rooted directory tree. -/
structure TreeWellFormed (state : NamespaceState) : Prop where
  indexes : state.WellFormed
  rootExists : ∃ rootId root,
    state.objects rootId = some root ∧
    root.id = rootId ∧
    root.path = CanonicalPath.root ∧
    root.kind = .directory
  parentDirectory : ∀ objectId object,
    state.objects objectId = some object →
      object.path ≠ CanonicalPath.root →
      ∃ parentId parent,
        state.objects parentId = some parent ∧
        state.paths parent.path = some parentId ∧
        parent.kind = .directory ∧
        DirectParent parent.path object.path

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

/-- The singleton initial namespace is a rooted directory tree. -/
theorem withRoot_treeWellFormed (rootId : ObjectId) :
    (withRoot rootId).TreeWellFormed := by
  refine ⟨withRoot_wellFormed rootId, ?_, ?_⟩
  · exact ⟨rootId, rootObject rootId, by simp [withRoot, replace], rfl, rfl, rfl⟩
  intro objectId object objectLookup notRoot
  by_cases sameId : objectId = rootId
  · subst objectId
    simp [withRoot, replace] at objectLookup
    subst object
    exact False.elim (notRoot rfl)
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
  generationCanIncrement : CanIncrementU64 state.generation
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

/-- Publishing a direct child preserves the rooted directory-tree invariant. -/
theorem create_preserves_treeWellFormed {state : NamespaceState}
    {object : NamespaceObject} (treeWellFormed : state.TreeWellFormed)
    (allowed : MayCreate state object) :
    (state.create object).TreeWellFormed := by
  rcases treeWellFormed.rootExists with
    ⟨rootId, root, rootLookup, rootIdentity, rootPath, rootKind⟩
  have objectIdDiffersFromRoot : object.id ≠ rootId := by
    intro sameId
    have rootIssued := treeWellFormed.indexes.liveWasIssued
      rootId root rootLookup
    rw [← sameId] at rootIssued
    rw [allowed.objectIdFresh] at rootIssued
    contradiction
  refine ⟨create_preserves_wellFormed treeWellFormed.indexes allowed, ?_, ?_⟩
  · exact ⟨rootId, root,
      by
        simpa [create, replace, objectIdDiffersFromRoot.symm] using
          rootLookup,
      rootIdentity, rootPath, rootKind⟩
  intro queriedId queriedObject queriedLookup queriedNotRoot
  by_cases isCreatedObject : queriedId = object.id
  · subst queriedId
    have exactObject : queriedObject = object := Option.some.inj
      (queriedLookup.symm.trans (create_stores_object state object))
    subst queriedObject
    exact ⟨allowed.parentId, allowed.parent,
      by
        have parentIdDiffers : allowed.parentId ≠ object.id := by
          intro sameId
          have parentLookup := allowed.parentLookup
          rw [sameId, allowed.objectAbsent] at parentLookup
          contradiction
        simpa [create, replace, parentIdDiffers] using allowed.parentLookup,
      by
        have parentPathDiffers : allowed.parent.path ≠ object.path := by
          intro samePath
          have parentPathLookup := allowed.parentPathLookup
          rw [samePath, allowed.pathAbsent] at parentPathLookup
          contradiction
        simpa [create, replace, parentPathDiffers] using allowed.parentPathLookup,
      allowed.parentIsDirectory, allowed.directChild⟩
  · have oldLookup : state.objects queriedId = some queriedObject := by
      simpa [create, replace, isCreatedObject] using queriedLookup
    rcases treeWellFormed.parentDirectory queriedId queriedObject oldLookup queriedNotRoot with
      ⟨parentId, parent, parentLookup, parentPathLookup, parentKind, directParent⟩
    have parentIdDiffers : parentId ≠ object.id := by
      intro sameId
      subst parentId
      rw [allowed.objectAbsent] at parentLookup
      contradiction
    exact ⟨parentId, parent,
      by simpa [create, replace, parentIdDiffers] using parentLookup,
      by
        have parentPathDiffers : parent.path ≠ object.path := by
          intro samePath
          rw [samePath, allowed.pathAbsent] at parentPathLookup
          contradiction
        simpa [create, replace, parentPathDiffers] using parentPathLookup,
      parentKind, directParent⟩

/-- Preconditions for removing one live, unopened object. -/
structure MayRemove (state : NamespaceState) (objectId : ObjectId) where
  generationCanIncrement : CanIncrementU64 state.generation
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

/-- Removing a non-root empty object preserves the rooted directory tree. -/
theorem remove_preserves_treeWellFormed {state : NamespaceState}
    {objectId : ObjectId} (treeWellFormed : state.TreeWellFormed)
    (allowed : MayRemove state objectId) :
    (state.remove objectId allowed.object).TreeWellFormed := by
  rcases treeWellFormed.rootExists with
    ⟨rootId, root, rootLookup, rootIdentity, rootPath, rootKind⟩
  have removedIdDiffersFromRoot : objectId ≠ rootId := by
    intro sameId
    have sameObject : allowed.object = root := Option.some.inj
      (allowed.objectLookup.symm.trans (sameId ▸ rootLookup))
    have removedRootPath : allowed.object.path = CanonicalPath.root := by
      rw [sameObject, rootPath]
    exact allowed.notRoot removedRootPath
  refine ⟨remove_preserves_wellFormed treeWellFormed.indexes allowed, ?_, ?_⟩
  · exact ⟨rootId, root,
      by
        simpa [remove, replace, removedIdDiffersFromRoot.symm] using rootLookup,
      rootIdentity, rootPath, rootKind⟩
  intro queriedId queriedObject queriedLookup queriedNotRoot
  have queriedIdDiffers : queriedId ≠ objectId := by
    intro sameId
    subst queriedId
    simp [remove] at queriedLookup
  have oldLookup : state.objects queriedId = some queriedObject := by
    simpa [remove, replace, queriedIdDiffers] using queriedLookup
  rcases treeWellFormed.parentDirectory queriedId queriedObject oldLookup queriedNotRoot with
    ⟨parentId, parent, parentLookup, parentPathLookup, parentKind, directParent⟩
  have parentIdDiffers : parentId ≠ objectId := by
    intro sameId
    have sameParent : parent = allowed.object := Option.some.inj
      (parentLookup.symm.trans (sameId ▸ allowed.objectLookup))
    have removedWasDirectory : allowed.object.kind = .directory := by
      rw [← sameParent]
      exact parentKind
    have descendant : ProperDescendant queriedObject.path allowed.object.path := by
      have := directParent_implies_properDescendant directParent
      simpa [sameParent] using this
    exact allowed.directoryEmpty removedWasDirectory queriedId queriedObject
      oldLookup descendant
  have parentPathDiffers : parent.path ≠ allowed.object.path := by
    intro samePath
    have sameOwner := Option.some.inj
      (parentPathLookup.symm.trans (samePath ▸ allowed.pathLookup))
    exact parentIdDiffers sameOwner
  exact ⟨parentId, parent,
    by simpa [remove, replace, parentIdDiffers] using parentLookup,
    by simpa [remove, replace, parentPathDiffers] using parentPathLookup,
    parentKind, directParent⟩

/--
A reversible subtree rebase. `sourceSubtreeRebased` fixes the exact suffix of
every moved path. Parent edges are preserved except at the moved root, whose
new parent is validated by `MayRename`.
-/
structure PathRenaming where
  source : CanonicalPath
  destination : CanonicalPath
  forward : CanonicalPath → CanonicalPath
  inverse : CanonicalPath → CanonicalPath
  inverseForward : ∀ path, inverse (forward path) = path
  forwardInverse : ∀ path, forward (inverse path) = path
  preservesRoot : forward CanonicalPath.root = CanonicalPath.root
  mapsSource : forward source = destination
  sourceSubtreeRebased : ∀ path suffix,
    path.segments = source.segments ++ suffix →
      (forward path).segments = destination.segments ++ suffix
  preservesDirectParentExceptSource : ∀ {parent child},
    child ≠ source →
      DirectParent parent child → DirectParent (forward parent) (forward child)

namespace PathRenaming

/-- A reversible path transformation is injective. -/
theorem forward_injective (pathMapping : PathRenaming) :
    ∀ {first second}, pathMapping.forward first = pathMapping.forward second →
      first = second := by
  intro first second sameDestination
  have := congrArg pathMapping.inverse sameDestination
  simpa [pathMapping.inverseForward] using this

end PathRenaming

/-- Safety preconditions for one no-replace subtree rename transaction. -/
structure MayRename (state : NamespaceState) (pathMapping : PathRenaming) : Prop where
  generationCanIncrement : CanIncrementU64 state.generation
  sourceExists : ∃ sourceId sourceObject,
    state.objects sourceId = some sourceObject ∧
    sourceObject.path = pathMapping.source
  sourceNotRoot : pathMapping.source ≠ CanonicalPath.root
  destinationOutsideSource : ¬ AtOrBelow pathMapping.destination pathMapping.source
  destinationSubtreeEmpty : ∀ objectId object,
    state.objects objectId = some object →
      ¬ AtOrBelow object.path pathMapping.destination
  destinationParentExists : ∃ parentId parent,
    state.objects parentId = some parent ∧
    state.paths parent.path = some parentId ∧
    parent.kind = .directory ∧
    DirectParent parent.path pathMapping.destination ∧
    pathMapping.forward parent.path = parent.path
  outsideSourceUnchanged : ∀ objectId object,
    state.objects objectId = some object →
      ¬ AtOrBelow object.path pathMapping.source →
      pathMapping.forward object.path = object.path
  movedHandlesClosed : ∀ objectId object,
    state.objects objectId = some object →
      AtOrBelow object.path pathMapping.source →
      object.openHandleCount = 0

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

/-- A parent-preserving subtree rebase preserves the rooted directory tree. -/
theorem rename_preserves_treeWellFormed {state : NamespaceState}
    (treeWellFormed : state.TreeWellFormed) (pathMapping : PathRenaming)
    (allowed : state.MayRename pathMapping) :
    (state.renamePaths pathMapping).TreeWellFormed := by
  rcases treeWellFormed.rootExists with
    ⟨rootId, root, rootLookup, rootIdentity, rootPath, rootKind⟩
  let renamedRoot : NamespaceObject :=
    { root with path := pathMapping.forward root.path }
  refine ⟨rename_preserves_wellFormed treeWellFormed.indexes pathMapping, ?_, ?_⟩
  · refine ⟨rootId, renamedRoot,
      rename_preserves_object_fields rootLookup, rootIdentity, ?_, rootKind⟩
    simp [renamedRoot, rootPath, pathMapping.preservesRoot]
  intro objectId renamedObject renamedLookup renamedNotRoot
  simp only [renamePaths] at renamedLookup
  cases oldLookup : state.objects objectId with
  | none => simp [oldLookup] at renamedLookup
  | some oldObject =>
      simp [oldLookup] at renamedLookup
      subst renamedObject
      have oldNotRoot : oldObject.path ≠ CanonicalPath.root := by
        intro oldWasRoot
        apply renamedNotRoot
        simp [oldWasRoot, pathMapping.preservesRoot]
      by_cases isMovedRoot : oldObject.path = pathMapping.source
      · rcases allowed.destinationParentExists with
          ⟨parentId, parent, parentLookup, parentPathLookup, parentKind,
            destinationParent, parentUnchanged⟩
        exact ⟨parentId, { parent with path := pathMapping.forward parent.path },
          rename_preserves_object_fields parentLookup,
          by simp [renamePaths, pathMapping.inverseForward, parentPathLookup],
          parentKind,
          by simpa [isMovedRoot, pathMapping.mapsSource, parentUnchanged] using
            destinationParent⟩
      · rcases treeWellFormed.parentDirectory objectId oldObject oldLookup oldNotRoot with
          ⟨parentId, parent, parentLookup, parentPathLookup, parentKind, directParent⟩
        exact ⟨parentId, { parent with path := pathMapping.forward parent.path },
          rename_preserves_object_fields parentLookup,
          by simp [renamePaths, pathMapping.inverseForward, parentPathLookup],
          parentKind,
          pathMapping.preservesDirectParentExceptSource isMovedRoot directParent⟩

/-- Open one live object without changing its canonical path or generation. -/
def withOpenHandleCount (object : NamespaceObject) (count : Nat) : NamespaceObject :=
  { object with openHandleCount := count }

/-- Replace only the open-handle count of one indexed object. -/
def updateOpenHandleCount (state : NamespaceState) (objectId : ObjectId)
    (object : NamespaceObject) (count : Nat) : NamespaceState :=
  { state with
    objects := replace state.objects objectId
      (some (withOpenHandleCount object count)) }

/-- Open one live object without changing its canonical path or generation. -/
def openObject (state : NamespaceState) (objectId : ObjectId)
    (object : NamespaceObject) : NamespaceState :=
  state.updateOpenHandleCount objectId object (object.openHandleCount + 1)

/-- Close one live object handle without changing its path or generation. -/
def closeObject (state : NamespaceState) (objectId : ObjectId)
    (object : NamespaceObject) : NamespaceState :=
  state.updateOpenHandleCount objectId object (object.openHandleCount - 1)

/-- Open increments only the selected object's live-handle count. -/
theorem openObject_increments_count (state : NamespaceState)
    (objectId : ObjectId) (object : NamespaceObject) :
    (state.openObject objectId object).objects objectId =
      some (withOpenHandleCount object (object.openHandleCount + 1)) := by
  simp [openObject, updateOpenHandleCount]

/-- Close decrements only the selected object's live-handle count. -/
theorem closeObject_decrements_count (state : NamespaceState)
    (objectId : ObjectId) (object : NamespaceObject) :
    (state.closeObject objectId object).objects objectId =
      some (withOpenHandleCount object (object.openHandleCount - 1)) := by
  simp [closeObject, updateOpenHandleCount]

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
        (by simpa [openObject, updateOpenHandleCount, replace, sameId] using queriedLookup)
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
        by simpa [openObject, updateOpenHandleCount, replace, sameId] using oldLookup,
        pathMatches⟩
  · intro queriedId queriedObject queriedLookup
    by_cases sameId : queriedId = objectId
    · subst queriedId
      exact wellFormed.liveWasIssued objectId object objectLookup
    · exact wellFormed.liveWasIssued queriedId queriedObject
        (by simpa [openObject, updateOpenHandleCount, replace, sameId] using queriedLookup)

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
        (by simpa [closeObject, updateOpenHandleCount, replace, sameId] using queriedLookup)
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
        by simpa [closeObject, updateOpenHandleCount, replace, sameId] using oldLookup,
        pathMatches⟩
  · intro queriedId queriedObject queriedLookup
    by_cases sameId : queriedId = objectId
    · subst queriedId
      exact wellFormed.liveWasIssued objectId object objectLookup
    · exact wellFormed.liveWasIssued queriedId queriedObject
        (by simpa [closeObject, updateOpenHandleCount, replace, sameId] using queriedLookup)

/-- Changing only one object's handle count preserves the rooted tree shape. -/
theorem updateOpenHandleCount_preserves_treeWellFormed {state : NamespaceState}
    {objectId : ObjectId} {object : NamespaceObject} {count : Nat}
    (treeWellFormed : state.TreeWellFormed)
    (objectLookup : state.objects objectId = some object)
    (updatedIndexes :
      (state.updateOpenHandleCount objectId object count).WellFormed) :
    (state.updateOpenHandleCount objectId object count).TreeWellFormed := by
  rcases treeWellFormed.rootExists with
    ⟨rootId, root, rootLookup, rootIdentity, rootPath, rootKind⟩
  refine ⟨updatedIndexes, ?_, ?_⟩
  · by_cases rootIsUpdated : rootId = objectId
    · have sameObject : root = object := Option.some.inj
        (rootLookup.symm.trans (rootIsUpdated ▸ objectLookup))
      subst root
      refine ⟨rootId, withOpenHandleCount object count, ?_, ?_, ?_, ?_⟩
      · simp [updateOpenHandleCount, replace, rootIsUpdated]
      · simpa [withOpenHandleCount] using rootIdentity
      · simpa [withOpenHandleCount] using rootPath
      · simpa [withOpenHandleCount] using rootKind
    · exact ⟨rootId, root,
        by simpa [updateOpenHandleCount, replace, rootIsUpdated] using rootLookup,
        rootIdentity, rootPath, rootKind⟩
  intro queriedId queriedObject queriedLookup queriedNotRoot
  by_cases queriedIsUpdated : queriedId = objectId
  · subst queriedId
    have exactObject : queriedObject = withOpenHandleCount object count := Option.some.inj
      (queriedLookup.symm.trans (by simp [updateOpenHandleCount]))
    subst queriedObject
    have oldNotRoot : object.path ≠ CanonicalPath.root := by
      simpa [withOpenHandleCount] using queriedNotRoot
    rcases treeWellFormed.parentDirectory objectId object objectLookup oldNotRoot with
      ⟨parentId, parent, parentLookup, parentPathLookup, parentKind, directParent⟩
    have parentIdDiffers : parentId ≠ objectId := by
      intro sameId
      have sameParent : parent = object := Option.some.inj
        (parentLookup.symm.trans (sameId ▸ objectLookup))
      subst parent
      exact directParent_irrefl object.path directParent
    exact ⟨parentId, parent,
      by simpa [updateOpenHandleCount, replace, parentIdDiffers] using parentLookup,
      parentPathLookup, parentKind,
      by simpa [withOpenHandleCount] using directParent⟩
  · have oldLookup : state.objects queriedId = some queriedObject := by
      simpa [updateOpenHandleCount, replace, queriedIsUpdated] using queriedLookup
    rcases treeWellFormed.parentDirectory queriedId queriedObject oldLookup queriedNotRoot with
      ⟨parentId, parent, parentLookup, parentPathLookup, parentKind, directParent⟩
    by_cases parentIsUpdated : parentId = objectId
    · have sameParent : parent = object := Option.some.inj
        (parentLookup.symm.trans (parentIsUpdated ▸ objectLookup))
      subst parent
      exact ⟨parentId, withOpenHandleCount object count,
        by simp [updateOpenHandleCount, replace, parentIsUpdated],
        parentPathLookup,
        by simpa [withOpenHandleCount] using parentKind,
        by simpa [withOpenHandleCount] using directParent⟩
    · exact ⟨parentId, parent,
        by simpa [updateOpenHandleCount, replace, parentIsUpdated] using parentLookup,
        parentPathLookup, parentKind, directParent⟩

/-- Opening a handle preserves both reciprocal indexes and directory-tree shape. -/
theorem openObject_preserves_treeWellFormed {state : NamespaceState}
    {objectId : ObjectId} {object : NamespaceObject}
    (treeWellFormed : state.TreeWellFormed)
    (objectLookup : state.objects objectId = some object) :
    (state.openObject objectId object).TreeWellFormed := by
  exact updateOpenHandleCount_preserves_treeWellFormed treeWellFormed objectLookup
    (openObject_preserves_wellFormed treeWellFormed.indexes objectLookup)

/-- Closing a handle preserves both reciprocal indexes and directory-tree shape. -/
theorem closeObject_preserves_treeWellFormed {state : NamespaceState}
    {objectId : ObjectId} {object : NamespaceObject}
    (treeWellFormed : state.TreeWellFormed)
    (objectLookup : state.objects objectId = some object) :
    (state.closeObject objectId object).TreeWellFormed := by
  exact updateOpenHandleCount_preserves_treeWellFormed treeWellFormed objectLookup
    (closeObject_preserves_wellFormed treeWellFormed.indexes objectLookup)

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
      CanIncrementU64 object.openHandleCount →
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

/-- Namespace generation and every live handle count fit Rust `u64` fields. -/
def CountersRepresentable (state : NamespaceState) : Prop :=
  FitsU64 state.generation ∧
    ∀ objectId object,
      state.objects objectId = some object → FitsU64 object.openHandleCount

/-- The singleton root namespace starts with representable counters. -/
theorem withRoot_countersRepresentable (rootId : ObjectId) :
    (withRoot rootId).CountersRepresentable := by
  constructor
  · simp [withRoot, FitsU64, u64Maximum]
  · intro objectId object objectLookup
    by_cases sameId : objectId = rootId
    · subst objectId
      simp [withRoot, replace] at objectLookup
      subst object
      simp [rootObject, FitsU64, u64Maximum]
    · simp [withRoot, replace, sameId] at objectLookup

/-- Checked namespace transitions preserve every Rust counter bound. -/
theorem Step.preserves_countersRepresentable {before after : NamespaceState}
    (transition : Step before after)
    (representable : before.CountersRepresentable) :
    after.CountersRepresentable := by
  cases transition with
  | create allowed =>
      rename_i createdObject
      constructor
      · exact allowed.generationCanIncrement.increment_fits
      · intro queriedId queriedObject queriedLookup
        by_cases sameId : queriedId = createdObject.id
        · subst queriedId
          have exactObject : queriedObject = createdObject := Option.some.inj
            (queriedLookup.symm.trans (create_stores_object before createdObject))
          subst queriedObject
          simp [allowed.startsClosed, FitsU64, u64Maximum]
        · have oldLookup : before.objects queriedId = some queriedObject := by
            simpa [NamespaceState.create, replace, sameId] using queriedLookup
          exact representable.2 queriedId queriedObject oldLookup
  | remove allowed =>
      rename_i removedId
      constructor
      · exact allowed.generationCanIncrement.increment_fits
      · intro queriedId queriedObject queriedLookup
        have differentId : queriedId ≠ removedId := by
          intro sameId
          subst queriedId
          simp [NamespaceState.remove] at queriedLookup
        have oldLookup : before.objects queriedId = some queriedObject := by
          simpa [NamespaceState.remove, replace, differentId] using queriedLookup
        exact representable.2 queriedId queriedObject oldLookup
  | renamePaths allowed =>
      constructor
      · exact allowed.generationCanIncrement.increment_fits
      · intro objectId renamedObject renamedLookup
        simp only [NamespaceState.renamePaths] at renamedLookup
        cases oldLookup : before.objects objectId with
        | none =>
            rw [oldLookup] at renamedLookup
            simp at renamedLookup
        | some oldObject =>
            rw [oldLookup] at renamedLookup
            simp at renamedLookup
            subst renamedObject
            exact representable.2 objectId oldObject oldLookup
  | openObject objectLookup canIncrement =>
      constructor
      · exact representable.1
      · intro queriedId queriedObject queriedLookup
        rename_i openedId openedObject
        by_cases sameId : queriedId = openedId
        · subst queriedId
          have exactObject : queriedObject =
              withOpenHandleCount openedObject (openedObject.openHandleCount + 1) :=
            Option.some.inj (queriedLookup.symm.trans
              (openObject_increments_count before openedId openedObject))
          subst queriedObject
          exact canIncrement.increment_fits
        · have oldLookup : before.objects queriedId = some queriedObject := by
            simpa [NamespaceState.openObject, updateOpenHandleCount, replace, sameId]
              using queriedLookup
          exact representable.2 queriedId queriedObject oldLookup
  | closeObject objectLookup _positive =>
      constructor
      · exact representable.1
      · intro queriedId queriedObject queriedLookup
        rename_i closedId closedObject
        by_cases sameId : queriedId = closedId
        · subst queriedId
          have exactObject : queriedObject =
              withOpenHandleCount closedObject (closedObject.openHandleCount - 1) :=
            Option.some.inj (queriedLookup.symm.trans
              (closeObject_decrements_count before closedId closedObject))
          subst queriedObject
          exact Nat.le_trans (Nat.sub_le _ _) <|
            representable.2 closedId closedObject objectLookup
        · have oldLookup : before.objects queriedId = some queriedObject := by
            simpa [NamespaceState.closeObject, updateOpenHandleCount, replace, sameId]
              using queriedLookup
          exact representable.2 queriedId queriedObject oldLookup

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

/-- Every accepted namespace step preserves the rooted directory-tree invariant. -/
theorem Step.preserves_treeWellFormed {before after : NamespaceState}
    (transition : Step before after) (treeWellFormed : before.TreeWellFormed) :
    after.TreeWellFormed := by
  cases transition with
  | create allowed => exact create_preserves_treeWellFormed treeWellFormed allowed
  | remove allowed => exact remove_preserves_treeWellFormed treeWellFormed allowed
  | renamePaths allowed =>
      exact rename_preserves_treeWellFormed treeWellFormed _ allowed
  | openObject objectLookup =>
      exact openObject_preserves_treeWellFormed treeWellFormed objectLookup
  | closeObject objectLookup _ =>
      exact closeObject_preserves_treeWellFormed treeWellFormed objectLookup

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

/-- The rooted directory tree remains valid after any finite execution. -/
theorem Steps.preserve_treeWellFormed {before after : NamespaceState}
    (transitions : Steps before after) (treeWellFormed : before.TreeWellFormed) :
    after.TreeWellFormed := by
  induction transitions with
  | refl => exact treeWellFormed
  | tail _ transition inductionHypothesis =>
      exact transition.preserves_treeWellFormed inductionHypothesis

/-- Namespace generation never decreases during any finite execution. -/
theorem Steps.generation_monotone {before after : NamespaceState}
    (transitions : Steps before after) : before.generation ≤ after.generation := by
  induction transitions with
  | refl => exact Nat.le_refl _
  | tail _ transition inductionHypothesis =>
      exact Nat.le_trans inductionHypothesis transition.generation_monotone

/-- Arbitrary accepted namespace executions stay within every `u64` bound. -/
theorem Steps.preserve_countersRepresentable {before after : NamespaceState}
    (transitions : Steps before after)
    (representable : before.CountersRepresentable) :
    after.CountersRepresentable := by
  induction transitions with
  | refl => exact representable
  | tail _ transition inductionHypothesis =>
      exact transition.preserves_countersRepresentable inductionHypothesis

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
