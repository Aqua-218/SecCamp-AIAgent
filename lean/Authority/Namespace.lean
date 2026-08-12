import Authority.State

/-!
# Capability Filesystem Namespace

An abstract namespace with reciprocal object/path indexes, monotone object
identity reservation, generation tracking, open-handle exclusion, finite alias
sets, and contained symbolic-link targets. The original single-primary-path
operations remain as the sequential core; the CapFS refinement layer gives the
transactional interpretation of aliases and failure outcomes.
-/

namespace Authority

/-- Canonical paths are equal exactly when their validated segment lists are equal. -/
instance : DecidableEq CanonicalPath := fun first second => by
  cases first
  cases second
  simp only [CanonicalPath.mk.injEq]
  infer_instance

/-- Object kinds accepted by the capability namespace. -/
inductive NamespaceObjectKind where
  | directory
  | regularFile
  | symlink
  deriving Repr, BEq, DecidableEq

/-- Current record for one live namespace object. -/
structure NamespaceObject where
  id : ObjectId
  /-- Stable representative used by the backwards-compatible sequential core. -/
  path : CanonicalPath
  kind : NamespaceObjectKind
  openHandleCount : Nat
  /-- Every live hard-link name, including `path`; finite by construction. -/
  aliases : List CanonicalPath := [path]
  /-- A validated repository-relative target exists exactly for symlinks. -/
  symlinkTarget : Option CanonicalPath := none
  deriving DecidableEq

namespace NamespaceObject

/-- Alias records are nonempty sets containing their stable representative. -/
def AliasesWellFormed (object : NamespaceObject) : Prop :=
  object.aliases.Nodup ∧ object.path ∈ object.aliases

/-- Object kind and optional symbolic-link target agree exactly. -/
def TargetWellFormed (object : NamespaceObject) : Prop :=
  match object.kind with
  | .symlink => object.symlinkTarget.isSome
  | .directory | .regularFile => object.symlinkTarget = none

/-- Complete per-object shape imported from Rust's manifest records. -/
def ShapeWellFormed (object : NamespaceObject) : Prop :=
  object.AliasesWellFormed ∧ object.TargetWellFormed

/-- A primary-only object remains a valid singleton alias set. -/
theorem singleton_aliases_wellFormed (object : NamespaceObject)
    (aliases : object.aliases = [object.path]) : object.AliasesWellFormed := by
  simp [AliasesWellFormed, aliases]

/-- A well-formed alias collection can never be empty. -/
theorem AliasesWellFormed.nonempty {object : NamespaceObject}
    (wellFormed : object.AliasesWellFormed) : object.aliases ≠ [] := by
  intro emptyAliases
  have representativePresent := wellFormed.2
  rw [emptyAliases] at representativePresent
  simp at representativePresent

/-- A symlink shape carries one concrete contained target. -/
theorem TargetWellFormed.symlink_has_target {object : NamespaceObject}
    (isSymlink : object.kind = .symlink)
    (wellFormed : object.TargetWellFormed) :
    ∃ target, object.symlinkTarget = some target := by
  rw [TargetWellFormed, isSymlink] at wellFormed
  exact Option.isSome_iff_exists.mp wellFormed

end NamespaceObject

/-- VM-wide namespace state before synchronization and backing operations. -/
structure NamespaceState where
  objects : ObjectId → Option NamespaceObject
  paths : CanonicalPath → Option ObjectId
  issuedObjects : ObjectId → Bool
  nextObjectSequence : Option Nat
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

/-- Canonical paths are determined by their validated segment lists. -/
theorem canonicalPath_eq {first second : CanonicalPath}
    (segmentsEqual : first.segments = second.segments) : first = second := by
  cases first
  cases second
  simp_all

/-- The executable prefix test recognizes exactly subtree membership. -/
theorem isPrefixOf_eq_true_iff_atOrBelow {path subtreeRoot : CanonicalPath} :
    subtreeRoot.segments.isPrefixOf path.segments = true ↔
      AtOrBelow path subtreeRoot := by
  rw [List.isPrefixOf_iff_prefix]
  constructor
  · rintro ⟨suffix, equality⟩
    exact ⟨suffix, equality.symm⟩
  · rintro ⟨suffix, equality⟩
    exact ⟨suffix, equality.symm⟩

/-- Dropping a prefix cannot introduce an invalid path segment. -/
private theorem all_drop_of_all {predicate : α → Bool} {items : List α}
    (count : Nat) (allItems : items.all predicate = true) :
    (items.drop count).all predicate = true := by
  induction count generalizing items with
  | zero => exact allItems
  | succ count inductionHypothesis =>
      cases items with
      | nil => simp
      | cons item items =>
          simp only [List.all_cons, Bool.and_eq_true] at allItems
          exact inductionHypothesis allItems.2

/-- Rebase a path under `source`, preserving its suffix; other paths are fixed. -/
def rebasePath (path source destination : CanonicalPath) : CanonicalPath :=
  if source.segments.isPrefixOf path.segments then
    { segments := destination.segments ++ path.segments.drop source.segments.length
      isValid := by
        simp [List.all_append, destination.isValid,
          all_drop_of_all source.segments.length path.isValid] }
  else
    path

/-- Rebasing a path in the selected subtree preserves its exact suffix. -/
theorem rebasePath_atOrBelow {path source destination : CanonicalPath}
    {suffix : List String}
    (pathEquality : path.segments = source.segments ++ suffix) :
    (rebasePath path source destination).segments =
      destination.segments ++ suffix := by
  simp [rebasePath, pathEquality]

/-- Rebasing fixes every path outside the selected subtree. -/
theorem rebasePath_outside {path source destination : CanonicalPath}
    (outside : ¬ AtOrBelow path source) :
    rebasePath path source destination = path := by
  have prefixIsFalse : source.segments.isPrefixOf path.segments = false := by
    apply Bool.eq_false_iff.mpr
    intro prefixIsTrue
    exact outside (isPrefixOf_eq_true_iff_atOrBelow.mp prefixIsTrue)
  simp [rebasePath, prefixIsFalse]

/-- The root is outside every proper non-root subtree. -/
theorem root_outside_subtree {subtreeRoot : CanonicalPath}
    (notRoot : subtreeRoot ≠ CanonicalPath.root) :
    ¬ AtOrBelow CanonicalPath.root subtreeRoot := by
  rintro ⟨suffix, equality⟩
  have appendIsEmpty : subtreeRoot.segments ++ suffix = [] := by
    simpa [CanonicalPath.root] using equality.symm
  have subtreeSegmentsEmpty := (List.append_eq_nil.mp appendIsEmpty).1
  exact notRoot (canonicalPath_eq subtreeSegmentsEmpty)

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
  nextObjectSequence := some 0
  generation := 0

/-- Concrete object identity generated by Rust's namespace allocator. -/
def allocatedObjectId (sequence : Nat) : ObjectId :=
  { value := "object-" ++ toString sequence }

/-- Checked successor for the optional Rust `u64` object cursor. -/
def advanceObjectCursor (sequence : Nat) : Option Nat :=
  if sequence < u64Maximum then some (sequence + 1) else none

/-- The final `u64` identity is allocated once and then exhausts the cursor. -/
theorem advanceObjectCursor_maximum :
    advanceObjectCursor u64Maximum = none := by
  simp [advanceObjectCursor]

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
    nextObjectSequence := some 1
    generation := 0 }

/-- Runtime initialization uses the exact root identity allocated at sequence zero. -/
def runtimeInitial : NamespaceState := withRoot (allocatedObjectId 0)

/-- Both indexes describe the same live objects and canonical paths. -/
structure WellFormed (state : NamespaceState) : Prop where
  objectToPath : ∀ objectId object,
    state.objects objectId = some object →
      object.id = objectId ∧ state.paths object.path = some objectId
  pathToObject : ∀ path objectId,
    state.paths path = some objectId →
      ∃ object, state.objects objectId = some object
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

/-- Every path index is exactly one member of a finite nonempty alias set. -/
structure AliasWellFormed (state : NamespaceState) : Prop where
  objectIdentity : ∀ objectId object,
    state.objects objectId = some object → object.id = objectId
  objectShape : ∀ objectId object,
    state.objects objectId = some object → object.ShapeWellFormed
  aliasToPath : ∀ objectId object path,
    state.objects objectId = some object →
      path ∈ object.aliases → state.paths path = some objectId
  pathToAlias : ∀ path objectId,
    state.paths path = some objectId →
      ∃ object, state.objects objectId = some object ∧ path ∈ object.aliases
  liveWasIssued : ∀ objectId object,
    state.objects objectId = some object → state.issuedObjects objectId = true

/-- Exact aliases, object shape, and every per-name parent edge form one namespace. -/
structure CompleteWellFormed (state : NamespaceState) : Prop where
  tree : state.TreeWellFormed
  aliases : state.AliasWellFormed
  directorySingleton : ∀ objectId object,
    state.objects objectId = some object → object.kind = .directory →
      object.aliases = [object.path]
  namedParentDirectory : ∀ objectId object name,
    state.objects objectId = some object →
      name ∈ object.aliases →
      name ≠ CanonicalPath.root →
      ∃ parentId parent,
        state.objects parentId = some parent ∧
        state.paths parent.path = some parentId ∧
        parent.kind = .directory ∧
        DirectParent parent.path name

/-- A complete state exposes its exact path-to-object relation. -/
theorem CompleteWellFormed.path_exact {state : NamespaceState}
    (wellFormed : state.CompleteWellFormed) {path : CanonicalPath}
    {objectId : ObjectId} :
    state.paths path = some objectId ↔
      ∃ object, state.objects objectId = some object ∧ path ∈ object.aliases := by
  constructor
  · exact wellFormed.aliases.pathToAlias path objectId
  · rintro ⟨object, objectLookup, aliasMember⟩
    exact wellFormed.aliases.aliasToPath objectId object path objectLookup aliasMember

/-- The root record has one name and no symbolic-link target. -/
theorem rootObject_shapeWellFormed (rootId : ObjectId) :
    (rootObject rootId).ShapeWellFormed := by
  simp [NamespaceObject.ShapeWellFormed,
    NamespaceObject.AliasesWellFormed,
    NamespaceObject.TargetWellFormed, rootObject]

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
      exact ⟨rootObject rootId, by simp [withRoot, replace]⟩
    · simp [withRoot, replace, samePath] at pathLookup
  · intro objectId object objectLookup
    by_cases sameId : objectId = rootId
    · subst objectId
      simp [withRoot, replace]
    · simp [withRoot, replace, sameId] at objectLookup

/-- The singleton root indexes exactly its singleton alias set. -/
theorem withRoot_aliasWellFormed (rootId : ObjectId) :
    (withRoot rootId).AliasWellFormed := by
  refine ⟨?_, ?_, ?_, ?_, ?_⟩
  · intro objectId object objectLookup
    exact (withRoot_wellFormed rootId).objectToPath objectId object objectLookup |>.1
  · intro objectId object objectLookup
    by_cases sameId : objectId = rootId
    · subst objectId
      simp [withRoot, replace] at objectLookup
      subst object
      exact rootObject_shapeWellFormed rootId
    · simp [withRoot, replace, sameId] at objectLookup
  · intro objectId object path objectLookup aliasMember
    by_cases sameId : objectId = rootId
    · subst objectId
      simp [withRoot, replace] at objectLookup
      subst object
      simp [rootObject] at aliasMember
      subst path
      simp [withRoot, replace]
    · simp [withRoot, replace, sameId] at objectLookup
  · intro path objectId pathLookup
    by_cases samePath : path = CanonicalPath.root
    · subst path
      simp [withRoot, replace] at pathLookup
      subst objectId
      exact ⟨rootObject rootId, by simp [withRoot, replace], by simp [rootObject]⟩
    · simp [withRoot, replace, samePath] at pathLookup
  · intro objectId object objectLookup
    exact (withRoot_wellFormed rootId).liveWasIssued objectId object objectLookup

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

/-- The singleton root satisfies the complete alias-aware tree invariant. -/
theorem withRoot_completeWellFormed (rootId : ObjectId) :
    (withRoot rootId).CompleteWellFormed := by
  refine ⟨withRoot_treeWellFormed rootId, withRoot_aliasWellFormed rootId,
    ?_, ?_⟩
  · intro objectId object objectLookup _isDirectory
    by_cases sameId : objectId = rootId
    · subst objectId
      simp [withRoot, replace] at objectLookup
      subst object
      rfl
    · simp [withRoot, replace, sameId] at objectLookup
  · intro objectId object name objectLookup nameMember notRoot
    by_cases sameId : objectId = rootId
    · subst objectId
      simp [withRoot, replace] at objectLookup
      subst object
      simp [rootObject] at nameMember
      exact False.elim (notRoot nameMember)
    · simp [withRoot, replace, sameId] at objectLookup

/-- Trusted import evidence enumerates every object in a complete namespace. -/
structure CompleteImport (state : NamespaceState) where
  manifest : List NamespaceObject
  manifestIdsNodup : (manifest.map NamespaceObject.id).Nodup
  objectsExact : ∀ objectId object,
    state.objects objectId = some object ↔
      object ∈ manifest ∧ object.id = objectId
  complete : state.CompleteWellFormed

/-- The concrete root import is constructively complete. -/
def withRoot_completeImport (rootId : ObjectId) :
    (withRoot rootId).CompleteImport := by
  refine ⟨[rootObject rootId], by simp, ?_, withRoot_completeWellFormed rootId⟩
  intro objectId object
  by_cases sameId : objectId = rootId
  · subst objectId
    constructor
    · intro objectLookup
      simp [withRoot, replace] at objectLookup
      subst object
      simp [rootObject]
    · rintro ⟨objectMember, identity⟩
      simp at objectMember
      subst object
      simp [withRoot, replace]
  · constructor
    · intro objectLookup
      simp [withRoot, replace, sameId] at objectLookup
    · rintro ⟨objectMember, identity⟩
      simp at objectMember
      subst object
      exact False.elim (sameId identity.symm)

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
  allocationSequence : Nat
  cursorExpected : state.nextObjectSequence = some allocationSequence
  sequenceRepresentable : FitsU64 allocationSequence
  objectIdAllocated : object.id = allocatedObjectId allocationSequence
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

/-- An exhausted object cursor admits no further creation. -/
theorem exhausted_cursor_rejects_create {state : NamespaceState}
    (exhausted : state.nextObjectSequence = none) :
    ∀ object, state.MayCreate object → False := by
  intro object allowed
  have cursor := allowed.cursorExpected
  rw [exhausted] at cursor
  cases cursor

/-- Atomically publish reciprocal object and path indexes. -/
def create (state : NamespaceState) (object : NamespaceObject) : NamespaceState :=
  { objects := replace state.objects object.id (some object)
    paths := replace state.paths object.path (some object.id)
    issuedObjects := replace state.issuedObjects object.id true
    nextObjectSequence := state.nextObjectSequence.bind advanceObjectCursor
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

/-- Creation advances from exactly the sequence that selected its object ID. -/
theorem create_advances_object_cursor {state : NamespaceState}
    {object : NamespaceObject} (allowed : state.MayCreate object) :
    (state.create object).nextObjectSequence =
      advanceObjectCursor allowed.allocationSequence := by
  simp [create, allowed.cursorExpected]

/-- Allocating the maximum object identity makes every later creation impossible. -/
theorem create_maximum_exhausts_object_cursor {state : NamespaceState}
    {object : NamespaceObject} (allowed : state.MayCreate object)
    (maximum : allowed.allocationSequence = u64Maximum) :
    (state.create object).nextObjectSequence = none := by
  rw [create_advances_object_cursor allowed, maximum, advanceObjectCursor_maximum]

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
      exact ⟨object, create_stores_object state object⟩
    · have oldLookup : state.paths queriedPath = some queriedId := by
        simpa [create, replace, samePath] using queriedLookup
      rcases wellFormed.pathToObject queriedPath queriedId oldLookup with
        ⟨oldObject, objectLookup⟩
      refine ⟨oldObject, ?_⟩
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

/-! ## Alias-aware namespace transactions -/

/-- Add one name to a live object's finite alias set. -/
def withAddedAlias (object : NamespaceObject) (alias : CanonicalPath) :
    NamespaceObject :=
  { object with aliases := object.aliases ++ [alias] }

/-- Appending one fresh name preserves finite-set representation. -/
private theorem nodup_append_singleton {items : List α} {item : α}
    (nodup : items.Nodup) (fresh : item ∉ items) :
    (items ++ [item]).Nodup := by
  induction items with
  | nil => simp
  | cons head tail inductionHypothesis =>
      simp only [List.nodup_cons, List.mem_cons, not_or] at nodup fresh
      simp only [List.cons_append, List.nodup_cons, List.mem_append,
        List.mem_singleton, not_or]
      exact ⟨⟨nodup.1, fun equality => fresh.1 equality.symm⟩,
        inductionHypothesis nodup.2 fresh.2⟩

/-- Preconditions for Rust's no-replace hard-link publish. -/
structure MayAddHardLink (state : NamespaceState) (objectId : ObjectId)
    (alias : CanonicalPath) where
  generationCanIncrement : CanIncrementU64 state.generation
  complete : state.CompleteWellFormed
  object : NamespaceObject
  objectLookup : state.objects objectId = some object
  sourceIsNotDirectory : object.kind ≠ .directory
  aliasAbsent : state.paths alias = none
  aliasNotRoot : alias ≠ CanonicalPath.root
  parentId : ObjectId
  parent : NamespaceObject
  parentLookup : state.objects parentId = some parent
  parentPathLookup : state.paths parent.path = some parentId
  parentIsDirectory : parent.kind = .directory
  directChild : DirectParent parent.path alias

/-- Atomically publish one additional hard-link name and its exact alias record. -/
def addHardLink (state : NamespaceState) (objectId : ObjectId)
    (object : NamespaceObject) (alias : CanonicalPath) : NamespaceState :=
  { state with
    objects := replace state.objects objectId (some (withAddedAlias object alias))
    paths := replace state.paths alias (some objectId)
    generation := state.generation + 1 }

/-- Hard-link publish stores the extended finite alias record. -/
theorem addHardLink_stores_object (state : NamespaceState) (objectId : ObjectId)
    (object : NamespaceObject) (alias : CanonicalPath) :
    (state.addHardLink objectId object alias).objects objectId =
      some (withAddedAlias object alias) := by
  simp [addHardLink]

/-- Hard-link publish installs the new reciprocal path index. -/
theorem addHardLink_stores_path (state : NamespaceState) (objectId : ObjectId)
    (object : NamespaceObject) (alias : CanonicalPath) :
    (state.addHardLink objectId object alias).paths alias = some objectId := by
  simp [addHardLink]

/-- A no-replace hard link is genuinely a new member of the alias set. -/
theorem MayAddHardLink.aliasFresh {state : NamespaceState} {objectId : ObjectId}
    {alias : CanonicalPath} (allowed : state.MayAddHardLink objectId alias) :
    alias ∉ allowed.object.aliases := by
  intro aliasMember
  have indexed := allowed.complete.aliases.aliasToPath objectId allowed.object alias
    allowed.objectLookup aliasMember
  rw [allowed.aliasAbsent] at indexed
  contradiction

/-- The hard-link target and its parent are different objects. -/
theorem MayAddHardLink.parentId_ne {state : NamespaceState} {objectId : ObjectId}
    {alias : CanonicalPath} (allowed : state.MayAddHardLink objectId alias) :
    allowed.parentId ≠ objectId := by
  intro sameId
  have sameObject : allowed.parent = allowed.object := by
    have lookup := allowed.parentLookup
    rw [sameId, allowed.objectLookup] at lookup
    exact Option.some.inj lookup.symm
  apply allowed.sourceIsNotDirectory
  rw [← sameObject]
  exact allowed.parentIsDirectory

/-- The new hard-link path is distinct from every previously indexed path. -/
theorem MayAddHardLink.ne_indexed_path {state : NamespaceState}
    {objectId : ObjectId} {alias path : CanonicalPath}
    (allowed : state.MayAddHardLink objectId alias)
    {owner : ObjectId} (indexed : state.paths path = some owner) :
    path ≠ alias := by
  intro samePath
  subst path
  rw [allowed.aliasAbsent] at indexed
  contradiction

/-- A checked hard-link publish preserves the complete alias-aware tree. -/
theorem addHardLink_preserves_completeWellFormed {state : NamespaceState}
    {objectId : ObjectId} {alias : CanonicalPath}
    (allowed : state.MayAddHardLink objectId alias) :
    (state.addHardLink objectId allowed.object alias).CompleteWellFormed := by
  let updated := withAddedAlias allowed.object alias
  have targetIdentity : allowed.object.id = objectId :=
    allowed.complete.aliases.objectIdentity objectId allowed.object
      allowed.objectLookup
  have aliasFresh := allowed.aliasFresh
  have objectShape := allowed.complete.aliases.objectShape objectId
    allowed.object allowed.objectLookup
  have primaryIndexed := allowed.complete.aliases.aliasToPath objectId allowed.object
    allowed.object.path allowed.objectLookup objectShape.1.2
  have primaryNeAlias : allowed.object.path ≠ alias :=
    allowed.ne_indexed_path primaryIndexed
  have parentPathNeAlias : allowed.parent.path ≠ alias :=
    allowed.ne_indexed_path allowed.parentPathLookup
  have parentIdNe := allowed.parentId_ne
  refine ⟨?_, ?_, ?_, ?_⟩
  · -- The legacy primary-path tree is unchanged except for the target record.
    refine ⟨?_, ?_, ?_⟩
    · refine ⟨?_, ?_, ?_⟩
      · intro queriedId queriedObject queriedLookup
        by_cases target : queriedId = objectId
        · subst queriedId
          have exactObject : queriedObject = updated := Option.some.inj
            (queriedLookup.symm.trans (addHardLink_stores_object state objectId
              allowed.object alias))
          subst queriedObject
          refine ⟨by simpa [updated, withAddedAlias] using targetIdentity, ?_⟩
          change replace state.paths alias (some objectId) allowed.object.path =
            some objectId
          simp [replace, primaryNeAlias, primaryIndexed]
        · have oldLookup : state.objects queriedId = some queriedObject := by
            simpa [addHardLink, replace, target] using queriedLookup
          rcases allowed.complete.tree.indexes.objectToPath queriedId queriedObject
            oldLookup with ⟨identity, pathLookup⟩
          exact ⟨identity, by
            have pathNe := allowed.ne_indexed_path pathLookup
            simpa [addHardLink, replace, pathNe] using pathLookup⟩
      · intro path queriedId pathLookup
        by_cases isAlias : path = alias
        · subst path
          have exactId : queriedId = objectId := Option.some.inj
            (pathLookup.symm.trans (addHardLink_stores_path state objectId
              allowed.object alias))
          subst queriedId
          exact ⟨updated, addHardLink_stores_object state objectId
            allowed.object alias⟩
        · have oldPath : state.paths path = some queriedId := by
            simpa [addHardLink, replace, isAlias] using pathLookup
          rcases allowed.complete.tree.indexes.pathToObject path queriedId oldPath with
            ⟨object, objectLookup⟩
          by_cases target : queriedId = objectId
          · subst queriedId
            exact ⟨updated, addHardLink_stores_object state objectId
              allowed.object alias⟩
          · exact ⟨object, by
              simpa [addHardLink, replace, target] using objectLookup⟩
      · intro queriedId queriedObject queriedLookup
        by_cases target : queriedId = objectId
        · subst queriedId
          exact allowed.complete.tree.indexes.liveWasIssued objectId
            allowed.object allowed.objectLookup
        · exact allowed.complete.tree.indexes.liveWasIssued queriedId queriedObject
            (by simpa [addHardLink, replace, target] using queriedLookup)
    · rcases allowed.complete.tree.rootExists with
        ⟨rootId, root, rootLookup, rootIdentity, rootPath, rootKind⟩
      have rootIdNe : rootId ≠ objectId := by
        intro sameId
        have sameObject : root = allowed.object := Option.some.inj
          (rootLookup.symm.trans (sameId ▸ allowed.objectLookup))
        apply allowed.sourceIsNotDirectory
        rw [← sameObject]
        exact rootKind
      exact ⟨rootId, root,
        by simpa [addHardLink, replace, rootIdNe] using rootLookup,
        rootIdentity, rootPath, rootKind⟩
    · intro queriedId queriedObject queriedLookup notRoot
      by_cases target : queriedId = objectId
      · subst queriedId
        have exactObject : queriedObject = updated := Option.some.inj
          (queriedLookup.symm.trans (addHardLink_stores_object state objectId
            allowed.object alias))
        subst queriedObject
        rcases allowed.complete.tree.parentDirectory objectId allowed.object
          allowed.objectLookup (by simpa [updated, withAddedAlias] using notRoot) with
          ⟨parentId, parent, parentLookup, parentPathLookup, parentKind, direct⟩
        have parentIdDiffers : parentId ≠ objectId := by
          intro sameId
          have sameParent : parent = allowed.object := Option.some.inj
            (parentLookup.symm.trans (sameId ▸ allowed.objectLookup))
          subst parent
          exact directParent_irrefl allowed.object.path direct
        exact ⟨parentId, parent,
          by simpa [addHardLink, replace, parentIdDiffers] using parentLookup,
          by simpa [addHardLink, replace,
            allowed.ne_indexed_path parentPathLookup] using parentPathLookup,
          parentKind, by simpa [updated, withAddedAlias] using direct⟩
      · have oldLookup : state.objects queriedId = some queriedObject := by
          simpa [addHardLink, replace, target] using queriedLookup
        rcases allowed.complete.tree.parentDirectory queriedId queriedObject
          oldLookup notRoot with
          ⟨parentId, parent, parentLookup, parentPathLookup, parentKind, direct⟩
        have parentIdDiffers : parentId ≠ objectId := by
          intro sameId
          have sameParent : parent = allowed.object := Option.some.inj
            (parentLookup.symm.trans (sameId ▸ allowed.objectLookup))
          have kindTarget : allowed.object.kind = .directory := by
            rw [← sameParent]
            exact parentKind
          exact allowed.sourceIsNotDirectory kindTarget
        exact ⟨parentId, parent,
          by simpa [addHardLink, replace, parentIdDiffers] using parentLookup,
          by simpa [addHardLink, replace,
            allowed.ne_indexed_path parentPathLookup] using parentPathLookup,
          parentKind, direct⟩
  · -- Exact aliases and object shape.
    refine ⟨?_, ?_, ?_, ?_, ?_⟩
    · intro queriedId queriedObject queriedLookup
      by_cases target : queriedId = objectId
      · subst queriedId
        have exactObject : queriedObject = updated := Option.some.inj
          (queriedLookup.symm.trans (addHardLink_stores_object state objectId
            allowed.object alias))
        subst queriedObject
        simpa [updated, withAddedAlias] using targetIdentity
      · exact allowed.complete.aliases.objectIdentity queriedId queriedObject
          (by simpa [addHardLink, replace, target] using queriedLookup)
    · intro queriedId queriedObject queriedLookup
      by_cases target : queriedId = objectId
      · subst queriedId
        have exactObject : queriedObject = updated := Option.some.inj
          (queriedLookup.symm.trans (addHardLink_stores_object state objectId
            allowed.object alias))
        subst queriedObject
        rcases allowed.complete.aliases.objectShape objectId allowed.object
          allowed.objectLookup with ⟨⟨nodup, representative⟩, targetShape⟩
        exact ⟨⟨by simpa [updated, withAddedAlias] using
          nodup_append_singleton nodup aliasFresh,
          by simpa [updated, withAddedAlias] using
            List.mem_append_left [alias] representative⟩,
          by simpa [updated, withAddedAlias] using targetShape⟩
      · exact allowed.complete.aliases.objectShape queriedId queriedObject
          (by simpa [addHardLink, replace, target] using queriedLookup)
    · intro queriedId queriedObject path queriedLookup member
      by_cases target : queriedId = objectId
      · subst queriedId
        have exactObject : queriedObject = updated := Option.some.inj
          (queriedLookup.symm.trans (addHardLink_stores_object state objectId
            allowed.object alias))
        subst queriedObject
        simp [updated, withAddedAlias] at member
        rcases member with oldMember | rfl
        · have oldPath := allowed.complete.aliases.aliasToPath objectId
            allowed.object path allowed.objectLookup oldMember
          simpa [addHardLink, replace, allowed.ne_indexed_path oldPath] using oldPath
        · simp [addHardLink]
      · have oldLookup : state.objects queriedId = some queriedObject := by
          simpa [addHardLink, replace, target] using queriedLookup
        have oldPath := allowed.complete.aliases.aliasToPath queriedId queriedObject
          path oldLookup member
        simpa [addHardLink, replace, allowed.ne_indexed_path oldPath] using oldPath
    · intro path queriedId pathLookup
      by_cases isAlias : path = alias
      · subst path
        have exactId : queriedId = objectId := Option.some.inj
          (pathLookup.symm.trans (addHardLink_stores_path state objectId
            allowed.object alias))
        subst queriedId
        exact ⟨updated, addHardLink_stores_object state objectId allowed.object alias,
          by simp [updated, withAddedAlias]⟩
      · have oldPath : state.paths path = some queriedId := by
          simpa [addHardLink, replace, isAlias] using pathLookup
        rcases allowed.complete.aliases.pathToAlias path queriedId oldPath with
          ⟨object, objectLookup, member⟩
        by_cases target : queriedId = objectId
        · subst queriedId
          have sameObject : object = allowed.object := Option.some.inj
            (objectLookup.symm.trans allowed.objectLookup)
          subst object
          exact ⟨updated, addHardLink_stores_object state objectId
            allowed.object alias, by simp [updated, withAddedAlias, member]⟩
        · exact ⟨object, by simpa [addHardLink, replace, target] using objectLookup,
            member⟩
    · intro queriedId queriedObject queriedLookup
      by_cases target : queriedId = objectId
      · subst queriedId
        exact allowed.complete.aliases.liveWasIssued objectId allowed.object
          allowed.objectLookup
      · exact allowed.complete.aliases.liveWasIssued queriedId queriedObject
          (by simpa [addHardLink, replace, target] using queriedLookup)
  · intro queriedId queriedObject queriedLookup isDirectory
    by_cases target : queriedId = objectId
    · subst queriedId
      have exactObject : queriedObject = updated := Option.some.inj
        (queriedLookup.symm.trans (addHardLink_stores_object state objectId
          allowed.object alias))
      subst queriedObject
      have impossible : allowed.object.kind = .directory := by
        simpa [updated, withAddedAlias] using isDirectory
      exact False.elim (allowed.sourceIsNotDirectory impossible)
    · exact allowed.complete.directorySingleton queriedId queriedObject
        (by simpa [addHardLink, replace, target] using queriedLookup) isDirectory
  · intro queriedId queriedObject name queriedLookup member notRoot
    by_cases target : queriedId = objectId
    · subst queriedId
      have exactObject : queriedObject = updated := Option.some.inj
        (queriedLookup.symm.trans (addHardLink_stores_object state objectId
          allowed.object alias))
      subst queriedObject
      simp [updated, withAddedAlias] at member
      rcases member with oldMember | rfl
      · rcases allowed.complete.namedParentDirectory objectId allowed.object name
          allowed.objectLookup oldMember notRoot with
          ⟨parentId, parent, parentLookup, parentPathLookup, parentKind, direct⟩
        have parentIdDiffers : parentId ≠ objectId := by
          intro sameId
          have sameParent : parent = allowed.object := Option.some.inj
            (parentLookup.symm.trans (sameId ▸ allowed.objectLookup))
          have targetDirectory : allowed.object.kind = .directory := by
            rw [← sameParent]
            exact parentKind
          exact allowed.sourceIsNotDirectory targetDirectory
        exact ⟨parentId, parent,
          by simpa [addHardLink, replace, parentIdDiffers] using parentLookup,
          by simpa [addHardLink, replace,
            allowed.ne_indexed_path parentPathLookup] using parentPathLookup,
          parentKind, direct⟩
      · exact ⟨allowed.parentId, allowed.parent,
          by simpa [addHardLink, replace, parentIdNe] using allowed.parentLookup,
          by simpa [addHardLink, replace, parentPathNeAlias] using
            allowed.parentPathLookup,
          allowed.parentIsDirectory, allowed.directChild⟩
    · have oldLookup : state.objects queriedId = some queriedObject := by
        simpa [addHardLink, replace, target] using queriedLookup
      rcases allowed.complete.namedParentDirectory queriedId queriedObject name
        oldLookup member notRoot with
        ⟨parentId, parent, parentLookup, parentPathLookup, parentKind, direct⟩
      have parentIdDiffers : parentId ≠ objectId := by
        intro sameId
        have sameParent : parent = allowed.object := Option.some.inj
          (parentLookup.symm.trans (sameId ▸ allowed.objectLookup))
        have targetDirectory : allowed.object.kind = .directory := by
          rw [← sameParent]
          exact parentKind
        exact allowed.sourceIsNotDirectory targetDirectory
      exact ⟨parentId, parent,
        by simpa [addHardLink, replace, parentIdDiffers] using parentLookup,
        by simpa [addHardLink, replace,
          allowed.ne_indexed_path parentPathLookup] using parentPathLookup,
        parentKind, direct⟩

/-- Replace an object's representative with the first surviving alias. -/
def withRemainingAliases (object : NamespaceObject) (newPrimary : CanonicalPath)
    (remaining : List CanonicalPath) : NamespaceObject :=
  { object with path := newPrimary, aliases := newPrimary :: remaining }

/-- Preconditions for unlinking one name while retaining the live object. -/
structure MayUnlinkName (state : NamespaceState) (objectId : ObjectId)
    (alias : CanonicalPath) where
  generationCanIncrement : CanIncrementU64 state.generation
  complete : state.CompleteWellFormed
  object : NamespaceObject
  objectLookup : state.objects objectId = some object
  sourceIsNotDirectory : object.kind ≠ .directory
  noOpenHandles : object.openHandleCount = 0
  aliasIndexed : state.paths alias = some objectId
  newPrimary : CanonicalPath
  remaining : List CanonicalPath
  /-- This both selects the removed name and proves at least one name survives. -/
  partition : object.aliases.Perm (alias :: newPrimary :: remaining)
  newPrimaryIndexed : state.paths newPrimary = some objectId
  newPrimaryNotRoot : newPrimary ≠ CanonicalPath.root
  parentId : ObjectId
  parent : NamespaceObject
  parentLookup : state.objects parentId = some parent
  parentPathLookup : state.paths parent.path = some parentId
  parentIsDirectory : parent.kind = .directory
  directChild : DirectParent parent.path newPrimary

/-- Atomically remove one name and publish a surviving representative. -/
def unlinkName (state : NamespaceState) (objectId : ObjectId)
    (object : NamespaceObject) (alias newPrimary : CanonicalPath)
    (remaining : List CanonicalPath) : NamespaceState :=
  { state with
    objects := replace state.objects objectId
      (some (withRemainingAliases object newPrimary remaining))
    paths := replace state.paths alias none
    generation := state.generation + 1 }

/-- Name unlink stores exactly the selected surviving alias list. -/
theorem unlinkName_stores_object (state : NamespaceState) (objectId : ObjectId)
    (object : NamespaceObject) (alias newPrimary : CanonicalPath)
    (remaining : List CanonicalPath) :
    (state.unlinkName objectId object alias newPrimary remaining).objects objectId =
      some (withRemainingAliases object newPrimary remaining) := by
  simp [unlinkName]

/-- Name unlink removes exactly the selected path index. -/
theorem unlinkName_clears_path (state : NamespaceState) (objectId : ObjectId)
    (object : NamespaceObject) (alias newPrimary : CanonicalPath)
    (remaining : List CanonicalPath) :
    (state.unlinkName objectId object alias newPrimary remaining).paths alias = none := by
  simp [unlinkName]

/-- Surviving aliases are precisely old aliases other than the removed name. -/
theorem MayUnlinkName.member_partition {state : NamespaceState}
    {objectId : ObjectId} {alias name : CanonicalPath}
    (allowed : state.MayUnlinkName objectId alias) :
    name ∈ allowed.object.aliases ↔
      name = alias ∨ name ∈ allowed.newPrimary :: allowed.remaining := by
  rw [allowed.partition.mem_iff]
  simp only [List.mem_cons]

/-- The selected removed name is absent from the surviving finite set. -/
theorem MayUnlinkName.alias_not_surviving {state : NamespaceState}
    {objectId : ObjectId} {alias : CanonicalPath}
    (allowed : state.MayUnlinkName objectId alias) :
    alias ∉ allowed.newPrimary :: allowed.remaining := by
  have oldNodup := (allowed.complete.aliases.objectShape objectId allowed.object
    allowed.objectLookup).1.1
  have partitionNodup := allowed.partition.nodup_iff.mp oldNodup
  exact (List.nodup_cons.mp partitionNodup).1

/-- The unlinked object cannot be its directory parent. -/
theorem MayUnlinkName.parentId_ne {state : NamespaceState} {objectId : ObjectId}
    {alias : CanonicalPath} (allowed : state.MayUnlinkName objectId alias) :
    allowed.parentId ≠ objectId := by
  intro sameId
  have lookup := allowed.parentLookup
  rw [sameId, allowed.objectLookup] at lookup
  have sameObject : allowed.parent = allowed.object := Option.some.inj lookup.symm
  have targetDirectory : allowed.object.kind = .directory := by
    rw [← sameObject]
    exact allowed.parentIsDirectory
  exact allowed.sourceIsNotDirectory targetDirectory

/-- A checked name unlink preserves the complete alias-aware tree. -/
theorem unlinkName_preserves_completeWellFormed {state : NamespaceState}
    {objectId : ObjectId} {alias : CanonicalPath}
    (allowed : state.MayUnlinkName objectId alias) :
    (state.unlinkName objectId allowed.object alias allowed.newPrimary
      allowed.remaining).CompleteWellFormed := by
  let updated := withRemainingAliases allowed.object allowed.newPrimary
    allowed.remaining
  have targetIdentity := allowed.complete.aliases.objectIdentity objectId
    allowed.object allowed.objectLookup
  have aliasNotSurviving := allowed.alias_not_surviving
  have newPrimaryNeAlias : allowed.newPrimary ≠ alias := by
    intro equality
    apply aliasNotSurviving
    simp [equality]
  have parentIdNe := allowed.parentId_ne
  have parentPathNeAlias : allowed.parent.path ≠ alias := by
    intro equality
    have sameOwner := Option.some.inj
      (allowed.parentPathLookup.symm.trans (equality ▸ allowed.aliasIndexed))
    exact parentIdNe sameOwner
  have oldShape := allowed.complete.aliases.objectShape objectId allowed.object
    allowed.objectLookup
  have partitionNodup := allowed.partition.nodup_iff.mp oldShape.1.1
  have survivingNodup : (allowed.newPrimary :: allowed.remaining).Nodup :=
    (List.nodup_cons.mp partitionNodup).2
  refine ⟨?_, ?_, ?_, ?_⟩
  · refine ⟨?_, ?_, ?_⟩
    · refine ⟨?_, ?_, ?_⟩
      · intro queriedId queriedObject queriedLookup
        by_cases target : queriedId = objectId
        · subst queriedId
          have exactObject : queriedObject = updated := Option.some.inj
            (queriedLookup.symm.trans (unlinkName_stores_object state objectId
              allowed.object alias allowed.newPrimary allowed.remaining))
          subst queriedObject
          refine ⟨by simpa [updated, withRemainingAliases] using targetIdentity, ?_⟩
          change replace state.paths alias none allowed.newPrimary = some objectId
          simp [replace, newPrimaryNeAlias, allowed.newPrimaryIndexed]
        · have oldLookup : state.objects queriedId = some queriedObject := by
            simpa [unlinkName, replace, target] using queriedLookup
          rcases allowed.complete.tree.indexes.objectToPath queriedId queriedObject
            oldLookup with ⟨identity, pathLookup⟩
          have pathNeAlias : queriedObject.path ≠ alias := by
            intro equality
            have sameOwner := Option.some.inj
              (pathLookup.symm.trans (equality ▸ allowed.aliasIndexed))
            exact target sameOwner
          exact ⟨identity, by
            simpa [unlinkName, replace, pathNeAlias] using pathLookup⟩
      · intro path queriedId pathLookup
        have pathNeAlias : path ≠ alias := by
          intro equality
          subst path
          simp [unlinkName] at pathLookup
        have oldPath : state.paths path = some queriedId := by
          simpa [unlinkName, replace, pathNeAlias] using pathLookup
        rcases allowed.complete.tree.indexes.pathToObject path queriedId oldPath with
          ⟨object, objectLookup⟩
        by_cases target : queriedId = objectId
        · subst queriedId
          exact ⟨updated, unlinkName_stores_object state objectId allowed.object
            alias allowed.newPrimary allowed.remaining⟩
        · exact ⟨object, by simpa [unlinkName, replace, target] using objectLookup⟩
      · intro queriedId queriedObject queriedLookup
        by_cases target : queriedId = objectId
        · subst queriedId
          exact allowed.complete.tree.indexes.liveWasIssued objectId allowed.object
            allowed.objectLookup
        · exact allowed.complete.tree.indexes.liveWasIssued queriedId queriedObject
            (by simpa [unlinkName, replace, target] using queriedLookup)
    · rcases allowed.complete.tree.rootExists with
        ⟨rootId, root, rootLookup, rootIdentity, rootPath, rootKind⟩
      have rootIdNe : rootId ≠ objectId := by
        intro sameId
        have lookup := rootLookup
        rw [sameId, allowed.objectLookup] at lookup
        have sameObject : root = allowed.object := (Option.some.inj lookup).symm
        have targetDirectory : allowed.object.kind = .directory := by
          rw [← sameObject]
          exact rootKind
        exact allowed.sourceIsNotDirectory targetDirectory
      exact ⟨rootId, root, by
        simpa [unlinkName, replace, rootIdNe] using rootLookup,
        rootIdentity, rootPath, rootKind⟩
    · intro queriedId queriedObject queriedLookup notRoot
      by_cases target : queriedId = objectId
      · subst queriedId
        have exactObject : queriedObject = updated := Option.some.inj
          (queriedLookup.symm.trans (unlinkName_stores_object state objectId
            allowed.object alias allowed.newPrimary allowed.remaining))
        subst queriedObject
        exact ⟨allowed.parentId, allowed.parent,
          by simpa [unlinkName, replace, parentIdNe] using allowed.parentLookup,
          by simpa [unlinkName, replace, parentPathNeAlias] using
            allowed.parentPathLookup,
          allowed.parentIsDirectory, by
            simpa [updated, withRemainingAliases] using allowed.directChild⟩
      · have oldLookup : state.objects queriedId = some queriedObject := by
          simpa [unlinkName, replace, target] using queriedLookup
        rcases allowed.complete.tree.parentDirectory queriedId queriedObject
          oldLookup notRoot with
          ⟨parentId, parent, parentLookup, parentPathLookup, parentKind, direct⟩
        have parentIdDiffers : parentId ≠ objectId := by
          intro sameId
          have lookup := parentLookup
          rw [sameId, allowed.objectLookup] at lookup
          have sameObject : parent = allowed.object := (Option.some.inj lookup).symm
          have targetDirectory : allowed.object.kind = .directory := by
            rw [← sameObject]
            exact parentKind
          exact allowed.sourceIsNotDirectory targetDirectory
        have parentPathDiffers : parent.path ≠ alias := by
          intro equality
          have sameOwner := Option.some.inj
            (parentPathLookup.symm.trans (equality ▸ allowed.aliasIndexed))
          exact parentIdDiffers sameOwner
        exact ⟨parentId, parent,
          by simpa [unlinkName, replace, parentIdDiffers] using parentLookup,
          by simpa [unlinkName, replace, parentPathDiffers] using parentPathLookup,
          parentKind, direct⟩
  · refine ⟨?_, ?_, ?_, ?_, ?_⟩
    · intro queriedId queriedObject queriedLookup
      by_cases target : queriedId = objectId
      · subst queriedId
        have exactObject : queriedObject = updated := Option.some.inj
          (queriedLookup.symm.trans (unlinkName_stores_object state objectId
            allowed.object alias allowed.newPrimary allowed.remaining))
        subst queriedObject
        simpa [updated, withRemainingAliases] using targetIdentity
      · exact allowed.complete.aliases.objectIdentity queriedId queriedObject
          (by simpa [unlinkName, replace, target] using queriedLookup)
    · intro queriedId queriedObject queriedLookup
      by_cases target : queriedId = objectId
      · subst queriedId
        have exactObject : queriedObject = updated := Option.some.inj
          (queriedLookup.symm.trans (unlinkName_stores_object state objectId
            allowed.object alias allowed.newPrimary allowed.remaining))
        subst queriedObject
        exact ⟨⟨by simpa [updated, withRemainingAliases] using survivingNodup,
          by simp [updated, withRemainingAliases]⟩,
          by simpa [updated, withRemainingAliases] using oldShape.2⟩
      · exact allowed.complete.aliases.objectShape queriedId queriedObject
          (by simpa [unlinkName, replace, target] using queriedLookup)
    · intro queriedId queriedObject path queriedLookup member
      by_cases target : queriedId = objectId
      · subst queriedId
        have exactObject : queriedObject = updated := Option.some.inj
          (queriedLookup.symm.trans (unlinkName_stores_object state objectId
            allowed.object alias allowed.newPrimary allowed.remaining))
        subst queriedObject
        have surviving : path ∈ allowed.newPrimary :: allowed.remaining := by
          simpa [updated, withRemainingAliases] using member
        have oldMember : path ∈ allowed.object.aliases :=
          allowed.member_partition.mpr (Or.inr surviving)
        have oldPath := allowed.complete.aliases.aliasToPath objectId allowed.object
          path allowed.objectLookup oldMember
        have pathNeAlias : path ≠ alias := by
          intro equality
          subst path
          exact aliasNotSurviving surviving
        simpa [unlinkName, replace, pathNeAlias] using oldPath
      · have oldLookup : state.objects queriedId = some queriedObject := by
          simpa [unlinkName, replace, target] using queriedLookup
        have oldPath := allowed.complete.aliases.aliasToPath queriedId queriedObject
          path oldLookup member
        have pathNeAlias : path ≠ alias := by
          intro equality
          have sameOwner := Option.some.inj
            (oldPath.symm.trans (equality ▸ allowed.aliasIndexed))
          exact target sameOwner
        simpa [unlinkName, replace, pathNeAlias] using oldPath
    · intro path queriedId pathLookup
      have pathNeAlias : path ≠ alias := by
        intro equality
        subst path
        simp [unlinkName] at pathLookup
      have oldPath : state.paths path = some queriedId := by
        simpa [unlinkName, replace, pathNeAlias] using pathLookup
      rcases allowed.complete.aliases.pathToAlias path queriedId oldPath with
        ⟨object, objectLookup, oldMember⟩
      by_cases target : queriedId = objectId
      · subst queriedId
        have sameObject : object = allowed.object := Option.some.inj
          (objectLookup.symm.trans allowed.objectLookup)
        subst object
        have surviving : path ∈ allowed.newPrimary :: allowed.remaining :=
          (allowed.member_partition.mp oldMember).resolve_left pathNeAlias
        exact ⟨updated, unlinkName_stores_object state objectId allowed.object
          alias allowed.newPrimary allowed.remaining,
          by simpa [updated, withRemainingAliases] using surviving⟩
      · exact ⟨object, by simpa [unlinkName, replace, target] using objectLookup,
          oldMember⟩
    · intro queriedId queriedObject queriedLookup
      by_cases target : queriedId = objectId
      · subst queriedId
        exact allowed.complete.aliases.liveWasIssued objectId allowed.object
          allowed.objectLookup
      · exact allowed.complete.aliases.liveWasIssued queriedId queriedObject
          (by simpa [unlinkName, replace, target] using queriedLookup)
  · intro queriedId queriedObject queriedLookup isDirectory
    by_cases target : queriedId = objectId
    · subst queriedId
      have exactObject : queriedObject = updated := Option.some.inj
        (queriedLookup.symm.trans (unlinkName_stores_object state objectId
          allowed.object alias allowed.newPrimary allowed.remaining))
      subst queriedObject
      have targetDirectory : allowed.object.kind = .directory := by
        simpa [updated, withRemainingAliases] using isDirectory
      exact False.elim (allowed.sourceIsNotDirectory targetDirectory)
    · exact allowed.complete.directorySingleton queriedId queriedObject
        (by simpa [unlinkName, replace, target] using queriedLookup) isDirectory
  · intro queriedId queriedObject name queriedLookup member notRoot
    by_cases target : queriedId = objectId
    · subst queriedId
      have exactObject : queriedObject = updated := Option.some.inj
        (queriedLookup.symm.trans (unlinkName_stores_object state objectId
          allowed.object alias allowed.newPrimary allowed.remaining))
      subst queriedObject
      have surviving : name ∈ allowed.newPrimary :: allowed.remaining := by
        simpa [updated, withRemainingAliases] using member
      have oldMember : name ∈ allowed.object.aliases :=
        allowed.member_partition.mpr (Or.inr surviving)
      rcases allowed.complete.namedParentDirectory objectId allowed.object name
        allowed.objectLookup oldMember notRoot with
        ⟨parentId, parent, parentLookup, parentPathLookup, parentKind, direct⟩
      have parentIdDiffers : parentId ≠ objectId := by
        intro sameId
        have lookup := parentLookup
        rw [sameId, allowed.objectLookup] at lookup
        have sameObject : parent = allowed.object := (Option.some.inj lookup).symm
        have targetDirectory : allowed.object.kind = .directory := by
          rw [← sameObject]
          exact parentKind
        exact allowed.sourceIsNotDirectory targetDirectory
      have parentPathDiffers : parent.path ≠ alias := by
        intro equality
        have sameOwner := Option.some.inj
          (parentPathLookup.symm.trans (equality ▸ allowed.aliasIndexed))
        exact parentIdDiffers sameOwner
      exact ⟨parentId, parent,
        by simpa [unlinkName, replace, parentIdDiffers] using parentLookup,
        by simpa [unlinkName, replace, parentPathDiffers] using parentPathLookup,
        parentKind, direct⟩
    · have oldLookup : state.objects queriedId = some queriedObject := by
        simpa [unlinkName, replace, target] using queriedLookup
      rcases allowed.complete.namedParentDirectory queriedId queriedObject name
        oldLookup member notRoot with
        ⟨parentId, parent, parentLookup, parentPathLookup, parentKind, direct⟩
      have parentIdDiffers : parentId ≠ objectId := by
        intro sameId
        have lookup := parentLookup
        rw [sameId, allowed.objectLookup] at lookup
        have sameObject : parent = allowed.object := (Option.some.inj lookup).symm
        have targetDirectory : allowed.object.kind = .directory := by
          rw [← sameObject]
          exact parentKind
        exact allowed.sourceIsNotDirectory targetDirectory
      have parentPathDiffers : parent.path ≠ alias := by
        intro equality
        have sameOwner := Option.some.inj
          (parentPathLookup.symm.trans (equality ▸ allowed.aliasIndexed))
        exact parentIdDiffers sameOwner
      exact ⟨parentId, parent,
        by simpa [unlinkName, replace, parentIdDiffers] using parentLookup,
        by simpa [unlinkName, replace, parentPathDiffers] using parentPathLookup,
        parentKind, direct⟩

/-- Preconditions for publishing one contained symbolic link. -/
structure MayCreateSymlink (state : NamespaceState) (object : NamespaceObject) where
  complete : state.CompleteWellFormed
  creation : state.MayCreate object
  kindIsSymlink : object.kind = .symlink
  aliasesSingleton : object.aliases = [object.path]
  target : CanonicalPath
  targetStored : object.symlinkTarget = some target

/-- Symlink publication is the ordinary atomic object/index publication. -/
def createSymlink (state : NamespaceState) (object : NamespaceObject) :
    NamespaceState := state.create object

/-- A checked symlink publication preserves the complete alias-aware tree. -/
theorem createSymlink_preserves_completeWellFormed {state : NamespaceState}
    {object : NamespaceObject} (allowed : state.MayCreateSymlink object) :
    (state.createSymlink object).CompleteWellFormed := by
  have objectShape : object.ShapeWellFormed := by
    refine ⟨object.singleton_aliases_wellFormed allowed.aliasesSingleton, ?_⟩
    rw [NamespaceObject.TargetWellFormed, allowed.kindIsSymlink,
      allowed.targetStored]
    simp
  have parentIdNe : allowed.creation.parentId ≠ object.id := by
    intro equality
    have lookup := allowed.creation.parentLookup
    rw [equality, allowed.creation.objectAbsent] at lookup
    contradiction
  have parentPathNe : allowed.creation.parent.path ≠ object.path := by
    intro equality
    have lookup := allowed.creation.parentPathLookup
    rw [equality, allowed.creation.pathAbsent] at lookup
    contradiction
  refine ⟨create_preserves_treeWellFormed allowed.complete.tree allowed.creation,
    ?_, ?_, ?_⟩
  · refine ⟨?_, ?_, ?_, ?_, ?_⟩
    · intro objectId queried queriedLookup
      by_cases created : objectId = object.id
      · subst objectId
        have exactObject : queried = object := Option.some.inj
          (queriedLookup.symm.trans (create_stores_object state object))
        subst queried
        rfl
      · exact allowed.complete.aliases.objectIdentity objectId queried
          (by simpa [createSymlink, create, replace, created] using queriedLookup)
    · intro objectId queried queriedLookup
      by_cases created : objectId = object.id
      · subst objectId
        have exactObject : queried = object := Option.some.inj
          (queriedLookup.symm.trans (create_stores_object state object))
        simpa [exactObject] using objectShape
      · exact allowed.complete.aliases.objectShape objectId queried
          (by simpa [createSymlink, create, replace, created] using queriedLookup)
    · intro objectId queried path queriedLookup member
      by_cases created : objectId = object.id
      · subst objectId
        have exactObject : queried = object := Option.some.inj
          (queriedLookup.symm.trans (create_stores_object state object))
        subst queried
        rw [allowed.aliasesSingleton] at member
        simp at member
        subst path
        exact create_stores_path state object
      · have oldLookup : state.objects objectId = some queried := by
          simpa [createSymlink, create, replace, created] using queriedLookup
        have oldPath := allowed.complete.aliases.aliasToPath objectId queried path
          oldLookup member
        have pathNe : path ≠ object.path := by
          intro equality
          rw [equality, allowed.creation.pathAbsent] at oldPath
          contradiction
        simpa [createSymlink, create, replace, pathNe] using oldPath
    · intro path objectId pathLookup
      by_cases createdPath : path = object.path
      · subst path
        have exactId : objectId = object.id := Option.some.inj
          (pathLookup.symm.trans (create_stores_path state object))
        subst objectId
        exact ⟨object, create_stores_object state object, by
          simp [allowed.aliasesSingleton]⟩
      · have oldPath : state.paths path = some objectId := by
          simpa [createSymlink, create, replace, createdPath] using pathLookup
        rcases allowed.complete.aliases.pathToAlias path objectId oldPath with
          ⟨queried, queriedLookup, member⟩
        have objectIdNe : objectId ≠ object.id := by
          intro equality
          subst objectId
          rw [allowed.creation.objectAbsent] at queriedLookup
          contradiction
        exact ⟨queried, by
          simpa [createSymlink, create, replace, objectIdNe] using queriedLookup,
          member⟩
    · intro objectId queried queriedLookup
      by_cases created : objectId = object.id
      · subst objectId
        exact create_reserves_identity state object
      · simpa [createSymlink, create, replace, created] using
          allowed.complete.aliases.liveWasIssued objectId queried
            (by simpa [createSymlink, create, replace, created] using queriedLookup)
  · intro objectId queried queriedLookup isDirectory
    by_cases created : objectId = object.id
    · subst objectId
      have exactObject : queried = object := Option.some.inj
        (queriedLookup.symm.trans (create_stores_object state object))
      subst queried
      rw [allowed.kindIsSymlink] at isDirectory
      contradiction
    · exact allowed.complete.directorySingleton objectId queried
        (by simpa [createSymlink, create, replace, created] using queriedLookup)
        isDirectory
  · intro objectId queried name queriedLookup member notRoot
    by_cases created : objectId = object.id
    · subst objectId
      have exactObject : queried = object := Option.some.inj
        (queriedLookup.symm.trans (create_stores_object state object))
      subst queried
      rw [allowed.aliasesSingleton] at member
      simp at member
      subst name
      exact ⟨allowed.creation.parentId, allowed.creation.parent,
        by simpa [createSymlink, create, replace, parentIdNe] using
          allowed.creation.parentLookup,
        by simpa [createSymlink, create, replace, parentPathNe] using
          allowed.creation.parentPathLookup,
        allowed.creation.parentIsDirectory, allowed.creation.directChild⟩
    · have oldLookup : state.objects objectId = some queried := by
        simpa [createSymlink, create, replace, created] using queriedLookup
      rcases allowed.complete.namedParentDirectory objectId queried name oldLookup
        member notRoot with
        ⟨parentId, parent, parentLookup, parentPathLookup, parentKind, direct⟩
      have oldParentIdNe : parentId ≠ object.id := by
        intro equality
        rw [equality, allowed.creation.objectAbsent] at parentLookup
        contradiction
      have oldParentPathNe : parent.path ≠ object.path := by
        intro equality
        rw [equality, allowed.creation.pathAbsent] at parentPathLookup
        contradiction
      exact ⟨parentId, parent,
        by simpa [createSymlink, create, replace, oldParentIdNe] using parentLookup,
        by simpa [createSymlink, create, replace, oldParentPathNe] using
          parentPathLookup,
        parentKind, direct⟩
/-- Preconditions for removing one live, unopened object. -/
structure MayRemove (state : NamespaceState) (objectId : ObjectId) where
  generationCanIncrement : CanIncrementU64 state.generation
  object : NamespaceObject
  objectLookup : state.objects objectId = some object
  identityMatches : object.id = objectId
  pathLookup : state.paths object.path = some objectId
  /-- Object removal is reserved for the final indexed name. -/
  onlyIndexedPath : ∀ path, state.paths path = some objectId → path = object.path
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
      ⟨queriedObject, oldObjectLookup⟩
    have differentId : queriedId ≠ objectId := by
      intro sameId
      subst queriedId
      exact differentPath (allowed.onlyIndexedPath queriedPath oldPathLookup)
    exact ⟨queriedObject,
      by simpa [remove, replace, differentId] using oldObjectLookup⟩
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
A subtree rebase request. Unlike a permutation of all canonical paths, this
contains only the two roots used by Rust's finite live-namespace transaction.
-/
structure PathRenaming where
  source : CanonicalPath
  destination : CanonicalPath

namespace PathRenaming

/-- Construct the unique suffix-preserving rebase request for any two paths. -/
def between (source destination : CanonicalPath) : PathRenaming :=
  { source, destination }

/-- Every source/destination pair has a concrete subtree-rebase witness. -/
theorem exists_between (source destination : CanonicalPath) :
    ∃ pathMapping : PathRenaming,
      pathMapping.source = source ∧ pathMapping.destination = destination := by
  exact ⟨between source destination, rfl, rfl⟩

/-- Rebase one path from the requested source to destination subtree. -/
def forward (pathMapping : PathRenaming) (path : CanonicalPath) : CanonicalPath :=
  rebasePath path pathMapping.source pathMapping.destination

/-- Recover an old source path from a path in the destination subtree. -/
def inverse (pathMapping : PathRenaming) (path : CanonicalPath) : CanonicalPath :=
  rebasePath path pathMapping.destination pathMapping.source

/-- The moved subtree root maps to the requested destination. -/
theorem mapsSource (pathMapping : PathRenaming) :
    pathMapping.forward pathMapping.source = pathMapping.destination := by
  apply canonicalPath_eq
  change (rebasePath pathMapping.source pathMapping.source
    pathMapping.destination).segments = pathMapping.destination.segments
  simpa using (rebasePath_atOrBelow
    (path := pathMapping.source) (source := pathMapping.source)
    (destination := pathMapping.destination) (suffix := []) (by simp))

/-- Every moved path retains its exact suffix. -/
theorem sourceSubtreeRebased (pathMapping : PathRenaming) {path : CanonicalPath}
    {suffix : List String}
    (pathEquality : path.segments = pathMapping.source.segments ++ suffix) :
    (pathMapping.forward path).segments =
      pathMapping.destination.segments ++ suffix := by
  exact rebasePath_atOrBelow pathEquality

/-- The local inverse restores every path in the destination subtree. -/
theorem destinationSubtreeRestored (pathMapping : PathRenaming)
    {path : CanonicalPath} {suffix : List String}
    (pathEquality : path.segments = pathMapping.destination.segments ++ suffix) :
    (pathMapping.inverse path).segments =
      pathMapping.source.segments ++ suffix := by
  exact rebasePath_atOrBelow pathEquality

/-- The local inverse cancels forward rebasing on the source subtree. -/
theorem inverseForward_atOrBelow (pathMapping : PathRenaming)
    {path : CanonicalPath} (inSource : AtOrBelow path pathMapping.source) :
    pathMapping.inverse (pathMapping.forward path) = path := by
  rcases inSource with ⟨suffix, pathEquality⟩
  apply canonicalPath_eq
  rw [pathMapping.destinationSubtreeRestored
    (pathMapping.sourceSubtreeRebased pathEquality), pathEquality]

/-- Forward rebasing cancels the local inverse on the destination subtree. -/
theorem forwardInverse_atOrBelow (pathMapping : PathRenaming)
    {path : CanonicalPath} (inDestination : AtOrBelow path pathMapping.destination) :
    pathMapping.forward (pathMapping.inverse path) = path := by
  rcases inDestination with ⟨suffix, pathEquality⟩
  apply canonicalPath_eq
  rw [pathMapping.sourceSubtreeRebased
    (pathMapping.destinationSubtreeRestored pathEquality), pathEquality]

/-- Paths outside the moved source subtree remain unchanged. -/
theorem forward_outside (pathMapping : PathRenaming) {path : CanonicalPath}
    (outside : ¬ AtOrBelow path pathMapping.source) :
    pathMapping.forward path = path := by
  exact rebasePath_outside outside

/-- Rebasing preserves every parent edge except the edge entering the moved root. -/
theorem preservesDirectParentExceptSource (pathMapping : PathRenaming)
    {parent child : CanonicalPath} (childIsNotSource : child ≠ pathMapping.source)
    (directParent : DirectParent parent child) :
    DirectParent (pathMapping.forward parent) (pathMapping.forward child) := by
  rcases directParent with ⟨segment, childEquality⟩
  by_cases childInSource : AtOrBelow child pathMapping.source
  · have sourcePrefixChild : pathMapping.source.segments <+: child.segments := by
      rcases childInSource with ⟨suffix, equality⟩
      exact ⟨suffix, equality.symm⟩
    have parentPrefixChild : parent.segments <+: child.segments :=
      ⟨[segment], childEquality.symm⟩
    have sourceLengthLess : pathMapping.source.segments.length < child.segments.length := by
      apply Nat.lt_of_le_of_ne sourcePrefixChild.length_le
      intro lengthsEqual
      have sourceEqualsChild := sourcePrefixChild.eq_of_length lengthsEqual
      exact childIsNotSource (canonicalPath_eq sourceEqualsChild.symm)
    have sourcePrefixParent : pathMapping.source.segments <+: parent.segments :=
      List.prefix_of_prefix_length_le sourcePrefixChild parentPrefixChild (by
        have childLength : child.segments.length = parent.segments.length + 1 := by
          simp [childEquality]
        omega)
    rcases sourcePrefixParent with ⟨parentSuffix, parentEquality⟩
    have childSuffixEquality :
        child.segments = pathMapping.source.segments ++ (parentSuffix ++ [segment]) := by
      rw [childEquality, ← parentEquality, List.append_assoc]
    exact ⟨segment, by
      rw [pathMapping.sourceSubtreeRebased parentEquality.symm,
        pathMapping.sourceSubtreeRebased childSuffixEquality]
      simp [List.append_assoc]⟩
  · have parentOutsideSource : ¬ AtOrBelow parent pathMapping.source := by
      intro parentInSource
      rcases parentInSource with ⟨suffix, parentEquality⟩
      apply childInSource
      exact ⟨suffix ++ [segment], by
        rw [childEquality, parentEquality, List.append_assoc]⟩
    simpa [pathMapping.forward_outside parentOutsideSource,
      pathMapping.forward_outside childInSource] using
      (⟨segment, childEquality⟩ : DirectParent parent child)

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
  movedHandlesClosed : ∀ objectId object,
    state.objects objectId = some object →
      AtOrBelow object.path pathMapping.source →
      object.openHandleCount = 0

/-- Rebuild the path index exactly as Rust removes sources then inserts destinations. -/
def renamedPaths (state : NamespaceState) (pathMapping : PathRenaming) :
    CanonicalPath → Option ObjectId := fun path =>
  if pathMapping.destination.segments.isPrefixOf path.segments then
    state.paths (pathMapping.inverse path)
  else if pathMapping.source.segments.isPrefixOf path.segments then
    none
  else
    state.paths path

/-- Rename every live path in the selected source subtree. -/
def renamePaths (state : NamespaceState) (pathMapping : PathRenaming) : NamespaceState :=
  { state with
    objects := fun objectId => (state.objects objectId).map
      (fun object => { object with path := pathMapping.forward object.path })
    paths := renamedPaths state pathMapping
    generation := state.generation + 1 }

/-- Rename never changes object identity, kind, or open-handle count. -/
theorem rename_preserves_object_fields {state : NamespaceState}
    {pathMapping : PathRenaming} {objectId : ObjectId} {object : NamespaceObject}
    (lookup : state.objects objectId = some object) :
    (state.renamePaths pathMapping).objects objectId = some {
      object with path := pathMapping.forward object.path
    } := by
  simp [renamePaths, lookup]

/-- The rebuilt index stores the new path of every old live object. -/
theorem rename_stores_path {state : NamespaceState} {pathMapping : PathRenaming}
    (allowed : state.MayRename pathMapping) {objectId : ObjectId}
    {object : NamespaceObject}
    (objectLookup : state.objects objectId = some object)
    (pathLookup : state.paths object.path = some objectId) :
    (state.renamePaths pathMapping).paths (pathMapping.forward object.path) =
      some objectId := by
  by_cases inSource : AtOrBelow object.path pathMapping.source
  · rcases inSource with ⟨suffix, pathEquality⟩
    have destinationPrefix :
        pathMapping.destination.segments.isPrefixOf
          (pathMapping.forward object.path).segments = true :=
      isPrefixOf_eq_true_iff_atOrBelow.mpr
        ⟨suffix, pathMapping.sourceSubtreeRebased pathEquality⟩
    simp [renamePaths, renamedPaths, destinationPrefix,
      pathMapping.inverseForward_atOrBelow ⟨suffix, pathEquality⟩, pathLookup]
  · have pathUnchanged := pathMapping.forward_outside inSource
    have outsideDestination := allowed.destinationSubtreeEmpty objectId object objectLookup
    have destinationPrefix :
        pathMapping.destination.segments.isPrefixOf object.path.segments = false :=
      Bool.eq_false_iff.mpr fun prefixIsTrue =>
        outsideDestination (isPrefixOf_eq_true_iff_atOrBelow.mp prefixIsTrue)
    have sourcePrefix :
        pathMapping.source.segments.isPrefixOf object.path.segments = false :=
      Bool.eq_false_iff.mpr fun prefixIsTrue =>
        inSource (isPrefixOf_eq_true_iff_atOrBelow.mp prefixIsTrue)
    simp [renamePaths, renamedPaths, pathUnchanged, destinationPrefix,
      sourcePrefix, pathLookup]

/-- Reciprocal indexes remain well formed under a valid finite subtree rebase. -/
theorem rename_preserves_wellFormed {state : NamespaceState}
    (wellFormed : state.WellFormed) (pathMapping : PathRenaming)
    (allowed : state.MayRename pathMapping) :
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
        exact ⟨identityMatches,
          rename_stores_path allowed oldLookup oldPathLookup⟩
  · intro renamedPath objectId renamedLookup
    simp only [renamePaths, renamedPaths] at renamedLookup
    split at renamedLookup
    · rename_i destinationPrefix
      have inDestination := isPrefixOf_eq_true_iff_atOrBelow.mp destinationPrefix
      rcases wellFormed.pathToObject (pathMapping.inverse renamedPath) objectId
          renamedLookup with ⟨oldObject, objectLookup⟩
      exact ⟨{ oldObject with path := pathMapping.forward oldObject.path },
        rename_preserves_object_fields objectLookup⟩
    · rename_i _outsideDestination
      split at renamedLookup
      · simp at renamedLookup
      · rename_i sourcePrefix
        have outsideSource : ¬ AtOrBelow renamedPath pathMapping.source := by
          intro inSource
          exact sourcePrefix (isPrefixOf_eq_true_iff_atOrBelow.mpr inSource)
        rcases wellFormed.pathToObject renamedPath objectId renamedLookup with
          ⟨oldObject, objectLookup⟩
        exact ⟨{ oldObject with path := pathMapping.forward oldObject.path },
          rename_preserves_object_fields objectLookup⟩
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
  have rootUnchanged :
      pathMapping.forward CanonicalPath.root = CanonicalPath.root :=
    pathMapping.forward_outside (root_outside_subtree allowed.sourceNotRoot)
  refine ⟨rename_preserves_wellFormed treeWellFormed.indexes pathMapping allowed,
    ?_, ?_⟩
  · refine ⟨rootId, renamedRoot,
      rename_preserves_object_fields rootLookup, rootIdentity, ?_, rootKind⟩
    simp [renamedRoot, rootPath, rootUnchanged]
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
        simp [oldWasRoot, rootUnchanged]
      by_cases isMovedRoot : oldObject.path = pathMapping.source
      · rcases allowed.destinationParentExists with
          ⟨parentId, parent, parentLookup, parentPathLookup, parentKind,
            destinationParent, parentUnchanged⟩
        exact ⟨parentId, { parent with path := pathMapping.forward parent.path },
          rename_preserves_object_fields parentLookup,
          rename_stores_path allowed parentLookup parentPathLookup,
          parentKind,
          by simpa [isMovedRoot, pathMapping.mapsSource, parentUnchanged] using
            destinationParent⟩
      · rcases treeWellFormed.parentDirectory objectId oldObject oldLookup oldNotRoot with
          ⟨parentId, parent, parentLookup, parentPathLookup, parentKind, directParent⟩
        exact ⟨parentId, { parent with path := pathMapping.forward parent.path },
          rename_preserves_object_fields parentLookup,
          rename_stores_path allowed parentLookup parentPathLookup,
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
      ⟨queriedObject, oldLookup⟩
    by_cases sameId : queriedId = objectId
    · subst queriedId
      have exactObject : queriedObject = object := Option.some.inj
        (oldLookup.symm.trans objectLookup)
      subst queriedObject
      exact ⟨withOpenHandleCount object (object.openHandleCount + 1),
        openObject_increments_count state objectId object⟩
    · exact ⟨queriedObject,
        by simpa [openObject, updateOpenHandleCount, replace, sameId] using oldLookup⟩
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
      ⟨queriedObject, oldLookup⟩
    by_cases sameId : queriedId = objectId
    · subst queriedId
      have exactObject : queriedObject = object := Option.some.inj
        (oldLookup.symm.trans objectLookup)
      subst queriedObject
      exact ⟨withOpenHandleCount object (object.openHandleCount - 1),
        closeObject_decrements_count state objectId object⟩
    · exact ⟨queriedObject,
        by simpa [closeObject, updateOpenHandleCount, replace, sameId] using oldLookup⟩
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

/-- Preconditions for Rust's atomic `create_open_child` transaction. -/
structure MayCreateOpen (state : NamespaceState) (object : NamespaceObject) where
  creation : state.MayCreate object

/-- Publish a new child with open count one as one externally visible state change. -/
def createOpen (state : NamespaceState) (object : NamespaceObject) : NamespaceState :=
  (state.create object).openObject object.id object

/-- Atomic create-open stores exactly one live handle count. -/
theorem createOpen_stores_object (state : NamespaceState) (object : NamespaceObject) :
    state.MayCreateOpen object →
      (state.createOpen object).objects object.id =
        some (withOpenHandleCount object 1) := by
  intro allowed
  simp [createOpen, openObject_increments_count, allowed.creation.startsClosed]

/-- Atomic create-open preserves reciprocal index consistency. -/
theorem createOpen_preserves_wellFormed {state : NamespaceState}
    {object : NamespaceObject} (wellFormed : state.WellFormed)
    (allowed : state.MayCreateOpen object) :
    (state.createOpen object).WellFormed := by
  apply openObject_preserves_wellFormed
    (create_preserves_wellFormed wellFormed allowed.creation)
  exact create_stores_object state object

/-- Atomic create-open preserves the rooted namespace tree. -/
theorem createOpen_preserves_treeWellFormed {state : NamespaceState}
    {object : NamespaceObject} (treeWellFormed : state.TreeWellFormed)
    (allowed : state.MayCreateOpen object) :
    (state.createOpen object).TreeWellFormed := by
  apply openObject_preserves_treeWellFormed
    (create_preserves_treeWellFormed treeWellFormed allowed.creation)
  exact create_stores_object state object

/-- Namespace-mutating steps and handle-count steps. -/
inductive Step : NamespaceState → NamespaceState → Prop
  | create {state : NamespaceState} {object : NamespaceObject} :
      MayCreate state object → Step state (state.create object)
  | createOpen {state : NamespaceState} {object : NamespaceObject} :
      MayCreateOpen state object → Step state (state.createOpen object)
  | remove {state : NamespaceState} {objectId : ObjectId} :
      (allowed : MayRemove state objectId) →
      Step state (state.remove objectId allowed.object)
  | renamePaths {state : NamespaceState} {pathMapping : PathRenaming} :
      MayRename state pathMapping → Step state (state.renamePaths pathMapping)
  | addHardLink {state : NamespaceState} {objectId : ObjectId}
      {alias : CanonicalPath} :
      (allowed : MayAddHardLink state objectId alias) →
      Step state (state.addHardLink objectId allowed.object alias)
  | unlinkName {state : NamespaceState} {objectId : ObjectId}
      {alias : CanonicalPath} :
      (allowed : MayUnlinkName state objectId alias) →
      Step state (state.unlinkName objectId allowed.object alias
        allowed.newPrimary allowed.remaining)
  | createSymlink {state : NamespaceState} {object : NamespaceObject} :
      (allowed : MayCreateSymlink state object) →
      Step state (state.createSymlink object)
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
  | createOpen => exact Nat.le_succ _
  | remove => exact Nat.le_succ _
  | renamePaths => exact Nat.le_succ _
  | addHardLink => exact Nat.le_succ _
  | unlinkName => exact Nat.le_succ _
  | createSymlink => exact Nat.le_succ _
  | openObject => exact Nat.le_refl _
  | closeObject => exact Nat.le_refl _

/-- Namespace generation and every live handle count fit Rust `u64` fields. -/
def CountersRepresentable (state : NamespaceState) : Prop :=
  FitsU64 state.generation ∧
    (∀ objectId object,
      state.objects objectId = some object → FitsU64 object.openHandleCount) ∧
    ∀ sequence, state.nextObjectSequence = some sequence → FitsU64 sequence

/-- The singleton root namespace starts with representable counters. -/
theorem withRoot_countersRepresentable (rootId : ObjectId) :
    (withRoot rootId).CountersRepresentable := by
  constructor
  · simp [withRoot, FitsU64, u64Maximum]
  constructor
  · intro objectId object objectLookup
    by_cases sameId : objectId = rootId
    · subst objectId
      simp [withRoot, replace] at objectLookup
      subst object
      simp [rootObject, FitsU64, u64Maximum]
    · simp [withRoot, replace, sameId] at objectLookup
  · intro sequence cursor
    simp [withRoot] at cursor
    subst sequence
    simp [FitsU64, u64Maximum]

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
      constructor
      · intro queriedId queriedObject queriedLookup
        by_cases sameId : queriedId = createdObject.id
        · subst queriedId
          have exactObject : queriedObject = createdObject := Option.some.inj
            (queriedLookup.symm.trans (create_stores_object before createdObject))
          subst queriedObject
          simp [allowed.startsClosed, FitsU64, u64Maximum]
        · have oldLookup : before.objects queriedId = some queriedObject := by
            simpa [NamespaceState.create, replace, sameId] using queriedLookup
          exact representable.2.1 queriedId queriedObject oldLookup
      · intro sequence cursor
        rw [NamespaceState.create, allowed.cursorExpected] at cursor
        simp only [Option.bind] at cursor
        unfold advanceObjectCursor at cursor
        split at cursor
        · rename_i canIncrement
          have exactSequence : sequence = allowed.allocationSequence + 1 :=
            Option.some.inj cursor.symm
          subst sequence
          exact (show CanIncrementU64 allowed.allocationSequence from canIncrement).increment_fits
        · simp at cursor
  | createOpen allowed =>
      rename_i createdObject
      constructor
      · exact allowed.creation.generationCanIncrement.increment_fits
      constructor
      · intro queriedId queriedObject queriedLookup
        by_cases sameId : queriedId = createdObject.id
        · subst queriedId
          have exactObject : queriedObject = withOpenHandleCount createdObject 1 :=
            Option.some.inj (queriedLookup.symm.trans
              (createOpen_stores_object before createdObject allowed))
          subst queriedObject
          simp [withOpenHandleCount, FitsU64, u64Maximum]
        · have oldLookup : before.objects queriedId = some queriedObject := by
            simpa [NamespaceState.createOpen, NamespaceState.openObject,
              updateOpenHandleCount, NamespaceState.create, replace, sameId]
              using queriedLookup
          exact representable.2.1 queriedId queriedObject oldLookup
      · intro sequence cursor
        rw [NamespaceState.createOpen, NamespaceState.openObject,
          updateOpenHandleCount, NamespaceState.create,
          allowed.creation.cursorExpected] at cursor
        simp only [Option.bind] at cursor
        unfold advanceObjectCursor at cursor
        split at cursor
        · rename_i canIncrement
          have exactSequence : sequence = allowed.creation.allocationSequence + 1 :=
            Option.some.inj cursor.symm
          subst sequence
          exact (show CanIncrementU64 allowed.creation.allocationSequence from
            canIncrement).increment_fits
        · simp at cursor
  | remove allowed =>
      rename_i removedId
      constructor
      · exact allowed.generationCanIncrement.increment_fits
      constructor
      · intro queriedId queriedObject queriedLookup
        have differentId : queriedId ≠ removedId := by
          intro sameId
          subst queriedId
          simp [NamespaceState.remove] at queriedLookup
        have oldLookup : before.objects queriedId = some queriedObject := by
          simpa [NamespaceState.remove, replace, differentId] using queriedLookup
        exact representable.2.1 queriedId queriedObject oldLookup
      · exact representable.2.2
  | renamePaths allowed =>
      constructor
      · exact allowed.generationCanIncrement.increment_fits
      constructor
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
            exact representable.2.1 objectId oldObject oldLookup
      · exact representable.2.2
  | addHardLink allowed =>
      constructor
      · exact allowed.generationCanIncrement.increment_fits
      constructor
      · intro queriedId queriedObject queriedLookup
        rename_i linkedId alias
        by_cases target : queriedId = linkedId
        · subst queriedId
          have exactObject : queriedObject =
              withAddedAlias allowed.object alias := Option.some.inj
            (queriedLookup.symm.trans
              (addHardLink_stores_object before linkedId allowed.object alias))
          subst queriedObject
          simpa [withAddedAlias] using
            representable.2.1 linkedId allowed.object allowed.objectLookup
        · exact representable.2.1 queriedId queriedObject
            (by simpa [NamespaceState.addHardLink, replace, target] using queriedLookup)
      · exact representable.2.2
  | unlinkName allowed =>
      constructor
      · exact allowed.generationCanIncrement.increment_fits
      constructor
      · intro queriedId queriedObject queriedLookup
        rename_i unlinkedId alias
        by_cases target : queriedId = unlinkedId
        · subst queriedId
          have exactObject : queriedObject = withRemainingAliases allowed.object
              allowed.newPrimary allowed.remaining := Option.some.inj
            (queriedLookup.symm.trans (unlinkName_stores_object before unlinkedId
              allowed.object alias allowed.newPrimary allowed.remaining))
          subst queriedObject
          simpa [withRemainingAliases] using
            representable.2.1 unlinkedId allowed.object allowed.objectLookup
        · exact representable.2.1 queriedId queriedObject
            (by simpa [NamespaceState.unlinkName, replace, target] using queriedLookup)
      · exact representable.2.2
  | createSymlink allowed =>
      rename_i createdObject
      constructor
      · exact allowed.creation.generationCanIncrement.increment_fits
      constructor
      · intro queriedId queriedObject queriedLookup
        by_cases sameId : queriedId = createdObject.id
        · subst queriedId
          have exactObject : queriedObject = createdObject := Option.some.inj
            (queriedLookup.symm.trans (create_stores_object before createdObject))
          subst queriedObject
          simp [allowed.creation.startsClosed, FitsU64, u64Maximum]
        · exact representable.2.1 queriedId queriedObject
            (by simpa [NamespaceState.createSymlink, NamespaceState.create,
              replace, sameId] using queriedLookup)
      · intro sequence cursor
        rw [NamespaceState.createSymlink, NamespaceState.create,
          allowed.creation.cursorExpected] at cursor
        simp only [Option.bind] at cursor
        unfold advanceObjectCursor at cursor
        split at cursor
        · rename_i canIncrement
          have exactSequence : sequence = allowed.creation.allocationSequence + 1 :=
            Option.some.inj cursor.symm
          subst sequence
          exact (show CanIncrementU64 allowed.creation.allocationSequence from
            canIncrement).increment_fits
        · simp at cursor
  | openObject objectLookup canIncrement =>
      constructor
      · exact representable.1
      constructor
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
          exact representable.2.1 queriedId queriedObject oldLookup
      · exact representable.2.2
  | closeObject objectLookup _positive =>
      constructor
      · exact representable.1
      constructor
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
            representable.2.1 closedId closedObject objectLookup
        · have oldLookup : before.objects queriedId = some queriedObject := by
            simpa [NamespaceState.closeObject, updateOpenHandleCount, replace, sameId]
              using queriedLookup
          exact representable.2.1 queriedId queriedObject oldLookup
      · exact representable.2.2

/-- Issued object identities are never released by any accepted transition. -/
theorem Step.issued_identity_monotone {before after : NamespaceState}
    (transition : Step before after) {objectId : ObjectId}
    (issuedBefore : before.issuedObjects objectId = true) :
    after.issuedObjects objectId = true := by
  cases transition with
  | create allowed =>
      exact create_preserves_issued_identity _ _ issuedBefore
  | createOpen allowed =>
      exact create_preserves_issued_identity _ _ issuedBefore
  | remove => exact issuedBefore
  | renamePaths => exact issuedBefore
  | addHardLink => exact issuedBefore
  | unlinkName => exact issuedBefore
  | createSymlink => exact create_preserves_issued_identity _ _ issuedBefore
  | openObject => exact issuedBefore
  | closeObject => exact issuedBefore

/-- Every accepted namespace step preserves reciprocal-index well-formedness. -/
theorem Step.preserves_wellFormed {before after : NamespaceState}
    (transition : Step before after) (wellFormed : before.WellFormed) :
    after.WellFormed := by
  cases transition with
  | create allowed => exact create_preserves_wellFormed wellFormed allowed
  | createOpen allowed => exact createOpen_preserves_wellFormed wellFormed allowed
  | remove allowed => exact remove_preserves_wellFormed wellFormed allowed
  | renamePaths allowed => exact rename_preserves_wellFormed wellFormed _ allowed
  | addHardLink allowed =>
      exact (addHardLink_preserves_completeWellFormed allowed).tree.indexes
  | unlinkName allowed =>
      exact (unlinkName_preserves_completeWellFormed allowed).tree.indexes
  | createSymlink allowed =>
      exact (createSymlink_preserves_completeWellFormed allowed).tree.indexes
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
  | createOpen allowed => exact createOpen_preserves_treeWellFormed treeWellFormed allowed
  | remove allowed => exact remove_preserves_treeWellFormed treeWellFormed allowed
  | renamePaths allowed =>
      exact rename_preserves_treeWellFormed treeWellFormed _ allowed
  | addHardLink allowed =>
      exact (addHardLink_preserves_completeWellFormed allowed).tree
  | unlinkName allowed =>
      exact (unlinkName_preserves_completeWellFormed allowed).tree
  | createSymlink allowed =>
      exact (createSymlink_preserves_completeWellFormed allowed).tree
  | openObject objectLookup =>
      exact openObject_preserves_treeWellFormed treeWellFormed objectLookup
  | closeObject objectLookup _ =>
      exact closeObject_preserves_treeWellFormed treeWellFormed objectLookup

/-- Alias-aware successful mutations whose preconditions establish full shape. -/
inductive CompleteStep : NamespaceState → NamespaceState → Prop
  | addHardLink {state : NamespaceState} {objectId : ObjectId}
      {alias : CanonicalPath} :
      (allowed : MayAddHardLink state objectId alias) →
      CompleteStep state (state.addHardLink objectId allowed.object alias)
  | unlinkName {state : NamespaceState} {objectId : ObjectId}
      {alias : CanonicalPath} :
      (allowed : MayUnlinkName state objectId alias) →
      CompleteStep state (state.unlinkName objectId allowed.object alias
        allowed.newPrimary allowed.remaining)
  | createSymlink {state : NamespaceState} {object : NamespaceObject} :
      (allowed : MayCreateSymlink state object) →
      CompleteStep state (state.createSymlink object)

/-- Every alias-aware successful mutation is also an ordinary namespace step. -/
theorem CompleteStep.toStep {before after : NamespaceState}
    (transition : CompleteStep before after) : Step before after := by
  cases transition with
  | addHardLink allowed => exact Step.addHardLink allowed
  | unlinkName allowed => exact Step.unlinkName allowed
  | createSymlink allowed => exact Step.createSymlink allowed

/-- Every alias-aware successful mutation preserves the complete invariant. -/
theorem CompleteStep.preserves_completeWellFormed {before after : NamespaceState}
    (transition : CompleteStep before after) : after.CompleteWellFormed := by
  cases transition with
  | addHardLink allowed => exact addHardLink_preserves_completeWellFormed allowed
  | unlinkName allowed => exact unlinkName_preserves_completeWellFormed allowed
  | createSymlink allowed => exact createSymlink_preserves_completeWellFormed allowed

/-- Reflexive-transitive closure of complete alias-aware mutations. -/
inductive CompleteSteps : NamespaceState → NamespaceState → Prop
  | refl (state : NamespaceState) : CompleteSteps state state
  | tail {first middle last : NamespaceState} :
      CompleteSteps first middle → CompleteStep middle last →
      CompleteSteps first last

/-- Arbitrary finite alias-aware executions preserve exact indexes and tree shape. -/
theorem CompleteSteps.preserve_completeWellFormed {before after : NamespaceState}
    (transitions : CompleteSteps before after)
    (wellFormed : before.CompleteWellFormed) : after.CompleteWellFormed := by
  induction transitions with
  | refl => exact wellFormed
  | tail _ transition _ => exact transition.preserves_completeWellFormed

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
