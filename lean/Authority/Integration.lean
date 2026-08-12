import Authority.Namespace

/-!
# Authority and Namespace Integration

Cross-component refinement invariant connecting Authority live handles to the
capability-filesystem open count. Neither component can prove this agreement in
isolation; adapters must preserve this relation at each atomic open/close
linearization point.
-/

namespace Authority

/-- Repository-wide admission state shared by every mount of one backing tree. -/
inductive RepositoryHealth where
  | operational
  | inDoubt
  deriving Repr, BEq, DecidableEq

/-- Combined logical view shared by Authority Core and the namespace registry. -/
structure IntegratedHandleState where
  authority : CapabilityState
  namespaceState : NamespaceState
  accountedHandles : ObjectId → List HandleId
  /-- Handle identities owned by this namespace adapter, including tombstones. -/
  managedHandles : HandleId → Bool
  /-- Shared quarantine is part of the logical state, not mount-local metadata. -/
  repositoryHealth : RepositoryHealth

namespace IntegratedHandleState

/-- Exact cross-component agreement required at an integration boundary. -/
structure WellFormed (state : IntegratedHandleState) : Prop where
  accountedHandlesNodup : ∀ objectId, (state.accountedHandles objectId).Nodup
  authorityHandlesExact : ∀ objectId handleId,
    handleId ∈ state.accountedHandles objectId ↔
      ∃ handle,
        state.authority.openHandles handleId = some handle ∧
        handle.object = objectId ∧
        state.managedHandles handleId = true
  namespaceCountsExact : ∀ objectId object,
    state.namespaceState.objects objectId = some object →
      (state.accountedHandles objectId).length = object.openHandleCount
  everyManagedHandleHasLiveObject : ∀ handleId handle,
    state.managedHandles handleId = true →
    state.authority.openHandles handleId = some handle →
      ∃ object, state.namespaceState.objects handle.object = some object
  liveHandleOwnerExact : ∀ handleId handle,
    state.authority.openHandles handleId = some handle →
      state.authority.issuedHandleOwners handleId = some handle.subject
  managedHandleReserved : ∀ handleId,
    state.managedHandles handleId = true →
      ∃ owner, state.authority.issuedHandleOwners handleId = some owner
  namespaceWellFormed : state.namespaceState.TreeWellFormed
  authorityCountersRepresentable : state.authority.CountersRepresentable
  namespaceCountersRepresentable : state.namespaceState.CountersRepresentable

/-- A startup manifest enumerates exactly the live namespace object records. -/
def ManifestExact (namespaceState : NamespaceState)
    (manifest : List NamespaceObject) : Prop :=
  (manifest.map NamespaceObject.id).Nodup ∧
    ∀ objectId object,
      namespaceState.objects objectId = some object ↔
        object ∈ manifest ∧ object.id = objectId

/-- Trusted restore evidence is separate from ordinary runtime initialization. -/
structure RestorableSnapshot (state : IntegratedHandleState) where
  manifest : List NamespaceObject
  manifestExact : ManifestExact state.namespaceState manifest
  wellFormed : state.WellFormed
  /-- Imported paths, aliases, object shapes, and every named parent are exact. -/
  namespaceComplete : state.namespaceState.CompleteWellFormed
  /-- Restore may expose operations only after durable ambiguity is reconciled. -/
  repositoryReconciled : state.repositoryHealth = .operational

/-- A state may be restored only when a trusted importer supplies snapshot evidence. -/
def Restorable (state : IntegratedHandleState) : Prop :=
  Nonempty (RestorableSnapshot state)

/-- Trusted restore evidence exposes the same invariant as ordinary reachability. -/
theorem Restorable.wellFormed {state : IntegratedHandleState}
    (restorable : state.Restorable) : state.WellFormed := by
  rcases restorable with ⟨snapshot⟩
  exact snapshot.wellFormed

/-- A restorable import carries the full alias-aware namespace invariant. -/
theorem Restorable.namespaceComplete {state : IntegratedHandleState}
    (restorable : state.Restorable) : state.namespaceState.CompleteWellFormed := by
  rcases restorable with ⟨snapshot⟩
  exact snapshot.namespaceComplete

/-- Restorable snapshots are operational only with explicit reconciliation evidence. -/
theorem Restorable.repository_operational {state : IntegratedHandleState}
    (restorable : state.Restorable) :
    state.repositoryHealth = .operational := by
  rcases restorable with ⟨snapshot⟩
  exact snapshot.repositoryReconciled

/-- Package an already validated finite snapshot at the explicit restore boundary. -/
theorem Restorable.ofWellFormedManifest {state : IntegratedHandleState}
    {manifest : List NamespaceObject}
    (manifestExact : ManifestExact state.namespaceState manifest)
    (wellFormed : state.WellFormed)
    (namespaceComplete : state.namespaceState.CompleteWellFormed)
    (repositoryReconciled : state.repositoryHealth = .operational) :
    state.Restorable :=
  ⟨{ manifest, manifestExact, wellFormed, namespaceComplete,
      repositoryReconciled }⟩

/-- Build a startup snapshot whose imported manifest has no open handles. -/
def initializeClosed (authority : CapabilityState)
    (namespaceState : NamespaceState) : IntegratedHandleState where
  authority := authority
  namespaceState := namespaceState
  accountedHandles := fun _ => []
  managedHandles := fun _ => false
  repositoryHealth := .operational

/-- A closed exact manifest and an empty handle registry establish the bridge. -/
theorem initializeClosed_wellFormed {authority : CapabilityState}
    {namespaceState : NamespaceState} {manifest : List NamespaceObject}
    (manifestExact : ManifestExact namespaceState manifest)
    (allObjectsClosed : ∀ object, object ∈ manifest → object.openHandleCount = 0)
    (noAuthorityHandles : ∀ handleId, authority.openHandles handleId = none)
    (namespaceWellFormed : namespaceState.TreeWellFormed)
    (authorityCounters : authority.CountersRepresentable)
    (namespaceCounters : namespaceState.CountersRepresentable) :
    (initializeClosed authority namespaceState).WellFormed := by
  constructor
  · simp [initializeClosed]
  · intro objectId handleId
    constructor
    · intro accounted
      simp [initializeClosed] at accounted
    · rintro ⟨handle, handleLookup, _, _⟩
      change authority.openHandles handleId = some handle at handleLookup
      rw [noAuthorityHandles handleId] at handleLookup
      cases handleLookup
  · intro objectId object objectLookup
    have inManifest := (manifestExact.2 objectId object).1 objectLookup
    simp [initializeClosed, inManifest.2,
      allObjectsClosed object inManifest.1]
  · intro handleId handle _managed handleLookup
    change authority.openHandles handleId = some handle at handleLookup
    rw [noAuthorityHandles handleId] at handleLookup
    cases handleLookup
  · intro handleId handle handleLookup
    change authority.openHandles handleId = some handle at handleLookup
    rw [noAuthorityHandles handleId] at handleLookup
    cases handleLookup
  · intro handleId managed
    simp [initializeClosed] at managed
  · exact namespaceWellFormed
  · exact authorityCounters
  · exact namespaceCounters

/-- The singleton runtime namespace is exactly its one-object startup manifest. -/
theorem runtimeInitial_manifestExact :
    ManifestExact NamespaceState.runtimeInitial
      [NamespaceState.rootObject (NamespaceState.allocatedObjectId 0)] := by
  constructor
  · simp
  · intro objectId object
    by_cases sameObject : objectId = NamespaceState.allocatedObjectId 0
    · subst objectId
      constructor
      · intro objectLookup
        have rootLookup :
            some (NamespaceState.rootObject (NamespaceState.allocatedObjectId 0)) =
              some object := by
          simpa [NamespaceState.runtimeInitial, NamespaceState.withRoot,
            replace] using objectLookup
        have exactObject : object = NamespaceState.rootObject
            (NamespaceState.allocatedObjectId 0) := Option.some.inj
          rootLookup.symm
        subst object
        simp [NamespaceState.rootObject]
      · rintro ⟨objectInManifest, _⟩
        have exactObject := List.mem_singleton.mp objectInManifest
        subst object
        simp [NamespaceState.runtimeInitial, NamespaceState.withRoot, replace]
    · constructor
      · intro objectLookup
        simp [NamespaceState.runtimeInitial, NamespaceState.withRoot,
          replace, sameObject] at objectLookup
      · rintro ⟨objectInManifest, objectIdentity⟩
        have exactObject := List.mem_singleton.mp objectInManifest
        subst object
        exact False.elim (sameObject objectIdentity.symm)

/-- Incrementing the runtime root yields an exact one-object open manifest. -/
theorem runtimeInitialOpen_manifestExact :
    ManifestExact
      (NamespaceState.runtimeInitial.openObject
        (NamespaceState.allocatedObjectId 0)
        (NamespaceState.rootObject (NamespaceState.allocatedObjectId 0)))
      [NamespaceState.withOpenHandleCount
        (NamespaceState.rootObject (NamespaceState.allocatedObjectId 0)) 1] := by
  constructor
  · simp
  · intro objectId object
    by_cases sameObject : objectId = NamespaceState.allocatedObjectId 0
    · subst objectId
      constructor
      · intro objectLookup
        have rootLookup :
            some (NamespaceState.withOpenHandleCount
              (NamespaceState.rootObject (NamespaceState.allocatedObjectId 0)) 1) =
              some object := by
          simpa [NamespaceState.runtimeInitial, NamespaceState.withRoot,
            NamespaceState.openObject, NamespaceState.updateOpenHandleCount,
            NamespaceState.rootObject, replace] using objectLookup
        have exactObject : object = NamespaceState.withOpenHandleCount
            (NamespaceState.rootObject (NamespaceState.allocatedObjectId 0)) 1 :=
          Option.some.inj rootLookup.symm
        subst object
        simp [NamespaceState.withOpenHandleCount, NamespaceState.rootObject]
      · rintro ⟨objectInManifest, _⟩
        have exactObject := List.mem_singleton.mp objectInManifest
        subst object
        simp [NamespaceState.runtimeInitial, NamespaceState.withRoot,
          NamespaceState.openObject, NamespaceState.updateOpenHandleCount,
          NamespaceState.rootObject, replace]
    · constructor
      · intro objectLookup
        simp [NamespaceState.runtimeInitial, NamespaceState.withRoot,
          NamespaceState.openObject, NamespaceState.updateOpenHandleCount,
          replace, sameObject] at objectLookup
      · rintro ⟨objectInManifest, objectIdentity⟩
        have exactObject := List.mem_singleton.mp objectInManifest
        subst object
        exact False.elim (sameObject objectIdentity.symm)

/-- Concrete runtime startup: empty Authority handles and one closed manifest root. -/
def initial (issuer : IssuerId) : IntegratedHandleState :=
  initializeClosed (CapabilityState.empty issuer) NamespaceState.runtimeInitial

/-- Ordinary execution starts only from the concrete empty runtime state. -/
def Initial (state : IntegratedHandleState) : Prop :=
  ∃ issuer, state = initial issuer

/-- The concrete runtime startup satisfies every exported invariant. -/
theorem initial_wellFormed (issuer : IssuerId) : (initial issuer).WellFormed := by
  apply initializeClosed_wellFormed runtimeInitial_manifestExact
  · intro object objectInManifest
    have exactObject := List.mem_singleton.mp objectInManifest
    subst object
    rfl
  · intro handleId
    rfl
  · exact NamespaceState.withRoot_treeWellFormed
      (NamespaceState.allocatedObjectId 0)
  · exact CapabilityState.empty_countersRepresentable issuer
  · exact NamespaceState.withRoot_countersRepresentable
      (NamespaceState.allocatedObjectId 0)

/-- Concrete initialization also satisfies exact aliases and every named parent. -/
theorem initial_namespaceComplete (issuer : IssuerId) :
    (initial issuer).namespaceState.CompleteWellFormed := by
  exact NamespaceState.withRoot_completeWellFormed
    (NamespaceState.allocatedObjectId 0)

/-- The concrete runtime startup is admitted by the initial-state relation. -/
theorem initial_isInitial (issuer : IssuerId) : (initial issuer).Initial :=
  ⟨issuer, rfl⟩

/-- Concrete initialization begins outside quarantine. -/
theorem initial_repository_operational (issuer : IssuerId) :
    (initial issuer).repositoryHealth = .operational := rfl

/-- Every ordinary initial state is exactly one concrete empty runtime state. -/
theorem Initial.wellFormed {state : IntegratedHandleState}
    (initialState : state.Initial) : state.WellFormed := by
  rcases initialState with ⟨issuer, rfl⟩
  exact initial_wellFormed issuer

/-- The startup relation is constructively inhabited for every issuer. -/
theorem initial_nonempty (issuer : IssuerId) :
    ∃ state : IntegratedHandleState, state.Initial :=
  ⟨initial issuer, initial_isInitial issuer⟩

/-- Minimal concrete envelope used only by the reachability witness subject. -/
def startupEnvelope : StaticAuthorityEnvelope where
  validity := {
    notBefore := { ticks := 0 }
    expiresAt := { ticks := 1 }
    isValid := by decide
  }
  authority := .file {
    repository := { value := "startup-repository" }
    effects := FileEffects.empty
    path := .exact CanonicalPath.root
  }

/-- Concrete root subject registered by the non-vacuity execution. -/
def startupSubject (subjectId : SubjectId) : Subject where
  id := subjectId
  parent := none
  envelope := startupEnvelope

/-- Registration preconditions hold in the concrete empty Authority state. -/
def initialMayRegisterSubject (issuer : IssuerId) (subjectId : SubjectId) :
    (CapabilityState.empty issuer).MayRegisterSubject (startupSubject subjectId) := by
  constructor
  · rfl
  · rfl
  · intro capabilityId
    rfl
  · intro parentId parentLookup
    simp [startupSubject] at parentLookup

/-- Startup after a real typed Authority subject-registration transition. -/
def readyInitial (issuer : IssuerId) (subjectId : SubjectId) :
    IntegratedHandleState :=
  { initial issuer with
    authority := (CapabilityState.empty issuer).registerSubject
      (startupSubject subjectId) }

/-- Concrete handle used to witness a reachable nonempty accounting snapshot. -/
def startupRootHandle (subject : SubjectId) (handleId : HandleId) : OpenHandle where
  id := handleId
  subject := subject
  object := NamespaceState.allocatedObjectId 0

/-- A live managed Authority handle is represented in the finite accounting set. -/
theorem WellFormed.live_managed_handle_is_accounted {state : IntegratedHandleState}
    (wellFormed : state.WellFormed) {handleId : HandleId} {handle : OpenHandle}
    (managed : state.managedHandles handleId = true)
    (lookup : state.authority.openHandles handleId = some handle) :
    handleId ∈ state.accountedHandles handle.object := by
  exact (wellFormed.authorityHandlesExact handle.object handleId).2
    ⟨handle, lookup, rfl, managed⟩

/-- A live object with zero namespace count has no live managed Authority handle. -/
theorem WellFormed.zero_count_excludes_managed_authority_handle
    {state : IntegratedHandleState} (wellFormed : state.WellFormed)
    {objectId : ObjectId} {object : NamespaceObject}
    (objectLookup : state.namespaceState.objects objectId = some object)
    (noOpenHandles : object.openHandleCount = 0) :
    ∀ handleId handle,
      state.managedHandles handleId = true →
      state.authority.openHandles handleId = some handle →
      handle.object ≠ objectId := by
  intro handleId handle managed handleLookup sameObject
  subst objectId
  have accounted := wellFormed.live_managed_handle_is_accounted managed handleLookup
  have emptyAccounting : (state.accountedHandles handle.object).length = 0 := by
    rw [wellFormed.namespaceCountsExact handle.object object objectLookup,
      noOpenHandles]
  have noMembers : state.accountedHandles handle.object = [] :=
    List.length_eq_zero.mp emptyAccounting
  rw [noMembers] at accounted
  simp at accounted

/-- Namespace removal preconditions exclude every live managed Authority handle. -/
theorem mayRemove_excludes_live_managed_authority_handles
    {state : IntegratedHandleState} (wellFormed : state.WellFormed)
    {objectId : ObjectId} (allowed : state.namespaceState.MayRemove objectId) :
    ∀ handleId handle,
      state.managedHandles handleId = true →
      state.authority.openHandles handleId = some handle →
      handle.object ≠ objectId := by
  exact wellFormed.zero_count_excludes_managed_authority_handle
    allowed.objectLookup allowed.noOpenHandles

/-- A rename excludes live managed Authority handles exactly in the moved subtree. -/
theorem mayRename_excludes_live_managed_authority_handles_in_subtree
    {state : IntegratedHandleState} (wellFormed : state.WellFormed)
    {pathMapping : NamespaceState.PathRenaming}
    (allowed : state.namespaceState.MayRename pathMapping) :
    ∀ objectId object,
      state.namespaceState.objects objectId = some object →
      NamespaceState.AtOrBelow object.path pathMapping.source →
      ∀ handleId handle,
        state.managedHandles handleId = true →
        state.authority.openHandles handleId = some handle →
        handle.object ≠ objectId := by
  intro objectId object objectLookup inMovedSubtree
  have closedCount := allowed.movedHandlesClosed objectId object
    objectLookup inMovedSubtree
  exact wellFormed.zero_count_excludes_managed_authority_handle
    objectLookup closedCount

/-- A live managed handle forces the corresponding namespace count to be positive. -/
theorem WellFormed.live_managed_handle_implies_positive_count
    {state : IntegratedHandleState} (wellFormed : state.WellFormed)
    {handleId : HandleId} {handle : OpenHandle}
    (managed : state.managedHandles handleId = true)
    (handleLookup : state.authority.openHandles handleId = some handle) :
    ∃ object,
      state.namespaceState.objects handle.object = some object ∧
      0 < object.openHandleCount := by
  rcases wellFormed.everyManagedHandleHasLiveObject handleId handle managed
      handleLookup with
    ⟨object, objectLookup⟩
  refine ⟨object, objectLookup, ?_⟩
  have accounted := wellFormed.live_managed_handle_is_accounted managed handleLookup
  have positiveCard : 0 < (state.accountedHandles handle.object).length :=
    List.length_pos_of_mem accounted
  simpa [wellFormed.namespaceCountsExact handle.object object objectLookup]
    using positiveCard

/-- Preconditions for one atomic Authority registration and namespace open. -/
structure MayOpen (state : IntegratedHandleState) (handle : OpenHandle) where
  subjectRunning : state.authority.subjectStatuses handle.subject = some .running
  handleFresh : state.authority.issuedHandleOwners handle.id = none
  object : NamespaceObject
  objectLookup : state.namespaceState.objects handle.object = some object
  countCanIncrement : CanIncrementU64 object.openHandleCount

/-- Atomically publish one handle in both components and the finite bridge. -/
def openHandle (state : IntegratedHandleState) (handle : OpenHandle)
    (object : NamespaceObject) : IntegratedHandleState where
  authority := state.authority.registerOpenHandle handle
  namespaceState := state.namespaceState.openObject handle.object object
  accountedHandles := replace state.accountedHandles handle.object
    (handle.id :: state.accountedHandles handle.object)
  managedHandles := replace state.managedHandles handle.id true
  repositoryHealth := state.repositoryHealth

/-- Opening the runtime root from a ready startup is an admitted atomic step. -/
def readyInitialMayOpen (issuer : IssuerId) (subject : SubjectId)
    (handleId : HandleId) :
    (readyInitial issuer subject).MayOpen (startupRootHandle subject handleId) := by
  refine {
    subjectRunning := ?_
    handleFresh := ?_
    object := NamespaceState.rootObject (NamespaceState.allocatedObjectId 0)
    objectLookup := ?_
    countCanIncrement := ?_
  }
  · simp [readyInitial, initial, initializeClosed, startupRootHandle,
      startupSubject, CapabilityState.registerSubject,
      CapabilityState.empty, replace]
  · rfl
  · simp [readyInitial, initial, initializeClosed, startupRootHandle,
      NamespaceState.runtimeInitial, NamespaceState.withRoot, replace]
  · simp [NamespaceState.rootObject, CanIncrementU64, u64Maximum]

/-- The first concrete reachable state with one exact root handle. -/
def openedInitial (issuer : IssuerId) (subject : SubjectId)
    (handleId : HandleId) : IntegratedHandleState :=
  (readyInitial issuer subject).openHandle
    (startupRootHandle subject handleId)
    (NamespaceState.rootObject (NamespaceState.allocatedObjectId 0))

/-- The opened witness still has one exact live-object manifest. -/
theorem openedInitial_manifestExact (issuer : IssuerId) (subject : SubjectId)
    (handleId : HandleId) :
    ManifestExact (openedInitial issuer subject handleId).namespaceState
      [NamespaceState.withOpenHandleCount
        (NamespaceState.rootObject (NamespaceState.allocatedObjectId 0)) 1] := by
  simpa [openedInitial, IntegratedHandleState.openHandle, readyInitial,
    initializeClosed, startupRootHandle] using runtimeInitialOpen_manifestExact

/-- Preconditions for one atomic Authority close and namespace count release. -/
structure MayClose (state : IntegratedHandleState) (caller : SubjectId)
    (handleId : HandleId) where
  handle : OpenHandle
  handleLookup : state.authority.openHandles handleId = some handle
  managed : state.managedHandles handleId = true
  owned : state.authority.MayCloseHandle caller handleId
  object : NamespaceObject
  objectLookup : state.namespaceState.objects handle.object = some object
  positiveCount : 0 < object.openHandleCount

/-- Atomically close one handle in both components and erase its bridge entry. -/
def closeHandle (state : IntegratedHandleState) (handleId : HandleId)
    (handle : OpenHandle) (object : NamespaceObject) : IntegratedHandleState where
  authority := state.authority.closeHandle handleId
  namespaceState := state.namespaceState.closeObject handle.object object
  accountedHandles := replace state.accountedHandles handle.object
    ((state.accountedHandles handle.object).erase handleId)
  managedHandles := state.managedHandles
  repositoryHealth := state.repositoryHealth

/-- Publish a closed namespace object without changing Authority handle state. -/
def createClosedObject (state : IntegratedHandleState)
    (object : NamespaceObject) : IntegratedHandleState where
  authority := state.authority
  namespaceState := state.namespaceState.create object
  accountedHandles := state.accountedHandles
  managedHandles := state.managedHandles
  repositoryHealth := state.repositoryHealth

/-- Integrated preconditions for publishing a namespace child closed. -/
structure MayCreateClosed (state : IntegratedHandleState)
    (object : NamespaceObject) where
  namespaceCreation : state.namespaceState.MayCreate object

/-- Preconditions for atomic namespace create plus Authority handle registration. -/
structure MayCreateOpen (state : IntegratedHandleState) (object : NamespaceObject)
    (handle : OpenHandle) where
  namespaceCreation : state.namespaceState.MayCreate object
  handleTargetsObject : handle.object = object.id
  subjectRunning : state.authority.subjectStatuses handle.subject = some .running
  handleFresh : state.authority.issuedHandleOwners handle.id = none

/-- Create one namespace child and its returned Authority handle atomically. -/
def createOpenHandle (state : IntegratedHandleState) (object : NamespaceObject)
    (handle : OpenHandle) : IntegratedHandleState :=
  (state.createClosedObject object).openHandle handle object

/-- Remove one closed object without changing Authority or handle ownership. -/
def removeObject (state : IntegratedHandleState) (objectId : ObjectId)
    (object : NamespaceObject) : IntegratedHandleState where
  authority := state.authority
  namespaceState := state.namespaceState.remove objectId object
  accountedHandles := state.accountedHandles
  managedHandles := state.managedHandles
  repositoryHealth := state.repositoryHealth

/-- Rename a closed subtree without changing Authority or handle ownership. -/
def renamePaths (state : IntegratedHandleState)
    (pathMapping : NamespaceState.PathRenaming) : IntegratedHandleState where
  authority := state.authority
  namespaceState := state.namespaceState.renamePaths pathMapping
  accountedHandles := state.accountedHandles
  managedHandles := state.managedHandles
  repositoryHealth := state.repositoryHealth

/-- Publish one hard-link name without changing Authority handle ownership. -/
def addHardLink (state : IntegratedHandleState) (objectId : ObjectId)
    (object : NamespaceObject) (alias : CanonicalPath) : IntegratedHandleState where
  authority := state.authority
  namespaceState := state.namespaceState.addHardLink objectId object alias
  accountedHandles := state.accountedHandles
  managedHandles := state.managedHandles
  repositoryHealth := state.repositoryHealth

/-- Unlink one name and publish the first surviving alias as representative. -/
def unlinkName (state : IntegratedHandleState) (objectId : ObjectId)
    (object : NamespaceObject) (alias newPrimary : CanonicalPath)
    (remaining : List CanonicalPath) : IntegratedHandleState where
  authority := state.authority
  namespaceState := state.namespaceState.unlinkName objectId object alias
    newPrimary remaining
  accountedHandles := state.accountedHandles
  managedHandles := state.managedHandles
  repositoryHealth := state.repositoryHealth

/-- Publish one closed symlink without changing Authority handle ownership. -/
def createSymlink (state : IntegratedHandleState)
    (object : NamespaceObject) : IntegratedHandleState where
  authority := state.authority
  namespaceState := state.namespaceState.createSymlink object
  accountedHandles := state.accountedHandles
  managedHandles := state.managedHandles
  repositoryHealth := state.repositoryHealth

/-- Replace only the Authority component. -/
def withAuthority (state : IntegratedHandleState)
    (authority : CapabilityState) : IntegratedHandleState where
  authority := authority
  namespaceState := state.namespaceState
  accountedHandles := state.accountedHandles
  managedHandles := state.managedHandles
  repositoryHealth := state.repositoryHealth

/-- Register then close a managed handle after the namespace-side open fails. -/
def failOpenAfterRegistration (state : IntegratedHandleState)
    (handle : OpenHandle) : IntegratedHandleState :=
  { state with
    authority := (state.authority.registerOpenHandle handle).closeHandle handle.id
    managedHandles := replace state.managedHandles handle.id true }

/-- Preconditions for a failed open that must still consume its handle identity. -/
structure MayFailOpenAfterRegistration (state : IntegratedHandleState)
    (handle : OpenHandle) where
  subjectRunning : state.authority.subjectStatuses handle.subject = some .running
  handleFresh : state.authority.issuedHandleOwners handle.id = none

/-- Authority-only steps may change foreign handles but not live managed records. -/
def PreservesManagedOpenHandles (state : IntegratedHandleState)
    (authority : CapabilityState) : Prop :=
  ∀ handleId,
    state.managedHandles handleId = true →
      authority.openHandles handleId = state.authority.openHandles handleId

/-- Typed integrated operations cover the complete modeled adapter boundary. -/
inductive Step : IntegratedHandleState → IntegratedHandleState → Prop
  | openAtomic {state : IntegratedHandleState} {handle : OpenHandle} :
      (allowed : MayOpen state handle) →
      Step state (state.openHandle handle allowed.object)
  | closeAtomic {state : IntegratedHandleState} {caller : SubjectId}
      {handleId : HandleId} :
      (allowed : MayClose state caller handleId) →
      Step state (state.closeHandle handleId allowed.handle allowed.object)
  | createOpenAtomic {state : IntegratedHandleState} {object : NamespaceObject}
      {handle : OpenHandle} :
      MayCreateOpen state object handle →
      Step state (state.createOpenHandle object handle)
  | createClosedAtomic {state : IntegratedHandleState} {object : NamespaceObject} :
      MayCreateClosed state object →
      Step state (state.createClosedObject object)
  | removeAtomic {state : IntegratedHandleState} {objectId : ObjectId} :
      (allowed : state.namespaceState.MayRemove objectId) →
      Step state (state.removeObject objectId allowed.object)
  | renameAtomic {state : IntegratedHandleState}
      {pathMapping : NamespaceState.PathRenaming} :
      (allowed : state.namespaceState.MayRename pathMapping) →
      Step state (state.renamePaths pathMapping)
  | hardLinkAtomic {state : IntegratedHandleState} {objectId : ObjectId}
      {alias : CanonicalPath} :
      (allowed : state.namespaceState.MayAddHardLink objectId alias) →
      Step state (state.addHardLink objectId allowed.object alias)
  | unlinkNameAtomic {state : IntegratedHandleState} {objectId : ObjectId}
      {alias : CanonicalPath} :
      (allowed : state.namespaceState.MayUnlinkName objectId alias) →
      Step state (state.unlinkName objectId allowed.object alias
        allowed.newPrimary allowed.remaining)
  | createSymlinkAtomic {state : IntegratedHandleState}
      {object : NamespaceObject} :
      (allowed : state.namespaceState.MayCreateSymlink object) →
      Step state (state.createSymlink object)
  | authorityOnly {state : IntegratedHandleState} {authority : CapabilityState} :
      (transition : CapabilityState.Step state.authority authority) →
      state.PreservesManagedOpenHandles authority →
      Step state (state.withAuthority authority)
  | failedOpenAfterRegistration {state : IntegratedHandleState}
      {handle : OpenHandle} :
      MayFailOpenAfterRegistration state handle →
      Step state (state.failOpenAfterRegistration handle)

/-- Legacy successful transitions preserve the repository admission state exactly. -/
theorem Step.preserves_repositoryHealth {before after : IntegratedHandleState}
    (transition : Step before after) :
    after.repositoryHealth = before.repositoryHealth := by
  cases transition <;> rfl

/-- An ordinary adapter step is a legacy successful step admitted while healthy. -/
structure OrdinaryStep (before after : IntegratedHandleState) : Prop where
  operational : before.repositoryHealth = .operational
  transition : Step before after

/-- Every admitted ordinary step remains operational. -/
theorem OrdinaryStep.after_operational {before after : IntegratedHandleState}
    (transition : OrdinaryStep before after) :
    after.repositoryHealth = .operational := by
  rw [transition.transition.preserves_repositoryHealth]
  exact transition.operational

/-- A globally fresh handle identity is absent from every bridge list. -/
theorem WellFormed.fresh_handle_not_accounted {state : IntegratedHandleState}
    (wellFormed : state.WellFormed) {handleId : HandleId}
    (fresh : state.authority.issuedHandleOwners handleId = none) :
    ∀ objectId, handleId ∉ state.accountedHandles objectId := by
  intro objectId accounted
  rcases (wellFormed.authorityHandlesExact objectId handleId).1 accounted with
    ⟨handle, handleLookup, _, _⟩
  have issued := wellFormed.liveHandleOwnerExact handleId handle handleLookup
  rw [fresh] at issued
  cases issued

/-- Atomic registration/open preserves exact cross-component agreement. -/
theorem openHandle_preserves_wellFormed {state : IntegratedHandleState}
    {handle : OpenHandle} (wellFormed : state.WellFormed)
    (allowed : state.MayOpen handle) :
    (state.openHandle handle allowed.object).WellFormed := by
  have freshEverywhere := wellFormed.fresh_handle_not_accounted allowed.handleFresh
  constructor
  · intro objectId
    by_cases sameObject : objectId = handle.object
    · subst objectId
      simp [IntegratedHandleState.openHandle]
      exact ⟨freshEverywhere handle.object, wellFormed.accountedHandlesNodup handle.object⟩
    · simpa [IntegratedHandleState.openHandle, replace, sameObject]
        using wellFormed.accountedHandlesNodup objectId
  · intro objectId handleId
    constructor
    · intro accounted
      by_cases sameObject : objectId = handle.object
      · subst objectId
        simp [IntegratedHandleState.openHandle] at accounted
        rcases accounted with sameHandle | oldAccounted
        · subst handleId
          exact ⟨handle, CapabilityState.registerOpenHandle_stores_exact_record
            state.authority handle, rfl, by simp [IntegratedHandleState.openHandle]⟩
        · rcases (wellFormed.authorityHandlesExact handle.object handleId).1
              oldAccounted with ⟨oldHandle, oldLookup, objectMatches, oldManaged⟩
          have differentHandle : handleId ≠ handle.id := by
            intro sameId
            subst handleId
            exact freshEverywhere handle.object oldAccounted
          exact ⟨oldHandle, by simpa [IntegratedHandleState.openHandle,
            CapabilityState.registerOpenHandle, replace, differentHandle] using oldLookup,
            objectMatches, by simpa [IntegratedHandleState.openHandle, replace,
              differentHandle] using oldManaged⟩
      · have oldAccounted : handleId ∈ state.accountedHandles objectId := by
          simpa [IntegratedHandleState.openHandle, replace, sameObject] using accounted
        rcases (wellFormed.authorityHandlesExact objectId handleId).1 oldAccounted with
          ⟨oldHandle, oldLookup, objectMatches, oldManaged⟩
        have differentHandle : handleId ≠ handle.id := by
          intro sameId
          subst handleId
          exact freshEverywhere objectId oldAccounted
        exact ⟨oldHandle, by simpa [IntegratedHandleState.openHandle,
          CapabilityState.registerOpenHandle, replace, differentHandle] using oldLookup,
          objectMatches, by simpa [IntegratedHandleState.openHandle, replace,
            differentHandle] using oldManaged⟩
    · rintro ⟨queriedHandle, handleLookup, objectMatches, managedAfter⟩
      by_cases sameHandle : handleId = handle.id
      · subst handleId
        have exactHandle : queriedHandle = handle := Option.some.inj
          (handleLookup.symm.trans
            (CapabilityState.registerOpenHandle_stores_exact_record state.authority handle))
        subst queriedHandle
        subst objectId
        simp [IntegratedHandleState.openHandle]
      · have oldLookup : state.authority.openHandles handleId = some queriedHandle := by
          simpa [IntegratedHandleState.openHandle, CapabilityState.registerOpenHandle,
            replace, sameHandle] using handleLookup
        have oldManaged : state.managedHandles handleId = true := by
          simpa [IntegratedHandleState.openHandle, replace, sameHandle] using managedAfter
        have oldAccounted := (wellFormed.authorityHandlesExact objectId handleId).2
          ⟨queriedHandle, oldLookup, objectMatches, oldManaged⟩
        by_cases sameObject : objectId = handle.object
        · subst objectId
          rw [sameObject] at oldAccounted
          change handleId ∈ replace state.accountedHandles handle.object
            (handle.id :: state.accountedHandles handle.object) queriedHandle.object
          rw [sameObject, replace_selected]
          exact List.mem_cons.mpr (Or.inr oldAccounted)
        · simpa [IntegratedHandleState.openHandle, replace, sameObject]
            using oldAccounted
  · intro objectId object objectLookup
    by_cases sameObject : objectId = handle.object
    · subst objectId
      have exactObject : object = NamespaceState.withOpenHandleCount allowed.object
          (allowed.object.openHandleCount + 1) := Option.some.inj
        (objectLookup.symm.trans (NamespaceState.openObject_increments_count
          state.namespaceState handle.object allowed.object))
      subst object
      simp [IntegratedHandleState.openHandle]
      rw [wellFormed.namespaceCountsExact handle.object allowed.object allowed.objectLookup]
      rfl
    · have oldLookup : state.namespaceState.objects objectId = some object := by
        simpa [IntegratedHandleState.openHandle, NamespaceState.openObject,
          NamespaceState.updateOpenHandleCount, replace, sameObject] using objectLookup
      simpa [IntegratedHandleState.openHandle, replace, sameObject] using
        wellFormed.namespaceCountsExact objectId object oldLookup
  · intro handleId queriedHandle managedAfter handleLookup
    by_cases sameHandle : handleId = handle.id
    · subst handleId
      have exactHandle : queriedHandle = handle := Option.some.inj
        (handleLookup.symm.trans
          (CapabilityState.registerOpenHandle_stores_exact_record state.authority handle))
      subst queriedHandle
      exact ⟨NamespaceState.withOpenHandleCount allowed.object
          (allowed.object.openHandleCount + 1),
        NamespaceState.openObject_increments_count state.namespaceState
          handle.object allowed.object⟩
    · have oldLookup : state.authority.openHandles handleId = some queriedHandle := by
        simpa [IntegratedHandleState.openHandle, CapabilityState.registerOpenHandle,
          replace, sameHandle] using handleLookup
      have oldManaged : state.managedHandles handleId = true := by
        simpa [IntegratedHandleState.openHandle, replace, sameHandle] using managedAfter
      rcases wellFormed.everyManagedHandleHasLiveObject handleId queriedHandle
          oldManaged oldLookup with
        ⟨oldObject, oldObjectLookup⟩
      by_cases sameObject : queriedHandle.object = handle.object
      · rw [sameObject] at oldObjectLookup ⊢
        have exactObject : oldObject = allowed.object := Option.some.inj
          (oldObjectLookup.symm.trans allowed.objectLookup)
        subst oldObject
        exact ⟨NamespaceState.withOpenHandleCount allowed.object
            (allowed.object.openHandleCount + 1),
          NamespaceState.openObject_increments_count state.namespaceState
            handle.object allowed.object⟩
      · exact ⟨oldObject, by simpa [IntegratedHandleState.openHandle,
          NamespaceState.openObject, NamespaceState.updateOpenHandleCount, replace,
          sameObject] using oldObjectLookup⟩
  · intro handleId queriedHandle handleLookup
    by_cases sameHandle : handleId = handle.id
    · subst handleId
      have exactHandle : queriedHandle = handle := Option.some.inj
        (handleLookup.symm.trans
          (CapabilityState.registerOpenHandle_stores_exact_record state.authority handle))
      subst queriedHandle
      exact CapabilityState.registerOpenHandle_reserves_identity state.authority handle
    · have oldLookup : state.authority.openHandles handleId = some queriedHandle := by
        simpa [IntegratedHandleState.openHandle, CapabilityState.registerOpenHandle,
          replace, sameHandle] using handleLookup
      have oldOwner := wellFormed.liveHandleOwnerExact handleId queriedHandle oldLookup
      simpa [IntegratedHandleState.openHandle, CapabilityState.registerOpenHandle,
        replace, sameHandle] using oldOwner
  · intro handleId managedAfter
    by_cases sameHandle : handleId = handle.id
    · subst handleId
      exact ⟨handle.subject,
        CapabilityState.registerOpenHandle_reserves_identity state.authority handle⟩
    · have oldManaged : state.managedHandles handleId = true := by
        simpa [IntegratedHandleState.openHandle, replace, sameHandle] using managedAfter
      rcases wellFormed.managedHandleReserved handleId oldManaged with ⟨owner, ownerLookup⟩
      exact ⟨owner, by simpa [IntegratedHandleState.openHandle,
        CapabilityState.registerOpenHandle, replace, sameHandle] using ownerLookup⟩
  · exact NamespaceState.openObject_preserves_treeWellFormed
      wellFormed.namespaceWellFormed allowed.objectLookup
  · exact (CapabilityState.Step.registerHandle allowed.subjectRunning
      allowed.handleFresh).preserves_countersRepresentable
      wellFormed.authorityCountersRepresentable
  · exact (NamespaceState.Step.openObject allowed.objectLookup
      allowed.countCanIncrement).preserves_countersRepresentable
      wellFormed.namespaceCountersRepresentable

/-- Atomic close/count-release preserves exact cross-component agreement. -/
theorem closeHandle_preserves_wellFormed {state : IntegratedHandleState}
    {caller : SubjectId} {handleId : HandleId} (wellFormed : state.WellFormed)
    (allowed : state.MayClose caller handleId) :
    (state.closeHandle handleId allowed.handle allowed.object).WellFormed := by
  have accounted : handleId ∈ state.accountedHandles allowed.handle.object :=
    wellFormed.live_managed_handle_is_accounted allowed.managed allowed.handleLookup
  have nodup := wellFormed.accountedHandlesNodup allowed.handle.object
  constructor
  · intro objectId
    by_cases sameObject : objectId = allowed.handle.object
    · subst objectId
      simpa [IntegratedHandleState.closeHandle] using nodup.erase handleId
    · simpa [IntegratedHandleState.closeHandle, replace, sameObject] using
        wellFormed.accountedHandlesNodup objectId
  · intro objectId queriedId
    constructor
    · intro remaining
      have oldAccounted : queriedId ∈ state.accountedHandles objectId := by
        by_cases sameObject : objectId = allowed.handle.object
        · subst objectId
          have erased : queriedId ∈
              (state.accountedHandles allowed.handle.object).erase handleId := by
            simpa [IntegratedHandleState.closeHandle] using remaining
          exact List.mem_of_mem_erase erased
        · simpa [IntegratedHandleState.closeHandle, replace, sameObject] using remaining
      rcases (wellFormed.authorityHandlesExact objectId queriedId).1 oldAccounted with
        ⟨queriedHandle, oldLookup, objectMatches, managed⟩
      have differentHandle : queriedId ≠ handleId := by
        intro sameId
        subst queriedId
        by_cases sameObject : objectId = allowed.handle.object
        · subst objectId
          rw [sameObject] at remaining
          have impossible : handleId ∉
              (state.accountedHandles allowed.handle.object).erase handleId :=
            nodup.not_mem_erase
          exact impossible (by simpa [IntegratedHandleState.closeHandle] using remaining)
        · have exactHandle : queriedHandle = allowed.handle := Option.some.inj
            (oldLookup.symm.trans allowed.handleLookup)
          subst queriedHandle
          exact sameObject objectMatches.symm
      exact ⟨queriedHandle, by simpa [IntegratedHandleState.closeHandle,
        CapabilityState.closeHandle, replace, differentHandle] using oldLookup,
        objectMatches, managed⟩
    · rintro ⟨queriedHandle, handleLookup, objectMatches, managed⟩
      have differentHandle : queriedId ≠ handleId := by
        intro sameId
        subst queriedId
        simp [IntegratedHandleState.closeHandle, CapabilityState.closeHandle] at handleLookup
      have oldLookup : state.authority.openHandles queriedId = some queriedHandle := by
        simpa [IntegratedHandleState.closeHandle, CapabilityState.closeHandle, replace,
          differentHandle] using handleLookup
      have oldAccounted := (wellFormed.authorityHandlesExact objectId queriedId).2
        ⟨queriedHandle, oldLookup, objectMatches, managed⟩
      by_cases sameObject : objectId = allowed.handle.object
      · subst objectId
        rw [sameObject] at oldAccounted ⊢
        change queriedId ∈ replace state.accountedHandles allowed.handle.object
          ((state.accountedHandles allowed.handle.object).erase handleId)
            allowed.handle.object
        rw [replace_selected]
        exact (List.mem_erase_of_ne differentHandle).2 oldAccounted
      · simpa [IntegratedHandleState.closeHandle, replace, sameObject]
          using oldAccounted
  · intro objectId object objectLookup
    by_cases sameObject : objectId = allowed.handle.object
    · subst objectId
      have exactObject : object = NamespaceState.withOpenHandleCount allowed.object
          (allowed.object.openHandleCount - 1) := Option.some.inj
        (objectLookup.symm.trans (NamespaceState.closeObject_decrements_count
          state.namespaceState allowed.handle.object allowed.object))
      subst object
      simp only [IntegratedHandleState.closeHandle, replace_selected]
      rw [List.length_erase_of_mem accounted,
        wellFormed.namespaceCountsExact allowed.handle.object allowed.object
          allowed.objectLookup]
      rfl
    · have oldLookup : state.namespaceState.objects objectId = some object := by
        simpa [IntegratedHandleState.closeHandle, NamespaceState.closeObject,
          NamespaceState.updateOpenHandleCount, replace, sameObject] using objectLookup
      simpa [IntegratedHandleState.closeHandle, replace, sameObject] using
        wellFormed.namespaceCountsExact objectId object oldLookup
  · intro queriedId queriedHandle managed handleLookup
    have differentHandle : queriedId ≠ handleId := by
      intro sameId
      subst queriedId
      simp [IntegratedHandleState.closeHandle, CapabilityState.closeHandle] at handleLookup
    have oldLookup : state.authority.openHandles queriedId = some queriedHandle := by
      simpa [IntegratedHandleState.closeHandle, CapabilityState.closeHandle, replace,
        differentHandle] using handleLookup
    rcases wellFormed.everyManagedHandleHasLiveObject queriedId queriedHandle
        managed oldLookup with
      ⟨oldObject, oldObjectLookup⟩
    by_cases sameObject : queriedHandle.object = allowed.handle.object
    · rw [sameObject] at oldObjectLookup ⊢
      have exactObject : oldObject = allowed.object := Option.some.inj
        (oldObjectLookup.symm.trans allowed.objectLookup)
      subst oldObject
      exact ⟨NamespaceState.withOpenHandleCount allowed.object
          (allowed.object.openHandleCount - 1),
        NamespaceState.closeObject_decrements_count state.namespaceState
          allowed.handle.object allowed.object⟩
    · exact ⟨oldObject, by simpa [IntegratedHandleState.closeHandle,
        NamespaceState.closeObject, NamespaceState.updateOpenHandleCount, replace,
        sameObject] using oldObjectLookup⟩
  · intro queriedId queriedHandle handleLookup
    have differentHandle : queriedId ≠ handleId := by
      intro sameId
      subst queriedId
      simp [IntegratedHandleState.closeHandle, CapabilityState.closeHandle] at handleLookup
    have oldLookup : state.authority.openHandles queriedId = some queriedHandle := by
      simpa [IntegratedHandleState.closeHandle, CapabilityState.closeHandle, replace,
        differentHandle] using handleLookup
    exact wellFormed.liveHandleOwnerExact queriedId queriedHandle oldLookup
  · exact wellFormed.managedHandleReserved
  · exact NamespaceState.closeObject_preserves_treeWellFormed
      wellFormed.namespaceWellFormed allowed.objectLookup
  · exact (CapabilityState.Step.closeHandle allowed.owned).preserves_countersRepresentable
      wellFormed.authorityCountersRepresentable
  · exact (NamespaceState.Step.closeObject allowed.objectLookup
      allowed.positiveCount).preserves_countersRepresentable
      wellFormed.namespaceCountersRepresentable

/-- Publishing a fresh closed object preserves the cross-component invariant. -/
theorem createClosedObject_preserves_wellFormed {state : IntegratedHandleState}
    {object : NamespaceObject} (wellFormed : state.WellFormed)
    (allowed : state.namespaceState.MayCreate object) :
    (state.createClosedObject object).WellFormed := by
  have newAccountingEmpty : state.accountedHandles object.id = [] := by
    apply List.eq_nil_iff_forall_not_mem.mpr
    intro handleId accounted
    rcases (wellFormed.authorityHandlesExact object.id handleId).1 accounted with
      ⟨handle, handleLookup, objectMatches, managed⟩
    rcases wellFormed.everyManagedHandleHasLiveObject handleId handle managed
        handleLookup with
      ⟨oldObject, oldObjectLookup⟩
    rw [objectMatches] at oldObjectLookup
    rw [allowed.objectAbsent] at oldObjectLookup
    cases oldObjectLookup
  constructor
  · exact wellFormed.accountedHandlesNodup
  · exact wellFormed.authorityHandlesExact
  · intro objectId queriedObject objectLookup
    by_cases sameObject : objectId = object.id
    · subst objectId
      have exactObject : queriedObject = object := Option.some.inj
        (objectLookup.symm.trans
          (NamespaceState.create_stores_object state.namespaceState object))
      subst queriedObject
      change (state.accountedHandles object.id).length = object.openHandleCount
      rw [newAccountingEmpty, allowed.startsClosed]
      rfl
    · have oldLookup : state.namespaceState.objects objectId = some queriedObject := by
        simpa [IntegratedHandleState.createClosedObject, NamespaceState.create,
          replace, sameObject] using objectLookup
      exact wellFormed.namespaceCountsExact objectId queriedObject oldLookup
  · intro handleId handle managed handleLookup
    rcases wellFormed.everyManagedHandleHasLiveObject handleId handle managed
        handleLookup with
      ⟨oldObject, oldObjectLookup⟩
    have differentObject : handle.object ≠ object.id := by
      intro sameObject
      rw [sameObject, allowed.objectAbsent] at oldObjectLookup
      cases oldObjectLookup
    exact ⟨oldObject, by simpa [IntegratedHandleState.createClosedObject,
      NamespaceState.create, replace, differentObject] using oldObjectLookup⟩
  · exact wellFormed.liveHandleOwnerExact
  · exact wellFormed.managedHandleReserved
  · exact NamespaceState.create_preserves_treeWellFormed
      wellFormed.namespaceWellFormed allowed
  · exact wellFormed.authorityCountersRepresentable
  · exact (NamespaceState.Step.create allowed).preserves_countersRepresentable
      wellFormed.namespaceCountersRepresentable

/-- Atomic create-open preserves Authority/namespace handle agreement. -/
theorem createOpenHandle_preserves_wellFormed {state : IntegratedHandleState}
    {object : NamespaceObject} {handle : OpenHandle}
    (wellFormed : state.WellFormed) (allowed : state.MayCreateOpen object handle) :
    (state.createOpenHandle object handle).WellFormed := by
  have createdWellFormed := createClosedObject_preserves_wellFormed wellFormed
    allowed.namespaceCreation
  let created := state.createClosedObject object
  let mayOpen : created.MayOpen handle := {
    subjectRunning := allowed.subjectRunning
    handleFresh := allowed.handleFresh
    object := object
    objectLookup := by
      rw [allowed.handleTargetsObject]
      exact NamespaceState.create_stores_object state.namespaceState object
    countCanIncrement := by
      rw [allowed.namespaceCreation.startsClosed]
      simp [CanIncrementU64, u64Maximum]
  }
  have opened := openHandle_preserves_wellFormed createdWellFormed mayOpen
  simpa [mayOpen, created, IntegratedHandleState.createOpenHandle] using opened

/-- Removing a closed object preserves managed-handle agreement. -/
theorem removeObject_preserves_wellFormed {state : IntegratedHandleState}
    {objectId : ObjectId} (wellFormed : state.WellFormed)
    (allowed : state.namespaceState.MayRemove objectId) :
    (state.removeObject objectId allowed.object).WellFormed := by
  constructor
  · exact wellFormed.accountedHandlesNodup
  · exact wellFormed.authorityHandlesExact
  · intro queriedId object objectLookup
    have differentId : queriedId ≠ objectId := by
      intro sameId
      subst queriedId
      simp [IntegratedHandleState.removeObject, NamespaceState.remove] at objectLookup
    have oldLookup : state.namespaceState.objects queriedId = some object := by
      simpa [IntegratedHandleState.removeObject, NamespaceState.remove, replace,
        differentId] using objectLookup
    exact wellFormed.namespaceCountsExact queriedId object oldLookup
  · intro handleId handle managed handleLookup
    rcases wellFormed.everyManagedHandleHasLiveObject handleId handle managed
        handleLookup with ⟨object, objectLookup⟩
    have differentObject : handle.object ≠ objectId :=
      mayRemove_excludes_live_managed_authority_handles wellFormed allowed
        handleId handle managed handleLookup
    exact ⟨object, by simpa [IntegratedHandleState.removeObject,
      NamespaceState.remove, replace, differentObject] using objectLookup⟩
  · exact wellFormed.liveHandleOwnerExact
  · exact wellFormed.managedHandleReserved
  · exact NamespaceState.remove_preserves_treeWellFormed
      wellFormed.namespaceWellFormed allowed
  · exact wellFormed.authorityCountersRepresentable
  · exact (NamespaceState.Step.remove allowed).preserves_countersRepresentable
      wellFormed.namespaceCountersRepresentable

/-- Renaming a closed subtree preserves managed-handle agreement. -/
theorem renamePaths_preserves_wellFormed {state : IntegratedHandleState}
    {pathMapping : NamespaceState.PathRenaming} (wellFormed : state.WellFormed)
    (allowed : state.namespaceState.MayRename pathMapping) :
    (state.renamePaths pathMapping).WellFormed := by
  constructor
  · exact wellFormed.accountedHandlesNodup
  · exact wellFormed.authorityHandlesExact
  · intro objectId renamedObject renamedLookup
    simp only [IntegratedHandleState.renamePaths,
      NamespaceState.renamePaths] at renamedLookup
    cases oldLookup : state.namespaceState.objects objectId with
    | none => simp [oldLookup] at renamedLookup
    | some oldObject =>
        simp [oldLookup] at renamedLookup
        subst renamedObject
        exact wellFormed.namespaceCountsExact objectId oldObject oldLookup
  · intro handleId handle managed handleLookup
    rcases wellFormed.everyManagedHandleHasLiveObject handleId handle managed
        handleLookup with ⟨object, objectLookup⟩
    exact ⟨{ object with path := pathMapping.forward object.path },
      NamespaceState.rename_preserves_object_fields objectLookup⟩
  · exact wellFormed.liveHandleOwnerExact
  · exact wellFormed.managedHandleReserved
  · exact NamespaceState.rename_preserves_treeWellFormed
      wellFormed.namespaceWellFormed pathMapping allowed
  · exact wellFormed.authorityCountersRepresentable
  · exact (NamespaceState.Step.renamePaths allowed).preserves_countersRepresentable
      wellFormed.namespaceCountersRepresentable

/-- Publishing one hard-link name preserves Authority/namespace handle agreement. -/
theorem addHardLink_preserves_wellFormed {state : IntegratedHandleState}
    {objectId : ObjectId} {alias : CanonicalPath} (wellFormed : state.WellFormed)
    (allowed : state.namespaceState.MayAddHardLink objectId alias) :
    (state.addHardLink objectId allowed.object alias).WellFormed := by
  constructor
  · exact wellFormed.accountedHandlesNodup
  · exact wellFormed.authorityHandlesExact
  · intro queriedId queriedObject queriedLookup
    by_cases target : queriedId = objectId
    · subst queriedId
      have exactObject : queriedObject =
          NamespaceState.withAddedAlias allowed.object alias := Option.some.inj
        (queriedLookup.symm.trans (NamespaceState.addHardLink_stores_object
          state.namespaceState objectId allowed.object alias))
      subst queriedObject
      rw [NamespaceState.withAddedAlias_openHandleCount]
      exact
        wellFormed.namespaceCountsExact objectId allowed.object allowed.objectLookup
    · exact wellFormed.namespaceCountsExact queriedId queriedObject
        (by simpa [IntegratedHandleState.addHardLink,
          NamespaceState.addHardLink, replace, target] using queriedLookup)
  · intro handleId handle managed handleLookup
    rcases wellFormed.everyManagedHandleHasLiveObject handleId handle managed
      handleLookup with ⟨object, objectLookup⟩
    by_cases target : handle.object = objectId
    · subst objectId
      have exactObject : object = allowed.object := Option.some.inj
        (objectLookup.symm.trans allowed.objectLookup)
      subst object
      exact ⟨NamespaceState.withAddedAlias allowed.object alias,
        NamespaceState.addHardLink_stores_object state.namespaceState handle.object
          allowed.object alias⟩
    · exact ⟨object, by simpa [IntegratedHandleState.addHardLink,
        NamespaceState.addHardLink, replace, target] using objectLookup⟩
  · exact wellFormed.liveHandleOwnerExact
  · exact wellFormed.managedHandleReserved
  · exact (NamespaceState.addHardLink_preserves_completeWellFormed allowed).tree
  · exact wellFormed.authorityCountersRepresentable
  · exact (NamespaceState.Step.addHardLink allowed).preserves_countersRepresentable
      wellFormed.namespaceCountersRepresentable

/-- Unlinking one of several names preserves Authority/namespace handle agreement. -/
theorem unlinkName_preserves_wellFormed {state : IntegratedHandleState}
    {objectId : ObjectId} {alias : CanonicalPath} (wellFormed : state.WellFormed)
    (allowed : state.namespaceState.MayUnlinkName objectId alias) :
    (state.unlinkName objectId allowed.object alias allowed.newPrimary
      allowed.remaining).WellFormed := by
  constructor
  · exact wellFormed.accountedHandlesNodup
  · exact wellFormed.authorityHandlesExact
  · intro queriedId queriedObject queriedLookup
    by_cases target : queriedId = objectId
    · subst queriedId
      have exactObject : queriedObject = NamespaceState.withRemainingAliases
          allowed.object allowed.newPrimary allowed.remaining := Option.some.inj
        (queriedLookup.symm.trans (NamespaceState.unlinkName_stores_object
          state.namespaceState objectId allowed.object alias allowed.newPrimary
          allowed.remaining))
      subst queriedObject
      simpa [IntegratedHandleState.unlinkName,
        NamespaceState.withRemainingAliases] using
        wellFormed.namespaceCountsExact objectId allowed.object allowed.objectLookup
    · exact wellFormed.namespaceCountsExact queriedId queriedObject
        (by simpa [IntegratedHandleState.unlinkName, NamespaceState.unlinkName,
          replace, target] using queriedLookup)
  · intro handleId handle managed handleLookup
    rcases wellFormed.everyManagedHandleHasLiveObject handleId handle managed
      handleLookup with ⟨object, objectLookup⟩
    by_cases target : handle.object = objectId
    · subst objectId
      have exactObject : object = allowed.object := Option.some.inj
        (objectLookup.symm.trans allowed.objectLookup)
      subst object
      exact ⟨NamespaceState.withRemainingAliases allowed.object allowed.newPrimary
          allowed.remaining,
        NamespaceState.unlinkName_stores_object state.namespaceState handle.object
          allowed.object alias allowed.newPrimary allowed.remaining⟩
    · exact ⟨object, by simpa [IntegratedHandleState.unlinkName,
        NamespaceState.unlinkName, replace, target] using objectLookup⟩
  · exact wellFormed.liveHandleOwnerExact
  · exact wellFormed.managedHandleReserved
  · exact (NamespaceState.unlinkName_preserves_completeWellFormed allowed).tree
  · exact wellFormed.authorityCountersRepresentable
  · exact (NamespaceState.Step.unlinkName allowed).preserves_countersRepresentable
      wellFormed.namespaceCountersRepresentable

/-- Publishing a checked closed symlink preserves the integrated invariant. -/
theorem createSymlink_preserves_wellFormed {state : IntegratedHandleState}
    {object : NamespaceObject} (wellFormed : state.WellFormed)
    (allowed : state.namespaceState.MayCreateSymlink object) :
    (state.createSymlink object).WellFormed := by
  simpa [IntegratedHandleState.createSymlink,
    IntegratedHandleState.createClosedObject, NamespaceState.createSymlink] using
    createClosedObject_preserves_wellFormed wellFormed allowed.creation

/-- Authority transitions preserve exact ownership for every handle left live. -/
theorem capabilityStep_preserves_liveHandleOwnerExact
    {before after : CapabilityState} (transition : CapabilityState.Step before after)
    (ownerExact : ∀ handleId handle,
      before.openHandles handleId = some handle →
        before.issuedHandleOwners handleId = some handle.subject) :
    ∀ handleId handle,
      after.openHandles handleId = some handle →
        after.issuedHandleOwners handleId = some handle.subject := by
  cases transition with
  | registerHandle _running fresh =>
      rename_i registeredHandle
      intro handleId handle handleLookup
      by_cases sameId : handleId = registeredHandle.id
      · subst handleId
        have exactHandle : handle = registeredHandle := Option.some.inj
          (handleLookup.symm.trans
            (CapabilityState.registerOpenHandle_stores_exact_record before
              registeredHandle))
        subst handle
        exact CapabilityState.registerOpenHandle_reserves_identity before
          registeredHandle
      · have oldLookup : before.openHandles handleId = some handle := by
          simpa [CapabilityState.registerOpenHandle, replace, sameId] using handleLookup
        have oldOwner := ownerExact handleId handle oldLookup
        simpa [CapabilityState.registerOpenHandle, replace, sameId] using oldOwner
  | closeHandle _owned =>
      rename_i caller closedId
      intro handleId handle handleLookup
      have differentId : handleId ≠ closedId := by
        intro sameId
        subst handleId
        simp [CapabilityState.closeHandle] at handleLookup
      have oldLookup : before.openHandles handleId = some handle := by
        simpa [CapabilityState.closeHandle, replace, differentId] using handleLookup
      exact ownerExact handleId handle oldLookup
  | registerSubject | issueRoot | issueAllocatedRoot | derive | allocatorExhausted | revoke |
      beginClose | finishClose | successfulNoop =>
      exact ownerExact

/-- An Authority-only step preserving managed live records preserves the bridge. -/
theorem authorityOnly_preserves_wellFormed {state : IntegratedHandleState}
    {authority : CapabilityState} (wellFormed : state.WellFormed)
    (transition : CapabilityState.Step state.authority authority)
    (preservesManaged : state.PreservesManagedOpenHandles authority) :
    (state.withAuthority authority).WellFormed := by
  constructor
  · exact wellFormed.accountedHandlesNodup
  · intro objectId handleId
    constructor
    · intro accounted
      rcases (wellFormed.authorityHandlesExact objectId handleId).1 accounted with
        ⟨handle, oldLookup, objectMatches, managed⟩
      exact ⟨handle, by simpa [IntegratedHandleState.withAuthority,
        preservesManaged handleId managed] using oldLookup, objectMatches, managed⟩
    · rintro ⟨handle, handleLookup, objectMatches, managed⟩
      have oldLookup : state.authority.openHandles handleId = some handle := by
        simpa [IntegratedHandleState.withAuthority,
          preservesManaged handleId managed] using handleLookup
      exact (wellFormed.authorityHandlesExact objectId handleId).2
        ⟨handle, oldLookup, objectMatches, managed⟩
  · exact wellFormed.namespaceCountsExact
  · intro handleId handle managed handleLookup
    have oldLookup : state.authority.openHandles handleId = some handle := by
      simpa [IntegratedHandleState.withAuthority,
        preservesManaged handleId managed] using handleLookup
    exact wellFormed.everyManagedHandleHasLiveObject handleId handle managed oldLookup
  · exact capabilityStep_preserves_liveHandleOwnerExact transition
      wellFormed.liveHandleOwnerExact
  · intro handleId managed
    rcases wellFormed.managedHandleReserved handleId managed with ⟨owner, ownerLookup⟩
    exact ⟨owner, transition.handle_identity_persists ownerLookup⟩
  · exact wellFormed.namespaceWellFormed
  · exact transition.preserves_countersRepresentable
      wellFormed.authorityCountersRepresentable
  · exact wellFormed.namespaceCountersRepresentable

/-- A foreign Authority registration changes no managed live-handle record. -/
theorem authorityRegisterForeign_isStep {state : IntegratedHandleState}
    {handle : OpenHandle} (wellFormed : state.WellFormed)
    (running : state.authority.subjectStatuses handle.subject = some .running)
    (fresh : state.authority.issuedHandleOwners handle.id = none) :
    Step state
      (state.withAuthority (state.authority.registerOpenHandle handle)) := by
  apply Step.authorityOnly (CapabilityState.Step.registerHandle running fresh)
  intro handleId managed
  have differentId : handleId ≠ handle.id := by
    intro sameId
    subst handleId
    rcases wellFormed.managedHandleReserved handle.id managed with ⟨owner, ownerLookup⟩
    rw [fresh] at ownerLookup
    cases ownerLookup
  simp [CapabilityState.registerOpenHandle, replace, differentId]

/-- Foreign Authority handles are live but remain outside namespace accounting. -/
theorem authorityRegisterForeign_is_scoped {state : IntegratedHandleState}
    {handle : OpenHandle} (wellFormed : state.WellFormed)
    (running : state.authority.subjectStatuses handle.subject = some .running)
    (fresh : state.authority.issuedHandleOwners handle.id = none) :
    let after := state.withAuthority (state.authority.registerOpenHandle handle)
    Step state after ∧
      after.authority.openHandles handle.id = some handle ∧
      after.managedHandles handle.id = false ∧
      ∀ objectId, after.accountedHandles objectId = state.accountedHandles objectId := by
  have unmanaged : state.managedHandles handle.id = false := by
    cases managedLookup : state.managedHandles handle.id with
    | false => rfl
    | true =>
        rcases wellFormed.managedHandleReserved handle.id managedLookup with
          ⟨owner, ownerLookup⟩
        rw [fresh] at ownerLookup
        cases ownerLookup
  exact ⟨authorityRegisterForeign_isStep wellFormed running fresh,
    CapabilityState.registerOpenHandle_stores_exact_record state.authority handle,
    unmanaged, fun _ => rfl⟩

/-- Freshness in the permanent owner table implies absence from the live map. -/
theorem WellFormed.fresh_handle_not_open {state : IntegratedHandleState}
    (wellFormed : state.WellFormed) {handleId : HandleId}
    (fresh : state.authority.issuedHandleOwners handleId = none) :
    state.authority.openHandles handleId = none := by
  cases lookup : state.authority.openHandles handleId with
  | none => rfl
  | some handle =>
      have owner := wellFormed.liveHandleOwnerExact handleId handle lookup
      rw [fresh] at owner
      cases owner

/-- Failed registration cleanup restores the old live-handle map exactly. -/
theorem failOpenAfterRegistration_openHandles {state : IntegratedHandleState}
    {handle : OpenHandle} (wellFormed : state.WellFormed)
    (allowed : state.MayFailOpenAfterRegistration handle) :
    (state.failOpenAfterRegistration handle).authority.openHandles =
      state.authority.openHandles := by
  funext queriedId
  by_cases sameId : queriedId = handle.id
  · subst queriedId
    simp [IntegratedHandleState.failOpenAfterRegistration,
      CapabilityState.closeHandle, wellFormed.fresh_handle_not_open allowed.handleFresh]
  · simp [IntegratedHandleState.failOpenAfterRegistration,
      CapabilityState.closeHandle, CapabilityState.registerOpenHandle,
      replace, sameId]

/-- Failed opens preserve the bridge while consuming a permanent managed tombstone. -/
theorem failOpenAfterRegistration_preserves_wellFormed
    {state : IntegratedHandleState} {handle : OpenHandle}
    (wellFormed : state.WellFormed)
    (allowed : state.MayFailOpenAfterRegistration handle) :
    (state.failOpenAfterRegistration handle).WellFormed := by
  have freshEverywhere := wellFormed.fresh_handle_not_accounted allowed.handleFresh
  have liveMapExact := failOpenAfterRegistration_openHandles wellFormed allowed
  constructor
  · exact wellFormed.accountedHandlesNodup
  · intro objectId handleId
    constructor
    · intro accounted
      rcases (wellFormed.authorityHandlesExact objectId handleId).1 accounted with
        ⟨oldHandle, oldLookup, objectMatches, oldManaged⟩
      have differentId : handleId ≠ handle.id := by
        intro sameId
        subst handleId
        exact freshEverywhere objectId accounted
      exact ⟨oldHandle, by simpa [liveMapExact] using oldLookup,
        objectMatches, by simpa [IntegratedHandleState.failOpenAfterRegistration,
          replace, differentId] using oldManaged⟩
    · rintro ⟨queriedHandle, handleLookup, objectMatches, managedAfter⟩
      have differentId : handleId ≠ handle.id := by
        intro sameId
        subst handleId
        simp [IntegratedHandleState.failOpenAfterRegistration,
          CapabilityState.closeHandle] at handleLookup
      have oldLookup : state.authority.openHandles handleId = some queriedHandle := by
        simpa [liveMapExact] using handleLookup
      have oldManaged : state.managedHandles handleId = true := by
        simpa [IntegratedHandleState.failOpenAfterRegistration, replace,
          differentId] using managedAfter
      exact (wellFormed.authorityHandlesExact objectId handleId).2
        ⟨queriedHandle, oldLookup, objectMatches, oldManaged⟩
  · exact wellFormed.namespaceCountsExact
  · intro handleId queriedHandle managedAfter handleLookup
    have differentId : handleId ≠ handle.id := by
      intro sameId
      subst handleId
      simp [IntegratedHandleState.failOpenAfterRegistration,
        CapabilityState.closeHandle] at handleLookup
    have oldLookup : state.authority.openHandles handleId = some queriedHandle := by
      simpa [liveMapExact] using handleLookup
    have oldManaged : state.managedHandles handleId = true := by
      simpa [IntegratedHandleState.failOpenAfterRegistration, replace,
        differentId] using managedAfter
    exact wellFormed.everyManagedHandleHasLiveObject handleId queriedHandle
      oldManaged oldLookup
  · intro handleId queriedHandle handleLookup
    have differentId : handleId ≠ handle.id := by
      intro sameId
      subst handleId
      simp [IntegratedHandleState.failOpenAfterRegistration,
        CapabilityState.closeHandle] at handleLookup
    have oldLookup : state.authority.openHandles handleId = some queriedHandle := by
      simpa [liveMapExact] using handleLookup
    have oldOwner := wellFormed.liveHandleOwnerExact handleId queriedHandle oldLookup
    simpa [IntegratedHandleState.failOpenAfterRegistration,
      CapabilityState.closeHandle, CapabilityState.registerOpenHandle,
      replace, differentId] using oldOwner
  · intro handleId managedAfter
    by_cases sameId : handleId = handle.id
    · subst handleId
      exact ⟨handle.subject, by simp [IntegratedHandleState.failOpenAfterRegistration,
        CapabilityState.closeHandle, CapabilityState.registerOpenHandle]⟩
    · have oldManaged : state.managedHandles handleId = true := by
        simpa [IntegratedHandleState.failOpenAfterRegistration, replace,
          sameId] using managedAfter
      rcases wellFormed.managedHandleReserved handleId oldManaged with
        ⟨owner, ownerLookup⟩
      exact ⟨owner, by simpa [IntegratedHandleState.failOpenAfterRegistration,
        CapabilityState.closeHandle, CapabilityState.registerOpenHandle,
        replace, sameId] using ownerLookup⟩
  · exact wellFormed.namespaceWellFormed
  · simpa [CapabilityState.CountersRepresentable,
      IntegratedHandleState.failOpenAfterRegistration,
      CapabilityState.closeHandle, CapabilityState.registerOpenHandle] using
      wellFormed.authorityCountersRepresentable
  · exact wellFormed.namespaceCountersRepresentable

/-- A failed open leaves no live record but permanently reserves the handle. -/
theorem failOpenAfterRegistration_consumes_tombstone
    (state : IntegratedHandleState) (handle : OpenHandle) :
    (state.failOpenAfterRegistration handle).authority.openHandles handle.id = none ∧
      (state.failOpenAfterRegistration handle).authority.issuedHandleOwners handle.id =
        some handle.subject ∧
      (state.failOpenAfterRegistration handle).managedHandles handle.id = true := by
  simp [IntegratedHandleState.failOpenAfterRegistration,
    CapabilityState.closeHandle, CapabilityState.registerOpenHandle]

/-- Every typed integrated handle transition preserves the bridge invariant. -/
theorem Step.preserves_wellFormed {before after : IntegratedHandleState}
    (transition : Step before after) (wellFormed : before.WellFormed) :
    after.WellFormed := by
  cases transition with
  | openAtomic allowed => exact openHandle_preserves_wellFormed wellFormed allowed
  | closeAtomic allowed => exact closeHandle_preserves_wellFormed wellFormed allowed
  | createOpenAtomic allowed =>
      exact createOpenHandle_preserves_wellFormed wellFormed allowed
  | createClosedAtomic allowed =>
      exact createClosedObject_preserves_wellFormed wellFormed
        allowed.namespaceCreation
  | removeAtomic allowed =>
      exact removeObject_preserves_wellFormed wellFormed allowed
  | renameAtomic allowed =>
      exact renamePaths_preserves_wellFormed wellFormed allowed
  | hardLinkAtomic allowed =>
      exact addHardLink_preserves_wellFormed wellFormed allowed
  | unlinkNameAtomic allowed =>
      exact unlinkName_preserves_wellFormed wellFormed allowed
  | createSymlinkAtomic allowed =>
      exact createSymlink_preserves_wellFormed wellFormed allowed
  | authorityOnly authorityStep preservesManaged =>
      exact authorityOnly_preserves_wellFormed wellFormed authorityStep
        preservesManaged
  | failedOpenAfterRegistration allowed =>
      exact failOpenAfterRegistration_preserves_wellFormed wellFormed allowed

/-- The full Rust adapter invariant combines handle accounting with exact aliases. -/
structure CompleteWellFormed (state : IntegratedHandleState) : Prop where
  bridge : state.WellFormed
  namespaceComplete : state.namespaceState.CompleteWellFormed

/-- Concrete startup establishes the full integrated invariant. -/
theorem initial_completeWellFormed (issuer : IssuerId) :
    (initial issuer).CompleteWellFormed :=
  ⟨initial_wellFormed issuer, initial_namespaceComplete issuer⟩

/-- Exact integrated steps are the operations whose shape proof is carried or preserved. -/
inductive CompleteStep : IntegratedHandleState → IntegratedHandleState → Prop
  | openAtomic {state : IntegratedHandleState} {handle : OpenHandle} :
      (complete : state.CompleteWellFormed) →
      (allowed : MayOpen state handle) →
      CompleteStep state (state.openHandle handle allowed.object)
  | closeAtomic {state : IntegratedHandleState} {caller : SubjectId}
      {handleId : HandleId} :
      (complete : state.CompleteWellFormed) →
      (allowed : MayClose state caller handleId) →
      CompleteStep state (state.closeHandle handleId allowed.handle allowed.object)
  | hardLinkAtomic {state : IntegratedHandleState} {objectId : ObjectId}
      {alias : CanonicalPath} :
      (complete : state.CompleteWellFormed) →
      (allowed : state.namespaceState.MayAddHardLink objectId alias) →
      CompleteStep state (state.addHardLink objectId allowed.object alias)
  | unlinkNameAtomic {state : IntegratedHandleState} {objectId : ObjectId}
      {alias : CanonicalPath} :
      (complete : state.CompleteWellFormed) →
      (allowed : state.namespaceState.MayUnlinkName objectId alias) →
      CompleteStep state (state.unlinkName objectId allowed.object alias
        allowed.newPrimary allowed.remaining)
  | createSymlinkAtomic {state : IntegratedHandleState}
      {object : NamespaceObject} :
      (complete : state.CompleteWellFormed) →
      (allowed : state.namespaceState.MayCreateSymlink object) →
      CompleteStep state (state.createSymlink object)
  | authorityOnly {state : IntegratedHandleState} {authority : CapabilityState} :
      (complete : state.CompleteWellFormed) →
      (transition : CapabilityState.Step state.authority authority) →
      state.PreservesManagedOpenHandles authority →
      CompleteStep state (state.withAuthority authority)
  | failedOpenAfterRegistration {state : IntegratedHandleState}
      {handle : OpenHandle} :
      (complete : state.CompleteWellFormed) →
      MayFailOpenAfterRegistration state handle →
      CompleteStep state (state.failOpenAfterRegistration handle)

/-- Every exact step is an existing integrated adapter step. -/
theorem CompleteStep.toStep {before after : IntegratedHandleState}
    (transition : CompleteStep before after) : Step before after := by
  cases transition with
  | openAtomic _ allowed => exact .openAtomic allowed
  | closeAtomic _ allowed => exact .closeAtomic allowed
  | hardLinkAtomic _ allowed => exact .hardLinkAtomic allowed
  | unlinkNameAtomic _ allowed => exact .unlinkNameAtomic allowed
  | createSymlinkAtomic _ allowed => exact .createSymlinkAtomic allowed
  | authorityOnly _ authorityStep preservesManaged =>
      exact .authorityOnly authorityStep preservesManaged
  | failedOpenAfterRegistration _ allowed =>
      exact .failedOpenAfterRegistration allowed

/-- Every exact integrated step preserves handle accounting and namespace shape. -/
theorem CompleteStep.preserves_completeWellFormed
    {before after : IntegratedHandleState}
    (transition : CompleteStep before after) : after.CompleteWellFormed := by
  cases transition with
  | openAtomic complete allowed =>
      exact ⟨openHandle_preserves_wellFormed complete.bridge allowed,
        NamespaceState.openObject_preserves_completeWellFormed complete.namespaceComplete
          allowed.objectLookup⟩
  | closeAtomic complete allowed =>
      exact ⟨closeHandle_preserves_wellFormed complete.bridge allowed,
        NamespaceState.closeObject_preserves_completeWellFormed complete.namespaceComplete
          allowed.objectLookup⟩
  | hardLinkAtomic complete allowed =>
      exact ⟨addHardLink_preserves_wellFormed complete.bridge allowed,
        NamespaceState.addHardLink_preserves_completeWellFormed allowed⟩
  | unlinkNameAtomic complete allowed =>
      exact ⟨unlinkName_preserves_wellFormed complete.bridge allowed,
        NamespaceState.unlinkName_preserves_completeWellFormed allowed⟩
  | createSymlinkAtomic complete allowed =>
      exact ⟨createSymlink_preserves_wellFormed complete.bridge allowed,
        NamespaceState.createSymlink_preserves_completeWellFormed allowed⟩
  | authorityOnly complete authorityStep preservesManaged =>
      exact ⟨authorityOnly_preserves_wellFormed complete.bridge authorityStep
          preservesManaged,
        complete.namespaceComplete⟩
  | failedOpenAfterRegistration complete allowed =>
      exact ⟨failOpenAfterRegistration_preserves_wellFormed complete.bridge allowed,
        complete.namespaceComplete⟩

/-- Arbitrary finite exact adapter executions, including non-reflexive traces. -/
inductive CompleteSteps : IntegratedHandleState → IntegratedHandleState → Prop
  | refl (state : IntegratedHandleState) : CompleteSteps state state
  | tail {first middle last : IntegratedHandleState} :
      CompleteSteps first middle → CompleteStep middle last →
      CompleteSteps first last

/-- Full integrated invariants survive every finite exact adapter execution. -/
theorem CompleteSteps.preserves_completeWellFormed
    {before after : IntegratedHandleState}
    (transitions : CompleteSteps before after)
    (complete : before.CompleteWellFormed) : after.CompleteWellFormed := by
  induction transitions with
  | refl => exact complete
  | tail _ transition _ => exact transition.preserves_completeWellFormed

/-- Finite executions consist solely of atomic bridge-preserving operations. -/
inductive Steps : IntegratedHandleState → IntegratedHandleState → Prop
  | refl (state : IntegratedHandleState) : Steps state state
  | tail {first middle last : IntegratedHandleState} :
      Steps first middle → Step middle last → Steps first last

/-- Exact executions embed in the legacy transition closure. -/
theorem CompleteSteps.toSteps {before after : IntegratedHandleState}
    (transitions : CompleteSteps before after) : Steps before after := by
  induction transitions with
  | refl => exact .refl _
  | tail _ transition inductionHypothesis =>
      exact .tail inductionHypothesis transition.toStep

/-- Finite legacy executions preserve repository health exactly. -/
theorem Steps.preserve_repositoryHealth {before after : IntegratedHandleState}
    (transitions : Steps before after) :
    after.repositoryHealth = before.repositoryHealth := by
  induction transitions with
  | refl => rfl
  | tail _ transition inductionHypothesis =>
      exact transition.preserves_repositoryHealth.trans inductionHypothesis

/-- Exact bridge agreement survives every finite integrated execution. -/
theorem Steps.preserves_wellFormed {before after : IntegratedHandleState}
    (transitions : Steps before after) (wellFormed : before.WellFormed) :
    after.WellFormed := by
  induction transitions with
  | refl => exact wellFormed
  | tail _ transition inductionHypothesis =>
      exact transition.preserves_wellFormed inductionHypothesis

/-- Arbitrary integrated executions preserve both Rust machine-counter bounds. -/
theorem Steps.preserves_countersRepresentable
    {before after : IntegratedHandleState}
    (transitions : Steps before after) (wellFormed : before.WellFormed) :
    after.authority.CountersRepresentable ∧
      after.namespaceState.CountersRepresentable := by
  have afterWellFormed := transitions.preserves_wellFormed wellFormed
  exact ⟨afterWellFormed.authorityCountersRepresentable,
    afterWellFormed.namespaceCountersRepresentable⟩

/-- Concatenation makes arbitrary suffix executions available to reachability. -/
theorem Steps.trans {first middle last : IntegratedHandleState}
    (earlier : Steps first middle) (later : Steps middle last) :
    Steps first last := by
  induction later with
  | refl => exact earlier
  | tail _ transition inductionHypothesis =>
      exact Steps.tail inductionHypothesis transition

/-- Reachable states start from a concrete manifest-backed initialization. -/
def Reachable (state : IntegratedHandleState) : Prop :=
  ∃ initialState, initialState.Initial ∧ Steps initialState state

/-- Every state reachable from concrete runtime initialization is well formed. -/
theorem Reachable.wellFormed {state : IntegratedHandleState}
    (reachable : state.Reachable) : state.WellFormed := by
  rcases reachable with ⟨initialState, initialStateIsInitial, transitions⟩
  exact transitions.preserves_wellFormed initialStateIsInitial.wellFormed

/-- Reachable states export both Authority and namespace machine bounds. -/
theorem Reachable.countersRepresentable {state : IntegratedHandleState}
    (reachable : state.Reachable) :
    state.authority.CountersRepresentable ∧
      state.namespaceState.CountersRepresentable :=
  ⟨reachable.wellFormed.authorityCountersRepresentable,
    reachable.wellFormed.namespaceCountersRepresentable⟩

/-- Any finite suffix of integrated steps preserves ordinary reachability. -/
theorem Reachable.steps {before after : IntegratedHandleState}
    (reachable : before.Reachable) (transitions : Steps before after) :
    after.Reachable := by
  rcases reachable with ⟨initialState, initialStateIsInitial, earlier⟩
  exact ⟨initialState, initialStateIsInitial, earlier.trans transitions⟩

/-- The concrete runtime startup is itself reachable. -/
theorem initial_reachable (issuer : IssuerId) : (initial issuer).Reachable :=
  ⟨initial issuer, initial_isInitial issuer, Steps.refl (initial issuer)⟩

/-- The ready state is reached by registering the complete concrete Subject record. -/
def initialRegisterSubjectStep (issuer : IssuerId) (subject : SubjectId) :
    Step (initial issuer) (readyInitial issuer subject) := by
  apply Step.authorityOnly
    (CapabilityState.Step.registerSubject (initialMayRegisterSubject issuer subject))
  · intro handleId managed
    simp [initial, initializeClosed] at managed

/-- Subject registration is also an exact alias-preserving integrated step. -/
def initialRegisterSubjectCompleteStep (issuer : IssuerId) (subject : SubjectId) :
    CompleteStep (initial issuer) (readyInitial issuer subject) := by
  apply CompleteStep.authorityOnly (initial_completeWellFormed issuer)
    (CapabilityState.Step.registerSubject (initialMayRegisterSubject issuer subject))
  intro handleId managed
  simp [initial, initializeClosed] at managed

/-- Exact finite executions have a concrete non-reflexive runtime witness. -/
theorem initial_to_ready_complete_nonreflexive (issuer : IssuerId)
    (subject : SubjectId) :
    CompleteSteps (initial issuer) (readyInitial issuer subject) ∧
      initial issuer ≠ readyInitial issuer subject := by
  constructor
  · exact .tail (.refl (initial issuer))
      (initialRegisterSubjectCompleteStep issuer subject)
  · intro equality
    have statuses := congrArg
      (fun state : IntegratedHandleState => state.authority.subjectStatuses subject)
      equality
    simp [initial, initializeClosed, readyInitial, startupSubject,
      CapabilityState.empty, CapabilityState.registerSubject, replace] at statuses

/-- Subject registration is part of ordinary reachability, not initialization. -/
theorem readyInitial_reachable (issuer : IssuerId) (subject : SubjectId) :
    (readyInitial issuer subject).Reachable := by
  exact ⟨initial issuer, initial_isInitial issuer,
    Steps.tail (Steps.refl (initial issuer))
      (initialRegisterSubjectStep issuer subject)⟩

/-- The concrete ready state may consume a handle after namespace open failure. -/
def readyInitialMayFailOpen (issuer : IssuerId) (subject : SubjectId)
    (handleId : HandleId) :
    (readyInitial issuer subject).MayFailOpenAfterRegistration
      (startupRootHandle subject handleId) := by
  constructor
  · simp [readyInitial, initial, initializeClosed, startupRootHandle,
      startupSubject, CapabilityState.registerSubject,
      CapabilityState.empty, replace]
  · rfl

/-- Concrete failed-open state with a consumed handle tombstone. -/
def failedOpenedInitial (issuer : IssuerId) (subject : SubjectId)
    (handleId : HandleId) : IntegratedHandleState :=
  (readyInitial issuer subject).failOpenAfterRegistration
    (startupRootHandle subject handleId)

/-- The concrete failed-open cleanup is part of ordinary reachability. -/
theorem failedOpenedInitial_reachable (issuer : IssuerId) (subject : SubjectId)
    (handleId : HandleId) :
    (failedOpenedInitial issuer subject handleId).Reachable := by
  apply (readyInitial_reachable issuer subject).steps
  exact Steps.tail (Steps.refl (readyInitial issuer subject))
    (by
      simpa [failedOpenedInitial] using
        (Step.failedOpenAfterRegistration
          (readyInitialMayFailOpen issuer subject handleId)))

/-- Failed-open reachability concretely exposes the consumed managed tombstone. -/
theorem failedOpenedInitial_has_tombstone (issuer : IssuerId)
    (subject : SubjectId) (handleId : HandleId) :
    let state := failedOpenedInitial issuer subject handleId
    let handle := startupRootHandle subject handleId
    state.authority.openHandles handleId = none ∧
      state.authority.issuedHandleOwners handleId = some subject ∧
      state.managedHandles handleId = true ∧
      state.accountedHandles handle.object = [] ∧
      state.Reachable ∧ state.WellFormed := by
  dsimp only
  refine ⟨?_, ?_, ?_, ?_, failedOpenedInitial_reachable issuer subject handleId,
    (failedOpenedInitial_reachable issuer subject handleId).wellFormed⟩
  · exact (failOpenAfterRegistration_consumes_tombstone
      (readyInitial issuer subject) (startupRootHandle subject handleId)).1
  · exact (failOpenAfterRegistration_consumes_tombstone
      (readyInitial issuer subject) (startupRootHandle subject handleId)).2.1
  · exact (failOpenAfterRegistration_consumes_tombstone
      (readyInitial issuer subject) (startupRootHandle subject handleId)).2.2
  · simp [failedOpenedInitial, IntegratedHandleState.failOpenAfterRegistration,
      readyInitial, initial, initializeClosed, startupRootHandle]

/-- One atomic root open produces a reachable state with an existing handle. -/
theorem openedInitial_reachable (issuer : IssuerId) (subject : SubjectId)
    (handleId : HandleId) :
    (openedInitial issuer subject handleId).Reachable := by
  rcases readyInitial_reachable issuer subject with
    ⟨initialState, initialStateIsInitial, registration⟩
  exact ⟨initialState, initialStateIsInitial,
    Steps.tail registration
      (by simpa [openedInitial] using
        Step.openAtomic (readyInitialMayOpen issuer subject handleId))⟩

/-- Existing exact handles may be packaged only at the explicit restore boundary. -/
theorem openedInitial_restorable (issuer : IssuerId) (subject : SubjectId)
    (handleId : HandleId) :
    (openedInitial issuer subject handleId).Restorable :=
  Restorable.ofWellFormedManifest
    (openedInitial_manifestExact issuer subject handleId)
    (openedInitial_reachable issuer subject handleId).wellFormed
    (by
      apply NamespaceState.openObject_preserves_completeWellFormed
      · simpa [readyInitial, initial, initializeClosed] using
          initial_namespaceComplete issuer
      · exact (readyInitialMayOpen issuer subject handleId).objectLookup)
    rfl

/-- The reachable open witness is exact in Authority, namespace, and accounting. -/
theorem openedInitial_has_exact_handle (issuer : IssuerId) (subject : SubjectId)
    (handleId : HandleId) :
    let state := openedInitial issuer subject handleId
    let handle := startupRootHandle subject handleId
    let object := NamespaceState.withOpenHandleCount
      (NamespaceState.rootObject (NamespaceState.allocatedObjectId 0)) 1
    state.authority.openHandles handleId = some handle ∧
      state.namespaceState.objects handle.object = some object ∧
      state.accountedHandles handle.object = [handleId] ∧
      state.managedHandles handleId = true ∧
      state.Reachable ∧ state.WellFormed := by
  dsimp only
  refine ⟨?_, ?_, ?_, ?_, openedInitial_reachable issuer subject handleId,
    (openedInitial_reachable issuer subject handleId).wellFormed⟩
  · simp [openedInitial, IntegratedHandleState.openHandle, readyInitial,
      initializeClosed, startupRootHandle, CapabilityState.registerOpenHandle,
      CapabilityState.empty, replace]
  · simp [openedInitial, IntegratedHandleState.openHandle, readyInitial,
      initializeClosed, startupRootHandle, NamespaceState.runtimeInitial,
      NamespaceState.withRoot, NamespaceState.openObject,
      NamespaceState.updateOpenHandleCount, NamespaceState.rootObject, replace]
  · simp [openedInitial, IntegratedHandleState.openHandle, readyInitial,
      initial, initializeClosed, startupRootHandle, replace]
  · simp [openedInitial, IntegratedHandleState.openHandle, readyInitial,
      initial, initializeClosed, startupRootHandle, replace]

/-- Reachability with an existing exact handle is constructively non-vacuous. -/
theorem reachable_with_existing_handle_nonempty (issuer : IssuerId)
    (subject : SubjectId) (handleId : HandleId) :
    ∃ (state : IntegratedHandleState) (handle : OpenHandle)
        (object : NamespaceObject),
      state.Reachable ∧ state.WellFormed ∧
      state.authority.openHandles handleId = some handle ∧
      state.namespaceState.objects handle.object = some object ∧
      state.accountedHandles handle.object = [handleId] ∧
      state.managedHandles handleId = true := by
  refine ⟨openedInitial issuer subject handleId,
    startupRootHandle subject handleId,
    NamespaceState.withOpenHandleCount
      (NamespaceState.rootObject (NamespaceState.allocatedObjectId 0)) 1, ?_⟩
  have exactHandle := openedInitial_has_exact_handle issuer subject handleId
  exact ⟨exactHandle.2.2.2.2.1, exactHandle.2.2.2.2.2,
    exactHandle.1, exactHandle.2.1, exactHandle.2.2.1,
    exactHandle.2.2.2.1⟩

/-- An accounted live handle refutes the finish-close premise for its owner. -/
theorem WellFormed.accounted_handle_blocks_subject_finish
    {state : IntegratedHandleState} (wellFormed : state.WellFormed)
    {objectId : ObjectId} {handleId : HandleId}
    (accounted : handleId ∈ state.accountedHandles objectId) :
    ∃ handle,
      state.authority.openHandles handleId = some handle ∧
      handle.object = objectId ∧
      ¬ (∀ queriedId queriedHandle,
        state.authority.openHandles queriedId = some queriedHandle →
          queriedHandle.subject ≠ handle.subject) := by
  rcases (wellFormed.authorityHandlesExact objectId handleId).1 accounted with
    ⟨handle, handleLookup, objectMatches, _managed⟩
  refine ⟨handle, handleLookup, objectMatches, ?_⟩
  intro finishAllowed
  exact finishAllowed handleId handle handleLookup rfl

end IntegratedHandleState

end Authority
