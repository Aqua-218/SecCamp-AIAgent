import Authority.Namespace

/-!
# Authority and Namespace Integration

Cross-component refinement invariant connecting Authority live handles to the
capability-filesystem open count. Neither component can prove this agreement in
isolation; adapters must preserve this relation at each atomic open/close
linearization point.
-/

namespace Authority

/-- Combined logical view shared by Authority Core and the namespace registry. -/
structure IntegratedHandleState where
  authority : CapabilityState
  namespaceState : NamespaceState
  accountedHandles : ObjectId → List HandleId

namespace IntegratedHandleState

/-- Exact cross-component agreement required at an integration boundary. -/
structure WellFormed (state : IntegratedHandleState) : Prop where
  accountedHandlesNodup : ∀ objectId, (state.accountedHandles objectId).Nodup
  authorityHandlesExact : ∀ objectId handleId,
    handleId ∈ state.accountedHandles objectId ↔
      ∃ handle,
        state.authority.openHandles handleId = some handle ∧
        handle.object = objectId
  namespaceCountsExact : ∀ objectId object,
    state.namespaceState.objects objectId = some object →
      (state.accountedHandles objectId).length = object.openHandleCount
  everyHandleHasLiveObject : ∀ handleId handle,
    state.authority.openHandles handleId = some handle →
      ∃ object, state.namespaceState.objects handle.object = some object
  liveHandleOwnerExact : ∀ handleId handle,
    state.authority.openHandles handleId = some handle →
      state.authority.issuedHandleOwners handleId = some handle.subject
  namespaceWellFormed : state.namespaceState.TreeWellFormed

/-- A startup manifest enumerates exactly the live namespace object records. -/
def ManifestExact (namespaceState : NamespaceState)
    (manifest : List NamespaceObject) : Prop :=
  (manifest.map NamespaceObject.id).Nodup ∧
    ∀ objectId object,
      namespaceState.objects objectId = some object ↔
        object ∈ manifest ∧ object.id = objectId

/-- Evidence that a published startup snapshot ties its manifest and both components. -/
structure Initialization (state : IntegratedHandleState) where
  manifest : List NamespaceObject
  manifestExact : ManifestExact state.namespaceState manifest
  accountedHandlesNodup : ∀ objectId, (state.accountedHandles objectId).Nodup
  authorityHandlesExact : ∀ objectId handleId,
    handleId ∈ state.accountedHandles objectId ↔
      ∃ handle,
        state.authority.openHandles handleId = some handle ∧
        handle.object = objectId
  manifestCountsExact : ∀ object,
    object ∈ manifest →
      (state.accountedHandles object.id).length = object.openHandleCount
  everyHandleTargetsManifest : ∀ handleId handle,
    state.authority.openHandles handleId = some handle →
      ∃ object, object ∈ manifest ∧ object.id = handle.object
  liveHandleOwnerExact : ∀ handleId handle,
    state.authority.openHandles handleId = some handle →
      state.authority.issuedHandleOwners handleId = some handle.subject
  namespaceWellFormed : state.namespaceState.TreeWellFormed

/-- A state is initial when it has concrete manifest-backed initialization evidence. -/
def Initial (state : IntegratedHandleState) : Prop :=
  Nonempty (Initialization state)

/-- Every admitted startup snapshot establishes the integration invariant. -/
theorem Initial.wellFormed {state : IntegratedHandleState}
    (initial : state.Initial) : state.WellFormed := by
  rcases initial with ⟨initial⟩
  constructor
  · exact initial.accountedHandlesNodup
  · exact initial.authorityHandlesExact
  · intro objectId object objectLookup
    have inManifest := (initial.manifestExact.2 objectId object).1 objectLookup
    simpa [inManifest.2] using initial.manifestCountsExact object inManifest.1
  · intro handleId handle handleLookup
    rcases initial.everyHandleTargetsManifest handleId handle handleLookup with
      ⟨object, objectInManifest, objectIdentity⟩
    exact ⟨object, (initial.manifestExact.2 handle.object object).2
      ⟨objectInManifest, objectIdentity⟩⟩
  · exact initial.liveHandleOwnerExact
  · exact initial.namespaceWellFormed

/-- A well-formed state with an exact finite live-object manifest may be restored. -/
theorem Initial.ofWellFormedManifest {state : IntegratedHandleState}
    {manifest : List NamespaceObject}
    (manifestExact : ManifestExact state.namespaceState manifest)
    (wellFormed : state.WellFormed) : state.Initial := by
  refine ⟨{
    manifest := manifest
    manifestExact := manifestExact
    accountedHandlesNodup := wellFormed.accountedHandlesNodup
    authorityHandlesExact := wellFormed.authorityHandlesExact
    manifestCountsExact := ?_
    everyHandleTargetsManifest := ?_
    liveHandleOwnerExact := wellFormed.liveHandleOwnerExact
    namespaceWellFormed := wellFormed.namespaceWellFormed
  }⟩
  · intro object objectInManifest
    have objectLookup := (manifestExact.2 object.id object).2
      ⟨objectInManifest, rfl⟩
    exact wellFormed.namespaceCountsExact object.id object objectLookup
  · intro handleId handle handleLookup
    rcases wellFormed.everyHandleHasLiveObject handleId handle handleLookup with
      ⟨object, objectLookup⟩
    have objectInManifest := (manifestExact.2 handle.object object).1 objectLookup
    exact ⟨object, objectInManifest.1, objectInManifest.2⟩

/-- Build a startup snapshot whose imported manifest has no open handles. -/
def initializeClosed (authority : CapabilityState)
    (namespaceState : NamespaceState) : IntegratedHandleState where
  authority := authority
  namespaceState := namespaceState
  accountedHandles := fun _ => []

/-- A closed exact manifest and an Authority state with no live handles initialize safely. -/
theorem Initial.ofClosedManifest {authority : CapabilityState}
    {namespaceState : NamespaceState} {manifest : List NamespaceObject}
    (manifestExact : ManifestExact namespaceState manifest)
    (allObjectsClosed : ∀ object, object ∈ manifest → object.openHandleCount = 0)
    (noAuthorityHandles : ∀ handleId, authority.openHandles handleId = none)
    (namespaceWellFormed : namespaceState.TreeWellFormed) :
    (initializeClosed authority namespaceState).Initial := by
  refine ⟨{
    manifest := manifest
    manifestExact := manifestExact
    accountedHandlesNodup := by simp [initializeClosed]
    authorityHandlesExact := ?_
    manifestCountsExact := ?_
    everyHandleTargetsManifest := ?_
    liveHandleOwnerExact := ?_
    namespaceWellFormed := namespaceWellFormed
  }⟩
  · intro objectId handleId
    constructor
    · intro accounted
      simp [initializeClosed] at accounted
    · rintro ⟨handle, handleLookup, _⟩
      change authority.openHandles handleId = some handle at handleLookup
      rw [noAuthorityHandles handleId] at handleLookup
      cases handleLookup
  · intro object objectInManifest
    simp [initializeClosed, allObjectsClosed object objectInManifest]
  · intro handleId handle handleLookup
    change authority.openHandles handleId = some handle at handleLookup
    rw [noAuthorityHandles handleId] at handleLookup
    cases handleLookup
  · intro handleId handle handleLookup
    change authority.openHandles handleId = some handle at handleLookup
    rw [noAuthorityHandles handleId] at handleLookup
    cases handleLookup

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

/-- The concrete runtime startup is admitted by the initialization relation. -/
theorem initial_isInitial (issuer : IssuerId) : (initial issuer).Initial := by
  apply Initial.ofClosedManifest runtimeInitial_manifestExact
  · intro object objectInManifest
    have exactObject := List.mem_singleton.mp objectInManifest
    subst object
    rfl
  · intro handleId
    rfl
  · exact NamespaceState.withRoot_treeWellFormed
      (NamespaceState.allocatedObjectId 0)

/-- The concrete runtime startup satisfies exact cross-component agreement. -/
theorem initial_wellFormed (issuer : IssuerId) : (initial issuer).WellFormed :=
  (initial_isInitial issuer).wellFormed

/-- The startup relation is constructively inhabited for every issuer. -/
theorem initial_nonempty (issuer : IssuerId) :
    ∃ state : IntegratedHandleState, state.Initial :=
  ⟨initial issuer, initial_isInitial issuer⟩

/-- A closed startup whose selected subject may immediately open a root handle. -/
def readyInitial (issuer : IssuerId) (subject : SubjectId) :
    IntegratedHandleState :=
  initializeClosed
    { CapabilityState.empty issuer with
      subjectStatuses := replace (fun _ => none) subject (some .running) }
    NamespaceState.runtimeInitial

/-- The ready startup remains a genuine closed-manifest initialization. -/
theorem readyInitial_isInitial (issuer : IssuerId) (subject : SubjectId) :
    (readyInitial issuer subject).Initial := by
  apply Initial.ofClosedManifest runtimeInitial_manifestExact
  · intro object objectInManifest
    have exactObject := List.mem_singleton.mp objectInManifest
    subst object
    rfl
  · intro handleId
    rfl
  · exact NamespaceState.withRoot_treeWellFormed
      (NamespaceState.allocatedObjectId 0)

/-- Concrete handle used to witness a reachable nonempty accounting snapshot. -/
def startupRootHandle (subject : SubjectId) (handleId : HandleId) : OpenHandle where
  id := handleId
  subject := subject
  object := NamespaceState.allocatedObjectId 0

/-- A live Authority handle is represented in the finite accounting set. -/
theorem WellFormed.live_handle_is_accounted {state : IntegratedHandleState}
    (wellFormed : state.WellFormed) {handleId : HandleId} {handle : OpenHandle}
    (lookup : state.authority.openHandles handleId = some handle) :
    handleId ∈ state.accountedHandles handle.object := by
  exact (wellFormed.authorityHandlesExact handle.object handleId).2
    ⟨handle, lookup, rfl⟩

/-- A live object with zero namespace count has no live Authority handle. -/
theorem WellFormed.zero_count_excludes_authority_handle
    {state : IntegratedHandleState} (wellFormed : state.WellFormed)
    {objectId : ObjectId} {object : NamespaceObject}
    (objectLookup : state.namespaceState.objects objectId = some object)
    (noOpenHandles : object.openHandleCount = 0) :
    ∀ handleId handle,
      state.authority.openHandles handleId = some handle →
      handle.object ≠ objectId := by
  intro handleId handle handleLookup sameObject
  subst objectId
  have accounted := wellFormed.live_handle_is_accounted handleLookup
  have emptyAccounting : (state.accountedHandles handle.object).length = 0 := by
    rw [wellFormed.namespaceCountsExact handle.object object objectLookup,
      noOpenHandles]
  have noMembers : state.accountedHandles handle.object = [] :=
    List.length_eq_zero.mp emptyAccounting
  rw [noMembers] at accounted
  simp at accounted

/-- Namespace removal preconditions exclude every live Authority handle. -/
theorem mayRemove_excludes_live_authority_handles
    {state : IntegratedHandleState} (wellFormed : state.WellFormed)
    {objectId : ObjectId} (allowed : state.namespaceState.MayRemove objectId) :
    ∀ handleId handle,
      state.authority.openHandles handleId = some handle →
      handle.object ≠ objectId := by
  exact wellFormed.zero_count_excludes_authority_handle
    allowed.objectLookup allowed.noOpenHandles

/-- A rename excludes live Authority handles exactly in the moved subtree. -/
theorem mayRename_excludes_live_authority_handles_in_subtree
    {state : IntegratedHandleState} (wellFormed : state.WellFormed)
    {pathMapping : NamespaceState.PathRenaming}
    (allowed : state.namespaceState.MayRename pathMapping) :
    ∀ objectId object,
      state.namespaceState.objects objectId = some object →
      NamespaceState.AtOrBelow object.path pathMapping.source →
      ∀ handleId handle,
        state.authority.openHandles handleId = some handle →
        handle.object ≠ objectId := by
  intro objectId object objectLookup inMovedSubtree
  have closedCount := allowed.movedHandlesClosed objectId object
    objectLookup inMovedSubtree
  exact wellFormed.zero_count_excludes_authority_handle objectLookup closedCount

/-- A live handle forces the corresponding namespace count to be positive. -/
theorem WellFormed.live_handle_implies_positive_count
    {state : IntegratedHandleState} (wellFormed : state.WellFormed)
    {handleId : HandleId} {handle : OpenHandle}
    (handleLookup : state.authority.openHandles handleId = some handle) :
    ∃ object,
      state.namespaceState.objects handle.object = some object ∧
      0 < object.openHandleCount := by
  rcases wellFormed.everyHandleHasLiveObject handleId handle handleLookup with
    ⟨object, objectLookup⟩
  refine ⟨object, objectLookup, ?_⟩
  have accounted := wellFormed.live_handle_is_accounted handleLookup
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
  · simp [readyInitial, initializeClosed, startupRootHandle,
      CapabilityState.empty, replace]
  · rfl
  · simp [readyInitial, initializeClosed, startupRootHandle,
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

/-- Publish a closed namespace object without changing Authority handle state. -/
def createClosedObject (state : IntegratedHandleState)
    (object : NamespaceObject) : IntegratedHandleState where
  authority := state.authority
  namespaceState := state.namespaceState.create object
  accountedHandles := state.accountedHandles

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

/-- Only typed atomic handle operations may change the integrated bridge. -/
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

/-- A globally fresh handle identity is absent from every bridge list. -/
theorem WellFormed.fresh_handle_not_accounted {state : IntegratedHandleState}
    (wellFormed : state.WellFormed) {handleId : HandleId}
    (fresh : state.authority.issuedHandleOwners handleId = none) :
    ∀ objectId, handleId ∉ state.accountedHandles objectId := by
  intro objectId accounted
  rcases (wellFormed.authorityHandlesExact objectId handleId).1 accounted with
    ⟨handle, handleLookup, _⟩
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
            state.authority handle, rfl⟩
        · rcases (wellFormed.authorityHandlesExact handle.object handleId).1
              oldAccounted with ⟨oldHandle, oldLookup, objectMatches⟩
          have differentHandle : handleId ≠ handle.id := by
            intro sameId
            subst handleId
            exact freshEverywhere handle.object oldAccounted
          exact ⟨oldHandle, by simpa [IntegratedHandleState.openHandle,
            CapabilityState.registerOpenHandle, replace, differentHandle] using oldLookup,
            objectMatches⟩
      · have oldAccounted : handleId ∈ state.accountedHandles objectId := by
          simpa [IntegratedHandleState.openHandle, replace, sameObject] using accounted
        rcases (wellFormed.authorityHandlesExact objectId handleId).1 oldAccounted with
          ⟨oldHandle, oldLookup, objectMatches⟩
        have differentHandle : handleId ≠ handle.id := by
          intro sameId
          subst handleId
          exact freshEverywhere objectId oldAccounted
        exact ⟨oldHandle, by simpa [IntegratedHandleState.openHandle,
          CapabilityState.registerOpenHandle, replace, differentHandle] using oldLookup,
          objectMatches⟩
    · rintro ⟨queriedHandle, handleLookup, objectMatches⟩
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
        have oldAccounted := (wellFormed.authorityHandlesExact objectId handleId).2
          ⟨queriedHandle, oldLookup, objectMatches⟩
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
  · intro handleId queriedHandle handleLookup
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
      rcases wellFormed.everyHandleHasLiveObject handleId queriedHandle oldLookup with
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
  · exact NamespaceState.openObject_preserves_treeWellFormed
      wellFormed.namespaceWellFormed allowed.objectLookup

/-- Atomic close/count-release preserves exact cross-component agreement. -/
theorem closeHandle_preserves_wellFormed {state : IntegratedHandleState}
    {caller : SubjectId} {handleId : HandleId} (wellFormed : state.WellFormed)
    (allowed : state.MayClose caller handleId) :
    (state.closeHandle handleId allowed.handle allowed.object).WellFormed := by
  have accounted : handleId ∈ state.accountedHandles allowed.handle.object :=
    wellFormed.live_handle_is_accounted allowed.handleLookup
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
        ⟨queriedHandle, oldLookup, objectMatches⟩
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
        objectMatches⟩
    · rintro ⟨queriedHandle, handleLookup, objectMatches⟩
      have differentHandle : queriedId ≠ handleId := by
        intro sameId
        subst queriedId
        simp [IntegratedHandleState.closeHandle, CapabilityState.closeHandle] at handleLookup
      have oldLookup : state.authority.openHandles queriedId = some queriedHandle := by
        simpa [IntegratedHandleState.closeHandle, CapabilityState.closeHandle, replace,
          differentHandle] using handleLookup
      have oldAccounted := (wellFormed.authorityHandlesExact objectId queriedId).2
        ⟨queriedHandle, oldLookup, objectMatches⟩
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
  · intro queriedId queriedHandle handleLookup
    have differentHandle : queriedId ≠ handleId := by
      intro sameId
      subst queriedId
      simp [IntegratedHandleState.closeHandle, CapabilityState.closeHandle] at handleLookup
    have oldLookup : state.authority.openHandles queriedId = some queriedHandle := by
      simpa [IntegratedHandleState.closeHandle, CapabilityState.closeHandle, replace,
        differentHandle] using handleLookup
    rcases wellFormed.everyHandleHasLiveObject queriedId queriedHandle oldLookup with
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
  · exact NamespaceState.closeObject_preserves_treeWellFormed
      wellFormed.namespaceWellFormed allowed.objectLookup

/-- Publishing a fresh closed object preserves the cross-component invariant. -/
theorem createClosedObject_preserves_wellFormed {state : IntegratedHandleState}
    {object : NamespaceObject} (wellFormed : state.WellFormed)
    (allowed : state.namespaceState.MayCreate object) :
    (state.createClosedObject object).WellFormed := by
  have newAccountingEmpty : state.accountedHandles object.id = [] := by
    apply List.eq_nil_iff_forall_not_mem.mpr
    intro handleId accounted
    rcases (wellFormed.authorityHandlesExact object.id handleId).1 accounted with
      ⟨handle, handleLookup, objectMatches⟩
    rcases wellFormed.everyHandleHasLiveObject handleId handle handleLookup with
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
  · intro handleId handle handleLookup
    rcases wellFormed.everyHandleHasLiveObject handleId handle handleLookup with
      ⟨oldObject, oldObjectLookup⟩
    have differentObject : handle.object ≠ object.id := by
      intro sameObject
      rw [sameObject, allowed.objectAbsent] at oldObjectLookup
      cases oldObjectLookup
    exact ⟨oldObject, by simpa [IntegratedHandleState.createClosedObject,
      NamespaceState.create, replace, differentObject] using oldObjectLookup⟩
  · exact wellFormed.liveHandleOwnerExact
  · exact NamespaceState.create_preserves_treeWellFormed
      wellFormed.namespaceWellFormed allowed

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

/-- Every typed integrated handle transition preserves the bridge invariant. -/
theorem Step.preserves_wellFormed {before after : IntegratedHandleState}
    (transition : Step before after) (wellFormed : before.WellFormed) :
    after.WellFormed := by
  cases transition with
  | openAtomic allowed => exact openHandle_preserves_wellFormed wellFormed allowed
  | closeAtomic allowed => exact closeHandle_preserves_wellFormed wellFormed allowed
  | createOpenAtomic allowed =>
      exact createOpenHandle_preserves_wellFormed wellFormed allowed

/-- Finite executions consist solely of atomic bridge-preserving operations. -/
inductive Steps : IntegratedHandleState → IntegratedHandleState → Prop
  | refl (state : IntegratedHandleState) : Steps state state
  | tail {first middle last : IntegratedHandleState} :
      Steps first middle → Step middle last → Steps first last

/-- Exact bridge agreement survives every finite integrated execution. -/
theorem Steps.preserves_wellFormed {before after : IntegratedHandleState}
    (transitions : Steps before after) (wellFormed : before.WellFormed) :
    after.WellFormed := by
  induction transitions with
  | refl => exact wellFormed
  | tail _ transition inductionHypothesis =>
      exact transition.preserves_wellFormed inductionHypothesis

/-- Reachable states start from a concrete manifest-backed initialization. -/
def Reachable (state : IntegratedHandleState) : Prop :=
  ∃ initialState, initialState.Initial ∧ Steps initialState state

/-- Every state reachable from an admitted initialization is well formed. -/
theorem Reachable.wellFormed {state : IntegratedHandleState}
    (reachable : state.Reachable) : state.WellFormed := by
  rcases reachable with ⟨initialState, initialStateIsInitial, transitions⟩
  exact transitions.preserves_wellFormed initialStateIsInitial.wellFormed

/-- The concrete runtime startup is itself reachable. -/
theorem initial_reachable (issuer : IssuerId) : (initial issuer).Reachable :=
  ⟨initial issuer, initial_isInitial issuer, Steps.refl (initial issuer)⟩

/-- One atomic root open produces a reachable state with an existing handle. -/
theorem openedInitial_reachable (issuer : IssuerId) (subject : SubjectId)
    (handleId : HandleId) :
    (openedInitial issuer subject handleId).Reachable := by
  refine ⟨readyInitial issuer subject, readyInitial_isInitial issuer subject, ?_⟩
  simpa [openedInitial] using Steps.tail (Steps.refl (readyInitial issuer subject))
    (Step.openAtomic (readyInitialMayOpen issuer subject handleId))

/-- Existing exact handles are also admitted as restorable initial snapshots. -/
theorem openedInitial_isInitial (issuer : IssuerId) (subject : SubjectId)
    (handleId : HandleId) :
    (openedInitial issuer subject handleId).Initial :=
  Initial.ofWellFormedManifest
    (openedInitial_manifestExact issuer subject handleId)
    (openedInitial_reachable issuer subject handleId).wellFormed

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
      state.Reachable ∧ state.WellFormed := by
  dsimp only
  refine ⟨?_, ?_, ?_, openedInitial_reachable issuer subject handleId,
    (openedInitial_reachable issuer subject handleId).wellFormed⟩
  · simp [openedInitial, IntegratedHandleState.openHandle, readyInitial,
      initializeClosed, startupRootHandle, CapabilityState.registerOpenHandle,
      CapabilityState.empty, replace]
  · simp [openedInitial, IntegratedHandleState.openHandle, readyInitial,
      initializeClosed, startupRootHandle, NamespaceState.runtimeInitial,
      NamespaceState.withRoot, NamespaceState.openObject,
      NamespaceState.updateOpenHandleCount, NamespaceState.rootObject, replace]
  · simp [openedInitial, IntegratedHandleState.openHandle, readyInitial,
      initializeClosed, startupRootHandle, replace]

/-- Reachability with an existing exact handle is constructively non-vacuous. -/
theorem reachable_with_existing_handle_nonempty (issuer : IssuerId)
    (subject : SubjectId) (handleId : HandleId) :
    ∃ (state : IntegratedHandleState) (handle : OpenHandle)
        (object : NamespaceObject),
      state.Reachable ∧ state.WellFormed ∧
      state.Initial ∧
      state.authority.openHandles handleId = some handle ∧
      state.namespaceState.objects handle.object = some object ∧
      state.accountedHandles handle.object = [handleId] := by
  refine ⟨openedInitial issuer subject handleId,
    startupRootHandle subject handleId,
    NamespaceState.withOpenHandleCount
      (NamespaceState.rootObject (NamespaceState.allocatedObjectId 0)) 1, ?_⟩
  have exactHandle := openedInitial_has_exact_handle issuer subject handleId
  exact ⟨exactHandle.2.2.2.1, exactHandle.2.2.2.2,
    openedInitial_isInitial issuer subject handleId,
    exactHandle.1, exactHandle.2.1, exactHandle.2.2.1⟩

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
    ⟨handle, handleLookup, objectMatches⟩
  refine ⟨handle, handleLookup, objectMatches, ?_⟩
  intro finishAllowed
  exact finishAllowed handleId handle handleLookup rfl

end IntegratedHandleState

end Authority
