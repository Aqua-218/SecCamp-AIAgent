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

/-- Only typed atomic handle operations may change the integrated bridge. -/
inductive Step : IntegratedHandleState → IntegratedHandleState → Prop
  | openAtomic {state : IntegratedHandleState} {handle : OpenHandle} :
      (allowed : MayOpen state handle) →
      Step state (state.openHandle handle allowed.object)
  | closeAtomic {state : IntegratedHandleState} {caller : SubjectId}
      {handleId : HandleId} :
      (allowed : MayClose state caller handleId) →
      Step state (state.closeHandle handleId allowed.handle allowed.object)

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

/-- Every typed integrated handle transition preserves the bridge invariant. -/
theorem Step.preserves_wellFormed {before after : IntegratedHandleState}
    (transition : Step before after) (wellFormed : before.WellFormed) :
    after.WellFormed := by
  cases transition with
  | openAtomic allowed => exact openHandle_preserves_wellFormed wellFormed allowed
  | closeAtomic allowed => exact closeHandle_preserves_wellFormed wellFormed allowed

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
