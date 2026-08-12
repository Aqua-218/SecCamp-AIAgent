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
  namespaceWellFormed : state.namespaceState.WellFormed

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

/-- A namespace rename precondition excludes every live Authority handle. -/
theorem mayRename_excludes_all_live_authority_handles
    {state : IntegratedHandleState} (wellFormed : state.WellFormed)
    {pathMapping : NamespaceState.PathRenaming}
    (allowed : state.namespaceState.MayRename pathMapping) :
    ∀ handleId, state.authority.openHandles handleId = none := by
  intro handleId
  cases handleLookup : state.authority.openHandles handleId with
  | none => rfl
  | some handle =>
      rcases wellFormed.everyHandleHasLiveObject handleId handle handleLookup with
        ⟨object, objectLookup⟩
      have closedCount := allowed.allHandlesClosed handle.object object objectLookup
      have handleExcluded := wellFormed.zero_count_excludes_authority_handle
        objectLookup closedCount handleId handle handleLookup
      exact False.elim (handleExcluded rfl)

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

/-- Closing a subject is impossible while any accounted object handle remains. -/
theorem finishClose_precondition_excludes_accounted_subject_handle
    {state : IntegratedHandleState} {subject : SubjectId}
    (finishAllowed : ∀ handleId handle,
      state.authority.openHandles handleId = some handle →
        handle.subject ≠ subject) :
    ∀ objectId handleId,
      handleId ∈ state.accountedHandles objectId →
      ∀ handle,
        state.authority.openHandles handleId = some handle →
        handle.subject ≠ subject := by
  intro objectId handleId accounted handle handleLookup sameSubject
  exact finishAllowed handleId handle handleLookup sameSubject

end IntegratedHandleState

end Authority
