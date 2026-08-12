import Authority.Capability

/-!
# Capability State Machine

An executable-shaped sequential specification for subject lifecycle,
capability issuance and delegation, transitive revocation, and open-handle
identity.  The Rust kernel is responsible for linearizing these transitions;
this module proves the security properties of the transition system itself.
-/

namespace Authority

/-- Minimal finite-key update for total functional maps. -/
def replace [DecidableEq keyType] (mapping : keyType → valueType)
    (selectedKey : keyType) (selectedValue : valueType) : keyType → valueType :=
  fun queriedKey => if queriedKey = selectedKey then selectedValue else mapping queriedKey

@[simp]
theorem replace_selected [DecidableEq keyType] (mapping : keyType → valueType)
    (selectedKey : keyType) (selectedValue : valueType) :
    replace mapping selectedKey selectedValue selectedKey = selectedValue := by
  simp [replace]

theorem replace_other [DecidableEq keyType] (mapping : keyType → valueType)
    (selectedKey queriedKey : keyType) (selectedValue : valueType)
    (differentKeys : queriedKey ≠ selectedKey) :
    replace mapping selectedKey selectedValue queriedKey = mapping queriedKey := by
  simp [replace, differentKeys]

/-- An opaque handle identity assigned once within a session. -/
structure HandleId where
  value : String
  deriving Repr, BEq, DecidableEq

/-- An opaque identity for one object in the shared filesystem namespace. -/
structure ObjectId where
  value : String
  deriving Repr, BEq, DecidableEq

/-- A live handle remains bound to its authenticated subject and object. -/
structure OpenHandle where
  id : HandleId
  subject : SubjectId
  object : ObjectId
  deriving Repr, DecidableEq

/-- The immutable authority ceiling assigned to a subject. -/
structure StaticAuthorityEnvelope where
  validity : TimeWindow
  authority : AuthorityBody

namespace StaticAuthorityEnvelope

/-- Semantic containment of proposed authority inside a subject ceiling. -/
def Contains (envelope : StaticAuthorityEnvelope) (validity : TimeWindow)
    (authority : AuthorityBody) : Prop :=
  validity.IsSubsetOf envelope.validity ∧
    ∀ request, authority.Matches request → envelope.authority.Matches request

/-- Executable containment check used by the Rust state machine. -/
def contains (envelope : StaticAuthorityEnvelope) (validity : TimeWindow)
    (authority : AuthorityBody) : Bool :=
  timeWindowBelow validity envelope.validity &&
    authorityBodyBelow authority envelope.authority

/-- The executable envelope check is sound for every typed request. -/
theorem contains_sound {envelope : StaticAuthorityEnvelope}
    {validity : TimeWindow} {authority : AuthorityBody}
    (isContained : envelope.contains validity authority = true) :
    envelope.Contains validity authority := by
  simp only [contains, Bool.and_eq_true] at isContained
  exact ⟨timeWindowBelow_sound isContained.1,
    authorityBodyBelow_sound isContained.2⟩

/-- Envelope containment is reflexive. -/
theorem contains_self (envelope : StaticAuthorityEnvelope) :
    envelope.contains envelope.validity envelope.authority = true := by
  simp [contains, timeWindowBelow_refl, authorityBodyBelow_refl]

end StaticAuthorityEnvelope

/-- A registered subject and its immutable authority ceiling. -/
structure Subject where
  id : SubjectId
  parent : Option SubjectId
  envelope : StaticAuthorityEnvelope

/-- Subject shutdown is monotone: running, then closing, then closed. -/
inductive SubjectStatus where
  | running
  | closing
  | closed
  deriving Repr, BEq, DecidableEq

namespace SubjectStatus

/-- Numeric rank used only to state lifecycle monotonicity. -/
def rank : SubjectStatus → Nat
  | .running => 0
  | .closing => 1
  | .closed => 2

/-- One accepted lifecycle transition. -/
inductive Step : SubjectStatus → SubjectStatus → Prop
  | beginClose : Step .running .closing
  | finishClose : Step .closing .closed
  | alreadyClosing : Step .closing .closing
  | alreadyClosed : Step .closed .closed

/-- Every lifecycle step is monotone. -/
theorem Step.rank_monotone {before after : SubjectStatus}
    (transition : Step before after) : before.rank ≤ after.rank := by
  cases transition <;> decide

/-- A closed subject cannot leave the terminal state. -/
theorem Step.closed_is_terminal {after : SubjectStatus}
    (transition : Step .closed after) : after = .closed := by
  cases transition
  rfl

/-- Reflexive-transitive closure of accepted lifecycle steps. -/
inductive Steps : SubjectStatus → SubjectStatus → Prop
  | refl (status : SubjectStatus) : Steps status status
  | next {before middle after : SubjectStatus} :
      Step before middle → Steps middle after → Steps before after

/-- Lifecycle rank remains monotone across an arbitrary execution. -/
theorem Steps.rank_monotone {before after : SubjectStatus}
    (execution : Steps before after) : before.rank ≤ after.rank := by
  induction execution with
  | refl => exact Nat.le_refl _
  | next transition remainingSteps inductionResult =>
      exact Nat.le_trans transition.rank_monotone inductionResult

/-- No finite accepted execution can revive a closed subject. -/
theorem Steps.closed_is_terminal {after : SubjectStatus}
    (execution : Steps .closed after) : after = .closed := by
  have rankBound := execution.rank_monotone
  cases after <;> simp [rank] at rankBound ⊢

end SubjectStatus

/-- Authority fields requested for a new capability. -/
structure CapabilityGrant where
  subject : SubjectId
  validity : TimeWindow
  authority : AuthorityBody
  delegable : Bool

/-- The abstract sequential state protected by the Rust kernel lock. -/
structure CapabilityState where
  issuer : IssuerId
  subjects : SubjectId → Option Subject
  subjectStatuses : SubjectId → Option SubjectStatus
  capabilities : CapId → Option Capability
  held : SubjectId → CapId → Bool
  revoked : CapId → Bool
  authorizationEpoch : Nat
  openHandles : HandleId → Option OpenHandle
  issuedHandleOwners : HandleId → Option SubjectId

namespace CapabilityState

/-- Empty state for one session-local issuer. -/
def empty (issuer : IssuerId) : CapabilityState where
  issuer := issuer
  subjects := fun _ => none
  subjectStatuses := fun _ => none
  capabilities := fun _ => none
  held := fun _ _ => false
  revoked := fun _ => false
  authorizationEpoch := 0
  openHandles := fun _ => none
  issuedHandleOwners := fun _ => none

/-- The capability is held by the named subject. -/
def HeldBy (state : CapabilityState) (subject : SubjectId)
    (capability : CapId) : Prop :=
  state.held subject capability = true

/-- A capability identity has been issued and therefore cannot be reused. -/
def WasIssued (state : CapabilityState) (capability : CapId) : Prop :=
  ∃ record, state.capabilities capability = some record

/-- A handle identity has been issued, even if its live record was closed. -/
def HandleWasIssued (state : CapabilityState) (handle : HandleId) : Prop :=
  ∃ owner, state.issuedHandleOwners handle = some owner

/-- Registration is allowed only for a fresh subject with a live parent. -/
structure MayRegisterSubject (state : CapabilityState) (subject : Subject) where
  subjectFresh : state.subjects subject.id = none
  statusFresh : state.subjectStatuses subject.id = none
  noExistingHoldings : ∀ capabilityId, state.held subject.id capabilityId = false
  parentReady : ∀ parentId, subject.parent = some parentId →
    (∃ parent, state.subjects parentId = some parent) ∧
      state.subjectStatuses parentId = some .running

/-- A direct parent edge follows the immutable metadata pointer exactly. -/
def DirectParent (state : CapabilityState) (child parent : CapId) : Prop :=
  ∃ childCapability parentCapability,
    state.capabilities child = some childCapability ∧
    state.capabilities parent = some parentCapability ∧
    childCapability.metadata.parent = some parent

/-- Every stored parent pointer resolves and is non-amplifying. -/
def GraphWellFormed (state : CapabilityState) : Prop :=
  ∀ childId childCapability parentId,
    state.capabilities childId = some childCapability →
    childCapability.metadata.parent = some parentId →
    ∃ parentCapability,
      state.capabilities parentId = some parentCapability ∧
      weakerThan childCapability parentCapability = true

/-- The empty capability graph is well formed. -/
theorem empty_graphWellFormed (issuer : IssuerId) :
    (empty issuer).GraphWellFormed := by
  intro childId childCapability parentId childLookup
  simp [empty] at childLookup

/-- A capability lies on its own finite parent chain. -/
inductive OnChain (state : CapabilityState) : CapId → CapId → Prop
  | self {capabilityId : CapId} (capability : Capability)
      (lookup : state.capabilities capabilityId = some capability) :
      OnChain state capabilityId capabilityId
  | next {child parent ancestor : CapId} :
      DirectParent state child parent →
      OnChain state parent ancestor →
      OnChain state child ancestor

/-- Every member of a capability chain resolves to an issued record. -/
theorem OnChain.ancestor_was_issued {state : CapabilityState}
    {child ancestor : CapId} (chain : OnChain state child ancestor) :
    state.WasIssued ancestor := by
  induction chain with
  | self capability lookup => exact ⟨capability, lookup⟩
  | next _ _ inductionResult => exact inductionResult

/-- Every member of a capability chain is no stronger than every ancestor. -/
theorem OnChain.weakerThan {state : CapabilityState} {child ancestor : CapId}
    (graphWellFormed : state.GraphWellFormed)
    (chain : OnChain state child ancestor) :
    ∀ {childCapability ancestorCapability : Capability},
      state.capabilities child = some childCapability →
      state.capabilities ancestor = some ancestorCapability →
      Authority.weakerThan childCapability ancestorCapability = true := by
  induction chain with
  | self storedCapability storedLookup =>
      intro childCapability ancestorCapability childLookup ancestorLookup
      have childIsStored : childCapability = storedCapability :=
        Option.some.inj (childLookup.symm.trans storedLookup)
      have ancestorIsStored : ancestorCapability = storedCapability :=
        Option.some.inj (ancestorLookup.symm.trans storedLookup)
      subst childCapability
      subst ancestorCapability
      exact weakerThan_refl storedCapability
  | next directParent remainingChain inductionResult =>
      intro childCapability ancestorCapability childLookup ancestorLookup
      rcases directParent with
        ⟨directChild, directParentCapability, directChildLookup, directParentLookup,
          parentPointer⟩
      have childIsStored : childCapability = directChild :=
        Option.some.inj (childLookup.symm.trans directChildLookup)
      subst childCapability
      rcases graphWellFormed _ _ _ directChildLookup parentPointer with
        ⟨verifiedParent, verifiedParentLookup, directNonAmplification⟩
      have parentIsVerified : directParentCapability = verifiedParent := Option.some.inj
        (directParentLookup.symm.trans verifiedParentLookup)
      subst verifiedParent
      exact weakerThan_trans directNonAmplification
        (inductionResult directParentLookup ancestorLookup)

/-- Arbitrarily deep delegation preserves the complete request set. -/
theorem OnChain.matches_subset {state : CapabilityState} {child ancestor : CapId}
    (graphWellFormed : state.GraphWellFormed)
    (chain : OnChain state child ancestor) {childCapability ancestorCapability : Capability}
    (childLookup : state.capabilities child = some childCapability)
    (ancestorLookup : state.capabilities ancestor = some ancestorCapability) :
    ∀ request, childCapability.Matches request → ancestorCapability.Matches request :=
  weakerThan_sound (chain.weakerThan graphWellFormed childLookup ancestorLookup)

/-- Every capability and ancestor must be unrevoked and time-valid. -/
def EffectivelyActive (state : CapabilityState) (capability : CapId)
    (now : MonotonicTime) : Prop :=
  ∃ record, state.capabilities capability = some record ∧
    ∀ ancestor, OnChain state capability ancestor →
      state.revoked ancestor = false ∧
        ∃ ancestorRecord, state.capabilities ancestor = some ancestorRecord ∧
          ancestorRecord.validity.Contains now

/-- Revoking any ancestor makes every descendant effectively inactive. -/
theorem revoked_ancestor_not_effectivelyActive {state : CapabilityState}
    {capability ancestor : CapId} {now : MonotonicTime}
    (chain : OnChain state capability ancestor)
    (ancestorRevoked : state.revoked ancestor = true) :
    ¬ state.EffectivelyActive capability now := by
  rintro ⟨_, _, everyAncestorActive⟩
  have ancestorNotRevoked := (everyAncestorActive ancestor chain).1
  simp [ancestorRevoked] at ancestorNotRevoked

/-- Full authorization binds lifecycle, possession, identity, activity, and scope. -/
def Authorizes (state : CapabilityState) (caller : SubjectId)
    (capabilityId : CapId) (request : CapabilityRequest) : Prop :=
  state.subjectStatuses caller = some .running ∧
    state.HeldBy caller capabilityId ∧
      ∃ capability, state.capabilities capabilityId = some capability ∧
        capability.metadata.subject = caller ∧
        state.EffectivelyActive capabilityId request.time ∧
        capability.Matches request

/-- Authorization always implies a running caller that holds the capability. -/
theorem authorizes_implies_running_holder {state : CapabilityState}
    {caller : SubjectId} {capabilityId : CapId} {request : CapabilityRequest}
    (authorized : state.Authorizes caller capabilityId request) :
    state.subjectStatuses caller = some .running ∧ state.HeldBy caller capabilityId :=
  ⟨authorized.1, authorized.2.1⟩

/-- Authorization always uses a capability bound to the authenticated caller. -/
theorem authorizes_implies_subject_binding {state : CapabilityState}
    {caller : SubjectId} {capabilityId : CapId} {request : CapabilityRequest}
    (authorized : state.Authorizes caller capabilityId request) :
    ∃ capability, state.capabilities capabilityId = some capability ∧
      capability.metadata.subject = caller := by
  exact ⟨authorized.2.2.choose, authorized.2.2.choose_spec.1,
    authorized.2.2.choose_spec.2.1⟩

/-- Authorization implies both effective activity and typed request matching. -/
theorem authorizes_implies_active_and_matches {state : CapabilityState}
    {caller : SubjectId} {capabilityId : CapId} {request : CapabilityRequest}
    (authorized : state.Authorizes caller capabilityId request) :
    state.EffectivelyActive capabilityId request.time ∧
      ∃ capability, state.capabilities capabilityId = some capability ∧
        capability.Matches request := by
  rcases authorized.2.2 with
    ⟨capability, capabilityLookup, _, effectiveActivity, requestMatches⟩
  exact ⟨effectiveActivity, ⟨capability, capabilityLookup, requestMatches⟩⟩

/-- A revoked ancestor rules out authorization of every descendant request. -/
theorem revoked_ancestor_not_authorized {state : CapabilityState}
    {caller : SubjectId} {capabilityId ancestor : CapId}
    {request : CapabilityRequest}
    (chain : OnChain state capabilityId ancestor)
    (ancestorRevoked : state.revoked ancestor = true) :
    ¬ state.Authorizes caller capabilityId request := by
  intro authorized
  exact revoked_ancestor_not_effectivelyActive chain ancestorRevoked
    (authorizes_implies_active_and_matches authorized).1

/-- Construct the exact capability record assigned by an accepted issuance. -/
def capabilityFromGrant (state : CapabilityState) (capabilityId : CapId)
    (parent : Option CapId) (grant : CapabilityGrant) : Capability where
  metadata := {
    id := capabilityId
    subject := grant.subject
    issuer := state.issuer
    parent := parent
    delegable := grant.delegable
  }
  validity := grant.validity
  authority := grant.authority

/-- Publish a validated subject atomically in the running state. -/
def registerSubject (state : CapabilityState) (subject : Subject) : CapabilityState :=
  { state with
    subjects := replace state.subjects subject.id (some subject)
    subjectStatuses := replace state.subjectStatuses subject.id (some .running)
    held := replace state.held subject.id (fun _ => false) }

/-- Registration stores the complete immutable subject record. -/
theorem registerSubject_stores_exact_record (state : CapabilityState) (subject : Subject) :
    (state.registerSubject subject).subjects subject.id = some subject := by
  simp [registerSubject]

/-- Every newly registered subject starts in the running state. -/
theorem registerSubject_starts_running (state : CapabilityState) (subject : Subject) :
    (state.registerSubject subject).subjectStatuses subject.id = some .running := by
  simp [registerSubject]

/-- Registration of a fresh identity preserves every pre-existing holding. -/
theorem registerSubject_preserves_holding {state : CapabilityState}
    {registeredSubject : Subject} (allowed : MayRegisterSubject state registeredSubject)
    {holder : SubjectId} {capabilityId : CapId}
    (heldBefore : state.HeldBy holder capabilityId) :
    (state.registerSubject registeredSubject).HeldBy holder capabilityId := by
  by_cases sameSubject : holder = registeredSubject.id
  · subst holder
    have noExistingHolding := allowed.noExistingHoldings capabilityId
    rw [heldBefore] at noExistingHolding
    cases noExistingHolding
  · simp [registerSubject, HeldBy, replace, sameSubject]
    exact heldBefore

/-- Registering another fresh identity cannot revive a closed subject. -/
theorem registerSubject_preserves_closed {state : CapabilityState}
    {registeredSubject : Subject} (allowed : MayRegisterSubject state registeredSubject)
    {closedSubject : SubjectId}
    (closedBefore : state.subjectStatuses closedSubject = some .closed) :
    (state.registerSubject registeredSubject).subjectStatuses closedSubject = some .closed := by
  by_cases sameSubject : closedSubject = registeredSubject.id
  · subst closedSubject
    have freshStatus := allowed.statusFresh
    rw [closedBefore] at freshStatus
    cases freshStatus
  · simp [registerSubject, replace, sameSubject]
    exact closedBefore

/-- Registration cannot synthesize or silently replace a parent. -/
theorem MayRegisterSubject.parent_exists_and_runs {state : CapabilityState}
    {subject : Subject} (allowed : MayRegisterSubject state subject)
    {parentId : SubjectId} (hasParent : subject.parent = some parentId) :
    (∃ parent, state.subjects parentId = some parent) ∧
      state.subjectStatuses parentId = some .running :=
  allowed.parentReady parentId hasParent

/-- Root issuance is allowed only inside a running subject's static ceiling. -/
structure MayIssueRoot (state : CapabilityState) (capabilityId : CapId)
    (grant : CapabilityGrant) where
  capabilityFresh : state.capabilities capabilityId = none
  targetSubject : Subject
  targetLookup : state.subjects grant.subject = some targetSubject
  targetRunning : state.subjectStatuses grant.subject = some .running
  grantInsideEnvelope :
    targetSubject.envelope.contains grant.validity grant.authority = true

/-- Every accepted root grant is semantically inside its immutable ceiling. -/
theorem MayIssueRoot.grant_semantically_inside_envelope {state : CapabilityState}
    {capabilityId : CapId} {grant : CapabilityGrant}
    (allowed : MayIssueRoot state capabilityId grant) :
    allowed.targetSubject.envelope.Contains grant.validity grant.authority :=
  StaticAuthorityEnvelope.contains_sound allowed.grantInsideEnvelope

/-- Commit a validated capability issuance. -/
def issue (state : CapabilityState) (capabilityId : CapId)
    (parent : Option CapId) (grant : CapabilityGrant) : CapabilityState :=
  { state with
    capabilities := replace state.capabilities capabilityId
      (some (state.capabilityFromGrant capabilityId parent grant))
    held := replace state.held grant.subject
      (replace (state.held grant.subject) capabilityId true) }

/-- The newly issued identity resolves to its exact record. -/
theorem issue_stores_exact_capability (state : CapabilityState)
    (capabilityId : CapId) (parent : Option CapId) (grant : CapabilityGrant) :
    (state.issue capabilityId parent grant).capabilities capabilityId =
      some (state.capabilityFromGrant capabilityId parent grant) := by
  simp [issue]

/-- The target subject holds every successfully issued capability. -/
theorem issue_assigns_holder (state : CapabilityState)
    (capabilityId : CapId) (parent : Option CapId) (grant : CapabilityGrant) :
    (state.issue capabilityId parent grant).HeldBy grant.subject capabilityId := by
  simp [issue, HeldBy]

/-- Issuance adds one holding without removing any existing holding. -/
theorem issue_preserves_holding (state : CapabilityState)
    (issuedId : CapId) (parent : Option CapId) (grant : CapabilityGrant)
    {holder : SubjectId} {capabilityId : CapId}
    (heldBefore : state.HeldBy holder capabilityId) :
    (state.issue issuedId parent grant).HeldBy holder capabilityId := by
  by_cases sameSubject : holder = grant.subject
  · subst holder
    by_cases sameCapability : capabilityId = issuedId
    · subst capabilityId
      simp [issue, HeldBy, replace]
    · simp [issue, HeldBy, replace, sameCapability]
      exact heldBefore
  · simp [issue, HeldBy, replace, sameSubject]
    exact heldBefore

/-- Issuance assigns identity, subject, issuer, parent, and delegation exactly. -/
theorem issue_assigns_exact_metadata (state : CapabilityState)
    (capabilityId : CapId) (parent : Option CapId) (grant : CapabilityGrant) :
    ((state.capabilityFromGrant capabilityId parent grant).metadata.id = capabilityId) ∧
    ((state.capabilityFromGrant capabilityId parent grant).metadata.subject = grant.subject) ∧
    ((state.capabilityFromGrant capabilityId parent grant).metadata.issuer = state.issuer) ∧
    ((state.capabilityFromGrant capabilityId parent grant).metadata.parent = parent) ∧
    ((state.capabilityFromGrant capabilityId parent grant).metadata.delegable = grant.delegable) := by
  simp [capabilityFromGrant]

/-- Validated derivation preconditions mirror the Rust transition boundary. -/
structure MayDerive (state : CapabilityState) (caller : SubjectId)
    (parentId childId : CapId) (grant : CapabilityGrant)
    (now : MonotonicTime) where
  callerRunning : state.subjectStatuses caller = some .running
  childFresh : state.capabilities childId = none
  parentCapability : Capability
  parentLookup : state.capabilities parentId = some parentCapability
  parentBoundToCaller : parentCapability.metadata.subject = caller
  parentHeld : state.HeldBy caller parentId
  parentActive : state.EffectivelyActive parentId now
  parentDelegable : parentCapability.metadata.delegable = true
  grantBelowParent :
    timeWindowBelow grant.validity parentCapability.validity = true ∧
      authorityBodyBelow grant.authority parentCapability.authority = true
  targetSubject : Subject
  targetLookup : state.subjects grant.subject = some targetSubject
  targetRunning : state.subjectStatuses grant.subject = some .running
  grantInsideEnvelope :
    targetSubject.envelope.contains grant.validity grant.authority = true

/-- A validated derived record is structurally no stronger than its parent. -/
theorem MayDerive.child_weakerThan_parent {state : CapabilityState}
    {caller : SubjectId} {parentId childId : CapId} {grant : CapabilityGrant}
    {now : MonotonicTime} (allowed : MayDerive state caller parentId childId grant now) :
    weakerThan (state.capabilityFromGrant childId (some parentId) grant)
      allowed.parentCapability = true := by
  simp only [weakerThan, capabilityFromGrant, Bool.and_eq_true]
  exact allowed.grantBelowParent

/-- Accepted derivation creates the exact direct parent edge. -/
theorem derive_creates_direct_parent {state : CapabilityState}
    {caller : SubjectId} {parentId childId : CapId} {grant : CapabilityGrant}
    {now : MonotonicTime} (allowed : MayDerive state caller parentId childId grant now) :
    DirectParent (state.issue childId (some parentId) grant) childId parentId := by
  refine ⟨state.capabilityFromGrant childId (some parentId) grant,
    allowed.parentCapability,
    issue_stores_exact_capability state childId (some parentId) grant, ?_,
    by simp [capabilityFromGrant]⟩
  have differentIds : parentId ≠ childId := by
    intro sameIdentity
    subst childId
    have freshness := allowed.childFresh
    rw [allowed.parentLookup] at freshness
    cases freshness
  simp [issue, replace, differentIds]
  exact allowed.parentLookup

/-- Extend a previously verified parent chain with one accepted derivation. -/
theorem derive_extends_chain {state : CapabilityState}
    {caller : SubjectId} {parentId childId ancestor : CapId}
    {grant : CapabilityGrant} {now : MonotonicTime}
    (allowed : MayDerive state caller parentId childId grant now)
    (parentChain : OnChain (state.issue childId (some parentId) grant) parentId ancestor) :
    OnChain (state.issue childId (some parentId) grant) childId ancestor :=
  .next (derive_creates_direct_parent allowed) parentChain

/-- Fresh issuance preserves graph integrity when its optional parent is valid. -/
theorem issue_preserves_graphWellFormed {state : CapabilityState}
    (graphWellFormed : state.GraphWellFormed) {issuedId : CapId}
    {parent : Option CapId} {grant : CapabilityGrant}
    (fresh : state.capabilities issuedId = none)
    (parentValid : ∀ parentId, parent = some parentId →
      ∃ parentCapability,
        state.capabilities parentId = some parentCapability ∧
        weakerThan (state.capabilityFromGrant issuedId parent grant)
          parentCapability = true) :
    (state.issue issuedId parent grant).GraphWellFormed := by
  intro childId childCapability parentId childLookup parentPointer
  by_cases newChild : childId = issuedId
  · subst childId
    have exactChild : childCapability =
        state.capabilityFromGrant issuedId parent grant := Option.some.inj
      (childLookup.symm.trans (issue_stores_exact_capability state issuedId parent grant))
    subst childCapability
    have exactParent : parent = some parentId := by
      simpa [capabilityFromGrant] using parentPointer
    rcases parentValid parentId exactParent with
      ⟨parentCapability, parentLookup, nonAmplification⟩
    refine ⟨parentCapability, ?_, nonAmplification⟩
    have differentIds : parentId ≠ issuedId := by
      intro sameId
      subst parentId
      rw [fresh] at parentLookup
      cases parentLookup
    simpa [issue, replace, differentIds] using parentLookup
  · have oldChildLookup : state.capabilities childId = some childCapability := by
      simpa [issue, replace, newChild] using childLookup
    rcases graphWellFormed childId childCapability parentId oldChildLookup parentPointer with
      ⟨parentCapability, parentLookup, nonAmplification⟩
    refine ⟨parentCapability, ?_, nonAmplification⟩
    have differentIds : parentId ≠ issuedId := by
      intro sameId
      subst parentId
      rw [fresh] at parentLookup
      cases parentLookup
    simpa [issue, replace, differentIds] using parentLookup

/-- Root issuance adds no parent pointer and preserves graph integrity. -/
theorem MayIssueRoot.preserves_graphWellFormed {state : CapabilityState}
    {capabilityId : CapId} {grant : CapabilityGrant}
    (allowed : MayIssueRoot state capabilityId grant)
    (graphWellFormed : state.GraphWellFormed) :
    (state.issue capabilityId none grant).GraphWellFormed := by
  apply issue_preserves_graphWellFormed graphWellFormed allowed.capabilityFresh
  intro parentId impossibleParent
  cases impossibleParent

/-- Derived issuance extends the graph with one verified non-amplifying edge. -/
theorem MayDerive.preserves_graphWellFormed {state : CapabilityState}
    {caller : SubjectId} {parentId childId : CapId} {grant : CapabilityGrant}
    {now : MonotonicTime} (allowed : MayDerive state caller parentId childId grant now)
    (graphWellFormed : state.GraphWellFormed) :
    (state.issue childId (some parentId) grant).GraphWellFormed := by
  apply issue_preserves_graphWellFormed graphWellFormed allowed.childFresh
  intro queriedParent exactParent
  have sameParent : queriedParent = parentId := Option.some.inj exactParent.symm
  subst queriedParent
  exact ⟨allowed.parentCapability, allowed.parentLookup,
    allowed.child_weakerThan_parent⟩

/-- Direct revocation changes only the monotone revoke set and epoch. -/
def revoke (state : CapabilityState) (capabilityId : CapId) : CapabilityState :=
  { state with
    revoked := replace state.revoked capabilityId true
    authorizationEpoch := state.authorizationEpoch + 1 }

/-- The selected capability is revoked after the transition. -/
theorem revoke_marks_selected (state : CapabilityState) (capabilityId : CapId) :
    (state.revoke capabilityId).revoked capabilityId = true := by
  simp [revoke]

/-- Direct revocation never unrevokes another capability. -/
theorem revoke_is_monotone (state : CapabilityState) (revokedId queriedId : CapId)
    (alreadyRevoked : state.revoked queriedId = true) :
    (state.revoke revokedId).revoked queriedId = true := by
  by_cases sameIdentity : queriedId = revokedId
  · subst queriedId
    exact revoke_marks_selected state revokedId
  · simp [revoke, replace, sameIdentity, alreadyRevoked]

/-- A new direct revocation advances the cache epoch exactly once. -/
theorem revoke_increments_epoch (state : CapabilityState) (capabilityId : CapId) :
    (state.revoke capabilityId).authorizationEpoch = state.authorizationEpoch + 1 := by
  rfl

/-- Beginning shutdown revokes all capabilities held by the subject. -/
def beginSubjectClose (state : CapabilityState) (subject : SubjectId) : CapabilityState :=
  { state with
    subjectStatuses := replace state.subjectStatuses subject (some .closing)
    revoked := fun capabilityId => state.revoked capabilityId || state.held subject capabilityId
    authorizationEpoch := state.authorizationEpoch + 1 }

/-- Shutdown immediately moves the subject into closing. -/
theorem beginSubjectClose_sets_closing (state : CapabilityState) (subject : SubjectId) :
    (state.beginSubjectClose subject).subjectStatuses subject = some .closing := by
  simp [beginSubjectClose]

/-- Shutdown revokes every capability held by the closing subject. -/
theorem beginSubjectClose_revokes_held (state : CapabilityState)
    (subject : SubjectId) (capabilityId : CapId)
    (held : state.HeldBy subject capabilityId) :
    (state.beginSubjectClose subject).revoked capabilityId = true := by
  simp [beginSubjectClose, HeldBy] at held ⊢
  exact Or.inr held

/-- Shutdown preserves every revocation that was already effective. -/
theorem beginSubjectClose_preserves_revocation (state : CapabilityState)
    (subject : SubjectId) (capabilityId : CapId)
    (alreadyRevoked : state.revoked capabilityId = true) :
    (state.beginSubjectClose subject).revoked capabilityId = true := by
  simp [beginSubjectClose, alreadyRevoked]

/-- Closing one running subject cannot revive a different closed subject. -/
theorem beginSubjectClose_preserves_closed {state : CapabilityState}
    {closingSubject closedSubject : SubjectId}
    (closingWasRunning : state.subjectStatuses closingSubject = some .running)
    (closedBefore : state.subjectStatuses closedSubject = some .closed) :
    (state.beginSubjectClose closingSubject).subjectStatuses closedSubject = some .closed := by
  by_cases sameSubject : closedSubject = closingSubject
  · subst closedSubject
    rw [closedBefore] at closingWasRunning
    cases closingWasRunning
  · simp [beginSubjectClose, replace, sameSubject]
    exact closedBefore

/-- Completing shutdown changes only closing to closed. -/
def finishSubjectClose (state : CapabilityState) (subject : SubjectId) : CapabilityState :=
  { state with
    subjectStatuses := replace state.subjectStatuses subject (some .closed) }

/-- A completed shutdown is terminal in the resulting state. -/
theorem finishSubjectClose_sets_closed (state : CapabilityState) (subject : SubjectId) :
    (state.finishSubjectClose subject).subjectStatuses subject = some .closed := by
  simp [finishSubjectClose]

/-- Finishing one shutdown preserves every already closed subject. -/
theorem finishSubjectClose_preserves_closed (state : CapabilityState)
    (finishingSubject closedSubject : SubjectId)
    (closedBefore : state.subjectStatuses closedSubject = some .closed) :
    (state.finishSubjectClose finishingSubject).subjectStatuses closedSubject = some .closed := by
  by_cases sameSubject : closedSubject = finishingSubject
  · subst closedSubject
    exact finishSubjectClose_sets_closed state finishingSubject
  · simp [finishSubjectClose, replace, sameSubject]
    exact closedBefore

/-- Commit a validated open-handle registration. -/
def registerOpenHandle (state : CapabilityState) (handle : OpenHandle) : CapabilityState :=
  { state with
    openHandles := replace state.openHandles handle.id (some handle)
    issuedHandleOwners := replace state.issuedHandleOwners handle.id
      (some handle.subject) }

/-- A registered handle remains bound to its exact owner and object. -/
theorem registerOpenHandle_stores_exact_record (state : CapabilityState)
    (handle : OpenHandle) :
    (state.registerOpenHandle handle).openHandles handle.id = some handle := by
  simp [registerOpenHandle]

/-- Registration permanently reserves the handle identity for its owner. -/
theorem registerOpenHandle_reserves_identity (state : CapabilityState)
    (handle : OpenHandle) :
    (state.registerOpenHandle handle).issuedHandleOwners handle.id =
      some handle.subject := by
  simp [registerOpenHandle]

/-- Closing removes only the live record and retains the issued owner. -/
def closeHandle (state : CapabilityState) (handleId : HandleId) : CapabilityState :=
  { state with openHandles := replace state.openHandles handleId none }

/-- A closed handle is no longer live. -/
theorem closeHandle_removes_live_record (state : CapabilityState) (handleId : HandleId) :
    (state.closeHandle handleId).openHandles handleId = none := by
  simp [closeHandle]

/-- Handle identity reservation survives close, preventing delayed rebinding. -/
theorem closeHandle_preserves_issued_owner (state : CapabilityState)
    (handleId : HandleId) :
    (state.closeHandle handleId).issuedHandleOwners = state.issuedHandleOwners := by
  rfl

/-- The caller may close a handle only when it is the permanently recorded owner. -/
def MayCloseHandle (state : CapabilityState) (caller : SubjectId)
    (handleId : HandleId) : Prop :=
  state.issuedHandleOwners handleId = some caller

/-- Successful idempotent calls that deliberately leave the state unchanged. -/
inductive MaySucceedWithoutChange (state : CapabilityState) : Prop
  | revokeAlready {capabilityId : CapId} :
      state.WasIssued capabilityId → state.revoked capabilityId = true →
      MaySucceedWithoutChange state
  | beginCloseAlreadyClosing {subject : SubjectId} :
      state.subjectStatuses subject = some .closing → MaySucceedWithoutChange state
  | beginCloseAlreadyClosed {subject : SubjectId} :
      state.subjectStatuses subject = some .closed → MaySucceedWithoutChange state
  | finishCloseAlreadyClosed {subject : SubjectId} :
      state.subjectStatuses subject = some .closed → MaySucceedWithoutChange state
  | closeHandleAlreadyClosed {caller : SubjectId} {handleId : HandleId} :
      state.MayCloseHandle caller handleId → state.openHandles handleId = none →
      MaySucceedWithoutChange state

/-- Ownership remains true after an authorized close. -/
theorem closeHandle_preserves_ownership {state : CapabilityState}
    {caller : SubjectId} {handleId : HandleId}
    (owned : state.MayCloseHandle caller handleId) :
    (state.closeHandle handleId).MayCloseHandle caller handleId := by
  exact owned

/-- Security-relevant accepted state transitions. -/
inductive Step : CapabilityState → CapabilityState → Prop
  | registerSubject {state : CapabilityState} {subject : Subject} :
      MayRegisterSubject state subject →
      Step state (state.registerSubject subject)
  | issueRoot {state : CapabilityState} {capabilityId : CapId}
      {grant : CapabilityGrant} :
      MayIssueRoot state capabilityId grant →
      Step state (state.issue capabilityId none grant)
  | derive {state : CapabilityState} {caller : SubjectId}
      {parentId childId : CapId} {grant : CapabilityGrant} {now : MonotonicTime} :
      MayDerive state caller parentId childId grant now →
      Step state (state.issue childId (some parentId) grant)
  | revoke {state : CapabilityState} {capabilityId : CapId} :
      state.WasIssued capabilityId → state.revoked capabilityId = false →
      Step state (state.revoke capabilityId)
  | beginClose {state : CapabilityState} {subject : SubjectId} :
      state.subjectStatuses subject = some .running →
      Step state (state.beginSubjectClose subject)
  | finishClose {state : CapabilityState} {subject : SubjectId} :
      state.subjectStatuses subject = some .closing →
      (∀ handle, state.openHandles handle = none ∨
        (state.openHandles handle).any (fun record => record.subject != subject)) →
      Step state (state.finishSubjectClose subject)
  | registerHandle {state : CapabilityState} {handle : OpenHandle} :
      state.subjectStatuses handle.subject = some .running →
      state.issuedHandleOwners handle.id = none →
      Step state (state.registerOpenHandle handle)
  | closeHandle {state : CapabilityState} {caller : SubjectId} {handleId : HandleId} :
      state.MayCloseHandle caller handleId →
      Step state (state.closeHandle handleId)
  | successfulNoop {state : CapabilityState} :
      MaySucceedWithoutChange state → Step state state

/-- Authorization epochs never decrease across accepted transitions. -/
theorem Step.epoch_monotone {before after : CapabilityState}
    (transition : Step before after) :
    before.authorizationEpoch ≤ after.authorizationEpoch := by
  cases transition with
  | registerSubject => exact Nat.le_refl _
  | issueRoot => exact Nat.le_refl _
  | derive => exact Nat.le_refl _
  | revoke => exact Nat.le_succ _
  | beginClose => exact Nat.le_succ _
  | finishClose => exact Nat.le_refl _
  | registerHandle => exact Nat.le_refl _
  | closeHandle => exact Nat.le_refl _
  | successfulNoop => exact Nat.le_refl _

/-- Accepted transitions never remove an issued capability record. -/
theorem Step.capability_records_persist {before after : CapabilityState}
    (transition : Step before after) {capabilityId : CapId} {record : Capability}
    (lookupBefore : before.capabilities capabilityId = some record) :
    after.capabilities capabilityId = some record := by
  cases transition with
  | registerSubject _ => exact lookupBefore
  | issueRoot allowed =>
      rename_i issuedId grant
      have differentIds : capabilityId ≠ issuedId := by
        intro sameIdentity
        subst capabilityId
        have freshness := allowed.capabilityFresh
        rw [lookupBefore] at freshness
        cases freshness
      simp [issue, replace, differentIds]
      exact lookupBefore
  | derive allowed =>
      rename_i caller parentId issuedId grant now
      have differentIds : capabilityId ≠ issuedId := by
        intro sameIdentity
        subst capabilityId
        have freshness := allowed.childFresh
        rw [lookupBefore] at freshness
        cases freshness
      simp [issue, replace, differentIds]
      exact lookupBefore
  | revoke _ _ => exact lookupBefore
  | beginClose _ => exact lookupBefore
  | finishClose _ _ => exact lookupBefore
  | registerHandle _ _ => exact lookupBefore
  | closeHandle _ => exact lookupBefore
  | successfulNoop _ => exact lookupBefore

/-- Every accepted transition preserves non-amplifying parent graph integrity. -/
theorem Step.graphWellFormed {before after : CapabilityState}
    (transition : Step before after) (wellFormed : before.GraphWellFormed) :
    after.GraphWellFormed := by
  cases transition with
  | registerSubject => exact wellFormed
  | issueRoot allowed => exact allowed.preserves_graphWellFormed wellFormed
  | derive allowed => exact allowed.preserves_graphWellFormed wellFormed
  | revoke | beginClose | finishClose | registerHandle | closeHandle |
      successfulNoop => exact wellFormed

/-- Accepted transitions never undo a direct revocation. -/
theorem Step.revocation_monotone {before after : CapabilityState}
    (transition : Step before after) {capabilityId : CapId}
    (revokedBefore : before.revoked capabilityId = true) :
    after.revoked capabilityId = true := by
  cases transition with
  | registerSubject _ => exact revokedBefore
  | issueRoot _ => exact revokedBefore
  | derive _ => exact revokedBefore
  | revoke => exact revoke_is_monotone _ _ _ revokedBefore
  | beginClose => exact beginSubjectClose_preserves_revocation _ _ _ revokedBefore
  | finishClose => exact revokedBefore
  | registerHandle => exact revokedBefore
  | closeHandle => exact revokedBefore
  | successfulNoop => exact revokedBefore

/-- Accepted transitions never forget that a handle identity was issued. -/
theorem Step.handle_identity_persists {before after : CapabilityState}
    (transition : Step before after) {handleId : HandleId} {owner : SubjectId}
    (ownerBefore : before.issuedHandleOwners handleId = some owner) :
    after.issuedHandleOwners handleId = some owner := by
  cases transition with
  | registerSubject _ => exact ownerBefore
  | issueRoot _ => exact ownerBefore
  | derive _ => exact ownerBefore
  | revoke _ _ => exact ownerBefore
  | beginClose _ => exact ownerBefore
  | finishClose _ _ => exact ownerBefore
  | registerHandle _ fresh =>
      simp_all [registerOpenHandle, replace]
      intro sameIdentity
      subst handleId
      rw [ownerBefore] at fresh
      cases fresh
  | closeHandle _ => exact ownerBefore
  | successfulNoop _ => exact ownerBefore

/-- Held capabilities are never silently removed by an accepted transition. -/
theorem Step.holdings_persist {before after : CapabilityState}
    (transition : Step before after) {subject : SubjectId} {capabilityId : CapId}
    (heldBefore : before.HeldBy subject capabilityId) :
    after.HeldBy subject capabilityId := by
  cases transition with
  | registerSubject allowed =>
      exact registerSubject_preserves_holding allowed heldBefore
  | issueRoot => exact issue_preserves_holding _ _ _ _ heldBefore
  | derive => exact issue_preserves_holding _ _ _ _ heldBefore
  | revoke => exact heldBefore
  | beginClose => exact heldBefore
  | finishClose => exact heldBefore
  | registerHandle => exact heldBefore
  | closeHandle => exact heldBefore
  | successfulNoop => exact heldBefore

/-- Once a registered subject is closed, accepted transitions cannot revive it. -/
theorem Step.closed_subject_remains_closed {before after : CapabilityState}
    (transition : Step before after) {subject : SubjectId}
    (closedBefore : before.subjectStatuses subject = some .closed) :
    after.subjectStatuses subject = some .closed := by
  cases transition with
  | registerSubject allowed =>
      exact registerSubject_preserves_closed allowed closedBefore
  | issueRoot => exact closedBefore
  | derive => exact closedBefore
  | revoke => exact closedBefore
  | beginClose runningBefore =>
      exact beginSubjectClose_preserves_closed runningBefore closedBefore
  | finishClose => exact finishSubjectClose_preserves_closed _ _ _ closedBefore
  | registerHandle => exact closedBefore
  | closeHandle => exact closedBefore
  | successfulNoop => exact closedBefore

/-- Metadata parent edges persist because capability records are immutable. -/
theorem Step.directParent_persists {before after : CapabilityState}
    (transition : Step before after) {child parent : CapId}
    (edge : before.DirectParent child parent) :
    after.DirectParent child parent := by
  rcases edge with ⟨childCapability, parentCapability, childLookup, parentLookup,
    parentPointer⟩
  exact ⟨childCapability, parentCapability,
    transition.capability_records_persist childLookup,
    transition.capability_records_persist parentLookup, parentPointer⟩

/-- Complete raw parent ancestry persists across every accepted transition. -/
theorem Step.onChain_persists {before after : CapabilityState}
    (transition : Step before after) {child ancestor : CapId}
    (chain : before.OnChain child ancestor) : after.OnChain child ancestor := by
  induction chain with
  | self capability lookup =>
      exact .self capability (transition.capability_records_persist lookup)
  | next edge _ inductionResult =>
      exact .next (transition.directParent_persists edge) inductionResult

/-- A closed, permanently reserved handle identity cannot be reopened by one step. -/
theorem Step.closed_handle_stays_closed {before after : CapabilityState}
    (transition : Step before after) {handleId : HandleId} {owner : SubjectId}
    (issued : before.issuedHandleOwners handleId = some owner)
    (closed : before.openHandles handleId = none) :
    after.openHandles handleId = none := by
  cases transition with
  | registerSubject | issueRoot | derive | revoke | beginClose | finishClose |
      successfulNoop => exact closed
  | registerHandle running fresh =>
      rename_i handle
      have differentId : handleId ≠ handle.id := by
        intro sameId
        subst handleId
        rw [issued] at fresh
        cases fresh
      simpa [registerOpenHandle, replace, differentId] using closed
  | closeHandle owned =>
      rename_i caller closedId
      by_cases sameId : handleId = closedId
      · subst handleId
        exact closeHandle_removes_live_record before closedId
      · simpa [CapabilityState.closeHandle, replace, sameId] using closed

/-- Finite accepted executions of the complete capability state machine. -/
inductive Steps : CapabilityState → CapabilityState → Prop
  | refl (state : CapabilityState) : Steps state state
  | tail {first middle last : CapabilityState} :
      Steps first middle → Step middle last → Steps first last

/-- Authorization epochs never decrease across a finite execution. -/
theorem Steps.epoch_monotone {before after : CapabilityState}
    (transitions : Steps before after) :
    before.authorizationEpoch ≤ after.authorizationEpoch := by
  induction transitions with
  | refl => exact Nat.le_refl _
  | tail _ transition inductionHypothesis =>
      exact Nat.le_trans inductionHypothesis transition.epoch_monotone

/-- Capability records remain immutable across a finite execution. -/
theorem Steps.capability_records_persist {before after : CapabilityState}
    (transitions : Steps before after) {capabilityId : CapId} {record : Capability}
    (lookup : before.capabilities capabilityId = some record) :
    after.capabilities capabilityId = some record := by
  induction transitions with
  | refl => exact lookup
  | tail _ transition inductionHypothesis =>
      exact transition.capability_records_persist inductionHypothesis

/-- Revocation remains effective across a finite execution. -/
theorem Steps.revocation_monotone {before after : CapabilityState}
    (transitions : Steps before after) {capabilityId : CapId}
    (revoked : before.revoked capabilityId = true) :
    after.revoked capabilityId = true := by
  induction transitions with
  | refl => exact revoked
  | tail _ transition inductionHypothesis =>
      exact transition.revocation_monotone inductionHypothesis

/-- Graph integrity is inductive across every finite execution. -/
theorem Steps.graphWellFormed {before after : CapabilityState}
    (transitions : Steps before after) (wellFormed : before.GraphWellFormed) :
    after.GraphWellFormed := by
  induction transitions with
  | refl => exact wellFormed
  | tail _ transition inductionHypothesis =>
      exact transition.graphWellFormed inductionHypothesis

/-- Raw parent ancestry remains stable across every finite execution. -/
theorem Steps.onChain_persists {before after : CapabilityState}
    (transitions : Steps before after) {child ancestor : CapId}
    (chain : before.OnChain child ancestor) : after.OnChain child ancestor := by
  induction transitions with
  | refl => exact chain
  | tail _ transition inductionHypothesis =>
      exact transition.onChain_persists inductionHypothesis

/-- Handle identity ownership remains permanent across every finite execution. -/
theorem Steps.handle_identity_persists {before after : CapabilityState}
    (transitions : Steps before after) {handleId : HandleId} {owner : SubjectId}
    (issued : before.issuedHandleOwners handleId = some owner) :
    after.issuedHandleOwners handleId = some owner := by
  induction transitions with
  | refl => exact issued
  | tail _ transition inductionHypothesis =>
      exact transition.handle_identity_persists inductionHypothesis

/-- Closed issued handle identities remain closed across every finite execution. -/
theorem Steps.closed_handle_never_reopens {before after : CapabilityState}
    (transitions : Steps before after) {handleId : HandleId} {owner : SubjectId}
    (issued : before.issuedHandleOwners handleId = some owner)
    (closed : before.openHandles handleId = none) :
    after.openHandles handleId = none := by
  induction transitions with
  | refl => exact closed
  | tail firstTransitions transition inductionHypothesis =>
      exact transition.closed_handle_stays_closed
        (firstTransitions.handle_identity_persists issued)
        inductionHypothesis

end CapabilityState

end Authority
