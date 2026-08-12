import Authority.State

/-!
# Egress Replay and Budget State Machines

Pure specifications for strict broker request ordering, idempotent replay, and
session-wide consumable budgets.  Cryptographic hashing and canonical CBOR are
implementation obligations; this module treats their outputs as opaque
identities and proves the state-machine consequences.
-/

namespace Authority

/-- Host-issued identity for one post-restore broker session. -/
structure BrokerSessionId where
  value : Nat
  deriving Repr, BEq, DecidableEq

/-- Caller-issued idempotency identity for one broker request. -/
structure BrokerRequestId where
  value : Nat
  deriving Repr, BEq, DecidableEq

/-- Opaque digest of one canonical request payload. -/
structure PayloadHash where
  value : Nat
  deriving Repr, BEq, DecidableEq

/-- Identity and ordering metadata supplied before dispatch. -/
structure BrokerEnvelope where
  session : BrokerSessionId
  sequence : Nat
  request : BrokerRequestId
  payloadHash : PayloadHash
  deriving Repr, DecidableEq

/-- Immutable binding retained for one accepted request identity. -/
structure AcceptedRequest where
  sequence : Nat
  payloadHash : PayloadHash
  deriving Repr, DecidableEq

/-- Replay state for one broker session. -/
structure ReplayState where
  session : BrokerSessionId
  capacity : Nat
  nextSequence : Option Nat
  acceptedCount : Nat
  accepted : BrokerRequestId → Option AcceptedRequest

namespace ReplayState

/-- Fresh replay state expects sequence zero. -/
def empty (session : BrokerSessionId) (capacity : Nat) : ReplayState where
  session := session
  capacity := capacity
  nextSequence := some 0
  acceptedCount := 0
  accepted := fun _ => none

/-- An envelope is an exact retry of a previously accepted request. -/
def ExactDuplicate (state : ReplayState) (envelope : BrokerEnvelope) : Prop :=
  envelope.session = state.session ∧
    state.accepted envelope.request = some {
      sequence := envelope.sequence
      payloadHash := envelope.payloadHash
    }

/-- Preconditions for accepting one new ordered request. -/
structure MayAcceptNew (state : ReplayState) (envelope : BrokerEnvelope) where
  sessionMatches : envelope.session = state.session
  requestFresh : state.accepted envelope.request = none
  sequenceExpected : state.nextSequence = some envelope.sequence
  capacityAvailable : state.acceptedCount < state.capacity

/-- Commit one validated new request binding. -/
def acceptNew (state : ReplayState) (envelope : BrokerEnvelope) : ReplayState :=
  { state with
    nextSequence := some (envelope.sequence + 1)
    acceptedCount := state.acceptedCount + 1
    accepted := replace state.accepted envelope.request (some {
      sequence := envelope.sequence
      payloadHash := envelope.payloadHash
    }) }

/-- Internal accounting and accepted sequences agree with the current cursor. -/
def WellFormed (state : ReplayState) : Prop :=
  state.acceptedCount ≤ state.capacity ∧
    ∀ request record, state.accepted request = some record →
      ∃ next, state.nextSequence = some next ∧ record.sequence < next

/-- Empty replay state is well formed for every capacity. -/
theorem empty_wellFormed (session : BrokerSessionId) (capacity : Nat) :
    (empty session capacity).WellFormed := by
  constructor
  · exact Nat.zero_le _
  · intro request record lookup
    simp [empty] at lookup

/-- A new acceptance stores the exact sequence and payload binding. -/
theorem acceptNew_stores_exact_binding (state : ReplayState)
    (envelope : BrokerEnvelope) :
    (state.acceptNew envelope).accepted envelope.request = some {
      sequence := envelope.sequence
      payloadHash := envelope.payloadHash
    } := by
  simp [acceptNew]

/-- A new acceptance advances the cursor by exactly one. -/
theorem acceptNew_advances_sequence (state : ReplayState)
    (envelope : BrokerEnvelope) :
    (state.acceptNew envelope).nextSequence = some (envelope.sequence + 1) := by
  rfl

/-- Accepting a fresh identity preserves all earlier request bindings. -/
theorem acceptNew_preserves_existing {state : ReplayState}
    {envelope : BrokerEnvelope} (allowed : MayAcceptNew state envelope)
    {request : BrokerRequestId} {record : AcceptedRequest}
    (existingLookup : state.accepted request = some record) :
    (state.acceptNew envelope).accepted request = some record := by
  by_cases sameRequest : request = envelope.request
  · subst request
    have freshness := allowed.requestFresh
    rw [existingLookup] at freshness
    cases freshness
  · simp [acceptNew, replace, sameRequest]
    exact existingLookup

/-- Accepted request identities can never be rebound to new bytes or sequence. -/
theorem accepted_identity_binding_unique {state : ReplayState}
    {first second : BrokerEnvelope}
    (firstDuplicate : state.ExactDuplicate first)
    (secondDuplicate : state.ExactDuplicate second)
    (sameRequest : first.request = second.request) :
    first.sequence = second.sequence ∧ first.payloadHash = second.payloadHash := by
  have secondLookupAtFirst : state.accepted first.request = some {
      sequence := second.sequence
      payloadHash := second.payloadHash
    } := by
    rw [sameRequest]
    exact secondDuplicate.2
  have sameRecord := Option.some.inj
    (firstDuplicate.2.symm.trans secondLookupAtFirst)
  exact ⟨congrArg AcceptedRequest.sequence sameRecord,
    congrArg AcceptedRequest.payloadHash sameRecord⟩

/-- A duplicate is necessarily bound to the current broker session. -/
theorem exactDuplicate_session_bound {state : ReplayState}
    {envelope : BrokerEnvelope} (duplicate : state.ExactDuplicate envelope) :
    envelope.session = state.session := duplicate.1

/-- New acceptance preserves replay-state well-formedness. -/
theorem acceptNew_preserves_wellFormed {state : ReplayState}
    {envelope : BrokerEnvelope} (wellFormed : state.WellFormed)
    (allowed : MayAcceptNew state envelope) :
    (state.acceptNew envelope).WellFormed := by
  constructor
  · simp only [acceptNew]
    exact Nat.succ_le_of_lt allowed.capacityAvailable
  · intro request record lookup
    refine ⟨envelope.sequence + 1, rfl, ?_⟩
    by_cases sameRequest : request = envelope.request
    · subst request
      have exactRecord : record = {
          sequence := envelope.sequence
          payloadHash := envelope.payloadHash
        } := Option.some.inj
          (lookup.symm.trans (acceptNew_stores_exact_binding state envelope))
      subst record
      simp
    · have oldLookup : state.accepted request = some record := by
        simpa [acceptNew, replace, sameRequest] using lookup
      rcases wellFormed.2 request record oldLookup with
        ⟨oldNext, oldCursor, recordBeforeCursor⟩
      rw [allowed.sequenceExpected] at oldCursor
      have cursorEquality := Option.some.inj oldCursor
      subst oldNext
      omega

/-- Accepted replay transitions: a fresh request mutates state; an exact retry does not. -/
inductive Step : ReplayState → ReplayState → Prop
  | fresh {state : ReplayState} {envelope : BrokerEnvelope} :
      MayAcceptNew state envelope → Step state (state.acceptNew envelope)
  | duplicate {state : ReplayState} {envelope : BrokerEnvelope} :
      ExactDuplicate state envelope → Step state state

/-- Accepted request bindings are immutable across one replay transition. -/
theorem Step.binding_immutable {before after : ReplayState}
    (transition : Step before after) {request : BrokerRequestId}
    {record : AcceptedRequest} (lookup : before.accepted request = some record) :
    after.accepted request = some record := by
  cases transition with
  | fresh allowed => exact acceptNew_preserves_existing allowed lookup
  | duplicate => exact lookup

/-- Accepted request count is monotone across replay transitions. -/
theorem Step.acceptedCount_monotone {before after : ReplayState}
    (transition : Step before after) : before.acceptedCount ≤ after.acceptedCount := by
  cases transition with
  | fresh => simp [acceptNew]
  | duplicate => exact Nat.le_refl _

/-- Finite replay execution. -/
inductive Steps : ReplayState → ReplayState → Prop
  | refl (state : ReplayState) : Steps state state
  | next {before middle after : ReplayState} :
      Step before middle → Steps middle after → Steps before after

/-- A request identity remains bound across an arbitrarily long replay execution. -/
theorem Steps.binding_immutable {before after : ReplayState}
    (execution : Steps before after) {request : BrokerRequestId}
    {record : AcceptedRequest} (lookup : before.accepted request = some record) :
    after.accepted request = some record := by
  induction execution with
  | refl => exact lookup
  | next firstStep remainingSteps inductionResult =>
      exact inductionResult (firstStep.binding_immutable lookup)

end ReplayState

/-- Immutable consumable ceilings for one broker session. -/
structure SessionBudgetLimits where
  maxRequests : Nat
  maxResponseBytes : Nat
  maxConcurrentRequests : Nat

/-- Bytes reserved for one active request identity. -/
structure ResponseReservation where
  request : BrokerRequestId
  maxResponseBytes : Nat
  deriving Repr, DecidableEq

/-- Stateful session-wide resource accounting. -/
structure SessionBudget where
  limits : SessionBudgetLimits
  startedRequests : Nat
  committedResponseBytes : Nat
  reservedResponseBytes : Nat
  activeRequests : Nat
  active : BrokerRequestId → Option ResponseReservation

namespace SessionBudget

/-- Unused budget under immutable session ceilings. -/
def empty (limits : SessionBudgetLimits) : SessionBudget where
  limits := limits
  startedRequests := 0
  committedResponseBytes := 0
  reservedResponseBytes := 0
  activeRequests := 0
  active := fun _ => none

/-- Aggregate counters stay within every immutable ceiling. -/
def WithinLimits (budget : SessionBudget) : Prop :=
  budget.startedRequests ≤ budget.limits.maxRequests ∧
    budget.committedResponseBytes + budget.reservedResponseBytes ≤
      budget.limits.maxResponseBytes ∧
    budget.activeRequests ≤ budget.limits.maxConcurrentRequests

/-- Empty accounting is within every limit. -/
theorem empty_withinLimits (limits : SessionBudgetLimits) :
    (empty limits).WithinLimits := by
  simp [empty, WithinLimits]

/-- Preconditions for consuming one request token and reserving response bytes. -/
structure MayStart (budget : SessionBudget) (request : BrokerRequestId)
    (maximumResponseBytes : Nat) where
  requestInactive : budget.active request = none
  requestAvailable : budget.startedRequests < budget.limits.maxRequests
  concurrencyAvailable : budget.activeRequests < budget.limits.maxConcurrentRequests
  bytesAvailable : budget.committedResponseBytes + budget.reservedResponseBytes +
    maximumResponseBytes ≤ budget.limits.maxResponseBytes

/-- Consume a request token and reserve its maximum response bytes. -/
def start (budget : SessionBudget) (request : BrokerRequestId)
    (maximumResponseBytes : Nat) : SessionBudget :=
  { budget with
    startedRequests := budget.startedRequests + 1
    reservedResponseBytes := budget.reservedResponseBytes + maximumResponseBytes
    activeRequests := budget.activeRequests + 1
    active := replace budget.active request (some {
      request := request
      maxResponseBytes := maximumResponseBytes
    }) }

/-- Preconditions for converting a live reservation into committed bytes. -/
structure MayComplete (budget : SessionBudget) (request : BrokerRequestId)
    (receivedResponseBytes : Nat) where
  reservation : ResponseReservation
  reservationLookup : budget.active request = some reservation
  requestBinding : reservation.request = request
  responseWithinReservation : receivedResponseBytes ≤ reservation.maxResponseBytes
  reservationAccounted : reservation.maxResponseBytes ≤ budget.reservedResponseBytes
  activeAccounted : 0 < budget.activeRequests

/-- Commit actual bytes and release the complete reservation. -/
def complete (budget : SessionBudget) (request : BrokerRequestId)
    (reservation : ResponseReservation) (receivedResponseBytes : Nat) : SessionBudget :=
  { budget with
    committedResponseBytes := budget.committedResponseBytes + receivedResponseBytes
    reservedResponseBytes := budget.reservedResponseBytes - reservation.maxResponseBytes
    activeRequests := budget.activeRequests - 1
    active := replace budget.active request none }

/-- Preconditions for aborting one live reservation. -/
structure MayAbort (budget : SessionBudget) (request : BrokerRequestId) where
  reservation : ResponseReservation
  reservationLookup : budget.active request = some reservation
  requestBinding : reservation.request = request
  reservationAccounted : reservation.maxResponseBytes ≤ budget.reservedResponseBytes
  activeAccounted : 0 < budget.activeRequests

/-- Release reserved bytes without refunding the consumed request token. -/
def abort (budget : SessionBudget) (request : BrokerRequestId)
    (reservation : ResponseReservation) : SessionBudget :=
  { budget with
    reservedResponseBytes := budget.reservedResponseBytes - reservation.maxResponseBytes
    activeRequests := budget.activeRequests - 1
    active := replace budget.active request none }

/-- Start stores the exact reservation binding. -/
theorem start_stores_exact_reservation (budget : SessionBudget)
    (request : BrokerRequestId) (maximumResponseBytes : Nat) :
    (budget.start request maximumResponseBytes).active request = some {
      request := request
      maxResponseBytes := maximumResponseBytes
    } := by
  simp [start]

/-- A validated start preserves all aggregate ceilings. -/
theorem start_preserves_limits {budget : SessionBudget}
    {request : BrokerRequestId} {maximumResponseBytes : Nat}
    (_withinLimits : budget.WithinLimits)
    (allowed : MayStart budget request maximumResponseBytes) :
    (budget.start request maximumResponseBytes).WithinLimits := by
  simp only [start, WithinLimits]
  exact ⟨Nat.succ_le_of_lt allowed.requestAvailable,
    by simpa [Nat.add_assoc] using allowed.bytesAvailable,
    Nat.succ_le_of_lt allowed.concurrencyAvailable⟩

/-- Completing within a reservation preserves all aggregate ceilings. -/
theorem complete_preserves_limits {budget : SessionBudget}
    {request : BrokerRequestId} {receivedResponseBytes : Nat}
    (withinLimits : budget.WithinLimits)
    (allowed : MayComplete budget request receivedResponseBytes) :
    (budget.complete request allowed.reservation receivedResponseBytes).WithinLimits := by
  simp only [complete, WithinLimits]
  rcases withinLimits with ⟨requestLimit, byteLimit, concurrentLimit⟩
  refine ⟨requestLimit, ?_, Nat.le_trans (Nat.sub_le _ _) concurrentLimit⟩
  have releasedBound : receivedResponseBytes +
      (budget.reservedResponseBytes - allowed.reservation.maxResponseBytes) ≤
      budget.reservedResponseBytes := by
    have responseBound := allowed.responseWithinReservation
    have reservationBound := allowed.reservationAccounted
    omega
  have withCommitted :=
    Nat.add_le_add_left releasedBound budget.committedResponseBytes
  have currentUsageBound : budget.committedResponseBytes + receivedResponseBytes +
      (budget.reservedResponseBytes - allowed.reservation.maxResponseBytes) ≤
      budget.committedResponseBytes + budget.reservedResponseBytes := by
    simpa only [Nat.add_assoc] using withCommitted
  exact Nat.le_trans currentUsageBound byteLimit

/-- Aborting a reservation preserves all aggregate ceilings. -/
theorem abort_preserves_limits {budget : SessionBudget}
    {request : BrokerRequestId} (withinLimits : budget.WithinLimits)
    (allowed : MayAbort budget request) :
    (budget.abort request allowed.reservation).WithinLimits := by
  simp only [abort, WithinLimits]
  rcases withinLimits with ⟨requestLimit, byteLimit, concurrentLimit⟩
  refine ⟨requestLimit, ?_, Nat.le_trans (Nat.sub_le _ _) concurrentLimit⟩
  exact Nat.le_trans
    (Nat.add_le_add_left (Nat.sub_le _ _) budget.committedResponseBytes) byteLimit

/-- Completion removes the live request identity. -/
theorem complete_removes_reservation {budget : SessionBudget}
    {request : BrokerRequestId} {receivedResponseBytes : Nat}
    (allowed : MayComplete budget request receivedResponseBytes) :
    (budget.complete request allowed.reservation receivedResponseBytes).active request = none := by
  simp [complete]

/-- Abort removes the live request identity. -/
theorem abort_removes_reservation {budget : SessionBudget}
    {request : BrokerRequestId} (allowed : MayAbort budget request) :
    (budget.abort request allowed.reservation).active request = none := by
  simp [abort]

/-- Abort never refunds the request-count token. -/
theorem abort_does_not_refund_request (budget : SessionBudget)
    (request : BrokerRequestId) (reservation : ResponseReservation) :
    (budget.abort request reservation).startedRequests = budget.startedRequests := by
  rfl

/-- Completion records exactly the received bytes, never the reservation maximum. -/
theorem complete_commits_actual_bytes (budget : SessionBudget)
    (request : BrokerRequestId) (reservation : ResponseReservation)
    (receivedResponseBytes : Nat) :
    (budget.complete request reservation receivedResponseBytes).committedResponseBytes =
      budget.committedResponseBytes + receivedResponseBytes := by
  rfl

/-- Accepted budget transitions. -/
inductive Step : SessionBudget → SessionBudget → Prop
  | start {budget : SessionBudget} {request : BrokerRequestId}
      {maximumResponseBytes : Nat} :
      MayStart budget request maximumResponseBytes →
      Step budget (budget.start request maximumResponseBytes)
  | complete {budget : SessionBudget} {request : BrokerRequestId}
      {receivedResponseBytes : Nat} :
      (allowed : MayComplete budget request receivedResponseBytes) →
      Step budget (budget.complete request allowed.reservation receivedResponseBytes)
  | abort {budget : SessionBudget} {request : BrokerRequestId} :
      (allowed : MayAbort budget request) →
      Step budget (budget.abort request allowed.reservation)

/-- Request consumption is monotone across every accepted transition. -/
theorem Step.startedRequests_monotone {before after : SessionBudget}
    (transition : Step before after) :
    before.startedRequests ≤ after.startedRequests := by
  cases transition with
  | start => exact Nat.le_succ _
  | complete => exact Nat.le_refl _
  | abort => exact Nat.le_refl _

/-- Committed response bytes are monotone across every accepted transition. -/
theorem Step.committedBytes_monotone {before after : SessionBudget}
    (transition : Step before after) :
    before.committedResponseBytes ≤ after.committedResponseBytes := by
  cases transition with
  | start => exact Nat.le_refl _
  | complete => exact Nat.le_add_right _ _
  | abort => exact Nat.le_refl _

/-- Every well-formed budget remains within limits after an accepted transition. -/
theorem Step.preserves_limits {before after : SessionBudget}
    (transition : Step before after) (withinLimits : before.WithinLimits) :
    after.WithinLimits := by
  cases transition with
  | start allowed => exact start_preserves_limits withinLimits allowed
  | complete allowed => exact complete_preserves_limits withinLimits allowed
  | abort allowed => exact abort_preserves_limits withinLimits allowed

/-- Finite budget execution. -/
inductive Steps : SessionBudget → SessionBudget → Prop
  | refl (budget : SessionBudget) : Steps budget budget
  | next {before middle after : SessionBudget} :
      Step before middle → Steps middle after → Steps before after

/-- Request tokens are never refunded across an arbitrary execution. -/
theorem Steps.startedRequests_monotone {before after : SessionBudget}
    (execution : Steps before after) :
    before.startedRequests ≤ after.startedRequests := by
  induction execution with
  | refl => exact Nat.le_refl _
  | next firstStep remainingSteps inductionResult =>
      exact Nat.le_trans firstStep.startedRequests_monotone inductionResult

/-- Aggregate ceilings hold throughout an arbitrary accepted execution. -/
theorem Steps.preserves_limits {before after : SessionBudget}
    (execution : Steps before after) (withinLimits : before.WithinLimits) :
    after.WithinLimits := by
  induction execution with
  | refl => exact withinLimits
  | next firstStep remainingSteps inductionResult =>
      exact inductionResult (firstStep.preserves_limits withinLimits)

end SessionBudget

end Authority
