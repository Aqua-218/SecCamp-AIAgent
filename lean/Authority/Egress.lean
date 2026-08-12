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

/-- Rust `checked_add(1)` for a logical `u64` sequence cursor. -/
def checkedSuccessor (sequence : Nat) : Option Nat :=
  if sequence < u64Maximum then some (sequence + 1) else none

/-- A sequence at `u64::MAX` is accepted once and then exhausts the cursor. -/
theorem checkedSuccessor_maximum : checkedSuccessor u64Maximum = none := by
  simp [checkedSuccessor, CanIncrementU64]

/-- A representable sequence is covered by the next cursor or exhaustion. -/
def CursorCovers (nextSequence : Option Nat) (sequence : Nat) : Prop :=
  FitsU64 sequence ∧
    match nextSequence with
    | some next => sequence < next
    | none => True

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
  sequenceRepresentable : FitsU64 envelope.sequence
  capacityAvailable : state.acceptedCount < state.capacity

/-- Commit one validated new request binding. -/
def acceptNew (state : ReplayState) (envelope : BrokerEnvelope) : ReplayState :=
  { state with
    nextSequence := checkedSuccessor envelope.sequence
    acceptedCount := state.acceptedCount + 1
    accepted := replace state.accepted envelope.request (some {
      sequence := envelope.sequence
      payloadHash := envelope.payloadHash
    }) }

/-- Internal accounting and accepted sequences agree with the current cursor. -/
def WellFormed (state : ReplayState) : Prop :=
  state.acceptedCount ≤ state.capacity ∧
    ∀ request record, state.accepted request = some record →
      CursorCovers state.nextSequence record.sequence

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
    (state.acceptNew envelope).nextSequence = checkedSuccessor envelope.sequence := by
  rfl

/-- Accepting `u64::MAX` records the binding and makes later fresh input impossible. -/
theorem acceptMaximum_exhausts_sequence (state : ReplayState)
    (envelope : BrokerEnvelope) (maximum : envelope.sequence = u64Maximum) :
    (state.acceptNew envelope).nextSequence = none := by
  rw [acceptNew_advances_sequence, maximum, checkedSuccessor_maximum]

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
    by_cases sameRequest : request = envelope.request
    · subst request
      have exactRecord : record = {
          sequence := envelope.sequence
          payloadHash := envelope.payloadHash
        } := Option.some.inj
          (lookup.symm.trans (acceptNew_stores_exact_binding state envelope))
      subst record
      refine ⟨allowed.sequenceRepresentable, ?_⟩
      simp only [acceptNew]
      by_cases canIncrement : envelope.sequence < u64Maximum
      · simp [checkedSuccessor, canIncrement]
      · simp [checkedSuccessor, canIncrement]
    · have oldLookup : state.accepted request = some record := by
        simpa [acceptNew, replace, sameRequest] using lookup
      have oldCovered := wellFormed.2 request record oldLookup
      rw [allowed.sequenceExpected] at oldCovered
      refine ⟨oldCovered.1, ?_⟩
      simp only [acceptNew]
      by_cases canIncrement : envelope.sequence < u64Maximum
      · simp [checkedSuccessor, canIncrement]
        exact Nat.lt.step oldCovered.2
      · simp [checkedSuccessor, canIncrement]

/-- Finite representation witnessing the exact domain of the replay map. -/
structure Accounting (state : ReplayState) (acceptedIds : List BrokerRequestId) : Prop where
  identitiesUnique : acceptedIds.Nodup
  countExact : state.acceptedCount = acceptedIds.length
  domainExact : ∀ request,
    request ∈ acceptedIds ↔ ∃ record, state.accepted request = some record

/-- Empty replay state has an exact empty finite representation. -/
theorem empty_accounting (session : BrokerSessionId) (capacity : Nat) :
    Accounting (empty session capacity) [] := by
  exact ⟨by simp, rfl, by simp [empty]⟩

/-- Fresh acceptance extends the exact finite representation by one identity. -/
theorem acceptNew_preserves_accounting {state : ReplayState}
    {envelope : BrokerEnvelope} {acceptedIds : List BrokerRequestId}
    (accounting : Accounting state acceptedIds)
    (allowed : MayAcceptNew state envelope) :
    Accounting (state.acceptNew envelope) (envelope.request :: acceptedIds) := by
  refine ⟨?_, ?_, ?_⟩
  · rw [List.nodup_cons]
    refine ⟨?_, accounting.identitiesUnique⟩
    intro alreadyPresent
    rcases (accounting.domainExact envelope.request).mp alreadyPresent with
      ⟨record, lookup⟩
    have fresh := allowed.requestFresh
    rw [lookup] at fresh
    cases fresh
  · simp [acceptNew, accounting.countExact]
  · intro request
    by_cases sameRequest : request = envelope.request
    · subst request
      simp [acceptNew_stores_exact_binding]
    · simp only [List.mem_cons, sameRequest, false_or]
      rw [accounting.domainExact request]
      constructor
      · rintro ⟨record, lookup⟩
        exact ⟨record, by simpa [acceptNew, replace, sameRequest] using lookup⟩
      · rintro ⟨record, lookup⟩
        exact ⟨record, by simpa [acceptNew, replace, sameRequest] using lookup⟩

/-- Fully accounted replay states have a real capacity bound on stored identities. -/
theorem accounting_implies_stored_identity_bound {state : ReplayState}
    {acceptedIds : List BrokerRequestId} (wellFormed : state.WellFormed)
    (accounting : Accounting state acceptedIds) :
    acceptedIds.length ≤ state.capacity := by
  rw [← accounting.countExact]
  exact wellFormed.1

/-- Existence of a duplicate-free finite representation for the replay map. -/
def FullyAccounted (state : ReplayState) : Prop :=
  ∃ acceptedIds, Accounting state acceptedIds

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

/-- Exact finite replay accounting is inductive across every accepted step. -/
theorem Step.preserves_accounting {before after : ReplayState}
    (transition : Step before after) (accounted : before.FullyAccounted) :
    after.FullyAccounted := by
  rcases accounted with ⟨acceptedIds, accounting⟩
  cases transition with
  | fresh allowed =>
      exact ⟨_, acceptNew_preserves_accounting accounting allowed⟩
  | duplicate => exact ⟨acceptedIds, accounting⟩

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

/-- Total maximum bytes represented by a finite reservation list. -/
def totalReserved : List ResponseReservation → Nat
  | [] => 0
  | reservation :: remaining =>
      reservation.maxResponseBytes + totalReserved remaining

/-- Reservation totals distribute over list append. -/
theorem totalReserved_append (first second : List ResponseReservation) :
    totalReserved (first ++ second) = totalReserved first + totalReserved second := by
  induction first with
  | nil => simp [totalReserved]
  | cons reservation remaining inductionHypothesis =>
      simp [totalReserved, inductionHypothesis, Nat.add_assoc]

/-- Exact finite representation of active-map and aggregate counters. -/
structure Accounting (budget : SessionBudget)
    (reservations : List ResponseReservation) : Prop where
  requestIdentitiesUnique : (reservations.map ResponseReservation.request).Nodup
  activeExact : ∀ request reservation,
    budget.active request = some reservation ↔
      reservation ∈ reservations ∧ reservation.request = request
  activeCountExact : budget.activeRequests = reservations.length
  reservedBytesExact : budget.reservedResponseBytes = totalReserved reservations

/-- Existence of a duplicate-free exact finite reservation representation. -/
def FullyAccounted (budget : SessionBudget) : Prop :=
  ∃ reservations, Accounting budget reservations

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

/-- Immutable broker ceilings fit the Rust integer fields that store them. -/
def LimitsRepresentable (limits : SessionBudgetLimits) : Prop :=
  FitsU64 limits.maxRequests ∧
    FitsU64 limits.maxResponseBytes ∧
    FitsU64 limits.maxConcurrentRequests

/-- Every logical budget counter has a faithful Rust integer representation. -/
def CountersRepresentable (budget : SessionBudget) : Prop :=
  LimitsRepresentable budget.limits ∧
    FitsU64 budget.startedRequests ∧
    FitsU64 budget.committedResponseBytes ∧
    FitsU64 budget.reservedResponseBytes ∧
    FitsU64 budget.activeRequests

/-- Empty accounting is within every limit. -/
theorem empty_withinLimits (limits : SessionBudgetLimits) :
    (empty limits).WithinLimits := by
  simp [empty, WithinLimits]

/-- An empty budget inherits representability from its immutable ceilings. -/
theorem empty_countersRepresentable {limits : SessionBudgetLimits}
    (representable : LimitsRepresentable limits) :
    (empty limits).CountersRepresentable := by
  simp [CountersRepresentable, empty, FitsU64, u64Maximum, representable]

/-- Empty accounting has an exact empty finite representation. -/
theorem empty_accounting (limits : SessionBudgetLimits) :
    Accounting (empty limits) [] := by
  exact ⟨by simp, by simp [empty], rfl, rfl⟩

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

/-- Release one selected live reservation from aggregate accounting. -/
def releaseReservation (budget : SessionBudget) (request : BrokerRequestId)
    (reservation : ResponseReservation) : SessionBudget :=
  { budget with
    reservedResponseBytes := budget.reservedResponseBytes - reservation.maxResponseBytes
    activeRequests := budget.activeRequests - 1
    active := replace budget.active request none }

/-- Commit actual bytes and release the complete reservation. -/
def complete (budget : SessionBudget) (request : BrokerRequestId)
    (reservation : ResponseReservation) (receivedResponseBytes : Nat) : SessionBudget :=
  { budget.releaseReservation request reservation with
    committedResponseBytes := budget.committedResponseBytes + receivedResponseBytes }

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
  budget.releaseReservation request reservation

/-- Start stores the exact reservation binding. -/
theorem start_stores_exact_reservation (budget : SessionBudget)
    (request : BrokerRequestId) (maximumResponseBytes : Nat) :
    (budget.start request maximumResponseBytes).active request = some {
      request := request
      maxResponseBytes := maximumResponseBytes
    } := by
  simp [start]

/-- Starting one fresh request preserves exact finite accounting. -/
theorem start_preserves_accounting {budget : SessionBudget}
    {request : BrokerRequestId} {maximumResponseBytes : Nat}
    {reservations : List ResponseReservation}
    (accounting : Accounting budget reservations)
    (allowed : MayStart budget request maximumResponseBytes) :
    Accounting (budget.start request maximumResponseBytes)
      ({ request := request, maxResponseBytes := maximumResponseBytes } :: reservations) := by
  let newReservation : ResponseReservation := {
    request := request
    maxResponseBytes := maximumResponseBytes
  }
  refine ⟨?_, ?_, ?_, ?_⟩
  · rw [List.map_cons, List.nodup_cons]
    refine ⟨?_, accounting.requestIdentitiesUnique⟩
    intro requestAlreadyActive
    rcases List.mem_map.mp requestAlreadyActive with
      ⟨reservation, reservationMember, sameRequest⟩
    have activeLookup := (accounting.activeExact reservation.request reservation).2
      ⟨reservationMember, rfl⟩
    have requestMatches : reservation.request = request := by
      simpa [newReservation] using sameRequest
    have targetLookup : budget.active request = some reservation := by
      rw [← requestMatches]
      exact activeLookup
    have inactive := allowed.requestInactive
    rw [targetLookup] at inactive
    cases inactive
  · intro queriedRequest reservation
    by_cases sameRequest : queriedRequest = request
    · subst queriedRequest
      constructor
      · intro lookup
        have exactReservation : reservation = newReservation := Option.some.inj
          (lookup.symm.trans (start_stores_exact_reservation budget request
            maximumResponseBytes))
        subst reservation
        exact ⟨by simp [newReservation], rfl⟩
      · rintro ⟨member, binding⟩
        simp only [List.mem_cons] at member
        rcases member with sameReservation | oldMember
        · subst reservation
          exact start_stores_exact_reservation budget request maximumResponseBytes
        · have oldLookup := (accounting.activeExact request reservation).2
            ⟨oldMember, binding⟩
          have inactive := allowed.requestInactive
          rw [oldLookup] at inactive
          cases inactive
    · simp only [start, replace, sameRequest, if_false]
      rw [accounting.activeExact queriedRequest reservation]
      constructor
      · rintro ⟨oldMember, binding⟩
        exact ⟨by simp [oldMember], binding⟩
      · rintro ⟨member, binding⟩
        simp only [List.mem_cons] at member
        rcases member with sameReservation | oldMember
        · subst reservation
          exact False.elim (sameRequest binding.symm)
        · exact ⟨oldMember, binding⟩
  · simp [start, accounting.activeCountExact]
  · simp [start, totalReserved, accounting.reservedBytesExact, newReservation,
      Nat.add_comm]

/-- In a unique reservation representation, the selected request occurs nowhere else. -/
theorem Accounting.selected_request_absent_from_remainder {budget : SessionBudget}
    {reservations : List ResponseReservation}
    (accounting : Accounting budget reservations) {reservation : ResponseReservation}
    {preceding following : List ResponseReservation}
    (decomposition : reservations = preceding ++ reservation :: following) :
    reservation.request ∉ (preceding ++ following).map ResponseReservation.request := by
  have unique :
      (preceding.map ResponseReservation.request ++
        reservation.request :: following.map ResponseReservation.request).Nodup := by
    simpa [decomposition, List.map_append] using accounting.requestIdentitiesUnique
  rcases List.pairwise_append.mp unique with
    ⟨_, rightUnique, crossUnique⟩
  have absentFromSuffix :
      reservation.request ∉ following.map ResponseReservation.request :=
    (List.nodup_cons.mp rightUnique).1
  intro member
  simp only [List.map_append, List.mem_append] at member
  rcases member with inPrefix | inSuffix
  · have different := crossUnique reservation.request inPrefix reservation.request
      (by simp)
    exact different rfl
  · exact absentFromSuffix inSuffix

/-- Removing a selected reservation preserves exact finite accounting. -/
theorem releaseReservation_preserves_accounting {budget : SessionBudget}
    {request : BrokerRequestId} {reservation : ResponseReservation}
    {reservations : List ResponseReservation}
    (accounting : Accounting budget reservations)
    (reservationLookup : budget.active request = some reservation)
    (requestBinding : reservation.request = request) :
    ∃ remaining,
      Accounting (budget.releaseReservation request reservation) remaining := by
  have reservationMember : reservation ∈ reservations :=
    (accounting.activeExact request reservation).mp reservationLookup |>.1
  rcases List.mem_iff_append.mp reservationMember with
    ⟨preceding, following, decomposition⟩
  let remaining := preceding ++ following
  have selectedAbsent : reservation.request ∉
      remaining.map ResponseReservation.request := by
    exact accounting.selected_request_absent_from_remainder decomposition
  refine ⟨remaining, ?_, ?_, ?_, ?_⟩
  · have remainingSublist : remaining.Sublist reservations := by
      rw [decomposition]
      exact List.Sublist.append (List.Sublist.refl preceding)
        (List.Sublist.cons reservation (List.Sublist.refl following))
    exact List.Nodup.sublist (remainingSublist.map ResponseReservation.request)
      accounting.requestIdentitiesUnique
  · intro queriedRequest queriedReservation
    by_cases sameRequest : queriedRequest = request
    · subst queriedRequest
      constructor
      · intro lookup
        simp [releaseReservation] at lookup
      · rintro ⟨member, binding⟩
        have selectedInRemaining : reservation.request ∈
            remaining.map ResponseReservation.request := by
          apply List.mem_map.mpr
          exact ⟨queriedReservation, member, by simpa [requestBinding] using binding⟩
        exact False.elim (selectedAbsent selectedInRemaining)
    · constructor
      · intro lookup
        have oldLookup : budget.active queriedRequest = some queriedReservation := by
          simpa [releaseReservation, replace, sameRequest] using lookup
        rcases (accounting.activeExact queriedRequest queriedReservation).mp oldLookup with
          ⟨oldMember, binding⟩
        rw [decomposition] at oldMember
        simp only [List.mem_append, List.mem_cons] at oldMember
        rcases oldMember with inPrefix | selectedOrSuffix
        · exact ⟨by simp [remaining, inPrefix], binding⟩
        · rcases selectedOrSuffix with selected | inSuffix
          · subst queriedReservation
            exact False.elim (sameRequest (binding.symm.trans requestBinding))
          · exact ⟨by simp [remaining, inSuffix], binding⟩
      · rintro ⟨member, binding⟩
        have oldMember : queriedReservation ∈ reservations := by
          rw [decomposition]
          simp only [List.mem_append, List.mem_cons]
          rcases (List.mem_append.mp member) with inPrefix | inSuffix
          · exact Or.inl inPrefix
          · exact Or.inr (Or.inr inSuffix)
        have oldLookup := (accounting.activeExact queriedRequest queriedReservation).mpr
          ⟨oldMember, binding⟩
        simpa [releaseReservation, replace, sameRequest] using oldLookup
  · rw [releaseReservation]
    simp only
    rw [accounting.activeCountExact, decomposition]
    simp [remaining]
    omega
  · rw [releaseReservation]
    simp only
    rw [accounting.reservedBytesExact, decomposition]
    simp [remaining, totalReserved_append, totalReserved]
    omega

/-- Completion preserves exact active-map and reservation accounting. -/
theorem complete_preserves_accounting {budget : SessionBudget}
    {request : BrokerRequestId} {receivedResponseBytes : Nat}
    {reservations : List ResponseReservation}
    (accounting : Accounting budget reservations)
    (allowed : MayComplete budget request receivedResponseBytes) :
    ∃ remaining,
      Accounting (budget.complete request allowed.reservation receivedResponseBytes)
        remaining := by
  rcases releaseReservation_preserves_accounting accounting
      allowed.reservationLookup allowed.requestBinding with
    ⟨remaining, releasedAccounting⟩
  exact ⟨remaining, releasedAccounting.requestIdentitiesUnique,
    by simpa [complete] using releasedAccounting.activeExact,
    by simpa [complete] using releasedAccounting.activeCountExact,
    by simpa [complete] using releasedAccounting.reservedBytesExact⟩

/-- Abort preserves exact active-map and reservation accounting. -/
theorem abort_preserves_accounting {budget : SessionBudget}
    {request : BrokerRequestId} {reservations : List ResponseReservation}
    (accounting : Accounting budget reservations)
    (allowed : MayAbort budget request) :
    ∃ remaining,
      Accounting (budget.abort request allowed.reservation) remaining := by
  simpa [abort] using releaseReservation_preserves_accounting accounting
    allowed.reservationLookup allowed.requestBinding

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
  simp [complete, releaseReservation]

/-- Abort removes the live request identity. -/
theorem abort_removes_reservation {budget : SessionBudget}
    {request : BrokerRequestId} (allowed : MayAbort budget request) :
    (budget.abort request allowed.reservation).active request = none := by
  simp [abort, releaseReservation]

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

/-- Accepted budget transitions never replace the immutable session ceilings. -/
theorem Step.limits_immutable {before after : SessionBudget}
    (transition : Step before after) : after.limits = before.limits := by
  cases transition <;> rfl

/-- Checked budget arithmetic preserves all Rust integer representation bounds. -/
theorem Step.preserves_countersRepresentable {before after : SessionBudget}
    (transition : Step before after) (withinLimits : before.WithinLimits)
    (representable : before.CountersRepresentable) :
    after.CountersRepresentable := by
  have afterWithinLimits := transition.preserves_limits withinLimits
  have limitsSame := transition.limits_immutable
  rcases representable with
    ⟨⟨requestLimitFits, responseLimitFits, concurrentLimitFits⟩,
      _startedFits, _committedFits, _reservedFits, _activeFits⟩
  have afterRequestLimitFits : FitsU64 after.limits.maxRequests := by
    rw [limitsSame]
    exact requestLimitFits
  have afterResponseLimitFits : FitsU64 after.limits.maxResponseBytes := by
    rw [limitsSame]
    exact responseLimitFits
  have afterConcurrentLimitFits : FitsU64 after.limits.maxConcurrentRequests := by
    rw [limitsSame]
    exact concurrentLimitFits
  refine ⟨⟨afterRequestLimitFits, afterResponseLimitFits,
      afterConcurrentLimitFits⟩, ?_, ?_, ?_, ?_⟩
  · exact Nat.le_trans afterWithinLimits.1 afterRequestLimitFits
  · exact Nat.le_trans (Nat.le_add_right _ _) <|
      Nat.le_trans afterWithinLimits.2.1 afterResponseLimitFits
  · exact Nat.le_trans (Nat.le_add_left _ _) <|
      Nat.le_trans afterWithinLimits.2.1 afterResponseLimitFits
  · exact Nat.le_trans afterWithinLimits.2.2 afterConcurrentLimitFits

/-- Exact reservation accounting is inductive across every accepted budget step. -/
theorem Step.preserves_accounting {before after : SessionBudget}
    (transition : Step before after) (accounted : before.FullyAccounted) :
    after.FullyAccounted := by
  rcases accounted with ⟨reservations, accounting⟩
  cases transition with
  | start allowed =>
      exact ⟨_, start_preserves_accounting accounting allowed⟩
  | complete allowed =>
      exact complete_preserves_accounting accounting allowed
  | abort allowed =>
      exact abort_preserves_accounting accounting allowed

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

/-- Arbitrary accepted budget executions keep every counter representable. -/
theorem Steps.preserve_countersRepresentable {before after : SessionBudget}
    (execution : Steps before after) (withinLimits : before.WithinLimits)
    (representable : before.CountersRepresentable) :
    after.CountersRepresentable := by
  induction execution with
  | refl => exact representable
  | next firstStep remainingSteps inductionResult =>
      exact inductionResult (firstStep.preserves_limits withinLimits)
        (firstStep.preserves_countersRepresentable withinLimits representable)

/-- Exact reservation accounting survives an arbitrary accepted execution. -/
theorem Steps.preserves_accounting {before after : SessionBudget}
    (execution : Steps before after) (accounted : before.FullyAccounted) :
    after.FullyAccounted := by
  induction execution with
  | refl => exact accounted
  | next firstStep remainingSteps inductionResult =>
      exact inductionResult (firstStep.preserves_accounting accounted)

end SessionBudget

end Authority
