import Authority.Egress

/-!
# Composed Egress Broker State Machine

Composition of replay binding, retryable budget admission, reservation release,
terminal outcome caching, and one external effect bit. This distinguishes a
retryable exact duplicate from a terminal exact duplicate.
-/

namespace Authority

/-- Opaque receipt retained after one committed broker effect. -/
structure BrokerEffectReceipt where
  value : Nat
  deriving Repr, DecidableEq

/-- Cached outcome controlling exact-duplicate behavior. -/
inductive BrokerOutcome where
  | retryableBudget (maximumResponseBytes : Nat)
  | pending
  | effectLinearized (receipt : BrokerEffectReceipt)
  | finalDenied
  | accountingInvariant
  | committedButUnrecorded
  | committed (receipt : BrokerEffectReceipt)
  deriving Repr, DecidableEq

namespace BrokerOutcome

/-- Terminal outcomes can never re-enter dispatch. -/
def Terminal : BrokerOutcome → Prop
  | .finalDenied | .accountingInvariant | .committedButUnrecorded | .committed _ => True
  | .retryableBudget _ | .pending | .effectLinearized _ => False

end BrokerOutcome

/-- Replay, budget, cache, and external effect at one dispatch boundary. -/
structure BrokerState where
  replay : ReplayState
  budget : SessionBudget
  outcomes : BrokerRequestId → Option BrokerOutcome
  effects : BrokerRequestId → Bool

namespace BrokerState

/-- Fresh broker state with no accepted request. -/
def empty (session : BrokerSessionId) (capacity : Nat)
    (limits : SessionBudgetLimits) : BrokerState where
  replay := .empty session capacity
  budget := .empty limits
  outcomes := fun _ => none
  effects := fun _ => false

/-- Cache one outcome without touching replay or budget state. -/
def storeOutcome (state : BrokerState) (request : BrokerRequestId)
    (outcome : BrokerOutcome) : BrokerState :=
  { state with outcomes := replace state.outcomes request (some outcome) }

/-- Budget admission can fail transiently only behind live reservations. -/
inductive RetryableStartDenial (budget : SessionBudget)
    (request : BrokerRequestId) (maximumResponseBytes : Nat) : Prop
  | concurrencyLimit :
      budget.active request = none →
      budget.startedRequests < budget.limits.maxRequests →
      budget.limits.maxConcurrentRequests ≤ budget.activeRequests →
      RetryableStartDenial budget request maximumResponseBytes
  | responseBytesReserved :
      budget.active request = none →
      budget.startedRequests < budget.limits.maxRequests →
      budget.activeRequests < budget.limits.maxConcurrentRequests →
      budget.limits.maxResponseBytes <
        budget.committedResponseBytes + budget.reservedResponseBytes + maximumResponseBytes →
      0 < budget.reservedResponseBytes →
      RetryableStartDenial budget request maximumResponseBytes

/-- Permanent admission failures can never become valid after reservations drain. -/
inductive PermanentStartDenial (budget : SessionBudget)
    (request : BrokerRequestId) (maximumResponseBytes : Nat) : Prop
  | reservationAlreadyActive : budget.active request ≠ none →
      PermanentStartDenial budget request maximumResponseBytes
  | requestCountExhausted :
      budget.active request = none →
      budget.limits.maxRequests ≤ budget.startedRequests →
      PermanentStartDenial budget request maximumResponseBytes
  | responseBytesExhausted :
      budget.active request = none →
      budget.startedRequests < budget.limits.maxRequests →
      budget.activeRequests < budget.limits.maxConcurrentRequests →
      budget.limits.maxResponseBytes <
        budget.committedResponseBytes + budget.reservedResponseBytes + maximumResponseBytes →
      budget.reservedResponseBytes = 0 →
      PermanentStartDenial budget request maximumResponseBytes

/-- A transient denial and successful admission cannot both describe one state. -/
theorem RetryableStartDenial.excludes_start {budget : SessionBudget}
    {request : BrokerRequestId} {maximumResponseBytes : Nat}
    (denial : RetryableStartDenial budget request maximumResponseBytes) :
    ¬ budget.MayStart request maximumResponseBytes := by
  intro allowed
  cases denial with
  | concurrencyLimit _ _ exhausted =>
      exact (Nat.not_lt_of_ge exhausted) allowed.concurrencyAvailable
  | responseBytesReserved _ _ _ exhausted _ =>
      exact (Nat.not_le_of_lt exhausted) allowed.bytesAvailable

/-- A permanent denial and successful admission cannot both describe one state. -/
theorem PermanentStartDenial.excludes_start {budget : SessionBudget}
    {request : BrokerRequestId} {maximumResponseBytes : Nat}
    (denial : PermanentStartDenial budget request maximumResponseBytes) :
    ¬ budget.MayStart request maximumResponseBytes := by
  intro allowed
  cases denial with
  | reservationAlreadyActive active => exact active allowed.requestInactive
  | requestCountExhausted _ exhausted =>
      exact (Nat.not_lt_of_ge exhausted) allowed.requestAvailable
  | responseBytesExhausted _ _ _ exhausted _ =>
      exact (Nat.not_le_of_lt exhausted) allowed.bytesAvailable

/-- Retryable and permanent budget denials are mutually exclusive. -/
theorem RetryableStartDenial.not_permanent {budget : SessionBudget}
    {request : BrokerRequestId} {maximumResponseBytes : Nat}
    (retryable : RetryableStartDenial budget request maximumResponseBytes) :
    ¬ PermanentStartDenial budget request maximumResponseBytes := by
  intro permanent
  cases retryable with
  | concurrencyLimit inactive requestAvailable concurrencyExhausted =>
      cases permanent with
      | reservationAlreadyActive active => exact active inactive
      | requestCountExhausted _ requestExhausted => omega
      | responseBytesExhausted _ _ concurrencyAvailable _ _ => omega
  | responseBytesReserved inactive requestAvailable concurrencyAvailable _ reserved =>
      cases permanent with
      | reservationAlreadyActive active => exact active inactive
      | requestCountExhausted _ requestExhausted => omega
      | responseBytesExhausted _ _ _ _ noReserved => omega

/-- Every failed budget admission has exactly one retryability class. -/
theorem start_denial_complete {budget : SessionBudget}
    {request : BrokerRequestId} {maximumResponseBytes : Nat}
    (notAllowed : ¬ budget.MayStart request maximumResponseBytes) :
    RetryableStartDenial budget request maximumResponseBytes ∨
      PermanentStartDenial budget request maximumResponseBytes := by
  by_cases inactive : budget.active request = none
  · by_cases requestAvailable : budget.startedRequests < budget.limits.maxRequests
    · by_cases concurrencyAvailable :
        budget.activeRequests < budget.limits.maxConcurrentRequests
      · by_cases bytesAvailable : budget.committedResponseBytes +
          budget.reservedResponseBytes + maximumResponseBytes ≤
          budget.limits.maxResponseBytes
        · exact False.elim (notAllowed ⟨inactive, requestAvailable,
            concurrencyAvailable, bytesAvailable⟩)
        · have bytesExhausted : budget.limits.maxResponseBytes <
              budget.committedResponseBytes + budget.reservedResponseBytes +
                maximumResponseBytes := Nat.lt_of_not_ge bytesAvailable
          by_cases reserved : 0 < budget.reservedResponseBytes
          · exact Or.inl (.responseBytesReserved inactive requestAvailable
              concurrencyAvailable bytesExhausted reserved)
          · exact Or.inr (.responseBytesExhausted inactive requestAvailable
              concurrencyAvailable bytesExhausted (Nat.eq_zero_of_not_pos reserved))
      · exact Or.inl (.concurrencyLimit inactive requestAvailable
          (Nat.le_of_not_gt concurrencyAvailable))
    · exact Or.inr (.requestCountExhausted inactive
        (Nat.le_of_not_gt requestAvailable))
  · exact Or.inr (.reservationAlreadyActive inactive)

/-- Failed admission is equivalent to a retryable or permanent denial. -/
theorem not_mayStart_iff_denied {budget : SessionBudget}
    {request : BrokerRequestId} {maximumResponseBytes : Nat} :
    ¬ budget.MayStart request maximumResponseBytes ↔
      RetryableStartDenial budget request maximumResponseBytes ∨
        PermanentStartDenial budget request maximumResponseBytes := by
  constructor
  · exact start_denial_complete
  · rintro (retryable | permanent)
    · exact retryable.excludes_start
    · exact permanent.excludes_start

/-- Accept a new replay binding and cache a retryable budget denial. -/
def acceptRetryable (state : BrokerState) (envelope : BrokerEnvelope)
    (maximumResponseBytes : Nat) : BrokerState :=
  { state with
    replay := state.replay.acceptNew envelope
    outcomes := replace state.outcomes envelope.request
      (some (.retryableBudget maximumResponseBytes)) }

/-- Accept a new replay binding and cache a permanent budget denial. -/
def acceptFinalDenied (state : BrokerState) (envelope : BrokerEnvelope) : BrokerState :=
  { state with
    replay := state.replay.acceptNew envelope
    outcomes := replace state.outcomes envelope.request (some .finalDenied) }

/-- Replace a retryable cache entry after a later permanent budget denial. -/
def retryFinalDenied (state : BrokerState) (request : BrokerRequestId) : BrokerState :=
  state.storeOutcome request .finalDenied

/-- Accept a new binding while consuming one budget reservation. -/
def acceptAndStart (state : BrokerState) (envelope : BrokerEnvelope)
    (maximumResponseBytes : Nat) : BrokerState :=
  { state with
    replay := state.replay.acceptNew envelope
    budget := state.budget.start envelope.request maximumResponseBytes
    outcomes := replace state.outcomes envelope.request (some .pending) }

/-- A retryable exact duplicate consumes budget without changing replay state. -/
def retryStart (state : BrokerState) (request : BrokerRequestId)
    (maximumResponseBytes : Nat) : BrokerState :=
  { state with
    budget := state.budget.start request maximumResponseBytes
    outcomes := replace state.outcomes request (some .pending) }

/-- Cross the external effect boundary before local accounting is finalized. -/
def linearizeEffect (state : BrokerState) (request : BrokerRequestId)
    (receipt : BrokerEffectReceipt) : BrokerState :=
  { state with
    outcomes := replace state.outcomes request (some (.effectLinearized receipt))
    effects := replace state.effects request true }

/-- Complete accounting and cache the successful terminal outcome. -/
def recordCommit (state : BrokerState) (request : BrokerRequestId)
    (reservation : ResponseReservation) (responseBytes : Nat)
    (receipt : BrokerEffectReceipt) : BrokerState :=
  { state with
    budget := state.budget.complete request reservation responseBytes
    outcomes := replace state.outcomes request (some (.committed receipt))
  }

/-- Charge the conservative reservation when the terminal effect is uncertain. -/
def recordCommittedButUnrecorded (state : BrokerState)
    (request : BrokerRequestId) (reservation : ResponseReservation)
    (responseBytes : Nat) : BrokerState :=
  { state with
    budget := state.budget.complete request reservation responseBytes
    outcomes := replace state.outcomes request (some .committedButUnrecorded) }

/-- Fail closed when even post-effect accounting cannot be recorded. -/
def abortAfterEffect (state : BrokerState) (request : BrokerRequestId)
    (reservation : ResponseReservation) : BrokerState :=
  { state with
    budget := state.budget.abort request reservation
    outcomes := replace state.outcomes request (some .accountingInvariant) }

/-- Abort one pending reservation and cache a terminal denial. -/
def deny (state : BrokerState) (request : BrokerRequestId)
    (reservation : ResponseReservation) : BrokerState :=
  { state with
    budget := state.budget.abort request reservation
    outcomes := replace state.outcomes request (some .finalDenied) }

/-- The replay guard contains one immutable binding for this request identity. -/
def HasReplayBinding (state : BrokerState) (request : BrokerRequestId) : Prop :=
  ∃ record, state.replay.accepted request = some record

/-- The budget contains one correctly keyed live reservation. -/
def HasActiveReservation (state : BrokerState) (request : BrokerRequestId) : Prop :=
  ∃ reservation, state.budget.active request = some reservation ∧
    reservation.request = request

/-- No external effect is waiting for its reservation to be settled. -/
def AccountingClear (state : BrokerState) : Prop :=
  ∀ request receipt,
    state.outcomes request ≠ some (.effectLinearized receipt)

/-- Every effect awaiting accounting belongs to the selected synchronous dispatch. -/
def AccountingTurn (state : BrokerState) (request : BrokerRequestId) : Prop :=
  ∀ other receipt,
    state.outcomes other = some (.effectLinearized receipt) → other = request

/-- Per-request coupling between replay, cache, reservation, and effect views. -/
def RequestCoupled (state : BrokerState) (request : BrokerRequestId) : Prop :=
  match state.outcomes request with
  | none => state.replay.accepted request = none ∧
      state.budget.active request = none ∧ state.effects request = false
  | some (.retryableBudget _) => state.HasReplayBinding request ∧
      state.budget.active request = none ∧ state.effects request = false
  | some .pending => state.HasReplayBinding request ∧
      state.HasActiveReservation request ∧ state.effects request = false
  | some (.effectLinearized _) => state.HasReplayBinding request ∧
      state.HasActiveReservation request ∧ state.effects request = true
  | some .finalDenied => state.HasReplayBinding request ∧
      state.budget.active request = none ∧ state.effects request = false
  | some .accountingInvariant => state.HasReplayBinding request ∧
      state.budget.active request = none ∧ state.effects request = true
  | some .committedButUnrecorded => state.HasReplayBinding request ∧
      state.budget.active request = none ∧ state.effects request = true
  | some (.committed _) => state.HasReplayBinding request ∧
      state.budget.active request = none ∧ state.effects request = true

/-- Exact finite accounting and all broker views agree request by request. -/
structure WellFormed (state : BrokerState) : Prop where
  replayWellFormed : state.replay.WellFormed
  replayAccounted : state.replay.FullyAccounted
  budgetAccounted : state.budget.FullyAccounted
  budgetWithinLimits : state.budget.WithinLimits
  budgetCountersRepresentable : state.budget.CountersRepresentable
  positiveLimits : 0 < state.budget.limits.maxRequests ∧
    0 < state.budget.limits.maxConcurrentRequests
  requestCoupled : ∀ request, state.RequestCoupled request

/-- The empty broker state satisfies every composed invariant. -/
theorem empty_wellFormed (session : BrokerSessionId) (capacity : Nat)
    {limits : SessionBudgetLimits}
    (representable : SessionBudget.LimitsRepresentable limits)
    (positive : 0 < limits.maxRequests ∧ 0 < limits.maxConcurrentRequests) :
    (empty session capacity limits).WellFormed := by
  refine ⟨ReplayState.empty_wellFormed session capacity,
    ⟨[], ReplayState.empty_accounting session capacity⟩,
    ⟨[], SessionBudget.empty_accounting limits⟩,
    SessionBudget.empty_withinLimits limits,
    SessionBudget.empty_countersRepresentable representable, positive, ?_⟩
  intro request
  simp [RequestCoupled, BrokerState.empty, ReplayState.empty, SessionBudget.empty]

/-- Fresh broker state has no effect awaiting synchronous accounting. -/
theorem empty_accountingClear (session : BrokerSessionId) (capacity : Nat)
    (limits : SessionBudgetLimits) :
    (empty session capacity limits).AccountingClear := by
  simp [AccountingClear, BrokerState.empty]

/-- Accepted composed broker transitions. -/
inductive Step : BrokerState → BrokerState → Prop
  | acceptRetryable {state : BrokerState} {envelope : BrokerEnvelope}
      {maximumResponseBytes : Nat} :
      state.AccountingClear →
      state.replay.MayAcceptNew envelope →
      state.outcomes envelope.request = none →
      RetryableStartDenial state.budget envelope.request maximumResponseBytes →
      FitsU64 maximumResponseBytes →
      Step state (state.acceptRetryable envelope maximumResponseBytes)
  | acceptFinalDenied {state : BrokerState} {envelope : BrokerEnvelope}
      {maximumResponseBytes : Nat} :
      state.AccountingClear →
      state.replay.MayAcceptNew envelope →
      state.outcomes envelope.request = none →
      PermanentStartDenial state.budget envelope.request maximumResponseBytes →
      FitsU64 maximumResponseBytes →
      Step state (state.acceptFinalDenied envelope)
  | acceptAndStart {state : BrokerState} {envelope : BrokerEnvelope}
      {maximumResponseBytes : Nat} :
      state.AccountingClear →
      state.replay.MayAcceptNew envelope →
      state.outcomes envelope.request = none →
      state.budget.MayStart envelope.request maximumResponseBytes →
      Step state (state.acceptAndStart envelope maximumResponseBytes)
  | retryStart {state : BrokerState} {envelope : BrokerEnvelope}
      {maximumResponseBytes : Nat} :
      state.AccountingClear →
      state.replay.ExactDuplicate envelope →
      state.outcomes envelope.request = some (.retryableBudget maximumResponseBytes) →
      state.budget.MayStart envelope.request maximumResponseBytes →
      Step state (state.retryStart envelope.request maximumResponseBytes)
  | retryFinalDenied {state : BrokerState} {envelope : BrokerEnvelope}
      {maximumResponseBytes : Nat} :
      state.AccountingClear →
      state.replay.ExactDuplicate envelope →
      state.outcomes envelope.request = some (.retryableBudget maximumResponseBytes) →
      PermanentStartDenial state.budget envelope.request maximumResponseBytes →
      FitsU64 maximumResponseBytes →
      Step state (state.retryFinalDenied envelope.request)
  | linearizeEffect {state : BrokerState} {request : BrokerRequestId}
      {receipt : BrokerEffectReceipt} :
      state.AccountingClear →
      state.outcomes request = some .pending →
      state.effects request = false →
      Step state (state.linearizeEffect request receipt)
  | recordCommit {state : BrokerState} {request : BrokerRequestId}
      {responseBytes : Nat} {receipt : BrokerEffectReceipt} :
      state.outcomes request = some (.effectLinearized receipt) →
      state.AccountingTurn request →
      (allowed : state.budget.MayComplete request responseBytes) →
      Step state (state.recordCommit request allowed.reservation responseBytes receipt)
  | recordCommittedButUnrecorded {state : BrokerState}
      {request : BrokerRequestId} {receipt : BrokerEffectReceipt}
      {responseBytes : Nat} :
      state.outcomes request = some (.effectLinearized receipt) →
      state.AccountingTurn request →
      (allowed : state.budget.MayComplete request responseBytes) →
      responseBytes = allowed.reservation.maxResponseBytes →
      Step state (state.recordCommittedButUnrecorded request allowed.reservation responseBytes)
  | abortAfterEffect {state : BrokerState} {request : BrokerRequestId}
      {receipt : BrokerEffectReceipt} :
      state.outcomes request = some (.effectLinearized receipt) →
      state.AccountingTurn request →
      (allowed : state.budget.MayAbort request) →
      Step state (state.abortAfterEffect request allowed.reservation)
  | deny {state : BrokerState} {request : BrokerRequestId} :
      state.AccountingClear →
      state.outcomes request = some .pending →
      (allowed : state.budget.MayAbort request) →
      Step state (state.deny request allowed.reservation)
  | terminalDuplicate {state : BrokerState} {envelope : BrokerEnvelope}
      {outcome : BrokerOutcome} :
      state.AccountingClear →
      state.replay.ExactDuplicate envelope →
      state.outcomes envelope.request = some outcome → outcome.Terminal →
      Step state state

/-- Linearization selects the only request that may take the accounting turn. -/
theorem linearizeEffect_starts_accounting_turn (state : BrokerState)
    (request : BrokerRequestId) (receipt : BrokerEffectReceipt)
    (accountingClear : state.AccountingClear) :
    (state.linearizeEffect request receipt).AccountingTurn request := by
  intro other otherReceipt linearized
  by_cases sameRequest : other = request
  · exact sameRequest
  · have prior : state.outcomes other = some (.effectLinearized otherReceipt) := by
      simpa [BrokerState.linearizeEffect, replace, sameRequest] using linearized
    exact False.elim (accountingClear other otherReceipt prior)

/-- A linearized effect forces the next step to settle that same dispatch. -/
theorem Step.effectLinearized_settles_next {before after : BrokerState}
    (transition : Step before after) {request : BrokerRequestId}
    {receipt : BrokerEffectReceipt}
    (linearized : before.outcomes request = some (.effectLinearized receipt)) :
    after.AccountingClear ∧
      (after.outcomes request = some (.committed receipt) ∨
        after.outcomes request = some .committedButUnrecorded ∨
        after.outcomes request = some .accountingInvariant) := by
  cases transition with
  | acceptRetryable accountingClear | acceptFinalDenied accountingClear |
      acceptAndStart accountingClear | retryStart accountingClear |
      retryFinalDenied accountingClear | linearizeEffect accountingClear |
      deny accountingClear | terminalDuplicate accountingClear =>
      exact False.elim (accountingClear request receipt linearized)
  | recordCommit cached accountingTurn allowed =>
      rename_i settledRequest responseBytes settledReceipt
      have sameRequest : request = settledRequest :=
        accountingTurn request receipt linearized
      subst settledRequest
      have sameReceipt : receipt = settledReceipt := by
        have sameOutcome := Option.some.inj (linearized.symm.trans cached)
        exact BrokerOutcome.effectLinearized.inj sameOutcome
      subst settledReceipt
      constructor
      · intro other otherReceipt afterLinearized
        by_cases sameOther : other = request
        · subst other
          simp [BrokerState.recordCommit] at afterLinearized
        · have prior : before.outcomes other =
              some (.effectLinearized otherReceipt) := by
            simpa [BrokerState.recordCommit, replace, sameOther] using afterLinearized
          exact sameOther (accountingTurn other otherReceipt prior)
      · exact Or.inl (by simp [BrokerState.recordCommit])
  | recordCommittedButUnrecorded cached accountingTurn allowed exactCharge =>
      rename_i settledRequest settledReceipt responseBytes
      have sameRequest : request = settledRequest :=
        accountingTurn request receipt linearized
      subst settledRequest
      constructor
      · intro other otherReceipt afterLinearized
        by_cases sameOther : other = request
        · subst other
          simp [BrokerState.recordCommittedButUnrecorded] at afterLinearized
        · have prior : before.outcomes other =
              some (.effectLinearized otherReceipt) := by
            simpa [BrokerState.recordCommittedButUnrecorded, replace, sameOther]
              using afterLinearized
          exact sameOther (accountingTurn other otherReceipt prior)
      · exact Or.inr (Or.inl (by simp [BrokerState.recordCommittedButUnrecorded]))
  | abortAfterEffect cached accountingTurn allowed =>
      rename_i settledRequest settledReceipt
      have sameRequest : request = settledRequest :=
        accountingTurn request receipt linearized
      subst settledRequest
      constructor
      · intro other otherReceipt afterLinearized
        by_cases sameOther : other = request
        · subst other
          simp [BrokerState.abortAfterEffect] at afterLinearized
        · have prior : before.outcomes other =
              some (.effectLinearized otherReceipt) := by
            simpa [BrokerState.abortAfterEffect, replace, sameOther] using afterLinearized
          exact sameOther (accountingTurn other otherReceipt prior)
      · exact Or.inr (Or.inr (by simp [BrokerState.abortAfterEffect]))

/-- One accepted transition preserves replay/cache/reservation/effect coupling. -/
theorem Step.preserves_requestCoupling {before after : BrokerState}
    (transition : Step before after)
    (coupled : ∀ request, before.RequestCoupled request) :
    ∀ request, after.RequestCoupled request := by
  intro request
  cases transition with
  | acceptRetryable accountingClear replayAllowed cacheFresh denial representable =>
      rename_i envelope maximumResponseBytes
      by_cases sameRequest : request = envelope.request
      · subst request
        have prior := coupled envelope.request
        simp only [RequestCoupled] at prior
        rw [cacheFresh] at prior
        simp only [RequestCoupled, BrokerState.acceptRetryable, replace_selected]
        exact ⟨⟨_, ReplayState.acceptNew_stores_exact_binding before.replay envelope⟩,
          prior.2.1, prior.2.2⟩
      · simpa [RequestCoupled, HasReplayBinding, HasActiveReservation,
          BrokerState.acceptRetryable, ReplayState.acceptNew, replace, sameRequest]
          using coupled request
  | acceptFinalDenied accountingClear replayAllowed cacheFresh denial representable =>
      rename_i envelope maximumResponseBytes
      by_cases sameRequest : request = envelope.request
      · subst request
        have prior := coupled envelope.request
        simp only [RequestCoupled] at prior
        rw [cacheFresh] at prior
        simp only [RequestCoupled, BrokerState.acceptFinalDenied, replace_selected]
        exact ⟨⟨_, ReplayState.acceptNew_stores_exact_binding before.replay envelope⟩,
          prior.2.1, prior.2.2⟩
      · simpa [RequestCoupled, HasReplayBinding, HasActiveReservation,
          BrokerState.acceptFinalDenied, ReplayState.acceptNew, replace, sameRequest]
          using coupled request
  | acceptAndStart accountingClear replayAllowed cacheFresh budgetAllowed =>
      rename_i envelope maximumResponseBytes
      by_cases sameRequest : request = envelope.request
      · subst request
        have prior := coupled envelope.request
        simp only [RequestCoupled] at prior
        rw [cacheFresh] at prior
        simp only [RequestCoupled, BrokerState.acceptAndStart, replace_selected]
        exact ⟨⟨_, ReplayState.acceptNew_stores_exact_binding before.replay envelope⟩,
          ⟨_, SessionBudget.start_stores_exact_reservation before.budget
            envelope.request maximumResponseBytes, rfl⟩, prior.2.2⟩
      · simpa [RequestCoupled, HasReplayBinding, HasActiveReservation,
          BrokerState.acceptAndStart, ReplayState.acceptNew, SessionBudget.start,
          replace, sameRequest] using coupled request
  | retryStart accountingClear duplicate retryable budgetAllowed =>
      rename_i envelope maximumResponseBytes
      by_cases sameRequest : request = envelope.request
      · subst request
        have prior := coupled envelope.request
        simp only [RequestCoupled] at prior
        rw [retryable] at prior
        simp only [RequestCoupled, BrokerState.retryStart, replace_selected]
        exact ⟨prior.1,
          ⟨_, SessionBudget.start_stores_exact_reservation before.budget
            envelope.request maximumResponseBytes, rfl⟩, prior.2.2⟩
      · simpa [RequestCoupled, HasReplayBinding, HasActiveReservation,
          BrokerState.retryStart, SessionBudget.start, replace, sameRequest]
          using coupled request
  | retryFinalDenied accountingClear duplicate retryable denial representable =>
      rename_i envelope maximumResponseBytes
      by_cases sameRequest : request = envelope.request
      · subst request
        have prior := coupled envelope.request
        simp only [RequestCoupled] at prior
        rw [retryable] at prior
        simp only [RequestCoupled, BrokerState.retryFinalDenied,
          BrokerState.storeOutcome, replace_selected]
        exact prior
      · simpa [RequestCoupled, HasReplayBinding, HasActiveReservation,
          BrokerState.retryFinalDenied, BrokerState.storeOutcome, replace, sameRequest]
          using coupled request
  | linearizeEffect accountingClear pending noEffect =>
      rename_i effectRequest receipt
      by_cases sameRequest : request = effectRequest
      · subst request
        have prior := coupled effectRequest
        simp only [RequestCoupled] at prior
        rw [pending] at prior
        simp only [RequestCoupled, BrokerState.linearizeEffect, replace_selected]
        exact ⟨prior.1, prior.2.1, by simp [BrokerState.linearizeEffect]⟩
      · simpa [RequestCoupled, HasReplayBinding, HasActiveReservation,
          BrokerState.linearizeEffect, replace, sameRequest] using coupled request
  | recordCommit linearized accountingTurn allowed =>
      rename_i committedRequest responseBytes receipt
      by_cases sameRequest : request = committedRequest
      · subst request
        have prior := coupled committedRequest
        simp only [RequestCoupled] at prior
        rw [linearized] at prior
        simp only [RequestCoupled, BrokerState.recordCommit, replace_selected]
        exact ⟨prior.1, SessionBudget.complete_removes_reservation allowed,
          prior.2.2⟩
      · simpa [RequestCoupled, HasReplayBinding, HasActiveReservation,
          BrokerState.recordCommit, SessionBudget.complete,
          SessionBudget.releaseReservation, replace, sameRequest] using coupled request
  | recordCommittedButUnrecorded linearized accountingTurn allowed exactCharge =>
      rename_i committedRequest receipt responseBytes
      by_cases sameRequest : request = committedRequest
      · subst request
        have prior := coupled committedRequest
        simp only [RequestCoupled] at prior
        rw [linearized] at prior
        simp only [RequestCoupled, BrokerState.recordCommittedButUnrecorded,
          replace_selected]
        exact ⟨prior.1, SessionBudget.complete_removes_reservation allowed,
          prior.2.2⟩
      · simpa [RequestCoupled, HasReplayBinding, HasActiveReservation,
          BrokerState.recordCommittedButUnrecorded, SessionBudget.complete,
          SessionBudget.releaseReservation, replace, sameRequest] using coupled request
  | abortAfterEffect linearized accountingTurn allowed =>
      rename_i committedRequest receipt
      by_cases sameRequest : request = committedRequest
      · subst request
        have prior := coupled committedRequest
        simp only [RequestCoupled] at prior
        rw [linearized] at prior
        simp only [RequestCoupled, BrokerState.abortAfterEffect, replace_selected]
        exact ⟨prior.1, SessionBudget.abort_removes_reservation allowed,
          prior.2.2⟩
      · simpa [RequestCoupled, HasReplayBinding, HasActiveReservation,
          BrokerState.abortAfterEffect, SessionBudget.abort,
          SessionBudget.releaseReservation, replace, sameRequest] using coupled request
  | deny accountingClear pending allowed =>
      rename_i deniedRequest
      by_cases sameRequest : request = deniedRequest
      · subst request
        have prior := coupled deniedRequest
        simp only [RequestCoupled] at prior
        rw [pending] at prior
        simp only [RequestCoupled, BrokerState.deny, replace_selected]
        exact ⟨prior.1, SessionBudget.abort_removes_reservation allowed,
          prior.2.2⟩
      · simpa [RequestCoupled, HasReplayBinding, HasActiveReservation,
          BrokerState.deny, SessionBudget.abort, SessionBudget.releaseReservation,
          replace, sameRequest] using coupled request
  | terminalDuplicate => exact coupled request

/-- A committed transition stores both the terminal receipt and effect bit. -/
theorem linearizeEffect_stores_effect (state : BrokerState)
    (request : BrokerRequestId) (receipt : BrokerEffectReceipt) :
    (state.linearizeEffect request receipt).outcomes request =
      some (.effectLinearized receipt) ∧
    (state.linearizeEffect request receipt).effects request = true := by
  simp [BrokerState.linearizeEffect]

/-- Terminal exact duplicates are accepted only as a state-preserving step. -/
theorem terminal_duplicate_is_noop {state : BrokerState} {envelope : BrokerEnvelope}
    {outcome : BrokerOutcome}
    (accountingClear : state.AccountingClear)
    (duplicate : state.replay.ExactDuplicate envelope)
    (cached : state.outcomes envelope.request = some outcome)
    (terminal : outcome.Terminal) : Step state state :=
  .terminalDuplicate accountingClear duplicate cached terminal

/-- Once an effect committed, no accepted transition can clear it. -/
theorem Step.effect_persists {before after : BrokerState}
    (transition : Step before after) {request : BrokerRequestId}
    (effect : before.effects request = true) : after.effects request = true := by
  cases transition with
  | acceptRetryable | acceptFinalDenied | acceptAndStart | retryStart |
      retryFinalDenied | deny | terminalDuplicate => exact effect
  | linearizeEffect accountingClear pending noEffect =>
      rename_i committedRequest receipt
      by_cases sameRequest : request = committedRequest
      · subst request
        simp [BrokerState.linearizeEffect]
      · simpa [BrokerState.linearizeEffect, replace, sameRequest] using effect
  | recordCommit | recordCommittedButUnrecorded | abortAfterEffect => exact effect

/-- A terminal cached outcome is immutable across every accepted transition. -/
theorem Step.terminal_outcome_immutable {before after : BrokerState}
    (transition : Step before after) {request : BrokerRequestId}
    {outcome : BrokerOutcome} (cached : before.outcomes request = some outcome)
    (terminal : outcome.Terminal) : after.outcomes request = some outcome := by
  cases transition with
  | acceptRetryable accountingClear replayAllowed cacheFresh denial representable =>
      rename_i envelope maximumResponseBytes
      have differentRequest : request ≠ envelope.request := by
        intro sameRequest
        subst request
        rw [cached] at cacheFresh
        cases cacheFresh
      simpa [BrokerState.acceptRetryable, replace, differentRequest] using cached
  | acceptFinalDenied accountingClear replayAllowed cacheFresh denial representable =>
      rename_i envelope maximumResponseBytes
      have differentRequest : request ≠ envelope.request := by
        intro sameRequest
        subst request
        rw [cached] at cacheFresh
        cases cacheFresh
      simpa [BrokerState.acceptFinalDenied, replace, differentRequest] using cached
  | acceptAndStart accountingClear replayAllowed cacheFresh budgetAllowed =>
      rename_i envelope maximumResponseBytes
      have differentRequest : request ≠ envelope.request := by
        intro sameRequest
        subst request
        rw [cached] at cacheFresh
        cases cacheFresh
      simpa [BrokerState.acceptAndStart, replace, differentRequest] using cached
  | retryStart accountingClear duplicate retryable budgetAllowed =>
      rename_i envelope maximumResponseBytes
      have differentRequest : request ≠ envelope.request := by
        intro sameRequest
        subst request
        have sameOutcome := Option.some.inj (cached.symm.trans retryable)
        subst outcome
        simp [BrokerOutcome.Terminal] at terminal
      simpa [BrokerState.retryStart, replace, differentRequest] using cached
  | retryFinalDenied accountingClear duplicate retryable denial representable =>
      rename_i envelope maximumResponseBytes
      have differentRequest : request ≠ envelope.request := by
        intro sameRequest
        subst request
        have sameOutcome := Option.some.inj (cached.symm.trans retryable)
        subst outcome
        simp [BrokerOutcome.Terminal] at terminal
      simpa [BrokerState.retryFinalDenied, BrokerState.storeOutcome, replace,
        differentRequest] using cached
  | linearizeEffect accountingClear pending noEffect =>
      rename_i committedRequest receipt
      have differentRequest : request ≠ committedRequest := by
        intro sameRequest
        subst request
        have sameOutcome := Option.some.inj (cached.symm.trans pending)
        subst outcome
        simp [BrokerOutcome.Terminal] at terminal
      simpa [BrokerState.linearizeEffect, replace, differentRequest] using cached
  | recordCommit linearized accountingTurn allowed =>
      rename_i committedRequest responseBytes receipt
      have differentRequest : request ≠ committedRequest := by
        intro sameRequest
        subst request
        have sameOutcome := Option.some.inj (cached.symm.trans linearized)
        subst outcome
        simp [BrokerOutcome.Terminal] at terminal
      simpa [BrokerState.recordCommit, replace, differentRequest] using cached
  | recordCommittedButUnrecorded linearized accountingTurn allowed exactCharge =>
      rename_i committedRequest receipt responseBytes
      have differentRequest : request ≠ committedRequest := by
        intro sameRequest
        subst request
        have sameOutcome := Option.some.inj (cached.symm.trans linearized)
        subst outcome
        simp [BrokerOutcome.Terminal] at terminal
      simpa [BrokerState.recordCommittedButUnrecorded, replace, differentRequest] using cached
  | abortAfterEffect linearized accountingTurn allowed =>
      rename_i committedRequest receipt
      have differentRequest : request ≠ committedRequest := by
        intro sameRequest
        subst request
        have sameOutcome := Option.some.inj (cached.symm.trans linearized)
        subst outcome
        simp [BrokerOutcome.Terminal] at terminal
      simpa [BrokerState.abortAfterEffect, replace, differentRequest] using cached
  | deny accountingClear pending allowed =>
      rename_i deniedRequest
      have differentRequest : request ≠ deniedRequest := by
        intro sameRequest
        subst request
        have sameOutcome := Option.some.inj (cached.symm.trans pending)
        subst outcome
        simp [BrokerOutcome.Terminal] at terminal
      simpa [BrokerState.deny, replace, differentRequest] using cached
  | terminalDuplicate => exact cached

/-- Replay finite accounting survives every composed broker transition. -/
theorem Step.preserves_replay_wellFormed {before after : BrokerState}
    (transition : Step before after) (wellFormed : before.replay.WellFormed) :
    after.replay.WellFormed := by
  cases transition with
  | acceptRetryable _ replayAllowed _ _ _ | acceptFinalDenied _ replayAllowed _ _ _ |
      acceptAndStart _ replayAllowed _ _ =>
      exact ReplayState.acceptNew_preserves_wellFormed wellFormed replayAllowed
  | retryStart | retryFinalDenied | linearizeEffect | recordCommit |
      recordCommittedButUnrecorded | abortAfterEffect | deny | terminalDuplicate =>
      exact wellFormed

/-- Replay finite accounting survives every composed broker transition. -/
theorem Step.preserves_replay_accounting {before after : BrokerState}
    (transition : Step before after) (accounted : before.replay.FullyAccounted) :
    after.replay.FullyAccounted := by
  cases transition with
  | acceptRetryable _ replayAllowed _ _ _ =>
      exact ReplayState.Step.preserves_accounting (.fresh replayAllowed) accounted
  | acceptFinalDenied _ replayAllowed _ _ _ =>
      exact ReplayState.Step.preserves_accounting (.fresh replayAllowed) accounted
  | acceptAndStart _ replayAllowed _ _ =>
      exact ReplayState.Step.preserves_accounting (.fresh replayAllowed) accounted
  | retryStart | retryFinalDenied | linearizeEffect | recordCommit |
      recordCommittedButUnrecorded | abortAfterEffect | deny | terminalDuplicate => exact accounted

/-- Budget finite accounting survives every composed broker transition. -/
theorem Step.preserves_budget_accounting {before after : BrokerState}
    (transition : Step before after) (accounted : before.budget.FullyAccounted) :
    after.budget.FullyAccounted := by
  cases transition with
  | acceptRetryable | acceptFinalDenied | retryFinalDenied | linearizeEffect |
      terminalDuplicate => exact accounted
  | acceptAndStart _ _ _ budgetAllowed =>
      exact SessionBudget.Step.preserves_accounting (.start budgetAllowed) accounted
  | retryStart _ _ _ budgetAllowed =>
      exact SessionBudget.Step.preserves_accounting (.start budgetAllowed) accounted
  | recordCommit _ _ allowed =>
      exact SessionBudget.Step.preserves_accounting (.complete allowed) accounted
  | recordCommittedButUnrecorded _ _ allowed _ =>
      exact SessionBudget.Step.preserves_accounting (.complete allowed) accounted
  | abortAfterEffect _ _ allowed =>
      exact SessionBudget.Step.preserves_accounting (.abort allowed) accounted
  | deny _ _ allowed =>
      exact SessionBudget.Step.preserves_accounting (.abort allowed) accounted

/-- Session-wide ceilings survive every composed broker transition. -/
theorem Step.preserves_budget_limits {before after : BrokerState}
    (transition : Step before after) (withinLimits : before.budget.WithinLimits) :
    after.budget.WithinLimits := by
  cases transition with
  | acceptRetryable | acceptFinalDenied | retryFinalDenied | linearizeEffect |
      terminalDuplicate => exact withinLimits
  | acceptAndStart _ _ _ allowed | retryStart _ _ _ allowed =>
      exact SessionBudget.Step.preserves_limits (.start allowed) withinLimits
  | recordCommit _ _ allowed | recordCommittedButUnrecorded _ _ allowed _ =>
      exact SessionBudget.Step.preserves_limits (.complete allowed) withinLimits
  | abortAfterEffect _ _ allowed | deny _ _ allowed =>
      exact SessionBudget.Step.preserves_limits (.abort allowed) withinLimits

/-- Checked budget transitions preserve the concrete `u64` representation boundary. -/
theorem Step.preserves_budget_countersRepresentable {before after : BrokerState}
    (transition : Step before after) (withinLimits : before.budget.WithinLimits)
    (representable : before.budget.CountersRepresentable) :
    after.budget.CountersRepresentable := by
  cases transition with
  | acceptRetryable | acceptFinalDenied | retryFinalDenied | linearizeEffect |
      terminalDuplicate => exact representable
  | acceptAndStart _ _ _ allowed | retryStart _ _ _ allowed =>
      exact SessionBudget.Step.preserves_countersRepresentable (.start allowed)
        withinLimits representable
  | recordCommit _ _ allowed | recordCommittedButUnrecorded _ _ allowed _ =>
      exact SessionBudget.Step.preserves_countersRepresentable (.complete allowed)
        withinLimits representable
  | abortAfterEffect _ _ allowed | deny _ _ allowed =>
      exact SessionBudget.Step.preserves_countersRepresentable (.abort allowed)
        withinLimits representable

/-- Broker transitions never replace immutable session ceilings. -/
theorem Step.budget_limits_immutable {before after : BrokerState}
    (transition : Step before after) : after.budget.limits = before.budget.limits := by
  cases transition <;> rfl

/-- The complete replay/budget/cache/effect invariant is inductive. -/
theorem Step.preserves_wellFormed {before after : BrokerState}
    (transition : Step before after) (wellFormed : before.WellFormed) :
    after.WellFormed :=
  ⟨transition.preserves_replay_wellFormed wellFormed.replayWellFormed,
    transition.preserves_replay_accounting wellFormed.replayAccounted,
    transition.preserves_budget_accounting wellFormed.budgetAccounted,
    transition.preserves_budget_limits wellFormed.budgetWithinLimits,
    transition.preserves_budget_countersRepresentable wellFormed.budgetWithinLimits
      wellFormed.budgetCountersRepresentable,
    by simpa [transition.budget_limits_immutable] using wellFormed.positiveLimits,
    transition.preserves_requestCoupling wellFormed.requestCoupled⟩

/-- Finite composed broker execution. -/
inductive Steps : BrokerState → BrokerState → Prop
  | refl (state : BrokerState) : Steps state state
  | tail {first middle last : BrokerState} :
      Steps first middle → Step middle last → Steps first last

/-- A committed effect bit persists through arbitrary retries and duplicates. -/
theorem Steps.effect_persists {before after : BrokerState}
    (transitions : Steps before after) {request : BrokerRequestId}
    (effect : before.effects request = true) : after.effects request = true := by
  induction transitions with
  | refl => exact effect
  | tail _ transition inductionHypothesis =>
      exact transition.effect_persists inductionHypothesis

/-- A terminal cache entry can never return to retryable or pending. -/
theorem Steps.terminal_outcome_immutable {before after : BrokerState}
    (transitions : Steps before after) {request : BrokerRequestId}
    {outcome : BrokerOutcome} (cached : before.outcomes request = some outcome)
    (terminal : outcome.Terminal) : after.outcomes request = some outcome := by
  induction transitions with
  | refl => exact cached
  | tail _ transition inductionHypothesis =>
      exact transition.terminal_outcome_immutable inductionHypothesis terminal

/-- Replay cache cardinality remains exact across arbitrary broker execution. -/
theorem Steps.preserves_replay_accounting {before after : BrokerState}
    (transitions : Steps before after) (accounted : before.replay.FullyAccounted) :
    after.replay.FullyAccounted := by
  induction transitions with
  | refl => exact accounted
  | tail _ transition inductionHypothesis =>
      exact transition.preserves_replay_accounting inductionHypothesis

/-- Active reservations and aggregate counters remain exact across arbitrary execution. -/
theorem Steps.preserves_budget_accounting {before after : BrokerState}
    (transitions : Steps before after) (accounted : before.budget.FullyAccounted) :
    after.budget.FullyAccounted := by
  induction transitions with
  | refl => exact accounted
  | tail _ transition inductionHypothesis =>
      exact transition.preserves_budget_accounting inductionHypothesis

/-- Every session-wide ceiling holds after an arbitrary broker execution. -/
theorem Steps.preserves_budget_limits {before after : BrokerState}
    (transitions : Steps before after) (withinLimits : before.budget.WithinLimits) :
    after.budget.WithinLimits := by
  induction transitions with
  | refl => exact withinLimits
  | tail _ transition inductionHypothesis =>
      exact transition.preserves_budget_limits inductionHypothesis

/-- Arbitrary broker execution preserves all concrete budget counter bounds. -/
theorem Steps.preserves_budget_countersRepresentable {before after : BrokerState}
    (transitions : Steps before after) (withinLimits : before.budget.WithinLimits)
    (representable : before.budget.CountersRepresentable) :
    after.budget.CountersRepresentable := by
  induction transitions with
  | refl => exact representable
  | tail earlier transition inductionHypothesis =>
      exact transition.preserves_budget_countersRepresentable
        (earlier.preserves_budget_limits withinLimits) inductionHypothesis

/-- Every state reachable from a well-formed broker state remains fully coupled. -/
theorem Steps.preserves_wellFormed {before after : BrokerState}
    (transitions : Steps before after) (wellFormed : before.WellFormed) :
    after.WellFormed := by
  induction transitions with
  | refl => exact wellFormed
  | tail _ transition inductionHypothesis =>
      exact transition.preserves_wellFormed inductionHypothesis

end BrokerState

end Authority
