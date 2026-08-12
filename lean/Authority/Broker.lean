import Authority.Egress

/-!
# Composed Egress Broker State Machine

Composition of replay binding, wire admission, retryable budget admission,
reservation release, canonical terminal outcome caching, and one external
effect-ambiguity bit. This distinguishes a retryable exact duplicate from a
terminal exact duplicate and models crash recovery on both sides of effect commit.
-/

namespace Authority

/-- Opaque receipt retained after one committed broker effect. -/
structure BrokerEffectReceipt where
  value : Nat
  deriving Repr, DecidableEq

/-- Opaque digest of one complete canonical response wire outcome. -/
structure CanonicalWireOutcome where
  digest : Nat
  deriving Repr, DecidableEq

/-- Operation class needed to enforce admission before an external effect. -/
inductive BrokerOperationKind where
  | publicFetch
  | githubMutation
  deriving Repr, DecidableEq

/-- The public body limit shared with `egress_protocol`'s canonical wire. -/
def maxPublicWireBodyBytes : Nat := 512 * 1024

/-- Only public responses have a control-wire body admission ceiling. -/
def WireAdmissible : BrokerOperationKind → Nat → Prop
  | .publicFetch, maximumResponseBytes =>
      maximumResponseBytes ≤ maxPublicWireBodyBytes
  | .githubMutation, _ => True

/-- The canonical wire cap is inclusive and rejects its immediate successor. -/
theorem public_wire_admission_boundary :
    WireAdmissible .publicFetch maxPublicWireBodyBytes ∧
      ¬ WireAdmissible .publicFetch (maxPublicWireBodyBytes + 1) := by
  simp [WireAdmissible]

/-- Effect evidence returned through the kernel commit callback. -/
inductive BrokerLinearizedEffect where
  | committed (receipt : BrokerEffectReceipt)
  | commitUnknown
  deriving Repr, DecidableEq

/-- Cached outcome controlling exact-duplicate behavior. -/
inductive BrokerOutcome where
  | acceptedPending (kind : BrokerOperationKind) (maximumResponseBytes : Nat)
  | retryableBudget (kind : BrokerOperationKind) (maximumResponseBytes : Nat)
  | pending (kind : BrokerOperationKind)
  | effectLinearized (effect : BrokerLinearizedEffect)
  | finalDenied (wire : CanonicalWireOutcome)
  | accountingInvariant (wire : CanonicalWireOutcome)
  | committedButUnrecorded (wire : CanonicalWireOutcome)
  | committed (receipt : BrokerEffectReceipt) (wire : CanonicalWireOutcome)
  deriving Repr, DecidableEq

namespace BrokerOutcome

/-- Terminal outcomes can never re-enter dispatch. -/
def Terminal : BrokerOutcome → Prop
  | .finalDenied _ | .accountingInvariant _ |
      .committedButUnrecorded _ | .committed _ _ => True
  | .acceptedPending _ _ | .retryableBudget _ _ |
      .pending _ | .effectLinearized _ => False

/-- A terminal cache contains the exact canonical bytes represented opaquely. -/
def wire? : BrokerOutcome → Option CanonicalWireOutcome
  | .finalDenied wire | .accountingInvariant wire |
      .committedButUnrecorded wire | .committed _ wire => some wire
  | .acceptedPending _ _ | .retryableBudget _ _ |
      .pending _ | .effectLinearized _ => none

/-- Terminality is equivalent to carrying a canonical wire observation. -/
theorem terminal_iff_wire {outcome : BrokerOutcome} :
    outcome.Terminal ↔ ∃ wire, outcome.wire? = some wire := by
  cases outcome <;> simp [Terminal, wire?]

end BrokerOutcome

/-- Replay, budget, cache, and conservative effect ambiguity at one dispatch boundary. -/
structure BrokerState where
  replay : ReplayState
  budget : SessionBudget
  outcomes : BrokerRequestId → Option BrokerOutcome
  effects : BrokerRequestId → Bool
  dispatchOwned : BrokerRequestId → Bool

namespace BrokerState

/-- Fresh broker state with no accepted request. -/
def empty (session : BrokerSessionId) (capacity : Nat)
    (limits : SessionBudgetLimits) : BrokerState where
  replay := .empty session capacity
  budget := .empty limits
  outcomes := fun _ => none
  effects := fun _ => false
  dispatchOwned := fun _ => false

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

/-- Accept a replay binding before any budget start or external effect. -/
def acceptPending (state : BrokerState) (envelope : BrokerEnvelope)
    (kind : BrokerOperationKind) (maximumResponseBytes : Nat) : BrokerState :=
  { state with
    replay := state.replay.acceptNew envelope
    outcomes := replace state.outcomes envelope.request
      (some (.acceptedPending kind maximumResponseBytes))
    dispatchOwned := replace state.dispatchOwned envelope.request true }

/-- Persist the crash marker before replay admission mutates its sequence. -/
def markAcceptedPending (state : BrokerState) (envelope : BrokerEnvelope)
    (kind : BrokerOperationKind) (maximumResponseBytes : Nat) : BrokerState :=
  { state with
    outcomes := replace state.outcomes envelope.request
      (some (.acceptedPending kind maximumResponseBytes))
    dispatchOwned := replace state.dispatchOwned envelope.request true }

/-- Accept a new replay binding and cache a retryable budget denial. -/
def acceptRetryable (state : BrokerState) (envelope : BrokerEnvelope)
    (kind : BrokerOperationKind) (maximumResponseBytes : Nat) : BrokerState :=
  { state with
    replay := state.replay.acceptNew envelope
    outcomes := replace state.outcomes envelope.request
      (some (.retryableBudget kind maximumResponseBytes)) }

/-- Accept a new replay binding and cache a permanent budget denial. -/
def acceptFinalDenied (state : BrokerState) (envelope : BrokerEnvelope)
    (wire : CanonicalWireOutcome) : BrokerState :=
  { state with
    replay := state.replay.acceptNew envelope
    outcomes := replace state.outcomes envelope.request (some (.finalDenied wire)) }

/-- Replace a retryable cache entry after a later permanent budget denial. -/
def retryFinalDenied (state : BrokerState) (request : BrokerRequestId)
    (wire : CanonicalWireOutcome) : BrokerState :=
  state.storeOutcome request (.finalDenied wire)

/-- Resume a crash-gap acceptance with a retryable budget result. -/
def continueAcceptedRetryable (state : BrokerState) (request : BrokerRequestId)
    (kind : BrokerOperationKind) (maximumResponseBytes : Nat) : BrokerState :=
  { state.storeOutcome request (.retryableBudget kind maximumResponseBytes) with
    dispatchOwned := replace state.dispatchOwned request false }

/-- Resume a crash-gap acceptance with a terminal pre-effect denial. -/
def continueAcceptedFinalDenied (state : BrokerState) (request : BrokerRequestId)
    (wire : CanonicalWireOutcome) : BrokerState :=
  { state.storeOutcome request (.finalDenied wire) with
    dispatchOwned := replace state.dispatchOwned request false }

/-- Accept a new binding while consuming one budget reservation. -/
def acceptAndStart (state : BrokerState) (envelope : BrokerEnvelope)
    (kind : BrokerOperationKind) (maximumResponseBytes : Nat) : BrokerState :=
  { state with
    replay := state.replay.acceptNew envelope
    budget := state.budget.start envelope.request maximumResponseBytes
    outcomes := replace state.outcomes envelope.request (some (.pending kind))
    dispatchOwned := replace state.dispatchOwned envelope.request true }

/-- A retryable exact duplicate consumes budget without changing replay state. -/
def retryStart (state : BrokerState) (request : BrokerRequestId)
    (kind : BrokerOperationKind) (maximumResponseBytes : Nat) : BrokerState :=
  { state with
    budget := state.budget.start request maximumResponseBytes
    outcomes := replace state.outcomes request (some (.pending kind))
    dispatchOwned := replace state.dispatchOwned request true }

/-- Resume an accepted-pending request by consuming its first reservation. -/
def continueAcceptedStart (state : BrokerState) (request : BrokerRequestId)
    (kind : BrokerOperationKind) (maximumResponseBytes : Nat) : BrokerState :=
  state.retryStart request kind maximumResponseBytes

/-- A crash drops the in-memory continuation without changing durable markers. -/
def crashDispatch (state : BrokerState) (request : BrokerRequestId) : BrokerState :=
  { state with dispatchOwned := replace state.dispatchOwned request false }

/-- A post-budget crash exposes Rust's durable accepted marker, not ghost execution state. -/
def crashPending (state : BrokerState) (request : BrokerRequestId)
    (kind : BrokerOperationKind) (maximumResponseBytes : Nat) : BrokerState :=
  { state with
    outcomes := replace state.outcomes request
      (some (.acceptedPending kind maximumResponseBytes))
    dispatchOwned := replace state.dispatchOwned request false }

/-- Conservatively terminalize an orphan accepted before budget admission. -/
def recoverAcceptedPending (state : BrokerState) (request : BrokerRequestId)
    (wire : CanonicalWireOutcome) : BrokerState :=
  { state with
    outcomes := replace state.outcomes request
      (some (.committedButUnrecorded wire))
    effects := replace state.effects request true }

/-- Admit replay while terminalizing a marker orphaned before replay mutation. -/
def recoverAcceptedPendingNew (state : BrokerState) (envelope : BrokerEnvelope)
    (wire : CanonicalWireOutcome) : BrokerState :=
  { state with
    replay := state.replay.acceptNew envelope
    outcomes := replace state.outcomes envelope.request
      (some (.committedButUnrecorded wire))
    effects := replace state.effects envelope.request true }

/-- Conservatively settle and charge an orphan after budget admission. -/
def recoverPending (state : BrokerState) (request : BrokerRequestId)
    (reservation : ResponseReservation) (responseBytes : Nat)
    (wire : CanonicalWireOutcome) : BrokerState :=
  { state with
    budget := state.budget.complete request reservation responseBytes
    outcomes := replace state.outcomes request
      (some (.committedButUnrecorded wire))
    effects := replace state.effects request true }

/-- Cross the external effect boundary before local accounting is finalized. -/
def linearizeEffect (state : BrokerState) (request : BrokerRequestId)
    (receipt : BrokerEffectReceipt) : BrokerState :=
  { state with
    outcomes := replace state.outcomes request
      (some (.effectLinearized (.committed receipt)))
    effects := replace state.effects request true }

/-- Commit an opaque GitHub sentinel when the post-send result is unknowable. -/
def linearizeCommitUnknown (state : BrokerState)
    (request : BrokerRequestId) : BrokerState :=
  { state with
    outcomes := replace state.outcomes request
      (some (.effectLinearized .commitUnknown))
    effects := replace state.effects request true }

/-- Complete accounting and cache the successful terminal outcome. -/
def recordCommit (state : BrokerState) (request : BrokerRequestId)
    (reservation : ResponseReservation) (responseBytes : Nat)
    (receipt : BrokerEffectReceipt) (wire : CanonicalWireOutcome) : BrokerState :=
  { state with
    budget := state.budget.complete request reservation responseBytes
    outcomes := replace state.outcomes request (some (.committed receipt wire))
    dispatchOwned := replace state.dispatchOwned request false
  }

/-- Charge the conservative reservation when the terminal effect is uncertain. -/
def recordCommittedButUnrecorded (state : BrokerState)
    (request : BrokerRequestId) (reservation : ResponseReservation)
    (responseBytes : Nat) (wire : CanonicalWireOutcome) : BrokerState :=
  { state with
    budget := state.budget.complete request reservation responseBytes
    outcomes := replace state.outcomes request
      (some (.committedButUnrecorded wire))
    dispatchOwned := replace state.dispatchOwned request false }

/-- Fail closed when even post-effect accounting cannot be recorded. -/
def abortAfterEffect (state : BrokerState) (request : BrokerRequestId)
    (reservation : ResponseReservation) (wire : CanonicalWireOutcome) : BrokerState :=
  { state with
    budget := state.budget.abort request reservation
    outcomes := replace state.outcomes request (some (.accountingInvariant wire))
    dispatchOwned := replace state.dispatchOwned request false }

/-- Abort one pending reservation and cache a terminal denial. -/
def deny (state : BrokerState) (request : BrokerRequestId)
    (reservation : ResponseReservation) (wire : CanonicalWireOutcome) : BrokerState :=
  { state with
    budget := state.budget.abort request reservation
    outcomes := replace state.outcomes request (some (.finalDenied wire))
    dispatchOwned := replace state.dispatchOwned request false }

/-- The canonical wire observation retained for one terminal request. -/
def observableWire (state : BrokerState)
    (request : BrokerRequestId) : Option CanonicalWireOutcome :=
  (state.outcomes request).bind BrokerOutcome.wire?

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
      state.budget.active request = none ∧ state.effects request = false ∧
      state.dispatchOwned request = false
  | some (.acceptedPending _ _) =>
      (state.replay.accepted request = none ∨ state.HasReplayBinding request) ∧
      (state.budget.active request = none ∨ state.HasActiveReservation request) ∧
      state.effects request = false
  | some (.retryableBudget _ _) => state.HasReplayBinding request ∧
      state.budget.active request = none ∧ state.effects request = false ∧
      state.dispatchOwned request = false
  | some (.pending _) => state.HasReplayBinding request ∧
      state.HasActiveReservation request ∧ state.effects request = false
  | some (.effectLinearized _) => state.HasReplayBinding request ∧
      state.HasActiveReservation request ∧ state.effects request = true ∧
      state.dispatchOwned request = true
  | some (.finalDenied _) => state.HasReplayBinding request ∧
      state.budget.active request = none ∧ state.effects request = false ∧
      state.dispatchOwned request = false
  | some (.accountingInvariant _) => state.HasReplayBinding request ∧
      state.budget.active request = none ∧ state.effects request = true ∧
      state.dispatchOwned request = false
  | some (.committedButUnrecorded _) => state.HasReplayBinding request ∧
      state.budget.active request = none ∧ state.effects request = true ∧
      state.dispatchOwned request = false
  | some (.committed _ _) => state.HasReplayBinding request ∧
      state.budget.active request = none ∧ state.effects request = true ∧
      state.dispatchOwned request = false

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
  | markAcceptedPending {state : BrokerState} {envelope : BrokerEnvelope}
      {kind : BrokerOperationKind} {maximumResponseBytes : Nat} :
      state.AccountingClear →
      state.replay.MayAcceptNew envelope →
      state.outcomes envelope.request = none →
      FitsU64 maximumResponseBytes →
      Step state (state.markAcceptedPending envelope kind maximumResponseBytes)
  | acceptPending {state : BrokerState} {envelope : BrokerEnvelope}
      {kind : BrokerOperationKind} {maximumResponseBytes : Nat} :
      state.AccountingClear →
      state.replay.MayAcceptNew envelope →
      state.outcomes envelope.request = none →
      FitsU64 maximumResponseBytes →
      Step state (state.acceptPending envelope kind maximumResponseBytes)
  | acceptRetryable {state : BrokerState} {envelope : BrokerEnvelope}
      {kind : BrokerOperationKind} {maximumResponseBytes : Nat} :
      state.AccountingClear →
      state.replay.MayAcceptNew envelope →
      state.outcomes envelope.request = none →
      WireAdmissible kind maximumResponseBytes →
      RetryableStartDenial state.budget envelope.request maximumResponseBytes →
      FitsU64 maximumResponseBytes →
      Step state (state.acceptRetryable envelope kind maximumResponseBytes)
  | acceptFinalDenied {state : BrokerState} {envelope : BrokerEnvelope}
      {kind : BrokerOperationKind} {maximumResponseBytes : Nat}
      {wire : CanonicalWireOutcome} :
      state.AccountingClear →
      state.replay.MayAcceptNew envelope →
      state.outcomes envelope.request = none →
      WireAdmissible kind maximumResponseBytes →
      PermanentStartDenial state.budget envelope.request maximumResponseBytes →
      FitsU64 maximumResponseBytes →
      Step state (state.acceptFinalDenied envelope wire)
  | acceptAndStart {state : BrokerState} {envelope : BrokerEnvelope}
      {kind : BrokerOperationKind} {maximumResponseBytes : Nat} :
      state.AccountingClear →
      state.replay.MayAcceptNew envelope →
      state.outcomes envelope.request = none →
      WireAdmissible kind maximumResponseBytes →
      state.budget.MayStart envelope.request maximumResponseBytes →
      Step state (state.acceptAndStart envelope kind maximumResponseBytes)
  | continueAcceptedRetryable {state : BrokerState} {envelope : BrokerEnvelope}
      {kind : BrokerOperationKind} {maximumResponseBytes : Nat} :
      state.AccountingClear →
      state.outcomes envelope.request =
        some (.acceptedPending kind maximumResponseBytes) →
      state.HasReplayBinding envelope.request →
      state.budget.active envelope.request = none →
      state.dispatchOwned envelope.request = true →
      WireAdmissible kind maximumResponseBytes →
      RetryableStartDenial state.budget envelope.request maximumResponseBytes →
      FitsU64 maximumResponseBytes →
      Step state (state.continueAcceptedRetryable envelope.request kind
        maximumResponseBytes)
  | continueAcceptedFinalDenied {state : BrokerState} {envelope : BrokerEnvelope}
      {kind : BrokerOperationKind} {maximumResponseBytes : Nat}
      {wire : CanonicalWireOutcome} :
      state.AccountingClear →
      state.outcomes envelope.request =
        some (.acceptedPending kind maximumResponseBytes) →
      state.HasReplayBinding envelope.request →
      state.budget.active envelope.request = none →
      state.dispatchOwned envelope.request = true →
      WireAdmissible kind maximumResponseBytes →
      PermanentStartDenial state.budget envelope.request maximumResponseBytes →
      FitsU64 maximumResponseBytes →
      Step state (state.continueAcceptedFinalDenied envelope.request wire)
  | continueAcceptedStart {state : BrokerState} {envelope : BrokerEnvelope}
      {kind : BrokerOperationKind} {maximumResponseBytes : Nat} :
      state.AccountingClear →
      state.outcomes envelope.request =
        some (.acceptedPending kind maximumResponseBytes) →
      state.HasReplayBinding envelope.request →
      state.budget.active envelope.request = none →
      state.dispatchOwned envelope.request = true →
      WireAdmissible kind maximumResponseBytes →
      state.budget.MayStart envelope.request maximumResponseBytes →
      Step state (state.continueAcceptedStart envelope.request kind
        maximumResponseBytes)
  | continuePublicOverWireCap {state : BrokerState} {envelope : BrokerEnvelope}
      {maximumResponseBytes : Nat} {wire : CanonicalWireOutcome} :
      state.AccountingClear →
      state.outcomes envelope.request =
        some (.acceptedPending .publicFetch maximumResponseBytes) →
      state.HasReplayBinding envelope.request →
      state.budget.active envelope.request = none →
      state.dispatchOwned envelope.request = true →
      maxPublicWireBodyBytes < maximumResponseBytes →
      Step state (state.continueAcceptedFinalDenied envelope.request wire)
  | crashAcceptedPending {state : BrokerState} {request : BrokerRequestId}
      {kind : BrokerOperationKind} {maximumResponseBytes : Nat} :
      state.AccountingClear →
      state.outcomes request = some (.acceptedPending kind maximumResponseBytes) →
      state.dispatchOwned request = true →
      Step state (state.crashDispatch request)
  | crashPending {state : BrokerState} {request : BrokerRequestId}
      {kind : BrokerOperationKind} {maximumResponseBytes : Nat} :
      state.AccountingClear →
      state.outcomes request = some (.pending kind) →
      state.dispatchOwned request = true →
      state.budget.active request =
        some { request, maxResponseBytes := maximumResponseBytes } →
      Step state (state.crashPending request kind maximumResponseBytes)
  | recoverAcceptedPending {state : BrokerState} {envelope : BrokerEnvelope}
      {kind : BrokerOperationKind} {maximumResponseBytes : Nat}
      {wire : CanonicalWireOutcome} :
      state.AccountingClear →
      state.replay.ExactDuplicate envelope →
      state.outcomes envelope.request =
        some (.acceptedPending kind maximumResponseBytes) →
      state.dispatchOwned envelope.request = false →
      state.budget.active envelope.request = none →
      state.effects envelope.request = false →
      Step state (state.recoverAcceptedPending envelope.request wire)
  | recoverAcceptedPendingNew {state : BrokerState} {envelope : BrokerEnvelope}
      {kind : BrokerOperationKind} {maximumResponseBytes : Nat}
      {wire : CanonicalWireOutcome} :
      state.AccountingClear →
      state.replay.MayAcceptNew envelope →
      state.outcomes envelope.request =
        some (.acceptedPending kind maximumResponseBytes) →
      state.dispatchOwned envelope.request = false →
      state.budget.active envelope.request = none →
      state.effects envelope.request = false →
      Step state (state.recoverAcceptedPendingNew envelope wire)
  | recoverPending {state : BrokerState} {envelope : BrokerEnvelope}
      {kind : BrokerOperationKind} {maximumResponseBytes responseBytes : Nat}
      {wire : CanonicalWireOutcome} :
      state.AccountingClear →
      state.replay.ExactDuplicate envelope →
      state.outcomes envelope.request =
        some (.acceptedPending kind maximumResponseBytes) →
      state.dispatchOwned envelope.request = false →
      state.effects envelope.request = false →
      (allowed : state.budget.MayComplete envelope.request responseBytes) →
      allowed.reservation.maxResponseBytes = maximumResponseBytes →
      responseBytes = allowed.reservation.maxResponseBytes →
      Step state (state.recoverPending envelope.request allowed.reservation
        responseBytes wire)
  | retryStart {state : BrokerState} {envelope : BrokerEnvelope}
      {kind : BrokerOperationKind} {maximumResponseBytes : Nat} :
      state.AccountingClear →
      state.replay.ExactDuplicate envelope →
      state.outcomes envelope.request =
        some (.retryableBudget kind maximumResponseBytes) →
      WireAdmissible kind maximumResponseBytes →
      state.budget.MayStart envelope.request maximumResponseBytes →
      Step state (state.retryStart envelope.request kind maximumResponseBytes)
  | retryFinalDenied {state : BrokerState} {envelope : BrokerEnvelope}
      {kind : BrokerOperationKind} {maximumResponseBytes : Nat}
      {wire : CanonicalWireOutcome} :
      state.AccountingClear →
      state.replay.ExactDuplicate envelope →
      state.outcomes envelope.request =
        some (.retryableBudget kind maximumResponseBytes) →
      WireAdmissible kind maximumResponseBytes →
      PermanentStartDenial state.budget envelope.request maximumResponseBytes →
      FitsU64 maximumResponseBytes →
      Step state (state.retryFinalDenied envelope.request wire)
  | linearizeEffect {state : BrokerState} {request : BrokerRequestId}
      {kind : BrokerOperationKind} {receipt : BrokerEffectReceipt} :
      state.AccountingClear →
      state.outcomes request = some (.pending kind) →
      state.effects request = false →
      state.dispatchOwned request = true →
      Step state (state.linearizeEffect request receipt)
  | linearizeCommitUnknown {state : BrokerState} {request : BrokerRequestId} :
      state.AccountingClear →
      state.outcomes request = some (.pending .githubMutation) →
      state.effects request = false →
      state.dispatchOwned request = true →
      Step state (state.linearizeCommitUnknown request)
  | recordCommit {state : BrokerState} {request : BrokerRequestId}
      {responseBytes : Nat} {receipt : BrokerEffectReceipt}
      {wire : CanonicalWireOutcome} :
      state.outcomes request =
        some (.effectLinearized (.committed receipt)) →
      state.AccountingTurn request →
      (allowed : state.budget.MayComplete request responseBytes) →
      Step state (state.recordCommit request allowed.reservation responseBytes receipt wire)
  | recordCommittedButUnrecorded {state : BrokerState}
      {request : BrokerRequestId} {effect : BrokerLinearizedEffect}
      {responseBytes : Nat} {wire : CanonicalWireOutcome} :
      state.outcomes request = some (.effectLinearized effect) →
      state.AccountingTurn request →
      (allowed : state.budget.MayComplete request responseBytes) →
      responseBytes = allowed.reservation.maxResponseBytes →
      Step state (state.recordCommittedButUnrecorded request allowed.reservation
        responseBytes wire)
  | abortAfterEffect {state : BrokerState} {request : BrokerRequestId}
      {receipt : BrokerEffectReceipt} {wire : CanonicalWireOutcome} :
      state.outcomes request =
        some (.effectLinearized (.committed receipt)) →
      state.AccountingTurn request →
      (allowed : state.budget.MayAbort request) →
      Step state (state.abortAfterEffect request allowed.reservation wire)
  | deny {state : BrokerState} {request : BrokerRequestId}
      {kind : BrokerOperationKind} {wire : CanonicalWireOutcome} :
      state.AccountingClear →
      state.outcomes request = some (.pending kind) →
      (allowed : state.budget.MayAbort request) →
      Step state (state.deny request allowed.reservation wire)
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
  intro other otherEffect linearized
  by_cases sameRequest : other = request
  · exact sameRequest
  · have prior : state.outcomes other = some (.effectLinearized otherEffect) := by
      simpa [BrokerState.linearizeEffect, replace, sameRequest] using linearized
    exact False.elim (accountingClear other otherEffect prior)

/-- A commit-unknown sentinel also selects one synchronous accounting turn. -/
theorem linearizeCommitUnknown_starts_accounting_turn (state : BrokerState)
    (request : BrokerRequestId) (accountingClear : state.AccountingClear) :
    (state.linearizeCommitUnknown request).AccountingTurn request := by
  intro other otherEffect linearized
  by_cases sameRequest : other = request
  · exact sameRequest
  · have prior : state.outcomes other = some (.effectLinearized otherEffect) := by
      simpa [BrokerState.linearizeCommitUnknown, replace, sameRequest] using linearized
    exact False.elim (accountingClear other otherEffect prior)

/-- One accepted transition preserves replay/cache/reservation/effect coupling. -/
theorem Step.preserves_requestCoupling {before after : BrokerState}
    (transition : Step before after)
    (coupled : ∀ request, before.RequestCoupled request) :
    ∀ request, after.RequestCoupled request := by
  intro request
  cases transition with
  | markAcceptedPending accountingClear replayAllowed cacheFresh representable =>
      rename_i envelope kind maximumResponseBytes
      by_cases sameRequest : request = envelope.request
      · subst request
        have prior := coupled envelope.request
        simp only [RequestCoupled] at prior
        rw [cacheFresh] at prior
        simp only [RequestCoupled, BrokerState.markAcceptedPending,
          replace_selected]
        exact ⟨Or.inl prior.1, Or.inl prior.2.1, prior.2.2.1⟩
      · simpa [RequestCoupled, HasReplayBinding, HasActiveReservation,
          BrokerState.markAcceptedPending, replace, sameRequest]
          using coupled request
  | acceptPending accountingClear replayAllowed cacheFresh representable =>
      rename_i envelope kind maximumResponseBytes
      by_cases sameRequest : request = envelope.request
      · subst request
        have prior := coupled envelope.request
        simp only [RequestCoupled] at prior
        rw [cacheFresh] at prior
        simp only [RequestCoupled, BrokerState.acceptPending, replace_selected]
        exact ⟨Or.inr ⟨_,
          ReplayState.acceptNew_stores_exact_binding before.replay envelope⟩,
          Or.inl prior.2.1, prior.2.2.1⟩
      · simpa [RequestCoupled, HasReplayBinding, HasActiveReservation,
          BrokerState.acceptPending, ReplayState.acceptNew, replace, sameRequest]
          using coupled request
  | acceptRetryable accountingClear replayAllowed cacheFresh wireAllowed denial representable =>
      rename_i envelope kind maximumResponseBytes
      by_cases sameRequest : request = envelope.request
      · subst request
        have prior := coupled envelope.request
        simp only [RequestCoupled] at prior
        rw [cacheFresh] at prior
        simp only [RequestCoupled, BrokerState.acceptRetryable, replace_selected]
        exact ⟨⟨_, ReplayState.acceptNew_stores_exact_binding before.replay envelope⟩,
          prior.2.1, prior.2.2.1, prior.2.2.2⟩
      · simpa [RequestCoupled, HasReplayBinding, HasActiveReservation,
          BrokerState.acceptRetryable, ReplayState.acceptNew, replace, sameRequest]
          using coupled request
  | acceptFinalDenied accountingClear replayAllowed cacheFresh wireAllowed denial representable =>
      rename_i envelope kind maximumResponseBytes wire
      by_cases sameRequest : request = envelope.request
      · subst request
        have prior := coupled envelope.request
        simp only [RequestCoupled] at prior
        rw [cacheFresh] at prior
        simp only [RequestCoupled, BrokerState.acceptFinalDenied, replace_selected]
        exact ⟨⟨_, ReplayState.acceptNew_stores_exact_binding before.replay envelope⟩,
          prior.2.1, prior.2.2.1, prior.2.2.2⟩
      · simpa [RequestCoupled, HasReplayBinding, HasActiveReservation,
          BrokerState.acceptFinalDenied, ReplayState.acceptNew, replace, sameRequest]
          using coupled request
  | acceptAndStart accountingClear replayAllowed cacheFresh wireAllowed budgetAllowed =>
      rename_i envelope kind maximumResponseBytes
      by_cases sameRequest : request = envelope.request
      · subst request
        have prior := coupled envelope.request
        simp only [RequestCoupled] at prior
        rw [cacheFresh] at prior
        simp only [RequestCoupled, BrokerState.acceptAndStart, replace_selected]
        exact ⟨⟨_, ReplayState.acceptNew_stores_exact_binding before.replay envelope⟩,
          ⟨_, SessionBudget.start_stores_exact_reservation before.budget
            envelope.request maximumResponseBytes, rfl⟩, prior.2.2.1⟩
      · simpa [RequestCoupled, HasReplayBinding, HasActiveReservation,
          BrokerState.acceptAndStart, ReplayState.acceptNew, SessionBudget.start,
          replace, sameRequest] using coupled request
  | continueAcceptedRetryable accountingClear accepted replayBound inactive owned wireAllowed denial representable =>
      rename_i envelope kind maximumResponseBytes
      by_cases sameRequest : request = envelope.request
      · subst request
        have prior := coupled envelope.request
        simp only [RequestCoupled] at prior
        rw [accepted] at prior
        simp only [RequestCoupled, BrokerState.continueAcceptedRetryable,
          BrokerState.storeOutcome, replace_selected]
        exact ⟨replayBound, inactive, prior.2.2, by simp⟩
      · simpa [RequestCoupled, HasReplayBinding, HasActiveReservation,
          BrokerState.continueAcceptedRetryable, BrokerState.storeOutcome, replace,
          sameRequest] using coupled request
  | continueAcceptedFinalDenied accountingClear accepted replayBound inactive owned wireAllowed denial representable =>
      rename_i envelope kind maximumResponseBytes wire
      by_cases sameRequest : request = envelope.request
      · subst request
        have prior := coupled envelope.request
        simp only [RequestCoupled] at prior
        rw [accepted] at prior
        simp only [RequestCoupled, BrokerState.continueAcceptedFinalDenied,
          BrokerState.storeOutcome, replace_selected]
        exact ⟨replayBound, inactive, prior.2.2, by simp⟩
      · simpa [RequestCoupled, HasReplayBinding, HasActiveReservation,
          BrokerState.continueAcceptedFinalDenied, BrokerState.storeOutcome, replace,
          sameRequest] using coupled request
  | continueAcceptedStart accountingClear accepted replayBound inactive owned wireAllowed budgetAllowed =>
      rename_i envelope kind maximumResponseBytes
      by_cases sameRequest : request = envelope.request
      · subst request
        have prior := coupled envelope.request
        simp only [RequestCoupled] at prior
        rw [accepted] at prior
        simp only [RequestCoupled, BrokerState.continueAcceptedStart,
          BrokerState.retryStart, replace_selected]
        exact ⟨replayBound,
          ⟨_, SessionBudget.start_stores_exact_reservation before.budget
            envelope.request maximumResponseBytes, rfl⟩, prior.2.2⟩
      · simpa [RequestCoupled, HasReplayBinding, HasActiveReservation,
          BrokerState.continueAcceptedStart, BrokerState.retryStart,
          SessionBudget.start, replace, sameRequest] using coupled request
  | continuePublicOverWireCap accountingClear accepted replayBound inactive owned oversized =>
      rename_i envelope maximumResponseBytes wire
      by_cases sameRequest : request = envelope.request
      · subst request
        have prior := coupled envelope.request
        simp only [RequestCoupled] at prior
        rw [accepted] at prior
        simp only [RequestCoupled, BrokerState.continueAcceptedFinalDenied,
          BrokerState.storeOutcome, replace_selected]
        exact ⟨replayBound, inactive, prior.2.2, by simp⟩
      · simpa [RequestCoupled, HasReplayBinding, HasActiveReservation,
          BrokerState.continueAcceptedFinalDenied, BrokerState.storeOutcome, replace,
          sameRequest] using coupled request
  | crashAcceptedPending accountingClear accepted owned =>
      rename_i crashedRequest kind maximumResponseBytes
      by_cases sameRequest : request = crashedRequest
      · subst request
        have prior := coupled crashedRequest
        simp only [RequestCoupled] at prior
        rw [accepted] at prior
        simp only [RequestCoupled, BrokerState.crashDispatch]
        rw [accepted]
        exact prior
      · simpa [RequestCoupled, HasReplayBinding, HasActiveReservation,
          BrokerState.crashDispatch, replace, sameRequest] using coupled request
  | crashPending accountingClear pending owned reservationLookup =>
      rename_i crashedRequest kind maximumResponseBytes
      by_cases sameRequest : request = crashedRequest
      · subst request
        have prior := coupled crashedRequest
        simp only [RequestCoupled] at prior
        rw [pending] at prior
        simp only [RequestCoupled, BrokerState.crashPending, replace_selected]
        exact ⟨Or.inr prior.1, Or.inr prior.2.1, prior.2.2⟩
      · simpa [RequestCoupled, HasReplayBinding, HasActiveReservation,
          BrokerState.crashPending, replace, sameRequest] using coupled request
  | recoverAcceptedPending accountingClear duplicate accepted owned inactive noEffect =>
      rename_i envelope kind maximumResponseBytes wire
      by_cases sameRequest : request = envelope.request
      · subst request
        have prior := coupled envelope.request
        simp only [RequestCoupled] at prior
        rw [accepted] at prior
        simp only [RequestCoupled, BrokerState.recoverAcceptedPending,
          replace_selected]
        exact ⟨⟨_, duplicate.2⟩, inactive, by simp, owned⟩
      · simpa [RequestCoupled, HasReplayBinding, HasActiveReservation,
          BrokerState.recoverAcceptedPending, replace, sameRequest]
          using coupled request
  | recoverAcceptedPendingNew accountingClear replayAllowed accepted owned inactive noEffect =>
      rename_i envelope kind maximumResponseBytes wire
      by_cases sameRequest : request = envelope.request
      · subst request
        simp only [RequestCoupled, BrokerState.recoverAcceptedPendingNew,
          replace_selected]
        exact ⟨⟨_, ReplayState.acceptNew_stores_exact_binding before.replay envelope⟩,
          inactive, by simp, owned⟩
      · simpa [RequestCoupled, HasReplayBinding, HasActiveReservation,
          BrokerState.recoverAcceptedPendingNew, ReplayState.acceptNew,
          replace, sameRequest] using coupled request
  | recoverPending accountingClear duplicate pending owned noEffect allowed capMatch exactCharge =>
      rename_i envelope kind maximumResponseBytes responseBytes wire
      by_cases sameRequest : request = envelope.request
      · subst request
        have prior := coupled envelope.request
        simp only [RequestCoupled] at prior
        rw [pending] at prior
        simp only [RequestCoupled, BrokerState.recoverPending, replace_selected]
        exact ⟨⟨_, duplicate.2⟩, SessionBudget.complete_removes_reservation allowed,
          by simp [BrokerState.recoverPending], owned⟩
      · simpa [RequestCoupled, HasReplayBinding, HasActiveReservation,
          BrokerState.recoverPending, SessionBudget.complete,
          SessionBudget.releaseReservation, replace, sameRequest]
          using coupled request
  | retryStart accountingClear duplicate retryable wireAllowed budgetAllowed =>
      rename_i envelope kind maximumResponseBytes
      by_cases sameRequest : request = envelope.request
      · subst request
        have prior := coupled envelope.request
        simp only [RequestCoupled] at prior
        rw [retryable] at prior
        simp only [RequestCoupled, BrokerState.retryStart, replace_selected]
        exact ⟨prior.1,
          ⟨_, SessionBudget.start_stores_exact_reservation before.budget
            envelope.request maximumResponseBytes, rfl⟩, prior.2.2.1⟩
      · simpa [RequestCoupled, HasReplayBinding, HasActiveReservation,
          BrokerState.retryStart, SessionBudget.start, replace, sameRequest]
          using coupled request
  | retryFinalDenied accountingClear duplicate retryable wireAllowed denial representable =>
      rename_i envelope kind maximumResponseBytes wire
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
  | linearizeEffect accountingClear pending noEffect owned =>
      rename_i effectRequest kind receipt
      by_cases sameRequest : request = effectRequest
      · subst request
        have prior := coupled effectRequest
        simp only [RequestCoupled] at prior
        rw [pending] at prior
        simp only [RequestCoupled, BrokerState.linearizeEffect, replace_selected]
        exact ⟨prior.1, prior.2.1, by simp [BrokerState.linearizeEffect], owned⟩
      · simpa [RequestCoupled, HasReplayBinding, HasActiveReservation,
          BrokerState.linearizeEffect, replace, sameRequest] using coupled request
  | linearizeCommitUnknown accountingClear pending noEffect owned =>
      rename_i effectRequest
      by_cases sameRequest : request = effectRequest
      · subst request
        have prior := coupled effectRequest
        simp only [RequestCoupled] at prior
        rw [pending] at prior
        simp only [RequestCoupled, BrokerState.linearizeCommitUnknown,
          replace_selected]
        exact ⟨prior.1, prior.2.1,
          by simp [BrokerState.linearizeCommitUnknown], owned⟩
      · simpa [RequestCoupled, HasReplayBinding, HasActiveReservation,
          BrokerState.linearizeCommitUnknown, replace, sameRequest] using coupled request
  | recordCommit linearized accountingTurn allowed =>
      rename_i committedRequest responseBytes receipt wire
      by_cases sameRequest : request = committedRequest
      · subst request
        have prior := coupled committedRequest
        simp only [RequestCoupled] at prior
        rw [linearized] at prior
        simp only [RequestCoupled, BrokerState.recordCommit, replace_selected]
        exact ⟨prior.1, SessionBudget.complete_removes_reservation allowed,
          prior.2.2.1, by simp [BrokerState.recordCommit]⟩
      · simpa [RequestCoupled, HasReplayBinding, HasActiveReservation,
          BrokerState.recordCommit, SessionBudget.complete,
          SessionBudget.releaseReservation, replace, sameRequest] using coupled request
  | recordCommittedButUnrecorded linearized accountingTurn allowed exactCharge =>
      rename_i committedRequest effect responseBytes wire
      by_cases sameRequest : request = committedRequest
      · subst request
        have prior := coupled committedRequest
        simp only [RequestCoupled] at prior
        rw [linearized] at prior
        simp only [RequestCoupled, BrokerState.recordCommittedButUnrecorded,
          replace_selected]
        exact ⟨prior.1, SessionBudget.complete_removes_reservation allowed,
          prior.2.2.1, by simp [BrokerState.recordCommittedButUnrecorded]⟩
      · simpa [RequestCoupled, HasReplayBinding, HasActiveReservation,
          BrokerState.recordCommittedButUnrecorded, SessionBudget.complete,
          SessionBudget.releaseReservation, replace, sameRequest] using coupled request
  | abortAfterEffect linearized accountingTurn allowed =>
      rename_i committedRequest receipt wire
      by_cases sameRequest : request = committedRequest
      · subst request
        have prior := coupled committedRequest
        simp only [RequestCoupled] at prior
        rw [linearized] at prior
        simp only [RequestCoupled, BrokerState.abortAfterEffect, replace_selected]
        exact ⟨prior.1, SessionBudget.abort_removes_reservation allowed,
          prior.2.2.1, by simp [BrokerState.abortAfterEffect]⟩
      · simpa [RequestCoupled, HasReplayBinding, HasActiveReservation,
          BrokerState.abortAfterEffect, SessionBudget.abort,
          SessionBudget.releaseReservation, replace, sameRequest] using coupled request
  | deny accountingClear pending allowed =>
      rename_i deniedRequest kind wire
      by_cases sameRequest : request = deniedRequest
      · subst request
        have prior := coupled deniedRequest
        simp only [RequestCoupled] at prior
        rw [pending] at prior
        simp only [RequestCoupled, BrokerState.deny, replace_selected]
        exact ⟨prior.1, SessionBudget.abort_removes_reservation allowed,
          prior.2.2, by simp [BrokerState.deny]⟩
      · simpa [RequestCoupled, HasReplayBinding, HasActiveReservation,
          BrokerState.deny, SessionBudget.abort, SessionBudget.releaseReservation,
          replace, sameRequest] using coupled request
  | terminalDuplicate => exact coupled request

/-- A committed transition stores both the terminal receipt and effect bit. -/
theorem linearizeEffect_stores_effect (state : BrokerState)
    (request : BrokerRequestId) (receipt : BrokerEffectReceipt) :
    (state.linearizeEffect request receipt).outcomes request =
      some (.effectLinearized (.committed receipt)) ∧
    (state.linearizeEffect request receipt).effects request = true := by
  simp [BrokerState.linearizeEffect]

/-- Commit-unknown crosses the effect boundary before terminal cache repair. -/
theorem linearizeCommitUnknown_stores_effect (state : BrokerState)
    (request : BrokerRequestId) :
    (state.linearizeCommitUnknown request).outcomes request =
      some (.effectLinearized .commitUnknown) ∧
    (state.linearizeCommitUnknown request).effects request = true := by
  simp [BrokerState.linearizeCommitUnknown]

/-- Terminal exact duplicates are accepted only as a state-preserving step. -/
theorem terminal_duplicate_is_noop {state : BrokerState} {envelope : BrokerEnvelope}
    {outcome : BrokerOutcome}
    (accountingClear : state.AccountingClear)
    (duplicate : state.replay.ExactDuplicate envelope)
    (cached : state.outcomes envelope.request = some outcome)
    (terminal : outcome.Terminal) : Step state state :=
  .terminalDuplicate accountingClear duplicate cached terminal

/-- Exact retries return the exact cached canonical wire and do not mutate state. -/
theorem terminal_duplicate_is_observational_noop
    {state : BrokerState} {envelope : BrokerEnvelope}
    {outcome : BrokerOutcome} {wire : CanonicalWireOutcome}
    (accountingClear : state.AccountingClear)
    (duplicate : state.replay.ExactDuplicate envelope)
    (cached : state.outcomes envelope.request = some outcome)
    (cachedWire : outcome.wire? = some wire) :
    Step state state ∧ state.observableWire envelope.request = some wire := by
  have terminal : outcome.Terminal :=
    BrokerOutcome.terminal_iff_wire.mpr ⟨wire, cachedWire⟩
  exact ⟨.terminalDuplicate accountingClear duplicate cached terminal,
    by simp [observableWire, cached, cachedWire]⟩

/-- Accepted-pending is pre-effect but may retain a reservation across a crash. -/
theorem WellFormed.acceptedPending_has_no_effect {state : BrokerState}
    (wellFormed : state.WellFormed) {request : BrokerRequestId}
    {kind : BrokerOperationKind} {maximumResponseBytes : Nat}
    (cached : state.outcomes request =
      some (.acceptedPending kind maximumResponseBytes)) :
    (state.budget.active request = none ∨ state.HasActiveReservation request) ∧
      state.effects request = false := by
  have coupled := wellFormed.requestCoupled request
  simp only [RequestCoupled] at coupled
  rw [cached] at coupled
  exact coupled.2

/-- Duplicate recovery before budget admission is terminal and charges nothing. -/
theorem acceptedPending_duplicate_recovers_without_charge
    {state : BrokerState} {envelope : BrokerEnvelope}
    {kind : BrokerOperationKind} {maximumResponseBytes : Nat}
    {wire : CanonicalWireOutcome}
    (accountingClear : state.AccountingClear)
    (duplicate : state.replay.ExactDuplicate envelope)
    (accepted : state.outcomes envelope.request =
      some (.acceptedPending kind maximumResponseBytes))
    (orphaned : state.dispatchOwned envelope.request = false)
    (inactive : state.budget.active envelope.request = none)
    (noEffect : state.effects envelope.request = false) :
    Step state (state.recoverAcceptedPending envelope.request wire) ∧
      (state.recoverAcceptedPending envelope.request wire).budget = state.budget ∧
      (state.recoverAcceptedPending envelope.request wire).outcomes envelope.request =
        some (.committedButUnrecorded wire) ∧
      (state.recoverAcceptedPending envelope.request wire).effects envelope.request =
        true := by
  refine ⟨.recoverAcceptedPending accountingClear duplicate accepted orphaned inactive
    noEffect, ?_⟩
  simp [BrokerState.recoverAcceptedPending]

/-- A marker orphaned before replay admission is admitted only to cache CBU. -/
theorem acceptedPending_new_recovery_without_charge
    {state : BrokerState} {envelope : BrokerEnvelope}
    {kind : BrokerOperationKind} {maximumResponseBytes : Nat}
    {wire : CanonicalWireOutcome}
    (accountingClear : state.AccountingClear)
    (replayAllowed : state.replay.MayAcceptNew envelope)
    (accepted : state.outcomes envelope.request =
      some (.acceptedPending kind maximumResponseBytes))
    (orphaned : state.dispatchOwned envelope.request = false)
    (inactive : state.budget.active envelope.request = none)
    (noEffect : state.effects envelope.request = false) :
    Step state (state.recoverAcceptedPendingNew envelope wire) ∧
      (state.recoverAcceptedPendingNew envelope wire).budget = state.budget ∧
      (state.recoverAcceptedPendingNew envelope wire).outcomes envelope.request =
        some (.committedButUnrecorded wire) ∧
      (state.recoverAcceptedPendingNew envelope wire).effects envelope.request =
        true := by
  refine ⟨.recoverAcceptedPendingNew accountingClear replayAllowed accepted orphaned
    inactive noEffect, ?_⟩
  simp [BrokerState.recoverAcceptedPendingNew]

/-- Duplicate recovery after budget admission terminalizes at the full reservation. -/
theorem pending_duplicate_recovers_with_full_charge
    {state : BrokerState} {envelope : BrokerEnvelope}
    {kind : BrokerOperationKind} {maximumResponseBytes responseBytes : Nat}
    {wire : CanonicalWireOutcome}
    (accountingClear : state.AccountingClear)
    (duplicate : state.replay.ExactDuplicate envelope)
    (pending : state.outcomes envelope.request =
      some (.acceptedPending kind maximumResponseBytes))
    (orphaned : state.dispatchOwned envelope.request = false)
    (noEffect : state.effects envelope.request = false)
    (allowed : state.budget.MayComplete envelope.request responseBytes)
    (capMatch : allowed.reservation.maxResponseBytes = maximumResponseBytes)
    (exactCharge : responseBytes = allowed.reservation.maxResponseBytes) :
    Step state (state.recoverPending envelope.request allowed.reservation
      responseBytes wire) ∧
      (state.recoverPending envelope.request allowed.reservation responseBytes wire).budget.committedResponseBytes =
        state.budget.committedResponseBytes + allowed.reservation.maxResponseBytes ∧
      (state.recoverPending envelope.request allowed.reservation responseBytes wire).budget.active
          envelope.request = none ∧
      (state.recoverPending envelope.request allowed.reservation responseBytes wire).outcomes
          envelope.request = some (.committedButUnrecorded wire) ∧
      (state.recoverPending envelope.request allowed.reservation responseBytes wire).effects
          envelope.request = true := by
  refine ⟨.recoverPending accountingClear duplicate pending orphaned noEffect allowed
    capMatch exactCharge, ?_⟩
  simp [BrokerState.recoverPending, SessionBudget.complete,
    SessionBudget.releaseReservation, exactCharge]

/-- Commit-unknown can only be terminalized; it cannot re-enter an adapter. -/
theorem Step.commitUnknown_settles_without_reexecution {before after : BrokerState}
    (transition : Step before after) {request : BrokerRequestId}
    (unknown : before.outcomes request =
      some (.effectLinearized .commitUnknown)) :
    ∃ wire reservation,
      after.outcomes request = some (.committedButUnrecorded wire) ∧
        before.budget.active request = some reservation ∧
        after.budget.committedResponseBytes =
          before.budget.committedResponseBytes + reservation.maxResponseBytes := by
  cases transition with
  | markAcceptedPending accountingClear | acceptPending accountingClear |
      acceptRetryable accountingClear |
      acceptFinalDenied accountingClear | acceptAndStart accountingClear |
      continueAcceptedRetryable accountingClear |
      continueAcceptedFinalDenied accountingClear |
      continueAcceptedStart accountingClear |
      continuePublicOverWireCap accountingClear |
      crashAcceptedPending accountingClear | crashPending accountingClear |
      recoverAcceptedPending accountingClear |
      recoverAcceptedPendingNew accountingClear | recoverPending accountingClear |
      retryStart accountingClear |
      retryFinalDenied accountingClear | linearizeEffect accountingClear |
      linearizeCommitUnknown accountingClear | deny accountingClear |
      terminalDuplicate accountingClear =>
      exact False.elim (accountingClear request .commitUnknown unknown)
  | recordCommit known accountingTurn allowed =>
      rename_i settledRequest responseBytes receipt wire
      have sameRequest : request = settledRequest :=
        accountingTurn request .commitUnknown unknown
      subst settledRequest
      have impossible := Option.some.inj (unknown.symm.trans known)
      cases impossible
  | recordCommittedButUnrecorded linearized accountingTurn allowed exactCharge =>
      rename_i settledRequest effect responseBytes wire
      have sameRequest : request = settledRequest :=
        accountingTurn request .commitUnknown unknown
      subst settledRequest
      refine ⟨wire, allowed.reservation,
        by simp [BrokerState.recordCommittedButUnrecorded],
        allowed.reservationLookup, ?_⟩
      simp [BrokerState.recordCommittedButUnrecorded, SessionBudget.complete,
        exactCharge]
  | abortAfterEffect linearized accountingTurn allowed =>
      rename_i settledRequest receipt wire
      have sameRequest : request = settledRequest :=
        accountingTurn request .commitUnknown unknown
      subst settledRequest
      have impossible := Option.some.inj (unknown.symm.trans linearized)
      cases impossible

/-- Once an effect may have crossed the boundary, no transition clears ambiguity. -/
theorem Step.effect_persists {before after : BrokerState}
    (transition : Step before after) {request : BrokerRequestId}
    (effect : before.effects request = true) : after.effects request = true := by
  cases transition with
  | markAcceptedPending | acceptPending | acceptRetryable |
      acceptFinalDenied | acceptAndStart |
      continueAcceptedRetryable | continueAcceptedFinalDenied |
      continueAcceptedStart | continuePublicOverWireCap |
      crashAcceptedPending | crashPending | retryStart |
      retryFinalDenied | recordCommit | recordCommittedButUnrecorded |
      abortAfterEffect | deny | terminalDuplicate => exact effect
  | recoverAcceptedPending accountingClear duplicate accepted owned inactive noEffect =>
      rename_i envelope kind maximumResponseBytes wire
      by_cases sameRequest : request = envelope.request
      · subst request
        simp [BrokerState.recoverAcceptedPending]
      · simpa [BrokerState.recoverAcceptedPending, replace, sameRequest] using effect
  | recoverAcceptedPendingNew accountingClear replayAllowed accepted owned inactive noEffect =>
      rename_i envelope kind maximumResponseBytes wire
      by_cases sameRequest : request = envelope.request
      · subst request
        simp [BrokerState.recoverAcceptedPendingNew]
      · simpa [BrokerState.recoverAcceptedPendingNew, replace, sameRequest]
          using effect
  | recoverPending accountingClear duplicate pending owned noEffect allowed capMatch exactCharge =>
      rename_i envelope kind maximumResponseBytes responseBytes wire
      by_cases sameRequest : request = envelope.request
      · subst request
        simp [BrokerState.recoverPending]
      · simpa [BrokerState.recoverPending, replace, sameRequest] using effect
  | linearizeEffect accountingClear pending noEffect owned =>
      rename_i committedRequest kind receipt
      by_cases sameRequest : request = committedRequest
      · subst request
        simp [BrokerState.linearizeEffect]
      · simpa [BrokerState.linearizeEffect, replace, sameRequest] using effect
  | linearizeCommitUnknown accountingClear pending noEffect owned =>
      rename_i committedRequest
      by_cases sameRequest : request = committedRequest
      · subst request
        simp [BrokerState.linearizeCommitUnknown]
      · simpa [BrokerState.linearizeCommitUnknown, replace, sameRequest] using effect

/-- A terminal cached outcome is immutable across every accepted transition. -/
theorem Step.terminal_outcome_immutable {before after : BrokerState}
    (transition : Step before after) {request : BrokerRequestId}
    {outcome : BrokerOutcome} (cached : before.outcomes request = some outcome)
    (terminal : outcome.Terminal) : after.outcomes request = some outcome := by
  cases transition with
  | markAcceptedPending accountingClear replayAllowed cacheFresh representable =>
      rename_i envelope kind maximumResponseBytes
      have differentRequest : request ≠ envelope.request := by
        intro sameRequest
        subst request
        rw [cached] at cacheFresh
        cases cacheFresh
      simpa [BrokerState.markAcceptedPending, replace, differentRequest] using cached
  | acceptPending accountingClear replayAllowed cacheFresh representable =>
      rename_i envelope kind maximumResponseBytes
      have differentRequest : request ≠ envelope.request := by
        intro sameRequest
        subst request
        rw [cached] at cacheFresh
        cases cacheFresh
      simpa [BrokerState.acceptPending, replace, differentRequest] using cached
  | acceptRetryable accountingClear replayAllowed cacheFresh wireAllowed denial representable =>
      rename_i envelope kind maximumResponseBytes
      have differentRequest : request ≠ envelope.request := by
        intro sameRequest
        subst request
        rw [cached] at cacheFresh
        cases cacheFresh
      simpa [BrokerState.acceptRetryable, replace, differentRequest] using cached
  | acceptFinalDenied accountingClear replayAllowed cacheFresh wireAllowed denial representable =>
      rename_i envelope kind maximumResponseBytes wire
      have differentRequest : request ≠ envelope.request := by
        intro sameRequest
        subst request
        rw [cached] at cacheFresh
        cases cacheFresh
      simpa [BrokerState.acceptFinalDenied, replace, differentRequest] using cached
  | acceptAndStart accountingClear replayAllowed cacheFresh wireAllowed budgetAllowed =>
      rename_i envelope kind maximumResponseBytes
      have differentRequest : request ≠ envelope.request := by
        intro sameRequest
        subst request
        rw [cached] at cacheFresh
        cases cacheFresh
      simpa [BrokerState.acceptAndStart, replace, differentRequest] using cached
  | continueAcceptedRetryable accountingClear accepted replayBound inactive owned wireAllowed denial representable =>
      rename_i envelope kind maximumResponseBytes
      have differentRequest : request ≠ envelope.request := by
        intro sameRequest
        subst request
        have sameOutcome := Option.some.inj (cached.symm.trans accepted)
        subst outcome
        simp [BrokerOutcome.Terminal] at terminal
      simpa [BrokerState.continueAcceptedRetryable, BrokerState.storeOutcome,
        replace, differentRequest] using cached
  | continueAcceptedFinalDenied accountingClear accepted replayBound inactive owned wireAllowed denial representable =>
      rename_i envelope kind maximumResponseBytes wire
      have differentRequest : request ≠ envelope.request := by
        intro sameRequest
        subst request
        have sameOutcome := Option.some.inj (cached.symm.trans accepted)
        subst outcome
        simp [BrokerOutcome.Terminal] at terminal
      simpa [BrokerState.continueAcceptedFinalDenied, BrokerState.storeOutcome, replace,
        differentRequest] using cached
  | continueAcceptedStart accountingClear accepted replayBound inactive owned wireAllowed budgetAllowed =>
      rename_i envelope kind maximumResponseBytes
      have differentRequest : request ≠ envelope.request := by
        intro sameRequest
        subst request
        have sameOutcome := Option.some.inj (cached.symm.trans accepted)
        subst outcome
        simp [BrokerOutcome.Terminal] at terminal
      simpa [BrokerState.continueAcceptedStart, BrokerState.retryStart, replace,
        differentRequest] using cached
  | continuePublicOverWireCap accountingClear accepted replayBound inactive owned oversized =>
      rename_i envelope maximumResponseBytes wire
      have differentRequest : request ≠ envelope.request := by
        intro sameRequest
        subst request
        have sameOutcome := Option.some.inj (cached.symm.trans accepted)
        subst outcome
        simp [BrokerOutcome.Terminal] at terminal
      simpa [BrokerState.continueAcceptedFinalDenied, BrokerState.storeOutcome,
        replace, differentRequest] using cached
  | crashAcceptedPending accountingClear accepted owned =>
      simpa [BrokerState.crashDispatch] using cached
  | crashPending accountingClear pending owned reservationLookup =>
      rename_i crashedRequest kind maximumResponseBytes
      have differentRequest : request ≠ crashedRequest := by
        intro sameRequest
        subst request
        have sameOutcome := Option.some.inj (cached.symm.trans pending)
        subst outcome
        simp [BrokerOutcome.Terminal] at terminal
      simpa [BrokerState.crashPending, replace, differentRequest] using cached
  | recoverAcceptedPending accountingClear duplicate accepted owned inactive noEffect =>
      rename_i envelope kind maximumResponseBytes wire
      have differentRequest : request ≠ envelope.request := by
        intro sameRequest
        subst request
        have sameOutcome := Option.some.inj (cached.symm.trans accepted)
        subst outcome
        simp [BrokerOutcome.Terminal] at terminal
      simpa [BrokerState.recoverAcceptedPending, replace, differentRequest]
        using cached
  | recoverAcceptedPendingNew accountingClear replayAllowed accepted owned inactive noEffect =>
      rename_i envelope kind maximumResponseBytes wire
      have differentRequest : request ≠ envelope.request := by
        intro sameRequest
        subst request
        have sameOutcome := Option.some.inj (cached.symm.trans accepted)
        subst outcome
        simp [BrokerOutcome.Terminal] at terminal
      simpa [BrokerState.recoverAcceptedPendingNew, replace, differentRequest]
        using cached
  | recoverPending accountingClear duplicate pending owned noEffect allowed capMatch exactCharge =>
      rename_i envelope kind maximumResponseBytes responseBytes wire
      have differentRequest : request ≠ envelope.request := by
        intro sameRequest
        subst request
        have sameOutcome := Option.some.inj (cached.symm.trans pending)
        subst outcome
        simp [BrokerOutcome.Terminal] at terminal
      simpa [BrokerState.recoverPending, replace, differentRequest] using cached
  | retryStart accountingClear duplicate retryable wireAllowed budgetAllowed =>
      rename_i envelope kind maximumResponseBytes
      have differentRequest : request ≠ envelope.request := by
        intro sameRequest
        subst request
        have sameOutcome := Option.some.inj (cached.symm.trans retryable)
        subst outcome
        simp [BrokerOutcome.Terminal] at terminal
      simpa [BrokerState.retryStart, replace, differentRequest] using cached
  | retryFinalDenied accountingClear duplicate retryable wireAllowed denial representable =>
      rename_i envelope kind maximumResponseBytes wire
      have differentRequest : request ≠ envelope.request := by
        intro sameRequest
        subst request
        have sameOutcome := Option.some.inj (cached.symm.trans retryable)
        subst outcome
        simp [BrokerOutcome.Terminal] at terminal
      simpa [BrokerState.retryFinalDenied, BrokerState.storeOutcome, replace,
        differentRequest] using cached
  | linearizeEffect accountingClear pending noEffect owned =>
      rename_i effectRequest kind receipt
      have differentRequest : request ≠ effectRequest := by
        intro sameRequest
        subst request
        have sameOutcome := Option.some.inj (cached.symm.trans pending)
        subst outcome
        simp [BrokerOutcome.Terminal] at terminal
      simpa [BrokerState.linearizeEffect, replace, differentRequest] using cached
  | linearizeCommitUnknown accountingClear pending noEffect owned =>
      rename_i effectRequest
      have differentRequest : request ≠ effectRequest := by
        intro sameRequest
        subst request
        have sameOutcome := Option.some.inj (cached.symm.trans pending)
        subst outcome
        simp [BrokerOutcome.Terminal] at terminal
      simpa [BrokerState.linearizeCommitUnknown, replace, differentRequest] using cached
  | recordCommit linearized accountingTurn allowed =>
      rename_i committedRequest responseBytes receipt wire
      have differentRequest : request ≠ committedRequest := by
        intro sameRequest
        subst request
        have sameOutcome := Option.some.inj (cached.symm.trans linearized)
        subst outcome
        simp [BrokerOutcome.Terminal] at terminal
      simpa [BrokerState.recordCommit, replace, differentRequest] using cached
  | recordCommittedButUnrecorded linearized accountingTurn allowed exactCharge =>
      rename_i committedRequest effect responseBytes wire
      have differentRequest : request ≠ committedRequest := by
        intro sameRequest
        subst request
        have sameOutcome := Option.some.inj (cached.symm.trans linearized)
        subst outcome
        simp [BrokerOutcome.Terminal] at terminal
      simpa [BrokerState.recordCommittedButUnrecorded, replace, differentRequest] using cached
  | abortAfterEffect linearized accountingTurn allowed =>
      rename_i committedRequest receipt wire
      have differentRequest : request ≠ committedRequest := by
        intro sameRequest
        subst request
        have sameOutcome := Option.some.inj (cached.symm.trans linearized)
        subst outcome
        simp [BrokerOutcome.Terminal] at terminal
      simpa [BrokerState.abortAfterEffect, replace, differentRequest] using cached
  | deny accountingClear pending allowed =>
      rename_i deniedRequest kind wire
      have differentRequest : request ≠ deniedRequest := by
        intro sameRequest
        subst request
        have sameOutcome := Option.some.inj (cached.symm.trans pending)
        subst outcome
        simp [BrokerOutcome.Terminal] at terminal
      simpa [BrokerState.deny, replace, differentRequest] using cached
  | terminalDuplicate => exact cached

/-- One transition preserves the complete wire observation of a terminal cache. -/
theorem Step.observableWire_immutable {before after : BrokerState}
    (transition : Step before after) {request : BrokerRequestId}
    {outcome : BrokerOutcome} (cached : before.outcomes request = some outcome)
    (terminal : outcome.Terminal) :
    after.observableWire request = before.observableWire request := by
  have afterCached := transition.terminal_outcome_immutable cached terminal
  simp [observableWire, cached, afterCached]

/-- Replay finite accounting survives every composed broker transition. -/
theorem Step.preserves_replay_wellFormed {before after : BrokerState}
    (transition : Step before after) (wellFormed : before.replay.WellFormed) :
    after.replay.WellFormed := by
  cases transition with
  | markAcceptedPending => exact wellFormed
  | acceptPending _ replayAllowed _ _ =>
      exact ReplayState.acceptNew_preserves_wellFormed wellFormed replayAllowed
  | acceptRetryable _ replayAllowed _ _ _ _ =>
      exact ReplayState.acceptNew_preserves_wellFormed wellFormed replayAllowed
  | acceptFinalDenied _ replayAllowed _ _ _ _ =>
      exact ReplayState.acceptNew_preserves_wellFormed wellFormed replayAllowed
  | acceptAndStart _ replayAllowed _ _ _ =>
      exact ReplayState.acceptNew_preserves_wellFormed wellFormed replayAllowed
  | continueAcceptedRetryable | continueAcceptedFinalDenied | continueAcceptedStart |
      continuePublicOverWireCap | crashAcceptedPending | crashPending |
      recoverAcceptedPending | recoverPending | retryStart | retryFinalDenied | linearizeEffect |
      linearizeCommitUnknown | recordCommit | recordCommittedButUnrecorded |
      abortAfterEffect | deny | terminalDuplicate =>
      exact wellFormed
  | recoverAcceptedPendingNew _ replayAllowed _ _ _ _ =>
      exact ReplayState.acceptNew_preserves_wellFormed wellFormed replayAllowed

/-- Replay finite accounting survives every composed broker transition. -/
theorem Step.preserves_replay_accounting {before after : BrokerState}
    (transition : Step before after) (accounted : before.replay.FullyAccounted) :
    after.replay.FullyAccounted := by
  cases transition with
  | markAcceptedPending => exact accounted
  | acceptPending _ replayAllowed _ _ =>
      exact ReplayState.Step.preserves_accounting (.fresh replayAllowed) accounted
  | acceptRetryable _ replayAllowed _ _ _ _ =>
      exact ReplayState.Step.preserves_accounting (.fresh replayAllowed) accounted
  | acceptFinalDenied _ replayAllowed _ _ _ _ =>
      exact ReplayState.Step.preserves_accounting (.fresh replayAllowed) accounted
  | acceptAndStart _ replayAllowed _ _ _ =>
      exact ReplayState.Step.preserves_accounting (.fresh replayAllowed) accounted
  | continueAcceptedRetryable | continueAcceptedFinalDenied | continueAcceptedStart |
      continuePublicOverWireCap | crashAcceptedPending | crashPending |
      recoverAcceptedPending | recoverPending | retryStart | retryFinalDenied | linearizeEffect |
      linearizeCommitUnknown | recordCommit | recordCommittedButUnrecorded |
      abortAfterEffect | deny | terminalDuplicate => exact accounted
  | recoverAcceptedPendingNew _ replayAllowed _ _ _ _ =>
      exact ReplayState.Step.preserves_accounting (.fresh replayAllowed) accounted

/-- Budget finite accounting survives every composed broker transition. -/
theorem Step.preserves_budget_accounting {before after : BrokerState}
    (transition : Step before after) (accounted : before.budget.FullyAccounted) :
    after.budget.FullyAccounted := by
  cases transition with
  | markAcceptedPending | acceptPending | acceptRetryable | acceptFinalDenied |
      continueAcceptedRetryable | continueAcceptedFinalDenied |
      continuePublicOverWireCap | crashAcceptedPending | crashPending |
      recoverAcceptedPending | recoverAcceptedPendingNew |
      retryFinalDenied | linearizeEffect |
      linearizeCommitUnknown | terminalDuplicate => exact accounted
  | acceptAndStart _ _ _ _ budgetAllowed =>
      exact SessionBudget.Step.preserves_accounting (.start budgetAllowed) accounted
  | continueAcceptedStart _ _ _ _ _ _ budgetAllowed =>
      exact SessionBudget.Step.preserves_accounting (.start budgetAllowed) accounted
  | retryStart _ _ _ _ budgetAllowed =>
      exact SessionBudget.Step.preserves_accounting (.start budgetAllowed) accounted
  | recordCommit _ _ allowed =>
      exact SessionBudget.Step.preserves_accounting (.complete allowed) accounted
  | recordCommittedButUnrecorded _ _ allowed _ =>
      exact SessionBudget.Step.preserves_accounting (.complete allowed) accounted
  | recoverPending _ _ _ _ _ allowed _ =>
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
  | markAcceptedPending | acceptPending | acceptRetryable | acceptFinalDenied |
      continueAcceptedRetryable | continueAcceptedFinalDenied |
      continuePublicOverWireCap | crashAcceptedPending | crashPending |
      recoverAcceptedPending | recoverAcceptedPendingNew |
      retryFinalDenied | linearizeEffect |
      linearizeCommitUnknown | terminalDuplicate => exact withinLimits
  | acceptAndStart _ _ _ _ allowed | continueAcceptedStart _ _ _ _ _ _ allowed |
      retryStart _ _ _ _ allowed =>
      exact SessionBudget.Step.preserves_limits (.start allowed) withinLimits
  | recordCommit _ _ allowed | recordCommittedButUnrecorded _ _ allowed _ =>
      exact SessionBudget.Step.preserves_limits (.complete allowed) withinLimits
  | recoverPending _ _ _ _ _ allowed _ =>
      exact SessionBudget.Step.preserves_limits (.complete allowed) withinLimits
  | abortAfterEffect _ _ allowed | deny _ _ allowed =>
      exact SessionBudget.Step.preserves_limits (.abort allowed) withinLimits

/-- Checked budget transitions preserve the concrete `u64` representation boundary. -/
theorem Step.preserves_budget_countersRepresentable {before after : BrokerState}
    (transition : Step before after) (withinLimits : before.budget.WithinLimits)
    (representable : before.budget.CountersRepresentable) :
    after.budget.CountersRepresentable := by
  cases transition with
  | markAcceptedPending | acceptPending | acceptRetryable | acceptFinalDenied |
      continueAcceptedRetryable | continueAcceptedFinalDenied |
      continuePublicOverWireCap | crashAcceptedPending | crashPending |
      recoverAcceptedPending | recoverAcceptedPendingNew |
      retryFinalDenied | linearizeEffect |
      linearizeCommitUnknown | terminalDuplicate => exact representable
  | acceptAndStart _ _ _ _ allowed | continueAcceptedStart _ _ _ _ _ _ allowed |
      retryStart _ _ _ _ allowed =>
      exact SessionBudget.Step.preserves_countersRepresentable (.start allowed)
        withinLimits representable
  | recordCommit _ _ allowed | recordCommittedButUnrecorded _ _ allowed _ =>
      exact SessionBudget.Step.preserves_countersRepresentable (.complete allowed)
        withinLimits representable
  | recoverPending _ _ _ _ _ allowed _ =>
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

/-- Effect ambiguity persists through arbitrary retries and duplicates. -/
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

/-- Arbitrary later activity preserves a terminal request's canonical wire bytes. -/
theorem Steps.observableWire_immutable {before after : BrokerState}
    (transitions : Steps before after) {request : BrokerRequestId}
    {outcome : BrokerOutcome} (cached : before.outcomes request = some outcome)
    (terminal : outcome.Terminal) :
    after.observableWire request = before.observableWire request := by
  induction transitions with
  | refl => rfl
  | tail earlier transition inductionHypothesis =>
      rw [transition.observableWire_immutable
        (earlier.terminal_outcome_immutable cached terminal) terminal]
      exact inductionHypothesis

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

namespace Trace

private def publicSession : BrokerSessionId := { value := 41 }
private def publicRequest : BrokerRequestId := { value := 42 }
private def publicEnvelope : BrokerEnvelope where
  session := publicSession
  sequence := 0
  request := publicRequest
  payloadHash := { value := 43 }
private def publicMaximum : Nat := maxPublicWireBodyBytes + 1
private def publicWire : CanonicalWireOutcome := { digest := 44 }
private def publicLimits : SessionBudgetLimits where
  maxRequests := 1
  maxResponseBytes := publicMaximum
  maxConcurrentRequests := 1
private def publicInitial : BrokerState :=
  .empty publicSession 1 publicLimits
private def publicAccepted : BrokerState :=
  publicInitial.acceptPending publicEnvelope .publicFetch publicMaximum
private def publicFinal : BrokerState :=
  publicAccepted.continueAcceptedFinalDenied publicRequest publicWire

private theorem public_accepts_into_crash_gap :
    Step publicInitial publicAccepted := by
  apply Step.acceptPending
  · exact empty_accountingClear publicSession 1 publicLimits
  · exact {
      sessionMatches := rfl
      requestFresh := rfl
      sequenceExpected := rfl
      sequenceRepresentable := by
        simp [publicEnvelope, FitsU64, u64Maximum]
      capacityAvailable := by
        simp [publicInitial, BrokerState.empty, ReplayState.empty]
    }
  · simp [publicInitial, BrokerState.empty, publicEnvelope]
  · simp [publicMaximum, maxPublicWireBodyBytes, FitsU64, u64Maximum]

private theorem public_over_cap_is_terminal_before_start :
    Step publicAccepted publicFinal := by
  apply Step.continuePublicOverWireCap
      (envelope := publicEnvelope) (maximumResponseBytes := publicMaximum)
  · intro request effect
    by_cases sameRequest : request = publicRequest
    · subst request
      simp [publicAccepted, acceptPending, publicEnvelope, publicRequest]
    · simp [publicAccepted, publicInitial, acceptPending, publicEnvelope,
        publicRequest, BrokerState.empty, replace, sameRequest]
  · rfl
  · exact ⟨_, ReplayState.acceptNew_stores_exact_binding
      publicInitial.replay publicEnvelope⟩
  · rfl
  · rfl
  · simp [publicMaximum]

/-- A concrete max-plus-one public request is cached without budget or effect. -/
theorem public_over_wire_cap_trace :
    Steps publicInitial publicFinal ∧
      publicFinal.budget.startedRequests = 0 ∧
      publicFinal.effects publicRequest = false ∧
      publicFinal.observableWire publicRequest = some publicWire := by
  refine ⟨.tail (.tail (.refl publicInitial) public_accepts_into_crash_gap)
    public_over_cap_is_terminal_before_start, ?_⟩
  simp [publicFinal, publicAccepted, publicInitial, continueAcceptedFinalDenied,
    storeOutcome, acceptPending, observableWire, BrokerOutcome.wire?, publicRequest,
    BrokerState.empty, SessionBudget.empty]

private def githubSession : BrokerSessionId := { value := 51 }
private def githubRequest : BrokerRequestId := { value := 52 }
private def githubEnvelope : BrokerEnvelope where
  session := githubSession
  sequence := 0
  request := githubRequest
  payloadHash := { value := 53 }
private def githubMaximum : Nat := 64
private def githubWire : CanonicalWireOutcome := { digest := 54 }
private def githubLimits : SessionBudgetLimits where
  maxRequests := 1
  maxResponseBytes := githubMaximum
  maxConcurrentRequests := 1
private def githubInitial : BrokerState :=
  .empty githubSession 1 githubLimits
private def githubMarked : BrokerState :=
  githubInitial.markAcceptedPending githubEnvelope .githubMutation githubMaximum
private def githubMarkedCrashed : BrokerState :=
  githubMarked.crashDispatch githubRequest
private def githubRecoveredBeforeReplay : BrokerState :=
  githubMarkedCrashed.recoverAcceptedPendingNew githubEnvelope githubWire
private def githubAccepted : BrokerState :=
  githubInitial.acceptPending githubEnvelope .githubMutation githubMaximum
private def githubStarted : BrokerState :=
  githubAccepted.continueAcceptedStart githubRequest .githubMutation githubMaximum
private def githubAcceptedCrashed : BrokerState :=
  githubAccepted.crashDispatch githubRequest
private def githubRecoveredBeforeStart : BrokerState :=
  githubAcceptedCrashed.recoverAcceptedPending githubRequest githubWire
private def githubStartedCrashed : BrokerState :=
  githubStarted.crashPending githubRequest .githubMutation githubMaximum
private def githubRecoveredAfterStart : BrokerState :=
  githubStartedCrashed.recoverPending githubRequest
    { request := githubRequest, maxResponseBytes := githubMaximum }
    githubMaximum githubWire
private def githubUnknown : BrokerState :=
  githubStarted.linearizeCommitUnknown githubRequest
private def githubFinal : BrokerState :=
  githubUnknown.recordCommittedButUnrecorded githubRequest
    { request := githubRequest, maxResponseBytes := githubMaximum }
    githubMaximum githubWire

private theorem github_accepts_into_crash_gap :
    Step githubInitial githubAccepted := by
  apply Step.acceptPending
  · exact empty_accountingClear githubSession 1 githubLimits
  · exact {
      sessionMatches := rfl
      requestFresh := rfl
      sequenceExpected := rfl
      sequenceRepresentable := by
        simp [githubEnvelope, FitsU64, u64Maximum]
      capacityAvailable := by
        simp [githubInitial, BrokerState.empty, ReplayState.empty]
    }
  · simp [githubInitial, BrokerState.empty, githubEnvelope]
  · simp [githubMaximum, FitsU64, u64Maximum]

private def githubInitialMayAccept :
    githubInitial.replay.MayAcceptNew githubEnvelope := {
  sessionMatches := rfl
  requestFresh := rfl
  sequenceExpected := rfl
  sequenceRepresentable := by
    simp [githubEnvelope, FitsU64, u64Maximum]
  capacityAvailable := by
    simp [githubInitial, BrokerState.empty, ReplayState.empty]
}

private theorem github_marks_before_replay :
    Step githubInitial githubMarked := by
  exact Step.markAcceptedPending
    (empty_accountingClear githubSession 1 githubLimits)
    githubInitialMayAccept
    (by simp [githubInitial, BrokerState.empty, githubEnvelope])
    (by simp [githubMaximum, FitsU64, u64Maximum])

private theorem githubMarked_accountingClear : githubMarked.AccountingClear := by
  intro request effect
  by_cases sameRequest : request = githubRequest
  · subst request
    simp [githubMarked, markAcceptedPending, githubEnvelope, githubRequest]
  · simp [githubMarked, githubInitial, markAcceptedPending, githubEnvelope,
      githubRequest, BrokerState.empty, replace, sameRequest]

private theorem github_crashes_before_replay :
    Step githubMarked githubMarkedCrashed := by
  apply Step.crashAcceptedPending
  · exact githubMarked_accountingClear
  · rfl
  · simp [githubMarked, markAcceptedPending, githubEnvelope, githubRequest]

private theorem github_recovers_before_replay :
    Step githubMarkedCrashed githubRecoveredBeforeReplay := by
  exact (acceptedPending_new_recovery_without_charge
    (state := githubMarkedCrashed) (envelope := githubEnvelope)
    (kind := .githubMutation) (maximumResponseBytes := githubMaximum)
    (wire := githubWire)
    (by
      intro request effect
      simpa [githubMarkedCrashed, crashDispatch] using
        githubMarked_accountingClear request effect)
    (by simpa [githubMarkedCrashed, githubMarked, crashDispatch,
      markAcceptedPending] using githubInitialMayAccept)
    (by rfl)
    (by simp [githubMarkedCrashed, crashDispatch, githubEnvelope,
      githubRequest])
    (by simp [githubMarkedCrashed, githubMarked, githubInitial,
      crashDispatch, markAcceptedPending, BrokerState.empty,
      SessionBudget.empty, githubRequest])
    (by simp [githubMarkedCrashed, githubMarked, githubInitial,
      crashDispatch, markAcceptedPending, BrokerState.empty,
      githubRequest])).1

private theorem githubAccepted_accountingClear :
    githubAccepted.AccountingClear := by
  intro request effect
  by_cases sameRequest : request = githubRequest
  · subst request
    simp [githubAccepted, acceptPending, githubEnvelope, githubRequest]
  · simp [githubAccepted, githubInitial, acceptPending, githubEnvelope,
      githubRequest, BrokerState.empty, replace, sameRequest]

private theorem githubAccepted_duplicate :
    githubAccepted.replay.ExactDuplicate githubEnvelope :=
  ⟨rfl, ReplayState.acceptNew_stores_exact_binding
    githubInitial.replay githubEnvelope⟩

private theorem github_crashes_before_budget_start :
    Step githubAccepted githubAcceptedCrashed := by
  apply Step.crashAcceptedPending
  · exact githubAccepted_accountingClear
  · rfl
  · simp [githubAccepted, acceptPending, githubEnvelope, githubRequest]

private theorem github_recovers_before_budget_start :
    Step githubAcceptedCrashed githubRecoveredBeforeStart := by
  exact (acceptedPending_duplicate_recovers_without_charge
    (state := githubAcceptedCrashed) (envelope := githubEnvelope)
    (kind := .githubMutation) (maximumResponseBytes := githubMaximum)
    (wire := githubWire)
    (by
      intro request effect
      simpa [githubAcceptedCrashed, crashDispatch] using
        githubAccepted_accountingClear request effect)
    (by simpa [githubAcceptedCrashed, crashDispatch] using githubAccepted_duplicate)
    (by rfl)
    (by simp [githubAcceptedCrashed, crashDispatch, githubEnvelope,
      githubRequest])
    (by simp [githubAcceptedCrashed, githubAccepted, githubInitial,
      crashDispatch, acceptPending, BrokerState.empty, SessionBudget.empty,
      githubRequest])
    (by simp [githubAcceptedCrashed, githubAccepted, githubInitial,
      crashDispatch, acceptPending, BrokerState.empty, githubRequest])).1

private theorem github_recovers_and_starts_once :
    Step githubAccepted githubStarted := by
  change Step githubAccepted
    (githubAccepted.continueAcceptedStart githubEnvelope.request .githubMutation
      githubMaximum)
  apply Step.continueAcceptedStart
  · intro request effect
    by_cases sameRequest : request = githubRequest
    · subst request
      simp [githubAccepted, acceptPending, githubEnvelope, githubRequest]
    · simp [githubAccepted, githubInitial, acceptPending, githubEnvelope,
        githubRequest, BrokerState.empty, replace, sameRequest]
  · rfl
  · exact ⟨_, ReplayState.acceptNew_stores_exact_binding
      githubInitial.replay githubEnvelope⟩
  · rfl
  · simp [githubAccepted, acceptPending, githubEnvelope, githubRequest]
  · simp [WireAdmissible]
  · exact {
      requestInactive := rfl
      requestAvailable := by simp [githubAccepted, githubInitial,
        acceptPending, BrokerState.empty, SessionBudget.empty, githubLimits]
      concurrencyAvailable := by simp [githubAccepted, githubInitial,
        acceptPending, BrokerState.empty, SessionBudget.empty, githubLimits]
      bytesAvailable := by simp [githubAccepted, githubInitial,
        acceptPending, BrokerState.empty, SessionBudget.empty, githubLimits,
        githubMaximum]
    }

private theorem githubStarted_accountingClear :
    githubStarted.AccountingClear := by
  intro request effect
  by_cases sameRequest : request = githubRequest
  · subst request
    simp [githubStarted, continueAcceptedStart, retryStart, githubRequest]
  · have differentLiteral : request ≠ ({ value := 52 } : BrokerRequestId) := by
      simpa [githubRequest] using sameRequest
    simp [githubStarted, githubAccepted, githubInitial, continueAcceptedStart,
      retryStart, acceptPending, githubRequest, githubEnvelope,
      BrokerState.empty, replace, sameRequest, differentLiteral]

private theorem github_crashes_after_budget_start :
    Step githubStarted githubStartedCrashed := by
  apply Step.crashPending
  · exact githubStarted_accountingClear
  · rfl
  · simp [githubStarted, githubAccepted, continueAcceptedStart, retryStart,
      acceptPending, githubRequest]
  · rfl

private def githubCrashedCompletion :
    githubStartedCrashed.budget.MayComplete githubRequest githubMaximum := {
  reservation := { request := githubRequest, maxResponseBytes := githubMaximum }
  reservationLookup := by
    simp [githubStartedCrashed, githubStarted, githubAccepted, githubInitial,
      crashPending, continueAcceptedStart, retryStart, acceptPending,
      SessionBudget.start, githubRequest]
  requestBinding := rfl
  responseWithinReservation := Nat.le_refl _
  reservationAccounted := by
    simp [githubStartedCrashed, githubStarted, githubAccepted, githubInitial,
      crashPending, continueAcceptedStart, retryStart, acceptPending,
      SessionBudget.start, githubMaximum]
  activeAccounted := by
    simp [githubStartedCrashed, githubStarted, githubAccepted, githubInitial,
      crashPending, continueAcceptedStart, retryStart, acceptPending,
      SessionBudget.start]
}

private theorem github_recovers_after_budget_start :
    Step githubStartedCrashed githubRecoveredAfterStart := by
  exact (pending_duplicate_recovers_with_full_charge
    (state := githubStartedCrashed) (envelope := githubEnvelope)
    (kind := .githubMutation) (responseBytes := githubMaximum)
    (wire := githubWire)
    (by
      intro request effect
      by_cases sameRequest : request = githubRequest
      · subst request
        simp [githubStartedCrashed, crashPending, githubRequest]
      · have differentLiteral :
          request ≠ ({ value := 52 } : BrokerRequestId) := by
          simpa [githubRequest] using sameRequest
        simp [githubStartedCrashed, githubStarted, githubAccepted,
          githubInitial, crashPending, continueAcceptedStart, retryStart,
          acceptPending, BrokerState.empty, replace, sameRequest,
          differentLiteral, githubRequest, githubEnvelope])
    (by
      simpa [githubStartedCrashed, githubStarted, crashPending,
        continueAcceptedStart, retryStart] using githubAccepted_duplicate)
    (by rfl)
    (by simp [githubStartedCrashed, crashPending, githubEnvelope,
      githubRequest])
    (by simp [githubStartedCrashed, githubStarted, githubAccepted,
      githubInitial, crashPending, continueAcceptedStart, retryStart,
      acceptPending, BrokerState.empty, githubRequest])
    githubCrashedCompletion rfl rfl).1

/-- A marker crash before replay admission recovers terminally with no charge. -/
theorem github_marker_before_replay_recovery_trace :
    Steps githubInitial githubRecoveredBeforeReplay ∧
      githubRecoveredBeforeReplay.budget.startedRequests = 0 ∧
      githubRecoveredBeforeReplay.budget.committedResponseBytes = 0 ∧
      githubRecoveredBeforeReplay.budget.active githubRequest = none ∧
      githubRecoveredBeforeReplay.effects githubRequest = true ∧
      githubRecoveredBeforeReplay.outcomes githubRequest =
        some (.committedButUnrecorded githubWire) ∧
      githubRecoveredBeforeReplay.replay.ExactDuplicate githubEnvelope := by
  refine ⟨.tail (.tail (.tail (.refl githubInitial) github_marks_before_replay)
    github_crashes_before_replay) github_recovers_before_replay,
    by simp [githubRecoveredBeforeReplay, githubMarkedCrashed, githubMarked,
      githubInitial, recoverAcceptedPendingNew, crashDispatch,
      markAcceptedPending, BrokerState.empty, SessionBudget.empty],
    by simp [githubRecoveredBeforeReplay, githubMarkedCrashed, githubMarked,
      githubInitial, recoverAcceptedPendingNew, crashDispatch,
      markAcceptedPending, BrokerState.empty, SessionBudget.empty],
    by simp [githubRecoveredBeforeReplay, githubMarkedCrashed, githubMarked,
      githubInitial, recoverAcceptedPendingNew, crashDispatch,
      markAcceptedPending, BrokerState.empty, SessionBudget.empty, githubRequest],
    by simp [githubRecoveredBeforeReplay, recoverAcceptedPendingNew,
      githubEnvelope, githubRequest],
    by simp [githubRecoveredBeforeReplay, recoverAcceptedPendingNew,
      githubEnvelope, githubRequest], ?_⟩
  exact ⟨rfl, by
    simpa [githubRecoveredBeforeReplay, recoverAcceptedPendingNew] using
      (ReplayState.acceptNew_stores_exact_binding githubMarkedCrashed.replay
        githubEnvelope)⟩

private theorem githubRecoveredBeforeReplay_accountingClear :
    githubRecoveredBeforeReplay.AccountingClear := by
  intro request effect
  by_cases sameRequest : request = githubRequest
  · subst request
    simp [githubRecoveredBeforeReplay, recoverAcceptedPendingNew,
      githubEnvelope, githubRequest]
  · have differentLiteral : request ≠ ({ value := 52 } : BrokerRequestId) := by
      simpa [githubRequest] using sameRequest
    simp [githubRecoveredBeforeReplay, githubMarkedCrashed, githubMarked,
      githubInitial, recoverAcceptedPendingNew, crashDispatch,
      markAcceptedPending, BrokerState.empty, replace, sameRequest,
      differentLiteral, githubEnvelope, githubRequest]

/-- Recovery of the pre-replay marker makes its exact retry a wire no-op. -/
theorem github_marker_recovery_exact_retry :
    Step githubRecoveredBeforeReplay githubRecoveredBeforeReplay ∧
      githubRecoveredBeforeReplay.observableWire githubRequest = some githubWire := by
  simpa [githubEnvelope, githubRequest] using
    (terminal_duplicate_is_observational_noop
      (state := githubRecoveredBeforeReplay) (envelope := githubEnvelope)
      (outcome := .committedButUnrecorded githubWire) (wire := githubWire)
      githubRecoveredBeforeReplay_accountingClear
      github_marker_before_replay_recovery_trace.2.2.2.2.2.2
      github_marker_before_replay_recovery_trace.2.2.2.2.2.1
      rfl)

/-- Any later execution preserves a recovered pre-replay marker's observation. -/
theorem github_marker_recovery_survives_arbitrary_steps {after : BrokerState}
    (continuation : Steps githubRecoveredBeforeReplay after) :
    after.effects githubRequest = true ∧
      after.observableWire githubRequest = some githubWire := by
  constructor
  · exact continuation.effect_persists
      github_marker_before_replay_recovery_trace.2.2.2.2.1
  · have preserved := continuation.observableWire_immutable
      github_marker_before_replay_recovery_trace.2.2.2.2.2.1
      (by simp [BrokerOutcome.Terminal])
    rw [preserved]
    simp [observableWire,
      github_marker_before_replay_recovery_trace.2.2.2.2.2.1,
      BrokerOutcome.wire?]

/-- A pre-budget orphan becomes CBU without starting or charging a reservation. -/
theorem github_pre_budget_orphan_recovery_trace :
    Steps githubInitial githubRecoveredBeforeStart ∧
      githubRecoveredBeforeStart.budget.startedRequests = 0 ∧
      githubRecoveredBeforeStart.budget.committedResponseBytes = 0 ∧
      githubRecoveredBeforeStart.budget.active githubRequest = none ∧
      githubRecoveredBeforeStart.effects githubRequest = true ∧
      githubRecoveredBeforeStart.outcomes githubRequest =
        some (.committedButUnrecorded githubWire) := by
  refine ⟨.tail (.tail (.tail (.refl githubInitial)
    github_accepts_into_crash_gap) github_crashes_before_budget_start)
    github_recovers_before_budget_start, ?_⟩
  simp [githubRecoveredBeforeStart, githubAcceptedCrashed, githubAccepted,
    githubInitial, recoverAcceptedPending, crashDispatch, acceptPending,
    BrokerState.empty, SessionBudget.empty, githubRequest]

/-- A post-budget orphan becomes CBU and settles the full reservation cap. -/
theorem github_post_budget_orphan_recovery_trace :
    Steps githubInitial githubRecoveredAfterStart ∧
      githubRecoveredAfterStart.budget.startedRequests = 1 ∧
      githubRecoveredAfterStart.budget.committedResponseBytes = githubMaximum ∧
      githubRecoveredAfterStart.budget.active githubRequest = none ∧
      githubRecoveredAfterStart.effects githubRequest = true ∧
      githubRecoveredAfterStart.outcomes githubRequest =
        some (.committedButUnrecorded githubWire) := by
  refine ⟨.tail (.tail (.tail (.tail (.refl githubInitial)
    github_accepts_into_crash_gap) github_recovers_and_starts_once)
    github_crashes_after_budget_start) github_recovers_after_budget_start, ?_⟩
  simp [githubRecoveredAfterStart, githubStartedCrashed, githubStarted,
    githubAccepted, githubInitial, recoverPending, crashPending,
    continueAcceptedStart, retryStart, acceptPending, SessionBudget.start,
    SessionBudget.complete, SessionBudget.releaseReservation, BrokerState.empty,
    SessionBudget.empty, githubRequest, githubMaximum]

private theorem githubRecoveredBeforeStart_accountingClear :
    githubRecoveredBeforeStart.AccountingClear := by
  intro request effect
  by_cases sameRequest : request = githubRequest
  · subst request
    simp [githubRecoveredBeforeStart, recoverAcceptedPending, githubRequest]
  · have differentLiteral : request ≠ ({ value := 52 } : BrokerRequestId) := by
      simpa [githubRequest] using sameRequest
    simp [githubRecoveredBeforeStart, githubAcceptedCrashed, githubAccepted,
      githubInitial, recoverAcceptedPending, crashDispatch, acceptPending,
      BrokerState.empty, replace, sameRequest, differentLiteral, githubRequest,
      githubEnvelope]

private theorem githubRecoveredAfterStart_accountingClear :
    githubRecoveredAfterStart.AccountingClear := by
  intro request effect
  by_cases sameRequest : request = githubRequest
  · subst request
    simp [githubRecoveredAfterStart, recoverPending, githubRequest]
  · have differentLiteral : request ≠ ({ value := 52 } : BrokerRequestId) := by
      simpa [githubRequest] using sameRequest
    simp [githubRecoveredAfterStart, githubStartedCrashed, githubStarted,
      githubAccepted, githubInitial, recoverPending, crashPending,
      continueAcceptedStart, retryStart, acceptPending, BrokerState.empty,
      replace, sameRequest, differentLiteral, githubRequest, githubEnvelope]

/-- Both recovery shapes make the next exact retry a wire-identical state no-op. -/
theorem github_orphan_recovery_exact_retries :
    (Step githubRecoveredBeforeStart githubRecoveredBeforeStart ∧
      githubRecoveredBeforeStart.observableWire githubRequest = some githubWire) ∧
    (Step githubRecoveredAfterStart githubRecoveredAfterStart ∧
      githubRecoveredAfterStart.observableWire githubRequest = some githubWire) := by
  constructor
  · simpa [githubEnvelope, githubRequest] using
      (terminal_duplicate_is_observational_noop
        (state := githubRecoveredBeforeStart) (envelope := githubEnvelope)
        (outcome := .committedButUnrecorded githubWire) (wire := githubWire)
        githubRecoveredBeforeStart_accountingClear
        (by simpa [githubRecoveredBeforeStart, githubAcceptedCrashed,
          crashDispatch, recoverAcceptedPending] using githubAccepted_duplicate)
        github_pre_budget_orphan_recovery_trace.2.2.2.2.2
        rfl)
  · simpa [githubEnvelope, githubRequest] using
      (terminal_duplicate_is_observational_noop
        (state := githubRecoveredAfterStart) (envelope := githubEnvelope)
        (outcome := .committedButUnrecorded githubWire) (wire := githubWire)
        githubRecoveredAfterStart_accountingClear
        (by simpa [githubRecoveredAfterStart, githubStartedCrashed,
          githubStarted, crashPending, recoverPending, continueAcceptedStart,
          retryStart] using githubAccepted_duplicate)
        github_post_budget_orphan_recovery_trace.2.2.2.2.2
        rfl)

/-- Arbitrary executions preserve both recovered CBU wires and ambiguity bits. -/
theorem github_orphan_recoveries_survive_arbitrary_steps
    {beforeStartAfter afterStartAfter : BrokerState}
    (beforeStartContinuation :
      Steps githubRecoveredBeforeStart beforeStartAfter)
    (afterStartContinuation :
      Steps githubRecoveredAfterStart afterStartAfter) :
    (beforeStartAfter.effects githubRequest = true ∧
      beforeStartAfter.observableWire githubRequest = some githubWire) ∧
    (afterStartAfter.effects githubRequest = true ∧
      afterStartAfter.observableWire githubRequest = some githubWire) := by
  constructor
  · constructor
    · exact beforeStartContinuation.effect_persists
        github_pre_budget_orphan_recovery_trace.2.2.2.2.1
    · have preserved := beforeStartContinuation.observableWire_immutable
        github_pre_budget_orphan_recovery_trace.2.2.2.2.2
        (by simp [BrokerOutcome.Terminal])
      rw [preserved]
      simp [observableWire,
        github_pre_budget_orphan_recovery_trace.2.2.2.2.2,
        BrokerOutcome.wire?]
  · constructor
    · exact afterStartContinuation.effect_persists
        github_post_budget_orphan_recovery_trace.2.2.2.2.1
    · have preserved := afterStartContinuation.observableWire_immutable
        github_post_budget_orphan_recovery_trace.2.2.2.2.2
        (by simp [BrokerOutcome.Terminal])
      rw [preserved]
      simp [observableWire,
        github_post_budget_orphan_recovery_trace.2.2.2.2.2,
        BrokerOutcome.wire?]

/-- Both crash-recovery executions are genuinely state-changing. -/
theorem github_orphan_recovery_traces_nontrivial :
    githubInitial ≠ githubRecoveredBeforeStart ∧
      githubInitial ≠ githubRecoveredAfterStart := by
  constructor <;> intro sameState
  · have initialEffect : githubInitial.effects githubRequest = false := rfl
    rw [sameState, github_pre_budget_orphan_recovery_trace.2.2.2.2.1]
      at initialEffect
    simp at initialEffect
  · have initialEffect : githubInitial.effects githubRequest = false := rfl
    rw [sameState, github_post_budget_orphan_recovery_trace.2.2.2.2.1]
      at initialEffect
    simp at initialEffect

private theorem github_linearizes_commit_unknown :
    Step githubStarted githubUnknown := by
  apply Step.linearizeCommitUnknown
  · intro request effect
    by_cases sameRequest : request = githubRequest
    · subst request
      simp [githubStarted, continueAcceptedStart, retryStart, githubRequest]
    · have differentLiteral : request ≠ ({ value := 52 } : BrokerRequestId) := by
        simpa [githubRequest] using sameRequest
      simp [githubStarted, githubAccepted, githubInitial, continueAcceptedStart,
        retryStart, acceptPending, githubRequest, githubEnvelope,
        BrokerState.empty, replace, sameRequest, differentLiteral]
  · simp [githubStarted, continueAcceptedStart, retryStart, githubRequest]
  · simp [githubStarted, githubAccepted, githubInitial, continueAcceptedStart,
      retryStart, acceptPending, githubRequest, BrokerState.empty]
  · simp [githubStarted, githubAccepted, continueAcceptedStart, retryStart,
      acceptPending, githubRequest]

private def githubCompletion :
    githubUnknown.budget.MayComplete githubRequest githubMaximum := {
  reservation := { request := githubRequest, maxResponseBytes := githubMaximum }
  reservationLookup := by
    simp [githubUnknown, githubStarted, githubAccepted, githubInitial,
      linearizeCommitUnknown, continueAcceptedStart, retryStart, acceptPending,
      SessionBudget.start, githubRequest]
  requestBinding := rfl
  responseWithinReservation := Nat.le_refl _
  reservationAccounted := by
    simp [githubUnknown, githubStarted, githubAccepted, githubInitial,
      linearizeCommitUnknown, continueAcceptedStart, retryStart, acceptPending,
      SessionBudget.start, githubMaximum]
  activeAccounted := by
    simp [githubUnknown, githubStarted, githubAccepted, githubInitial,
      linearizeCommitUnknown, continueAcceptedStart, retryStart, acceptPending,
      SessionBudget.start]
}

private theorem github_unknown_becomes_charged_terminal :
    Step githubUnknown githubFinal := by
  exact Step.recordCommittedButUnrecorded
    (effect := .commitUnknown) (wire := githubWire)
    (by simp [githubUnknown, linearizeCommitUnknown, githubRequest])
    (linearizeCommitUnknown_starts_accounting_turn githubStarted githubRequest
      (by
        intro request effect
        by_cases sameRequest : request = githubRequest
        · subst request
          simp [githubStarted, continueAcceptedStart, retryStart, githubRequest]
        · have differentLiteral : request ≠ ({ value := 52 } : BrokerRequestId) := by
            simpa [githubRequest] using sameRequest
          simp [githubStarted, githubAccepted, githubInitial,
            continueAcceptedStart, retryStart, acceptPending, githubRequest,
            githubEnvelope, BrokerState.empty, replace, sameRequest,
            differentLiteral]))
    githubCompletion rfl

/-- Concrete GitHub ambiguity sets the conservative bit and charges the full cap. -/
theorem github_commit_unknown_trace :
    Steps githubInitial githubFinal ∧
      githubFinal.effects githubRequest = true ∧
      githubFinal.budget.committedResponseBytes = githubMaximum ∧
      githubFinal.budget.active githubRequest = none ∧
      githubFinal.outcomes githubRequest =
        some (.committedButUnrecorded githubWire) := by
  refine ⟨.tail (.tail (.tail (.tail (.refl githubInitial)
    github_accepts_into_crash_gap) github_recovers_and_starts_once)
    github_linearizes_commit_unknown) github_unknown_becomes_charged_terminal, ?_⟩
  simp [githubFinal, githubUnknown, githubStarted, githubAccepted, githubInitial,
    recordCommittedButUnrecorded, linearizeCommitUnknown, continueAcceptedStart,
    retryStart, acceptPending, SessionBudget.start, SessionBudget.complete,
    SessionBudget.releaseReservation, BrokerState.empty, SessionBudget.empty,
    githubRequest, githubMaximum]

/-- The concrete exact retry is a state no-op with byte-for-byte wire identity. -/
theorem github_commit_unknown_exact_retry :
    Step githubFinal githubFinal ∧
      githubFinal.observableWire githubRequest = some githubWire := by
  simpa [githubEnvelope, githubRequest] using
    (terminal_duplicate_is_observational_noop
      (state := githubFinal) (envelope := githubEnvelope)
      (outcome := .committedButUnrecorded githubWire) (wire := githubWire)
      (by
        intro request effect
        by_cases sameRequest : request = githubRequest
        · subst request
          simp [githubFinal, recordCommittedButUnrecorded, githubRequest]
        · have differentLiteral : request ≠ ({ value := 52 } : BrokerRequestId) := by
            simpa [githubRequest] using sameRequest
          simp [githubFinal, githubUnknown, githubStarted, githubAccepted,
            githubInitial, recordCommittedButUnrecorded,
            linearizeCommitUnknown, continueAcceptedStart, retryStart,
            acceptPending, githubRequest, githubEnvelope, BrokerState.empty,
            replace, sameRequest, differentLiteral])
      ⟨rfl, ReplayState.acceptNew_stores_exact_binding
        githubInitial.replay githubEnvelope⟩
      rfl
      rfl)

/-- The commit-unknown trace is genuinely state-changing, not a vacuous reflexive proof. -/
theorem github_commit_unknown_trace_nontrivial :
    githubInitial ≠ githubFinal ∧ Steps githubInitial githubFinal := by
  constructor
  · intro sameState
    have noInitialEffect : githubInitial.effects githubRequest = false := rfl
    have finalEffect : githubFinal.effects githubRequest = true :=
      github_commit_unknown_trace.2.1
    rw [sameState] at noInitialEffect
    rw [finalEffect] at noInitialEffect
    contradiction
  · exact github_commit_unknown_trace.1

/-- Every arbitrary continuation retains both ambiguity effect and wire result. -/
theorem github_commit_unknown_survives_arbitrary_steps {after : BrokerState}
    (continuation : Steps githubFinal after) :
    after.effects githubRequest = true ∧
      after.observableWire githubRequest = some githubWire := by
  constructor
  · exact continuation.effect_persists github_commit_unknown_trace.2.1
  · have preserved := continuation.observableWire_immutable
      github_commit_unknown_trace.2.2.2.2
      (by simp [BrokerOutcome.Terminal])
    rw [preserved]
    simp [observableWire, github_commit_unknown_trace.2.2.2.2,
      BrokerOutcome.wire?]

end Trace

end BrokerState

end Authority
