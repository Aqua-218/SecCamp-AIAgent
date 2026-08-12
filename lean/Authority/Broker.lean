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
  | retryableBudget
  | pending
  | finalDenied
  | committed (receipt : BrokerEffectReceipt)
  deriving Repr, DecidableEq

namespace BrokerOutcome

/-- Terminal outcomes can never re-enter dispatch. -/
def Terminal : BrokerOutcome → Prop
  | .finalDenied | .committed _ => True
  | .retryableBudget | .pending => False

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

/-- Accept a new replay binding and cache a retryable budget denial. -/
def acceptRetryable (state : BrokerState) (envelope : BrokerEnvelope) : BrokerState :=
  { state with
    replay := state.replay.acceptNew envelope
    outcomes := replace state.outcomes envelope.request (some .retryableBudget) }

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

/-- Commit one pending effect and its final cache entry. -/
def commit (state : BrokerState) (request : BrokerRequestId)
    (reservation : ResponseReservation) (responseBytes : Nat)
    (receipt : BrokerEffectReceipt) : BrokerState :=
  { state with
    budget := state.budget.complete request reservation responseBytes
    outcomes := replace state.outcomes request (some (.committed receipt))
    effects := replace state.effects request true }

/-- Abort one pending reservation and cache a terminal denial. -/
def deny (state : BrokerState) (request : BrokerRequestId)
    (reservation : ResponseReservation) : BrokerState :=
  { state with
    budget := state.budget.abort request reservation
    outcomes := replace state.outcomes request (some .finalDenied) }

/-- Accepted composed broker transitions. -/
inductive Step : BrokerState → BrokerState → Prop
  | acceptRetryable {state : BrokerState} {envelope : BrokerEnvelope} :
      state.replay.MayAcceptNew envelope →
      state.outcomes envelope.request = none →
      Step state (state.acceptRetryable envelope)
  | acceptAndStart {state : BrokerState} {envelope : BrokerEnvelope}
      {maximumResponseBytes : Nat} :
      state.replay.MayAcceptNew envelope →
      state.outcomes envelope.request = none →
      state.budget.MayStart envelope.request maximumResponseBytes →
      Step state (state.acceptAndStart envelope maximumResponseBytes)
  | retryStart {state : BrokerState} {envelope : BrokerEnvelope}
      {maximumResponseBytes : Nat} :
      state.replay.ExactDuplicate envelope →
      state.outcomes envelope.request = some .retryableBudget →
      state.budget.MayStart envelope.request maximumResponseBytes →
      Step state (state.retryStart envelope.request maximumResponseBytes)
  | commit {state : BrokerState} {request : BrokerRequestId}
      {responseBytes : Nat} {receipt : BrokerEffectReceipt} :
      state.outcomes request = some .pending →
      state.effects request = false →
      (allowed : state.budget.MayComplete request responseBytes) →
      Step state (state.commit request allowed.reservation responseBytes receipt)
  | deny {state : BrokerState} {request : BrokerRequestId} :
      state.outcomes request = some .pending →
      (allowed : state.budget.MayAbort request) →
      Step state (state.deny request allowed.reservation)
  | terminalDuplicate {state : BrokerState} {envelope : BrokerEnvelope}
      {outcome : BrokerOutcome} :
      state.replay.ExactDuplicate envelope →
      state.outcomes envelope.request = some outcome → outcome.Terminal →
      Step state state

/-- A committed transition stores both the terminal receipt and effect bit. -/
theorem commit_stores_effect (state : BrokerState) (request : BrokerRequestId)
    (reservation : ResponseReservation) (responseBytes : Nat)
    (receipt : BrokerEffectReceipt) :
    (state.commit request reservation responseBytes receipt).outcomes request =
      some (.committed receipt) ∧
    (state.commit request reservation responseBytes receipt).effects request = true := by
  simp [BrokerState.commit]

/-- Terminal exact duplicates are accepted only as a state-preserving step. -/
theorem terminal_duplicate_is_noop {state : BrokerState} {envelope : BrokerEnvelope}
    {outcome : BrokerOutcome}
    (duplicate : state.replay.ExactDuplicate envelope)
    (cached : state.outcomes envelope.request = some outcome)
    (terminal : outcome.Terminal) : Step state state :=
  .terminalDuplicate duplicate cached terminal

/-- Once an effect committed, no accepted transition can clear it. -/
theorem Step.effect_persists {before after : BrokerState}
    (transition : Step before after) {request : BrokerRequestId}
    (effect : before.effects request = true) : after.effects request = true := by
  cases transition with
  | acceptRetryable | acceptAndStart | retryStart | deny | terminalDuplicate => exact effect
  | commit pending noEffect allowed =>
      rename_i committedRequest responseBytes receipt
      by_cases sameRequest : request = committedRequest
      · subst request
        simp [BrokerState.commit]
      · simpa [BrokerState.commit, replace, sameRequest] using effect

/-- A terminal cached outcome is immutable across every accepted transition. -/
theorem Step.terminal_outcome_immutable {before after : BrokerState}
    (transition : Step before after) {request : BrokerRequestId}
    {outcome : BrokerOutcome} (cached : before.outcomes request = some outcome)
    (terminal : outcome.Terminal) : after.outcomes request = some outcome := by
  cases transition with
  | acceptRetryable replayAllowed cacheFresh =>
      rename_i envelope
      have differentRequest : request ≠ envelope.request := by
        intro sameRequest
        subst request
        rw [cached] at cacheFresh
        cases cacheFresh
      simpa [BrokerState.acceptRetryable, replace, differentRequest] using cached
  | acceptAndStart replayAllowed cacheFresh budgetAllowed =>
      rename_i envelope maximumResponseBytes
      have differentRequest : request ≠ envelope.request := by
        intro sameRequest
        subst request
        rw [cached] at cacheFresh
        cases cacheFresh
      simpa [BrokerState.acceptAndStart, replace, differentRequest] using cached
  | retryStart duplicate retryable budgetAllowed =>
      rename_i envelope maximumResponseBytes
      have differentRequest : request ≠ envelope.request := by
        intro sameRequest
        subst request
        have sameOutcome := Option.some.inj (cached.symm.trans retryable)
        subst outcome
        simp [BrokerOutcome.Terminal] at terminal
      simpa [BrokerState.retryStart, replace, differentRequest] using cached
  | commit pending noEffect allowed =>
      rename_i committedRequest responseBytes receipt
      have differentRequest : request ≠ committedRequest := by
        intro sameRequest
        subst request
        have sameOutcome := Option.some.inj (cached.symm.trans pending)
        subst outcome
        simp [BrokerOutcome.Terminal] at terminal
      simpa [BrokerState.commit, replace, differentRequest] using cached
  | deny pending allowed =>
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
theorem Step.preserves_replay_accounting {before after : BrokerState}
    (transition : Step before after) (accounted : before.replay.FullyAccounted) :
    after.replay.FullyAccounted := by
  cases transition with
  | acceptRetryable replayAllowed _ =>
      exact ReplayState.Step.preserves_accounting (.fresh replayAllowed) accounted
  | acceptAndStart replayAllowed _ _ =>
      exact ReplayState.Step.preserves_accounting (.fresh replayAllowed) accounted
  | retryStart | commit | deny | terminalDuplicate => exact accounted

/-- Budget finite accounting survives every composed broker transition. -/
theorem Step.preserves_budget_accounting {before after : BrokerState}
    (transition : Step before after) (accounted : before.budget.FullyAccounted) :
    after.budget.FullyAccounted := by
  cases transition with
  | acceptRetryable | terminalDuplicate => exact accounted
  | acceptAndStart _ _ budgetAllowed =>
      exact SessionBudget.Step.preserves_accounting (.start budgetAllowed) accounted
  | retryStart _ _ budgetAllowed =>
      exact SessionBudget.Step.preserves_accounting (.start budgetAllowed) accounted
  | commit _ _ allowed =>
      exact SessionBudget.Step.preserves_accounting (.complete allowed) accounted
  | deny _ allowed =>
      exact SessionBudget.Step.preserves_accounting (.abort allowed) accounted

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

end BrokerState

end Authority
