import Authority.Broker

/-!
# Broker Observation Refinement

Versioned logical observations for the composed broker state machine.  The
executable checks below validate supplied Lean data and its denotation; they do
not claim that a Rust process emitted the data or that the Rust source was
verified.
-/

namespace Authority.Refinement.Broker

abbrev ModelState := Authority.BrokerState

/-- The only observation schema understood by this checker. -/
def schemaVersion : Nat := 1

/-- Replay/cache phase visible at the Rust dispatch boundary. -/
inductive ReplayPhase where
  | markerBeforeReplay
  | acceptedPendingPreBudget
  | retryableBudget
  | acceptedPendingPostBudget
  | effectLinearized
  | terminal
  | exactRetry
  deriving Repr, BEq, DecidableEq

/-- Persistence boundary reported for the retained marker/audit/cache path. -/
inductive DurablePhase where
  | acceptedMarkerStored
  | replayBindingStored
  | budgetReservationLive
  | attemptStarted
  | terminalRecorded
  | terminalWriteFailed
  | recoveredAmbiguity
  | exactRetry
  deriving Repr, BEq, DecidableEq

/-- What is known about the external attempt at this observation point. -/
inductive AttemptOutcome where
  | notAttempted
  | failedBeforeCommit
  | committed (receipt : BrokerEffectReceipt)
  | commitUnknown
  | unobserved
  deriving Repr, BEq, DecidableEq

/-- Request metadata carried by the canonical Rust envelope and dispatch cap. -/
structure RequestContext where
  envelope : BrokerEnvelope
  operation : BrokerOperationKind
  responseCap : Nat
  deriving Repr, DecidableEq

namespace RequestContext

def request (context : RequestContext) : BrokerRequestId :=
  context.envelope.request

end RequestContext

/-- Exact scalar budget observation after one event. -/
structure BudgetObservation where
  reservation : Option Nat
  startedRequests : Nat
  committedResponseBytes : Nat
  reservedResponseBytes : Nat
  activeRequests : Nat
  deriving Repr, BEq, DecidableEq

namespace BudgetObservation

/-- Observe one request's reservation together with all aggregate counters. -/
def ofState (state : ModelState) (request : BrokerRequestId) : BudgetObservation where
  reservation := (state.budget.active request).map ResponseReservation.maxResponseBytes
  startedRequests := state.budget.startedRequests
  committedResponseBytes := state.budget.committedResponseBytes
  reservedResponseBytes := state.budget.reservedResponseBytes
  activeRequests := state.budget.activeRequests

end BudgetObservation

/-- Closed inventory of broker state-machine labels. -/
inductive Label where
  | markAcceptedPending
  | acceptPending
  | acceptRetryable
  | acceptFinalDenied (wire : CanonicalWireOutcome)
  | acceptAndStart
  | continueAcceptedRetryable
  | continueAcceptedFinalDenied (wire : CanonicalWireOutcome)
  | continueAcceptedStart
  | continuePublicOverWireCap (wire : CanonicalWireOutcome)
  | crashAcceptedPending
  | crashPending
  | recoverAcceptedPending (wire : CanonicalWireOutcome)
  | recoverAcceptedPendingNew (wire : CanonicalWireOutcome)
  | recoverPending (responseBytes : Nat) (wire : CanonicalWireOutcome)
  | retryStart
  | retryFinalDenied (wire : CanonicalWireOutcome)
  | linearizeEffect (receipt : BrokerEffectReceipt)
  | linearizeCommitUnknown
  | recordCommit (responseBytes : Nat) (receipt : BrokerEffectReceipt)
      (wire : CanonicalWireOutcome)
  | recordCommittedButUnrecorded (effect : BrokerLinearizedEffect)
      (responseBytes : Nat) (wire : CanonicalWireOutcome)
  | abortAfterEffect (receipt : BrokerEffectReceipt) (wire : CanonicalWireOutcome)
  | deny (wire : CanonicalWireOutcome)
  | terminalDuplicate (outcome : BrokerOutcome)
  deriving Repr, DecidableEq

namespace Label

/-- Phase expected after each closed transition label. -/
def expectedPhase : Label → ReplayPhase
  | .markAcceptedPending => .markerBeforeReplay
  | .acceptPending | .continueAcceptedRetryable | .crashAcceptedPending =>
      .acceptedPendingPreBudget
  | .acceptRetryable => .retryableBudget
  | .acceptAndStart | .continueAcceptedStart | .retryStart | .crashPending =>
      .acceptedPendingPostBudget
  | .linearizeEffect _ | .linearizeCommitUnknown => .effectLinearized
  | .acceptFinalDenied _ | .continueAcceptedFinalDenied _ |
      .continuePublicOverWireCap _ | .recoverAcceptedPending _ |
      .recoverAcceptedPendingNew _ | .recoverPending _ _ |
      .retryFinalDenied _ | .recordCommit _ _ _ |
      .recordCommittedButUnrecorded _ _ _ | .abortAfterEffect _ _ |
      .deny _ => .terminal
  | .terminalDuplicate _ => .exactRetry

/-- Attempt evidence expected from each transition label. -/
def expectedAttempt : Label → AttemptOutcome
  | .linearizeEffect receipt | .recordCommit _ receipt _ |
      .abortAfterEffect receipt _ => .committed receipt
  | .linearizeCommitUnknown => .commitUnknown
  | .recordCommittedButUnrecorded effect _ _ =>
      match effect with
      | .committed receipt => .committed receipt
      | .commitUnknown => .commitUnknown
  | .recoverAcceptedPending _ | .recoverAcceptedPendingNew _ |
      .recoverPending _ _ => .unobserved
  | .deny _ => .failedBeforeCommit
  | .crashAcceptedPending | .crashPending => .unobserved
  | .markAcceptedPending | .acceptPending | .acceptRetryable |
      .acceptFinalDenied _ | .acceptAndStart |
      .continueAcceptedRetryable | .continueAcceptedFinalDenied _ |
      .continueAcceptedStart | .continuePublicOverWireCap _ |
      .retryStart | .retryFinalDenied _ | .terminalDuplicate _ => .notAttempted

/-- Persistence phase expected from each broker label. -/
def expectedDurablePhase : Label → DurablePhase
  | .markAcceptedPending | .crashAcceptedPending | .crashPending =>
      .acceptedMarkerStored
  | .acceptPending | .acceptRetryable | .continueAcceptedRetryable =>
      .replayBindingStored
  | .acceptAndStart | .continueAcceptedStart | .retryStart =>
      .budgetReservationLive
  | .linearizeEffect _ | .linearizeCommitUnknown => .attemptStarted
  | .recordCommittedButUnrecorded _ _ _ => .terminalWriteFailed
  | .recoverAcceptedPending _ | .recoverAcceptedPendingNew _ |
      .recoverPending _ _ => .recoveredAmbiguity
  | .terminalDuplicate _ => .exactRetry
  | .acceptFinalDenied _ | .continueAcceptedFinalDenied _ |
      .continuePublicOverWireCap _ | .retryFinalDenied _ |
      .recordCommit _ _ _ | .abortAfterEffect _ _ | .deny _ => .terminalRecorded

end Label

/-- One versioned, request-bound broker transition observation. -/
structure Event where
  schemaVersion : Nat
  context : RequestContext
  label : Label
  replayPhase : ReplayPhase
  durablePhase : DurablePhase
  budget : BudgetObservation
  terminalWireDigest : Option Nat
  attemptOutcome : AttemptOutcome
  deriving Repr, DecidableEq

namespace Event

/-- Canonical terminal digest projection from the abstract cache. -/
def observedWireDigest (state : ModelState) (request : BrokerRequestId) : Option Nat :=
  (state.observableWire request).map CanonicalWireOutcome.digest

/-- Exact state-projectable meaning of all redundant event fields. -/
def Shape (event : Event) (after : ModelState) : Prop :=
  event.schemaVersion = Authority.Refinement.Broker.schemaVersion ∧
    event.context.envelope.session = after.replay.session ∧
    event.replayPhase = event.label.expectedPhase ∧
    event.durablePhase = event.label.expectedDurablePhase ∧
    event.budget = BudgetObservation.ofState after event.context.request ∧
    event.terminalWireDigest = observedWireDigest after event.context.request ∧
    event.attemptOutcome = event.label.expectedAttempt

/-- Constructive decision procedure for the finite event projection. -/
def shapeDecidable (event : Event) (after : ModelState) : Decidable (event.Shape after) := by
  unfold Shape
  infer_instance

/-- Executably validate every state-projectable event field. -/
def validateAt (event : Event) (after : ModelState) : Bool :=
  @decide (event.Shape after) (shapeDecidable event after)

/-- The executable shape check is sound for the supplied logical state. -/
theorem validateAt_sound {event : Event} {after : ModelState}
    (valid : event.validateAt after = true) : event.Shape after := by
  unfold validateAt at valid
  exact @of_decide_eq_true _ (shapeDecidable event after) valid

/-- Build the canonical current-version observation of a transition result. -/
def ofState (context : RequestContext) (label : Label)
    (after : ModelState) : Event where
  schemaVersion := Authority.Refinement.Broker.schemaVersion
  context := context
  label := label
  replayPhase := label.expectedPhase
  durablePhase := label.expectedDurablePhase
  budget := BudgetObservation.ofState after context.request
  terminalWireDigest := observedWireDigest after context.request
  attemptOutcome := label.expectedAttempt

/-- Canonically projected events pass the executable shape check. -/
theorem validateAt_ofState (context : RequestContext) (label : Label)
    (after : ModelState) (sessionBound : context.envelope.session = after.replay.session) :
    (ofState context label after).validateAt after = true := by
  simp [validateAt, shapeDecidable, Shape, ofState, sessionBound]

end Event

/-- Current Rust canonical response-chunk schema version. -/
def responseChunkSchemaVersion : Nat := 1

/-- Current expanded public response body ceiling (32 MiB). -/
def maxExpandedPublicBodyBytes : Nat := 32 * 1024 * 1024

/-- Current complete canonical response allocation ceiling. -/
def maxExpandedCanonicalResponseBytes : Nat :=
  maxExpandedPublicBodyBytes + 253 + 8 * 1024 + 128

/-- Maximum bytes carried by one canonical response chunk. -/
def maxResponseChunkBytes : Nat := 1024 * 1024 - 128

/-- Canonical nonzero chunk count used by Rust's `div_ceil`. -/
def canonicalChunkCount (totalLength : Nat) : Nat :=
  (totalLength + maxResponseChunkBytes - 1) / maxResponseChunkBytes

/-- Canonical payload length for one zero-based chunk index. -/
def canonicalChunkLength (totalLength index : Nat) : Nat :=
  min (totalLength - index * maxResponseChunkBytes) maxResponseChunkBytes

/-- Shared request/digest/length metadata for a canonical chunk sequence. -/
structure ChunkManifest where
  schemaVersion : Nat
  requestId : BrokerRequestId
  chunkCount : Nat
  totalLength : Nat
  completeWireDigest : Nat
  deriving Repr, BEq, DecidableEq

/-- One finite observation of Rust's seven-field canonical chunk wire. -/
structure ChunkObservation where
  manifest : ChunkManifest
  chunkIndex : Nat
  payloadBytes : Nat
  deriving Repr, BEq, DecidableEq

namespace ChunkObservation

/-- Exact request/digest/bounds/length meaning of one supplied chunk. -/
def ValidFor (chunk : ChunkObservation) (event : Event) : Prop :=
  chunk.manifest.schemaVersion = responseChunkSchemaVersion ∧
    chunk.manifest.requestId = event.context.request ∧
    event.terminalWireDigest = some chunk.manifest.completeWireDigest ∧
    0 < chunk.manifest.totalLength ∧
    chunk.manifest.totalLength ≤ maxExpandedCanonicalResponseBytes ∧
    chunk.manifest.chunkCount = canonicalChunkCount chunk.manifest.totalLength ∧
    chunk.chunkIndex < chunk.manifest.chunkCount ∧
    chunk.payloadBytes = canonicalChunkLength chunk.manifest.totalLength chunk.chunkIndex

end ChunkObservation

/-- Ordered chunks all share one manifest and carry consecutive indices. -/
def OrderedChunks (event : Event) (manifest : ChunkManifest) :
    Nat → List ChunkObservation → Prop
  | _, [] => True
  | expectedIndex, chunk :: remaining =>
      chunk.manifest = manifest ∧ chunk.chunkIndex = expectedIndex ∧
        chunk.ValidFor event ∧ OrderedChunks event manifest (expectedIndex + 1) remaining

/-- Exact finite trace meaning of a complete canonical chunk sequence. -/
def ChunkTraceValid (event : Event) : List ChunkObservation → Prop
  | [] => False
  | first :: remaining =>
      (first :: remaining).length = first.manifest.chunkCount ∧
        OrderedChunks event first.manifest 0 (first :: remaining)

/-- Constructive decision procedure for one canonical chunk member. -/
def chunkValidDecidable (event : Event) (chunk : ChunkObservation) :
    Decidable (chunk.ValidFor event) := by
  unfold ChunkObservation.ValidFor
  infer_instance

/-- Executable validity check for one canonical chunk member. -/
def checkChunk (event : Event) (chunk : ChunkObservation) : Bool :=
  @decide (chunk.ValidFor event) (chunkValidDecidable event chunk)

/-- Executably check a finite sequence's manifest and consecutive indices. -/
def checkOrderedChunks (event : Event) (manifest : ChunkManifest) :
    Nat → List ChunkObservation → Bool
  | _, [] => true
  | expectedIndex, chunk :: remaining =>
      decide (chunk.manifest = manifest) && decide (chunk.chunkIndex = expectedIndex) &&
        checkChunk event chunk &&
          checkOrderedChunks event manifest (expectedIndex + 1) remaining

/-- Ordered-chunk checking is sound for the supplied finite list. -/
theorem checkOrderedChunks_sound {event : Event} {manifest : ChunkManifest}
    {expectedIndex : Nat} {chunks : List ChunkObservation}
    (accepted : checkOrderedChunks event manifest expectedIndex chunks = true) :
    OrderedChunks event manifest expectedIndex chunks := by
  induction chunks generalizing expectedIndex with
  | nil => trivial
  | cons chunk remaining inductionHypothesis =>
      simp only [checkOrderedChunks, Bool.and_eq_true] at accepted
      rcases accepted with ⟨⟨⟨sameManifest, sameIndex⟩, valid⟩, rest⟩
      refine ⟨of_decide_eq_true sameManifest, of_decide_eq_true sameIndex, ?_,
        inductionHypothesis rest⟩
      unfold checkChunk at valid
      exact @of_decide_eq_true _ (chunkValidDecidable event chunk) valid

/-- Executably check the complete ordered chunk manifest and every member. -/
def checkChunkTrace (event : Event) (chunks : List ChunkObservation) : Bool :=
  match chunks with
  | [] => false
  | first :: remaining =>
      decide ((first :: remaining).length = first.manifest.chunkCount) &&
        checkOrderedChunks event first.manifest 0 (first :: remaining)

/-- Chunk-trace acceptance proves only the supplied finite wire metadata. -/
theorem checkChunkTrace_sound {event : Event} {chunks : List ChunkObservation}
    (accepted : checkChunkTrace event chunks = true) : ChunkTraceValid event chunks := by
  cases chunks with
  | nil => simp [checkChunkTrace] at accepted
  | cons first remaining =>
      simp only [checkChunkTrace, Bool.and_eq_true] at accepted
      exact ⟨of_decide_eq_true accepted.1, checkOrderedChunks_sound accepted.2⟩

/-- The current expanded body cap is exactly 32 MiB. -/
theorem expanded_public_body_cap_is_32_mib :
    maxExpandedPublicBodyBytes = 33_554_432 := by decide

/-- Versioned state snapshot with independently checked replay and budget scalars. -/
structure StateSnapshot where
  schemaVersion : Nat
  model : ModelState
  session : BrokerSessionId
  nextSequence : Option Nat
  replayCapacity : Nat
  acceptedCount : Nat
  maxRequests : Nat
  maxResponseBytes : Nat
  maxConcurrentRequests : Nat
  startedRequests : Nat
  committedResponseBytes : Nat
  reservedResponseBytes : Nat
  activeRequests : Nat

namespace StateSnapshot

/-- Consistency of the redundant finite snapshot with its denoted model. -/
def Consistent (snapshot : StateSnapshot) : Prop :=
  snapshot.schemaVersion = Authority.Refinement.Broker.schemaVersion ∧
    snapshot.session = snapshot.model.replay.session ∧
    snapshot.nextSequence = snapshot.model.replay.nextSequence ∧
    snapshot.replayCapacity = snapshot.model.replay.capacity ∧
    snapshot.acceptedCount = snapshot.model.replay.acceptedCount ∧
    snapshot.maxRequests = snapshot.model.budget.limits.maxRequests ∧
    snapshot.maxResponseBytes = snapshot.model.budget.limits.maxResponseBytes ∧
    snapshot.maxConcurrentRequests = snapshot.model.budget.limits.maxConcurrentRequests ∧
    snapshot.startedRequests = snapshot.model.budget.startedRequests ∧
    snapshot.committedResponseBytes = snapshot.model.budget.committedResponseBytes ∧
    snapshot.reservedResponseBytes = snapshot.model.budget.reservedResponseBytes ∧
    snapshot.activeRequests = snapshot.model.budget.activeRequests

/-- Logical denotation of a checked snapshot. -/
def Denotes (snapshot : StateSnapshot) (state : ModelState) : Prop :=
  snapshot.model = state ∧ snapshot.Consistent

/-- Construct the canonical snapshot of an abstract broker state. -/
def ofState (state : ModelState) : StateSnapshot where
  schemaVersion := Authority.Refinement.Broker.schemaVersion
  model := state
  session := state.replay.session
  nextSequence := state.replay.nextSequence
  replayCapacity := state.replay.capacity
  acceptedCount := state.replay.acceptedCount
  maxRequests := state.budget.limits.maxRequests
  maxResponseBytes := state.budget.limits.maxResponseBytes
  maxConcurrentRequests := state.budget.limits.maxConcurrentRequests
  startedRequests := state.budget.startedRequests
  committedResponseBytes := state.budget.committedResponseBytes
  reservedResponseBytes := state.budget.reservedResponseBytes
  activeRequests := state.budget.activeRequests

/-- Constructive decision procedure for the finite state projection. -/
def consistentDecidable (snapshot : StateSnapshot) : Decidable snapshot.Consistent := by
  unfold Consistent
  infer_instance

/-- Executably reject unknown versions and inconsistent scalar observations. -/
def validate (snapshot : StateSnapshot) : Bool :=
  @decide snapshot.Consistent (consistentDecidable snapshot)

/-- Canonical state snapshots pass validation. -/
theorem validate_ofState (state : ModelState) : (ofState state).validate = true := by
  simp [validate, Consistent, ofState]

/-- Validation proves denotation only for the supplied logical model. -/
theorem validate_sound {snapshot : StateSnapshot}
    (valid : snapshot.validate = true) : snapshot.Denotes snapshot.model := by
  refine ⟨rfl, ?_⟩
  unfold validate at valid
  exact @of_decide_eq_true _ (consistentDecidable snapshot) valid

/-- Canonical snapshots denote their source state. -/
theorem ofState_denotes (state : ModelState) : (ofState state).Denotes state := by
  simp [Denotes, Consistent, ofState]

end StateSnapshot

/-- Label-specific evidence tied to exact constructors of `BrokerState.Step`. -/
inductive Accepted : Label → RequestContext → ModelState → ModelState → Prop
  | markAcceptedPending {state : ModelState} {context : RequestContext}
      (accountingClear : state.AccountingClear)
      (replayAllowed : state.replay.MayAcceptNew context.envelope)
      (fresh : state.outcomes context.request = none)
      (capFits : FitsU64 context.responseCap) :
      Accepted .markAcceptedPending context state
        (state.markAcceptedPending context.envelope context.operation context.responseCap)
  | acceptPending {state : ModelState} {context : RequestContext}
      (accountingClear : state.AccountingClear)
      (replayAllowed : state.replay.MayAcceptNew context.envelope)
      (fresh : state.outcomes context.request = none)
      (capFits : FitsU64 context.responseCap) :
      Accepted .acceptPending context state
        (state.acceptPending context.envelope context.operation context.responseCap)
  | acceptRetryable {state : ModelState} {context : RequestContext}
      (accountingClear : state.AccountingClear)
      (replayAllowed : state.replay.MayAcceptNew context.envelope)
      (fresh : state.outcomes context.request = none)
      (wireAdmissible : WireAdmissible context.operation context.responseCap)
      (denied : BrokerState.RetryableStartDenial state.budget context.request
        context.responseCap) (capFits : FitsU64 context.responseCap) :
      Accepted .acceptRetryable context state
        (state.acceptRetryable context.envelope context.operation context.responseCap)
  | acceptFinalDenied {state : ModelState} {context : RequestContext}
      {wire : CanonicalWireOutcome}
      (accountingClear : state.AccountingClear)
      (replayAllowed : state.replay.MayAcceptNew context.envelope)
      (fresh : state.outcomes context.request = none)
      (wireAdmissible : WireAdmissible context.operation context.responseCap)
      (denied : BrokerState.PermanentStartDenial state.budget context.request
        context.responseCap) (capFits : FitsU64 context.responseCap) :
      Accepted (.acceptFinalDenied wire) context state
        (state.acceptFinalDenied context.envelope wire)
  | acceptAndStart {state : ModelState} {context : RequestContext}
      (accountingClear : state.AccountingClear)
      (replayAllowed : state.replay.MayAcceptNew context.envelope)
      (fresh : state.outcomes context.request = none)
      (wireAdmissible : WireAdmissible context.operation context.responseCap)
      (allowed : state.budget.MayStart context.request context.responseCap) :
      Accepted .acceptAndStart context state
        (state.acceptAndStart context.envelope context.operation context.responseCap)
  | continueAcceptedRetryable {state : ModelState} {context : RequestContext}
      (accountingClear : state.AccountingClear)
      (pending : state.outcomes context.request =
        some (.acceptedPending context.operation context.responseCap))
      (bound : state.HasReplayBinding context.request)
      (inactive : state.budget.active context.request = none)
      (owned : state.dispatchOwned context.request = true)
      (wireAdmissible : WireAdmissible context.operation context.responseCap)
      (denied : BrokerState.RetryableStartDenial state.budget context.request
        context.responseCap) (capFits : FitsU64 context.responseCap) :
      Accepted .continueAcceptedRetryable context state
        (state.continueAcceptedRetryable context.request context.operation context.responseCap)
  | continueAcceptedFinalDenied {state : ModelState} {context : RequestContext}
      {wire : CanonicalWireOutcome}
      (accountingClear : state.AccountingClear)
      (pending : state.outcomes context.request =
        some (.acceptedPending context.operation context.responseCap))
      (bound : state.HasReplayBinding context.request)
      (inactive : state.budget.active context.request = none)
      (owned : state.dispatchOwned context.request = true)
      (wireAdmissible : WireAdmissible context.operation context.responseCap)
      (denied : BrokerState.PermanentStartDenial state.budget context.request
        context.responseCap) (capFits : FitsU64 context.responseCap) :
      Accepted (.continueAcceptedFinalDenied wire) context state
        (state.continueAcceptedFinalDenied context.request wire)
  | continueAcceptedStart {state : ModelState} {context : RequestContext}
      (accountingClear : state.AccountingClear)
      (pending : state.outcomes context.request =
        some (.acceptedPending context.operation context.responseCap))
      (bound : state.HasReplayBinding context.request)
      (inactive : state.budget.active context.request = none)
      (owned : state.dispatchOwned context.request = true)
      (wireAdmissible : WireAdmissible context.operation context.responseCap)
      (allowed : state.budget.MayStart context.request context.responseCap) :
      Accepted .continueAcceptedStart context state
        (state.continueAcceptedStart context.request context.operation context.responseCap)
  | continuePublicOverWireCap {state : ModelState} {context : RequestContext}
      {wire : CanonicalWireOutcome}
      (publicKind : context.operation = .publicFetch)
      (accountingClear : state.AccountingClear)
      (pending : state.outcomes context.request =
        some (.acceptedPending .publicFetch context.responseCap))
      (bound : state.HasReplayBinding context.request)
      (inactive : state.budget.active context.request = none)
      (owned : state.dispatchOwned context.request = true)
      (overCap : maxPublicWireBodyBytes < context.responseCap) :
      Accepted (.continuePublicOverWireCap wire) context state
        (state.continueAcceptedFinalDenied context.request wire)
  | crashAcceptedPending {state : ModelState} {context : RequestContext}
      (accountingClear : state.AccountingClear)
      (pending : state.outcomes context.request =
        some (.acceptedPending context.operation context.responseCap))
      (owned : state.dispatchOwned context.request = true) :
      Accepted .crashAcceptedPending context state (state.crashDispatch context.request)
  | crashPending {state : ModelState} {context : RequestContext}
      (accountingClear : state.AccountingClear)
      (pending : state.outcomes context.request = some (.pending context.operation))
      (owned : state.dispatchOwned context.request = true)
      (reservation : state.budget.active context.request = some {
        request := context.request, maxResponseBytes := context.responseCap }) :
      Accepted .crashPending context state
        (state.crashPending context.request context.operation context.responseCap)
  | recoverAcceptedPending {state : ModelState} {context : RequestContext}
      {wire : CanonicalWireOutcome}
      (accountingClear : state.AccountingClear)
      (duplicate : state.replay.ExactDuplicate context.envelope)
      (pending : state.outcomes context.request =
        some (.acceptedPending context.operation context.responseCap))
      (unowned : state.dispatchOwned context.request = false)
      (inactive : state.budget.active context.request = none)
      (noEffect : state.effects context.request = false) :
      Accepted (.recoverAcceptedPending wire) context state
        (state.recoverAcceptedPending context.request wire)
  | recoverAcceptedPendingNew {state : ModelState} {context : RequestContext}
      {wire : CanonicalWireOutcome}
      (accountingClear : state.AccountingClear)
      (replayAllowed : state.replay.MayAcceptNew context.envelope)
      (pending : state.outcomes context.request =
        some (.acceptedPending context.operation context.responseCap))
      (unowned : state.dispatchOwned context.request = false)
      (inactive : state.budget.active context.request = none)
      (noEffect : state.effects context.request = false) :
      Accepted (.recoverAcceptedPendingNew wire) context state
        (state.recoverAcceptedPendingNew context.envelope wire)
  | recoverPending {state : ModelState} {context : RequestContext}
      {responseBytes : Nat} {wire : CanonicalWireOutcome}
      (accountingClear : state.AccountingClear)
      (duplicate : state.replay.ExactDuplicate context.envelope)
      (pending : state.outcomes context.request =
        some (.acceptedPending context.operation context.responseCap))
      (unowned : state.dispatchOwned context.request = false)
      (noEffect : state.effects context.request = false)
      (allowed : state.budget.MayComplete context.request responseBytes)
      (capExact : allowed.reservation.maxResponseBytes = context.responseCap)
      (fullCharge : responseBytes = allowed.reservation.maxResponseBytes) :
      Accepted (.recoverPending responseBytes wire) context state
        (state.recoverPending context.request allowed.reservation responseBytes wire)
  | retryStart {state : ModelState} {context : RequestContext}
      (accountingClear : state.AccountingClear)
      (duplicate : state.replay.ExactDuplicate context.envelope)
      (retryable : state.outcomes context.request =
        some (.retryableBudget context.operation context.responseCap))
      (wireAdmissible : WireAdmissible context.operation context.responseCap)
      (allowed : state.budget.MayStart context.request context.responseCap) :
      Accepted .retryStart context state
        (state.retryStart context.request context.operation context.responseCap)
  | retryFinalDenied {state : ModelState} {context : RequestContext}
      {wire : CanonicalWireOutcome}
      (accountingClear : state.AccountingClear)
      (duplicate : state.replay.ExactDuplicate context.envelope)
      (retryable : state.outcomes context.request =
        some (.retryableBudget context.operation context.responseCap))
      (wireAdmissible : WireAdmissible context.operation context.responseCap)
      (denied : BrokerState.PermanentStartDenial state.budget context.request
        context.responseCap) (capFits : FitsU64 context.responseCap) :
      Accepted (.retryFinalDenied wire) context state
        (state.retryFinalDenied context.request wire)
  | linearizeEffect {state : ModelState} {context : RequestContext}
      {receipt : BrokerEffectReceipt}
      (accountingClear : state.AccountingClear)
      (pending : state.outcomes context.request = some (.pending context.operation))
      (noEffect : state.effects context.request = false)
      (owned : state.dispatchOwned context.request = true) :
      Accepted (.linearizeEffect receipt) context state
        (state.linearizeEffect context.request receipt)
  | linearizeCommitUnknown {state : ModelState} {context : RequestContext}
      (githubKind : context.operation = .githubMutation)
      (accountingClear : state.AccountingClear)
      (pending : state.outcomes context.request = some (.pending .githubMutation))
      (noEffect : state.effects context.request = false)
      (owned : state.dispatchOwned context.request = true) :
      Accepted .linearizeCommitUnknown context state
        (state.linearizeCommitUnknown context.request)
  | recordCommit {state : ModelState} {context : RequestContext}
      {responseBytes : Nat} {receipt : BrokerEffectReceipt}
      {wire : CanonicalWireOutcome}
      (linearized : state.outcomes context.request =
        some (.effectLinearized (.committed receipt)))
      (turn : state.AccountingTurn context.request)
      (allowed : state.budget.MayComplete context.request responseBytes)
      (capExact : allowed.reservation.maxResponseBytes = context.responseCap) :
      Accepted (.recordCommit responseBytes receipt wire) context state
        (state.recordCommit context.request allowed.reservation responseBytes receipt wire)
  | recordCommittedButUnrecorded {state : ModelState} {context : RequestContext}
      {effect : BrokerLinearizedEffect} {responseBytes : Nat}
      {wire : CanonicalWireOutcome}
      (linearized : state.outcomes context.request = some (.effectLinearized effect))
      (turn : state.AccountingTurn context.request)
      (allowed : state.budget.MayComplete context.request responseBytes)
      (capExact : allowed.reservation.maxResponseBytes = context.responseCap)
      (fullCharge : responseBytes = allowed.reservation.maxResponseBytes) :
      Accepted (.recordCommittedButUnrecorded effect responseBytes wire) context state
        (state.recordCommittedButUnrecorded context.request allowed.reservation
          responseBytes wire)
  | abortAfterEffect {state : ModelState} {context : RequestContext}
      {receipt : BrokerEffectReceipt} {wire : CanonicalWireOutcome}
      (linearized : state.outcomes context.request =
        some (.effectLinearized (.committed receipt)))
      (turn : state.AccountingTurn context.request)
      (allowed : state.budget.MayAbort context.request)
      (capExact : allowed.reservation.maxResponseBytes = context.responseCap) :
      Accepted (.abortAfterEffect receipt wire) context state
        (state.abortAfterEffect context.request allowed.reservation wire)
  | deny {state : ModelState} {context : RequestContext}
      {wire : CanonicalWireOutcome}
      (accountingClear : state.AccountingClear)
      (pending : state.outcomes context.request = some (.pending context.operation))
      (allowed : state.budget.MayAbort context.request)
      (capExact : allowed.reservation.maxResponseBytes = context.responseCap) :
      Accepted (.deny wire) context state
        (state.deny context.request allowed.reservation wire)
  | terminalDuplicate {state : ModelState} {context : RequestContext}
      {outcome : BrokerOutcome}
      (accountingClear : state.AccountingClear)
      (duplicate : state.replay.ExactDuplicate context.envelope)
      (cached : state.outcomes context.request = some outcome)
      (terminal : outcome.Terminal) :
      Accepted (.terminalDuplicate outcome) context state state

/-- Every accepted label is exactly one existing abstract broker step. -/
theorem Accepted.toStep {label : Label} {context : RequestContext}
    {before after : ModelState} (accepted : Accepted label context before after) :
    BrokerState.Step before after := by
  cases accepted with
  | markAcceptedPending clear replay fresh fits =>
      exact .markAcceptedPending clear replay fresh fits
  | acceptPending clear replay fresh fits => exact .acceptPending clear replay fresh fits
  | acceptRetryable clear replay fresh wire denied fits =>
      exact .acceptRetryable clear replay fresh wire denied fits
  | acceptFinalDenied clear replay fresh wire denied fits =>
      exact .acceptFinalDenied clear replay fresh wire denied fits
  | acceptAndStart clear replay fresh wire allowed =>
      exact .acceptAndStart clear replay fresh wire allowed
  | continueAcceptedRetryable clear pending bound inactive owned wire denied fits =>
      exact .continueAcceptedRetryable clear pending bound inactive owned wire denied fits
  | continueAcceptedFinalDenied clear pending bound inactive owned wire denied fits =>
      exact .continueAcceptedFinalDenied clear pending bound inactive owned wire denied fits
  | continueAcceptedStart clear pending bound inactive owned wire allowed =>
      exact .continueAcceptedStart clear pending bound inactive owned wire allowed
  | continuePublicOverWireCap _publicKind clear pending bound inactive owned overCap =>
      exact .continuePublicOverWireCap clear pending bound inactive owned overCap
  | crashAcceptedPending clear pending owned => exact .crashAcceptedPending clear pending owned
  | crashPending clear pending owned reservation => exact .crashPending clear pending owned reservation
  | recoverAcceptedPending clear duplicate pending unowned inactive noEffect =>
      exact .recoverAcceptedPending clear duplicate pending unowned inactive noEffect
  | recoverAcceptedPendingNew clear replay pending unowned inactive noEffect =>
      exact .recoverAcceptedPendingNew clear replay pending unowned inactive noEffect
  | recoverPending clear duplicate pending unowned noEffect allowed capExact fullCharge =>
      exact .recoverPending clear duplicate pending unowned noEffect allowed capExact fullCharge
  | retryStart clear duplicate retryable wire allowed =>
      exact .retryStart clear duplicate retryable wire allowed
  | retryFinalDenied clear duplicate retryable wire denied fits =>
      exact .retryFinalDenied clear duplicate retryable wire denied fits
  | linearizeEffect clear pending noEffect owned =>
      exact .linearizeEffect clear pending noEffect owned
  | linearizeCommitUnknown githubKind clear pending noEffect owned =>
      exact .linearizeCommitUnknown clear pending noEffect owned
  | recordCommit linearized turn allowed capExact =>
      exact .recordCommit linearized turn allowed
  | recordCommittedButUnrecorded linearized turn allowed capExact fullCharge =>
      exact .recordCommittedButUnrecorded linearized turn allowed fullCharge
  | abortAfterEffect linearized turn allowed capExact =>
      exact .abortAfterEffect linearized turn allowed
  | deny clear pending allowed capExact => exact .deny clear pending allowed
  | terminalDuplicate clear duplicate cached terminal =>
      exact .terminalDuplicate clear duplicate cached terminal

/-- Every label-specific accepted observation forward-simulates one step. -/
theorem Accepted.forwardSimulation {label : Label} {context : RequestContext}
    {before after : ModelState} (accepted : Accepted label context before after) :
    BrokerState.Steps before after :=
  .tail (.refl before) accepted.toStep

/-- Candidate transition evidence for facts involving total functional maps. -/
structure EventCandidate (before : StateSnapshot) (event : Event) where
  after : StateSnapshot
  accepted : Accepted event.label event.context before.model after.model

/-- Result returned only after both snapshots and the event shape validate. -/
structure CheckedEvent (before : StateSnapshot) (event : Event) where
  after : StateSnapshot
  beforeDenotes : before.Denotes before.model
  afterDenotes : after.Denotes after.model
  shape : event.Shape after.model
  accepted : Accepted event.label event.context before.model after.model

/-- Executable validation around a proof-carrying abstract transition candidate. -/
def checkEvent (before : StateSnapshot) (event : Event)
    (candidate : EventCandidate before event) : Option (CheckedEvent before event) :=
  if beforeValid : before.validate = true then
    if afterValid : candidate.after.validate = true then
      if shapeValid : event.validateAt candidate.after.model = true then
        some ⟨candidate.after, StateSnapshot.validate_sound beforeValid,
          StateSnapshot.validate_sound afterValid, Event.validateAt_sound shapeValid,
          candidate.accepted⟩
      else none
    else none
  else none

/-- A returned event denotes exact model states and one label-specific transition. -/
theorem checkEvent_sound {before : StateSnapshot} {event : Event}
    {candidate : EventCandidate before event} {checked : CheckedEvent before event}
    (_result : checkEvent before event candidate = some checked) :
    before.Denotes before.model ∧ checked.after.Denotes checked.after.model ∧
      event.Shape checked.after.model ∧
      Accepted event.label event.context before.model checked.after.model :=
  ⟨checked.beforeDenotes, checked.afterDenotes, checked.shape, checked.accepted⟩

/-- Every checked event forward-simulates the existing broker model. -/
theorem CheckedEvent.forwardSimulation {before : StateSnapshot} {event : Event}
    (checked : CheckedEvent before event) :
    BrokerState.Steps before.model checked.after.model :=
  checked.accepted.forwardSimulation

/-- Successful event checking yields an existing finite broker execution. -/
theorem checkEvent_forwardSimulation {before : StateSnapshot} {event : Event}
    {candidate : EventCandidate before event} {checked : CheckedEvent before event}
    (_result : checkEvent before event candidate = some checked) :
    BrokerState.Steps before.model checked.after.model :=
  checked.forwardSimulation

/-- Canonically valid inputs are accepted with the candidate's exact result snapshot. -/
theorem checkEvent_accepts {before : StateSnapshot} {event : Event}
    (candidate : EventCandidate before event)
    (beforeValid : before.validate = true)
    (afterValid : candidate.after.validate = true)
    (shapeValid : event.validateAt candidate.after.model = true) :
    ∃ checked, checkEvent before event candidate = some checked ∧
      checked.after = candidate.after := by
  unfold checkEvent
  simp only [beforeValid, afterValid, shapeValid, dite_true]
  exact ⟨_, rfl, rfl⟩

/-- Concatenate two finite broker executions. -/
theorem steps_trans {first middle last : ModelState}
    (firstSteps : BrokerState.Steps first middle)
    (suffix : BrokerState.Steps middle last) : BrokerState.Steps first last := by
  induction suffix with
  | refl => exact firstSteps
  | tail earlier transition inductionHypothesis =>
      exact .tail inductionHypothesis transition

/-- A checked finite observation trace and its exact abstract simulation. -/
structure CheckedTrace (before : StateSnapshot) where
  after : StateSnapshot
  initialDenotation : before.Denotes before.model
  finalDenotation : after.Denotes after.model
  simulation : BrokerState.Steps before.model after.model

/-- Dependent inputs align each event with the previous observed result. -/
inductive TraceInput : StateSnapshot → Type
  | nil (state : StateSnapshot) : TraceInput state
  | cons {state : StateSnapshot} (event : Event)
      (candidate : EventCandidate state event)
      (remaining : TraceInput candidate.after) : TraceInput state

/-- Final supplied snapshot of a dependent trace input. -/
def TraceInput.final : {before : StateSnapshot} → TraceInput before → StateSnapshot
  | _, .nil state => state
  | _, .cons _ _ remaining => remaining.final

/-- Finite evidence that every executable check in a trace will succeed. -/
inductive TraceCheckable : {before : StateSnapshot} → TraceInput before → Prop
  | nil {state : StateSnapshot} (valid : state.validate = true) :
      TraceCheckable (.nil state)
  | cons {state : StateSnapshot} {event : Event}
      {candidate : EventCandidate state event}
      {remaining : TraceInput candidate.after}
      (beforeValid : state.validate = true)
      (afterValid : candidate.after.validate = true)
      (shapeValid : event.validateAt candidate.after.model = true)
      (rest : TraceCheckable remaining) :
      TraceCheckable (.cons event candidate remaining)

/-- Validate and forward-simulate a finite sequence of versioned observations. -/
def checkTrace : {before : StateSnapshot} → TraceInput before → Option (CheckedTrace before)
  | before, .nil _ =>
      if valid : before.validate = true then
        some ⟨before, StateSnapshot.validate_sound valid,
          StateSnapshot.validate_sound valid, .refl before.model⟩
      else none
  | before, .cons event candidate remaining =>
      match checkEvent before event candidate with
      | none => none
      | some checked =>
          match checkTrace remaining with
          | none => none
          | some rest =>
              some ⟨rest.after, checked.beforeDenotes, rest.finalDenotation,
                steps_trans candidate.accepted.forwardSimulation rest.simulation⟩

/-- Every accepted finite observation trace is an existing broker execution. -/
theorem checkTrace_sound {before : StateSnapshot} {input : TraceInput before}
    {checked : CheckedTrace before} (_result : checkTrace input = some checked) :
    before.Denotes before.model ∧ checked.after.Denotes checked.after.model ∧
      BrokerState.Steps before.model checked.after.model :=
  ⟨checked.initialDenotation, checked.finalDenotation, checked.simulation⟩

/-- Checkability evidence produces a result at the supplied final snapshot. -/
theorem checkTrace_accepts {before : StateSnapshot} {input : TraceInput before}
    (checkable : TraceCheckable input) :
    ∃ checked, checkTrace input = some checked ∧ checked.after = input.final := by
  induction checkable with
  | nil valid =>
      let checked : CheckedTrace _ := ⟨_, StateSnapshot.validate_sound valid,
        StateSnapshot.validate_sound valid, .refl _⟩
      refine ⟨checked, ?_, ?_⟩
      · simp [checkTrace, valid, checked]
      · rfl
  | @cons state event candidate remaining beforeValid afterValid shapeValid rest ih =>
      rcases checkEvent_accepts candidate beforeValid afterValid shapeValid with
        ⟨eventChecked, eventAccepted, _⟩
      rcases ih with ⟨restChecked, restAccepted, finalExact⟩
      refine ⟨⟨restChecked.after, eventChecked.beforeDenotes,
        restChecked.finalDenotation,
        steps_trans candidate.accepted.forwardSimulation restChecked.simulation⟩,
        ?_, finalExact⟩
      simp only [checkTrace, eventAccepted, restAccepted]

/-- Checked traces preserve the complete replay/budget/cache coupling invariant. -/
theorem CheckedTrace.preserves_wellFormed {before : StateSnapshot}
    (checked : CheckedTrace before) (wellFormed : before.model.WellFormed) :
    checked.after.model.WellFormed :=
  checked.simulation.preserves_wellFormed wellFormed

/-- Checked traces preserve exact finite replay accounting. -/
theorem CheckedTrace.preserves_replay_accounting {before : StateSnapshot}
    (checked : CheckedTrace before) (accounted : before.model.replay.FullyAccounted) :
    checked.after.model.replay.FullyAccounted :=
  checked.simulation.preserves_replay_accounting accounted

/-- Checked traces preserve exact finite reservation accounting. -/
theorem CheckedTrace.preserves_budget_accounting {before : StateSnapshot}
    (checked : CheckedTrace before) (accounted : before.model.budget.FullyAccounted) :
    checked.after.model.budget.FullyAccounted :=
  checked.simulation.preserves_budget_accounting accounted

/-- Checked traces preserve all modeled Rust-width budget counters. -/
theorem CheckedTrace.preserves_budget_counters {before : StateSnapshot}
    (checked : CheckedTrace before) (withinLimits : before.model.budget.WithinLimits)
    (representable : before.model.budget.CountersRepresentable) :
    checked.after.model.budget.CountersRepresentable :=
  checked.simulation.preserves_budget_countersRepresentable withinLimits representable

/-- Checked continuations retain an already observed conservative effect bit. -/
theorem CheckedTrace.effect_persists {before : StateSnapshot}
    (checked : CheckedTrace before) {request : BrokerRequestId}
    (effect : before.model.effects request = true) :
    checked.after.model.effects request = true :=
  checked.simulation.effect_persists effect

namespace Witness

private def session : BrokerSessionId := ⟨701⟩
private def request : BrokerRequestId := ⟨702⟩
private def payloadHash : PayloadHash := ⟨703⟩
private def responseCap : Nat := 40
private def wire : CanonicalWireOutcome := ⟨704⟩

private def envelope : BrokerEnvelope where
  session := session
  sequence := 0
  request := request
  payloadHash := payloadHash

private def context : RequestContext where
  envelope := envelope
  operation := .githubMutation
  responseCap := responseCap

private def limits : SessionBudgetLimits where
  maxRequests := 2
  maxResponseBytes := 100
  maxConcurrentRequests := 1

private def initial : ModelState := BrokerState.empty session 4 limits
private def acceptedPending : ModelState :=
  initial.acceptPending envelope .githubMutation responseCap
private def postBudget : ModelState :=
  acceptedPending.continueAcceptedStart request .githubMutation responseCap
private def commitUnknown : ModelState := postBudget.linearizeCommitUnknown request

private def reservation : ResponseReservation where
  request := request
  maxResponseBytes := responseCap

private def terminal : ModelState :=
  commitUnknown.recordCommittedButUnrecorded request reservation responseCap wire

private def initialSnapshot := StateSnapshot.ofState initial
private def acceptedSnapshot := StateSnapshot.ofState acceptedPending
private def postBudgetSnapshot := StateSnapshot.ofState postBudget
private def unknownSnapshot := StateSnapshot.ofState commitUnknown
private def terminalSnapshot := StateSnapshot.ofState terminal

private def acceptEvent : Event := Event.ofState context .acceptPending acceptedPending
private def startEvent : Event := Event.ofState context .continueAcceptedStart postBudget
private def unknownEvent : Event := Event.ofState context .linearizeCommitUnknown commitUnknown
private def settleEvent : Event := Event.ofState context
  (.recordCommittedButUnrecorded .commitUnknown responseCap wire) terminal
private def retryEvent : Event := Event.ofState context
  (.terminalDuplicate (.committedButUnrecorded wire)) terminal

private theorem replayAllowed : initial.replay.MayAcceptNew envelope := by
  refine ⟨rfl, rfl, rfl, ?_, by simp [initial, BrokerState.empty, ReplayState.empty]⟩
  change 0 ≤ u64Maximum
  omega

private theorem acceptedBound : acceptedPending.HasReplayBinding request := by
  exact ⟨_, ReplayState.acceptNew_stores_exact_binding initial.replay envelope⟩

private theorem startAllowed : acceptedPending.budget.MayStart request responseCap := by
  refine ⟨rfl, ?_, ?_, ?_⟩ <;>
    simp [acceptedPending, initial, BrokerState.acceptPending,
      BrokerState.empty, SessionBudget.empty, limits, responseCap]

private theorem acceptedClear : acceptedPending.AccountingClear := by
  intro other effect lookup
  by_cases same : other = request
  · subst other
    simp [acceptedPending, BrokerState.acceptPending, initial, BrokerState.empty,
      replace, envelope, request] at lookup
  · have differentLiteral : other ≠ ({ value := 702 } : BrokerRequestId) := by
      simpa [request] using same
    simp [acceptedPending, BrokerState.acceptPending, initial, BrokerState.empty,
      replace, envelope, request, differentLiteral] at lookup

private theorem postBudgetClear : postBudget.AccountingClear := by
  intro other effect lookup
  by_cases same : other = request
  · subst other
    simp [postBudget, acceptedPending, BrokerState.continueAcceptedStart,
      BrokerState.retryStart, BrokerState.acceptPending, initial, BrokerState.empty,
      replace, envelope, request] at lookup
  · have differentLiteral : other ≠ ({ value := 702 } : BrokerRequestId) := by
      simpa [request] using same
    simp [postBudget, acceptedPending, BrokerState.continueAcceptedStart,
      BrokerState.retryStart, BrokerState.acceptPending, initial, BrokerState.empty,
      replace, envelope, request, differentLiteral] at lookup

private def acceptCandidate : EventCandidate initialSnapshot acceptEvent :=
  ⟨acceptedSnapshot, by
    change Accepted .acceptPending context initial acceptedPending
    exact .acceptPending (BrokerState.empty_accountingClear session 4 limits)
      replayAllowed rfl (by change 40 ≤ u64Maximum; decide)⟩

private def startCandidate : EventCandidate acceptedSnapshot startEvent :=
  ⟨postBudgetSnapshot, by
    change Accepted .continueAcceptedStart context acceptedPending postBudget
    exact .continueAcceptedStart acceptedClear
      (by simp [acceptedPending, BrokerState.acceptPending, context,
        RequestContext.request, envelope, request])
      acceptedBound rfl rfl
      (by change WireAdmissible .githubMutation responseCap; simp [WireAdmissible])
      startAllowed⟩

private def unknownCandidate : EventCandidate postBudgetSnapshot unknownEvent :=
  ⟨unknownSnapshot, by
    change Accepted .linearizeCommitUnknown context postBudget commitUnknown
    exact .linearizeCommitUnknown rfl postBudgetClear
      (by simp [postBudget, BrokerState.continueAcceptedStart,
        BrokerState.retryStart, context, RequestContext.request, envelope, request])
      (by simp [postBudget, BrokerState.continueAcceptedStart,
        BrokerState.retryStart, acceptedPending, BrokerState.acceptPending,
        initial, BrokerState.empty, context, RequestContext.request, envelope, request])
      (by simp [postBudget, BrokerState.continueAcceptedStart,
        BrokerState.retryStart, context, RequestContext.request, envelope, request])⟩

private def completionAllowed :
    commitUnknown.budget.MayComplete request responseCap := by
  refine {
    reservation := reservation
    reservationLookup := ?_
    requestBinding := rfl
    responseWithinReservation := by
      change responseCap ≤ responseCap
      exact Nat.le_refl _
    reservationAccounted := ?_
    activeAccounted := ?_ }
  · simp [commitUnknown, postBudget, BrokerState.linearizeCommitUnknown,
      BrokerState.continueAcceptedStart, BrokerState.retryStart, acceptedPending,
      BrokerState.acceptPending, initial, BrokerState.empty, SessionBudget.start,
      reservation, request, responseCap]
  · simp [commitUnknown, postBudget, BrokerState.linearizeCommitUnknown,
      BrokerState.continueAcceptedStart, BrokerState.retryStart, acceptedPending,
      BrokerState.acceptPending, initial, BrokerState.empty, SessionBudget.start,
      reservation, responseCap]
  · simp [commitUnknown, postBudget, BrokerState.linearizeCommitUnknown,
      BrokerState.continueAcceptedStart, BrokerState.retryStart, acceptedPending,
      BrokerState.acceptPending, initial, BrokerState.empty, SessionBudget.start]

private def settleCandidate : EventCandidate unknownSnapshot settleEvent :=
  ⟨terminalSnapshot, by
    change Accepted
      (.recordCommittedButUnrecorded .commitUnknown responseCap wire)
      context commitUnknown terminal
    have linearized : commitUnknown.outcomes request =
        some (.effectLinearized .commitUnknown) := by
      simp [commitUnknown, BrokerState.linearizeCommitUnknown, request]
    have turn : commitUnknown.AccountingTurn request :=
      BrokerState.linearizeCommitUnknown_starts_accounting_turn
        postBudget request postBudgetClear
    simpa [terminal, completionAllowed, context, RequestContext.request,
      envelope, request] using
      (Accepted.recordCommittedButUnrecorded (state := commitUnknown)
        (context := context) (effect := .commitUnknown)
        (responseBytes := responseCap) (wire := wire)
        linearized turn completionAllowed rfl rfl)⟩

private theorem terminalClear : terminal.AccountingClear := by
  intro other effect lookup
  by_cases same : other = request
  · subst other
    simp [terminal, BrokerState.recordCommittedButUnrecorded] at lookup
  · simp [terminal, commitUnknown, postBudget, acceptedPending,
      BrokerState.recordCommittedButUnrecorded, BrokerState.linearizeCommitUnknown,
      BrokerState.continueAcceptedStart, BrokerState.retryStart,
      BrokerState.acceptPending, initial, BrokerState.empty, replace, same] at lookup

private theorem terminalDuplicate : terminal.replay.ExactDuplicate envelope := by
  exact ⟨rfl, by
    simpa [terminal, commitUnknown, postBudget, acceptedPending,
      BrokerState.recordCommittedButUnrecorded, BrokerState.linearizeCommitUnknown,
      BrokerState.continueAcceptedStart, BrokerState.retryStart] using
      ReplayState.acceptNew_stores_exact_binding initial.replay envelope⟩

private def retryCandidate : EventCandidate terminalSnapshot retryEvent :=
  ⟨terminalSnapshot, by
    change Accepted (.terminalDuplicate (.committedButUnrecorded wire))
      context terminal terminal
    exact .terminalDuplicate terminalClear terminalDuplicate
      (by change terminal.outcomes request = some (.committedButUnrecorded wire)
          simp [terminal, BrokerState.recordCommittedButUnrecorded, request])
      (by simp [BrokerOutcome.Terminal])⟩

private def rustShapedTrace : TraceInput initialSnapshot :=
  .cons acceptEvent acceptCandidate
    (.cons startEvent startCandidate
      (.cons unknownEvent unknownCandidate
        (.cons settleEvent settleCandidate
          (.cons retryEvent retryCandidate (.nil terminalSnapshot)))))

private def rustShapedTraceCheckable : TraceCheckable rustShapedTrace := by
  apply TraceCheckable.cons
  · exact StateSnapshot.validate_ofState initial
  · exact StateSnapshot.validate_ofState acceptedPending
  · exact Event.validateAt_ofState context .acceptPending acceptedPending rfl
  · apply TraceCheckable.cons
    · exact StateSnapshot.validate_ofState acceptedPending
    · exact StateSnapshot.validate_ofState postBudget
    · exact Event.validateAt_ofState context .continueAcceptedStart postBudget rfl
    · apply TraceCheckable.cons
      · exact StateSnapshot.validate_ofState postBudget
      · exact StateSnapshot.validate_ofState commitUnknown
      · exact Event.validateAt_ofState context .linearizeCommitUnknown commitUnknown rfl
      · apply TraceCheckable.cons
        · exact StateSnapshot.validate_ofState commitUnknown
        · exact StateSnapshot.validate_ofState terminal
        · exact Event.validateAt_ofState context
            (.recordCommittedButUnrecorded .commitUnknown responseCap wire) terminal rfl
        · apply TraceCheckable.cons
          · exact StateSnapshot.validate_ofState terminal
          · exact StateSnapshot.validate_ofState terminal
          · exact Event.validateAt_ofState context
              (.terminalDuplicate (.committedButUnrecorded wire)) terminal rfl
          · exact .nil (StateSnapshot.validate_ofState terminal)

private def expandedManifest : ChunkManifest where
  schemaVersion := responseChunkSchemaVersion
  requestId := request
  chunkCount := 2
  totalLength := maxResponseChunkBytes + 1
  completeWireDigest := wire.digest

private def expandedFirstChunk : ChunkObservation where
  manifest := expandedManifest
  chunkIndex := 0
  payloadBytes := maxResponseChunkBytes

private def expandedFinalChunk : ChunkObservation where
  manifest := expandedManifest
  chunkIndex := 1
  payloadBytes := 1

private def expandedChunkTrace : List ChunkObservation :=
  [expandedFirstChunk, expandedFinalChunk]

/-- A current-version multi-chunk response manifest is concretely checkable. -/
theorem expanded_chunk_trace_witness :
    checkChunkTrace retryEvent expandedChunkTrace = true ∧
      expandedManifest.totalLength ≤ maxExpandedCanonicalResponseBytes ∧
      expandedManifest.chunkCount = 2 := by
  decide

/-- The accepted-pending observation is pre-budget and consumes no counters. -/
theorem acceptedPending_pre_budget_witness :
    ∃ checked, checkEvent initialSnapshot acceptEvent acceptCandidate = some checked ∧
      checked.after.model.outcomes request =
        some (.acceptedPending .githubMutation responseCap) ∧
      checked.after.model.budget.startedRequests = 0 ∧
      checked.after.model.budget.active request = none := by
  rcases checkEvent_accepts acceptCandidate
      (StateSnapshot.validate_ofState initial)
      (StateSnapshot.validate_ofState acceptedPending)
      (Event.validateAt_ofState context .acceptPending acceptedPending rfl) with
    ⟨checked, accepted, afterExact⟩
  refine ⟨checked, accepted, ?_⟩
  rw [afterExact]
  change acceptedPending.outcomes request =
      some (.acceptedPending .githubMutation responseCap) ∧
    acceptedPending.budget.startedRequests = 0 ∧
    acceptedPending.budget.active request = none
  simp [acceptedSnapshot, acceptedPending, BrokerState.acceptPending,
    initial, BrokerState.empty, SessionBudget.empty, request, envelope, responseCap]

/-- Continuing the accepted marker consumes one token and reserves the exact cap. -/
theorem acceptedPending_post_budget_witness :
    ∃ checked, checkEvent acceptedSnapshot startEvent startCandidate = some checked ∧
      checked.after.model.budget.startedRequests = 1 ∧
      checked.after.model.budget.reservedResponseBytes = responseCap ∧
      checked.after.model.budget.active request = some reservation := by
  rcases checkEvent_accepts startCandidate
      (StateSnapshot.validate_ofState acceptedPending)
      (StateSnapshot.validate_ofState postBudget)
      (Event.validateAt_ofState context .continueAcceptedStart postBudget rfl) with
    ⟨checked, accepted, afterExact⟩
  refine ⟨checked, accepted, ?_⟩
  rw [afterExact]
  change postBudget.budget.startedRequests = 1 ∧
    postBudget.budget.reservedResponseBytes = responseCap ∧
    postBudget.budget.active request = some reservation
  simp [postBudgetSnapshot, postBudget, BrokerState.continueAcceptedStart,
    BrokerState.retryStart, acceptedPending, BrokerState.acceptPending,
    initial, BrokerState.empty, SessionBudget.empty, SessionBudget.start, reservation, request,
    envelope, responseCap]

/-- Commit-unknown is a state-changing effect observation, not a failed precommit. -/
theorem commitUnknown_witness :
    ∃ checked, checkEvent postBudgetSnapshot unknownEvent unknownCandidate = some checked ∧
      checked.after.model.effects request = true ∧
      checked.after.model.outcomes request =
        some (.effectLinearized .commitUnknown) ∧
      unknownEvent.attemptOutcome = .commitUnknown := by
  rcases checkEvent_accepts unknownCandidate
      (StateSnapshot.validate_ofState postBudget)
      (StateSnapshot.validate_ofState commitUnknown)
      (Event.validateAt_ofState context .linearizeCommitUnknown commitUnknown rfl) with
    ⟨checked, accepted, afterExact⟩
  refine ⟨checked, accepted, ?_⟩
  rw [afterExact]
  change commitUnknown.effects request = true ∧
    commitUnknown.outcomes request = some (.effectLinearized .commitUnknown) ∧
    unknownEvent.attemptOutcome = .commitUnknown
  simp [unknownSnapshot, unknownEvent, Event.ofState, Label.expectedAttempt,
    commitUnknown, BrokerState.linearizeCommitUnknown, request]

/-- Full-cap settlement retains ambiguity and produces one canonical terminal digest. -/
theorem commitUnknown_terminal_witness :
    ∃ checked, checkEvent unknownSnapshot settleEvent settleCandidate = some checked ∧
      checked.after.model.effects request = true ∧
      checked.after.model.budget.reservedResponseBytes = 0 ∧
      checked.after.model.budget.committedResponseBytes = responseCap ∧
      settleEvent.terminalWireDigest = some wire.digest ∧
      settleEvent.durablePhase = .terminalWriteFailed := by
  rcases checkEvent_accepts settleCandidate
      (StateSnapshot.validate_ofState commitUnknown)
      (StateSnapshot.validate_ofState terminal)
      (Event.validateAt_ofState context
        (.recordCommittedButUnrecorded .commitUnknown responseCap wire) terminal rfl) with
    ⟨checked, accepted, afterExact⟩
  refine ⟨checked, accepted, ?_⟩
  rw [afterExact]
  change terminal.effects request = true ∧
    terminal.budget.reservedResponseBytes = 0 ∧
    terminal.budget.committedResponseBytes = responseCap ∧
    settleEvent.terminalWireDigest = some wire.digest ∧
    settleEvent.durablePhase = .terminalWriteFailed
  simp [terminalSnapshot, settleEvent, Event.ofState, Event.observedWireDigest,
    terminal, BrokerState.observableWire, BrokerState.recordCommittedButUnrecorded,
    completionAllowed, SessionBudget.complete, SessionBudget.releaseReservation,
    commitUnknown, BrokerState.linearizeCommitUnknown, postBudget,
    BrokerState.continueAcceptedStart, BrokerState.retryStart, acceptedPending,
    BrokerState.acceptPending, initial, BrokerState.empty, SessionBudget.empty,
    SessionBudget.start, reservation, responseCap, context,
    RequestContext.request, BrokerOutcome.wire?, Label.expectedDurablePhase,
    envelope, request]

/-- An exact retry checks as an observational no-op with the identical wire digest. -/
theorem exact_retry_witness :
    ∃ checked, checkEvent terminalSnapshot retryEvent retryCandidate = some checked ∧
      checked.after.model = terminal ∧
      retryEvent.replayPhase = .exactRetry ∧
      retryEvent.terminalWireDigest = some wire.digest := by
  rcases checkEvent_accepts retryCandidate
      (StateSnapshot.validate_ofState terminal)
      (StateSnapshot.validate_ofState terminal)
      (Event.validateAt_ofState context
        (.terminalDuplicate (.committedButUnrecorded wire)) terminal rfl) with
    ⟨checked, accepted, afterExact⟩
  refine ⟨checked, accepted, ?_⟩
  rw [afterExact]
  change terminal = terminal ∧ retryEvent.replayPhase = .exactRetry ∧
    retryEvent.terminalWireDigest = some wire.digest
  simp [retryEvent, Event.ofState, Event.observedWireDigest, Label.expectedPhase,
    terminal, BrokerState.observableWire, BrokerState.recordCommittedButUnrecorded,
    context, RequestContext.request, BrokerOutcome.wire?, envelope, request]

/-- The complete Rust-shaped path, including its retry, is a checked finite trace. -/
theorem rust_shaped_trace_witness :
    ∃ checked, checkTrace rustShapedTrace = some checked ∧
      checked.after.model = terminal ∧
      BrokerState.Steps initial terminal := by
  rcases checkTrace_accepts rustShapedTraceCheckable with
    ⟨checked, accepted, finalExact⟩
  have simulation := checked.simulation
  rw [finalExact] at simulation
  refine ⟨checked, accepted, ?_, ?_⟩
  · rw [finalExact]
    rfl
  · simpa [initialSnapshot, terminalSnapshot] using simulation

end Witness

end Authority.Refinement.Broker
