import Authority.Refinement.Broker
import Authority.Refinement.CapabilityState
import Authority.Refinement.OrchestratorRuntime

/-!
# Rust Runtime Observation Corpus

This module parses a closed, proof-free TSV schema emitted by the Rust runtime
corpus binary. Authority observations drive an executable state transition;
Broker and orchestrator observations are checked against their existing
refinement models. This does not prove that arbitrary Rust executions emit
honest observations.
-/

namespace Authority.Refinement.RuntimeCorpus

private def corpusHeader := "# authority-runtime-corpus-v1"

structure Fields where
  values : List String
  consumed : Nat := 0

namespace Fields

def take (fields : Fields) (label : String) : Except String (String × Fields) :=
  match fields.values with
  | [] => .error s!"missing {label} at field {fields.consumed + 1}"
  | value :: remaining =>
      .ok (value, { values := remaining, consumed := fields.consumed + 1 })

def finish (fields : Fields) : Except String Unit :=
  match fields.values with
  | [] => .ok ()
  | extra :: _ =>
      .error s!"unexpected field {fields.consumed + 1} with value `{extra}`"

end Fields

def parseNat (value label : String) : Except String Nat :=
  match value.toNat? with
  | some parsed => .ok parsed
  | none => .error s!"invalid {label} `{value}`; expected a natural number"

def parseFlag (value label : String) : Except String Bool :=
  match value with
  | "0" => .ok false
  | "1" => .ok true
  | _ => .error s!"invalid {label} `{value}`; expected 0 or 1"

structure AuthorityRow where
  name : String
  version : Nat
  caller : String
  owner : String
  capability : String
  outcome : String
  beforeEpoch : Nat
  afterEpoch : Nat
  activeBefore : Bool
  activeAfter : Bool
  beforeNextAttempt : Nat
  afterNextAttempt : Nat
  attemptId : Option Nat
  evidenceAttemptId : Option Nat
  evidenceBytes : Nat
  auditOutcome : String
  beforeEffectCount : Nat
  afterEffectCount : Nat
  deriving Repr, BEq

structure BrokerRow where
  name : String
  version : Nat
  sequence : Nat
  requestId : String
  payloadHash : String
  responseCap : Nat
  phase : String
  reservation : String
  startedRequests : Nat
  committedResponseBytes : Nat
  reservedResponseBytes : Nat
  activeRequests : Nat
  terminalDigest : Option Nat
  chunkCount : Option Nat
  totalLength : Option Nat
  deriving Repr, BEq

structure ChunkRow where
  name : String
  version : Nat
  requestId : String
  index : Nat
  count : Nat
  totalLength : Nat
  digest : Nat
  payloadBytes : Nat
  deriving Repr, BEq

structure RetryRow where
  name : String
  version : Nat
  sequence : Nat
  requestId : String
  payloadHash : String
  responseCap : Nat
  phase : String
  terminalDigest : Nat
  deriving Repr, BEq

structure OrchestratorRow where
  name : String
  version : Nat
  sessionId : String
  brokerSessionId : String
  phase : String
  shutdownReason : String
  events : String
  deriving Repr, BEq

inductive Row where
  | authority (row : AuthorityRow)
  | broker (row : BrokerRow)
  | chunk (row : ChunkRow)
  | retry (row : RetryRow)
  | orchestrator (row : OrchestratorRow)
  deriving Repr, BEq

private def takeNat (fields : Fields) (label : String) : Except String (Nat × Fields) := do
  let (value, remaining) ← fields.take label
  pure (← parseNat value label, remaining)

private def takeOptionalNat (fields : Fields) (label : String) :
    Except String (Option Nat × Fields) := do
  let (value, remaining) ← fields.take label
  if value == "-" then
    pure (none, remaining)
  else
    pure (some (← parseNat value label), remaining)

private def takeFlag (fields : Fields) (label : String) : Except String (Bool × Fields) := do
  let (value, remaining) ← fields.take label
  pure (← parseFlag value label, remaining)

private def parseAuthority (fields : Fields) : Except String Row := do
  let (name, fields) ← fields.take "authority row name"
  let (version, fields) ← takeNat fields "authority schema version"
  let (caller, fields) ← fields.take "authority caller"
  let (owner, fields) ← fields.take "authority owner"
  let (capability, fields) ← fields.take "authority capability"
  let (outcome, fields) ← fields.take "authority outcome"
  let (beforeEpoch, fields) ← takeNat fields "authority epoch before"
  let (afterEpoch, fields) ← takeNat fields "authority epoch after"
  let (activeBefore, fields) ← takeFlag fields "authority active before"
  let (activeAfter, fields) ← takeFlag fields "authority active after"
  let (beforeNextAttempt, fields) ← takeNat fields "authority next attempt before"
  let (afterNextAttempt, fields) ← takeNat fields "authority next attempt after"
  let (attemptId, fields) ← takeOptionalNat fields "authority attempt ID"
  let (evidenceAttemptId, fields) ←
    takeOptionalNat fields "authority evidence attempt ID"
  let (evidenceBytes, fields) ← takeNat fields "authority evidence bytes"
  let (auditOutcome, fields) ← fields.take "authority audit outcome"
  let (beforeEffectCount, fields) ← takeNat fields "authority effect count before"
  let (afterEffectCount, fields) ← takeNat fields "authority effect count after"
  fields.finish
  let row : AuthorityRow := {
    name, version, caller, owner, capability, outcome, beforeEpoch, afterEpoch,
    activeBefore, activeAfter,
    beforeNextAttempt, afterNextAttempt, attemptId, evidenceAttemptId,
    evidenceBytes, auditOutcome, beforeEffectCount, afterEffectCount }
  pure (.authority row)

private def parseBroker (fields : Fields) : Except String Row := do
  let (name, fields) ← fields.take "Broker row name"
  let (version, fields) ← takeNat fields "Broker schema version"
  let (sequence, fields) ← takeNat fields "Broker sequence"
  let (requestId, fields) ← fields.take "Broker request ID"
  let (payloadHash, fields) ← fields.take "Broker payload hash"
  let (responseCap, fields) ← takeNat fields "Broker response cap"
  let (phase, fields) ← fields.take "Broker durable phase"
  let (reservation, fields) ← fields.take "Broker reservation"
  let (startedRequests, fields) ← takeNat fields "Broker started requests"
  let (committedResponseBytes, fields) ← takeNat fields "Broker committed bytes"
  let (reservedResponseBytes, fields) ← takeNat fields "Broker reserved bytes"
  let (activeRequests, fields) ← takeNat fields "Broker active requests"
  match name with
  | "terminal" => do
      let (terminalDigest, fields) ← takeNat fields "Broker terminal digest"
      let (chunkCount, fields) ← takeNat fields "Broker chunk count"
      let (totalLength, fields) ← takeNat fields "Broker total wire length"
      fields.finish
      let row : BrokerRow := {
        name, version, sequence, requestId, payloadHash, responseCap, phase,
        reservation, startedRequests, committedResponseBytes,
        reservedResponseBytes, activeRequests
        terminalDigest := some terminalDigest
        chunkCount := some chunkCount
        totalLength := some totalLength }
      pure (.broker row)
  | "accepted-pending" | "budget-reserved" => do
      fields.finish
      let row : BrokerRow := {
        name, version, sequence, requestId, payloadHash, responseCap, phase,
        reservation, startedRequests, committedResponseBytes,
        reservedResponseBytes, activeRequests
        terminalDigest := none
        chunkCount := none
        totalLength := none }
      pure (.broker row)
  | other => .error s!"unknown Broker row `{other}`"

private def parseChunk (fields : Fields) : Except String Row := do
  let (name, fields) ← fields.take "chunk row name"
  let (version, fields) ← takeNat fields "chunk schema version"
  let (requestId, fields) ← fields.take "chunk request ID"
  let (index, fields) ← takeNat fields "chunk index"
  let (count, fields) ← takeNat fields "chunk count"
  let (totalLength, fields) ← takeNat fields "chunk total length"
  let (digest, fields) ← takeNat fields "chunk digest"
  let (payloadBytes, fields) ← takeNat fields "chunk payload bytes"
  fields.finish
  let row : ChunkRow := {
    name, version, requestId, index, count, totalLength, digest, payloadBytes }
  pure (.chunk row)

private def parseRetry (fields : Fields) : Except String Row := do
  let (name, fields) ← fields.take "retry row name"
  let (version, fields) ← takeNat fields "retry schema version"
  let (sequence, fields) ← takeNat fields "retry sequence"
  let (requestId, fields) ← fields.take "retry request ID"
  let (payloadHash, fields) ← fields.take "retry payload hash"
  let (responseCap, fields) ← takeNat fields "retry response cap"
  let (phase, fields) ← fields.take "retry durable phase"
  let (terminalDigest, fields) ← takeNat fields "retry terminal digest"
  fields.finish
  let row : RetryRow := {
    name, version, sequence, requestId, payloadHash, responseCap, phase,
    terminalDigest }
  pure (.retry row)

private def parseOrchestrator (fields : Fields) : Except String Row := do
  let (name, fields) ← fields.take "orchestrator row name"
  let (version, fields) ← takeNat fields "orchestrator schema version"
  let (sessionId, fields) ← fields.take "orchestrator session ID"
  let (brokerSessionId, fields) ← fields.take "orchestrator Broker session ID"
  let (phase, fields) ← fields.take "orchestrator phase"
  let (shutdownReason, fields) ← fields.take "orchestrator shutdown reason"
  let (events, fields) ← fields.take "orchestrator event sequence"
  fields.finish
  let row : OrchestratorRow := {
    name, version, sessionId, brokerSessionId, phase, shutdownReason, events }
  pure (.orchestrator row)

def parseRow (line : String) : Except String Row := do
  let fields := { values := line.splitOn "\t" : Fields }
  let (family, fields) ← fields.take "row family"
  match family with
  | "authority" => parseAuthority fields
  | "broker" =>
      match fields.values with
      | "exact-retry" :: _ => parseRetry fields
      | _ => parseBroker fields
  | "chunk" => parseChunk fields
  | "orchestrator" => parseOrchestrator fields
  | other => .error s!"unknown runtime corpus row family `{other}`"

structure Corpus where
  commitUnknown : AuthorityRow
  foreignRevoke : AuthorityRow
  ownedRevoke : AuthorityRow
  acceptedPending : BrokerRow
  budgetReserved : BrokerRow
  terminal : BrokerRow
  chunks : List ChunkRow
  exactRetry : RetryRow
  orchestrator : OrchestratorRow
  deriving Repr, BEq

private def parseRows : List String → Except String (List Row)
  | [] => .ok []
  | line :: remaining => do
      let row ← parseRow line
      pure (row :: (← parseRows remaining))

def parseCorpus (input : String) : Except String Corpus := do
  let lines := (input.splitOn "\n").filter (· != "")
  let header ← match lines.head? with
    | some header => .ok header
    | none => .error s!"missing corpus header `{corpusHeader}`"
  if header != corpusHeader then
    throw s!"missing corpus header `{corpusHeader}`"
  let rows ← parseRows lines.tail
  match rows with
  | [.authority commitUnknown, .authority foreignRevoke, .authority ownedRevoke,
      .broker acceptedPending, .broker budgetReserved, .broker terminal,
      .chunk first, .chunk second, .retry exactRetry,
      .orchestrator orchestrator] =>
      pure {
        commitUnknown, foreignRevoke, ownedRevoke, acceptedPending, budgetReserved, terminal
        chunks := [first, second]
        exactRetry, orchestrator }
  | _ => throw "runtime corpus must contain the closed ten-row v1 sequence"

private def expectedRequestId := "32323232323232323232323232323232"
private def expectedPayloadHash :=
  "9e94ed390951393a51c32ffcc653c61f75204d3fc2cc24c2d407c52fca78c7b3"
private def expectedSessionId := "01010101010101010101010101010101"
private def expectedBrokerSessionId := "07070707070707070707070707070707"
private def expectedOrchestratorEvents :=
  "clone,establish,worker-running,start-paused-vm,inject,worker-gate,release,poll,poll,revoke,kill,close,isolate"
private def responseCap : Nat := 1_100_000
private def maximumCommitUnknownEvidenceBytes : Nat := 64 * 1024
private def u64Maximum : Nat := 18_446_744_073_709_551_615

inductive AuthorityCommand where
  | authorizeCommitUnknown
  | revokeForeign
  | revokeOwned
  deriving Repr, BEq

inductive AuthorityOutcome where
  | commitUnknown
  | capabilityNotHeld
  | newlyRevoked
  deriving Repr, BEq

inductive AuthorityAuditOutcome where
  | none
  | commitUnknown
  deriving Repr, BEq

/-- A versioned, proof-free authority observation decoded from TSV fields. -/
structure AuthorityObservation where
  version : Nat
  command : AuthorityCommand
  caller : String
  owner : String
  capability : String
  outcome : AuthorityOutcome
  beforeEpoch : Nat
  afterEpoch : Nat
  activeBefore : Bool
  activeAfter : Bool
  beforeNextAttempt : Nat
  afterNextAttempt : Nat
  attemptId : Option Nat
  evidenceAttemptId : Option Nat
  evidenceBytes : Nat
  auditOutcome : AuthorityAuditOutcome
  beforeEffectCount : Nat
  afterEffectCount : Nat
  deriving Repr, BEq

/-- Closed authority state retained between proof-free observations. -/
structure AuthoritySnapshot where
  owner : String
  capability : String
  revoked : Bool
  epoch : Nat
  nextAttempt : Nat
  effectCount : Nat
  deriving Repr, BEq

private def decodeAuthorityCommand (name : String) : Except String AuthorityCommand :=
  match name with
  | "commit-unknown" => .ok .authorizeCommitUnknown
  | "revoke-foreign" => .ok .revokeForeign
  | "revoke-owned" => .ok .revokeOwned
  | other => .error s!"unknown authority command `{other}`"

private def decodeAuthorityOutcome (outcome : String) : Except String AuthorityOutcome :=
  match outcome with
  | "commit-unknown" => .ok .commitUnknown
  | "capability-not-held" => .ok .capabilityNotHeld
  | "newly-revoked" => .ok .newlyRevoked
  | other => .error s!"unknown authority outcome `{other}`"

private def decodeAuthorityAuditOutcome
    (outcome : String) : Except String AuthorityAuditOutcome :=
  match outcome with
  | "none" => .ok .none
  | "commit-unknown" => .ok .commitUnknown
  | other => .error s!"unknown authority audit outcome `{other}`"

/-- Converts parsed strings to the closed executable authority observation. -/
def AuthorityRow.toObservation (row : AuthorityRow) : Except String AuthorityObservation := do
  pure {
    version := row.version
    command := ← decodeAuthorityCommand row.name
    caller := row.caller
    owner := row.owner
    capability := row.capability
    outcome := ← decodeAuthorityOutcome row.outcome
    beforeEpoch := row.beforeEpoch
    afterEpoch := row.afterEpoch
    activeBefore := row.activeBefore
    activeAfter := row.activeAfter
    beforeNextAttempt := row.beforeNextAttempt
    afterNextAttempt := row.afterNextAttempt
    attemptId := row.attemptId
    evidenceAttemptId := row.evidenceAttemptId
    evidenceBytes := row.evidenceBytes
    auditOutcome := ← decodeAuthorityAuditOutcome row.auditOutcome
    beforeEffectCount := row.beforeEffectCount
    afterEffectCount := row.afterEffectCount }

private def AuthorityObservation.matchesBefore
    (observation : AuthorityObservation) (state : AuthoritySnapshot) : Bool :=
  observation.version == 1 && observation.owner == state.owner &&
    observation.capability == state.capability &&
    observation.beforeEpoch == state.epoch &&
    observation.activeBefore == !state.revoked &&
    observation.beforeNextAttempt == state.nextAttempt &&
    observation.beforeEffectCount == state.effectCount &&
    observation.beforeEpoch ≤ u64Maximum &&
    observation.beforeNextAttempt ≤ u64Maximum

private def AuthorityObservation.matchesAfter
    (observation : AuthorityObservation) (state : AuthoritySnapshot) : Bool :=
  observation.afterEpoch == state.epoch &&
    observation.activeAfter == !state.revoked &&
    observation.afterNextAttempt == state.nextAttempt &&
    observation.afterEffectCount == state.effectCount

private def noAttemptEvidence (observation : AuthorityObservation) : Bool :=
  observation.attemptId == none && observation.evidenceAttemptId == none &&
    observation.evidenceBytes == 0 && observation.auditOutcome == .none

/-- Computes one authority transition entirely from parsed, proof-free data. -/
def checkAuthorityObservation (before : AuthoritySnapshot)
    (observation : AuthorityObservation) : Option AuthoritySnapshot :=
  if !observation.matchesBefore before then
    none
  else
    let after? := match observation.command with
      | .authorizeCommitUnknown =>
          if observation.caller == before.owner && !before.revoked &&
              observation.outcome == .commitUnknown &&
              observation.auditOutcome == .commitUnknown &&
              observation.attemptId == some before.nextAttempt &&
              observation.evidenceAttemptId == observation.attemptId &&
              0 < observation.evidenceBytes &&
              observation.evidenceBytes ≤ maximumCommitUnknownEvidenceBytes &&
              before.nextAttempt < u64Maximum then
            some { before with nextAttempt := before.nextAttempt + 1 }
          else
            none
      | .revokeForeign =>
          if observation.caller != before.owner &&
              observation.outcome == .capabilityNotHeld &&
              noAttemptEvidence observation then
            some before
          else
            none
      | .revokeOwned =>
          if observation.caller == before.owner && !before.revoked &&
              observation.outcome == .newlyRevoked &&
              noAttemptEvidence observation && before.epoch < u64Maximum then
            some { before with revoked := true, epoch := before.epoch + 1 }
          else
            none
    match after? with
    | some after => if observation.matchesAfter after then some after else none
    | none => none

private def checkAuthorityTrace :
    AuthoritySnapshot → List AuthorityObservation → Option AuthoritySnapshot
  | state, [] => some state
  | state, observation :: remaining => do
      let next ← checkAuthorityObservation state observation
      checkAuthorityTrace next remaining

private def authorityTraceValid (corpus : Corpus) : Bool :=
  let rows := [corpus.commitUnknown, corpus.foreignRevoke, corpus.ownedRevoke]
  match rows.mapM AuthorityRow.toObservation with
  | .error _ => false
  | .ok [commitUnknown, revokeForeign, revokeOwned] =>
      let initial : AuthoritySnapshot := {
        owner := corpus.commitUnknown.owner
        capability := corpus.commitUnknown.capability
        revoked := false
        epoch := corpus.commitUnknown.beforeEpoch
        nextAttempt := corpus.commitUnknown.beforeNextAttempt
        effectCount := corpus.commitUnknown.beforeEffectCount }
      match checkAuthorityTrace initial [commitUnknown, revokeForeign, revokeOwned] with
      | some final =>
          commitUnknown.command == .authorizeCommitUnknown &&
            revokeForeign.command == .revokeForeign &&
            revokeOwned.command == .revokeOwned && final.revoked
      | none => false
  | .ok _ => false

private def exampleAuthorityState : AuthoritySnapshot := {
  owner := "owner"
  capability := "capability"
  revoked := false
  epoch := 7
  nextAttempt := 11
  effectCount := 3 }

private def exampleCommitUnknown : AuthorityObservation := {
  version := 1
  command := .authorizeCommitUnknown
  caller := "owner"
  owner := "owner"
  capability := "capability"
  outcome := .commitUnknown
  beforeEpoch := 7
  afterEpoch := 7
  activeBefore := true
  activeAfter := true
  beforeNextAttempt := 11
  afterNextAttempt := 12
  attemptId := some 11
  evidenceAttemptId := some 11
  evidenceBytes := 9
  auditOutcome := .commitUnknown
  beforeEffectCount := 3
  afterEffectCount := 3 }

example : (checkAuthorityObservation exampleAuthorityState exampleCommitUnknown ==
    some { exampleAuthorityState with nextAttempt := 12 }) = true := by native_decide

example : (checkAuthorityObservation exampleAuthorityState
    { exampleCommitUnknown with evidenceAttemptId := some 12 }).isNone = true := by native_decide

example : (checkAuthorityObservation exampleAuthorityState {
    exampleCommitUnknown with
    command := .revokeForeign
    outcome := .capabilityNotHeld
    attemptId := none
    evidenceAttemptId := none
    evidenceBytes := 0
    auditOutcome := .none
    afterNextAttempt := 11 }).isNone = true := by native_decide

namespace BrokerCheck

open Authority
open Authority.Refinement.Broker

private def session : BrokerSessionId := ⟨49⟩
private def request : BrokerRequestId := ⟨50⟩
private def payloadHash : PayloadHash := ⟨51⟩
private def receipt : BrokerEffectReceipt := ⟨52⟩

private def envelope : BrokerEnvelope where
  session := session
  sequence := 0
  request := request
  payloadHash := payloadHash

private def context : RequestContext where
  envelope := envelope
  operation := .publicFetch
  responseCap := Authority.Refinement.RuntimeCorpus.responseCap

private def limits : SessionBudgetLimits where
  maxRequests := 2
  maxResponseBytes := 2_500_000
  maxConcurrentRequests := 1

private def initial : ModelState := BrokerState.empty session 4 limits
private def acceptedPending : ModelState :=
  initial.acceptPending envelope .publicFetch responseCap
private def postBudget : ModelState :=
  acceptedPending.continueAcceptedStart request .publicFetch responseCap
private def linearized : ModelState := postBudget.linearizeEffect request receipt

private def reservation : ResponseReservation where
  request := request
  maxResponseBytes := responseCap

private def terminal (wire : CanonicalWireOutcome) : ModelState :=
  linearized.recordCommit request reservation responseCap receipt wire

private theorem replayAllowed : initial.replay.MayAcceptNew envelope := by
  refine ⟨rfl, rfl, rfl, ?_, by
    simp [initial, BrokerState.empty, ReplayState.empty]⟩
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
  · have differentLiteral : other ≠ ({ value := 50 } : BrokerRequestId) := by
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
  · have differentLiteral : other ≠ ({ value := 50 } : BrokerRequestId) := by
      simpa [request] using same
    simp [postBudget, acceptedPending, BrokerState.continueAcceptedStart,
      BrokerState.retryStart, BrokerState.acceptPending, initial, BrokerState.empty,
      replace, envelope, request, differentLiteral] at lookup

private def completionAllowed :
    linearized.budget.MayComplete request responseCap := by
  refine {
    reservation := reservation
    reservationLookup := ?_
    requestBinding := rfl
    responseWithinReservation := Nat.le_refl _
    reservationAccounted := ?_
    activeAccounted := ?_ }
  · simp [linearized, postBudget, BrokerState.linearizeEffect,
      BrokerState.continueAcceptedStart, BrokerState.retryStart, acceptedPending,
      BrokerState.acceptPending, initial, BrokerState.empty, SessionBudget.start,
      reservation, request, responseCap]
  · simp [linearized, postBudget, BrokerState.linearizeEffect,
      BrokerState.continueAcceptedStart, BrokerState.retryStart, acceptedPending,
      BrokerState.acceptPending, initial, BrokerState.empty, SessionBudget.start,
      reservation, responseCap]
  · simp [linearized, postBudget, BrokerState.linearizeEffect,
      BrokerState.continueAcceptedStart, BrokerState.retryStart, acceptedPending,
      BrokerState.acceptPending, initial, BrokerState.empty, SessionBudget.start]

private def initialSnapshot :=
  Authority.Refinement.Broker.StateSnapshot.ofState initial
private def acceptedSnapshot :=
  Authority.Refinement.Broker.StateSnapshot.ofState acceptedPending
private def postBudgetSnapshot :=
  Authority.Refinement.Broker.StateSnapshot.ofState postBudget
private def linearizedSnapshot :=
  Authority.Refinement.Broker.StateSnapshot.ofState linearized
private def terminalSnapshot (wire : CanonicalWireOutcome) :=
  Authority.Refinement.Broker.StateSnapshot.ofState (terminal wire)

private def acceptEvent : Event := Event.ofState context .acceptPending acceptedPending
private def startEvent : Event := Event.ofState context .continueAcceptedStart postBudget
private def linearizeEvent : Event :=
  Event.ofState context (.linearizeEffect receipt) linearized
private def terminalEvent (wire : CanonicalWireOutcome) : Event :=
  Event.ofState context (.recordCommit responseCap receipt wire) (terminal wire)
private def retryEvent (wire : CanonicalWireOutcome) : Event :=
  Event.ofState context (.terminalDuplicate (.committed receipt wire)) (terminal wire)

private def acceptCandidate : EventCandidate initialSnapshot acceptEvent :=
  ⟨acceptedSnapshot, by
    change Accepted .acceptPending context initial acceptedPending
    exact .acceptPending (BrokerState.empty_accountingClear session 4 limits)
      replayAllowed rfl (by change responseCap ≤ u64Maximum; decide)⟩

private def startCandidate : EventCandidate acceptedSnapshot startEvent :=
  ⟨postBudgetSnapshot, by
    change Accepted .continueAcceptedStart context acceptedPending postBudget
    exact .continueAcceptedStart acceptedClear
      (by simp [acceptedPending, BrokerState.acceptPending, context,
        RequestContext.request, envelope, request])
      acceptedBound rfl rfl
      (by
        change 1_100_000 ≤ 33_554_432
        omega)
      startAllowed⟩

private def linearizeCandidate : EventCandidate postBudgetSnapshot linearizeEvent :=
  ⟨linearizedSnapshot, by
    change Accepted (.linearizeEffect receipt) context postBudget linearized
    exact .linearizeEffect postBudgetClear
      (by simp [postBudget, BrokerState.continueAcceptedStart,
        BrokerState.retryStart, context, RequestContext.request, envelope, request])
      (by simp [postBudget, BrokerState.continueAcceptedStart,
        BrokerState.retryStart, acceptedPending, BrokerState.acceptPending,
        initial, BrokerState.empty, context, RequestContext.request, envelope, request])
      (by simp [postBudget, BrokerState.continueAcceptedStart,
        BrokerState.retryStart, context, RequestContext.request, envelope, request])⟩

private def terminalCandidate (wire : CanonicalWireOutcome) :
    EventCandidate linearizedSnapshot (terminalEvent wire) :=
  ⟨terminalSnapshot wire, by
    change Accepted (.recordCommit responseCap receipt wire)
      context linearized (terminal wire)
    have linearizedOutcome : linearized.outcomes request =
        some (.effectLinearized (.committed receipt)) := by
      simp [linearized, BrokerState.linearizeEffect, request]
    have turn : linearized.AccountingTurn request :=
      BrokerState.linearizeEffect_starts_accounting_turn
        postBudget request receipt postBudgetClear
    simpa [terminal, completionAllowed, context, RequestContext.request,
      envelope, request] using
      (Accepted.recordCommit (state := linearized) (context := context)
        (responseBytes := responseCap) (receipt := receipt) (wire := wire)
        linearizedOutcome turn completionAllowed rfl)⟩

private theorem terminalClear (wire : CanonicalWireOutcome) :
    (terminal wire).AccountingClear := by
  intro other effect lookup
  by_cases same : other = request
  · subst other
    simp [terminal, BrokerState.recordCommit] at lookup
  · simp [terminal, linearized, postBudget, acceptedPending,
      BrokerState.recordCommit, BrokerState.linearizeEffect,
      BrokerState.continueAcceptedStart, BrokerState.retryStart,
      BrokerState.acceptPending, initial, BrokerState.empty, replace, same] at lookup

private theorem terminalDuplicate (wire : CanonicalWireOutcome) :
    (terminal wire).replay.ExactDuplicate envelope := by
  exact ⟨rfl, by
    simpa [terminal, linearized, postBudget, acceptedPending,
      BrokerState.recordCommit, BrokerState.linearizeEffect,
      BrokerState.continueAcceptedStart, BrokerState.retryStart] using
      ReplayState.acceptNew_stores_exact_binding initial.replay envelope⟩

private def retryCandidate (wire : CanonicalWireOutcome) :
    EventCandidate (terminalSnapshot wire) (retryEvent wire) :=
  ⟨terminalSnapshot wire, by
    change Accepted (.terminalDuplicate (.committed receipt wire))
      context (terminal wire) (terminal wire)
    exact .terminalDuplicate (terminalClear wire) (terminalDuplicate wire)
      (by simp [terminal, BrokerState.recordCommit, context,
        RequestContext.request, envelope, request, replace])
      (by simp [BrokerOutcome.Terminal])⟩

private def trace (wire : CanonicalWireOutcome) : TraceInput initialSnapshot :=
  .cons acceptEvent acceptCandidate
    (.cons startEvent startCandidate
      (.cons linearizeEvent linearizeCandidate
        (.cons (terminalEvent wire) (terminalCandidate wire)
          (.cons (retryEvent wire) (retryCandidate wire)
            (.nil (terminalSnapshot wire))))))

def traceAccepted (digest : Nat) : Bool :=
  (Authority.Refinement.Broker.checkTrace (trace ⟨digest⟩)).isSome

def chunkTraceAccepted (digest : Nat) (chunks : List ChunkRow) : Bool :=
  let wire : CanonicalWireOutcome := ⟨digest⟩
  let observations := chunks.map fun chunk => {
    manifest := {
      schemaVersion := chunk.version
      requestId := request
      chunkCount := chunk.count
      totalLength := chunk.totalLength
      completeWireDigest := chunk.digest }
    chunkIndex := chunk.index
    payloadBytes := chunk.payloadBytes : ChunkObservation }
  Authority.Refinement.Broker.checkChunkTrace (terminalEvent wire) observations

end BrokerCheck

namespace OrchestratorCheck

open Authority.Orchestrator
open Authority.Refinement.OrchestratorRuntime

private def ledger : IdentityLedger := fun _ => false

private def identity : SessionIdentity where
  session := ⟨"01010101010101010101010101010101"⟩
  request := ⟨"02020202020202020202020202020202"⟩
  vm := ⟨"03030303030303030303030303030303"⟩
  subject := ⟨"04040404040404040404040404040404"⟩
  workspace := ⟨"05050505050505050505050505050505"⟩
  capability := ⟨"06060606060606060606060606060606"⟩
  brokerSession := ⟨"07070707070707070707070707070707"⟩

private def workspace : WorkspaceLease where
  session := identity.session
  workspace := identity.workspace

private def broker : BrokerLease where
  session := identity.session
  brokerSession := identity.brokerSession

private def vm : VmLease where
  session := identity.session
  vm := identity.vm
  workspace := identity.workspace
  brokerSession := identity.brokerSession

private def capability : CapabilityLease where
  session := identity.session
  subject := identity.subject
  capability := identity.capability

private def workload : WorkloadLease where
  session := identity.session
  vm := identity.vm
  subject := identity.subject
  capability := identity.capability

private theorem identityFresh : IdentityBatchFresh ledger identity := by
  constructor
  · intro kind
    rfl
  · intro first second same
    cases first <;> cases second <;>
      simp [identity, SessionIdentity.forKind] at same ⊢

private def initial : RuntimeState := RuntimeState.initial ledger
private def reserved : RuntimeState :=
  initial.withManaged { initial.managed with
    core := reserveIdentities initial.managed.core identity }
private def cloned : RuntimeState :=
  reserved.withManaged { reserved.managed with
    core := commitWorkspace reserved.managed.core workspace }
private def bound : RuntimeState :=
  { cloned with
    managed := { cloned.managed with core := commitBroker cloned.managed.core broker }
    worker := .bound broker }
private def workerReady : RuntimeState := { bound with worker := .running broker }
private def paused : RuntimeState :=
  { workerReady with
    managed := { workerReady.managed with core := commitVm workerReady.managed.core vm }
    vmPaused := true }
private def injected : RuntimeState :=
  paused.withManaged { paused.managed with
    core := commitCapability paused.managed.core capability }
private def released : RuntimeState :=
  { injected with
    managed := { injected.managed with core := commitWorkload injected.managed.core workload }
    vmPaused := false
    workloadReleased := true }
private def running : RuntimeState :=
  released.withManaged { released.managed with core := markRunning released.managed.core }

private def reserveStep : Step (.reserveIdentities identity) initial reserved :=
  .reserve rfl (Or.inl rfl) identityFresh

private def workspaceStep : Step (.workspaceCloned workspace) reserved cloned :=
  .workspace rfl rfl rfl ⟨rfl, rfl⟩

private def bindStep : Step (.brokerBound broker) cloned bound :=
  .brokerBound rfl rfl rfl ⟨rfl, rfl⟩ rfl

private def workerStep : Step (.workerRunning broker) bound workerReady := by
  exact .workerRunning rfl (by
    simp [bound, cloned, commitBroker, broker])

private def vmStep : Step (.pausedVmStarted vm) workerReady paused := by
  exact .pausedVmStarted rfl rfl rfl ⟨rfl, rfl, rfl, rfl⟩
    (by simp [workerReady, bound, cloned, commitBroker, broker]) rfl

private def capabilityStep :
    Step (.rootCapabilityInjected capability) paused injected := by
  exact .capabilityInjected rfl rfl rfl ⟨rfl, rfl, rfl⟩
    (by simp [paused, workerReady, bound, cloned, commitVm, commitBroker, broker])
    rfl rfl rfl

private def workloadStep : Step (.workloadReleased workload) injected released := by
  exact .workloadReleased rfl rfl rfl ⟨rfl, rfl, rfl, rfl⟩
    (by simp [injected, paused, workerReady, bound, cloned,
      RuntimeState.withManaged, commitCapability, commitVm, commitBroker, broker])
    rfl rfl

private def publishStep : Step .runningPublished released running := by
  exact .runningPublished rfl rfl
    (by simp [released, injected, paused, workerReady, bound, cloned,
      RuntimeState.withManaged, commitWorkload, commitCapability, commitVm,
      commitBroker, broker]) rfl rfl

private theorem runningBrokerLookup :
    running.managed.core.resources.broker = some broker := by
  simp [running, released, injected, paused, workerReady, bound, cloned,
    RuntimeState.withManaged, markRunning, commitWorkload, commitCapability,
    commitVm, commitBroker, broker]

private def stopping : RuntimeState :=
  running.beginShutdown (.brokerExited .panicked) (.exited broker .panicked)
private def revoked : RuntimeState :=
  stopping.recordCleanup stopping.managed.cleanup.revokeCapability
private def killed : RuntimeState := revoked.recordCleanup revoked.managed.cleanup.killVm
private def joined : RuntimeState :=
  { killed.recordCleanup killed.managed.cleanup.closeBroker with
    worker := .joined broker .panicked }
private def isolated : RuntimeState :=
  joined.recordCleanup joined.managed.cleanup.isolateWorkspace
private def closed : RuntimeState := isolated.finishClosed

private def exitStep : Step (.unexpectedBrokerExit broker .panicked) running stopping := by
  exact .unexpectedExit rfl rfl runningBrokerLookup rfl

private def revokeStep : Step .capabilityRevoked stopping revoked :=
  .capabilityRevoked rfl

private def killStep : Step .vmKilled revoked killed := .vmKilled rfl rfl

private def joinStep : Step (.brokerCancelledAndJoined broker .panicked) killed joined := by
  exact .brokerJoined rfl rfl
    (by
      change running.managed.core.resources.broker = some broker
      exact runningBrokerLookup) (.exited)

private def isolateStep : Step .workspaceIsolated joined isolated :=
  .workspaceIsolated rfl rfl rfl trivial

private theorem isolatedComplete : isolated.managed.cleanup.Complete := by
  change true = true ∧ true = true ∧ true = true ∧ true = true
  exact ⟨rfl, rfl, rfl, rfl⟩

private def closeStep : Step .closedPublished isolated closed :=
  .closedPublished rfl isolatedComplete trivial

private def snapshot (state : RuntimeState) :=
  Authority.Refinement.OrchestratorRuntime.StateSnapshot.ofState state
private def event (label : Label) (after : RuntimeState) :=
  Authority.Refinement.OrchestratorRuntime.Event.ofState label after

private def candidate {before after : RuntimeState} {label : Label}
    (transition : Step label before after) :
    EventCandidate (snapshot before) (event label after) :=
  ⟨snapshot after, transition⟩

private def trace : TraceInput (snapshot initial) :=
  .cons (event (.reserveIdentities identity) reserved) (candidate reserveStep)
    (.cons (event (.workspaceCloned workspace) cloned) (candidate workspaceStep)
      (.cons (event (.brokerBound broker) bound) (candidate bindStep)
        (.cons (event (.workerRunning broker) workerReady) (candidate workerStep)
          (.cons (event (.pausedVmStarted vm) paused) (candidate vmStep)
            (.cons (event (.rootCapabilityInjected capability) injected)
              (candidate capabilityStep)
              (.cons (event (.workloadReleased workload) released)
                (candidate workloadStep)
                (.cons (event .runningPublished running) (candidate publishStep)
                  (.cons (event (.unexpectedBrokerExit broker .panicked) stopping)
                    (candidate exitStep)
                    (.cons (event .capabilityRevoked revoked) (candidate revokeStep)
                      (.cons (event .vmKilled killed) (candidate killStep)
                        (.cons (event (.brokerCancelledAndJoined broker .panicked) joined)
                          (candidate joinStep)
                          (.cons (event .workspaceIsolated isolated)
                            (candidate isolateStep)
                            (.cons (event .closedPublished closed) (candidate closeStep)
                              (.nil (snapshot closed)))))))))))))))

def traceAccepted : Bool :=
  (Authority.Refinement.OrchestratorRuntime.checkTrace trace).isSome

theorem traceAccepted_sound : traceAccepted = true := by native_decide

end OrchestratorCheck

private def authoritySchemaValid (corpus : Corpus) : Bool :=
  authorityTraceValid corpus

private def brokerSchemaValid (corpus : Corpus) : Bool :=
  let accepted := corpus.acceptedPending
  let reserved := corpus.budgetReserved
  let terminal := corpus.terminal
  let retry := corpus.exactRetry
  accepted.name == "accepted-pending" && accepted.version == 1 &&
    accepted.sequence == 0 && accepted.requestId == expectedRequestId &&
    accepted.payloadHash == expectedPayloadHash && accepted.responseCap == responseCap &&
    accepted.phase == "accepted-pending" && accepted.reservation == "-" &&
    accepted.startedRequests == 0 && accepted.committedResponseBytes == 0 &&
    accepted.reservedResponseBytes == 0 && accepted.activeRequests == 0 &&
    accepted.terminalDigest == none && accepted.chunkCount == none &&
    accepted.totalLength == none &&
  reserved.name == "budget-reserved" && reserved.version == 1 &&
    reserved.sequence == accepted.sequence && reserved.requestId == accepted.requestId &&
    reserved.payloadHash == accepted.payloadHash && reserved.responseCap == responseCap &&
    reserved.phase == "accepted-pending" && reserved.reservation == "1100000" &&
    reserved.startedRequests == 1 && reserved.committedResponseBytes == 0 &&
    reserved.reservedResponseBytes == responseCap && reserved.activeRequests == 1 &&
    reserved.terminalDigest == none && reserved.chunkCount == none &&
    reserved.totalLength == none &&
  terminal.name == "terminal" && terminal.version == 1 &&
    terminal.sequence == accepted.sequence && terminal.requestId == accepted.requestId &&
    terminal.payloadHash == accepted.payloadHash && terminal.responseCap == responseCap &&
    terminal.phase == "final" && terminal.reservation == "-" &&
    terminal.startedRequests == 1 && terminal.committedResponseBytes == responseCap &&
    terminal.reservedResponseBytes == 0 && terminal.activeRequests == 0 &&
    terminal.chunkCount == some corpus.chunks.length &&
  retry.name == "exact-retry" && retry.version == 1 &&
    retry.sequence == terminal.sequence && retry.requestId == terminal.requestId &&
    retry.payloadHash == terminal.payloadHash && retry.responseCap == responseCap &&
    retry.phase == "final" && some retry.terminalDigest == terminal.terminalDigest &&
  corpus.chunks.all fun chunk =>
    chunk.name == "terminal-public" && chunk.version == 1 &&
      chunk.requestId == terminal.requestId &&
      some chunk.count == terminal.chunkCount &&
      some chunk.totalLength == terminal.totalLength &&
      some chunk.digest == terminal.terminalDigest

private def orchestratorSchemaValid (corpus : Corpus) : Bool :=
  corpus.orchestrator == {
    name := "owned-exit"
    version := 1
    sessionId := expectedSessionId
    brokerSessionId := expectedBrokerSessionId
    phase := "closed"
    shutdownReason := "broker-exited"
    events := expectedOrchestratorEvents : OrchestratorRow }

/-- Existing Broker and orchestrator refinements applied to parsed observations. -/
def checkerAgreement (corpus : Corpus) : Bool :=
  match corpus.terminal.terminalDigest with
  | none => false
  | some digest =>
      BrokerCheck.traceAccepted digest &&
        BrokerCheck.chunkTraceAccepted digest corpus.chunks &&
        OrchestratorCheck.traceAccepted

/-- Closed-schema and existing-checker validation for one parsed corpus. -/
def checkCorpus (corpus : Corpus) : Bool :=
  authoritySchemaValid corpus && brokerSchemaValid corpus &&
    orchestratorSchemaValid corpus && checkerAgreement corpus

/-- Acceptance explicitly includes both proof-carrying subsystem checkers. -/
theorem checkCorpus_checkerAgreement {corpus : Corpus}
    (accepted : checkCorpus corpus = true) : checkerAgreement corpus = true := by
  simp only [checkCorpus, Bool.and_eq_true] at accepted
  exact accepted.2

/-- Checked agreement supplies a terminal digest and all subsystem checks. -/
theorem checkerAgreement_sound {corpus : Corpus}
    (accepted : checkerAgreement corpus = true) :
    ∃ digest, corpus.terminal.terminalDigest = some digest ∧
      BrokerCheck.traceAccepted digest = true ∧
      BrokerCheck.chunkTraceAccepted digest corpus.chunks = true ∧
      OrchestratorCheck.traceAccepted = true := by
  unfold checkerAgreement at accepted
  split at accepted
  · contradiction
  · rename_i digest terminalDigest
    simp only [Bool.and_eq_true] at accepted
    exact ⟨digest, terminalDigest, accepted.1.1, accepted.1.2, accepted.2⟩

private def renderAuthority (row : AuthorityRow) : String :=
  let attemptId := row.attemptId.map toString |>.getD "-"
  let evidenceAttemptId := row.evidenceAttemptId.map toString |>.getD "-"
  let activeBefore := if row.activeBefore then "1" else "0"
  let activeAfter := if row.activeAfter then "1" else "0"
  s!"authority\t{row.name}\t{row.version}\t{row.caller}\t{row.owner}\t{row.capability}\t{row.outcome}\t{row.beforeEpoch}\t{row.afterEpoch}\t{activeBefore}\t{activeAfter}\t{row.beforeNextAttempt}\t{row.afterNextAttempt}\t{attemptId}\t{evidenceAttemptId}\t{row.evidenceBytes}\t{row.auditOutcome}\t{row.beforeEffectCount}\t{row.afterEffectCount}"

private def renderBroker (row : BrokerRow) : String :=
  let baseLine :=
    s!"broker\t{row.name}\t{row.version}\t{row.sequence}\t{row.requestId}\t{row.payloadHash}\t{row.responseCap}\t{row.phase}\t{row.reservation}\t{row.startedRequests}\t{row.committedResponseBytes}\t{row.reservedResponseBytes}\t{row.activeRequests}"
  match row.terminalDigest, row.chunkCount, row.totalLength with
  | none, none, none => baseLine
  | some digest, some count, some length => s!"{baseLine}\t{digest}\t{count}\t{length}"
  | _, _, _ => baseLine

private def renderChunk (row : ChunkRow) : String :=
  s!"chunk\t{row.name}\t{row.version}\t{row.requestId}\t{row.index}\t{row.count}\t{row.totalLength}\t{row.digest}\t{row.payloadBytes}"

private def renderRetry (row : RetryRow) : String :=
  s!"broker\t{row.name}\t{row.version}\t{row.sequence}\t{row.requestId}\t{row.payloadHash}\t{row.responseCap}\t{row.phase}\t{row.terminalDigest}"

private def renderOrchestrator (row : OrchestratorRow) : String :=
  s!"orchestrator\t{row.name}\t{row.version}\t{row.sessionId}\t{row.brokerSessionId}\t{row.phase}\t{row.shutdownReason}\t{row.events}"

/-- Canonical lines emitted after successful validation. -/
def normalizedLines (corpus : Corpus) : List String :=
  [corpusHeader, renderAuthority corpus.commitUnknown,
    renderAuthority corpus.foreignRevoke,
    renderAuthority corpus.ownedRevoke, renderBroker corpus.acceptedPending,
    renderBroker corpus.budgetReserved, renderBroker corpus.terminal] ++
    corpus.chunks.map renderChunk ++
    [renderRetry corpus.exactRetry, renderOrchestrator corpus.orchestrator]

/-- Parse, check, and normalize a proof-free Rust runtime corpus. -/
def evaluateCorpus (input : String) : Except String (List String) := do
  let corpus ← parseCorpus input
  if checkCorpus corpus then
    pure (normalizedLines corpus)
  else
    throw "runtime corpus observation failed schema or refinement checking"

example : (parseCorpus "unknown\n").isOk = false := by native_decide

end Authority.Refinement.RuntimeCorpus
