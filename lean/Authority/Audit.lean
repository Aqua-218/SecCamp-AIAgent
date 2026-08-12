import Authority.State

/-!
# Authorization Audit State Machine

Logical specification of the append-only authorization journal.  Byte framing,
checksums, `fsync`, and crash recovery remain Rust implementation obligations;
this module proves the state and receipt invariants those mechanisms preserve.
-/

namespace Authority

/-- Monotone identity for one authorization attempt. -/
structure AttemptId where
  value : Nat
  deriving Repr, BEq, DecidableEq

/-- A nonempty set of requests checked at one shared commit boundary. -/
structure CapabilityRequestSet where
  first : CapabilityRequest
  additional : List CapabilityRequest

namespace CapabilityRequestSet

/-- Every request in a compound operation, preserving authorization order. -/
def toList (requests : CapabilityRequestSet) : List CapabilityRequest :=
  requests.first :: requests.additional

/-- A request set cannot be empty. -/
theorem toList_ne_nil (requests : CapabilityRequestSet) : requests.toList ≠ [] := by
  simp [toList]

end CapabilityRequestSet

/-- Current outcome of one authorization attempt. -/
inductive AttemptOutcome where
  | started
  | denied
  | failedBeforeCommit
  | committed
  deriving Repr, BEq, DecidableEq

namespace AttemptOutcome

/-- An outcome is terminal exactly when it is no longer `started`. -/
def Terminal : AttemptOutcome → Prop
  | .started => False
  | .denied => True
  | .failedBeforeCommit => True
  | .committed => True

/-- No terminal outcome is `started`. -/
theorem terminal_ne_started {outcome : AttemptOutcome}
    (terminal : outcome.Terminal) : outcome ≠ .started := by
  cases outcome <;> simp [Terminal] at terminal ⊢

end AttemptOutcome

/-- A bounded opaque token proving external acceptance of one attempt. -/
structure CommitReceipt where
  attemptId : AttemptId
  token : List UInt8
  deriving Repr, DecidableEq

/-- Immutable metadata recorded before the executor is invoked. -/
structure AttemptMetadata where
  caller : SubjectId
  capabilityId : CapId
  requests : CapabilityRequestSet
  authorizationEpoch : Nat

/-- Complete logical record recovered from the durable journal. -/
structure AttemptRecord where
  id : AttemptId
  startSequence : Nat
  metadata : AttemptMetadata
  outcome : AttemptOutcome
  finishSequence : Option Nat
  receipt : Option CommitReceipt

/-- Sequential audit state before byte-level serialization. -/
structure AuditState where
  nextSequence : Nat
  attempts : AttemptId → Option AttemptRecord

namespace AuditState

/-- Empty journal state. -/
def empty : AuditState where
  nextSequence := 0
  attempts := fun _ => none

/-- An attempt identity is permanently reserved after its start record. -/
def WasStarted (state : AuditState) (attemptId : AttemptId) : Prop :=
  ∃ record, state.attempts attemptId = some record

/-- The journal exposes an effect exactly for a committed attempt. -/
def HasEffect (state : AuditState) (attemptId : AttemptId) : Prop :=
  ∃ record receipt,
    state.attempts attemptId = some record ∧
    record.outcome = .committed ∧
    record.receipt = some receipt ∧
    receipt.attemptId = attemptId

/-- Preconditions for appending and syncing a start record. -/
structure MayBegin (state : AuditState) (attemptId : AttemptId) where
  fresh : state.attempts attemptId = none

/-- Receipt policy for a terminal record. -/
def ValidReceipt (attemptId : AttemptId) (outcome : AttemptOutcome)
    (receipt : Option CommitReceipt) : Prop :=
  match outcome, receipt with
  | .committed, some committedReceipt => committedReceipt.attemptId = attemptId
  | .committed, none => False
  | .started, _ => False
  | .denied, none => True
  | .failedBeforeCommit, none => True
  | .denied, some _ => False
  | .failedBeforeCommit, some _ => False

/-- Preconditions for appending and syncing a terminal record. -/
structure MayFinish (state : AuditState) (attemptId : AttemptId)
    (outcome : AttemptOutcome) (receipt : Option CommitReceipt) where
  currentRecord : AttemptRecord
  currentLookup : state.attempts attemptId = some currentRecord
  stillStarted : currentRecord.outcome = .started
  receiptValid : ValidReceipt attemptId outcome receipt

/-- Recover the attempt identity indexed by validated finish evidence. -/
def MayFinish.attemptId {state : AuditState} {attemptId : AttemptId}
    {outcome : AttemptOutcome} {receipt : Option CommitReceipt}
    (_ : MayFinish state attemptId outcome receipt) : AttemptId := attemptId

/-- Construct the exact record written by an accepted begin transition. -/
def startedRecord (state : AuditState) (attemptId : AttemptId)
    (metadata : AttemptMetadata) : AttemptRecord where
  id := attemptId
  startSequence := state.nextSequence
  metadata := metadata
  outcome := .started
  finishSequence := none
  receipt := none

/-- Append one start record and consume one journal sequence. -/
def beginAttempt (state : AuditState) (attemptId : AttemptId)
    (metadata : AttemptMetadata) : AuditState :=
  { nextSequence := state.nextSequence + 1
    attempts := replace state.attempts attemptId
      (some (state.startedRecord attemptId metadata)) }

/-- Construct a terminal record without changing immutable start metadata. -/
def terminalRecord (state : AuditState) (current : AttemptRecord)
    (outcome : AttemptOutcome) (receipt : Option CommitReceipt) : AttemptRecord :=
  { current with
    outcome := outcome
    finishSequence := some state.nextSequence
    receipt := receipt }

/-- Append one validated terminal record and consume one journal sequence. -/
def finishAttempt (state : AuditState) (attemptId : AttemptId)
    (current : AttemptRecord) (outcome : AttemptOutcome)
    (receipt : Option CommitReceipt) : AuditState :=
  { nextSequence := state.nextSequence + 1
    attempts := replace state.attempts attemptId
      (some (state.terminalRecord current outcome receipt)) }

/-- A begin transition stores its exact start record. -/
theorem beginAttempt_stores_exact_record (state : AuditState)
    (attemptId : AttemptId) (metadata : AttemptMetadata) :
    (state.beginAttempt attemptId metadata).attempts attemptId =
      some (state.startedRecord attemptId metadata) := by
  simp [beginAttempt]

/-- A start record uses the current sequence and has no inferred completion. -/
theorem startedRecord_fields (state : AuditState) (attemptId : AttemptId)
    (metadata : AttemptMetadata) :
    (state.startedRecord attemptId metadata).id = attemptId ∧
    (state.startedRecord attemptId metadata).startSequence = state.nextSequence ∧
    (state.startedRecord attemptId metadata).metadata = metadata ∧
    (state.startedRecord attemptId metadata).outcome = .started ∧
    (state.startedRecord attemptId metadata).finishSequence = none ∧
    (state.startedRecord attemptId metadata).receipt = none := by
  simp [startedRecord]

/-- Beginning a fresh attempt preserves every earlier attempt record. -/
theorem beginAttempt_preserves_existing {state : AuditState}
    {newAttempt existingAttempt : AttemptId} {metadata : AttemptMetadata}
    (allowed : MayBegin state newAttempt) {existingRecord : AttemptRecord}
    (existingLookup : state.attempts existingAttempt = some existingRecord) :
    (state.beginAttempt newAttempt metadata).attempts existingAttempt =
      some existingRecord := by
  by_cases sameAttempt : existingAttempt = newAttempt
  · subst existingAttempt
    have freshness := allowed.fresh
    rw [existingLookup] at freshness
    cases freshness
  · simp [beginAttempt, replace, sameAttempt]
    exact existingLookup

/-- A finish transition stores the exact selected terminal fields. -/
theorem finishAttempt_stores_exact_record {state : AuditState}
    {attemptId : AttemptId} {outcome : AttemptOutcome}
    {receipt : Option CommitReceipt} (allowed : MayFinish state attemptId outcome receipt) :
    (state.finishAttempt attemptId allowed.currentRecord outcome receipt).attempts attemptId =
      some (state.terminalRecord allowed.currentRecord outcome receipt) := by
  simp [finishAttempt]

/-- Finishing an attempt preserves its start identity, sequence, and metadata. -/
theorem terminalRecord_preserves_start_fields (state : AuditState)
    (current : AttemptRecord) (outcome : AttemptOutcome)
    (receipt : Option CommitReceipt) :
    (state.terminalRecord current outcome receipt).id = current.id ∧
    (state.terminalRecord current outcome receipt).startSequence = current.startSequence ∧
    (state.terminalRecord current outcome receipt).metadata = current.metadata := by
  simp [terminalRecord]

/-- Finishing one attempt preserves every other attempt record. -/
theorem finishAttempt_preserves_other (state : AuditState)
    (finishedAttempt : AttemptId) (current : AttemptRecord)
    (outcome : AttemptOutcome) (receipt : Option CommitReceipt)
    {existingAttempt : AttemptId} (differentAttempts : existingAttempt ≠ finishedAttempt) :
    (state.finishAttempt finishedAttempt current outcome receipt).attempts existingAttempt =
      state.attempts existingAttempt := by
  simp [finishAttempt, replace, differentAttempts]

/-- A valid committed terminal record must carry a matching receipt. -/
theorem validReceipt_committed_iff {attemptId : AttemptId}
    {receipt : Option CommitReceipt} :
    ValidReceipt attemptId .committed receipt ↔
      ∃ committedReceipt, receipt = some committedReceipt ∧
        committedReceipt.attemptId = attemptId := by
  cases receipt with
  | none => simp [ValidReceipt]
  | some committedReceipt => simp [ValidReceipt]

/-- Denied and pre-commit-failed attempts cannot carry a receipt. -/
theorem validReceipt_noncommitted_is_none {attemptId : AttemptId}
    {outcome : AttemptOutcome} {receipt : Option CommitReceipt}
    (notCommitted : outcome = .denied ∨ outcome = .failedBeforeCommit)
    (valid : ValidReceipt attemptId outcome receipt) : receipt = none := by
  rcases notCommitted with denied | failed
  · subst outcome
    cases receipt <;> simp [ValidReceipt] at valid ⊢
  · subst outcome
    cases receipt <;> simp [ValidReceipt] at valid ⊢

/-- `started` can never be appended as a terminal record. -/
theorem validReceipt_rejects_started (attemptId : AttemptId)
    (receipt : Option CommitReceipt) :
    ¬ ValidReceipt attemptId .started receipt := by
  cases receipt <;> simp [ValidReceipt]

/-- Security-relevant accepted audit transitions. -/
inductive Step : AuditState → AuditState → Prop
  | begin {state : AuditState} {attemptId : AttemptId} {metadata : AttemptMetadata} :
      MayBegin state attemptId →
      Step state (state.beginAttempt attemptId metadata)
  | finish {state : AuditState} {attemptId : AttemptId}
      {outcome : AttemptOutcome} {receipt : Option CommitReceipt} :
      (allowed : MayFinish state attemptId outcome receipt) →
      Step state (state.finishAttempt attemptId allowed.currentRecord outcome receipt)

/-- Every accepted append consumes exactly one sequence number. -/
theorem Step.nextSequence_exact {before after : AuditState}
    (transition : Step before after) :
    after.nextSequence = before.nextSequence + 1 := by
  cases transition <;> rfl

/-- Once started, an attempt identity remains permanently reserved. -/
theorem Step.started_attempt_persists {before after : AuditState}
    (transition : Step before after) {attemptId : AttemptId}
    (startedBefore : before.WasStarted attemptId) :
    after.WasStarted attemptId := by
  rcases startedBefore with ⟨existingRecord, existingLookup⟩
  cases transition with
  | begin allowed =>
      exact ⟨existingRecord, beginAttempt_preserves_existing allowed existingLookup⟩
  | finish allowed =>
      by_cases sameAttempt : attemptId = allowed.attemptId
      · subst attemptId
        exact ⟨_, finishAttempt_stores_exact_record allowed⟩
      · exact ⟨existingRecord,
          (finishAttempt_preserves_other _ _ _ _ _ sameAttempt).trans existingLookup⟩

/-- A terminal attempt is immutable under all later accepted appends. -/
theorem Step.terminal_attempt_immutable {before after : AuditState}
    (transition : Step before after) {attemptId : AttemptId}
    {terminalRecord : AttemptRecord}
    (terminalLookup : before.attempts attemptId = some terminalRecord)
    (terminal : terminalRecord.outcome.Terminal) :
    after.attempts attemptId = some terminalRecord := by
  cases transition with
  | begin allowed => exact beginAttempt_preserves_existing allowed terminalLookup
  | finish allowed =>
      by_cases sameAttempt : attemptId = allowed.attemptId
      · subst attemptId
        have sameRecord : terminalRecord = allowed.currentRecord :=
          Option.some.inj (terminalLookup.symm.trans allowed.currentLookup)
        subst terminalRecord
        have terminalWasStarted := allowed.stillStarted
        rw [terminalWasStarted] at terminal
        simp [AttemptOutcome.Terminal] at terminal
      · exact (finishAttempt_preserves_other _ _ _ _ _ sameAttempt).trans terminalLookup

/-- A committed finish creates one effect with a receipt bound to the attempt. -/
theorem finish_committed_creates_effect {state : AuditState}
    {attemptId : AttemptId} {receipt : Option CommitReceipt}
    (allowed : MayFinish state attemptId .committed receipt) :
    (state.finishAttempt attemptId allowed.currentRecord .committed receipt).HasEffect attemptId := by
  rcases validReceipt_committed_iff.mp allowed.receiptValid with
    ⟨committedReceipt, receiptIsSome, receiptMatches⟩
  subst receipt
  refine ⟨state.terminalRecord allowed.currentRecord .committed (some committedReceipt),
    committedReceipt, finishAttempt_stores_exact_record allowed, ?_, ?_, receiptMatches⟩
  · rfl
  · rfl

/-- Denied and pre-commit-failed finishes never create an effect snapshot. -/
theorem finish_noncommitted_has_no_effect {state : AuditState}
    {attemptId : AttemptId} {outcome : AttemptOutcome}
    {receipt : Option CommitReceipt}
    (nonCommitted : outcome = .denied ∨ outcome = .failedBeforeCommit)
    (allowed : MayFinish state attemptId outcome receipt) :
    ¬ (state.finishAttempt attemptId allowed.currentRecord outcome receipt).HasEffect attemptId := by
  have receiptIsNone := validReceipt_noncommitted_is_none nonCommitted allowed.receiptValid
  subst receipt
  intro effect
  rcases effect with ⟨effectRecord, _, effectLookup, committedOutcome, _, _⟩
  have storedRecordIsTerminal :
      effectRecord = state.terminalRecord allowed.currentRecord outcome none :=
    Option.some.inj
      (effectLookup.symm.trans (finishAttempt_stores_exact_record allowed))
  subst effectRecord
  rcases nonCommitted with denied | failed
  · subst outcome
    simp [terminalRecord] at committedOutcome
  · subst outcome
    simp [terminalRecord] at committedOutcome

/-- Every effect snapshot refers to a started record and a matching receipt. -/
theorem hasEffect_implies_started_and_matching_receipt {state : AuditState}
    {attemptId : AttemptId} (effect : state.HasEffect attemptId) :
    state.WasStarted attemptId ∧
      ∃ record receipt,
        state.attempts attemptId = some record ∧
        record.outcome = .committed ∧
        record.receipt = some receipt ∧
        receipt.attemptId = attemptId := by
  rcases effect with ⟨record, receipt, lookup, committed, storedReceipt, matchingId⟩
  exact ⟨⟨record, lookup⟩,
    ⟨record, receipt, lookup, committed, storedReceipt, matchingId⟩⟩

/-- A finite accepted execution of audit appends. -/
inductive Steps : AuditState → AuditState → Nat → Prop
  | refl (state : AuditState) : Steps state state 0
  | next {before middle after : AuditState} {remainingLength : Nat} :
      Step before middle → Steps middle after remainingLength →
      Steps before after (remainingLength + 1)

/-- Sequence growth exactly counts every accepted append in an arbitrary run. -/
theorem Steps.nextSequence_exact {before after : AuditState} {length : Nat}
    (execution : Steps before after length) :
    after.nextSequence = before.nextSequence + length := by
  induction execution with
  | refl => simp
  | next firstStep remainingSteps inductionResult =>
      rw [inductionResult, firstStep.nextSequence_exact]
      omega

/-- Terminal records remain immutable across an arbitrary accepted execution. -/
theorem Steps.terminal_attempt_immutable {before after : AuditState} {length : Nat}
    (execution : Steps before after length) {attemptId : AttemptId}
    {terminalRecord : AttemptRecord}
    (terminalLookup : before.attempts attemptId = some terminalRecord)
    (terminal : terminalRecord.outcome.Terminal) :
    after.attempts attemptId = some terminalRecord := by
  induction execution generalizing terminalRecord with
  | refl => exact terminalLookup
  | next firstStep remainingSteps inductionResult =>
      exact inductionResult
        (firstStep.terminal_attempt_immutable terminalLookup terminal) terminal

end AuditState

end Authority
