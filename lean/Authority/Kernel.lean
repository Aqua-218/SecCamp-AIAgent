import Authority.Audit

/-!
# Authorization Kernel Protocol

Composition of capability authorization, durable audit intent, and an explicit
external-effect linearization event. The model proves successful-call ordering
and binding. Lock semantics, storage durability, and executor honesty remain
explicit refinement obligations.
-/

namespace Authority

/-- Every request in one attempt was authorized by the same locked epoch. -/
def AttemptMetadata.AllAuthorized (metadata : AttemptMetadata)
    (authority : CapabilityState) : Prop :=
  metadata.authorizationEpoch = authority.authorizationEpoch ∧
    ∀ request, request ∈ metadata.requests.toList →
      authority.Authorizes metadata.caller metadata.capabilityId request

/-- A journal contains a record with the supplied immutable start metadata. -/
def AuditState.HasMetadata (state : AuditState) (attemptId : AttemptId)
    (metadata : AttemptMetadata) : Prop :=
  ∃ record, state.attempts attemptId = some record ∧ record.metadata = metadata

/-- Beginning another fresh attempt preserves immutable metadata. -/
theorem AuditState.begin_preserves_metadata {state : AuditState}
    {newAttempt existingAttempt : AttemptId} {newMetadata existingMetadata : AttemptMetadata}
    (allowed : state.MayBegin newAttempt)
    (existing : state.HasMetadata existingAttempt existingMetadata) :
    (state.beginAttempt newAttempt newMetadata).HasMetadata
      existingAttempt existingMetadata := by
  rcases existing with ⟨record, lookup, metadataMatches⟩
  exact ⟨record, beginAttempt_preserves_existing allowed lookup, metadataMatches⟩

/-- Finishing an attempt preserves every immutable start metadata record. -/
theorem AuditState.finish_preserves_metadata {state : AuditState}
    {finishedAttempt existingAttempt : AttemptId} {outcome : AttemptOutcome}
    {receipt : Option CommitReceipt} {metadata : AttemptMetadata}
    (allowed : state.MayFinish finishedAttempt outcome receipt)
    (existing : state.HasMetadata existingAttempt metadata) :
    (state.finishAttempt finishedAttempt allowed.currentRecord outcome receipt).HasMetadata
      existingAttempt metadata := by
  rcases existing with ⟨record, lookup, metadataMatches⟩
  by_cases sameAttempt : existingAttempt = finishedAttempt
  · subst existingAttempt
    have sameRecord : record = allowed.currentRecord := Option.some.inj
      (lookup.symm.trans allowed.currentLookup)
    subst record
    exact ⟨state.terminalRecord allowed.currentRecord outcome receipt,
      finishAttempt_stores_exact_record allowed,
      by simpa [terminalRecord] using metadataMatches⟩
  · exact ⟨record,
      (finishAttempt_preserves_other _ _ _ _ _ sameAttempt).trans lookup,
      metadataMatches⟩

/-- Recording an ambiguous terminal preserves every immutable start metadata record. -/
theorem AuditState.finishCommitUnknown_preserves_metadata {state : AuditState}
    {finishedAttempt existingAttempt : AttemptId}
    {evidence : CommitUnknownEvidence} {metadata : AttemptMetadata}
    (allowed : state.MayFinishCommitUnknown finishedAttempt evidence)
    (existing : state.HasMetadata existingAttempt metadata) :
    AuditState.HasMetadata
      (state.finishCommitUnknownAttempt finishedAttempt allowed.currentRecord evidence)
        existingAttempt metadata := by
  rcases existing with ⟨record, lookup, metadataMatches⟩
  by_cases sameAttempt : existingAttempt = finishedAttempt
  · subst existingAttempt
    have sameRecord : record = allowed.currentRecord := Option.some.inj
      (lookup.symm.trans allowed.currentLookup)
    subst record
    exact ⟨state.terminalRecord allowed.currentRecord .commitUnknown none,
      (finishCommitUnknown_stores_exact allowed).1,
      by simpa [terminalRecord] using metadataMatches⟩
  · exact ⟨record,
      (finishCommitUnknown_preserves_other _ _ _ _ sameAttempt).trans lookup,
      metadataMatches⟩

/-- Composed state at protocol linearization points. -/
structure KernelState where
  authority : CapabilityState
  audit : AuditState
  activeAttempts : List AttemptId
  durableStarts : AttemptId → Option AttemptMetadata
  authorizations : AttemptId → Option AttemptMetadata
  authorizationAuthorities : AttemptId → Option CapabilityState
  externalEffects : AttemptId → Option CommitReceipt

namespace KernelState

/-- Initial composed state contains no attempts or external effects. -/
def initial (authority : CapabilityState) : KernelState where
  authority := authority
  audit := .empty
  activeAttempts := []
  durableStarts := fun _ => none
  authorizations := fun _ => none
  authorizationAuthorities := fun _ => none
  externalEffects := fun _ => none

/-- The named attempt has durable intent and same-snapshot authorization. -/
def HasAuthorizedSnapshot (state : KernelState) (attemptId : AttemptId) : Prop :=
  ∃ metadata authoritySnapshot,
    state.durableStarts attemptId = some metadata ∧
    state.authorizations attemptId = some metadata ∧
    state.authorizationAuthorities attemptId = some authoritySnapshot ∧
    metadata.AllAuthorized authoritySnapshot

/-- Audit, authorization, and external-effect views agree. -/
structure WellFormed (state : KernelState) : Prop where
  activeAttemptsNodup : state.activeAttempts.Nodup
  activeAttemptStarted : ∀ attemptId, attemptId ∈ state.activeAttempts →
    ∃ metadata record,
      state.durableStarts attemptId = some metadata ∧
        state.audit.attempts attemptId = some record ∧
        record.metadata = metadata ∧
        record.outcome = .started
  durableStartMirrored : ∀ attemptId metadata,
    state.durableStarts attemptId = some metadata →
      state.audit.HasMetadata attemptId metadata
  committedHasEffect : ∀ attemptId,
    state.audit.HasEffect attemptId →
      ∃ receipt, state.externalEffects attemptId = some receipt ∧
        receipt.attemptId = attemptId
  effectWasAuthorized : ∀ attemptId receipt,
    state.externalEffects attemptId = some receipt →
      receipt.attemptId = attemptId ∧ state.HasAuthorizedSnapshot attemptId

/-- Empty maps satisfy the composed invariant. -/
theorem initial_wellFormed (authority : CapabilityState) :
    (initial authority).WellFormed := by
  constructor
  · simp [initial]
  · intro attemptId active
    simp [initial] at active
  · intro attemptId metadata lookup
    simp [initial] at lookup
  · intro attemptId effect
    rcases effect with ⟨record, receipt, lookup, _⟩
    simp [initial, AuditState.empty] at lookup
  · intro attemptId receipt effect
    simp [initial] at effect

/-- Preconditions for writing durable intent for a fresh attempt. -/
structure MayBegin (state : KernelState) (attemptId : AttemptId) where
  notActive : attemptId ∉ state.activeAttempts
  auditAllowed : state.audit.MayBegin attemptId
  noDurableStart : state.durableStarts attemptId = none
  noAuthorization : state.authorizations attemptId = none
  noExternalEffect : state.externalEffects attemptId = none

/-- Append durable intent before final authorization or execution. -/
def beginAttempt (state : KernelState) (attemptId : AttemptId)
    (metadata : AttemptMetadata) : KernelState :=
  { state with
    audit := state.audit.beginAttempt attemptId metadata
    activeAttempts := attemptId :: state.activeAttempts
    durableStarts := replace state.durableStarts attemptId (some metadata) }

/-- Preconditions for the final authorization check under the shared guard. -/
structure MayAuthorize (state : KernelState) (attemptId : AttemptId) where
  active : attemptId ∈ state.activeAttempts
  metadata : AttemptMetadata
  durableLookup : state.durableStarts attemptId = some metadata
  currentRecord : AttemptRecord
  auditLookup : state.audit.attempts attemptId = some currentRecord
  auditStillStarted : currentRecord.outcome = .started
  noPriorAuthorization : state.authorizations attemptId = none
  allAuthorized : metadata.AllAuthorized state.authority

/-- Retain the exact authorization snapshot used by the executor. -/
def authorizeAttempt (state : KernelState) (attemptId : AttemptId)
    (metadata : AttemptMetadata) : KernelState :=
  { state with
    authorizations := replace state.authorizations attemptId (some metadata)
    authorizationAuthorities := replace state.authorizationAuthorities attemptId
      (some state.authority) }

/-- Preconditions for crossing the external effect linearization point. -/
structure MayLinearizeEffect (state : KernelState) (attemptId : AttemptId)
    (receipt : CommitReceipt) where
  receiptMatches : receipt.attemptId = attemptId
  active : attemptId ∈ state.activeAttempts
  authorized : state.HasAuthorizedSnapshot attemptId
  currentRecord : AttemptRecord
  auditLookup : state.audit.attempts attemptId = some currentRecord
  auditStillStarted : currentRecord.outcome = .started
  noPriorEffect : state.externalEffects attemptId = none

/-- Record the executor's one successful external linearization event. -/
def linearizeEffect (state : KernelState) (attemptId : AttemptId)
    (receipt : CommitReceipt) : KernelState :=
  { state with
    externalEffects := replace state.externalEffects attemptId (some receipt) }

/-- A terminal audit record cannot pass the final authorization gate. -/
theorem terminal_attempt_rejects_authorization {state : KernelState}
    {attemptId : AttemptId} {record : AttemptRecord}
    (lookup : state.audit.attempts attemptId = some record)
    (terminal : record.outcome.Terminal) :
    ∀ _allowed : MayAuthorize state attemptId, False := by
  intro allowed
  have sameRecord := Option.some.inj (lookup.symm.trans allowed.auditLookup)
  subst record
  have notStarted := AttemptOutcome.terminal_ne_started terminal
  exact notStarted allowed.auditStillStarted

/-- A terminal audit record cannot cross the external effect boundary. -/
theorem terminal_attempt_rejects_effect {state : KernelState}
    {attemptId : AttemptId} {record : AttemptRecord}
    (lookup : state.audit.attempts attemptId = some record)
    (terminal : record.outcome.Terminal) :
    ∀ receipt, MayLinearizeEffect state attemptId receipt → False := by
  intro receipt allowed
  have sameRecord := Option.some.inj (lookup.symm.trans allowed.auditLookup)
  subst record
  have notStarted := AttemptOutcome.terminal_ne_started terminal
  exact notStarted allowed.auditStillStarted

/-- A committed finish must correspond to the already-linearized effect. -/
structure MayCommit (state : KernelState) (attemptId : AttemptId)
    (receipt : CommitReceipt) where
  auditAllowed : state.audit.MayFinish attemptId .committed (some receipt)
  active : attemptId ∈ state.activeAttempts
  effectLookup : state.externalEffects attemptId = some receipt
  authorized : state.HasAuthorizedSnapshot attemptId

/-- A denial or pre-commit failure must have no external effect. -/
structure MayReject (state : KernelState) (attemptId : AttemptId)
    (outcome : AttemptOutcome) where
  nonCommitted : outcome = .denied ∨ outcome = .failedBeforeCommit
  active : attemptId ∈ state.activeAttempts
  auditAllowed : state.audit.MayFinish attemptId outcome none
  noExternalEffect : state.externalEffects attemptId = none

/-- An ambiguous completion records evidence without asserting an external effect. -/
structure MayCommitUnknown (state : KernelState) (attemptId : AttemptId)
    (evidence : CommitUnknownEvidence) where
  auditAllowed : state.audit.MayFinishCommitUnknown attemptId evidence
  active : attemptId ∈ state.activeAttempts
  authorized : state.HasAuthorizedSnapshot attemptId
  noExternalEffect : state.externalEffects attemptId = none

/-- Rust error paths where a terminal audit append can fail. -/
inductive TerminalAuditFailure where
  | denialAudit
  | precommitAudit
  | committedButAudit
  | commitUnknownAndAudit
  deriving Repr, BEq, DecidableEq

namespace TerminalAuditFailure

/-- Evidence retained for each explicit terminal-audit failure result. -/
def Evidence (failure : TerminalAuditFailure) (state : KernelState)
    (attemptId : AttemptId) : Prop :=
  match failure with
  | .denialAudit =>
      state.authorizations attemptId = none ∧
        state.externalEffects attemptId = none
  | .precommitAudit =>
      state.HasAuthorizedSnapshot attemptId ∧
        state.externalEffects attemptId = none
  | .committedButAudit =>
      ∃ receipt,
        state.externalEffects attemptId = some receipt ∧
          receipt.attemptId = attemptId ∧
          state.HasAuthorizedSnapshot attemptId
  | .commitUnknownAndAudit =>
      ∃ evidence : CommitUnknownEvidence,
        evidence.attemptId = attemptId ∧
          state.HasAuthorizedSnapshot attemptId ∧
          state.externalEffects attemptId = none

end TerminalAuditFailure

/-- Preconditions for releasing a read guard after a terminal audit write fails. -/
structure MayFailTerminalAudit (state : KernelState) (attemptId : AttemptId)
    (failure : TerminalAuditFailure) where
  active : attemptId ∈ state.activeAttempts
  currentRecord : AttemptRecord
  auditLookup : state.audit.attempts attemptId = some currentRecord
  auditStillStarted : currentRecord.outcome = .started
  evidence : failure.Evidence state attemptId

/-- Remove every occurrence of one attempt from the finite active-reader set. -/
def releaseAttempt (state : KernelState) (attemptId : AttemptId) : KernelState :=
  { state with
    activeAttempts := state.activeAttempts.filter fun activeAttempt =>
      activeAttempt ≠ attemptId }

/-- Releasing a guard removes only the selected active-attempt identity. -/
theorem mem_releaseAttempt_iff (state : KernelState)
    (releasedAttempt queriedAttempt : AttemptId) :
    queriedAttempt ∈ (state.releaseAttempt releasedAttempt).activeAttempts ↔
      queriedAttempt ∈ state.activeAttempts ∧ queriedAttempt ≠ releasedAttempt := by
  simp [releaseAttempt]

/-- Append a matching committed terminal audit record. -/
def commitAttempt (state : KernelState) (attemptId : AttemptId)
    (receipt : CommitReceipt) (current : AttemptRecord) : KernelState :=
  let finishedAudit := state.audit.finishAttempt attemptId current
    .committed (some receipt)
  { state.releaseAttempt attemptId with audit := finishedAudit }

/-- Append a terminal denial or pre-commit failure. -/
def rejectAttempt (state : KernelState) (attemptId : AttemptId)
    (outcome : AttemptOutcome) (current : AttemptRecord) : KernelState :=
  let finishedAudit := state.audit.finishAttempt attemptId current outcome none
  { state.releaseAttempt attemptId with audit := finishedAudit }

/-- Durably record an ambiguous completion and release its shared guard. -/
def commitUnknownAttempt (state : KernelState) (attemptId : AttemptId)
    (evidence : CommitUnknownEvidence) (current : AttemptRecord) : KernelState :=
  let finishedAudit :=
    state.audit.finishCommitUnknownAttempt attemptId current evidence
  { state.releaseAttempt attemptId with audit := finishedAudit }

/-- Release the shared guard while retaining the Started audit and result evidence. -/
def failTerminalAudit (state : KernelState) (attemptId : AttemptId) : KernelState :=
  state.releaseAttempt attemptId

/-- Mutate capability state only while no effect protocol holds the shared guard. -/
def mutateAuthority (state : KernelState) (authority : CapabilityState) : KernelState :=
  { state with authority := authority }

/-- Accepted protocol transitions while one shared authority guard is held. -/
inductive Step : KernelState → KernelState → Prop
  | begin {state : KernelState} {attemptId : AttemptId}
      {metadata : AttemptMetadata} :
      MayBegin state attemptId → Step state (state.beginAttempt attemptId metadata)
  | authorize {state : KernelState} {attemptId : AttemptId} :
      (allowed : MayAuthorize state attemptId) →
      Step state (state.authorizeAttempt attemptId allowed.metadata)
  | linearizeEffect {state : KernelState} {attemptId : AttemptId}
      {receipt : CommitReceipt} :
      MayLinearizeEffect state attemptId receipt →
      Step state (state.linearizeEffect attemptId receipt)
  | commit {state : KernelState} {attemptId : AttemptId}
      {receipt : CommitReceipt} :
      (allowed : MayCommit state attemptId receipt) →
      Step state (state.commitAttempt attemptId receipt allowed.auditAllowed.currentRecord)
  | reject {state : KernelState} {attemptId : AttemptId}
      {outcome : AttemptOutcome} :
      (allowed : MayReject state attemptId outcome) →
      Step state (state.rejectAttempt attemptId outcome allowed.auditAllowed.currentRecord)
  | commitUnknown {state : KernelState} {attemptId : AttemptId}
      {evidence : CommitUnknownEvidence} :
      (allowed : MayCommitUnknown state attemptId evidence) →
      Step state
        (state.commitUnknownAttempt attemptId evidence allowed.auditAllowed.currentRecord)
  | terminalAuditFailure {state : KernelState} {attemptId : AttemptId}
      {failure : TerminalAuditFailure} :
      MayFailTerminalAudit state attemptId failure →
      Step state (state.failTerminalAudit attemptId)
  | authorityTransition {state : KernelState} {authority : CapabilityState} :
      state.activeAttempts = [] →
      CapabilityState.Step state.authority authority →
      Step state (state.mutateAuthority authority)

/-- Authority mutations are accepted only outside a guarded effect protocol. -/
theorem Step.authority_change_requires_unlocked {before after : KernelState}
    (transition : Step before after) (changed : after.authority ≠ before.authority) :
    before.activeAttempts = [] ∧ after.activeAttempts = [] := by
  cases transition with
  | authorityTransition unlocked _ => exact ⟨unlocked, unlocked⟩
  | begin | authorize | linearizeEffect | commit | reject | commitUnknown |
      terminalAuditFailure =>
      exact False.elim (changed rfl)

/-- While an attempt owns the guard, one step cannot mutate authority. -/
theorem Step.locked_authority_stable {before after : KernelState}
    (transition : Step before after) {attemptId : AttemptId}
    (active : attemptId ∈ before.activeAttempts) :
    after.authority = before.authority := by
  cases transition with
  | authorityTransition unlocked _ => simp [unlocked] at active
  | begin | authorize | linearizeEffect | commit | reject | commitUnknown |
      terminalAuditFailure => rfl

/-- Begin stores both the exact audit record and durable-intent mirror. -/
theorem begin_stores_exact_intent (state : KernelState) (attemptId : AttemptId)
    (metadata : AttemptMetadata) :
    (state.beginAttempt attemptId metadata).durableStarts attemptId = some metadata ∧
    (state.beginAttempt attemptId metadata).audit.HasMetadata attemptId metadata := by
  constructor
  · simp [KernelState.beginAttempt]
  · exact ⟨state.audit.startedRecord attemptId metadata,
      AuditState.beginAttempt_stores_exact_record state.audit attemptId metadata, rfl⟩

/-- Authorization stores the exact metadata checked under the shared guard. -/
theorem authorize_has_exact_snapshot {state : KernelState} {attemptId : AttemptId}
    (allowed : MayAuthorize state attemptId) :
    (state.authorizeAttempt attemptId allowed.metadata).HasAuthorizedSnapshot attemptId := by
  exact ⟨allowed.metadata, state.authority, allowed.durableLookup,
    by simp [KernelState.authorizeAttempt],
    by simp [KernelState.authorizeAttempt], allowed.allAuthorized⟩

/-- Effect linearization retains the exact receipt. -/
theorem linearizeEffect_stores_exact_receipt (state : KernelState)
    (attemptId : AttemptId) (receipt : CommitReceipt) :
    (state.linearizeEffect attemptId receipt).externalEffects attemptId = some receipt := by
  simp [KernelState.linearizeEffect]

/-- Beginning an attempt activates its shared authority guard. -/
theorem begin_activates_attempt (state : KernelState) (attemptId : AttemptId)
    (metadata : AttemptMetadata) :
    attemptId ∈ (state.beginAttempt attemptId metadata).activeAttempts := by
  simp [KernelState.beginAttempt]

/-- Beginning a distinct reader does not displace an already-active reader. -/
theorem begin_preserves_active_attempt (state : KernelState)
    (newAttempt activeAttempt : AttemptId) (metadata : AttemptMetadata)
    (active : activeAttempt ∈ state.activeAttempts) :
    activeAttempt ∈ (state.beginAttempt newAttempt metadata).activeAttempts := by
  simp [KernelState.beginAttempt, active]

/-- A terminal audit failure releases exactly the named shared guard. -/
theorem failTerminalAudit_releases_attempt (state : KernelState)
    (attemptId : AttemptId) :
    attemptId ∉ (state.failTerminalAudit attemptId).activeAttempts := by
  simp [failTerminalAudit, releaseAttempt]

/-- Releasing the only reader makes the authority guard globally available. -/
theorem failTerminalAudit_unlocks_singleton {state : KernelState}
    {attemptId : AttemptId}
    (onlyActive : state.activeAttempts = [attemptId]) :
    (state.failTerminalAudit attemptId).activeAttempts = [] := by
  simp [failTerminalAudit, releaseAttempt, onlyActive]

/-- Releasing one failed attempt preserves every other active reader. -/
theorem failTerminalAudit_preserves_other_active (state : KernelState)
    {failedAttempt activeAttempt : AttemptId}
    (different : activeAttempt ≠ failedAttempt)
    (active : activeAttempt ∈ state.activeAttempts) :
    activeAttempt ∈ (state.failTerminalAudit failedAttempt).activeAttempts := by
  simp [failTerminalAudit, releaseAttempt, different, active]

/-- A terminal audit failure leaves the durable Started record unchanged. -/
theorem failTerminalAudit_retains_started {state : KernelState}
    {attemptId : AttemptId} {failure : TerminalAuditFailure}
    (allowed : MayFailTerminalAudit state attemptId failure) :
    ∃ record,
      (state.failTerminalAudit attemptId).audit.attempts attemptId = some record ∧
        record.outcome = .started := by
  exact ⟨allowed.currentRecord, allowed.auditLookup, allowed.auditStillStarted⟩

/-- A terminal audit failure retains its typed result evidence. -/
theorem failTerminalAudit_retains_evidence {state : KernelState}
    {attemptId : AttemptId} {failure : TerminalAuditFailure}
    (allowed : MayFailTerminalAudit state attemptId failure) :
    failure.Evidence (state.failTerminalAudit attemptId) attemptId := by
  cases failure <;>
    simpa [TerminalAuditFailure.Evidence, failTerminalAudit, releaseAttempt]
      using allowed.evidence

/-- In particular, a failed terminal append cannot erase a linearized effect. -/
theorem failTerminalAudit_retains_effect {state : KernelState}
    (attemptId : AttemptId) {receipt : CommitReceipt}
    (effect : state.externalEffects attemptId = some receipt) :
    (state.failTerminalAudit attemptId).externalEffects attemptId = some receipt := by
  exact effect

/-- A denial-audit error releases the guard with no authorization or effect. -/
theorem denialAudit_failure_result {state : KernelState}
    {attemptId : AttemptId}
    (allowed : MayFailTerminalAudit state attemptId .denialAudit) :
    attemptId ∉ (state.failTerminalAudit attemptId).activeAttempts ∧
      (∃ record,
        (state.failTerminalAudit attemptId).audit.attempts attemptId = some record ∧
          record.outcome = .started) ∧
      (state.failTerminalAudit attemptId).authorizations attemptId = none ∧
      (state.failTerminalAudit attemptId).externalEffects attemptId = none := by
  rcases allowed.evidence with ⟨noAuthorization, noEffect⟩
  exact ⟨failTerminalAudit_releases_attempt state attemptId,
    failTerminalAudit_retains_started allowed, noAuthorization, noEffect⟩

/-- A pre-commit audit error releases the guard with authorization but no effect. -/
theorem precommitAudit_failure_result {state : KernelState}
    {attemptId : AttemptId}
    (allowed : MayFailTerminalAudit state attemptId .precommitAudit) :
    attemptId ∉ (state.failTerminalAudit attemptId).activeAttempts ∧
      (∃ record,
        (state.failTerminalAudit attemptId).audit.attempts attemptId = some record ∧
          record.outcome = .started) ∧
      (state.failTerminalAudit attemptId).HasAuthorizedSnapshot attemptId ∧
      (state.failTerminalAudit attemptId).externalEffects attemptId = none := by
  rcases allowed.evidence with ⟨authorized, noEffect⟩
  exact ⟨failTerminalAudit_releases_attempt state attemptId,
    failTerminalAudit_retains_started allowed, authorized, noEffect⟩

/-- `CommittedButAudit` releases the guard without losing the possible effect. -/
theorem committedButAudit_failure_result {state : KernelState}
    {attemptId : AttemptId}
    (allowed : MayFailTerminalAudit state attemptId .committedButAudit) :
    attemptId ∉ (state.failTerminalAudit attemptId).activeAttempts ∧
      ∃ record receipt,
        (state.failTerminalAudit attemptId).audit.attempts attemptId = some record ∧
          record.outcome = .started ∧
          (state.failTerminalAudit attemptId).externalEffects attemptId = some receipt ∧
          receipt.attemptId = attemptId ∧
          (state.failTerminalAudit attemptId).HasAuthorizedSnapshot attemptId := by
  rcases allowed.evidence with ⟨receipt, effect, matching, authorized⟩
  exact ⟨failTerminalAudit_releases_attempt state attemptId,
    allowed.currentRecord, receipt, allowed.auditLookup, allowed.auditStillStarted,
    effect, matching, authorized⟩

/-- `CommitUnknownAndAudit` leaves Started durable state and no claimed effect. -/
theorem commitUnknownAndAudit_failure_result {state : KernelState}
    {attemptId : AttemptId}
    (allowed : MayFailTerminalAudit state attemptId .commitUnknownAndAudit) :
    attemptId ∉ (state.failTerminalAudit attemptId).activeAttempts ∧
      ∃ (record : AttemptRecord) (evidence : CommitUnknownEvidence),
        (state.failTerminalAudit attemptId).audit.attempts attemptId = some record ∧
          record.outcome = .started ∧
          evidence.attemptId = attemptId ∧
          evidence.token ≠ [] ∧
          evidence.token.length ≤ commitUnknownEvidenceMaximumBytes ∧
          (state.failTerminalAudit attemptId).HasAuthorizedSnapshot attemptId ∧
          (state.failTerminalAudit attemptId).externalEffects attemptId = none := by
  rcases allowed.evidence with ⟨evidence, matching, authorized, noEffect⟩
  exact ⟨failTerminalAudit_releases_attempt state attemptId,
    allowed.currentRecord, evidence, allowed.auditLookup, allowed.auditStillStarted,
    matching, evidence.tokenNonempty, evidence.tokenBounded, authorized, noEffect⟩

/-- A durable ambiguous terminal stores evidence without creating an effect snapshot. -/
theorem commitUnknown_result {state : KernelState} {attemptId : AttemptId}
    {evidence : CommitUnknownEvidence}
    (allowed : MayCommitUnknown state attemptId evidence) :
    attemptId ∉ (state.commitUnknownAttempt attemptId evidence
        allowed.auditAllowed.currentRecord).activeAttempts ∧
      (∃ record,
        (state.commitUnknownAttempt attemptId evidence
            allowed.auditAllowed.currentRecord).audit.attempts attemptId =
          some record ∧ record.outcome = .commitUnknown) ∧
      evidence.attemptId = attemptId ∧
      evidence.token ≠ [] ∧
      evidence.token.length ≤ commitUnknownEvidenceMaximumBytes ∧
      (state.commitUnknownAttempt attemptId evidence
          allowed.auditAllowed.currentRecord).audit.commitUnknownEvidence attemptId =
        some evidence ∧
      ¬ (state.commitUnknownAttempt attemptId evidence
          allowed.auditAllowed.currentRecord).audit.HasEffect attemptId ∧
      (state.commitUnknownAttempt attemptId evidence
          allowed.auditAllowed.currentRecord).externalEffects attemptId = none := by
  refine ⟨?_, ?_, allowed.auditAllowed.evidenceMatches, evidence.tokenNonempty,
    evidence.tokenBounded, ?_, ?_, allowed.noExternalEffect⟩
  · simp [commitUnknownAttempt, releaseAttempt]
  · exact ⟨state.audit.terminalRecord allowed.auditAllowed.currentRecord
        .commitUnknown none,
      (AuditState.finishCommitUnknown_stores_exact allowed.auditAllowed).1,
      by simp [AuditState.terminalRecord]⟩
  · exact (AuditState.finishCommitUnknown_stores_exact allowed.auditAllowed).2
  · exact AuditState.finish_commitUnknown_has_no_effect allowed.auditAllowed

/-- Two distinct read-side attempts can be active at the same time. -/
theorem two_attempts_can_overlap (authority : CapabilityState)
    (firstMetadata secondMetadata : AttemptMetadata) :
    ∃ afterFirst afterSecond,
      Step (initial authority) afterFirst ∧
        Step afterFirst afterSecond ∧
        (⟨0⟩ : AttemptId) ∈ afterSecond.activeAttempts ∧
        (⟨1⟩ : AttemptId) ∈ afterSecond.activeAttempts ∧
        (⟨0⟩ : AttemptId) ≠ ⟨1⟩ := by
  let firstAttempt : AttemptId := ⟨0⟩
  let secondAttempt : AttemptId := ⟨1⟩
  let afterFirst := (initial authority).beginAttempt firstAttempt firstMetadata
  let afterSecond := afterFirst.beginAttempt secondAttempt secondMetadata
  have firstAllowed : MayBegin (initial authority) firstAttempt := by
    refine ⟨?_, ?_, ?_, ?_, ?_⟩
    · simp [firstAttempt, initial]
    · exact
        { fresh := by simp [firstAttempt, initial, AuditState.empty]
          allocatedIdentity := by simp [firstAttempt, initial, AuditState.empty]
          sequenceAvailable := by simp [initial, AuditState.empty]
          sequenceRepresentable := by
            change FitsU64 0
            simp [FitsU64, u64Maximum]
          identityAvailable := by simp [initial, AuditState.empty]
          identityRepresentable := by
            change FitsU64 0
            simp [FitsU64, u64Maximum] }
    · rfl
    · rfl
    · rfl
  have secondAllowed : MayBegin afterFirst secondAttempt := by
    refine ⟨?_, ?_, ?_, ?_, ?_⟩
    · change secondAttempt ∉ firstAttempt :: []
      simp [secondAttempt, firstAttempt]
    · exact
        { fresh := by
            simp [afterFirst, secondAttempt, firstAttempt, initial,
              KernelState.beginAttempt, AuditState.beginAttempt, AuditState.empty,
              replace]
          allocatedIdentity := by
            simp [afterFirst, secondAttempt, firstAttempt, initial,
              KernelState.beginAttempt, AuditState.beginAttempt, AuditState.empty,
              advanceU64, u64Maximum]
          sequenceAvailable := by
            simp [afterFirst, firstAttempt, initial, KernelState.beginAttempt,
              AuditState.beginAttempt, AuditState.empty, advanceU64, u64Maximum]
          sequenceRepresentable := by
            change FitsU64 1
            simp [FitsU64, u64Maximum]
          identityAvailable := by
            simp [afterFirst, firstAttempt, initial, KernelState.beginAttempt,
              AuditState.beginAttempt, AuditState.empty, advanceU64, u64Maximum]
          identityRepresentable := by
            change FitsU64 1
            simp [FitsU64, u64Maximum] }
    · change replace (fun _ => none) firstAttempt (some firstMetadata)
          secondAttempt = none
      simp [replace, firstAttempt, secondAttempt]
    · rfl
    · rfl
  refine ⟨afterFirst, afterSecond, .begin firstAllowed, .begin secondAllowed, ?_⟩
  simp [afterSecond, afterFirst, secondAttempt, firstAttempt,
    KernelState.beginAttempt]

/-- Durable start mirrors persist across one accepted step. -/
theorem Step.durable_start_persists {before after : KernelState}
    (transition : Step before after) {attemptId : AttemptId}
    {metadata : AttemptMetadata}
    (started : before.durableStarts attemptId = some metadata) :
    after.durableStarts attemptId = some metadata := by
  cases transition with
  | begin allowed =>
      rename_i newAttempt newMetadata
      have differentAttempt : attemptId ≠ newAttempt := by
        intro sameAttempt
        subst attemptId
        have absent := allowed.noDurableStart
        rw [started] at absent
        cases absent
      simpa [KernelState.beginAttempt, replace, differentAttempt] using started
  | authorize | linearizeEffect | commit | reject | commitUnknown | terminalAuditFailure |
      authorityTransition => exact started

/-- Same-snapshot authorization evidence persists across one accepted step. -/
theorem Step.authorized_snapshot_persists {before after : KernelState}
    (transition : Step before after) {attemptId : AttemptId}
    (authorized : before.HasAuthorizedSnapshot attemptId) :
    after.HasAuthorizedSnapshot attemptId := by
  rcases authorized with ⟨metadata, authoritySnapshot, durableLookup,
    authorizationLookup, authorityLookup, allAuthorized⟩
  cases transition with
  | begin allowed =>
      rename_i newAttempt newMetadata
      exact ⟨metadata, authoritySnapshot,
        Step.durable_start_persists (.begin allowed) durableLookup,
        authorizationLookup, authorityLookup, allAuthorized⟩
  | authorize allowed =>
      rename_i newAttempt
      have differentAttempt : attemptId ≠ newAttempt := by
        intro sameAttempt
        subst attemptId
        have absent := allowed.noPriorAuthorization
        rw [authorizationLookup] at absent
        cases absent
      refine ⟨metadata, authoritySnapshot, durableLookup, ?_, ?_, allAuthorized⟩
      · simpa [KernelState.authorizeAttempt, replace, differentAttempt]
          using authorizationLookup
      · simpa [KernelState.authorizeAttempt, replace, differentAttempt]
          using authorityLookup
  | linearizeEffect | commit | reject | commitUnknown | terminalAuditFailure |
      authorityTransition =>
      exact ⟨metadata, authoritySnapshot, durableLookup, authorizationLookup,
        authorityLookup, allAuthorized⟩

/-- External effects, once linearized, cannot disappear or be replaced. -/
theorem Step.external_effect_persists {before after : KernelState}
    (transition : Step before after) {attemptId : AttemptId} {receipt : CommitReceipt}
    (effect : before.externalEffects attemptId = some receipt) :
    after.externalEffects attemptId = some receipt := by
  cases transition with
  | begin | authorize | commit | reject | commitUnknown | terminalAuditFailure |
      authorityTransition =>
      exact effect
  | linearizeEffect allowed =>
      rename_i newAttempt newReceipt
      have differentAttempt : attemptId ≠ newAttempt := by
        intro sameAttempt
        subst attemptId
        have absent := allowed.noPriorEffect
        rw [effect] at absent
        cases absent
      simpa [KernelState.linearizeEffect, replace, differentAttempt] using effect

/-- Audit metadata mirrors persist across one accepted step. -/
theorem Step.audit_metadata_persists {before after : KernelState}
    (transition : Step before after) {attemptId : AttemptId}
    {metadata : AttemptMetadata}
    (mirrored : before.audit.HasMetadata attemptId metadata) :
    after.audit.HasMetadata attemptId metadata := by
  cases transition with
  | begin allowed =>
      exact AuditState.begin_preserves_metadata allowed.auditAllowed mirrored
  | authorize | linearizeEffect | terminalAuditFailure => exact mirrored
  | commit allowed =>
      exact AuditState.finish_preserves_metadata allowed.auditAllowed mirrored
  | reject allowed =>
      exact AuditState.finish_preserves_metadata allowed.auditAllowed mirrored
  | commitUnknown allowed =>
      exact AuditState.finishCommitUnknown_preserves_metadata
        allowed.auditAllowed mirrored
  | authorityTransition => exact mirrored

/-- Recover an earlier committed effect across a new begin transition. -/
theorem committed_before_begin {state : KernelState} {newAttempt attemptId : AttemptId}
    {metadata : AttemptMetadata}
    (committed : (state.audit.beginAttempt newAttempt metadata).HasEffect attemptId) :
    state.audit.HasEffect attemptId := by
  have differentAttempt : attemptId ≠ newAttempt := by
    intro sameAttempt
    subst attemptId
    rcases committed with ⟨record, receipt, lookup, committedOutcome⟩
    have exactStarted := AuditState.beginAttempt_stores_exact_record
      state.audit newAttempt metadata
    have sameRecord := Option.some.inj (lookup.symm.trans exactStarted)
    subst record
    simp [AuditState.startedRecord] at committedOutcome
  rcases committed with ⟨record, receipt, lookup, outcome, storedReceipt, matching⟩
  exact ⟨record, receipt,
    by simpa [AuditState.beginAttempt, replace, differentAttempt] using lookup,
    outcome, storedReceipt, matching⟩

/-- Recover an earlier effect across a terminal finish for another attempt. -/
theorem committed_before_other_finish {state : KernelState}
    {finishedAttempt attemptId : AttemptId} {outcome : AttemptOutcome}
    {receipt : Option CommitReceipt}
    (allowed : state.audit.MayFinish finishedAttempt outcome receipt)
    (differentAttempt : attemptId ≠ finishedAttempt)
    (committed :
      (state.audit.finishAttempt finishedAttempt allowed.currentRecord outcome receipt).HasEffect
        attemptId) :
    state.audit.HasEffect attemptId := by
  rcases committed with ⟨record, committedReceipt, lookup, committedOutcome,
    storedReceipt, matching⟩
  exact ⟨record, committedReceipt,
    by simpa [AuditState.finishAttempt, replace, differentAttempt] using lookup,
    committedOutcome, storedReceipt, matching⟩

/-- Recover an earlier effect across an ambiguous finish for another attempt. -/
theorem committed_before_other_unknown_finish {state : KernelState}
    {finishedAttempt attemptId : AttemptId} {evidence : CommitUnknownEvidence}
    (allowed : state.audit.MayFinishCommitUnknown finishedAttempt evidence)
    (differentAttempt : attemptId ≠ finishedAttempt)
    (committed :
      (state.audit.finishCommitUnknownAttempt finishedAttempt
        allowed.currentRecord evidence).HasEffect attemptId) :
    state.audit.HasEffect attemptId := by
  rcases committed with ⟨record, receipt, lookup, committedOutcome,
    storedReceipt, matching⟩
  exact ⟨record, receipt,
    by simpa [AuditState.finishCommitUnknownAttempt, replace, differentAttempt]
      using lookup,
    committedOutcome, storedReceipt, matching⟩

/-- Every accepted protocol step preserves audit/effect coupling. -/
theorem Step.preserves_wellFormed {before after : KernelState}
    (transition : Step before after) (wellFormed : before.WellFormed) :
    after.WellFormed := by
  constructor
  · cases transition with
    | begin allowed =>
        apply wellFormed.activeAttemptsNodup.cons
        intro activeAttempt activeBefore sameAttempt
        subst activeAttempt
        exact allowed.notActive activeBefore
    | commit allowed =>
        simpa [commitAttempt, releaseAttempt] using
          wellFormed.activeAttemptsNodup.filter
            (fun activeAttempt => activeAttempt ≠ allowed.auditAllowed.attemptId)
    | reject allowed =>
        simpa [rejectAttempt, releaseAttempt] using
          wellFormed.activeAttemptsNodup.filter
            (fun activeAttempt => activeAttempt ≠ allowed.auditAllowed.attemptId)
    | commitUnknown allowed =>
        simpa [commitUnknownAttempt, releaseAttempt] using
          wellFormed.activeAttemptsNodup.filter
            (fun activeAttempt => activeAttempt ≠ allowed.auditAllowed.attemptId)
    | terminalAuditFailure allowed =>
        rename_i failedAttempt failure
        simpa [failTerminalAudit, releaseAttempt] using
          wellFormed.activeAttemptsNodup.filter
            (fun activeAttempt => activeAttempt ≠ failedAttempt)
    | authorize | linearizeEffect | authorityTransition =>
        exact wellFormed.activeAttemptsNodup
  · intro attemptId activeAfter
    cases transition with
    | begin allowed =>
        rename_i newAttempt newMetadata
        change attemptId ∈ newAttempt :: before.activeAttempts at activeAfter
        simp only [List.mem_cons] at activeAfter
        rcases activeAfter with sameAttempt | activeBefore
        · subst attemptId
          exact ⟨newMetadata, before.audit.startedRecord newAttempt newMetadata,
            by simp [KernelState.beginAttempt],
            AuditState.beginAttempt_stores_exact_record
              before.audit newAttempt newMetadata,
            rfl, rfl⟩
        · rcases wellFormed.activeAttemptStarted attemptId activeBefore with
            ⟨metadata, record, durableLookup, auditLookup, metadataMatches,
              stillStarted⟩
          have differentAttempt : attemptId ≠ newAttempt := by
            intro sameAttempt
            subst attemptId
            exact allowed.notActive activeBefore
          exact ⟨metadata, record,
            by simpa [KernelState.beginAttempt, replace, differentAttempt]
              using durableLookup,
            AuditState.beginAttempt_preserves_existing
              allowed.auditAllowed auditLookup,
            metadataMatches, stillStarted⟩
    | authorize | linearizeEffect =>
        exact wellFormed.activeAttemptStarted attemptId activeAfter
    | commit allowed =>
        rename_i finishedAttempt receipt
        have activeAndDifferent :
            attemptId ∈ before.activeAttempts ∧ attemptId ≠ finishedAttempt := by
          simpa [commitAttempt, releaseAttempt] using activeAfter
        have activeBefore := activeAndDifferent.1
        have differentAttempt := activeAndDifferent.2
        rcases wellFormed.activeAttemptStarted attemptId activeBefore with
          ⟨metadata, record, durableLookup, auditLookup, metadataMatches,
            stillStarted⟩
        exact ⟨metadata, record, durableLookup,
          by simpa [commitAttempt, releaseAttempt] using
            (AuditState.finishAttempt_preserves_other before.audit finishedAttempt
              allowed.auditAllowed.currentRecord .committed (some receipt)
              differentAttempt).trans auditLookup,
          metadataMatches, stillStarted⟩
    | reject allowed =>
        rename_i finishedAttempt outcome
        have activeAndDifferent :
            attemptId ∈ before.activeAttempts ∧ attemptId ≠ finishedAttempt := by
          simpa [rejectAttempt, releaseAttempt] using activeAfter
        have activeBefore := activeAndDifferent.1
        have differentAttempt := activeAndDifferent.2
        rcases wellFormed.activeAttemptStarted attemptId activeBefore with
          ⟨metadata, record, durableLookup, auditLookup, metadataMatches,
            stillStarted⟩
        exact ⟨metadata, record, durableLookup,
          by simpa [rejectAttempt, releaseAttempt] using
            (AuditState.finishAttempt_preserves_other before.audit finishedAttempt
              allowed.auditAllowed.currentRecord outcome none
              differentAttempt).trans auditLookup,
          metadataMatches, stillStarted⟩
    | commitUnknown allowed =>
        rename_i finishedAttempt evidence
        have activeAndDifferent :
            attemptId ∈ before.activeAttempts ∧ attemptId ≠ finishedAttempt := by
          simpa [commitUnknownAttempt, releaseAttempt] using activeAfter
        have activeBefore := activeAndDifferent.1
        have differentAttempt := activeAndDifferent.2
        rcases wellFormed.activeAttemptStarted attemptId activeBefore with
          ⟨metadata, record, durableLookup, auditLookup, metadataMatches,
            stillStarted⟩
        exact ⟨metadata, record, durableLookup,
          by simpa [commitUnknownAttempt, releaseAttempt] using
            (AuditState.finishCommitUnknown_preserves_other before.audit finishedAttempt
              allowed.auditAllowed.currentRecord evidence differentAttempt).trans auditLookup,
          metadataMatches, stillStarted⟩
    | terminalAuditFailure allowed =>
        rename_i failedAttempt failure
        have activeAndDifferent :
            attemptId ∈ before.activeAttempts ∧ attemptId ≠ failedAttempt := by
          simpa [failTerminalAudit, releaseAttempt] using activeAfter
        exact wellFormed.activeAttemptStarted attemptId activeAndDifferent.1
    | authorityTransition unlocked _ =>
        simp [mutateAuthority, unlocked] at activeAfter
  · intro attemptId metadata durableLookup
    cases transition with
    | begin allowed =>
        rename_i newAttempt newMetadata
        by_cases sameAttempt : attemptId = newAttempt
        · subst attemptId
          have exactMetadata : metadata = newMetadata := Option.some.inj
            (durableLookup.symm.trans (begin_stores_exact_intent before newAttempt newMetadata).1)
          subst metadata
          exact (begin_stores_exact_intent before newAttempt newMetadata).2
        · have oldLookup : before.durableStarts attemptId = some metadata := by
            simpa [KernelState.beginAttempt, replace, sameAttempt] using durableLookup
          exact Step.audit_metadata_persists (.begin allowed)
            (wellFormed.durableStartMirrored attemptId metadata oldLookup)
    | authorize allowed =>
        exact Step.audit_metadata_persists (.authorize allowed)
          (wellFormed.durableStartMirrored attemptId metadata durableLookup)
    | linearizeEffect allowed =>
        exact Step.audit_metadata_persists (.linearizeEffect allowed)
          (wellFormed.durableStartMirrored attemptId metadata durableLookup)
    | commit allowed =>
        exact Step.audit_metadata_persists (.commit allowed)
          (wellFormed.durableStartMirrored attemptId metadata durableLookup)
    | reject allowed =>
        exact Step.audit_metadata_persists (.reject allowed)
          (wellFormed.durableStartMirrored attemptId metadata durableLookup)
    | commitUnknown allowed =>
        exact Step.audit_metadata_persists (.commitUnknown allowed)
          (wellFormed.durableStartMirrored attemptId metadata durableLookup)
    | terminalAuditFailure allowed =>
        exact Step.audit_metadata_persists (.terminalAuditFailure allowed)
          (wellFormed.durableStartMirrored attemptId metadata durableLookup)
    | authorityTransition unlocked authorityStep =>
        exact Step.audit_metadata_persists (.authorityTransition unlocked authorityStep)
          (wellFormed.durableStartMirrored attemptId metadata durableLookup)
  · intro attemptId committed
    cases transition with
    | begin allowed =>
      exact wellFormed.committedHasEffect attemptId
          (committed_before_begin committed)
    | authorize => exact wellFormed.committedHasEffect attemptId committed
    | linearizeEffect =>
        rcases wellFormed.committedHasEffect attemptId committed with
          ⟨receipt, effect, matching⟩
        rename_i allowed
        exact ⟨receipt, Step.external_effect_persists (.linearizeEffect allowed) effect,
          matching⟩
    | commit allowed =>
        rename_i committedAttempt receipt
        by_cases sameAttempt : attemptId = committedAttempt
        · subst attemptId
          exact ⟨receipt, allowed.effectLookup,
            allowed.auditAllowed.receiptValid⟩
        · exact wellFormed.committedHasEffect attemptId
            (committed_before_other_finish allowed.auditAllowed sameAttempt committed)
    | reject allowed =>
        rename_i rejectedAttempt outcome
        by_cases sameAttempt : attemptId = rejectedAttempt
        · subst attemptId
          rcases committed with ⟨record, receipt, lookup, committedOutcome⟩
          have exactTerminal := AuditState.finishAttempt_stores_exact_record
            allowed.auditAllowed
          have sameRecord := Option.some.inj (lookup.symm.trans exactTerminal)
          subst record
          rcases allowed.nonCommitted with denied | failed
          · subst outcome
            simp [AuditState.terminalRecord] at committedOutcome
          · subst outcome
            simp [AuditState.terminalRecord] at committedOutcome
        · exact wellFormed.committedHasEffect attemptId
            (committed_before_other_finish allowed.auditAllowed sameAttempt committed)
    | commitUnknown allowed =>
        rename_i unknownAttempt evidence
        by_cases sameAttempt : attemptId = unknownAttempt
        · subst attemptId
          rcases committed with ⟨record, receipt, lookup, committedOutcome⟩
          have exactTerminal := AuditState.finishCommitUnknown_stores_exact
            allowed.auditAllowed
          have sameRecord := Option.some.inj (lookup.symm.trans exactTerminal.1)
          subst record
          simp [AuditState.terminalRecord] at committedOutcome
        · exact wellFormed.committedHasEffect attemptId
            (committed_before_other_unknown_finish allowed.auditAllowed sameAttempt committed)
    | terminalAuditFailure | authorityTransition =>
        exact wellFormed.committedHasEffect attemptId committed
  · intro attemptId receipt effect
    cases transition with
    | begin allowed =>
        rcases wellFormed.effectWasAuthorized attemptId receipt effect with
          ⟨matching, authorized⟩
        exact ⟨matching,
          Step.authorized_snapshot_persists (.begin allowed) authorized⟩
    | authorize allowed =>
        rcases wellFormed.effectWasAuthorized attemptId receipt effect with
          ⟨matching, authorized⟩
        exact ⟨matching,
          Step.authorized_snapshot_persists (.authorize allowed) authorized⟩
    | commit allowed =>
        rcases wellFormed.effectWasAuthorized attemptId receipt effect with
          ⟨matching, authorized⟩
        exact ⟨matching,
          Step.authorized_snapshot_persists (.commit allowed) authorized⟩
    | reject allowed =>
        rcases wellFormed.effectWasAuthorized attemptId receipt effect with
          ⟨matching, authorized⟩
        exact ⟨matching,
          Step.authorized_snapshot_persists (.reject allowed) authorized⟩
    | commitUnknown allowed =>
        rcases wellFormed.effectWasAuthorized attemptId receipt effect with
          ⟨matching, authorized⟩
        exact ⟨matching,
          Step.authorized_snapshot_persists (.commitUnknown allowed) authorized⟩
    | terminalAuditFailure allowed =>
        rcases wellFormed.effectWasAuthorized attemptId receipt effect with
          ⟨matching, authorized⟩
        exact ⟨matching,
          Step.authorized_snapshot_persists (.terminalAuditFailure allowed) authorized⟩
    | linearizeEffect allowed =>
        rename_i newAttempt newReceipt
        by_cases sameAttempt : attemptId = newAttempt
        · subst attemptId
          have sameReceipt : receipt = newReceipt := Option.some.inj
            (effect.symm.trans
              (linearizeEffect_stores_exact_receipt before newAttempt newReceipt))
          subst receipt
          exact ⟨allowed.receiptMatches, allowed.authorized⟩
        · have oldEffect : before.externalEffects attemptId = some receipt := by
            simpa [KernelState.linearizeEffect, replace, sameAttempt] using effect
          rcases wellFormed.effectWasAuthorized attemptId receipt oldEffect with
            ⟨matching, authorized⟩
          exact ⟨matching,
            Step.authorized_snapshot_persists (.linearizeEffect allowed) authorized⟩
    | authorityTransition unlocked authorityStep =>
        rcases wellFormed.effectWasAuthorized attemptId receipt effect with
          ⟨matching, authorized⟩
        exact ⟨matching,
          Step.authorized_snapshot_persists (.authorityTransition unlocked authorityStep)
            authorized⟩

/-- Releasing a failed terminal audit append preserves the composed invariant. -/
theorem failTerminalAudit_preserves_wellFormed {state : KernelState}
    {attemptId : AttemptId} {failure : TerminalAuditFailure}
    (allowed : MayFailTerminalAudit state attemptId failure)
    (wellFormed : state.WellFormed) :
    (state.failTerminalAudit attemptId).WellFormed :=
  Step.preserves_wellFormed (.terminalAuditFailure allowed) wellFormed

/-- Finite executions of the guarded protocol. -/
inductive Steps : KernelState → KernelState → Prop
  | refl (state : KernelState) : Steps state state
  | tail {first middle last : KernelState} :
      Steps first middle → Step middle last → Steps first last

/-- Audit/effect coupling is inductive across every finite protocol execution. -/
theorem Steps.preserve_wellFormed {before after : KernelState}
    (transitions : Steps before after) (wellFormed : before.WellFormed) :
    after.WellFormed := by
  induction transitions with
  | refl => exact wellFormed
  | tail _ transition inductionHypothesis =>
      exact transition.preserves_wellFormed inductionHypothesis

/-- The concrete `CommitUnknown` trace is well formed and exposes no committed effect. -/
theorem commitUnknown_trace_preserves_wellFormed {state : KernelState}
    {attemptId : AttemptId} {evidence : CommitUnknownEvidence}
    (wellFormed : state.WellFormed)
    (allowed : MayCommitUnknown state attemptId evidence) :
    ∃ after,
      Steps state after ∧ after.WellFormed ∧
        (∃ record, after.audit.attempts attemptId = some record ∧
          record.outcome = .commitUnknown) ∧
        evidence.attemptId = attemptId ∧
        evidence.token ≠ [] ∧
        evidence.token.length ≤ commitUnknownEvidenceMaximumBytes ∧
        after.audit.commitUnknownEvidence attemptId = some evidence ∧
        ¬ after.audit.HasEffect attemptId ∧
        after.externalEffects attemptId = none := by
  let after := state.commitUnknownAttempt attemptId evidence
    allowed.auditAllowed.currentRecord
  have transition : Step state after := .commitUnknown allowed
  have trace : Steps state after := .tail (.refl state) transition
  rcases commitUnknown_result allowed with
    ⟨_, terminal, matching, nonempty, bounded, stored, noEffectSnapshot, noEffect⟩
  exact ⟨after, trace, trace.preserve_wellFormed wellFormed,
    terminal, matching, nonempty, bounded, stored, noEffectSnapshot, noEffect⟩

/-- Durable start evidence persists across arbitrary finite protocol execution. -/
theorem Steps.durable_start_persists {before after : KernelState}
    (transitions : Steps before after) {attemptId : AttemptId}
    {metadata : AttemptMetadata}
    (started : before.durableStarts attemptId = some metadata) :
    after.durableStarts attemptId = some metadata := by
  induction transitions with
  | refl => exact started
  | tail _ transition inductionHypothesis =>
      exact transition.durable_start_persists inductionHypothesis

/-- Authorization snapshots persist across arbitrary finite protocol execution. -/
theorem Steps.authorized_snapshot_persists {before after : KernelState}
    (transitions : Steps before after) {attemptId : AttemptId}
    (authorized : before.HasAuthorizedSnapshot attemptId) :
    after.HasAuthorizedSnapshot attemptId := by
  induction transitions with
  | refl => exact authorized
  | tail _ transition inductionHypothesis =>
      exact transition.authorized_snapshot_persists inductionHypothesis

/-- Linearized effects persist across arbitrary finite protocol execution. -/
theorem Steps.external_effect_persists {before after : KernelState}
    (transitions : Steps before after) {attemptId : AttemptId}
    {receipt : CommitReceipt}
    (effect : before.externalEffects attemptId = some receipt) :
    after.externalEffects attemptId = some receipt := by
  induction transitions with
  | refl => exact effect
  | tail _ transition inductionHypothesis =>
      exact transition.external_effect_persists inductionHypothesis

/-- Every committed audit record denotes a real, matching external effect. -/
theorem committed_audit_implies_external_effect {state : KernelState}
    (wellFormed : state.WellFormed) {attemptId : AttemptId}
    (committed : state.audit.HasEffect attemptId) :
    ∃ receipt, state.externalEffects attemptId = some receipt ∧
      receipt.attemptId = attemptId :=
  wellFormed.committedHasEffect attemptId committed

/-- Every external effect has durable intent and same-snapshot authorization. -/
theorem external_effect_implies_started_and_authorized {state : KernelState}
    (wellFormed : state.WellFormed) {attemptId : AttemptId}
    {receipt : CommitReceipt}
    (effect : state.externalEffects attemptId = some receipt) :
    receipt.attemptId = attemptId ∧
      ∃ metadata authoritySnapshot,
        state.durableStarts attemptId = some metadata ∧
        state.audit.HasMetadata attemptId metadata ∧
        state.authorizationAuthorities attemptId = some authoritySnapshot ∧
        metadata.AllAuthorized authoritySnapshot := by
  rcases wellFormed.effectWasAuthorized attemptId receipt effect with
    ⟨matching, metadata, authoritySnapshot, durableLookup, _, authorityLookup,
      authorized⟩
  exact ⟨matching, metadata, authoritySnapshot, durableLookup,
    wellFormed.durableStartMirrored attemptId metadata durableLookup,
    authorityLookup, authorized⟩

/-- A denial or pre-commit failure is accepted only before any external effect. -/
theorem rejected_finish_has_no_external_effect {state : KernelState}
    {attemptId : AttemptId} {outcome : AttemptOutcome}
    (allowed : MayReject state attemptId outcome) :
    state.externalEffects attemptId = none :=
  allowed.noExternalEffect

end KernelState

end Authority
