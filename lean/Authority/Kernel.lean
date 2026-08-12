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

/-- Composed state at protocol linearization points. -/
structure KernelState where
  authority : CapabilityState
  audit : AuditState
  lockedAttempt : Option AttemptId
  durableStarts : AttemptId → Option AttemptMetadata
  authorizations : AttemptId → Option AttemptMetadata
  authorizationAuthorities : AttemptId → Option CapabilityState
  externalEffects : AttemptId → Option CommitReceipt

namespace KernelState

/-- Initial composed state contains no attempts or external effects. -/
def initial (authority : CapabilityState) : KernelState where
  authority := authority
  audit := .empty
  lockedAttempt := none
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
  · intro attemptId metadata lookup
    simp [initial] at lookup
  · intro attemptId effect
    rcases effect with ⟨record, receipt, lookup, _⟩
    simp [initial, AuditState.empty] at lookup
  · intro attemptId receipt effect
    simp [initial] at effect

/-- Preconditions for writing durable intent for a fresh attempt. -/
structure MayBegin (state : KernelState) (attemptId : AttemptId) where
  lockAvailable : state.lockedAttempt = none
  auditAllowed : state.audit.MayBegin attemptId
  noDurableStart : state.durableStarts attemptId = none
  noAuthorization : state.authorizations attemptId = none
  noExternalEffect : state.externalEffects attemptId = none

/-- Append durable intent before final authorization or execution. -/
def beginAttempt (state : KernelState) (attemptId : AttemptId)
    (metadata : AttemptMetadata) : KernelState :=
  { state with
    audit := state.audit.beginAttempt attemptId metadata
    lockedAttempt := some attemptId
    durableStarts := replace state.durableStarts attemptId (some metadata) }

/-- Preconditions for the final authorization check under the shared guard. -/
structure MayAuthorize (state : KernelState) (attemptId : AttemptId) where
  lockHeld : state.lockedAttempt = some attemptId
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
  lockHeld : state.lockedAttempt = some attemptId
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
  lockHeld : state.lockedAttempt = some attemptId
  effectLookup : state.externalEffects attemptId = some receipt
  authorized : state.HasAuthorizedSnapshot attemptId

/-- A denial or pre-commit failure must have no external effect. -/
structure MayReject (state : KernelState) (attemptId : AttemptId)
    (outcome : AttemptOutcome) where
  nonCommitted : outcome = .denied ∨ outcome = .failedBeforeCommit
  lockHeld : state.lockedAttempt = some attemptId
  auditAllowed : state.audit.MayFinish attemptId outcome none
  noExternalEffect : state.externalEffects attemptId = none

/-- Append a matching committed terminal audit record. -/
def commitAttempt (state : KernelState) (attemptId : AttemptId)
    (receipt : CommitReceipt) (current : AttemptRecord) : KernelState :=
  let finishedAudit := state.audit.finishAttempt attemptId current
    .committed (some receipt)
  { state with audit := finishedAudit, lockedAttempt := none }

/-- Append a terminal denial or pre-commit failure. -/
def rejectAttempt (state : KernelState) (attemptId : AttemptId)
    (outcome : AttemptOutcome) (current : AttemptRecord) : KernelState :=
  let finishedAudit := state.audit.finishAttempt attemptId current outcome none
  { state with audit := finishedAudit, lockedAttempt := none }

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
  | authorityTransition {state : KernelState} {authority : CapabilityState} :
      state.lockedAttempt = none →
      CapabilityState.Step state.authority authority →
      Step state (state.mutateAuthority authority)

/-- Authority mutations are accepted only outside a guarded effect protocol. -/
theorem Step.authority_change_requires_unlocked {before after : KernelState}
    (transition : Step before after) (changed : after.authority ≠ before.authority) :
    before.lockedAttempt = none ∧ after.lockedAttempt = none := by
  cases transition with
  | authorityTransition unlocked _ => exact ⟨unlocked, unlocked⟩
  | begin | authorize | linearizeEffect | commit | reject =>
      exact False.elim (changed rfl)

/-- While an attempt owns the guard, one step cannot mutate authority. -/
theorem Step.locked_authority_stable {before after : KernelState}
    (transition : Step before after) {attemptId : AttemptId}
    (locked : before.lockedAttempt = some attemptId) :
    after.authority = before.authority := by
  cases transition with
  | authorityTransition unlocked _ => rw [locked] at unlocked; contradiction
  | begin | authorize | linearizeEffect | commit | reject => rfl

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
  | authorize | linearizeEffect | commit | reject | authorityTransition => exact started

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
  | linearizeEffect | commit | reject | authorityTransition =>
      exact ⟨metadata, authoritySnapshot, durableLookup, authorizationLookup,
        authorityLookup, allAuthorized⟩

/-- External effects, once linearized, cannot disappear or be replaced. -/
theorem Step.external_effect_persists {before after : KernelState}
    (transition : Step before after) {attemptId : AttemptId} {receipt : CommitReceipt}
    (effect : before.externalEffects attemptId = some receipt) :
    after.externalEffects attemptId = some receipt := by
  cases transition with
  | begin | authorize | commit | reject | authorityTransition => exact effect
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
  | authorize | linearizeEffect => exact mirrored
  | commit allowed =>
      exact AuditState.finish_preserves_metadata allowed.auditAllowed mirrored
  | reject allowed =>
      exact AuditState.finish_preserves_metadata allowed.auditAllowed mirrored
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

/-- Every accepted protocol step preserves audit/effect coupling. -/
theorem Step.preserves_wellFormed {before after : KernelState}
    (transition : Step before after) (wellFormed : before.WellFormed) :
    after.WellFormed := by
  constructor
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
    | authorityTransition => exact wellFormed.committedHasEffect attemptId committed
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
