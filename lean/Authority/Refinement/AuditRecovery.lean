import Authority.Kernel

/-!
# Durable Audit Recovery Refinement

An abstract refinement model for the sealed durable-audit boundary. It models
one writer authority, freely copied immutable recovery views, and reconciliation
that may commit a recovered `started` record only after provider acceptance has
been verified for the same attempt.

This module proves properties of the logical boundary below. It does not claim
that Rust file handles, visibility modifiers, `fsync`, or provider adapters
refine this model; those connections remain implementation obligations.
-/

namespace Authority
namespace AuditRecovery

/-- Stable identity of the one component authorized to mutate a journal. -/
structure WriterId where
  value : Nat
  deriving Repr, DecidableEq

/-- An authority presented by a prospective journal writer. -/
structure WriterAuthority where
  writerId : WriterId
  deriving Repr, DecidableEq

/-- Recovery state at the sealed durable-audit boundary. -/
structure State where
  writerId : WriterId
  kernel : KernelState
  /-- Provider acceptances already verified by the backend adapter. -/
  backendAcceptances : AttemptId → Option CommitReceipt

/-- A detached immutable snapshot with no writer authority. -/
structure ReadOnlyView where
  audit : AuditState

namespace State

/-- Capture the current audit value without transferring writer authority. -/
def readOnlyView (state : State) : ReadOnlyView :=
  { audit := state.kernel.audit }

/-- Exactly the configured writer identity may request a mutation. -/
def MayWrite (state : State) (authority : WriterAuthority) : Prop :=
  authority.writerId = state.writerId

/-- Any two authorities accepted by one state denote the same writer. -/
theorem writer_authority_unique {state : State}
    {first second : WriterAuthority}
    (firstAllowed : state.MayWrite first)
    (secondAllowed : state.MayWrite second) : first = second := by
  cases first with
  | mk firstId =>
      cases second with
      | mk secondId =>
          simp only [MayWrite] at firstAllowed secondAllowed
          simp_all

end State

/-- Provider evidence verified for one exact attempt and receipt. -/
structure VerifiedProviderEvidence (state : State) (attemptId : AttemptId)
    (receipt : CommitReceipt) : Prop where
  receiptMatches : receipt.attemptId = attemptId
  backendAccepted : state.backendAcceptances attemptId = some receipt

/-- A recovered start whose in-process guard was lost at the crash boundary. -/
structure StartedCrashState (state : State) (attemptId : AttemptId) where
  currentRecord : AttemptRecord
  auditLookup : state.kernel.audit.attempts attemptId = some currentRecord
  stillStarted : currentRecord.outcome = .started
  inactive : attemptId ∉ state.kernel.activeAttempts

/-- Preconditions for the sole recovery mutation that records provider commit. -/
structure MayReconcileCommit (state : State) (authority : WriterAuthority)
    (attemptId : AttemptId) where
  writerAllowed : state.MayWrite authority
  crash : StartedCrashState state attemptId
  receipt : CommitReceipt
  verified : VerifiedProviderEvidence state attemptId receipt
  authorized : state.kernel.HasAuthorizedSnapshot attemptId
  sequenceAvailable : state.kernel.audit.sequenceExhausted = false
  sequenceRepresentable : FitsU64 state.kernel.audit.nextSequence

namespace MayReconcileCommit

/-- Verified recovery evidence satisfies the existing audit finish API. -/
def auditAllowed {state : State} {authority : WriterAuthority}
    {attemptId : AttemptId}
    (allowed : MayReconcileCommit state authority attemptId) :
    state.kernel.audit.MayFinish attemptId .committed (some allowed.receipt) where
  currentRecord := allowed.crash.currentRecord
  currentLookup := allowed.crash.auditLookup
  stillStarted := allowed.crash.stillStarted
  receiptValid := by
    simpa [AuditState.ValidReceipt] using allowed.verified.receiptMatches
  sequenceAvailable := allowed.sequenceAvailable
  sequenceRepresentable := allowed.sequenceRepresentable

end MayReconcileCommit

/-- Update only the audit terminal record and recovered external-effect mirror. -/
def reconcileKernelCommit (state : KernelState) (attemptId : AttemptId)
    (current : AttemptRecord) (receipt : CommitReceipt) : KernelState :=
  { state with
    audit := state.audit.finishAttempt attemptId current .committed (some receipt)
    externalEffects := replace state.externalEffects attemptId (some receipt) }

namespace State

/-- Record a provider-verified commit through the unique writer boundary. -/
def reconcileCommit (state : State) {authority : WriterAuthority}
    {attemptId : AttemptId}
    (allowed : MayReconcileCommit state authority attemptId) : State :=
  { state with
    kernel := reconcileKernelCommit state.kernel attemptId
      allowed.crash.currentRecord allowed.receipt }

/-- Cross-layer assumptions maintained by the abstract recovery boundary. -/
structure WellFormed (state : State) : Prop where
  kernelWellFormed : state.kernel.WellFormed
  auditCountersRepresentable : state.kernel.audit.CountersRepresentable
  backendAcceptanceMatches : ∀ attemptId receipt,
    state.backendAcceptances attemptId = some receipt →
      receipt.attemptId = attemptId

end State

/-- Access mode for recovery operations. Views intentionally have no write case. -/
inductive Access where
  | writer (authority : WriterAuthority)
  | readOnly (view : ReadOnlyView)

/-- The only durable-audit recovery transition is a writer-authorized reconcile. -/
inductive Step : Access → State → State → Prop where
  | reconcileCommit {state : State} {authority : WriterAuthority}
      {attemptId : AttemptId}
      (allowed : MayReconcileCommit state authority attemptId) :
      Step (.writer authority) state (state.reconcileCommit allowed)

/-- A detached read-only view cannot transition the writer state. -/
theorem readOnlyView_cannot_transition_writer (view : ReadOnlyView)
    (before after : State) : ¬ Step (.readOnly view) before after := by
  intro transition
  cases transition

/-- Two accepted recovery mutations from one state must use the same writer authority. -/
theorem Step.writer_is_unique {state firstAfter secondAfter : State}
    {firstWriter secondWriter : WriterAuthority}
    (first : Step (.writer firstWriter) state firstAfter)
    (second : Step (.writer secondWriter) state secondAfter) :
    firstWriter = secondWriter := by
  cases first with
  | reconcileCommit firstAllowed =>
      cases second with
      | reconcileCommit secondAllowed =>
          exact State.writer_authority_unique firstAllowed.writerAllowed
            secondAllowed.writerAllowed

/-- A receipt for another attempt cannot become verified reconciliation evidence. -/
theorem mismatched_evidence_rejected {state : State} {attemptId : AttemptId}
    {receipt : CommitReceipt} (mismatched : receipt.attemptId ≠ attemptId) :
    ¬ VerifiedProviderEvidence state attemptId receipt := by
  intro evidence
  exact mismatched evidence.receiptMatches

/-- A backend rejection cannot be promoted to verified reconciliation evidence. -/
theorem unaccepted_evidence_rejected {state : State} {attemptId : AttemptId}
    {receipt : CommitReceipt}
    (notAccepted : state.backendAcceptances attemptId ≠ some receipt) :
    ¬ VerifiedProviderEvidence state attemptId receipt := by
  intro evidence
  exact notAccepted evidence.backendAccepted

/-- With no accepted provider result, no arbitrary receipt can enable reconciliation. -/
theorem missing_backend_acceptance_rejects_reconciliation {state : State}
    {authority : WriterAuthority} {attemptId : AttemptId}
    (notAccepted : state.backendAcceptances attemptId = none) :
    MayReconcileCommit state authority attemptId → False := by
  intro allowed
  have accepted := allowed.verified.backendAccepted
  rw [notAccepted] at accepted
  contradiction

/-- A backend result bound to another attempt cannot enable reconciliation. -/
theorem mismatched_backend_acceptance_rejects_reconciliation {state : State}
    {authority : WriterAuthority} {attemptId : AttemptId}
    {receipt : CommitReceipt}
    (accepted : state.backendAcceptances attemptId = some receipt)
    (mismatched : receipt.attemptId ≠ attemptId) :
    MayReconcileCommit state authority attemptId → False := by
  intro allowed
  have exactReceipt : receipt = allowed.receipt := Option.some.inj
    (accepted.symm.trans allowed.verified.backendAccepted)
  subst receipt
  exact mismatched allowed.verified.receiptMatches

/-- An arbitrary unknown attempt cannot pass the recovered-start precondition. -/
theorem unknown_attempt_reconciliation_rejected {state : State}
    {authority : WriterAuthority} {attemptId : AttemptId}
    (unknown : state.kernel.audit.attempts attemptId = none) :
    MayReconcileCommit state authority attemptId → False := by
  intro allowed
  have lookup := allowed.crash.auditLookup
  rw [unknown] at lookup
  contradiction

/-- Reconciliation appends the existing API's matching committed audit effect. -/
theorem reconcileCommit_creates_audit_effect {state : State}
    {authority : WriterAuthority} {attemptId : AttemptId}
    (allowed : MayReconcileCommit state authority attemptId) :
    (state.reconcileCommit allowed).kernel.audit.HasEffect attemptId := by
  simpa [State.reconcileCommit, reconcileKernelCommit] using
    AuditState.finish_committed_creates_effect allowed.auditAllowed

/-- A reconciled committed record has matching backend and external acceptance. -/
theorem reconciled_commit_implies_external_acceptance {state : State}
    {authority : WriterAuthority} {attemptId : AttemptId}
    (allowed : MayReconcileCommit state authority attemptId) :
    (state.reconcileCommit allowed).kernel.audit.HasEffect attemptId ∧
      (state.reconcileCommit allowed).backendAcceptances attemptId =
        some allowed.receipt ∧
      (state.reconcileCommit allowed).kernel.externalEffects attemptId =
        some allowed.receipt ∧
      allowed.receipt.attemptId = attemptId := by
  exact ⟨reconcileCommit_creates_audit_effect allowed,
    allowed.verified.backendAccepted,
    by simp [State.reconcileCommit, reconcileKernelCommit],
    allowed.verified.receiptMatches⟩

/-- Provider-verified reconciliation preserves the existing kernel invariant. -/
theorem reconcileCommit_preserves_kernelWellFormed {state : State}
    {authority : WriterAuthority} {attemptId : AttemptId}
    (allowed : MayReconcileCommit state authority attemptId)
    (wellFormed : state.kernel.WellFormed) :
    (state.reconcileCommit allowed).kernel.WellFormed := by
  let auditAllowed := allowed.auditAllowed
  constructor
  · simpa [State.reconcileCommit, reconcileKernelCommit] using
      wellFormed.activeAttemptsNodup
  · intro queriedId activeAfter
    have activeBefore : queriedId ∈ state.kernel.activeAttempts := by
      simpa [State.reconcileCommit, reconcileKernelCommit] using activeAfter
    rcases wellFormed.activeAttemptStarted queriedId activeBefore with
      ⟨metadata, record, durableLookup, auditLookup, metadataMatches, stillStarted⟩
    have differentAttempt : queriedId ≠ attemptId := by
      intro sameAttempt
      subst queriedId
      exact allowed.crash.inactive activeBefore
    exact ⟨metadata, record, durableLookup,
      by simpa [State.reconcileCommit, reconcileKernelCommit, auditAllowed] using
        (AuditState.finishAttempt_preserves_other state.kernel.audit attemptId
          allowed.crash.currentRecord .committed (some allowed.receipt)
          differentAttempt).trans auditLookup,
      metadataMatches, stillStarted⟩
  · intro queriedId metadata durableAfter
    have durableBefore : state.kernel.durableStarts queriedId = some metadata := by
      simpa [State.reconcileCommit, reconcileKernelCommit] using durableAfter
    have mirrored := wellFormed.durableStartMirrored queriedId metadata durableBefore
    simpa [State.reconcileCommit, reconcileKernelCommit, auditAllowed] using
      AuditState.finish_preserves_metadata auditAllowed mirrored
  · intro queriedId committedAfter
    by_cases sameAttempt : queriedId = attemptId
    · subst queriedId
      exact ⟨allowed.receipt,
        by simp [State.reconcileCommit, reconcileKernelCommit],
        allowed.verified.receiptMatches⟩
    · have committedBefore : state.kernel.audit.HasEffect queriedId := by
        apply KernelState.committed_before_other_finish auditAllowed sameAttempt
        simpa [State.reconcileCommit, reconcileKernelCommit, auditAllowed] using committedAfter
      rcases wellFormed.committedHasEffect queriedId committedBefore with
        ⟨receipt, effectLookup, receiptMatches⟩
      exact ⟨receipt,
        by simpa [State.reconcileCommit, reconcileKernelCommit, replace, sameAttempt]
          using effectLookup,
        receiptMatches⟩
  · intro queriedId receipt effectAfter
    by_cases sameAttempt : queriedId = attemptId
    · subst queriedId
      have exactReceipt : receipt = allowed.receipt := Option.some.inj
        (effectAfter.symm.trans (by
          simp [State.reconcileCommit, reconcileKernelCommit]))
      subst receipt
      exact ⟨allowed.verified.receiptMatches,
        by simpa [State.reconcileCommit, reconcileKernelCommit] using allowed.authorized⟩
    · have effectBefore : state.kernel.externalEffects queriedId = some receipt := by
        simpa [State.reconcileCommit, reconcileKernelCommit, replace, sameAttempt]
          using effectAfter
      rcases wellFormed.effectWasAuthorized queriedId receipt effectBefore with
        ⟨receiptMatches, authorized⟩
      exact ⟨receiptMatches,
        by simpa [State.reconcileCommit, reconcileKernelCommit] using authorized⟩

/-- Reconciliation is an ordinary validated audit finish for counter safety. -/
theorem reconcileCommit_preserves_auditCounters {state : State}
    {authority : WriterAuthority} {attemptId : AttemptId}
    (allowed : MayReconcileCommit state authority attemptId)
    (representable : state.kernel.audit.CountersRepresentable) :
    (state.reconcileCommit allowed).kernel.audit.CountersRepresentable := by
  simpa [State.reconcileCommit, reconcileKernelCommit] using
    (AuditState.Step.preserves_countersRepresentable
      (.finish allowed.auditAllowed) representable)

/-- The complete sealed-boundary invariant survives a reconcile transition. -/
theorem reconcileCommit_preserves_wellFormed {state : State}
    {authority : WriterAuthority} {attemptId : AttemptId}
    (allowed : MayReconcileCommit state authority attemptId)
    (wellFormed : state.WellFormed) :
    (state.reconcileCommit allowed).WellFormed := by
  refine {
    kernelWellFormed := reconcileCommit_preserves_kernelWellFormed allowed
      wellFormed.kernelWellFormed
    auditCountersRepresentable := reconcileCommit_preserves_auditCounters allowed
      wellFormed.auditCountersRepresentable
    backendAcceptanceMatches := ?_
  }
  intro queriedId receipt accepted
  exact wellFormed.backendAcceptanceMatches queriedId receipt accepted

/-- Every recovery step preserves the complete sealed-boundary invariant. -/
theorem Step.preserves_wellFormed {access : Access} {before after : State}
    (transition : Step access before after)
    (wellFormed : before.WellFormed) : after.WellFormed := by
  cases transition with
  | reconcileCommit allowed =>
      exact reconcileCommit_preserves_wellFormed allowed wellFormed

/-- Concrete maps witness a real provider-verified `started` reconciliation. -/
theorem reconcileCommit_is_nonvacuous (authoritySnapshot : CapabilityState)
    (metadata : AttemptMetadata)
    (allAuthorized : metadata.AllAuthorized authoritySnapshot) :
    ∃ writer before after view attemptId receipt,
      view = before.readOnlyView ∧
      Nonempty (StartedCrashState before attemptId) ∧
      VerifiedProviderEvidence before attemptId receipt ∧
      before.WellFormed ∧
      after.WellFormed ∧
      Step (.writer writer) before after ∧
      after.kernel.audit.HasEffect attemptId ∧
      after.backendAcceptances attemptId = some receipt := by
  let writerId : WriterId := ⟨7⟩
  let writer : WriterAuthority := ⟨writerId⟩
  let attemptId : AttemptId := ⟨0⟩
  let receipt : CommitReceipt :=
    { attemptId := attemptId
      token := [7] }
  let record : AttemptRecord :=
    { id := attemptId
      startSequence := 0
      metadata := metadata
      outcome := .started
      finishSequence := none
      receipt := none }
  let audit : AuditState :=
    { nextSequence := 1
      sequenceExhausted := false
      nextAttemptId := 1
      attemptIdExhausted := false
      attempts := replace (fun _ => none) attemptId (some record) }
  let kernel : KernelState :=
    { authority := authoritySnapshot
      audit := audit
      activeAttempts := []
      durableStarts := replace (fun _ => none) attemptId (some metadata)
      authorizations := replace (fun _ => none) attemptId (some metadata)
      authorizationAuthorities := replace (fun _ => none) attemptId
        (some authoritySnapshot)
      externalEffects := fun _ => none }
  let before : State :=
    { writerId := writerId
      kernel := kernel
      backendAcceptances := replace (fun _ => none) attemptId (some receipt) }
  let crash : StartedCrashState before attemptId := {
    currentRecord := record
    auditLookup := by simp [before, kernel, audit]
    stillStarted := rfl
    inactive := by simp [before, kernel]
  }
  let verified : VerifiedProviderEvidence before attemptId receipt := {
    receiptMatches := rfl
    backendAccepted := by simp [before]
  }
  let allowed : MayReconcileCommit before writer attemptId := {
    writerAllowed := rfl
    crash := crash
    receipt := receipt
    verified := verified
    authorized := by
      exact ⟨metadata, authoritySnapshot,
        by simp [before, kernel], by simp [before, kernel],
        by simp [before, kernel], allAuthorized⟩
    sequenceAvailable := rfl
    sequenceRepresentable := by
      simp [before, kernel, audit, FitsU64, u64Maximum]
  }
  let beforeWellFormed : before.WellFormed := {
    kernelWellFormed := by
      constructor <;>
        simp [before, kernel, audit, record, AuditState.HasMetadata,
          AuditState.HasEffect, replace]
    auditCountersRepresentable := by
      simp [before, kernel, audit, AuditState.CountersRepresentable,
        FitsU64, u64Maximum]
    backendAcceptanceMatches := by
      intro queriedId queriedReceipt accepted
      simp [before, replace] at accepted
      rcases accepted with ⟨rfl, rfl⟩
      rfl
  }
  let after := before.reconcileCommit allowed
  exact ⟨writer, before, after, before.readOnlyView, attemptId, receipt,
    rfl, ⟨crash⟩, verified, beforeWellFormed,
    reconcileCommit_preserves_wellFormed allowed beforeWellFormed,
    .reconcileCommit allowed,
    reconcileCommit_creates_audit_effect allowed, verified.backendAccepted⟩

private def witnessCaller : SubjectId := ⟨"recovery-subject"⟩

private def witnessCapabilityId : CapId := ⟨"recovery-capability"⟩

private def witnessIssuer : IssuerId := ⟨"recovery-issuer"⟩

private def witnessTime : MonotonicTime := ⟨0⟩

private def witnessWindow : TimeWindow :=
  { notBefore := witnessTime
    expiresAt := ⟨1⟩
    isValid := by decide }

private def witnessRepository : RepoId := ⟨"recovery-repository"⟩

private def witnessFileAuthority : FileAuthority :=
  { repository := witnessRepository
    effects := FileEffects.only .readData
    path := .exact CanonicalPath.root }

private def witnessRequest : CapabilityRequest :=
  { time := witnessTime
    authority := .file {
      repository := witnessRepository
      effect := .readData
      path := CanonicalPath.root } }

private def witnessSubject : Subject :=
  { id := witnessCaller
    parent := none
    envelope := {
      validity := witnessWindow
      authority := .file witnessFileAuthority } }

private def witnessCapability : Capability :=
  { metadata := {
      id := witnessCapabilityId
      subject := witnessCaller
      issuer := witnessIssuer
      parent := none
      delegable := false }
    validity := witnessWindow
    authority := .file witnessFileAuthority }

private def witnessAuthorityState : CapabilityState :=
  { issuer := witnessIssuer
    nextCapabilitySequence := 0
    capabilityIdsExhausted := false
    subjects := fun _ => some witnessSubject
    subjectStatuses := fun _ => some .running
    capabilities := fun _ => some witnessCapability
    held := fun _ _ => true
    revoked := fun _ => false
    authorizationEpoch := 0
    openHandles := fun _ => none
    issuedHandleOwners := fun _ => none }

private def witnessMetadata : AttemptMetadata :=
  { caller := witnessCaller
    capabilityId := witnessCapabilityId
    requests := {
      first := witnessRequest
      additional := [] }
    authorizationEpoch := 0 }

private theorem witness_authorized :
    witnessAuthorityState.Authorizes witnessCaller witnessCapabilityId witnessRequest := by
  refine ⟨by rfl, by rfl, witnessCapability, by rfl, rfl, ?_, ?_⟩
  · refine ⟨witnessCapability, rfl, ?_⟩
    intro ancestor chain
    cases chain with
    | self storedCapability lookup =>
        have normalizedLookup : some witnessCapability = some storedCapability := by
          simpa [witnessAuthorityState] using lookup
        have exactCapability : storedCapability = witnessCapability :=
          (Option.some.inj normalizedLookup).symm
        subst storedCapability
        exact ⟨rfl, witnessCapability, rfl,
          by simp [witnessCapability, witnessWindow, witnessTime, witnessRequest,
            TimeWindow.Contains]⟩
    | next edge _ =>
        rcases edge with
          ⟨childCapability, _, childLookup, _, parentPointer⟩
        have normalizedLookup : some witnessCapability = some childCapability := by
          simpa [witnessAuthorityState] using childLookup
        have exactChild : childCapability = witnessCapability :=
          (Option.some.inj normalizedLookup).symm
        subst childCapability
        simp [witnessCapability] at parentPointer
  · constructor
    · simp [witnessCapability, witnessWindow, witnessRequest, witnessTime,
        TimeWindow.Contains]
    · exact ⟨rfl, by decide, rfl⟩

private theorem witness_allAuthorized :
    witnessMetadata.AllAuthorized witnessAuthorityState := by
  refine ⟨rfl, ?_⟩
  intro request member
  have exactRequest : request = witnessRequest := by
    simpa [witnessMetadata, CapabilityRequestSet.toList] using member
  subst request
  exact witness_authorized

/-- The model has an unconditional, fully concrete reconcile transition. -/
theorem reconcileCommit_has_concrete_witness :
    ∃ writer before after view attemptId receipt,
      view = before.readOnlyView ∧
      Nonempty (StartedCrashState before attemptId) ∧
      VerifiedProviderEvidence before attemptId receipt ∧
      before.WellFormed ∧
      after.WellFormed ∧
      Step (.writer writer) before after ∧
      after.kernel.audit.HasEffect attemptId ∧
      after.backendAcceptances attemptId = some receipt := by
  exact reconcileCommit_is_nonvacuous witnessAuthorityState witnessMetadata
    witness_allAuthorized

end AuditRecovery
end Authority
