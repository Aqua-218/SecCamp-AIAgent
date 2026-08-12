import Authority.State

/-!
# Session Orchestration

A sequential specification of durable identity reservation, resource binding,
ordered startup, and retryable cleanup. Backend I/O refines the successful
transitions below; failures do not gain authority to skip a transition.
-/

namespace Authority

namespace Orchestrator

/-- Opaque identity used by every orchestration identity domain. -/
structure OrchestrationId where
  value : String
  deriving Repr, BEq, DecidableEq

/-- The seven independently reserved identity domains. -/
inductive IdentityKind where
  | session
  | request
  | vm
  | subject
  | workspace
  | capability
  | brokerSession
  deriving Repr, BEq, DecidableEq

/-- All identities that bind the resources of one session. -/
structure SessionIdentity where
  session : OrchestrationId
  request : OrchestrationId
  vm : OrchestrationId
  subject : OrchestrationId
  workspace : OrchestrationId
  capability : OrchestrationId
  brokerSession : OrchestrationId
  deriving DecidableEq

/-- Select the identity belonging to one ledger domain. -/
def SessionIdentity.forKind (identity : SessionIdentity) :
    IdentityKind → OrchestrationId
  | .session => identity.session
  | .request => identity.request
  | .vm => identity.vm
  | .subject => identity.subject
  | .workspace => identity.workspace
  | .capability => identity.capability
  | .brokerSession => identity.brokerSession

/-- A total view of the global, cross-domain durable no-reuse ledger. -/
abbrev IdentityLedger := OrchestrationId → Bool

/-- The batch contains one supplied identity value. -/
def SessionIdentity.contains (identity : SessionIdentity)
    (value : OrchestrationId) : Bool :=
  decide (value = identity.session) || decide (value = identity.request) ||
  decide (value = identity.vm) || decide (value = identity.subject) ||
  decide (value = identity.workspace) || decide (value = identity.capability) ||
  decide (value = identity.brokerSession)

/-- Every identity in a batch is fresh in its own domain. -/
def IdentityBatchFresh (ledger : IdentityLedger)
    (identity : SessionIdentity) : Prop :=
  (∀ kind, ledger (identity.forKind kind) = false) ∧
  ∀ first second,
    identity.forKind first = identity.forKind second → first = second

/-- Atomically reserve the complete session identity batch. -/
def reserveBatch (ledger : IdentityLedger)
    (identity : SessionIdentity) : IdentityLedger :=
  fun value => ledger value || identity.contains value

/-- A successful batch reservation records every identity domain. -/
theorem reserveBatch_records_all (ledger : IdentityLedger)
    (identity : SessionIdentity) (kind : IdentityKind) :
    reserveBatch ledger identity (identity.forKind kind) = true := by
  cases kind <;> simp [reserveBatch, SessionIdentity.contains, SessionIdentity.forKind]

/-- Batch reservation cannot release any previously issued identity. -/
theorem reserveBatch_preserves_issued (ledger : IdentityLedger)
    (identity : SessionIdentity) {value : OrchestrationId}
    (issued : ledger value = true) :
    reserveBatch ledger identity value = true := by
  simp [reserveBatch, issued]

/-- A workspace clone is bound to one session and one allocated clone identity. -/
structure WorkspaceLease where
  session : OrchestrationId
  workspace : OrchestrationId
  deriving DecidableEq

/-- A Broker connection is bound to one session and post-restore identity. -/
structure BrokerLease where
  session : OrchestrationId
  brokerSession : OrchestrationId
  deriving DecidableEq

/-- A VM is bound to the session, workspace, and Broker connection it uses. -/
structure VmLease where
  session : OrchestrationId
  vm : OrchestrationId
  workspace : OrchestrationId
  brokerSession : OrchestrationId
  deriving DecidableEq

/-- A root capability is bound to one session subject. -/
structure CapabilityLease where
  session : OrchestrationId
  subject : OrchestrationId
  capability : OrchestrationId
  deriving DecidableEq

/-- A released workload is bound to its VM, subject, and root capability. -/
structure WorkloadLease where
  session : OrchestrationId
  vm : OrchestrationId
  subject : OrchestrationId
  capability : OrchestrationId
  deriving DecidableEq

/-- Exact workspace lease binding. -/
def WorkspaceLease.Matches (lease : WorkspaceLease)
    (identity : SessionIdentity) : Prop :=
  lease.session = identity.session ∧ lease.workspace = identity.workspace

/-- Exact Broker lease binding. -/
def BrokerLease.Matches (lease : BrokerLease)
    (identity : SessionIdentity) : Prop :=
  lease.session = identity.session ∧
    lease.brokerSession = identity.brokerSession

/-- Exact VM dependency binding. -/
def VmLease.Matches (lease : VmLease) (identity : SessionIdentity) : Prop :=
  lease.session = identity.session ∧ lease.vm = identity.vm ∧
    lease.workspace = identity.workspace ∧
    lease.brokerSession = identity.brokerSession

/-- Exact root-capability binding. -/
def CapabilityLease.Matches (lease : CapabilityLease)
    (identity : SessionIdentity) : Prop :=
  lease.session = identity.session ∧ lease.subject = identity.subject ∧
    lease.capability = identity.capability

/-- Exact released-workload binding. -/
def WorkloadLease.Matches (lease : WorkloadLease)
    (identity : SessionIdentity) : Prop :=
  lease.session = identity.session ∧ lease.vm = identity.vm ∧
    lease.subject = identity.subject ∧
    lease.capability = identity.capability

/-- Successful startup phases, including the internal durable-reservation phase. -/
inductive LifecyclePhase where
  | ready
  | identitiesReserved
  | workspaceCloned
  | brokerEstablished
  | vmStarted
  | rootCapabilityInjected
  | workloadReleased
  | running
  | closed
  deriving Repr, BEq, DecidableEq

/-- Resource leases committed by successful startup stages. -/
structure Resources where
  workspace : Option WorkspaceLease
  broker : Option BrokerLease
  vm : Option VmLease
  capability : Option CapabilityLease
  workload : Option WorkloadLease
  deriving DecidableEq

/-- No backend resource has committed. -/
def Resources.empty : Resources where
  workspace := none
  broker := none
  vm := none
  capability := none
  workload := none

/-- Pure orchestration state at one startup linearization point. -/
structure State where
  phase : LifecyclePhase
  ledger : IdentityLedger
  identity : Option SessionIdentity
  resources : Resources

/-- Initial orchestrator state. -/
def State.initial (ledger : IdentityLedger) : State where
  phase := .ready
  ledger := ledger
  identity := none
  resources := .empty

/-- Exact resource shape and binding required at every successful phase. -/
def State.WellFormed (state : State) : Prop :=
  match state.phase with
  | .ready | .closed =>
      state.identity = none ∧ state.resources = .empty
  | .identitiesReserved =>
      ∃ identity, state.identity = some identity ∧ state.resources = .empty
  | .workspaceCloned =>
      ∃ identity workspace,
        state.identity = some identity ∧
        state.resources = { Resources.empty with workspace := some workspace } ∧
        workspace.Matches identity
  | .brokerEstablished =>
      ∃ identity workspace broker,
        state.identity = some identity ∧
        state.resources = {
          workspace := some workspace
          broker := some broker
          vm := none
          capability := none
          workload := none } ∧
        workspace.Matches identity ∧ broker.Matches identity
  | .vmStarted =>
      ∃ identity workspace broker vm,
        state.identity = some identity ∧
        state.resources = {
          workspace := some workspace
          broker := some broker
          vm := some vm
          capability := none
          workload := none } ∧
        workspace.Matches identity ∧ broker.Matches identity ∧ vm.Matches identity
  | .rootCapabilityInjected =>
      ∃ identity workspace broker vm capability,
        state.identity = some identity ∧
        state.resources = {
          workspace := some workspace
          broker := some broker
          vm := some vm
          capability := some capability
          workload := none } ∧
        workspace.Matches identity ∧ broker.Matches identity ∧ vm.Matches identity ∧
        capability.Matches identity
  | .workloadReleased | .running =>
      ∃ identity workspace broker vm capability workload,
        state.identity = some identity ∧
        state.resources = {
          workspace := some workspace
          broker := some broker
          vm := some vm
          capability := some capability
          workload := some workload } ∧
        workspace.Matches identity ∧ broker.Matches identity ∧ vm.Matches identity ∧
        capability.Matches identity ∧ workload.Matches identity

/-- Initial state satisfies the exact phase/resource invariant. -/
theorem State.initial_wellFormed (ledger : IdentityLedger) :
    (State.initial ledger).WellFormed := by
  simp [State.initial, State.WellFormed, Resources.empty]

/-- Reserve identities before any backend resource can be committed. -/
def reserveIdentities (state : State) (identity : SessionIdentity) : State :=
  { phase := .identitiesReserved
    ledger := reserveBatch state.ledger identity
    identity := some identity
    resources := .empty }

/-- Commit a correctly bound workspace lease. -/
def commitWorkspace (state : State) (workspace : WorkspaceLease) : State :=
  { state with
    phase := .workspaceCloned
    resources := { Resources.empty with workspace := some workspace } }

/-- Commit a correctly bound Broker lease. -/
def commitBroker (state : State) (broker : BrokerLease) : State :=
  { state with
    phase := .brokerEstablished
    resources := { state.resources with broker := some broker } }

/-- Commit a correctly bound VM lease. -/
def commitVm (state : State) (vm : VmLease) : State :=
  { state with
    phase := .vmStarted
    resources := { state.resources with vm := some vm } }

/-- Commit a correctly bound root-capability lease. -/
def commitCapability (state : State) (capability : CapabilityLease) : State :=
  { state with
    phase := .rootCapabilityInjected
    resources := { state.resources with capability := some capability } }

/-- Commit the final workload release lease. -/
def commitWorkload (state : State) (workload : WorkloadLease) : State :=
  { state with
    phase := .workloadReleased
    resources := { state.resources with workload := some workload } }

/-- Publish a fully committed startup as running. -/
def markRunning (state : State) : State := { state with phase := .running }

/-- Forget terminal resource records only after cleanup has completed. -/
def markClosed (state : State) : State :=
  { state with phase := .closed, identity := none, resources := .empty }

/-- Accepted successful startup transitions. -/
inductive Step : State → State → Prop
  | reserve {state : State} {identity : SessionIdentity} :
      (state.phase = .ready ∨ state.phase = .closed) →
      IdentityBatchFresh state.ledger identity →
      Step state (reserveIdentities state identity)
  | workspace {state : State} {identity : SessionIdentity}
      {workspace : WorkspaceLease} :
      state.phase = .identitiesReserved → state.identity = some identity →
      workspace.Matches identity → Step state (commitWorkspace state workspace)
  | broker {state : State} {identity : SessionIdentity} {broker : BrokerLease} :
      state.phase = .workspaceCloned → state.identity = some identity →
      broker.Matches identity → Step state (commitBroker state broker)
  | vm {state : State} {identity : SessionIdentity} {vm : VmLease} :
      state.phase = .brokerEstablished → state.identity = some identity →
      vm.Matches identity → Step state (commitVm state vm)
  | capability {state : State} {identity : SessionIdentity}
      {capability : CapabilityLease} :
      state.phase = .vmStarted → state.identity = some identity →
      capability.Matches identity → Step state (commitCapability state capability)
  | workload {state : State} {identity : SessionIdentity}
      {workload : WorkloadLease} :
      state.phase = .rootCapabilityInjected → state.identity = some identity →
      workload.Matches identity → Step state (commitWorkload state workload)
  | running {state : State} :
      state.phase = .workloadReleased → Step state (markRunning state)

/-- Successful startup never releases a durable identity reservation. -/
theorem Step.ledger_monotone {before after : State} (transition : Step before after) :
    ∀ value, before.ledger value = true → after.ledger value = true := by
  intro value issued
  cases transition with
  | reserve => exact reserveBatch_preserves_issued _ _ issued
  | workspace | broker | vm | capability | workload | running => exact issued

/-- Every accepted successful transition preserves exact resource binding. -/
theorem Step.preserves_wellFormed {before after : State} (transition : Step before after)
    (wellFormed : before.WellFormed) : after.WellFormed := by
  cases transition with
  | reserve phase _ =>
      exact ⟨_, rfl, rfl⟩
  | workspace phase identityLookup binding =>
      rw [State.WellFormed, phase] at wellFormed
      rcases wellFormed with ⟨storedIdentity, storedLookup, resourcesEmpty⟩
      have sameIdentity : storedIdentity = _ := Option.some.inj
        (storedLookup.symm.trans identityLookup)
      subst storedIdentity
      refine ⟨_, _, ?_, rfl, binding⟩
      simpa [commitWorkspace] using identityLookup
  | broker phase identityLookup binding =>
      rw [State.WellFormed, phase] at wellFormed
      rcases wellFormed with ⟨storedIdentity, workspace, storedLookup,
        resourcesShape, workspaceBinding⟩
      have sameIdentity : storedIdentity = _ := Option.some.inj
        (storedLookup.symm.trans identityLookup)
      subst storedIdentity
      refine ⟨_, workspace, _, ?_, ?_, workspaceBinding, binding⟩
      · simpa [commitBroker] using identityLookup
      · simp [commitBroker, resourcesShape, Resources.empty]
  | vm phase identityLookup binding =>
      rw [State.WellFormed, phase] at wellFormed
      rcases wellFormed with ⟨storedIdentity, workspace, broker, storedLookup,
        resourcesShape, workspaceBinding, brokerBinding⟩
      have sameIdentity : storedIdentity = _ := Option.some.inj
        (storedLookup.symm.trans identityLookup)
      subst storedIdentity
      refine ⟨_, workspace, broker, _, ?_, ?_, workspaceBinding, brokerBinding,
        binding⟩
      · simpa [commitVm] using identityLookup
      · simp [commitVm, resourcesShape]
  | capability phase identityLookup binding =>
      rw [State.WellFormed, phase] at wellFormed
      rcases wellFormed with ⟨storedIdentity, workspace, broker, vm, storedLookup,
        resourcesShape, workspaceBinding, brokerBinding, vmBinding⟩
      have sameIdentity : storedIdentity = _ := Option.some.inj
        (storedLookup.symm.trans identityLookup)
      subst storedIdentity
      refine ⟨_, workspace, broker, vm, _, ?_, ?_, workspaceBinding,
        brokerBinding, vmBinding, binding⟩
      · simpa [commitCapability] using identityLookup
      · simp [commitCapability, resourcesShape]
  | workload phase identityLookup binding =>
      rw [State.WellFormed, phase] at wellFormed
      rcases wellFormed with ⟨storedIdentity, workspace, broker, vm, capability,
        storedLookup, resourcesShape, workspaceBinding, brokerBinding, vmBinding,
        capabilityBinding⟩
      have sameIdentity : storedIdentity = _ := Option.some.inj
        (storedLookup.symm.trans identityLookup)
      subst storedIdentity
      refine ⟨_, workspace, broker, vm, capability, _, ?_, ?_, workspaceBinding,
        brokerBinding, vmBinding, capabilityBinding, binding⟩
      · simpa [commitWorkload] using identityLookup
      · simp [commitWorkload, resourcesShape]
  | running phase =>
      rw [State.WellFormed, phase] at wellFormed
      simpa [markRunning, State.WellFormed] using wellFormed

/-- Finite successful executions. -/
inductive Steps : State → State → Prop
  | refl (state : State) : Steps state state
  | tail {first middle last : State} :
      Steps first middle → Step middle last → Steps first last

/-- Exact resource binding holds after every finite successful execution. -/
theorem Steps.preserve_wellFormed {before after : State} (transitions : Steps before after)
    (wellFormed : before.WellFormed) : after.WellFormed := by
  induction transitions with
  | refl => exact wellFormed
  | tail _ transition inductionHypothesis =>
      exact transition.preserves_wellFormed inductionHypothesis

/-- Durable identity reservations survive every finite successful execution. -/
theorem Steps.ledger_monotone {before after : State} (transitions : Steps before after)
    {value : OrchestrationId}
    (issued : before.ledger value = true) : after.ledger value = true := by
  induction transitions with
  | refl => exact issued
  | tail _ transition inductionHypothesis =>
      exact transition.ledger_monotone _ inductionHypothesis

/-- A running well-formed state contains the complete correctly bound chain. -/
theorem running_has_exact_resource_chain {state : State}
    (wellFormed : state.WellFormed) (running : state.phase = .running) :
    ∃ identity workspace broker vm capability workload,
      state.identity = some identity ∧
      state.resources.workspace = some workspace ∧
      state.resources.broker = some broker ∧ state.resources.vm = some vm ∧
      state.resources.capability = some capability ∧
      state.resources.workload = some workload ∧
      workspace.Matches identity ∧ broker.Matches identity ∧ vm.Matches identity ∧
      capability.Matches identity ∧ workload.Matches identity := by
  rw [State.WellFormed, running] at wellFormed
  rcases wellFormed with ⟨identity, workspace, broker, vm, capability, workload,
    identityLookup, resourcesShape, bindings⟩
  rw [resourcesShape]
  exact ⟨identity, workspace, broker, vm, capability, workload, identityLookup,
    rfl, rfl, rfl, rfl, rfl, bindings⟩

/-- Resources retained solely so failed-start cleanup can be retried.

These leases are deliberately separate from `State.resources`: a backend may
return a lease with invalid bindings, and a failed VM start may leave backend
state to clean up without returning any VM lease.
-/
structure CleanupOwnership where
  resources : Resources
  vmStartAttempted : Bool
  deriving DecidableEq

/-- No failed-start or normal-stop resources are retained. -/
def CleanupOwnership.empty : CleanupOwnership where
  resources := .empty
  vmStartAttempted := false

/-- Normal cleanup owns exactly the successfully committed resource prefix. -/
def CleanupOwnership.forResources (resources : Resources) : CleanupOwnership where
  resources := resources
  vmStartAttempted := resources.vm.isSome

/-- Retain an invalid workspace lease outside the valid core resource chain. -/
def CleanupOwnership.invalidWorkspace (workspace : WorkspaceLease) :
    CleanupOwnership where
  resources := { Resources.empty with workspace := some workspace }
  vmStartAttempted := false

/-- Extend the valid workspace prefix with the exact invalid Broker lease returned. -/
def CleanupOwnership.invalidBroker (resources : Resources)
    (broker : BrokerLease) : CleanupOwnership :=
  CleanupOwnership.forResources { resources with broker := some broker }

/-- Extend the valid Broker prefix with the exact invalid VM lease returned. -/
def CleanupOwnership.invalidVm (resources : Resources) (vm : VmLease) :
    CleanupOwnership :=
  CleanupOwnership.forResources { resources with vm := some vm }

/-- Extend the valid VM prefix with the exact invalid capability lease returned. -/
def CleanupOwnership.invalidCapability (resources : Resources)
    (capability : CapabilityLease) : CleanupOwnership :=
  CleanupOwnership.forResources { resources with capability := some capability }

/-- A VM start attempt can require cleanup even though it returned no lease. -/
def CleanupOwnership.failedVmStart (resources : Resources) : CleanupOwnership where
  resources := resources
  vmStartAttempted := true

/-- Retryable cleanup progress for one active session. -/
structure CleanupState where
  capabilityRevoked : Bool
  vmKilled : Bool
  brokerClosed : Bool
  workspaceIsolated : Bool
  deriving DecidableEq

/-- No cleanup operation has yet committed. -/
def CleanupState.pending : CleanupState where
  capabilityRevoked := false
  vmKilled := false
  brokerClosed := false
  workspaceIsolated := false

/-- Cleanup starts complete only for resources and effects that were never acquired. -/
def CleanupState.forOwnership (ownership : CleanupOwnership) : CleanupState where
  capabilityRevoked := ownership.resources.capability.isNone
  vmKilled := ownership.resources.vm.isNone && !ownership.vmStartAttempted
  brokerClosed := ownership.resources.broker.isNone
  workspaceIsolated := ownership.resources.workspace.isNone

/-- All cleanup dependencies have committed. -/
def CleanupState.Complete (state : CleanupState) : Prop :=
  state.capabilityRevoked = true ∧ state.vmKilled = true ∧
    state.brokerClosed = true ∧ state.workspaceIsolated = true

/-- Every cleanup effect known to be absent is already accounted for. -/
def CleanupState.CoversAbsentOwnership (state : CleanupState)
    (ownership : CleanupOwnership) : Prop :=
  (ownership.resources.capability = none → state.capabilityRevoked = true) ∧
  (ownership.resources.vm = none → ownership.vmStartAttempted = false →
    state.vmKilled = true) ∧
  (ownership.resources.broker = none → state.brokerClosed = true) ∧
  (ownership.resources.workspace = none → state.workspaceIsolated = true)

/-- Ownership-derived cleanup progress accounts for every absent effect. -/
theorem CleanupState.forOwnership_coversAbsentOwnership
    (ownership : CleanupOwnership) :
    (CleanupState.forOwnership ownership).CoversAbsentOwnership ownership := by
  cases ownership with
  | mk resources vmStartAttempted =>
      cases resources with
      | mk workspace broker vm capability workload =>
          cases workspace <;> cases broker <;> cases vm <;> cases capability <;>
            cases vmStartAttempted <;>
              simp [CleanupState.forOwnership,
                CleanupState.CoversAbsentOwnership]

/-- Mark a successful capability revocation. -/
def CleanupState.revokeCapability (state : CleanupState) : CleanupState :=
  { state with capabilityRevoked := true }

/-- Mark a successful VM kill. -/
def CleanupState.killVm (state : CleanupState) : CleanupState :=
  { state with vmKilled := true }

/-- Mark a successful Broker close. -/
def CleanupState.closeBroker (state : CleanupState) : CleanupState :=
  { state with brokerClosed := true }

/-- Isolate the workspace only after VM and Broker reach terminal cleanup. -/
def CleanupState.isolateWorkspace (state : CleanupState) : CleanupState :=
  { state with workspaceIsolated := true }

/-- Accepted cleanup commits; failed backend calls make no transition. -/
inductive CleanupStep : CleanupState → CleanupState → Prop
  | revokeCapability {state : CleanupState} :
      CleanupStep state state.revokeCapability
  | killVm {state : CleanupState} : CleanupStep state state.killVm
  | closeBroker {state : CleanupState} : CleanupStep state state.closeBroker
  | isolateWorkspace {state : CleanupState} :
      state.vmKilled = true → state.brokerClosed = true →
      CleanupStep state state.isolateWorkspace

/-- Every cleanup flag is monotone across a successful cleanup commit. -/
theorem CleanupStep.flags_monotone {before after : CleanupState}
    (transition : CleanupStep before after) :
    (before.capabilityRevoked = true → after.capabilityRevoked = true) ∧
    (before.vmKilled = true → after.vmKilled = true) ∧
    (before.brokerClosed = true → after.brokerClosed = true) ∧
    (before.workspaceIsolated = true → after.workspaceIsolated = true) := by
  cases transition <;> simp [CleanupState.revokeCapability, CleanupState.killVm,
    CleanupState.closeBroker, CleanupState.isolateWorkspace]

/-- Cleanup retries preserve the accounting for effects absent at startup failure. -/
theorem CleanupStep.preserves_coversAbsentOwnership {before after : CleanupState}
    {ownership : CleanupOwnership} (transition : CleanupStep before after)
    (covers : before.CoversAbsentOwnership ownership) :
    after.CoversAbsentOwnership ownership := by
  rcases transition.flags_monotone with ⟨capability, vm, broker, workspace⟩
  rcases covers with ⟨capabilityAbsent, vmAbsent, brokerAbsent, workspaceAbsent⟩
  exact ⟨fun absent => capability (capabilityAbsent absent),
    fun absent notAttempted => vm (vmAbsent absent notAttempted),
    fun absent => broker (brokerAbsent absent),
    fun absent => workspace (workspaceAbsent absent)⟩

/-- Workspace isolation cannot commit while the VM or Broker is still live. -/
theorem CleanupStep.workspace_isolation_requires_dependencies
    {before after : CleanupState} (transition : CleanupStep before after)
    (newlyIsolated : before.workspaceIsolated = false)
    (isolatedAfter : after.workspaceIsolated = true) :
    before.vmKilled = true ∧ before.brokerClosed = true := by
  cases transition with
  | revokeCapability => simp [CleanupState.revokeCapability, newlyIsolated] at isolatedAfter
  | killVm => simp [CleanupState.killVm, newlyIsolated] at isolatedAfter
  | closeBroker => simp [CleanupState.closeBroker, newlyIsolated] at isolatedAfter
  | isolateWorkspace vmKilled brokerClosed => exact ⟨vmKilled, brokerClosed⟩

/-- Finite retry sequence of successful cleanup commits. -/
inductive CleanupSteps : CleanupState → CleanupState → Prop
  | refl (state : CleanupState) : CleanupSteps state state
  | tail {first middle last : CleanupState} :
      CleanupSteps first middle → CleanupStep middle last → CleanupSteps first last

/-- Cleanup flags remain committed across all later retries. -/
theorem CleanupSteps.flags_monotone {before after : CleanupState}
    (transitions : CleanupSteps before after) :
    (before.capabilityRevoked = true → after.capabilityRevoked = true) ∧
    (before.vmKilled = true → after.vmKilled = true) ∧
    (before.brokerClosed = true → after.brokerClosed = true) ∧
    (before.workspaceIsolated = true → after.workspaceIsolated = true) := by
  induction transitions with
  | refl => simp
  | tail _ transition inductionHypothesis =>
      rcases inductionHypothesis with ⟨capabilityBefore, vmBefore, brokerBefore,
        workspaceBefore⟩
      rcases transition.flags_monotone with ⟨capabilityAfter, vmAfter, brokerAfter,
        workspaceAfter⟩
      exact ⟨fun issued => capabilityAfter (capabilityBefore issued),
        fun killed => vmAfter (vmBefore killed),
        fun closed => brokerAfter (brokerBefore closed),
        fun isolated => workspaceAfter (workspaceBefore isolated)⟩

/-- Phases with a committed workspace retain a cleanup-reachable startup prefix. -/
def LifecyclePhase.CleanupEligible : LifecyclePhase → Prop
  | .workspaceCloned | .brokerEstablished | .vmStarted
  | .rootCapabilityInjected | .workloadReleased | .running => True
  | .ready | .identitiesReserved | .closed => False

/-- A cleanup-eligible startup prefix cannot already be Closed. -/
theorem LifecyclePhase.CleanupEligible.ne_closed {phase : LifecyclePhase}
    (eligible : phase.CleanupEligible) : phase ≠ .closed := by
  intro closed
  subst phase
  exact eligible

/-- Lifecycle state composed with retryable cleanup progress. -/
structure ManagedState where
  core : State
  stopping : Bool
  cleanup : CleanupState
  ownership : CleanupOwnership

/-- Initial managed session has no active cleanup transaction. -/
def ManagedState.initial (ledger : IdentityLedger) : ManagedState where
  core := State.initial ledger
  stopping := false
  cleanup := .pending
  ownership := .empty

/-- Enter retryable cleanup while retaining a normal or partial startup resource chain. -/
def ManagedState.beginStop (state : ManagedState) : ManagedState :=
  let ownership := CleanupOwnership.forResources state.core.resources
  { core := state.core,
    stopping := true,
    cleanup := CleanupState.forOwnership ownership,
    ownership := ownership }

/-- Retain cleanup-only ownership after startup and its first cleanup attempt fail. -/
def ManagedState.retainFailedStart (state : ManagedState)
    (ownership : CleanupOwnership) : ManagedState :=
  { core := state.core,
    stopping := true,
    cleanup := CleanupState.forOwnership ownership,
    ownership := ownership }

/-- Commit one successful cleanup action without discarding resource leases. -/
def ManagedState.recordCleanup (state : ManagedState)
    (cleanup : CleanupState) : ManagedState :=
  { state with cleanup := cleanup }

/-- Publish Closed only after all cleanup dependencies have committed. -/
def ManagedState.finishStop (state : ManagedState) : ManagedState :=
  { core := markClosed state.core,
    stopping := false,
    cleanup := state.cleanup,
    ownership := .empty }

/-- Exact origins of cleanup ownership, kept separate from valid core bindings. -/
inductive ManagedState.HasCleanupContext (state : ManagedState) : Prop
  | normal :
      state.core.phase.CleanupEligible →
      state.ownership = CleanupOwnership.forResources state.core.resources →
      HasCleanupContext state
  | invalidWorkspace {identity : SessionIdentity} {workspace : WorkspaceLease} :
      state.core.phase = .identitiesReserved →
      state.core.identity = some identity →
      state.ownership = CleanupOwnership.invalidWorkspace workspace →
      ¬workspace.Matches identity → HasCleanupContext state
  | invalidBroker {identity : SessionIdentity} {broker : BrokerLease} :
      state.core.phase = .workspaceCloned →
      state.core.identity = some identity →
      state.ownership = CleanupOwnership.invalidBroker state.core.resources broker →
      ¬broker.Matches identity → HasCleanupContext state
  | invalidVm {identity : SessionIdentity} {vm : VmLease} :
      state.core.phase = .brokerEstablished →
      state.core.identity = some identity →
      state.ownership = CleanupOwnership.invalidVm state.core.resources vm →
      ¬vm.Matches identity → HasCleanupContext state
  | invalidCapability {identity : SessionIdentity}
      {capability : CapabilityLease} :
      state.core.phase = .vmStarted →
      state.core.identity = some identity →
      state.ownership =
        CleanupOwnership.invalidCapability state.core.resources capability →
      ¬capability.Matches identity → HasCleanupContext state
  | failedVmStart :
      state.core.phase = .brokerEstablished →
      state.ownership = CleanupOwnership.failedVmStart state.core.resources →
      HasCleanupContext state

/-- Every exact cleanup origin retains a nonterminal core phase. -/
theorem ManagedState.HasCleanupContext.ne_closed {state : ManagedState}
    (context : state.HasCleanupContext) : state.core.phase ≠ .closed := by
  intro closed
  cases context with
  | normal eligible _ => exact eligible.ne_closed closed
  | invalidWorkspace phase _ _ _
  | invalidBroker phase _ _ _
  | invalidVm phase _ _ _
  | invalidCapability phase _ _ _
  | failedVmStart phase _ =>
      rw [phase] at closed
      cases closed

/-- Core bindings, Closed gating, and cleanup-only ownership accounting agree. -/
structure ManagedState.WellFormed (state : ManagedState) : Prop where
  coreWellFormed : state.core.WellFormed
  inactiveReleasesOwnership :
    state.stopping = false → state.ownership = .empty
  closedRequiresCleanup : state.core.phase = .closed → state.cleanup.Complete
  stoppingRetainsCleanupContext :
    state.stopping = true → state.HasCleanupContext
  stoppingCoversAbsentOwnership :
    state.stopping = true →
      state.cleanup.CoversAbsentOwnership state.ownership

/-- The initial managed state satisfies lifecycle/cleanup coupling. -/
theorem ManagedState.initial_wellFormed (ledger : IdentityLedger) :
    (ManagedState.initial ledger).WellFormed := by
  constructor
  · exact State.initial_wellFormed ledger
  · intro _
    rfl
  · intro impossible
    simp [ManagedState.initial, State.initial] at impossible
  · intro impossible
    simp [ManagedState.initial] at impossible
  · intro impossible
    simp [ManagedState.initial] at impossible

/-- Startup transitions never directly publish the terminal Closed phase. -/
theorem Step.after_ne_closed {before after : State} (transition : Step before after) :
    after.phase ≠ .closed := by
  cases transition <;> simp [reserveIdentities, commitWorkspace, commitBroker,
    commitVm, commitCapability, commitWorkload, markRunning]

/-- Accepted lifecycle transitions including retryable cleanup and its close gate. -/
inductive ManagedStep : ManagedState → ManagedState → Prop
  | startup {state : ManagedState} {core : State} :
      state.stopping = false → Step state.core core →
      ManagedStep state { state with core := core }
  | beginStop {state : ManagedState} :
      state.stopping = false → state.core.phase.CleanupEligible →
      ManagedStep state state.beginStop
  | retainInvalidWorkspace {state : ManagedState} {identity : SessionIdentity}
      {workspace : WorkspaceLease} :
      state.stopping = false →
      state.core.phase = .identitiesReserved →
      state.core.identity = some identity →
      ¬workspace.Matches identity →
      ManagedStep state
        (state.retainFailedStart (CleanupOwnership.invalidWorkspace workspace))
  | retainInvalidBroker {state : ManagedState} {identity : SessionIdentity}
      {broker : BrokerLease} :
      state.stopping = false →
      state.core.phase = .workspaceCloned →
      state.core.identity = some identity →
      ¬broker.Matches identity →
      ManagedStep state
        (state.retainFailedStart
          (CleanupOwnership.invalidBroker state.core.resources broker))
  | retainInvalidVm {state : ManagedState} {identity : SessionIdentity}
      {vm : VmLease} :
      state.stopping = false →
      state.core.phase = .brokerEstablished →
      state.core.identity = some identity →
      ¬vm.Matches identity →
      ManagedStep state
        (state.retainFailedStart
          (CleanupOwnership.invalidVm state.core.resources vm))
  | retainInvalidCapability {state : ManagedState} {identity : SessionIdentity}
      {capability : CapabilityLease} :
      state.stopping = false →
      state.core.phase = .vmStarted →
      state.core.identity = some identity →
      ¬capability.Matches identity →
      ManagedStep state
        (state.retainFailedStart
          (CleanupOwnership.invalidCapability state.core.resources capability))
  | retainFailedVmStart {state : ManagedState} :
      state.stopping = false → state.core.phase = .brokerEstablished →
      ManagedStep state
        (state.retainFailedStart
          (CleanupOwnership.failedVmStart state.core.resources))
  | cleanup {state : ManagedState} {cleanup : CleanupState} :
      state.stopping = true → CleanupStep state.cleanup cleanup →
      ManagedStep state (state.recordCleanup cleanup)
  | cleanupFailure {state : ManagedState} :
      state.stopping = true → ManagedStep state state
  | finishStop {state : ManagedState} :
      state.stopping = true → state.cleanup.Complete →
      ManagedStep state state.finishStop

/-- A failed cleanup call leaves both Stopping and cleanup ownership intact. -/
theorem cleanupFailure_retains_stopping_and_ownership {state : ManagedState}
    (stopping : state.stopping = true) :
    ∃ after,
      ManagedStep state after ∧ after.stopping = true ∧
      after.ownership = state.ownership :=
  ⟨state, ManagedStep.cleanupFailure stopping, stopping, rfl⟩

/-- Lifecycle/cleanup coupling is inductive across every accepted managed step. -/
theorem ManagedStep.preserves_wellFormed {before after : ManagedState}
    (transition : ManagedStep before after) (wellFormed : before.WellFormed) :
    after.WellFormed := by
  cases transition with
  | startup notStopping startupStep =>
      constructor
      · exact startupStep.preserves_wellFormed wellFormed.coreWellFormed
      · intro _
        exact wellFormed.inactiveReleasesOwnership notStopping
      · intro closed
        exact False.elim (startupStep.after_ne_closed closed)
      · intro impossible
        simp [notStopping] at impossible
      · intro impossible
        simp [notStopping] at impossible
  | beginStop notStopping eligible =>
      exact ⟨wellFormed.coreWellFormed,
        fun impossible => False.elim (by
          simp [ManagedState.beginStop] at impossible),
        fun closed => False.elim (by
          change before.core.phase = .closed at closed
          exact eligible.ne_closed closed),
        fun _ => ManagedState.HasCleanupContext.normal eligible rfl,
        fun _ => by
          simpa [ManagedState.beginStop] using
            CleanupState.forOwnership_coversAbsentOwnership
              (CleanupOwnership.forResources before.core.resources)⟩
  | retainInvalidWorkspace notStopping phase identityLookup mismatch =>
      exact ⟨wellFormed.coreWellFormed,
        fun impossible => False.elim (by
          simp [ManagedState.retainFailedStart] at impossible),
        fun closed => False.elim (by
          change before.core.phase = .closed at closed
          rw [phase] at closed
          cases closed),
        fun _ => ManagedState.HasCleanupContext.invalidWorkspace
          phase identityLookup rfl mismatch,
        fun _ => by
          simpa [ManagedState.retainFailedStart] using
            CleanupState.forOwnership_coversAbsentOwnership
              (CleanupOwnership.invalidWorkspace _)⟩
  | retainInvalidBroker notStopping phase identityLookup mismatch =>
      exact ⟨wellFormed.coreWellFormed,
        fun impossible => False.elim (by
          simp [ManagedState.retainFailedStart] at impossible),
        fun closed => False.elim (by
          change before.core.phase = .closed at closed
          rw [phase] at closed
          cases closed),
        fun _ => ManagedState.HasCleanupContext.invalidBroker
          phase identityLookup rfl mismatch,
        fun _ => by
          simpa [ManagedState.retainFailedStart] using
            CleanupState.forOwnership_coversAbsentOwnership
              (CleanupOwnership.invalidBroker before.core.resources _)⟩
  | retainInvalidVm notStopping phase identityLookup mismatch =>
      exact ⟨wellFormed.coreWellFormed,
        fun impossible => False.elim (by
          simp [ManagedState.retainFailedStart] at impossible),
        fun closed => False.elim (by
          change before.core.phase = .closed at closed
          rw [phase] at closed
          cases closed),
        fun _ => ManagedState.HasCleanupContext.invalidVm
          phase identityLookup rfl mismatch,
        fun _ => by
          simpa [ManagedState.retainFailedStart] using
            CleanupState.forOwnership_coversAbsentOwnership
              (CleanupOwnership.invalidVm before.core.resources _)⟩
  | retainInvalidCapability notStopping phase identityLookup mismatch =>
      exact ⟨wellFormed.coreWellFormed,
        fun impossible => False.elim (by
          simp [ManagedState.retainFailedStart] at impossible),
        fun closed => False.elim (by
          change before.core.phase = .closed at closed
          rw [phase] at closed
          cases closed),
        fun _ => ManagedState.HasCleanupContext.invalidCapability
          phase identityLookup rfl mismatch,
        fun _ => by
          simpa [ManagedState.retainFailedStart] using
            CleanupState.forOwnership_coversAbsentOwnership
              (CleanupOwnership.invalidCapability before.core.resources _)⟩
  | retainFailedVmStart notStopping phase =>
      exact ⟨wellFormed.coreWellFormed,
        fun impossible => False.elim (by
          simp [ManagedState.retainFailedStart] at impossible),
        fun closed => False.elim (by
          change before.core.phase = .closed at closed
          rw [phase] at closed
          cases closed),
        fun _ => ManagedState.HasCleanupContext.failedVmStart phase rfl,
        fun _ => by
          simpa [ManagedState.retainFailedStart] using
            CleanupState.forOwnership_coversAbsentOwnership
              (CleanupOwnership.failedVmStart before.core.resources)⟩
  | cleanup stopping cleanupStep =>
      exact ⟨wellFormed.coreWellFormed,
        fun impossible => False.elim (by
          simp [ManagedState.recordCleanup, stopping] at impossible),
        fun closed => False.elim (by
          have context := wellFormed.stoppingRetainsCleanupContext stopping
          change before.core.phase = .closed at closed
          exact context.ne_closed closed),
        fun _ => by
          have context := wellFormed.stoppingRetainsCleanupContext stopping
          cases context with
          | normal eligible ownership =>
              exact ManagedState.HasCleanupContext.normal eligible ownership
          | invalidWorkspace phase identityLookup ownership mismatch =>
              exact ManagedState.HasCleanupContext.invalidWorkspace
                phase identityLookup ownership mismatch
          | invalidBroker phase identityLookup ownership mismatch =>
              exact ManagedState.HasCleanupContext.invalidBroker
                phase identityLookup ownership mismatch
          | invalidVm phase identityLookup ownership mismatch =>
              exact ManagedState.HasCleanupContext.invalidVm
                phase identityLookup ownership mismatch
          | invalidCapability phase identityLookup ownership mismatch =>
              exact ManagedState.HasCleanupContext.invalidCapability
                phase identityLookup ownership mismatch
          | failedVmStart phase ownership =>
              exact ManagedState.HasCleanupContext.failedVmStart phase ownership,
        fun _ => cleanupStep.preserves_coversAbsentOwnership
          (wellFormed.stoppingCoversAbsentOwnership stopping)⟩
  | cleanupFailure _ =>
      exact wellFormed
  | finishStop stopping complete =>
      constructor
      · simp [ManagedState.finishStop, markClosed, State.WellFormed,
          Resources.empty]
      · intro _
        rfl
      · intro _
        exact complete
      · intro impossible
        simp [ManagedState.finishStop] at impossible
      · intro impossible
        simp [ManagedState.finishStop] at impossible

/-- A managed session can be Closed only after every cleanup stage committed. -/
theorem ManagedState.closed_implies_cleanup_complete {state : ManagedState}
    (wellFormed : state.WellFormed) (closed : state.core.phase = .closed) :
    state.cleanup.Complete :=
  wellFormed.closedRequiresCleanup closed

/-- Finite managed lifecycle execution. -/
inductive ManagedSteps : ManagedState → ManagedState → Prop
  | refl (state : ManagedState) : ManagedSteps state state
  | tail {first middle last : ManagedState} :
      ManagedSteps first middle → ManagedStep middle last →
      ManagedSteps first last

/-- Cleanup gating and exact resource binding survive arbitrary lifecycle execution. -/
theorem ManagedSteps.preserves_wellFormed {before after : ManagedState}
    (transitions : ManagedSteps before after) (wellFormed : before.WellFormed) :
    after.WellFormed := by
  induction transitions with
  | refl => exact wellFormed
  | tail _ transition inductionHypothesis =>
      exact transition.preserves_wellFormed inductionHypothesis

/-- Concatenate two finite managed executions. -/
theorem ManagedSteps.trans {first middle last : ManagedState}
    (firstSteps : ManagedSteps first middle) (lastSteps : ManagedSteps middle last) :
    ManagedSteps first last := by
  induction lastSteps with
  | refl => exact firstSteps
  | tail _ transition inductionHypothesis =>
      exact ManagedSteps.tail inductionHypothesis transition

/-- Any retained cleanup transaction can commit its retries and then close. -/
theorem stopping_reaches_closed {state : ManagedState}
    (stopping : state.stopping = true) :
    ∃ closed,
      ManagedSteps state closed ∧ closed.core.phase = .closed ∧
      closed.cleanup.Complete ∧ closed.ownership = .empty := by
  let revoked := state.recordCleanup state.cleanup.revokeCapability
  let killed := revoked.recordCleanup revoked.cleanup.killVm
  let brokerClosed := killed.recordCleanup killed.cleanup.closeBroker
  let workspaceIsolated :=
    brokerClosed.recordCleanup brokerClosed.cleanup.isolateWorkspace
  let closed := workspaceIsolated.finishStop
  have revokeTransition : ManagedStep state revoked := by
    apply ManagedStep.cleanup stopping
    exact CleanupStep.revokeCapability
  have killTransition : ManagedStep revoked killed := by
    apply ManagedStep.cleanup
    · simpa [revoked, ManagedState.recordCleanup] using stopping
    · exact CleanupStep.killVm
  have brokerTransition : ManagedStep killed brokerClosed := by
    apply ManagedStep.cleanup
    · simpa [brokerClosed, killed, revoked, ManagedState.recordCleanup] using stopping
    · exact CleanupStep.closeBroker
  have workspaceTransition : ManagedStep brokerClosed workspaceIsolated := by
    apply ManagedStep.cleanup
    · simpa [brokerClosed, killed, revoked, ManagedState.recordCleanup] using stopping
    · apply CleanupStep.isolateWorkspace
      · simp [brokerClosed, killed, revoked, ManagedState.recordCleanup,
          CleanupState.revokeCapability, CleanupState.killVm,
          CleanupState.closeBroker]
      · simp [brokerClosed, killed, revoked, ManagedState.recordCleanup,
          CleanupState.revokeCapability, CleanupState.killVm,
          CleanupState.closeBroker]
  have complete : workspaceIsolated.cleanup.Complete := by
    simp [workspaceIsolated, brokerClosed, killed, revoked,
      ManagedState.recordCleanup, CleanupState.Complete,
      CleanupState.revokeCapability, CleanupState.killVm,
      CleanupState.closeBroker, CleanupState.isolateWorkspace]
  have finishTransition : ManagedStep workspaceIsolated closed := by
    apply ManagedStep.finishStop
    · simpa [workspaceIsolated, brokerClosed, killed, revoked,
        ManagedState.recordCleanup] using stopping
    · exact complete
  have revokedSteps : ManagedSteps state revoked :=
    ManagedSteps.tail (ManagedSteps.refl state) revokeTransition
  have killedSteps : ManagedSteps state killed :=
    ManagedSteps.tail revokedSteps killTransition
  have brokerSteps : ManagedSteps state brokerClosed :=
    ManagedSteps.tail killedSteps brokerTransition
  have isolatedSteps : ManagedSteps state workspaceIsolated :=
    ManagedSteps.tail brokerSteps workspaceTransition
  refine ⟨closed, ManagedSteps.tail isolatedSteps finishTransition, ?_, ?_, ?_⟩
  · simp [closed, ManagedState.finishStop, markClosed]
  · simpa [closed, ManagedState.finishStop] using complete
  · rfl

/-- Finite reachability from an initial managed orchestrator state. -/
def ManagedState.Reachable (ledger : IdentityLedger) (state : ManagedState) : Prop :=
  ManagedSteps (ManagedState.initial ledger) state

/-- Every finitely reachable managed state preserves lifecycle and cleanup coupling. -/
theorem ManagedState.Reachable.wellFormed {ledger : IdentityLedger}
    {state : ManagedState} (reachable : state.Reachable ledger) :
    state.WellFormed :=
  reachable.preserves_wellFormed (ManagedState.initial_wellFormed ledger)

/-- Closed is cleanup-complete on every finite normal-stop or failed-start execution. -/
theorem ManagedState.Reachable.closed_implies_cleanup_complete
    {ledger : IdentityLedger} {state : ManagedState}
    (reachable : state.Reachable ledger) (closed : state.core.phase = .closed) :
    state.cleanup.Complete :=
  ManagedState.closed_implies_cleanup_complete reachable.wellFormed closed

/-- An invalid first workspace lease is retained outside the well-formed core
chain and can be retried constructively to Closed. -/
theorem invalidWorkspaceCleanup_constructively_reachable
    {ledger : IdentityLedger} {identity : SessionIdentity}
    {workspace : WorkspaceLease}
    (fresh : IdentityBatchFresh ledger identity)
    (mismatch : ¬workspace.Matches identity) :
    ∃ retained closed,
      retained.Reachable ledger ∧
      retained.core.phase = .identitiesReserved ∧
      retained.core.WellFormed ∧ retained.stopping = true ∧
      retained.ownership = CleanupOwnership.invalidWorkspace workspace ∧
      retained.cleanup.workspaceIsolated = false ∧
      ManagedSteps retained closed ∧ closed.core.phase = .closed ∧
      closed.cleanup.Complete := by
  let initial := ManagedState.initial ledger
  let reserved : ManagedState :=
    { initial with core := reserveIdentities initial.core identity }
  let retained :=
    reserved.retainFailedStart (CleanupOwnership.invalidWorkspace workspace)
  have reserveTransition : ManagedStep initial reserved := by
    apply ManagedStep.startup
    · rfl
    · apply Step.reserve
      · exact Or.inl rfl
      · exact fresh
  have retainTransition : ManagedStep reserved retained := by
    apply @ManagedStep.retainInvalidWorkspace reserved identity workspace
    · simp [reserved, initial, ManagedState.initial]
    · simp [reserved, reserveIdentities]
    · simp [reserved, reserveIdentities]
    · exact mismatch
  have reservedSteps : ManagedSteps initial reserved :=
    ManagedSteps.tail (ManagedSteps.refl initial) reserveTransition
  have retainedSteps : ManagedSteps initial retained :=
    ManagedSteps.tail reservedSteps retainTransition
  have reachable : retained.Reachable ledger := by
    simpa [initial] using retainedSteps
  have stopping : retained.stopping = true := by
    simp [retained, ManagedState.retainFailedStart]
  rcases stopping_reaches_closed stopping with
    ⟨closed, cleanupSteps, closedPhase, closedComplete, _⟩
  refine ⟨retained, closed, reachable, ?_, reachable.wellFormed.coreWellFormed,
    stopping, ?_, ?_, cleanupSteps, closedPhase, closedComplete⟩
  · simp [retained, reserved, ManagedState.retainFailedStart,
      reserveIdentities]
  · simp [retained, ManagedState.retainFailedStart]
  · simp [retained, ManagedState.retainFailedStart,
      CleanupState.forOwnership, CleanupOwnership.invalidWorkspace,
      Resources.empty]

/-- A failed VM start retains a cleanup obligation without inventing a VM
lease, and successful retries constructively reach Closed. -/
theorem failedVmStartCleanup_constructively_reachable
    {ledger : IdentityLedger} {identity : SessionIdentity}
    {workspace : WorkspaceLease} {broker : BrokerLease}
    (fresh : IdentityBatchFresh ledger identity)
    (workspaceBinding : workspace.Matches identity)
    (brokerBinding : broker.Matches identity) :
    ∃ retained closed,
      retained.Reachable ledger ∧
      retained.core.phase = .brokerEstablished ∧
      retained.core.WellFormed ∧ retained.stopping = true ∧
      retained.ownership.resources.workspace = some workspace ∧
      retained.ownership.resources.broker = some broker ∧
      retained.ownership.resources.vm = none ∧
      retained.ownership.vmStartAttempted = true ∧
      retained.cleanup.vmKilled = false ∧
      ManagedSteps retained closed ∧ closed.core.phase = .closed ∧
      closed.cleanup.Complete := by
  let initial := ManagedState.initial ledger
  let reserved : ManagedState :=
    { initial with core := reserveIdentities initial.core identity }
  let cloned : ManagedState :=
    { reserved with core := commitWorkspace reserved.core workspace }
  let brokered : ManagedState :=
    { cloned with core := commitBroker cloned.core broker }
  let retained := brokered.retainFailedStart
    (CleanupOwnership.failedVmStart brokered.core.resources)
  have reserveTransition : ManagedStep initial reserved := by
    apply ManagedStep.startup
    · rfl
    · apply Step.reserve
      · exact Or.inl rfl
      · exact fresh
  have workspaceTransition : ManagedStep reserved cloned := by
    apply ManagedStep.startup
    · simp [reserved, initial, ManagedState.initial]
    · apply @Step.workspace reserved.core identity workspace
      · simp [reserved, reserveIdentities]
      · simp [reserved, reserveIdentities]
      · exact workspaceBinding
  have brokerTransition : ManagedStep cloned brokered := by
    apply ManagedStep.startup
    · simp [cloned, reserved, initial, ManagedState.initial]
    · apply @Step.broker cloned.core identity broker
      · simp [cloned, commitWorkspace]
      · simp [cloned, reserved, commitWorkspace, reserveIdentities]
      · exact brokerBinding
  have retainTransition : ManagedStep brokered retained := by
    apply ManagedStep.retainFailedVmStart
    · simp [brokered, cloned, reserved, initial, ManagedState.initial]
    · simp [brokered, commitBroker]
  have retainedSteps : ManagedSteps initial retained :=
    ManagedSteps.tail
      (ManagedSteps.tail
        (ManagedSteps.tail (ManagedSteps.refl initial) reserveTransition)
        workspaceTransition)
      brokerTransition |>.tail retainTransition
  have reachable : retained.Reachable ledger := by
    simpa [initial] using retainedSteps
  have stopping : retained.stopping = true := by
    simp [retained, ManagedState.retainFailedStart]
  rcases stopping_reaches_closed stopping with
    ⟨closed, cleanupSteps, closedPhase, closedComplete, _⟩
  refine ⟨retained, closed, reachable, ?_, reachable.wellFormed.coreWellFormed,
    stopping, ?_, ?_, ?_, ?_, ?_, cleanupSteps, closedPhase, closedComplete⟩
  · simp [retained, brokered, cloned, ManagedState.retainFailedStart,
      commitBroker, commitWorkspace]
  · simp [retained, brokered, cloned, ManagedState.retainFailedStart,
      CleanupOwnership.failedVmStart, commitBroker, commitWorkspace]
  · simp [retained, brokered, ManagedState.retainFailedStart,
      cloned, reserved, CleanupOwnership.failedVmStart, commitBroker,
      commitWorkspace, reserveIdentities]
  · simp [retained, brokered, cloned, reserved,
      ManagedState.retainFailedStart, CleanupOwnership.failedVmStart,
      commitBroker, commitWorkspace, reserveIdentities, Resources.empty]
  · simp [retained, ManagedState.retainFailedStart,
      CleanupOwnership.failedVmStart]
  · simp [retained, brokered, ManagedState.retainFailedStart,
      CleanupOwnership.failedVmStart, CleanupState.forOwnership, commitBroker]

/-- An invalid Broker lease extends the exact valid workspace prefix and remains
owned until a cleanup-complete path closes the session. -/
theorem invalidBrokerCleanup_retains_and_reaches_closed
    {state : ManagedState} {identity : SessionIdentity} {broker : BrokerLease}
    (notStopping : state.stopping = false)
    (phase : state.core.phase = .workspaceCloned)
    (identityLookup : state.core.identity = some identity)
    (mismatch : ¬broker.Matches identity) :
    let retained := state.retainFailedStart
      (CleanupOwnership.invalidBroker state.core.resources broker)
    ManagedStep state retained ∧
      retained.ownership.resources =
        { state.core.resources with broker := some broker } ∧
      ∃ closed,
        ManagedSteps retained closed ∧ closed.core.phase = .closed ∧
        closed.cleanup.Complete := by
  dsimp
  have retainedTransition := ManagedStep.retainInvalidBroker
    notStopping phase identityLookup mismatch
  have stopping :
      (state.retainFailedStart
        (CleanupOwnership.invalidBroker state.core.resources broker)).stopping = true := by
    rfl
  rcases stopping_reaches_closed stopping with
    ⟨closed, cleanupSteps, closedPhase, closedComplete, _⟩
  exact ⟨retainedTransition, rfl, closed, cleanupSteps, closedPhase,
    closedComplete⟩

/-- An invalid VM lease extends the exact valid Broker prefix and remains owned
until a cleanup-complete path closes the session. -/
theorem invalidVmCleanup_retains_and_reaches_closed
    {state : ManagedState} {identity : SessionIdentity} {vm : VmLease}
    (notStopping : state.stopping = false)
    (phase : state.core.phase = .brokerEstablished)
    (identityLookup : state.core.identity = some identity)
    (mismatch : ¬vm.Matches identity) :
    let retained := state.retainFailedStart
      (CleanupOwnership.invalidVm state.core.resources vm)
    ManagedStep state retained ∧
      retained.ownership.resources = { state.core.resources with vm := some vm } ∧
      ∃ closed,
        ManagedSteps retained closed ∧ closed.core.phase = .closed ∧
        closed.cleanup.Complete := by
  dsimp
  have retainedTransition := ManagedStep.retainInvalidVm
    notStopping phase identityLookup mismatch
  have stopping :
      (state.retainFailedStart
        (CleanupOwnership.invalidVm state.core.resources vm)).stopping = true := by
    rfl
  rcases stopping_reaches_closed stopping with
    ⟨closed, cleanupSteps, closedPhase, closedComplete, _⟩
  exact ⟨retainedTransition, rfl, closed, cleanupSteps, closedPhase,
    closedComplete⟩

/-- An invalid capability lease extends the exact valid VM prefix and remains
owned until a cleanup-complete path closes the session. -/
theorem invalidCapabilityCleanup_retains_and_reaches_closed
    {state : ManagedState} {identity : SessionIdentity}
    {capability : CapabilityLease}
    (notStopping : state.stopping = false)
    (phase : state.core.phase = .vmStarted)
    (identityLookup : state.core.identity = some identity)
    (mismatch : ¬capability.Matches identity) :
    let retained := state.retainFailedStart
      (CleanupOwnership.invalidCapability state.core.resources capability)
    ManagedStep state retained ∧
      retained.ownership.resources =
        { state.core.resources with capability := some capability } ∧
      ∃ closed,
        ManagedSteps retained closed ∧ closed.core.phase = .closed ∧
        closed.cleanup.Complete := by
  dsimp
  have retainedTransition := ManagedStep.retainInvalidCapability
    notStopping phase identityLookup mismatch
  have stopping :
      (state.retainFailedStart
        (CleanupOwnership.invalidCapability state.core.resources capability)).stopping = true := by
    rfl
  rcases stopping_reaches_closed stopping with
    ⟨closed, cleanupSteps, closedPhase, closedComplete, _⟩
  exact ⟨retainedTransition, rfl, closed, cleanupSteps, closedPhase,
    closedComplete⟩

/-- Every committed startup prefix, including Running, has a finite path to Closed. -/
theorem cleanupEligible_reaches_closed {state : ManagedState}
    (notStopping : state.stopping = false)
    (eligible : state.core.phase.CleanupEligible) :
    ∃ closed,
      ManagedSteps state closed ∧ closed.core.phase = .closed ∧
      closed.cleanup.Complete := by
  let stopping := state.beginStop
  have beginTransition : ManagedStep state stopping :=
    ManagedStep.beginStop notStopping eligible
  have began : ManagedSteps state stopping :=
    ManagedSteps.tail (ManagedSteps.refl state) beginTransition
  have stoppingActive : stopping.stopping = true := by
    simp [stopping, ManagedState.beginStop]
  rcases stopping_reaches_closed stoppingActive with
    ⟨closed, cleanupSteps, closedPhase, complete, _⟩
  exact ⟨closed, began.trans cleanupSteps, closedPhase, complete⟩

end Orchestrator

end Authority
