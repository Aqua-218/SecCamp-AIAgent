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

/-- Cleanup starts complete for resources that a failed startup never acquired. -/
def CleanupState.forResources (resources : Resources) : CleanupState where
  capabilityRevoked := resources.capability.isNone
  vmKilled := resources.vm.isNone
  brokerClosed := resources.broker.isNone
  workspaceIsolated := resources.workspace.isNone

/-- All cleanup dependencies have committed. -/
def CleanupState.Complete (state : CleanupState) : Prop :=
  state.capabilityRevoked = true ∧ state.vmKilled = true ∧
    state.brokerClosed = true ∧ state.workspaceIsolated = true

/-- Every absent resource is already accounted for by cleanup progress. -/
def CleanupState.CoversAbsentResources (state : CleanupState)
    (resources : Resources) : Prop :=
  (resources.capability = none → state.capabilityRevoked = true) ∧
  (resources.vm = none → state.vmKilled = true) ∧
  (resources.broker = none → state.brokerClosed = true) ∧
  (resources.workspace = none → state.workspaceIsolated = true)

/-- Resource-derived cleanup progress accounts for every unacquired stage. -/
theorem CleanupState.forResources_coversAbsentResources (resources : Resources) :
    (CleanupState.forResources resources).CoversAbsentResources resources := by
  cases resources with
  | mk workspace broker vm capability workload =>
      cases workspace <;> cases broker <;> cases vm <;> cases capability <;>
        simp [CleanupState.forResources, CleanupState.CoversAbsentResources]

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

/-- Cleanup retries preserve the accounting for resources absent at startup failure. -/
theorem CleanupStep.preserves_coversAbsentResources {before after : CleanupState}
    {resources : Resources} (transition : CleanupStep before after)
    (covers : before.CoversAbsentResources resources) :
    after.CoversAbsentResources resources := by
  rcases transition.flags_monotone with ⟨capability, vm, broker, workspace⟩
  rcases covers with ⟨capabilityAbsent, vmAbsent, brokerAbsent, workspaceAbsent⟩
  exact ⟨fun absent => capability (capabilityAbsent absent),
    fun absent => vm (vmAbsent absent),
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

/-- Initial managed session has no active cleanup transaction. -/
def ManagedState.initial (ledger : IdentityLedger) : ManagedState where
  core := State.initial ledger
  stopping := false
  cleanup := .pending

/-- Enter retryable cleanup while retaining a normal or partial startup resource chain. -/
def ManagedState.beginStop (state : ManagedState) : ManagedState :=
  { state with
    stopping := true
    cleanup := CleanupState.forResources state.core.resources }

/-- Commit one successful cleanup action without discarding resource leases. -/
def ManagedState.recordCleanup (state : ManagedState)
    (cleanup : CleanupState) : ManagedState :=
  { state with cleanup := cleanup }

/-- Publish Closed only after all cleanup dependencies have committed. -/
def ManagedState.finishStop (state : ManagedState) : ManagedState :=
  { core := markClosed state.core, stopping := false, cleanup := state.cleanup }

/-- Core bindings, Closed gating, and partial-start cleanup accounting agree. -/
structure ManagedState.WellFormed (state : ManagedState) : Prop where
  coreWellFormed : state.core.WellFormed
  closedRequiresCleanup : state.core.phase = .closed → state.cleanup.Complete
  stoppingRetainsCleanupPrefix :
    state.stopping = true → state.core.phase.CleanupEligible
  stoppingCoversAbsentResources :
    state.stopping = true →
      state.cleanup.CoversAbsentResources state.core.resources

/-- The initial managed state satisfies lifecycle/cleanup coupling. -/
theorem ManagedState.initial_wellFormed (ledger : IdentityLedger) :
    (ManagedState.initial ledger).WellFormed := by
  constructor
  · exact State.initial_wellFormed ledger
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
  | cleanup {state : ManagedState} {cleanup : CleanupState} :
      state.stopping = true → CleanupStep state.cleanup cleanup →
      ManagedStep state (state.recordCleanup cleanup)
  | finishStop {state : ManagedState} :
      state.stopping = true → state.cleanup.Complete →
      ManagedStep state state.finishStop

/-- Lifecycle/cleanup coupling is inductive across every accepted managed step. -/
theorem ManagedStep.preserves_wellFormed {before after : ManagedState}
    (transition : ManagedStep before after) (wellFormed : before.WellFormed) :
    after.WellFormed := by
  cases transition with
  | startup notStopping startupStep =>
      constructor
      · exact startupStep.preserves_wellFormed wellFormed.coreWellFormed
      · intro closed
        exact False.elim (startupStep.after_ne_closed closed)
      · intro impossible
        simp [notStopping] at impossible
      · intro impossible
        simp [notStopping] at impossible
  | beginStop notStopping eligible =>
      exact ⟨wellFormed.coreWellFormed,
        fun closed => False.elim (by
          change before.core.phase = .closed at closed
          exact eligible.ne_closed closed),
        fun _ => eligible,
        fun _ => by
          simpa [ManagedState.beginStop] using
            CleanupState.forResources_coversAbsentResources before.core.resources⟩
  | cleanup stopping cleanupStep =>
      exact ⟨wellFormed.coreWellFormed,
        fun closed => False.elim (by
          have eligible := wellFormed.stoppingRetainsCleanupPrefix stopping
          change before.core.phase = .closed at closed
          exact eligible.ne_closed closed),
        fun _ => wellFormed.stoppingRetainsCleanupPrefix stopping,
        fun _ => cleanupStep.preserves_coversAbsentResources
          (wellFormed.stoppingCoversAbsentResources stopping)⟩
  | finishStop stopping complete =>
      constructor
      · simp [ManagedState.finishStop, markClosed, State.WellFormed,
          Resources.empty]
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

/-- Every committed startup prefix, including Running, has a finite path to Closed. -/
theorem cleanupEligible_reaches_closed {state : ManagedState}
    (notStopping : state.stopping = false)
    (eligible : state.core.phase.CleanupEligible) :
    ∃ closed,
      ManagedSteps state closed ∧ closed.core.phase = .closed ∧
      closed.cleanup.Complete := by
  let stopping := state.beginStop
  let revoked := stopping.recordCleanup stopping.cleanup.revokeCapability
  let killed := revoked.recordCleanup revoked.cleanup.killVm
  let brokerClosed := killed.recordCleanup killed.cleanup.closeBroker
  let workspaceIsolated :=
    brokerClosed.recordCleanup brokerClosed.cleanup.isolateWorkspace
  let closed := workspaceIsolated.finishStop
  have beginTransition : ManagedStep state stopping :=
    ManagedStep.beginStop notStopping eligible
  have revokeTransition : ManagedStep stopping revoked := by
    apply ManagedStep.cleanup
    · simp [stopping, ManagedState.beginStop]
    · exact CleanupStep.revokeCapability
  have killTransition : ManagedStep revoked killed := by
    apply ManagedStep.cleanup
    · simp [revoked, stopping, ManagedState.recordCleanup,
        ManagedState.beginStop]
    · exact CleanupStep.killVm
  have brokerTransition : ManagedStep killed brokerClosed := by
    apply ManagedStep.cleanup
    · simp [killed, revoked, stopping, ManagedState.recordCleanup,
        ManagedState.beginStop]
    · exact CleanupStep.closeBroker
  have workspaceTransition : ManagedStep brokerClosed workspaceIsolated := by
    apply ManagedStep.cleanup
    · simp [brokerClosed, killed, revoked, stopping,
        ManagedState.recordCleanup, ManagedState.beginStop]
    · apply CleanupStep.isolateWorkspace
      · simp [brokerClosed, killed, revoked, stopping,
          ManagedState.recordCleanup, ManagedState.beginStop,
          CleanupState.revokeCapability, CleanupState.killVm,
          CleanupState.closeBroker]
      · simp [brokerClosed, killed, revoked, stopping,
          ManagedState.recordCleanup, ManagedState.beginStop,
          CleanupState.revokeCapability, CleanupState.killVm,
          CleanupState.closeBroker]
  have complete : workspaceIsolated.cleanup.Complete := by
    simp [workspaceIsolated, brokerClosed, killed, revoked, stopping,
      ManagedState.recordCleanup, ManagedState.beginStop,
      CleanupState.Complete, CleanupState.revokeCapability,
      CleanupState.killVm, CleanupState.closeBroker,
      CleanupState.isolateWorkspace]
  have finishTransition : ManagedStep workspaceIsolated closed := by
    apply ManagedStep.finishStop
    · simp [workspaceIsolated, brokerClosed, killed, revoked, stopping,
        ManagedState.recordCleanup, ManagedState.beginStop]
    · exact complete
  have began : ManagedSteps state stopping :=
    ManagedSteps.tail (ManagedSteps.refl state) beginTransition
  have revokedSteps : ManagedSteps state revoked :=
    ManagedSteps.tail began revokeTransition
  have killedSteps : ManagedSteps state killed :=
    ManagedSteps.tail revokedSteps killTransition
  have brokerSteps : ManagedSteps state brokerClosed :=
    ManagedSteps.tail killedSteps brokerTransition
  have isolatedSteps : ManagedSteps state workspaceIsolated :=
    ManagedSteps.tail brokerSteps workspaceTransition
  refine ⟨closed, ?_, ?_, ?_⟩
  · exact ManagedSteps.tail isolatedSteps finishTransition
  · simp [closed, ManagedState.finishStop, markClosed]
  · simpa [closed, ManagedState.finishStop] using complete

end Orchestrator

end Authority
