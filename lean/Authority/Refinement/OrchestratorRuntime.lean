import Authority.Orchestrator

/-!
# Session Owner Runtime Refinement

A logical refinement of the synchronous Rust `SessionOwner` and its exclusively
owned Broker worker.  The checker validates supplied Lean observations; it does
not claim that a Rust process emitted them or that platform side effects ran.
-/

namespace Authority.Refinement.OrchestratorRuntime

open Authority.Orchestrator

abbrev ModelState := ManagedState

/-- The only observation schema accepted by this checker. -/
def schemaVersion : Nat := 1

/-- Typed terminal reasons corresponding to the owned Rust Broker worker. -/
inductive BrokerWorkerExit where
  | cancelled
  | connectionClosed
  | acceptFailed
  | unexpectedPeer
  | shutdownHandleFailed
  | panicked
  | exitChannelLost
  deriving Repr, BEq, DecidableEq

/-- Runtime ownership state for one exact Broker worker lease. -/
inductive BrokerWorker where
  | absent
  | bound (lease : BrokerLease)
  | running (lease : BrokerLease)
  | exited (lease : BrokerLease) (reason : BrokerWorkerExit)
  | cancelling (lease : BrokerLease) (reason : BrokerWorkerExit)
  | joined (lease : BrokerLease) (reason : BrokerWorkerExit)
  deriving DecidableEq

namespace BrokerWorker

/-- A running, exited, or already-cancelling worker can enter the join path. -/
inductive MayCancel : BrokerWorker → BrokerLease → BrokerWorkerExit → Prop
  | running {lease : BrokerLease} : MayCancel (.running lease) lease .cancelled
  | exited {lease : BrokerLease} {reason : BrokerWorkerExit} :
      MayCancel (.exited lease reason) lease reason
  | cancelling {lease : BrokerLease} {reason : BrokerWorkerExit} :
      MayCancel (.cancelling lease reason) lease reason

/-- A worker is terminal only after its exact join completed or when absent. -/
def Terminal : BrokerWorker → Prop
  | .absent | .joined _ _ => True
  | .bound _ | .running _ | .exited _ _ | .cancelling _ _ => False

end BrokerWorker

/-- Stable reason retained by the owner across cleanup retries. -/
inductive ShutdownReason where
  | externalRequest
  | brokerExited (exit : BrokerWorkerExit)
  | brokerStatusUnavailable
  | startupRollback
  deriving Repr, DecidableEq

/-- Runtime state layered over the existing pure managed orchestrator. -/
structure RuntimeState where
  managed : ModelState
  worker : BrokerWorker
  vmPaused : Bool
  workloadReleased : Bool
  shutdownReason : Option ShutdownReason

namespace RuntimeState

/-- Fresh runtime state with no backend or worker ownership. -/
def initial (ledger : IdentityLedger) : RuntimeState where
  managed := .initial ledger
  worker := .absent
  vmPaused := false
  workloadReleased := false
  shutdownReason := none

/-- Replace only the abstract managed-state projection. -/
def withManaged (state : RuntimeState) (managed : ModelState) : RuntimeState :=
  { state with managed := managed }

/-- Begin owner cleanup without discarding any runtime handle. -/
def beginShutdown (state : RuntimeState) (reason : ShutdownReason)
    (worker : BrokerWorker := state.worker) : RuntimeState :=
  { state with
    managed := state.managed.beginStop
    worker := worker
    shutdownReason := some reason }

/-- Commit one abstract cleanup flag while preserving all leases and handles. -/
def recordCleanup (state : RuntimeState) (cleanup : CleanupState) : RuntimeState :=
  { state with managed := state.managed.recordCleanup cleanup }

/-- Publish closed only after cleanup and worker termination have completed. -/
def finishClosed (state : RuntimeState) : RuntimeState :=
  { state with
    managed := state.managed.finishStop
    vmPaused := false
    workloadReleased := false }

/-- Exact active or retained Broker ownership exposed by the orchestrator. -/
def OwnsBroker (state : RuntimeState) (lease : BrokerLease) : Prop :=
  state.managed.core.resources.broker = some lease ∨
    state.managed.ownership.resources.broker = some lease

end RuntimeState

/-- Closed inventory of owner/runtime transition labels. -/
inductive Label where
  | reserveIdentities (identity : SessionIdentity)
  | workspaceCloned (workspace : WorkspaceLease)
  | brokerBound (broker : BrokerLease)
  | workerRunning (broker : BrokerLease)
  | pausedVmStarted (vm : VmLease)
  | rootCapabilityInjected (capability : CapabilityLease)
  | workloadReleased (workload : WorkloadLease)
  | runningPublished
  | externalStop (broker : BrokerLease)
  | unexpectedBrokerExit (broker : BrokerLease) (exit : BrokerWorkerExit)
  | brokerStatusUnavailable (broker : BrokerLease)
  | capabilityRevoked
  | vmKilled
  | brokerCancelledAndJoined (broker : BrokerLease) (exit : BrokerWorkerExit)
  | brokerJoinTimeout (broker : BrokerLease) (exit : BrokerWorkerExit)
  | cleanupError
  | workspaceIsolated
  | closedPublished
  | foreignLeaseIgnored (foreign : BrokerLease)
  | foreignExitIgnored (foreign : BrokerLease) (exit : BrokerWorkerExit)
  deriving DecidableEq

/-- Observable result class for one owner/runtime event. -/
inductive Outcome where
  | accepted
  | retryableFailure
  | ignoredForeign
  deriving Repr, BEq, DecidableEq

namespace Label

/-- Result class fixed by the closed label inventory. -/
def expectedOutcome : Label → Outcome
  | .brokerJoinTimeout _ _ | .cleanupError => .retryableFailure
  | .foreignLeaseIgnored _ | .foreignExitIgnored _ _ => .ignoredForeign
  | .reserveIdentities _ | .workspaceCloned _ | .brokerBound _ |
      .workerRunning _ | .pausedVmStarted _ | .rootCapabilityInjected _ |
      .workloadReleased _ | .runningPublished | .externalStop _ |
      .unexpectedBrokerExit _ _ | .brokerStatusUnavailable _ |
      .capabilityRevoked | .vmKilled | .brokerCancelledAndJoined _ _ |
      .workspaceIsolated | .closedPublished => .accepted

end Label

/-- Strong runtime transitions with an explicit abstract orchestrator projection. -/
inductive Step : Label → RuntimeState → RuntimeState → Prop
  | reserve {state : RuntimeState} {identity : SessionIdentity}
      (notStopping : state.managed.stopping = false)
      (phase : state.managed.core.phase = .ready ∨
        state.managed.core.phase = .closed)
      (fresh : IdentityBatchFresh state.managed.core.ledger identity) :
      Step (.reserveIdentities identity) state
        (state.withManaged { state.managed with
          core := reserveIdentities state.managed.core identity })
  | workspace {state : RuntimeState} {identity : SessionIdentity}
      {workspace : WorkspaceLease}
      (notStopping : state.managed.stopping = false)
      (phase : state.managed.core.phase = .identitiesReserved)
      (identityLookup : state.managed.core.identity = some identity)
      (binding : workspace.Matches identity) :
      Step (.workspaceCloned workspace) state
        (state.withManaged { state.managed with
          core := commitWorkspace state.managed.core workspace })
  | brokerBound {state : RuntimeState} {identity : SessionIdentity}
      {broker : BrokerLease}
      (notStopping : state.managed.stopping = false)
      (phase : state.managed.core.phase = .workspaceCloned)
      (identityLookup : state.managed.core.identity = some identity)
      (binding : broker.Matches identity)
      (noWorker : state.worker = .absent) :
      Step (.brokerBound broker) state
        { state with
          managed := { state.managed with core := commitBroker state.managed.core broker }
          worker := .bound broker }
  | workerRunning {state : RuntimeState} {broker : BrokerLease}
      (bound : state.worker = .bound broker)
      (owned : state.managed.core.resources.broker = some broker) :
      Step (.workerRunning broker) state { state with worker := .running broker }
  | pausedVmStarted {state : RuntimeState} {identity : SessionIdentity}
      {broker : BrokerLease} {vm : VmLease}
      (notStopping : state.managed.stopping = false)
      (phase : state.managed.core.phase = .brokerEstablished)
      (identityLookup : state.managed.core.identity = some identity)
      (binding : vm.Matches identity)
      (brokerLookup : state.managed.core.resources.broker = some broker)
      (running : state.worker = .running broker) :
      Step (.pausedVmStarted vm) state
        { state with
          managed := { state.managed with core := commitVm state.managed.core vm }
          vmPaused := true }
  | capabilityInjected {state : RuntimeState} {identity : SessionIdentity}
      {broker : BrokerLease} {capability : CapabilityLease}
      (notStopping : state.managed.stopping = false)
      (phase : state.managed.core.phase = .vmStarted)
      (identityLookup : state.managed.core.identity = some identity)
      (binding : capability.Matches identity)
      (brokerLookup : state.managed.core.resources.broker = some broker)
      (running : state.worker = .running broker)
      (paused : state.vmPaused = true)
      (notReleased : state.workloadReleased = false) :
      Step (.rootCapabilityInjected capability) state
        (state.withManaged { state.managed with
          core := commitCapability state.managed.core capability })
  | workloadReleased {state : RuntimeState} {identity : SessionIdentity}
      {broker : BrokerLease} {workload : WorkloadLease}
      (notStopping : state.managed.stopping = false)
      (phase : state.managed.core.phase = .rootCapabilityInjected)
      (identityLookup : state.managed.core.identity = some identity)
      (binding : workload.Matches identity)
      (brokerLookup : state.managed.core.resources.broker = some broker)
      (running : state.worker = .running broker)
      (paused : state.vmPaused = true) :
      Step (.workloadReleased workload) state
        { state with
          managed := { state.managed with core := commitWorkload state.managed.core workload }
          vmPaused := false
          workloadReleased := true }
  | runningPublished {state : RuntimeState} {broker : BrokerLease}
      (notStopping : state.managed.stopping = false)
      (phase : state.managed.core.phase = .workloadReleased)
      (brokerLookup : state.managed.core.resources.broker = some broker)
      (running : state.worker = .running broker)
      (released : state.workloadReleased = true) :
      Step .runningPublished state
        (state.withManaged { state.managed with core := markRunning state.managed.core })
  | externalStop {state : RuntimeState} {broker : BrokerLease}
      (notStopping : state.managed.stopping = false)
      (runningPhase : state.managed.core.phase = .running)
      (brokerLookup : state.managed.core.resources.broker = some broker)
      (workerRunning : state.worker = .running broker) :
      Step (.externalStop broker) state
        (state.beginShutdown .externalRequest)
  | unexpectedExit {state : RuntimeState} {broker : BrokerLease}
      {exit : BrokerWorkerExit}
      (notStopping : state.managed.stopping = false)
      (runningPhase : state.managed.core.phase = .running)
      (brokerLookup : state.managed.core.resources.broker = some broker)
      (workerRunning : state.worker = .running broker) :
      Step (.unexpectedBrokerExit broker exit) state
        (state.beginShutdown (.brokerExited exit) (.exited broker exit))
  | statusUnavailable {state : RuntimeState} {broker : BrokerLease}
      (notStopping : state.managed.stopping = false)
      (runningPhase : state.managed.core.phase = .running)
      (brokerLookup : state.managed.core.resources.broker = some broker)
      (workerRunning : state.worker = .running broker) :
      Step (.brokerStatusUnavailable broker) state
        (state.beginShutdown .brokerStatusUnavailable)
  | capabilityRevoked {state : RuntimeState}
      (stopping : state.managed.stopping = true) :
      Step .capabilityRevoked state
        (state.recordCleanup state.managed.cleanup.revokeCapability)
  | vmKilled {state : RuntimeState}
      (stopping : state.managed.stopping = true)
      (revoked : state.managed.cleanup.capabilityRevoked = true) :
      Step .vmKilled state (state.recordCleanup state.managed.cleanup.killVm)
  | brokerJoined {state : RuntimeState} {broker : BrokerLease}
      {exit : BrokerWorkerExit}
      (stopping : state.managed.stopping = true)
      (killed : state.managed.cleanup.vmKilled = true)
      (owned : state.managed.ownership.resources.broker = some broker)
      (joinable : state.worker.MayCancel broker exit) :
      Step (.brokerCancelledAndJoined broker exit) state
        { state.recordCleanup state.managed.cleanup.closeBroker with
          worker := .joined broker exit }
  | brokerJoinTimeout {state : RuntimeState} {broker : BrokerLease}
      {exit : BrokerWorkerExit}
      (stopping : state.managed.stopping = true)
      (killed : state.managed.cleanup.vmKilled = true)
      (owned : state.managed.ownership.resources.broker = some broker)
      (joinable : state.worker.MayCancel broker exit) :
      Step (.brokerJoinTimeout broker exit) state
        { state with worker := .cancelling broker exit }
  | cleanupError {state : RuntimeState}
      (stopping : state.managed.stopping = true) :
      Step .cleanupError state state
  | workspaceIsolated {state : RuntimeState}
      (stopping : state.managed.stopping = true)
      (killed : state.managed.cleanup.vmKilled = true)
      (closed : state.managed.cleanup.brokerClosed = true)
      (workerTerminal : state.worker.Terminal) :
      Step .workspaceIsolated state
        (state.recordCleanup state.managed.cleanup.isolateWorkspace)
  | closedPublished {state : RuntimeState}
      (stopping : state.managed.stopping = true)
      (complete : state.managed.cleanup.Complete)
      (workerTerminal : state.worker.Terminal) :
      Step .closedPublished state state.finishClosed
  | foreignLeaseIgnored {state : RuntimeState} {owned foreign : BrokerLease}
      (ownedLookup : state.OwnsBroker owned) (different : foreign ≠ owned) :
      Step (.foreignLeaseIgnored foreign) state state
  | foreignExitIgnored {state : RuntimeState} {owned foreign : BrokerLease}
      {exit : BrokerWorkerExit}
      (ownedLookup : state.OwnsBroker owned) (different : foreign ≠ owned) :
      Step (.foreignExitIgnored foreign exit) state state

/-- Every runtime transition projects to existing managed orchestration steps. -/
theorem Step.forwardSimulation {label : Label} {before after : RuntimeState}
    (transition : Step label before after) :
    ManagedSteps before.managed after.managed := by
  cases transition with
  | reserve notStopping phase fresh =>
      exact .tail (.refl _) (.startup notStopping (.reserve phase fresh))
  | workspace notStopping phase identityLookup binding =>
      exact .tail (.refl _)
        (.startup notStopping (.workspace phase identityLookup binding))
  | brokerBound notStopping phase identityLookup binding noWorker =>
      exact .tail (.refl _)
        (.startup notStopping (.broker phase identityLookup binding))
  | workerRunning | foreignLeaseIgnored | foreignExitIgnored => exact .refl _
  | pausedVmStarted notStopping phase identityLookup binding brokerLookup running =>
      exact .tail (.refl _) (.startup notStopping (.vm phase identityLookup binding))
  | capabilityInjected notStopping phase identityLookup binding brokerLookup running paused notReleased =>
      exact .tail (.refl _)
        (.startup notStopping (.capability phase identityLookup binding))
  | workloadReleased notStopping phase identityLookup binding brokerLookup running paused =>
      exact .tail (.refl _)
        (.startup notStopping (.workload phase identityLookup binding))
  | runningPublished notStopping phase brokerLookup running released =>
      exact .tail (.refl _) (.startup notStopping (.running phase))
  | externalStop notStopping runningPhase brokerLookup workerRunning
  | unexpectedExit notStopping runningPhase brokerLookup workerRunning
  | statusUnavailable notStopping runningPhase brokerLookup workerRunning =>
      exact .tail (.refl _) (.beginStop notStopping (by
        rw [runningPhase]
        trivial))
  | capabilityRevoked stopping =>
      exact .tail (.refl _) (.cleanup stopping .revokeCapability)
  | vmKilled stopping revoked =>
      exact .tail (.refl _) (.cleanup stopping .killVm)
  | brokerJoined stopping killed owned joinable =>
      exact .tail (.refl _) (.cleanup stopping .closeBroker)
  | brokerJoinTimeout stopping killed owned joinable
  | cleanupError stopping =>
      exact .tail (.refl _) (.cleanupFailure stopping)
  | workspaceIsolated stopping killed closed terminal =>
      exact .tail (.refl _) (.cleanup stopping (.isolateWorkspace killed closed))
  | closedPublished stopping complete terminal =>
      exact .tail (.refl _) (.finishStop stopping complete)

/-- Runtime transitions preserve the existing lifecycle/cleanup invariant. -/
theorem Step.preserves_managedWellFormed {label : Label}
    {before after : RuntimeState} (transition : Step label before after)
    (wellFormed : before.managed.WellFormed) : after.managed.WellFormed :=
  transition.forwardSimulation.preserves_wellFormed wellFormed

/-- The running gate is an explicit prerequisite of paused VM startup. -/
theorem paused_vm_requires_running_worker {state after : RuntimeState}
    {vm : VmLease} (transition : Step (.pausedVmStarted vm) state after) :
    ∃ broker, state.worker = .running broker ∧
      state.managed.core.resources.broker = some broker := by
  cases transition with
  | pausedVmStarted _ _ _ _ brokerLookup running => exact ⟨_, running, brokerLookup⟩

/-- Capability injection occurs while the VM remains paused. -/
theorem capability_injection_requires_paused_vm {state after : RuntimeState}
    {capability : CapabilityLease}
    (transition : Step (.rootCapabilityInjected capability) state after) :
    state.vmPaused = true ∧ state.workloadReleased = false := by
  cases transition with
  | capabilityInjected _ _ _ _ _ _ paused notReleased => exact ⟨paused, notReleased⟩

/-- Workload release requires both a running exact worker and a paused VM. -/
theorem workload_release_requires_gates {state after : RuntimeState}
    {workload : WorkloadLease}
    (transition : Step (.workloadReleased workload) state after) :
    ∃ broker, state.worker = .running broker ∧ state.vmPaused = true := by
  cases transition with
  | workloadReleased _ _ _ _ _ running paused => exact ⟨_, running, paused⟩

/-- Join timeout retains exact abstract ownership for a later retry. -/
theorem join_timeout_retains_ownership {before after : RuntimeState}
    {broker : BrokerLease} {exit : BrokerWorkerExit}
    (transition : Step (.brokerJoinTimeout broker exit) before after) :
    after.managed = before.managed ∧
      after.managed.ownership.resources.broker = some broker ∧
      after.worker = .cancelling broker exit := by
  cases transition with
  | brokerJoinTimeout _ _ owned _ => exact ⟨rfl, owned, rfl⟩

/-- A generic cleanup error retains every ownership and progress field. -/
theorem cleanup_error_is_retryable {before after : RuntimeState}
    (transition : Step .cleanupError before after) : after = before := by
  cases transition
  rfl

/-- Foreign lease observations and foreign typed exits are exact no-ops. -/
theorem foreign_observation_is_noop {label : Label} {before after : RuntimeState}
    (foreign : (∃ lease, label = .foreignLeaseIgnored lease) ∨
      ∃ lease exit, label = .foreignExitIgnored lease exit)
    (transition : Step label before after) : after = before := by
  rcases foreign with ⟨lease, rfl⟩ | ⟨lease, exit, rfl⟩ <;>
    cases transition <;> rfl

/-- Finite runtime execution. -/
inductive Steps : RuntimeState → RuntimeState → Prop
  | refl (state : RuntimeState) : Steps state state
  | tail {first middle last : RuntimeState} {label : Label} :
      Steps first middle → Step label middle last → Steps first last

/-- Every finite runtime trace forward-simulates the existing managed model. -/
theorem Steps.forwardSimulation {before after : RuntimeState}
    (transitions : Steps before after) : ManagedSteps before.managed after.managed := by
  induction transitions with
  | refl => exact .refl _
  | tail earlier transition inductionHypothesis =>
      exact inductionHypothesis.trans transition.forwardSimulation

/-- Arbitrary runtime traces preserve lifecycle and cleanup well-formedness. -/
theorem Steps.preserves_managedWellFormed {before after : RuntimeState}
    (transitions : Steps before after) (wellFormed : before.managed.WellFormed) :
    after.managed.WellFormed :=
  transitions.forwardSimulation.preserves_wellFormed wellFormed

/-- Durable identity reservations survive arbitrary runtime activity. -/
theorem Steps.ledger_monotone {before after : RuntimeState}
    (transitions : Steps before after) {identity : OrchestrationId}
    (issued : before.managed.core.ledger identity = true) :
    after.managed.core.ledger identity = true := by
  induction transitions with
  | refl => exact issued
  | tail earlier transition inductionHypothesis =>
      cases transition with
      | reserve notStopping phase fresh =>
          exact reserveBatch_preserves_issued _ _ inductionHypothesis
      | workspace | brokerBound | workerRunning | pausedVmStarted |
          capabilityInjected | workloadReleased | runningPublished | externalStop |
          unexpectedExit | statusUnavailable | capabilityRevoked | vmKilled |
          brokerJoined | brokerJoinTimeout | cleanupError | workspaceIsolated |
          foreignLeaseIgnored | foreignExitIgnored => exact inductionHypothesis
      | closedPublished => exact inductionHypothesis

/-- Versioned observation of runtime and abstract cleanup projections. -/
structure StateSnapshot where
  schemaVersion : Nat
  model : RuntimeState
  phase : LifecyclePhase
  stopping : Bool
  worker : BrokerWorker
  vmPaused : Bool
  workloadReleased : Bool
  shutdownReason : Option ShutdownReason
  capabilityRevoked : Bool
  vmKilled : Bool
  brokerClosed : Bool
  workspaceIsolated : Bool

namespace StateSnapshot

/-- Exact consistency of finite observed fields with the supplied logical model. -/
def Consistent (snapshot : StateSnapshot) : Prop :=
  snapshot.schemaVersion = Authority.Refinement.OrchestratorRuntime.schemaVersion ∧
    snapshot.phase = snapshot.model.managed.core.phase ∧
    snapshot.stopping = snapshot.model.managed.stopping ∧
    snapshot.worker = snapshot.model.worker ∧
    snapshot.vmPaused = snapshot.model.vmPaused ∧
    snapshot.workloadReleased = snapshot.model.workloadReleased ∧
    snapshot.shutdownReason = snapshot.model.shutdownReason ∧
    snapshot.capabilityRevoked = snapshot.model.managed.cleanup.capabilityRevoked ∧
    snapshot.vmKilled = snapshot.model.managed.cleanup.vmKilled ∧
    snapshot.brokerClosed = snapshot.model.managed.cleanup.brokerClosed ∧
    snapshot.workspaceIsolated = snapshot.model.managed.cleanup.workspaceIsolated

/-- Denotation of a validated logical runtime snapshot. -/
def Denotes (snapshot : StateSnapshot) (state : RuntimeState) : Prop :=
  snapshot.model = state ∧ snapshot.Consistent

/-- Canonical current-version snapshot. -/
def ofState (state : RuntimeState) : StateSnapshot where
  schemaVersion := Authority.Refinement.OrchestratorRuntime.schemaVersion
  model := state
  phase := state.managed.core.phase
  stopping := state.managed.stopping
  worker := state.worker
  vmPaused := state.vmPaused
  workloadReleased := state.workloadReleased
  shutdownReason := state.shutdownReason
  capabilityRevoked := state.managed.cleanup.capabilityRevoked
  vmKilled := state.managed.cleanup.vmKilled
  brokerClosed := state.managed.cleanup.brokerClosed
  workspaceIsolated := state.managed.cleanup.workspaceIsolated

/-- Constructive decision procedure for finite snapshot consistency. -/
def consistentDecidable (snapshot : StateSnapshot) : Decidable snapshot.Consistent := by
  unfold Consistent
  infer_instance

/-- Executable snapshot validator. -/
def validate (snapshot : StateSnapshot) : Bool :=
  @decide snapshot.Consistent (consistentDecidable snapshot)

theorem validate_sound {snapshot : StateSnapshot}
    (valid : snapshot.validate = true) : snapshot.Denotes snapshot.model := by
  refine ⟨rfl, ?_⟩
  unfold validate at valid
  exact @of_decide_eq_true _ (consistentDecidable snapshot) valid

theorem validate_ofState (state : RuntimeState) : (ofState state).validate = true := by
  simp [validate, consistentDecidable, Consistent, ofState]

theorem ofState_denotes (state : RuntimeState) : (ofState state).Denotes state := by
  simp [Denotes, Consistent, ofState]

end StateSnapshot

/-- One labeled versioned owner/runtime observation. -/
structure Event where
  schemaVersion : Nat
  label : Label
  outcome : Outcome
  observedPhase : LifecyclePhase
  observedWorker : BrokerWorker
  observedShutdownReason : Option ShutdownReason

namespace Event

/-- Exact finite meaning of redundant event fields at its post-state. -/
def Shape (event : Event) (after : RuntimeState) : Prop :=
  event.schemaVersion = Authority.Refinement.OrchestratorRuntime.schemaVersion ∧
    event.outcome = event.label.expectedOutcome ∧
    event.observedPhase = after.managed.core.phase ∧
    event.observedWorker = after.worker ∧
    event.observedShutdownReason = after.shutdownReason

/-- Canonical event projection from one transition result. -/
def ofState (label : Label) (after : RuntimeState) : Event where
  schemaVersion := Authority.Refinement.OrchestratorRuntime.schemaVersion
  label := label
  outcome := label.expectedOutcome
  observedPhase := after.managed.core.phase
  observedWorker := after.worker
  observedShutdownReason := after.shutdownReason

def shapeDecidable (event : Event) (after : RuntimeState) :
    Decidable (event.Shape after) := by
  unfold Shape
  infer_instance

/-- Executable event projection validator. -/
def validateAt (event : Event) (after : RuntimeState) : Bool :=
  @decide (event.Shape after) (shapeDecidable event after)

theorem validateAt_sound {event : Event} {after : RuntimeState}
    (valid : event.validateAt after = true) : event.Shape after := by
  unfold validateAt at valid
  exact @of_decide_eq_true _ (shapeDecidable event after) valid

theorem validateAt_ofState (label : Label) (after : RuntimeState) :
    (ofState label after).validateAt after = true := by
  simp [validateAt, shapeDecidable, Shape, ofState]

end Event

/-- Proof-carrying candidate for one exact runtime transition. -/
structure EventCandidate (before : StateSnapshot) (event : Event) where
  after : StateSnapshot
  transition : Step event.label before.model after.model

/-- Result returned only after both snapshots and the event shape validate. -/
structure CheckedEvent (before : StateSnapshot) (event : Event) where
  after : StateSnapshot
  beforeDenotes : before.Denotes before.model
  afterDenotes : after.Denotes after.model
  shape : event.Shape after.model
  transition : Step event.label before.model after.model

/-- Executable observation validation around an exact transition candidate. -/
def checkEvent (before : StateSnapshot) (event : Event)
    (candidate : EventCandidate before event) : Option (CheckedEvent before event) :=
  if beforeValid : before.validate = true then
    if afterValid : candidate.after.validate = true then
      if shapeValid : event.validateAt candidate.after.model = true then
        some ⟨candidate.after, StateSnapshot.validate_sound beforeValid,
          StateSnapshot.validate_sound afterValid, Event.validateAt_sound shapeValid,
          candidate.transition⟩
      else none
    else none
  else none

/-- Checker soundness concerns only supplied and checked logical data. -/
theorem checkEvent_sound {before : StateSnapshot} {event : Event}
    {candidate : EventCandidate before event} {checked : CheckedEvent before event}
    (_result : checkEvent before event candidate = some checked) :
    before.Denotes before.model ∧ checked.after.Denotes checked.after.model ∧
      event.Shape checked.after.model ∧
      Step event.label before.model checked.after.model :=
  ⟨checked.beforeDenotes, checked.afterDenotes, checked.shape, checked.transition⟩

/-- Every checked event forward-simulates existing managed orchestration. -/
theorem CheckedEvent.forwardSimulation {before : StateSnapshot} {event : Event}
    (checked : CheckedEvent before event) :
    ManagedSteps before.model.managed checked.after.model.managed :=
  checked.transition.forwardSimulation

/-- Canonical valid observations are accepted at the candidate result. -/
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

/-- Dependent finite event inputs align every candidate with its predecessor. -/
inductive TraceInput : StateSnapshot → Type
  | nil (state : StateSnapshot) : TraceInput state
  | cons {state : StateSnapshot} (event : Event)
      (candidate : EventCandidate state event)
      (remaining : TraceInput candidate.after) : TraceInput state

/-- Final supplied snapshot of a dependent observation trace. -/
def TraceInput.final : {before : StateSnapshot} → TraceInput before → StateSnapshot
  | _, .nil state => state
  | _, .cons _ _ remaining => remaining.final

/-- Evidence that all finite executable checks in a trace succeed. -/
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

/-- Concatenate two finite runtime executions. -/
theorem Steps.trans {first middle last : RuntimeState}
    (firstSteps : Steps first middle) (suffix : Steps middle last) : Steps first last := by
  induction suffix with
  | refl => exact firstSteps
  | tail earlier transition inductionHypothesis => exact .tail inductionHypothesis transition

/-- Checked finite runtime observation trace. -/
structure CheckedTrace (before : StateSnapshot) where
  after : StateSnapshot
  initialDenotation : before.Denotes before.model
  finalDenotation : after.Denotes after.model
  runtimeSteps : Steps before.model after.model
  simulation : ManagedSteps before.model.managed after.model.managed

/-- Validate every supplied versioned observation in a finite trace. -/
def checkTrace : {before : StateSnapshot} → TraceInput before → Option (CheckedTrace before)
  | before, .nil _ =>
      if valid : before.validate = true then
        some ⟨before, StateSnapshot.validate_sound valid,
          StateSnapshot.validate_sound valid, .refl _, .refl _⟩
      else none
  | before, .cons event candidate remaining =>
      match checkEvent before event candidate with
      | none => none
      | some checked =>
          match checkTrace remaining with
          | none => none
          | some rest =>
              some ⟨rest.after, checked.beforeDenotes, rest.finalDenotation,
                (Steps.tail (.refl before.model) candidate.transition).trans
                  rest.runtimeSteps,
                (candidate.transition.forwardSimulation).trans rest.simulation⟩

/-- Every accepted finite trace denotes its endpoints and forward-simulates. -/
theorem checkTrace_sound {before : StateSnapshot} {input : TraceInput before}
    {checked : CheckedTrace before} (_result : checkTrace input = some checked) :
    before.Denotes before.model ∧ checked.after.Denotes checked.after.model ∧
      Steps before.model checked.after.model ∧
      ManagedSteps before.model.managed checked.after.model.managed :=
  ⟨checked.initialDenotation, checked.finalDenotation,
    checked.runtimeSteps, checked.simulation⟩

/-- Checkability evidence produces a result at the supplied final snapshot. -/
theorem checkTrace_accepts {before : StateSnapshot} {input : TraceInput before}
    (checkable : TraceCheckable input) :
    ∃ checked, checkTrace input = some checked ∧ checked.after = input.final := by
  induction checkable with
  | nil valid =>
      let checked : CheckedTrace _ := ⟨_, StateSnapshot.validate_sound valid,
        StateSnapshot.validate_sound valid, .refl _, .refl _⟩
      refine ⟨checked, ?_, ?_⟩
      · simp [checkTrace, valid, checked]
      · rfl
  | @cons state event candidate remaining beforeValid afterValid shapeValid rest ih =>
      rcases checkEvent_accepts candidate beforeValid afterValid shapeValid with
        ⟨eventChecked, eventAccepted, _⟩
      rcases ih with ⟨restChecked, restAccepted, finalExact⟩
      let runtimeSteps :=
        (Steps.tail (.refl state.model) candidate.transition).trans restChecked.runtimeSteps
      let simulation := candidate.transition.forwardSimulation.trans restChecked.simulation
      refine ⟨⟨restChecked.after, eventChecked.beforeDenotes,
        restChecked.finalDenotation, runtimeSteps, simulation⟩, ?_, finalExact⟩
      simp only [checkTrace, eventAccepted, restAccepted]

/-- Checked traces preserve the existing managed-state invariant. -/
theorem CheckedTrace.preserves_managedWellFormed {before : StateSnapshot}
    (checked : CheckedTrace before) (wellFormed : before.model.managed.WellFormed) :
    checked.after.model.managed.WellFormed :=
  checked.simulation.preserves_wellFormed wellFormed

/-- Checked traces preserve every durable identity reservation. -/
theorem CheckedTrace.ledger_monotone {before : StateSnapshot}
    (checked : CheckedTrace before) {identity : OrchestrationId}
    (issued : before.model.managed.core.ledger identity = true) :
    checked.after.model.managed.core.ledger identity = true :=
  checked.runtimeSteps.ledger_monotone issued

namespace Witness

private def ledger : IdentityLedger := fun _ => false

private def identity : SessionIdentity where
  session := ⟨"runtime-session"⟩
  request := ⟨"runtime-request"⟩
  vm := ⟨"runtime-vm"⟩
  subject := ⟨"runtime-subject"⟩
  workspace := ⟨"runtime-workspace"⟩
  capability := ⟨"runtime-capability"⟩
  brokerSession := ⟨"runtime-broker"⟩

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

private def reserveStep : Step (.reserveIdentities identity) initial reserved := by
  exact .reserve rfl (Or.inl rfl) identityFresh

private def workspaceStep : Step (.workspaceCloned workspace) reserved cloned := by
  exact .workspace rfl rfl rfl (by exact ⟨rfl, rfl⟩)

private def bindStep : Step (.brokerBound broker) cloned bound := by
  exact .brokerBound rfl rfl rfl (by exact ⟨rfl, rfl⟩) rfl

private def workerStep : Step (.workerRunning broker) bound workerReady := by
  exact .workerRunning rfl (by
    simp [bound, cloned, commitBroker, broker])

private def vmStep : Step (.pausedVmStarted vm) workerReady paused := by
  exact .pausedVmStarted rfl rfl rfl
    (by exact ⟨rfl, rfl, rfl, rfl⟩)
    (by simp [workerReady, bound, cloned, commitBroker, broker]) rfl

private def capabilityStep :
    Step (.rootCapabilityInjected capability) paused injected := by
  exact .capabilityInjected rfl rfl rfl (by exact ⟨rfl, rfl, rfl⟩)
    (by simp [paused, workerReady, bound, cloned, commitVm, commitBroker, broker])
    rfl rfl rfl

private def workloadStep : Step (.workloadReleased workload) injected released := by
  exact .workloadReleased rfl rfl rfl (by exact ⟨rfl, rfl, rfl, rfl⟩)
    (by simp [injected, paused, workerReady, bound, cloned,
      RuntimeState.withManaged,
      commitCapability, commitVm, commitBroker, broker]) rfl rfl

private def publishStep : Step .runningPublished released running := by
  exact .runningPublished rfl rfl
    (by simp [released, injected, paused, workerReady, bound, cloned,
      RuntimeState.withManaged,
      commitWorkload, commitCapability, commitVm, commitBroker, broker]) rfl rfl

private theorem runningBrokerLookup :
    running.managed.core.resources.broker = some broker := by
  simp [running, released, injected, paused, workerReady, bound, cloned,
    RuntimeState.withManaged, markRunning, commitWorkload, commitCapability,
    commitVm, commitBroker, broker]

private def snapshot (state : RuntimeState) := StateSnapshot.ofState state
private def event (label : Label) (after : RuntimeState) := Event.ofState label after

private def candidate {before after : RuntimeState} {label : Label}
    (transition : Step label before after) :
    EventCandidate (snapshot before) (event label after) :=
  ⟨snapshot after, transition⟩

private def normalTrace : TraceInput (snapshot initial) :=
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
                  (.nil (snapshot running)))))))))

private def normalTraceCheckable : TraceCheckable normalTrace := by
  apply TraceCheckable.cons (StateSnapshot.validate_ofState _)
    (StateSnapshot.validate_ofState _) (Event.validateAt_ofState _ _)
  apply TraceCheckable.cons (StateSnapshot.validate_ofState _)
    (StateSnapshot.validate_ofState _) (Event.validateAt_ofState _ _)
  apply TraceCheckable.cons (StateSnapshot.validate_ofState _)
    (StateSnapshot.validate_ofState _) (Event.validateAt_ofState _ _)
  apply TraceCheckable.cons (StateSnapshot.validate_ofState _)
    (StateSnapshot.validate_ofState _) (Event.validateAt_ofState _ _)
  apply TraceCheckable.cons (StateSnapshot.validate_ofState _)
    (StateSnapshot.validate_ofState _) (Event.validateAt_ofState _ _)
  apply TraceCheckable.cons (StateSnapshot.validate_ofState _)
    (StateSnapshot.validate_ofState _) (Event.validateAt_ofState _ _)
  apply TraceCheckable.cons (StateSnapshot.validate_ofState _)
    (StateSnapshot.validate_ofState _) (Event.validateAt_ofState _ _)
  apply TraceCheckable.cons (StateSnapshot.validate_ofState _)
    (StateSnapshot.validate_ofState _) (Event.validateAt_ofState _ _)
  exact .nil (StateSnapshot.validate_ofState running)

/-- The complete healthy startup reaches Running through every enforced gate. -/
theorem normal_trace_witness :
    ∃ checked, checkTrace normalTrace = some checked ∧
      checked.after.model = running ∧
      running.managed.core.phase = .running ∧
      running.worker = .running broker ∧ running.workloadReleased = true := by
  rcases checkTrace_accepts normalTraceCheckable with ⟨checked, accepted, finalExact⟩
  refine ⟨checked, accepted, ?_, rfl, rfl, rfl⟩
  rw [finalExact]
  rfl

private def stoppingAfterExit : RuntimeState :=
  running.beginShutdown (.brokerExited .panicked) (.exited broker .panicked)
private def revoked : RuntimeState :=
  stoppingAfterExit.recordCleanup stoppingAfterExit.managed.cleanup.revokeCapability
private def killed : RuntimeState := revoked.recordCleanup revoked.managed.cleanup.killVm
private def joined : RuntimeState :=
  { killed.recordCleanup killed.managed.cleanup.closeBroker with
    worker := .joined broker .panicked }
private def isolated : RuntimeState :=
  joined.recordCleanup joined.managed.cleanup.isolateWorkspace
private def closed : RuntimeState := isolated.finishClosed

private def exitStep :
    Step (.unexpectedBrokerExit broker .panicked) running stoppingAfterExit := by
  exact .unexpectedExit rfl rfl
    (by simp [running, released, injected, paused, workerReady, bound, cloned,
      RuntimeState.withManaged,
      markRunning, commitWorkload, commitCapability, commitVm, commitBroker, broker]) rfl

private def revokeStep : Step .capabilityRevoked stoppingAfterExit revoked :=
  .capabilityRevoked rfl

private def killStep : Step .vmKilled revoked killed := .vmKilled rfl rfl

private def joinStep :
    Step (.brokerCancelledAndJoined broker .panicked) killed joined := by
  exact .brokerJoined rfl rfl
    (by
      change running.managed.core.resources.broker = some broker
      exact runningBrokerLookup) (.exited)

private def isolateStep : Step .workspaceIsolated joined isolated := by
  exact .workspaceIsolated rfl rfl rfl (by trivial)

private theorem isolatedComplete : isolated.managed.cleanup.Complete := by
  change true = true ∧ true = true ∧ true = true ∧ true = true
  exact ⟨rfl, rfl, rfl, rfl⟩

private def closeStep : Step .closedPublished isolated closed := by
  exact .closedPublished rfl isolatedComplete (by trivial)

private def exitTrace : TraceInput (snapshot running) :=
  .cons (event (.unexpectedBrokerExit broker .panicked) stoppingAfterExit)
    (candidate exitStep)
    (.cons (event .capabilityRevoked revoked) (candidate revokeStep)
      (.cons (event .vmKilled killed) (candidate killStep)
        (.cons (event (.brokerCancelledAndJoined broker .panicked) joined)
          (candidate joinStep)
          (.cons (event .workspaceIsolated isolated) (candidate isolateStep)
            (.cons (event .closedPublished closed) (candidate closeStep)
              (.nil (snapshot closed)))))))

private def exitTraceCheckable : TraceCheckable exitTrace := by
  apply TraceCheckable.cons (StateSnapshot.validate_ofState _)
    (StateSnapshot.validate_ofState _) (Event.validateAt_ofState _ _)
  apply TraceCheckable.cons (StateSnapshot.validate_ofState _)
    (StateSnapshot.validate_ofState _) (Event.validateAt_ofState _ _)
  apply TraceCheckable.cons (StateSnapshot.validate_ofState _)
    (StateSnapshot.validate_ofState _) (Event.validateAt_ofState _ _)
  apply TraceCheckable.cons (StateSnapshot.validate_ofState _)
    (StateSnapshot.validate_ofState _) (Event.validateAt_ofState _ _)
  apply TraceCheckable.cons (StateSnapshot.validate_ofState _)
    (StateSnapshot.validate_ofState _) (Event.validateAt_ofState _ _)
  apply TraceCheckable.cons (StateSnapshot.validate_ofState _)
    (StateSnapshot.validate_ofState _) (Event.validateAt_ofState _ _)
  exact .nil (StateSnapshot.validate_ofState closed)

/-- An unexpected typed exit drives the exact ordered cleanup to Closed. -/
theorem unexpected_exit_trace_witness :
    ∃ checked, checkTrace exitTrace = some checked ∧
      checked.after.model = closed ∧ closed.managed.core.phase = .closed ∧
      closed.managed.cleanup.Complete ∧ closed.worker = .joined broker .panicked := by
  rcases checkTrace_accepts exitTraceCheckable with ⟨checked, accepted, finalExact⟩
  refine ⟨checked, accepted, ?_, rfl, ?_, rfl⟩
  · rw [finalExact]
    rfl
  · change isolated.managed.cleanup.Complete
    exact isolatedComplete

private def timedOut : RuntimeState := { killed with worker := .cancelling broker .panicked }

private def timeoutStep :
    Step (.brokerJoinTimeout broker .panicked) killed timedOut := by
  exact .brokerJoinTimeout rfl rfl
    (by
      change running.managed.core.resources.broker = some broker
      exact runningBrokerLookup) (.exited)

private def retryJoinStep :
    Step (.brokerCancelledAndJoined broker .panicked) timedOut joined := by
  exact .brokerJoined rfl rfl
    (by
      change running.managed.core.resources.broker = some broker
      exact runningBrokerLookup) (.cancelling)

private def timeoutRetryTrace : TraceInput (snapshot killed) :=
  .cons (event (.brokerJoinTimeout broker .panicked) timedOut) (candidate timeoutStep)
    (.cons (event (.brokerCancelledAndJoined broker .panicked) joined)
      (candidate retryJoinStep)
      (.cons (event .workspaceIsolated isolated) (candidate isolateStep)
        (.cons (event .closedPublished closed) (candidate closeStep)
          (.nil (snapshot closed)))))

private def timeoutRetryTraceCheckable : TraceCheckable timeoutRetryTrace := by
  apply TraceCheckable.cons (StateSnapshot.validate_ofState _)
    (StateSnapshot.validate_ofState _) (Event.validateAt_ofState _ _)
  apply TraceCheckable.cons (StateSnapshot.validate_ofState _)
    (StateSnapshot.validate_ofState _) (Event.validateAt_ofState _ _)
  apply TraceCheckable.cons (StateSnapshot.validate_ofState _)
    (StateSnapshot.validate_ofState _) (Event.validateAt_ofState _ _)
  apply TraceCheckable.cons (StateSnapshot.validate_ofState _)
    (StateSnapshot.validate_ofState _) (Event.validateAt_ofState _ _)
  exact .nil (StateSnapshot.validate_ofState closed)

/-- Join timeout retains ownership, then an exact retry joins and closes. -/
theorem timeout_retry_trace_witness :
    ∃ checked, checkTrace timeoutRetryTrace = some checked ∧
      timedOut.managed.ownership.resources.broker = some broker ∧
      timedOut.worker = .cancelling broker .panicked ∧
      checked.after.model = closed := by
  rcases checkTrace_accepts timeoutRetryTraceCheckable with
    ⟨checked, accepted, finalExact⟩
  refine ⟨checked, accepted, ?_, rfl, ?_⟩
  · change running.managed.core.resources.broker = some broker
    exact runningBrokerLookup
  · rw [finalExact]
    rfl

private def foreignBroker : BrokerLease where
  session := ⟨"foreign-session"⟩
  brokerSession := ⟨"foreign-broker"⟩

/-- A foreign typed exit cannot mutate the owned running session. -/
theorem foreign_exit_witness :
    Step (.foreignExitIgnored foreignBroker .panicked) running running := by
  apply Step.foreignExitIgnored (owned := broker)
  · exact Or.inl (by
      simp [running, released, injected, paused, workerReady, bound, cloned,
        RuntimeState.OwnsBroker, RuntimeState.withManaged,
        markRunning, commitWorkload, commitCapability, commitVm, commitBroker,
        broker])
  · decide

end Witness

end Authority.Refinement.OrchestratorRuntime
