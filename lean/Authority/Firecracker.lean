import Authority.Isolation

/-!
# Firecracker Runtime

Pure configuration, restored-identity, lifecycle, and shutdown specifications
for the Firecracker runtime. Cryptographic correctness, filesystem stability,
and backend command/API honesty are refinement obligations.
-/

namespace Authority

namespace Firecracker

/-- Opaque SHA-256 digest at the pure model boundary. -/
structure Digest where
  value : Nat
  deriving Repr, BEq, DecidableEq

/-- An artifact is accepted only when its path and immutable digest are safe. -/
structure PinnedArtifact where
  path : Isolation.HostPath
  digest : Digest
  deriving DecidableEq

/-- Exact lexical path checks performed by the Firecracker runtime boundary. -/
def RuntimePathValid (path : Isolation.HostPath) : Prop :=
  path.absolute = true ∧ ".." ∉ path.components ∧
    (∀ component, component ∈ path.components → component.toLower ≠ "latest") ∧
    ∀ component, component ∈ path.components → '\u0000' ∉ component.toList

/-- Rust's nonempty ASCII alphanumeric/underscore/hyphen identifier grammar. -/
def SafeName (name : String) : Prop :=
  name ≠ "" ∧ ∀ character, character ∈ name.toList →
    character.isAlphanum = true ∨ character = '_' ∨ character = '-'

/-- Pure artifact validation predicate. -/
def PinnedArtifact.Valid (artifact : PinnedArtifact) : Prop :=
  RuntimePathValid artifact.path ∧ artifact.digest.value ≠ 0

/-- Six host namespaces required by the jailer boundary. -/
structure NamespaceSwitches where
  user : Bool
  pid : Bool
  mount : Bool
  network : Bool
  ipc : Bool
  uts : Bool
  deriving DecidableEq

/-- All namespace switches must be enabled. -/
def NamespaceSwitches.Complete (switches : NamespaceSwitches) : Prop :=
  switches.user = true ∧ switches.pid = true ∧ switches.mount = true ∧
    switches.network = true ∧ switches.ipc = true ∧ switches.uts = true

/-- Security-relevant pure launch configuration. -/
structure RuntimeConfig where
  firecracker : PinnedArtifact
  kernel : PinnedArtifact
  rootfs : PinnedArtifact
  verityHash : PinnedArtifact
  jailer : PinnedArtifact
  seccompFilter : PinnedArtifact
  apiSocket : Isolation.HostPath
  workspaceSource : Isolation.HostPath
  workspaceRoot : Isolation.HostPath
  workspaceCloneId : String
  verityDataDevice : Isolation.HostPath
  verityHashDevice : Isolation.HostPath
  verityRootHash : Digest
  mapperName : String
  vsockCid : Nat
  vsockSocket : Isolation.HostPath
  networkDevices : List String
  vcpuCount : Nat
  memoryMib : Nat
  cgroupPath : Isolation.HostPath
  cgroupMemoryMax : Nat
  cgroupCpuQuota : Nat
  namespaces : NamespaceSwitches
  blockedSyscalls : List String
  bootArguments : String

/-- Syscalls that every host seccomp profile must deny. -/
def requiredBlockedSyscalls : List String :=
  ["bpf", "connect", "mount", "perf_event_open", "ptrace", "setns",
    "socket", "unshare"]

/-- Reduced compatibility payload used by snapshot fingerprinting. -/
structure FingerprintPayload where
  firecrackerDigest : Digest
  kernelDigest : Digest
  rootfsDigest : Digest
  verityHashDigest : Digest
  jailerDigest : Digest
  seccompDigest : Digest
  verityRootHash : Digest
  vsockCid : Nat
  deriving DecidableEq

/-- Exact fields included by the Rust fingerprint implementation. -/
def RuntimeConfig.fingerprintPayload (config : RuntimeConfig) : FingerprintPayload where
  firecrackerDigest := config.firecracker.digest
  kernelDigest := config.kernel.digest
  rootfsDigest := config.rootfs.digest
  verityHashDigest := config.verityHash.digest
  jailerDigest := config.jailer.digest
  seccompDigest := config.seccompFilter.digest
  verityRootHash := config.verityRootHash
  vsockCid := config.vsockCid

/-- Complete pure configuration validation contract. -/
structure RuntimeConfig.Valid (config : RuntimeConfig) : Prop where
  firecrackerValid : config.firecracker.Valid
  kernelValid : config.kernel.Valid
  rootfsValid : config.rootfs.Valid
  verityHashValid : config.verityHash.Valid
  jailerValid : config.jailer.Valid
  seccompFilterValid : config.seccompFilter.Valid
  apiSocketSafe : RuntimePathValid config.apiSocket
  workspaceSourceSafe : RuntimePathValid config.workspaceSource
  workspaceRootSafe : RuntimePathValid config.workspaceRoot
  verityDataSafe : RuntimePathValid config.verityDataDevice
  verityHashDeviceSafe : RuntimePathValid config.verityHashDevice
  vsockSocketSafe : RuntimePathValid config.vsockSocket
  cgroupPathSafe : RuntimePathValid config.cgroupPath
  verityDataMatchesRootfs : config.verityDataDevice = config.rootfs.path
  verityHashMatchesArtifact : config.verityHashDevice = config.verityHash.path
  verityRootHashNonzero : config.verityRootHash.value ≠ 0
  mapperNameValid : SafeName config.mapperName
  cloneIdValid : SafeName config.workspaceCloneId
  workspaceDisjoint :
    ¬ config.workspaceSource.AtOrBelow config.workspaceRoot ∧
    ¬ config.workspaceRoot.AtOrBelow config.workspaceSource
  vsockCidReservedRangeExcluded : 3 ≤ config.vsockCid
  noNetworkDevices : config.networkDevices = []
  vcpuPositive : 0 < config.vcpuCount
  memoryPositive : 0 < config.memoryMib
  cgroupNotRoot : config.cgroupPath ≠ Isolation.HostPath.root
  cgroupMemoryPositive : 0 < config.cgroupMemoryMax
  cgroupCpuPositive : 0 < config.cgroupCpuQuota
  allNamespaces : config.namespaces.Complete
  requiredSyscallsBlocked : ∀ syscall,
    syscall ∈ requiredBlockedSyscalls → syscall ∈ config.blockedSyscalls

/-- Valid launch configuration cannot expose a network device. -/
theorem RuntimeConfig.Valid.network_disabled {config : RuntimeConfig}
    (valid : config.Valid) : config.networkDevices = [] :=
  valid.noNetworkDevices

/-- Valid launch configuration enables every jailer namespace. -/
theorem RuntimeConfig.Valid.namespaces_complete {config : RuntimeConfig}
    (valid : config.Valid) : config.namespaces.Complete :=
  valid.allNamespaces

/-- Every required host syscall denial is present in a valid profile. -/
theorem RuntimeConfig.Valid.blocks_required_syscall {config : RuntimeConfig}
    (valid : config.Valid) {syscall : String}
    (required : syscall ∈ requiredBlockedSyscalls) :
    syscall ∈ config.blockedSyscalls :=
  valid.requiredSyscallsBlocked syscall required

/-- Fingerprints deliberately omit vCPU count. -/
theorem fingerprint_unchanged_by_vcpu_count (config : RuntimeConfig) (count : Nat) :
    ({ config with vcpuCount := count }).fingerprintPayload =
      config.fingerprintPayload := by
  rfl

/-- Fingerprints also omit the dm-verity mapper selected during launch. -/
theorem fingerprint_unchanged_by_mapper_name (config : RuntimeConfig) (mapperName : String) :
    ({ config with mapperName := mapperName }).fingerprintPayload =
      config.fingerprintPayload := by
  rfl

/-- Shutdown-relevant configuration retained by a live Rust runtime instance. -/
structure InstanceBinding where
  fingerprint : FingerprintPayload
  mapperName : String
  deriving DecidableEq

/-- Capture the configuration identity and mapper owned at instance creation. -/
def InstanceBinding.fromConfig (config : RuntimeConfig) : InstanceBinding where
  fingerprint := config.fingerprintPayload
  mapperName := config.mapperName

/-- A shutdown configuration must identify both the original config and mapper. -/
def InstanceBinding.MatchesShutdownConfig (binding : InstanceBinding)
    (config : RuntimeConfig) : Prop :=
  config.fingerprintPayload = binding.fingerprint ∧
    config.mapperName = binding.mapperName

/-- Launch configuration is bound to the instance metadata it creates. -/
theorem InstanceBinding.fromConfig_matches_shutdown (config : RuntimeConfig) :
    (InstanceBinding.fromConfig config).MatchesShutdownConfig config := by
  exact ⟨rfl, rfl⟩

/-- A bound shutdown configuration necessarily closes the instance-owned mapper. -/
theorem InstanceBinding.shutdown_config_closes_owned_mapper
    {binding : InstanceBinding} {config : RuntimeConfig}
    (bound : binding.MatchesShutdownConfig config) :
    config.mapperName = binding.mapperName :=
  bound.2

/-- Fingerprint equality alone cannot bind shutdown to the instance-owned mapper. -/
theorem fingerprint_match_does_not_bind_shutdown_mapper
    (config : RuntimeConfig) (otherMapper : String)
    (different : otherMapper ≠ config.mapperName) :
    ({ config with mapperName := otherMapper }).fingerprintPayload =
        (InstanceBinding.fromConfig config).fingerprint ∧
      ¬ (InstanceBinding.fromConfig config).MatchesShutdownConfig
        { config with mapperName := otherMapper } := by
  constructor
  · rfl
  · intro bound
    exact different (by simpa [InstanceBinding.MatchesShutdownConfig,
      InstanceBinding.fromConfig] using bound.2)

/-- Five guest-visible identity domains regenerated after restore. -/
inductive GuestIdentityKind where
  | vm
  | session
  | request
  | subject
  | capability
  deriving Repr, BEq, DecidableEq

/-- Fresh guest-visible identity bundle. -/
structure IdentityBundle where
  vm : Nat
  session : Nat
  request : Nat
  subject : Nat
  capability : Nat
  deriving DecidableEq

/-- Select one identity domain from a bundle. -/
def IdentityBundle.forKind (bundle : IdentityBundle) : GuestIdentityKind → Nat
  | .vm => bundle.vm
  | .session => bundle.session
  | .request => bundle.request
  | .subject => bundle.subject
  | .capability => bundle.capability

/-- Exact nonzero, pairwise-distinct, snapshot-fresh identity contract. -/
def IdentityBundle.Valid (bundle : IdentityBundle) (forbidden : List Nat) : Prop :=
  (∀ kind, bundle.forKind kind ≠ 0) ∧
  (∀ first second, bundle.forKind first = bundle.forKind second → first = second) ∧
  ∀ kind, bundle.forKind kind ∉ forbidden

/-- Snapshot descriptor relevant to compatibility and stale identities. -/
structure Snapshot where
  fingerprint : FingerprintPayload
  forbiddenIdentities : List Nat

/-- Runtime-created snapshots carry no session identity from workload-stopped state. -/
def createInternalSnapshot (config : RuntimeConfig) : Snapshot where
  fingerprint := config.fingerprintPayload
  forbiddenIdentities := []

/-- Internally created snapshots have an empty forbidden-identity set. -/
theorem internal_snapshot_forbidden_empty (config : RuntimeConfig) :
    (createInternalSnapshot config).forbiddenIdentities = [] := by
  rfl

/-- Internal snapshots therefore reduce freshness to intrinsic bundle validity. -/
theorem internal_snapshot_freshness_check_is_vacuous
    (config : RuntimeConfig) (bundle : IdentityBundle) :
    bundle.Valid (createInternalSnapshot config).forbiddenIdentities ↔
      ((∀ kind, bundle.forKind kind ≠ 0) ∧
        ∀ first second, bundle.forKind first = bundle.forKind second → first = second) := by
  simp [IdentityBundle.Valid, createInternalSnapshot]

/-- Publicly reachable successful lifecycle phases. -/
inductive Phase where
  | workloadStopped
  | snapshotted
  | identityRegenerated
  | identityInjected
  | running
  | stopped
  deriving Repr, BEq, DecidableEq

/-- Pure runtime instance state. -/
structure State where
  phase : Phase
  fingerprint : FingerprintPayload
  identities : Option IdentityBundle
  forbiddenIdentities : List Nat

/-- Successful launch stops the guest before any restored identity exists. -/
def State.launched (config : RuntimeConfig) : State where
  phase := .workloadStopped
  fingerprint := config.fingerprintPayload
  identities := none
  forbiddenIdentities := []

/-- Reachable phase/identity refinement. -/
def State.WellFormed (state : State) : Prop :=
  match state.phase with
  | .workloadStopped | .snapshotted => state.identities = none
  | .identityRegenerated | .identityInjected | .running =>
      ∃ bundle, state.identities = some bundle ∧
        bundle.Valid state.forbiddenIdentities
  | .stopped => True

/-- A newly launched runtime satisfies phase refinement. -/
theorem State.launched_wellFormed (config : RuntimeConfig) :
    (State.launched config).WellFormed := by
  simp [State.launched, State.WellFormed]

/-- Record snapshot creation at the workload-stopped gate. -/
def State.markSnapshotted (state : State) : State :=
  { state with phase := .snapshotted }

/-- Restore directly into the identity-regenerated gate. -/
def State.restore (snapshot : Snapshot) (bundle : IdentityBundle) : State where
  phase := .identityRegenerated
  fingerprint := snapshot.fingerprint
  identities := some bundle
  forbiddenIdentities := snapshot.forbiddenIdentities

/-- Record successful guest identity injection. -/
def State.markIdentityInjected (state : State) : State :=
  { state with phase := .identityInjected }

/-- Release workload execution only after identity injection. -/
def State.markRunning (state : State) : State :=
  { state with phase := .running }

/-- Accepted successful lifecycle transitions. -/
inductive Step : State → State → Prop
  | snapshot {state : State} :
      state.phase = .workloadStopped → Step state state.markSnapshotted
  | restore {current : State} {snapshot : Snapshot} {bundle : IdentityBundle} :
      snapshot.fingerprint = current.fingerprint →
      bundle.Valid snapshot.forbiddenIdentities →
      Step current (State.restore snapshot bundle)
  | inject {state : State} {bundle : IdentityBundle} :
      state.phase = .identityRegenerated → state.identities = some bundle →
      Step state state.markIdentityInjected
  | start {state : State} :
      state.phase = .identityInjected → Step state state.markRunning

/-- Every accepted lifecycle transition preserves identity refinement. -/
theorem Step.preserves_wellFormed {before after : State}
    (transition : Step before after) (wellFormed : before.WellFormed) :
    after.WellFormed := by
  cases transition with
  | snapshot phase => simpa [State.markSnapshotted, State.WellFormed, phase] using wellFormed
  | restore fingerprint valid => exact ⟨_, rfl, valid⟩
  | inject phase identityLookup =>
      simpa [State.markIdentityInjected, State.WellFormed, phase] using wellFormed
  | start phase => simpa [State.markRunning, State.WellFormed, phase] using wellFormed

/-- Running is reachable only with a valid regenerated identity bundle. -/
theorem State.running_has_fresh_identity {state : State}
    (wellFormed : state.WellFormed) (running : state.phase = .running) :
    ∃ bundle, state.identities = some bundle ∧
      bundle.Valid state.forbiddenIdentities := by
  simpa [State.WellFormed, running] using wellFormed

/-- Retryable shutdown resource state. -/
structure CleanupState where
  processStopped : Bool
  verityOpened : Bool
  workspaceRemoved : Bool
  deriving DecidableEq

/-- Live runtime resources before shutdown. -/
def CleanupState.live : CleanupState where
  processStopped := false
  verityOpened := true
  workspaceRemoved := false

/-- Dependency safety of shutdown cleanup. -/
def CleanupState.Safe (state : CleanupState) : Prop :=
  state.workspaceRemoved = true →
    state.processStopped = true ∧ state.verityOpened = false

/-- All runtime resources have reached their terminal cleanup state. -/
def CleanupState.Complete (state : CleanupState) : Prop :=
  state.processStopped = true ∧ state.verityOpened = false ∧
    state.workspaceRemoved = true

/-- Initial live resources satisfy dependency safety. -/
theorem CleanupState.live_safe : CleanupState.live.Safe := by
  simp [CleanupState.live, CleanupState.Safe]

/-- Record successful process termination. -/
def CleanupState.stopProcess (state : CleanupState) : CleanupState :=
  { state with processStopped := true }

/-- Close dm-verity only after process termination. -/
def CleanupState.closeVerity (state : CleanupState) : CleanupState :=
  { state with verityOpened := false }

/-- Remove the workspace only after process and verity dependencies terminate. -/
def CleanupState.removeWorkspace (state : CleanupState) : CleanupState :=
  { state with workspaceRemoved := true }

/-- Successful shutdown commits; backend failures stutter outside this relation. -/
inductive CleanupStep : CleanupState → CleanupState → Prop
  | stopProcess {state : CleanupState} : CleanupStep state state.stopProcess
  | closeVerity {state : CleanupState} :
      state.processStopped = true → CleanupStep state state.closeVerity
  | removeWorkspace {state : CleanupState} :
      state.processStopped = true → state.verityOpened = false →
      CleanupStep state state.removeWorkspace
  | retryNoop {state : CleanupState} : CleanupStep state state

/-- Shutdown dependency safety is inductive across every successful commit. -/
theorem CleanupStep.preserves_safety {before after : CleanupState}
    (transition : CleanupStep before after) (safe : before.Safe) : after.Safe := by
  cases transition with
  | stopProcess =>
      intro removed
      exact ⟨rfl, (safe removed).2⟩
  | closeVerity processStopped =>
      intro removed
      exact ⟨processStopped, rfl⟩
  | removeWorkspace processStopped verityClosed =>
      intro _
      exact ⟨processStopped, verityClosed⟩
  | retryNoop => exact safe

/-- Once complete, no accepted cleanup retry can recreate a resource. -/
theorem CleanupStep.preserves_complete {before after : CleanupState}
    (transition : CleanupStep before after) (complete : before.Complete) :
    after.Complete := by
  rcases complete with ⟨processStopped, verityClosed, workspaceRemoved⟩
  cases transition with
  | stopProcess => exact ⟨rfl, verityClosed, workspaceRemoved⟩
  | closeVerity => exact ⟨processStopped, rfl, workspaceRemoved⟩
  | removeWorkspace => exact ⟨processStopped, verityClosed, rfl⟩
  | retryNoop => exact ⟨processStopped, verityClosed, workspaceRemoved⟩

/-- Finite retry execution of dependency-gated cleanup. -/
inductive CleanupSteps : CleanupState → CleanupState → Prop
  | refl (state : CleanupState) : CleanupSteps state state
  | tail {first middle last : CleanupState} :
      CleanupSteps first middle → CleanupStep middle last → CleanupSteps first last

/-- Shutdown dependency safety survives arbitrary retry sequences. -/
theorem CleanupSteps.preserve_safety {before after : CleanupState}
    (transitions : CleanupSteps before after) (safe : before.Safe) : after.Safe := by
  induction transitions with
  | refl => exact safe
  | tail _ transition inductionHypothesis =>
      exact transition.preserves_safety inductionHypothesis

/-- Process termination is monotone across arbitrary retry sequences. -/
theorem CleanupSteps.process_stop_monotone {before after : CleanupState}
    (transitions : CleanupSteps before after)
    (stopped : before.processStopped = true) : after.processStopped = true := by
  induction transitions with
  | refl => exact stopped
  | tail _ transition inductionHypothesis =>
      cases transition with
      | stopProcess => rfl
      | closeVerity | removeWorkspace | retryNoop => exact inductionHypothesis

/-- Once closed, dm-verity cannot be reopened by cleanup retries. -/
theorem CleanupSteps.verity_close_monotone {before after : CleanupState}
    (transitions : CleanupSteps before after)
    (closed : before.verityOpened = false) : after.verityOpened = false := by
  induction transitions with
  | refl => exact closed
  | tail _ transition inductionHypothesis =>
      cases transition with
      | closeVerity => rfl
      | stopProcess | removeWorkspace | retryNoop => exact inductionHypothesis

/-- Workspace removal can never precede process stop and verity close. -/
theorem CleanupState.removed_implies_dependencies {state : CleanupState}
    (safe : state.Safe) (removed : state.workspaceRemoved = true) :
    state.processStopped = true ∧ state.verityOpened = false :=
  safe removed

/-- Observable success/failure results of Rust's best-effort rollback calls. -/
structure RollbackResults where
  processStopSucceeded : Bool
  verityCloseSucceeded : Bool
  workspaceRemoveSucceeded : Bool
  deriving DecidableEq

/-- Rust rollback attempts all owned resources even after process-stop failure. -/
def CleanupState.rollbackAttempt (state : CleanupState)
    (results : RollbackResults) : CleanupState where
  processStopped := state.processStopped || results.processStopSucceeded
  verityOpened := state.verityOpened && !results.verityCloseSucceeded
  workspaceRemoved := state.workspaceRemoved || results.workspaceRemoveSucceeded

/-- Concrete failing-stop/successful-dependency rollback outcome. -/
def unsafeRollbackResults : RollbackResults where
  processStopSucceeded := false
  verityCloseSucceeded := true
  workspaceRemoveSucceeded := true

/-- Current Rust rollback can remove backing resources while the process remains live. -/
theorem rollback_stop_failure_can_violate_dependency_safety :
    ¬ (CleanupState.live.rollbackAttempt unsafeRollbackResults).Safe := by
  intro safe
  have dependencies := safe (by rfl)
  simp [CleanupState.live, CleanupState.rollbackAttempt, unsafeRollbackResults] at dependencies

/-- Dependency-gated shutdown and best-effort rollback are distinct contracts. -/
theorem unsafe_rollback_is_not_a_cleanup_step :
    ¬ CleanupStep CleanupState.live
      (CleanupState.live.rollbackAttempt unsafeRollbackResults) := by
  intro transition
  have violatesSafety := rollback_stop_failure_can_violate_dependency_safety
  exact violatesSafety (transition.preserves_safety CleanupState.live_safe)

/-- Runtime lifecycle composed with the retryable, dependency-gated cleanup state. -/
structure ManagedState where
  core : State
  cleanup : CleanupState

/-- A newly launched runtime owns all three live resources. -/
def ManagedState.launched (config : RuntimeConfig) : ManagedState where
  core := State.launched config
  cleanup := .live

/-- Publish Stopped only after all owned resources are gone. -/
def ManagedState.finishShutdown (state : ManagedState) : ManagedState :=
  { core := { state.core with phase := .stopped }, cleanup := state.cleanup }

/-- Identity refinement and the Stopped/cleanup gate agree. -/
structure ManagedState.WellFormed (state : ManagedState) : Prop where
  coreWellFormed : state.core.WellFormed
  stoppedRequiresCleanup : state.core.phase = .stopped → state.cleanup.Complete
  cleanupSafe : state.cleanup.Safe

/-- A newly launched runtime satisfies lifecycle/cleanup coupling. -/
theorem ManagedState.launched_wellFormed (config : RuntimeConfig) :
    (ManagedState.launched config).WellFormed := by
  constructor
  · exact State.launched_wellFormed config
  · intro impossible
    simp [ManagedState.launched, State.launched] at impossible
  · exact CleanupState.live_safe

/-- Successful runtime protocol transitions never directly publish Stopped. -/
theorem Step.after_ne_stopped {before after : State} (transition : Step before after) :
    after.phase ≠ .stopped := by
  cases transition <;> simp [State.markSnapshotted, State.restore,
    State.markIdentityInjected, State.markRunning]

/-- Same-instance lifecycle steps, cleanup commits, and the terminal shutdown gate.
Rust restore returns a new instance rather than reviving a stopped one. -/
inductive ManagedStep : ManagedState → ManagedState → Prop
  | runtime {state : ManagedState} {core : State} :
      state.core.phase ≠ .stopped →
      Step state.core core → ManagedStep state { state with core := core }
  | cleanup {state : ManagedState} {cleanup : CleanupState} :
      CleanupStep state.cleanup cleanup →
      ManagedStep state { state with cleanup := cleanup }
  | finishShutdown {state : ManagedState} :
      state.cleanup.Complete → ManagedStep state state.finishShutdown

/-- Lifecycle/cleanup coupling survives every managed runtime transition. -/
theorem ManagedStep.preserves_wellFormed {before after : ManagedState}
    (transition : ManagedStep before after) (wellFormed : before.WellFormed) :
    after.WellFormed := by
  cases transition with
  | runtime _ runtimeStep =>
      exact ⟨runtimeStep.preserves_wellFormed wellFormed.coreWellFormed,
        fun stopped => False.elim (runtimeStep.after_ne_stopped stopped),
        wellFormed.cleanupSafe⟩
  | cleanup cleanupStep =>
      constructor
      · exact wellFormed.coreWellFormed
      · intro stopped
        have completeBefore := wellFormed.stoppedRequiresCleanup stopped
        exact cleanupStep.preserves_complete completeBefore
      · exact cleanupStep.preserves_safety wellFormed.cleanupSafe
  | finishShutdown complete =>
      exact ⟨by simp [ManagedState.finishShutdown, State.WellFormed],
        fun _ => complete, wellFormed.cleanupSafe⟩

/-- Stopped is terminal for the instance core, including cleanup retries. -/
theorem ManagedStep.stopped_terminal {before after : ManagedState}
    (transition : ManagedStep before after)
    (stopped : before.core.phase = .stopped) :
    after.core.phase = .stopped := by
  cases transition with
  | runtime live _ => exact False.elim (live stopped)
  | cleanup => exact stopped
  | finishShutdown => rfl

/-- A Stopped runtime has no live process, dm-verity mapping, or workspace. -/
theorem ManagedState.stopped_implies_cleanup_complete {state : ManagedState}
    (wellFormed : state.WellFormed) (stopped : state.core.phase = .stopped) :
    state.cleanup.Complete :=
  wellFormed.stoppedRequiresCleanup stopped

/-- Finite managed Firecracker execution. -/
inductive ManagedSteps : ManagedState → ManagedState → Prop
  | refl (state : ManagedState) : ManagedSteps state state
  | tail {first middle last : ManagedState} :
      ManagedSteps first middle → ManagedStep middle last → ManagedSteps first last

/-- Cleanup gating and identity refinement survive arbitrary runtime execution. -/
theorem ManagedSteps.preserves_wellFormed {before after : ManagedState}
    (transitions : ManagedSteps before after) (wellFormed : before.WellFormed) :
    after.WellFormed := by
  induction transitions with
  | refl => exact wellFormed
  | tail _ transition inductionHypothesis =>
      exact transition.preserves_wellFormed inductionHypothesis

/-- No finite execution can revive the core of a stopped runtime instance. -/
theorem ManagedSteps.stopped_terminal {before after : ManagedState}
    (transitions : ManagedSteps before after)
    (stopped : before.core.phase = .stopped) :
    after.core.phase = .stopped := by
  induction transitions with
  | refl => exact stopped
  | tail _ transition inductionHypothesis =>
      exact transition.stopped_terminal inductionHypothesis

end Firecracker

end Authority
