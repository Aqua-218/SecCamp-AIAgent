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
  deriving DecidableEq

/-- Syscalls that every host seccomp profile must deny. -/
def requiredBlockedSyscalls : List String :=
  ["bpf", "connect", "mount", "perf_event_open", "ptrace", "setns",
    "socket", "unshare"]

/-- Snapshot compatibility preimage. Retaining the complete configuration makes
field omission impossible when restore begins consuming another configuration field. -/
structure FingerprintPayload where
  restoreConfig : RuntimeConfig
  deriving DecidableEq

/-- Exact restore configuration covered by snapshot compatibility. -/
def RuntimeConfig.fingerprintPayload (config : RuntimeConfig) : FingerprintPayload where
  restoreConfig := config

/-- Fingerprint equality covers every field of the restore configuration. -/
theorem fingerprintPayload_eq_iff {first second : RuntimeConfig} :
    first.fingerprintPayload = second.fingerprintPayload ↔ first = second := by
  simp [RuntimeConfig.fingerprintPayload]

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

/-- Concrete valid launch configuration used to prove model non-vacuity. -/
def validRuntimeConfigWitness : RuntimeConfig where
  firecracker := ⟨⟨true, ["safe"]⟩, ⟨1⟩⟩
  kernel := ⟨⟨true, ["safe"]⟩, ⟨1⟩⟩
  rootfs := ⟨⟨true, ["safe"]⟩, ⟨1⟩⟩
  verityHash := ⟨⟨true, ["safe"]⟩, ⟨1⟩⟩
  jailer := ⟨⟨true, ["safe"]⟩, ⟨1⟩⟩
  seccompFilter := ⟨⟨true, ["safe"]⟩, ⟨1⟩⟩
  apiSocket := ⟨true, ["safe"]⟩
  workspaceSource := ⟨true, ["source"]⟩
  workspaceRoot := ⟨true, ["root"]⟩
  workspaceCloneId := "clone"
  verityDataDevice := ⟨true, ["safe"]⟩
  verityHashDevice := ⟨true, ["safe"]⟩
  verityRootHash := ⟨1⟩
  mapperName := "mapper"
  vsockCid := 3
  vsockSocket := ⟨true, ["safe"]⟩
  networkDevices := []
  vcpuCount := 1
  memoryMib := 1
  cgroupPath := ⟨true, ["safe"]⟩
  cgroupMemoryMax := 1
  cgroupCpuQuota := 1
  namespaces := ⟨true, true, true, true, true, true⟩
  blockedSyscalls := requiredBlockedSyscalls
  bootArguments := ""

/-- The launch-configuration validity predicate has a concrete inhabitant. -/
theorem validRuntimeConfigWitness_valid : validRuntimeConfigWitness.Valid := by
  constructor <;>
    simp [validRuntimeConfigWitness, PinnedArtifact.Valid, RuntimePathValid,
      SafeName, NamespaceSwitches.Complete, Isolation.HostPath.AtOrBelow,
      Isolation.HostPath.root] <;>
    native_decide

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

/-- A changed vCPU count is incompatible with the snapshot. -/
theorem fingerprint_changed_by_vcpu_count (config : RuntimeConfig) (count : Nat)
    (different : count ≠ config.vcpuCount) :
    ({ config with vcpuCount := count }).fingerprintPayload ≠
      config.fingerprintPayload := by
  intro compatible
  have configsEqual : { config with vcpuCount := count } = config :=
    fingerprintPayload_eq_iff.mp compatible
  exact different (congrArg RuntimeConfig.vcpuCount configsEqual)

/-- A changed dm-verity mapper is incompatible with the snapshot. -/
theorem fingerprint_changed_by_mapper_name (config : RuntimeConfig)
    (mapperName : String) (different : mapperName ≠ config.mapperName) :
    ({ config with mapperName := mapperName }).fingerprintPayload ≠
      config.fingerprintPayload := by
  intro compatible
  have configsEqual : { config with mapperName := mapperName } = config :=
    fingerprintPayload_eq_iff.mp compatible
  exact different (congrArg RuntimeConfig.mapperName configsEqual)

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

/-- Fingerprint equality now binds shutdown to the instance-owned mapper. -/
theorem fingerprint_match_binds_shutdown_mapper
    {created shutdown : RuntimeConfig}
    (compatible : shutdown.fingerprintPayload =
      (InstanceBinding.fromConfig created).fingerprint) :
    shutdown.mapperName = (InstanceBinding.fromConfig created).mapperName := by
  have configsEqual : shutdown = created := by
    apply fingerprintPayload_eq_iff.mp
    simpa [InstanceBinding.fromConfig] using compatible
  simp [InstanceBinding.fromConfig, configsEqual]

/-- The former mapper-substitution counterexample is excluded by compatibility. -/
theorem changed_mapper_cannot_match_instance_fingerprint
    (config : RuntimeConfig) (otherMapper : String)
    (different : otherMapper ≠ config.mapperName) :
    ({ config with mapperName := otherMapper }).fingerprintPayload ≠
      (InstanceBinding.fromConfig config).fingerprint := by
  simpa [InstanceBinding.fromConfig] using
    fingerprint_changed_by_mapper_name config otherMapper different

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

/-- Concrete fresh identities witnessing that the identity contract is inhabited. -/
def freshIdentityWitness : IdentityBundle where
  vm := 1
  session := 2
  request := 3
  subject := 4
  capability := 5

/-- The concrete bundle is intrinsically valid for a pre-session snapshot. -/
theorem freshIdentityWitness_valid (config : RuntimeConfig) :
    freshIdentityWitness.Valid
      (createInternalSnapshot config).forbiddenIdentities := by
  refine ⟨?_, ?_, ?_⟩
  · intro kind
    cases kind <;> decide
  · intro first second equal
    cases first <;> cases second <;>
      simp [IdentityBundle.forKind, freshIdentityWitness] at equal ⊢
  · intro kind
    simp [createInternalSnapshot]

/-- A copied snapshot identity is rejected, so freshness is not vacuous. -/
theorem forbidden_identity_counterexample_excluded :
    ¬ freshIdentityWitness.Valid [freshIdentityWitness.vm] := by
  intro valid
  exact valid.2.2 .vm (by simp [IdentityBundle.forKind])

/-- Publicly reachable successful lifecycle phases. -/
inductive Phase where
  | workloadStopped
  | snapshotted
  | restoredPaused
  | guestGate
  | identityAcknowledged
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
  | .workloadStopped | .snapshotted | .restoredPaused => state.identities = none
  | .guestGate | .identityAcknowledged | .running =>
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

/-- Restore into a paused guest before any identity can reach the guest gate. -/
def State.restore (snapshot : Snapshot) : State where
  phase := .restoredPaused
  fingerprint := snapshot.fingerprint
  identities := none
  forbiddenIdentities := snapshot.forbiddenIdentities

/-- Install host-generated identities while guest authority remains gated. -/
def State.markGuestGate (state : State) (bundle : IdentityBundle) : State :=
  { state with phase := .guestGate, identities := some bundle }

/-- Record the guest's acknowledgement of the complete fresh identity bundle. -/
def State.markIdentityAcknowledged (state : State) : State :=
  { state with phase := .identityAcknowledged }

/-- Release workload execution only after fresh identity acknowledgement. -/
def State.markRunning (state : State) : State :=
  { state with phase := .running }

/-- Accepted successful lifecycle transitions. -/
inductive Step : State → State → Prop
  | snapshot {state : State} :
      state.phase = .workloadStopped → Step state state.markSnapshotted
  | restore {current : State} {snapshot : Snapshot} :
      current.phase = .snapshotted →
      snapshot.fingerprint = current.fingerprint →
      Step current (State.restore snapshot)
  | regenerate {state : State} {bundle : IdentityBundle} :
      state.phase = .restoredPaused →
      bundle.Valid state.forbiddenIdentities →
      Step state (state.markGuestGate bundle)
  | acknowledge {state : State} {bundle : IdentityBundle} :
      state.phase = .guestGate → state.identities = some bundle →
      Step state state.markIdentityAcknowledged
  | start {state : State} :
      state.phase = .identityAcknowledged → Step state state.markRunning

/-- Every accepted lifecycle transition preserves identity refinement. -/
theorem Step.preserves_wellFormed {before after : State}
    (transition : Step before after) (wellFormed : before.WellFormed) :
    after.WellFormed := by
  cases transition with
  | snapshot phase => simpa [State.markSnapshotted, State.WellFormed, phase] using wellFormed
  | restore phase _ => simp [State.restore, State.WellFormed]
  | regenerate phase valid => exact ⟨_, rfl, valid⟩
  | acknowledge phase identityLookup =>
      simpa [State.markIdentityAcknowledged, State.WellFormed, phase] using wellFormed
  | start phase => simpa [State.markRunning, State.WellFormed, phase] using wellFormed

/-- Running is reachable only with a valid regenerated identity bundle. -/
theorem State.running_has_fresh_identity {state : State}
    (wellFormed : state.WellFormed) (running : state.phase = .running) :
    ∃ bundle, state.identities = some bundle ∧
      bundle.Valid state.forbiddenIdentities := by
  simpa [State.WellFormed, running] using wellFormed

/-- Authority is released exactly when the workload-running phase is published. -/
def State.AuthorityReleased (state : State) : Prop :=
  state.phase = .running

/-- Fresh identity acknowledgement remains observable after workload release. -/
def State.FreshIdentityAcknowledged (state : State) : Prop :=
  (state.phase = .identityAcknowledged ∨ state.phase = .running) ∧
    ∃ bundle, state.identities = some bundle ∧
      bundle.Valid state.forbiddenIdentities

/-- A transition that releases authority must start at the acknowledged identity gate. -/
theorem Step.release_requires_fresh_identity_acknowledgement
    {before after : State} (transition : Step before after)
    (wellFormed : before.WellFormed) (released : after.AuthorityReleased) :
    before.phase = .identityAcknowledged ∧
      ∃ bundle, before.identities = some bundle ∧
        bundle.Valid before.forbiddenIdentities := by
  cases transition with
  | snapshot phase => simp [State.AuthorityReleased, State.markSnapshotted] at released
  | restore phase compatible => simp [State.AuthorityReleased, State.restore] at released
  | regenerate phase valid => simp [State.AuthorityReleased, State.markGuestGate] at released
  | acknowledge phase identityLookup =>
      simp [State.AuthorityReleased, State.markIdentityAcknowledged] at released
  | start phase =>
      refine ⟨phase, ?_⟩
      simpa [State.WellFormed, phase] using wellFormed

/-- Finite successful runtime execution. -/
inductive Steps : State → State → Prop
  | refl (state : State) : Steps state state
  | tail {first middle last : State} :
      Steps first middle → Step middle last → Steps first last

/-- Identity refinement survives every finite successful runtime execution. -/
theorem Steps.preserves_wellFormed {before after : State}
    (transitions : Steps before after) (wellFormed : before.WellFormed) :
    after.WellFormed := by
  induction transitions with
  | refl => exact wellFormed
  | tail _ transition inductionHypothesis =>
      exact transition.preserves_wellFormed inductionHypothesis

/-- Reachability starts from one concrete launched runtime configuration. -/
def State.Reachable (config : RuntimeConfig) (state : State) : Prop :=
  config.Valid ∧ Steps (State.launched config) state

/-- Launch is an inhabited origin for runtime reachability. -/
theorem State.launched_reachable (config : RuntimeConfig) (valid : config.Valid) :
    (State.launched config).Reachable config :=
  ⟨valid, Steps.refl (State.launched config)⟩

/-- Valid launched-origin reachability is concretely nonempty. -/
theorem State.reachable_nonempty :
    ∃ state : State, state.Reachable validRuntimeConfigWitness :=
  ⟨State.launched validRuntimeConfigWitness,
    State.launched_reachable validRuntimeConfigWitness validRuntimeConfigWitness_valid⟩

/-- Every launched-origin reachable state satisfies identity refinement. -/
theorem State.Reachable.wellFormed {config : RuntimeConfig} {state : State}
    (reachable : state.Reachable config) : state.WellFormed :=
  reachable.2.preserves_wellFormed (State.launched_wellFormed config)

/-- Workload release in a reachable state carries a fresh acknowledged bundle. -/
theorem State.Reachable.release_has_fresh_acknowledgement
    {config : RuntimeConfig} {state : State}
    (reachable : state.Reachable config) (released : state.AuthorityReleased) :
    state.FreshIdentityAcknowledged := by
  refine ⟨Or.inr released, ?_⟩
  exact State.running_has_fresh_identity reachable.wellFormed released

/-- Reachable authority release has an acknowledged, fresh immediate predecessor. -/
theorem State.Reachable.no_release_before_fresh_identity_acknowledgement
    {config : RuntimeConfig} {state : State}
    (reachable : state.Reachable config) (released : state.AuthorityReleased) :
    ∃ acknowledged,
      Steps (State.launched config) acknowledged ∧
      acknowledged.phase = .identityAcknowledged ∧
      (∃ bundle, acknowledged.identities = some bundle ∧
        bundle.Valid acknowledged.forbiddenIdentities) ∧
      Step acknowledged state := by
  cases reachable.2 with
  | refl => simp [State.AuthorityReleased, State.launched] at released
  | tail preceding transition =>
      have wellFormed := preceding.preserves_wellFormed
        (State.launched_wellFormed config)
      have gate := transition.release_requires_fresh_identity_acknowledgement
        wellFormed released
      exact ⟨_, preceding, gate.1, gate.2, transition⟩

/-- A restore-shaped result can only follow the snapshot gate. -/
theorem Step.restored_paused_requires_snapshot_gate
    {before after : State} (transition : Step before after)
    (restored : after.phase = .restoredPaused) :
    before.phase = .snapshotted := by
  cases transition with
  | snapshot phase => simp [State.markSnapshotted] at restored
  | restore phase compatible => exact phase
  | regenerate phase valid => simp [State.markGuestGate] at restored
  | acknowledge phase identityLookup =>
      simp [State.markIdentityAcknowledged] at restored
  | start phase => simp [State.markRunning] at restored

/-- Restore cannot bypass the snapshot gate from a running workload. -/
theorem restore_from_running_counterexample_excluded
    {current : State} (snapshot : Snapshot)
    (running : current.phase = .running) :
    ¬ Step current (State.restore snapshot) := by
  intro transition
  have snapshotted := transition.restored_paused_requires_snapshot_gate (by rfl)
  rw [running] at snapshotted
  contradiction

/-- The complete restore/acknowledge/release path is constructively reachable. -/
theorem State.running_constructively_reachable
    (config : RuntimeConfig) (valid : config.Valid) :
    ∃ state : State, state.Reachable config ∧ state.AuthorityReleased ∧
      state.FreshIdentityAcknowledged := by
  let launched := State.launched config
  let snapshotted := launched.markSnapshotted
  let snapshot := createInternalSnapshot config
  let restored := State.restore snapshot
  let gated := restored.markGuestGate freshIdentityWitness
  let acknowledged := gated.markIdentityAcknowledged
  let running := acknowledged.markRunning
  have snapshotStep : Step launched snapshotted := by
    exact Step.snapshot rfl
  have restoreStep : Step snapshotted restored := by
    apply Step.restore
    · rfl
    · rfl
  have regenerateStep : Step restored gated := by
    apply Step.regenerate
    · rfl
    · simpa [restored, snapshot, State.restore] using
        freshIdentityWitness_valid config
  have acknowledgeStep : Step gated acknowledged := by
    exact Step.acknowledge rfl rfl
  have startStep : Step acknowledged running := by
    exact Step.start rfl
  have launchedSteps : Steps launched snapshotted :=
    Steps.tail (Steps.refl launched) snapshotStep
  have restoredSteps : Steps launched restored :=
    Steps.tail launchedSteps restoreStep
  have gatedSteps : Steps launched gated :=
    Steps.tail restoredSteps regenerateStep
  have acknowledgedSteps : Steps launched acknowledged :=
    Steps.tail gatedSteps acknowledgeStep
  have runningSteps : Steps launched running :=
    Steps.tail acknowledgedSteps startStep
  have reachable : running.Reachable config := by
    exact ⟨valid, runningSteps⟩
  exact ⟨running, reachable, rfl,
    reachable.release_has_fresh_acknowledgement rfl⟩

/-- The safety theorem applies to an actual reachable workload release. -/
theorem State.running_reachable_nonempty :
    ∃ state : State,
      state.Reachable validRuntimeConfigWitness ∧
      state.AuthorityReleased ∧ state.FreshIdentityAcknowledged :=
  State.running_constructively_reachable validRuntimeConfigWitness
    validRuntimeConfigWitness_valid

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
    State.markGuestGate, State.markIdentityAcknowledged, State.markRunning]

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
