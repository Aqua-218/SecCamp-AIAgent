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

/-- Pure artifact validation predicate. -/
def PinnedArtifact.Valid (artifact : PinnedArtifact) : Prop :=
  artifact.path.CleanAbsolute ∧ artifact.digest.value ≠ 0

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
  workspaceCloneIdSafe : Bool
  verityDataDevice : Isolation.HostPath
  verityHashDevice : Isolation.HostPath
  verityRootHash : Digest
  mapperNameSafe : Bool
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
  apiSocketSafe : config.apiSocket.CleanAbsolute
  workspaceSourceSafe : config.workspaceSource.CleanAbsolute
  workspaceRootSafe : config.workspaceRoot.CleanAbsolute
  verityDataSafe : config.verityDataDevice.CleanAbsolute
  verityHashDeviceSafe : config.verityHashDevice.CleanAbsolute
  vsockSocketSafe : config.vsockSocket.CleanAbsolute
  cgroupPathSafe : config.cgroupPath.CleanAbsolute
  verityDataMatchesRootfs : config.verityDataDevice = config.rootfs.path
  verityHashMatchesArtifact : config.verityHashDevice = config.verityHash.path
  verityRootHashNonzero : config.verityRootHash.value ≠ 0
  mapperNameValid : config.mapperNameSafe = true
  cloneIdValid : config.workspaceCloneIdSafe = true
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

end Firecracker

end Authority
