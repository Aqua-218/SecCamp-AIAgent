import Authority.State

/-!
# Checked Capability-State Observations

Versioned logical observation records for refinement checks. These records
carry a complete Lean `CapabilityState` plus redundant scalar fields that a
producer must report consistently. Validation establishes only consistency of
the supplied data; it does not establish that any Rust process produced it.
-/

namespace Authority.Refinement

/-- Schema version understood by this checker. -/
def observationSchemaVersion : Nat := 1

/-- A versioned logical snapshot with independently checked scalar fields. -/
structure StateSnapshot where
  schemaVersion : Nat
  model : Authority.CapabilityState
  issuer : IssuerId
  authorizationEpoch : Nat
  nextCapabilitySequence : Nat
  capabilityIdsExhausted : Bool

namespace StateSnapshot

/-- Construct the canonical current-version observation of a logical state. -/
def ofState (state : Authority.CapabilityState) : StateSnapshot where
  schemaVersion := observationSchemaVersion
  model := state
  issuer := state.issuer
  authorizationEpoch := state.authorizationEpoch
  nextCapabilitySequence := state.nextCapabilitySequence
  capabilityIdsExhausted := state.capabilityIdsExhausted

/-- Executably reject unknown versions and inconsistent scalar observations. -/
def validate (snapshot : StateSnapshot) : Bool :=
  snapshot.schemaVersion == observationSchemaVersion &&
    snapshot.issuer.value == snapshot.model.issuer.value &&
    snapshot.authorizationEpoch == snapshot.model.authorizationEpoch &&
    snapshot.nextCapabilitySequence == snapshot.model.nextCapabilitySequence &&
    snapshot.capabilityIdsExhausted == snapshot.model.capabilityIdsExhausted

/-- Logical denotation of a validated snapshot at one abstract state. -/
def Denotes (snapshot : StateSnapshot)
    (state : Authority.CapabilityState) : Prop :=
  snapshot.model = state ∧
    snapshot.schemaVersion = observationSchemaVersion ∧
    snapshot.issuer.value = state.issuer.value ∧
    snapshot.authorizationEpoch = state.authorizationEpoch ∧
    snapshot.nextCapabilitySequence = state.nextCapabilitySequence ∧
    snapshot.capabilityIdsExhausted = state.capabilityIdsExhausted

/-- Canonical snapshots pass the executable schema check. -/
theorem validate_ofState (state : Authority.CapabilityState) :
    (ofState state).validate = true := by
  simp [validate, ofState]

/-- Validation soundness concerns the supplied logical model, not an external observer. -/
theorem validate_sound {snapshot : StateSnapshot}
    (valid : snapshot.validate = true) : snapshot.Denotes snapshot.model := by
  simp only [validate, Bool.and_eq_true] at valid
  rcases valid with ⟨⟨⟨⟨version, issuer⟩, epoch⟩, sequence⟩, exhausted⟩
  refine ⟨rfl, by simpa using version, ?_, by simpa using epoch,
    by simpa using sequence, by simpa using exhausted⟩
  simpa using issuer

/-- Canonical snapshots denote exactly their source state. -/
theorem ofState_denotes (state : Authority.CapabilityState) :
    (ofState state).Denotes state := by
  simp [Denotes, ofState]

end StateSnapshot

end Authority.Refinement
