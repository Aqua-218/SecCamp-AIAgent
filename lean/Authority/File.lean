import Authority.Path
import Authority.Repository

/-!
# File Authorities

File effects, authority request semantics, and proofs that the executable
delegation rule is reflexive, transitive, and sound.
-/

namespace Authority

/-- A filesystem effect that can be authorized independently. -/
inductive FileEffect where
  /-- Reads file contents. -/
  | readData
  /-- Lists entries in a directory. -/
  | listDirectory
  /-- Writes file contents without truncating first. -/
  | writeData
  /-- Changes a file's length. -/
  | truncate
  /-- Creates a regular file. -/
  | createFile
  /-- Creates a directory. -/
  | createDirectory
  /-- Removes a regular file. -/
  | removeFile
  /-- Removes a directory. -/
  | removeDirectory
  /-- Renames a file or directory. -/
  | rename
  /-- Changes supported metadata such as mode or timestamps. -/
  | setMetadata
  deriving Repr, BEq, DecidableEq

/-- A set of permitted file effects represented by its membership decision. -/
abbrev FileEffects := FileEffect → Bool

namespace FileEffects

/-- The effect set that permits no requests. -/
def empty : FileEffects := fun _ => false

/-- The effect set containing exactly `selected`. -/
def only (selected : FileEffect) : FileEffects := fun effect => effect == selected

/-- Creates an effect set from a list, ignoring duplicate entries. -/
def ofList (effects : List FileEffect) : FileEffects := fun effect => effects.contains effect

/-- States that at least one effect belongs to the set. -/
def Nonempty (effects : FileEffects) : Prop := ∃ effect, effects effect = true

end FileEffects

private def allFileEffects : List FileEffect :=
  [.readData, .listDirectory, .writeData, .truncate, .createFile,
    .createDirectory, .removeFile, .removeDirectory, .rename, .setMetadata]

private theorem FileEffect.mem_allFileEffects (effect : FileEffect) :
    effect ∈ allFileEffects := by
  cases effect <;> simp [allFileEffects]

/-- Returns whether every child effect also belongs to the parent set. -/
def fileEffectsBelow (child parent : FileEffects) : Bool :=
  allFileEffects.all fun effect => !child effect || parent effect

/-- Effect-set containment decides pointwise membership implication. -/
theorem fileEffectsBelow_iff_subset {child parent : FileEffects} :
    fileEffectsBelow child parent = true ↔
      ∀ effect, child effect = true → parent effect = true := by
  rw [fileEffectsBelow, List.all_eq_true]
  constructor
  · intro allEffects effect childContains
    have condition := allEffects effect effect.mem_allFileEffects
    simpa [childContains] using condition
  · intro isSubset effect _
    cases childContains : child effect with
    | false => simp [childContains]
    | true => simp [childContains, isSubset effect childContains]

/-- Effect-set containment is reflexive. -/
theorem fileEffectsBelow_refl (effects : FileEffects) :
    fileEffectsBelow effects effects = true :=
  fileEffectsBelow_iff_subset.mpr fun _ contains => contains

/-- Effect-set containment is transitive. -/
theorem fileEffectsBelow_trans {first second third : FileEffects}
    (firstBelowSecond : fileEffectsBelow first second = true)
    (secondBelowThird : fileEffectsBelow second third = true) :
    fileEffectsBelow first third = true := by
  apply fileEffectsBelow_iff_subset.mpr
  intro effect firstContains
  exact fileEffectsBelow_iff_subset.mp secondBelowThird effect
    (fileEffectsBelow_iff_subset.mp firstBelowSecond effect firstContains)

/-- The file operations permitted within one repository and path pattern. -/
structure FileAuthority where
  /-- The governed repository. -/
  repository : RepoId
  /-- The permitted effects. -/
  effects : FileEffects
  /-- The governed path pattern. -/
  path : PathPattern

/-- A single filesystem authorization request. -/
structure FileRequest where
  /-- The target repository. -/
  repository : RepoId
  /-- The requested effect. -/
  effect : FileEffect
  /-- The target path. -/
  path : CanonicalPath

namespace FileAuthority

/-- States that an authority permits a request. -/
def Matches (authority : FileAuthority) (request : FileRequest) : Prop :=
  authority.repository = request.repository ∧
    authority.effects request.effect = true ∧
    authority.path.Matches request.path

end FileAuthority

/-- Returns whether `authority` permits `request`. -/
def fileMatches (authority : FileAuthority) (request : FileRequest) : Bool :=
  decide (authority.repository = request.repository) &&
    authority.effects request.effect &&
    pathMatches authority.path request.path

/-- The executable file matching decision exactly represents `Matches`. -/
theorem fileMatches_iff_matches {authority : FileAuthority} {request : FileRequest} :
    fileMatches authority request = true ↔ authority.Matches request := by
  simp only [fileMatches, Bool.and_eq_true, decide_eq_true_eq, pathMatches_iff_matches]
  constructor
  · intro executableMatches
    exact ⟨executableMatches.1.1, executableMatches.1.2, executableMatches.2⟩
  · intro semanticMatches
    exact ⟨⟨semanticMatches.1, semanticMatches.2.1⟩, semanticMatches.2.2⟩

/-- Returns whether `child` satisfies the structural file-delegation rule. -/
def fileBodyBelow (child parent : FileAuthority) : Bool :=
  decide (child.repository = parent.repository) &&
    fileEffectsBelow child.effects parent.effects &&
    pathBelow child.path parent.path

/-- File authority containment is reflexive. -/
theorem fileBodyBelow_refl (authority : FileAuthority) :
    fileBodyBelow authority authority = true := by
  simp [fileBodyBelow, fileEffectsBelow_refl, pathBelow_refl]

/-- File authority containment is transitive. -/
theorem fileBodyBelow_trans {first second third : FileAuthority}
    (firstBelowSecond : fileBodyBelow first second = true)
    (secondBelowThird : fileBodyBelow second third = true) :
    fileBodyBelow first third = true := by
  simp only [fileBodyBelow, Bool.and_eq_true, decide_eq_true_eq]
    at firstBelowSecond secondBelowThird ⊢
  exact ⟨⟨firstBelowSecond.1.1.trans secondBelowThird.1.1,
    fileEffectsBelow_trans firstBelowSecond.1.2 secondBelowThird.1.2⟩,
    pathBelow_trans firstBelowSecond.2 secondBelowThird.2⟩

/-- A successful file containment decision implies semantic set inclusion. -/
theorem fileBodyBelow_sound {child parent : FileAuthority}
    (isBelow : fileBodyBelow child parent = true) :
    ∀ request, child.Matches request → parent.Matches request := by
  simp only [fileBodyBelow, Bool.and_eq_true, decide_eq_true_eq] at isBelow
  intro request childMatches
  exact ⟨isBelow.1.1.symm.trans childMatches.1,
    fileEffectsBelow_iff_subset.mp isBelow.1.2 request.effect childMatches.2.1,
    pathBelow_sound isBelow.2 request.path childMatches.2.2⟩

private theorem PathPattern.hasMatch (pattern : PathPattern) :
    ∃ path, pattern.Matches path := by
  cases pattern with
  | exact path => exact ⟨path, rfl⟩
  | «prefix» path => exact ⟨path, List.prefix_rfl⟩

/--
Semantic inclusion implies the structural decision when the child permits at
least one effect. Without this premise, an empty child denotes the empty set
regardless of its repository and path, so unconditional completeness is false.
-/
theorem fileBodyBelow_complete_of_effects_nonempty {child parent : FileAuthority}
    (hasEffect : child.effects.Nonempty)
    (isSubset : ∀ request, child.Matches request → parent.Matches request) :
    fileBodyBelow child parent = true := by
  rcases hasEffect with ⟨witnessEffect, witnessEffectEnabled⟩
  rcases child.path.hasMatch with ⟨witnessPath, witnessPathMatches⟩
  have parentMatchesWitness := isSubset
    { repository := child.repository
      effect := witnessEffect
      path := witnessPath }
    ⟨rfl, witnessEffectEnabled, witnessPathMatches⟩
  have repositoryBelow : child.repository = parent.repository :=
    parentMatchesWitness.1.symm
  have effectsBelow : fileEffectsBelow child.effects parent.effects = true := by
    apply fileEffectsBelow_iff_subset.mpr
    intro effect childContains
    exact (isSubset
      { repository := child.repository
        effect
        path := witnessPath }
      ⟨rfl, childContains, witnessPathMatches⟩).2.1
  have pathsBelow : pathBelow child.path parent.path = true := by
    apply pathBelow_complete
    intro path childPathMatches
    exact (isSubset
      { repository := child.repository
        effect := witnessEffect
        path }
      ⟨rfl, witnessEffectEnabled, childPathMatches⟩).2.2
  simp only [fileBodyBelow, Bool.and_eq_true, decide_eq_true_eq]
  exact ⟨⟨repositoryBelow, effectsBelow⟩, pathsBelow⟩

/--
For a child with at least one effect, the executable decision exactly
characterizes semantic request-set inclusion.
-/
theorem fileBodyBelow_iff_matches_subset_of_effects_nonempty
    {child parent : FileAuthority} (hasEffect : child.effects.Nonempty) :
    fileBodyBelow child parent = true ↔
      ∀ request, child.Matches request → parent.Matches request :=
  ⟨fileBodyBelow_sound, fileBodyBelow_complete_of_effects_nonempty hasEffect⟩

end Authority
