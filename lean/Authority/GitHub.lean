import Authority.Repository

/-!
# GitHub Authorities

Closed GitHub operations, validated branch selectors, executable authorization
decisions, and proofs that delegation preserves the permitted request set.
-/

namespace Authority

/-- An opaque GitHub App installation identity assigned by the session host. -/
structure InstallationId where
  /-- The uninterpreted host-assigned identity. -/
  value : String
  deriving Repr, BEq, DecidableEq

/-- Returns whether a character is forbidden in a Git branch component. -/
def isForbiddenBranchCharacter (character : Char) : Bool :=
  decide (character.toNat < 0x20) ||
    decide (0x7f ≤ character.toNat && character.toNat ≤ 0x9f) ||
    character == ' ' ||
    character == '~' ||
    character == '^' ||
    character == ':' ||
    character == '?' ||
    character == '*' ||
    character == '[' ||
    character == '\\' ||
    character == '/'

private def containsSubsequence (needle : List Char) : List Char → Bool
  | [] => false
  | haystack :: remaining =>
    needle.isPrefixOf (haystack :: remaining) ||
      containsSubsequence needle remaining

private def containsBranchSequence (needle : List Char) (segment : String) : Bool :=
  containsSubsequence needle segment.toList

/-- Returns whether a string is a safe Git branch-name component. -/
def isValidBranchSegment (segment : String) : Bool :=
  let characters := segment.toList
  !characters.isEmpty &&
    characters.head? != some '.' &&
    !['.', 'l', 'o', 'c', 'k'].isSuffixOf characters &&
    !segment.endsWith "." &&
    !containsBranchSequence ['.', '.'] segment &&
    !containsBranchSequence ['@', '{'] segment &&
    !characters.any isForbiddenBranchCharacter

private def firstSegmentStartsWithDash : List String → Bool
  | [] => false
  | first :: _ => first.toList.head? == some '-'

private def isRefsNamespace : List String → Bool
  | "refs" :: _ :: _ => true
  | _ => false

/-- Returns whether slash-separated segments form a safe branch shorthand. -/
def isValidBranchName (segments : List String) : Bool :=
  segments.all isValidBranchSegment &&
    (!segments.isEmpty &&
      !firstSegmentStartsWithDash segments &&
      !isRefsNamespace segments &&
      segments != ["@"])

/--
A Git branch name whose components have passed validation.

Components make prefix delegation segment-aware, so a prefix such as
`agents/alice` cannot accidentally include `agents/alice-other`.
-/
structure BranchName where
  /-- Validated slash-separated branch-name components in order. -/
  segments : List String
  /-- Evidence that the complete branch shorthand satisfies every validation rule. -/
  isValid : isValidBranchName segments = true

namespace BranchName

private def childSuffix : BranchName :=
  { segments := ["child"]
    isValid := by native_decide }

private theorem childSuffixIsValid :
    childSuffix.segments.all isValidBranchSegment = true := by
  native_decide

/-- Creates a branch name when every supplied component is valid. -/
def ofSegments (segments : List String) : Option BranchName :=
  if isValid : isValidBranchName segments = true then
    some ⟨segments, isValid⟩
  else
    none

/-- Concatenates branch-name components and revalidates the complete shorthand. -/
def append (branch suffix : BranchName) : Option BranchName :=
  ofSegments (branch.segments ++ suffix.segments)

private def refsBranch : BranchName :=
  { segments := ["refs"]
    isValid := by native_decide }

private def headsBranch : BranchName :=
  { segments := ["heads"]
    isValid := by native_decide }

/-- The append rejection example uses two independently constructible branch names. -/
theorem refsHeadsComponents_nonempty :
    (ofSegments ["refs"]).isSome = true ∧
      (ofSegments ["heads"]).isSome = true := by
  native_decide

/-- The full branch validator rejects the reserved `refs/heads` spelling. -/
theorem refsHeads_rejected : (ofSegments ["refs", "heads"]).isNone = true := by
  native_decide

/-- Revalidation rejects composing valid `refs` and `heads` values into `refs/heads`. -/
theorem append_refs_heads_rejected : (append refsBranch headsBranch).isNone = true := by
  native_decide

/-- A valid shorthand below `refs` can only be the one-level branch `refs` itself. -/
theorem eq_refs_of_refs_prefix (branch : BranchName)
    (hasRefsPrefix : ["refs"] <+: branch.segments) : branch.segments = ["refs"] := by
  rcases hasRefsPrefix with ⟨suffix, segmentsEq⟩
  have branchIsValid := branch.isValid
  rw [← segmentsEq] at branchIsValid ⊢
  cases suffix with
  | nil => rfl
  | cons first remaining =>
      simp [isValidBranchName, isRefsNamespace] at branchIsValid

/-- Appending the fixed child segment preserves validity except under reserved `refs`. -/
theorem childAppendValid (branch : BranchName)
    (isNotRefs : branch.segments ≠ ["refs"]) :
    isValidBranchName (branch.segments ++ childSuffix.segments) = true := by
  have branchIsValid := branch.isValid
  simp only [isValidBranchName, Bool.and_eq_true] at branchIsValid ⊢
  refine ⟨?_, ?_⟩
  · simpa [List.all_append] using
      And.intro branchIsValid.1 childSuffixIsValid
  · cases segmentsEq : branch.segments with
    | nil => simp [segmentsEq] at branchIsValid
    | cons first remaining =>
      simp only [segmentsEq, List.cons_append, firstSegmentStartsWithDash]
      simp only [segmentsEq, firstSegmentStartsWithDash] at branchIsValid
      refine ⟨⟨⟨by simp, branchIsValid.2.1.1.2⟩, ?_⟩, by simp [childSuffix]⟩
      by_cases firstIsRefs : first = "refs"
      · subst first
        cases remaining with
        | nil => exact False.elim (isNotRefs (by simp [segmentsEq]))
        | cons second rest =>
            simp [isRefsNamespace] at branchIsValid
      · simp [isRefsNamespace, firstIsRefs]

/-- Any valid shorthand other than `refs` remains valid after a `/child` suffix. -/
theorem append_child_is_some (branch : BranchName)
    (isNotRefs : branch.segments ≠ ["refs"]) :
    append branch childSuffix =
      some
        { segments := branch.segments ++ childSuffix.segments
          isValid := childAppendValid branch isNotRefs } := by
  simp [append, ofSegments, childAppendValid branch isNotRefs]

end BranchName

/-- A safe, segment-aware branch selector. -/
inductive BranchPattern where
  /-- Selects exactly one branch. -/
  | exact (branch : BranchName)
  /-- Selects a branch and all branches below it by component. -/
  | prefix (branch : BranchName)

namespace BranchPattern

/-- States that a pattern selects a branch. -/
def Matches (pattern : BranchPattern) (branch : BranchName) : Prop :=
  match pattern with
  | .exact selected => selected.segments = branch.segments
  | .prefix selected => selected.segments <+: branch.segments

end BranchPattern

/-- Returns whether `pattern` selects `branch`. -/
def branchMatches (pattern : BranchPattern) (branch : BranchName) : Bool :=
  match pattern with
  | .exact selected => selected.segments == branch.segments
  | .prefix selected => selected.segments.isPrefixOf branch.segments

/-- The executable branch check exactly represents `BranchPattern.Matches`. -/
theorem branchMatches_iff_matches {pattern : BranchPattern} {branch : BranchName} :
    branchMatches pattern branch = true ↔ pattern.Matches branch := by
  cases pattern <;> simp [branchMatches, BranchPattern.Matches]

/-- Returns whether every branch selected by `child` is also selected by `parent`. -/
def branchPatternBelow (child parent : BranchPattern) : Bool :=
  match child, parent with
  | .exact child, .exact parent => child.segments == parent.segments
  | .exact child, .prefix parent => parent.segments.isPrefixOf child.segments
  | .prefix child, .prefix parent => parent.segments.isPrefixOf child.segments
  | .prefix child, .exact parent =>
      child.segments == ["refs"] && parent.segments == ["refs"]

/-- Branch-pattern containment is reflexive. -/
theorem branchPatternBelow_refl (pattern : BranchPattern) :
    branchPatternBelow pattern pattern = true := by
  cases pattern <;> simp [branchPatternBelow]

/-- Branch-pattern containment is transitive. -/
theorem branchPatternBelow_trans {first second third : BranchPattern}
    (firstBelowSecond : branchPatternBelow first second = true)
    (secondBelowThird : branchPatternBelow second third = true) :
    branchPatternBelow first third = true := by
  cases first with
  | exact firstBranch =>
      cases second with
      | exact secondBranch =>
          cases third with
          | exact thirdBranch =>
              simp [branchPatternBelow] at firstBelowSecond secondBelowThird ⊢
              exact firstBelowSecond.trans secondBelowThird
          | «prefix» thirdBranch =>
              simp [branchPatternBelow] at firstBelowSecond secondBelowThird ⊢
              rw [firstBelowSecond]
              exact secondBelowThird
      | «prefix» secondBranch =>
          cases third with
          | exact thirdBranch =>
              simp [branchPatternBelow] at firstBelowSecond secondBelowThird ⊢
              have firstIsRefs := BranchName.eq_refs_of_refs_prefix firstBranch
                (secondBelowThird.1 ▸ firstBelowSecond)
              exact firstIsRefs.trans secondBelowThird.2.symm
          | «prefix» thirdBranch =>
              simp [branchPatternBelow] at firstBelowSecond secondBelowThird ⊢
              exact secondBelowThird.trans firstBelowSecond
  | «prefix» firstBranch =>
      cases second with
      | exact secondBranch =>
          cases third with
          | exact thirdBranch =>
              simp [branchPatternBelow] at firstBelowSecond secondBelowThird ⊢
              exact ⟨firstBelowSecond.1, secondBelowThird ▸ firstBelowSecond.2⟩
          | «prefix» thirdBranch =>
              simp [branchPatternBelow] at firstBelowSecond secondBelowThird ⊢
              rw [firstBelowSecond.1]
              exact firstBelowSecond.2 ▸ secondBelowThird
      | «prefix» secondBranch =>
          cases third with
          | exact thirdBranch =>
              simp [branchPatternBelow] at firstBelowSecond secondBelowThird ⊢
              have firstIsRefs := BranchName.eq_refs_of_refs_prefix firstBranch
                (secondBelowThird.1 ▸ firstBelowSecond)
              exact ⟨firstIsRefs, secondBelowThird.2⟩
          | «prefix» thirdBranch =>
              simp [branchPatternBelow] at firstBelowSecond secondBelowThird ⊢
              exact secondBelowThird.trans firstBelowSecond

/-- A successful branch-pattern decision implies semantic set inclusion. -/
theorem branchPatternBelow_sound {child parent : BranchPattern}
    (isBelow : branchPatternBelow child parent = true) :
    ∀ branch, child.Matches branch → parent.Matches branch := by
  intro branch childMatches
  cases child <;> cases parent <;>
    simp [branchPatternBelow] at isBelow <;>
    simp [BranchPattern.Matches] at childMatches ⊢
  · exact isBelow.symm.trans childMatches
  · rw [← childMatches]
    exact isBelow
  · rw [isBelow.2]
    exact (BranchName.eq_refs_of_refs_prefix branch (isBelow.1 ▸ childMatches)).symm
  · exact isBelow.trans childMatches

/-- Semantic branch-set inclusion implies a successful containment decision. -/
theorem branchPatternBelow_complete {child parent : BranchPattern}
    (isSubset : ∀ branch, child.Matches branch → parent.Matches branch) :
    branchPatternBelow child parent = true := by
  cases child <;> cases parent <;>
    simp [branchPatternBelow, BranchPattern.Matches] at isSubset ⊢
  · exact (isSubset _ rfl).symm
  · exact isSubset _ rfl
  · rename_i childBranch parentBranch
    have parentMatchesChild := isSubset childBranch List.prefix_rfl
    cases childIsRefs : childBranch.segments == ["refs"] with
    | false =>
        have childIsNotRefs : childBranch.segments ≠ ["refs"] := by
          simpa using childIsRefs
        let descendant : BranchName :=
          { segments := childBranch.segments ++ BranchName.childSuffix.segments
            isValid := BranchName.childAppendValid childBranch childIsNotRefs }
        have parentMatchesDescendant : parentBranch.segments = descendant.segments :=
          isSubset descendant ⟨BranchName.childSuffix.segments, rfl⟩
        have : False := by
          have suffixMustBeEmpty : BranchName.childSuffix.segments = [] := by
            apply List.append_cancel_left
            calc
              childBranch.segments ++ BranchName.childSuffix.segments
                  = descendant.segments := rfl
              _ = parentBranch.segments := parentMatchesDescendant.symm
              _ = childBranch.segments := parentMatchesChild
              _ = childBranch.segments ++ [] := by simp
          simp [BranchName.childSuffix] at suffixMustBeEmpty
        exact False.elim this
    | true =>
        have childIsRefs : childBranch.segments = ["refs"] := by
          simpa using childIsRefs
        exact ⟨childIsRefs, parentMatchesChild.trans childIsRefs⟩
  · exact isSubset _ List.prefix_rfl

/-- The executable decision exactly characterizes semantic branch-set inclusion. -/
theorem branchPatternBelow_iff_matches_subset {child parent : BranchPattern} :
    branchPatternBelow child parent = true ↔
      ∀ branch, child.Matches branch → parent.Matches branch :=
  ⟨branchPatternBelow_sound, branchPatternBelow_complete⟩

private theorem BranchPattern.hasMatch (pattern : BranchPattern) :
    ∃ branch, pattern.Matches branch := by
  cases pattern with
  | exact branch => exact ⟨branch, rfl⟩
  | «prefix» branch => exact ⟨branch, List.prefix_rfl⟩

/--
A GitHub operation for which the broker has a dedicated request builder.

No constructor represents arbitrary HTTP methods, paths, headers, or bodies.
-/
inductive GitHubOperation where
  /-- Publishes a branch using an expected old object ID. -/
  | publishBranch
  /-- Creates a pull request between an authorized base and head branch. -/
  | createPullRequest
  deriving Repr, BEq, DecidableEq

/-- A set of permitted closed GitHub operations represented by membership. -/
abbrev GitHubOperations := GitHubOperation → Bool

namespace GitHubOperations

/-- The operation set that permits no requests. -/
def empty : GitHubOperations := fun _ => false

/-- The operation set containing exactly `selected`. -/
def only (selected : GitHubOperation) : GitHubOperations := fun operation => operation == selected

/-- Creates an operation set from a list, ignoring duplicate entries. -/
def ofList (operations : List GitHubOperation) : GitHubOperations :=
  fun operation => operations.contains operation

/-- States that at least one operation belongs to the set. -/
def Nonempty (operations : GitHubOperations) : Prop :=
  ∃ operation, operations operation = true

end GitHubOperations

private def allGitHubOperations : List GitHubOperation :=
  [.publishBranch, .createPullRequest]

private theorem GitHubOperation.mem_allGitHubOperations (operation : GitHubOperation) :
    operation ∈ allGitHubOperations := by
  cases operation <;> simp [allGitHubOperations]

/-- Returns whether every child operation also belongs to the parent set. -/
def gitHubOperationsBelow (child parent : GitHubOperations) : Bool :=
  allGitHubOperations.all fun operation => !child operation || parent operation

/-- Operation-set containment decides pointwise membership implication. -/
theorem gitHubOperationsBelow_iff_subset {child parent : GitHubOperations} :
    gitHubOperationsBelow child parent = true ↔
      ∀ operation, child operation = true → parent operation = true := by
  rw [gitHubOperationsBelow, List.all_eq_true]
  constructor
  · intro allOperations operation childContains
    have condition := allOperations operation operation.mem_allGitHubOperations
    simpa [childContains] using condition
  · intro isSubset operation _
    cases childContains : child operation with
    | false => simp [childContains]
    | true => simp [childContains, isSubset operation childContains]

/-- Operation-set containment is reflexive. -/
theorem gitHubOperationsBelow_refl (operations : GitHubOperations) :
    gitHubOperationsBelow operations operations = true :=
  gitHubOperationsBelow_iff_subset.mpr fun _ contains => contains

/-- Operation-set containment is transitive. -/
theorem gitHubOperationsBelow_trans {first second third : GitHubOperations}
    (firstBelowSecond : gitHubOperationsBelow first second = true)
    (secondBelowThird : gitHubOperationsBelow second third = true) :
    gitHubOperationsBelow first third = true := by
  apply gitHubOperationsBelow_iff_subset.mpr
  intro operation firstContains
  exact gitHubOperationsBelow_iff_subset.mp secondBelowThird operation
    (gitHubOperationsBelow_iff_subset.mp firstBelowSecond operation firstContains)

/-- The GitHub operations, installation, repository, and branches a capability governs. -/
structure GitHubAuthority where
  /-- The GitHub App installation through which the broker performs the action. -/
  installation : InstallationId
  /-- The exact repository the action targets. -/
  repository : RepoId
  /-- The permitted dedicated broker operations. -/
  operations : GitHubOperations
  /-- The permitted pull-request base branches. -/
  base : BranchPattern
  /-- The permitted published and pull-request head branches. -/
  head : BranchPattern

/-- A single closed GitHub authorization request. -/
structure GitHubRequest where
  /-- The GitHub App installation used for this request. -/
  installation : InstallationId
  /-- The target repository. -/
  repository : RepoId
  /-- The dedicated operation to perform. -/
  operation : GitHubOperation
  /-- The pull-request base branch or branch comparison base. -/
  base : BranchName
  /-- The branch to publish or use as a pull-request head. -/
  head : BranchName

namespace GitHubAuthority

/-- States that an authority permits a GitHub request. -/
def Matches (authority : GitHubAuthority) (request : GitHubRequest) : Prop :=
  authority.installation = request.installation ∧
    authority.repository = request.repository ∧
    authority.operations request.operation = true ∧
    authority.base.Matches request.base ∧
    authority.head.Matches request.head

/-- States that the authority permits at least one GitHub request. -/
def Nonempty (authority : GitHubAuthority) : Prop :=
  ∃ request, authority.Matches request

end GitHubAuthority

/-- Returns whether `authority` permits `request`. -/
def gitHubMatches (authority : GitHubAuthority) (request : GitHubRequest) : Bool :=
  decide (authority.installation = request.installation) &&
    (decide (authority.repository = request.repository) &&
      (authority.operations request.operation &&
        (branchMatches authority.base request.base &&
          branchMatches authority.head request.head)))

/-- The executable GitHub check exactly represents `GitHubAuthority.Matches`. -/
theorem gitHubMatches_iff_matches {authority : GitHubAuthority} {request : GitHubRequest} :
    gitHubMatches authority request = true ↔ authority.Matches request := by
  simp [gitHubMatches, GitHubAuthority.Matches, branchMatches_iff_matches]

/-- Returns whether `child` satisfies the structural GitHub-delegation rule. -/
def gitHubBodyBelow (child parent : GitHubAuthority) : Bool :=
  decide (child.installation = parent.installation) &&
    (decide (child.repository = parent.repository) &&
      (gitHubOperationsBelow child.operations parent.operations &&
        (branchPatternBelow child.base parent.base &&
          branchPatternBelow child.head parent.head)))

/-- The executable containment check exactly represents component containment. -/
theorem gitHubBodyBelow_iff_components {child parent : GitHubAuthority} :
    gitHubBodyBelow child parent = true ↔
      child.installation = parent.installation ∧
        child.repository = parent.repository ∧
        gitHubOperationsBelow child.operations parent.operations = true ∧
        branchPatternBelow child.base parent.base = true ∧
        branchPatternBelow child.head parent.head = true := by
  simp [gitHubBodyBelow]

/-- GitHub authority containment is reflexive. -/
theorem gitHubBodyBelow_refl (authority : GitHubAuthority) :
    gitHubBodyBelow authority authority = true := by
  simp [gitHubBodyBelow, gitHubOperationsBelow_refl, branchPatternBelow_refl]

/-- GitHub authority containment is transitive. -/
theorem gitHubBodyBelow_trans {first second third : GitHubAuthority}
    (firstBelowSecond : gitHubBodyBelow first second = true)
    (secondBelowThird : gitHubBodyBelow second third = true) :
    gitHubBodyBelow first third = true := by
  rw [gitHubBodyBelow_iff_components] at firstBelowSecond secondBelowThird ⊢
  exact ⟨firstBelowSecond.1.trans secondBelowThird.1,
    firstBelowSecond.2.1.trans secondBelowThird.2.1,
    gitHubOperationsBelow_trans firstBelowSecond.2.2.1 secondBelowThird.2.2.1,
    branchPatternBelow_trans firstBelowSecond.2.2.2.1 secondBelowThird.2.2.2.1,
    branchPatternBelow_trans firstBelowSecond.2.2.2.2 secondBelowThird.2.2.2.2⟩

/-- A successful GitHub containment decision implies semantic request-set inclusion. -/
theorem gitHubBodyBelow_sound {child parent : GitHubAuthority}
    (isBelow : gitHubBodyBelow child parent = true) :
    ∀ request, child.Matches request → parent.Matches request := by
  rw [gitHubBodyBelow_iff_components] at isBelow
  intro request childMatches
  exact ⟨isBelow.1.symm.trans childMatches.1,
    isBelow.2.1.symm.trans childMatches.2.1,
    gitHubOperationsBelow_iff_subset.mp isBelow.2.2.1 request.operation childMatches.2.2.1,
    branchPatternBelow_sound isBelow.2.2.2.1 request.base childMatches.2.2.2.1,
    branchPatternBelow_sound isBelow.2.2.2.2 request.head childMatches.2.2.2.2⟩

/-- A nonempty operation set makes a GitHub authority semantically nonempty. -/
theorem gitHubAuthority_nonempty_of_operations_nonempty {authority : GitHubAuthority}
    (hasOperation : authority.operations.Nonempty) : authority.Nonempty := by
  rcases hasOperation with ⟨operation, operationEnabled⟩
  rcases authority.base.hasMatch with ⟨base, baseMatches⟩
  rcases authority.head.hasMatch with ⟨head, headMatches⟩
  let request : GitHubRequest :=
    { installation := authority.installation
      repository := authority.repository
      operation := operation
      base := base
      head := head }
  refine ⟨request, ?_⟩
  exact ⟨rfl, rfl, operationEnabled, baseMatches, headMatches⟩

/-- A semantically nonempty GitHub authority has a nonempty operation set. -/
theorem gitHubOperations_nonempty_of_authority_nonempty {authority : GitHubAuthority}
    (hasRequest : authority.Nonempty) : authority.operations.Nonempty := by
  rcases hasRequest with ⟨request, requestMatches⟩
  exact ⟨request.operation, requestMatches.2.2.1⟩

/-- GitHub authority nonemptiness is equivalent to operation-set nonemptiness. -/
theorem gitHubAuthority_nonempty_iff_operations_nonempty (authority : GitHubAuthority) :
    authority.Nonempty ↔ authority.operations.Nonempty :=
  ⟨gitHubOperations_nonempty_of_authority_nonempty,
    gitHubAuthority_nonempty_of_operations_nonempty⟩

/--
Semantic inclusion implies structural containment for an authority with a
permitted operation. Without nonemptiness, every empty operation set denotes
the same empty request set regardless of installation, repository, or branches.
-/
theorem gitHubBodyBelow_complete_of_operations_nonempty {child parent : GitHubAuthority}
    (hasOperation : child.operations.Nonempty)
    (isSubset : ∀ request, child.Matches request → parent.Matches request) :
    gitHubBodyBelow child parent = true := by
  rcases hasOperation with ⟨witnessOperation, witnessOperationEnabled⟩
  rcases child.base.hasMatch with ⟨witnessBase, witnessBaseMatches⟩
  rcases child.head.hasMatch with ⟨witnessHead, witnessHeadMatches⟩
  have parentMatchesWitness := isSubset
    { installation := child.installation
      repository := child.repository
      operation := witnessOperation
      base := witnessBase
      head := witnessHead }
    ⟨rfl, rfl, witnessOperationEnabled, witnessBaseMatches, witnessHeadMatches⟩
  have installationBelow : child.installation = parent.installation :=
    parentMatchesWitness.1.symm
  have repositoryBelow : child.repository = parent.repository :=
    parentMatchesWitness.2.1.symm
  have operationsBelow : gitHubOperationsBelow child.operations parent.operations = true := by
    apply gitHubOperationsBelow_iff_subset.mpr
    intro operation childContains
    exact (isSubset
      { installation := child.installation
        repository := child.repository
        operation
        base := witnessBase
        head := witnessHead }
      ⟨rfl, rfl, childContains, witnessBaseMatches, witnessHeadMatches⟩).2.2.1
  have baseBelow : branchPatternBelow child.base parent.base = true := by
    apply branchPatternBelow_complete
    intro base childBaseMatches
    exact (isSubset
      { installation := child.installation
        repository := child.repository
        operation := witnessOperation
        base
        head := witnessHead }
      ⟨rfl, rfl, witnessOperationEnabled, childBaseMatches, witnessHeadMatches⟩).2.2.2.1
  have headBelow : branchPatternBelow child.head parent.head = true := by
    apply branchPatternBelow_complete
    intro head childHeadMatches
    exact (isSubset
      { installation := child.installation
        repository := child.repository
        operation := witnessOperation
        base := witnessBase
        head }
      ⟨rfl, rfl, witnessOperationEnabled, witnessBaseMatches, childHeadMatches⟩).2.2.2.2
  exact gitHubBodyBelow_iff_components.mpr
    ⟨installationBelow, repositoryBelow, operationsBelow, baseBelow, headBelow⟩

/-- Semantic inclusion implies structural containment for a nonempty authority. -/
theorem gitHubBodyBelow_complete_of_nonempty {child parent : GitHubAuthority}
    (hasRequest : child.Nonempty)
    (isSubset : ∀ request, child.Matches request → parent.Matches request) :
    gitHubBodyBelow child parent = true :=
  gitHubBodyBelow_complete_of_operations_nonempty
    (gitHubOperations_nonempty_of_authority_nonempty hasRequest) isSubset

/--
For a child with a permitted operation, the executable decision exactly
characterizes semantic GitHub request-set inclusion.
-/
theorem gitHubBodyBelow_iff_matches_subset_of_operations_nonempty
    {child parent : GitHubAuthority} (hasOperation : child.operations.Nonempty) :
    gitHubBodyBelow child parent = true ↔
      ∀ request, child.Matches request → parent.Matches request :=
  ⟨gitHubBodyBelow_sound,
    gitHubBodyBelow_complete_of_operations_nonempty hasOperation⟩

/--
For a nonempty child authority, the executable decision exactly characterizes
semantic GitHub request-set inclusion.
-/
theorem gitHubBodyBelow_iff_matches_subset_of_nonempty
    {child parent : GitHubAuthority} (hasRequest : child.Nonempty) :
    gitHubBodyBelow child parent = true ↔
      ∀ request, child.Matches request → parent.Matches request :=
  ⟨gitHubBodyBelow_sound, gitHubBodyBelow_complete_of_nonempty hasRequest⟩

end Authority
