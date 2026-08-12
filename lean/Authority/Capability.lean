import Authority.File
import Authority.GitHub
import Authority.Http
import Authority.Time

/-!
# Capability Envelopes

Typed capability envelopes, executable authorization decisions, and proofs
that delegation preserves the complete time-and-authority request set.
-/

namespace Authority

/-- An opaque, session-unique capability identity assigned by the host. -/
structure CapId where
  /-- The uninterpreted host-assigned identity. -/
  value : String
  deriving Repr, BEq, DecidableEq

/-- An opaque identity for a subject that holds capabilities. -/
structure SubjectId where
  /-- The uninterpreted host-assigned identity. -/
  value : String
  deriving Repr, BEq, DecidableEq

/-- An opaque identity for a component that issues capabilities. -/
structure IssuerId where
  /-- The uninterpreted host-assigned identity. -/
  value : String
  deriving Repr, BEq, DecidableEq

/-- Identity and issuance data carried by a capability envelope. -/
structure CapabilityMetadata where
  /-- This capability's identity. -/
  id : CapId
  /-- The subject that holds this capability. -/
  subject : SubjectId
  /-- The component that issued this capability. -/
  issuer : IssuerId
  /-- The capability from which this capability was derived, if any. -/
  parent : Option CapId
  /-- Whether the state machine may derive a child from this capability. -/
  delegable : Bool

/-- A typed authority body carried by a capability. -/
inductive AuthorityBody where
  /-- Repository filesystem authority. -/
  | file (authority : FileAuthority)
  /-- Public HTTP fetch authority. -/
  | httpFetch (authority : HttpFetchAuthority)
  /-- Closed GitHub API authority. -/
  | gitHub (authority : GitHubAuthority)

/-- A typed operation checked against an `AuthorityBody`. -/
inductive AuthorityRequest where
  /-- Repository filesystem request. -/
  | file (request : FileRequest)
  /-- Public HTTP fetch request. -/
  | httpFetch (request : HttpFetchRequest)
  /-- Closed GitHub API request. -/
  | gitHub (request : GitHubRequest)

namespace AuthorityBody

/-- States that a typed authority body permits a typed request. -/
def Matches (authority : AuthorityBody) (request : AuthorityRequest) : Prop :=
  match authority, request with
  | .file authority, .file request => authority.Matches request
  | .httpFetch authority, .httpFetch request => authority.Matches request
  | .gitHub authority, .gitHub request => authority.Matches request
  | _, _ => False

/-- States that the authority body permits at least one typed request. -/
def Nonempty (authority : AuthorityBody) : Prop :=
  ∃ request, authority.Matches request

end AuthorityBody

/-- Returns whether a typed authority body permits a typed request. -/
def authorityMatches (authority : AuthorityBody) (request : AuthorityRequest) : Bool :=
  match authority, request with
  | .file authority, .file request => fileMatches authority request
  | .httpFetch authority, .httpFetch request => httpFetchMatches authority request
  | .gitHub authority, .gitHub request => gitHubMatches authority request
  | _, _ => false

/-- The executable typed-authority check exactly represents `Matches`. -/
theorem authorityMatches_iff_matches {authority : AuthorityBody}
    {request : AuthorityRequest} :
    authorityMatches authority request = true ↔ authority.Matches request := by
  cases authority <;> cases request <;>
    simp [authorityMatches, AuthorityBody.Matches, fileMatches_iff_matches,
      httpFetchMatches_iff_matches, gitHubMatches_iff_matches]

/-- Returns whether the child's typed request set is structurally below the parent's. -/
def authorityBodyBelow (child parent : AuthorityBody) : Bool :=
  match child, parent with
  | .file child, .file parent => fileBodyBelow child parent
  | .httpFetch child, .httpFetch parent => httpFetchBodyBelow child parent
  | .gitHub child, .gitHub parent => gitHubBodyBelow child parent
  | _, _ => false

/-- Typed-authority containment is reflexive. -/
theorem authorityBodyBelow_refl (authority : AuthorityBody) :
    authorityBodyBelow authority authority = true := by
  cases authority <;> simp [authorityBodyBelow, fileBodyBelow_refl,
    httpFetchBodyBelow_refl, gitHubBodyBelow_refl]

/-- Typed-authority containment is transitive. -/
theorem authorityBodyBelow_trans {first second third : AuthorityBody}
    (firstBelowSecond : authorityBodyBelow first second = true)
    (secondBelowThird : authorityBodyBelow second third = true) :
    authorityBodyBelow first third = true := by
  cases first <;> cases second <;> cases third <;>
    simp [authorityBodyBelow] at firstBelowSecond secondBelowThird ⊢
  · exact fileBodyBelow_trans firstBelowSecond secondBelowThird
  · exact httpFetchBodyBelow_trans firstBelowSecond secondBelowThird
  · exact gitHubBodyBelow_trans firstBelowSecond secondBelowThird

/-- A successful typed-authority decision implies semantic request-set inclusion. -/
theorem authorityBodyBelow_sound {child parent : AuthorityBody}
    (isBelow : authorityBodyBelow child parent = true) :
    ∀ request, child.Matches request → parent.Matches request := by
  intro request childMatches
  cases child <;> cases parent <;> cases request <;>
    simp [authorityBodyBelow, AuthorityBody.Matches] at isBelow childMatches ⊢
  · exact fileBodyBelow_sound isBelow _ childMatches
  · exact httpFetchBodyBelow_sound isBelow _ childMatches
  · exact gitHubBodyBelow_sound isBelow _ childMatches

/--
Semantic request-set inclusion implies structural containment when the child
authority is nonempty.
-/
theorem authorityBodyBelow_complete_of_nonempty {child parent : AuthorityBody}
    (hasRequest : child.Nonempty)
    (isSubset : ∀ request, child.Matches request → parent.Matches request) :
    authorityBodyBelow child parent = true := by
  cases child with
  | file child =>
    cases parent with
    | file parent =>
      apply fileBodyBelow_complete_of_effects_nonempty
      · rcases hasRequest with ⟨request, childMatches⟩
        cases request with
        | file request => exact ⟨request.effect, childMatches.2.1⟩
        | httpFetch => simp [AuthorityBody.Matches] at childMatches
        | gitHub => simp [AuthorityBody.Matches] at childMatches
      · intro request childMatches
        exact isSubset (.file request) childMatches
    | httpFetch parent =>
      exfalso
      rcases hasRequest with ⟨request, childMatches⟩
      cases request with
      | file request =>
        have parentMatches := isSubset (.file request) childMatches
        simp [AuthorityBody.Matches] at parentMatches
      | httpFetch => simp [AuthorityBody.Matches] at childMatches
      | gitHub => simp [AuthorityBody.Matches] at childMatches
    | gitHub parent =>
      exfalso
      rcases hasRequest with ⟨request, childMatches⟩
      cases request with
      | file request =>
        have parentMatches := isSubset (.file request) childMatches
        simp [AuthorityBody.Matches] at parentMatches
      | httpFetch => simp [AuthorityBody.Matches] at childMatches
      | gitHub => simp [AuthorityBody.Matches] at childMatches
  | httpFetch child =>
    cases parent with
    | file parent =>
      exfalso
      rcases hasRequest with ⟨request, childMatches⟩
      cases request with
      | file => simp [AuthorityBody.Matches] at childMatches
      | httpFetch request =>
        have parentMatches := isSubset (.httpFetch request) childMatches
        simp [AuthorityBody.Matches] at parentMatches
      | gitHub => simp [AuthorityBody.Matches] at childMatches
    | httpFetch parent =>
      apply httpFetchBodyBelow_complete_of_methods_nonempty
      · rcases hasRequest with ⟨request, childMatches⟩
        cases request with
        | file => simp [AuthorityBody.Matches] at childMatches
        | httpFetch request => exact ⟨request.method, childMatches.2.1⟩
        | gitHub => simp [AuthorityBody.Matches] at childMatches
      · intro request childMatches
        exact isSubset (.httpFetch request) childMatches
    | gitHub parent =>
      exfalso
      rcases hasRequest with ⟨request, childMatches⟩
      cases request with
      | file => simp [AuthorityBody.Matches] at childMatches
      | httpFetch request =>
        have parentMatches := isSubset (.httpFetch request) childMatches
        simp [AuthorityBody.Matches] at parentMatches
      | gitHub => simp [AuthorityBody.Matches] at childMatches
  | gitHub child =>
    cases parent with
    | file parent =>
      exfalso
      rcases hasRequest with ⟨request, childMatches⟩
      cases request with
      | file => simp [AuthorityBody.Matches] at childMatches
      | httpFetch => simp [AuthorityBody.Matches] at childMatches
      | gitHub request =>
        have parentMatches := isSubset (.gitHub request) childMatches
        simp [AuthorityBody.Matches] at parentMatches
    | httpFetch parent =>
      exfalso
      rcases hasRequest with ⟨request, childMatches⟩
      cases request with
      | file => simp [AuthorityBody.Matches] at childMatches
      | httpFetch => simp [AuthorityBody.Matches] at childMatches
      | gitHub request =>
        have parentMatches := isSubset (.gitHub request) childMatches
        simp [AuthorityBody.Matches] at parentMatches
    | gitHub parent =>
      apply gitHubBodyBelow_complete_of_operations_nonempty
      · rcases hasRequest with ⟨request, childMatches⟩
        cases request with
        | file => simp [AuthorityBody.Matches] at childMatches
        | httpFetch => simp [AuthorityBody.Matches] at childMatches
        | gitHub request => exact ⟨request.operation, childMatches.2.2.1⟩
      · intro request childMatches
        exact isSubset (.gitHub request) childMatches

/-- An immutable capability envelope. -/
structure Capability where
  /-- Identity and issuance metadata. -/
  metadata : CapabilityMetadata
  /-- The nonempty half-open validity window. -/
  validity : TimeWindow
  /-- The typed authority body. -/
  authority : AuthorityBody

/-- An operation and the monotonic time at which it is authorized. -/
structure CapabilityRequest where
  /-- The authorization time. -/
  time : MonotonicTime
  /-- The typed operation being requested. -/
  authority : AuthorityRequest

namespace Capability

/-- States that a capability permits a time-stamped request. -/
def Matches (capability : Capability) (request : CapabilityRequest) : Prop :=
  capability.validity.Contains request.time ∧
    capability.authority.Matches request.authority

end Capability

/-- Returns whether `capability` permits `request` at the supplied time. -/
def capabilityMatches (capability : Capability) (request : CapabilityRequest) : Bool :=
  timeMatches capability.validity request.time &&
    authorityMatches capability.authority request.authority

/-- The executable capability check exactly represents `Matches`. -/
theorem capabilityMatches_iff_matches {capability : Capability}
    {request : CapabilityRequest} :
    capabilityMatches capability request = true ↔ capability.Matches request := by
  simp [capabilityMatches, Capability.Matches, timeMatches_iff_contains,
    authorityMatches_iff_matches]

/-- Returns whether the child's complete authority set is below the parent's. -/
def weakerThan (child parent : Capability) : Bool :=
  timeWindowBelow child.validity parent.validity &&
    authorityBodyBelow child.authority parent.authority

/-- Capability containment is reflexive. -/
theorem weakerThan_refl (capability : Capability) :
    weakerThan capability capability = true := by
  simp [weakerThan, timeWindowBelow_refl, authorityBodyBelow_refl]

/-- Capability containment is transitive across arbitrarily long delegation chains. -/
theorem weakerThan_trans {first second third : Capability}
    (firstBelowSecond : weakerThan first second = true)
    (secondBelowThird : weakerThan second third = true) :
    weakerThan first third = true := by
  simp only [weakerThan, Bool.and_eq_true] at firstBelowSecond secondBelowThird ⊢
  exact ⟨timeWindowBelow_trans firstBelowSecond.1 secondBelowThird.1,
    authorityBodyBelow_trans firstBelowSecond.2 secondBelowThird.2⟩

/-- A successful `weakerThan` decision implies complete semantic set inclusion. -/
theorem weakerThan_sound {child parent : Capability}
    (isBelow : weakerThan child parent = true) :
    ∀ request, child.Matches request → parent.Matches request := by
  simp only [weakerThan, Bool.and_eq_true] at isBelow
  intro request childMatches
  exact ⟨timeWindowBelow_sound isBelow.1 request.time childMatches.1,
    authorityBodyBelow_sound isBelow.2 request.authority childMatches.2⟩

/--
Semantic capability inclusion implies `weakerThan` when the child's authority
body is nonempty. The premise is necessary because every empty authority body
denotes the same empty capability request set, regardless of structural fields.
-/
theorem weakerThan_complete_of_authority_nonempty {child parent : Capability}
    (hasAuthorityRequest : child.authority.Nonempty)
    (isSubset : ∀ request, child.Matches request → parent.Matches request) :
    weakerThan child parent = true := by
  rcases hasAuthorityRequest with ⟨witnessRequest, witnessMatches⟩
  have timeBelow : timeWindowBelow child.validity parent.validity = true := by
    apply timeWindowBelow_complete
    intro time childContainsTime
    exact (isSubset
      { time
        authority := witnessRequest }
      ⟨childContainsTime, witnessMatches⟩).1
  have authorityBelow : authorityBodyBelow child.authority parent.authority = true := by
    apply authorityBodyBelow_complete_of_nonempty
    · exact ⟨witnessRequest, witnessMatches⟩
    · intro request childAuthorityMatches
      exact (isSubset
        { time := child.validity.notBefore
          authority := request }
        ⟨⟨Nat.le_refl _, child.validity.isValid⟩, childAuthorityMatches⟩).2
  simp [weakerThan, timeBelow, authorityBelow]

/--
For a nonempty child authority, the executable decision exactly characterizes
semantic inclusion of all time-stamped requests.
-/
theorem weakerThan_iff_matches_subset_of_authority_nonempty
    {child parent : Capability} (hasAuthorityRequest : child.authority.Nonempty) :
    weakerThan child parent = true ↔
      ∀ request, child.Matches request → parent.Matches request :=
  ⟨weakerThan_sound,
    weakerThan_complete_of_authority_nonempty hasAuthorityRequest⟩

end Authority
