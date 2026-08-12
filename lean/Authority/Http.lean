/-!
# HTTP Fetch Authorities

Public HTTP fetch authority, restricted to canonical hosts and GET or HEAD
requests. The executable matching and delegation decisions are proved to be
sound with respect to their request-set semantics.
-/

namespace Authority

/--
An HTTP host that the boundary has already canonicalized.

Host parsing, case folding, IDNA processing, and default-port handling belong
to the HTTP boundary. This type makes the resulting exact host identity
explicit in authority checks.
-/
structure CanonicalHost where
  /-- The boundary-produced canonical host identity. -/
  value : String
  deriving Repr, BEq, DecidableEq

private def isAsciiAlphaNumeric (character : Char) : Bool :=
  let code := character.toNat
  (48 ≤ code && code ≤ 57) ||
    (65 ≤ code && code ≤ 90) ||
    (97 ≤ code && code ≤ 122)

private def isAsciiDnsLabel (label : String) : Bool :=
  !label.isEmpty &&
    label.length ≤ 63 &&
    !label.startsWith "-" &&
    !label.endsWith "-" &&
    label.toList.all (fun character =>
      isAsciiAlphaNumeric character || character == '-')

private def isIpv4Octet (label : String) : Bool :=
  label.toList.all (fun character =>
      let code := character.toNat
      48 ≤ code && code ≤ 57) &&
    (label == "0" || !label.startsWith "0") &&
    match label.toNat? with
    | some value => value ≤ 255
    | none => false

private def isIpv4Literal : List String → Bool
  | [first, second, third, fourth] =>
    isIpv4Octet first && isIpv4Octet second &&
      isIpv4Octet third && isIpv4Octet fourth
  | _ => false

private def canonicalHostValue (value : String) : String :=
  let withoutTerminalDot :=
    if value.endsWith "." then value.dropRight 1 else value
  withoutTerminalDot.toLower

private def isValidCanonicalHost (host : String) : Bool :=
  !host.isEmpty &&
    host.length ≤ 253 &&
    host.toList.all (fun character => character.toNat < 128) &&
    let labels := host.splitOn "."
    labels.all isAsciiDnsLabel &&
    !isIpv4Literal labels

namespace CanonicalHost

/-- Canonicalizes and validates an ASCII DNS host for authority comparison. -/
def ofString (value : String) : Option CanonicalHost :=
  let canonical := canonicalHostValue value
  if value.toList.all (fun character => character.toNat < 128) &&
      isValidCanonicalHost canonical then
    some { value := canonical }
  else
    none

end CanonicalHost

/-- A safe HTTP method supported by public fetch authorities. -/
inductive HttpMethod where
  /-- Retrieves a response representation. -/
  | get
  /-- Retrieves response metadata without a response body. -/
  | head
  deriving Repr, BEq, DecidableEq

/-- A set of permitted HTTP methods represented by its membership decision. -/
abbrev HttpMethods := HttpMethod → Bool

namespace HttpMethods

/-- The method set that permits no fetch requests. -/
def empty : HttpMethods := fun _ => false

/-- The method set containing exactly `selected`. -/
def only (selected : HttpMethod) : HttpMethods := fun method => method == selected

/-- Creates a method set from a list, ignoring duplicate entries. -/
def ofList (methods : List HttpMethod) : HttpMethods := fun method => methods.contains method

/-- States that at least one method belongs to the set. -/
def Nonempty (methods : HttpMethods) : Prop := ∃ method, methods method = true

end HttpMethods

private def allHttpMethods : List HttpMethod := [.get, .head]

private theorem HttpMethod.mem_allHttpMethods (method : HttpMethod) :
    method ∈ allHttpMethods := by
  cases method <;> simp [allHttpMethods]

/-- Returns whether every child method also belongs to the parent set. -/
def httpMethodsBelow (child parent : HttpMethods) : Bool :=
  allHttpMethods.all fun method => !child method || parent method

/-- Method-set containment decides pointwise membership implication. -/
theorem httpMethodsBelow_iff_subset {child parent : HttpMethods} :
    httpMethodsBelow child parent = true ↔
      ∀ method, child method = true → parent method = true := by
  rw [httpMethodsBelow, List.all_eq_true]
  constructor
  · intro allMethods method childContains
    have condition := allMethods method method.mem_allHttpMethods
    simpa [childContains] using condition
  · intro isSubset method _
    cases childContains : child method with
    | false => simp [childContains]
    | true => simp [childContains, isSubset method childContains]

/-- Method-set containment is reflexive. -/
theorem httpMethodsBelow_refl (methods : HttpMethods) :
    httpMethodsBelow methods methods = true :=
  httpMethodsBelow_iff_subset.mpr fun _ contains => contains

/-- Method-set containment is transitive. -/
theorem httpMethodsBelow_trans {first second third : HttpMethods}
    (firstBelowSecond : httpMethodsBelow first second = true)
    (secondBelowThird : httpMethodsBelow second third = true) :
    httpMethodsBelow first third = true := by
  apply httpMethodsBelow_iff_subset.mpr
  intro method firstContains
  exact httpMethodsBelow_iff_subset.mp secondBelowThird method
    (httpMethodsBelow_iff_subset.mp firstBelowSecond method firstContains)

/-- Returns whether a character is an unencoded RFC 3986 URL path character. -/
private def isUnencodedUrlPathCharacter (character : Char) : Bool :=
  isAsciiAlphaNumeric character ||
    List.contains ['-', '.', '_', '~', '!', '$', '&', '\'', '(', ')', '*', '+', ',', ';', '=', ':', '@']
      character

/-- Returns whether one URL path segment has the authority's sole safe spelling. -/
def isValidUrlPathSegment (segment : String) : Bool :=
  let characters := segment.toList
  !characters.isEmpty &&
    segment != "." &&
    segment != ".." &&
    characters.all isUnencodedUrlPathCharacter

/--
A canonical URL path represented as validated URL path segments.

The empty segment list denotes `/`. The HTTP boundary must remove query and
fragment components and reject alternate percent-encoded or dot-segment
spellings before constructing this value.
-/
structure CanonicalUrlPath where
  /-- Validated URL path segments in order. -/
  segments : List String
  /-- Evidence that every segment has the authority's canonical URL spelling. -/
  isValid : segments.all isValidUrlPathSegment = true

namespace CanonicalUrlPath

/-- The canonical URL path denoting `/`. -/
def root : CanonicalUrlPath :=
  { segments := []
    isValid := rfl }

/-- Creates a canonical URL path when every supplied segment is valid. -/
def ofSegments (segments : List String) : Option CanonicalUrlPath :=
  if isValid : segments.all isValidUrlPathSegment = true then
    some { segments, isValid }
  else
    none

/-- Concatenates two canonical URL paths while preserving segment validity. -/
def append (path suffix : CanonicalUrlPath) : CanonicalUrlPath :=
  { segments := path.segments ++ suffix.segments
    isValid := by simp [List.all_append, path.isValid, suffix.isValid] }

end CanonicalUrlPath

/-- A URL path selector used by HTTP fetch authorities. -/
inductive UrlPathPattern where
  /-- Selects exactly one canonical URL path. -/
  | exact (path : CanonicalUrlPath)
  /-- Selects a canonical URL path and every path below it. -/
  | prefix (path : CanonicalUrlPath)

namespace UrlPathPattern

/-- States that a URL path pattern selects a canonical URL path. -/
def Matches (pattern : UrlPathPattern) (path : CanonicalUrlPath) : Prop :=
  match pattern with
  | .exact selected => selected.segments = path.segments
  | .prefix selected => selected.segments <+: path.segments

end UrlPathPattern

/-- Returns whether `pattern` selects `path`. -/
def urlPathMatches (pattern : UrlPathPattern) (path : CanonicalUrlPath) : Bool :=
  match pattern with
  | .exact selected => selected.segments == path.segments
  | .prefix selected => selected.segments.isPrefixOf path.segments

/-- The executable URL path decision exactly represents `Matches`. -/
theorem urlPathMatches_iff_matches {pattern : UrlPathPattern} {path : CanonicalUrlPath} :
    urlPathMatches pattern path = true ↔ pattern.Matches path := by
  cases pattern <;> simp [urlPathMatches, UrlPathPattern.Matches]

/-- Returns whether every URL path selected by `child` is also selected by `parent`. -/
def urlPathBelow (child parent : UrlPathPattern) : Bool :=
  match child, parent with
  | .exact child, .exact parent => child.segments == parent.segments
  | .exact child, .prefix parent => parent.segments.isPrefixOf child.segments
  | .prefix child, .prefix parent => parent.segments.isPrefixOf child.segments
  | .prefix _, .exact _ => false

/-- URL path containment is reflexive. -/
theorem urlPathBelow_refl (pattern : UrlPathPattern) : urlPathBelow pattern pattern = true := by
  cases pattern <;> simp [urlPathBelow]

/-- URL path containment is transitive. -/
theorem urlPathBelow_trans {first second third : UrlPathPattern}
    (firstBelowSecond : urlPathBelow first second = true)
    (secondBelowThird : urlPathBelow second third = true) :
    urlPathBelow first third = true := by
  cases first <;> cases second <;> cases third <;>
    simp [urlPathBelow] at firstBelowSecond secondBelowThird ⊢
  · exact firstBelowSecond.trans secondBelowThird
  · rw [firstBelowSecond]
    exact secondBelowThird
  · exact secondBelowThird.trans firstBelowSecond
  · exact secondBelowThird.trans firstBelowSecond

/-- A successful URL path containment decision implies semantic set inclusion. -/
theorem urlPathBelow_sound {child parent : UrlPathPattern}
    (isBelow : urlPathBelow child parent = true) :
    ∀ path, child.Matches path → parent.Matches path := by
  intro path childMatches
  cases child <;> cases parent <;>
    simp [urlPathBelow] at isBelow <;>
    simp [UrlPathPattern.Matches] at childMatches ⊢
  · exact isBelow.symm.trans childMatches
  · rw [← childMatches]
    exact isBelow
  · exact isBelow.trans childMatches

private def strictUrlSuffix : CanonicalUrlPath :=
  { segments := ["_"]
    isValid := by decide }

/-- Semantic URL path inclusion implies a successful containment decision. -/
theorem urlPathBelow_complete {child parent : UrlPathPattern}
    (isSubset : ∀ path, child.Matches path → parent.Matches path) :
    urlPathBelow child parent = true := by
  cases child <;> cases parent <;>
    simp [urlPathBelow, UrlPathPattern.Matches] at isSubset ⊢
  · exact (isSubset _ rfl).symm
  · exact isSubset _ rfl
  · rename_i childPath parentPath
    have parentMatchesChild := isSubset childPath List.prefix_rfl
    have parentMatchesDescendant :=
      isSubset (CanonicalUrlPath.append childPath strictUrlSuffix) (by
        simp [CanonicalUrlPath.append])
    simp [CanonicalUrlPath.append, strictUrlSuffix, parentMatchesChild]
      at parentMatchesDescendant
  · exact isSubset _ List.prefix_rfl

/-- URL path containment exactly characterizes semantic set inclusion. -/
theorem urlPathBelow_iff_matches_subset {child parent : UrlPathPattern} :
    urlPathBelow child parent = true ↔
      ∀ path, child.Matches path → parent.Matches path :=
  ⟨urlPathBelow_sound, urlPathBelow_complete⟩

/-- Authority for unauthenticated HTTP fetches from one canonical host. -/
structure HttpFetchAuthority where
  /-- The permitted GET and/or HEAD methods. -/
  methods : HttpMethods
  /-- The one canonical host from which responses may be fetched. -/
  host : CanonicalHost
  /-- The permitted canonical URL path pattern. -/
  path : UrlPathPattern
  /-- An inclusive upper bound on response bytes, matching Rust's `u64` domain. -/
  maxResponseBytes : UInt64

/-- A bounded, unauthenticated HTTP fetch request. -/
structure HttpFetchRequest where
  /-- The requested GET or HEAD method. -/
  method : HttpMethod
  /-- The canonical target host. -/
  host : CanonicalHost
  /-- The canonical target URL path. -/
  path : CanonicalUrlPath
  /-- The maximum number of response bytes the request may consume. -/
  maxResponseBytes : UInt64

namespace HttpFetchAuthority

/-- States that an HTTP fetch authority permits a bounded fetch request. -/
def Matches (authority : HttpFetchAuthority) (request : HttpFetchRequest) : Prop :=
  authority.host = request.host ∧
    authority.methods request.method = true ∧
    authority.path.Matches request.path ∧
    request.maxResponseBytes ≤ authority.maxResponseBytes

end HttpFetchAuthority

/-- Returns whether `authority` permits `request`. -/
def httpFetchMatches (authority : HttpFetchAuthority) (request : HttpFetchRequest) : Bool :=
  decide (authority.host = request.host) &&
    authority.methods request.method &&
    urlPathMatches authority.path request.path &&
    decide (request.maxResponseBytes ≤ authority.maxResponseBytes)

/-- The executable HTTP fetch decision exactly represents `Matches`. -/
theorem httpFetchMatches_iff_matches {authority : HttpFetchAuthority}
    {request : HttpFetchRequest} :
    httpFetchMatches authority request = true ↔ authority.Matches request := by
  simp only [httpFetchMatches, Bool.and_eq_true, decide_eq_true_eq,
    urlPathMatches_iff_matches]
  constructor
  · intro executableMatches
    exact ⟨executableMatches.1.1.1, executableMatches.1.1.2,
      executableMatches.1.2, executableMatches.2⟩
  · intro semanticMatches
    exact ⟨⟨⟨semanticMatches.1, semanticMatches.2.1⟩,
      semanticMatches.2.2.1⟩, semanticMatches.2.2.2⟩

/-- Returns whether `child` satisfies the structural HTTP-fetch delegation rule. -/
def httpFetchBodyBelow (child parent : HttpFetchAuthority) : Bool :=
  decide (child.host = parent.host) &&
    httpMethodsBelow child.methods parent.methods &&
    urlPathBelow child.path parent.path &&
    decide (child.maxResponseBytes ≤ parent.maxResponseBytes)

/-- HTTP fetch authority containment is reflexive. -/
theorem httpFetchBodyBelow_refl (authority : HttpFetchAuthority) :
    httpFetchBodyBelow authority authority = true := by
  simp [httpFetchBodyBelow, httpMethodsBelow_refl, urlPathBelow_refl]

/-- HTTP fetch authority containment is transitive. -/
theorem httpFetchBodyBelow_trans {first second third : HttpFetchAuthority}
    (firstBelowSecond : httpFetchBodyBelow first second = true)
    (secondBelowThird : httpFetchBodyBelow second third = true) :
    httpFetchBodyBelow first third = true := by
  simp only [httpFetchBodyBelow, Bool.and_eq_true, decide_eq_true_eq]
    at firstBelowSecond secondBelowThird ⊢
  exact ⟨⟨⟨firstBelowSecond.1.1.1.trans secondBelowThird.1.1.1,
    httpMethodsBelow_trans firstBelowSecond.1.1.2 secondBelowThird.1.1.2⟩,
    urlPathBelow_trans firstBelowSecond.1.2 secondBelowThird.1.2⟩,
    UInt64.le_trans firstBelowSecond.2 secondBelowThird.2⟩

/-- A successful HTTP fetch containment decision implies semantic set inclusion. -/
theorem httpFetchBodyBelow_sound {child parent : HttpFetchAuthority}
    (isBelow : httpFetchBodyBelow child parent = true) :
    ∀ request, child.Matches request → parent.Matches request := by
  simp only [httpFetchBodyBelow, Bool.and_eq_true, decide_eq_true_eq] at isBelow
  intro request childMatches
  exact ⟨isBelow.1.1.1.symm.trans childMatches.1,
    httpMethodsBelow_iff_subset.mp isBelow.1.1.2 request.method childMatches.2.1,
    urlPathBelow_sound isBelow.1.2 request.path childMatches.2.2.1,
    UInt64.le_trans childMatches.2.2.2 isBelow.2⟩

private theorem UrlPathPattern.hasMatch (pattern : UrlPathPattern) :
    ∃ path, pattern.Matches path := by
  cases pattern with
  | exact path => exact ⟨path, rfl⟩
  | «prefix» path => exact ⟨path, List.prefix_rfl⟩

/--
Semantic inclusion implies structural containment when the child permits at
least one method. Without this premise, an empty child denotes the empty set
regardless of its host, path, and response-byte bound.
-/
theorem httpFetchBodyBelow_complete_of_methods_nonempty
    {child parent : HttpFetchAuthority} (hasMethod : child.methods.Nonempty)
    (isSubset : ∀ request, child.Matches request → parent.Matches request) :
    httpFetchBodyBelow child parent = true := by
  rcases hasMethod with ⟨witnessMethod, witnessMethodEnabled⟩
  rcases child.path.hasMatch with ⟨witnessPath, witnessPathMatches⟩
  have parentMatchesWitness := isSubset
    { method := witnessMethod
      host := child.host
      path := witnessPath
      maxResponseBytes := child.maxResponseBytes }
    ⟨rfl, witnessMethodEnabled, witnessPathMatches, UInt64.le_refl _⟩
  have hostBelow : child.host = parent.host := parentMatchesWitness.1.symm
  have methodsBelow : httpMethodsBelow child.methods parent.methods = true := by
    apply httpMethodsBelow_iff_subset.mpr
    intro method childContains
    exact (isSubset
      { method
        host := child.host
        path := witnessPath
        maxResponseBytes := child.maxResponseBytes }
      ⟨rfl, childContains, witnessPathMatches, UInt64.le_refl _⟩).2.1
  have pathsBelow : urlPathBelow child.path parent.path = true := by
    apply urlPathBelow_complete
    intro path childPathMatches
    exact (isSubset
      { method := witnessMethod
        host := child.host
        path
        maxResponseBytes := child.maxResponseBytes }
      ⟨rfl, witnessMethodEnabled, childPathMatches, UInt64.le_refl _⟩).2.2.1
  have responseBytesBelow : child.maxResponseBytes ≤ parent.maxResponseBytes :=
    parentMatchesWitness.2.2.2
  simp only [httpFetchBodyBelow, Bool.and_eq_true, decide_eq_true_eq]
  exact ⟨⟨⟨hostBelow, methodsBelow⟩, pathsBelow⟩, responseBytesBelow⟩

/--
For a child with at least one permitted method, the executable decision exactly
characterizes semantic HTTP fetch request-set inclusion.
-/
theorem httpFetchBodyBelow_iff_matches_subset_of_methods_nonempty
    {child parent : HttpFetchAuthority} (hasMethod : child.methods.Nonempty) :
    httpFetchBodyBelow child parent = true ↔
      ∀ request, child.Matches request → parent.Matches request :=
  ⟨httpFetchBodyBelow_sound,
    httpFetchBodyBelow_complete_of_methods_nonempty hasMethod⟩

end Authority
