import AuthorityTests

/-!
# Shared Authority Corpus Runner

Parses and evaluates the versioned authority decision corpus with the Lean
implementation. `AuthorityTests` remains imported so its proof-checked examples
are part of the test target as well.
-/

namespace AuthorityCorpus

open Authority

private def corpusHeader : String := "# authority-corpus-v1"

structure CaseResult where
  name : String
  actual : Bool
  deriving Repr, BEq, DecidableEq

structure Fields where
  values : List String
  consumed : Nat := 0

namespace Fields

def take (fields : Fields) (label : String) : Except String (String × Fields) :=
  match fields.values with
  | [] => .error s!"missing {label} at field {fields.consumed + 1}; check the corpus schema"
  | value :: remaining =>
    .ok (value, { values := remaining, consumed := fields.consumed + 1 })

def finish (fields : Fields) : Except String Unit :=
  match fields.values with
  | [] => .ok ()
  | extra :: _ =>
    .error s!"unexpected field {fields.consumed + 1} with value `{extra}`; check the corpus schema"

end Fields

def parseBool (value label : String) : Except String Bool :=
  match value with
  | "true" => .ok true
  | "false" => .ok false
  | _ => .error s!"invalid {label} `{value}`; expected `true` or `false`"

private def maxUInt64Ticks : Nat := 18446744073709551615

def parseTicks (value label : String) : Except String MonotonicTime :=
  match value.toNat? with
  | some ticks =>
    if ticks ≤ maxUInt64Ticks then
      .ok { ticks }
    else
      .error s!"invalid {label} `{value}`; expected u64 ticks"
  | none => .error s!"invalid {label} `{value}`; expected u64 ticks"

def decodeSegments (encoded : String) : List String :=
  if encoded == "-" then
    []
  else
    (encoded.splitOn "|").map fun segment => segment.replace "\\0" "\x00"

def parsePath (encoded label : String) : Except String CanonicalPath :=
  match CanonicalPath.ofSegments (decodeSegments encoded) with
  | some path => .ok path
  | none => .error s!"invalid {label} `{encoded}`; expected canonical path segments"

def parsePattern (fields : Fields) (role : String) : Except String (PathPattern × Fields) := do
  let (kind, fields) ← fields.take s!"{role} pattern kind"
  let (encodedPath, fields) ← fields.take s!"{role} pattern path"
  let path ← parsePath encodedPath s!"{role} pattern path"
  match kind with
  | "exact" => .ok (.exact path, fields)
  | "prefix" => .ok (.prefix path, fields)
  | _ => .error s!"invalid {role} pattern kind `{kind}`; expected `exact` or `prefix`"

def parseEffect (value label : String) : Except String FileEffect :=
  match value with
  | "read_data" => .ok .readData
  | "list_directory" => .ok .listDirectory
  | "write_data" => .ok .writeData
  | "truncate" => .ok .truncate
  | "create_file" => .ok .createFile
  | "create_directory" => .ok .createDirectory
  | "remove_file" => .ok .removeFile
  | "remove_directory" => .ok .removeDirectory
  | "rename" => .ok .rename
  | "set_metadata" => .ok .setMetadata
  | "read_link" => .ok .readLink
  | "create_symlink" => .ok .createSymlink
  | "create_hard_link" => .ok .createHardLink
  | _ => .error s!"invalid {label} `{value}`; expected a file effect"

def parseEffectList (values : List String) (label : String) : Except String (List FileEffect) :=
  match values with
  | [] => .ok []
  | value :: remaining => do
    let effect ← parseEffect value label
    let effects ← parseEffectList remaining label
    .ok (effect :: effects)

def parseEffects (encoded label : String) : Except String FileEffects := do
  if encoded == "-" then
    .ok FileEffects.empty
  else
    let effects ← parseEffectList (encoded.splitOn "|") label
    .ok (FileEffects.ofList effects)

def parseFileAuthority (fields : Fields) (role : String) :
    Except String (FileAuthority × Fields) := do
  let (repository, fields) ← fields.take s!"{role} repository"
  let (encodedEffects, fields) ← fields.take s!"{role} effects"
  let effects ← parseEffects encodedEffects s!"{role} effects"
  let (path, fields) ← parsePattern fields role
  .ok ({ repository := { value := repository }, effects, path }, fields)

def parseFileRequest (fields : Fields) (role : String) :
    Except String (FileRequest × Fields) := do
  let (repository, fields) ← fields.take s!"{role} repository"
  let (encodedEffect, fields) ← fields.take s!"{role} effect"
  let effect ← parseEffect encodedEffect s!"{role} effect"
  let (encodedPath, fields) ← fields.take s!"{role} path"
  let path ← parsePath encodedPath s!"{role} path"
  .ok ({ repository := { value := repository }, effect, path }, fields)

def parseHttpMethod (value label : String) : Except String HttpMethod :=
  match value with
  | "get" => .ok .get
  | "head" => .ok .head
  | _ => .error s!"invalid {label} `{value}`; expected `get` or `head`"

def parseHttpMethodList (values : List String) (label : String) : Except String (List HttpMethod) :=
  match values with
  | [] => .ok []
  | value :: remaining => do
    let method ← parseHttpMethod value label
    let methods ← parseHttpMethodList remaining label
    .ok (method :: methods)

def parseHttpMethods (encoded label : String) : Except String HttpMethods := do
  if encoded == "-" then
    .ok HttpMethods.empty
  else
    let methods ← parseHttpMethodList (encoded.splitOn "|") label
    .ok (HttpMethods.ofList methods)

def parseUrlPath (encoded label : String) : Except String CanonicalUrlPath :=
  if encoded == "/" then
    .ok CanonicalUrlPath.root
  else if !encoded.startsWith "/" || encoded.endsWith "/" then
    .error s!"invalid {label} `{encoded}`; expected a canonical origin path"
  else
    match CanonicalUrlPath.ofSegments ((encoded.drop 1).splitOn "/") with
    | some path => .ok path
    | none => .error s!"invalid {label} `{encoded}`; expected a canonical origin path"

def parseHost (encoded label : String) : Except String CanonicalHost :=
  match CanonicalHost.ofString encoded with
  | some host => .ok host
  | none => .error s!"invalid {label} `{encoded}`; expected a canonical DNS host"

def parseUrlPattern (fields : Fields) (role : String) : Except String (UrlPathPattern × Fields) := do
  let (kind, fields) ← fields.take s!"{role} URL path pattern kind"
  let (encodedPath, fields) ← fields.take s!"{role} URL path pattern"
  let path ← parseUrlPath encodedPath s!"{role} URL path pattern"
  match kind with
  | "exact" => .ok (.exact path, fields)
  | "prefix" => .ok (.prefix path, fields)
  | _ => .error s!"invalid {role} URL path pattern kind `{kind}`; expected `exact` or `prefix`"

def parseUInt64 (encoded label : String) : Except String UInt64 :=
  match encoded.toNat? with
  | some value =>
    if value ≤ maxUInt64Ticks then
      .ok (UInt64.ofNat value)
    else
      .error s!"invalid {label} `{encoded}`; expected u64"
  | none => .error s!"invalid {label} `{encoded}`; expected u64"

def parseHttpAuthority (fields : Fields) (role : String) :
    Except String (HttpFetchAuthority × Fields) := do
  let (encodedMethods, fields) ← fields.take s!"{role} HTTP methods"
  let methods ← parseHttpMethods encodedMethods s!"{role} HTTP methods"
  let (encodedHost, fields) ← fields.take s!"{role} HTTP host"
  let host ← parseHost encodedHost s!"{role} HTTP host"
  let (path, fields) ← parseUrlPattern fields role
  let (encodedMaxResponseBytes, fields) ← fields.take s!"{role} HTTP maximum response bytes"
  let maxResponseBytes ← parseUInt64 encodedMaxResponseBytes s!"{role} HTTP maximum response bytes"
  .ok ({ methods, host, path, maxResponseBytes }, fields)

def parseHttpRequest (fields : Fields) (role : String) :
    Except String (HttpFetchRequest × Fields) := do
  let (encodedMethod, fields) ← fields.take s!"{role} HTTP method"
  let method ← parseHttpMethod encodedMethod s!"{role} HTTP method"
  let (encodedHost, fields) ← fields.take s!"{role} HTTP host"
  let host ← parseHost encodedHost s!"{role} HTTP host"
  let (encodedPath, fields) ← fields.take s!"{role} HTTP URL path"
  let path ← parseUrlPath encodedPath s!"{role} HTTP URL path"
  let (encodedMaxResponseBytes, fields) ← fields.take s!"{role} HTTP maximum response bytes"
  let maxResponseBytes ← parseUInt64 encodedMaxResponseBytes s!"{role} HTTP maximum response bytes"
  .ok ({ method, host, path, maxResponseBytes }, fields)

def parseGitHubOperation (value label : String) : Except String GitHubOperation :=
  match value with
  | "publish_branch" => .ok .publishBranch
  | "create_pull_request" => .ok .createPullRequest
  | _ => .error s!"invalid {label} `{value}`; expected a GitHub operation"

def parseGitHubOperationList (values : List String) (label : String) :
    Except String (List GitHubOperation) :=
  match values with
  | [] => .ok []
  | value :: remaining => do
    let operation ← parseGitHubOperation value label
    let operations ← parseGitHubOperationList remaining label
    .ok (operation :: operations)

def parseGitHubOperations (encoded label : String) : Except String GitHubOperations := do
  if encoded == "-" then
    .ok GitHubOperations.empty
  else
    let operations ← parseGitHubOperationList (encoded.splitOn "|") label
    .ok (GitHubOperations.ofList operations)

def parseBranch (encoded label : String) : Except String BranchName :=
  match BranchName.ofSegments (encoded.splitOn "/") with
  | some branch => .ok branch
  | none => .error s!"invalid {label} `{encoded}`; expected a safe branch name"

def parseBranchPattern (fields : Fields) (role : String) : Except String (BranchPattern × Fields) := do
  let (kind, fields) ← fields.take s!"{role} branch pattern kind"
  let (encodedBranch, fields) ← fields.take s!"{role} branch pattern"
  let branch ← parseBranch encodedBranch s!"{role} branch pattern"
  match kind with
  | "exact" => .ok (.exact branch, fields)
  | "prefix" => .ok (.prefix branch, fields)
  | _ => .error s!"invalid {role} branch pattern kind `{kind}`; expected `exact` or `prefix`"

def parseGitHubAuthority (fields : Fields) (role : String) :
    Except String (GitHubAuthority × Fields) := do
  let (installation, fields) ← fields.take s!"{role} GitHub installation"
  let (repository, fields) ← fields.take s!"{role} GitHub repository"
  let (encodedOperations, fields) ← fields.take s!"{role} GitHub operations"
  let operations ← parseGitHubOperations encodedOperations s!"{role} GitHub operations"
  let (base, fields) ← parseBranchPattern fields s!"{role} GitHub base"
  let (head, fields) ← parseBranchPattern fields s!"{role} GitHub head"
  let authority : GitHubAuthority :=
    { installation := { value := installation }
      repository := { value := repository }
      operations
      base
      head }
  .ok (authority, fields)

def parseGitHubRequest (fields : Fields) (role : String) :
    Except String (GitHubRequest × Fields) := do
  let (installation, fields) ← fields.take s!"{role} GitHub installation"
  let (repository, fields) ← fields.take s!"{role} GitHub repository"
  let (encodedOperation, fields) ← fields.take s!"{role} GitHub operation"
  let operation ← parseGitHubOperation encodedOperation s!"{role} GitHub operation"
  let (encodedBase, fields) ← fields.take s!"{role} GitHub base branch"
  let base ← parseBranch encodedBase s!"{role} GitHub base branch"
  let (encodedHead, fields) ← fields.take s!"{role} GitHub head branch"
  let head ← parseBranch encodedHead s!"{role} GitHub head branch"
  let request : GitHubRequest :=
    { installation := { value := installation }
      repository := { value := repository }
      operation
      base
      head }
  .ok (request, fields)

def parseTimeWindow (fields : Fields) (role : String) : Except String (TimeWindow × Fields) := do
  let (encodedStart, fields) ← fields.take s!"{role} not_before"
  let notBefore ← parseTicks encodedStart s!"{role} not_before"
  let (encodedEnd, fields) ← fields.take s!"{role} expires_at"
  let expiresAt ← parseTicks encodedEnd s!"{role} expires_at"
  match TimeWindow.ofBounds notBefore expiresAt with
  | some window => .ok (window, fields)
  | none => .error s!"invalid {role} time window: not_before must be less than expires_at"

private def corpusMetadata : CapabilityMetadata :=
  { id := { value := "corpus-capability" }
    subject := { value := "corpus-subject" }
    issuer := { value := "corpus-runner" }
    parent := none
    delegable := false }

def parseCapability (fields : Fields) (role : String) : Except String (Capability × Fields) := do
  let (validity, fields) ← parseTimeWindow fields role
  let (authority, fields) ← parseFileAuthority fields role
  .ok ({ metadata := corpusMetadata, validity, authority := .file authority }, fields)

def parseCapabilityRequest (fields : Fields) (role : String) :
    Except String (CapabilityRequest × Fields) := do
  let (encodedTime, fields) ← fields.take s!"{role} time"
  let time ← parseTicks encodedTime s!"{role} time"
  let (request, fields) ← parseFileRequest fields role
  .ok ({ time, authority := .file request }, fields)

def parseHttpCapability (fields : Fields) (role : String) : Except String (Capability × Fields) := do
  let (validity, fields) ← parseTimeWindow fields role
  let (authority, fields) ← parseHttpAuthority fields role
  .ok ({ metadata := corpusMetadata, validity, authority := .httpFetch authority }, fields)

def parseHttpCapabilityRequest (fields : Fields) (role : String) :
    Except String (CapabilityRequest × Fields) := do
  let (encodedTime, fields) ← fields.take s!"{role} time"
  let time ← parseTicks encodedTime s!"{role} time"
  let (request, fields) ← parseHttpRequest fields role
  .ok ({ time, authority := .httpFetch request }, fields)

def parseGitHubCapability (fields : Fields) (role : String) :
    Except String (Capability × Fields) := do
  let (validity, fields) ← parseTimeWindow fields role
  let (authority, fields) ← parseGitHubAuthority fields role
  .ok ({ metadata := corpusMetadata, validity, authority := .gitHub authority }, fields)

def parseGitHubCapabilityRequest (fields : Fields) (role : String) :
    Except String (CapabilityRequest × Fields) := do
  let (encodedTime, fields) ← fields.take s!"{role} time"
  let time ← parseTicks encodedTime s!"{role} time"
  let (request, fields) ← parseGitHubRequest fields role
  .ok ({ time, authority := .gitHub request }, fields)

def evaluateOperation (kind : String) (fields : Fields) : Except String (Bool × Fields) := do
  match kind with
  | "path_valid" =>
    let (encoded, fields) ← fields.take "path"
    .ok ((CanonicalPath.ofSegments (decodeSegments encoded)).isSome, fields)
  | "path_matches" =>
    let (pattern, fields) ← parsePattern fields "authority"
    let (encodedPath, fields) ← fields.take "request path"
    let path ← parsePath encodedPath "request path"
    .ok (pathMatches pattern path, fields)
  | "path_below" =>
    let (child, fields) ← parsePattern fields "child"
    let (parent, fields) ← parsePattern fields "parent"
    .ok (pathBelow child parent, fields)
  | "time_valid" =>
    let (encodedStart, fields) ← fields.take "not_before"
    let notBefore ← parseTicks encodedStart "not_before"
    let (encodedEnd, fields) ← fields.take "expires_at"
    let expiresAt ← parseTicks encodedEnd "expires_at"
    .ok ((TimeWindow.ofBounds notBefore expiresAt).isSome, fields)
  | "time_matches" =>
    let (window, fields) ← parseTimeWindow fields "authority"
    let (encodedTime, fields) ← fields.take "request time"
    let time ← parseTicks encodedTime "request time"
    .ok (timeMatches window time, fields)
  | "time_below" =>
    let (child, fields) ← parseTimeWindow fields "child"
    let (parent, fields) ← parseTimeWindow fields "parent"
    .ok (timeWindowBelow child parent, fields)
  | "file_matches" =>
    let (authority, fields) ← parseFileAuthority fields "authority"
    let (request, fields) ← parseFileRequest fields "request"
    .ok (fileMatches authority request, fields)
  | "file_below" =>
    let (child, fields) ← parseFileAuthority fields "child"
    let (parent, fields) ← parseFileAuthority fields "parent"
    .ok (fileBodyBelow child parent, fields)
  | "http_matches" =>
    let (authority, fields) ← parseHttpAuthority fields "authority"
    let (request, fields) ← parseHttpRequest fields "request"
    .ok (httpFetchMatches authority request, fields)
  | "http_below" =>
    let (child, fields) ← parseHttpAuthority fields "child"
    let (parent, fields) ← parseHttpAuthority fields "parent"
    .ok (httpFetchBodyBelow child parent, fields)
  | "github_matches" =>
    let (authority, fields) ← parseGitHubAuthority fields "authority"
    let (request, fields) ← parseGitHubRequest fields "request"
    .ok (gitHubMatches authority request, fields)
  | "github_below" =>
    let (child, fields) ← parseGitHubAuthority fields "child"
    let (parent, fields) ← parseGitHubAuthority fields "parent"
    .ok (gitHubBodyBelow child parent, fields)
  | "capability_matches" =>
    let (capability, fields) ← parseCapability fields "authority"
    let (request, fields) ← parseCapabilityRequest fields "request"
    .ok (capabilityMatches capability request, fields)
  | "weaker_than" =>
    let (child, fields) ← parseCapability fields "child"
    let (parent, fields) ← parseCapability fields "parent"
    .ok (weakerThan child parent, fields)
  | "http_capability_matches" =>
    let (capability, fields) ← parseHttpCapability fields "authority"
    let (request, fields) ← parseHttpCapabilityRequest fields "request"
    .ok (capabilityMatches capability request, fields)
  | "http_weaker_than" =>
    let (child, fields) ← parseHttpCapability fields "child"
    let (parent, fields) ← parseHttpCapability fields "parent"
    .ok (weakerThan child parent, fields)
  | "github_capability_matches" =>
    let (capability, fields) ← parseGitHubCapability fields "authority"
    let (request, fields) ← parseGitHubCapabilityRequest fields "request"
    .ok (capabilityMatches capability request, fields)
  | "github_weaker_than" =>
    let (child, fields) ← parseGitHubCapability fields "child"
    let (parent, fields) ← parseGitHubCapability fields "parent"
    .ok (weakerThan child parent, fields)
  | _ => .error s!"unknown case kind `{kind}`; expected a supported authority decision"

def evaluateCase (line : String) (lineNumber : Nat) : Except String CaseResult := do
  let fields : Fields := { values := line.splitOn "\t" }
  let (kind, fields) ← fields.take "case kind"
  let (name, fields) ← fields.take "case name"
  let (encodedExpected, fields) ← fields.take "expected result"
  let expected ← parseBool encodedExpected "expected result"
  let (actual, fields) ← evaluateOperation kind fields
  fields.finish
  if actual == expected then
    .ok { name, actual }
  else
    .error s!"line {lineNumber} ({name}): expected {expected}, but Lean returned {actual}"

def withLineContext (lineNumber : Nat) (result : Except String CaseResult) :
    Except String CaseResult :=
  match result with
  | .ok value => .ok value
  | .error error =>
    if error.startsWith "line " then
      .error error
    else
      .error s!"line {lineNumber}: {error}"

def evaluateLines : List String → Nat → Bool → List String → List CaseResult →
    Except String (List CaseResult)
  | [], _, sawHeader, _, results =>
    if !sawHeader then
      .error s!"missing corpus header `{corpusHeader}`"
    else if results.isEmpty then
      .error "authority corpus contains no cases"
    else
      .ok results.reverse
  | line :: remaining, lineNumber, sawHeader, names, results =>
    if line == corpusHeader then
      evaluateLines remaining (lineNumber + 1) true names results
    else if line.isEmpty || line.startsWith "#" then
      evaluateLines remaining (lineNumber + 1) sawHeader names results
    else if !sawHeader then
      .error s!"line {lineNumber}: missing `{corpusHeader}` before the first case"
    else
      match withLineContext lineNumber (evaluateCase line lineNumber) with
      | .error error => .error error
      | .ok result =>
        if names.contains result.name then
          .error s!"line {lineNumber}: duplicate case name `{result.name}`; names must be unique"
        else
          evaluateLines remaining (lineNumber + 1) sawHeader
            (result.name :: names) (result :: results)

def evaluateCorpus (input : String) : Except String (List CaseResult) :=
  evaluateLines (input.splitOn "\n") 1 false [] []

-- Specification: `docs/design/verification.md`, shared corpus format versioning.
-- Category: error. Mutation target: accepting unversioned fixture formats.
example :
    (evaluateCorpus "path_valid\troot\ttrue\t-\n").isOk = false := by
  native_decide

-- Specification: shared corpus schema. Category: error.
-- Mutation target: silently ignoring unknown decision families.
example :
    (evaluateCorpus s!"{corpusHeader}\nunknown\tcase-name\ttrue\n").isOk = false := by
  native_decide

-- Specification: shared corpus schema. Category: error.
-- Mutation target: missing-field defaults and permissive parsing.
example :
    (evaluateCorpus s!"{corpusHeader}\npath_valid\tcase-name\ttrue\n").isOk = false := by
  native_decide

-- Specification: the shared runtime domain is Rust `u64`. Category: boundary/error.
-- Mutation target: accepting Lean `Nat` values that the Rust parser must reject.
example :
    (evaluateCorpus
      s!"{corpusHeader}\ntime_valid\toverflow\ttrue\t0\t18446744073709551616\n").isOk = false := by
  native_decide

-- Specification: shared corpus oracle. Category: contract.
-- Mutation target: two implementations agreeing on the wrong answer.
example :
    (evaluateCorpus s!"{corpusHeader}\npath_valid\troot\tfalse\t-\n").isOk = false := by
  native_decide

-- Specification: differential output keys. Category: contract.
-- Mutation target: ambiguous duplicate case names.
example :
    (evaluateCorpus
      s!"{corpusHeader}\npath_valid\troot\ttrue\t-\npath_valid\troot\ttrue\t-\n").isOk = false := by
  native_decide

private def defaultCorpusPath : String := "../tests/fixtures/authority-core.tsv"

def corpusPathFromArgs : List String → Except String String
  | [] => .ok defaultCorpusPath
  | [path] => .ok path
  | _ => .error
    "too many arguments; usage: authority_corpus [tests/fixtures/authority-core.tsv]"

def runCorpus (path : String) : IO UInt32 := do
  try
    let input ← IO.FS.readFile path
    match evaluateCorpus input with
    | .error error =>
      IO.eprintln s!"authority corpus failed: {error}"
      pure 1
    | .ok results =>
      for result in results do
        IO.println s!"{result.name}\t{result.actual}"
      pure 0
  catch error =>
    IO.eprintln s!"authority corpus failed: failed to read `{path}`: {error}"
    pure 1

end AuthorityCorpus

def main (arguments : List String) : IO UInt32 :=
  match AuthorityCorpus.corpusPathFromArgs arguments with
  | .ok path => AuthorityCorpus.runCorpus path
  | .error error => do
    IO.eprintln s!"authority corpus failed: {error}"
    pure 1
