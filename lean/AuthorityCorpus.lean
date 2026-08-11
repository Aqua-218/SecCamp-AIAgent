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
  | "capability_matches" =>
    let (capability, fields) ← parseCapability fields "authority"
    let (request, fields) ← parseCapabilityRequest fields "request"
    .ok (capabilityMatches capability request, fields)
  | "weaker_than" =>
    let (child, fields) ← parseCapability fields "child"
    let (parent, fields) ← parseCapability fields "parent"
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
