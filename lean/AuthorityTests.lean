import Authority.Capability

/-!
# Authority Decision Tests

Executable boundary examples mirrored by the Rust authority tests.
-/

namespace AuthorityTests

open Authority

private def root : CanonicalPath := CanonicalPath.root

private def tick (value : Nat) : MonotonicTime := { ticks := value }

private def broadWindow : TimeWindow :=
  { notBefore := tick 10
    expiresAt := tick 30
    isValid := by decide }

private def narrowWindow : TimeWindow :=
  { notBefore := tick 15
    expiresAt := tick 20
    isValid := by decide }

private def laterWindow : TimeWindow :=
  { notBefore := tick 20
    expiresAt := tick 40
    isValid := by decide }

example : (TimeWindow.ofBounds (tick 10) (tick 11)).isSome = true := by decide

example :
    (TimeWindow.ofBounds (tick 10) (tick 10)).isSome = false ∧
      (TimeWindow.ofBounds (tick 11) (tick 10)).isSome = false := by
  decide

example :
    timeMatches broadWindow (tick 10) = true ∧
      timeMatches broadWindow (tick 29) = true ∧
      timeMatches broadWindow (tick 30) = false := by
  decide

example :
    timeWindowBelow narrowWindow broadWindow = true ∧
      timeWindowBelow broadWindow narrowWindow = false ∧
      timeWindowBelow laterWindow broadWindow = false := by
  decide

example :
    let middleWindow : TimeWindow :=
      { notBefore := tick 12
        expiresAt := tick 25
        isValid := by decide }
    timeWindowBelow narrowWindow middleWindow = true ∧
      timeWindowBelow middleWindow broadWindow = true ∧
      timeWindowBelow narrowWindow broadWindow = true := by
  decide

private def src : CanonicalPath :=
  { segments := ["src"]
    isValid := by decide }

private def docs : CanonicalPath :=
  { segments := ["docs"]
    isValid := by decide }

private def design : CanonicalPath :=
  { segments := ["docs", "design.md"]
    isValid := by decide }

private def parser : CanonicalPath :=
  { segments := ["src", "parser"]
    isValid := by decide }

private def main : CanonicalPath :=
  { segments := ["src", "main.rs"]
    isValid := by decide }

private def lib : CanonicalPath :=
  { segments := ["src", "lib.rs"]
    isValid := by decide }

private def lexer : CanonicalPath :=
  { segments := ["src", "parser", "lexer.rs"]
    isValid := by decide }

example : (CanonicalPath.ofSegments []).isSome = true := by decide

example : (CanonicalPath.ofSegments ["src", "parser", "lexer.rs"]).isSome = true := by
  decide

example :
    (CanonicalPath.ofSegments ["src", "", "output"]).isSome = false ∧
    (CanonicalPath.ofSegments ["src", ".", "output"]).isSome = false ∧
    (CanonicalPath.ofSegments ["src", "..", "output"]).isSome = false ∧
    (CanonicalPath.ofSegments ["src", "parser/lexer.rs", "output"]).isSome = false ∧
    (CanonicalPath.ofSegments ["src", "secret\x00name", "output"]).isSome = false ∧
    (CanonicalPath.ofSegments ["src", "*.rs", "output"]).isSome = false := by
  decide

example : pathBelow (.exact main) (.exact main) = true := by decide

example : pathBelow (.exact main) (.exact lib) = false := by decide

example : pathBelow (.exact lexer) (.prefix parser) = true := by decide

example : pathBelow (.exact main) (.prefix docs) = false := by decide

example : pathBelow (.prefix parser) (.prefix src) = true := by decide

example : pathBelow (.prefix src) (.prefix parser) = false := by decide

example : pathBelow (.prefix src) (.prefix docs) = false := by decide

example : pathBelow (.prefix src) (.exact src) = false := by decide

example : pathBelow (.exact main) (.prefix root) = true := by decide

example : pathBelow (.exact root) (.prefix src) = false := by decide

example : pathBelow (.prefix root) (.prefix root) = true := by decide

example : pathBelow (.prefix root) (.exact root) = false := by decide

private def workspace : RepoId := { value := "workspace" }

private def otherRepository : RepoId := { value := "other" }

private def readEffects : FileEffects := FileEffects.only .readData

private def readWriteEffects : FileEffects :=
  FileEffects.ofList [.readData, .writeData]

private def sourceReadWrite : FileAuthority :=
  { repository := workspace
    effects := readWriteEffects
    path := .prefix src }

example :
    let duplicateEffects := FileEffects.ofList [.readData, .writeData, .readData]
    duplicateEffects .readData = true ∧
      duplicateEffects .writeData = true ∧
      duplicateEffects .rename = false ∧
      FileEffects.empty .readData = false := by
  decide

example :
    fileEffectsBelow FileEffects.empty readEffects = true ∧
      fileEffectsBelow readEffects readEffects = true ∧
      fileEffectsBelow readEffects readWriteEffects = true ∧
      fileEffectsBelow readWriteEffects readEffects = false := by
  decide

example : fileMatches sourceReadWrite
    { repository := workspace
      effect := .readData
      path := main } = true := by
  decide

example : fileMatches sourceReadWrite
    { repository := workspace
      effect := .writeData
      path := src } = true := by
  decide

example : fileMatches sourceReadWrite
    { repository := workspace
      effect := .rename
      path := main } = false := by
  decide

example : fileMatches sourceReadWrite
    { repository := otherRepository
      effect := .readData
      path := main } = false := by
  decide

example : fileMatches sourceReadWrite
    { repository := workspace
      effect := .readData
      path := design } = false := by
  decide

private def readMain : FileAuthority :=
  { repository := workspace
    effects := readEffects
    path := .exact main }

private def readRenameMain : FileAuthority :=
  { repository := workspace
    effects := FileEffects.ofList [.readData, .rename]
    path := .exact main }

private def otherReadMain : FileAuthority :=
  { repository := otherRepository
    effects := readEffects
    path := .exact main }

private def rootRead : FileAuthority :=
  { repository := workspace
    effects := readEffects
    path := .prefix root }

example : fileBodyBelow sourceReadWrite sourceReadWrite = true := by decide

example : fileBodyBelow readMain sourceReadWrite = true := by decide

example : fileBodyBelow readRenameMain sourceReadWrite = false := by decide

example : fileBodyBelow otherReadMain sourceReadWrite = false := by decide

example : fileBodyBelow rootRead sourceReadWrite = false := by decide

private def readLexer : FileAuthority :=
  { repository := workspace
    effects := readEffects
    path := .exact lexer }

private def parserReadWrite : FileAuthority :=
  { repository := workspace
    effects := readWriteEffects
    path := .prefix parser }

private def sourceReadWriteRename : FileAuthority :=
  { repository := workspace
    effects := FileEffects.ofList [.readData, .writeData, .rename]
    path := .prefix src }

example :
    fileBodyBelow readLexer parserReadWrite = true ∧
      fileBodyBelow parserReadWrite sourceReadWriteRename = true ∧
      fileBodyBelow readLexer sourceReadWriteRename = true := by
  decide

private def rootMetadata : CapabilityMetadata :=
  { id := { value := "cap-root" }
    subject := { value := "subject-root" }
    issuer := { value := "host" }
    parent := none
    delegable := true }

private def childMetadata : CapabilityMetadata :=
  { id := { value := "cap-child" }
    subject := { value := "subject-child" }
    issuer := { value := "host" }
    parent := some rootMetadata.id
    delegable := false }

private def rootCapability : Capability :=
  { metadata := rootMetadata
    validity := broadWindow
    authority := .file sourceReadWriteRename }

private def childCapability : Capability :=
  { metadata := childMetadata
    validity := narrowWindow
    authority := .file readMain }

private def parserCapability : Capability :=
  { metadata := childMetadata
    validity :=
      { notBefore := tick 12
        expiresAt := tick 25
        isValid := by decide }
    authority := .file parserReadWrite }

private def lexerCapability : Capability :=
  { metadata := childMetadata
    validity := narrowWindow
    authority := .file readLexer }

private def earlyChildCapability : Capability :=
  { metadata := childMetadata
    validity :=
      { notBefore := tick 9
        expiresAt := tick 20
        isValid := by decide }
    authority := .file readMain }

private def sourceReadRequest (ticks : Nat) : CapabilityRequest :=
  { time := tick ticks
    authority := .file
      { repository := workspace
        effect := .readData
        path := main } }

example :
    capabilityMatches childCapability (sourceReadRequest 15) = true ∧
      capabilityMatches childCapability (sourceReadRequest 20) = false := by
  decide

example :
    capabilityMatches childCapability
      { time := tick 15
        authority := .file
          { repository := workspace
            effect := .readData
            path := design } } = false := by
  decide

example : weakerThan rootCapability rootCapability = true := by decide

example : weakerThan childCapability rootCapability = true := by decide

example :
    weakerThan lexerCapability parserCapability = true ∧
      weakerThan parserCapability rootCapability = true ∧
      weakerThan lexerCapability rootCapability = true := by
  decide

example : weakerThan earlyChildCapability rootCapability = false := by decide

example : weakerThan rootCapability childCapability = false := by decide

end AuthorityTests
