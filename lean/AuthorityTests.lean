import Authority.Path

/-!
# Canonical Repository Path Tests

Executable boundary examples mirrored by the Rust path containment tests.
-/

namespace AuthorityTests

open Authority

private def root : CanonicalPath := CanonicalPath.root

private def src : CanonicalPath :=
  { segments := ["src"]
    isValid := by native_decide }

private def docs : CanonicalPath :=
  { segments := ["docs"]
    isValid := by native_decide }

private def parser : CanonicalPath :=
  { segments := ["src", "parser"]
    isValid := by native_decide }

private def main : CanonicalPath :=
  { segments := ["src", "main.rs"]
    isValid := by native_decide }

private def lib : CanonicalPath :=
  { segments := ["src", "lib.rs"]
    isValid := by native_decide }

private def lexer : CanonicalPath :=
  { segments := ["src", "parser", "lexer.rs"]
    isValid := by native_decide }

example : (CanonicalPath.ofSegments []).isSome = true := by native_decide

example : (CanonicalPath.ofSegments ["src", "parser", "lexer.rs"]).isSome = true := by
  native_decide

example :
    (CanonicalPath.ofSegments ["src", "", "output"]).isSome = false ∧
    (CanonicalPath.ofSegments ["src", ".", "output"]).isSome = false ∧
    (CanonicalPath.ofSegments ["src", "..", "output"]).isSome = false ∧
    (CanonicalPath.ofSegments ["src", "parser/lexer.rs", "output"]).isSome = false ∧
    (CanonicalPath.ofSegments ["src", "secret\x00name", "output"]).isSome = false ∧
    (CanonicalPath.ofSegments ["src", "*.rs", "output"]).isSome = false := by
  native_decide

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

end AuthorityTests
