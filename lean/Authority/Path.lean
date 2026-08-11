/-!
# Canonical Repository Paths

Validated repository paths, path authority patterns, and proofs that the
executable containment decision is reflexive, transitive, and sound.
-/

namespace Authority

/-- Returns whether a string is a valid repository path segment. -/
def isValidPathSegment (segment : String) : Bool :=
  !segment.isEmpty &&
    segment != "." &&
    segment != ".." &&
    !segment.contains '/' &&
    !segment.contains '\x00' &&
    !segment.contains '*'

/--
A repository-relative path whose segments have passed validation.

The empty list denotes the repository root.
-/
structure CanonicalPath where
  /-- Validated repository-relative segments in order. -/
  segments : List String
  /-- Evidence that every segment satisfies `isValidPathSegment`. -/
  isValid : segments.all isValidPathSegment = true

namespace CanonicalPath

/-- The canonical path denoting the repository root. -/
def root : CanonicalPath :=
  { segments := []
    isValid := rfl }

/-- Creates a canonical path when every supplied segment is valid. -/
def ofSegments (segments : List String) : Option CanonicalPath :=
  if isValid : segments.all isValidPathSegment = true then
    some { segments, isValid }
  else
    none

end CanonicalPath

/-- A path selector used by file authorities. -/
inductive PathPattern where
  /-- Selects exactly one canonical path. -/
  | exact (path : CanonicalPath)
  /-- Selects a canonical path and every path below it. -/
  | prefix (path : CanonicalPath)

namespace PathPattern

/-- States that a pattern selects a canonical path. -/
def Matches (pattern : PathPattern) (path : CanonicalPath) : Prop :=
  match pattern with
  | .exact selected => selected.segments = path.segments
  | .prefix selected => selected.segments <+: path.segments

end PathPattern

/-- Returns whether every path selected by `child` is also selected by `parent`. -/
def pathBelow (child parent : PathPattern) : Bool :=
  match child, parent with
  | .exact child, .exact parent => child.segments == parent.segments
  | .exact child, .prefix parent => parent.segments.isPrefixOf child.segments
  | .prefix child, .prefix parent => parent.segments.isPrefixOf child.segments
  | .prefix _, .exact _ => false

/-- Path containment is reflexive. -/
theorem pathBelow_refl (pattern : PathPattern) : pathBelow pattern pattern = true := by
  cases pattern <;> simp [pathBelow]

/-- Path containment is transitive. -/
theorem pathBelow_trans {first second third : PathPattern}
    (firstBelowSecond : pathBelow first second = true)
    (secondBelowThird : pathBelow second third = true) :
    pathBelow first third = true := by
  cases first <;> cases second <;> cases third <;>
    simp [pathBelow] at firstBelowSecond secondBelowThird ⊢
  · exact firstBelowSecond.trans secondBelowThird
  · rw [firstBelowSecond]
    exact secondBelowThird
  · exact secondBelowThird.trans firstBelowSecond
  · exact secondBelowThird.trans firstBelowSecond

/-- A successful containment decision implies semantic set inclusion. -/
theorem pathBelow_sound {child parent : PathPattern}
    (isBelow : pathBelow child parent = true) :
    ∀ path, child.Matches path → parent.Matches path := by
  intro path childMatches
  cases child <;> cases parent <;>
    simp [pathBelow] at isBelow <;>
    simp [PathPattern.Matches] at childMatches ⊢
  · exact isBelow.symm.trans childMatches
  · rw [← childMatches]
    exact isBelow
  · exact isBelow.trans childMatches

end Authority
