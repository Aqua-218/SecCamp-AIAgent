/-!
# Canonical Repository Paths

Validated repository paths, path authority patterns, and proofs that the
executable containment decision exactly characterizes semantic containment.
-/

namespace Authority

/-- Returns whether a string is a valid repository path segment. -/
def isValidPathSegment (segment : String) : Bool :=
  let characters := segment.toList
  !characters.isEmpty &&
    characters != ['.'] &&
    characters != ['.', '.'] &&
    !characters.contains '/' &&
    !characters.contains '\x00' &&
    !characters.contains '*'

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

/-- Concatenates two canonical paths while preserving segment validity. -/
def append (path suffix : CanonicalPath) : CanonicalPath :=
  { segments := path.segments ++ suffix.segments
    isValid := by simp [List.all_append, path.isValid, suffix.isValid] }

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

private def strictSuffix : CanonicalPath :=
  { segments := ["_"]
    isValid := by decide }

/-- Semantic set inclusion implies a successful path containment decision. -/
theorem pathBelow_complete {child parent : PathPattern}
    (isSubset : ∀ path, child.Matches path → parent.Matches path) :
    pathBelow child parent = true := by
  cases child <;> cases parent <;>
    simp [pathBelow, PathPattern.Matches] at isSubset ⊢
  · exact (isSubset _ rfl).symm
  · exact isSubset _ rfl
  · rename_i childPath parentPath
    have parentMatchesChild := isSubset childPath List.prefix_rfl
    have parentMatchesDescendant :=
      isSubset (CanonicalPath.append childPath strictSuffix) (by
        simp [CanonicalPath.append])
    simp [CanonicalPath.append, strictSuffix, parentMatchesChild] at parentMatchesDescendant
  · exact isSubset _ List.prefix_rfl

/--
The executable decision is true exactly when the child's denotation is a
subset of the parent's denotation.
-/
theorem pathBelow_iff_matches_subset {child parent : PathPattern} :
    pathBelow child parent = true ↔
      ∀ path, child.Matches path → parent.Matches path :=
  ⟨pathBelow_sound, pathBelow_complete⟩

end Authority
