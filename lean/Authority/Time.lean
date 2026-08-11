/-!
# Monotonic Time Windows

Validated half-open validity windows and proofs that the executable containment
decision exactly characterizes semantic time-set inclusion.
-/

namespace Authority

/-- A tick from a session-local monotonic clock. -/
structure MonotonicTime where
  /-- Elapsed ticks from the clock origin shared by the compared values. -/
  ticks : Nat
  deriving Repr, BEq, DecidableEq

/-- A nonempty half-open validity window `[notBefore, expiresAt)`. -/
structure TimeWindow where
  /-- The first tick contained by the window. -/
  notBefore : MonotonicTime
  /-- The first tick after the window. -/
  expiresAt : MonotonicTime
  /-- Evidence that the window contains at least one tick. -/
  isValid : notBefore.ticks < expiresAt.ticks

namespace TimeWindow

/-- Creates a validity window only when its bounds are strictly ordered. -/
def ofBounds (notBefore expiresAt : MonotonicTime) : Option TimeWindow :=
  if isValid : notBefore.ticks < expiresAt.ticks then
    some { notBefore, expiresAt, isValid }
  else
    none

/-- States that `time` belongs to the half-open window. -/
def Contains (window : TimeWindow) (time : MonotonicTime) : Prop :=
  window.notBefore.ticks ≤ time.ticks ∧ time.ticks < window.expiresAt.ticks

/-- States that every tick in `child` also belongs to `parent`. -/
def IsSubsetOf (child parent : TimeWindow) : Prop :=
  ∀ time, child.Contains time → parent.Contains time

end TimeWindow

/-- Returns whether `window` contains `time`. -/
def timeMatches (window : TimeWindow) (time : MonotonicTime) : Bool :=
  decide (window.notBefore.ticks ≤ time.ticks) &&
    decide (time.ticks < window.expiresAt.ticks)

/-- The executable time check exactly represents half-open membership. -/
theorem timeMatches_iff_contains {window : TimeWindow} {time : MonotonicTime} :
    timeMatches window time = true ↔ window.Contains time := by
  simp [timeMatches, TimeWindow.Contains]

/-- Returns whether the child's bounds fit entirely inside the parent's bounds. -/
def timeWindowBelow (child parent : TimeWindow) : Bool :=
  decide (parent.notBefore.ticks ≤ child.notBefore.ticks) &&
    decide (child.expiresAt.ticks ≤ parent.expiresAt.ticks)

/-- The executable containment check exactly represents endpoint containment. -/
theorem timeWindowBelow_iff_bounds {child parent : TimeWindow} :
    timeWindowBelow child parent = true ↔
      parent.notBefore.ticks ≤ child.notBefore.ticks ∧
        child.expiresAt.ticks ≤ parent.expiresAt.ticks := by
  simp [timeWindowBelow]

/-- Time-window containment is reflexive. -/
theorem timeWindowBelow_refl (window : TimeWindow) :
    timeWindowBelow window window = true := by
  simp [timeWindowBelow]

/-- Time-window containment is transitive. -/
theorem timeWindowBelow_trans {first second third : TimeWindow}
    (firstBelowSecond : timeWindowBelow first second = true)
    (secondBelowThird : timeWindowBelow second third = true) :
    timeWindowBelow first third = true := by
  rw [timeWindowBelow_iff_bounds] at firstBelowSecond secondBelowThird ⊢
  exact ⟨Nat.le_trans secondBelowThird.1 firstBelowSecond.1,
    Nat.le_trans firstBelowSecond.2 secondBelowThird.2⟩

/-- A successful endpoint check implies semantic time-set inclusion. -/
theorem timeWindowBelow_sound {child parent : TimeWindow}
    (isBelow : timeWindowBelow child parent = true) :
    child.IsSubsetOf parent := by
  rw [timeWindowBelow_iff_bounds] at isBelow
  intro time childContains
  exact ⟨Nat.le_trans isBelow.1 childContains.1,
    Nat.lt_of_lt_of_le childContains.2 isBelow.2⟩

/-- Semantic time-set inclusion implies endpoint containment. -/
theorem timeWindowBelow_complete {child parent : TimeWindow}
    (isSubset : child.IsSubsetOf parent) :
    timeWindowBelow child parent = true := by
  have parentContainsStart := isSubset child.notBefore
    ⟨Nat.le_refl _, child.isValid⟩
  apply timeWindowBelow_iff_bounds.mpr
  refine ⟨parentContainsStart.1, ?_⟩
  apply Nat.le_of_not_lt
  intro parentEndBeforeChildEnd
  have childContainsParentEnd : child.Contains parent.expiresAt :=
    ⟨Nat.le_of_lt parentContainsStart.2, parentEndBeforeChildEnd⟩
  have parentContainsParentEnd := isSubset parent.expiresAt childContainsParentEnd
  exact (Nat.lt_irrefl _ parentContainsParentEnd.2)

/-- Endpoint containment is equivalent to semantic time-set inclusion. -/
theorem timeWindowBelow_iff_subset {child parent : TimeWindow} :
    timeWindowBelow child parent = true ↔ child.IsSubsetOf parent :=
  ⟨timeWindowBelow_sound, timeWindowBelow_complete⟩

end Authority
