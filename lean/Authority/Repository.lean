/-!
# Repository Identities

Opaque host-assigned identifiers used for exact repository comparisons in
capability authorities.
-/

namespace Authority

/-- An opaque repository identity assigned by the session host. -/
structure RepoId where
  /-- The host-assigned identity value. -/
  value : String
  deriving Repr, BEq, DecidableEq

end Authority
