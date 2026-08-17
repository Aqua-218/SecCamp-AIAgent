#!/usr/bin/env bash
#
# Builds every crate alone and enforces the dependency boundaries the design
# depends on.
#
# A workspace build unifies features and pulls in every member, so a crate can
# quietly acquire a dependency it never declares and still compile. Two crates
# here are supposed to sit at the bottom of the tree with nothing from this
# workspace beneath them, and losing that is invisible to any other check:
#
#   authority-core     Every permission decision resolves here, and the Lean
#                      double implementation is written against it alone. A
#                      workspace dependency would put code the proofs do not
#                      model underneath the decision it is proving.
#   runtime-isolation  This is the crate that issues the syscalls. Keeping it
#                      free of workspace dependencies is what lets it be audited
#                      on its own, and what keeps the isolation boundary from
#                      depending on the authority logic it is meant to contain.
#
# Building each crate on its own also proves that its declared feature set is
# actually sufficient, which is what a downstream consumer would get.

set -euo pipefail

readonly repository_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly tool_bin="${CI_TOOLS_DIR:-${repository_root}/.ci-tools}/cargo/bin"
export PATH="${tool_bin}:${PATH}"
cd -- "${repository_root}"

# Crates that must have no workspace crate beneath them at all.
readonly independent_crates=(
  authority-core
  runtime-isolation
)

failures=0

fail() {
  printf 'FAIL %s\n' "$1" >&2
  failures=$((failures + 1))
}

mapfile -t workspace_members < <(
  awk '
    /^members = \[/ { inside = 1; next }
    /^\]/ { inside = 0 }
    inside {
      gsub(/[",]/, "")
      gsub(/^[[:space:]]+|[[:space:]]+$/, "")
      if ($0 != "") { sub(/^crates\//, ""); print }
    }
  ' Cargo.toml | sort
)

if [[ "${#workspace_members[@]}" -eq 0 ]]; then
  printf 'no workspace members found in Cargo.toml\n' >&2
  exit 1
fi

for member in "${workspace_members[@]}"; do
  if ! cargo check --locked --all-targets --all-features \
    --manifest-path "crates/${member}/Cargo.toml" > /dev/null; then
    fail "${member}: does not build on its own"
  fi
done

# `cargo tree` resolves the real graph, so this sees a dependency however it was
# acquired: directly, transitively, or through a feature. Only normal edges are
# considered; a dev-dependency exists to test the crate, not to sit beneath it.
for member in "${independent_crates[@]}"; do
  while IFS= read -r dependency; do
    [[ -n "${dependency}" ]] || continue
    [[ "${dependency}" == "${member}" ]] && continue
    fail "${member}: depends on workspace crate ${dependency}, but must sit at the bottom of the tree"
  done < <(
    cargo tree --locked --package "${member}" --all-features --edges normal --prefix none \
      | grep -F "(${repository_root}/crates/" \
      | sed 's/ v[0-9].*//' \
      | sort -u
  )
done

if [[ "${failures}" -gt 0 ]]; then
  printf '\ncrate isolation: %d problem(s)\n' "${failures}" >&2
  exit 1
fi

printf 'crate isolation: %d crate(s) build alone, %d crate(s) confirmed free of workspace dependencies\n' \
  "${#workspace_members[@]}" "${#independent_crates[@]}"
