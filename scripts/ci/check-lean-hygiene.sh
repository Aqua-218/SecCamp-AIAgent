#!/usr/bin/env bash
#
# Keeps the Lean side of the double implementation worth trusting.
#
# The differential corpus compares Rust against Lean and reports agreement. That
# result is only meaningful if the Lean side actually proves what it claims: a
# single `sorry` turns a theorem into an assumption, and a stray `axiom` can make
# any statement provable while every gate stays green. Neither shows up as a
# build failure, so nothing else in this pipeline would notice.
#
# `native_decide` is deliberately allowed. The corpus proofs use it to evaluate
# decision procedures on concrete inputs, which is the point of the corpus; it
# widens the trusted base to the compiler rather than admitting an unproved
# statement. The count is reported so a sudden jump is visible in review.

set -euo pipefail

readonly repository_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
cd -- "${repository_root}"

failures=0

fail() {
  printf 'FAIL %s\n' "$1" >&2
  failures=$((failures + 1))
}

mapfile -t lean_sources < <(find lean -type f -name '*.lean' -not -path 'lean/.lake/*' | sort)

if [[ "${#lean_sources[@]}" -eq 0 ]]; then
  printf 'no Lean sources found\n' >&2
  exit 1
fi

# `sorry` as a whole word: a comment mentioning the word in prose is not a hole,
# but `sorry` standing alone as a term is.
while IFS= read -r hit; do
  fail "${hit}: a proof hole leaves the statement unproved"
done < <(grep -nE '(^|[^[:alnum:]_])sorry([^[:alnum:]_]|$)' "${lean_sources[@]}" || true)

while IFS= read -r hit; do
  fail "${hit}: an axiom can make any statement provable"
done < <(grep -nE '^[[:space:]]*axiom[[:space:]]' "${lean_sources[@]}" || true)

# The toolchain the proofs were checked with must be the one the pipeline
# installs, or the differential result describes a different Lean.
readonly toolchain_pin="lean/lean-toolchain"
if [[ ! -f "${toolchain_pin}" ]]; then
  fail "${toolchain_pin}: the Lean toolchain is not pinned"
elif ! grep -qE '^leanprover/lean4:v[0-9]+\.[0-9]+\.[0-9]+$' "${toolchain_pin}"; then
  fail "${toolchain_pin}: the Lean toolchain pin is not an exact version"
fi

if [[ ! -f lean/lake-manifest.json ]]; then
  fail 'lean/lake-manifest.json: the Lean dependency set is not locked'
fi

native_decide_uses="$(grep -cE '(^|[^[:alnum:]_])native_decide([^[:alnum:]_]|$)' "${lean_sources[@]}" \
  | awk -F: '{ total += $2 } END { print total + 0 }')"

if [[ "${failures}" -gt 0 ]]; then
  printf '\nLean proof hygiene: %d problem(s)\n' "${failures}" >&2
  exit 1
fi

printf 'Lean proof hygiene: %d source(s), no proof holes or axioms, %s native_decide use(s)\n' \
  "${#lean_sources[@]}" "${native_decide_uses}"
