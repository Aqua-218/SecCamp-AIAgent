#!/usr/bin/env bash
#
# Structural checks on Cargo.lock and the workspace manifest.
#
# `--locked` proves the lockfile is current. It does not prove the lockfile is
# safe: a git dependency, a vendored source replacement, or a package with no
# checksum all resolve happily under `--locked` and all move the trust boundary
# somewhere `cargo audit` and `cargo deny` cannot follow.
#
# deny.toml already forbids unknown registries and git sources at policy level.
# This runs the same conclusion off the lockfile bytes, so the check survives a
# cargo-deny outage and runs in the fast tier where cargo-deny does not.

set -euo pipefail

readonly repository_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
cd -- "${repository_root}"

readonly crates_io_source='registry+https://github.com/rust-lang/crates.io-index'

failures=0

fail() {
  printf 'FAIL %s\n' "$1" >&2
  failures=$((failures + 1))
}

if [[ ! -f Cargo.lock ]]; then
  printf 'Cargo.lock is missing\n' >&2
  exit 1
fi

readonly lock_version="$(awk -F'= ' '/^version = /{ gsub(/"/, "", $2); print $2; exit }' Cargo.lock)"
if [[ "${lock_version}" != '4' ]]; then
  fail "Cargo.lock format version is ${lock_version:-<empty>}, expected 4"
fi

# A git or path-replaced source is a dependency whose bytes are not addressed by
# a registry checksum, so nothing downstream can reproduce or audit it.
while IFS= read -r offending_source; do
  fail "Cargo.lock contains a non-registry source: ${offending_source}"
done < <(grep -E '^source = ' Cargo.lock | grep -vF "\"${crates_io_source}\"" | sort -u)

# Every package that comes from outside the workspace must carry a checksum.
readonly missing_checksums="$(
  awk '
    /^\[\[package\]\]/ { name = ""; has_source = 0; has_checksum = 0; next }
    /^name = / { gsub(/"/, ""); name = $3; next }
    /^source = / { has_source = 1; next }
    /^checksum = / { has_checksum = 1; next }
    /^$/ {
      if (name != "" && has_source && !has_checksum) { print name }
      name = ""; has_source = 0; has_checksum = 0
    }
    END {
      if (name != "" && has_source && !has_checksum) { print name }
    }
  ' Cargo.lock
)"
if [[ -n "${missing_checksums}" ]]; then
  while IFS= read -r package_name; do
    fail "Cargo.lock package has a source but no checksum: ${package_name}"
  done <<< "${missing_checksums}"
fi

# `[patch]` and `[replace]` redirect a resolved package to different bytes after
# the lockfile has been written.
while IFS= read -r -d '' candidate_manifest; do
  while IFS= read -r offending_table; do
    fail "${candidate_manifest} uses ${offending_table}, which redirects resolved sources"
  done < <(grep -oE '^\[(patch(\.[^]]+)?|replace)\]' "${candidate_manifest}")
done < <(find . -name Cargo.toml -not -path './target/*' -print0)

# The workspace resolver version decides feature unification. A silent downgrade
# changes what every other gate actually compiled.
readonly resolver="$(awk -F'"' '/^resolver = /{ print $2; exit }' Cargo.toml)"
if [[ "${resolver}" != '3' ]]; then
  fail "[workspace].resolver is ${resolver:-<empty>}, expected 3"
fi

# Finally the part only cargo can answer: the lockfile still satisfies the
# manifests exactly, with no resolution allowed.
if ! cargo metadata --locked --format-version 1 --offline > /dev/null 2>&1; then
  if ! cargo metadata --locked --format-version 1 > /dev/null; then
    fail 'cargo metadata --locked failed: Cargo.lock does not satisfy the manifests'
  fi
fi

if [[ "${failures}" -gt 0 ]]; then
  printf '\nlockfile integrity: %d problem(s)\n' "${failures}" >&2
  exit 1
fi

printf 'lockfile integrity: every dependency is a checksummed crates.io package\n'
