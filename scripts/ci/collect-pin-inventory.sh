#!/usr/bin/env bash
#
# Collects every version and digest this repository pins into one reviewable list.
#
# The pins are the supply chain. They are spread across a toolchain file, a Lean
# toolchain file, several installer scripts, two sets of pipeline definitions,
# and the guest artifact downloads, which means no reviewer ever sees them
# together and nobody can answer "what exactly do we trust?" without a search.
#
# This is a gate rather than a report because each category is also an assertion:
# a category that suddenly collects nothing means a pin was removed or a file was
# renamed, and that is exactly the change that should not pass unnoticed.

set -euo pipefail

readonly repository_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
cd -- "${repository_root}"

readonly inventory_directory="reports"
readonly inventory_file="${inventory_directory}/pin-inventory.txt"

failures=0

fail() {
  printf 'FAIL %s\n' "$1" >&2
  failures=$((failures + 1))
}

mkdir -p -- "${inventory_directory}"
: > "${inventory_file}"

# Writes a section and fails when it turns out to be empty.
collect() {
  local heading="$1"
  shift
  local content
  content="$("$@" || true)"
  {
    printf '## %s\n' "${heading}"
    if [[ -n "${content}" ]]; then
      printf '%s\n' "${content}"
    else
      printf '(none found)\n'
    fi
    printf '\n'
  } >> "${inventory_file}"
  if [[ -z "${content}" ]]; then
    fail "${heading}: no pins collected, so either a pin was removed or this collector is stale"
  fi
}

collect 'Rust toolchain' \
  grep -hE '^channel' rust-toolchain.toml

collect 'Lean toolchain' \
  cat lean/lean-toolchain

collect 'GitHub Actions (full commit SHA)' \
  bash -c "awk '/^[[:space:]]*uses:/ { print \$2 }' .github/workflows/*.yml .github/actions/*/action.yml | grep -v '^\\./' | sort -u"

collect 'Container images (digest)' \
  bash -c "grep -Eho '(docker\\.io|ghcr\\.io|registry\\.gitlab\\.com)/[^[:space:]\"'\\'']+' .github/workflows/*.yml .gitlab-ci.yml .gitlab/ci/*.yml | sort -u"

collect 'Pipeline tools (version and SHA-256)' \
  bash -c "grep -hE '^readonly [a-z_]+_(version|sha256)=' scripts/ci/install-pipeline-tools.sh scripts/ci/install-release-tools.sh | sort -u"

collect 'Cargo tools (pinned versions)' \
  bash -c "grep -hE '^readonly [a-z_]+_version=' scripts/ci/install-cargo-tools.sh | sort -u"

collect 'Firecracker and guest artifacts (version and digest)' \
  bash -c "grep -hE '^readonly [a-z_]+_(version|sha256|digest)=' scripts/ci/install-firecracker.sh scripts/ci/install-guest-artifacts.sh | sort -u"

# An unpinned Action or image would already fail validate-pipelines.sh; repeating
# the shape check here keeps the inventory from recording something as a pin that
# is not one.
while IFS= read -r action_reference; do
  [[ -n "${action_reference}" ]] || continue
  if [[ ! "${action_reference}" =~ @[0-9a-f]{40}$ ]]; then
    fail "${action_reference}: recorded as a pin but is not a full commit SHA"
  fi
done < <(awk '/^[[:space:]]*uses:/ { print $2 }' .github/workflows/*.yml .github/actions/*/action.yml \
  | grep -v '^\./' | sort -u)

if [[ "${failures}" -gt 0 ]]; then
  printf '\npin inventory: %d problem(s)\n' "${failures}" >&2
  exit 1
fi

printf 'pin inventory: %d line(s) written to %s\n' \
  "$(wc -l < "${inventory_file}")" "${inventory_file}"
