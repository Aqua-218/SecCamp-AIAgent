#!/usr/bin/env bash
#
# Proves the paths that decide what CI trusts still require an owner's review.
#
# CODEOWNERS is the only thing standing between a contributor and the definition
# of the checks that judge their own change. A pattern that no longer matches
# anything is worse than a missing one, because the file still reads as if the
# path were protected. The required list below is the set of paths where an
# unreviewed edit can weaken every other gate at once: the pipeline definitions,
# the scripts those pipelines run, the gate manifest that decides which of them
# must pass, and the dependency and static-analysis policy.

set -euo pipefail

readonly repository_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
cd -- "${repository_root}"

readonly codeowners_file='CODEOWNERS'

readonly required_paths=(
  '.github/'
  '.gitlab/'
  '.gitlab-ci.yml'
  'scripts/ci/'
  'ci/'
  'service/'
  'deploy/'
  'guest/'
  'deny.toml'
  '.semgrep.yml'
)

failures=0

fail() {
  printf 'FAIL %s\n' "$1" >&2
  failures=$((failures + 1))
}

[[ -f "${codeowners_file}" ]] || {
  printf '%s is missing\n' "${codeowners_file}" >&2
  exit 1
}

declare -a owned_patterns=()
while IFS= read -r line; do
  line="${line%%#*}"
  [[ -n "${line//[[:space:]]/}" ]] || continue
  read -r pattern owners <<< "${line}"
  if [[ -z "${owners}" ]]; then
    fail "${pattern}: pattern has no owner"
    continue
  fi
  owned_patterns+=("${pattern}")

  # Only leading-slash, directory-or-file patterns are used here, which keeps
  # this resolvable without reimplementing the whole CODEOWNERS grammar.
  resolved="${pattern#/}"
  if [[ ! -e "${resolved}" ]]; then
    fail "${pattern}: owned path does not exist"
  fi
done < "${codeowners_file}"

for required in "${required_paths[@]}"; do
  covered=false
  for pattern in "${owned_patterns[@]+"${owned_patterns[@]}"}"; do
    normalized="${pattern#/}"
    if [[ "${required}" == "${normalized}" || "${required}" == "${normalized}"* ]]; then
      covered=true
      break
    fi
  done
  if [[ "${covered}" != true ]]; then
    fail "${required}: change here can weaken every gate but requires no owner review"
  fi
done

if [[ "${failures}" -gt 0 ]]; then
  printf '\nCODEOWNERS coverage: %d problem(s)\n' "${failures}" >&2
  exit 1
fi

printf 'CODEOWNERS coverage: %d pattern(s) resolve, %d required path(s) covered\n' \
  "${#owned_patterns[@]}" "${#required_paths[@]}"
