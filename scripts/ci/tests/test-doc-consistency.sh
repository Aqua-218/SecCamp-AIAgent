#!/usr/bin/env bash
#
# Negative and determinism tests for check-doc-consistency.sh.
#
# The fixtures are deliberately invalid. If either invocation becomes green,
# the checker has stopped enforcing a part of the evidence contract. Running
# the valid manifest twice also guards against output or iteration order that
# depends on an unordered YAML representation.

set -euo pipefail

repository_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly repository_root
readonly checker="${repository_root}/scripts/ci/check-doc-consistency.sh"
readonly valid_manifest="${repository_root}/docs/verification-status.yml"
readonly missing_evidence="${repository_root}/ci/fixtures/verification-status-missing-evidence.yml"
readonly invalid_status="${repository_root}/ci/fixtures/verification-status-invalid-status.yml"

failures=0
checks=0

fail() {
  printf 'FAIL %s\n' "$1" >&2
  failures=$((failures + 1))
}

expect_failure() {
  local label="$1" manifest="$2" expected="$3" output
  checks=$((checks + 1))
  if output="$(${checker} "${manifest}" 2>&1)"; then
    fail "${label}: invalid manifest unexpectedly passed"
    return
  fi
  if ! grep -Fq -- "${expected}" <<< "${output}"; then
    fail "${label}: failure did not mention ${expected}"
  fi
}

[[ -x "${checker}" ]] || fail "checker is not executable: ${checker}"
[[ -f "${valid_manifest}" ]] || fail "valid manifest is missing: ${valid_manifest}"

expect_failure \
  'missing evidence fixture' \
  "${missing_evidence}" \
  'evidence.commands: at least one entry is required'
expect_failure \
  'invalid status fixture' \
  "${invalid_status}" \
  'expected verified or unverified'

checks=$((checks + 1))
first_output="$(${checker} "${valid_manifest}")"
second_output="$(${checker} "${valid_manifest}")"
if [[ "${first_output}" != "${second_output}" ]]; then
  fail 'valid manifest checker output is not deterministic'
fi

if [[ "${failures}" -gt 0 ]]; then
  printf '\ndoc consistency self-test: %d of %d check(s) failed\n' \
    "${failures}" "${checks}" >&2
  exit 1
fi

printf 'doc consistency self-test: %d check(s) passed\n' "${checks}"
