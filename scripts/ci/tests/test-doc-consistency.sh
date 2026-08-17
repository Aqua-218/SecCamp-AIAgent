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
yq_bin="${CI_TOOLS_DIR:-${repository_root}/.ci-tools}/bin/yq"
if [[ ! -x "${yq_bin}" ]]; then
  yq_bin="$(command -v yq || true)"
fi
readonly fixture_dir="$(mktemp -d)"

cleanup() {
  rm -rf -- "${fixture_dir}"
}
trap cleanup EXIT

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

mutated_manifest() {
  local name="$1" expression="$2" path
  path="${fixture_dir}/${name}.yml"
  cp -- "${valid_manifest}" "${path}"
  "${yq_bin}" eval -i "${expression}" "${path}"
  printf '%s\n' "${path}"
}

[[ -x "${checker}" ]] || fail "checker is not executable: ${checker}"
[[ -f "${valid_manifest}" ]] || fail "valid manifest is missing: ${valid_manifest}"
[[ -n "${yq_bin}" ]] || fail 'yq is required for manifest mutation tests'

expect_failure \
  'missing evidence fixture' \
  "${missing_evidence}" \
  'evidence.commands: at least one entry is required'
expect_failure \
  'invalid status fixture' \
  "${invalid_status}" \
  'expected verified, unverified, or blocked'

missing_metadata="$(mutated_manifest missing-metadata 'del(.claims[0].prerequisites)')"
expect_failure \
  'missing prerequisite metadata' \
  "${missing_metadata}" \
  'prerequisites: required sequence is missing'

ignored_cargo="$(mutated_manifest ignored-cargo '.claims[0].evidence.commands = ["cargo test --locked -p authority-core --all-targets -- --ignored"] | .claims[0].gate.commands = ["cargo test --locked -p authority-core --all-targets -- --ignored"]')"
expect_failure \
  'direct ignored cargo evidence' \
  "${ignored_cargo}" \
  'verified cargo evidence cannot use an ignored'

path_only="$(mutated_manifest path-only '.claims[0].evidence.commands = ["crates/authority-core/tests"] | .claims[0].gate.commands = ["crates/authority-core/tests"]')"
expect_failure \
  'path-only evidence' \
  "${path_only}" \
  'unsupported evidence command boundary'

shell_fragment="$(mutated_manifest shell-fragment '.claims[0].evidence.commands = ["cargo test --locked -p authority-core --all-targets || true"] | .claims[0].gate.commands = ["cargo test --locked -p authority-core --all-targets || true"]')"
expect_failure \
  'shell fragment evidence' \
  "${shell_fragment}" \
  'command must be one non-empty, single-line argv shape'

blocked_without_reason="$(mutated_manifest blocked-without-reason '.claims[0].status = "blocked" | .claims[0].residual_reasons = []')"
expect_failure \
  'blocked claim without residual reason' \
  "${blocked_without_reason}" \
  'unverified or blocked claims require a reason'

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
