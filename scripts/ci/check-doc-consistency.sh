#!/usr/bin/env bash
#
# Checks the machine-readable verification boundary manifest.
#
# Documentation can say "verified" while the command that produced the claim
# has disappeared, or while a source/test link quietly points at a file that no
# longer exists.  This gate does not run the commands and does not promote a
# claim: it only proves that every claim is explicit, bounded to one execution
# scope, backed by existing repository paths, and honest about residual work.
# Actual execution remains the responsibility of the command recorded in the
# manifest and of the hosted/privileged/KVM job that invokes it.

set -euo pipefail

repository_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly repository_root
readonly tool_bin="${CI_TOOLS_DIR:-${repository_root}/.ci-tools}/bin"
export PATH="${tool_bin}:${PATH}"
cd -- "${repository_root}"

readonly expected_yq_version='v4.47.2'
readonly manifest_default='docs/verification-status.yml'
readonly manifest="${1:-${manifest_default}}"

failures=0

fail() {
  printf 'FAIL %s\n' "$1" >&2
  failures=$((failures + 1))
}

if ! command -v yq > /dev/null 2>&1; then
  printf 'yq is required; run scripts/ci/install-pipeline-tools.sh first\n' >&2
  exit 1
fi

if ! yq --version 2>/dev/null | grep -Fq "${expected_yq_version}"; then
  printf 'yq %s is required; found: %s\n' "${expected_yq_version}" "$(yq --version 2>&1 || true)" >&2
  exit 1
fi

if [[ ! -f "${manifest}" ]]; then
  printf 'verification manifest is missing: %s\n' "${manifest}" >&2
  exit 1
fi

if ! yq eval '.' "${manifest}" > /dev/null 2>&1; then
  printf 'verification manifest is not valid YAML: %s\n' "${manifest}" >&2
  exit 1
fi

schema="$(yq eval -r '.schema // ""' "${manifest}")"
if [[ "${schema}" != 'verification-status/v1' ]]; then
  fail ".schema: expected verification-status/v1, found ${schema:-<empty>}"
fi

if [[ "$(yq eval -r 'has("claims") and (.claims | type == "!!seq")' "${manifest}")" != 'true' ]]; then
  fail '.claims: required sequence is missing'
  printf '\nverification status: %d problem(s)\n' "${failures}" >&2
  exit 1
fi

claim_count="$(yq eval -r '.claims | length' "${manifest}")"
if [[ ! "${claim_count}" =~ ^[0-9]+$ || "${claim_count}" -eq 0 ]]; then
  fail '.claims: at least one claim is required'
  printf '\nverification status: %d problem(s)\n' "${failures}" >&2
  exit 1
fi

declare -A seen_ids=()
readonly allowed_statuses=' verified unverified '
readonly allowed_scopes=' hosted privileged kvm external '

repository_path_is_real() {
  local relative="$1" current="${repository_root}" component
  IFS='/' read -r -a components <<< "${relative}"
  for component in "${components[@]}"; do
    [[ -n "${component}" ]] || return 1
    current="${current}/${component}"
    [[ ! -L "${current}" ]] || return 1
  done
  [[ -e "${current}" ]]
}

check_evidence_command() {
  local command_line="$1" label="$2" executable
  executable="${command_line%% *}"
  case "${executable}" in
    cargo)
      [[ "${command_line}" == *' --locked '* || "${command_line}" == *' --locked' ]] \
        || fail "${label}: cargo evidence must use --locked"
      ;;
    scripts/*)
      if ! repository_path_is_real "${executable}" \
        || [[ ! -f "${repository_root}/${executable}" || ! -x "${repository_root}/${executable}" ]]; then
        fail "${label}: repository command is missing, symlinked, or not executable: ${executable}"
      fi
      ;;
    *) fail "${label}: unsupported evidence command boundary: ${executable}" ;;
  esac
}

check_string_array() {
  local index="$1" field="$2" label="$3"
  local array_type length item item_index
  array_type="$(yq eval -r ".claims[${index}].evidence.${field} | type" "${manifest}")"
  if [[ "${array_type}" != '!!seq' ]]; then
    fail "${label}: expected a sequence"
    return
  fi
  length="$(yq eval -r ".claims[${index}].evidence.${field} | length" "${manifest}")"
  if [[ "${length}" -eq 0 ]]; then
    fail "${label}: at least one entry is required"
    return
  fi
  for ((item_index = 0; item_index < length; item_index++)); do
    item="$(yq eval -r ".claims[${index}].evidence.${field}[${item_index}] // \"\"" "${manifest}")"
    if [[ -z "${item}" || "${item}" == 'null' ]]; then
      fail "${label}[${item_index}]: entry is empty"
    elif [[ "${item}" == *$'\n'* || "${item}" == *$'\r'* ]]; then
      fail "${label}[${item_index}]: entry contains a line break"
    elif [[ "${field}" == commands ]]; then
      check_evidence_command "${item}" "${label}[${item_index}]"
    fi
  done
}

check_path_array() {
  local index="$1" field="$2" label="$3"
  local array_type length item item_index
  array_type="$(yq eval -r ".claims[${index}].evidence.${field} | type" "${manifest}")"
  if [[ "${array_type}" != '!!seq' ]]; then
    fail "${label}: expected a sequence"
    return
  fi
  length="$(yq eval -r ".claims[${index}].evidence.${field} | length" "${manifest}")"
  if [[ "${length}" -eq 0 ]]; then
    fail "${label}: at least one path is required"
    return
  fi
  for ((item_index = 0; item_index < length; item_index++)); do
    item="$(yq eval -r ".claims[${index}].evidence.${field}[${item_index}] // \"\"" "${manifest}")"
    if [[ -z "${item}" || "${item}" == 'null' ]]; then
      fail "${label}[${item_index}]: path is empty"
      continue
    fi
    # Evidence is repository-local by construction. Reject absolute paths and
    # traversal so a manifest cannot silently depend on a runner's filesystem.
    if [[ "${item}" == /* || "${item}" == '.' || "${item}" == '..' || "${item}" == */../* || "${item}" == ../* || "${item}" == */.. ]]; then
      fail "${label}[${item_index}]: path must be repository-relative: ${item}"
      continue
    fi
    if ! repository_path_is_real "${item}"; then
      fail "${label}[${item_index}]: path is missing or crosses a symlink: ${item}"
    fi
  done
}

for ((index = 0; index < claim_count; index++)); do
  id="$(yq eval -r ".claims[${index}].id // \"\"" "${manifest}")"
  component="$(yq eval -r ".claims[${index}].component // \"\"" "${manifest}")"
  scope="$(yq eval -r ".claims[${index}].scope // \"\"" "${manifest}")"
  status="$(yq eval -r ".claims[${index}].status // \"\"" "${manifest}")"
  summary="$(yq eval -r ".claims[${index}].summary // \"\"" "${manifest}")"

  [[ -n "${id}" && "${id}" != 'null' ]] || fail "claims[${index}].id: required"
  [[ -n "${component}" && "${component}" != 'null' ]] || fail "claims[${index}].component: required"
  [[ -n "${summary}" && "${summary}" != 'null' ]] || fail "claims[${index}].summary: required"

  if [[ -n "${id}" && "${id}" != 'null' ]]; then
    if [[ -n "${seen_ids[${id}]+present}" ]]; then
      fail "claims[${index}].id: duplicate claim ID ${id}"
    fi
    seen_ids["${id}"]=1
  fi

  if [[ "${allowed_scopes}" != *" ${scope} "* ]]; then
    fail "claims[${index}].scope: expected hosted, privileged, kvm, or external; found ${scope:-<empty>}"
  fi
  if [[ "${allowed_statuses}" != *" ${status} "* ]]; then
    fail "claims[${index}].status: expected verified or unverified; found ${status:-<empty>}"
  fi

  evidence_type="$(yq eval -r ".claims[${index}].evidence | type" "${manifest}")"
  if [[ "${evidence_type}" != '!!map' ]]; then
    fail "claims[${index}].evidence: required map is missing"
  else
    check_string_array "${index}" commands "claims[${index}].evidence.commands"
    check_path_array "${index}" sources "claims[${index}].evidence.sources"
    check_path_array "${index}" tests "claims[${index}].evidence.tests"
  fi

  reasons_type="$(yq eval -r ".claims[${index}].residual_reasons | type" "${manifest}")"
  if [[ "${reasons_type}" != '!!seq' ]]; then
    fail "claims[${index}].residual_reasons: required sequence is missing"
  else
    reasons_length="$(yq eval -r ".claims[${index}].residual_reasons | length" "${manifest}")"
    if [[ "${status}" == 'unverified' && "${reasons_length}" -eq 0 ]]; then
      fail "claims[${index}].residual_reasons: unverified claims require a reason"
    elif [[ "${status}" == 'verified' && "${reasons_length}" -ne 0 ]]; then
      fail "claims[${index}].residual_reasons: verified claims cannot carry residual reasons"
    fi
    for ((reason_index = 0; reason_index < reasons_length; reason_index++)); do
      reason="$(yq eval -r ".claims[${index}].residual_reasons[${reason_index}] // \"\"" "${manifest}")"
      if [[ -z "${reason}" || "${reason}" == 'null' ]]; then
        fail "claims[${index}].residual_reasons[${reason_index}]: reason is empty"
      fi
    done
  fi
done

if [[ "${failures}" -gt 0 ]]; then
  printf '\nverification status: %d problem(s) across %d claim(s)\n' \
    "${failures}" "${claim_count}" >&2
  exit 1
fi

printf 'verification status: %d claim(s) checked; scopes and evidence paths are consistent\n' \
  "${claim_count}"
