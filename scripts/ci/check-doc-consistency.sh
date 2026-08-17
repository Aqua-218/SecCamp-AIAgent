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
readonly allowed_statuses=' verified unverified blocked '
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

command_is_safe_shape() {
  local command_line="$1" label="$2"

  # Evidence is recorded for humans and is never executed by this checker. It
  # is nevertheless a command contract, not an arbitrary shell fragment. A
  # newline or shell operator would make a copied command ambiguous and could
  # turn a review-only field into an injection primitive.
  if [[ -z "${command_line}" || "${command_line}" =~ [[:cntrl:]] ||
    "${command_line}" =~ [\;\|\&\$\`\<\>\(\)\{\}] ]]; then
    fail "${label}: command must be one non-empty, single-line argv shape"
    return 1
  fi
  if [[ "${command_line}" == *' || true'* || "${command_line}" == *' || :'* ||
    "${command_line}" == *'continue-on-error'* || "${command_line}" == *'allow_failure'* ]]; then
    fail "${label}: command cannot make a failed verification look successful"
    return 1
  fi
  return 0
}

command_has_forbidden_test_mode() {
  local command_line="$1"
  local token
  for token in --ignored --include-ignored --no-run --list --skip --exclude; do
    if [[ "${command_line}" =~ (^|[[:space:]])${token}([[:space:]]|$) ]]; then
      return 0
    fi
  done
  return 1
}

check_evidence_command() {
  local command_line="$1" label="$2" mode="${3:-evidence}" executable
  command_is_safe_shape "${command_line}" "${label}" || return 0
  executable="${command_line%% *}"
  [[ -n "${executable}" && "${executable}" != "." && "${executable}" != ".." ]] || {
    fail "${label}: command executable is empty"
    return
  }
  case "${executable}" in
    cargo)
      [[ "${command_line}" == *' --locked '* || "${command_line}" == *' --locked' ]] \
        || fail "${label}: cargo evidence must use --locked"
      if [[ "${mode}" == verified ]] && command_has_forbidden_test_mode "${command_line}"; then
        fail "${label}: verified cargo evidence cannot use an ignored, skipped, listed, or non-executing test mode"
      fi
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

check_required_wrapper() {
  local command_line="$1" label="$2" executable
  executable="${command_line%% *}"
  [[ "${executable}" == scripts/* ]] || return 0
  if ! grep -qE '^[[:space:]]*set[[:space:]]+-euo[[:space:]]+pipefail([[:space:]]|$)' "${repository_root}/${executable}"; then
    fail "${label}: required wrapper must use set -euo pipefail so a failed prerequisite cannot look green"
  fi
  case "${executable}" in
    scripts/ci/verify-*)
      if ! grep -qE '(^|[[:space:]])exit[[:space:]]+[1-9]([[:space:]]|$)' "${repository_root}/${executable}"; then
        fail "${label}: verification wrapper must have a non-zero prerequisite/failure exit path"
      fi
      ;;
  esac
}

check_string_array() {
  local index="$1" field="$2" label="$3" claim_status="${4:-unverified}"
  local array_type length item item_type item_index
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
    item_type="$(yq eval -r ".claims[${index}].evidence.${field}[${item_index}] | type" "${manifest}")"
    item="$(yq eval -r ".claims[${index}].evidence.${field}[${item_index}] // \"\"" "${manifest}")"
    if [[ "${item_type}" != '!!str' ]]; then
      fail "${label}[${item_index}]: entry must be a string"
    elif [[ -z "${item}" || "${item}" == 'null' ]]; then
      fail "${label}[${item_index}]: entry is empty"
    elif [[ "${item}" == *$'\n'* || "${item}" == *$'\r'* ]]; then
      fail "${label}[${item_index}]: entry contains a line break"
    elif [[ "${field}" == commands ]]; then
      check_evidence_command "${item}" "${label}[${item_index}]" "${claim_status}"
    fi
  done
}

check_path_array() {
  local index="$1" field="$2" label="$3"
  local array_type length item item_type item_index
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
    item_type="$(yq eval -r ".claims[${index}].evidence.${field}[${item_index}] | type" "${manifest}")"
    item="$(yq eval -r ".claims[${index}].evidence.${field}[${item_index}] // \"\"" "${manifest}")"
    if [[ "${item_type}" != '!!str' ]]; then
      fail "${label}[${item_index}]: path must be a string"
      continue
    fi
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

check_prerequisites() {
  local index="$1"
  local label="claims[${index}].prerequisites"
  local prerequisites_type length item_type prerequisite_id prerequisite_id_type description description_type check check_type index_name
  prerequisites_type="$(yq eval -r ".claims[${index}].prerequisites | type" "${manifest}")"
  if [[ "${prerequisites_type}" != '!!seq' ]]; then
    fail "${label}: required sequence is missing"
    return
  fi
  length="$(yq eval -r ".claims[${index}].prerequisites | length" "${manifest}")"
  if [[ "${length}" -eq 0 ]]; then
    fail "${label}: at least one prerequisite is required; use an explicit condition instead of an empty list"
    return
  fi
  for ((index_name = 0; index_name < length; index_name++)); do
    item_type="$(yq eval -r ".claims[${index}].prerequisites[${index_name}] | type" "${manifest}")"
    if [[ "${item_type}" != '!!map' ]]; then
      fail "${label}[${index_name}]: prerequisite must be a map with id, description, and check"
      continue
    fi
    prerequisite_id_type="$(yq eval -r ".claims[${index}].prerequisites[${index_name}].id | type" "${manifest}")"
    description_type="$(yq eval -r ".claims[${index}].prerequisites[${index_name}].description | type" "${manifest}")"
    check_type="$(yq eval -r ".claims[${index}].prerequisites[${index_name}].check | type" "${manifest}")"
    prerequisite_id="$(yq eval -r ".claims[${index}].prerequisites[${index_name}].id // \"\"" "${manifest}")"
    description="$(yq eval -r ".claims[${index}].prerequisites[${index_name}].description // \"\"" "${manifest}")"
    check="$(yq eval -r ".claims[${index}].prerequisites[${index_name}].check // \"\"" "${manifest}")"
    [[ "${prerequisite_id_type}" == '!!str' && "${prerequisite_id}" =~ ^[a-z0-9][a-z0-9_-]*$ ]] ||
      fail "${label}[${index_name}].id: required stable identifier"
    [[ "${description_type}" == '!!str' && -n "${description}" && "${description}" != 'null' ]] ||
      fail "${label}[${index_name}].description: required non-empty description"
    [[ "${check_type}" == '!!str' && -n "${check}" && "${check}" != 'null' && "${check}" != *$'\n'* && "${check}" != *$'\r'* ]] ||
      fail "${label}[${index_name}].check: required one-line condition or probe"
  done
}

check_gate() {
  local index="$1" claim_status="$2"
  local label="claims[${index}].gate"
  local gate_type gate_id gate_result prerequisite_policy commands_type length command command_index
  gate_type="$(yq eval -r ".claims[${index}].gate | type" "${manifest}")"
  if [[ "${gate_type}" != '!!map' ]]; then
    fail "${label}: required map with id and commands is missing"
    return
  fi
  gate_id="$(yq eval -r ".claims[${index}].gate.id // \"\"" "${manifest}")"
  [[ "${gate_id}" =~ ^[a-z0-9][a-z0-9_-]*$ ]] ||
    fail "${label}.id: required stable gate identifier"
  gate_result="$(yq eval -r ".claims[${index}].gate.result // \"\"" "${manifest}")"
  [[ "${gate_result}" == required ]] ||
    fail "${label}.result: must be 'required'; optional or advisory gates cannot verify a claim"
  prerequisite_policy="$(yq eval -r ".claims[${index}].gate.on_prerequisite_failure // \"\"" "${manifest}")"
  [[ "${prerequisite_policy}" == fail ]] ||
    fail "${label}.on_prerequisite_failure: must be 'fail'; unavailable prerequisites cannot look green"
  commands_type="$(yq eval -r ".claims[${index}].gate.commands | type" "${manifest}")"
  if [[ "${commands_type}" != '!!seq' ]]; then
    fail "${label}.commands: required sequence is missing"
    return
  fi
  length="$(yq eval -r ".claims[${index}].gate.commands | length" "${manifest}")"
  if [[ "${length}" -eq 0 ]]; then
    fail "${label}.commands: at least one executable gate command is required"
    return
  fi
  for ((command_index = 0; command_index < length; command_index++)); do
    command="$(yq eval -r ".claims[${index}].gate.commands[${command_index}] // \"\"" "${manifest}")"
    if [[ -z "${command}" || "${command}" == 'null' ]]; then
      fail "${label}.commands[${command_index}]: command is empty"
    else
      check_evidence_command "${command}" "${label}.commands[${command_index}]" "${claim_status}"
      check_required_wrapper "${command}" "${label}.commands[${command_index}]"
    fi
  done
}

check_verification_page() {
  local index="$1"
  local page label="claims[${index}].verification_page"
  page="$(yq eval -r ".claims[${index}].verification_page // \"\"" "${manifest}")"
  if [[ -z "${page}" || "${page}" == 'null' ]]; then
    fail "${label}: required repository-relative verification page"
    return
  fi
  if [[ "${page}" == /* || "${page}" == '.' || "${page}" == '..' || "${page}" == */../* ||
    "${page}" == ../* || "${page}" == */.. || "${page}" == *$'\n'* || "${page}" == *$'\r'* ]]; then
    fail "${label}: path must be repository-relative and single-line: ${page}"
    return
  fi
  if ! repository_path_is_real "${page}" || [[ ! -f "${repository_root}/${page}" ]]; then
    fail "${label}: page is missing or crosses a symlink: ${page}"
  fi
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

  if [[ ! "${id}" =~ ^[a-z0-9][a-z0-9_-]*$ ]]; then
    fail "claims[${index}].id: must be a stable lowercase identifier"
  fi
  if [[ ! "${component}" =~ ^[a-z0-9][a-z0-9_-]*$ ]]; then
    fail "claims[${index}].component: must be a stable lowercase identifier"
  fi

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
    fail "claims[${index}].status: expected verified, unverified, or blocked; found ${status:-<empty>}"
  fi

  check_verification_page "${index}"
  check_prerequisites "${index}"
  check_gate "${index}" "${status}"

  evidence_type="$(yq eval -r ".claims[${index}].evidence | type" "${manifest}")"
  if [[ "${evidence_type}" != '!!map' ]]; then
    fail "claims[${index}].evidence: required map is missing"
  else
    check_string_array "${index}" commands "claims[${index}].evidence.commands" "${status}"
    check_path_array "${index}" sources "claims[${index}].evidence.sources"
    check_path_array "${index}" tests "claims[${index}].evidence.tests"
  fi

  reasons_type="$(yq eval -r ".claims[${index}].residual_reasons | type" "${manifest}")"
  if [[ "${reasons_type}" != '!!seq' ]]; then
    fail "claims[${index}].residual_reasons: required sequence is missing"
  else
    reasons_length="$(yq eval -r ".claims[${index}].residual_reasons | length" "${manifest}")"
    if [[ ( "${status}" == 'unverified' || "${status}" == 'blocked' ) && "${reasons_length}" -eq 0 ]]; then
      fail "claims[${index}].residual_reasons: unverified or blocked claims require a reason"
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
