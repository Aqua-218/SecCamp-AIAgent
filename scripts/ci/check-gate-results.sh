#!/usr/bin/env bash
#
# Fail-closed fan-in.
#
# The old fan-in asked one question: did every dependency report success? That
# question cannot distinguish a gate that passed from a gate that quietly left
# the workflow, and it cannot express a gate this pipeline was never meant to
# run. This one compares the observed results against the plan that produced
# them, and every disagreement is a failure:
#
#   required    must be present and `success`
#   skipped     must be absent, or present and `skipped`
#   unavailable must be absent, or present and `skipped`
#   planned     must be absent; a result means a job exists for a gate the
#               manifest still calls unbuilt
#   anything reported that the manifest does not declare is drift
#
# Deliberately pure bash. It runs on the Debian-based GitLab image as well as on
# the GitHub hosted runner, and the only JSON it reads is the compact document
# that `plan-pipeline.sh` writes.

set -euo pipefail

readonly repository_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
cd -- "${repository_root}"

plan_path=''
report_path=''
result_paths=()

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --plan)
      [[ "$#" -ge 2 ]] || {
        printf -- '--plan requires a value\n' >&2
        exit 2
      }
      plan_path="$2"
      shift 2
      ;;
    --results)
      [[ "$#" -ge 2 ]] || {
        printf -- '--results requires a value\n' >&2
        exit 2
      }
      result_paths+=("$2")
      shift 2
      ;;
    --report)
      [[ "$#" -ge 2 ]] || {
        printf -- '--report requires a value\n' >&2
        exit 2
      }
      report_path="$2"
      shift 2
      ;;
    *)
      printf 'unknown argument: %s\n' "$1" >&2
      exit 2
      ;;
  esac
done

if [[ -z "${plan_path}" || "${#result_paths[@]}" -eq 0 ]]; then
  printf 'usage: %s --plan <plan.json> --results <results.tsv> [--results ...]\n' "$0" >&2
  exit 2
fi

if [[ ! -f "${plan_path}" ]]; then
  printf 'plan file is missing: %s\n' "${plan_path}" >&2
  exit 1
fi

readonly plan="$(cat -- "${plan_path}")"

# The plan is machine-generated in one compact shape, so the `gates` object can
# be lifted out by position rather than by a JSON parser this image may not have.
gates_blob="${plan#*\"gates\":\{}"
if [[ "${gates_blob}" == "${plan}" ]]; then
  printf 'plan does not contain a gates object: %s\n' "${plan_path}" >&2
  exit 1
fi
gates_blob="${gates_blob%%\}*}"

declare -A planned=()
declare -A observed=()

IFS=',' read -r -a plan_entries <<< "${gates_blob}"
for entry in "${plan_entries[@]}"; do
  [[ -n "${entry}" ]] || continue
  entry_id="${entry%%:*}"
  entry_status="${entry#*:}"
  entry_id="${entry_id//\"/}"
  entry_status="${entry_status//\"/}"
  planned["${entry_id}"]="${entry_status}"
done

if [[ "${#planned[@]}" -eq 0 ]]; then
  printf 'plan declares no gates: %s\n' "${plan_path}" >&2
  exit 1
fi

for result_path in "${result_paths[@]}"; do
  if [[ ! -f "${result_path}" ]]; then
    printf 'result file is missing: %s\n' "${result_path}" >&2
    exit 1
  fi
  while IFS=$'\t' read -r gate_id gate_result; do
    [[ -n "${gate_id}" ]] || continue
    # A fan-in job aggregating other fan-ins reports itself; it is not a gate.
    if [[ -z "${planned[${gate_id}]:-}" ]]; then
      case "${gate_id}" in
        *_complete | plan | standard_quality | standard_security | quality | security) continue ;;
      esac
    fi
    if [[ -n "${observed[${gate_id}]:-}" && "${observed[${gate_id}]}" != "${gate_result}" ]]; then
      printf 'conflicting results reported for %s: %s and %s\n' \
        "${gate_id}" "${observed[${gate_id}]}" "${gate_result}" >&2
      exit 1
    fi
    observed["${gate_id}"]="${gate_result}"
  done < "${result_path}"
done

failures=0

fail() {
  printf 'FAIL %s\n' "$1" >&2
  failures=$((failures + 1))
}

for gate_id in "${!planned[@]}"; do
  status="${planned[${gate_id}]}"
  result="${observed[${gate_id}]:-<absent>}"

  case "${status}" in
    required)
      if [[ "${result}" != 'success' ]]; then
        fail "${gate_id}: plan required it, observed ${result}"
      fi
      ;;
    skipped | unavailable)
      if [[ "${result}" != '<absent>' && "${result}" != 'skipped' ]]; then
        fail "${gate_id}: plan marked it ${status}, observed ${result}"
      fi
      ;;
    planned)
      # A planned gate has no job anywhere. Seeing any result for one means a
      # job was built without promoting the gate, which is exactly the drift the
      # `status` field exists to prevent.
      if [[ "${result}" != '<absent>' ]]; then
        fail "${gate_id}: planned gates must run nowhere, observed ${result}"
      fi
      ;;
    *)
      fail "${gate_id}: unknown planned status ${status}"
      ;;
  esac
done

for gate_id in "${!observed[@]}"; do
  if [[ -z "${planned[${gate_id}]:-}" ]]; then
    fail "${gate_id}: reported a result but the plan does not declare it"
  fi
done

if [[ -n "${report_path}" ]]; then
  mkdir -p -- "$(dirname -- "${report_path}")"
  {
    printf '| Gate | Planned | Observed |\n'
    printf '|---|---|---|\n'
    for gate_id in $(printf '%s\n' "${!planned[@]}" | sort); do
      printf '| `%s` | %s | %s |\n' \
        "${gate_id}" "${planned[${gate_id}]}" "${observed[${gate_id}]:-absent}"
    done
  } > "${report_path}"
fi

if [[ "${failures}" -gt 0 ]]; then
  printf '\ngate fan-in: %d disagreement(s) between the plan and the observed results\n' \
    "${failures}" >&2
  exit 1
fi

printf 'gate fan-in: %d gate(s) reconciled against the plan\n' "${#planned[@]}"
