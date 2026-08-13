#!/usr/bin/env bash
#
# Records that one gate finished successfully.
#
# GitLab CI has no equivalent of the GitHub `needs` context, so a job proves it
# ran by writing its own receipt. The call belongs on the last line of `script:`
# and never in `after_script:`: a job that fails earlier must leave no receipt,
# which is what lets the fan-in tell "this gate passed" apart from "this gate
# never existed in the pipeline".

set -euo pipefail

readonly repository_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly pipeline_tool_bin="${CI_TOOLS_DIR:-${repository_root}/.ci-tools}/bin"
export PATH="${pipeline_tool_bin}:${PATH}"
cd -- "${repository_root}"

if [[ "$#" -lt 1 || "$#" -gt 2 ]]; then
  printf 'usage: %s <gate-id> [result]\n' "$0" >&2
  exit 2
fi

readonly gate_id="$1"
readonly result="${2:-success}"

if [[ ! "${gate_id}" =~ ^[a-z][a-z0-9_]*$ ]]; then
  printf 'invalid gate id: %s\n' "${gate_id}" >&2
  exit 2
fi

if ! declared_gate_ids="$(yq eval '.gates[].id' ci/gates.yml)"; then
  printf 'unable to read the gate manifest\n' >&2
  exit 1
fi

if ! grep -qxF "${gate_id}" <<< "${declared_gate_ids}"; then
  printf 'gate id is not declared in ci/gates.yml: %s\n' "${gate_id}" >&2
  exit 1
fi

mkdir -p -- reports/gates
printf '%s\n' "${result}" > "reports/gates/${gate_id}.result"
printf 'recorded %s=%s\n' "${gate_id}" "${result}"
