#!/usr/bin/env bash
#
# Normalizes observed gate results into the tab-separated form that
# `check-gate-results.sh` consumes.
#
# The two platforms know what happened in different ways, so there are two
# sources and one output format:
#
#   --from-needs   GitHub Actions. Reads `toJSON(needs)` from NEEDS_JSON. The
#                  job id equals the gate id by manifest rule, and a matrix job
#                  already reports one aggregate result.
#   --from-dir     GitLab CI. Reads the `reports/gates/*.result` files that each
#                  job writes as its final script line, so a job that failed
#                  before that line leaves no evidence of success behind.
#
# Output is `<gate-id><TAB><result>` on stdout, one gate per line.

set -euo pipefail

readonly repository_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
cd -- "${repository_root}"

source_mode=''
source_dir=''
output_path=''

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --from-needs)
      source_mode='needs'
      shift
      ;;
    --from-dir)
      [[ "$#" -ge 2 ]] || {
        printf -- '--from-dir requires a value\n' >&2
        exit 2
      }
      source_mode='dir'
      source_dir="$2"
      shift 2
      ;;
    --output)
      [[ "$#" -ge 2 ]] || {
        printf -- '--output requires a value\n' >&2
        exit 2
      }
      output_path="$2"
      shift 2
      ;;
    *)
      printf 'unknown argument: %s\n' "$1" >&2
      exit 2
      ;;
  esac
done

collect_from_needs() {
  if [[ -z "${NEEDS_JSON:-}" ]]; then
    printf 'NEEDS_JSON is required for --from-needs\n' >&2
    exit 2
  fi
  # `needs` is a GitHub-only structure and this branch only ever runs on a
  # GitHub runner, where jq is part of the hosted image.
  jq -r 'to_entries[] | .key + "\t" + .value.result' <<< "${NEEDS_JSON}"
}

collect_from_dir() {
  local result_file gate_id result
  if [[ ! -d "${source_dir}" ]]; then
    return 0
  fi
  while IFS= read -r -d '' result_file; do
    gate_id="$(basename -- "${result_file}" .result)"
    result="$(tr -d '[:space:]' < "${result_file}")"
    printf '%s\t%s\n' "${gate_id}" "${result}"
  done < <(find "${source_dir}" -type f -name '*.result' -print0 | sort -z)
}

case "${source_mode}" in
  needs) collected="$(collect_from_needs)" ;;
  dir) collected="$(collect_from_dir)" ;;
  *)
    printf 'exactly one of --from-needs or --from-dir is required\n' >&2
    exit 2
    ;;
esac

if [[ -n "${output_path}" ]]; then
  mkdir -p -- "$(dirname -- "${output_path}")"
  printf '%s\n' "${collected}" > "${output_path}"
fi

printf '%s\n' "${collected}"
