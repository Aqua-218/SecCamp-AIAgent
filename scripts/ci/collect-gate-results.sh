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
#   --from-dir     Reads repository-owned result receipts.
#   --from-gitlab-api
#                  Reads the immutable current-pipeline job set from GitLab and
#                  collapses matrix instances to their manifest gate.
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
    --from-gitlab-api)
      source_mode='gitlab-api'
      shift
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

collect_from_gitlab_api() {
  for variable in CI_API_V4_URL CI_PROJECT_ID CI_PIPELINE_ID CI_JOB_TOKEN; do
    [[ -n "${!variable:-}" ]] || {
      printf '%s is required for --from-gitlab-api\n' "${variable}" >&2
      exit 2
    }
  done
  local jobs_file
  jobs_file="$(mktemp)"
  trap 'rm -f -- "${jobs_file}"' RETURN
  curl --fail-with-body --silent --show-error --location \
    --connect-timeout 15 --max-time 30 \
    --header "JOB-TOKEN: ${CI_JOB_TOKEN}" \
    "${CI_API_V4_URL}/projects/${CI_PROJECT_ID}/pipelines/${CI_PIPELINE_ID}/jobs?per_page=100&include_retried=false" \
    > "${jobs_file}"
  jq --exit-status 'type == "array" and length < 100' "${jobs_file}" > /dev/null || {
    printf 'GitLab job response is malformed or hit the one-page safety limit\n' >&2
    exit 1
  }

  while IFS=$'\t' read -r gate_name platform_name; do
    statuses="$(jq -r --arg name "${platform_name}" '
      .[] | select((.name == $name) or (.name | startswith($name + ":"))) | .status
    ' "${jobs_file}")"
    [[ -n "${statuses}" ]] || continue
    if grep -Evqx 'success' <<< "${statuses}"; then
      if grep -Eqx 'failed|canceled' <<< "${statuses}"; then
        printf '%s\tfailure\n' "${gate_name}"
      elif grep -Evqx 'skipped' <<< "${statuses}"; then
        printf '%s\tincomplete\n' "${gate_name}"
      else
        printf '%s\tskipped\n' "${gate_name}"
      fi
    else
      printf '%s\tsuccess\n' "${gate_name}"
    fi
  done < <(yq eval -r '.gates[] | select(.status == "implemented" and .gitlab != null) | [.id, .gitlab] | @tsv' ci/gates.yml)
}

case "${source_mode}" in
  needs) collected="$(collect_from_needs)" ;;
  dir) collected="$(collect_from_dir)" ;;
  gitlab-api) collected="$(collect_from_gitlab_api)" ;;
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
