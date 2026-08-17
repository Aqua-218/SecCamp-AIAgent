#!/usr/bin/env bash
#
# Computes the execution plan for one pipeline run.
#
# The plan is a single-line JSON document that names, for every gate in
# ci/gates.yml, whether this run must execute it (`required`), may leave it out
# (`skipped`), or cannot host it on this platform (`unavailable`). It also
# carries the expanded matrices, so a workflow never hard-codes a crate list
# that can drift away from the manifest.
#
# The plan is what makes the fan-in honest: `check-gate-results.sh` compares the
# observed job results against it, so a gate that silently disappears from a
# workflow is a failure rather than a green pipeline with one fewer check.
#
# Inputs (environment)
#   PLAN_EVENT          pull_request | push | merge_group | schedule |
#                       workflow_dispatch | tag | web | api
#   PLAN_PLATFORM       github | gitlab                       (default: github)
#   PLAN_TIER           auto | fast | standard | deep | full  (default: auto)
#   PLAN_LABELS         Comma-separated pull-request labels   (default: empty)
#   PLAN_CHANGED_FILES  File holding one changed path per line. When it is
#                       absent or empty the diff is unknown and every scope is
#                       treated as changed.
#
# Options
#   --stages a,b,c      Restrict the plan to these manifest stages.
#   --workflow FILE     Restrict the plan to gates owned by one GitHub workflow.
#   --output PATH       Write the plan to PATH as well as to stdout.

set -euo pipefail

readonly repository_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly pipeline_tool_bin="${CI_TOOLS_DIR:-${repository_root}/.ci-tools}/bin"
export PATH="${pipeline_tool_bin}:${PATH}"
cd -- "${repository_root}"

readonly manifest="ci/gates.yml"

stage_filter=""
workflow_filter=""
output_path=""

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --stages)
      [[ "$#" -ge 2 ]] || {
        printf -- '--stages requires a value\n' >&2
        exit 2
      }
      stage_filter="$2"
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
    --workflow)
      [[ "$#" -ge 2 ]] || {
        printf -- '--workflow requires a value\n' >&2
        exit 2
      }
      workflow_filter="$2"
      shift 2
      ;;
    *)
      printf 'unknown argument: %s\n' "$1" >&2
      exit 2
      ;;
  esac
done

readonly event="${PLAN_EVENT:-}"
readonly platform="${PLAN_PLATFORM:-github}"
readonly requested_tier="${PLAN_TIER:-auto}"
readonly labels="${PLAN_LABELS:-}"
readonly changed_files="${PLAN_CHANGED_FILES:-}"

if [[ -z "${event}" ]]; then
  printf 'PLAN_EVENT is required\n' >&2
  exit 2
fi

case "${platform}" in
  github | gitlab) ;;
  *)
    printf 'unknown platform: %s\n' "${platform}" >&2
    exit 2
    ;;
esac

# ---------------------------------------------------------------------- tier --

# An unrecognized event resolves to the widest tier on purpose. A new trigger
# must not be able to enter the pipeline running less than a scheduled run does.
resolve_tier() {
  case "${requested_tier}" in
    fast | standard | deep | full)
      printf '%s' "${requested_tier}"
      return
      ;;
    auto) ;;
    *)
      printf 'unknown PLAN_TIER: %s\n' "${requested_tier}" >&2
      exit 2
      ;;
  esac

  case ",${labels}," in
    *,ci:full,*)
      printf 'full'
      return
      ;;
    *,ci:deep,*)
      printf 'deep'
      return
      ;;
  esac

  case "${event}" in
    schedule | workflow_dispatch | web | api) printf 'deep' ;;
    pull_request | push | merge_group | tag) printf 'standard' ;;
    *) printf 'deep' ;;
  esac
}

readonly tier="$(resolve_tier)"

tier_enabled() {
  local gate_tier="$1"
  case "${tier}" in
    fast) [[ "${gate_tier}" == 'fast' ]] ;;
    standard) [[ "${gate_tier}" == 'fast' || "${gate_tier}" == 'standard' ]] ;;
    deep | full) return 0 ;;
    *) return 1 ;;
  esac
}

# -------------------------------------------------------------------- scopes --

declare -A scope_patterns=()
declare -A scope_active=()

while IFS='|' read -r scope_name patterns; do
  [[ -n "${scope_name}" ]] || continue
  scope_patterns["${scope_name}"]="${patterns}"
  scope_active["${scope_name}"]='false'
done < <(yq eval \
  '.scopes | to_entries | .[] | .key + "|" + (.value.patterns | join(","))' \
  "${manifest}")

scope_active[always]='true'

diff_known='true'
if [[ "${tier}" == 'full' ]] || [[ -z "${changed_files}" ]] || [[ ! -s "${changed_files}" ]]; then
  diff_known='false'
fi

classify_path() {
  local path="$1"
  local scope_name patterns pattern matched='false'

  for scope_name in "${!scope_patterns[@]}"; do
    patterns="${scope_patterns[${scope_name}]}"
    [[ -n "${patterns}" ]] || continue
    IFS=',' read -r -a pattern_list <<< "${patterns}"
    for pattern in "${pattern_list[@]}"; do
      if [[ "${path}" == "${pattern}"* ]]; then
        scope_active["${scope_name}"]='true'
        matched='true'
      fi
    done
  done

  # A path the manifest does not classify widens the plan instead of narrowing
  # it. Forgetting to register a new directory must not silence a gate.
  if [[ "${matched}" == 'false' ]]; then
    for scope_name in "${!scope_patterns[@]}"; do
      scope_active["${scope_name}"]='true'
    done
  fi
}

if [[ "${diff_known}" == 'true' ]]; then
  while IFS= read -r changed_path; do
    [[ -n "${changed_path}" ]] || continue
    classify_path "${changed_path}"
  done < "${changed_files}"
else
  for scope_key in "${!scope_patterns[@]}"; do
    scope_active["${scope_key}"]='true'
  done
fi

scope_matched() {
  local candidates="$1" candidate
  IFS=',' read -r -a candidate_list <<< "${candidates}"
  for candidate in "${candidate_list[@]}"; do
    if [[ "${scope_active[${candidate}]:-false}" == 'true' ]]; then
      return 0
    fi
  done
  return 1
}

event_allowed() {
  local allowed_events="$1" allowed_event
  [[ -z "${allowed_events}" ]] && return 0
  IFS=',' read -r -a allowed_event_list <<< "${allowed_events}"
  for allowed_event in "${allowed_event_list[@]}"; do
    if [[ "${event}" == "${allowed_event}" ]]; then
      return 0
    fi
  done
  return 1
}

stage_selected() {
  local stage="$1"
  [[ -n "${stage_filter}" ]] || return 0
  case ",${stage_filter}," in
    *",${stage},"*) return 0 ;;
    *) return 1 ;;
  esac
}

# ------------------------------------------------------------------- matrices --

# Matrices are always emitted at full width, even for a gate this run skips.
# GitHub rejects an empty `include`, so the guard belongs on the job condition
# rather than on the matrix itself.
readonly packages="$(yq eval '.packages | join(",")' "${manifest}")"

test_shards_json() {
  local index=0 package separator=''
  printf '['
  IFS=',' read -r -a package_list <<< "${packages}"
  for package in "${package_list[@]}"; do
    index=$((index + 1))
    printf '%s{"shard":%d,"package":"%s"}' "${separator}" "${index}" "${package}"
    separator=','
  done
  printf ']'
}

isolation_packages_json() {
  local package separator=''
  printf '['
  IFS=',' read -r -a package_list <<< "${packages}"
  for package in "${package_list[@]}"; do
    printf '%s{"package":"%s"}' "${separator}" "${package}"
    separator=','
  done
  printf ']'
}

project_matrix() {
  yq eval --output-format=json --indent=0 "$1" "${manifest}"
}

# ----------------------------------------------------------------------- plan --

required_gates=()
skipped_gates=()
unavailable_gates=()
planned_gates=()
gate_entries=()

while IFS='|' read -r gate_id gate_stage gate_tier gate_scopes github_job gitlab_job gate_status gate_workflow gate_events; do
  [[ -n "${gate_id}" ]] || continue
  stage_selected "${gate_stage}" || continue
  # Planned gates deliberately have no workflow/include: that is the topology
  # assertion that no platform job exists yet. Keep them in a filtered plan so
  # the plan and fan-in report the unbuilt boundary instead of dropping it from
  # the evidence document entirely. Implemented gates remain restricted to the
  # workflow that owns their job.
  if [[ -n "${workflow_filter}" && "${gate_workflow}" != "${workflow_filter}" \
    && "${gate_status}" != 'planned' ]]; then
    continue
  fi

  local_job='null'
  if [[ "${platform}" == 'github' ]]; then
    local_job="${github_job}"
  else
    local_job="${gitlab_job}"
  fi

  # `planned` and `unavailable` both mean "expect no result", but they are not
  # the same claim: one says nobody has built the gate, the other says this
  # platform cannot host a gate that does exist. Reporting a planned gate as
  # unavailable would quietly blame the platform for missing work.
  if [[ "${gate_status}" == 'planned' ]]; then
    status='planned'
    planned_gates+=("${gate_id}")
  elif [[ "${local_job}" == 'null' ]]; then
    status='unavailable'
    unavailable_gates+=("${gate_id}")
  elif ! tier_enabled "${gate_tier}"; then
    status='skipped'
    skipped_gates+=("${gate_id}")
  elif ! scope_matched "${gate_scopes}"; then
    status='skipped'
    skipped_gates+=("${gate_id}")
  elif ! event_allowed "${gate_events}"; then
    status='skipped'
    skipped_gates+=("${gate_id}")
  else
    status='required'
    required_gates+=("${gate_id}")
  fi

  gate_entries+=("\"${gate_id}\":\"${status}\"")
done < <(yq eval \
  '.gates[] | [.id, .stage, .tier, (.scopes | join(",")), (.github // "null"), (.gitlab // "null"), (.status // "null"), (.workflow // "null"), (.events // [] | join(","))] | join("|")' \
  "${manifest}")

join_json_array() {
  local separator='' item
  printf '['
  for item in "$@"; do
    printf '%s"%s"' "${separator}" "${item}"
    separator=','
  done
  printf ']'
}

join_object() {
  local separator='' item
  printf '{'
  for item in "$@"; do
    printf '%s%s' "${separator}" "${item}"
    separator=','
  done
  printf '}'
}

active_scope_list=()
for scope_key in "${!scope_active[@]}"; do
  if [[ "${scope_active[${scope_key}]}" == 'true' ]]; then
    active_scope_list+=("${scope_key}")
  fi
done
mapfile -t active_scope_list < <(printf '%s\n' "${active_scope_list[@]}" | sort)

plan="$(
  printf '{'
  printf '"event":"%s",' "${event}"
  printf '"platform":"%s",' "${platform}"
  printf '"tier":"%s",' "${tier}"
  printf '"diff_known":%s,' "${diff_known}"
  printf '"scopes":%s,' "$(join_json_array "${active_scope_list[@]}")"
  printf '"gates":%s,' "$(join_object "${gate_entries[@]}")"
  printf '"required":%s,' "$(join_json_array "${required_gates[@]+"${required_gates[@]}"}")"
  printf '"skipped":%s,' "$(join_json_array "${skipped_gates[@]+"${skipped_gates[@]}"}")"
  printf '"unavailable":%s,' "$(join_json_array "${unavailable_gates[@]+"${unavailable_gates[@]}"}")"
  printf '"planned":%s,' "$(join_json_array "${planned_gates[@]+"${planned_gates[@]}"}")"
  printf '"matrix":{'
  printf '"test_shards":%s,' "$(test_shards_json)"
  printf '"isolation_packages":%s,' "$(isolation_packages_json)"
  printf '"cross_targets":%s,' \
    "$(project_matrix '[.matrices.cross_targets.values[] | {"triple": .triple}]')"
  printf '"miri_packages":%s,' \
    "$(project_matrix '[.matrices.miri_packages.values[] | {"package": .package, "filter": .filter}]')"
  printf '"sanitizer_modes":%s,' \
    "$(project_matrix '[.matrices.sanitizer_modes.values[] | {"mode": .mode, "package": .package}]')"
  printf '"fuzz_targets":%s,' \
    "$(project_matrix '[.matrices.fuzz_targets.values[] | {"package": .package, "target": .target}]')"
  printf '"mutation_shards":%s' \
    "$(project_matrix '[.matrices.mutation_shards.values[] | {"shard": .shard, "package": .package}]')"
  printf '}'
  printf '}'
)"

if [[ -n "${output_path}" ]]; then
  mkdir -p -- "$(dirname -- "${output_path}")"
  printf '%s\n' "${plan}" > "${output_path}"
fi

printf '%s\n' "${plan}"
