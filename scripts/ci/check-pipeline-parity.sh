#!/usr/bin/env bash
#
# Proves that the two platforms still implement the same pipeline.
#
# The manifest in ci/gates.yml claims a topology. Nothing enforces a claim, so
# this script checks it from both directions:
#
#   manifest -> platform   every declared gate has a real job, in the file the
#                          manifest names, with an explicit timeout and a job
#                          name derived from the manifest title
#   platform -> manifest   every job in those files is either a declared gate or
#                          one of the few named orchestration jobs
#
# It also checks the structural rules that a gate list cannot express: the
# workspace member list behind the test shards, the trigger surface, credential
# handling on checkout, and the include graph on the GitLab side.
#
# A platform that genuinely cannot host a gate declares `null` plus a
# `why_platform` sentence. That is the only way to be missing a gate, and the
# sentence lands in the operations document rather than in someone's memory.

set -euo pipefail

readonly repository_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly pipeline_tool_bin="${CI_TOOLS_DIR:-${repository_root}/.ci-tools}/bin"
export PATH="${pipeline_tool_bin}:${PATH}"
cd -- "${repository_root}"

readonly manifest="ci/gates.yml"

# Jobs that orchestrate the pipeline rather than gate it. Every other job in a
# workflow that owns gates must be declared in the manifest.
readonly github_orchestration_jobs=(
  plan
  collect
  ci_complete
  security_complete
  deep_complete
  pipeline_summary
  package
  verify
  publish
  record
  quality
  security
)

readonly gitlab_orchestration_jobs=(
  pipeline_plan
  pipeline_summary
  package_release
  verify_release
  publish_release
  create_release
)

failures=0

fail() {
  printf 'FAIL %s\n' "$1" >&2
  failures=$((failures + 1))
}

contains() {
  local needle="$1"
  shift
  local candidate
  for candidate in "$@"; do
    [[ "${candidate}" == "${needle}" ]] && return 0
  done
  return 1
}

# ------------------------------------------------- workspace member agreement --

# The test shard matrix is generated from `packages`. If that list drifts away
# from the workspace, a crate stops being tested and nothing else notices.
manifest_packages="$(yq eval '.packages | sort | join(" ")' "${manifest}")"
workspace_packages="$(
  awk '
    /^members = \[/ { inside = 1; next }
    /^\]/ { inside = 0 }
    inside {
      gsub(/[",]/, "")
      gsub(/^[[:space:]]+|[[:space:]]+$/, "")
      if ($0 != "") { sub(/^crates\//, ""); print }
    }
  ' Cargo.toml | sort | tr '\n' ' ' | sed 's/[[:space:]]*$//'
)"

if [[ "${manifest_packages}" != "${workspace_packages}" ]]; then
  fail "ci/gates.yml packages do not match [workspace].members"
  printf '  manifest:  %s\n' "${manifest_packages}" >&2
  printf '  workspace: %s\n' "${workspace_packages}" >&2
fi

# -------------------------------------------------------- manifest -> platform --

declare -A github_expected=()
declare -A gitlab_expected=()

while IFS='|' read -r gate_id title github_job gitlab_job workflow include why_platform status why_planned; do
  [[ -n "${gate_id}" ]] || continue

  case "${status}" in
    implemented) ;;
    planned)
      # A planned gate is a design that nothing runs yet. Requiring it to have no
      # job anywhere is what keeps the distinction honest: a half-built gate
      # cannot sit in the manifest looking like a check that guards merges.
      if [[ "${why_planned}" == 'null' || -z "${why_planned}" ]]; then
        fail "${gate_id}: a planned gate must say what is missing in why_planned"
      fi
      for planned_field in "${github_job}" "${gitlab_job}" "${workflow}" "${include}"; do
        if [[ "${planned_field}" != 'null' ]]; then
          fail "${gate_id}: planned gates must declare no platform job, found ${planned_field}"
          break
        fi
      done
      continue
      ;;
    *)
      fail "${gate_id}: status must be 'implemented' or 'planned', found '${status}'"
      continue
      ;;
  esac

  if [[ "${github_job}" == 'null' && "${gitlab_job}" == 'null' ]]; then
    fail "${gate_id}: no platform implements this gate"
    continue
  fi

  if [[ "${github_job}" == 'null' || "${gitlab_job}" == 'null' ]] \
    && [[ "${why_platform}" == 'null' || -z "${why_platform}" ]]; then
    fail "${gate_id}: a platform-specific gate must explain itself in why_platform"
  fi

  if [[ "${github_job}" != 'null' ]]; then
    if [[ "${github_job}" != "${gate_id}" ]]; then
      fail "${gate_id}: GitHub job id must equal the gate id, found ${github_job}"
    fi
    if [[ "${workflow}" == 'null' ]]; then
      fail "${gate_id}: declares a GitHub job but no workflow file"
      continue
    fi
    github_expected["${gate_id}"]="${workflow}|${title}"
  fi

  if [[ "${gitlab_job}" != 'null' ]]; then
    if [[ "${include}" == 'null' ]]; then
      fail "${gate_id}: declares a GitLab job but no include file"
      continue
    fi
    gitlab_expected["${gitlab_job}"]="${include}|${gate_id}"
  fi
done < <(yq eval \
  '.gates[] | [.id, .title, (.github // "null"), (.gitlab // "null"), (.workflow // "null"), (.include // "null"), (.why_platform // "null"), (.status // "null"), (.why_planned // "null")] | join("|")' \
  "${manifest}")

for gate_id in "${!github_expected[@]}"; do
  entry="${github_expected[${gate_id}]}"
  workflow_file=".github/workflows/${entry%%|*}"
  gate_title="${entry#*|}"

  if [[ ! -f "${workflow_file}" ]]; then
    fail "${gate_id}: workflow file does not exist: ${workflow_file}"
    continue
  fi

  if [[ "$(yq eval ".jobs | has(\"${gate_id}\")" "${workflow_file}")" != 'true' ]]; then
    fail "${gate_id}: no job with that id in ${workflow_file}"
    continue
  fi

  if [[ "$(yq eval ".jobs.${gate_id} | has(\"timeout-minutes\")" "${workflow_file}")" != 'true' ]]; then
    fail "${gate_id}: job in ${workflow_file} has no timeout-minutes"
  fi

  job_name="$(yq eval ".jobs.${gate_id}.name // \"\"" "${workflow_file}")"
  if [[ "${job_name}" != "${gate_title}"* ]]; then
    fail "${gate_id}: job name '${job_name}' does not start with the manifest title '${gate_title}'"
  fi
done

for gitlab_job in "${!gitlab_expected[@]}"; do
  entry="${gitlab_expected[${gitlab_job}]}"
  include_file=".gitlab/ci/${entry%%|*}"
  gate_id="${entry#*|}"

  if [[ ! -f "${include_file}" ]]; then
    fail "${gate_id}: include file does not exist: ${include_file}"
    continue
  fi

  if [[ "$(yq eval "has(\"${gitlab_job}\")" "${include_file}")" != 'true' ]]; then
    fail "${gate_id}: no job named ${gitlab_job} in ${include_file}"
    continue
  fi

  if [[ "$(yq eval ".${gitlab_job} | has(\"timeout\")" "${include_file}")" != 'true' ]]; then
    fail "${gate_id}: job ${gitlab_job} in ${include_file} has no timeout"
  fi
done

# -------------------------------------------------------- platform -> manifest --

mapfile -t gate_ids < <(yq eval '.gates[].id' "${manifest}")
mapfile -t gitlab_job_names < <(yq eval '.gates[] | select(.gitlab != null) | .gitlab' "${manifest}")

while IFS= read -r -d '' workflow_file; do
  # Only workflows that own gates are held to the rule; a workflow the manifest
  # never references owns no gates and is checked structurally further down.
  while IFS= read -r job_id; do
    [[ -n "${job_id}" ]] || continue
    if contains "${job_id}" "${github_orchestration_jobs[@]}"; then
      continue
    fi
    if contains "${job_id}" "${gate_ids[@]}"; then
      continue
    fi
    fail "${workflow_file}: job '${job_id}' is not declared in ${manifest}"
  done < <(yq eval '.jobs | keys | .[]' "${workflow_file}")
done < <(find .github/workflows -type f -name '*.yml' -print0 | sort -z)

while IFS= read -r -d '' include_file; do
  while IFS= read -r job_name; do
    [[ -n "${job_name}" ]] || continue
    case "${job_name}" in
      .* | stages | variables | workflow | default | include) continue ;;
    esac
    if contains "${job_name}" "${gitlab_orchestration_jobs[@]}"; then
      continue
    fi
    if contains "${job_name}" "${gitlab_job_names[@]}"; then
      continue
    fi
    fail "${include_file}: job '${job_name}' is not declared in ${manifest}"
  done < <(yq eval 'keys | .[]' "${include_file}")
done < <(find .gitlab/ci -type f -name '*.yml' -print0 | sort -z)

# ------------------------------------------------------------- release stages --

# A release stage may be `null` on one platform when that platform reaches the
# same outcome in fewer calls. It carries the same burden a gate does: say why,
# and never be null on both.
while IFS='|' read -r stage_id github_job gitlab_job why_platform; do
  [[ -n "${stage_id}" ]] || continue

  if [[ "${github_job}" == 'null' && "${gitlab_job}" == 'null' ]]; then
    fail "release stage ${stage_id}: no platform implements this stage"
    continue
  fi

  if [[ "${github_job}" == 'null' || "${gitlab_job}" == 'null' ]] \
    && [[ "${why_platform}" == 'null' || -z "${why_platform}" ]]; then
    fail "release stage ${stage_id}: a platform-specific stage must explain itself in why_platform"
  fi

  if [[ "${github_job}" != 'null' ]] \
    && [[ "$(yq eval ".jobs | has(\"${github_job}\")" .github/workflows/release.yml)" != 'true' ]]; then
    fail "release stage ${stage_id}: no job '${github_job}' in .github/workflows/release.yml"
  fi
  if [[ "${gitlab_job}" != 'null' ]] \
    && [[ "$(yq eval "has(\"${gitlab_job}\")" .gitlab/ci/release.yml)" != 'true' ]]; then
    fail "release stage ${stage_id}: no job '${gitlab_job}' in .gitlab/ci/release.yml"
  fi
done < <(yq eval '.release_stages[] | [.id, (.github // "null"), (.gitlab // "null"), (.why_platform // "null")] | join("|")' "${manifest}")

# --------------------------------------------------------- structural policy --

while IFS= read -r -d '' workflow_file; do
  if [[ "$(yq eval '.on | has("pull_request_target")' "${workflow_file}")" == 'true' ]]; then
    fail "${workflow_file}: pull_request_target runs untrusted code with repository credentials"
  fi

  if [[ "$(yq eval 'has("permissions")' "${workflow_file}")" != 'true' ]]; then
    fail "${workflow_file}: no workflow-level permissions block"
  fi

  if [[ "$(yq eval 'has("concurrency")' "${workflow_file}")" != 'true' ]] \
    && [[ "$(yq eval '.on | has("workflow_call")' "${workflow_file}")" != 'true' ]]; then
    fail "${workflow_file}: an entry-point workflow must declare a concurrency group"
  fi

  # A checkout that keeps the token in .git/config leaves it readable by every
  # later step, including anything a dependency's build script decides to run.
  #
  # Counting rather than reading each value is deliberate. yq's `//` returns the
  # right-hand side when the left is null *or false*, so the obvious
  # `.with.persist-credentials // "missing"` reports a correctly hardened
  # checkout as unset and can never distinguish it from a missing one.
  checkout_steps="$(yq eval \
    '[.jobs[].steps[]? | select(.uses // "" | test("^actions/checkout@"))] | length' \
    "${workflow_file}")"
  hardened_checkout_steps="$(yq eval \
    '[.jobs[].steps[]? | select(.uses // "" | test("^actions/checkout@")) | select(.with["persist-credentials"] == false)] | length' \
    "${workflow_file}")"
  if [[ "${checkout_steps}" != "${hardened_checkout_steps}" ]]; then
    fail "${workflow_file}: $((checkout_steps - hardened_checkout_steps)) of ${checkout_steps} actions/checkout steps do not set persist-credentials: false"
  fi
done < <(find .github/workflows -type f -name '*.yml' -print0 | sort -z)

# The include graph must actually pull in every file that defines a job.
while IFS= read -r -d '' include_file; do
  include_reference="${include_file#./}"
  if ! grep -qF "local: ${include_reference}" .gitlab-ci.yml; then
    fail ".gitlab-ci.yml does not include ${include_reference}"
  fi
done < <(find .gitlab/ci -type f -name '*.yml' -print0 | sort -z)

if [[ "${failures}" -gt 0 ]]; then
  printf '\npipeline parity: %d problem(s)\n' "${failures}" >&2
  exit 1
fi

implemented_count="$(yq eval '[.gates[] | select(.status == "implemented")] | length' "${manifest}")"
planned_count="$(yq eval '[.gates[] | select(.status == "planned")] | length' "${manifest}")"
printf 'pipeline parity: %d gate(s) implemented consistently on both platforms, %d planned and running nowhere\n' \
  "${implemented_count}" "${planned_count}"
