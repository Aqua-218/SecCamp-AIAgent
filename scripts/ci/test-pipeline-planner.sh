#!/usr/bin/env bash
#
# Exercises the pipeline planner against inputs whose answers are known.
#
# `plan-pipeline.sh` decides which gates a run must execute, and
# `check-gate-results.sh` fails a pipeline whose observed results disagree with
# that plan. A planner bug is therefore not a reporting problem: a gate quietly
# demoted to `skipped` disappears from the required set, the fan-in still passes,
# and nothing anywhere says a check stopped running. Nothing else in this
# pipeline exercises the planner, because every real run takes whatever plan it
# produces as the definition of correct.
#
# The cases below pin the behaviour that a silent failure would change: tier
# filtering, scope filtering, platform availability, and the planned/unavailable
# distinction.

set -euo pipefail

readonly repository_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly pipeline_tool_bin="${CI_TOOLS_DIR:-${repository_root}/.ci-tools}/bin"
export PATH="${pipeline_tool_bin}:${PATH}"
cd -- "${repository_root}"

work_directory="$(mktemp -d)"
readonly work_directory
cleanup() { rm -rf -- "${work_directory}"; }
trap cleanup EXIT

failures=0
checks=0

fail() {
  printf 'FAIL %s\n' "$1" >&2
  failures=$((failures + 1))
}

# Asserts one gate's planned status in a plan produced with the given environment.
expect_status() {
  local description="$1" gate_id="$2" expected="$3" plan="$4"
  checks=$((checks + 1))
  local actual
  actual="$(printf '%s' "${plan}" | yq eval -p json -o tsv ".gates.${gate_id}" -)"
  if [[ "${actual}" != "${expected}" ]]; then
    fail "${description}: ${gate_id} planned as '${actual}', expected '${expected}'"
  fi
}

plan_for() {
  env "$@" "${repository_root}/scripts/ci/plan-pipeline.sh"
}

# ------------------------------------------------------------- tier filtering --

# A pull request runs the fast and standard tiers and must not reach for a host
# that only a scheduled run can have.
pull_request_plan="$(plan_for PLAN_EVENT=pull_request PLAN_PLATFORM=github)"
expect_status 'pull request' rust_tests required "${pull_request_plan}"
expect_status 'pull request' coverage required "${pull_request_plan}"
expect_status 'pull request' real_vm skipped "${pull_request_plan}"
expect_status 'pull request' real_runtime_lifecycle skipped "${pull_request_plan}"
expect_status 'pull request' session_owner_kvm skipped "${pull_request_plan}"
expect_status 'pull request' real_capfs skipped "${pull_request_plan}"
expect_status 'pull request' egress_real_https skipped "${pull_request_plan}"
expect_status 'pull request' external_provider_smoke skipped "${pull_request_plan}"
expect_status 'pull request' privileged_isolation skipped "${pull_request_plan}"

# A scheduled run is the only thing that reaches the deep tier.
schedule_plan="$(plan_for PLAN_EVENT=schedule PLAN_PLATFORM=github)"
expect_status 'schedule' real_vm required "${schedule_plan}"
expect_status 'schedule' real_runtime_lifecycle required "${schedule_plan}"
expect_status 'schedule' session_owner_kvm required "${schedule_plan}"
expect_status 'schedule' real_capfs required "${schedule_plan}"
expect_status 'schedule' egress_real_https required "${schedule_plan}"
expect_status 'schedule' external_provider_smoke skipped "${schedule_plan}"
expect_status 'schedule' privileged_isolation required "${schedule_plan}"

# The external-provider gate mutates a disposable repository, so it is never
# eligible for the unattended schedule. GitHub dispatch and protected GitLab
# web/API runs are the only allowed on-demand events.
github_dispatch_plan="$(plan_for PLAN_EVENT=workflow_dispatch PLAN_PLATFORM=github)"
expect_status 'GitHub workflow dispatch' external_provider_smoke required "${github_dispatch_plan}"
gitlab_web_plan="$(plan_for PLAN_EVENT=web PLAN_PLATFORM=gitlab)"
expect_status 'GitLab web pipeline' external_provider_smoke required "${gitlab_web_plan}"
gitlab_api_plan="$(plan_for PLAN_EVENT=api PLAN_PLATFORM=gitlab)"
expect_status 'GitLab API pipeline' external_provider_smoke required "${gitlab_api_plan}"

# A workflow-filtered deep plan must require the production composition gate.
deep_workflow_plan="$(PLAN_EVENT=schedule PLAN_PLATFORM=github \
  "${repository_root}/scripts/ci/plan-pipeline.sh" --workflow deep.yml)"
expect_status 'deep workflow' session_owner_kvm required "${deep_workflow_plan}"

# ------------------------------------------------------ platform availability --

# CodeQL and Scorecard are GitHub-only and say so in the manifest. On GitLab they
# must read as unavailable, never as skipped, or a missing gate would look like a
# filtered one.
gitlab_plan="$(plan_for PLAN_EVENT=schedule PLAN_PLATFORM=gitlab)"
expect_status 'gitlab' codeql unavailable "${gitlab_plan}"
expect_status 'gitlab' scorecard unavailable "${gitlab_plan}"
expect_status 'gitlab' sast required "${gitlab_plan}"

# ------------------------------------------------------------ planned mapping --

# A planned gate must never be reported as unavailable: one says nobody built it,
# the other blames the platform.
checks=$((checks + 1))
planned_ids="$(yq eval '[.gates[] | select(.status == "planned") | .id] | join(" ")' ci/gates.yml)"
for planned_id in ${planned_ids}; do
  expect_status 'planned gate' "${planned_id}" planned "${pull_request_plan}"
done

# ------------------------------------------------------------ scope filtering --

# A change that touches only documentation must still run the always-scoped
# gates and must not claim the Rust ones ran.
docs_only="${work_directory}/docs-only.txt"
printf 'docs/README.md\n' > "${docs_only}"
docs_plan="$(plan_for PLAN_EVENT=pull_request PLAN_PLATFORM=github PLAN_CHANGED_FILES="${docs_only}")"
expect_status 'docs-only change' docs_policy required "${docs_plan}"
expect_status 'docs-only change' rust_tests skipped "${docs_plan}"

# A Rust change must run the Rust gates.
rust_only="${work_directory}/rust-only.txt"
printf 'crates/authority-core/src/lib.rs\n' > "${rust_only}"
rust_plan="$(plan_for PLAN_EVENT=pull_request PLAN_PLATFORM=github PLAN_CHANGED_FILES="${rust_only}")"
expect_status 'rust-only change' rust_tests required "${rust_plan}"

# --------------------------------------------------------------- plan shape --

# Every gate in the manifest must appear in the plan. A gate the planner forgets
# is a gate `check-gate-results.sh` will never ask about.
checks=$((checks + 1))
manifest_gate_count="$(yq eval '.gates | length' ci/gates.yml)"
planned_gate_count="$(printf '%s' "${pull_request_plan}" | yq eval -p json '.gates | length' -)"
if [[ "${manifest_gate_count}" != "${planned_gate_count}" ]]; then
  fail "plan covers ${planned_gate_count} gates, manifest declares ${manifest_gate_count}"
fi

# ------------------------------------------------------------- fan-in semantics --

# The fan-in is the last security boundary: a required protected gate must fail
# when it is absent or skipped, while an unavailable platform gate may be absent
# or explicitly skipped. Planned gates must have no result at all.
fanin_plan="${work_directory}/fanin-plan.json"
printf '%s\n' '{"gates":{"required_gate":"required","skipped_gate":"skipped","unavailable_gate":"unavailable","planned_gate":"planned"}}' > "${fanin_plan}"

expect_fanin() {
  local description="$1" expected="$2" result_path="$3"
  checks=$((checks + 1))
  local actual='failure'
  if "${repository_root}/scripts/ci/check-gate-results.sh" \
    --plan "${fanin_plan}" --results "${result_path}" >/dev/null 2>&1; then
    actual='success'
  fi
  if [[ "${actual}" != "${expected}" ]]; then
    fail "${description}: fan-in returned ${actual}, expected ${expected}"
  fi
}

# A scheduled plan must reject an external-provider result even if a runner
# accidentally creates the job. This protects against a destructive mutation
# being smuggled into the unattended fan-in by topology drift.
scheduled_external_plan="${work_directory}/scheduled-external-plan.json"
printf '%s\n' '{"gates":{"external_provider_smoke":"skipped"}}' > "${scheduled_external_plan}"
scheduled_external_result="${work_directory}/scheduled-external-result.tsv"
printf 'external_provider_smoke\tsuccess\n' > "${scheduled_external_result}"
checks=$((checks + 1))
if "${repository_root}/scripts/ci/check-gate-results.sh" \
  --plan "${scheduled_external_plan}" --results "${scheduled_external_result}" >/dev/null 2>&1; then
  fail 'scheduled external mutation result: fan-in accepted a result for a skipped gate'
fi

fanin_pass="${work_directory}/fanin-pass.tsv"
printf 'required_gate\tsuccess\nskipped_gate\tskipped\nunavailable_gate\tskipped\n' > "${fanin_pass}"
expect_fanin 'successful required and explicitly skipped optional gates' success "${fanin_pass}"

fanin_required_missing="${work_directory}/fanin-required-missing.tsv"
: > "${fanin_required_missing}"
expect_fanin 'missing required gate' failure "${fanin_required_missing}"

fanin_required_skipped="${work_directory}/fanin-required-skipped.tsv"
printf 'required_gate\tskipped\n' > "${fanin_required_skipped}"
expect_fanin 'skipped required gate' failure "${fanin_required_skipped}"

fanin_unavailable_success="${work_directory}/fanin-unavailable-success.tsv"
printf 'required_gate\tsuccess\nunavailable_gate\tsuccess\n' > "${fanin_unavailable_success}"
expect_fanin 'successful unavailable gate result' failure "${fanin_unavailable_success}"

fanin_planned_result="${work_directory}/fanin-planned-result.tsv"
printf 'required_gate\tsuccess\nplanned_gate\tsuccess\n' > "${fanin_planned_result}"
expect_fanin 'result reported for planned gate' failure "${fanin_planned_result}"

if [[ "${failures}" -gt 0 ]]; then
  printf '\npipeline planner self-test: %d of %d check(s) failed\n' "${failures}" "${checks}" >&2
  exit 1
fi

printf 'pipeline planner self-test: %d check(s) passed\n' "${checks}"
