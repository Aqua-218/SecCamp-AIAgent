#!/usr/bin/env bash

# Validate the authored commit subjects in one explicit event range.
#
# CI must not infer a range from whatever shallow checkout happened to be
# provisioned by a runner. The caller supplies --base/--head (or the script
# derives both from the platform event metadata), and a shallow repository is
# rejected before any revision is inspected. Merge commits are topology
# records created by the integration platform; authored commits are checked
# with --no-merges.

set -euo pipefail

readonly script_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"

usage() {
  cat >&2 <<'EOF'
usage: check-commit-policy.sh [--repo PATH] [--base REV --head REV]

Without --base/--head, the range is derived from GitHub or GitLab event
variables. A complete, non-shallow repository is required. A zero base
revision means an initial push and validates every authored commit reachable
from --head.
EOF
}

repository_root="${COMMIT_POLICY_REPOSITORY:-${script_root}}"
base_revision="${COMMIT_POLICY_BASE:-}"
head_revision="${COMMIT_POLICY_HEAD:-}"

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --repo)
      [[ "$#" -ge 2 ]] || { usage; exit 2; }
      repository_root="$2"
      shift 2
      ;;
    --base)
      [[ "$#" -ge 2 ]] || { usage; exit 2; }
      base_revision="$2"
      shift 2
      ;;
    --head)
      [[ "$#" -ge 2 ]] || { usage; exit 2; }
      head_revision="$2"
      shift 2
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      printf 'unknown argument: %s\n' "$1" >&2
      usage
      exit 2
      ;;
  esac
done

repository_root="$(cd -- "${repository_root}" && pwd)"
git -C "${repository_root}" rev-parse --git-dir >/dev/null

if [[ "$(git -C "${repository_root}" rev-parse --is-shallow-repository)" == 'true' ]]; then
  printf 'commit policy requires a complete repository; shallow history is not accepted\n' >&2
  exit 1
fi

event_name="${GITHUB_EVENT_NAME:-${CI_PIPELINE_SOURCE:-}}"
event_path="${GITHUB_EVENT_PATH:-}"

if [[ -z "${base_revision}" || -z "${head_revision}" ]]; then
  case "${event_name}" in
    pull_request|merge_request_event)
      base_revision="${GITHUB_BASE_SHA:-${CI_MERGE_REQUEST_DIFF_BASE_SHA:-}}"
      head_revision="${GITHUB_SHA:-${CI_COMMIT_SHA:-}}"
      ;;
    merge_group)
      if [[ -z "${event_path}" || ! -f "${event_path}" ]]; then
        printf 'merge_group commit policy requires GITHUB_EVENT_PATH\n' >&2
        exit 2
      fi
      base_revision="$(jq -er '.merge_group.base_sha' "${event_path}")"
      head_revision="$(jq -er '.merge_group.head_sha' "${event_path}")"
      ;;
    push|schedule|web|api|pipeline|parent_pipeline|trigger)
      if [[ -n "${event_path}" && -f "${event_path}" ]] && command -v jq >/dev/null 2>&1; then
        base_revision="$(jq -er '.before // empty' "${event_path}" 2>/dev/null || true)"
        head_revision="$(jq -er '.after // empty' "${event_path}" 2>/dev/null || true)"
      fi
      base_revision="${base_revision:-${CI_COMMIT_BEFORE_SHA:-}}"
      head_revision="${head_revision:-${GITHUB_SHA:-${CI_COMMIT_SHA:-}}}"
      ;;
    '')
      # A local invocation with no event metadata intentionally checks the tip
      # commit only. CI always passes event metadata and therefore checks the
      # complete event range.
      head_revision="${head_revision:-HEAD}"
      base_revision="${base_revision:-HEAD^}"
      ;;
    *)
      printf 'unsupported commit-policy event: %s\n' "${event_name}" >&2
      exit 2
      ;;
  esac
fi

if [[ -z "${base_revision}" || -z "${head_revision}" ]]; then
  printf 'commit policy could not determine both base and head revisions\n' >&2
  exit 2
fi

readonly zero_revision='0000000000000000000000000000000000000000'
if [[ "${head_revision}" == "${zero_revision}" ]]; then
  printf 'commit policy received an all-zero head revision\n' >&2
  exit 2
fi

resolved_head="$(git -C "${repository_root}" rev-parse --verify "${head_revision}^{commit}")"
if [[ "${base_revision}" == "${zero_revision}" ]]; then
  mapfile -t commits < <(git -C "${repository_root}" rev-list --reverse --no-merges "${resolved_head}")
  range_description="<root>..${resolved_head}"
else
  resolved_base="$(git -C "${repository_root}" rev-parse --verify "${base_revision}^{commit}")"
  mapfile -t commits < <(git -C "${repository_root}" rev-list --reverse --no-merges "${resolved_base}..${resolved_head}")
  range_description="${resolved_base}..${resolved_head}"
fi

readonly subject_pattern='^(feat|fix|docs|test|refactor|perf|chore|build|ci|security|revert)(\([[:alnum:]][[:alnum:]./_-]*\))?(!)?: [^[:space:]].*$'
failures=0
for commit in "${commits[@]}"; do
  subject="$(git -C "${repository_root}" show -s --format=%s "${commit}")"
  if [[ "${#subject}" -gt 100 ]]; then
    printf 'commit %s subject exceeds 100 characters: %s\n' "${commit:0:12}" "${subject}" >&2
    failures=$((failures + 1))
    continue
  fi
  if [[ "${subject}" =~ [[:cntrl:]] || "${subject}" =~ [[:space:]]$ ]]; then
    printf 'commit %s subject contains control or trailing whitespace: %s\n' "${commit:0:12}" "${subject}" >&2
    failures=$((failures + 1))
    continue
  fi
  if [[ ! "${subject}" =~ ${subject_pattern} ]]; then
    printf 'commit %s subject is not Conventional Commit shaped: %s\n' "${commit:0:12}" "${subject}" >&2
    failures=$((failures + 1))
  fi
done

if [[ "${failures}" -gt 0 ]]; then
  printf 'commit policy: %d invalid authored commit(s) in %s\n' "${failures}" "${range_description}" >&2
  exit 1
fi

printf 'commit policy passed: %d authored commit(s) checked in %s\n' "${#commits[@]}" "${range_description}"
