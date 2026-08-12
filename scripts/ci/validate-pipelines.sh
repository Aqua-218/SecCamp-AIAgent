#!/usr/bin/env bash

set -euo pipefail

readonly repository_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly pipeline_tool_bin="${CI_TOOLS_DIR:-${repository_root}/.ci-tools}/bin"
export PATH="${pipeline_tool_bin}:${PATH}"
cd -- "${repository_root}"

actionlint -shellcheck="${pipeline_tool_bin}/shellcheck"

while IFS= read -r -d '' yaml_file; do
  yq eval '.' "${yaml_file}" > /dev/null
done < <(find .github .gitlab -type f \( -name '*.yml' -o -name '*.yaml' \) -print0)
yq eval '.' .gitlab-ci.yml > /dev/null

while IFS= read -r -d '' shell_file; do
  # Command substitutions intentionally initialize readonly values atomically.
  shellcheck --severity=warning --exclude=SC2155 "${shell_file}"
done < <(find scripts -type f -name '*.sh' -print0)

while IFS= read -r action_reference; do
  if [[ "${action_reference}" == ./* ]]; then
    continue
  fi
  if [[ ! "${action_reference}" =~ ^[^@[:space:]]+@[0-9a-f]{40}$ ]]; then
    printf 'GitHub Action is not pinned to a full commit SHA: %s\n' \
      "${action_reference}" >&2
    exit 1
  fi
done < <(awk '/^[[:space:]]*uses:/ { print $2 }' .github/workflows/*.yml .github/actions/*/action.yml)

readonly image_reference_pattern="(docker\\.io|ghcr\\.io|registry\\.gitlab\\.com)/[^[:space:]\"']+"
while IFS= read -r image_reference; do
  if [[ ! "${image_reference}" =~ @sha256:[0-9a-f]{64}$ ]]; then
    printf 'Container image is not pinned to a digest: %s\n' "${image_reference}" >&2
    exit 1
  fi
done < <(grep -Eho "${image_reference_pattern}" \
  .github/workflows/*.yml .gitlab-ci.yml .gitlab/ci/*.yml | sort -u)

if grep -ERn \
  'permissions:[[:space:]]*write-all|continue-on-error:[[:space:]]*true|allow_failure:[[:space:]]*true|\|\|[[:space:]]*true' \
  .github .gitlab .gitlab-ci.yml; then
  printf 'forbidden failure suppression or broad permissions detected\n' >&2
  exit 1
fi

printf 'pipeline policy validation passed\n'
