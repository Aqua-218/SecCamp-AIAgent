#!/usr/bin/env bash

set -euo pipefail

readonly repository_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
cd -- "${repository_root}"

if [[ "$#" -ne 1 ]]; then
  printf 'usage: %s <semantic-version-tag>\n' "$0" >&2
  exit 2
fi

readonly release_tag="$1"
if [[ ! "${release_tag}" =~ ^v[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]+)?$ ]]; then
  printf 'invalid release tag: %s\n' "${release_tag}" >&2
  exit 2
fi
if [[ -z "${GITHUB_REPOSITORY:-}" ]]; then
  printf 'GITHUB_REPOSITORY is required\n' >&2
  exit 2
fi

set -a
# shellcheck disable=SC1091
source dist/release.env
set +a

if [[ "${release_tag}" != "${RELEASE_TAG}" ]]; then
  printf 'release metadata tag does not match requested tag\n' >&2
  exit 1
fi

readonly release_temp="$(mktemp -d)"
trap 'rm -rf -- "${release_temp}"' EXIT
readonly release_api="repos/${GITHUB_REPOSITORY}/releases/tags/${release_tag}"
readonly release_assets=("${ARCHIVE_NAME}" "${SBOM_NAME}" "${CHECKSUM_NAME}")

if ! gh release view "${release_tag}" > /dev/null 2>&1; then
  gh release create "${release_tag}" \
    --verify-tag \
    --draft \
    --title "${release_tag}" \
    --generate-notes
fi

# Compare every existing asset before mutating the release.
for asset_name in "${release_assets[@]}"; do
  local_asset="dist/${asset_name}"
  if [[ ! -f "${local_asset}" ]]; then
    printf 'release asset is missing: %s\n' "${local_asset}" >&2
    exit 1
  fi

  asset_id="$(gh api "${release_api}" \
    --jq ".assets[] | select(.name == \"${asset_name}\") | .id")"
  if [[ -z "${asset_id}" ]]; then
    continue
  fi

  existing_asset="${release_temp}/${asset_name}"
  gh api \
    --header 'Accept: application/octet-stream' \
    "repos/${GITHUB_REPOSITORY}/releases/assets/${asset_id}" > "${existing_asset}"
  if ! cmp --silent "${local_asset}" "${existing_asset}"; then
    printf 'existing release asset differs and will not be overwritten: %s\n' \
      "${asset_name}" >&2
    exit 1
  fi
done

for asset_name in "${release_assets[@]}"; do
  local_asset="dist/${asset_name}"
  asset_id="$(gh api "${release_api}" \
    --jq ".assets[] | select(.name == \"${asset_name}\") | .id")"
  if [[ -z "${asset_id}" ]]; then
    gh release upload "${release_tag}" "${local_asset}"
  fi
done

if [[ "$(gh release view "${release_tag}" --json isDraft --jq '.isDraft')" == "true" ]]; then
  gh release edit "${release_tag}" --draft=false
fi
