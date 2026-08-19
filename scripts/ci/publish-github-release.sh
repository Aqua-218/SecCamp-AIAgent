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

# shellcheck source=scripts/ci/release-metadata-lib.sh
source "${repository_root}/scripts/ci/release-metadata-lib.sh"
release_metadata_load dist/release.env

if [[ "${release_tag}" != "${RELEASE_TAG}" ]]; then
  printf 'release metadata tag does not match requested tag\n' >&2
  exit 1
fi

readonly release_temp="$(mktemp -d)"
trap 'rm -rf -- "${release_temp}"' EXIT
readonly release_assets=("${ARCHIVE_NAME}" "${SBOM_NAME}" "${CHECKSUM_NAME}")

expected_asset_names="$(printf '%s\n' "${release_assets[@]}" | sort)"
readonly expected_asset_names
for asset_name in "${release_assets[@]}"; do
  if [[ ! -f "dist/${asset_name}" ]]; then
    printf 'release asset is missing: dist/%s\n' "${asset_name}" >&2
    exit 1
  fi
done

find_release_ids() {
  gh api --paginate "repos/${GITHUB_REPOSITORY}/releases?per_page=100" \
    --jq ".[] | select(.tag_name == \"${release_tag}\") | .id"
}

find_release_ids_with_retry() {
  local attempts="$1"
  local attempt
  local release_ids_found

  for ((attempt = 1; attempt <= attempts; attempt++)); do
    release_ids_found="$(find_release_ids)"
    if [[ -n "${release_ids_found}" ]]; then
      printf '%s\n' "${release_ids_found}"
      return 0
    fi
    if [[ "${attempt}" -lt "${attempts}" ]]; then
      sleep 2
    fi
  done
}

release_id_lines="$(find_release_ids_with_retry 1)"
release_ids=()
if [[ -n "${release_id_lines}" ]]; then
  mapfile -t release_ids <<< "${release_id_lines}"
fi
if [[ "${#release_ids[@]}" -gt 1 ]]; then
  printf 'multiple releases exist for tag %s\n' "${release_tag}" >&2
  exit 1
fi
if [[ "${#release_ids[@]}" -eq 0 ]]; then
  create_arguments=(
    "${release_tag}"
    --verify-tag
    --draft
    --title "${release_tag}"
    --generate-notes
  )
  if [[ "${release_tag}" == *-* ]]; then
    create_arguments+=(--prerelease)
  fi
  gh release create "${create_arguments[@]}"
  # Draft releases are eventually visible through the list API even though
  # `gh release create` has already returned successfully.
  release_id_lines="$(find_release_ids_with_retry 5)"
  release_ids=()
  if [[ -n "${release_id_lines}" ]]; then
    mapfile -t release_ids <<< "${release_id_lines}"
  fi
fi
if [[ "${#release_ids[@]}" -ne 1 || ! "${release_ids[0]}" =~ ^[0-9]+$ ]]; then
  printf 'could not resolve the release id for tag %s\n' "${release_tag}" >&2
  exit 1
fi

readonly release_id="${release_ids[0]}"
readonly release_api="repos/${GITHUB_REPOSITORY}/releases/${release_id}"
remote_asset_names="$(gh api "${release_api}" --jq '.assets[].name' | sort)"
readonly remote_asset_names
while IFS= read -r remote_name; do
  [[ -z "${remote_name}" ]] && continue
  if ! grep -Fxq -- "${remote_name}" <<< "${expected_asset_names}"; then
    printf 'existing release contains an undeclared asset: %s\n' "${remote_name}" >&2
    exit 1
  fi
done <<< "${remote_asset_names}"

# Compare every existing asset before mutating the release.
for asset_name in "${release_assets[@]}"; do
  local_asset="dist/${asset_name}"
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
    gh api \
      --method POST \
      --header 'Content-Type: application/octet-stream' \
      --input "${local_asset}" \
      "https://uploads.github.com/repos/${GITHUB_REPOSITORY}/releases/${release_id}/assets?name=${asset_name}" \
      > /dev/null
  fi
done

final_asset_names="$(gh api "${release_api}" --jq '.assets[].name' | sort)"
readonly final_asset_names
if [[ "${final_asset_names}" != "${expected_asset_names}" ]]; then
  printf 'published release does not contain the exact declared asset set\n' >&2
  exit 1
fi

release_is_prerelease=false
if [[ "${release_tag}" == *-* ]]; then
  release_is_prerelease=true
fi
gh api \
  --method PATCH \
  --field draft=false \
  --field prerelease="${release_is_prerelease}" \
  "${release_api}" > /dev/null

if [[ "$(gh api "${release_api}" --jq '.draft')" != 'false' ]]; then
  printf 'release remained a draft after publication\n' >&2
  exit 1
fi
if [[ "$(gh api "${release_api}" --jq '.prerelease')" != "${release_is_prerelease}" ]]; then
  printf 'release prerelease classification does not match tag %s\n' "${release_tag}" >&2
  exit 1
fi
