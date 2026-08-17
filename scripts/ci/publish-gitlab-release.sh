#!/usr/bin/env bash

set -euo pipefail

readonly repository_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
cd -- "${repository_root}"

for required_variable in CI_API_V4_URL CI_PROJECT_ID CI_JOB_TOKEN CI_COMMIT_TAG; do
  if [[ -z "${!required_variable:-}" ]]; then
    printf 'required GitLab CI variable is missing: %s\n' "${required_variable}" >&2
    exit 2
  fi
done

if [[ ! -f dist/release.env ]]; then
  printf 'dist/release.env is missing\n' >&2
  exit 1
fi

# shellcheck source=scripts/ci/release-metadata-lib.sh
source "${repository_root}/scripts/ci/release-metadata-lib.sh"
release_metadata_load dist/release.env

if [[ "${CI_COMMIT_TAG}" != "${RELEASE_TAG}" ]]; then
  printf 'release metadata tag does not match CI_COMMIT_TAG\n' >&2
  exit 1
fi

readonly package_registry_url="${CI_API_V4_URL}/projects/${CI_PROJECT_ID}/packages/generic/authority-corpus/${CI_COMMIT_TAG}"
readonly publish_temp="$(mktemp -d)"
trap 'rm -rf -- "${publish_temp}"' EXIT

readonly release_assets=(
  "${ARCHIVE_NAME}"
  "${SBOM_NAME}"
  "${CHECKSUM_NAME}"
  "${SIGNATURE_BUNDLE_NAME}"
)

for asset_name in "${release_assets[@]}"; do
  local_asset="dist/${asset_name}"
  existing_asset="${publish_temp}/${asset_name}"
  asset_url="${package_registry_url}/${asset_name}"

  if [[ ! -f "${local_asset}" ]]; then
    printf 'release asset is missing: %s\n' "${local_asset}" >&2
    exit 1
  fi

  http_status="$(curl --silent --show-error --location \
    --connect-timeout 15 \
    --header "JOB-TOKEN: ${CI_JOB_TOKEN}" \
    --output "${existing_asset}" \
    --write-out '%{http_code}' \
    "${asset_url}")"

  case "${http_status}" in
    200)
      if ! cmp --silent "${local_asset}" "${existing_asset}"; then
        printf 'existing package asset differs and will not be overwritten: %s\n' \
          "${asset_name}" >&2
        exit 1
      fi
      ;;
    404)
      curl --fail-with-body --location \
        --retry 5 --retry-all-errors --connect-timeout 15 \
        --header "JOB-TOKEN: ${CI_JOB_TOKEN}" \
        --upload-file "${local_asset}" \
        "${asset_url}"
      ;;
    *)
      printf 'unexpected package registry response for %s: HTTP %s\n' \
        "${asset_name}" "${http_status}" >&2
      exit 1
      ;;
  esac
done

# GitLab's generic-package upload endpoint addresses one file at a time and
# does not itself reject undeclared files already present in the version. Query
# the package record after all idempotent uploads and require the registry-side
# file set to equal the release contract exactly.
packages_json="${publish_temp}/packages.json"
packages_headers="${publish_temp}/packages.headers"
curl --fail-with-body --silent --show-error --location \
  --connect-timeout 15 \
  --header "JOB-TOKEN: ${CI_JOB_TOKEN}" \
  --dump-header "${packages_headers}" \
  --output "${packages_json}" \
  --get \
  --data-urlencode 'package_type=generic' \
  --data-urlencode 'package_name=authority-corpus' \
  --data-urlencode "package_version=${CI_COMMIT_TAG}" \
  --data-urlencode 'per_page=100' \
  "${CI_API_V4_URL}/projects/${CI_PROJECT_ID}/packages"

if [[ "$(tr -d '\r' < "${packages_headers}" | awk -F': *' 'tolower($1) == "x-next-page" {print $2}' | tail -1)" != '' ]]; then
  printf 'GitLab returned more package records than the bounded verification page\n' >&2
  exit 1
fi
package_id="$(jq --raw-output \
  --arg tag "${CI_COMMIT_TAG}" \
  '[.[] | select(.package_type == "generic" and .name == "authority-corpus" and .version == $tag)]
   | if length == 1 then .[0].id else empty end' \
  "${packages_json}")"
if [[ ! "${package_id}" =~ ^[0-9]+$ ]]; then
  printf 'GitLab registry did not return exactly one matching generic package record\n' >&2
  exit 1
fi

files_json="${publish_temp}/package-files.json"
files_headers="${publish_temp}/package-files.headers"
curl --fail-with-body --silent --show-error --location \
  --connect-timeout 15 \
  --header "JOB-TOKEN: ${CI_JOB_TOKEN}" \
  --dump-header "${files_headers}" \
  --output "${files_json}" \
  --get --data-urlencode 'per_page=100' \
  "${CI_API_V4_URL}/projects/${CI_PROJECT_ID}/packages/${package_id}/package_files"
if [[ "$(tr -d '\r' < "${files_headers}" | awk -F': *' 'tolower($1) == "x-next-page" {print $2}' | tail -1)" != '' ]]; then
  printf 'GitLab package contains more files than the bounded verification page\n' >&2
  exit 1
fi

expected_files="$(printf '%s\n' "${release_assets[@]}" | sort)"
actual_files="$(jq --raw-output '.[].file_name' "${files_json}" | sort)"
if [[ "${actual_files}" != "${expected_files}" ]]; then
  printf 'GitLab package file set differs from the declared release assets\n' >&2
  diff -u <(printf '%s\n' "${expected_files}") <(printf '%s\n' "${actual_files}") >&2 || true
  exit 1
fi
