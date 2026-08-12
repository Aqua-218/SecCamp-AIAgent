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

set -a
# shellcheck disable=SC1091
source dist/release.env
set +a

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
