#!/bin/sh

set -eu

: "${CI_API_V4_URL:?CI_API_V4_URL is required}"
: "${CI_PROJECT_ID:?CI_PROJECT_ID is required}"
: "${CI_JOB_TOKEN:?CI_JOB_TOKEN is required}"
: "${CI_COMMIT_SHA:?CI_COMMIT_SHA is required}"
: "${CI_COMMIT_TAG:?CI_COMMIT_TAG is required}"

if [ ! -f dist/release.env ]; then
  printf 'dist/release.env is missing\n' >&2
  exit 1
fi

set -a
# shellcheck disable=SC1091
. dist/release.env
set +a

if [ "${CI_COMMIT_TAG}" != "${RELEASE_TAG}" ]; then
  printf 'release metadata tag does not match CI_COMMIT_TAG\n' >&2
  exit 1
fi

readonly package_registry_url="${CI_API_V4_URL}/projects/${CI_PROJECT_ID}/packages/generic/authority-corpus/${CI_COMMIT_TAG}"
readonly release_name="Release ${CI_COMMIT_TAG}"
readonly release_notes="dist/release-notes.md"
readonly existing_release="$(mktemp)"
trap 'rm -f -- "${existing_release}"' EXIT

printf 'Release %s\n\nVerified checksums, SPDX SBOM, and Sigstore bundle are attached.\n' \
  "${CI_COMMIT_TAG}" > "${release_notes}"

expected_assets="$(jq --compact-output --null-input \
  --arg base "${package_registry_url}" \
  --arg archive "${ARCHIVE_NAME}" \
  --arg sbom "${SBOM_NAME}" \
  --arg checksum "${CHECKSUM_NAME}" \
  --arg signature "${SIGNATURE_BUNDLE_NAME}" \
  '[
    {name: $archive, url: ($base + "/" + $archive), link_type: "package"},
    {name: $sbom, url: ($base + "/" + $sbom), link_type: "other"},
    {name: $checksum, url: ($base + "/" + $checksum), link_type: "other"},
    {name: $signature, url: ($base + "/" + $signature), link_type: "other"}
  ]')"

export GLAB_ENABLE_CI_AUTOLOGIN=true

if glab release view "${CI_COMMIT_TAG}" --output json > "${existing_release}"; then
  if jq --exit-status \
    --arg tag "${CI_COMMIT_TAG}" \
    --arg name "${release_name}" \
    --arg description "$(cat "${release_notes}")" \
    --argjson expected "${expected_assets}" \
    '(.tag_name == $tag) and
     (.name == $name) and
     (.description == $description) and
     (([.assets.links[] | {name, url, link_type}] | sort_by(.name)) ==
      ($expected | sort_by(.name)))' \
    "${existing_release}" > /dev/null; then
    printf 'GitLab release already exists with identical metadata: %s\n' \
      "${CI_COMMIT_TAG}"
    exit 0
  fi

  printf 'existing GitLab release differs and will not be overwritten: %s\n' \
    "${CI_COMMIT_TAG}" >&2
  exit 1
fi

glab release create "${CI_COMMIT_TAG}" \
  --no-update \
  --ref "${CI_COMMIT_SHA}" \
  --name "${release_name}" \
  --notes-file "${release_notes}" \
  --assets-links "${expected_assets}"
