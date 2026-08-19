#!/usr/bin/env bash

set -euo pipefail

readonly repository_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly release_tool_bin="${CI_TOOLS_DIR:-${repository_root}/.ci-tools}/bin"
export PATH="${release_tool_bin}:${PATH}"
cd -- "${repository_root}"

readonly requested_release_tag="${RELEASE_TAG:-}"
# shellcheck source=scripts/ci/release-metadata-lib.sh
source "${repository_root}/scripts/ci/release-metadata-lib.sh"
release_metadata_load dist/release.env

if [[ -n "${requested_release_tag}" && "${requested_release_tag}" != "${RELEASE_TAG}" ]]; then
  printf 'release metadata tag does not match the requested release tag\n' >&2
  exit 1
fi
if git rev-parse --verify HEAD > /dev/null 2>&1 \
  && [[ "$(git rev-parse HEAD)" != "${SOURCE_REVISION}" ]]; then
  printf 'release metadata revision does not match the checked-out verifier revision\n' >&2
  exit 1
fi

readonly expected_checksum_entries="$(printf '%s\n' \
  "${ARCHIVE_NAME}" "${SBOM_NAME}" | sort)"
actual_checksum_entries="$(awk '
  NF != 2 || $1 !~ /^[0-9a-f]{64}$/ || $2 !~ /^\*?[A-Za-z0-9][A-Za-z0-9._-]*$/ { exit 2 }
  { sub(/^\*/, "", $2); print $2 }
' "dist/${CHECKSUM_NAME}" | sort)" || {
  printf 'checksum manifest has malformed entries\n' >&2
  exit 1
}
readonly actual_checksum_entries
if [[ "${actual_checksum_entries}" != "${expected_checksum_entries}" ]]; then
  printf 'checksum manifest does not contain the exact declared asset set\n' >&2
  exit 1
fi

(
  cd -- dist
  sha256sum --check --strict "${CHECKSUM_NAME}"
)

readonly expected_members="$(printf '%s\n' \
  "${ARTIFACT_STEM}/" \
  "${ARTIFACT_STEM}/BUILD-METADATA.json" \
  "${ARTIFACT_STEM}/LICENSE" \
  "${ARTIFACT_STEM}/bin/" \
  "${ARTIFACT_STEM}/bin/authority-corpus" | sort)"
actual_members="$(env -u TAR_OPTIONS tar -tzf "dist/${ARCHIVE_NAME}" | sort)" || {
  printf 'release archive cannot be listed\n' >&2
  exit 1
}
readonly actual_members
if [[ "${actual_members}" != "${expected_members}" ]]; then
  printf 'release archive does not contain the exact declared member set\n' >&2
  exit 1
fi
if env -u TAR_OPTIONS tar -tvzf "dist/${ARCHIVE_NAME}" \
  | awk '$1 !~ /^d/ && $1 !~ /^-/ { exit 1 }'; then
  :
else
  printf 'release archive contains a non-regular, non-directory member\n' >&2
  exit 1
fi

archive_metadata="$(env -u TAR_OPTIONS tar -xOzf "dist/${ARCHIVE_NAME}" \
  "${ARTIFACT_STEM}/BUILD-METADATA.json")" || {
  printf 'release archive metadata cannot be read\n' >&2
  exit 1
}
readonly archive_metadata
jq --exit-status \
  --arg artifact "${ARTIFACT_STEM}" \
  --arg revision "${SOURCE_REVISION}" \
  --arg tag "${RELEASE_TAG}" \
  '(.artifact == $artifact) and (.source_revision == $revision) and
   (.source_tag == $tag) and (.target == "x86_64-unknown-linux-gnu") and
   (.workspace_version == ($tag | ltrimstr("v"))) and
   (.license == "AGPL-3.0-only") and
   (.source_repository | test("^https://github\\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")) and
   (.corresponding_source == (.source_repository + "/archive/" + $revision + ".tar.gz"))' \
  <<< "${archive_metadata}" > /dev/null

readonly source_timestamp="$(date --utc --date="@${SOURCE_EPOCH}" '+%Y-%m-%dT%H:%M:%SZ')"
readonly document_namespace="https://spdx.org/spdxdocs/${ARTIFACT_STEM}-${SOURCE_REVISION}"
jq --exit-status \
  --arg name "${ARTIFACT_STEM}" \
  --arg version "${RELEASE_TAG}" \
  --arg namespace "${document_namespace}" \
  --arg created "${source_timestamp}" \
  '(.spdxVersion == "SPDX-2.3") and (.dataLicense == "CC0-1.0") and
   (.SPDXID == "SPDXRef-DOCUMENT") and (.name == $name) and
   (.documentNamespace == $namespace) and (.creationInfo.created == $created) and
   (.packages | type == "array" and length >= 1) and
   (any(.packages[]; .name == $name and .versionInfo == $version))' \
  "dist/${SBOM_NAME}" > /dev/null

if [[ "${VERIFY_SIGSTORE:-false}" == "true" ]]; then
  if [[ -z "${CERTIFICATE_IDENTITY:-}" || -z "${CERTIFICATE_OIDC_ISSUER:-}" ]]; then
    printf 'certificate identity and issuer are required for Sigstore verification\n' >&2
    exit 2
  fi
  cosign verify-blob \
    --bundle "dist/${SIGNATURE_BUNDLE_NAME}" \
    --certificate-identity "${CERTIFICATE_IDENTITY}" \
    --certificate-oidc-issuer "${CERTIFICATE_OIDC_ISSUER}" \
    "dist/${CHECKSUM_NAME}"
fi
