#!/usr/bin/env bash

set -euo pipefail

readonly repository_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly release_tool_bin="${CI_TOOLS_DIR:-${repository_root}/.ci-tools}/bin"
export PATH="${release_tool_bin}:${PATH}"
cd -- "${repository_root}"

if [[ ! -f dist/release.env ]]; then
  printf 'dist/release.env is missing\n' >&2
  exit 1
fi

set -a
# shellcheck disable=SC1091
source dist/release.env
set +a

readonly archive_path="dist/${ARCHIVE_NAME}"
readonly sbom_path="dist/${SBOM_NAME}"
readonly source_timestamp="$(date --utc --date="@${SOURCE_EPOCH}" '+%Y-%m-%dT%H:%M:%SZ')"
readonly document_namespace="https://spdx.org/spdxdocs/${ARTIFACT_STEM}-${SOURCE_REVISION}"

syft "file:${archive_path}" \
  --source-name "${ARTIFACT_STEM}" \
  --source-version "${RELEASE_TAG}" \
  --output "spdx-json=${sbom_path}"

# Syft intentionally emits a random document namespace and wall-clock timestamp.
# Normalize both to source-derived values so reruns produce identical release assets.
sed -E -i \
  -e "s#\"documentNamespace\":\"[^\"]+\"#\"documentNamespace\":\"${document_namespace}\"#" \
  -e "s#\"created\":\"[^\"]+\"#\"created\":\"${source_timestamp}\"#" \
  "${sbom_path}"
(
  cd -- dist
  sha256sum "${ARCHIVE_NAME}" "${SBOM_NAME}" > "${CHECKSUM_NAME}"
)

if [[ "${SIGN_RELEASE:-false}" == "true" ]]; then
  cosign sign-blob --yes \
    --bundle "dist/${SIGNATURE_BUNDLE_NAME}" \
    "dist/${CHECKSUM_NAME}"
fi
