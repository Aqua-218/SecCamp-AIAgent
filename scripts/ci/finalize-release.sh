#!/usr/bin/env bash

set -euo pipefail

readonly repository_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly release_tool_bin="${CI_TOOLS_DIR:-${repository_root}/.ci-tools}/bin"
export PATH="${release_tool_bin}:${PATH}"
cd -- "${repository_root}"

# shellcheck source=scripts/ci/release-metadata-lib.sh
source "${repository_root}/scripts/ci/release-metadata-lib.sh"
release_metadata_load dist/release.env

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

expected_namespace="https://spdx.org/spdxdocs/${ARTIFACT_STEM}-${SOURCE_REVISION}"
readonly expected_namespace
jq --exit-status \
  --arg name "${ARTIFACT_STEM}" \
  --arg version "${RELEASE_TAG}" \
  --arg namespace "${expected_namespace}" \
  '(.spdxVersion == "SPDX-2.3") and
   (.dataLicense == "CC0-1.0") and
   (.SPDXID == "SPDXRef-DOCUMENT") and
   (.name == $name) and
   (.documentNamespace == $namespace) and
   (.packages | type == "array" and length >= 1) and
   (any(.packages[]; .name == $name and .versionInfo == $version))' \
  "${sbom_path}" > /dev/null
(
  cd -- dist
  sha256sum "${ARCHIVE_NAME}" "${SBOM_NAME}" > "${CHECKSUM_NAME}"
)

if [[ "${SIGN_RELEASE:-false}" == "true" ]]; then
  cosign sign-blob --yes \
    --bundle "dist/${SIGNATURE_BUNDLE_NAME}" \
    "dist/${CHECKSUM_NAME}"
fi
