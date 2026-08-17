#!/usr/bin/env bash

# Parse generated release metadata as data. Artifact boundaries must never be evaluated as shell
# code: a forged release.env is otherwise an arbitrary-code execution primitive in verification
# and publication jobs.

release_metadata_die() {
  printf 'release-metadata: %s\n' "$*" >&2
  return 1
}

release_metadata_load() {
  local metadata_path="$1" line key value index=0
  local -a expected_keys=(
    RELEASE_TAG ARTIFACT_STEM ARCHIVE_NAME SBOM_NAME CHECKSUM_NAME
    SIGNATURE_BUNDLE_NAME SOURCE_REVISION SOURCE_EPOCH
  )
  [[ -f "${metadata_path}" && ! -L "${metadata_path}" ]] \
    || release_metadata_die "metadata is not a regular non-symlink file: ${metadata_path}"
  [[ "$(stat -c '%s' -- "${metadata_path}")" -le 4096 ]] \
    || release_metadata_die "metadata exceeds the 4096-byte bound"

  while IFS= read -r line || [[ -n "${line}" ]]; do
    (( index < ${#expected_keys[@]} )) \
      || release_metadata_die "metadata has unexpected trailing fields"
    key="${line%%=*}"
    value="${line#*=}"
    [[ "${line}" == *=* && "${key}" == "${expected_keys[index]}" && -n "${value}" ]] \
      || release_metadata_die "metadata field $((index + 1)) is malformed or out of order"
    printf -v "${key}" '%s' "${value}"
    export "${key}"
    index=$((index + 1))
  done < "${metadata_path}"
  (( index == ${#expected_keys[@]} )) \
    || release_metadata_die "metadata is missing required fields"

  [[ "${RELEASE_TAG}" =~ ^v[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]+)?$ ]] \
    || release_metadata_die "release tag is invalid"
  [[ "${SOURCE_REVISION}" =~ ^[0-9a-f]{40}$ ]] \
    || release_metadata_die "source revision is not a full lowercase commit SHA"
  [[ "${SOURCE_EPOCH}" =~ ^[0-9]{1,12}$ ]] \
    || release_metadata_die "source epoch is invalid"
  [[ "${ARTIFACT_STEM}" == "authority-corpus-${RELEASE_TAG}-x86_64-unknown-linux-gnu" ]] \
    || release_metadata_die "artifact stem is not derived from the release tag"
  [[ "${ARCHIVE_NAME}" == "${ARTIFACT_STEM}.tar.gz" ]] \
    || release_metadata_die "archive name is not derived from the artifact stem"
  [[ "${SBOM_NAME}" == "${ARCHIVE_NAME}.spdx.json" ]] \
    || release_metadata_die "SBOM name is not derived from the archive"
  [[ "${CHECKSUM_NAME}" == "SHA256SUMS" ]] \
    || release_metadata_die "checksum manifest name is not canonical"
  [[ "${SIGNATURE_BUNDLE_NAME}" == "SHA256SUMS.sigstore.json" ]] \
    || release_metadata_die "signature bundle name is not canonical"
}
