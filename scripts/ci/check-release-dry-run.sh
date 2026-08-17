#!/usr/bin/env bash
#
# Runs the whole release build on a normal pipeline, stopping before publication.
#
# Every release step other than publishing is exercised only by a tag. That is
# the one moment when a failure is most expensive and least recoverable: the tag
# already exists, it is immutable, and fixing the pipeline means either a new
# version number or a tag everyone has to be told to ignore. Packaging, SBOM
# generation, checksum manifests, and verification all have inputs that drift —
# a renamed binary, a new crate, a changed manifest field — and none of that
# drift is visible until the tag is pushed.
#
# This runs the same repository-owned scripts a release would, with no signing
# identity and no publication step, so the failure lands on a merge request
# instead.

set -euo pipefail

readonly repository_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly tool_bin="${CI_TOOLS_DIR:-${repository_root}/.ci-tools}/cargo/bin"
readonly pipeline_tool_bin="${CI_TOOLS_DIR:-${repository_root}/.ci-tools}/bin"
export PATH="${tool_bin}:${pipeline_tool_bin}:${PATH}"
cd -- "${repository_root}"

# The version in the workspace manifest is what a real tag would have to match,
# so building it here is what makes the rehearsal representative.
dry_run_tag="v$(awk '
  /^\[workspace\.package\]$/ { in_workspace_package = 1; next }
  /^\[/ { in_workspace_package = 0 }
  in_workspace_package && /^version = / { gsub(/["[:space:]]/, "", $3); print $3; exit }
' Cargo.toml)"
readonly dry_run_tag

if [[ ! "${dry_run_tag}" =~ ^v[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]+)?$ ]]; then
  printf 'workspace version does not form a valid release tag: %s\n' "${dry_run_tag}" >&2
  exit 1
fi

printf 'rehearsing the release of %s\n' "${dry_run_tag}"

scripts/ci/package-release.sh "${dry_run_tag}"

# SIGN_RELEASE stays unset: a dry run must not reach for a signing identity, and
# finalize-release.sh is expected to produce the checksum manifest without one.
scripts/ci/finalize-release.sh

# VERIFY_SIGSTORE stays unset for the same reason. Checksum verification is the
# part that can catch a packaging mistake.
scripts/ci/verify-release.sh

failures=0

require_artifact() {
  local description="$1" path="$2"
  if [[ ! -s "${path}" ]]; then
    printf 'FAIL %s is missing or empty: %s\n' "${description}" "${path}" >&2
    failures=$((failures + 1))
  fi
}

require_artifact 'release metadata' dist/release.env
require_artifact 'checksum manifest' dist/SHA256SUMS

archive_count="$(find dist -maxdepth 1 -type f -name '*.tar.gz' | wc -l)"
if [[ "${archive_count}" -eq 0 ]]; then
  printf 'FAIL the rehearsal produced no release archive\n' >&2
  failures=$((failures + 1))
fi

# An archive without an SBOM beside it would ship unattested contents.
while IFS= read -r archive; do
  require_artifact 'SBOM' "${archive}.spdx.json"
done < <(find dist -maxdepth 1 -type f -name '*.tar.gz' | sort)

if [[ "${failures}" -gt 0 ]]; then
  printf '\nrelease dry run: %d problem(s)\n' "${failures}" >&2
  exit 1
fi

printf 'release dry run: %s packaged, checksummed, and verified without publishing\n' "${dry_run_tag}"
