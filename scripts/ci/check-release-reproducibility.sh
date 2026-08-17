#!/usr/bin/env bash
#
# Rebuilds the release archive and requires the bytes to match.
#
# The release is attested and signed, which binds a signature to a digest. That
# only means something if the digest can be derived from the source: without
# reproducibility, a signature says "this build machine produced these bytes"
# rather than "these bytes are what this commit builds into", and nobody
# downstream can check the second claim. It also makes a compromised builder
# undetectable, because there is no second opinion to disagree with it.
#
# Determinism here is not free — it depends on a pinned toolchain, a fixed
# archive ordering, and timestamps that do not leak the clock. Any of those can
# regress silently, and only a second build notices.

set -euo pipefail

readonly repository_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly tool_bin="${CI_TOOLS_DIR:-${repository_root}/.ci-tools}/cargo/bin"
export PATH="${tool_bin}:${PATH}"
cd -- "${repository_root}"

# The tag only names the archive; the bytes come from the working tree, so a
# release tag is not required to prove determinism.
release_tag="${REPRODUCIBILITY_TAG:-v$(awk '
  /^\[workspace\.package\]$/ { in_workspace_package = 1; next }
  /^\[/ { in_workspace_package = 0 }
  in_workspace_package && /^version = / { gsub(/["[:space:]]/, "", $3); print $3; exit }
' Cargo.toml)}"
readonly release_tag

comparison_directory="$(mktemp -d)"
readonly comparison_directory
cleanup() { rm -rf -- "${comparison_directory}"; }
trap cleanup EXIT

package_once() {
  local destination="$1" target_directory="$2"
  RELEASE_TARGET_DIR="${target_directory}" \
    scripts/ci/package-release.sh "${release_tag}" > /dev/null
  scripts/ci/finalize-release.sh
  mkdir -p -- "${destination}"
  # Copy the exact declared asset set. Wildcards could let stale files make a
  # supposedly reproducible build pass without producing the current release.
  # shellcheck source=scripts/ci/release-metadata-lib.sh
  source "${repository_root}/scripts/ci/release-metadata-lib.sh"
  release_metadata_load dist/release.env
  cp -- \
    "dist/${ARCHIVE_NAME}" \
    "dist/${SBOM_NAME}" \
    "dist/${CHECKSUM_NAME}" \
    dist/release.env \
    "${destination}/"
}

printf 'building %s twice from the same tree\n' "${release_tag}"

package_once \
  "${comparison_directory}/first" \
  "${comparison_directory}/target-first"
package_once \
  "${comparison_directory}/second" \
  "${comparison_directory}/target-second"

failures=0

while IFS= read -r first_asset; do
  asset_name="$(basename "${first_asset}")"
  second_asset="${comparison_directory}/second/${asset_name}"

  if [[ ! -f "${second_asset}" ]]; then
    printf 'FAIL %s: the second build did not produce this asset\n' "${asset_name}" >&2
    failures=$((failures + 1))
    continue
  fi

  if ! cmp -s -- "${first_asset}" "${second_asset}"; then
    printf 'FAIL %s: rebuild is not byte-identical\n' "${asset_name}" >&2
    printf '  first:  %s\n' "$(sha256sum < "${first_asset}" | cut -d' ' -f1)" >&2
    printf '  second: %s\n' "$(sha256sum < "${second_asset}" | cut -d' ' -f1)" >&2
    failures=$((failures + 1))
    continue
  fi

  printf 'reproducible %s %s\n' "$(sha256sum < "${first_asset}" | cut -d' ' -f1)" "${asset_name}"
done < <(find "${comparison_directory}/first" -maxdepth 1 -type f | sort)

if [[ "${failures}" -gt 0 ]]; then
  printf '\nrelease reproducibility: %d asset(s) differ between builds\n' "${failures}" >&2
  exit 1
fi

printf 'release reproducibility: every declared asset rebuilt byte-identically\n'
