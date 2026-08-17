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
  local destination="$1"
  scripts/ci/package-release.sh "${release_tag}" > /dev/null
  mkdir -p -- "${destination}"
  cp -- dist/*.tar.gz "${destination}/"
}

printf 'building %s twice from the same tree\n' "${release_tag}"

package_once "${comparison_directory}/first"

# Removing the compiled binary forces the second archive to come from a real
# rebuild rather than from whatever the first run left in the target directory.
rm -rf -- target/release/authority-corpus
package_once "${comparison_directory}/second"

failures=0

while IFS= read -r first_archive; do
  archive_name="$(basename "${first_archive}")"
  second_archive="${comparison_directory}/second/${archive_name}"

  if [[ ! -f "${second_archive}" ]]; then
    printf 'FAIL %s: the second build did not produce this archive\n' "${archive_name}" >&2
    failures=$((failures + 1))
    continue
  fi

  if ! cmp -s -- "${first_archive}" "${second_archive}"; then
    printf 'FAIL %s: rebuild is not byte-identical\n' "${archive_name}" >&2
    printf '  first:  %s\n' "$(sha256sum < "${first_archive}" | cut -d' ' -f1)" >&2
    printf '  second: %s\n' "$(sha256sum < "${second_archive}" | cut -d' ' -f1)" >&2
    failures=$((failures + 1))
    continue
  fi

  printf 'reproducible %s %s\n' "$(sha256sum < "${first_archive}" | cut -d' ' -f1)" "${archive_name}"
done < <(find "${comparison_directory}/first" -type f -name '*.tar.gz' | sort)

if [[ "${failures}" -gt 0 ]]; then
  printf '\nrelease reproducibility: %d archive(s) differ between builds\n' "${failures}" >&2
  exit 1
fi

printf 'release reproducibility: every archive rebuilt byte-identically\n'
