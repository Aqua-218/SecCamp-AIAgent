#!/usr/bin/env bash
#
# Produces an SBOM for everything the workspace resolves to, and checks it.
#
# `cargo audit` answers "is any of this known to be vulnerable today" and
# `cargo deny` answers "is any of this licensed or sourced in a way we refuse".
# Neither leaves behind a record of what the answer was about. When an advisory
# lands next month, the question is whether a given version was ever in the tree,
# and that needs an inventory that was captured at the time.
#
# The release already attaches an SBOM to each archive. That one covers the
# archive's contents; this one covers the whole resolved dependency graph,
# including everything that only ever appears at build or test time and would
# therefore never show up in a shipped artifact.

set -euo pipefail

readonly repository_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly pipeline_tool_bin="${CI_TOOLS_DIR:-${repository_root}/.ci-tools}/bin"
export PATH="${pipeline_tool_bin}:${PATH}"
cd -- "${repository_root}"

readonly inventory_directory="reports"
readonly sbom_file="${inventory_directory}/workspace-sbom.spdx.json"

# The resolved graph is large and stable; a collapse to a handful of packages
# means the scanner stopped understanding the lockfile rather than that the
# dependencies went away.
readonly minimum_expected_packages=100

command -v syft > /dev/null || {
  printf 'syft is required; run scripts/ci/install-release-tools.sh\n' >&2
  exit 2
}

mkdir -p -- "${inventory_directory}"

# The lockfile is the authority on what a build resolves to, which is exactly
# the set an advisory will later be asked about.
syft scan "file:Cargo.lock" -o spdx-json > "${sbom_file}"

package_count="$(yq eval -o json '.packages | length' "${sbom_file}")"
sbom_names="$(yq eval -o tsv '.packages[].name' "${sbom_file}")"
readonly sbom_names

failures=0

fail() {
  printf 'FAIL %s\n' "$1" >&2
  failures=$((failures + 1))
}

if [[ "${package_count}" -lt "${minimum_expected_packages}" ]]; then
  fail "the SBOM lists ${package_count} packages, below the ${minimum_expected_packages} expected from this lockfile"
fi

# Every workspace member must appear. A missing one means the scanner silently
# skipped part of the tree and the inventory understates what ships.
while IFS= read -r member; do
  if ! printf '%s\n' "${sbom_names}" | grep -qxF -- "${member}"; then
    fail "${member}: workspace member is absent from the SBOM"
  fi
done < <(
  awk '
    /^members = \[/ { inside = 1; next }
    /^\]/ { inside = 0 }
    inside {
      gsub(/[",]/, "")
      gsub(/^[[:space:]]+|[[:space:]]+$/, "")
      if ($0 != "") { sub(/^crates\//, ""); print }
    }
  ' Cargo.toml | sort
)

# A package without a version cannot be matched against an advisory later, which
# defeats the reason for keeping the inventory.
unversioned="$(yq eval -o json '[.packages[] | select(has("versionInfo") | not)] | length' "${sbom_file}")"
if [[ "${unversioned}" -ne 0 ]]; then
  fail "${unversioned} package(s) in the SBOM carry no version"
fi

if [[ "${failures}" -gt 0 ]]; then
  printf '\nsupply-chain inventory: %d problem(s)\n' "${failures}" >&2
  exit 1
fi

printf 'supply-chain inventory: %s packages recorded in %s\n' "${package_count}" "${sbom_file}"
