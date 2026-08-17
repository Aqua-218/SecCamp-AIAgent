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
readonly fuzz_sbom_file="${inventory_directory}/fuzz-sbom.spdx.json"

# The resolved graph is large and stable; a collapse to a handful of packages
# means the scanner stopped understanding the lockfile rather than that the
# dependencies went away.
readonly minimum_expected_packages=100

command -v syft > /dev/null || {
  printf 'syft is required; run scripts/ci/install-release-tools.sh\n' >&2
  exit 2
}

mkdir -p -- "${inventory_directory}"

# The lockfile is the authority on what the primary workspace resolves to. The
# separate fuzz workspace is scanned as a directory so its non-published root
# package is retained alongside the dependencies resolved by its lockfile.
syft scan "file:Cargo.lock" -o spdx-json > "${sbom_file}"
syft scan "dir:fuzz" \
  --source-name ai-agent-fuzz-workspace \
  --source-version 0.0.0 \
  -o spdx-json > "${fuzz_sbom_file}"

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

fuzz_package_count="$(yq eval -o json '.packages | length' "${fuzz_sbom_file}")"
fuzz_sbom_names="$(yq eval -o tsv '.packages[].name' "${fuzz_sbom_file}")"
readonly fuzz_sbom_names
if [[ "${fuzz_package_count}" -lt 20 ]]; then
  fail "the fuzz SBOM lists ${fuzz_package_count} packages, below the 20 expected from fuzz/Cargo.lock"
fi
if ! grep -qxF -- ai-agent-fuzz <<< "${fuzz_sbom_names}"; then
  fail 'ai-agent-fuzz: fuzz workspace root is absent from the fuzz SBOM'
fi
fuzz_unversioned="$(
  yq eval -o json \
    '[.packages[] | select(has("versionInfo") | not) | select(.primaryPackagePurpose != "FILE")] | length' \
    "${fuzz_sbom_file}"
)"
if [[ "${fuzz_unversioned}" -ne 0 ]]; then
  fail "${fuzz_unversioned} fuzz package(s) in the SBOM carry no version"
fi

if [[ "${failures}" -gt 0 ]]; then
  printf '\nsupply-chain inventory: %d problem(s)\n' "${failures}" >&2
  exit 1
fi

printf 'supply-chain inventory: %s workspace and %s fuzz packages recorded\n' \
  "${package_count}" "${fuzz_package_count}"
