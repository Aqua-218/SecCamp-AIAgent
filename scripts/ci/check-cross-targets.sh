#!/usr/bin/env bash
#
# Type-checks the workspace against every target the manifest declares.
#
# The crates closest to the kernel reach for libc types directly, and those types
# are not spelled the same everywhere: `statfs::f_type` is signed on glibc and
# unsigned on musl, syscall numbers are per-architecture, and a `c_ulong` is not
# the same width on every host. None of that is visible from a single-target
# build, so the first person to learn about it is whoever tries to build for the
# other target — which, for a static-linkage target, is whoever tries to produce
# the guest binary.
#
# The target list lives in `ci/gates.yml` next to the reason each one is there,
# so adding a target does not mean editing this script.

set -euo pipefail

readonly repository_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly tool_bin="${CI_TOOLS_DIR:-${repository_root}/.ci-tools}/cargo/bin"
readonly pipeline_tool_bin="${CI_TOOLS_DIR:-${repository_root}/.ci-tools}/bin"
export PATH="${tool_bin}:${pipeline_tool_bin}:${PATH}"
cd -- "${repository_root}"

failures=0

fail() {
  printf 'FAIL %s\n' "$1" >&2
  failures=$((failures + 1))
}

mapfile -t cross_targets < <(yq eval '.matrices.cross_targets.values[].triple' ci/gates.yml)

if [[ "${#cross_targets[@]}" -eq 0 ]]; then
  printf 'ci/gates.yml declares no cross targets\n' >&2
  exit 1
fi

for triple in "${cross_targets[@]}"; do
  # Installing here rather than in a setup step keeps the target list in one
  # place: the manifest.
  if ! rustup target add "${triple}" > /dev/null 2>&1; then
    fail "${triple}: the standard library for this target could not be installed"
    continue
  fi

  # `--all-targets` would pull in dev-dependencies that are not expected to
  # cross-compile; the library and binary surface is what has to build.
  if ! cargo check --locked --workspace --all-features --target "${triple}"; then
    fail "${triple}: the workspace does not build for this target"
  fi
done

if [[ "${failures}" -gt 0 ]]; then
  printf '\ncross-target check: %d target(s) failed\n' "${failures}" >&2
  exit 1
fi

printf 'cross-target check: %d target(s) build\n' "${#cross_targets[@]}"
