#!/usr/bin/env bash
#
# Installs the native C toolchains required by the cross-target gate.
#
# The CI images are Debian-family systems. Package names live in ci/gates.yml
# beside their Rust triples, so adding a target cannot update only one platform.

set -euo pipefail

readonly repository_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly pipeline_tool_bin="${CI_TOOLS_DIR:-${repository_root}/.ci-tools}/bin"
export PATH="${pipeline_tool_bin}:${PATH}"
cd -- "${repository_root}"

if ! command -v yq > /dev/null 2>&1; then
  printf 'yq is required; run scripts/ci/install-pipeline-tools.sh first\n' >&2
  exit 1
fi

invalid_package_sets="$(
  yq eval \
    '[.matrices.cross_targets.values[] | select((.debian_packages | type) != "!!seq" or (.debian_packages | length) == 0)] | length' \
    ci/gates.yml
)"
if [[ "${invalid_package_sets}" -ne 0 ]]; then
  printf 'every cross target must declare a non-empty debian_packages list\n' >&2
  exit 1
fi

mapfile -t packages < <(
  yq eval '.matrices.cross_targets.values[].debian_packages[]' ci/gates.yml | sort -u
)
mapfile -t compilers < <(
  yq eval '.matrices.cross_targets.values[].cc' ci/gates.yml | sort -u
)

if [[ "${#packages[@]}" -eq 0 || "${#compilers[@]}" -eq 0 ]]; then
  printf 'ci/gates.yml declares no cross-target packages or compilers\n' >&2
  exit 1
fi

if [[ "$(id -u)" -eq 0 ]]; then
  apt=(env DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=l apt-get)
elif command -v sudo > /dev/null 2>&1; then
  apt=(sudo env DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=l apt-get)
else
  printf 'installing cross toolchains requires root or sudo on a Debian-family host\n' >&2
  exit 1
fi

"${apt[@]}" update
"${apt[@]}" install --yes --no-install-recommends "${packages[@]}"

for compiler in "${compilers[@]}"; do
  if ! command -v "${compiler}" > /dev/null 2>&1; then
    printf 'installed package set did not provide required compiler %s\n' "${compiler}" >&2
    exit 1
  fi

  # A cross GCC can exist without its target libc development headers when apt
  # recommendations are disabled. Native crates such as ring then resolve the
  # host stdint.h and fail later with a misleading missing bits/ header.
  if ! printf '#include <stdint.h>\n' | "${compiler}" -x c -fsyntax-only -; then
    printf 'installed package set did not provide usable target C headers for %s\n' \
      "${compiler}" >&2
    exit 1
  fi
done

printf 'cross toolchains: %d compiler(s) available\n' "${#compilers[@]}"
