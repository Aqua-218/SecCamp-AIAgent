#!/usr/bin/env bash
#
# Builds the guest kernel the composed session actually needs.
#
# The Firecracker CI bucket publishes prebuilt kernels, and this project used
# one. Those kernels cannot run this guest:
#
#   no FUSE      Every guest file operation goes through the CapFS mount, and
#                no published Firecracker CI kernel, on any revision or release
#                line, sets CONFIG_FUSE_FS. The session fails at its first
#                mount.
#   no Landlock  runtime-isolation requires Landlock ABI 3, which first exists
#                in 6.2. The published kernels are 5.10 and 6.1 and do not set
#                CONFIG_SECURITY_LANDLOCK at all, so the isolation transaction
#                cannot even query the ABI.
#
# Building from kernel.org source also improves provenance rather than costing
# it: the source tarball has a published SHA-256, while the prebuilt kernels are
# unsigned binaries from a CI bucket. What this repository trusts becomes a
# version, a digest, a committed configuration, and a committed patch.
#
# The patch is required. `acpi_gbl_default_address_spaces` names PCI config
# space unconditionally while its handler is compiled only when CONFIG_PCI is
# set; the Firecracker configuration disables PCI, so ACPI table loading fails
# and the kernel never finds its root device. The condition is still present in
# 6.12 LTS, which is why the prebuilt kernels carry an out-of-tree fix.

set -euo pipefail

readonly repository_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly tools_root="${CI_TOOLS_DIR:-${repository_root}/.ci-tools}"
readonly downloads="${tools_root}/downloads"

readonly kernel_version="6.12.103"
readonly kernel_archive="linux-${kernel_version}.tar.xz"
readonly kernel_sha256="f143aaade8877ba5616e788b4482576db28481bcf557ef537f4fcc3938fc3176"
readonly kernel_url="https://cdn.kernel.org/pub/linux/kernel/v6.x/${kernel_archive}"

readonly kernel_config="${repository_root}/guest/kernel/linux-${kernel_version}-guest.config"
readonly acpi_patch="${repository_root}/guest/kernel/0001-acpi-skip-pci-config-default-space-without-pci.patch"

build_recipe_digest="$({ sha256sum "${kernel_config}" "${acpi_patch}"; printf '%s\n' "${kernel_version}"; } | sha256sum | awk '{print $1}')"
readonly build_recipe_digest
readonly install_root="${tools_root}/guest-kernel/${kernel_version}/${build_recipe_digest}"
readonly built_kernel="${install_root}/vmlinux-${kernel_version}"

if [[ "$(uname -m)" != "x86_64" ]]; then
  printf 'guest kernel build supports x86_64 only, found %s\n' "$(uname -m)" >&2
  exit 2
fi

for tool in make ld bc bison flex; do
  command -v "${tool}" > /dev/null || {
    printf 'building the guest kernel requires %s\n' "${tool}" >&2
    exit 2
  }
done

# Choose the compiler explicitly instead of taking whatever `gcc` resolves to.
# A developer machine can easily have a language toolchain earlier in PATH than
# the distribution compiler, and the kernel is far more particular about its
# compiler than the rest of this repository is.
compiler="${GUEST_KERNEL_CC:-/usr/bin/gcc}"
if [[ ! -x "${compiler}" ]]; then
  compiler="$(command -v gcc || true)"
fi
readonly compiler
[[ -x "${compiler}" ]] || {
  printf 'building the guest kernel requires gcc; set GUEST_KERNEL_CC to choose one\n' >&2
  exit 2
}

if [[ -f "${built_kernel}" ]]; then
  printf '%s\n' "${built_kernel}"
  exit 0
fi

mkdir -p -- "${downloads}"

if [[ ! -f "${downloads}/${kernel_archive}" ]]; then
  curl --fail --location --retry 5 --retry-all-errors --connect-timeout 15 \
    --output "${downloads}/${kernel_archive}" "${kernel_url}"
fi
printf '%s  %s\n' "${kernel_sha256}" "${downloads}/${kernel_archive}" | sha256sum --check --strict

build_directory="$(mktemp -d)"
readonly build_directory
cleanup() { rm -rf -- "${build_directory}"; }
trap cleanup EXIT

tar -x -f "${downloads}/${kernel_archive}" -C "${build_directory}"
readonly source_tree="${build_directory}/linux-${kernel_version}"

patch --directory "${source_tree}" --strip 1 --forward < "${acpi_patch}"

cp -- "${kernel_config}" "${source_tree}/.config"
make -C "${source_tree}" CC="${compiler}" HOSTCC="${compiler}" olddefconfig > /dev/null

# The three settings this build exists for. A silent config drop would produce a
# kernel that boots and then fails deep inside a session.
for required in CONFIG_FUSE_FS=y CONFIG_SECURITY_LANDLOCK=y CONFIG_ACPI=y; do
  grep -qx -- "${required}" "${source_tree}/.config" || {
    printf 'guest kernel configuration lost %s\n' "${required}" >&2
    exit 1
  }
done
grep -qE '^CONFIG_LSM="([^",]+,)*landlock(,[^"]+)*"$' "${source_tree}/.config" || {
  printf '%s\n' 'guest kernel configuration does not enable Landlock in the boot LSM list' >&2
  exit 1
}

make -C "${source_tree}" CC="${compiler}" HOSTCC="${compiler}" -j"$(nproc)" vmlinux > /dev/null

# The kernel must actually carry FUSE and Landlock, not merely have been asked
# to. The symbol table is the right place to look: the build strips `vmlinux`,
# so searching it for strings would report a correct kernel as broken.
for symbol in fuse_init fuse_fs_type __x64_sys_landlock_add_rule; do
  grep -qE "^[0-9a-f]+ [a-zA-Z] ${symbol}\$" "${source_tree}/System.map" || {
    printf 'built guest kernel has no %s symbol; the feature it belongs to is absent\n' \
      "${symbol}" >&2
    exit 1
  }
done

install -D -m 0444 "${source_tree}/vmlinux" "${built_kernel}"
sha256sum "${built_kernel}" >&2
printf '%s\n' "${built_kernel}"
