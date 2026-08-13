#!/usr/bin/env bash

# Installs the pinned guest kernel and read-only rootfs used by real-VM verification, and formats
# the dm-verity hash device that `RuntimeConfig` requires alongside the rootfs.
#
# The upstream bucket publishes no signature for these artifacts, so the digests below are the ones
# this repository observed and accepted. They pin the bytes against silent replacement from here
# on; they are not evidence that the upstream build is trustworthy.
#
# Everything lands in a version-scoped, immutable directory. `RuntimeConfig` rejects a mutable
# artifact path and verifies a pinned SHA-256 before launch, so a host config must name a path
# whose contents cannot change under it. The digests and the verity root hash are printed for
# exactly that purpose.

set -euo pipefail

readonly repository_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly tools_root="${CI_TOOLS_DIR:-${repository_root}/.ci-tools}"
readonly downloads="${tools_root}/downloads"

readonly bucket="https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/v1.12/x86_64"
readonly guest_revision="v1.12"

readonly kernel_name="vmlinux-6.1.128"
readonly kernel_sha256="27a8310b9a727517e9eb02044524b6ceb77de5728e3491b6974d5c846227ecc8"

readonly rootfs_name="ubuntu-24.04.squashfs"
readonly rootfs_sha256="88821a26b5a38c92b84a064d452167d7f80f9e17cf4441d1ebbae7569e340aee"

readonly install_root="${tools_root}/guest/${guest_revision}"

if [[ "$(uname -m)" != "x86_64" ]]; then
  printf 'guest artifact install supports x86_64 only, found %s\n' "$(uname -m)" >&2
  exit 2
fi

if ! command -v veritysetup > /dev/null; then
  printf 'veritysetup is required to format the rootfs hash device\n' >&2
  exit 2
fi

mkdir -p -- "${downloads}"

fetch_pinned() {
  local name="$1"
  local expected="$2"
  local target="${downloads}/${name}"
  if [[ ! -f "${target}" ]]; then
    curl --fail --location --retry 5 --retry-all-errors --connect-timeout 15 \
      --output "${target}" "${bucket}/${name}"
  fi
  printf '%s  %s\n' "${expected}" "${target}" | sha256sum --check --strict
}

if [[ ! -f "${install_root}/${kernel_name}" ]] \
  || [[ ! -f "${install_root}/${rootfs_name}" ]] \
  || [[ ! -f "${install_root}/${rootfs_name}.hash" ]]; then
  fetch_pinned "${kernel_name}" "${kernel_sha256}"
  fetch_pinned "${rootfs_name}" "${rootfs_sha256}"

  # A fresh directory is installed atomically so a partially written one is never observable.
  staging="${install_root}.staging"
  rm -rf -- "${staging}"
  mkdir -p -- "${staging}"
  install -m 0444 "${downloads}/${kernel_name}" "${staging}/${kernel_name}"
  install -m 0444 "${downloads}/${rootfs_name}" "${staging}/${rootfs_name}"
  # The hash device is derived here rather than downloaded: it must match these exact rootfs bytes,
  # and the root hash it prints is what a host config pins.
  veritysetup format "${staging}/${rootfs_name}" "${staging}/${rootfs_name}.hash" \
    > "${staging}/${rootfs_name}.verity"
  chmod 0444 "${staging}/${rootfs_name}.hash" "${staging}/${rootfs_name}.verity"
  rm -rf -- "${install_root}"
  mkdir -p -- "$(dirname -- "${install_root}")"
  mv -- "${staging}" "${install_root}"
fi

sha256sum \
  "${install_root}/${kernel_name}" \
  "${install_root}/${rootfs_name}" \
  "${install_root}/${rootfs_name}.hash"
grep -E '^Root hash:' "${install_root}/${rootfs_name}.verity"
printf '%s\n' "${install_root}"
