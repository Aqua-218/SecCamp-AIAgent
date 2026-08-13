#!/usr/bin/env bash

# Installs the pinned Firecracker and jailer binaries used by real-VM verification.
#
# The binaries land in a version-scoped, immutable directory rather than a `latest` path.
# `RuntimeConfig` rejects a mutable artifact path and verifies a pinned SHA-256 digest before
# launch, so a host config must name a path whose contents cannot change under it. This script
# prints the digest of each installed binary for exactly that purpose.

set -euo pipefail

readonly repository_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly tools_root="${CI_TOOLS_DIR:-${repository_root}/.ci-tools}"
readonly downloads="${tools_root}/downloads"

readonly firecracker_version="1.16.1"
readonly firecracker_sha256="382a02a869e4d6d5cb14c40577f9545e8458021ea8b0b2d3fc10ec14d9c242e6"
readonly firecracker_archive="${downloads}/firecracker-v${firecracker_version}-x86_64.tgz"
readonly firecracker_url="https://github.com/firecracker-microvm/firecracker/releases/download/v${firecracker_version}/firecracker-v${firecracker_version}-x86_64.tgz"
readonly install_root="${tools_root}/firecracker/v${firecracker_version}"

if [[ "$(uname -m)" != "x86_64" ]]; then
  printf 'firecracker install supports x86_64 only, found %s\n' "$(uname -m)" >&2
  exit 2
fi

mkdir -p -- "${downloads}"

if [[ ! -x "${install_root}/firecracker" ]] || [[ ! -x "${install_root}/jailer" ]]; then
  curl --fail --location --retry 5 --retry-all-errors --connect-timeout 15 \
    --output "${firecracker_archive}" "${firecracker_url}"
  printf '%s  %s\n' "${firecracker_sha256}" "${firecracker_archive}" | sha256sum --check --strict
  extraction="$(mktemp -d)"
  trap 'rm -rf -- "${extraction}"' EXIT
  tar -xzf "${firecracker_archive}" -C "${extraction}"
  # A fresh directory is installed atomically so a partially written one is never observable.
  staging="${install_root}.staging"
  rm -rf -- "${staging}"
  mkdir -p -- "${staging}"
  install -m 0755 \
    "${extraction}/release-v${firecracker_version}-x86_64/firecracker-v${firecracker_version}-x86_64" \
    "${staging}/firecracker"
  install -m 0755 \
    "${extraction}/release-v${firecracker_version}-x86_64/jailer-v${firecracker_version}-x86_64" \
    "${staging}/jailer"
  rm -rf -- "${install_root}"
  mkdir -p -- "$(dirname -- "${install_root}")"
  mv -- "${staging}" "${install_root}"
fi

"${install_root}/firecracker" --version | head -n 1
sha256sum "${install_root}/firecracker" "${install_root}/jailer"
printf '%s\n' "${install_root}"
