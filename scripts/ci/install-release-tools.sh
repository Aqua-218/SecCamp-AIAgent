#!/usr/bin/env bash

set -euo pipefail

readonly repository_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly tools_root="${CI_TOOLS_DIR:-${repository_root}/.ci-tools}"
readonly tool_bin="${tools_root}/bin"
readonly downloads="${tools_root}/downloads"

readonly syft_version="1.51.0"
readonly syft_sha256="2a2e837a2c8d59ec9af5472ee22d3b04ee463c4e44476ecf993fd1e5ab6ebc7f"
readonly syft_archive="${downloads}/syft-${syft_version}-linux-amd64.tar.gz"
readonly syft_url="https://github.com/anchore/syft/releases/download/v${syft_version}/syft_${syft_version}_linux_amd64.tar.gz"

readonly cosign_version="3.1.3"
readonly cosign_sha256="4629c757b7618056f8ddd7e2625ae9fdd94c0372a65049520bc7d9df9efc7f71"
readonly cosign_download="${downloads}/cosign-${cosign_version}-linux-amd64"
readonly cosign_url="https://github.com/sigstore/cosign/releases/download/v${cosign_version}/cosign-linux-amd64"

mkdir -p -- "${tool_bin}" "${downloads}"

if [[ ! -x "${tool_bin}/syft" ]] || ! "${tool_bin}/syft" version | grep -Fq "${syft_version}"; then
  curl --fail --location --retry 5 --retry-all-errors --connect-timeout 15 \
    --output "${syft_archive}" "${syft_url}"
  printf '%s  %s\n' "${syft_sha256}" "${syft_archive}" | sha256sum --check --strict
  tar -xzf "${syft_archive}" -C "${tool_bin}" syft
  chmod 0755 "${tool_bin}/syft"
fi

if [[ ! -x "${tool_bin}/cosign" ]] || ! "${tool_bin}/cosign" version | grep -Fq "v${cosign_version}"; then
  curl --fail --location --retry 5 --retry-all-errors --connect-timeout 15 \
    --output "${cosign_download}" "${cosign_url}"
  printf '%s  %s\n' "${cosign_sha256}" "${cosign_download}" | sha256sum --check --strict
  install -m 0755 "${cosign_download}" "${tool_bin}/cosign"
fi

printf '%s\n' "${tool_bin}"
