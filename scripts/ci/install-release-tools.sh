#!/usr/bin/env bash

set -euo pipefail
umask 077

readonly repository_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly tools_root="${CI_TOOLS_DIR:-${repository_root}/.ci-tools}"
readonly tool_bin="${tools_root}/bin"
readonly downloads="${tools_root}/downloads"

readonly syft_version="1.51.0"
readonly syft_sha256="2a2e837a2c8d59ec9af5472ee22d3b04ee463c4e44476ecf993fd1e5ab6ebc7f"
readonly syft_binary_sha256="5a8b71e94f4607973145f02e27e01d50b9f7c7bc41e38d40b39606ad138b43b5"
readonly syft_archive="${downloads}/syft-${syft_version}-linux-amd64.tar.gz"
readonly syft_url="https://github.com/anchore/syft/releases/download/v${syft_version}/syft_${syft_version}_linux_amd64.tar.gz"

readonly cosign_version="3.1.3"
readonly cosign_sha256="4629c757b7618056f8ddd7e2625ae9fdd94c0372a65049520bc7d9df9efc7f71"
readonly cosign_download="${downloads}/cosign-${cosign_version}-linux-amd64"
readonly cosign_url="https://github.com/sigstore/cosign/releases/download/v${cosign_version}/cosign-linux-amd64"

# shellcheck source=scripts/ci/install-binary-tool-lib.sh
source "${repository_root}/scripts/ci/install-binary-tool-lib.sh"
binary_install_init

binary_fetch_pinned syft "${syft_url}" "${syft_archive}" "${syft_sha256}"
binary_publish_archive_member syft "${syft_archive}" "${syft_sha256}" syft \
  "${syft_binary_sha256}" "${tool_bin}/syft"

binary_fetch_pinned cosign "${cosign_url}" "${cosign_download}" "${cosign_sha256}"
binary_publish_direct cosign "${cosign_download}" "${cosign_sha256}" "${tool_bin}/cosign"

printf '%s\n' "${tool_bin}"
