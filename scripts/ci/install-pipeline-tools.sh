#!/usr/bin/env bash

set -euo pipefail
umask 077

readonly repository_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly tools_root="${CI_TOOLS_DIR:-${repository_root}/.ci-tools}"
readonly tool_bin="${tools_root}/bin"
readonly downloads="${tools_root}/downloads"

readonly actionlint_version="1.7.12"
readonly actionlint_sha256="8aca8db96f1b94770f1b0d72b6dddcb1ebb8123cb3712530b08cc387b349a3d8"
readonly actionlint_binary_sha256="c872d6db8c6bf83a8eaa704fc93999f027d55dffbc63b8a6abdccb47df5f4cd4"
readonly actionlint_archive="${downloads}/actionlint-${actionlint_version}-linux-amd64.tar.gz"
readonly actionlint_url="https://github.com/rhysd/actionlint/releases/download/v${actionlint_version}/actionlint_${actionlint_version}_linux_amd64.tar.gz"

readonly shellcheck_version="0.11.0"
readonly shellcheck_sha256="b7af85e41cc99489dcc21d66c6d5f3685138f06d34651e6d34b42ec6d54fe6f6"
readonly shellcheck_binary_sha256="4da528ddb3a4d1b7b24a59d4e16eb2f5fd960f4bd9a3708a15baddbdf1d5a55b"
readonly shellcheck_archive="${downloads}/shellcheck-${shellcheck_version}-linux-x86_64.tar.gz"
readonly shellcheck_url="https://github.com/koalaman/shellcheck/releases/download/v${shellcheck_version}/shellcheck-v${shellcheck_version}.linux.x86_64.tar.gz"

readonly yq_version="4.47.2"
readonly yq_sha256="1bb99e1019e23de33c7e6afc23e93dad72aad6cf2cb03c797f068ea79814ddb0"
readonly yq_download="${downloads}/yq-${yq_version}-linux-amd64"
readonly yq_url="https://github.com/mikefarah/yq/releases/download/v${yq_version}/yq_linux_amd64"

# shellcheck source=scripts/ci/install-binary-tool-lib.sh
source "${repository_root}/scripts/ci/install-binary-tool-lib.sh"
binary_install_init "${tools_root}" "${tool_bin}" "${downloads}"

binary_fetch_pinned actionlint "${actionlint_url}" "${actionlint_archive}" "${actionlint_sha256}"
binary_publish_archive_member actionlint "${actionlint_archive}" "${actionlint_sha256}" \
  actionlint "${actionlint_binary_sha256}" "${tool_bin}/actionlint"

binary_fetch_pinned shellcheck "${shellcheck_url}" "${shellcheck_archive}" "${shellcheck_sha256}"
binary_publish_archive_member shellcheck "${shellcheck_archive}" "${shellcheck_sha256}" \
  "shellcheck-v${shellcheck_version}/shellcheck" "${shellcheck_binary_sha256}" \
  "${tool_bin}/shellcheck"

binary_fetch_pinned yq "${yq_url}" "${yq_download}" "${yq_sha256}"
binary_publish_direct yq "${yq_download}" "${yq_sha256}" "${tool_bin}/yq"

printf '%s\n' "${tool_bin}"
