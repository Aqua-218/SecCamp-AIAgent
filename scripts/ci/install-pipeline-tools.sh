#!/usr/bin/env bash

set -euo pipefail

readonly repository_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly tools_root="${CI_TOOLS_DIR:-${repository_root}/.ci-tools}"
readonly tool_bin="${tools_root}/bin"
readonly downloads="${tools_root}/downloads"

readonly actionlint_version="1.7.12"
readonly actionlint_sha256="8aca8db96f1b94770f1b0d72b6dddcb1ebb8123cb3712530b08cc387b349a3d8"
readonly actionlint_archive="${downloads}/actionlint-${actionlint_version}-linux-amd64.tar.gz"
readonly actionlint_url="https://github.com/rhysd/actionlint/releases/download/v${actionlint_version}/actionlint_${actionlint_version}_linux_amd64.tar.gz"

readonly shellcheck_version="0.11.0"
readonly shellcheck_sha256="b7af85e41cc99489dcc21d66c6d5f3685138f06d34651e6d34b42ec6d54fe6f6"
readonly shellcheck_archive="${downloads}/shellcheck-${shellcheck_version}-linux-x86_64.tar.gz"
readonly shellcheck_url="https://github.com/koalaman/shellcheck/releases/download/v${shellcheck_version}/shellcheck-v${shellcheck_version}.linux.x86_64.tar.gz"

readonly yq_version="4.47.2"
readonly yq_sha256="1bb99e1019e23de33c7e6afc23e93dad72aad6cf2cb03c797f068ea79814ddb0"
readonly yq_download="${downloads}/yq-${yq_version}-linux-amd64"
readonly yq_url="https://github.com/mikefarah/yq/releases/download/v${yq_version}/yq_linux_amd64"

mkdir -p -- "${tool_bin}" "${downloads}"

if [[ ! -x "${tool_bin}/actionlint" ]] || ! "${tool_bin}/actionlint" -version | grep -Fq "${actionlint_version}"; then
  curl --fail --location --retry 5 --retry-all-errors --connect-timeout 15 \
    --output "${actionlint_archive}" "${actionlint_url}"
  printf '%s  %s\n' "${actionlint_sha256}" "${actionlint_archive}" | sha256sum --check --strict
  tar -xzf "${actionlint_archive}" -C "${tool_bin}" actionlint
  chmod 0755 "${tool_bin}/actionlint"
fi

if [[ ! -x "${tool_bin}/shellcheck" ]] || ! "${tool_bin}/shellcheck" --version | grep -Fq "version: ${shellcheck_version}"; then
  curl --fail --location --retry 5 --retry-all-errors --connect-timeout 15 \
    --output "${shellcheck_archive}" "${shellcheck_url}"
  printf '%s  %s\n' "${shellcheck_sha256}" "${shellcheck_archive}" | sha256sum --check --strict
  readonly shellcheck_extraction="$(mktemp -d)"
  tar -xzf "${shellcheck_archive}" -C "${shellcheck_extraction}"
  install -m 0755 \
    "${shellcheck_extraction}/shellcheck-v${shellcheck_version}/shellcheck" \
    "${tool_bin}/shellcheck"
fi

if [[ ! -x "${tool_bin}/yq" ]] || ! "${tool_bin}/yq" --version | grep -Fq "v${yq_version}"; then
  curl --fail --location --retry 5 --retry-all-errors --connect-timeout 15 \
    --output "${yq_download}" "${yq_url}"
  printf '%s  %s\n' "${yq_sha256}" "${yq_download}" | sha256sum --check --strict
  install -m 0755 "${yq_download}" "${tool_bin}/yq"
fi

printf '%s\n' "${tool_bin}"
