#!/usr/bin/env bash

set -euo pipefail

readonly repository_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly tools_root="${CI_TOOLS_DIR:-${repository_root}/.ci-tools}"
readonly elan_home="${tools_root}/elan"
readonly elan_version="4.2.3"
readonly elan_sha256="df0b2b3a439961ffcbb3985214365ffe40f49bc871df04dff268c7d8e21ca8b2"
readonly elan_archive="${tools_root}/downloads/elan-${elan_version}-x86_64-unknown-linux-gnu.tar.gz"
readonly elan_url="https://github.com/leanprover/elan/releases/download/v${elan_version}/elan-x86_64-unknown-linux-gnu.tar.gz"
readonly lean_toolchain="$(tr -d '[:space:]' < "${repository_root}/lean/lean-toolchain")"

mkdir -p -- "${tools_root}/downloads" "${elan_home}"

if [[ ! -x "${elan_home}/bin/elan" ]]; then
  curl --fail --location --retry 5 --retry-all-errors --connect-timeout 15 \
    --output "${elan_archive}" "${elan_url}"
  printf '%s  %s\n' "${elan_sha256}" "${elan_archive}" | sha256sum --check --strict

  readonly extraction_root="$(mktemp -d)"
  tar -xzf "${elan_archive}" -C "${extraction_root}"
  ELAN_HOME="${elan_home}" "${extraction_root}/elan-init" \
    -y --no-modify-path --default-toolchain none
fi

export ELAN_HOME="${elan_home}"
export PATH="${elan_home}/bin:${PATH}"

elan toolchain install "${lean_toolchain}"
printf '%s\n' "${elan_home}/bin"
