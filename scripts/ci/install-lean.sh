#!/usr/bin/env bash

# Install Lean without ever executing an unverified executable restored from a CI cache. The
# release archive, elan itself, and the normalized contents of the complete Lean toolchain are
# independently pinned. The tree digest includes file bytes, modes, paths, and symlink targets.

set -euo pipefail

readonly repository_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly tools_root="${CI_TOOLS_DIR:-${repository_root}/.ci-tools}"
readonly elan_home="${tools_root}/elan"
readonly tool_bin="${tools_root}/bootstrap-bin"
readonly downloads="${tools_root}/downloads"
readonly elan_version="4.2.3"
readonly elan_archive_sha256="df0b2b3a439961ffcbb3985214365ffe40f49bc871df04dff268c7d8e21ca8b2"
readonly elan_binary_sha256="840179e70803ef373c2ec53342d6a45ea7d022533e4145489fc1278b4f716385"
readonly elan_archive="${downloads}/elan-${elan_version}-x86_64-unknown-linux-gnu.tar.gz"
readonly elan_url="https://github.com/leanprover/elan/releases/download/v${elan_version}/elan-x86_64-unknown-linux-gnu.tar.gz"
readonly lean_toolchain="$(tr -d '[:space:]' < "${repository_root}/lean/lean-toolchain")"
readonly lean_toolchain_directory="${elan_home}/toolchains/leanprover--lean4---v4.16.0"
readonly lean_toolchain_tree_sha256="36e9994285883e24c1874cecfcb39e4bb0b2726ca076902f9416c2487f619cb1"

# shellcheck source=scripts/ci/install-binary-tool-lib.sh
source "${repository_root}/scripts/ci/install-binary-tool-lib.sh"
binary_install_init

[[ "${lean_toolchain}" == "leanprover/lean4:v4.16.0" ]] \
  || binary_install_die "Lean toolchain pin changed without a reviewed tree digest"

binary_fetch_pinned "elan ${elan_version}" "${elan_url}" "${elan_archive}" \
  "${elan_archive_sha256}"
binary_publish_archive_member "elan ${elan_version}" "${elan_archive}" \
  "${elan_archive_sha256}" elan-init "${elan_binary_sha256}" "${tool_bin}/elan-init"

if [[ ! -e "${elan_home}/bin/elan" && ! -L "${elan_home}/bin/elan" ]]; then
  binary_ensure_directory "${elan_home}" || binary_install_die "unsafe ELAN_HOME"
  ELAN_HOME="${elan_home}" "${tool_bin}/elan-init" \
    -y --no-modify-path --default-toolchain none
fi

binary_directory_is_safe "${elan_home}" || binary_install_die "unsafe ELAN_HOME"
binary_directory_is_safe "${elan_home}/bin" || binary_install_die "unsafe elan bin directory"
binary_file_is_safe "${elan_home}/bin/elan" 755 \
  && binary_digest_matches "${elan_home}/bin/elan" "${elan_binary_sha256}" \
  || binary_install_die "cached elan executable is unsafe or unpinned"

lean_tree_digest() {
  local tree="$1"
  [[ -d "${tree}" && ! -L "${tree}" ]] || return 1
  env -u TAR_OPTIONS tar \
    --sort=name \
    --mtime='UTC 1970-01-01' \
    --owner=0 --group=0 --numeric-owner \
    --format=posix --pax-option=delete=atime,delete=ctime \
    -C "${tree}" -cf - . | sha256sum | awk '{print $1}'
}

lean_tree_matches() {
  local actual
  actual="$(lean_tree_digest "${lean_toolchain_directory}")" || return 1
  [[ "${actual}" == "${lean_toolchain_tree_sha256}" ]]
}

export ELAN_HOME="${elan_home}"
if [[ -e "${lean_toolchain_directory}" || -L "${lean_toolchain_directory}" ]]; then
  lean_tree_matches || binary_install_die "cached Lean toolchain is unsafe or corrupt"
else
  "${elan_home}/bin/elan" toolchain install "${lean_toolchain}"
  lean_tree_matches \
    || binary_install_die "installed Lean toolchain does not match the reviewed tree digest"
fi

printf '%s\n' "${elan_home}/bin"
