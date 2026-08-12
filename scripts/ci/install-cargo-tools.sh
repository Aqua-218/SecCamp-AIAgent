#!/usr/bin/env bash

set -euo pipefail

readonly repository_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly tool_root="${CI_TOOLS_DIR:-${repository_root}/.ci-tools}/cargo"
readonly tool_bin="${tool_root}/bin"

readonly nextest_version="0.9.143"
readonly audit_version="0.22.2"
readonly deny_version="0.20.2"
readonly llvm_cov_version="0.8.7"

mkdir -p -- "${tool_bin}"

install_tool() {
  local binary="$1"
  local crate="$2"
  local version="$3"

  if [[ -x "${tool_bin}/${binary}" ]] \
    && "${tool_bin}/${binary}" "${binary#cargo-}" --version | grep -Fq "${version}"; then
    return
  fi

  cargo install --locked --root "${tool_root}" --version "${version}" "${crate}"
}

if [[ "$#" -eq 0 ]]; then
  printf 'usage: %s <nextest|coverage|security> [...]\n' "$0" >&2
  exit 2
fi

for tool_group in "$@"; do
  case "${tool_group}" in
    nextest)
      install_tool cargo-nextest cargo-nextest "${nextest_version}"
      ;;
    coverage)
      install_tool cargo-llvm-cov cargo-llvm-cov "${llvm_cov_version}"
      ;;
    security)
      install_tool cargo-audit cargo-audit "${audit_version}"
      install_tool cargo-deny cargo-deny "${deny_version}"
      ;;
    *)
      printf 'unknown tool group: %s\n' "${tool_group}" >&2
      exit 2
      ;;
  esac
done

printf '%s\n' "${tool_bin}"
