#!/usr/bin/env bash

# Installs the exact Cargo tool versions used by CI.
#
# Cargo's registry checksum verification, an exact package version, and each package's committed
# Cargo.lock are the reproducibility boundary available to `cargo install`. They protect bytes
# fetched from the registry, but are not upstream release signatures or independent provenance.

set -euo pipefail
umask 077

repository_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly repository_root
readonly configured_tools_root="${CI_TOOLS_DIR:-${repository_root}/.ci-tools}"
readonly tools_root="${configured_tools_root}"
readonly tool_root="${tools_root}/cargo"
readonly tool_bin="${tool_root}/bin"
current_uid="$(id -u)"
readonly current_uid

readonly nextest_version="0.9.143"
readonly audit_version="0.22.2"
readonly deny_version="0.20.2"
readonly llvm_cov_version="0.8.7"
readonly public_api_version="0.52.0"
readonly mutants_version="27.1.0"
readonly fuzz_version="0.13.2"

is_present() {
  [[ -e "$1" || -L "$1" ]]
}

mode_is_non_writable_by_other_users() {
  local mode="$1"
  [[ "${mode}" =~ ^[0-7]{3,4}$ ]] || return 1
  (( (8#${mode} & 8#022) == 0 ))
}

directory_is_safe() {
  local path="$1"
  [[ -d "${path}" && ! -L "${path}" ]] || return 1

  local owner mode
  owner="$(stat -c '%u' -- "${path}")" || return 1
  mode="$(stat -c '%a' -- "${path}")" || return 1
  [[ "${owner}" == "${current_uid}" ]] || return 1
  mode_is_non_writable_by_other_users "${mode}"
}

regular_file_is_safe() {
  local path="$1"
  local expected_mode="${2:-}"
  [[ -f "${path}" && ! -L "${path}" ]] || return 1

  local owner mode
  owner="$(stat -c '%u' -- "${path}")" || return 1
  mode="$(stat -c '%a' -- "${path}")" || return 1
  [[ "${owner}" == "${current_uid}" ]] || return 1
  mode_is_non_writable_by_other_users "${mode}" || return 1
  [[ -z "${expected_mode}" || "${mode}" == "${expected_mode}" ]]
}

parent_component_is_safe() {
  local path="$1"
  [[ -d "${path}" && ! -L "${path}" ]] || return 1

  local owner mode
  owner="$(stat -c '%u' -- "${path}")" || return 1
  mode="$(stat -c '%a' -- "${path}")" || return 1
  [[ "${owner}" == "${current_uid}" || "${owner}" == 0 ]] || return 1

  if ! mode_is_non_writable_by_other_users "${mode}"; then
    (( owner == 0 && (8#${mode} & 8#1000) != 0 )) || return 1
  fi
}

parent_chain_is_safe() {
  local current="$1"
  case "${current}" in
    ..|../*|*/..|*/../*) return 1 ;;
  esac
  [[ "${current}" == /* ]] || current="${PWD}/${current}"
  while [[ ! -e "${current}" && ! -L "${current}" ]]; do
    [[ "${current}" != "/" ]] || break
    current="$(dirname -- "${current}")"
  done

  while [[ "${current}" != "/" ]]; do
    parent_component_is_safe "${current}" || return 1
    current="$(dirname -- "${current}")"
  done
}

ensure_directory() {
  local path="$1"
  parent_chain_is_safe "${path}" || return 1
  if is_present "${path}"; then
    directory_is_safe "${path}" || return 1
  else
    mkdir -m 0755 -- "${path}" || return 1
    chmod 0755 -- "${path}" || return 1
    directory_is_safe "${path}"
  fi
}

no_stale_entries() {
  local directory="$1"
  local prefix="$2"
  local -a matches=()
  shopt -s nullglob
  matches=("${directory}/${prefix}"*)
  shopt -u nullglob
  ((${#matches[@]} == 0))
}

die() {
  printf 'install-cargo-tools: %s\n' "$*" >&2
  exit 1
}

tool_matches_version_from_path() {
  local path="$1"
  local binary="$2"
  local version="$3"
  local output first_line version_regex
  output="$("${path}" "${binary#cargo-}" --version 2>&1)" || return 1
  first_line="${output%%$'\n'*}"
  version_regex="${version//./\\.}"
  [[ "${first_line}" == "${binary}"* ]] || return 1
  [[ "${first_line}" =~ (^|[^0-9])${version_regex}([^0-9]|$) ]]
}

tool_matches_version() {
  local binary="$1"
  local version="$2"
  local path="${tool_bin}/${binary}"
  regular_file_is_safe "${path}" 755 || return 1
  tool_matches_version_from_path "${path}" "${binary}" "${version}"
}

install_tool() {
  local binary="$1"
  local crate="$2"
  local version="$3"
  local target="${tool_bin}/${binary}"

  if is_present "${target}"; then
    regular_file_is_safe "${target}" 755 \
      || die "existing Cargo tool is not a safe regular file: ${target}"
    if tool_matches_version "${binary}" "${version}"; then
      return
    fi
  fi

  no_stale_entries "${tool_root}" ".staging-${binary}." \
    || die "partial Cargo staging exists for ${binary}"
  no_stale_entries "${tool_bin}" "${binary}.new." \
    || die "partial Cargo replacement exists for ${binary}"

  local staging_root staging_binary replacement
  staging_root="$(mktemp -d -- "${tool_root}/.staging-${binary}.XXXXXX")" \
    || die "cannot create private Cargo staging root for ${binary}"
  directory_is_safe "${staging_root}" \
    || die "Cargo staging root is unsafe for ${binary}"
  staging_binary="${staging_root}/bin/${binary}"

  if ! cargo install --locked --registry crates-io --root "${staging_root}" \
    --version "${version}" "${crate}"; then
    rm -rf -- "${staging_root}"
    die "cargo install failed for ${crate} ${version}"
  fi
  # Cargo honors this installer's private umask and commonly emits mode 0700.
  # The staged file only needs to be owner-controlled here; the atomic
  # replacement below deliberately normalizes the published mode to 0755.
  regular_file_is_safe "${staging_binary}" \
    || { rm -rf -- "${staging_root}"; die "Cargo produced an unsafe binary for ${binary}"; }
  tool_matches_version_from_path "${staging_binary}" "${binary}" "${version}" \
    || { rm -rf -- "${staging_root}"; die "Cargo tool reported an unexpected version for ${binary}"; }

  replacement="$(mktemp -- "${target}.new.XXXXXX")" \
    || { rm -rf -- "${staging_root}"; die "cannot create atomic replacement for ${binary}"; }
  install -m 0755 -- "${staging_binary}" "${replacement}"
  regular_file_is_safe "${replacement}" 755 \
    || { rm -f -- "${replacement}"; rm -rf -- "${staging_root}"; die "Cargo replacement is unsafe for ${binary}"; }

  # A symlink or unsafe destination is never silently replaced. A regular binary with an old
  # pinned version is intentionally replaced only after the new staged binary passed validation.
  if is_present "${target}"; then
    regular_file_is_safe "${target}" 755 \
      || { rm -f -- "${replacement}"; rm -rf -- "${staging_root}"; die "Cargo tool destination changed for ${binary}"; }
  fi
  mv -T -- "${replacement}" "${target}" \
    || { rm -f -- "${replacement}"; rm -rf -- "${staging_root}"; die "cannot publish Cargo tool ${binary}"; }
  regular_file_is_safe "${target}" 755 \
    || { rm -rf -- "${staging_root}"; die "published Cargo tool is unsafe: ${binary}"; }
  tool_matches_version "${binary}" "${version}" \
    || { rm -rf -- "${staging_root}"; die "published Cargo tool version mismatch: ${binary}"; }
  rm -rf -- "${staging_root}"
}

main() {
  ensure_directory "${tools_root}" || die "tools root is missing or unsafe: ${tools_root}"
  ensure_directory "${tool_root}" || die "Cargo tool root is missing or unsafe: ${tool_root}"
  ensure_directory "${tool_bin}" || die "Cargo tool bin root is missing or unsafe: ${tool_bin}"

  if [[ "$#" -eq 0 ]]; then
    printf 'usage: %s <nextest|coverage|security|public-api|miri|sanitizers|mutation|fuzz> [...]\n' "$0" >&2
    exit 2
  fi

  local tool_group
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
      public-api)
        "${repository_root}/scripts/ci/install-nightly-toolchain.sh" > /dev/null
        install_tool cargo-public-api cargo-public-api "${public_api_version}"
        ;;
      miri|sanitizers)
        "${repository_root}/scripts/ci/install-nightly-toolchain.sh" > /dev/null
        ;;
      mutation)
        install_tool cargo-mutants cargo-mutants "${mutants_version}"
        ;;
      fuzz)
        "${repository_root}/scripts/ci/install-nightly-toolchain.sh" > /dev/null
        install_tool cargo-fuzz cargo-fuzz "${fuzz_version}"
        ;;
      *)
        printf 'unknown tool group: %s\n' "${tool_group}" >&2
        exit 2
        ;;
    esac
  done

  printf '%s\n' "${tool_bin}"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
