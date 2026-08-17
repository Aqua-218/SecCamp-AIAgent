#!/usr/bin/env bash

# Installs the pinned Firecracker and jailer binaries used by real-VM verification.
#
# The binaries land in a version-scoped, immutable directory rather than a `latest` path.
# `RuntimeConfig` rejects a mutable artifact path and verifies a pinned SHA-256 digest before
# launch, so a host config must name a path whose contents cannot change under it. This script
# prints the digest of each installed binary for exactly that purpose.
#
# The GitHub archive digest is an integrity check for the bytes observed by this repository. It is
# not an upstream signature and does not establish provenance for the release build.

set -euo pipefail
umask 077

repository_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly repository_root
readonly configured_tools_root="${CI_TOOLS_DIR:-${repository_root}/.ci-tools}"
readonly tools_root="${configured_tools_root}"
readonly downloads="${tools_root}/downloads"
current_uid="$(id -u)"
readonly current_uid

readonly firecracker_version="1.16.1"
readonly firecracker_sha256="382a02a869e4d6d5cb14c40577f9545e8458021ea8b0b2d3fc10ec14d9c242e6"
readonly firecracker_archive="${downloads}/firecracker-v${firecracker_version}-x86_64.tgz"
readonly firecracker_url="https://github.com/firecracker-microvm/firecracker/releases/download/v${firecracker_version}/firecracker-v${firecracker_version}-x86_64.tgz"
readonly install_root="${tools_root}/firecracker/v${firecracker_version}"
readonly firecracker_member="release-v${firecracker_version}-x86_64/firecracker-v${firecracker_version}-x86_64"
readonly jailer_member="release-v${firecracker_version}-x86_64/jailer-v${firecracker_version}-x86_64"

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
    # A root-owned sticky directory such as /tmp prevents another user from replacing a
    # child entry. It is safe as an ancestor, but never accepted as an install/cache root.
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
  printf 'install-firecracker: %s\n' "$*" >&2
  exit 1
}

validate_install_tree() {
  local root="$1"
  local firecracker_path="${root}/firecracker"
  local jailer_path="${root}/jailer"

  directory_is_safe "${root}" || return 1
  regular_file_is_safe "${firecracker_path}" 755 || return 1
  regular_file_is_safe "${jailer_path}" 755 || return 1

  local entry name
  while IFS= read -r -d '' entry; do
    name="${entry##*/}"
    case "${name}" in
      firecracker|jailer) ;;
      *) return 1 ;;
    esac
  done < <(find -P "${root}" -mindepth 1 -maxdepth 1 -print0) || return 1
}

cache_file_is_safe() {
  local path="$1"
  if is_present "${path}"; then
    regular_file_is_safe "${path}"
  fi
}

archive_cache_is_valid() {
  local path="$1"
  cache_file_is_safe "${path}" || return 1
  [[ -f "${path}" ]] || return 1
  printf '%s  %s\n' "${firecracker_sha256}" "${path}" \
    | sha256sum --check --strict --status
}

download_archive_if_needed() {
  cache_file_is_safe "${firecracker_archive}" || die "archive cache is not a safe regular file: ${firecracker_archive}"

  if archive_cache_is_valid "${firecracker_archive}"; then
    return
  fi

  no_stale_entries "${downloads}" "${firecracker_archive##*/}.download." \
    || die "partial archive download staging exists"

  local temporary_archive
  temporary_archive="$(mktemp -- "${firecracker_archive}.download.XXXXXX")" \
    || die "cannot create a private archive staging file"
  curl --fail --location --retry 5 --retry-all-errors --connect-timeout 15 \
    --output "${temporary_archive}" "${firecracker_url}" \
    || die "failed to download Firecracker archive"
  regular_file_is_safe "${temporary_archive}" \
    || die "downloaded archive staging file is unsafe"
  printf '%s  %s\n' "${firecracker_sha256}" "${temporary_archive}" \
    | sha256sum --check --strict \
    || die "downloaded Firecracker archive digest mismatch"

  # Re-check an existing destination immediately before replacement. A symlink or unsafe
  # destination is never followed or silently replaced.
  cache_file_is_safe "${firecracker_archive}" \
    || die "archive cache destination changed while downloading"
  mv -T -- "${temporary_archive}" "${firecracker_archive}" \
    || die "cannot publish Firecracker archive cache"
  regular_file_is_safe "${firecracker_archive}" \
    || die "published archive cache is unsafe"
}

archive_member_is_exact_regular_file() {
  local archive="$1"
  local member="$2"
  local metadata line_count
  metadata="$(env -u TAR_OPTIONS tar -tvzf "${archive}" -- "${member}")" \
    || return 1
  line_count="$(printf '%s\n' "${metadata}" | awk 'END { print NR }')"
  [[ "${line_count}" == 1 ]] || return 1
  [[ "${metadata:0:1}" == "-" ]]
}

validate_archive_members() {
  local archive="${1:-${firecracker_archive}}"
  archive_member_is_exact_regular_file "${archive}" "${firecracker_member}" || return 1
  archive_member_is_exact_regular_file "${archive}" "${jailer_member}" || return 1
}

extract_archive_member() {
  local archive="$1"
  local member="$2"
  local output="$3"
  is_present "${output}" && return 1
  parent_chain_is_safe "$(dirname -- "${output}")" || return 1

  # Extract only the two exact, previously validated regular members to stdout. No archive
  # pathname is ever materialized, so unrelated traversal, symlink, device, and hardlink
  # members cannot affect the host filesystem.
  env -u TAR_OPTIONS tar --extract --file "${archive}" --to-stdout \
    --occurrence=1 -- "${member}" > "${output}" || return 1
  regular_file_is_safe "${output}"
}

main() {
  [[ "$(uname -m)" == "x86_64" ]] \
    || die "firecracker install supports x86_64 only, found $(uname -m)"

  ensure_directory "${tools_root}" || die "tools root is missing or unsafe: ${tools_root}"
  ensure_directory "${downloads}" || die "download root is missing or unsafe: ${downloads}"
  ensure_directory "$(dirname -- "${install_root}")" \
    || die "install parent is missing or unsafe: $(dirname -- "${install_root}")"

  download_archive_if_needed

  validate_archive_members \
    || die "archive does not contain exactly one regular Firecracker and jailer member"

  local extraction
  extraction="$(mktemp -d -- "${tools_root}/firecracker-extract.XXXXXX")" \
    || die "cannot create private extraction directory"
  if ! directory_is_safe "${extraction}"; then
    die "extraction directory is unsafe"
  fi
  trap 'if [[ -d "${extraction:-}" && ! -L "${extraction:-}" ]]; then rm -rf -- "${extraction}"; fi' EXIT

  extract_archive_member "${firecracker_archive}" "${firecracker_member}" "${extraction}/firecracker" \
    || die "cannot extract Firecracker member"
  extract_archive_member "${firecracker_archive}" "${jailer_member}" "${extraction}/jailer" \
    || die "cannot extract jailer member"

  if is_present "${install_root}"; then
    validate_install_tree "${install_root}" \
      || die "existing Firecracker install tree is unsafe, partial, or has replacement entries"
    cmp -s -- "${extraction}/firecracker" "${install_root}/firecracker" \
      || die "existing Firecracker binary differs; refusing replacement"
    cmp -s -- "${extraction}/jailer" "${install_root}/jailer" \
      || die "existing jailer binary differs; refusing replacement"
  else
    local staging="${install_root}.staging"
    is_present "${staging}" && die "stale install staging tree exists: ${staging}"
    mkdir -m 0755 -- "${staging}" || die "cannot create install staging tree"
    chmod 0755 -- "${staging}" || die "cannot set install staging mode"
    install -m 0755 -- "${extraction}/firecracker" "${staging}/firecracker"
    install -m 0755 -- "${extraction}/jailer" "${staging}/jailer"
    validate_install_tree "${staging}" \
      || die "staged Firecracker install tree is unsafe"
    is_present "${install_root}" && die "install destination appeared during staging"
    mv -T -- "${staging}" "${install_root}" \
      || die "cannot publish Firecracker install tree"
    validate_install_tree "${install_root}" \
      || die "published Firecracker install tree is unsafe"
  fi

  # A final shape check closes the normal path before executing a host binary.
  validate_install_tree "${install_root}" || die "final Firecracker install validation failed"
  "${install_root}/firecracker" --version | head -n 1
  sha256sum "${install_root}/firecracker" "${install_root}/jailer"
  printf '%s\n' "${install_root}"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
