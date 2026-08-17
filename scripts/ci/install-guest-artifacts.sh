#!/usr/bin/env bash

# Installs the pinned guest kernel and read-only rootfs used by real-VM verification, and formats
# the dm-verity hash device that `RuntimeConfig` requires alongside the rootfs.
#
# The upstream bucket publishes no signature for these artifacts, so the digests below are the ones
# this repository observed and accepted. They pin the bytes against silent replacement from here
# on; they are not evidence that the upstream build is trustworthy or upstream provenance.
#
# Everything lands in a version-scoped, immutable directory. `RuntimeConfig` rejects a mutable
# artifact path and verifies a pinned SHA-256 before launch, so a host config must name a path
# whose contents cannot change under it. The digests and the verity root hash are printed for
# exactly that purpose.

set -euo pipefail
umask 077

repository_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly repository_root
readonly configured_tools_root="${CI_TOOLS_DIR:-${repository_root}/.ci-tools}"
readonly tools_root="${configured_tools_root}"
readonly downloads="${tools_root}/downloads"
current_uid="$(id -u)"
readonly current_uid

readonly bucket="https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/v1.12/x86_64"
readonly guest_revision="v1.12"

readonly kernel_name="vmlinux-6.1.128"
readonly kernel_sha256="27a8310b9a727517e9eb02044524b6ceb77de5728e3491b6974d5c846227ecc8"

readonly rootfs_name="ubuntu-24.04.squashfs"
readonly rootfs_sha256="88821a26b5a38c92b84a064d452167d7f80f9e17cf4441d1ebbae7569e340aee"

readonly install_root="${tools_root}/guest/${guest_revision}"

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
    # A root-owned sticky directory such as /tmp is acceptable only as an ancestor.
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
  printf 'install-guest-artifacts: %s\n' "$*" >&2
  exit 1
}

validate_install_tree() {
  local root="$1"
  local entry name

  directory_is_safe "${root}" || return 1
  regular_file_is_safe "${root}/${kernel_name}" 444 || return 1
  regular_file_is_safe "${root}/${rootfs_name}" 444 || return 1
  regular_file_is_safe "${root}/${rootfs_name}.hash" 444 || return 1
  regular_file_is_safe "${root}/${rootfs_name}.verity" 444 || return 1

  while IFS= read -r -d '' entry; do
    name="${entry##*/}"
    case "${name}" in
      "${kernel_name}"|"${rootfs_name}"|"${rootfs_name}.hash"|"${rootfs_name}.verity") ;;
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

pinned_cache_is_valid() {
  local path="$1"
  local expected="$2"
  cache_file_is_safe "${path}" || return 1
  [[ -f "${path}" ]] || return 1
  printf '%s  %s\n' "${expected}" "${path}" \
    | sha256sum --check --strict --status
}

fetch_pinned() {
  local name="$1"
  local expected="$2"
  local target="${downloads}/${name}"

  cache_file_is_safe "${target}" \
    || die "download cache is not a safe regular file: ${target}"
  if pinned_cache_is_valid "${target}" "${expected}"; then
    return
  fi

  no_stale_entries "${downloads}" "${target##*/}.download." \
    || die "partial ${name} download staging exists"

  local temporary
  temporary="$(mktemp -- "${target}.download.XXXXXX")" \
    || die "cannot create a private download staging file for ${name}"
  curl --fail --location --retry 5 --retry-all-errors --connect-timeout 15 \
    --output "${temporary}" "${bucket}/${name}" \
    || die "failed to download ${name}"
  regular_file_is_safe "${temporary}" \
    || die "downloaded ${name} staging file is unsafe"
  printf '%s  %s\n' "${expected}" "${temporary}" \
    | sha256sum --check --strict \
    || die "downloaded ${name} digest mismatch"

  cache_file_is_safe "${target}" \
    || die "download cache destination changed while downloading ${name}"
  mv -T -- "${temporary}" "${target}" \
    || die "cannot publish ${name} download cache"
  regular_file_is_safe "${target}" \
    || die "published ${name} download cache is unsafe"
}

installed_artifacts_are_valid() {
  validate_install_tree "${install_root}" || return 1

  local root_hash
  printf '%s  %s\n' "${kernel_sha256}" "${install_root}/${kernel_name}" \
    | sha256sum --check --strict --status \
    || return 1
  printf '%s  %s\n' "${rootfs_sha256}" "${install_root}/${rootfs_name}" \
    | sha256sum --check --strict --status \
    || return 1
  root_hash="$(awk '/^Root hash:/ { print $3; exit }' \
    "${install_root}/${rootfs_name}.verity")" || return 1
  [[ "${root_hash}" =~ ^[0-9a-f]{64}$ ]] || return 1
  veritysetup verify \
    "${install_root}/${rootfs_name}" \
    "${install_root}/${rootfs_name}.hash" \
    "${root_hash}" > /dev/null
}

main() {
  [[ "$(uname -m)" == "x86_64" ]] \
    || die "guest artifact install supports x86_64 only, found $(uname -m)"
  command -v veritysetup > /dev/null \
    || die 'veritysetup is required to format the rootfs hash device'

  ensure_directory "${tools_root}" || die "tools root is missing or unsafe: ${tools_root}"
  ensure_directory "${downloads}" || die "download root is missing or unsafe: ${downloads}"
  ensure_directory "$(dirname -- "${install_root}")" \
    || die "install parent is missing or unsafe: $(dirname -- "${install_root}")"

  if is_present "${install_root}"; then
    validate_install_tree "${install_root}" \
      || die "existing guest install tree is unsafe, partial, or has replacement entries"
    installed_artifacts_are_valid \
      || die "existing guest artifacts failed digest or dm-verity verification; refusing replacement"
  else
    fetch_pinned "${kernel_name}" "${kernel_sha256}"
    fetch_pinned "${rootfs_name}" "${rootfs_sha256}"

    local staging="${install_root}.staging"
    is_present "${staging}" && die "stale install staging tree exists: ${staging}"
    mkdir -m 0755 -- "${staging}" || die "cannot create guest install staging tree"
    chmod 0755 -- "${staging}" || die "cannot set guest install staging mode"
    install -m 0444 "${downloads}/${kernel_name}" "${staging}/${kernel_name}"
    install -m 0444 "${downloads}/${rootfs_name}" "${staging}/${rootfs_name}"
    # The hash device is derived here rather than downloaded: it must match these exact rootfs bytes,
    # and the root hash it prints is what a host config pins.
    veritysetup format "${staging}/${rootfs_name}" "${staging}/${rootfs_name}.hash" \
      > "${staging}/${rootfs_name}.verity" \
      || die 'veritysetup failed to format the rootfs hash device'
    chmod 0444 "${staging}/${rootfs_name}.hash" "${staging}/${rootfs_name}.verity"
    validate_install_tree "${staging}" || die "staged guest install tree is unsafe"
    is_present "${install_root}" && die 'install destination appeared during staging'
    mv -T -- "${staging}" "${install_root}" \
      || die 'cannot publish guest install tree'
  fi

  installed_artifacts_are_valid || die 'installed guest artifacts failed final validation'
  sha256sum \
    "${install_root}/${kernel_name}" \
    "${install_root}/${rootfs_name}" \
    "${install_root}/${rootfs_name}.hash"
  grep -E '^Root hash:' "${install_root}/${rootfs_name}.verity"
  printf '%s\n' "${install_root}"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
