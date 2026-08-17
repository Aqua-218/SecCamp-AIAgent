#!/usr/bin/env bash

# Shared fail-closed boundary for pinned prebuilt CI tools. Callers must provide both the release
# object digest and the digest of the exact executable they publish. Cached bytes are never run
# until ownership, mode, type, and digest have been checked.

binary_install_die() {
  printf 'install-binary-tool: %s\n' "$*" >&2
  return 1
}

binary_mode_is_safe() {
  local mode="$1"
  [[ "${mode}" =~ ^[0-7]{3,4}$ ]] && (( (8#${mode} & 8#022) == 0 ))
}

binary_directory_is_safe() {
  local path="$1" owner mode
  [[ -d "${path}" && ! -L "${path}" ]] || return 1
  owner="$(stat -c '%u' -- "${path}")" || return 1
  mode="$(stat -c '%a' -- "${path}")" || return 1
  [[ "${owner}" == "${binary_install_uid}" ]] && binary_mode_is_safe "${mode}"
}

binary_file_is_safe() {
  local path="$1" expected_mode="${2:-}" owner mode
  [[ -f "${path}" && ! -L "${path}" ]] || return 1
  owner="$(stat -c '%u' -- "${path}")" || return 1
  mode="$(stat -c '%a' -- "${path}")" || return 1
  [[ "${owner}" == "${binary_install_uid}" ]] || return 1
  binary_mode_is_safe "${mode}" || return 1
  [[ -z "${expected_mode}" || "${mode}" == "${expected_mode}" ]]
}

binary_digest_matches() {
  local path="$1" expected="$2" actual
  actual="$(sha256sum -- "${path}")" || return 1
  [[ "${actual%% *}" == "${expected}" ]]
}

binary_ensure_directory() {
  local path="$1"
  if [[ -e "${path}" || -L "${path}" ]]; then
    binary_directory_is_safe "${path}"
  else
    mkdir -m 0755 -- "${path}" && binary_directory_is_safe "${path}"
  fi
}

binary_install_init() {
  binary_install_uid="$(id -u)"
  readonly binary_install_uid
  umask 077
  binary_ensure_directory "${tools_root}" \
    || binary_install_die "unsafe tools root: ${tools_root}"
  binary_ensure_directory "${tool_bin}" \
    || binary_install_die "unsafe tool bin: ${tool_bin}"
  binary_ensure_directory "${downloads}" \
    || binary_install_die "unsafe download cache: ${downloads}"
}

binary_fetch_pinned() {
  local label="$1" url="$2" destination="$3" digest="$4" partial
  if [[ -e "${destination}" || -L "${destination}" ]]; then
    binary_file_is_safe "${destination}" \
      && binary_digest_matches "${destination}" "${digest}" \
      || binary_install_die "unsafe or corrupt cached ${label}: ${destination}"
    return
  fi
  partial="$(mktemp -- "${destination}.download.XXXXXX")" \
    || binary_install_die "cannot create ${label} download staging"
  if ! curl --fail --location --retry 5 --retry-all-errors --connect-timeout 15 \
    --output "${partial}" "${url}"; then
    rm -f -- "${partial}"
    binary_install_die "cannot download ${label}"
  fi
  binary_file_is_safe "${partial}" \
    && binary_digest_matches "${partial}" "${digest}" \
    || { rm -f -- "${partial}"; binary_install_die "${label} release digest mismatch"; }
  chmod 0644 -- "${partial}"
  mv -T -- "${partial}" "${destination}"
}

binary_publish_direct() {
  local label="$1" source="$2" source_digest="$3" target="$4"
  binary_file_is_safe "${source}" && binary_digest_matches "${source}" "${source_digest}" \
    || binary_install_die "unsafe ${label} source"
  binary_publish_file "${label}" "${source}" "${source_digest}" "${target}"
}

binary_publish_archive_member() {
  local label="$1" archive="$2" archive_digest="$3" member="$4" member_digest="$5" target="$6"
  local listing replacement
  binary_file_is_safe "${archive}" && binary_digest_matches "${archive}" "${archive_digest}" \
    || binary_install_die "unsafe ${label} archive"
  listing="$(env -u TAR_OPTIONS tar -tvzf "${archive}" -- "${member}")" \
    || binary_install_die "cannot inspect ${label} archive member"
  [[ "$(wc -l <<< "${listing}")" -eq 1 && "${listing:0:1}" == '-' ]] \
    || binary_install_die "${label} archive member is absent, duplicated, or not regular"
  replacement="$(mktemp -- "${target}.new.XXXXXX")" \
    || binary_install_die "cannot stage ${label}"
  if ! env -u TAR_OPTIONS tar -xOzf "${archive}" -- "${member}" > "${replacement}"; then
    rm -f -- "${replacement}"
    binary_install_die "cannot extract exact ${label} member"
  fi
  chmod 0755 -- "${replacement}"
  binary_file_is_safe "${replacement}" 755 \
    && binary_digest_matches "${replacement}" "${member_digest}" \
    || { rm -f -- "${replacement}"; binary_install_die "${label} executable digest mismatch"; }
  binary_publish_file "${label}" "${replacement}" "${member_digest}" "${target}"
  rm -f -- "${replacement}"
}

binary_publish_file() {
  local label="$1" source="$2" digest="$3" target="$4" replacement
  if [[ -e "${target}" || -L "${target}" ]]; then
    binary_file_is_safe "${target}" 755 && binary_digest_matches "${target}" "${digest}" \
      || binary_install_die "unsafe or unpinned cached ${label}: ${target}"
    return
  fi
  replacement="$(mktemp -- "${target}.new.XXXXXX")" \
    || binary_install_die "cannot create ${label} replacement"
  install -m 0755 -- "${source}" "${replacement}"
  binary_file_is_safe "${replacement}" 755 && binary_digest_matches "${replacement}" "${digest}" \
    || { rm -f -- "${replacement}"; binary_install_die "staged ${label} changed"; }
  mv -T -- "${replacement}" "${target}"
}
