#!/usr/bin/env bash

# Builds an immutable squashfs + dm-verity pair that boots guest-control-init as PID 1.
#
# The workload is copied into the image under one fixed path. It is never received through the
# host-to-guest control channel; host control can only release that preconfigured executable after
# it has injected the exact regenerated identity bundle.

set -euo pipefail

usage() {
  printf '%s\n' \
    'usage: build-guest-control-image.sh --base-rootfs PATH --guest-control-init PATH --workload PATH --port PORT --output-rootfs PATH --output-hash PATH' >&2
}

fail() {
  printf 'build-guest-control-image: %s\n' "$1" >&2
  exit 2
}

require_absolute_file() {
  local label="$1"
  local path="$2"
  [[ "${path}" == /* ]] || fail "${label} must be absolute: ${path}"
  [[ -f "${path}" && ! -L "${path}" ]] || fail "${label} must be a regular non-symlink file: ${path}"
}

require_absolute_lexical_path() {
  local label="$1"
  local path="$2"
  [[ "${path}" == /* ]] || fail "${label} must be absolute: ${path}"
  case "${path}" in
    /|*'//'|*/./*|*/../*|*/.|*/..)
      fail "${label} must not contain empty, current-directory, or parent-directory components: ${path}"
      ;;
  esac
}

require_output_file_or_absent() {
  local label="$1"
  local path="$2"
  [[ ! -L "${path}" ]] || fail "${label} must not be a symlink: ${path}"
  [[ ! -e "${path}" || -f "${path}" ]] || fail "${label} must be a regular file or absent: ${path}"
}

base_rootfs=''
guest_control_init=''
workload=''
port=''
output_rootfs=''
output_hash=''

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --base-rootfs)
      [[ "$#" -ge 2 ]] || { usage; exit 2; }
      base_rootfs="$2"
      shift 2
      ;;
    --guest-control-init)
      [[ "$#" -ge 2 ]] || { usage; exit 2; }
      guest_control_init="$2"
      shift 2
      ;;
    --workload)
      [[ "$#" -ge 2 ]] || { usage; exit 2; }
      workload="$2"
      shift 2
      ;;
    --port)
      [[ "$#" -ge 2 ]] || { usage; exit 2; }
      port="$2"
      shift 2
      ;;
    --output-rootfs)
      [[ "$#" -ge 2 ]] || { usage; exit 2; }
      output_rootfs="$2"
      shift 2
      ;;
    --output-hash)
      [[ "$#" -ge 2 ]] || { usage; exit 2; }
      output_hash="$2"
      shift 2
      ;;
    *)
      usage
      exit 2
      ;;
  esac
done

[[ -n "${base_rootfs}" && -n "${guest_control_init}" && -n "${workload}" ]] || {
  usage
  exit 2
}
[[ "${port}" =~ ^[0-9]+$ ]] || fail 'port must be decimal'
((port > 0 && port < 4294967295)) || fail 'port must be explicit, non-zero, and non-wildcard'

require_absolute_file 'base rootfs' "${base_rootfs}"
require_absolute_file 'guest-control init' "${guest_control_init}"
require_absolute_file 'workload' "${workload}"
[[ -x "${guest_control_init}" ]] || fail 'guest-control init must be executable'
[[ -x "${workload}" ]] || fail 'workload must be executable'

require_absolute_lexical_path 'rootfs output path' "${output_rootfs}"
require_absolute_lexical_path 'hash output path' "${output_hash}"
output_rootfs_name="$(basename -- "${output_rootfs}")"
output_hash_name="$(basename -- "${output_hash}")"
output_directory="$(dirname -- "${output_rootfs}")"
hash_directory="$(dirname -- "${output_hash}")"
[[ -d "${output_directory}" && ! -L "${output_directory}" ]] || fail 'rootfs output directory must exist and not be a symlink'
[[ -d "${hash_directory}" && ! -L "${hash_directory}" ]] || fail 'hash output directory must exist and not be a symlink'
output_directory="$(cd -P -- "${output_directory}" && pwd)"
hash_directory="$(cd -P -- "${hash_directory}" && pwd)"
[[ "${output_directory}" == "${hash_directory}" ]] || fail 'rootfs and hash outputs must share one directory'
output_rootfs="${output_directory}/${output_rootfs_name}"
output_hash="${output_directory}/${output_hash_name}"
output_verity="${output_rootfs}.verity"
[[ "${output_rootfs}" != "${output_hash}" && "${output_rootfs}" != "${output_verity}" && "${output_hash}" != "${output_verity}" ]] || fail 'rootfs, hash, and verity outputs must differ'
require_output_file_or_absent 'rootfs output' "${output_rootfs}"
require_output_file_or_absent 'hash output' "${output_hash}"
require_output_file_or_absent 'verity output' "${output_verity}"
for input in "${base_rootfs}" "${guest_control_init}" "${workload}"; do
  [[ ! "${output_rootfs}" -ef "${input}" ]] || fail 'rootfs output must not replace an input artifact'
  [[ ! "${output_hash}" -ef "${input}" ]] || fail 'hash output must not replace an input artifact'
  [[ ! "${output_verity}" -ef "${input}" ]] || fail 'verity output must not replace an input artifact'
done

command -v unsquashfs >/dev/null || fail 'unsquashfs is required'
command -v mksquashfs >/dev/null || fail 'mksquashfs is required'
command -v veritysetup >/dev/null || fail 'veritysetup is required'

staging="$(mktemp -d "${output_directory}/.guest-control-image.XXXXXX")"
cleanup() {
  rm -rf -- "${staging}"
}
trap cleanup EXIT

unsquashfs -f -d "${staging}/root" "${base_rootfs}" >/dev/null
install -D -m 0755 "${guest_control_init}" "${staging}/root/usr/local/libexec/guest-control-init"
install -D -m 0755 "${workload}" "${staging}/root/usr/local/libexec/guest-workload"
mksquashfs "${staging}/root" "${staging}/rootfs" -noappend -all-root -comp xz >/dev/null
veritysetup format "${staging}/rootfs" "${staging}/rootfs.hash" >"${staging}/rootfs.verity"

rootfs_temporary="${output_directory}/.$(basename -- "${output_rootfs}").tmp.$$"
hash_temporary="${output_directory}/.$(basename -- "${output_hash}").tmp.$$"
verity_temporary="${output_directory}/.$(basename -- "${output_rootfs}").verity.tmp.$$"
rm -f -- "${rootfs_temporary}" "${hash_temporary}" "${verity_temporary}"
install -m 0444 "${staging}/rootfs" "${rootfs_temporary}"
install -m 0444 "${staging}/rootfs.hash" "${hash_temporary}"
install -m 0444 "${staging}/rootfs.verity" "${verity_temporary}"
mv -f -- "${rootfs_temporary}" "${output_rootfs}"
mv -f -- "${hash_temporary}" "${output_hash}"
mv -f -- "${verity_temporary}" "${output_verity}"

printf 'rootfs SHA-256: '
sha256sum "${output_rootfs}" | awk '{print $1}'
printf 'hash SHA-256: '
sha256sum "${output_hash}" | awk '{print $1}'
grep -E '^Root hash:' "${output_verity}"
printf 'boot args: console=ttyS0 reboot=k panic=1 pci=off init=/usr/local/libexec/guest-control-init -- --port %s --workload /usr/local/libexec/guest-workload\n' "${port}"
