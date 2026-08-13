#!/usr/bin/env bash

# Builds the immutable guest image containing the complete capability runtime.
#
# No executable, repository identifier, or runtime path is supplied through the host-to-guest
# control channel. The only dynamic host input remains the verified identity bundle accepted by
# guest-control-init; the image itself fixes guest-supervisor-init, the isolation launcher, and
# the workload executable.

set -euo pipefail

usage() {
  printf '%s\n' \
    'usage: build-guest-runtime-image.sh --base-rootfs PATH --guest-control-init PATH --guest-supervisor-init PATH --isolation-launcher PATH --agent-workload PATH --repository ID --port PORT --output-rootfs PATH --output-hash PATH' >&2
}

fail() {
  printf 'build-guest-runtime-image: %s\n' "$1" >&2
  exit 2
}

require_absolute_file() {
  local label="$1"
  local path="$2"
  [[ "${path}" == /* ]] || fail "${label} must be absolute: ${path}"
  [[ -f "${path}" && ! -L "${path}" ]] || fail "${label} must be a regular non-symlink file: ${path}"
  [[ -x "${path}" ]] || fail "${label} must be executable: ${path}"
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

require_private_output_directory() {
  local directory="$1"
  local owner mode
  owner="$(stat -c '%u' -- "${directory}")" || fail 'could not determine output directory owner'
  mode="$(stat -c '%a' -- "${directory}")" || fail 'could not determine output directory mode'
  [[ "${owner}" == "$(id -u)" ]] || fail 'output directory must be owned by the invoking user'
  (( (8#${mode} & 8#022) == 0 )) || fail 'output directory must not be group- or world-writable'
}

base_rootfs=''
guest_control_init=''
guest_supervisor_init=''
isolation_launcher=''
agent_workload=''
repository=''
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
    --guest-supervisor-init)
      [[ "$#" -ge 2 ]] || { usage; exit 2; }
      guest_supervisor_init="$2"
      shift 2
      ;;
    --isolation-launcher)
      [[ "$#" -ge 2 ]] || { usage; exit 2; }
      isolation_launcher="$2"
      shift 2
      ;;
    --agent-workload)
      [[ "$#" -ge 2 ]] || { usage; exit 2; }
      agent_workload="$2"
      shift 2
      ;;
    --repository)
      [[ "$#" -ge 2 ]] || { usage; exit 2; }
      repository="$2"
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

[[ -n "${base_rootfs}" && -n "${guest_control_init}" && -n "${guest_supervisor_init}" ]] || {
  usage
  exit 2
}
[[ -n "${isolation_launcher}" && -n "${agent_workload}" && -n "${repository}" ]] || {
  usage
  exit 2
}
[[ "${repository}" =~ ^[A-Za-z0-9._-]{1,128}$ ]] || fail 'repository must be one safe non-empty identifier'
[[ "${port}" =~ ^[0-9]+$ ]] || fail 'port must be decimal'
((port > 0 && port < 4294967295)) || fail 'port must be explicit, non-zero, and non-wildcard'

for input in "${base_rootfs}" "${guest_control_init}" "${guest_supervisor_init}" "${isolation_launcher}" "${agent_workload}"; do
  require_absolute_file 'runtime input' "${input}"
done
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
require_private_output_directory "${output_directory}"
output_rootfs="${output_directory}/${output_rootfs_name}"
output_hash="${output_directory}/${output_hash_name}"
output_verity="${output_rootfs}.verity"
[[ "${output_rootfs}" != "${output_hash}" && "${output_rootfs}" != "${output_verity}" && "${output_hash}" != "${output_verity}" ]] || fail 'rootfs, hash, and verity outputs must differ'
require_output_file_or_absent 'rootfs output' "${output_rootfs}"
require_output_file_or_absent 'hash output' "${output_hash}"
require_output_file_or_absent 'verity output' "${output_verity}"

command -v unsquashfs >/dev/null || fail 'unsquashfs is required'
command -v mksquashfs >/dev/null || fail 'mksquashfs is required'
command -v veritysetup >/dev/null || fail 'veritysetup is required'

staging="$(mktemp -d "${output_directory}/.guest-runtime-image.XXXXXX")"
cleanup() {
  rm -rf -- "${staging}"
}
trap cleanup EXIT

unsquashfs -f -d "${staging}/root" "${base_rootfs}" >/dev/null
install -D -m 0755 "${guest_control_init}" "${staging}/root/usr/local/libexec/guest-control-init"
install -D -m 0755 "${guest_supervisor_init}" "${staging}/root/usr/local/libexec/guest-supervisor-init"
install -D -m 0755 "${isolation_launcher}" "${staging}/root/usr/local/libexec/workload-isolation-launcher"
install -D -m 0755 "${agent_workload}" "${staging}/root/usr/local/libexec/agent-workload"
install -d -m 0755 "${staging}/root/run/guest-supervisor"
install -d -m 0755 "${staging}/root/workspace"
install -d -m 1777 "${staging}/root/tmp"

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
printf 'boot args: console=ttyS0 reboot=k panic=1 pci=off init=/usr/local/libexec/guest-control-init -- --port %s --workload /usr/local/libexec/guest-supervisor-init -- --workspace-device /dev/vdb --runtime-dir /run/guest-supervisor --cgroup-parent /sys/fs/cgroup --isolation-launcher /usr/local/libexec/workload-isolation-launcher --workload /usr/local/libexec/agent-workload --repository %s\n' "${port}" "${repository}"
