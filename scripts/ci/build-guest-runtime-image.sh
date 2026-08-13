#!/usr/bin/env bash

# Builds the immutable guest image containing the complete capability runtime.
#
# No executable, repository identifier, or runtime path is supplied through the host-to-guest
# control channel. The only dynamic host input remains the verified identity bundle accepted by
# guest-control-init; the image itself fixes guest-supervisor-init, the isolation launcher,
# workload executable, and the guest CapFS authority policy.

set -euo pipefail

usage() {
  printf '%s\n' \
    'usage: build-guest-runtime-image.sh --base-rootfs PATH --guest-control-init PATH --guest-supervisor-init PATH --isolation-launcher PATH --agent-workload PATH --repository ID --file-effects CANONICAL-LIST --path-prefix /|PATH --port PORT --broker-port PORT --output-rootfs PATH --output-hash PATH' >&2
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

require_absolute_regular_file() {
  local label="$1"
  local path="$2"
  [[ "${path}" == /* ]] || fail "${label} must be absolute: ${path}"
  [[ -f "${path}" && ! -L "${path}" ]] || fail "${label} must be a regular non-symlink file: ${path}"
}

install_elf_dependencies() {
  local executable="$1"
  local output=''
  local line=''
  local library=''

  if ! output="$(LC_ALL=C ldd -- "${executable}" 2>&1)"; then
    case "${output}" in
      *'not a dynamic executable'*|*'statically linked'*)
        return 0
        ;;
      *)
        fail "could not resolve ELF dependencies for ${executable}: ${output}"
        ;;
    esac
  fi

  case "${output}" in
    *'not a dynamic executable'*|*'statically linked'*)
      return 0
      ;;
  esac

  while IFS= read -r line; do
    case "${line}" in
      *' => '*)
        library="${line#* => }"
        library="${library%% *}"
        ;;
      [[:space:]]/*)
        library="${line#${line%%[![:space:]]*}}"
        library="${library%% *}"
        ;;
      *)
        continue
        ;;
    esac
    [[ "${library}" == /* ]] || fail "ELF dependency is not an absolute path: ${library}"
    [[ -f "${library}" ]] || fail "ELF dependency is not a regular file: ${library}"
    install -D -m 0755 "${library}" "${staging}/root${library}"
  done <<< "${output}"
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

validate_file_effects() {
  local value="$1"
  local name=''
  local previous=-1
  local current=-1
  local -a names=()

  [[ "${value}" != ,* && "${value}" != *, && "${value}" != *',,'* ]] || fail 'file effects cannot contain empty entries'
  IFS=',' read -r -a names <<< "${value}"
  ((${#names[@]} > 0)) || fail 'file effects cannot be empty'
  for name in "${names[@]}"; do
    case "${name}" in
      read-data) current=0 ;;
      list-directory) current=1 ;;
      write-data) current=2 ;;
      truncate) current=3 ;;
      create-file) current=4 ;;
      create-directory) current=5 ;;
      remove-file) current=6 ;;
      remove-directory) current=7 ;;
      rename) current=8 ;;
      set-metadata) current=9 ;;
      read-link) current=10 ;;
      create-symlink) current=11 ;;
      create-hard-link) current=12 ;;
      *) fail 'file effects must be canonical closed effect names' ;;
    esac
    ((current > previous)) || fail 'file effects must be strictly ordered without duplicates'
    previous=${current}
  done
}

validate_path_prefix() {
  local value="$1"
  local segment=''
  local -a segments=()

  [[ "${value}" == '/' ]] && return
  [[ "${value}" =~ ^[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)*$ ]] || fail 'path prefix must be / or canonical repository-relative segments'
  IFS='/' read -r -a segments <<< "${value}"
  for segment in "${segments[@]}"; do
    [[ "${segment}" != '.' && "${segment}" != '..' ]] || fail 'path prefix cannot contain current or parent components'
  done
}

base_rootfs=''
guest_control_init=''
guest_supervisor_init=''
isolation_launcher=''
agent_workload=''
repository=''
file_effects=''
path_prefix=''
port=''
broker_port=''
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
    --file-effects)
      [[ "$#" -ge 2 ]] || { usage; exit 2; }
      file_effects="$2"
      shift 2
      ;;
    --path-prefix)
      [[ "$#" -ge 2 ]] || { usage; exit 2; }
      path_prefix="$2"
      shift 2
      ;;
    --port)
      [[ "$#" -ge 2 ]] || { usage; exit 2; }
      port="$2"
      shift 2
      ;;
    --broker-port)
      [[ "$#" -ge 2 ]] || { usage; exit 2; }
      broker_port="$2"
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
[[ -n "${isolation_launcher}" && -n "${agent_workload}" && -n "${repository}" && -n "${file_effects}" && -n "${path_prefix}" && -n "${broker_port}" ]] || {
  usage
  exit 2
}
[[ "${repository}" =~ ^[A-Za-z0-9._-]{1,128}$ ]] || fail 'repository must be one safe non-empty identifier'
validate_file_effects "${file_effects}"
validate_path_prefix "${path_prefix}"
[[ "${port}" =~ ^[0-9]+$ ]] || fail 'port must be decimal'
((port > 0 && port < 4294967295)) || fail 'port must be explicit, non-zero, and non-wildcard'
[[ "${broker_port}" =~ ^[0-9]+$ ]] || fail 'broker port must be decimal'
((broker_port > 0 && broker_port < 4294967295)) || fail 'broker port must be explicit, non-zero, and non-wildcard'

require_absolute_regular_file 'base rootfs' "${base_rootfs}"
for input in "${guest_control_init}" "${guest_supervisor_init}" "${isolation_launcher}" "${agent_workload}"; do
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
command -v ldd >/dev/null || fail 'ldd is required to close ELF dependencies into the guest rootfs'

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
for executable in "${guest_control_init}" "${guest_supervisor_init}" "${isolation_launcher}" "${agent_workload}"; do
  install_elf_dependencies "${executable}"
done
install -d -m 0755 "${staging}/root/run/guest-supervisor"
install -d -m 0755 "${staging}/root/.old-root"
install -d -m 0755 "${staging}/root/workspace"
install -d -m 0755 "${staging}/root/sys/fs/cgroup"
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
printf 'boot args: console=ttyS0 reboot=k panic=1 pci=off init=/usr/local/libexec/guest-control-init -- --port %s --workload /usr/local/libexec/guest-supervisor-init -- --workspace-device /dev/vdb --runtime-dir /run/guest-supervisor --cgroup-parent /sys/fs/cgroup --broker-port %s --isolation-launcher /usr/local/libexec/workload-isolation-launcher --workload /usr/local/libexec/agent-workload --repository %s --file-effects %s --path-prefix %s\n' "${port}" "${broker_port}" "${repository}" "${file_effects}" "${path_prefix}"
