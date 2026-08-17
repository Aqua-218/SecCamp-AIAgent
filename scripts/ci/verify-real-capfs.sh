#!/usr/bin/env bash

# Runs the Linux CapFS integration suite against the host FUSE kernel device.
#
# The ordinary workspace test keeps FUSE tests portable by skipping them when a
# hosted kernel has no /dev/fuse. This gate is different: it is evidence for
# the real mount boundary, so an unavailable device is an unavailable gate and
# never a successful verification. The test-side CAPFS_REQUIRE_FUSE check is
# kept as a second line of defense against an accidental skip.

set -euo pipefail

repository_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly repository_root

if [[ "$(uname -s)" != Linux ]]; then
  printf '%s\n' 'real CapFS FUSE verification requires a Linux host' >&2
  exit 2
fi
if [[ "$(id -u)" -ne 0 ]]; then
  printf '%s\n' 'real CapFS FUSE verification requires root to own and clean up the mount' >&2
  exit 2
fi
if [[ ! -c /dev/fuse ]]; then
  printf '%s\n' 'real CapFS FUSE verification requires the /dev/fuse character device' >&2
  exit 2
fi
if [[ ! -r /dev/fuse || ! -w /dev/fuse ]]; then
  printf '%s\n' 'real CapFS FUSE verification requires a readable and writable /dev/fuse' >&2
  exit 2
fi
command -v cargo >/dev/null || {
  printf '%s\n' 'real CapFS FUSE verification requires cargo' >&2
  exit 2
}
command -v findmnt >/dev/null || {
  printf '%s\n' 'real CapFS FUSE verification requires findmnt' >&2
  exit 2
}
command -v umount >/dev/null || {
  printf '%s\n' 'real CapFS FUSE verification requires umount' >&2
  exit 2
}

baseline_capfs_mounts=()
while IFS= read -r mountpoint; do
  baseline_capfs_mounts+=("${mountpoint}")
done < <(findmnt -rn -t fuse -o TARGET,SOURCE | awk '$2 == "capfs" { print $1 }')

is_baseline_capfs_mount() {
  local candidate="$1" known
  for known in "${baseline_capfs_mounts[@]}"; do
    [[ "${candidate}" == "${known}" ]] && return 0
  done
  return 1
}

cleanup_new_capfs_mounts() {
  local mountpoint cleanup_failed=0
  while IFS= read -r mountpoint; do
    is_baseline_capfs_mount "${mountpoint}" && continue
    if [[ ! "${mountpoint}" =~ ^/tmp/\.tmp[[:alnum:]]{6}(/nested)?$ ]]; then
      printf 'refusing to clean unexpected residual CapFS mount: %s\n' "${mountpoint}" >&2
      cleanup_failed=1
      continue
    fi
    printf 'cleaning residual CapFS test mount: %s\n' "${mountpoint}" >&2
    if ! umount --lazy -- "${mountpoint}"; then
      printf 'failed to clean residual CapFS test mount: %s\n' "${mountpoint}" >&2
      cleanup_failed=1
    elif ! rmdir -- "${mountpoint}" 2>/dev/null; then
      printf 'residual CapFS mountpoint is not an empty test directory: %s\n' "${mountpoint}" >&2
      cleanup_failed=1
    fi
  done < <(findmnt -rn -t fuse -o TARGET,SOURCE | awk '$2 == "capfs" { print $1 }')
  return "${cleanup_failed}"
}

cleanup_capfs_mounts_on_exit() {
  local status=$?
  trap - EXIT
  if ! cleanup_new_capfs_mounts; then
    status=1
  fi
  exit "${status}"
}
trap cleanup_capfs_mounts_on_exit EXIT

cd -- "${repository_root}"

# Serialize mounts so the gate is deterministic on hosts with a single FUSE
# session queue. The test binary still exercises its explicit write/revoke
# interleaving with a real backing file and a real kernel mount.
CAPFS_REQUIRE_FUSE=1 \
  cargo test \
    --locked \
    --manifest-path "${repository_root}/Cargo.toml" \
    -p capfs \
    --test read_only_fuse \
    -- \
    --test-threads=1 \
    --nocapture

if ! cleanup_new_capfs_mounts; then
  printf '%s\n' 'real CapFS FUSE verification left a mount that could not be cleaned' >&2
  exit 1
fi
trap - EXIT

printf '%s\n' 'real CapFS FUSE verification: kernel mount and revoke regressions passed'
