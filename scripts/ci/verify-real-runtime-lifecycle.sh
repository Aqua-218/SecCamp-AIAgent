#!/usr/bin/env bash

# Runs the production Runtime::launch gate over real dm-verity, the pinned Firecracker jailer,
# cgroup-v2, mount/PID namespaces, Firecracker's seccomp filter, and the real Unix API socket.
#
# The guest image is intentionally a tiny test image assembled locally from the host's pinned
# static BusyBox.  The lifecycle gate only needs Firecracker to accept the configured VM and stay
# alive long enough for the host ownership checks; it does not claim to verify guest CapFS or the
# guest supervisor.  Those are separate real-KVM gates.

set -euo pipefail
# The jailer drops to its configured non-root UID.  The runtime-owned workspace image is created
# by the filesystem adapter before jailer starts, so this gate needs the ordinary traversable
# directory mode that production provisioning gives its dedicated jailer user.
umask 022

repository_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly repository_root
readonly tools_root="${CI_TOOLS_DIR:-${repository_root}/.ci-tools}"
readonly firecracker_version="1.16.1"
readonly firecracker_archive_sha256="382a02a869e4d6d5cb14c40577f9545e8458021ea8b0b2d3fc10ec14d9c242e6"
readonly firecracker="${tools_root}/firecracker/v${firecracker_version}/firecracker"
readonly jailer="${tools_root}/firecracker/v${firecracker_version}/jailer"
readonly archive="${tools_root}/downloads/firecracker-v${firecracker_version}-x86_64.tgz"
readonly kernel="${tools_root}/guest/v1.12/vmlinux-6.1.128"
readonly seccompiler_member="release-v${firecracker_version}-x86_64/seccompiler-bin-v${firecracker_version}-x86_64"
readonly seccomp_json_member="release-v${firecracker_version}-x86_64/seccomp-filter-v${firecracker_version}-x86_64.json"
readonly lifecycle_token="${BASHPID}-$(date +%s%N)"
readonly lifecycle_clone_id="lifecycle-${lifecycle_token}"
readonly lifecycle_mapper_name="runtime-lifecycle-${lifecycle_token}"
readonly lifecycle_cgroup_parent="/sys/fs/cgroup/firecracker-runtime-lifecycle-${lifecycle_token}"
readonly lifecycle_cgroup="${lifecycle_cgroup_parent}/${lifecycle_clone_id}"

[[ "$(id -u)" -eq 0 ]] || {
  printf '%s\n' 'real runtime lifecycle verification requires root for dm-verity, mount, and cgroup-v2' >&2
  exit 2
}
[[ "$(uname -m)" == "x86_64" ]] || {
  printf '%s\n' 'real runtime lifecycle verification supports x86_64 only' >&2
  exit 2
}
[[ -c /dev/kvm ]] || {
  printf '%s\n' 'real runtime lifecycle verification requires /dev/kvm' >&2
  exit 2
}
[[ -c /dev/vhost-vsock ]] || {
  printf '%s\n' 'real runtime lifecycle verification requires /dev/vhost-vsock' >&2
  exit 2
}
[[ "$(stat -fc '%T' /sys/fs/cgroup)" == cgroup2fs ]] || {
  printf '%s\n' 'real runtime lifecycle verification requires a cgroup-v2 hierarchy' >&2
  exit 2
}
for command_name in cargo date mksquashfs mkfs.ext4 veritysetup sha256sum tar; do
  command -v "${command_name}" >/dev/null || {
    printf 'real runtime lifecycle verification requires %s\n' "${command_name}" >&2
    exit 2
  }
done
busybox="$(command -v busybox || true)"
[[ -n "${busybox}" && -f "${busybox}" && ! -L "${busybox}" ]] || {
  printf '%s\n' 'real runtime lifecycle verification requires a static BusyBox binary' >&2
  exit 2
}

"${repository_root}/scripts/ci/install-firecracker.sh" >/dev/null
"${repository_root}/scripts/ci/install-guest-artifacts.sh" >/dev/null

[[ -f "${firecracker}" && ! -L "${firecracker}" ]] || {
  printf '%s\n' "pinned Firecracker binary is unavailable: ${firecracker}" >&2
  exit 2
}
[[ -f "${jailer}" && ! -L "${jailer}" ]] || {
  printf '%s\n' "pinned jailer binary is unavailable: ${jailer}" >&2
  exit 2
}
[[ -f "${kernel}" && ! -L "${kernel}" ]] || {
  printf '%s\n' "pinned guest kernel is unavailable: ${kernel}" >&2
  exit 2
}
[[ -f "${archive}" && ! -L "${archive}" ]] || {
  printf '%s\n' "pinned Firecracker archive is unavailable: ${archive}" >&2
  exit 2
}
printf '%s  %s\n' "${firecracker_archive_sha256}" "${archive}" | sha256sum --check --strict

staging="$(mktemp -d "${repository_root}/.real-runtime-lifecycle.XXXXXX")"
mapper_name="${lifecycle_mapper_name}"
cleanup() {
  if [[ -d "${lifecycle_cgroup}" ]]; then
    if [[ -f "${lifecycle_cgroup}/cgroup.kill" ]]; then
      printf '1\n' >"${lifecycle_cgroup}/cgroup.kill" 2>/dev/null || true
    fi
    for process in $(<"${lifecycle_cgroup}/cgroup.procs"); do
      if [[ "${process}" =~ ^[0-9]+$ ]]; then
        kill -KILL -- "${process}" 2>/dev/null || true
      fi
    done
    for _attempt in {1..50}; do
      [[ ! -s "${lifecycle_cgroup}/cgroup.procs" ]] && break
      sleep 0.1
    done
    rmdir -- "${lifecycle_cgroup}" 2>/dev/null || true
  fi
  if [[ -n "${mapper_name:-}" ]]; then
    veritysetup close "${mapper_name}" >/dev/null 2>&1 || true
  fi
  rmdir -- "${lifecycle_cgroup_parent}" 2>/dev/null || true
  rm -rf -- "${staging}"
}
trap cleanup EXIT

extract_archive_member() {
  local member="$1"
  local output="$2"
  env -u TAR_OPTIONS tar --extract --file "${archive}" --to-stdout --occurrence=1 -- "${member}" >"${output}"
  chmod 0755 -- "${output}"
}

extract_archive_member "${seccompiler_member}" "${staging}/seccompiler"
extract_archive_member "${seccomp_json_member}" "${staging}/seccomp.json"

"${staging}/seccompiler" \
  --target-arch x86_64 \
  --input-file "${staging}/seccomp.json" \
  --output-file "${staging}/seccomp.bin"
[[ -f "${staging}/seccomp.bin" && ! -L "${staging}/seccomp.bin" ]] || {
  printf '%s\n' 'pinned Firecracker seccomp compiler did not produce a filter' >&2
  exit 2
}

# Build an image below MAX_ARTIFACT_BYTES so the production artifact reader can digest it without
# silently widening its bound. BusyBox is static and provides the only init process required for
# this host-side lifecycle gate.
mkdir -p -- "${staging}/root/bin" "${staging}/root/usr/local/libexec"
install -m 0755 -- "${busybox}" "${staging}/root/bin/busybox"
printf '%s\n' '#!/bin/busybox sh' 'exec /bin/busybox sleep 600' >"${staging}/root/usr/local/libexec/guest-control-init"
chmod 0755 -- "${staging}/root/usr/local/libexec/guest-control-init"
mksquashfs "${staging}/root" "${staging}/rootfs.squashfs" -noappend -all-root -comp xz >/dev/null
veritysetup format "${staging}/rootfs.squashfs" "${staging}/rootfs.hash" >"${staging}/rootfs.verity"
root_hash="$(awk '/^Root hash:/ {print $3}' "${staging}/rootfs.verity")"
[[ "${root_hash}" =~ ^[0-9a-f]{64}$ ]] || {
  printf '%s\n' 'minimal lifecycle image did not produce one lower-case dm-verity root hash' >&2
  exit 2
}

REAL_RUNTIME_LIFECYCLE=1 \
REAL_RUNTIME_LIFECYCLE_CLONE_ID="${lifecycle_clone_id}" \
REAL_RUNTIME_LIFECYCLE_MAPPER_NAME="${lifecycle_mapper_name}" \
REAL_RUNTIME_LIFECYCLE_CGROUP_PARENT="${lifecycle_cgroup_parent}" \
REAL_FIRECRACKER_BIN="${firecracker}" \
REAL_FIRECRACKER_JAILER="${jailer}" \
REAL_FIRECRACKER_KERNEL="${kernel}" \
REAL_FIRECRACKER_ROOTFS="${staging}/rootfs.squashfs" \
REAL_FIRECRACKER_VERITY_HASH="${staging}/rootfs.hash" \
REAL_FIRECRACKER_ROOT_HASH="${root_hash}" \
REAL_FIRECRACKER_SECCOMP="${staging}/seccomp.bin" \
REAL_VERITYSETUP="$(command -v veritysetup)" \
REAL_WORKSPACE_FORMATTER="$(realpath -e -- "$(command -v mkfs.ext4)")" \
  cargo test \
    --manifest-path "${repository_root}/Cargo.toml" \
    -p firecracker-runtime \
    --test real_runtime_lifecycle \
    --locked \
    -- \
    --ignored \
    --exact real_runtime_launches_and_cleans_real_jailer_lifecycle
