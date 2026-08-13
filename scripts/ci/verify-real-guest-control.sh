#!/usr/bin/env bash

# Runs the opt-in Firecracker guest-control test against real KVM, dm-verity, and AF_VSOCK.
#
# This is intentionally a privileged Linux verification job. It builds the static PID 1 from this
# checkout and combines it with the pinned downloaded kernel/rootfs before making any VM. The
# guest workload is a static BusyBox sleep process; it exists only to prove the gate and does not
# receive a host-supplied command or credentials.

set -euo pipefail

repository_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly repository_root
readonly tools_root="${CI_TOOLS_DIR:-${repository_root}/.ci-tools}"
readonly firecracker="${tools_root}/firecracker/v1.16.1/firecracker"
readonly kernel="${tools_root}/guest/v1.12/vmlinux-6.1.128"
readonly base_rootfs="${tools_root}/guest/v1.12/ubuntu-24.04.squashfs"
busybox="$(command -v busybox || true)"
readonly busybox

[[ "$(id -u)" -eq 0 ]] || { printf '%s\n' 'real guest-control verification requires root for dm-verity' >&2; exit 2; }
[[ -c /dev/kvm ]] || { printf '%s\n' 'real guest-control verification requires /dev/kvm' >&2; exit 2; }
[[ -c /dev/vhost-vsock ]] || { printf '%s\n' 'real guest-control verification requires /dev/vhost-vsock' >&2; exit 2; }
command -v veritysetup >/dev/null || { printf '%s\n' 'real guest-control verification requires veritysetup' >&2; exit 2; }
[[ -n "${busybox}" ]] || { printf '%s\n' 'real guest-control verification requires busybox' >&2; exit 2; }

"${repository_root}/scripts/ci/install-firecracker.sh"
"${repository_root}/scripts/ci/install-guest-artifacts.sh"

RUSTFLAGS='-C target-feature=+crt-static' cargo build \
  --manifest-path "${repository_root}/Cargo.toml" \
  -p firecracker-runtime \
  --bin guest-control-init \
  --release \
  --locked

staging="$(mktemp -d)"
mapper_name="guest-control-ci-$$"
cleanup() {
  veritysetup close "${mapper_name}" >/dev/null 2>&1 || true
  rm -rf -- "${staging}"
}
trap cleanup EXIT

"${repository_root}/scripts/ci/build-guest-control-image.sh" \
  --base-rootfs "${base_rootfs}" \
  --guest-control-init "${repository_root}/target/release/guest-control-init" \
  --workload "${busybox}" \
  --port 18080 \
  --output-rootfs "${staging}/guest-control.squashfs" \
  --output-hash "${staging}/guest-control.squashfs.hash"

root_hash="$(awk '/^Root hash:/ {print $3}' "${staging}/guest-control.squashfs.verity")"
[[ "${root_hash}" =~ ^[0-9a-f]{64}$ ]] || { printf '%s\n' 'guest image did not emit one lower-case dm-verity root hash' >&2; exit 2; }
veritysetup open \
  "${staging}/guest-control.squashfs" \
  "${mapper_name}" \
  "${staging}/guest-control.squashfs.hash" \
  "${root_hash}"
veritysetup status "${mapper_name}" | grep -q 'mode:        readonly'

REAL_FIRECRACKER_BIN="${firecracker}" \
REAL_FIRECRACKER_KERNEL="${kernel}" \
REAL_FIRECRACKER_ROOTFS="/dev/mapper/${mapper_name}" \
cargo test \
  --manifest-path "${repository_root}/Cargo.toml" \
  -p firecracker-runtime \
  --test real_guest_control \
  --locked \
  -- \
  --ignored \
  --exact real_firecracker_guest_control_enforces_identity_gate_over_vsock
