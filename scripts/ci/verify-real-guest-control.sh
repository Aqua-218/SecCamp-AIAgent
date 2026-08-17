#!/usr/bin/env bash

# Runs opt-in Firecracker guest-control and guest-to-host Broker tests over real KVM, dm-verity,
# and AF_VSOCK.
#
# This is intentionally a privileged Linux verification job. It builds the static PID 1 from this
# checkout and combines it with the pinned downloaded kernel/rootfs before making any VM. The
# fixed guest workloads are a static BusyBox sleep process and a static canonical Broker probe;
# neither receives a host-supplied command, credential, or authority body.

set -euo pipefail

repository_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly repository_root
readonly tools_root="${CI_TOOLS_DIR:-${repository_root}/.ci-tools}"
readonly firecracker="${tools_root}/firecracker/v1.16.1/firecracker"
readonly base_rootfs="${tools_root}/guest/v1.12/ubuntu-24.04.squashfs"
busybox="$(command -v busybox || true)"
readonly busybox

[[ "$(id -u)" -eq 0 ]] || { printf '%s\n' 'real guest-control verification requires root for dm-verity' >&2; exit 2; }
[[ -c /dev/kvm ]] || { printf '%s\n' 'real guest-control verification requires /dev/kvm' >&2; exit 2; }
[[ -c /dev/vhost-vsock ]] || { printf '%s\n' 'real guest-control verification requires /dev/vhost-vsock' >&2; exit 2; }
command -v veritysetup >/dev/null || { printf '%s\n' 'real guest-control verification requires veritysetup' >&2; exit 2; }
[[ -n "${busybox}" ]] || { printf '%s\n' 'real guest-control verification requires busybox' >&2; exit 2; }
command -v mkfs.ext4 >/dev/null || { printf '%s\n' 'real guest-control verification requires mkfs.ext4' >&2; exit 2; }
command -v truncate >/dev/null || { printf '%s\n' 'real guest-control verification requires truncate' >&2; exit 2; }

"${repository_root}/scripts/ci/install-firecracker.sh"
"${repository_root}/scripts/ci/install-guest-artifacts.sh"

# The rootfs still comes from the pinned Firecracker artifacts, but the kernel
# does not: no published Firecracker CI kernel carries FUSE or Landlock, and the
# guest session needs both. `build-guest-kernel.sh` explains the choice and
# leaves the result in a version-scoped directory, so this only builds once.
kernel="${REAL_GUEST_KERNEL:-$("${repository_root}/scripts/ci/build-guest-kernel.sh")}"
readonly kernel
[[ "${kernel}" == /* && -f "${kernel}" && ! -L "${kernel}" ]] || {
  printf '%s\n' 'real guest-control verification requires an absolute regular guest kernel image' >&2
  exit 2
}

RUSTFLAGS='-C target-feature=+crt-static' cargo build \
  --manifest-path "${repository_root}/Cargo.toml" \
  -p firecracker-runtime \
  --bin guest-control-init \
  --bin guest-broker-probe \
  --release \
  --locked
cargo build \
  --manifest-path "${repository_root}/Cargo.toml" \
  -p supervisor \
  --bin guest-supervisor-init \
  --release \
  --locked
cargo build \
  --manifest-path "${repository_root}/Cargo.toml" \
  -p runtime-isolation \
  --bin workload-isolation-launcher \
  --release \
  --locked

staging="$(mktemp -d)"
mapper_name=''
cleanup() {
  [[ -z "${mapper_name}" ]] || veritysetup close "${mapper_name}" >/dev/null 2>&1 || true
  rm -rf -- "${staging}"
}
trap cleanup EXIT

run_real_test() {
  local mode="$1"
  local workload="$2"
  local test_name="$3"
  local image_rootfs="${staging}/${mode}.squashfs"
  local image_hash="${image_rootfs}.hash"
  local root_hash=''
  local workload_name='guest-workload'

  if [[ "${mode}" == control ]]; then
    workload_name='sleep'
  fi

  mapper_name="guest-control-ci-$$-${mode}"
  "${repository_root}/scripts/ci/build-guest-control-image.sh" \
    --base-rootfs "${base_rootfs}" \
    --guest-control-init "${repository_root}/target/release/guest-control-init" \
    --workload "${workload}" \
    --workload-name "${workload_name}" \
    --port 18080 \
    --output-rootfs "${image_rootfs}" \
    --output-hash "${image_hash}"
  root_hash="$(awk '/^Root hash:/ {print $3}' "${image_rootfs}.verity")"
  [[ "${root_hash}" =~ ^[0-9a-f]{64}$ ]] || { printf '%s\n' 'guest image did not emit one lower-case dm-verity root hash' >&2; exit 2; }
  veritysetup open "${image_rootfs}" "${mapper_name}" "${image_hash}" "${root_hash}"
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
    --exact "${test_name}"
  veritysetup close "${mapper_name}"
  mapper_name=''
}

run_real_test \
  control \
  "${busybox}" \
  real_firecracker_guest_control_enforces_identity_gate_over_vsock
run_real_test \
  broker \
  "${repository_root}/target/release/guest-broker-probe" \
  real_firecracker_guest_reaches_host_broker_over_vsock

run_runtime_test() {
  local image_rootfs="${staging}/runtime.squashfs"
  local image_hash="${image_rootfs}.hash"
  local workspace_image="${staging}/workspace.ext4"
  local root_hash=''

  mapper_name="guest-runtime-ci-$$"
  truncate -s 64M "${workspace_image}"
  mkfs.ext4 -F -q "${workspace_image}"
  "${repository_root}/scripts/ci/build-guest-runtime-image.sh" \
    --base-rootfs "${base_rootfs}" \
    --guest-control-init "${repository_root}/target/release/guest-control-init" \
    --guest-supervisor-init "${repository_root}/target/release/guest-supervisor-init" \
    --isolation-launcher "${repository_root}/target/release/workload-isolation-launcher" \
    --agent-workload "${repository_root}/target/release/guest-broker-probe" \
    --repository workspace \
    --file-effects read-data,list-directory,write-data \
    --path-prefix / \
    --port 18080 \
    --broker-port 18081 \
    --output-rootfs "${image_rootfs}" \
    --output-hash "${image_hash}"
  root_hash="$(awk '/^Root hash:/ {print $3}' "${image_rootfs}.verity")"
  [[ "${root_hash}" =~ ^[0-9a-f]{64}$ ]] || { printf '%s\n' 'guest runtime image did not emit one lower-case dm-verity root hash' >&2; exit 2; }
  veritysetup open "${image_rootfs}" "${mapper_name}" "${image_hash}" "${root_hash}"
  veritysetup status "${mapper_name}" | grep -q 'mode:        readonly'

  REAL_FIRECRACKER_BIN="${firecracker}" \
  REAL_FIRECRACKER_KERNEL="${kernel}" \
  REAL_FIRECRACKER_ROOTFS="/dev/mapper/${mapper_name}" \
  REAL_FIRECRACKER_WORKSPACE="${workspace_image}" \
  cargo test \
    --manifest-path "${repository_root}/Cargo.toml" \
    -p firecracker-runtime \
    --test real_guest_control \
    --locked \
    -- \
    --ignored \
    --exact real_firecracker_guest_runtime_preserves_the_broker_channel_through_isolation
  veritysetup close "${mapper_name}"
  mapper_name=''
}

run_runtime_test
