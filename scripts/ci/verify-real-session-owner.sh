#!/usr/bin/env bash

# Runs the complete production SessionOwner lifecycle against real KVM, the real Firecracker
# jailer/runtime, a real guest supervisor/CapFS image, and the production durable Broker.  The
# egress adapters are intentionally closed: this gate proves lifecycle ownership and readiness,
# not an external provider call.

set -euo pipefail
umask 022

repository_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly repository_root
readonly tools_root="${CI_TOOLS_DIR:-${repository_root}/.ci-tools}"
readonly firecracker_version="${FIRECRACKER_VERSION:-1.16.1}"
readonly firecracker="${tools_root}/firecracker/v${firecracker_version}/firecracker"
readonly jailer="${tools_root}/firecracker/v${firecracker_version}/jailer"
readonly archive="${tools_root}/downloads/firecracker-v${firecracker_version}-x86_64.tgz"
readonly seccompiler_member="release-v${firecracker_version}-x86_64/seccompiler-bin-v${firecracker_version}-x86_64"
readonly seccomp_json_member="release-v${firecracker_version}-x86_64/seccomp-filter-v${firecracker_version}-x86_64.json"

fail() {
  printf 'real session-owner lifecycle: %s\n' "$1" >&2
  exit 2
}

[[ "$(id -u)" -eq 0 ]] || fail 'requires root for dm-verity, cgroup-v2, and the jailer'
[[ "$(uname -m)" == x86_64 ]] || fail 'supports x86_64 only'
[[ -c /dev/kvm ]] || fail 'requires /dev/kvm'
[[ -c /dev/vhost-vsock ]] || fail 'requires /dev/vhost-vsock'
[[ "$(stat -fc '%T' /sys/fs/cgroup)" == cgroup2fs ]] || fail 'requires cgroup-v2'

for command_name in awk cargo chmod dmsetup env file findmnt grep id install ln mkdir mkfs.ext4 mktemp mksquashfs realpath rm rmdir seq sha256sum sleep stat tar truncate umount uname unsquashfs veritysetup; do
  command -v "${command_name}" >/dev/null || fail "requires ${command_name}"
done

# The jailer executes Firecracker after entering the configured chroot.  A tmpfs such as this
# host's /run may be suitable for sockets but still carry MS_NOEXEC, which makes that child exit
# before it can be pinned into its cgroup.  Resolve the nearest mount entry rather than assuming
# the candidate is a separate mount, and reject an explicitly noexec mount before creating any
# guest state.
mount_options_for_path() {
  local candidate="$1"
  awk -v candidate="${candidate}" '
    function is_parent(mount) {
      return candidate == mount ||
        (mount == "/" ? substr(candidate, 1, 1) == "/" : index(candidate, mount "/") == 1)
    }
    is_parent($5) && length($5) > best_length {
      best_length = length($5)
      best_options = $6
    }
    END {
      if (best_options == "") {
        exit 1
      }
      print best_options
    }
  ' /proc/self/mountinfo
}

assert_exec_mount() {
  local path="$1"
  local filesystem_type
  local mount_options
  [[ "${path}" == /* && -d "${path}" && ! -L "${path}" ]] \
    || fail "exec staging parent must be an absolute non-symlink directory: ${path}"
  filesystem_type="$(stat -fc '%T' -- "${path}")" \
    || fail "cannot inspect filesystem for exec staging parent: ${path}"
  [[ -n "${filesystem_type}" && "${filesystem_type}" != UNKNOWN ]] \
    || fail "filesystem type is unavailable for exec staging parent: ${path}"
  mount_options="$(mount_options_for_path "${path}")" \
    || fail "cannot inspect mount flags for exec staging parent: ${path}"
  case ",${mount_options}," in
    *,noexec,*)
      fail "exec staging parent is mounted noexec: ${path} (${mount_options})"
      ;;
  esac
}

assert_private_directory_chain() {
  local directory="$1"
  local mode
  local owner
  while :; do
    [[ -d "${directory}" && ! -L "${directory}" ]] \
      || fail "exec staging parent chain contains a non-directory or symlink: ${directory}"
    mode="$(stat -c '%a' -- "${directory}")" \
      || fail "cannot inspect permissions for exec staging parent: ${directory}"
    owner="$(stat -c '%u' -- "${directory}")" \
      || fail "cannot inspect owner for exec staging parent: ${directory}"
    (( (0${mode} & 022) == 0 )) \
      || fail "exec staging parent chain is group/world-writable: ${directory}"
    [[ "${owner}" == 0 || "${owner}" == "$(id -u)" ]] \
      || fail "exec staging parent chain has an untrusted owner: ${directory}"
    [[ "${directory}" == / ]] && break
    directory="${directory%/*}"
    [[ -n "${directory}" ]] || directory=/
  done
}

test_parent="${REAL_SESSION_TEMP_PARENT:-/root}"
assert_private_directory_chain "${test_parent}"
assert_exec_mount "${test_parent}"

busybox="$(command -v busybox || true)"
[[ -n "${busybox}" && -f "${busybox}" && ! -L "${busybox}" ]] || fail 'requires a static BusyBox'
if ! file "${busybox}" | grep -q 'statically linked'; then
  fail 'BusyBox must be statically linked'
fi

"${repository_root}/scripts/ci/install-firecracker.sh" >/dev/null
[[ -f "${firecracker}" && ! -L "${firecracker}" ]] || fail "missing Firecracker binary: ${firecracker}"
[[ -f "${jailer}" && ! -L "${jailer}" ]] || fail "missing jailer binary: ${jailer}"
[[ -f "${archive}" && ! -L "${archive}" ]] || fail "missing Firecracker archive: ${archive}"

kernel="${REAL_SESSION_KERNEL:-$(${repository_root}/scripts/ci/build-guest-kernel.sh)}"
readonly kernel
[[ "${kernel}" == /* && -f "${kernel}" && ! -L "${kernel}" ]] || fail 'guest kernel must be an absolute regular file'

RUSTFLAGS='-C target-feature=+crt-static' cargo build \
  --manifest-path "${repository_root}/Cargo.toml" \
  -p firecracker-runtime \
  --bin guest-control-init \
  --bin guest-broker-probe \
  --release \
  --locked
cargo rustc \
  --manifest-path "${repository_root}/Cargo.toml" \
  -p supervisor \
  --bin guest-supervisor-init \
  --release \
  --locked \
  -- \
  -C target-feature=+crt-static
cargo rustc \
  --manifest-path "${repository_root}/Cargo.toml" \
  -p runtime-isolation \
  --bin workload-isolation-launcher \
  --release \
  --locked \
  -- \
  -C target-feature=+crt-static

for guest_binary in \
  "${repository_root}/target/release/guest-control-init" \
  "${repository_root}/target/release/guest-broker-probe" \
  "${repository_root}/target/release/guest-supervisor-init" \
  "${repository_root}/target/release/workload-isolation-launcher"; do
  if ! file "${guest_binary}" | grep -Eq 'statically linked|static-pie linked'; then
    fail "guest runtime binary must be statically linked: ${guest_binary}"
  fi
done

staging="$(mktemp -d "${repository_root}/.real-session-owner.XXXXXX")"
cleanup_state="${staging}/cleanup-state"
cleanup_cgroup_parent="/sys/fs/cgroup/session-owner-real-ci-$$"
cleanup_mapper_base="session-owner-real-ci-$$"
test_root=''

remove_mapper() {
  local mapper="$1"
  local attempt
  dmsetup info --noheadings -c -- "${mapper}" >/dev/null 2>&1 || return 0
  for attempt in $(seq 1 50); do
    if dmsetup remove -- "${mapper}" >/dev/null 2>&1; then
      return 0
    fi
    dmsetup info --noheadings -c -- "${mapper}" >/dev/null 2>&1 || return 0
    sleep 0.1
  done
  printf 'real session-owner cleanup: mapper remains after bounded removal: %s\n' \
    "${mapper}" >&2
  return 0
}

remove_cgroup() {
  local cgroup="$1"
  local attempt
  [[ -d "${cgroup}" && ! -L "${cgroup}" ]] || return 0
  if [[ -f "${cgroup}/cgroup.kill" ]]; then
    printf '1\n' >"${cgroup}/cgroup.kill" || true
  fi
  for _ in $(seq 1 50); do
    [[ -z "$(<"${cgroup}/cgroup.procs")" ]] && break
    sleep 0.1
  done
  for attempt in $(seq 1 50); do
    if rmdir -- "${cgroup}" >/dev/null 2>&1; then
      return 0
    fi
    [[ -d "${cgroup}" ]] || return 0
    sleep 0.1
  done
  printf 'real session-owner cleanup: cgroup remains after bounded removal: %s\n' \
    "${cgroup}" >&2
  return 0
}

cleanup() {
  local workspace_id=''
  local jailer_base=''
  local cgroup=''
  local mapper=''
  local mount_target=''
  if [[ -f "${cleanup_state}" && ! -L "${cleanup_state}" ]]; then
    workspace_id="$(awk -F= '$1 == "workspace_id" {print $2}' "${cleanup_state}")"
    jailer_base="$(awk -F= '$1 == "jailer_base" {print $2}' "${cleanup_state}")"
  fi
  if [[ "${workspace_id}" =~ ^[0-9a-f]{32}$ ]]; then
    remove_cgroup "${cleanup_cgroup_parent}/${workspace_id}"
    remove_mapper "${cleanup_mapper_base}-${workspace_id}"
    if [[ "${jailer_base}" =~ ^/[A-Za-z0-9._/-]+$ && "${jailer_base}" != / ]]; then
      rm -rf -- "${jailer_base}/firecracker/${workspace_id}"
    fi
  fi

  # A panic can happen before the Rust test publishes cleanup-state.  Enumerate only resources
  # below this invocation's exact random root/name instead of relying on that hand-off file.
  # Firecracker processes are killed first, then their rootfs bind mounts are detached before the
  # dm-verity mappings are removed.
  shopt -s nullglob
  for cgroup in "${cleanup_cgroup_parent}"/*; do
    case "${cgroup##*/}" in
      template | [0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f])
        remove_cgroup "${cgroup}"
        ;;
    esac
  done
  shopt -u nullglob

  if [[ -n "${test_root}" ]]; then
    while IFS= read -r mount_target; do
      case "${mount_target}" in
        "${test_root}"/*/jailer/firecracker/*/root/dev/rootfs)
          umount -- "${mount_target}" >/dev/null 2>&1 || true
          ;;
      esac
    done < <(findmnt -rn -o TARGET 2>/dev/null || true)
  fi

  while read -r mapper _; do
    if [[ "${mapper}" == "${cleanup_mapper_base}" \
      || "${mapper}" =~ ^${cleanup_mapper_base}-[0-9a-f]{32}$ ]]; then
      remove_mapper "${mapper}"
    fi
  done < <(dmsetup ls --target verity --noheadings 2>/dev/null || true)

  rmdir -- "${cleanup_cgroup_parent}" >/dev/null 2>&1 || true
  if [[ -n "${test_root}" ]]; then
    rm -rf -- "${test_root}"
  fi
  rm -rf -- "${staging}"
}
trap cleanup EXIT

# The published Ubuntu image is useful for broad guest-control verification, but it is too large
# for RuntimeConfig's bounded artifact reader once the supervisor and isolation binaries are
# installed.  A tiny immutable BusyBox base keeps this gate within that bound while the actual
# guest supervisor, CapFS runtime, isolation launcher, and workload are still built from this
# checkout and inserted below.
mkdir -p -- "${staging}/minimal-base/bin"
install -m 0755 -- "${busybox}" "${staging}/minimal-base/bin/busybox"
ln -s -- busybox "${staging}/minimal-base/bin/sh"
base_rootfs="${staging}/minimal-base.squashfs"
mksquashfs "${staging}/minimal-base" "${base_rootfs}" -noappend -all-root -comp xz >/dev/null
readonly base_rootfs

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
[[ -f "${staging}/seccomp.bin" && ! -L "${staging}/seccomp.bin" ]] || fail 'seccomp compiler produced no filter'

image_rootfs="${staging}/runtime.squashfs"
image_hash="${staging}/runtime.squashfs.hash"
"${repository_root}/scripts/ci/build-guest-runtime-image.sh" \
  --base-rootfs "${base_rootfs}" \
  --guest-control-init "${repository_root}/target/release/guest-control-init" \
  --guest-supervisor-init "${repository_root}/target/release/guest-supervisor-init" \
  --isolation-launcher "${repository_root}/target/release/workload-isolation-launcher" \
  --agent-workload "${repository_root}/target/release/guest-broker-probe" \
  --repository workspace \
  --file-effects read-data,list-directory,write-data,truncate,create-file,create-directory,remove-file,remove-directory,rename,set-metadata,read-link,create-symlink,create-hard-link \
  --path-prefix / \
  --port 19002 \
  --broker-port 19001 \
  --output-rootfs "${image_rootfs}" \
  --output-hash "${image_hash}"
root_hash="$(awk '/^Root hash:/ {print $3}' "${image_rootfs}.verity")"
[[ "${root_hash}" =~ ^[0-9a-f]{64}$ ]] || fail 'guest runtime image emitted no canonical dm-verity root hash'
test_root="$(mktemp -d "${test_parent%/}/so.XXXXXX")"
chmod 0700 -- "${test_root}"

run_lifecycle() {
  local fixed_directory="${1:-}"
  local crash_checkpoint="${2:-}"
  local crash_marker="${3:-}"
  local -a crash_environment=()
  if [[ -n "${fixed_directory}" ]]; then
    crash_environment+=(REAL_SESSION_FIXED_DIRECTORY="${fixed_directory}")
  fi
  if [[ -n "${crash_checkpoint}" ]]; then
    crash_environment+=(
      SESSION_ORCHESTRATOR_CRASH_CHECKPOINT="${crash_checkpoint}"
      SESSION_ORCHESTRATOR_CRASH_READY_FILE="${crash_marker}"
    )
  fi

  env \
    -u SESSION_ORCHESTRATOR_CRASH_CHECKPOINT \
    -u SESSION_ORCHESTRATOR_CRASH_READY_FILE \
    "${crash_environment[@]}" \
    REAL_SESSION_OWNER_LIFECYCLE=1 \
    REAL_SESSION_TEMP_ROOT="${test_root}" \
    REAL_SESSION_CGROUP_PARENT="${cleanup_cgroup_parent}" \
    REAL_SESSION_MAPPER_NAME="${cleanup_mapper_base}" \
    REAL_SESSION_CLEANUP_STATE="${cleanup_state}" \
    REAL_SESSION_FIRECRACKER_BIN="${firecracker}" \
    REAL_SESSION_FIRECRACKER_JAILER="${jailer}" \
    REAL_SESSION_KERNEL="${kernel}" \
    REAL_SESSION_ROOTFS="${image_rootfs}" \
    REAL_SESSION_VERITY_HASH="${image_hash}" \
    REAL_SESSION_ROOT_HASH="${root_hash}" \
    REAL_SESSION_SECCOMP="${staging}/seccomp.bin" \
    REAL_SESSION_VERITYSETUP="$(realpath -e -- "$(command -v veritysetup)")" \
    REAL_SESSION_DMSETUP="$(realpath -e -- "$(command -v dmsetup)")" \
    REAL_SESSION_WORKSPACE_FORMATTER="$(realpath -e -- "$(command -v mkfs.ext4)")" \
    cargo test \
    --manifest-path "${repository_root}/Cargo.toml" \
    -p session-orchestrator \
    --test real_production_lifecycle \
    --features crash-test-hooks \
    --locked \
    -- \
    --ignored \
    --nocapture \
    --exact \
    real_production_session_owner_runs_ready_poll_stop_and_cleans_every_owned_resource
}

run_crash_case() {
  local checkpoint="$1"
  # The production Broker and Firecracker vsock endpoints are Unix sockets.
  # Keep the restart-stable component intentionally tiny so even the longest
  # nested endpoint remains below Linux SUN_LEN. The recovery run removes this
  # directory before the next matrix case reuses the name.
  local fixed_directory='c'
  local marker="${test_root}/marker-${checkpoint}"
  local log="${staging}/crash-${checkpoint}.log"
  local cargo_pid test_pid observed_checkpoint command_line status
  rm -f -- "${marker}" "${log}"

  run_lifecycle "${fixed_directory}" "${checkpoint}" "${marker}" >"${log}" 2>&1 &
  cargo_pid=$!
  for _ in $(seq 1 2400); do
    [[ -s "${marker}" ]] && break
    if ! kill -0 "${cargo_pid}" 2>/dev/null; then
      wait "${cargo_pid}" || true
      tail -n 80 -- "${log}" >&2 || true
      fail "crash checkpoint ${checkpoint} exited before publishing its marker"
    fi
    sleep 0.1
  done
  [[ -s "${marker}" && ! -L "${marker}" ]] \
    || fail "crash checkpoint ${checkpoint} did not publish a regular marker before timeout"
  test_pid="$(awk -F= '$1 == "pid" {print $2}' "${marker}")"
  observed_checkpoint="$(awk -F= '$1 == "checkpoint" {print $2}' "${marker}")"
  [[ "${test_pid}" =~ ^[1-9][0-9]*$ && "${observed_checkpoint}" == "${checkpoint}" ]] \
    || fail "crash checkpoint ${checkpoint} published an invalid marker"
  [[ -r "/proc/${test_pid}/cmdline" ]] \
    || fail "crash checkpoint ${checkpoint} test process disappeared before SIGKILL"
  command_line="$(tr '\0' ' ' <"/proc/${test_pid}/cmdline")"
  [[ "${command_line}" == *real_production_lifecycle* \
    && "${command_line}" == *real_production_session_owner_runs_ready_poll_stop_and_cleans_every_owned_resource* ]] \
    || fail "refusing to kill process ${test_pid} with unexpected command line"
  kill -KILL "${test_pid}"
  set +e
  wait "${cargo_pid}"
  status=$?
  set -e
  [[ "${status}" -ne 0 ]] \
    || fail "crash checkpoint ${checkpoint} unexpectedly exited successfully after SIGKILL"

  rm -f -- "${marker}"
  run_lifecycle "${fixed_directory}" '' ''
  printf 'real session-owner crash recovery: %s killed externally and recovered\n' "${checkpoint}"
}

if [[ "${REAL_SESSION_CRASH_MATRIX:-0}" == 1 ]]; then
  requested_checkpoint="${REAL_SESSION_CRASH_MATRIX_CASE:-}"
  matched_checkpoint=0
  for checkpoint in \
    identity-reserved \
    workspace-cloned \
    broker-established \
    vm-started \
    root-capability-injected \
    workload-released \
    running \
    cleanup-capability-revoked \
    cleanup-vm-killed \
    cleanup-broker-closed \
    cleanup-workspace-isolated; do
    if [[ -n "${requested_checkpoint}" && "${checkpoint}" != "${requested_checkpoint}" ]]; then
      continue
    fi
    matched_checkpoint=1
    run_crash_case "${checkpoint}"
  done
  [[ "${matched_checkpoint}" -eq 1 ]] \
    || fail "unknown REAL_SESSION_CRASH_MATRIX_CASE: ${requested_checkpoint}"
  printf '%s\n' 'real session-owner crash recovery: every lifecycle checkpoint recovered without residue'
else
  run_lifecycle '' '' ''
fi
