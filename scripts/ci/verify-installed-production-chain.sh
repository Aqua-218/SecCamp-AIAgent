#!/usr/bin/env bash

# Test suite: exact installed production control chain.
# Specification: deploy/README.md "Production multi-session installation" and "Snapshot
# provisioning". This gate installs the checked-in production units at their real paths, runs an
# authenticated caller through host-controld and two concurrent KVM workers, exercises normal
# stop, worker-crash recovery, and controller-restart reconciliation, then restores the host.
# Prerequisites: disposable x86_64 systemd host, root, KVM/vsock/device-mapper, polkit, and an
# artifact bundle exported by verify-real-session-owner.sh.

set -Eeuo pipefail
umask 077

repository_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly repository_root
readonly artifact_root="${INSTALLED_CHAIN_ARTIFACT_ROOT:-}"
readonly controller_unit=/etc/systemd/system/host-controld.service
readonly worker_unit=/etc/systemd/system/host-sessiond@.service
readonly recovery_unit=/etc/systemd/system/host-sessiond-recover@.service
readonly polkit_rule=/etc/polkit-1/rules.d/50-host-controld.rules
readonly udev_rule=/etc/udev/rules.d/70-host-sessiond-device-mapper.rules
readonly controller_config_root=/etc/host-controld
readonly worker_config_root=/etc/host-sessiond
readonly controller_state_root=/var/lib/host-controld
readonly worker_state_root=/var/lib/host-sessiond
readonly worker_jail_root=/var/lib/host-jails
readonly controller_runtime_root=/run/host-controld
readonly worker_runtime_root=/run/host-sessiond
readonly firecracker_root=/opt/firecracker
readonly guest_root=/opt/guest
readonly client_gid=2000
readonly controller_uid=960
readonly worker_uid=961
readonly worker_gid=961
readonly guest_cid=42
readonly broker_port=19001
readonly guest_control_port=19002

fail() {
  printf 'installed production chain: %s\n' "$1" >&2
  exit 2
}

[[ "$(id -u)" -eq 0 ]] || fail 'requires root'
[[ "$(uname -m)" == x86_64 ]] || fail 'supports x86_64 only'
[[ "$(ps -p 1 -o comm=)" == systemd ]] || fail 'requires systemd as PID 1'
[[ -c /dev/kvm ]] || fail 'requires /dev/kvm'
[[ -c /dev/vhost-vsock ]] || fail 'requires /dev/vhost-vsock'
[[ -c /dev/mapper/control ]] || fail 'requires /dev/mapper/control'
[[ "$(stat -fc '%T' /sys/fs/cgroup)" == cgroup2fs ]] || fail 'requires cgroup v2'
[[ -n "${artifact_root}" && "${artifact_root}" == /* && "${artifact_root}" != / ]] \
  || fail 'INSTALLED_CHAIN_ARTIFACT_ROOT must be an absolute non-root path'

for command_name in \
  awk cargo chmod chown dirname dmsetup find getent git grep groupadd groupdel id install kill \
  mkfs.ext4 mktemp openssl ps readlink realpath rm sed seq setpriv sha256sum sleep sort stat \
  systemctl systemd-analyze tr udevadm umount uname useradd userdel usermod veritysetup wc; do
  command -v "${command_name}" >/dev/null || fail "requires ${command_name}"
done

assert_secure_directory_chain() {
  local directory="$1"
  local mode owner
  while :; do
    [[ -d "${directory}" && ! -L "${directory}" ]] \
      || fail "secure directory chain contains a non-directory or symlink: ${directory}"
    mode="$(stat -c '%a' -- "${directory}")"
    owner="$(stat -c '%u' -- "${directory}")"
    (( (0${mode} & 022) == 0 )) \
      || fail "secure directory chain is group/world writable: ${directory}"
    [[ "${owner}" == 0 ]] || fail "secure directory chain is not root-owned: ${directory}"
    [[ "${directory}" == / ]] && break
    directory="${directory%/*}"
    [[ -n "${directory}" ]] || directory=/
  done
}

assert_secure_directory_chain "${artifact_root}"
readonly expected_artifacts=(
  firecracker
  jailer
  seccompiler
  vmlinux
  rootfs.squashfs
  rootfs.verity
  seccomp.bin
  seccomp.json
  snapshot.state
  snapshot.memory
  rootfs.root-hash
)
[[ -f "${artifact_root}/SHA256SUMS" && ! -L "${artifact_root}/SHA256SUMS" ]] \
  || fail 'artifact SHA256SUMS is absent or not a regular file'
[[ "$(wc -l <"${artifact_root}/SHA256SUMS")" -eq "${#expected_artifacts[@]}" ]] \
  || fail 'artifact SHA256SUMS does not contain the exact file set'
for artifact in "${expected_artifacts[@]}"; do
  [[ -f "${artifact_root}/${artifact}" && ! -L "${artifact_root}/${artifact}" ]] \
    || fail "artifact is absent or not a regular file: ${artifact}"
  grep -Eq "^[0-9a-f]{64}  ${artifact//./\\.}$" "${artifact_root}/SHA256SUMS" \
    || fail "artifact manifest omits the exact ${artifact} entry"
done
(cd -- "${artifact_root}" && sha256sum --check --strict SHA256SUMS) \
  || fail 'artifact digest verification failed'
[[ "$("${artifact_root}/firecracker" --version 2>&1 | sed -n '1p')" =~ ^Firecracker\ v1\.16\. ]] \
  || fail 'the snapshot clone gate requires Firecracker 1.16.x'

for target in \
  /usr/local/bin/host-sessiond \
  /usr/local/bin/host-controld \
  /usr/local/bin/host-control \
  "${controller_unit}" \
  "${worker_unit}" \
  "${recovery_unit}" \
  "${polkit_rule}" \
  "${udev_rule}" \
  "${controller_config_root}" \
  "${worker_config_root}" \
  "${controller_state_root}" \
  "${worker_state_root}" \
  "${worker_jail_root}" \
  "${controller_runtime_root}" \
  "${worker_runtime_root}" \
  "${firecracker_root}" \
  "${guest_root}"; do
  [[ ! -e "${target}" && ! -L "${target}" ]] \
    || fail "refuses pre-existing deployment target: ${target}"
done

getent passwd host-controld >/dev/null && fail 'host-controld account already exists'
getent passwd host-sessiond >/dev/null && fail 'host-sessiond account already exists'
getent group host-control >/dev/null && fail 'host-control group already exists'
getent group host-sessiond >/dev/null && fail 'host-sessiond group already exists'
getent passwd "${controller_uid}" >/dev/null && fail "UID ${controller_uid} is already allocated"
getent passwd "${worker_uid}" >/dev/null && fail "UID ${worker_uid} is already allocated"
getent group "${client_gid}" >/dev/null && fail "GID ${client_gid} is already allocated"
getent group "${worker_gid}" >/dev/null && fail "GID ${worker_gid} is already allocated"
if systemctl list-units --all --no-legend \
  'host-controld.service' 'host-sessiond@*.service' 'host-sessiond-recover@*.service' \
  | awk '$3 ~ /^(active|activating|deactivating)$/ { found = 1 } END { exit !found }'; then
  fail 'a production control-chain unit is already owned by systemd'
fi
[[ -z "$(git -C "${repository_root}" status --porcelain=v1 --untracked-files=normal)" ]] \
  || fail 'the validation deployment requires a clean checkout'

staging="$(mktemp -d /root/.installed-production-chain.XXXXXX)"
readonly staging
readonly device_metadata="${staging}/device-metadata"
sessions=()
deployment_started=0

record_device_metadata() {
  local device
  : >"${device_metadata}"
  shopt -s nullglob
  for device in /dev/kvm /dev/vhost-vsock /dev/loop-control /dev/loop[0-9]* /dev/dm-*; do
    [[ -e "${device}" && ! -L "${device}" ]] || continue
    stat -Lc '%n %u %g %a' -- "${device}" >>"${device_metadata}"
  done
  shopt -u nullglob
}

restore_device_metadata() {
  local device owner group mode
  [[ -f "${device_metadata}" ]] || return 0
  while read -r device owner group mode; do
    case "${device}" in
      /dev/kvm | /dev/vhost-vsock | /dev/loop-control | /dev/loop[0-9]* | /dev/dm-*)
        if [[ -e "${device}" && ! -L "${device}" ]]; then
          chown "${owner}:${group}" -- "${device}" >/dev/null 2>&1 || true
          chmod "${mode}" -- "${device}" >/dev/null 2>&1 || true
        fi
        ;;
    esac
  done <"${device_metadata}"
}

cleanup() {
  local session
  set +e
  if [[ "${deployment_started}" -eq 1 ]]; then
    systemctl stop host-controld.service >/dev/null 2>&1
    while read -r session; do
      [[ "${session}" =~ ^[0-9a-f]{32}$ ]] && sessions+=("${session}")
    done < <(
      for instance_root in \
        "${worker_state_root}/instances" \
        "${worker_runtime_root}/instances" \
        "${worker_jail_root}"; do
        [[ -d "${instance_root}" ]] \
          && find "${instance_root}" -mindepth 1 -maxdepth 1 -type d -printf '%f\n'
      done | sort -u
    )
    for session in "${sessions[@]}"; do
      if [[ "${session}" =~ ^[0-9a-f]{32}$ ]]; then
        systemctl stop "host-sessiond@${session}.service" >/dev/null 2>&1
        systemctl start "host-sessiond-recover@${session}.service" >/dev/null 2>&1
        systemctl reset-failed \
          "host-sessiond@${session}.service" \
          "host-sessiond-recover@${session}.service" >/dev/null 2>&1
      fi
    done
    rm -f -- \
      "${controller_unit}" \
      "${worker_unit}" \
      "${recovery_unit}" \
      "${polkit_rule}" \
      "${udev_rule}"
    systemctl daemon-reload >/dev/null 2>&1
    udevadm control --reload-rules >/dev/null 2>&1
    udevadm trigger --subsystem-match=misc --subsystem-match=block --action=add >/dev/null 2>&1
    udevadm settle >/dev/null 2>&1
    restore_device_metadata
    systemctl restart polkit.service >/dev/null 2>&1
    rm -rf -- \
      "${controller_config_root}" \
      "${worker_config_root}" \
      "${controller_state_root}" \
      "${worker_state_root}" \
      "${worker_jail_root}" \
      "${controller_runtime_root}" \
      "${worker_runtime_root}" \
      "${firecracker_root}" \
      "${guest_root}"
    rm -f -- \
      /usr/local/bin/host-sessiond \
      /usr/local/bin/host-controld \
      /usr/local/bin/host-control
    userdel host-controld >/dev/null 2>&1
    userdel host-sessiond >/dev/null 2>&1
    groupdel host-control >/dev/null 2>&1
    groupdel host-sessiond >/dev/null 2>&1
  fi
  rm -rf -- "${staging}"
}
trap cleanup EXIT

record_device_metadata

cargo build --release --locked --manifest-path "${repository_root}/Cargo.toml" \
  -p session-orchestrator --bin host-sessiond --bin host-controld --bin host-control
install -d -o root -g root -m 0700 -- "${staging}/host-bin"
for binary in host-sessiond host-controld host-control; do
  install -o root -g root -m 0500 -- \
    "${repository_root}/target/release/${binary}" "${staging}/host-bin/${binary}"
done
(
  cd -- "${staging}/host-bin"
  sha256sum host-sessiond host-controld host-control >SHA256SUMS
  sha256sum --check --strict SHA256SUMS
)

deployment_started=1
groupadd --system --gid "${client_gid}" host-control
useradd --system --uid "${controller_uid}" --gid host-control --no-create-home \
  --home-dir "${controller_state_root}" --shell /usr/sbin/nologin host-controld
groupadd --system --gid "${worker_gid}" host-sessiond
useradd --system --uid "${worker_uid}" --gid host-sessiond --no-create-home \
  --home-dir "${worker_state_root}" --shell /usr/sbin/nologin host-sessiond
usermod --append --groups kvm host-sessiond

[[ "$(id -u host-controld)" == "${controller_uid}" \
  && "$(id -g host-controld)" == "${client_gid}" ]] \
  || fail 'controller account identity does not match the deployment contract'
[[ "$(id -u host-sessiond)" == "${worker_uid}" \
  && "$(id -g host-sessiond)" == "${worker_gid}" ]] \
  || fail 'worker account identity does not match the deployment contract'
id -nG host-sessiond | tr ' ' '\n' | grep -qx kvm \
  || fail 'worker account did not receive the kvm supplementary group'

install -o root -g root -m 0755 -- "${staging}/host-bin/host-sessiond" /usr/local/bin/host-sessiond
install -o root -g root -m 0755 -- "${staging}/host-bin/host-controld" /usr/local/bin/host-controld
install -o root -g root -m 0755 -- "${staging}/host-bin/host-control" /usr/local/bin/host-control
for binary in host-sessiond host-controld host-control; do
  expected="$(awk -v name="${binary}" '$2 == name { print $1 }' "${staging}/host-bin/SHA256SUMS")"
  actual="$(sha256sum "/usr/local/bin/${binary}" | awk '{ print $1 }')"
  [[ "${actual}" == "${expected}" ]] || fail "installed ${binary} digest changed"
done

install -d -o root -g root -m 0555 -- "${firecracker_root}" "${guest_root}"
install -o root -g root -m 0555 -- "${artifact_root}/firecracker" "${firecracker_root}/fc"
install -o root -g root -m 0555 -- "${artifact_root}/jailer" "${firecracker_root}/jailer"
install -o root -g root -m 0555 -- "${artifact_root}/seccompiler" "${firecracker_root}/seccompiler"
install -o root -g root -m 0444 -- "${artifact_root}/seccomp.bin" "${firecracker_root}/seccomp.bin"
install -o root -g root -m 0444 -- "${artifact_root}/seccomp.json" "${firecracker_root}/seccomp.json"
install -o root -g root -m 0444 -- "${artifact_root}/vmlinux" "${guest_root}/vmlinux"
install -o root -g root -m 0444 -- "${artifact_root}/rootfs.squashfs" "${guest_root}/rootfs.squashfs"
install -o root -g root -m 0444 -- "${artifact_root}/rootfs.verity" "${guest_root}/rootfs.verity"
install -o root -g root -m 0444 -- "${artifact_root}/snapshot.state" "${guest_root}/snapshot.state"
install -o root -g root -m 0444 -- "${artifact_root}/snapshot.memory" "${guest_root}/snapshot.memory"

install -d -o root -g host-control -m 0750 -- "${controller_config_root}"
install -d -o root -g host-sessiond -m 0750 -- "${worker_config_root}"
install -d -o host-sessiond -g host-sessiond -m 0750 -- \
  "${worker_state_root}" "${worker_state_root}/instances"
install -d -o root -g host-sessiond -m 0550 -- "${worker_state_root}/workspace-source"
install -o root -g host-sessiond -m 0440 /dev/null \
  "${worker_state_root}/workspace-source/installed-chain-marker"

systemctl_digest="$(sha256sum /usr/bin/systemctl | awk '{ print $1 }')"
root_hash="$(sed -n '1p' "${artifact_root}/rootfs.root-hash")"
[[ "${root_hash}" =~ ^[0-9a-f]{64}$ ]] || fail 'artifact root hash is not canonical'
firecracker_digest="$(sha256sum "${firecracker_root}/fc" | awk '{ print $1 }')"
jailer_digest="$(sha256sum "${firecracker_root}/jailer" | awk '{ print $1 }')"
seccompiler_digest="$(sha256sum "${firecracker_root}/seccompiler" | awk '{ print $1 }')"
seccomp_digest="$(sha256sum "${firecracker_root}/seccomp.bin" | awk '{ print $1 }')"
seccomp_policy_digest="$(sha256sum "${firecracker_root}/seccomp.json" | awk '{ print $1 }')"
kernel_digest="$(sha256sum "${guest_root}/vmlinux" | awk '{ print $1 }')"
rootfs_digest="$(sha256sum "${guest_root}/rootfs.squashfs" | awk '{ print $1 }')"
verity_digest="$(sha256sum "${guest_root}/rootfs.verity" | awk '{ print $1 }')"
snapshot_state_digest="$(sha256sum "${guest_root}/snapshot.state" | awk '{ print $1 }')"
snapshot_memory_digest="$(sha256sum "${guest_root}/snapshot.memory" | awk '{ print $1 }')"
formatter="$(realpath -e -- "$(command -v mkfs.ext4)")"
formatter_digest="$(sha256sum "${formatter}" | awk '{ print $1 }')"
veritysetup="$(realpath -e -- "$(command -v veritysetup)")"
veritysetup_digest="$(sha256sum "${veritysetup}" | awk '{ print $1 }')"
dmsetup="$(realpath -e -- "$(command -v dmsetup)")"
dmsetup_digest="$(sha256sum "${dmsetup}" | awk '{ print $1 }')"

install -o root -g host-control -m 0640 /dev/stdin "${controller_config_root}/controld.env" <<EOF
HOST_CONTROLD_CLIENT_GID=${client_gid}
HOST_CONTROLD_SYSTEMCTL_SHA256=${systemctl_digest}
HOST_CONTROLD_MAX_SESSIONS=2
HOST_CONTROLD_MAX_SESSIONS_PER_PRINCIPAL=2
HOST_CONTROLD_POLL_MILLIS=20
EOF
openssl rand -out "${controller_config_root}/control.key" 32
chown host-controld:host-control -- "${controller_config_root}/control.key"
chmod 0440 -- "${controller_config_root}/control.key"

install -o root -g host-sessiond -m 0640 /dev/stdin "${worker_config_root}/worker.env" <<EOF
HOST_SESSIOND_FIRECRACKER=${firecracker_root}/fc
HOST_SESSIOND_FIRECRACKER_SHA256=${firecracker_digest}
HOST_SESSIOND_JAILER=${firecracker_root}/jailer
HOST_SESSIOND_JAILER_SHA256=${jailer_digest}
HOST_SESSIOND_KERNEL_SOURCE=${guest_root}/vmlinux
HOST_SESSIOND_KERNEL_SOURCE_SHA256=${kernel_digest}
HOST_SESSIOND_ROOTFS=${guest_root}/rootfs.squashfs
HOST_SESSIOND_ROOTFS_SHA256=${rootfs_digest}
HOST_SESSIOND_VERITY_HASH=${guest_root}/rootfs.verity
HOST_SESSIOND_VERITY_HASH_SHA256=${verity_digest}
HOST_SESSIOND_ROOTFS_VERITY_ROOT_HASH=${root_hash}
HOST_SESSIOND_WORKSPACE_FORMATTER=${formatter}
HOST_SESSIOND_WORKSPACE_FORMATTER_SHA256=${formatter_digest}
HOST_SESSIOND_WORKSPACE_SOURCE=${worker_state_root}/workspace-source
HOST_SESSIOND_SECCOMP_COMPILER=${firecracker_root}/seccompiler
HOST_SESSIOND_SECCOMP_COMPILER_SHA256=${seccompiler_digest}
HOST_SESSIOND_SECCOMP_SOURCE=${firecracker_root}/seccomp.bin
HOST_SESSIOND_SECCOMP_SOURCE_SHA256=${seccomp_digest}
HOST_SESSIOND_SECCOMP_POLICY_SOURCE=${firecracker_root}/seccomp.json
HOST_SESSIOND_SECCOMP_POLICY_SOURCE_SHA256=${seccomp_policy_digest}
HOST_SESSIOND_SNAPSHOT_ID=a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5
HOST_SESSIOND_SNAPSHOT_STATE=${guest_root}/snapshot.state
HOST_SESSIOND_SNAPSHOT_STATE_SHA256=${snapshot_state_digest}
HOST_SESSIOND_SNAPSHOT_MEMORY=${guest_root}/snapshot.memory
HOST_SESSIOND_SNAPSHOT_MEMORY_SHA256=${snapshot_memory_digest}
HOST_SESSIOND_VERITYSETUP=${veritysetup}
HOST_SESSIOND_VERITYSETUP_SHA256=${veritysetup_digest}
HOST_SESSIOND_DMSETUP=${dmsetup}
HOST_SESSIOND_DMSETUP_SHA256=${dmsetup_digest}
HOST_SESSIOND_JAILER_CHROOT_BASE=${worker_jail_root}
HOST_SESSIOND_CGROUP_PARENT=system.slice
HOST_SESSIOND_IDENTITY_LEDGER_ROOT=${worker_state_root}/instances
HOST_SESSIOND_RECOVERY_JOURNAL_ROOT=${worker_state_root}/instances
HOST_SESSIOND_AUTHORITY_AUDIT_ROOT=${worker_state_root}/instances
HOST_SESSIOND_BROKER_WAL_BASE=${worker_state_root}/instances
HOST_SESSIOND_STOP_ROOT=${worker_runtime_root}/instances
HOST_SESSIOND_STATUS_ROOT=${worker_runtime_root}/instances
HOST_SESSIOND_JAILER_UID=${worker_uid}
HOST_SESSIOND_JAILER_GID=${worker_gid}
HOST_SESSIOND_VERITY_MAPPER_PREFIX=host-sessiond-rootfs
HOST_SESSIOND_WORKSPACE_IMAGE_BYTES=67108864
HOST_SESSIOND_MEMORY_MAX_BYTES=536870912
HOST_SESSIOND_CPU_QUOTA_MICROS=100000
HOST_SESSIOND_CPU_PERIOD_MICROS=100000
HOST_SESSIOND_GUEST_CID=${guest_cid}
HOST_SESSIOND_VCPU_COUNT=1
HOST_SESSIOND_MEMORY_MIB=256
HOST_SESSIOND_BOOT_ARGS=console=ttyS0 reboot=k panic=1 pci=off root=/dev/vda rootfstype=squashfs ro init=/usr/local/libexec/guest-control-init -- --port ${guest_control_port} --workload /usr/local/libexec/guest-supervisor-init --workspace-device /dev/vdb --runtime-dir /run/guest-supervisor --cgroup-parent /sys/fs/cgroup --broker-port ${broker_port} --isolation-launcher /usr/local/libexec/workload-isolation-launcher --workload /usr/local/libexec/agent-workload --repository workspace --file-effects read-data,list-directory,write-data,truncate,create-file,create-directory,remove-file,remove-directory,rename,set-metadata,read-link,create-symlink,create-hard-link --path-prefix / --hold-workload-after-probe
HOST_SESSIOND_ISSUER=host-sessiond-installed-chain
HOST_SESSIOND_WORKSPACE_TEMPLATE=installed-chain
HOST_SESSIOND_AUTHORITY_AUDIT_MODE=auto
HOST_SESSIOND_BROKER_HOST_CID=2
HOST_SESSIOND_BROKER_PORT=${broker_port}
HOST_SESSIOND_BROKER_BACKLOG=8
HOST_SESSIOND_GUEST_CONTROL_PORT=${guest_control_port}
HOST_SESSIOND_BROKER_REPLAY_CAPACITY=256
HOST_SESSIOND_BROKER_BUDGET_REQUESTS=1000
HOST_SESSIOND_BROKER_BUDGET_RESPONSE_BYTES=67108864
HOST_SESSIOND_BROKER_BUDGET_CONCURRENT=4
HOST_SESSIOND_GITHUB_RESPONSE_CAP_BYTES=16777216
HOST_SESSIOND_BROKER_MAX_CONNECTION_REQUESTS=256
HOST_SESSIOND_REPOSITORY=workspace
HOST_SESSIOND_FILE_EFFECTS=read-data,list-directory,write-data,truncate,create-file,create-directory,remove-file,remove-directory,rename,set-metadata,read-link,create-symlink,create-hard-link
HOST_SESSIOND_PATH_PREFIX=/
HOST_SESSIOND_POLL_MILLIS=20
HOST_SESSIOND_SHUTDOWN_TIMEOUT_MILLIS=300000
EOF

install -o root -g root -m 0644 -- "${repository_root}/deploy/70-host-sessiond-device-mapper.rules" "${udev_rule}"
udevadm control --reload-rules
udevadm trigger --subsystem-match=misc --subsystem-match=block --action=add
udevadm settle
[[ "$(stat -Lc '%u:%g' /dev/mapper/control)" == "0:${worker_gid}" ]] \
  || fail 'udev did not grant the worker group device-mapper control access'
[[ "$(stat -Lc '%u:%g' /dev/loop-control)" == "0:${worker_gid}" ]] \
  || fail 'udev did not grant the worker group loop-control access'

install -o root -g root -m 0644 -- "${repository_root}/service/host-sessiond@.service" "${worker_unit}"
install -o root -g root -m 0644 -- "${repository_root}/service/host-sessiond-recover@.service" "${recovery_unit}"
install -o root -g root -m 0644 -- "${repository_root}/service/host-controld.service" "${controller_unit}"
install -o root -g root -m 0644 -- "${repository_root}/deploy/polkit-1/rules.d/50-host-controld.rules" "${polkit_rule}"
systemctl daemon-reload
systemctl restart polkit.service
systemd-analyze verify "${controller_unit}" "${worker_unit}" "${recovery_unit}"
systemctl start host-controld.service

wait_for_controller() {
  for _ in $(seq 1 500); do
    [[ -S "${controller_runtime_root}/control.sock" ]] && return 0
    [[ "$(systemctl is-active host-controld.service || true)" == active ]] || break
    sleep 0.02
  done
  systemctl status --no-pager host-controld.service >&2 || true
  return 1
}

control() {
  setpriv --reuid=65534 --regid="${client_gid}" --clear-groups \
    /usr/local/bin/host-control \
      --socket "${controller_runtime_root}/control.sock" \
      --key-file "${controller_config_root}/control.key" \
      --client-gid "${client_gid}" "$@"
}

wait_for_controller || fail 'controller did not publish its production socket'
controller_pid="$(systemctl show --property=MainPID --value host-controld.service)"
[[ "${controller_pid}" =~ ^[1-9][0-9]*$ \
  && "$(stat -c '%u' "/proc/${controller_pid}")" == "${controller_uid}" ]] \
  || fail 'controller is not running as the dedicated unprivileged account'
if setpriv --reuid=65534 --regid=65534 --clear-groups \
  /usr/local/bin/host-control \
    --socket "${controller_runtime_root}/control.sock" \
    --key-file "${controller_config_root}/control.key" \
    --client-gid "${client_gid}" start >/dev/null 2>&1; then
  fail 'a caller outside host-control read the authenticated client key'
fi

worker_firecracker_pid=''
worker_workspace_id=''
assert_worker_ready() {
  local session="$1"
  local unit="host-sessiond@${session}.service"
  local main_pid control_group cgroup_root candidate_pid executable status_file mapper
  [[ "$(systemctl is-active "${unit}")" == active ]] || fail "worker is not active: ${unit}"
  main_pid="$(systemctl show --property=MainPID --value "${unit}")"
  [[ "${main_pid}" =~ ^[1-9][0-9]*$ \
    && "$(stat -c '%u' "/proc/${main_pid}")" == "${worker_uid}" ]] \
    || fail "worker main process has the wrong identity: ${unit}"
  grep -qxF "0::/system.slice/${unit}/daemon" "/proc/${main_pid}/cgroup" \
    || fail "worker is outside its exact delegated system.slice cgroup: ${unit}"
  status_file="${worker_runtime_root}/instances/${session}/status"
  grep -q '"event":"ready"' "${status_file}" \
    || fail "worker did not publish its ready status: ${unit}"
  worker_workspace_id="$(sed -n 's/.*"workspace_id":"\([0-9a-f]\{32\}\)".*/\1/p' "${status_file}")"
  [[ "${worker_workspace_id}" =~ ^[0-9a-f]{32}$ ]] \
    || fail "worker status omitted its workspace identity: ${unit}"
  [[ -S "${worker_jail_root}/${session}/fc/${worker_workspace_id}/root/v" ]] \
    || fail "worker did not expose its session-scoped Firecracker UDS: ${unit}"
  mapper="host-sessiond-rootfs-${session}-${worker_workspace_id}"
  dmsetup info --noheadings -c -- "${mapper}" >/dev/null \
    || fail "worker dm-verity mapper is absent: ${mapper}"
  [[ "$(stat -Lc '%u:%g:%a' "/dev/mapper/${mapper}")" == \
      "${worker_uid}:${worker_gid}:400" ]] \
    || fail "worker dm-verity node did not retain its exact jailer ownership: ${mapper}"
  control_group="$(systemctl show --property=ControlGroup --value "${unit}")"
  cgroup_root="/sys/fs/cgroup${control_group}"
  worker_firecracker_pid=''
  while read -r candidate_pid; do
    [[ "${candidate_pid}" =~ ^[1-9][0-9]*$ && -e "/proc/${candidate_pid}/exe" ]] || continue
    executable="$(readlink -f "/proc/${candidate_pid}/exe" 2>/dev/null || true)"
    if [[ "${executable##*/}" == fc ]]; then
      worker_firecracker_pid="${candidate_pid}"
      break
    fi
  done < <(find "${cgroup_root}" -name cgroup.procs -type f -exec awk 'NF { print }' {} + | sort -u)
  [[ "${worker_firecracker_pid}" =~ ^[1-9][0-9]*$ ]] \
    || fail "worker cgroup has no live Firecracker process: ${unit}"
  [[ "$(stat -c '%u:%g' "/proc/${worker_firecracker_pid}")" == \
      "${worker_uid}:${worker_gid}" ]] \
    || fail "Firecracker did not retain the dedicated unprivileged identity: ${unit}"
}

wait_for_recovery() {
  local session="$1"
  local result status
  for _ in $(seq 1 1800); do
    result="$(systemctl show --property=Result --value "host-sessiond-recover@${session}.service" 2>/dev/null || true)"
    status="$(systemctl show --property=ExecMainStatus --value "host-sessiond-recover@${session}.service" 2>/dev/null || true)"
    if [[ "${result}" == success && "${status}" == 0 \
      && "$(systemctl is-active "host-sessiond@${session}.service" || true)" != active ]]; then
      return 0
    fi
    sleep 0.1
  done
  systemctl status --no-pager \
    "host-sessiond@${session}.service" \
    "host-sessiond-recover@${session}.service" >&2 || true
  return 1
}

session_one="$(control start)"
sessions+=("${session_one}")
session_two="$(control start)"
sessions+=("${session_two}")
[[ "${session_one}" =~ ^[0-9a-f]{32}$ \
  && "${session_two}" =~ ^[0-9a-f]{32}$ \
  && "${session_one}" != "${session_two}" ]] \
  || fail 'controller did not allocate two distinct canonical sessions'
assert_worker_ready "${session_one}"
firecracker_one="${worker_firecracker_pid}"
workspace_one="${worker_workspace_id}"
assert_worker_ready "${session_two}"
firecracker_two="${worker_firecracker_pid}"
workspace_two="${worker_workspace_id}"
[[ "${firecracker_one}" != "${firecracker_two}" \
  && "${workspace_one}" != "${workspace_two}" ]] \
  || fail 'concurrent workers did not receive distinct VM/workspace resources'
if control start >/dev/null 2>&1; then
  fail 'controller admitted a third session beyond the exact quota'
fi

control stop "${session_one}"
[[ "$(systemctl is-active "host-sessiond@${session_one}.service" || true)" == inactive ]] \
  || fail 'normal stop left the first worker active'
kill -0 "${firecracker_two}" || fail 'stopping the first worker killed the second Firecracker'

worker_two_pid="$(systemctl show --property=MainPID --value "host-sessiond@${session_two}.service")"
[[ "${worker_two_pid}" =~ ^[1-9][0-9]*$ ]] || fail 'second worker PID disappeared before crash injection'
kill -KILL -- "${worker_two_pid}"
wait_for_recovery "${session_two}" || fail 'controller did not recover the killed production worker'

session_restart=""
for _attempt in $(seq 1 600); do
  if candidate_session="$(control start 2>/dev/null)" \
    && [[ "${candidate_session}" =~ ^[0-9a-f]{32}$ ]]; then
    session_restart="${candidate_session}"
    sessions+=("${session_restart}")
    break
  fi
  sleep 0.1
done
[[ "${session_restart}" =~ ^[0-9a-f]{32}$ ]] \
  || fail 'controller did not release quota after worker-crash recovery'
assert_worker_ready "${session_restart}"

systemctl restart host-controld.service
wait_for_controller || fail 'controller did not restart on its production unit'
wait_for_recovery "${session_restart}" \
  || fail 'controller restart did not reconcile its live production worker'

session_final="$(control start)"
sessions+=("${session_final}")
[[ "${session_final}" =~ ^[0-9a-f]{32}$ ]] \
  || fail 'restarted controller did not admit a fresh session'
assert_worker_ready "${session_final}"
control stop "${session_final}"
[[ "$(systemctl is-active "host-sessiond@${session_final}.service" || true)" == inactive ]] \
  || fail 'final normal stop left its worker active'

for session in "${sessions[@]}"; do
  [[ "$(systemctl is-active "host-sessiond@${session}.service" || true)" != active ]] \
    || fail "worker remained active after verification: ${session}"
done
if dmsetup ls --target verity --noheadings 2>/dev/null \
  | awk '{ print $1 }' | grep -Eq '^host-sessiond-rootfs-'; then
  fail 'a production validation dm-verity mapper remained after all stops'
fi

printf '%s\n' \
  'installed production chain: authenticated controller -> exact systemd worker -> real KVM passed'
printf '%s\n' \
  'installed production chain: concurrent isolation, normal stop, worker-crash recovery, and controller-restart reconciliation passed'
