#!/usr/bin/env bash
#
# Keeps the checked-in production service boundary aligned with the invariants enforced by the
# daemons. This is deliberately a static gate: the privileged real-systemd gate exercises the
# protocol and polkit path, while this gate prevents the deployable units from drifting away from
# that tested composition.

set -euo pipefail

readonly repository_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
cd -- "${repository_root}"

failures=0

fail() {
  printf 'FAIL %s\n' "$1" >&2
  failures=$((failures + 1))
}

require_line() {
  local file="$1"
  local expected="$2"
  grep -qxF -- "${expected}" "${file}" \
    || fail "${file}: missing exact contract line: ${expected}"
}

reject_line() {
  local file="$1"
  local rejected="$2"
  if grep -qxF -- "${rejected}" "${file}"; then
    fail "${file}: forbidden contract line is present: ${rejected}"
  fi
}

require_sha256() {
  local file="$1"
  local expected="$2"
  local actual
  actual="$(sha256sum -- "${file}" | cut -d' ' -f1)"
  [[ "${actual}" == "${expected}" ]] \
    || fail "${file}: complete security-boundary digest changed: ${actual}"
}

readonly controller='service/host-controld.service'
readonly worker='service/host-sessiond@.service'
readonly recovery='service/host-sessiond-recover@.service'
readonly single_worker='service/host-sessiond.service'
readonly polkit_rule='deploy/polkit-1/rules.d/50-host-controld.rules'
readonly udev_rule='deploy/70-host-sessiond-device-mapper.rules'
readonly controller_environment='deploy/host-controld.env.example'
readonly worker_environment='deploy/host-sessiond-worker.env.example'
readonly deployment_readme='deploy/README.md'

for required in \
  "${controller}" \
  "${worker}" \
  "${recovery}" \
  "${single_worker}" \
  "${polkit_rule}" \
  "${udev_rule}" \
  "${controller_environment}" \
  "${worker_environment}" \
  "${deployment_readme}"; do
  [[ -f "${required}" ]] || fail "${required}: required deployment artifact is missing"
done

# These whole-file locks make additive directives fail too. Updating one requires changing this
# owner-reviewed gate, so a second permissive capability assignment or polkit rule cannot hide
# behind the required secure lines below.
require_sha256 "${controller}" '8fb7ef8ba3735570675b29436bbcd7df150dafaed7abcf73882a0d3b917c35fc'
require_sha256 "${worker}" 'ceee8cf909824ab611ab83c0786bbdfb687b5e3404f28860c1868cf1445762cb'
require_sha256 "${recovery}" '1ba6404050d1471066a108e2ea0e7122080178173ee47362fa8945333758cae0'
require_sha256 "${single_worker}" '98989c0f7221ebef228d04dcae942dddd3ea51c7f7a871a6857ca89f4f5aec39'
require_sha256 "${polkit_rule}" '58041aab07b6b490a75dd941c71d921af9a11a036e4cc048c29f4f97fbe3ab6b'
require_sha256 "${udev_rule}" 'ee003a6e5852e5ac0f5710e0f9e6ba644ab3a7672c643693c8637e7819a6a602'
require_sha256 "${controller_environment}" 'fc12a7d45db0c41e79877c0e9ac6eaf427fb2275127f9f32e51d6636469fbb21'
require_sha256 "${worker_environment}" '9b93306e5b38d2efa704a3eca4f9ad7f84216c528fb3ec4a19c422e9ef3b83fd'
require_sha256 "${deployment_readme}" '27a565a782f051edd57e41edd68d199fc266bd5ea9c868d5207b3a33a35f6fb5'

# host-controld checks both the socket parent and the HMAC key against --client-gid. Its primary
# group therefore has to be the client group; a supplementary group does not affect systemd's
# RuntimeDirectory ownership.
require_line "${controller}" 'User=host-controld'
require_line "${controller}" 'Group=host-control'
reject_line "${controller}" 'SupplementaryGroups=host-control'
require_line "${controller}" 'StateDirectoryMode=0700'
require_line "${controller}" 'RuntimeDirectoryMode=0750'
require_line "${controller}" 'NoNewPrivileges=yes'
require_line "${controller}" 'CapabilityBoundingSet='
require_line "${controller}" 'AmbientCapabilities='
require_line "${controller}" 'RestrictAddressFamilies=AF_UNIX'
require_line "${controller}" 'ProtectSystem=strict'
require_line "${controller}" 'ProtectControlGroups=yes'
require_line "${controller}" 'ExecStart=/usr/local/bin/host-controld \'

for unit in "${worker}" "${recovery}"; do
  require_line "${unit}" 'User=host-sessiond'
  require_line "${unit}" 'Group=host-sessiond'
  require_line "${unit}" 'SupplementaryGroups=kvm'
  require_line "${unit}" 'EnvironmentFile=/etc/host-sessiond/worker.env'
  require_line "${unit}" 'Slice=system.slice'
  require_line "${unit}" 'NoNewPrivileges=yes'
  require_line "${unit}" 'ProtectSystem=strict'
  require_line "${unit}" 'DevicePolicy=closed'
  require_line "${unit}" 'DeviceAllow=/dev/kvm rw'
  require_line "${unit}" 'DeviceAllow=/dev/vhost-vsock rw'
  require_line "${unit}" 'DeviceAllow=/dev/mapper/control rw'
  require_line "${unit}" 'DeviceAllow=/dev/loop-control rw'
  require_line "${unit}" 'DeviceAllow=block-loop rw'
  require_line "${unit}" 'DeviceAllow=block-device-mapper rw'
  reject_line "${unit}" 'DeviceAllow=/dev/mapper/host-sessiond-rootfs-* rw'
  require_line "${unit}" 'ReadWritePaths=/var/lib/host-sessiond/instances/%i /var/lib/host-jails/%i /run/host-sessiond/instances/%i'
  require_line "${unit}" 'ReadOnlyPaths=/var/lib/host-sessiond/workspace-source'
  if grep -E '^ReadWritePaths=.*workspace-source' -- "${unit}" >/dev/null; then
    fail "${unit}: immutable workspace source is writable"
  fi
done

require_line "${worker}" 'Type=notify'
require_line "${worker}" 'StateDirectory=host-sessiond/instances/%i/broker-wal'
require_line "${worker}" 'StateDirectory=host-jails/%i/fc'
require_line "${worker}" 'After=local-fs.target'
reject_line "${worker}" 'Wants=dev-kvm.device dev-vhost\x2dvsock.device'
reject_line "${worker}" 'After=local-fs.target dev-kvm.device dev-vhost\x2dvsock.device'
require_line "${worker}" 'ExecStart=/usr/local/bin/host-sessiond --systemd-instance %i --mode run'
require_line "${worker}" 'Restart=no'
require_line "${worker}" 'DelegateSubgroup=daemon'
require_line "${worker}" 'CapabilityBoundingSet=CAP_SYS_ADMIN CAP_SYS_CHROOT CAP_SETUID CAP_SETGID CAP_DAC_OVERRIDE CAP_DAC_READ_SEARCH CAP_CHOWN CAP_FOWNER CAP_MKNOD CAP_KILL'
require_line "${worker}" 'AmbientCapabilities=CAP_SYS_ADMIN CAP_SYS_CHROOT CAP_SETUID CAP_SETGID CAP_DAC_OVERRIDE CAP_DAC_READ_SEARCH CAP_CHOWN CAP_FOWNER CAP_MKNOD CAP_KILL'
require_line "${recovery}" 'Type=oneshot'
require_line "${recovery}" 'StateDirectory=host-sessiond/instances/%i/broker-wal'
require_line "${recovery}" 'StateDirectory=host-jails/%i/fc'
require_line "${recovery}" 'ExecStart=/usr/local/bin/host-sessiond --systemd-instance %i --mode recover'
require_line "${recovery}" 'CapabilityBoundingSet=CAP_SYS_ADMIN CAP_SYS_CHROOT CAP_SETUID CAP_SETGID CAP_DAC_READ_SEARCH CAP_KILL'
require_line "${recovery}" 'AmbientCapabilities=CAP_SYS_ADMIN CAP_SYS_CHROOT CAP_SETUID CAP_SETGID CAP_DAC_READ_SEARCH CAP_KILL'

# Keep the legacy one-session unit at least as restrictive around the source template.
require_line "${single_worker}" 'After=local-fs.target'
require_line "${single_worker}" 'StateDirectory=host-sessiond/broker-wal'
require_line "${single_worker}" 'StateDirectory=host-sessiond/jailer/firecracker'
reject_line "${single_worker}" 'Wants=dev-kvm.device dev-vhost\x2dvsock.device'
reject_line "${single_worker}" 'After=local-fs.target dev-kvm.device dev-vhost\x2dvsock.device'
require_line "${single_worker}" 'ReadOnlyPaths=/var/lib/host-sessiond/workspace-source'
require_line "${single_worker}" 'DelegateSubgroup=daemon'
require_line "${single_worker}" 'CapabilityBoundingSet=CAP_SYS_ADMIN CAP_SYS_CHROOT CAP_SETUID CAP_SETGID CAP_DAC_OVERRIDE CAP_DAC_READ_SEARCH CAP_CHOWN CAP_FOWNER CAP_MKNOD CAP_KILL'
require_line "${single_worker}" 'AmbientCapabilities=CAP_SYS_ADMIN CAP_SYS_CHROOT CAP_SETUID CAP_SETGID CAP_DAC_OVERRIDE CAP_DAC_READ_SEARCH CAP_CHOWN CAP_FOWNER CAP_MKNOD CAP_KILL'
require_line "${single_worker}" 'DevicePolicy=closed'
require_line "${single_worker}" 'DeviceAllow=/dev/loop-control rw'
require_line "${single_worker}" 'DeviceAllow=block-loop rw'
require_line "${single_worker}" 'DeviceAllow=block-device-mapper rw'
reject_line "${single_worker}" 'DeviceAllow=/dev/mapper/host-sessiond-rootfs-* rw'
if grep -E '^ReadWritePaths=.*workspace-source' -- "${single_worker}" >/dev/null; then
  fail "${single_worker}: immutable workspace source is writable"
fi

# The policy accepts only fixed 128-bit lowercase-hex instances and only the lifecycle verbs the
# controller adapter emits. Any broader wildcard or stop permission on recovery would enlarge the
# privileged operation vocabulary.
require_line "${polkit_rule}" '        subject.user !== "host-controld") {'
require_line "${polkit_rule}" '    var worker = /^host-sessiond@[0-9a-f]{32}\.service$/;'
require_line "${polkit_rule}" '    var recovery = /^host-sessiond-recover@[0-9a-f]{32}\.service$/;'
require_line "${polkit_rule}" '    if ((verb === "start" && (worker.test(unit) || recovery.test(unit))) ||'
require_line "${polkit_rule}" '        (verb === "stop" && worker.test(unit))) {'

require_line "${udev_rule}" 'KERNEL=="device-mapper", OWNER="root", GROUP="host-sessiond", MODE="0660"'
require_line "${udev_rule}" 'KERNEL=="dm-*", ENV{DM_NAME}=="host-sessiond-rootfs-*", OWNER="host-sessiond", GROUP="host-sessiond", MODE="0660"'
require_line "${udev_rule}" 'KERNEL=="loop-control", OWNER="root", GROUP="host-sessiond", MODE="0660"'
require_line "${udev_rule}" 'KERNEL=="loop[0-9]*", OWNER="root", GROUP="host-sessiond", MODE="0660"'

require_line "${controller_environment}" 'HOST_CONTROLD_CLIENT_GID=2000'
require_line "${controller_environment}" 'HOST_CONTROLD_SYSTEMCTL_SHA256=0000000000000000000000000000000000000000000000000000000000000000'
require_line "${worker_environment}" 'HOST_SESSIOND_WORKSPACE_SOURCE=/var/lib/host-sessiond/workspace-source'
require_line "${worker_environment}" 'HOST_SESSIOND_JAILER_UID=961'
require_line "${worker_environment}" 'HOST_SESSIOND_JAILER_GID=961'
require_line "${worker_environment}" 'HOST_SESSIOND_GUEST_CID=42'
require_line "${worker_environment}" 'HOST_SESSIOND_BROKER_PORT=5001'
require_line "${worker_environment}" 'HOST_SESSIOND_FIRECRACKER=/opt/firecracker/fc'
require_line "${worker_environment}" 'HOST_SESSIOND_JAILER_CHROOT_BASE=/var/lib/host-jails'
require_line "${worker_environment}" 'HOST_SESSIOND_BROKER_REPLAY_CAPACITY=256'
require_line "${worker_environment}" 'HOST_SESSIOND_BROKER_BUDGET_REQUESTS=1000'
require_line "${worker_environment}" 'HOST_SESSIOND_BROKER_MAX_CONNECTION_REQUESTS=256'
require_line "${worker_environment}" 'HOST_SESSIOND_GUEST_CONTROL_PORT=5000'
require_line "${worker_environment}" 'HOST_SESSIOND_BOOT_ARGS=console=ttyS0 reboot=k panic=1 pci=off root=/dev/vda rootfstype=squashfs ro init=/usr/local/libexec/guest-control-init -- --port 5000 --workload /usr/local/libexec/guest-supervisor-init --workspace-device /dev/vdb --runtime-dir /run/guest-supervisor --cgroup-parent /sys/fs/cgroup --broker-port 5001 --isolation-launcher /usr/local/libexec/workload-isolation-launcher --workload /usr/local/libexec/agent-workload --repository workspace --file-effects read-data,list-directory,write-data,truncate,create-file,create-directory,remove-file,remove-directory,rename,set-metadata,read-link,create-symlink,create-hard-link --path-prefix /'
require_line "${deployment_readme}" 'udevadm trigger --subsystem-match=misc --subsystem-match=block --action=add'
require_line "${deployment_readme}" 'udevadm settle'
require_line "${deployment_readme}" 'install -d -o root -g host-sessiond -m 0550 \'
require_line "${deployment_readme}" 'reviewed_manifest_sha256=REPLACE_WITH_EXTERNALLY_AUTHENTICATED_MANIFEST_SHA256'
require_line "${deployment_readme}" 'set -Eeuo pipefail'
require_line "${deployment_readme}" '(cd "${install_staging}" && sha256sum --check --strict host-sessiond-binaries.sha256)'
require_line "${deployment_readme}" 'The legacy unit must reuse `/usr/local/bin/host-sessiond` installed by the authenticated revision,'
if grep -E '^(CapabilityBoundingSet|AmbientCapabilities)=.*(CAP_CHOWN|CAP_FOWNER|CAP_MKNOD|CAP_DAC_OVERRIDE)' -- \
  "${recovery}" >/dev/null; then
  fail "${recovery}: jailer-only capabilities leaked into recovery mode"
fi
if grep -Ei '(token|password|secret)=' -- \
  "${controller_environment}" "${worker_environment}" >/dev/null; then
  fail 'deployment environment examples must not contain inline credentials'
fi

if [[ "${failures}" -gt 0 ]]; then
  printf '\nservice boundaries: %d problem(s)\n' "${failures}" >&2
  exit 1
fi

printf 'service boundaries: controller, worker, recovery, polkit, and environment contracts agree\n'
