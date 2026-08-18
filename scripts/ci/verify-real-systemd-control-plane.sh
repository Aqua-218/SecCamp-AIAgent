#!/usr/bin/env bash

# Exercises the production authenticated transport and pinned fixed-systemd worker adapter as an
# unprivileged controller. It proves two workers are distinct concurrent processes, then kills the
# controller and requires durable restart reconciliation to stop the orphan and run recovery.

set -euo pipefail
umask 077

repository_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly repository_root
readonly worker_unit=/run/systemd/system/host-sessiond@.service
readonly recovery_unit=/run/systemd/system/host-sessiond-recover@.service
readonly polkit_rule=/etc/polkit-1/rules.d/99-host-controld-test.rules
readonly test_runtime=/run/host-sessiond-control-test

[[ "$(id -u)" -eq 0 ]] || {
  printf '%s\n' 'real systemd control-plane verification requires root' >&2
  exit 2
}
[[ "$(ps -p 1 -o comm=)" == systemd ]] || {
  printf '%s\n' 'real systemd control-plane verification requires systemd as PID 1' >&2
  exit 2
}
for path in "${worker_unit}" "${recovery_unit}" "${polkit_rule}" "${test_runtime}"; do
  [[ ! -e "${path}" ]] || {
    printf 'real systemd control-plane verification refuses existing path: %s\n' "${path}" >&2
    exit 2
  }
done
for command_name in cargo dd install setpriv sha256sum systemctl; do
  command -v "${command_name}" >/dev/null || {
    printf 'real systemd control-plane verification requires %s\n' "${command_name}" >&2
    exit 2
  }
done

staging="$(mktemp -d /tmp/ai-agent-systemd-control.XXXXXX)"
controller_pid=''
session_one=''
session_two=''
session_anchor=''
session_failed=''
session_crash=''

cleanup() {
  if [[ -n "${controller_pid}" ]]; then
    kill -KILL -- "${controller_pid}" 2>/dev/null || true
    wait "${controller_pid}" 2>/dev/null || true
  fi
  for session in \
    "${session_one}" "${session_two}" "${session_anchor}" "${session_failed}" "${session_crash}"; do
    if [[ "${session}" =~ ^[0-9a-f]{32}$ ]]; then
      systemctl stop "host-sessiond@${session}.service" >/dev/null 2>&1 || true
      if [[ -f "${test_runtime}/state/${session}.resource-pid" ]]; then
        /bin/sh "${test_runtime}/recover" "${session}" >/dev/null 2>&1 || true
      fi
      systemctl reset-failed \
        "host-sessiond@${session}.service" \
        "host-sessiond-recover@${session}.service" >/dev/null 2>&1 || true
    fi
  done
  rm -f -- "${worker_unit}" "${recovery_unit}" "${polkit_rule}"
  systemctl daemon-reload >/dev/null 2>&1 || true
  rm -rf -- "${test_runtime}"
  rm -rf -- "${staging}"
}
trap cleanup EXIT

cargo build --manifest-path "${repository_root}/Cargo.toml" -p session-orchestrator \
  --bin host-controld --bin host-control --locked
chown nobody:nogroup "${staging}"
chmod 0750 "${staging}"
install -d -o nobody -g nogroup -m 0750 "${staging}/bin"
install -m 0755 "${repository_root}/target/debug/host-controld" "${staging}/bin/host-controld"
install -m 0755 "${repository_root}/target/debug/host-control" "${staging}/bin/host-control"

install -m 0644 "${repository_root}/scripts/ci/fixtures/host-sessiond-test@.service" "${worker_unit}"
install -m 0644 "${repository_root}/scripts/ci/fixtures/host-sessiond-recover-test@.service" "${recovery_unit}"
install -m 0644 "${repository_root}/scripts/ci/fixtures/99-host-controld-test.rules" "${polkit_rule}"
install -d -o root -g root -m 0755 "${test_runtime}"
install -d -o daemon -g daemon -m 0700 "${test_runtime}/state"
install -o root -g root -m 0555 \
  "${repository_root}/scripts/ci/fixtures/host-sessiond-test-worker.sh" \
  "${test_runtime}/worker"
install -o root -g root -m 0555 \
  "${repository_root}/scripts/ci/fixtures/host-sessiond-test-recover.sh" \
  "${test_runtime}/recover"
systemctl daemon-reload
systemctl restart polkit.service

install -d -o nobody -g nogroup -m 0750 "${staging}/run" "${staging}/state"
dd if=/dev/urandom of="${staging}/control.key" bs=32 count=1 status=none
chown nobody:nogroup "${staging}/control.key"
chmod 0440 "${staging}/control.key"

systemctl_digest="$(sha256sum /usr/bin/systemctl | awk '{print $1}')"
client_gid="$(getent group nogroup | awk -F: '{print $3}')"
readonly systemctl_digest client_gid

start_controller() {
  setpriv --reuid=nobody --regid=nogroup --clear-groups \
    "${staging}/bin/host-controld" \
      --socket "${staging}/run/control.sock" \
      --journal "${staging}/state/control.journal" \
      --key-file "${staging}/control.key" \
      --client-gid "${client_gid}" \
      --systemctl /usr/bin/systemctl \
      --systemctl-sha256 "${systemctl_digest}" \
      --max-sessions 2 \
      --max-sessions-per-principal 2 \
      --poll-millis 20 \
      >"${staging}/controller.log" 2>&1 &
  controller_pid=$!
  for _attempt in {1..100}; do
    [[ -S "${staging}/run/control.sock" ]] && return 0
    kill -0 "${controller_pid}" 2>/dev/null || {
      sed -n '1,120p' "${staging}/controller.log" >&2
      return 1
    }
    sleep 0.02
  done
  printf '%s\n' 'host-controld did not publish its socket' >&2
  return 1
}

control() {
  setpriv --reuid=nobody --regid=nogroup --clear-groups \
    "${staging}/bin/host-control" \
      --socket "${staging}/run/control.sock" \
      --key-file "${staging}/control.key" \
      --client-gid "${client_gid}" "$@"
}

start_controller
session_one="$(control start)"
session_two="$(control start)"
[[ "${session_one}" =~ ^[0-9a-f]{32}$ && "${session_two}" =~ ^[0-9a-f]{32}$ ]]
[[ "${session_one}" != "${session_two}" ]]

pid_one="$(systemctl show --property=MainPID --value "host-sessiond@${session_one}.service")"
pid_two="$(systemctl show --property=MainPID --value "host-sessiond@${session_two}.service")"
[[ "${pid_one}" =~ ^[1-9][0-9]*$ && "${pid_two}" =~ ^[1-9][0-9]*$ ]]
[[ "${pid_one}" != "${pid_two}" && "${pid_one}" != "${controller_pid}" && "${pid_two}" != "${controller_pid}" ]]
[[ "$(ps -o user= -p "${controller_pid}" | xargs)" == nobody ]]
[[ "$(ps -o user= -p "${pid_one}" | xargs)" == daemon ]]
[[ "$(ps -o user= -p "${pid_two}" | xargs)" == daemon ]]

control stop "${session_one}"
control stop "${session_two}"
[[ "$(systemctl is-active "host-sessiond@${session_one}.service" || true)" == inactive ]]
[[ "$(systemctl is-active "host-sessiond@${session_two}.service" || true)" == inactive ]]

# Keep one healthy worker live so the failed worker fills the two-session quota. A replacement can
# start only after the controller removes the failed owner from its live map.
session_anchor="$(control start)"
[[ "${session_anchor}" =~ ^[0-9a-f]{32}$ ]]

# A non-zero worker exit is not a clean inactive result. The fixture leaves a separately tracked
# process in the failed unit's cgroup. The adapter must observe `failed`, complete the exact
# stop+recovery path, kill that resource, report a successful recovery unit, and preserve the
# sticky failed tombstone.
session_failed="$(control start)"
failed_pid="$(systemctl show --property=MainPID --value "host-sessiond@${session_failed}.service")"
[[ "${failed_pid}" =~ ^[1-9][0-9]*$ ]]
failed_resource_pid=''
for _attempt in {1..100}; do
  if [[ -s "${test_runtime}/state/${session_failed}.resource-pid" ]]; then
    failed_resource_pid="$(<"${test_runtime}/state/${session_failed}.resource-pid")"
    break
  fi
  sleep 0.02
done
[[ "${failed_resource_pid}" =~ ^[1-9][0-9]*$ ]]
kill -0 -- "${failed_resource_pid}"
[[ "${failed_resource_pid}" != "${failed_pid}" ]]
grep -Fq "/host-sessiond@${session_failed}.service" \
  "/proc/${failed_resource_pid}/cgroup"
kill -KILL -- "${failed_pid}"
recovery_started='0'
recovery_result=''
recovery_status=''
for _attempt in {1..100}; do
  recovery_started="$(systemctl show --property=ExecMainStartTimestampMonotonic --value \
    "host-sessiond-recover@${session_failed}.service")"
  recovery_result="$(systemctl show --property=Result --value \
    "host-sessiond-recover@${session_failed}.service")"
  recovery_status="$(systemctl show --property=ExecMainStatus --value \
    "host-sessiond-recover@${session_failed}.service")"
  if [[ "$(systemctl is-active "host-sessiond@${session_failed}.service" || true)" == failed \
    && "${recovery_started}" =~ ^[1-9][0-9]*$ \
    && "${recovery_result}" == success \
    && "${recovery_status}" == 0 \
    && -f "${test_runtime}/state/${session_failed}.recovered" ]] \
    && ! kill -0 -- "${failed_resource_pid}" 2>/dev/null; then
    break
  fi
  sleep 0.02
done
if [[ "$(systemctl is-active "host-sessiond@${session_failed}.service" || true)" != failed \
  || ! "${recovery_started}" =~ ^[1-9][0-9]*$ \
  || "${recovery_result}" != success \
  || "${recovery_status}" != 0 \
  || ! -f "${test_runtime}/state/${session_failed}.recovered" \
  || "$(systemctl show --property=MainPID --value "host-sessiond@${session_failed}.service")" != 0 ]] \
  || kill -0 -- "${failed_resource_pid}" 2>/dev/null; then
  sed -n '1,160p' "${staging}/controller.log" >&2
  systemctl show --property=LoadState --property=ActiveState --property=Result --property=MainPID \
    "host-sessiond@${session_failed}.service" >&2
  systemctl show --property=ActiveState --property=Result --property=ExecMainStatus \
    --property=ExecMainStartTimestampMonotonic \
    "host-sessiond-recover@${session_failed}.service" >&2
  printf '%s\n' 'failed worker was not stopped and reconciled through recovery' >&2
  exit 1
fi

for _attempt in {1..100}; do
  if candidate_session="$(control start 2>/dev/null)" \
    && [[ "${candidate_session}" =~ ^[0-9a-f]{32}$ ]]; then
    session_crash="${candidate_session}"
    break
  fi
  sleep 0.02
done
if [[ ! "${session_crash}" =~ ^[0-9a-f]{32}$ ]]; then
  sed -n '1,160p' "${staging}/controller.log" >&2
  printf '%s\n' 'controller did not release quota after failed-worker recovery' >&2
  exit 1
fi
[[ "$(systemctl is-active "host-sessiond@${session_crash}.service")" == active ]]
control stop "${session_anchor}"
[[ "$(systemctl is-active "host-sessiond@${session_anchor}.service" || true)" == inactive ]]
kill -KILL -- "${controller_pid}"
wait "${controller_pid}" 2>/dev/null || true
controller_pid=''
rm -f -- "${staging}/run/control.sock"

start_controller
for _attempt in {1..100}; do
  [[ "$(systemctl is-active "host-sessiond@${session_crash}.service" || true)" == inactive ]] && break
  sleep 0.02
done
[[ "$(systemctl is-active "host-sessiond@${session_crash}.service" || true)" == inactive ]]

kill -TERM -- "${controller_pid}"
wait "${controller_pid}"
controller_pid=''
printf '%s\n' 'real systemd control-plane verification: ok'
