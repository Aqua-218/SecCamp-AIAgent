#!/bin/sh

set -eu

fail() {
  printf 'fixture recovery: %s\n' "$1" >&2
  exit 1
}

session="${1:-}"
case "${session}" in
  [0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]) ;;
  *) fail 'invalid session ID' ;;
esac

state="/run/host-sessiond-control-test/state/${session}"
pid_file="${state}.resource-pid"
test -f "${pid_file}" || fail 'resource PID file is missing'
resource_pid="$(cat "${pid_file}")"
case "${resource_pid}" in
  ''|*[!0-9]*) fail 'resource PID is not decimal' ;;
esac

test -r "/proc/${resource_pid}/cmdline" || fail 'resource process is absent'
test "$(tr '\000' ' ' <"/proc/${resource_pid}/cmdline")" = '/usr/bin/sleep infinity ' \
  || fail 'resource command line is not the closed fixture command'
kill -TERM "${resource_pid}"
attempt=0
while kill -0 "${resource_pid}" 2>/dev/null; do
  attempt=$((attempt + 1))
  test "${attempt}" -lt 100 || fail 'resource process survived bounded termination'
  sleep 0.02
done
rm -f -- "${pid_file}"
printf '%s\n' "${session}" >"${state}.recovered"
