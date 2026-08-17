#!/usr/bin/env bash

# Applies the 13 isolation steps through the real `LinuxBackend` and asks the kernel what it
# enforces against the isolated child. The target also runs the production
# `workload-isolation-launcher`, reaches the fixed workload through a real `execve`, and repeats
# the hostile checks after exec. It also runs the real LinuxBackend mount-failure rollback probe.
#
# This is intentionally a privileged Linux verification job. Every other runtime-isolation test
# drives a recording mock that never enters the kernel, so nothing else in this repository can
# tell whether a step actually creates the boundary it claims. The target refuses to report a
# skip as a pass: on a host that cannot satisfy the prerequisites it prints the same
# `CapabilityReport` reasons the backend would refuse to start with, and this script turns that
# into a distinct exit code rather than a green result.
#
# The probe never mutates the host mount table. It builds its read-only rootfs inside a mount
# namespace it unshares for itself, and the only host state it creates is one cgroup under
# `/sys/fs/cgroup`, which the launcher removes after reaping its child.

set -euo pipefail

repository_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly repository_root
readonly tool_bin="${CI_TOOLS_DIR:-${repository_root}/.ci-tools}/cargo/bin"
export PATH="${tool_bin}:${PATH}"

readonly cgroup_root="${PRIVILEGED_ISOLATION_CGROUP_ROOT:-/sys/fs/cgroup}"

[[ "$(id -u)" -eq 0 ]] || {
  printf '%s\n' 'privileged isolation verification requires root' >&2
  exit 2
}
[[ -d "${cgroup_root}" && -w "${cgroup_root}" ]] || {
  printf 'privileged isolation verification requires a writable cgroup v2 root at %s\n' "${cgroup_root}" >&2
  exit 2
}
delegated="$(cat "${cgroup_root}/cgroup.subtree_control" 2>/dev/null || true)"
readonly delegated
for controller in memory pids; do
  if ! printf '%s' "${delegated}" | grep -qw -- "${controller}"; then
    printf 'privileged isolation verification requires memory and pids delegated in %s/cgroup.subtree_control (found: %s)\n' \
      "${cgroup_root}" "${delegated}" >&2
    printf 'enable them with: echo "+memory +pids" > %s/cgroup.subtree_control\n' "${cgroup_root}" >&2
    exit 2
  fi
done

cd -- "${repository_root}"

# The target is `test = false`, so it is named explicitly rather than picked up by a default
# test run. Build the production launcher first: the hostile post-exec scenario executes this
# exact binary, not a test-only substitute.
cargo build --locked -p runtime-isolation --bin workload-isolation-launcher
export RUNTIME_ISOLATION_LAUNCHER="${repository_root}/target/debug/workload-isolation-launcher"

# Its output is the record of which boundaries the kernel confirmed.
status=0
output="$(cargo test --locked -p runtime-isolation --test privileged_isolation 2>&1)" || status=$?
printf '%s\n' "${output}"

if printf '%s' "${output}" | grep -q 'privileged .*verification unavailable'; then
  printf '%s\n' 'privileged isolation verification did not run; refusing to report an unverified boundary as passed' >&2
  exit 2
fi

if [[ "${status}" -ne 0 ]]; then
  exit "${status}"
fi

printf '%s\n' 'privileged isolation verification: boundary confirmed by the kernel'
