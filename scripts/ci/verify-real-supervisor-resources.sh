#!/usr/bin/env bash

set -euo pipefail

repository_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repository_root}"

# Keep real mount observations inside a private namespace. Cgroup changes are not isolated by a
# mount namespace, so the wrapper supplies one exact parent name and cleans only its known leaves.
if [[ "${SUPERVISOR_REAL_RESOURCES_NAMESPACE:-0}" != 1 ]]; then
    if ! command -v unshare >/dev/null 2>&1; then
        echo "prerequisite unavailable: unshare is required for the real supervisor resource gate" >&2
        exit 2
    fi
    if ! unshare --mount --propagation private true >/dev/null 2>&1; then
        echo "prerequisite unavailable: a private mount namespace cannot be created" >&2
        exit 2
    fi
    exec env SUPERVISOR_REAL_RESOURCES_NAMESPACE=1 \
        unshare --mount --propagation private "${BASH_SOURCE[0]}" "$@"
fi

if [[ "$(uname -s)" != Linux ]]; then
    echo "prerequisite unavailable: real supervisor resource verification requires Linux" >&2
    exit 2
fi
if [[ "$(id -u)" != 0 ]]; then
    echo "prerequisite unavailable: real supervisor resource verification requires root" >&2
    exit 2
fi
if [[ ! -c /dev/fuse || ! -r /dev/fuse || ! -w /dev/fuse ]]; then
    echo "prerequisite unavailable: /dev/fuse must be a readable and writable character device" >&2
    exit 2
fi
if [[ ! -f /sys/fs/cgroup/cgroup.controllers || ! -w /sys/fs/cgroup ]]; then
    echo "prerequisite unavailable: writable cgroup v2 is required" >&2
    exit 2
fi
controllers="$(< /sys/fs/cgroup/cgroup.controllers)"
if [[ " ${controllers} " != *" memory "* || " ${controllers} " != *" pids "* ]]; then
    echo "prerequisite unavailable: memory and pids cgroup controllers must be delegated" >&2
    exit 2
fi
if ! command -v cargo >/dev/null 2>&1; then
    echo "prerequisite unavailable: cargo is required" >&2
    exit 2
fi

probe="/sys/fs/cgroup/supervisor-real-resources-prerequisite-$$"
if ! mkdir "${probe}" 2>/dev/null; then
    echo "prerequisite unavailable: cgroup v2 leaf creation is not permitted" >&2
    exit 2
fi
rmdir "${probe}"

test_cgroup_parent="/sys/fs/cgroup/supervisor-real-resources-${BASHPID}"
if [[ -e "${test_cgroup_parent}" ]]; then
    echo "prerequisite unavailable: exact test cgroup parent already exists: ${test_cgroup_parent}" >&2
    exit 2
fi

cgroup_empty() {
    local cgroup_path="$1"
    local procs populated key value remainder seen_populated
    [[ -d "${cgroup_path}" && ! -L "${cgroup_path}" ]] || return 1
    [[ -r "${cgroup_path}/cgroup.procs" && -r "${cgroup_path}/cgroup.events" ]] || return 1
    procs="$(< "${cgroup_path}/cgroup.procs")"
    [[ -z "${procs//[[:space:]]/}" ]] || return 1
    populated=""
    seen_populated=0
    while read -r key value remainder; do
        [[ -n "${key}" && -n "${value}" && -z "${remainder}" ]] || return 1
        if [[ "${key}" == populated ]]; then
            [[ "${seen_populated}" == 0 && ("${value}" == 0 || "${value}" == 1) ]] || return 1
            populated="${value}"
            seen_populated=1
        fi
    done < "${cgroup_path}/cgroup.events"
    [[ "${seen_populated}" == 1 && "${populated}" == 0 ]]
}

cleanup_test_cgroup() {
    local failure=0
    local cgroup_path
    local subject_path="${test_cgroup_parent}/real-supervisor-resource"
    for cgroup_path in \
        "${subject_path}/occupied-child" \
        "${subject_path}" \
        "${test_cgroup_parent}"; do
        if [[ ! -e "${cgroup_path}" ]]; then
            continue
        fi
        if ! cgroup_empty "${cgroup_path}"; then
            echo "cleanup refused non-empty or replaced cgroup: ${cgroup_path}" >&2
            failure=1
            continue
        fi
        if ! rmdir -- "${cgroup_path}"; then
            echo "cleanup could not remove exact cgroup leaf: ${cgroup_path}" >&2
            failure=1
        fi
    done
    return "${failure}"
}

on_exit() {
    local test_status="$?"
    set +e
    if ! cleanup_test_cgroup; then
        echo "real supervisor resource gate left cgroup state for manual inspection" >&2
        if [[ "${test_status}" == 0 ]]; then
            test_status=1
        fi
    fi
    exit "${test_status}"
}
trap on_exit EXIT

SUPERVISOR_REAL_RESOURCES_CGROUP_PARENT="${test_cgroup_parent}" \
    cargo test --manifest-path crates/supervisor/Cargo.toml --package supervisor \
        --test real_resources --locked -- \
        --ignored --exact real_linux_host_resources_exercises_kernel_side_effects --nocapture
