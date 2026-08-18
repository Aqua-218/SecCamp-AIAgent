#!/usr/bin/env bash

# Bounded privileged soak for namespace, cgroup, Landlock, seccomp, descriptor, rollback, and
# post-exec escape boundaries. Unavailable prerequisites fail through the shared gate.

set -euo pipefail

repository_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly repository_root
iterations="${RUNTIME_ISOLATION_SOAK_ITERATIONS:-20}"
[[ "${iterations}" =~ ^[1-9][0-9]*$ && "${iterations}" -le 100 ]] || {
  printf '%s\n' 'RUNTIME_ISOLATION_SOAK_ITERATIONS must be an integer from 1 through 100' >&2
  exit 2
}
readonly iterations

for ((iteration = 1; iteration <= iterations; iteration++)); do
  printf 'runtime isolation soak: iteration %d/%d\n' "${iteration}" "${iterations}"
  "${repository_root}/scripts/ci/verify-privileged-isolation.sh"
done

printf 'runtime isolation soak: %d iteration(s) passed without residue\n' "${iterations}"
