#!/usr/bin/env bash

# Runs the production Runtime lifecycle against the current and immediately previous supported
# pinned Firecracker release. Each nested gate performs its own digest verification and no-skip
# KVM prerequisite checks.

set -euo pipefail

repository_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly repository_root
[[ -x "${repository_root}/scripts/ci/verify-real-runtime-lifecycle.sh" ]] || {
  printf '%s\n' 'real Runtime lifecycle wrapper is unavailable' >&2
  exit 2
}

for version in 1.15.1 1.16.1; do
  printf 'real Runtime version matrix: Firecracker %s\n' "${version}"
  FIRECRACKER_VERSION="${version}" \
    "${repository_root}/scripts/ci/verify-real-runtime-lifecycle.sh"
done

printf '%s\n' 'real Runtime version matrix: every pinned version passed'
