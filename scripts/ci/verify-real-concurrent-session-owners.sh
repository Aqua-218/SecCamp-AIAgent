#!/usr/bin/env bash

# Reuses the pinned production guest-image preparation and selects the dedicated two-KVM-owner
# test. Both owners remain live together, use distinct CID/port/cgroup/process resources, and are
# stopped independently.

set -euo pipefail
repository_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly repository_root

if ! REAL_SESSION_TEST_NAME=real_production_two_session_owners_run_concurrently_and_clean_independently \
  "${repository_root}/scripts/ci/verify-real-session-owner.sh"; then
  printf '%s\n' 'concurrent SessionOwner verification failed or its prerequisites are unavailable' >&2
  exit 1
fi
