#!/usr/bin/env bash

# Runs the production SessionOwner KVM gate once per lifecycle commit point, waits for the
# feature-gated process marker, sends SIGKILL from this wrapper, and restarts against the exact
# same durable and host-resource paths.  The ordinary gate remains the fast single lifecycle.

set -euo pipefail

repository_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly repository_root
[[ -x "${repository_root}/scripts/ci/verify-real-session-owner.sh" ]] || {
  printf '%s\n' 'real SessionOwner wrapper is unavailable' >&2
  exit 2
}

REAL_SESSION_CRASH_MATRIX=1 \
  exec "${repository_root}/scripts/ci/verify-real-session-owner.sh"
