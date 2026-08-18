#!/usr/bin/env bash

# Architecture-bound wrapper for the real privileged isolation gate. Cross-compilation is not
# evidence: this entry point refuses every non-aarch64 kernel before invoking the shared no-skip
# boundary probe.

set -euo pipefail

repository_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly repository_root

case "$(uname -m)" in
  aarch64 | arm64) ;;
  *)
    printf '%s\n' 'aarch64 privileged isolation verification requires a real aarch64 kernel' >&2
    exit 2
    ;;
esac

exec "${repository_root}/scripts/ci/verify-privileged-isolation.sh"
