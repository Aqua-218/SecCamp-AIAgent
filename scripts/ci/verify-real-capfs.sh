#!/usr/bin/env bash

# Runs the Linux CapFS integration suite against the host FUSE kernel device.
#
# The ordinary workspace test keeps FUSE tests portable by skipping them when a
# hosted kernel has no /dev/fuse. This gate is different: it is evidence for
# the real mount boundary, so an unavailable device is an unavailable gate and
# never a successful verification. The test-side CAPFS_REQUIRE_FUSE check is
# kept as a second line of defense against an accidental skip.

set -euo pipefail

repository_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly repository_root

if [[ "$(uname -s)" != Linux ]]; then
  printf '%s\n' 'real CapFS FUSE verification requires a Linux host' >&2
  exit 2
fi
if [[ "$(id -u)" -ne 0 ]]; then
  printf '%s\n' 'real CapFS FUSE verification requires root to own and clean up the mount' >&2
  exit 2
fi
if [[ ! -c /dev/fuse ]]; then
  printf '%s\n' 'real CapFS FUSE verification requires the /dev/fuse character device' >&2
  exit 2
fi
if [[ ! -r /dev/fuse || ! -w /dev/fuse ]]; then
  printf '%s\n' 'real CapFS FUSE verification requires a readable and writable /dev/fuse' >&2
  exit 2
fi
command -v cargo >/dev/null || {
  printf '%s\n' 'real CapFS FUSE verification requires cargo' >&2
  exit 2
}

cd -- "${repository_root}"

# Serialize mounts so the gate is deterministic on hosts with a single FUSE
# session queue. The test binary still exercises its explicit write/revoke
# interleaving with a real backing file and a real kernel mount.
CAPFS_REQUIRE_FUSE=1 \
  cargo test \
    --locked \
    --manifest-path "${repository_root}/Cargo.toml" \
    -p capfs \
    --test read_only_fuse \
    -- \
    --test-threads=1 \
    --nocapture

printf '%s\n' 'real CapFS FUSE verification: kernel mount and revoke regressions passed'
