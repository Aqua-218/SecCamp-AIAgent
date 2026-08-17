#!/usr/bin/env bash

set -euo pipefail

readonly repository_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
cd -- "${repository_root}"

if [[ "$(uname -s)" != 'Linux' ]]; then
  printf 'Sanitizer gate requires Linux; refusing to run on %s\n' "$(uname -s)" >&2
  exit 1
fi

if [[ "$#" -ne 2 ]]; then
  printf 'usage: %s <address|leak> <package>\n' "$0" >&2
  exit 2
fi

readonly mode="$1"
readonly package="$2"
case "${mode}:${package}" in
  address:egress-protocol|leak:egress-protocol)
    ;;
  *)
    printf 'unsupported sanitizer mode/package pair: %s %s\n' "${mode}" "${package}" >&2
    exit 2
    ;;
esac

readonly nightly_toolchain="$(scripts/ci/install-nightly-toolchain.sh)"
printf 'Sanitizer: mode=%s package=%s toolchain=%s\n' \
  "${mode}" "${package}" "${nightly_toolchain}"

listed_tests="$(
  RUSTUP_TOOLCHAIN="${nightly_toolchain}" RUSTFLAGS="-Zsanitizer=${mode}" \
    cargo test --locked --package "${package}" --lib --no-default-features -- --list
)"
readonly listed_tests
if ! grep -qE ': test$' <<< "${listed_tests}"; then
  printf 'sanitizer configuration selected no tests: %s %s\n' "${mode}" "${package}" >&2
  exit 1
fi

# The protocol crate's no-default-features library tests exercise the bounded
# decoder and frame/session state without requiring a privileged runtime.
# Keep the sanitizer flag on the test binary, rather than compiling only a
# check or an empty target.
RUSTUP_TOOLCHAIN="${nightly_toolchain}" \
RUSTFLAGS="-Zsanitizer=${mode}" \
  cargo test --locked --package "${package}" --lib --no-default-features -- \
  --test-threads=1
