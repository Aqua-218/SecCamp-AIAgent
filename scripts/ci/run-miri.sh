#!/usr/bin/env bash

set -euo pipefail

readonly repository_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
cd -- "${repository_root}"

if [[ "$(uname -s)" != 'Linux' ]]; then
  printf 'Miri gate requires Linux; refusing to run on %s\n' "$(uname -s)" >&2
  exit 1
fi

if [[ "$#" -ne 2 ]]; then
  printf 'usage: %s <package> <test-filter>\n' "$0" >&2
  exit 2
fi

readonly package="$1"
readonly test_filter="$2"

# Miri cannot model the filesystem and syscall boundary exercised by the
# runtime crates. Keep the supported set explicit so a matrix edit cannot
# silently turn this into an unsupported whole-crate run.
case "${package}:${test_filter}" in
  authority-core:capability::tests|\
  authority-core:file::tests|\
  authority-core:github::tests|\
  authority-core:http::tests|\
  authority-core:path::tests|\
  authority-core:policy::tests|\
  authority-core:repository::tests|\
  authority-core:state::tests|\
  authority-core:time::tests|\
  egress-protocol:budget::tests|\
  egress-protocol:cbor::tests|\
  egress-protocol:frame::tests|\
  egress-protocol:operation::tests|\
  egress-protocol:session::tests)
    ;;
  *)
    printf 'unsupported Miri package/filter pair: %s %s\n' "${package}" "${test_filter}" >&2
    exit 2
    ;;
esac

readonly nightly_toolchain="$(scripts/ci/install-nightly-toolchain.sh)"
printf 'Miri: package=%s filter=%s toolchain=%s\n' \
  "${package}" "${test_filter}" "${nightly_toolchain}"

# Do not disable Miri isolation. These tests are deliberately pure; disabling
# isolation would turn a passing check into a test of the host filesystem.
RUSTUP_TOOLCHAIN="${nightly_toolchain}" \
  cargo miri test --locked --package "${package}" --lib "${test_filter}" -- \
  --test-threads=1
