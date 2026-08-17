#!/usr/bin/env bash

set -euo pipefail

readonly repository_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
cd -- "${repository_root}"

if [[ "$(uname -s)" != 'Linux' ]]; then
  printf 'Fuzz gate requires Linux; refusing to run on %s\n' "$(uname -s)" >&2
  exit 1
fi

if [[ "$#" -ne 2 ]]; then
  printf 'usage: %s <package> <target>\n' "$0" >&2
  exit 2
fi

readonly package="$1"
readonly target="$2"
case "${package}:${target}" in
  authority-core:canonical_path|\
  egress-protocol:cbor_request_decode|\
  egress-protocol:frame_decode|\
  egress-protocol:response_decode|\
  egress-protocol:session_accept)
    ;;
  *)
    printf 'unsupported fuzz package/target pair: %s %s\n' "${package}" "${target}" >&2
    exit 2
    ;;
esac

readonly corpus_source="${repository_root}/fuzz/corpus/${target}"
if [[ ! -d "${corpus_source}" ]] || ! find "${corpus_source}" -mindepth 1 -type f -print -quit | grep -q .; then
  printf 'fuzz target has no committed seed corpus: %s\n' "${corpus_source}" >&2
  exit 1
fi
if [[ ! -f "${repository_root}/fuzz/Cargo.toml" ]]; then
  printf 'fuzz workspace is missing: fuzz/Cargo.toml\n' >&2
  exit 1
fi

if ! command -v cargo-fuzz > /dev/null 2>&1; then
  printf 'cargo-fuzz is required; run scripts/ci/install-cargo-tools.sh fuzz first\n' >&2
  exit 1
fi

readonly nightly_toolchain="$(scripts/ci/install-nightly-toolchain.sh)"
readonly scratch_directory="$(mktemp -d)"
trap 'rm -rf -- "${scratch_directory}"' EXIT
readonly corpus_copy="${scratch_directory}/corpus"
readonly artifact_directory="${scratch_directory}/artifacts"
mkdir -p -- "${corpus_copy}" "${artifact_directory}"
cp -- "${corpus_source}"/* "${corpus_copy}/"

printf 'Fuzz: package=%s target=%s toolchain=%s runs=256 max_total_time=20s\n' \
  "${package}" "${target}" "${nightly_toolchain}"
RUSTUP_TOOLCHAIN="${nightly_toolchain}" \
  cargo fuzz run --fuzz-dir fuzz --sanitizer address "${target}" "${corpus_copy}" -- \
  -runs=256 -max_total_time=20 -timeout=2 -max_len=4096 -detect_leaks=0 \
  "-artifact_prefix=${artifact_directory}/"
