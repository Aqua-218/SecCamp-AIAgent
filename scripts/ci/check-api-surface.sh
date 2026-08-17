#!/usr/bin/env bash

set -euo pipefail

readonly repository_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly baseline_root="${repository_root}/ci/api-baselines"
readonly nightly_channel="$(awk -F'"' '/^readonly nightly_channel=/{ print $2; exit }' "${repository_root}/scripts/ci/install-nightly-toolchain.sh")"
readonly temporary_root="$(mktemp -d)"
trap 'rm -rf -- "${temporary_root}"' EXIT

update=false
while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --update)
      update=true
      shift
      ;;
    --help|-h)
      printf 'usage: %s [--update]\n' "$0"
      printf '  --update  intentionally rewrite per-crate API digest baselines\n'
      exit 0
      ;;
    *)
      printf 'unknown argument: %s\n' "$1" >&2
      exit 2
      ;;
  esac
  done

cd -- "${repository_root}"
if [[ ! -d "${baseline_root}" ]]; then
  printf 'API baseline directory is missing: %s\n' "${baseline_root}" >&2
  exit 1
fi
cargo metadata --locked --format-version 1 > /dev/null

mapfile -t packages < <(
  cargo metadata --no-deps --format-version 1 \
    | jq -r '.packages[] | select(any(.targets[]; (.kind | index("lib")) != null)) | .name' \
    | sort
)
if [[ "${#packages[@]}" -eq 0 ]]; then
  printf 'workspace contains no library packages for API verification\n' >&2
  exit 1
fi

failures=0
for package in "${packages[@]}"; do
  output_path="${temporary_root}/${package}.api"
  baseline_path="${baseline_root}/${package}.api"
  if [[ ! -f "${baseline_path}" ]]; then
    printf '%s: missing baseline; run %s --update intentionally\n' \
      "${package}" "$0" >&2
    failures=$((failures + 1))
    continue
  fi

  RUSTUP_TOOLCHAIN="${nightly_channel}" \
  CARGO_NET_OFFLINE=true \
    cargo public-api --package "${package}" --simplified --simplified --simplified \
      --all-features --color never > "${output_path}"

  if ! cmp -s -- "${output_path}" "${baseline_path}"; then
    if [[ "${update}" == true ]]; then
      cp -- "${output_path}" "${baseline_path}"
      printf '%s: reviewable API baseline updated\n' "${package}"
    else
      printf '%s: public API changed; normalized diff follows\n' "${package}" >&2
      diff -u -- "${baseline_path}" "${output_path}" >&2 || true
      printf 'review the API diff and rerun intentionally: %s --update\n' "$0" >&2
      failures=$((failures + 1))
    fi
  else
    printf '%s: public API matches its reviewable baseline\n' "${package}"
  fi
  done

if [[ "${failures}" -gt 0 ]]; then
  printf 'API surface: %d problem(s)\n' "${failures}" >&2
  exit 1
fi

printf 'API surface: %d library package baseline(s) verified\n' "${#packages[@]}"
