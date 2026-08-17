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
  baseline_path="${baseline_root}/${package}.sha256"
  if [[ ! -f "${baseline_path}" ]]; then
    printf '%s: missing baseline; run %s --update intentionally\n' \
      "${package}" "$0" >&2
    failures=$((failures + 1))
    continue
  fi

  RUSTUP_TOOLCHAIN="${nightly_channel}" \
    cargo public-api --package "${package}" --simplified --simplified --simplified \
      --color never > "${output_path}"
  actual_digest="$(sha256sum "${output_path}" | awk '{print $1}')"
  expected_digest="$(awk 'NF { print $1; exit }' "${baseline_path}")"
  if [[ ! "${expected_digest}" =~ ^[0-9a-f]{64}$ ]]; then
    printf '%s: malformed baseline digest in %s\n' "${package}" "${baseline_path}" >&2
    failures=$((failures + 1))
    continue
  fi

  if [[ "${actual_digest}" != "${expected_digest}" ]]; then
    if [[ "${update}" == true ]]; then
      printf '%s  %s\n' "${actual_digest}" "${package}" > "${baseline_path}"
      printf '%s: baseline updated to %s\n' "${package}" "${actual_digest}"
    else
      printf '%s: public API digest changed (expected %s, got %s)\n' \
        "${package}" "${expected_digest}" "${actual_digest}" >&2
      printf '  review the generated API and rerun: %s --update\n' "$0" >&2
      failures=$((failures + 1))
    fi
  else
    printf '%s: public API matches baseline %s\n' "${package}" "${expected_digest}"
  fi
  done

if [[ "${failures}" -gt 0 ]]; then
  printf 'API surface: %d problem(s)\n' "${failures}" >&2
  exit 1
fi

printf 'API surface: %d library package baseline(s) verified\n' "${#packages[@]}"
