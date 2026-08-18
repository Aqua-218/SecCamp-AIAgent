#!/usr/bin/env bash

set -euo pipefail

readonly repository_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly temporary_root="$(mktemp -d)"
trap 'rm -rf -- "${temporary_root}"' EXIT

for variable_name in \
  EXTERNAL_REVIEW_REPORT_B64 \
  EXTERNAL_REVIEW_SIGNATURE_B64 \
  EXTERNAL_REVIEW_PUBLIC_KEY_B64 \
  EXTERNAL_REVIEW_ARTIFACT_B64 \
  EXTERNAL_REVIEW_DISPOSITION_B64 \
  EXTERNAL_REVIEW_TRUSTED_KEY_SHA256; do
  [[ -n "${!variable_name:-}" ]] || {
    printf 'external review: protected variable is missing: %s\n' "${variable_name}" >&2
    exit 2
  }
done

umask 077
printf '%s' "${EXTERNAL_REVIEW_REPORT_B64}" | base64 --decode > "${temporary_root}/report.tsv"
printf '%s' "${EXTERNAL_REVIEW_SIGNATURE_B64}" | base64 --decode > "${temporary_root}/signature.bin"
printf '%s' "${EXTERNAL_REVIEW_PUBLIC_KEY_B64}" | base64 --decode > "${temporary_root}/reviewer.pub.pem"
printf '%s' "${EXTERNAL_REVIEW_ARTIFACT_B64}" | base64 --decode > "${temporary_root}/review-artifact"
printf '%s' "${EXTERNAL_REVIEW_DISPOSITION_B64}" | base64 --decode > "${temporary_root}/disposition.tsv"

exec "${repository_root}/scripts/ci/verify-external-review.sh" \
  "${temporary_root}/report.tsv" \
  "${temporary_root}/signature.bin" \
  "${temporary_root}/reviewer.pub.pem" \
  "${temporary_root}/review-artifact" \
  "${temporary_root}/disposition.tsv"
