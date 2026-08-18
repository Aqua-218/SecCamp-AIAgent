#!/usr/bin/env bash

set -euo pipefail

readonly repository_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly temporary_root="$(mktemp -d)"
trap 'rm -rf -- "${temporary_root}"' EXIT
readonly test_repository="${temporary_root}/repository"
readonly external_inputs="${temporary_root}/external"

mkdir -p -- "${test_repository}/scripts/ci" "${external_inputs}"
cp -- "${repository_root}/scripts/ci/verify-external-review.sh" \
  "${test_repository}/scripts/ci/verify-external-review.sh"
printf 'review fixture\n' > "${test_repository}/tracked.txt"
git -C "${test_repository}" init --quiet
git -C "${test_repository}" config user.name 'Review Gate Test'
git -C "${test_repository}" config user.email 'review-gate@example.invalid'
git -C "${test_repository}" add scripts/ci/verify-external-review.sh tracked.txt
git -C "${test_repository}" commit --quiet -m 'review fixture'

openssl genpkey -algorithm ED25519 -out "${external_inputs}/private.pem" 2>/dev/null
openssl pkey -in "${external_inputs}/private.pem" -pubout \
  -out "${external_inputs}/public.pem" 2>/dev/null
readonly revision="$(git -C "${test_repository}" rev-parse HEAD)"
readonly tree="$(git -C "${test_repository}" rev-parse 'HEAD^{tree}')"
printf '# Independent review fixture\n\nNo critical or high findings remain.\n' \
  > "${external_inputs}/review.md"
printf 'external-review-disposition-v1\nF-001\thigh\tfixed\nF-002\tmedium\topen\n' \
  > "${external_inputs}/disposition.tsv"
readonly review_digest="$(sha256sum -- "${external_inputs}/review.md" | awk '{print $1}')"
readonly disposition_digest="$(sha256sum -- "${external_inputs}/disposition.tsv" | awk '{print $1}')"
printf 'external-security-review-v1\t%s\t%s\trepository\treviewer@example.invalid\tIndependent-Lab\taffirmed\t%s\t%s\t0\t0\tapprove\n' \
  "${revision}" "${tree}" "${review_digest}" "${disposition_digest}" \
  > "${external_inputs}/report.tsv"
openssl pkeyutl -sign -inkey "${external_inputs}/private.pem" -rawin \
  -in "${external_inputs}/report.tsv" -out "${external_inputs}/signature.bin"
readonly fingerprint="$(sha256sum -- "${external_inputs}/public.pem" | awk '{print $1}')"

(
  cd -- "${test_repository}"
  EXTERNAL_REVIEW_TRUSTED_KEY_SHA256="${fingerprint}" \
    scripts/ci/verify-external-review.sh \
      "${external_inputs}/report.tsv" \
      "${external_inputs}/signature.bin" \
      "${external_inputs}/public.pem" \
      "${external_inputs}/review.md" \
      "${external_inputs}/disposition.tsv" >/dev/null
)

cp -- "${external_inputs}/report.tsv" "${external_inputs}/tampered.tsv"
sed -i 's/\tapprove$/\treject/' "${external_inputs}/tampered.tsv"
if (
  cd -- "${test_repository}"
  EXTERNAL_REVIEW_TRUSTED_KEY_SHA256="${fingerprint}" \
    scripts/ci/verify-external-review.sh \
      "${external_inputs}/tampered.tsv" \
      "${external_inputs}/signature.bin" \
      "${external_inputs}/public.pem" \
      "${external_inputs}/review.md" \
      "${external_inputs}/disposition.tsv" >/dev/null 2>&1
); then
  printf 'tampered external review unexpectedly passed\n' >&2
  exit 1
fi

printf 'external-security-review-v1\t%s\t%s\trepository\treviewer@example.invalid\tIndependent-Lab\taffirmed\t%s\t%s\t0\t0\tapprove\n' \
  "$(printf '0%.0s' {1..40})" "${tree}" "${review_digest}" "${disposition_digest}" \
  > "${external_inputs}/wrong-revision.tsv"
openssl pkeyutl -sign -inkey "${external_inputs}/private.pem" -rawin \
  -in "${external_inputs}/wrong-revision.tsv" -out "${external_inputs}/wrong-revision.sig"
if (
  cd -- "${test_repository}"
  EXTERNAL_REVIEW_TRUSTED_KEY_SHA256="${fingerprint}" \
    scripts/ci/verify-external-review.sh \
      "${external_inputs}/wrong-revision.tsv" \
      "${external_inputs}/wrong-revision.sig" \
      "${external_inputs}/public.pem" \
      "${external_inputs}/review.md" \
      "${external_inputs}/disposition.tsv" >/dev/null 2>&1
); then
  printf 'wrong-revision external review unexpectedly passed\n' >&2
  exit 1
fi

if (
  cd -- "${test_repository}"
  EXTERNAL_REVIEW_TRUSTED_KEY_SHA256="$(printf '0%.0s' {1..64})" \
    scripts/ci/verify-external-review.sh \
      "${external_inputs}/report.tsv" \
      "${external_inputs}/signature.bin" \
      "${external_inputs}/public.pem" \
      "${external_inputs}/review.md" \
      "${external_inputs}/disposition.tsv" >/dev/null 2>&1
); then
  printf 'wrong trust anchor unexpectedly passed\n' >&2
  exit 1
fi

printf 'dirty\n' >> "${test_repository}/tracked.txt"
if (
  cd -- "${test_repository}"
  EXTERNAL_REVIEW_TRUSTED_KEY_SHA256="${fingerprint}" \
    scripts/ci/verify-external-review.sh \
      "${external_inputs}/report.tsv" \
      "${external_inputs}/signature.bin" \
      "${external_inputs}/public.pem" \
      "${external_inputs}/review.md" \
      "${external_inputs}/disposition.tsv" >/dev/null 2>&1
); then
  printf 'dirty-tree external review unexpectedly passed\n' >&2
  exit 1
fi

git -C "${test_repository}" restore tracked.txt
printf 'external-review-disposition-v1\nF-001\thigh\topen\n' \
  > "${external_inputs}/unresolved.tsv"
readonly unresolved_digest="$(sha256sum -- "${external_inputs}/unresolved.tsv" | awk '{print $1}')"
printf 'external-security-review-v1\t%s\t%s\trepository\treviewer@example.invalid\tIndependent-Lab\taffirmed\t%s\t%s\t0\t0\tapprove\n' \
  "${revision}" "${tree}" "${review_digest}" "${unresolved_digest}" \
  > "${external_inputs}/unresolved-manifest.tsv"
openssl pkeyutl -sign -inkey "${external_inputs}/private.pem" -rawin \
  -in "${external_inputs}/unresolved-manifest.tsv" -out "${external_inputs}/unresolved.sig"
if (
  cd -- "${test_repository}"
  EXTERNAL_REVIEW_TRUSTED_KEY_SHA256="${fingerprint}" \
    scripts/ci/verify-external-review.sh \
      "${external_inputs}/unresolved-manifest.tsv" \
      "${external_inputs}/unresolved.sig" \
      "${external_inputs}/public.pem" \
      "${external_inputs}/review.md" \
      "${external_inputs}/unresolved.tsv" >/dev/null 2>&1
); then
  printf 'unresolved high finding unexpectedly passed\n' >&2
  exit 1
fi

printf 'external review gate self-test: positive and negative cases passed\n'
