#!/usr/bin/env bash

set -euo pipefail

readonly repository_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"

if [[ "$#" -ne 5 ]]; then
  printf 'usage: %s <signed-manifest.tsv> <signature.bin> <ed25519-public-key.pem> <review-report> <disposition.tsv>\n' "$0" >&2
  exit 2
fi

readonly report_path="$1"
readonly signature_path="$2"
readonly public_key_path="$3"
readonly review_artifact_path="$4"
readonly disposition_path="$5"
readonly trusted_fingerprint="${EXTERNAL_REVIEW_TRUSTED_KEY_SHA256:-}"

fail() {
  printf 'external review: %s\n' "$1" >&2
  exit 1
}

for dependency in git openssl sha256sum realpath stat awk grep wc tail od tr; do
  command -v "${dependency}" >/dev/null 2>&1 \
    || fail "required command is unavailable: ${dependency}"
done

[[ "${trusted_fingerprint}" =~ ^[0-9a-f]{64}$ ]] \
  || fail 'EXTERNAL_REVIEW_TRUSTED_KEY_SHA256 must be an independently configured lowercase SHA-256'

for input_path in \
  "${report_path}" \
  "${signature_path}" \
  "${public_key_path}" \
  "${review_artifact_path}" \
  "${disposition_path}"; do
  [[ -f "${input_path}" && ! -L "${input_path}" ]] \
    || fail "input must be a non-symlink regular file: ${input_path}"
  resolved_input="$(realpath -- "${input_path}")"
  case "${resolved_input}" in
    "${repository_root}"|"${repository_root}"/*)
      fail "review inputs must be supplied outside the repository: ${resolved_input}"
      ;;
  esac
  input_mode="$(stat -c '%a' -- "${input_path}")"
  if (( (8#${input_mode}) & 8#022 )); then
    fail "review input must not be group/world writable: ${input_path}"
  fi
done

[[ "$(wc -c < "${report_path}")" -le 4096 ]] || fail 'canonical report exceeds 4096 bytes'
[[ "$(wc -c < "${signature_path}")" -le 1024 ]] || fail 'detached signature exceeds 1024 bytes'
[[ "$(wc -c < "${public_key_path}")" -le 4096 ]] || fail 'public key exceeds 4096 bytes'
[[ "$(wc -c < "${review_artifact_path}")" -le 10485760 ]] || fail 'review artifact exceeds 10 MiB'
[[ "$(wc -c < "${disposition_path}")" -le 1048576 ]] || fail 'review disposition exceeds 1 MiB'
[[ "$(wc -l < "${report_path}")" -eq 1 ]] || fail 'canonical report must contain exactly one LF-terminated line'
[[ "$(tail -c 1 -- "${report_path}" | od -An -tu1 | tr -d '[:space:]')" == 10 ]] \
  || fail 'canonical report must end with exactly one LF'
LC_ALL=C awk 'index($0, "\r") || NF != 12 { exit 1 }' FS='\t' "${report_path}" \
  || fail 'canonical report must contain exactly twelve tab-separated fields and no CR'

IFS=$'\t' read -r schema revision tree scope reviewer organization independent review_digest disposition_digest critical_open high_open decision < "${report_path}"
[[ "${schema}" == 'external-security-review-v1' ]] || fail 'report schema is not external-security-review-v1'
[[ "${revision}" =~ ^[0-9a-f]{40,64}$ ]] || fail 'review revision is not a canonical object ID'
[[ "${tree}" =~ ^[0-9a-f]{40,64}$ ]] || fail 'review tree is not a canonical object ID'
[[ "${scope}" == 'repository' ]] || fail 'review scope must be the complete repository'
[[ "${reviewer}" =~ ^[A-Za-z0-9][A-Za-z0-9._@+-]{2,127}$ ]] || fail 'reviewer identity is not canonical'
[[ "${organization}" =~ ^[A-Za-z0-9][A-Za-z0-9._+-]{1,127}$ ]] || fail 'reviewer organization is not canonical'
[[ "${independent}" == 'affirmed' ]] || fail 'reviewer did not affirm independence'
[[ "${review_digest}" =~ ^[0-9a-f]{64}$ ]] || fail 'review artifact digest is not canonical SHA-256'
[[ "${disposition_digest}" =~ ^[0-9a-f]{64}$ ]] || fail 'disposition digest is not canonical SHA-256'
[[ "${critical_open}" == '0' ]] || fail 'review leaves an open critical finding'
[[ "${high_open}" == '0' ]] || fail 'review leaves an open high finding'
[[ "${decision}" == 'approve' ]] || fail 'review decision is not approve'

cd -- "${repository_root}"
[[ -z "$(git status --porcelain=v1 --untracked-files=all)" ]] \
  || fail 'working tree is dirty; an external report can attest only an exact committed revision'
readonly actual_revision="$(git rev-parse --verify HEAD)"
readonly actual_tree="$(git rev-parse --verify 'HEAD^{tree}')"
[[ "${revision}" == "${actual_revision}" ]] || fail 'review revision does not equal HEAD'
[[ "${tree}" == "${actual_tree}" ]] || fail 'review tree does not equal the HEAD tree'

readonly actual_review_digest="$(sha256sum -- "${review_artifact_path}" | awk '{print $1}')"
readonly actual_disposition_digest="$(sha256sum -- "${disposition_path}" | awk '{print $1}')"
[[ "${review_digest}" == "${actual_review_digest}" ]] || fail 'signed review artifact digest does not match'
[[ "${disposition_digest}" == "${actual_disposition_digest}" ]] || fail 'signed disposition digest does not match'
LC_ALL=C awk -F '\t' '
  NR == 1 {
    if ($0 != "external-review-disposition-v1") exit 1
    next
  }
  NF != 3 { exit 1 }
  $1 !~ /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/ { exit 1 }
  seen[$1]++ { exit 1 }
  $2 !~ /^(critical|high|medium|low|info)$/ { exit 1 }
  $3 !~ /^(fixed|accepted-risk|open)$/ { exit 1 }
  ($2 == "critical" || $2 == "high") && $3 != "fixed" { exit 1 }
  END { if (NR < 1) exit 1 }
' "${disposition_path}" || fail 'finding disposition is noncanonical or leaves critical/high unresolved'

readonly actual_fingerprint="$(sha256sum -- "${public_key_path}" | awk '{print $1}')"
[[ "${actual_fingerprint}" == "${trusted_fingerprint}" ]] \
  || fail 'public key does not match the independently configured trust anchor'
openssl pkey -pubin -in "${public_key_path}" -text -noout 2>&1 \
  | grep -q 'ED25519' || fail 'review key is not an Ed25519 public key'
openssl pkeyutl -verify -pubin -inkey "${public_key_path}" -rawin \
  -in "${report_path}" -sigfile "${signature_path}" >/dev/null 2>&1 \
  || fail 'detached review signature is invalid'

printf 'external review: verified revision %s, tree %s, reviewer %s (%s)\n' \
  "${revision}" "${tree}" "${reviewer}" "${organization}"
