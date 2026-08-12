#!/usr/bin/env bash

set -euo pipefail

readonly repository_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly release_tool_bin="${CI_TOOLS_DIR:-${repository_root}/.ci-tools}/bin"
export PATH="${release_tool_bin}:${PATH}"
cd -- "${repository_root}"

set -a
# shellcheck disable=SC1091
source dist/release.env
set +a

(
  cd -- dist
  sha256sum --check --strict "${CHECKSUM_NAME}"
)

if [[ "${VERIFY_SIGSTORE:-false}" == "true" ]]; then
  if [[ -z "${CERTIFICATE_IDENTITY:-}" || -z "${CERTIFICATE_OIDC_ISSUER:-}" ]]; then
    printf 'certificate identity and issuer are required for Sigstore verification\n' >&2
    exit 2
  fi
  cosign verify-blob \
    --bundle "dist/${SIGNATURE_BUNDLE_NAME}" \
    --certificate-identity "${CERTIFICATE_IDENTITY}" \
    --certificate-oidc-issuer "${CERTIFICATE_OIDC_ISSUER}" \
    "dist/${CHECKSUM_NAME}"
fi
