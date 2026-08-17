#!/usr/bin/env bash

# Opt-in smoke for the fixed typed GitHub provider. This script intentionally
# does not use curl or accept an endpoint: the ignored Rust test constructs a
# RustlsGitHubProvider and dispatches only through TypedGitHubAdapter.
#
# The target repository is destructive disposable scope. Every invocation must
# name that exact repository in the acknowledgement, and the operator owns
# cleanup of the created pull request/branch state.

set -euo pipefail

repository_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly repository_root

require_environment() {
  local name="$1"
  if [[ -z "${!name:-}" ]]; then
    printf 'live GitHub verification requires %s\n' "${name}" >&2
    exit 2
  fi
}

for name in \
  EGRESS_GITHUB_TOKEN \
  EGRESS_GITHUB_INSTALLATION_ID \
  EGRESS_GITHUB_DISPOSABLE_REPOSITORY \
  EGRESS_GITHUB_BASE_BRANCH \
  EGRESS_GITHUB_HEAD_BRANCH \
  EGRESS_GITHUB_EXPECTED_OLD_OBJECT \
  EGRESS_GITHUB_NEW_OBJECT \
  EGRESS_GITHUB_DISPOSABLE_ACK; do
  require_environment "${name}"
done

repository="${EGRESS_GITHUB_DISPOSABLE_REPOSITORY}"
if [[ ! "${repository}" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*/[A-Za-z0-9][A-Za-z0-9._-]*$ ]]; then
  printf '%s\n' 'live GitHub verification requires an exact owner/name repository' >&2
  exit 2
fi
if [[ "${EGRESS_GITHUB_DISPOSABLE_ACK}" != "I_UNDERSTAND_DISPOSABLE_REPOSITORY:${repository}" ]]; then
  printf '%s\n' 'live GitHub verification requires acknowledgement bound to the exact disposable repository' >&2
  exit 2
fi
if [[ ! "${EGRESS_GITHUB_EXPECTED_OLD_OBJECT}" =~ ^[[:xdigit:]]+$ ]] || {
  [[ "${#EGRESS_GITHUB_EXPECTED_OLD_OBJECT}" -ne 40 ]] &&
  [[ "${#EGRESS_GITHUB_EXPECTED_OLD_OBJECT}" -ne 64 ]];
}; then
  printf '%s\n' 'live GitHub verification requires a 40- or 64-character expected-old object ID' >&2
  exit 2
fi
if [[ ! "${EGRESS_GITHUB_NEW_OBJECT}" =~ ^[[:xdigit:]]+$ ]] || {
  [[ "${#EGRESS_GITHUB_NEW_OBJECT}" -ne 40 ]] &&
  [[ "${#EGRESS_GITHUB_NEW_OBJECT}" -ne 64 ]];
}; then
  printf '%s\n' 'live GitHub verification requires a 40- or 64-character new object ID' >&2
  exit 2
fi
if [[ "${EGRESS_GITHUB_BASE_BRANCH}" =~ [[:space:][:cntrl:]] ||
  "${EGRESS_GITHUB_HEAD_BRANCH}" =~ [[:space:][:cntrl:]] ||
  "${EGRESS_GITHUB_INSTALLATION_ID}" =~ [[:space:][:cntrl:]] ]]; then
  printf '%s\n' 'live GitHub verification rejects whitespace or control characters in typed identities' >&2
  exit 2
fi
command -v cargo >/dev/null || {
  printf '%s\n' 'live GitHub verification requires cargo' >&2
  exit 2
}

cd -- "${repository_root}"

# Do not print the environment or enable shell tracing: EGRESS_GITHUB_TOKEN
# remains an inherited secret and is read only by RustlsGitHubProvider.
cargo test \
  --locked \
  --manifest-path "${repository_root}/Cargo.toml" \
  -p egress-broker \
  --lib \
  -- \
  --ignored \
  --exact \
  github::tests::live_github_disposable_repository_smoke

printf '%s\n' 'live GitHub verification: typed disposable-repository smoke passed'
