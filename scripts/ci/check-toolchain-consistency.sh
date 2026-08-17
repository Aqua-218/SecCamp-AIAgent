#!/usr/bin/env bash
#
# Proves that one Rust version is written the same way everywhere.
#
# The pinned toolchain appears in six places that no compiler relates to each
# other: the rustup pin, the workspace MSRV, the assertion inside the GitHub
# composite action, the GitLab before_script assertion, the GitLab container tag,
# and the operations document. Five of them agreeing while the sixth drifts is
# exactly the failure that produces "works on the runner, not on the mirror".
#
# The Lean toolchain is pinned once, in lean/lean-toolchain, and every consumer
# reads that file. This script only checks that the file exists and that nothing
# has started to hard-code a Lean version beside it.

set -euo pipefail

readonly repository_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
cd -- "${repository_root}"

failures=0

fail() {
  printf 'FAIL %s\n' "$1" >&2
  failures=$((failures + 1))
}

expect_equal() {
  local label="$1" expected="$2" actual="$3"
  if [[ "${expected}" != "${actual}" ]]; then
    fail "${label}: expected ${expected}, found ${actual:-<empty>}"
  fi
}

# ------------------------------------------------------------------ Rust pin --

readonly toolchain_channel="$(
  awk -F'"' '/^channel = /{ print $2; exit }' rust-toolchain.toml
)"

if [[ ! "${toolchain_channel}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  fail "rust-toolchain.toml channel is not an exact version: ${toolchain_channel:-<empty>}"
  printf '\ntoolchain consistency: %d problem(s)\n' "$((failures + 1))" >&2
  exit 1
fi

readonly workspace_rust_version="$(
  awk '
    /^\[workspace\.package\]$/ { inside = 1; next }
    /^\[/ { inside = 0 }
    inside && /^rust-version = / { gsub(/["[:space:]]/, "", $3); print $3; exit }
  ' Cargo.toml
)"
expect_equal '[workspace.package].rust-version' "${toolchain_channel}" "${workspace_rust_version}"

readonly github_assertion="$(
  sed -nE 's/.*grep -F "rustc ([0-9]+\.[0-9]+\.[0-9]+) ".*/\1/p' \
    .github/actions/setup-rust/action.yml | head -n 1
)"
expect_equal '.github/actions/setup-rust assertion' "${toolchain_channel}" "${github_assertion}"

readonly gitlab_assertion="$(
  sed -nE 's/.*grep -F "rustc ([0-9]+\.[0-9]+\.[0-9]+) ".*/\1/p' \
    .gitlab/ci/common.yml | head -n 1
)"
expect_equal '.gitlab/ci/common.yml assertion' "${toolchain_channel}" "${gitlab_assertion}"

readonly gitlab_image_version="$(
  sed -nE 's#.*docker\.io/library/rust:([0-9]+\.[0-9]+\.[0-9]+)-bookworm@sha256:[0-9a-f]{64}.*#\1#p' \
    .gitlab-ci.yml | head -n 1
)"
expect_equal '.gitlab-ci.yml default image tag' "${toolchain_channel}" "${gitlab_image_version}"

if ! grep -qF "rust-toolchain.toml" docs/ci-cd.md; then
  fail 'docs/ci-cd.md no longer points at rust-toolchain.toml as the pin'
fi

# ------------------------------------------------------------------ Lean pin --

if [[ ! -f lean/lean-toolchain ]]; then
  fail 'lean/lean-toolchain is missing'
else
  lean_toolchain="$(tr -d '[:space:]' < lean/lean-toolchain)"
  readonly lean_toolchain
  if [[ -z "${lean_toolchain}" ]]; then
    fail 'lean/lean-toolchain is empty'
  fi

  # Any second place that names a Lean version becomes a second pin to forget.
  if lean_offenders="$(
    grep -REn 'leanprover/lean4:v?[0-9]' \
      --include='*.yml' --include='*.yaml' --include='*.sh' \
      .github .gitlab scripts
  )"; then
    while IFS= read -r offender; do
      fail "Lean version hard-coded outside lean/lean-toolchain: ${offender}"
    done <<< "${lean_offenders}"
  fi
fi

# ------------------------------------------------------- nightly pin, if any --

# The deep tier uses a separate nightly. It is pinned in one script and nowhere
# else, for the same reason the stable channel is.
if [[ -f scripts/ci/install-nightly-toolchain.sh ]]; then
  nightly_pin="$(
    awk -F'"' '/^readonly nightly_channel=/{ print $2; exit }' \
      scripts/ci/install-nightly-toolchain.sh
  )"
  readonly nightly_pin
  if [[ ! "${nightly_pin}" =~ ^nightly-[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]]; then
    fail "install-nightly-toolchain.sh does not pin a dated nightly: ${nightly_pin:-<empty>}"
  fi

  if nightly_offenders="$(
    grep -REn 'cargo \+nightly|rustup toolchain install nightly' \
      --include='*.yml' --include='*.yaml' --include='*.sh' \
      .github .gitlab scripts \
      | grep -v -E '^scripts/ci/(install-nightly-toolchain|check-toolchain-consistency)\.sh:'
  )"; then
    while IFS= read -r offender; do
      fail "nightly toolchain named outside install-nightly-toolchain.sh: ${offender}"
    done <<< "${nightly_offenders}"
  fi
fi

if [[ "${failures}" -gt 0 ]]; then
  printf '\ntoolchain consistency: %d problem(s)\n' "${failures}" >&2
  exit 1
fi

printf 'toolchain consistency: Rust %s agreed across every pin\n' "${toolchain_channel}"
