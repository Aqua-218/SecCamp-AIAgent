#!/usr/bin/env bash

set -euo pipefail

readonly repository_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly tool_bin="${CI_TOOLS_DIR:-${repository_root}/.ci-tools}/cargo/bin"
export PATH="${tool_bin}:${PATH}"

cd -- "${repository_root}"

if [[ "$#" -lt 1 ]]; then
  printf 'usage: %s <command> [argument]\n' "$0" >&2
  exit 2
fi

readonly command_name="$1"
shift

case "${command_name}" in
  format)
    cargo fmt --all -- --check
    ;;
  check)
    cargo check --workspace --all-targets --all-features --locked
    ;;
  clippy)
    cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
    ;;
  docs)
    RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --locked --no-deps
    ;;
  docs-policy)
    scripts/ci/check-docs.sh
    scripts/ci/check-doc-consistency.sh
    scripts/ci/tests/test-doc-consistency.sh
    ;;
  commit-policy)
    scripts/ci/check-commit-policy.sh
    ;;
  commit-policy-self-test)
    scripts/ci/test-commit-policy.sh
    ;;
  api-surface)
    scripts/ci/check-api-surface.sh
    ;;
  test)
    if [[ "$#" -ne 1 ]]; then
      printf 'test requires one shard number\n' >&2
      exit 2
    fi
    case "$1" in
      1)
        cargo nextest run --profile ci --locked -p authority-core -p egress-protocol
        ;;
      2)
        cargo nextest run --profile ci --locked -p capfs -p runtime-isolation
        ;;
      3)
        cargo nextest run --profile ci --locked -p egress-broker -p firecracker-runtime
        ;;
      4)
        cargo nextest run --profile ci --locked -p supervisor -p session-orchestrator
        ;;
      *)
        printf 'unknown test shard: %s\n' "$1" >&2
        exit 2
        ;;
    esac
    ;;
  test-package)
    if [[ "$#" -ne 1 ]]; then
      printf 'test-package requires one manifest package name\n' >&2
      exit 2
    fi
    if ! awk '/^packages:/{inside=1; next} inside && /^  - /{sub(/^  - /, ""); print; next} inside && !/^  - /{exit}' ci/gates.yml \
      | grep -qxF -- "$1"; then
      printf 'package is not declared by ci/gates.yml: %s\n' "$1" >&2
      exit 2
    fi
    cargo nextest run --profile ci --locked --package "$1"
    ;;
  doctest)
    cargo test --workspace --doc --all-features --locked
    ;;
  loom)
    RUSTFLAGS="--cfg loom" cargo test --locked \
      --package authority-core --test authorization_kernel_loom
    RUSTFLAGS="--cfg loom" cargo clippy --locked \
      --package authority-core --test authorization_kernel_loom -- -D warnings
    ;;
  lean)
    export ELAN_HOME="${CI_TOOLS_DIR:-${repository_root}/.ci-tools}/elan"
    export PATH="${ELAN_HOME}/bin:${PATH}"
    (
      cd -- lean
      lake build
    )
    ;;
  differential)
    export ELAN_HOME="${CI_TOOLS_DIR:-${repository_root}/.ci-tools}/elan"
    export PATH="${ELAN_HOME}/bin:${PATH}"
    scripts/check-authority-corpus.sh
    scripts/check-runtime-corpus.sh
    ;;
  coverage)
    mkdir -p -- coverage
    # One audit test intentionally forks a competing writer. Running another
    # reopen test during the fork-to-exec window can transiently inherit its
    # flock even though every descriptor is close-on-exec. nextest isolates the
    # normal test suite by process; make cargo-test coverage deterministic too.
    cargo llvm-cov --workspace --all-features --locked \
      --lcov --output-path coverage/lcov.info --fail-under-lines 75 \
      -- --test-threads=1
    cargo llvm-cov report --cobertura --output-path coverage/cobertura.xml
    cargo llvm-cov report --summary-only | tee coverage/summary.txt
    ;;
  audit)
    mkdir -p -- reports
    cargo audit --json > reports/cargo-audit.json
    cargo audit --file fuzz/Cargo.lock --json > reports/cargo-audit-fuzz.json
    ;;
  deny)
    mkdir -p -- reports
    cargo deny --format json check advisories bans licenses sources 2> reports/cargo-deny.json
    cargo deny --manifest-path fuzz/Cargo.toml --format json \
      check advisories bans licenses sources 2> reports/cargo-deny-fuzz.json
    ;;
  privileged-isolation)
    scripts/ci/verify-privileged-isolation.sh
    ;;
  privileged-isolation-aarch64)
    scripts/ci/verify-privileged-isolation-aarch64.sh
    ;;
  runtime-isolation-soak)
    scripts/ci/verify-runtime-isolation-soak.sh
    ;;
  real-capfs)
    scripts/ci/verify-real-capfs.sh
    ;;
  real-runtime-lifecycle)
    scripts/ci/verify-real-runtime-lifecycle.sh
    ;;
  real-runtime-version-matrix)
    scripts/ci/verify-real-runtime-version-matrix.sh
    ;;
  real-session-owner)
    scripts/ci/verify-real-session-owner.sh
    ;;
  real-session-crash-recovery)
    scripts/ci/verify-real-session-crash-recovery.sh
    ;;
  systemd-control-plane)
    scripts/ci/verify-real-systemd-control-plane.sh
    ;;
  concurrent-session-owners)
    scripts/ci/verify-real-concurrent-session-owners.sh
    ;;
  post-exec-isolation)
    # Backward-compatible entry point: the production-launcher post-exec
    # scenario is one of the required privileged-isolation scenarios.
    scripts/ci/verify-privileged-isolation.sh
    ;;
  real-public-https)
    scripts/ci/verify-real-public-https.sh
    ;;
  live-github)
    scripts/ci/verify-live-github.sh
    ;;
  external-review)
    scripts/ci/verify-external-review-from-env.sh
    ;;
  repository-policy)
    scripts/ci/check-adr-index.sh
    scripts/ci/check-verification-traceability.sh
    scripts/ci/check-codeowners-coverage.sh
    scripts/ci/check-repository-hygiene.sh
    scripts/ci/check-lean-hygiene.sh
    scripts/ci/collect-pin-inventory.sh
    ;;
  crate-isolation)
    scripts/ci/check-crate-isolation.sh
    ;;
  release-dry-run)
    scripts/ci/check-release-dry-run.sh
    ;;
  reproducibility)
    scripts/ci/check-release-reproducibility.sh
    ;;
  supply-chain-inventory)
    scripts/ci/collect-supply-chain-inventory.sh
    ;;
  cross-targets)
    scripts/ci/check-cross-targets.sh
    ;;
  miri)
    if [[ "$#" -ne 2 ]]; then
      printf 'miri requires one package and one test filter\n' >&2
      exit 2
    fi
    scripts/ci/run-miri.sh "$1" "$2"
    ;;
  sanitizers)
    if [[ "$#" -ne 2 ]]; then
      printf 'sanitizers requires one mode and one package\n' >&2
      exit 2
    fi
    scripts/ci/run-sanitizer.sh "$1" "$2"
    ;;
  mutation)
    if [[ "$#" -ne 2 ]]; then
      printf 'mutation requires one shard and one package\n' >&2
      exit 2
    fi
    scripts/ci/run-mutation.sh "$1" "$2"
    ;;
  fuzz)
    if [[ "$#" -ne 2 ]]; then
      printf 'fuzz requires one package and one target\n' >&2
      exit 2
    fi
    scripts/ci/run-fuzz.sh "$1" "$2"
    ;;
  benchmarks)
    scripts/ci/run-benchmark.sh "$@"
    ;;
  *)
    printf 'unknown command: %s\n' "${command_name}" >&2
    exit 2
    ;;
esac
