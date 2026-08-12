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
    cargo llvm-cov --workspace --all-features --locked \
      --lcov --output-path coverage/lcov.info --fail-under-lines 75
    cargo llvm-cov report --cobertura --output-path coverage/cobertura.xml
    cargo llvm-cov report --summary-only | tee coverage/summary.txt
    ;;
  audit)
    mkdir -p -- reports
    cargo audit --json > reports/cargo-audit.json
    ;;
  deny)
    mkdir -p -- reports
    cargo deny --format json check advisories bans licenses sources 2> reports/cargo-deny.json
    ;;
  *)
    printf 'unknown command: %s\n' "${command_name}" >&2
    exit 2
    ;;
esac
