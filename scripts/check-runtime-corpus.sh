#!/usr/bin/env bash

# Executes the public Rust runtime APIs, then requires Lean to accept and
# reproduce their proof-free normalized observations byte for byte.
set -euo pipefail

readonly repository_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
corpus_scratch="$(mktemp -d)"
readonly corpus_scratch
readonly rust_output="${corpus_scratch}/rust.tsv"
readonly lean_output="${corpus_scratch}/lean.tsv"

cleanup() {
  rm -rf -- "${corpus_scratch}"
}
trap cleanup EXIT

(
  cd -- "${repository_root}"
  cargo run --quiet -p session-orchestrator --bin authority-runtime-corpus
) >"${rust_output}"

(
  cd -- "${repository_root}/lean"
  lake exe authority_runtime_corpus "${rust_output}"
) >"${lean_output}"

diff -u --label Rust --label Lean "${rust_output}" "${lean_output}"

row_count="$(($(wc -l <"${rust_output}") - 1))"
readonly row_count
printf 'runtime corpus: Lean accepted and matched all %s Rust observations\n' "${row_count}"
