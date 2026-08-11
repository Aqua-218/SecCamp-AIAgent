#!/usr/bin/env bash

# Runs both implementations against one oracle-backed corpus, then requires
# byte-for-byte agreement between their normalized decision reports.
set -euo pipefail

readonly repository_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
readonly default_corpus_path="${repository_root}/tests/fixtures/authority-core.tsv"

if [[ "$#" -gt 1 ]]; then
  printf 'usage: %s [authority-corpus.tsv]\n' "$0" >&2
  exit 2
fi

readonly corpus_path="${1:-${default_corpus_path}}"
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
  cargo run --quiet -p authority-core --bin authority-corpus -- "${corpus_path}"
) >"${rust_output}"

(
  cd -- "${repository_root}/lean"
  lake exe authority_corpus "${corpus_path}"
) >"${lean_output}"

diff -u --label Rust --label Lean "${rust_output}" "${lean_output}"

case_count="$(wc -l <"${rust_output}" | tr -d '[:space:]')"
readonly case_count
printf 'authority corpus: Rust and Lean matched all %s cases\n' "${case_count}"
