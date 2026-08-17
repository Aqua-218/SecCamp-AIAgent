#!/usr/bin/env bash
#
# Proves the decision log and its index still describe the same set of records.
#
# An ADR that exists but is not indexed is a decision nobody will find, and an
# index entry with no file behind it is a decision that appears to have been
# made. Both failures look identical from the outside: someone reads the index,
# believes the question is settled, and re-litigates it or builds on a record
# that was never written. The numbering is checked too, because a gap is how a
# record silently disappears from an ordered log.

set -euo pipefail

readonly repository_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
cd -- "${repository_root}"

readonly decisions_directory="docs/decisions"
readonly index_page="${decisions_directory}/README.md"

failures=0

fail() {
  printf 'FAIL %s\n' "$1" >&2
  failures=$((failures + 1))
}

[[ -f "${index_page}" ]] || {
  printf 'decision index is missing: %s\n' "${index_page}" >&2
  exit 1
}

mapfile -t record_files < <(
  find "${decisions_directory}" -maxdepth 1 -type f -name '[0-9][0-9][0-9][0-9]-*.md' \
    -printf '%f\n' | sort
)

if [[ "${#record_files[@]}" -eq 0 ]]; then
  fail "${decisions_directory}: no decision records found"
fi

# Only links whose target sits next to the index count. A record referenced from
# somewhere else in the tree is a cross-reference, not an index entry.
mapfile -t indexed_records < <(
  grep -oE '\]\([0-9]{4}-[a-z0-9-]+\.md\)' "${index_page}" \
    | sed -e 's/^](//' -e 's/)$//' | sort -u
)

for record in "${record_files[@]}"; do
  found=false
  for indexed in "${indexed_records[@]}"; do
    [[ "${indexed}" == "${record}" ]] && found=true && break
  done
  if [[ "${found}" != true ]]; then
    fail "${record}: decision record is not linked from ${index_page}"
  fi
done

for indexed in "${indexed_records[@]}"; do
  if [[ ! -f "${decisions_directory}/${indexed}" ]]; then
    fail "${indexed}: indexed in ${index_page} but no such record exists"
  fi
done

expected_number=0
for record in "${record_files[@]}"; do
  actual_number="${record%%-*}"
  printf -v padded_expected '%04d' "${expected_number}"
  if [[ "${actual_number}" != "${padded_expected}" ]]; then
    fail "${record}: decision numbering skips ${padded_expected}"
    break
  fi
  expected_number=$((expected_number + 1))
done

if [[ "${failures}" -gt 0 ]]; then
  printf '\ndecision record index: %d problem(s)\n' "${failures}" >&2
  exit 1
fi

printf 'decision record index: %d record(s) indexed and numbered without a gap\n' \
  "${#record_files[@]}"
