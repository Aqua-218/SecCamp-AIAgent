#!/usr/bin/env bash
#
# Structural policy gate for docs/.
#
# Checks that every documentation page declares a doc-type marker and carries
# the sections that its type requires, and that every relative link resolves.
# Structure only: whether the content is concrete, or whether a diagram shows
# the real mechanism, is a review concern.
#
# See docs/document-conventions.md for the conventions this enforces.

set -euo pipefail

readonly repository_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
cd -- "${repository_root}"

# Minimum line counts. These are floors that catch pages which are obviously
# unwritten, not a quality measure.
readonly min_lines_concept=100
readonly min_lines_contract=60
readonly min_lines_verification=40
readonly min_lines_design=80

readonly valid_types="concept contract verification decision design index exempt"

failures=0
checked=0

# Body of the page with fenced blocks removed. Skeletons and examples inside
# code fences must not count as real headings or links.
prose=""

fail() {
  printf '%s:%s\n' "$1" "$2" >&2
  failures=$((failures + 1))
}

strip_fences() {
  awk '/^```/ { inside = !inside; next } !inside' "$1"
}

# has_section <file> <heading text>
has_section() {
  grep -qxF "## $2" -- "$1"
}

has_table() {
  grep -qE '^\|[[:space:]]*:?-+:?[[:space:]]*\|' -- "$1"
}

has_fence() {
  grep -qE "^\`\`\`$2\$" -- "$1"
}

has_source_link() {
  grep -qE '\]\((\.\./)*crates/[^)]+\.rs\)' -- "$1"
}

# The breadcrumb must appear within the three lines that follow the H1.
has_breadcrumb() {
  local h1_line
  h1_line="$(grep -n -m1 '^# ' -- "${prose}" | cut -d: -f1)"
  [[ -n "${h1_line}" ]] || return 1
  sed -n "$((h1_line + 1)),$((h1_line + 3))p" -- "${prose}" |
    grep -qE '^\[[^]]+\]\([^)]+\)( / .+)?$'
}

check_links() {
  local file="$1" directory target
  directory="$(dirname -- "${file}")"

  while IFS= read -r target; do
    # Skip absolute URLs, mail links and same-page anchors.
    case "${target}" in
      http://* | https://* | mailto:* | '#'*) continue ;;
    esac
    # Drop any anchor fragment before resolving.
    target="${target%%#*}"
    [[ -n "${target}" ]] || continue

    if ! (cd -- "${directory}" && [[ -e "${target}" ]]); then
      fail "${file}" " broken relative link: ${target}"
    fi
  done < <(grep -oE '\]\([^)]+\)' -- "${prose}" | sed -E 's/^\]\(//; s/\)$//')
}

check_file() {
  local file="$1"
  local first_line doc_type lines

  checked=$((checked + 1))

  prose="$(mktemp)"
  # shellcheck disable=SC2064
  trap "rm -f -- '${prose}'" RETURN
  strip_fences "${file}" > "${prose}"

  first_line="$(head -n 1 -- "${file}")"
  if [[ ! "${first_line}" =~ ^\<!--[[:space:]]doc-type:[[:space:]]([a-z]+)[[:space:]]--\>$ ]]; then
    fail "${file}" '1 missing doc-type marker on line 1 (see docs/document-conventions.md)'
    return
  fi
  doc_type="${BASH_REMATCH[1]}"

  if [[ " ${valid_types} " != *" ${doc_type} "* ]]; then
    fail "${file}" "1 unknown doc-type: ${doc_type} (valid: ${valid_types})"
    return
  fi

  # Rules common to every type.
  if [[ "$(grep -c '^# ' -- "${prose}")" -ne 1 ]]; then
    fail "${file}" ' expected exactly one H1 heading'
  fi
  # docs/README.md is the root of the tree and has no parent to point at.
  if [[ "${file}" != 'docs/README.md' ]]; then
    has_breadcrumb ||
      fail "${file}" ' missing breadcrumb line directly below the H1'
  fi
  grep -qE '^> \*\*対象読者:\*\* .+' -- "${prose}" ||
    fail "${file}" ' missing "> **対象読者:**" line'
  has_section "${prose}" '関連' ||
    fail "${file}" ' missing "## 関連" section'
  check_links "${file}"

  lines="$(wc -l < "${file}")"

  case "${doc_type}" in
    concept)
      has_source_link "${prose}" ||
        fail "${file}" ' missing link to a crates/**/*.rs source file'
      has_fence "${file}" 'mermaid' ||
        fail "${file}" ' missing mermaid diagram (at least one required)'
      has_section "${prose}" '正確な保証範囲' ||
        fail "${file}" ' missing "## 正確な保証範囲" section'
      has_section "${prose}" '変更時の確認点' ||
        fail "${file}" ' missing "## 変更時の確認点" section'
      [[ "${lines}" -ge "${min_lines_concept}" ]] ||
        fail "${file}" " ${lines} lines, below the ${min_lines_concept} line floor for concept pages"
      ;;
    contract)
      has_source_link "${prose}" ||
        fail "${file}" ' missing link to a crates/**/*.rs source file'
      has_table "${prose}" ||
        fail "${file}" ' missing table (contracts are written as tables, not prose)'
      has_section "${prose}" '保証範囲外' ||
        fail "${file}" ' missing "## 保証範囲外" section'
      [[ "${lines}" -ge "${min_lines_contract}" ]] ||
        fail "${file}" " ${lines} lines, below the ${min_lines_contract} line floor for contract pages"
      ;;
    verification)
      has_section "${prose}" 'local test で確認したこと' ||
        fail "${file}" ' missing "## local test で確認したこと" section'
      has_section "${prose}" '実行コマンド' ||
        fail "${file}" ' missing "## 実行コマンド" section'
      has_section "${prose}" '未検証の境界' ||
        fail "${file}" ' missing "## 未検証の境界" section'
      has_fence "${file}" 'bash' ||
        fail "${file}" ' missing bash block with the focused test commands'
      [[ "${lines}" -ge "${min_lines_verification}" ]] ||
        fail "${file}" " ${lines} lines, below the ${min_lines_verification} line floor for verification pages"
      ;;
    decision)
      for section in 'Status' '背景と課題' '検討した選択肢' '決定' '結果'; do
        has_section "${prose}" "${section}" ||
          fail "${file}" " missing \"## ${section}\" section required by MADR"
      done
      grep -qE '^\*\*採用しなかった理由:\*\*|採用しなかった理由' -- "${file}" ||
        fail "${file}" ' records no rejected option; an ADR must say what was turned down and why'
      ;;
    design)
      has_fence "${file}" 'mermaid' ||
        fail "${file}" ' missing mermaid diagram (at least one required)'
      [[ "${lines}" -ge "${min_lines_design}" ]] ||
        fail "${file}" " ${lines} lines, below the ${min_lines_design} line floor for design pages"
      ;;
    index)
      has_table "${prose}" ||
        fail "${file}" ' missing table listing the child pages'
      has_fence "${file}" 'mermaid' ||
        fail "${file}" ' missing architecture diagram (at least one mermaid block required)'
      ;;
    exempt) ;;
  esac
}

main() {
  local files=()

  if [[ "$#" -gt 0 ]]; then
    files=("$@")
  else
    # docs/templates/ holds the skeletons themselves; their placeholder links
    # and headings are deliberately unresolvable.
    mapfile -t files < <(
      find docs -type f -name '*.md' -not -path 'docs/templates/*' | sort
    )
  fi

  local file
  for file in "${files[@]}"; do
    check_file "${file}"
  done

  if [[ "${failures}" -gt 0 ]]; then
    printf '\ndocs policy: %d problem(s) across %d file(s)\n' \
      "${failures}" "${#files[@]}" >&2
    exit 1
  fi

  printf 'docs policy: %d file(s) checked, no problems\n' "${checked}"
}

main "$@"
