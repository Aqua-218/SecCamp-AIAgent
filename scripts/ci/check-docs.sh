#!/usr/bin/env bash
#
# Structural policy gate for docs/.
#
# Checks that every documentation page declares a doc-type marker and carries
# the sections that its type requires, and that every relative link resolves.
# A no-argument run also audits the root README language switch and translation
# parity against the English canonical README.
# Structure only: whether the content is concrete, or whether a diagram shows
# the real mechanism, is a review concern.
#
# See docs/document-conventions.md for the conventions this enforces.

set -euo pipefail

repository_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly repository_root
cd -- "${repository_root}"

# Minimum line counts. These are floors that catch pages which are obviously
# unwritten, not a quality measure.
readonly min_lines_concept=100
readonly min_lines_contract=60
readonly min_lines_verification=40
readonly min_lines_design=80
readonly min_lines_localized=20

readonly valid_types="concept contract verification decision design index localized exempt"
readonly -a expected_locales=(ja zh-CN zh-TW ko es fr de pt-BR)

failures=0
checked=0

fail() {
  printf '%s:%s\n' "$1" "$2" >&2
  failures=$((failures + 1))
}

strip_fences() {
  awk '/^[[:space:]]*```/ { inside = !inside; next } !inside' "$1"
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
  h1_line="$(grep -n -m1 '^# ' -- "$1" | cut -d: -f1)"
  [[ -n "${h1_line}" ]] || return 1
  sed -n "$((h1_line + 1)),$((h1_line + 3))p" -- "$1" |
    grep -qE '^\[[^]]+\]\([^)]+\)( / .+)?$'
}

check_links() {
  local file="$1" prose_file="$2" directory target
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
  done < <(grep -oE '\]\([^)]+\)' -- "${prose_file}" | sed -E 's/^\]\(//; s/\)$//')
}

repository_relative_path() {
  local file="$1"
  if [[ "${file}" == "${repository_root}"/* ]]; then
    printf '%s\n' "${file#"${repository_root}"/}"
  else
    printf '%s\n' "${file}"
  fi
}

is_localized_path() {
  local relative_file
  relative_file="$(repository_relative_path "$1")"
  [[ "${relative_file}" == docs/i18n/* ]]
}

# Extract each fenced code block, including its opener and closer, and record
# the opener language. Markdown prose is allowed to differ between translations,
# but executable examples and other non-Mermaid blocks must remain byte-identical.
extract_fenced_blocks() {
  local file="$1" output_directory="$2" metadata_file
  metadata_file="${output_directory}/metadata.tsv"
  : > "${metadata_file}"

  awk \
    -v output_directory="${output_directory}" \
    -v metadata_file="${metadata_file}" \
    '
      function block_path(number) {
        return sprintf("%s/block-%04d", output_directory, number)
      }

      BEGIN {
        inside = 0
        number = 0
      }

      {
        if (!inside && $0 ~ /^[[:space:]]*```[^`]*$/) {
          number++
          inside = 1
          current = block_path(number)
          opener = $0
          language = $0
          sub(/^[[:space:]]*```/, "", language)
          sub(/^[[:space:]]+/, "", language)
          sub(/[[:space:]].*$/, "", language)
          print number "\t" language "\t" opener >> metadata_file
          print $0 > current
          next
        }

        if (inside) {
          print $0 > current
          if ($0 ~ /^[[:space:]]*```[[:space:]]*$/) {
            close(current)
            inside = 0
          }
          next
        }
      }

      END {
        if (inside) {
          close(current)
          exit 2
        }
        close(metadata_file)
      }
    ' "${file}"
}

compare_fenced_blocks() {
  local file="$1" canonical_directory="$2" translation_directory="$3"
  local canonical_metadata="${canonical_directory}/metadata.tsv"
  local translation_metadata="${translation_directory}/metadata.tsv"
  local -a canonical_entries=() translation_entries=()
  local index canonical_number canonical_language canonical_opener
  local translation_number translation_opener

  mapfile -t canonical_entries < "${canonical_metadata}"
  mapfile -t translation_entries < "${translation_metadata}"

  if [[ "${#canonical_entries[@]}" -ne "${#translation_entries[@]}" ]]; then
    fail "${file}" " fence block count differs from README.md: expected ${#canonical_entries[@]}, found ${#translation_entries[@]}"
    return
  fi

  for ((index = 0; index < ${#canonical_entries[@]}; index++)); do
    IFS=$'\t' read -r canonical_number canonical_language canonical_opener <<< "${canonical_entries[${index}]}"
    IFS=$'\t' read -r translation_number _ translation_opener <<< "${translation_entries[${index}]}"

    if [[ "${canonical_opener}" != "${translation_opener}" ]]; then
      fail "${file}" " fence opener ${index} differs from README.md"
    fi

    if [[ "${canonical_language}" != 'mermaid' ]] &&
      ! cmp -s -- \
        "${canonical_directory}/block-$(printf '%04d' "${canonical_number}")" \
        "${translation_directory}/block-$(printf '%04d' "${translation_number}")"; then
      fail "${file}" " non-Mermaid code block ${index} differs from README.md"
    fi
  done
}

check_localized_file() {
  local file="$1" prose_file="$2"
  local relative_file locale_directory locale_line canonical_line lines prose_lines h1_count

  relative_file="$(repository_relative_path "${file}")"
  locale_directory="$(basename -- "$(dirname -- "${file}")")"
  locale_line="$(sed -n '2p' -- "${file}")"
  canonical_line="$(sed -n '3p' -- "${file}")"

  if [[ ! "${locale_line}" =~ ^'<!-- locale: '([[:alnum:]]+(-[[:alnum:]]+)*)' -->'$ ]]; then
    fail "${file}" '2 localized pages require an exact locale marker: <!-- locale: <locale> -->'
  elif [[ "${relative_file}" == 'docs/i18n/README.md' ]]; then
    [[ "${BASH_REMATCH[1]}" == 'mul' ]] ||
      fail "${file}" '2 the multilingual parent index requires <!-- locale: mul -->'
  else
    if [[ "${BASH_REMATCH[1]}" != "${locale_directory}" ]]; then
      fail "${file}" "2 locale marker ${BASH_REMATCH[1]} does not match directory ${locale_directory}"
    fi
  fi

  [[ "${canonical_line}" == '<!-- canonical: docs/README.md -->' ]] ||
    fail "${file}" '3 localized pages require <!-- canonical: docs/README.md -->'

  h1_count="$(grep -c '^# ' -- "${prose_file}" || true)"
  [[ "${h1_count}" -eq 1 ]] ||
    fail "${file}" ' expected exactly one H1 heading'
  has_table "${prose_file}" ||
    fail "${file}" ' missing table required by localized pages'
  has_fence "${file}" 'mermaid' ||
    fail "${file}" ' missing mermaid diagram required by localized pages'
  check_links "${file}" "${prose_file}"

  lines="$(wc -l < "${file}")"
  prose_lines="$(grep -c '[^[:space:]]' -- "${prose_file}" || true)"
  [[ "${prose_lines}" -ge "${min_lines_localized}" ]] ||
    fail "${file}" " ${lines} lines (${prose_lines} non-blank prose lines), below the ${min_lines_localized} line floor for localized pages"

  # Keep this assignment visible to shellcheck and make the path restriction
  # explicit in the diagnostic when a caller passes an out-of-tree file.
  [[ "${relative_file}" == docs/i18n/* ]] ||
    fail "${file}" ' localized doc-type is only valid below docs/i18n/'
}

check_file() {
  local file="$1"
  local first_line doc_type lines prose_file h1_count

  checked=$((checked + 1))

  prose_file="$(mktemp)"
  strip_fences "${file}" > "${prose_file}"

  first_line="$(head -n 1 -- "${file}")"
  if [[ ! "${first_line}" =~ ^\<!--[[:space:]]doc-type:[[:space:]]([a-z]+)[[:space:]]--\>$ ]]; then
    fail "${file}" '1 missing doc-type marker on line 1 (see docs/document-conventions.md)'
    rm -f -- "${prose_file}"
    return
  fi
  doc_type="${BASH_REMATCH[1]}"

  if [[ " ${valid_types} " != *" ${doc_type} "* ]]; then
    fail "${file}" "1 unknown doc-type: ${doc_type} (valid: ${valid_types})"
    rm -f -- "${prose_file}"
    return
  fi

  if [[ "${doc_type}" == 'localized' ]]; then
    if ! is_localized_path "${file}"; then
      fail "${file}" ' localized doc-type is only valid below docs/i18n/'
    fi
    check_localized_file "${file}" "${prose_file}"
    rm -f -- "${prose_file}"
    return
  fi

  # Rules common to every type.
  h1_count="$(grep -c '^# ' -- "${prose_file}" || true)"
  if [[ "${h1_count}" -ne 1 ]]; then
    fail "${file}" ' expected exactly one H1 heading'
  fi
  # docs/README.md is the root of the tree and has no parent to point at.
  if [[ "${file}" != 'docs/README.md' ]]; then
    has_breadcrumb "${prose_file}" ||
      fail "${file}" ' missing breadcrumb line directly below the H1'
  fi
  grep -qE '^> \*\*対象読者:\*\* .+' -- "${prose_file}" ||
    fail "${file}" ' missing "> **対象読者:**" line'
  has_section "${prose_file}" '関連' ||
    fail "${file}" ' missing "## 関連" section'
  check_links "${file}" "${prose_file}"

  lines="$(wc -l < "${file}")"

  case "${doc_type}" in
    concept)
      has_source_link "${prose_file}" ||
        fail "${file}" ' missing link to a crates/**/*.rs source file'
      has_fence "${file}" 'mermaid' ||
        fail "${file}" ' missing mermaid diagram (at least one required)'
      has_section "${prose_file}" '正確な保証範囲' ||
        fail "${file}" ' missing "## 正確な保証範囲" section'
      has_section "${prose_file}" '変更時の確認点' ||
        fail "${file}" ' missing "## 変更時の確認点" section'
      [[ "${lines}" -ge "${min_lines_concept}" ]] ||
        fail "${file}" " ${lines} lines, below the ${min_lines_concept} line floor for concept pages"
      ;;
    contract)
      has_source_link "${prose_file}" ||
        fail "${file}" ' missing link to a crates/**/*.rs source file'
      has_table "${prose_file}" ||
        fail "${file}" ' missing table (contracts are written as tables, not prose)'
      has_section "${prose_file}" '保証範囲外' ||
        fail "${file}" ' missing "## 保証範囲外" section'
      [[ "${lines}" -ge "${min_lines_contract}" ]] ||
        fail "${file}" " ${lines} lines, below the ${min_lines_contract} line floor for contract pages"
      ;;
    verification)
      has_section "${prose_file}" 'local test で確認したこと' ||
        fail "${file}" ' missing "## local test で確認したこと" section'
      has_section "${prose_file}" '実行コマンド' ||
        fail "${file}" ' missing "## 実行コマンド" section'
      has_section "${prose_file}" '未検証の境界' ||
        fail "${file}" ' missing "## 未検証の境界" section'
      has_fence "${file}" 'bash' ||
        fail "${file}" ' missing bash block with the focused test commands'
      [[ "${lines}" -ge "${min_lines_verification}" ]] ||
        fail "${file}" " ${lines} lines, below the ${min_lines_verification} line floor for verification pages"
      ;;
    decision)
      for section in 'Status' '背景と課題' '検討した選択肢' '決定' '結果'; do
        has_section "${prose_file}" "${section}" ||
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
      has_table "${prose_file}" ||
        fail "${file}" ' missing table listing the child pages'
      has_fence "${file}" 'mermaid' ||
        fail "${file}" ' missing architecture diagram (at least one mermaid block required)'
      ;;
    exempt) ;;
  esac

  rm -f -- "${prose_file}"
}

check_language_switch() {
  local file="$1" prose_file="$2"
  local locale expected_target target found

  for locale in "${expected_locales[@]}"; do
    expected_target="README-${locale}.md"
    found=0
    while IFS= read -r target; do
      case "${target}" in
        http://* | https://* | mailto:* | '#'*) continue ;;
      esac
      target="${target%%#*}"
      while [[ "${target}" == ./* ]]; do
        target="${target#./}"
      done
      if [[ "${target}" == "${expected_target}" ]]; then
        found=1
        break
      fi
    done < <(grep -oE '\]\([^)]+\)' -- "${prose_file}" | sed -E 's/^\]\(//; s/\)$//')

    (( found == 1 )) ||
      fail "${file}" " language switch does not reach ${expected_target}"
  done
}

check_root_translation() {
  local locale="$1" file="$2" canonical_directory="$3" canonical_fences_valid="$4"
  local first_line second_line prose_file h1_count translation_directory

  first_line="$(sed -n '1p' -- "${file}")"
  second_line="$(sed -n '2p' -- "${file}")"
  [[ "${first_line}" == "<!-- locale: ${locale} -->" ]] ||
    fail "${file}" "1 expected <!-- locale: ${locale} -->"
  [[ "${second_line}" == '<!-- translation-source: README.md -->' ]] ||
    fail "${file}" '2 expected <!-- translation-source: README.md -->'

  prose_file="$(mktemp)"
  strip_fences "${file}" > "${prose_file}"
  h1_count="$(grep -c '^# ' -- "${prose_file}" || true)"
  [[ "${h1_count}" -eq 1 ]] ||
    fail "${file}" ' expected exactly one H1 heading'
  check_links "${file}" "${prose_file}"

  translation_directory="${canonical_directory}/$(basename -- "${file}")"
  mkdir -p -- "${translation_directory}"
  if extract_fenced_blocks "${file}" "${translation_directory}"; then
    if [[ "${canonical_fences_valid}" == true ]]; then
      compare_fenced_blocks "${file}" "${canonical_directory}" "${translation_directory}"
    fi
  else
    fail "${file}" ' contains an unterminated fenced code block'
  fi
  rm -f -- "${prose_file}"
}

check_translation_contract() {
  local audit_directory canonical_directory root_prose_file locale root_translation hub
  local canonical_fences_valid=false

  audit_directory="$(mktemp -d)"
  canonical_directory="${audit_directory}/README"
  mkdir -p -- "${canonical_directory}"

  if [[ ! -f README.md ]]; then
    fail 'README.md' ' missing canonical README.md'
  else
    root_prose_file="${audit_directory}/root-prose"
    strip_fences README.md > "${root_prose_file}"
    check_language_switch README.md "${root_prose_file}"
    if extract_fenced_blocks README.md "${canonical_directory}"; then
      canonical_fences_valid=true
    else
      fail 'README.md' ' contains an unterminated fenced code block'
    fi
  fi

  for locale in "${expected_locales[@]}"; do
    root_translation="README-${locale}.md"
    hub="docs/i18n/${locale}/README.md"

    if [[ -f "${root_translation}" ]]; then
      check_root_translation \
        "${locale}" "${root_translation}" "${canonical_directory}" "${canonical_fences_valid}"
    else
      fail "${root_translation}" ' missing expected root translation'
    fi

    [[ -f "${hub}" ]] ||
      fail "${hub}" ' missing expected localized documentation hub'
  done

  [[ -f docs/i18n/en/README.md ]] ||
    fail 'docs/i18n/en/README.md' ' missing English localized documentation hub'
  [[ -f docs/i18n/README.md ]] ||
    fail 'docs/i18n/README.md' ' missing multilingual documentation parent index'

  rm -rf -- "${audit_directory}"
}

main() {
  local files=()
  local run_translation_contract=false

  if [[ "$#" -gt 0 ]]; then
    files=("$@")
  else
    run_translation_contract=true
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

  if [[ "${run_translation_contract}" == true ]]; then
    check_translation_contract
  fi

  if [[ "${failures}" -gt 0 ]]; then
    printf '\ndocs policy: %d problem(s) across %d file(s)\n' \
      "${failures}" "${#files[@]}" >&2
    exit 1
  fi

  printf 'docs policy: %d file(s) checked, no problems\n' "${checked}"
}

main "$@"
