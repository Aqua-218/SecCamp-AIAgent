#!/usr/bin/env bash
#
# Proves every crate still carries a reachable verification page.
#
# This repository's central claim is that it says what it has not verified. That
# claim rests entirely on `docs/<crate>/verification.md` existing for every
# crate, being reachable from the crate's own documentation entry point, and
# carrying the `未検証の境界` section. A crate added without one gets its
# guarantees judged by its tests alone, which is exactly the confusion the
# section exists to prevent.
#
# `check-docs.sh` validates the shape of a verification page it is given. This
# checks the other direction: that a page exists for every workspace member and
# that a reader can get to it.

set -euo pipefail

readonly repository_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
cd -- "${repository_root}"

failures=0

fail() {
  printf 'FAIL %s\n' "$1" >&2
  failures=$((failures + 1))
}

mapfile -t workspace_members < <(
  awk '
    /^members = \[/ { inside = 1; next }
    /^\]/ { inside = 0 }
    inside {
      gsub(/[",]/, "")
      gsub(/^[[:space:]]+|[[:space:]]+$/, "")
      if ($0 != "") { sub(/^crates\//, ""); print }
    }
  ' Cargo.toml | sort
)

if [[ "${#workspace_members[@]}" -eq 0 ]]; then
  printf 'no workspace members found in Cargo.toml\n' >&2
  exit 1
fi

for member in "${workspace_members[@]}"; do
  readonly_entry="docs/${member}/README.md"
  verification_page="docs/${member}/verification.md"

  if [[ ! -f "${verification_page}" ]]; then
    fail "${member}: no verification page at ${verification_page}"
    continue
  fi

  if [[ ! -f "${readonly_entry}" ]]; then
    fail "${member}: no documentation entry point at ${readonly_entry}"
    continue
  fi

  if ! grep -qE '\]\(verification\.md[)#]' "${readonly_entry}"; then
    fail "${member}: ${readonly_entry} does not link to its verification page"
  fi

  if ! grep -qE '^##[[:space:]]+未検証の境界[[:space:]]*$' "${verification_page}"; then
    fail "${member}: ${verification_page} has no 未検証の境界 section"
  fi
done

# A verification page for something that is not a crate is fine, but one for a
# crate that no longer exists means the workspace shrank and the claim stayed.
while IFS= read -r page; do
  subject="$(basename "$(dirname "${page}")")"
  case "${subject}" in
    design | templates) continue ;;
  esac
  found=false
  for member in "${workspace_members[@]}"; do
    [[ "${member}" == "${subject}" ]] && found=true && break
  done
  if [[ "${found}" != true ]]; then
    fail "${page}: verification page for '${subject}', which is not a workspace member"
  fi
done < <(find docs -mindepth 2 -maxdepth 2 -type f -name 'verification.md' | sort)

if [[ "${failures}" -gt 0 ]]; then
  printf '\nverification traceability: %d problem(s)\n' "${failures}" >&2
  exit 1
fi

printf 'verification traceability: %d crate(s) have a reachable verification page\n' \
  "${#workspace_members[@]}"
