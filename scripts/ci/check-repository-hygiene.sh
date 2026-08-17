#!/usr/bin/env bash
#
# Rejects the tracked-file mistakes that no compiler or linter will catch.
#
# Each check here corresponds to something that has a security or reviewability
# cost rather than a stylistic one:
#
#   executable bits   A tracked file that is executable and is not a script is
#                     either a committed binary or an accident. Both are things
#                     a reviewer reads as "someone meant this".
#   build artifacts   Anything under an ignored output directory that is tracked
#                     anyway ships bytes nobody rebuilt from source.
#   large files       A blob too big to read in review is a blob nobody reviewed.
#   CRLF              Mixed line endings make a diff lie about what changed.
#   .env              A committed environment file is how credentials leak.

set -euo pipefail

readonly repository_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
cd -- "${repository_root}"

# 1 MiB. Cargo.lock and the licence text are the largest legitimate files here
# and both sit far below it.
readonly maximum_tracked_bytes=$((1024 * 1024))

failures=0

fail() {
  printf 'FAIL %s\n' "$1" >&2
  failures=$((failures + 1))
}

mapfile -t tracked_files < <(git ls-files)

if [[ "${#tracked_files[@]}" -eq 0 ]]; then
  printf 'no tracked files found; run this inside the repository\n' >&2
  exit 1
fi

for tracked in "${tracked_files[@]}"; do
  [[ -f "${tracked}" ]] || continue

  if [[ -x "${tracked}" ]]; then
    # In a `case` pattern `*` spans slashes, so this covers every depth below
    # scripts/.
    case "${tracked}" in
      scripts/*.sh) ;;
      *) fail "${tracked}: tracked file is executable but is not a script" ;;
    esac
  fi

  case "${tracked}" in
    target/* | dist/* | coverage/* | reports/* | .ci-tools/* | .cargo-home/* | lean/.lake/*)
      fail "${tracked}: build output is tracked"
      ;;
    .env | .env.*)
      if [[ "${tracked}" != '.env.example' ]]; then
        fail "${tracked}: environment files must not be tracked"
      fi
      ;;
  esac

  file_bytes="$(wc -c < "${tracked}")"
  if [[ "${file_bytes}" -gt "${maximum_tracked_bytes}" ]]; then
    fail "${tracked}: ${file_bytes} bytes exceeds the ${maximum_tracked_bytes} byte review limit"
  fi

  if LC_ALL=C grep -qU $'\r$' -- "${tracked}"; then
    fail "${tracked}: contains CRLF line endings"
  fi
done

# A script that is not executable is a job that fails at run time with a
# permission error rather than a readable message.
while IFS= read -r script_file; do
  if [[ ! -x "${script_file}" ]]; then
    fail "${script_file}: script is tracked without an executable bit"
  fi
done < <(printf '%s\n' "${tracked_files[@]}" | grep -E '^scripts/.*\.sh$' || true)

if [[ "${failures}" -gt 0 ]]; then
  printf '\nrepository hygiene: %d problem(s)\n' "${failures}" >&2
  exit 1
fi

printf 'repository hygiene: %d tracked file(s) checked, no problems\n' "${#tracked_files[@]}"
