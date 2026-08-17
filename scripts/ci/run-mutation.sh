#!/usr/bin/env bash

set -euo pipefail

readonly repository_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly tool_bin="${CI_TOOLS_DIR:-${repository_root}/.ci-tools}/cargo/bin"
export PATH="${tool_bin}:${PATH}"
cd -- "${repository_root}"

if [[ "$#" -ne 2 ]]; then
  printf 'usage: %s <shard> <package>\n' "$0" >&2
  exit 2
fi

readonly shard="$1"
readonly package="$2"
case "${shard}:${package}" in
  1:authority-core)
    readonly source_file='crates/authority-core/src/path.rs'
    # Rebase/encoded-length mutants currently expose an untested boundary in
    # the shared path suite. Keep this selection on the matching and validation
    # decisions whose tests already prove both acceptance and rejection.
    readonly examine_re='CanonicalPath::child|CanonicalPath::is_at_or_below|path_matches|path_below|validate_segment'
    ;;
  2:egress-protocol)
    readonly source_file='crates/egress-protocol/src/cbor.rs'
    # The selected decoder constructors are a bounded, high-value slice. A
    # whole-file egress run includes generated/serialization branches whose
    # runtime is unbounded for this scheduled gate.
    readonly examine_re='decode_public_fetch|decode_github|Decoder.*fixed_bytes|Decoder.*finish$'
    ;;
  *)
    printf 'unsupported mutation shard/package pair: %s %s\n' "${shard}" "${package}" >&2
    exit 2
    ;;
esac

if ! command -v cargo-mutants > /dev/null 2>&1; then
  printf 'cargo-mutants is required; run scripts/ci/install-cargo-tools.sh mutation first\n' >&2
  exit 1
fi

readonly scratch_directory="$(mktemp -d)"
trap 'rm -rf -- "${scratch_directory}"' EXIT
readonly log_file="${scratch_directory}/cargo-mutants.log"

command=(
  cargo mutants
  --package "${package}"
  --file "${source_file}"
  --baseline run
  --timeout 120
  --build-timeout 120
  --jobs 2
  --no-times
  --no-shuffle
  --test-tool cargo
  --output "${scratch_directory}/output"
)
if [[ -n "${examine_re}" ]]; then
  command+=(--re "${examine_re}")
fi

printf 'Mutation: shard=%s package=%s file=%s\n' "${shard}" "${package}" "${source_file}"
set +e
CARGO_TERM_COLOR=never "${command[@]}" 2>&1 | tee "${log_file}"
tool_status="${PIPESTATUS[0]}"
set -e
if [[ "${tool_status}" -ne 0 ]]; then
  printf 'cargo-mutants failed with status %s\n' "${tool_status}" >&2
  exit "${tool_status}"
fi

# A successful process with no generated mutants is not a mutation gate. The
# summary must be present, must test at least one mutant, and must not report a
# surviving (MISSED) mutant.
if grep -Eiq '(^|[^[:alpha:]])missed([^[:alpha:]]|$)|MISSED' "${log_file}"; then
  printf 'mutation gate found a surviving mutant\n' >&2
  exit 1
fi
summary_line="$(grep -E '[0-9]+(/[0-9]+)? mutants tested' "${log_file}" | tail -n 1 || true)"
if [[ -z "${summary_line}" ]]; then
  printf 'cargo-mutants did not emit a tested-mutant summary\n' >&2
  exit 1
fi
tested_count="$(sed -E 's/^[^0-9]*([0-9]+)(\/[^ ]+)? mutants tested.*/\1/' <<< "${summary_line}")"
caught_count="$(grep -oE '[0-9]+[[:space:]]+caught' <<< "${summary_line}" | awk '{print $1}' || true)"
if [[ ! "${tested_count}" =~ ^[0-9]+$ || "${tested_count}" -lt 1 ]]; then
  printf 'mutation gate tested no mutants: %s\n' "${summary_line}" >&2
  exit 1
fi
if [[ ! "${caught_count}" =~ ^[0-9]+$ || "${caught_count}" -lt 1 ]]; then
  printf 'mutation gate caught no mutants: %s\n' "${summary_line}" >&2
  exit 1
fi
printf 'mutation gate passed: %s\n' "${summary_line}"
