#!/usr/bin/env bash

set -euo pipefail

readonly repository_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly default_baseline="${repository_root}/ci/benchmarks/capability-check.baseline"
benchmark_temp_directory=""

cleanup_benchmark_temp_directory() {
  if [[ -n "${benchmark_temp_directory}" ]]; then
    rm -rf -- "${benchmark_temp_directory}"
    benchmark_temp_directory=""
  fi
}

convert_to_ns() {
  local value="$1" unit="$2"
  case "${unit}" in
    ns) printf '%s\n' "${value}" ;;
    us|μs|µs) printf '%s\n' "$((value * 1000))" ;;
    ms) printf '%s\n' "$((value * 1000000))" ;;
    s) printf '%s\n' "$((value * 1000000000))" ;;
    *)
      printf 'unsupported Criterion time unit: %s\n' "${unit}" >&2
      return 1
      ;;
  esac
}

validate_output() {
  local output_file="$1"
  local baseline_file="${BENCHMARK_BASELINE:-${default_baseline}}"
  [[ -f "${output_file}" ]] || { printf 'benchmark output is missing: %s\n' "${output_file}" >&2; return 1; }
  [[ -f "${baseline_file}" ]] || { printf 'benchmark baseline is missing: %s\n' "${baseline_file}" >&2; return 1; }

  declare -A measured_ns=()
  declare -A spread_ns=()
  declare -A expected_names=()
  local line name value unit spread spread_unit
  while IFS= read -r line; do
    [[ "${line}" =~ ^test[[:space:]]+ ]] || continue
    name="$(awk '{print $2}' <<< "${line}")"
    if [[ "${line}" =~ bench:[[:space:]]+([0-9]+)[[:space:]]+([^/[:space:]]+)/iter[[:space:]]+\(\+/-[[:space:]]+([0-9]+)[[:space:]]+([^/[:space:]]+)/iter ]]; then
      value="${BASH_REMATCH[1]}"
      unit="${BASH_REMATCH[2]}"
      spread="${BASH_REMATCH[3]}"
      spread_unit="${BASH_REMATCH[4]}"
      measured_ns["${name}"]="$(convert_to_ns "${value}" "${unit}")"
      spread_ns["${name}"]="$(convert_to_ns "${spread}" "${spread_unit}")"
    elif [[ "${line}" =~ bench:[[:space:]]+([0-9]+)[[:space:]]+([^/[:space:]]+)/iter[[:space:]]+\(\+/-[[:space:]]+([0-9]+)\) ]]; then
      value="${BASH_REMATCH[1]}"
      unit="${BASH_REMATCH[2]}"
      spread="${BASH_REMATCH[3]}"
      measured_ns["${name}"]="$(convert_to_ns "${value}" "${unit}")"
      spread_ns["${name}"]="$(convert_to_ns "${spread}" "${unit}")"
    fi
  done < "${output_file}"

  local failures=0 baseline threshold noise measured spread relative spread_allow allowance upper
  while read -r name baseline threshold noise; do
    [[ -n "${name}" ]] || continue
    [[ "${name}" == \#* ]] && continue
    expected_names["${name}"]=1
    if [[ ! "${baseline}" =~ ^[0-9]+$ || ! "${threshold}" =~ ^[0-9]+$ || ! "${noise}" =~ ^[0-9]+$ || "${baseline}" -le 0 ]]; then
      printf 'invalid benchmark baseline row: %s %s %s %s\n' "${name}" "${baseline}" "${threshold}" "${noise}" >&2
      failures=$((failures + 1))
      continue
    fi
    if [[ -z "${measured_ns[${name}]+present}" ]]; then
      printf 'benchmark output is missing required measurement: %s\n' "${name}" >&2
      failures=$((failures + 1))
      continue
    fi
    measured="${measured_ns[${name}]}"
    spread="${spread_ns[${name}]}"
    relative=$((baseline * threshold / 100))
    spread_allow=$((spread * 3))
    allowance="${relative}"
    if (( spread_allow > allowance )); then
      allowance="${spread_allow}"
    fi
    if (( noise > allowance )); then
      allowance="${noise}"
    fi
    upper=$((baseline + allowance))
    printf 'benchmark %s: measured=%sns baseline=%sns spread=%sns allowed_upper=%sns\n' \
      "${name}" "${measured}" "${baseline}" "${spread}" "${upper}"
    if (( measured > upper )); then
      printf 'benchmark regression: %s is %sns, above %sns\n' "${name}" "${measured}" "${upper}" >&2
      failures=$((failures + 1))
    fi
  done < "${baseline_file}"

  for name in "${!measured_ns[@]}"; do
    if [[ -z "${expected_names[${name}]+present}" ]]; then
      printf 'benchmark output contains an unbaselined measurement: %s\n' "${name}" >&2
      failures=$((failures + 1))
    fi
  done

  (( failures == 0 )) || { printf 'benchmark gate failed: %d regression/contract error(s)\n' "${failures}" >&2; return 1; }
}

main() {
  cd -- "${repository_root}"
  if [[ "$(uname -s)" != 'Linux' ]]; then
    printf 'Benchmark gate requires Linux; refusing to run on %s\n' "$(uname -s)" >&2
    exit 1
  fi
  if [[ "${1:-}" == '--validate-output' ]]; then
    [[ "$#" -eq 2 ]] || { printf 'usage: %s --validate-output <file>\n' "$0" >&2; exit 2; }
    validate_output "$2"
    return
  fi

  if [[ -e /dev/fuse ]]; then
    printf 'Privileged FUSE benchmark availability: device-present (mount not exercised; outside this standard gate)\n'
  else
    printf 'Privileged FUSE benchmark availability: device-unavailable (layers intentionally excluded from this standard gate)\n'
  fi
  if [[ "${REQUIRE_FUSE:-0}" == '1' && ! -e /dev/fuse ]]; then
    printf 'REQUIRE_FUSE=1 but /dev/fuse is unavailable\n' >&2
    exit 1
  fi

  local output_file benchmark_status
  benchmark_temp_directory="$(mktemp -d)"
  trap cleanup_benchmark_temp_directory EXIT
  output_file="${benchmark_temp_directory}/criterion-bencher.txt"
  set +e
  CARGO_TERM_COLOR=never cargo bench --locked --package capfs --bench capfs_overhead -- \
    capability_check --noplot --sample-size 10 --warm-up-time 0.5 \
    --measurement-time 0.5 --nresamples 1000 --noise-threshold 0.05 \
    --output-format bencher --quiet 2>&1 | tee "${output_file}"
  benchmark_status="${PIPESTATUS[0]}"
  set -e
  if [[ "${benchmark_status}" -ne 0 ]]; then
    printf 'criterion benchmark failed with status %s\n' "${benchmark_status}" >&2
    exit "${benchmark_status}"
  fi
  validate_output "${output_file}"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
