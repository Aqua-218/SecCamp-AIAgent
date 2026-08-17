#!/usr/bin/env bash

set -euo pipefail

readonly repository_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly checker="${repository_root}/scripts/ci/run-benchmark.sh"
readonly work_directory="$(mktemp -d)"
trap 'rm -rf -- "${work_directory}"' EXIT

cat > "${work_directory}/healthy.txt" <<'EOF'
test capability_check/commit ... bench:         600 ns/iter (+/- 20 ns/iter)
test capability_check/observe ... bench:         140 ns/iter (+/- 5 ns/iter)
EOF
cat > "${work_directory}/regressed.txt" <<'EOF'
test capability_check/commit ... bench:        2000 ns/iter (+/- 20 ns/iter)
test capability_check/observe ... bench:         140 ns/iter (+/- 5 ns/iter)
EOF
cat > "${work_directory}/unbaselined.txt" <<'EOF'
test capability_check/commit ... bench:         600 ns/iter (+/- 20 ns/iter)
test capability_check/observe ... bench:         140 ns/iter (+/- 5 ns/iter)
test capability_check/new_path ... bench:         100 ns/iter (+/- 5 ns/iter)
EOF

if ! BENCHMARK_BASELINE="${repository_root}/ci/benchmarks/capability-check.baseline" \
  "${checker}" --validate-output "${work_directory}/healthy.txt"; then
  printf 'benchmark self-test: healthy output unexpectedly failed\n' >&2
  exit 1
fi
if BENCHMARK_BASELINE="${repository_root}/ci/benchmarks/capability-check.baseline" \
  "${checker}" --validate-output "${work_directory}/regressed.txt"; then
  printf 'benchmark self-test: regressed output unexpectedly passed\n' >&2
  exit 1
fi
if BENCHMARK_BASELINE="${repository_root}/ci/benchmarks/capability-check.baseline" \
  "${checker}" --validate-output "${work_directory}/unbaselined.txt"; then
  printf 'benchmark self-test: unbaselined output unexpectedly passed\n' >&2
  exit 1
fi
printf 'benchmark gate self-test: positive and negative cases passed\n'
