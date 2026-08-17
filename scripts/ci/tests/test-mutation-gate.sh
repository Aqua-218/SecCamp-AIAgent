#!/usr/bin/env bash

set -euo pipefail

readonly repository_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly work_directory="$(mktemp -d)"
trap 'find "${work_directory}" -type f -delete; find "${work_directory}" -depth -type d -empty -delete' EXIT

cat > "${work_directory}/cargo" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [[ "${MUTATION_MOCK_OUTCOME:-pass}" == 'pass' ]]; then
  printf '28/28 mutants tested, 19 caught, 9 unviable, 0s elapsed\n'
else
  printf '3/3 mutants tested, 2 caught, 1 MISSED\n'
fi
EOF
chmod 0755 "${work_directory}/cargo"
printf '#!/usr/bin/env bash\nexit 0\n' > "${work_directory}/cargo-mutants"
chmod 0755 "${work_directory}/cargo-mutants"

if ! MUTATION_MOCK_OUTCOME=pass PATH="${work_directory}:${PATH}" \
  CI_TOOLS_DIR=.ci-tools "${repository_root}/scripts/ci/run-mutation.sh" 2 egress-protocol; then
  printf 'mutation gate self-test: caught-only summary unexpectedly failed\n' >&2
  exit 1
fi
if MUTATION_MOCK_OUTCOME=missed PATH="${work_directory}:${PATH}" \
  CI_TOOLS_DIR=.ci-tools "${repository_root}/scripts/ci/run-mutation.sh" 2 egress-protocol; then
  printf 'mutation gate self-test: surviving mutant unexpectedly passed\n' >&2
  exit 1
fi
printf 'mutation gate self-test: positive and negative cases passed\n'
