#!/usr/bin/env bash

set -euo pipefail

readonly repository_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
cd -- "${repository_root}"
mkdir -p -- reports

semgrep scan \
  --config .semgrep.yml \
  --error \
  --metrics off \
  --exclude target \
  --exclude lean/.lake \
  --json-output reports/semgrep.json \
  crates
