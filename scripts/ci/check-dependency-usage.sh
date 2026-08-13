#!/usr/bin/env bash
#
# Finds dependencies a crate declares and never mentions.
#
# An unused dependency is not a style problem here. Every entry in a manifest is
# code that `cargo audit` must keep clearing, that `cargo deny` must keep
# licensing, and that lands in the SBOM attached to a signed release. A crate
# that stopped using a library should stop shipping it.
#
# The check is lexical on purpose: it looks for the crate identifier anywhere in
# the crate's own sources. That cannot be fooled into a false pass by feature
# unification the way a build can, and the only way it produces a false failure
# is a dependency used exclusively through a macro that never names it.
# `ci/dependency-usage-allow.txt` exists for that case and requires a reason.

set -euo pipefail

readonly repository_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
cd -- "${repository_root}"

readonly allowlist='ci/dependency-usage-allow.txt'

failures=0
checked=0

fail() {
  printf 'FAIL %s\n' "$1" >&2
  failures=$((failures + 1))
}

allowed() {
  local entry="$1"
  [[ -f "${allowlist}" ]] || return 1
  grep -vE '^[[:space:]]*(#|$)' "${allowlist}" | grep -qxF "${entry}"
}

# Emits every dependency name from every dependency table in one manifest,
# including target-specific and dev tables. A renamed dependency
# (`foo = { package = "bar" }`) is reported under the name the source uses.
dependency_names() {
  awk '
    /^\[/ {
      in_dependencies = ($0 ~ /^\[([^]]*\.)?(dependencies|dev-dependencies|build-dependencies)\]$/)
      next
    }
    !in_dependencies { next }
    # Only a column-zero `name = ...` starts an entry. A continuation line of an
    # inline table is indented and must not be read as another dependency.
    /^[A-Za-z_][A-Za-z0-9_-]*[[:space:]]*=/ {
      name = $1
      gsub(/[[:space:]]/, "", name)
      print name
    }
  ' "$1"
}

for manifest in crates/*/Cargo.toml; do
  crate_directory="$(dirname -- "${manifest}")"
  crate_name="$(basename -- "${crate_directory}")"

  while IFS= read -r dependency; do
    [[ -n "${dependency}" ]] || continue
    checked=$((checked + 1))

    # Rust sees `-` in a package name as `_` in an identifier, and a path
    # dependency may be referenced either way in attributes and documentation.
    identifier="${dependency//-/_}"

    if grep -rqE "(^|[^A-Za-z0-9_])(${dependency}|${identifier})([^A-Za-z0-9_]|$)" \
      --include='*.rs' -- "${crate_directory}"; then
      continue
    fi

    if allowed "${crate_name}/${dependency}"; then
      continue
    fi

    fail "${manifest}: '${dependency}' is declared but never named in ${crate_directory}"
  done < <(dependency_names "${manifest}")
done

if [[ "${failures}" -gt 0 ]]; then
  printf '\ndependency usage: %d unused declaration(s) across %d dependencies\n' \
    "${failures}" "${checked}" >&2
  exit 1
fi

printf 'dependency usage: %d declaration(s) checked, all referenced\n' "${checked}"
