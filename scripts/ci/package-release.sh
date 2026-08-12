#!/usr/bin/env bash

set -euo pipefail

readonly repository_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
cd -- "${repository_root}"

if [[ "$#" -ne 1 ]]; then
  printf 'usage: %s <vMAJOR.MINOR.PATCH[-PRERELEASE]>\n' "$0" >&2
  exit 2
fi

readonly release_tag="$1"
if [[ ! "${release_tag}" =~ ^v[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]+)?$ ]]; then
  printf 'invalid release tag: %s\n' "${release_tag}" >&2
  exit 2
fi

readonly workspace_version="$(awk '
  /^\[workspace\.package\]$/ { in_workspace_package = 1; next }
  /^\[/ { in_workspace_package = 0 }
  in_workspace_package && /^version = / {
    gsub(/["[:space:]]/, "", $3); print $3; exit
  }
' Cargo.toml)"

if [[ "${release_tag#v}" != "${workspace_version}" ]]; then
  printf 'tag %s does not match workspace version %s\n' \
    "${release_tag}" "${workspace_version}" >&2
  exit 1
fi

readonly target_triple="x86_64-unknown-linux-gnu"
readonly host_triple="$(rustc -vV | awk '/^host:/ { print $2 }')"
readonly artifact_stem="authority-corpus-${release_tag}-${target_triple}"
readonly archive_name="${artifact_stem}.tar.gz"
readonly source_revision="$(git rev-parse HEAD)"
readonly source_epoch="$(git show -s --format=%ct HEAD)"
readonly staging_root="$(mktemp -d)"
readonly package_root="${staging_root}/${artifact_stem}"
trap 'rm -rf -- "${staging_root}"' EXIT

if [[ ! "${source_revision}" =~ ^[0-9a-f]{40}$ ]]; then
  printf 'source revision is not a full commit SHA\n' >&2
  exit 1
fi
if [[ "${host_triple}" != "${target_triple}" ]]; then
  printf 'release runner host %s does not match artifact target %s\n' \
    "${host_triple}" "${target_triple}" >&2
  exit 1
fi

mkdir -p -- dist "${package_root}/bin"
cargo build --release --locked --target "${target_triple}" \
  --package authority-core --bin authority-corpus
install -m 0755 "target/${target_triple}/release/authority-corpus" \
  "${package_root}/bin/authority-corpus"

cat > "${package_root}/BUILD-METADATA.json" <<EOF
{
  "artifact": "${artifact_stem}",
  "source_revision": "${source_revision}",
  "source_tag": "${release_tag}",
  "target": "${target_triple}",
  "workspace_version": "${workspace_version}"
}
EOF

tar \
  --sort=name \
  --mtime="@${source_epoch}" \
  --owner=0 \
  --group=0 \
  --numeric-owner \
  -czf "dist/${archive_name}" \
  -C "${staging_root}" "${artifact_stem}"

cat > dist/release.env <<EOF
RELEASE_TAG=${release_tag}
ARTIFACT_STEM=${artifact_stem}
ARCHIVE_NAME=${archive_name}
SBOM_NAME=${archive_name}.spdx.json
CHECKSUM_NAME=SHA256SUMS
SIGNATURE_BUNDLE_NAME=SHA256SUMS.sigstore.json
SOURCE_REVISION=${source_revision}
SOURCE_EPOCH=${source_epoch}
EOF

printf '%s\n' "dist/${archive_name}"
