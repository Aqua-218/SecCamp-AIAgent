#!/usr/bin/env bash

# Deterministic negative tests for the privileged installer trust boundary. The tests source the
# installers only to exercise their pure path/archive validators; no network, Cargo, veritysetup,
# or repository cache is touched.
# shellcheck disable=SC1091,SC2016,SC2154

set -euo pipefail
umask 077

test_repository_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly test_repository_root
test_root="$(mktemp -d -- "${TMPDIR:-/tmp}/install-boundaries.XXXXXX")"
readonly test_root
trap 'rm -rf -- "${test_root}"' EXIT

fail() {
  printf 'install-boundary self-test: %s\n' "$*" >&2
  exit 1
}

expect_failure() {
  if "$@"; then
    fail "expected failure: $*"
  fi
}

run_firecracker_tests() (
  set -euo pipefail
  source "${test_repository_root}/scripts/ci/install-firecracker.sh"

  local root="${test_root}/firecracker"
  local release_dir="${root}/release-v${firecracker_version}-x86_64"
  local archive="${test_root}/firecracker.tgz"
  local outside="${test_root}/outside"
  local output="${test_root}/extracted-firecracker"
  mkdir -p -- "${release_dir}"
  printf '#!/usr/bin/env bash\nprintf Firecracker-test\\n' > "${release_dir}/firecracker-v${firecracker_version}-x86_64"
  printf '#!/usr/bin/env bash\nprintf Jailer-test\\n' > "${release_dir}/jailer-v${firecracker_version}-x86_64"
  chmod 0755 "${release_dir}/firecracker-v${firecracker_version}-x86_64" \
    "${release_dir}/jailer-v${firecracker_version}-x86_64"
  printf keep > "${outside}"
  ln -s -- "${outside}" "${release_dir}/unrelated-link"
  printf traversal > "${root}/escape"
  tar -czf "${archive}" --transform='s#escape#../escape#' -C "${root}" \
    "release-v${firecracker_version}-x86_64" escape

  validate_archive_members "${archive}" \
    || fail 'valid archive members were rejected'
  extract_archive_member "${archive}" "${firecracker_member}" "${output}" \
    || fail 'exact regular archive member was not extracted'
  grep -Fq 'Firecracker-test' "${output}" \
    || fail 'extracted bytes differ from the expected member'
  [[ "$(<"${outside}")" == keep ]] \
    || fail 'archive traversal or link changed an unrelated path'

  local bad_root="${test_root}/firecracker-bad"
  local bad_release_dir="${bad_root}/release-v${firecracker_version}-x86_64"
  local bad_archive="${test_root}/firecracker-bad.tgz"
  mkdir -p -- "${bad_release_dir}"
  ln -s -- "${outside}" "${bad_release_dir}/firecracker-v${firecracker_version}-x86_64"
  printf jailer > "${bad_release_dir}/jailer-v${firecracker_version}-x86_64"
  chmod 0755 "${bad_release_dir}/jailer-v${firecracker_version}-x86_64"
  tar -czf "${bad_archive}" -C "${bad_root}" \
    "release-v${firecracker_version}-x86_64"
  expect_failure validate_archive_members "${bad_archive}"

  local corrupt_cache="${test_root}/corrupt-firecracker-cache"
  printf corrupt > "${corrupt_cache}"
  expect_failure archive_cache_is_valid "${corrupt_cache}"
  printf partial > "${test_root}/firecracker.tgz.download.partial"
  expect_failure no_stale_entries "${test_root}" 'firecracker.tgz.download.'
  local unsafe_dir="${test_root}/unsafe-firecracker-dir"
  mkdir -p -- "${unsafe_dir}"
  chmod 0777 "${unsafe_dir}"
  expect_failure directory_is_safe "${unsafe_dir}"
  local ancestor_real="${test_root}/firecracker-ancestor-real"
  local ancestor_link="${test_root}/firecracker-ancestor-link"
  mkdir -p -- "${ancestor_real}"
  ln -s -- "${ancestor_real}" "${ancestor_link}"
  expect_failure parent_chain_is_safe "${ancestor_link}/child"

  local install_tree="${test_root}/firecracker-install"
  local install_link="${test_root}/firecracker-install-link"
  ln -s -- "${install_tree}" "${install_link}"
  expect_failure validate_install_tree "${install_link}"
  mkdir -p -- "${install_tree}"
  printf firecracker > "${install_tree}/firecracker"
  printf jailer > "${install_tree}/jailer"
  chmod 0755 "${install_tree}/firecracker" "${install_tree}/jailer"
  validate_install_tree "${install_tree}" || fail 'complete install tree was rejected'
  rm -- "${install_tree}/jailer"
  expect_failure validate_install_tree "${install_tree}"
  printf jailer > "${install_tree}/jailer"
  chmod 0755 "${install_tree}/jailer"
  ln -s -- "${outside}" "${install_tree}/unexpected-link"
  expect_failure validate_install_tree "${install_tree}"
  rm -- "${install_tree}/unexpected-link"
  printf unexpected > "${install_tree}/unexpected
name"
  expect_failure validate_install_tree "${install_tree}"
)

run_guest_tests() (
  set -euo pipefail
  source "${test_repository_root}/scripts/ci/install-guest-artifacts.sh"

  local corrupt_cache="${test_root}/corrupt-guest-cache"
  printf corrupt > "${corrupt_cache}"
  expect_failure pinned_cache_is_valid "${corrupt_cache}" "${kernel_sha256}"
  printf partial > "${test_root}/vmlinux-6.1.128.download.partial"
  expect_failure no_stale_entries "${test_root}" 'vmlinux-6.1.128.download.'
  local cache_link="${test_root}/guest-cache-link"
  ln -s -- "${corrupt_cache}" "${cache_link}"
  expect_failure cache_file_is_safe "${cache_link}"

  local unsafe_dir="${test_root}/unsafe-guest-dir"
  mkdir -p -- "${unsafe_dir}"
  chmod 0777 "${unsafe_dir}"
  expect_failure directory_is_safe "${unsafe_dir}"

  local install_tree="${test_root}/guest-install"
  local install_link="${test_root}/guest-install-link"
  ln -s -- "${install_tree}" "${install_link}"
  expect_failure validate_install_tree "${install_link}"
  mkdir -p -- "${install_tree}"
  printf kernel > "${install_tree}/${kernel_name}"
  printf rootfs > "${install_tree}/${rootfs_name}"
  printf hash > "${install_tree}/${rootfs_name}.hash"
  printf 'Root hash: %064d\n' 0 > "${install_tree}/${rootfs_name}.verity"
  chmod 0444 "${install_tree}"/*
  validate_install_tree "${install_tree}" || fail 'complete guest install tree was rejected'
  rm -- "${install_tree}/${rootfs_name}.hash"
  expect_failure validate_install_tree "${install_tree}"
  printf hash > "${install_tree}/${rootfs_name}.hash"
  chmod 0444 "${install_tree}/${rootfs_name}.hash"
  ln -s -- "${test_root}/outside" "${install_tree}/unexpected-link"
  expect_failure validate_install_tree "${install_tree}"
)

run_cargo_tests() (
  set -euo pipefail
  source "${test_repository_root}/scripts/ci/install-cargo-tools.sh"

  local good="${test_root}/cargo-nextest"
  printf '#!/usr/bin/env bash\nprintf "cargo-nextest 0.9.143 (fixture)\\n"\n' > "${good}"
  chmod 0755 "${good}"
  tool_matches_version_from_path "${good}" cargo-nextest 0.9.143 \
    || fail 'exact Cargo tool version was rejected'

  local wrong="${test_root}/cargo-nextest-wrong"
  printf '#!/usr/bin/env bash\nprintf "cargo-nextest 0.9.1430\\n"\n' > "${wrong}"
  chmod 0755 "${wrong}"
  expect_failure tool_matches_version_from_path "${wrong}" cargo-nextest 0.9.143

  local link="${test_root}/cargo-nextest-link"
  ln -s -- "${good}" "${link}"
  expect_failure regular_file_is_safe "${link}" 755
  local unsafe_dir="${test_root}/unsafe-cargo-dir"
  mkdir -p -- "${unsafe_dir}"
  chmod 0777 "${unsafe_dir}"
  expect_failure directory_is_safe "${unsafe_dir}"
  mkdir -p -- "${test_root}/.staging-cargo-nextest.partial"
  expect_failure no_stale_entries "${test_root}" '.staging-cargo-nextest.'

  local fake_bin="${test_root}/fake-cargo-bin"
  local fake_cargo="${fake_bin}/cargo"
  local cargo_tools_root="${test_root}/cargo-tools"
  local cargo_marker="${test_root}/fake-cargo-called"
  mkdir -p -- "${fake_bin}"
  printf '%s\n' \
    '#!/usr/bin/env bash' \
    'set -euo pipefail' \
    'root=' \
    'version=' \
    'crate=' \
    'while (($#)); do' \
    '  case "$1" in' \
    '    --root|--version|--registry) key="$1"; value="$2"; shift 2;;' \
    '    --locked) shift;;' \
    '    *) crate="$1"; shift;;' \
    '  esac' \
    '  case "${key:-}" in --root) root="$value";; --version) version="$value";; esac' \
    '  key=' \
    'done' \
    'if [[ -e "${FAKE_CARGO_MARKER}" ]]; then exit 77; fi' \
    'printf marker > "${FAKE_CARGO_MARKER}"' \
    'mkdir -p "${root}/bin"' \
    'printf "#!/usr/bin/env bash\\nprintf \"%s %s (fixture)\\\\n\"\\n" "${crate}" "${version}" > "${root}/bin/${crate}"' \
    '# Real cargo install honors the caller umask and emits an owner-only staging binary.' \
    'chmod 0700 "${root}/bin/${crate}"' \
    > "${fake_cargo}"
  chmod 0755 "${fake_cargo}"
  PATH="${fake_bin}:${PATH}" CI_TOOLS_DIR="${cargo_tools_root}" \
    FAKE_CARGO_MARKER="${cargo_marker}" \
    "${test_repository_root}/scripts/ci/install-cargo-tools.sh" nextest > /dev/null \
    || fail 'isolated Cargo staging install failed'
  PATH="${fake_bin}:${PATH}" CI_TOOLS_DIR="${cargo_tools_root}" \
    FAKE_CARGO_MARKER="${cargo_marker}" \
    "${test_repository_root}/scripts/ci/install-cargo-tools.sh" nextest > /dev/null \
    || fail 'valid Cargo cache was not reused'
  local installed_tool="${cargo_tools_root}/cargo/bin/cargo-nextest"
  [[ "$(stat -c '%a' -- "${installed_tool}")" == 755 ]] \
    || fail 'published Cargo tool mode was not normalized to 0755'
  rm -- "${installed_tool}"
  ln -s -- "${good}" "${installed_tool}"
  if PATH="${fake_bin}:${PATH}" CI_TOOLS_DIR="${cargo_tools_root}" \
    FAKE_CARGO_MARKER="${cargo_marker}" \
    "${test_repository_root}/scripts/ci/install-cargo-tools.sh" nextest > /dev/null 2>&1; then
    fail 'Cargo symlink replacement was accepted'
  fi
)

run_firecracker_tests
run_guest_tests
run_cargo_tests
printf 'install-boundary self-test: PASS\n'
