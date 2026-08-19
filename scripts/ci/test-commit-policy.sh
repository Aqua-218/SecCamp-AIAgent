#!/usr/bin/env bash

set -euo pipefail

readonly repository_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly checker="${repository_root}/scripts/ci/check-commit-policy.sh"
readonly fixture_root="$(mktemp -d)"
trap 'rm -rf -- "${fixture_root}"' EXIT

fail() {
  printf 'FAIL %s\n' "$1" >&2
  exit 1
}

git_fixture="${fixture_root}/fixture"
git init --quiet --initial-branch=main "${git_fixture}"
git -C "${git_fixture}" config user.name 'CI commit policy'
git -C "${git_fixture}" config user.email 'ci-commit-policy@example.invalid'
git -C "${git_fixture}" config commit.gpgsign false

git -C "${git_fixture}" commit --quiet --allow-empty -m 'chore(test): initialize fixture'
base_revision="$(git -C "${git_fixture}" rev-parse HEAD)"
git -C "${git_fixture}" commit --quiet --allow-empty -m 'feat(ci): add a valid commit'
head_revision="$(git -C "${git_fixture}" rev-parse HEAD)"

"${checker}" --repo "${git_fixture}" --base "${base_revision}" --head "${head_revision}"

domain_type_base="${head_revision}"
for subject in \
  'style(ci): format a workflow fixture' \
  'bench(ci): measure a pipeline fixture' \
  'prove(ci): verify a policy fixture'; do
  git -C "${git_fixture}" commit --quiet --allow-empty -m "${subject}"
done
domain_type_head="$(git -C "${git_fixture}" rev-parse HEAD)"
"${checker}" --repo "${git_fixture}" --base "${domain_type_base}" --head "${domain_type_head}"

git -C "${git_fixture}" commit --quiet --allow-empty -m 'not a conventional commit'
invalid_head="$(git -C "${git_fixture}" rev-parse HEAD)"
if "${checker}" --repo "${git_fixture}" --base "${domain_type_head}" --head "${invalid_head}"; then
  fail 'invalid commit subject was accepted'
fi

git -C "${git_fixture}" reset --quiet --hard "${domain_type_head}"
zero_revision='0000000000000000000000000000000000000000'
"${checker}" --repo "${git_fixture}" --base "${zero_revision}" --head "${domain_type_head}"

source_repo="${fixture_root}/source"
git clone --quiet --no-local "${git_fixture}" "${source_repo}"
git -C "${source_repo}" config user.name 'CI commit policy'
git -C "${source_repo}" config user.email 'ci-commit-policy@example.invalid'
git -C "${source_repo}" commit --quiet --allow-empty -m 'fix(ci): create shallow-history boundary'
source_base="$(git -C "${source_repo}" rev-parse HEAD^)"
source_head="$(git -C "${source_repo}" rev-parse HEAD)"

shallow_repo="${fixture_root}/shallow"
git clone --quiet --no-local --depth 1 "${source_repo}" "${shallow_repo}"
if "${checker}" --repo "${shallow_repo}" --base "${source_base}" --head "${source_head}"; then
  fail 'shallow repository was accepted'
fi

printf 'commit policy self-test passed\n'
