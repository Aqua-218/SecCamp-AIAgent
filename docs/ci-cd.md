<!-- doc-type: exempt -->

# CI/CD Operations

[ドキュメント一覧](README.md) / CI/CD operations

> **対象読者:** リポジトリ管理者、リリース担当者、pipeline を変更する人

This repository ships equivalent, fail-closed delivery pipelines for GitHub Actions and GitLab CI. Both platforms execute the same repository-owned scripts so that a platform migration does not change the quality, security, or release contract.

The release boundary is deliberately limited to the artifact this repository can prove today: the `authority-corpus` Linux binary. No production deployment job is present because the repository does not define a deployable service image, environment manifest, infrastructure target, or rollback contract.

## Pipeline topology

| Gate | GitHub Actions | GitLab CI | Contract |
|---|---|---|---|
| Pipeline policy | `Continuous Integration / Pipeline policy` | `pipeline_policy` | Parse all YAML, lint Actions and shell, require full Action SHAs and container digests, reject broad permissions and suppressed failures |
| Rust quality | `Rust quality gate` | `rust_quality` | Format, all-target/all-feature check, Clippy with warnings denied, rustdoc with warnings denied |
| Rust tests | Four `Rust tests` jobs | Four `rust_tests` matrix jobs | Workspace split into four deterministic nextest shards with JUnit reports |
| Repository invariants | `Toolchain consistency`, `Declared dependency usage`, `Lockfile integrity`, `Documentation policy`, `Repository hygiene`, `Pin inventory` | `toolchain_consistency`, `dependency_usage`, `lockfile_integrity`, `docs_policy`, `repository_hygiene`, `pin_inventory` | Pinned toolchains agree, every declared dependency is used, the lockfile matches the manifests, the documentation tree obeys its conventions, no tracked file is an unreviewable blob or a stray build output, and every pinned version and digest is collected into one reviewable list |
| Claim traceability | `Decision record index`, `Verification page traceability`, `CODEOWNERS coverage`, `Lean proof hygiene` | `adr_index`, `verification_traceability`, `codeowners_coverage`, `lean_hygiene` | The decision log matches its index and numbers without a gap, every crate has a reachable verification page carrying its `未検証の境界` section, the paths that define the gates still require owner review, and no Lean proof contains a hole or an axiom |
| Pipeline self-test | `Pipeline script self-test` | `pipeline_self_test` | Drives `plan-pipeline.sh` against inputs with known answers, so a planner bug cannot silently demote a gate to `skipped` and still pass the fan-in |
| Dependency floor | `Per-crate isolation build` | `crate_isolation` | Every crate builds alone, and `authority-core` and `runtime-isolation` are proven to have no workspace crate beneath them |
| Portability | `Cross-target check` | `cross_targets` | The workspace type-checks for `x86_64-unknown-linux-musl` and `aarch64-unknown-linux-gnu`, where libc spells `statfs::f_type` differently and syscall numbers change |
| Delivery rehearsal | `Release dry run`, `Release reproducibility` | `release_dry_run`, `reproducibility` | The full package, SBOM, checksum, and verification path runs on every merge request instead of first running against an immutable tag; the archive is then rebuilt and required to be byte-identical |
| Supply-chain record | `Supply-chain inventory` | `supply_chain_inventory` | An SPDX SBOM of everything the lockfile resolves to, so a future advisory can be matched against what was actually in the tree |
| Specialized verification | `Rust doctests`, `Loom concurrency model`, `Lean proofs`, `Rust and Lean differential corpus` | `rust_doctests`, `loom`, `lean_proofs`, `differential_corpus` | Doctests, bounded concurrency exploration, Lean build, and the 150-case Rust/Lean decision corpus |
| Coverage | `Workspace coverage` | `coverage` | LCOV, Cobertura, and summary artifacts; minimum line coverage is 75% |
| Dependency assurance | `RustSec advisory audit`, `Dependency policy` | `dependency_audit`, `dependency_policy` | Advisory audit plus license, source, and wildcard dependency policy |
| SAST and secrets | CodeQL, Semgrep, Gitleaks | Semgrep, Gitleaks | Extended Rust data-flow analysis on GitHub, repository-specific static rules, and full-history secret detection |
| Supply-chain posture | Weekly OpenSSF Scorecard | Administratively managed | Scheduled repository posture report on GitHub |
| System verification | `Real Firecracker VM verification`, `Privileged runtime isolation verification` | `real_vm`, `privileged_isolation` | Scheduled only, on hosts that a shared runner pool cannot provide. See [Privileged runners](#privileged-runners) |
| Deep correctness and performance | `Miri undefined-behaviour check`, `Sanitizer run`, `Mutation testing`, `Fuzz targets`, `Benchmark regression` | `miri`, `sanitizers`, `mutation`, `fuzz`, `benchmarks` | Scheduled nightly and on demand. Miri is restricted to pure test modules, sanitizers run the protocol test binary, mutation/fuzz selections are bounded, and the benchmark gate measures capability decisions against a committed noise-aware baseline. Privileged FUSE layers are reported separately and are not treated as a standard hosted pass |
| Release | `Trusted Release` | tag pipeline package/verify/publish/release stages | Re-run all gates, build deterministic archive, generate SPDX SBOM and checksums, attest or sign, verify, then publish through a protected environment |

GitHub exposes truthful fan-in checks named `CI complete`, `Security complete`, and `Deep verification complete`. A failed, cancelled, or skipped required dependency makes the corresponding fan-in fail. GitLab uses ordered stages and does not permit failures on any gate.

### Implemented and planned gates

`ci/gates.yml` is both the plan and the record, so every gate carries a `status`.

- `implemented` means a repository-owned script runs and both platforms call it. Parity requires the job to exist on every platform the gate does not explicitly excuse itself from with `why_platform`.
- `planned` means the gate is designed but nothing runs yet. Parity requires it to have no job on either platform, and `why_planned` records what is missing.

The distinction is load-bearing. Without it a gate that runs on every pipeline and a gate that exists only as an intention read identically, `check-pipeline-parity.sh` can never pass, and the claim that both platforms implement the same gates cannot be true. `plan-pipeline.sh` reports planned gates as `planned` rather than `unavailable`, because those are different statements: one says nobody has built the gate, the other says this platform cannot host a gate that does exist. `check-gate-results.sh` fails if any result is observed for a planned gate, so a job cannot appear without the manifest being promoted alongside it.

Promoting a gate is one field change plus the job it now demands. The manifest now has 39 implemented gates and no planned gates. The nightly gates use one pinned toolchain, execute non-empty supported subsets, and fail closed when a selection, baseline, corpus, or tool is missing. The benchmark gate deliberately measures the pure capability decision path; `/dev/fuse` availability is printed as operational evidence rather than converted into a fake green result.

No planned gate is given a job that trivially succeeds. An empty gate is worse than a missing one: it reports the same green as a real check while proving nothing, and it removes the pressure to build the thing it stands in for.

### Privileged runners

The two system-stage gates need hosts that hosted runner pools do not offer. Both run on a schedule or on demand, never on pull requests, because a host carrying either label runs repository code with elevated rights, and because a gate that silently skips when a device is missing teaches reviewers to ignore it.

| Label | Host must provide | Gate |
|---|---|---|
| `kvm` | `/dev/kvm`, `/dev/vhost-vsock`, `veritysetup`, `busybox`, `mkfs.ext4` | Real Firecracker VM verification |
| `privileged` | root, and a cgroup v2 root delegating `memory` and `pids` to its children. No KVM needed | Privileged runtime isolation verification |

GitHub label names are declared in [`.github/actionlint.yaml`](../.github/actionlint.yaml) so the linter can tell a typo from a custom label; GitLab uses the same two names as runner tags. Neither script reports a skip as a pass: on a host missing the prerequisites they print what is absent and exit with a distinct status.

## Triggers and cancellation

- GitHub runs CI and security on pull requests and `main`; CI also runs on `release/**`. Security runs weekly. Deep verification runs daily at 03:17 UTC and on demand. Tags matching `v*.*.*` enter the release workflow, where a strict semantic-version check rejects invalid tags.
- GitLab creates pipelines for merge requests, the default branch, tags, schedules, web runs, and API runs. New commits cancel only interruptible work. Package, verification, publication, release, and system-stage jobs are never interrupted.
- GitHub pull-request concurrency cancels obsolete work. A release concurrency group never cancels an in-flight release.

## Toolchain and dependency controls

- Rust is repository-pinned by `rust-toolchain.toml`; all Cargo commands use `--locked`.
- Lean is repository-pinned by `lean/lean-toolchain`. The elan bootstrap archive is version- and SHA-256-pinned before execution.
- nextest, cargo-audit, cargo-deny, cargo-llvm-cov, cargo-public-api, cargo-mutants, cargo-fuzz, actionlint, ShellCheck, yq, Syft, and Cosign are installed at exact versions. Miri and sanitizer jobs use the separately pinned nightly toolchain. Downloaded standalone binaries are verified by SHA-256.
- Every third-party GitHub Action reference is a full 40-character commit SHA. Every CI container is pinned by digest.
- Cargo caches contain registries and compiled CI tools, never build outputs or release artifacts. Cache poisoning therefore cannot bypass a source rebuild.
- Dependabot proposes weekly Cargo and GitHub Actions updates. `CODEOWNERS` requires repository-owner review for pipeline and supply-chain policy changes.

Run the same entry points locally:

```bash
scripts/ci/install-pipeline-tools.sh
scripts/ci/validate-pipelines.sh

scripts/ci/run.sh format
scripts/ci/run.sh check
scripts/ci/run.sh clippy
scripts/ci/run.sh docs

scripts/ci/install-cargo-tools.sh nextest coverage security
for shard in 1 2 3 4; do scripts/ci/run.sh test "$shard"; done
scripts/ci/run.sh doctest
scripts/ci/run.sh loom
scripts/ci/run.sh coverage
scripts/ci/run.sh audit
scripts/ci/run.sh deny

scripts/ci/install-lean.sh
scripts/ci/run.sh lean
scripts/ci/run.sh differential
```

実 VM 検証だけは、hosted pipeline ではなく `/dev/kvm` を持つ host で行う。次の 2 本が必要な artifact を version-scoped の不変 directory へ置き、`RuntimeConfig` が pin する SHA-256 と dm-verity root hash を印字する。

```bash
scripts/ci/install-firecracker.sh      # firecracker + jailer
scripts/ci/install-guest-artifacts.sh  # guest kernel + read-only rootfs + verity hash device
```

Firecracker は上流が公開する SHA-256 と照合する。guest artifact の bucket は署名を公開していないため、script に書かれた digest は「この repository が観測して受け入れた bytes」であり、上流 build の信頼性を示すものではない。rootfs の hash device は download せず、その rootfs の bytes からその場で `veritysetup format` する。

Semgrep and Gitleaks run from digest-pinned containers in both hosted pipelines. Their output, as well as JUnit, coverage, audit, and policy reports, is retained as CI artifacts.

## GitHub administration

The YAML is ready without repository secrets. Configure the following controls in repository settings:

1. Create a ruleset for `main`. Require pull requests, owner approval for CODEOWNERS changes, conversation resolution, a current branch, signed commits if the contributor workflow supports them, and the `CI complete` and `Security complete` status checks. Enable merge queue for high-concurrency development; both workflows handle its `merge_group` event. Block force pushes and deletion.
2. Create an environment named `release`. Restrict it to protected semantic-version tags and require at least one independent reviewer. Do not allow administrators to bypass protection.
3. Create a tag ruleset for `v*.*.*` that blocks update and deletion after creation.
4. Enable GitHub Advanced Security default setup prerequisites if the repository visibility or organization policy requires them for CodeQL.
5. Keep Actions permissions at read-only by default and disallow unpinned actions through organization policy. The workflows elevate only the individual jobs that need `security-events: write`, `id-token: write`, `attestations: write`, or `contents: write`.

Create and push a release tag only after changing `[workspace.package].version` to the same version:

```bash
git tag -s v0.2.0 -m "v0.2.0"
git push origin v0.2.0
```

The release workflow checks out the immutable tag commit, re-runs CI and security, creates a deterministic archive and SPDX document, and produces separate SLSA build-provenance and SBOM attestations through OIDC. The `release` environment then gates publication. A rerun downloads and compares any existing asset byte-for-byte; it never overwrites a conflicting asset.

Consumers can verify the downloaded archive with the GitHub CLI:

```bash
sha256sum --check SHA256SUMS
gh attestation verify authority-corpus-v0.2.0-x86_64-unknown-linux-gnu.tar.gz \
  --repo Aqua-218/SecCamp-AIAgent
```

## GitLab administration

Mirror or push the same repository and configure these controls in the GitLab project:

1. Protect the default branch. Require merge requests, successful pipelines, resolved discussions, and Code Owner approval. Enable merged-results pipelines and merge trains for high-concurrency development. Disable direct pushes except for the release automation role if one is required.
2. Protect the `v*.*.*` tag pattern and limit tag creation to release maintainers.
3. Protect the `release` environment and restrict deployments to release maintainers. The `publish_release` job is an explicit, blocking, confirmed manual approval on semantic-version tag pipelines. Configure deployment approval rules as an additional control when the GitLab tier supports them.
4. Configure a scheduled default-branch pipeline for recurring advisory and secret scans.
5. Keep the default separation between protected and non-protected caches. Run GitLab CI Lint in the target project before enabling merge restrictions. Included local files require project context, so the target GitLab instance is the authoritative lint environment.

No long-lived signing secret is used. A tag job requests `SIGSTORE_ID_TOKEN` with the `sigstore` audience, signs `SHA256SUMS` keylessly, and verifies the resulting bundle against the exact project pipeline identity and GitLab issuer before publication. GitLab.com supports this Sigstore flow directly. A self-managed instance must provide a compatible trusted OIDC/Fulcio configuration or replace this job with the organization's signing service.

Publication uploads the archive, SPDX SBOM, checksums, and Sigstore bundle to the Generic Package Registry under `authority-corpus/<tag>`, then creates a GitLab Release with immutable asset links. Reruns compare existing registry objects byte-for-byte and compare the complete release record; they fail instead of overwriting a conflict.

Consumers can verify GitLab release assets with:

```bash
sha256sum --check SHA256SUMS
cosign verify-blob \
  --bundle SHA256SUMS.sigstore.json \
  --certificate-identity "https://gitlab.com/GROUP/PROJECT//.gitlab-ci.yml@refs/tags/v0.2.0" \
  --certificate-oidc-issuer "https://gitlab.com" \
  SHA256SUMS
```

Replace the host, group, project, and tag with the values for the publishing project.

## Release invariants and recovery

The release archive contains the versioned binary, the complete `AGPL-3.0-only` license text, and `BUILD-METADATA.json`. The metadata identifies the immutable source revision and gives a direct URL for downloading its corresponding source. Archive entries are sorted, ownership is normalized to root, and timestamps come from the source commit. The SPDX namespace and creation time are likewise normalized to source data. The reproducibility gate uses two empty, independent Cargo target directories and compares the archive, SPDX document, checksum manifest, and release metadata byte for byte; a cached first build therefore cannot masquerade as a rebuild.

A failed package or signature job publishes nothing. A failed protected publication can be retried because both publisher scripts are idempotent. If a release asset already exists with different bytes, the job stops and requires investigation; deleting or replacing a published asset is intentionally not automated. Rollback means publishing a new patch version, not mutating an existing release.

## Performance, cost, and residual risk

The four test shards, quality checks, specialized verification, coverage, and security scanners run in parallel where their dependencies allow it. The first run compiles pinned Cargo tools; caches reduce subsequent latency. Expect approximately 15–35 minutes of wall time and 20–60 Linux runner-minutes for a cold full run, depending on runner size and registry performance. Release pipelines intentionally repeat all gates and therefore cost roughly another full run.

The pipelines do not claim production deployment readiness. They do not exercise a real Firecracker host, FUSE mount, AF_VSOCK transport, external DNS/HTTPS service, or cloud environment. Container digest and Action SHA updates still require human review, and a compromised hosted runner remains inside the trusted build boundary. The protected release environment, minimal job permissions, OIDC signing, immutable tag policy, provenance, checksums, and fail-closed rerun behavior reduce that boundary but do not eliminate it.

## 関連

- [ドキュメント一覧](README.md)
- [検証戦略](design/verification.md)
- [文書規約](document-conventions.md)
