<!-- doc-type: verification -->

# Hardening completion ledger (2026-08-18)

[検証戦略](../design/verification.md) / Hardening completion ledger

> **対象読者:** hardening wave の実装者、CI 運用者、最終判定を行うレビュー担当者

This ledger controls the post-verification hardening wave.  It is not evidence that a control is
implemented: a track moves to `verified` only when the named gate succeeds in the required
environment and the corresponding claim in `docs/verification-status.yml` is updated.  The
status is scope-limited; this ledger does not contain a CI run ID or an execution transcript.

## local test で確認したこと

この ledger 自体が security control の成立を証明することはない。local では、記載した
gate 名が CI 定義と一致すること、pipeline parity、verification claim の schema と相互参照、
および hosted test で再現できる failure-injection のみを確認する。実 KVM、外部 provider、
alternate architecture、独立レビューは各 track の required environment で別に成立させる。

## 実行コマンド

```bash
scripts/ci/check-docs.sh
scripts/ci/validate-pipelines.sh
scripts/ci/check-pipeline-parity.sh
scripts/ci/test-pipeline-planner.sh
scripts/ci/tests/test-external-review.sh
cargo test --locked -p session-orchestrator --all-targets --features crash-test-hooks
docker run --rm --volume "${PWD}:/src" --workdir /src docker.io/semgrep/semgrep:1.172.0@sha256:a8298d1c09c84b9a0bbc75ec915e37023fc4657360b6dbfa645261d2353a366c semgrep scan --config .semgrep.yml --error --metrics off --exclude target --exclude lean/.lake crates
# Every declared entry in ci/gates.yml was run through the matching bounded gate.
while IFS=$'\t' read -r package filter; do scripts/ci/run-miri.sh "$package" "$filter"; done < <(.ci-tools/bin/yq -o=tsv '.matrices.miri_packages.values[] | [.package, .filter]' ci/gates.yml)
scripts/ci/run-sanitizer.sh address egress-protocol
scripts/ci/run-sanitizer.sh leak egress-protocol
scripts/ci/run-fuzz.sh authority-core canonical_path
scripts/ci/run-fuzz.sh egress-protocol cbor_request_decode
scripts/ci/run-fuzz.sh egress-protocol frame_decode
scripts/ci/run-mutation.sh 1 authority-core
scripts/ci/run-mutation.sh 2 egress-protocol
scripts/ci/run.sh coverage
scripts/ci/run.sh benchmarks
scripts/ci/run.sh audit
scripts/ci/run.sh deny
scripts/ci/check-cross-targets.sh
scripts/ci/collect-supply-chain-inventory.sh
scripts/ci/check-release-dry-run.sh
scripts/ci/check-release-reproducibility.sh
scripts/ci/verify-real-capfs.sh
scripts/ci/verify-real-public-https.sh
scripts/ci/verify-real-guest-control.sh
scripts/ci/verify-real-session-owner.sh
scripts/ci/verify-real-session-crash-recovery.sh
scripts/ci/check-service-boundaries.sh
scripts/ci/verify-real-systemd-control-plane.sh
scripts/ci/verify-real-concurrent-session-owners.sh
scripts/ci/run.sh installed-production-chain
```

Release dry-run と reproducibility は、未commitのhardening差分をそのまま適用して一時commitした
隔離clean cloneで実行した。元の作業treeをcommitしたり、publish/signingを実行したりしていない。

最後のコマンドは root、KVM、vhost-vsock、device-mapper、cgroup v2 を要求し、不足時は
成功扱いにしない。

## Preserved constraints

- One workload remains owned by one `SessionOwner`, one microVM, one workspace clone, one Broker
  session, and one non-reusable identity bundle.
- The guest never receives provider credentials, arbitrary host commands, or an ambient host
  filesystem handle.
- Authorization, lifecycle recovery, and cleanup continue to fail closed.
- Existing verified claims may move backwards when a regression is found; they may not be hidden,
  weakened, or silently re-scoped.
- External prerequisites and independent-review evidence are never fabricated or replaced by a
  self-review.

## Acceptance tracks

`Current state` は verification manifest の declared scope を写した分類であり、このファイルの読者に対する新しい実行証拠ではない。`Exit condition` は gate が満たすべき条件を示す。実際の run、revision、artifact は対応する gate の CI 証跡で確認し、条件を満たさない scope へ `verified` を拡張しない。

| Track | Current state | Exit condition |
|---|---|---|
| Real crash recovery | verified | Every declared durable lifecycle checkpoint is killed from outside the daemon; restart either completes cleanup or refuses reuse, and the host residue probe is empty. |
| Runtime variance | partial | Bounded x86_64 soak/escape and Firecracker 1.15.1/1.16.1 gates pass with resource/time ceilings; protected aarch64 execution remains required and unavailable runners are never success. |
| Privileged host TCB | verified | The exact checked-in binaries, units, policy, udev rules, environment, sealed privileged helpers, jailer UID drop, and two real KVM worker trees execute together; normal stop and failed-worker cleanup leave no owned residue. |
| Multi-session control plane | verified | Authenticated admission, unauthorized and quota rejection, two concurrent live KVM/Broker owners, independent stop, failed-worker recovery, quota release, controller restart reconciliation, and a fresh final session pass through the installed production chain. |
| Live external provider | blocked | The protected destructive gate succeeds with an exact disposable repository and least-privilege installation credential. |
| Independent review | blocked | A named external reviewer supplies a revision-bound report and the import gate verifies its scope, revision, and disposition without accepting a repository-authored substitute. |

## Cycle ledger

Scores are review estimates on the hardening-loop 0–10 scale, not measured probabilities.  A score
can reach the 9.8 exit threshold only with the gate in the final column above.

| Cycle | Attack lens | Threat | Performance | Regression | Operations | Review | Rollout | Cost | Observability | Abuse resistance | Release | Verdict |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|
| 1 baseline | surviving TCB, crash and scope boundaries | 9.5 | 9.0 | 9.5 | 8.8 | 8.5 | 8.8 | 9.0 | 8.8 | 9.3 | 9.8 | continue: operational crash proof is the first weak axis |
| 2 crash matrix | external SIGKILL at 11 durable lifecycle boundaries | 9.7 | 8.9 | 9.7 | 9.6 | 9.0 | 9.2 | 8.8 | 9.5 | 9.6 | 9.8 | continue: runtime variance and privileged TCB remain |
| 3 runtime variance | high-risk raw syscalls, 20 full privileged repetitions, two pinned Firecracker releases | 9.7 | 9.2 | 9.7 | 9.6 | 9.1 | 9.4 | 9.0 | 9.6 | 9.7 | 9.8 | continue: real aarch64, privileged TCB, and multi-session remain |
| 4 control surfaces | sealed command construction, HMAC admission, durable quotas/no-reuse, controller fencing, signed-review import | 9.8 | 9.1 | 9.7 | 9.5 | 9.3 | 9.4 | 9.0 | 9.7 | 9.8 | 9.8 | continue: production helper/worker integration and external evidence remain |
| 5 fail-closed challenge | transient journal path loss, pre-effect revalidation, fork/exec lock inheritance, readiness timing, worker health cleanup, signed report/disposition digest binding | 9.8 | 9.2 | 9.8 | 9.7 | 9.4 | 9.5 | 9.0 | 9.8 | 9.8 | 9.8 | stop: remaining gaps require new architecture, hardware, credentials, or an independent reviewer |
| 6 operational replay | all 11 KVM crash points, panic fallback cleanup, stale mapper/loop/cgroup residue, post-run host probe | 9.8 | 9.2 | 9.8 | 9.8 | 9.7 | 9.6 | 9.1 | 9.8 | 9.8 | 9.8 | stop: every locally satisfiable track is green; only declared external/architectural ceilings remain |
| 7 downgrade and path-race reopen | production v1 rejection, descriptor-sealed publish plans and systemd credentials, credential-source precedence, atomic control-journal creation, stop/control metadata failure | 9.8 | 9.2 | 9.8 | 9.8 | 9.8 | 9.7 | 9.1 | 9.8 | 9.8 | 9.8 | stop: fresh hostile review found no further locally executable high-risk repair; external/architectural ceilings remain explicit |
| 8 production composition review | exact-digest systemd/polkit boundary, failed-unit recovery, root-owned workspace source, two simultaneous live KVM/Broker owners, independent stop | 9.7 | 9.2 | 9.8 | 9.8 | 9.6 | 9.7 | 9.1 | 9.8 | 9.8 | 9.7 | continue: exact installed production controller-to-VM execution remains separate from its component gates |
| 9 exact installed production chain | checked-in production paths, authenticated caller, concurrent KVM workers, quota rejection, worker crash, controller restart, final residue audit | 9.8 | 9.2 | 9.8 | 9.8 | 9.8 | 9.8 | 9.1 | 9.8 | 9.8 | 9.8 | stop: all locally executable x86_64 system tracks are green; declared external and alternate-architecture ceilings remain |

## External ceilings

- The live GitHub result requires operator-owned credentials and a disposable repository.
- Alternate-architecture privileged execution requires a real compatible runner; cross-compilation
  is not runtime evidence.
- Independent review requires a genuinely independent person or organization.  Repository-owned
  automation can validate an imported report but cannot create independence.
- Multi-host failover, distributed revoke, and replicated Broker state are outside the current
  single-host state machine. Adding them changes the trust model rather than completing an
  unimplemented branch of this design.
- Host kernel, KVM, Firecracker, hardware, and microarchitectural behavior remain upstream or
  physical TCB unless the deployment chooses a different isolation architecture.

The independent-review artifact is one canonical LF-terminated TSV record:

```text
external-security-review-v1<TAB>commit<TAB>tree<TAB>repository<TAB>reviewer<TAB>organization<TAB>affirmed<TAB>report-sha256<TAB>disposition-sha256<TAB>0<TAB>0<TAB>approve
```

The reviewer signs those exact bytes with Ed25519. The signed digests bind a full review artifact
and a canonical disposition ledger whose header is `external-review-disposition-v1` and whose
remaining rows are `finding-id<TAB>severity<TAB>status`. Duplicate IDs, unknown values, and any
critical/high row not marked `fixed` are rejected. The manifest, full report, disposition,
signature, and public key must be injected from outside the checkout; the public-key SHA-256 must
be a separate protected variable. The import gate also requires a clean worktree and exact `HEAD`
commit/tree equality. Its local self-test creates a temporary signer only to test positive/negative
parser, digest, disposition, and signature behavior; that fixture is never review evidence.

## 未検証の境界

acceptance table の `partial`、`open`、`out of scope`、`blocked` は未検証境界である。実装だけで
外部前提を満たしたことにはしない。特に protected runner が無い alternate architecture、
operator credential が無い live provider、repository の作者と独立していない review は、
local greenでも `verified` へ進めない。x86_64の exact installed production chain は
`verification-status.yml` が宣言する `kvm` scope の claim として扱うが、この台帳自体は
その実行時刻や artifact を保持せず、別の環境へ結果を一般化しない。

## 関連

- [検証ステータスの規約](../verification-status.md)
- [検証ステータス manifest](../verification-status.yml)
- [検証戦略](../design/verification.md)
- [Firecracker runtime の検証](../firecracker-runtime/verification.md)
- [Session orchestrator](../session-orchestrator/README.md)
