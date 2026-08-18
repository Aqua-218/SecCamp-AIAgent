<!-- doc-type: verification -->

# Hardening completion ledger (2026-08-18)

[検証戦略](../design/verification.md) / Hardening completion ledger

> **対象読者:** hardening wave の実装者、CI 運用者、最終判定を行うレビュー担当者

This ledger controls the post-verification hardening wave.  It is not evidence that a control is
implemented: a track moves to `verified` only when the named gate succeeds in the required
environment and the corresponding claim in `docs/verification-status.yml` is updated.

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
cargo test -p session-orchestrator --all-targets --features crash-test-hooks --locked
scripts/ci/verify-real-session-crash-recovery.sh
```

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

| Track | Current state | Exit condition |
|---|---|---|
| Real crash recovery | verified | Every declared durable lifecycle checkpoint is killed from outside the daemon; restart either completes cleanup or refuses reuse, and the host residue probe is empty. |
| Runtime variance | partial | Bounded x86_64 soak/escape and Firecracker 1.15.1/1.16.1 gates pass with resource/time ceilings; protected aarch64 execution remains required and unavailable runners are never success. |
| Privileged host TCB | partial | Arbitrary external `CommandSpec` construction is sealed; a separate privileged helper process and unprivileged-controller production composition are still required. |
| Multi-session control plane | partial | The authenticated, quota-bound, crash-recovering scheduler core and controller fencing pass hosted tests; production worker/socket integration and concurrent real-KVM evidence remain. |
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

## External ceilings

- The live GitHub result requires operator-owned credentials and a disposable repository.
- Alternate-architecture privileged execution requires a real compatible runner; cross-compilation
  is not runtime evidence.
- Independent review requires a genuinely independent person or organization.  Repository-owned
  automation can validate an imported report but cannot create independence.
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

この wave の開始時点では acceptance table の `partial`、`open`、`out of scope`、`blocked`
がそのまま未検証境界である。実装だけで外部前提を満たしたことにはしない。特に protected
runner が無い architecture、operator credential が無い live provider、repository の作者と
独立していない review は、local green でも `verified` へ進めない。

## 関連

- [検証ステータス](../verification-status.yml)
- [検証戦略](../design/verification.md)
- [Firecracker runtime の検証](../firecracker-runtime/verification.md)
- [Session orchestrator](../session-orchestrator/README.md)
