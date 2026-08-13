<!-- doc-type: verification -->

# 検証対応表

[Supervisor adapter](README.md) / 検証対応表

> **対象読者:** supervisor の実装者、レビュー担当者、統合 test を書く人

この crate の test は 2 種類ある。lifecycle と認可の contract test は `CapabilityKernel`（本物）と `FakeResources`（event log）と `StaticCallerResolver`（in-memory map）を組み合わせ、実 syscall を出さない。control socket の module test だけが実 `SOCK_SEQPACKET` socket と実 `SO_PEERCRED` を使う。

## local test で確認したこと

| 境界 | test |
|---|---|
| 親の下に子 subject を作り、derive して revoke できる（成功経路のみ） | `root_derive_and_revoke_use_typed_authority_kernel_transitions` |
| `claimed_subject` の詐称が無視され、caller 自身の handle が閉じる | `request_subject_spoof_is_ignored_in_favor_of_connection_identity` |
| 認証済みの別 subject が他人の handle を閉じられない | `authenticated_foreign_subject_cannot_close_another_subjects_handle` |
| mount 失敗で確保済み resource だけを rollback し、subject を残さない | `partial_setup_rolls_back_already_acquired_resources` |
| control 閉鎖の失敗時に mount と cgroup を意図的に保持し、retry で解放できる | `setup_rollback_retains_prerequisites_when_control_close_fails` |
| unmount 失敗で `Closing` に留まり、新規要求を拒否し、retry で `Closed` になる | `cleanup_failure_keeps_subject_closing_and_blocks_new_requests` |
| 同じ handle の 2 回目の close が `StaleHandle`、shutdown 後の要求が `SubjectClosed` | `stale_handle_and_post_close_requests_are_rejected` |
| 閉じた `HandleId` の再 open が、adapter を呼ぶ前に `StaleHandle` になる | `closed_handle_id_cannot_be_reused` |
| kernel 登録失敗と補償失敗が重なっても、ID が予約され、shutdown が runtime close を retry する | `failed_handle_registration_retains_runtime_cleanup_and_reserves_id` |
| 未 bind の connection と非 Running の subject が revoke できない | `revoke_requires_a_bound_running_connection` |

control socket は実 socket に対して確認する。

| 境界 | test |
|---|---|
| accept が kernel の `SO_PEERCRED` から identity を作り、listener の subject へ解決する | `accept_binds_the_listening_subject_from_the_kernel_credential` |
| 4 KiB を超える datagram を decode 前に拒否する | `oversized_datagram_is_rejected_without_decoding` |
| 受理した socket ID が単調で、release 後に解決不能になる | `accepted_socket_identities_are_not_reused_across_connections` |
| 未 bind の socket ID と、subject の credential と違う peer を拒否する | `resolution_fails_closed_for_unbound_and_foreign_credentials` |
| 相対 path と root path を bind しない | `listener_rejects_paths_it_cannot_own` |
| bind 直後の socket node が mode 0600 である | `bound_socket_is_owner_only` |

spoof の test には注意点がある。詐称した `CloseHandle` は**拒否されるのではなく、caller 自身の handle を閉じる**。claim が捨てられることを示しているのであって、詐称に対する error 経路が存在するわけではない。

`authenticated_foreign_subject_cannot_close_another_subjects_handle` は直接 API を呼ぶ。`dispatch_wire` は経由しない。`resources.close_handle` が呼ばれなかったことも assert していない。

## 実行コマンド

```bash
cargo fmt --manifest-path crates/supervisor/Cargo.toml -- --check
cargo test --manifest-path crates/supervisor/Cargo.toml
cargo clippy --manifest-path crates/supervisor/Cargo.toml --all-targets -- -D warnings
```

## 未検証の境界

### test double が代わりに立っているもの

| 本来の依存 | 代替 | 省いていること |
|---|---|---|
| `RuntimeResources` | `FakeResources`（`Vec<&'static str>` の event log） | namespace、cgroup、mount、descriptor の実操作。process が止まったこと、mount が消えたことは一切示さない |
| `CallerResolver` | `StaticCallerResolver`（in-memory map） | `SO_PEERCRED` / `SCM_CREDENTIALS`、実 socket の identity |
| transport | 無し | 実 `SOCK_SEQPACKET` listener、guest との接続 |

event の順序 assertion が示すのは呼び出し順だけ。副作用は示さない。

### 検査があるのに test が無いもの

| 対象 | 何が未検証か |
|---|---|
| `ConnectionNotBoundToSubject` | 2 つの connection を 1 subject に bind し、誤った channel から呼ぶ経路 |
| `CallerBindingError` | 未 bind の connection から `dispatch_wire` / `derive` / `open_handle` / `close_handle` を呼ぶ経路 |
| `GrantSubjectMismatch` | `issue_root` に別 subject の grant を渡す経路 |
| `DuplicateSubject` | 同じ `SubjectId` で 2 回 `create_subject` を呼ぶ経路 |
| 親の gate | `Creating` / `Closing` / `Closed` / 未知の親。Running の成功経路しか通っていない |
| `derive` | 拒否経路が 1 つも無い。`Closing` の caller、親を持たない caller、grant の対象検査が無いことの影響 |
| `revoke` の所有権 | caller と lifecycle は test 済み。対象 capability を caller が保持しているかは検査も test も無い |
| `CleanupStep::BeginClose` / `FinishClose` | kernel が `finish_subject_close` を拒否する経路、および `begin_subject_close` の `?` で subject が非 Running のまま止まる経路 |
| cleanup 失敗の形 | `stop_workload` 失敗、`remove_cgroup` 失敗、shutdown 中の `close_handle` 失敗、複数 phase の同時失敗 |
| `CloseSubject` の spoof | wire 経路で別 subject を落とせないことを直接示す test が無い。spoof の test は `CloseHandle` のみ |
| protocol の境界値 | ちょうど 4096 bytes、ちょうど 256 bytes の field、`TrailingBytes`、`Truncated`。fuzz も property test も無い |
| 並行性 | `AuthorityKernel` の method は `&self` を取り、`CapabilityKernel` は内部 lock を持つ。同じ kernel を共有する別コンポーネントが supervisor の step 間に状態を変える経路。特に `register_subject` と `start_workload` の間の窓 |
| record 再作成 | clean rollback 後に同じ `SubjectId` を作り直したときの、supervisor 忘却 / kernel 記憶の食い違い |
| 資源の増加 | `issued_handles` と `subjects` は追記のみで上限が無い |

### 到達不能な分岐

「workload token はあるが cgroup token が無い」分岐は、public API からは到達できない。test も無い。

### 証明

Lean にこの crate を扱う定理は無い。`lean/Authority/` には `State`、`Kernel`、`Audit`、`Egress`、`Orchestrator` などがあるが、Supervisor に対応するものは存在しない。

mock test が全部通っても、実 socket、実 credential、実 namespace / cgroup / mount が動くことの根拠にはしない。この方針は [docs/README.md](../README.md) の宣言に従う。

## 関連

- [Supervisor adapter](README.md)
- [誰の要求として扱うか](caller-identity.md)
- [wire protocol](wire-protocol.md)
- [subject の setup と shutdown](subject-lifecycle.md)
- [handle の lifecycle](handle-lifecycle.md)
- [検証戦略](../design/verification.md)
- [用語集](../glossary.md)
