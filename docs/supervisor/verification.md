<!-- doc-type: verification -->

# 検証対応表

[Supervisor adapter](README.md) / 検証対応表

> **対象読者:** supervisor の実装者、レビュー担当者、統合 test を書く人

この crate の test は 2 種類ある。lifecycle と認可の contract test は `CapabilityKernel`（本物）と `FakeResources`（event log）と `StaticCallerResolver`（in-memory map）を組み合わせ、実 syscall を出さない。control socket と Linux host resource の module test は、実 `SOCK_SEQPACKET` socket、実 `SO_PEERCRED`、実 cgroup v2、実 process を使う。cgroup v2 が書けない host では後者だけ skip する。

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

実 Linux resource は実 cgroup v2 と実 process に対して確認する。

| 境界 | test |
|---|---|
| workload が cgroup に閉じ込められ、停止で子孫ごと消える | `a_confined_workload_is_stopped_with_every_descendant` |
| 1 subject が持てる cgroup と control socket は 1 つずつで、解放は idempotent | `one_subject_owns_at_most_one_cgroup_and_control_socket` |
| 他 subject の token で workload を起動できない | `a_workload_cannot_borrow_another_subjects_tokens` |
| directory を抜け出せる subject 名を拒否する | `subject_names_that_could_escape_their_directory_are_refused` |
| handle は subject ごとに追跡され、close は idempotent | `handles_are_tracked_per_subject_and_close_is_idempotent` |
| 設定した directory が実在しなければ構築を拒否する | `host_config_requires_existing_owned_directories` |

返信の形式も固定してある。

| 境界 | test |
|---|---|
| 全 response が bounded encoding を round trip する | `every_response_round_trips_through_the_bounded_encoding` |
| 壊れた response を推測せず拒否する | `malformed_responses_are_rejected_rather_than_guessed` |
| response が guest の学べる識別子を運ばない | `a_response_never_carries_an_identifier_a_guest_could_learn_from` |
| 返信が 1 datagram として peer へ届く | `a_reply_reaches_the_peer_as_one_bounded_datagram` |

spoof の test には注意点がある。詐称した `CloseHandle` は**拒否されるのではなく、caller 自身の handle を閉じる**。claim が捨てられることを示しているのであって、詐称に対する error 経路が存在するわけではない。

`authenticated_foreign_subject_cannot_close_another_subjects_handle` は直接 API を呼ぶ。`dispatch_wire` は経由しない。`resources.close_handle` が呼ばれなかったことも assert していない。

### 拒否経路の test

| 対象 | test |
|---|---|
| `ConnectionNotBoundToSubject` | `a_second_connection_bound_to_one_subject_cannot_act_as_it` |
| `CallerBindingError` | `an_unbound_connection_reaches_no_authority_operation` |
| `GrantSubjectMismatch` | `issue_root_refuses_a_grant_naming_another_subject` |
| `DuplicateSubject` | `the_same_subject_id_cannot_be_created_twice` |
| 親の gate | `a_child_cannot_be_created_under_a_parent_that_is_not_running` |
| `derive` の拒否 | `derive_requires_a_running_caller_and_a_capability_it_holds` |

いずれも「adapter に届く前に落ちる」ことまで確認する。resource の event log が拒否前後で変わらないことを assert しているので、検査だけ通って副作用が残る形にはならない。

`derive` の grant 対象検査が無いこと自体は依然として意図された契約であり、test はその非対称を固定していない。


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
| `CallerResolver` | `StaticCallerResolver`（in-memory map） | lifecycle test の中でだけ。production 経路は `SubjectCredentialResolver` が実 `SO_PEERCRED` を使う |
| transport | lifecycle test では無し | lifecycle test は listener を経由しない。listener 自体は別 test で実 socket に対して検証している |

event の順序 assertion が示すのは呼び出し順だけ。副作用は示さない。

### 検査があるのに test が無いもの

| 対象 | 何が未検証か |
|---|---|
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
