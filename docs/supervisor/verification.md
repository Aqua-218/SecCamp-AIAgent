<!-- doc-type: verification -->

# 検証対応表

[Supervisor adapter](README.md) / 検証対応表

> **対象読者:** supervisor の実装者、レビュー担当者、統合 test を書く人

この crate の test は 3 種類ある。lifecycle と認可の contract test は `CapabilityKernel`（本物）と `FakeResources`（event log）と `StaticCallerResolver`（in-memory map）を組み合わせ、実 syscall を出さない。control socket と Linux host resource の module test は、実 `SOCK_SEQPACKET` socket、実 `SO_PEERCRED`、実 cgroup v2、実 process を使う。さらに `real_resources.rs` は ignored privileged integration test として、`resources_mut()` から production `LinuxHostResources` / `CapfsRuntimeResources` を直接観測し、実 FUSE mount、cgroup、descriptor、credential、cleanup retry を確認する。これは `Supervisor::create_subject` / `shutdown_subject` 全体や successful `start_workload` の証明ではない。通常の test では integration target を実行せず、`scripts/ci/verify-real-supervisor-resources.sh` が root と disposable mount namespace を確認した後にだけ実行する。前提を満たさない host では wrapper が exit 2 で停止する。

## local test で確認したこと

| 境界 | test |
|---|---|
| 親の下に子 subject を作り、derive して revoke できる（成功経路のみ） | `root_derive_and_revoke_use_typed_authority_kernel_transitions` |
| `claimed_subject` の詐称が無視され、caller 自身の handle が閉じる | `request_subject_spoof_is_ignored_in_favor_of_connection_identity` |
| 認証済みの別 subject が wire 経由で他人の handle を閉じられず、resource adapter に到達しない | `authenticated_foreign_subject_cannot_close_another_subjects_handle` |
| `CloseSubject` の claim が別 subject を閉じず、connection caller 自身だけを閉じる | `close_subject_claim_cannot_close_a_foreign_subject` |
| mount 失敗で確保済み resource だけを rollback し、subject を残さない | `partial_setup_rolls_back_already_acquired_resources` |
| control 閉鎖の失敗時に mount と cgroup を意図的に保持し、retry で解放できる | `setup_rollback_retains_prerequisites_when_control_close_fails` |
| unmount 失敗で `Closing` に留まり、新規要求を拒否し、retry で `Closed` になる | `cleanup_failure_keeps_subject_closing_and_blocks_new_requests` |
| `begin_subject_close` の失敗で `Closing` に留まり、retry で authority と resource cleanup を完了する | `begin_close_failure_is_retryable_after_local_closing_transition` |
| 外部 resource cleanup 後の `finish_subject_close` の失敗を保持し、retry で `Closed` にする | `finish_close_failure_is_retryable_after_external_cleanup` |
| `stop_workload`、`remove_cgroup`、shutdown 中の `close_handle` の失敗を保持し、各 retry で依存 phase を再実行する | `stop_workload_failure_is_retained_and_retried_before_mount_cleanup`, `remove_cgroup_failure_is_retained_after_mount_cleanup_and_retried`, `close_handle_failure_is_retained_and_retried_before_unmount` |
| 複数 cleanup phase が同時に失敗しても全 token を record に残し、次回 shutdown で matrix を消化する | `simultaneous_cleanup_failures_are_all_retained_for_one_retry_matrix` |
| authority が `register_subject` と `start_workload` の間で変化した場合に workload を公開せず rollback する | `register_to_start_authority_mutation_fails_closed_and_rolls_back_resources` |
| clean rollback 後の同じ `SubjectId` を永久予約し、再作成を adapter 前に拒否する | `clean_setup_rollback_permanently_reserves_subject_id` |
| permanent registry の zero validation、subject exhaustion、rollback 後の exhaustion、handle close 後の exhaustion を adapter 前で拒否する | `zero_registry_capacity_is_rejected_during_supervisor_construction`, `subject_capacity_exhaustion_happens_before_the_resource_adapter`, `clean_rollback_consumes_subject_capacity_permanently`, `issued_handle_capacity_remains_exhausted_after_close_before_adapter_call` |
| 同じ handle の 2 回目の close が `StaleHandle`、shutdown 後の要求が `SubjectClosed` | `stale_handle_and_post_close_requests_are_rejected` |
| 閉じた `HandleId` の再 open が、adapter を呼ぶ前に `StaleHandle` になる | `closed_handle_id_cannot_be_reused` |
| kernel 登録失敗と補償失敗が重なっても、ID が予約され、shutdown が runtime close を retry する | `failed_handle_registration_retains_runtime_cleanup_and_reserves_id` |
| 未 bind / 非 Running の connection が revoke できず、非 holder の revoke も kernel で拒否される | `revoke_requires_a_bound_running_connection`, `root_derive_and_revoke_use_typed_authority_kernel_transitions` |

control socket は実 socket に対して確認する。

| 境界 | test |
|---|---|
| accept が kernel の `SO_PEERCRED` から identity を作り、listener の subject へ解決する | `accept_binds_the_listening_subject_from_the_kernel_credential` |
| 4 KiB を超える datagram を decode 前に拒否する | `oversized_datagram_is_rejected_without_decoding` |
| 受理した socket ID が単調で、release 後に解決不能になる | `accepted_socket_identities_are_not_reused_across_connections` |
| resolver を共有する subject listener 間でも socket ID を非再利用にする | `accepted_socket_identities_are_global_across_subject_listeners` |
| 未 bind の socket ID と、subject の credential と違う peer を拒否する | `resolution_fails_closed_for_unbound_and_foreign_credentials` |
| duplicate bind 後も accepted socket を解放し listener を継続する | `resolver_rebind_failure_drops_accepted_socket_and_listener_remains_usable` |
| 相対 path と root path を bind しない | `listener_rejects_paths_it_cannot_own` |
| backlog を `1..=128` に、receive/send timeout を 300 秒以下に bounded する | `listener_rejects_zero_negative_and_excessive_backlogs`, `listener_rejects_zero_and_excessive_timeouts_before_socket_creation` |
| idle receive と blocked send の deadline を typed error にする | `idle_peer_receive_timeout_is_typed_and_bounded`, `blocked_peer_send_timeout_is_typed_and_bounded` |
| bind 直後の socket node が mode 0600 である | `bound_socket_is_owner_only` |
| reply を一つの bounded datagram として送る | `a_reply_reaches_the_peer_as_one_bounded_datagram` |
| unlink に失敗した control socket の token を保持し、stale node の除去を retry できる | `control_socket_cleanup_retains_token_until_stale_node_is_removed` |

実 Linux resource は実 cgroup v2 と実 process に対して確認する。

| 境界 | test |
|---|---|
| workload が cgroup に閉じ込められ、停止で子孫ごと消える | `a_confined_workload_is_stopped_with_every_descendant` |
| 1 subject が持てる cgroup と control socket は 1 つずつで、解放は idempotent | `one_subject_owns_at_most_one_cgroup_and_control_socket` |
| 他 subject の token で workload を起動できない | `a_workload_cannot_borrow_another_subjects_tokens` |
| directory を抜け出せる subject 名を拒否する | `subject_names_that_could_escape_their_directory_are_refused` |
| handle は subject ごとに追跡され、close は idempotent | `handles_are_tracked_per_subject_and_close_is_idempotent` |
| 設定した directory が実在しなければ構築を拒否する | `host_config_requires_existing_owned_directories` |
| production adapter が実 FUSE mount、cgroup、seqpacket credential、cgroup cleanup retry、record 再作成、handle 増減を観測可能にする | `scripts/ci/verify-real-supervisor-resources.sh` → `real_linux_host_resources_exercises_kernel_side_effects` |

返信の形式も固定してあり、bounded encoder/decoder と実 socket の datagram 送受信を確認する。

| 境界 | test |
|---|---|
| 全 response が bounded encoding を round trip する | `every_response_round_trips_through_the_bounded_encoding` |
| 壊れた response を推測せず拒否する | `malformed_responses_are_rejected_rather_than_guessed` |
| response が guest の学べる識別子を運ばない | `a_response_never_carries_an_identifier_a_guest_could_learn_from` |
| 返信が 1 datagram として peer へ届く | `a_reply_reaches_the_peer_as_one_bounded_datagram` |
| request/response の truncated、trailing、field 上限、datagram 上限を bounded decoder が拒否する | `decoder_rejects_invalid_utf8_and_truncated_fields`, `decoder_rejects_trailing_bytes_after_a_complete_request`, `encoder_and_decoder_accept_exact_field_limit`, `decoder_accepts_request_at_datagram_limit_before_schema_validation`, `decoder_accepts_response_at_datagram_limit_before_schema_validation` |

spoof の test には注意点がある。詐称した `CloseHandle` は**拒否される**（対象 handle が caller の所有ではないため）。caller 自身の handle で claim だけを詐称した場合は、claim が捨てられ caller 自身の handle が閉じる。`CloseSubject` も同じく claim ではなく connection caller の subject だけを閉じる。

`authenticated_foreign_subject_cannot_close_another_subjects_handle` は `dispatch_wire` を経由し、`resources.close_handle` が呼ばれないことまで assert する。

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
# root + private mount namespace + cgroup v2 + /dev/fuse がある場合だけ
scripts/ci/verify-real-supervisor-resources.sh
```

## 未検証の境界

### guest kernel が満たさなければならない前提

`guest-supervisor-init` は実 microVM 上で完走する。ただしそれは guest kernel が 3 つの条件を満たす場合に限る。いずれも Firecracker CI が公開する prebuilt kernel は満たさない。

| 前提 | 無いとどうなるか |
|---|---|
| `CONFIG_FUSE_FS` | capfs の workspace mount が `ENODEV` になり、guest の全ファイル操作が始まらない |
| Landlock ABI 3 以上（kernel 6.2 以降 + `CONFIG_SECURITY_LANDLOCK`） | isolation の capability detection が ABI を取得できず、workload を起動できない |
| PCI 無効時に ACPI が読める kernel | Firecracker は virtio-mmio device を ACPI 経由で列挙する。upstream には `CONFIG_PCI` 無効時に ACPI table load が失敗する不具合が 6.12 LTS まで残っており、root device が見つからず panic する |

[`build-guest-kernel.sh`](../../scripts/ci/build-guest-kernel.sh) が kernel.org の pin 済み source から 3 条件を満たす kernel を build する。3 つ目は [commit 済みの patch](../../guest/kernel/) で塞いでいる。

`/dev/fuse` のノード自体は `ensure_fuse_device` が常に作れる。device node は major/minor を持つ inode に過ぎず、driver の有無とは無関係だからである。そのため FUSE の不在は以前 `CapFS` server の spawn 失敗（`ENODEV`）としてしか現れず、message は runtime directory の path を指していた。現在は `verify_kernel_supports_fuse` が procfs mount 直後に kernel 自身の filesystem 一覧を読み、authority を 1 つも作る前に原因を名指しして停止する。

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
| cleanup の実環境 failure injection | FakeResources の retry matrix は test 済み。Linux adapter が `stop_workload` / `unmount` / cgroup removal / control unlink の各実 syscall failure を返した場合の全組み合わせは privileged test の境界外 |
| 並行性 | register→start の authority close/revoke を snapshot で検出する test はあるが、`AuthorityKernel` を共有する外部 component の任意の interleaving を Supervisor が lock で直列化する保証はない |
| supervisor record 再作成 | clean rollback 後の同じ `SubjectId` 再作成は永久予約で拒否する test 済み。kernel の durable entry を消して再利用する運用は提供しない |
| 資源の増加 | `subjects` は既定 1024、`issued_handles` は既定 65536 の session 永久上限を持ち、zero validation / exhaustion / adapter 未到達を test 済み。異なる運用値と memory sizing は deployment 側の判断 |

### 到達不能な分岐

「workload token はあるが cgroup token が無い」分岐は、public API からは到達できない。`create_subject` は cgroup ownership token を確認してから `start_workload` を呼び、内部 record は private で外部から token を組み替えられない。これは construction/API invariant としての non-goal であり、直接 token を注入する test は提供しない。unknown token を fail-closed にする production adapter の防御分岐は privileged integration test で別に確認する。

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
