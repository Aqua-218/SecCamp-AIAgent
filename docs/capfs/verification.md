<!-- doc-type: verification -->

# 検証対応表

[capfs 実装ガイド](README.md) / 検証対応表

> **対象読者:** capfs の実装者、レビュー担当者、統合 test を書く人

capfs はこの repository で最も実環境に近い test を持つ。実 directory、実 file、実 symlink、実 hard link を作り、実 FUSE mount 上で操作する test がある。それでも VM の中では一度も動いていない。

## local test で確認したこと

### startup の事前検証（実 filesystem）

| 境界 |
|---|
| link を含む木から path 順の manifest が得られ、root fd が返却後も有効 |
| regular file を root にできない |
| root が symlink なら拒否し、repository 内で完結する entry symlink は target ごと import |
| 名前が全て repository 内にある hard link は 1 object として import |
| 外に名前がある inode を既定 policy が実体化し、repository 内の alias 関係だけを残して境界をまたぐ関係を切る |
| `Reject` policy では repository ごと拒否し、repository 内の名前を全件報告する |
| 実体化の copy 予算超過を拒否し、tree を元のまま残す |
| special file、非 UTF-8 名、canonical 規則違反を拒否 |
| entry 数と深さの上限超過を拒否 |
| host 割り当ての `RepoId`、backing root、manifest 由来 registry を同じ owner へ取り込む |
| 同じ `ImportedRepository` を clone した複数 mount が同じ root fd を保持し、片方の open count をもう片方から観測・close できる |
| preflight 失敗時に部分的な namespace 所有型を返さない |

mount ID の相違と、Linux が返しうる全 unsupported object kind の分類は module 内 test が直接検査する。さらに required FUSE gate では backing 配下へ実 FUSE mount を重ね、二度目の preflight が nested mount を拒否することを確認する。通常の hosted unit test は metadata 判定までで、実 nested mount の証拠は gate 側だけに置く。

### runtime の I/O 境界（実 filesystem）

| 境界 | test |
|---|---|
| preflight 後に差し替えられた symlink を open が拒否 | `runtime_open_rejects_a_symlink_substituted_after_preflight` |
| preflight 後に同じ kind の別 inode へ regular file / directory を差し替えても runtime が拒否 | `runtime_open_rejects_a_same_kind_inode_replacement_after_preflight`, `runtime_directory_metadata_rejects_a_same_kind_replacement_after_preflight` |
| create が既存 symlink を辿らない | `runtime_create_does_not_follow_an_existing_target_symlink` |
| preflight 後に追加された hard link を metadata が拒否 | `runtime_metadata_rejects_a_hard_link_added_after_preflight` |
| 同じく remove が拒否 | `runtime_remove_rejects_hard_link_introduced_after_preflight` |
| 同じく mode 変更が、変更前に拒否 | `runtime_permissions_reject_hard_link_before_metadata_change` |
| rename が子孫の kind 変更を syscall 前に拒否 | `runtime_rename_rejects_descendant_kind_change_before_syscall` |
| symlink の作成と読み戻しが registry の記録と一致し、外で書き換えられた target を拒否 | `runtime_symlink_creation_and_read_agree_with_the_namespace_record` |
| hard link が同一 inode へ 2 つ目の名前を作り、その後 capfs の外で足された 3 つ目を拒否 | `runtime_hard_link_creates_a_second_name_for_the_same_inode` |
| directory への hard link を backing へ触れる前に拒否 | `runtime_hard_link_refuses_a_directory_source` |
| 書き込み用 open が directory を拒否 | `runtime_writable_open_rejects_a_directory_object` |
| 直接の子でない path を backing に触れる前に拒否 | `runtime_create_rejects_a_non_direct_child_before_touching_backing` |
| create が既存 file を置き換えない | `runtime_create_does_not_replace_an_existing_backing_entry` |
| create が既存 directory を置き換えない | `runtime_create_directory_does_not_replace_an_existing_backing_entry` |
| exclusive create が検証済み open file を返し、umask 0o027 で 0o1666 が 0o640 になる | `runtime_create_file_is_exclusive_and_returns_validated_open_file` |
| set-ID と sticky を落とし、正確な mode を当てる（0o7754 → 0o754） | `runtime_permissions_strip_privileged_bits_and_apply_exact_mode` |
| mtime のみの更新で atime が保たれる | `runtime_timestamps_set_exact_values_and_omit_unspecified_fields` |
| positioned write が未書き込み部分を保つ | `runtime_positioned_write_preserves_unwritten_file_content` |
| NOREPLACE rename の失敗が backing も namespace も変えない | `failed_no_replace_rename_leaves_backing_and_namespace_unchanged` |
| create 後の検証失敗が、namespace rollback の前に backing entry を削除する | `post_create_failure_removes_backing_entry_before_namespace_rollback` |
| remove 後に同じ path を fresh inode へ再作成でき、path identity registry が stale にならない | `runtime_remove_then_recreate_rebinds_the_path_identity` |
| runtime / preflight が `MNT_ID` 不在の metadata mask を fail closed で拒否 | `runtime_metadata_mask_rejects_missing_mount_id`, `metadata_mask_rejects_missing_mount_id` |
| backing object/path identity registry の lock poison を unavailable として拒否 | `identity_registry_poison_fails_closed` |

### FUSE adapter（実 mount）

revoke 後の既存 file descriptor からの read / write / size 変更 / mode 変更、既存 directory stream からの次の listing、既存 parent directory fd に対する `mkdirat` が拒否されることを、実 mount 上で確認している。

create / remove / rename が directory stream の途中で成功した場合、古い cookie を使わず `EAGAIN` で再開を要求することも確認している。

`mounted_view_linearizes_backing_mutation_against_revoke` は、実 FUSE handle から backing file へ反復 write を行う thread と capability revoke を競合させる。revoke が返った後の同じ handle の write は拒否され、backing の最終長は revoke 前に commit した write 数と一致する。したがって、逐次的な revoke 後拒否だけでなく、実 mount を通る mutation/revoke の線形化点も検査する。

link については、実 mount 上で次を確認している。

| 境界 | test |
|---|---|
| symlink の作成・読み戻し・追従が通り、許可範囲外を指す link の追従が止まる | `mounted_view_creates_reads_and_follows_symlinks_inside_its_range` |
| 絶対 target、root 外へ出る target、名前付き component の後ろに `..` を持つ target を作らせない | `mounted_view_refuses_symlink_targets_that_leave_the_repository` |
| `CreateSymlink` と `ReadLink` がそれぞれ独立に要る | `mounted_view_gates_symlink_creation_and_reading_on_their_own_effects` |
| hard link が同一 inode へ 2 つ目の名前を作り、許可範囲外へは作れない | `mounted_view_creates_hard_links_only_within_its_authorized_range` |
| 許可範囲外に別名を持つ inode は、範囲内の名前からも read 不能で listing にも現れない | `mounted_view_denies_an_inode_whose_other_name_is_out_of_range` |
| `mknod(2)` が `ENOSYS` ではなく `EPERM` になる | `mounted_view_refuses_device_and_fifo_creation_with_eperm` |
| backing の同種 inode 差し替えと symlink 置換を実 mount 上で `EIO` にし、replacement / outside content を返さない | `mounted_view_rejects_backing_replacement_and_symlink_substitution` |
| contained な深い symlink chain は解決し、cycle は kernel の `ELOOP` を返す | `mounted_view_handles_deep_symlink_chains_and_cycles` |
| backing 配下の実 nested FUSE mount を fresh preflight が `NestedMount` として拒否 | `mounted_view_rejects_a_real_nested_mount_during_preflight` |

## 実行コマンド

```bash
cargo fmt --manifest-path crates/capfs/Cargo.toml -- --check
cargo test --manifest-path crates/capfs/Cargo.toml
cargo clippy --manifest-path crates/capfs/Cargo.toml --all-targets -- -D warnings
# Linux / root / /dev/fuse が必要な no-skip gate
scripts/ci/verify-real-capfs.sh
```

通常の `cargo test` では、`/dev/fuse` が無い hosted 環境に限って実 mount test を skip する。実 kernel の証拠を作るときは `scripts/ci/verify-real-capfs.sh` を使う。この script は Linux、root、読み書き可能な `/dev/fuse` を先に確認し、`CAPFS_REQUIRE_FUSE=1` を設定して全 21 件の実 FUSE test を一件も skip せずに実行する。device が無い、mount が拒否される、または test 側が skip を検出した場合は exit 2 または test failure になり、green にはならない。

## 未検証の境界

| 未検証の対象 | なぜ |
|---|---|
| 全ての変更系 operation と revoke の並行競合 | 実 FUSE write と revoke の線形化競合は `mounted_view_linearizes_backing_mutation_against_revoke` で確認済み。rename / unlink / create / metadata の全 interleaving と、全 kernel scheduling は未検証 |
| cross-filesystem / bind mount を含む全 nested mount の越境 | backing 配下の実 FUSE nested mount は gate で確認済みだが、全種類の mount topology と全 kernel mount namespace 組合せは未検証 |
| 敵対的な backing 差し替えの全 race | 実 FUSE 上で同種 regular file と symlink の置換を bounded deterministic case として確認済み。連続 rename/create race、全 scheduler interleaving、別 process の無制限 mutation は未検証 |
| symlink chain の全長・全 topology | 8 段の contained chain と 2-node cycle の `ELOOP` は gate で確認済み。kernel の上限近傍、複雑な相互参照、全 chain 長は未検証 |
| VM 内での動作 | guest の中で capfs を mount して agent が触る経路は一度も実行していない |
| 全 interleaving の loom model | [Authorization guard](../authority-core/authorization-guard.md) の loom は Authority Core 側の同期境界だけを扱う。capfs の namespace lock は対象外 |
| `MNT_ID` を返さない kernel での実挙動 | required mask の fail-closed test はあるが、実際に MNT_ID を欠落させる kernel / filesystem はこの host で再現していない |
| lock poisoning 後の復旧 | namespace / node と backing identity registry が poison 後に拒否することは test 済み。復旧は意図せず、全 interleaving や process restart 後の運用は対象外 |

capfs が守れるのは、supervisor が backing tree を非信頼 process から隔離した実行基盤の上でだけ。**host 上の任意の process を、この FUSE adapter だけで止めることはできない。** 隔離境界は [runtime-isolation](../runtime-isolation/README.md) を含めて完成する。

## 関連

- [capfs 実装ガイド](README.md)
- [Backing repository の事前検証](backing-preflight.md)
- [共有 namespace registry](namespace-registry.md)
- [mount ごとの node table](node-tables.md)
- [Direct-I/O FUSE adapter](read-only-fuse.md)
- [backing への実 I/O](runtime-backing-io.md)
- [検証戦略](../design/verification.md)
- [用語集](../glossary.md)
