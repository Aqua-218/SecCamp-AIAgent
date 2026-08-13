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

mount ID の相違と、Linux が返しうる全 unsupported object kind の分類は module 内 test が直接検査する。**実 nested mount の作成には mount namespace の権限が要るため、通常の unit test は metadata 判定までしか固定していない。**

### runtime の I/O 境界（実 filesystem）

| 境界 | test |
|---|---|
| preflight 後に差し替えられた symlink を open が拒否 | `runtime_open_rejects_a_symlink_substituted_after_preflight` |
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

### FUSE adapter（実 mount）

revoke 後の既存 file descriptor からの read / write / size 変更 / mode 変更、既存 directory stream からの次の listing、既存 parent directory fd に対する `mkdirat` が拒否されることを、実 mount 上で確認している。

create / remove / rename が directory stream の途中で成功した場合、古い cookie を使わず `EAGAIN` で再開を要求することも確認している。

link については、実 mount 上で次を確認している。

| 境界 | test |
|---|---|
| symlink の作成・読み戻し・追従が通り、許可範囲外を指す link の追従が止まる | `mounted_view_creates_reads_and_follows_symlinks_inside_its_range` |
| 絶対 target、root 外へ出る target、名前付き component の後ろに `..` を持つ target を作らせない | `mounted_view_refuses_symlink_targets_that_leave_the_repository` |
| `CreateSymlink` と `ReadLink` がそれぞれ独立に要る | `mounted_view_gates_symlink_creation_and_reading_on_their_own_effects` |
| hard link が同一 inode へ 2 つ目の名前を作り、許可範囲外へは作れない | `mounted_view_creates_hard_links_only_within_its_authorized_range` |
| 許可範囲外に別名を持つ inode は、範囲内の名前からも read 不能で listing にも現れない | `mounted_view_denies_an_inode_whose_other_name_is_out_of_range` |
| `mknod(2)` が `ENOSYS` ではなく `EPERM` になる | `mounted_view_refuses_device_and_fifo_creation_with_eperm` |

## 実行コマンド

```bash
cargo fmt --manifest-path crates/capfs/Cargo.toml -- --check
cargo test --manifest-path crates/capfs/Cargo.toml
cargo clippy --manifest-path crates/capfs/Cargo.toml --all-targets -- -D warnings
```

実 mount を伴う test は、FUSE が使える環境でのみ実行される。

## 未検証の境界

| 未検証の対象 | なぜ |
|---|---|
| 変更系 operation と revoke の並行競合 | 実 mount 上で同時に走らせる統合 test が無い。revoke 後の逐次拒否は確認済みだが、競合中の挙動は未検証 |
| 実 nested mount の越境 | mount namespace の権限が要るため、通常の unit test では metadata 判定まで |
| 敵対的な backing 差し替え | symlink と hard link の個別 case は実 file で確認しているが、体系的な差し替え攻撃の test は無い |
| symlink chain | 単一 link の解決と containment は実 mount で確認しているが、深い chain と cycle は kernel の `ELOOP` に委ねており、test を置いていない |
| VM 内での動作 | guest の中で capfs を mount して agent が触る経路は一度も実行していない |
| 全 interleaving の loom model | [Authorization guard](../authority-core/authorization-guard.md) の loom は Authority Core 側の同期境界だけを扱う。capfs の namespace lock は対象外 |
| `MNT_ID` を返さない kernel での挙動 | fail closed であることはコードから読めるが、そういう環境で実行していない |
| lock poisoning からの復旧 | create 失敗時の panic が `RwLock` を poison することは設計だが、その後の運用経路は無い |

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
