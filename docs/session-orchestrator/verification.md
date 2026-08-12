<!-- doc-type: verification -->

# 検証対応表

[Session orchestrator](README.md) / 検証対応表

> **対象読者:** orchestrator の実装者、レビュー担当者、実機で統合 test を回す人

test は 3 系統ある。mock backend による state machine test、durable ledger を直接叩く test、production adapter の composition test。実 VM、実 vsock、実 filesystem はどれにも出てこない。

## local test で確認したこと

| 境界 | 検証手段 |
|---|---|
| 正常な startup と stop の全 stage | mock backend |
| 各 stage の失敗と、その時点までの rollback | mock backend |
| rollback 自体の失敗と `Stopping` の保持 | mock backend |
| VM kill 失敗時に workspace を保持する | mock backend |
| snapshot に継承 identity がある場合の拒否 | mock backend |
| 同じ identity の再利用の拒否 | mock backend + failing ledger stub |
| active session の二重起動の拒否 | mock backend |
| foreign lease（workspace、Broker、VM）の拒否 | mock backend |
| workspace lease が別 session のとき、clone を解放してから返す | mock backend |
| stop の retry が未完了 stage だけを実行する | mock backend |
| ledger の header / record checksum、truncation、sequence 連続性 | 実 file を使う直接 test |
| 同一 process からの二重 open が拒否される | 実 file を使う直接 test |
| identity の 32 桁 hex 表現 | 単体 |
| workspace clone、listener 所有、snapshot binding、Firecracker identity 注入、Authority subject の閉包 | production adapter composition test（全境界 fake） |

## 実行コマンド

```bash
cargo fmt --manifest-path crates/session-orchestrator/Cargo.toml -- --check
cargo test --manifest-path crates/session-orchestrator/Cargo.toml
cargo clippy --manifest-path crates/session-orchestrator/Cargo.toml --all-targets -- -D warnings
```

## 未検証の境界

### test double が代わりに立っているもの

| 本来の依存 | 代替 |
|---|---|
| Firecracker、jailer、dm-verity | `TestRunner`、`TestApi` |
| filesystem | `TestFileSystem` |
| `AF_VSOCK` listener | `ListenerFactory` |
| entropy | `SequenceRandom`（`[0x01; 16]` などの決定的な値） |
| durable ledger（orchestrator 経由） | `InMemoryIdentityLedger` と `FailingLedger` |

`tests/production_adapters.rs` が示すのは identity が adapter を貫通することだけ。Firecracker が起動すること、dm-verity や seccomp が適用されること、実 `AF_VSOCK` socket が bind すること、guest 内で capfs が動くことは、いずれも示していない。

### 検査があるのに test が無いもの

| 対象 | 何が未検証か |
|---|---|
| `validate_workspace` | `CrossSessionLease` 経路と、その clone 解放は `foreign_workspace_lease_isolates_the_clone_before_returning` で検証済み。`LeaseIdentityMismatch` 側の分岐は未検証 |
| `SessionOrchestrator::new_durable` | どの test からも呼ばれていない。durable ledger を orchestrator 経由で動かす経路が皆無 |
| ledger の crash consistency | record の sync と header の write の間で落とす fault injection が無い。「header の commit 範囲外に trailing bytes」の分岐は未到達（既存 test は `set_len` で `Truncated` に当たる） |
| `poisoned` 経路 | 実 `DurableIdentityLedger` で起こす test が無い。mock が `WriteFailed` / `SyncFailed` を返すだけ |
| `CapacityExceeded` | 定数の値を assert しているのみ。append 時、file size、header 宣言件数の 3 つの bound すべて未実行 |
| stale lock の回収 | 既存 test は同一 process から 2 回 open するので `/proc` を一度も見ない。cross-process の排他も、死んだ所有者からの復旧も未検証 |
| 並行性 | 2 thread も 2 process も `open` / `reserve_batch` を競わせていない。排他は sidecar file と `create_new` に依存していて、contention 下で未検証 |
| `OsEntropy` | 実行する test が無い。`/dev/urandom` を開くこと、16 bytes 読むこと、予測不可能であることのいずれも未確認 |
| ledger の error variant | `Symlink`、`NotRegularFile`、`UnsupportedVersion`、file 内 `Duplicate`、非連続 sequence、未知 kind tag、非ゼロ reserved がすべて未到達 |
| 空 failure の `StopError::Cleanup` | flag が false で lease が `None` の場合に `Stopping` へ永久固着する。structural に防いでおらず test も無い |
| `rollback_failures` の完全性 | index 0 しか確認していない test が 1 本。gate で飛ばした stage が failure に現れないことを固定する test が無い |
| `LifecycleState` の中間値 | `state()` から観測できないため、`WorkspaceCloned` 等を確認する test は存在しえない |

### この crate が構造的に確認しないこと

snapshot image を一度も読まない。`SnapshotDescriptor` は呼び出し側の申告なので、「この snapshot に session identity は無い」は caller の主張である。**中身が汚れていて descriptor が綺麗な image は素通りする。**

ledger の CRC-32 は MAC ではない。file に書ける者は record を削除して CRC を計算し直せる。防御は filesystem permission と advisory な sidecar lock だけ。

ledger file は `O_NOFOLLOW` なしで開く。open 前後の 2 回の検査は別の syscall で、後者は fd が regular file であることを見るが同一 inode であることは見ない。

mock test が全部通っても、VM 実起動や full isolation の完成とは判断しない。この方針は [docs/README.md](../README.md) の宣言に従う。

## 関連

- [Session orchestrator](README.md)
- [session の commit 順序と cleanup](lifecycle.md)
- [identity と ledger](identity-ledger.md)
- [lease の binding](lease-binding.md)
- [production backend 契約](contracts.md)
- [検証戦略](../design/verification.md)
- [用語集](../glossary.md)
