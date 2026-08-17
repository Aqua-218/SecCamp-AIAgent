<!-- doc-type: verification -->

# 検証対応表

[Session orchestrator](README.md) / 検証対応表

> **対象読者:** orchestrator の実装者、レビュー担当者、実機で統合 test を回す人

test には、mock backend による state machine test、durable ledger を直接叩く test、production adapter の composition test、実機専用の production `SessionOwner` KVM gate がある。通常の test では最後の gate を実行せず、要求された Linux/KVM host で wrapper を明示的に起動する。

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
| `new_durable` の実 `start_session` が最初の backend effect より前に7 identityをcommitし、stop後も再openできる | `tests/ledger.rs` の実 durable orchestrator probe |
| record-sync前後の crash 相当 staged tail、rename/length drift 後の poison と再試行拒否、write/sync fault 後の poison と reopen | `tests/ledger.rs` の実 file fault test + `lib.rs` の private deterministic seam |
| cross-process contention と owner process kill 後の stale lock 再取得 | `tests/ledger.rs` の child process test |
| request/header/file の capacity hard bound、最大件数ちょうどの実データ commit、malformed header/symlink/non-regular-file fail-closed | `tests/ledger.rs` の実 file test |
| Linux kernel entropy source からの16 byte読出し、public `new_durable` の all-zero bounded retry/fail-closed | `tests/ledger.rs` の `OsEntropy` / durable orchestrator tests |
| identity の 32 桁 hex 表現 | 単体 |
| workspace clone、listener 所有、snapshot binding、Firecracker identity 注入、Authority subject の閉包 | production adapter composition test（全境界 fake） |
| production `SessionOwner` の build → 実 Firecracker snapshot restore → guest readiness → `Continue` poll → stop → `Closed` | `real_production_lifecycle.rs`（実 `Runtime`、jailer、dm-verity、filesystem、AF_VSOCK、durable Broker、guest supervisor。`REAL_SESSION_OWNER_LIFECYCLE=1` の ignored gate） |

## 実行コマンド

```bash
cargo fmt --manifest-path crates/session-orchestrator/Cargo.toml -- --check
cargo test --manifest-path crates/session-orchestrator/Cargo.toml
cargo clippy --manifest-path crates/session-orchestrator/Cargo.toml --all-targets -- -D warnings
```

## 実機 production lifecycle gate

次の wrapper は、固定された Firecracker/jailer、guest kernel、guest runtime image、seccomp
filter を用意し、`ProductionSessionRuntimeBuilder` から実 `SessionOwner` を構築する。
guest-control の identity injection と guest supervisor readiness が確認されてから workload
を解放し、`Continue` の Broker health poll、外部 stop、`Closed` までを一つの test で通す。
stop 後は subject 操作の durable audit、identity ledger、recovery journal、Broker WAL を再度
読み、VM、cgroup leaf、dm-verity mapper、jail、API/vsock socket、workspace clone/image が
残っていないことを検査する。

```bash
scripts/ci/verify-real-session-owner.sh
```

これは root、x86_64 KVM、`/dev/vhost-vsock`、cgroup-v2、dm-verity、`mksquashfs`、および
guest kernel build toolchain を必要とする。jailer が chroot 内で Firecracker を実行できるよう、
既定の staging は短い `/root/so.XXXXXX`（private かつ実行可能な mount）に作り、wrapper は
mount flags と statfs、および全 ancestor の所有者・mode を検査して `noexec` や共有 writable
の候補を fail closed で拒否する。`REAL_SESSION_TEMP_PARENT` で別の専用 parent を指定する
場合も、同じ検査を通過する必要がある。egress adapter は意図的に closed/rejecting で、
外部 HTTP/GitHub provider の到達性や mutation はこの gate の対象外である。guest 内の
CapFS/supervisor が readiness まで進むことは確認するが、全ての file effect、FUSE/OS の
意味論、外部 provider の安全性をこの test だけで証明するものではない。

## 未検証の境界

### test double が代わりに立っているもの

| 本来の依存 | 代替 |
|---|---|
| Firecracker、jailer、dm-verity | `TestRunner`、`TestApi`（通常の composition test） |
| filesystem | `TestFileSystem`（通常の composition test） |
| `AF_VSOCK` listener | `ListenerFactory` |
| entropy | `SequenceRandom`（`[0x01; 16]` などの決定的な値） |
| durable ledger（通常の state-machine test） | `InMemoryIdentityLedger` と `FailingLedger`。実 durable path は下記 `tests/ledger.rs` |

`tests/production_adapters.rs` が示すのは identity が adapter を貫通することだけ。実機 gate は
Firecracker 起動、dm-verity/seccomp、guest-control の identity gate、guest supervisor readiness、
Broker listener の生存、依存順 cleanup までを追加で確認する。ただし Broker の egress は closed
であり、外部 provider の接続・mutation、任意の CapFS effect と OS/FUSE の全挙動は示さない。

### 検査があるのに test が無いもの

| 対象 | 何が未検証か |
|---|---|
| `validate_workspace` | `CrossSessionLease` 経路と、その clone 解放は `foreign_workspace_lease_isolates_the_clone_before_returning` で検証済み。`LeaseIdentityMismatch` 側の分岐は未検証 |
| `SessionOrchestrator::new_durable` | public integration test は実 `start_session` の7 record commit、backend effect前のfile state、stop後のreopenを固定する。実 `SessionOwner` / production builder の経路は別の ignored gateに依存する |
| ledger の crash consistency | valid staged tail の再open破棄、部分 tail、header redundancy、rename/length drift、write/sync fault は実 file と private deterministic seam で固定した。ledger 自身に rename syscall はなく、path replacement は実 `fs::rename` で検証する |
| `poisoned` 経路 | rename/length drift と write/sync syscall failure 後の typed error、同一 handle の `Unavailable`、reopen 後の safe reuse/duplicate rejection を固定した。header sync は syscall が実際に header を反映してから失敗する場合もあるため、reopen の両結果を安全条件として検証する |
| `CapacityExceeded` | request batch、header declared count、file size の3 hard bound に加え、最大件数ちょうどを実データで埋めた成功、次 record の拒否、reopen 後の件数を固定した |
| stale lock の回収 | child processをkillした後のkernel lock再取得、stable lock inode、cross-process `Locked`を実行済み。異常終了がOS以外の外部ロック実装を含むことは保証しない |
| 並行性 | 2 process の `open` contention は固定した。lock保持中に2つのwriterが同時にreserve成功する競合試験は、exclusive openで成立しないため未実行 |
| `OsEntropy` | Linux `/dev/urandom` のopenと16 bytes読出し、2回の値がall-zeroでないこと、public allocation の all-zero bounded retry と persistent-zero typed failure、entropy I/O failure の typed propagation を固定した。予測不可能性や kernel/host entropy品質は証明せず、host OS RNG を TCB とする |
| ledger の error variant | `Symlink`、`NotRegularFile`、`UnsupportedVersion`、`Corrupt`、`Truncated`、`Duplicate`、`CapacityExceeded`、`PathIdentityChanged`、`LengthChanged`、`Unavailable`、未知kind、非連続 sequence、非ゼロ reserved は実行済み |
| 空 failure の `StopError::Cleanup` | flag が false で lease が `None` の場合に `Stopping` へ永久固着する。structural に防いでおらず test も無い |
| `rollback_failures` の完全性 | index 0 しか確認していない test が 1 本。gate で飛ばした stage が failure に現れないことを固定する test が無い |
| `LifecycleState` の中間値 | `state()` から観測できないため、`WorkspaceCloned` 等を確認する test は存在しえない |

### この crate が構造的に確認しないこと

snapshot image を一度も読まない。`SnapshotDescriptor` は呼び出し側の申告なので、「この snapshot に session identity は無い」は caller の主張である。**中身が汚れていて descriptor が綺麗な image は素通りする。**

ledger の CRC-32 は MAC ではない。file に書ける者は record を削除して CRC を計算し直せる。防御は filesystem permission と advisory な sidecar lock だけ。

Linux では ledger と lock を `O_NOFOLLOW` 付きの held parent-directory descriptor 相対で開く。open 前後の検査は別の syscall なので、parent/fileの交換競合を完全には原子的に証明せず、held descriptor と device/inode の再検証で fail closed にする。

mock test が全部通っても、VM 実起動や full isolation の完成とは判断しない。実機 gate が通っても、
その保証範囲は上記の明示された lifecycle と cleanup に限る。この方針は [docs/README.md](../README.md)
の宣言に従う。

## 関連

- [Session orchestrator](README.md)
- [session の commit 順序と cleanup](lifecycle.md)
- [identity と ledger](identity-ledger.md)
- [lease の binding](lease-binding.md)
- [production backend 契約](contracts.md)
- [検証戦略](../design/verification.md)
- [用語集](../glossary.md)
