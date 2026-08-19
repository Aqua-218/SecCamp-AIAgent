<!-- doc-type: verification -->

# capfs overhead ベンチマーク

[capfs 実装ガイド](README.md) / capfs overhead ベンチマーク

> **対象読者:** capfs 導入コストを見積もる実装者、mount 設定・attribute TTL・認可経路を変更する担当者

このページは [`crates/capfs/benches/capfs_overhead.rs`](../../crates/capfs/benches/capfs_overhead.rs) が「capfs がある場合とない場合」のコスト差をどう測るか、そしてその数値から何が言えて何が言えないかを述べる。

## 4 層で測る理由

`capfs` と `native` の 2 点だけを比べると倍率は出るが、その倍率が FUSE 往復に由来するのか capability enforcement に由来するのかが分からない。分からないままでは、遅いときにどこを直せばよいかも決まらない。そこで同一の client 側 workload を 4 層に流す。

| 層 | 何を通るか | 何を測るか |
| --- | --- | --- |
| `native` | backing filesystem 直接 | capfs が無いときにアプリが得るコスト |
| `passthrough` | 同じ mount 設定の FUSE、認可を一切しない | FUSE 往復そのもののコスト |
| `capfs` | 実際の [`capfs::filesystem::CapabilityFilesystem`](../../crates/capfs/src/read_only.rs) mount | 実運用で払うコスト |
| `kernel` | FUSE を通さない in-process の Capability 判定 | 認可判定単体のコスト |

比の読み方は次の 3 つに固定する。

- `capfs / native` — capfs 導入で実際に払う倍率
- `passthrough / native` — そのうち FUSE 往復が占める分
- `capfs / passthrough` — capability enforcement が上乗せする分

## 対照が対照であるための条件

`passthrough` は「FUSE だけを残して capfs を引いた」層でなければ対照にならない。そのため次を揃えている。

| 揃えるもの | 実装 |
| --- | --- |
| mount option、thread 数、ACL、`clone_fd` | [`capfs::filesystem::mount_config`](../../crates/capfs/src/read_only.rs) をそのまま呼び、`FSName` / `Subtype` だけ差し替える |
| `OPEN` の応答 flag | 両層とも read-only handle は cached、writable handle は `FOPEN_DIRECT_IO`。`FOPEN_KEEP_CACHE` は付けないので、page cache は handle が開いている間だけ有効 |
| attribute TTL | 両層とも同じ有限値。stat は TTL 内なら OS の cache から返る |
| 1 request あたりの上限 | 両層とも `init` で `max_write` を 1 MiB に設定する |
| `READDIR` の内容 | 両層とも `.` と `..` を先頭 2 件として返す |

`native` だけは page cache を経由する通常の buffered I/O にしてある。capfs が無いときアプリが実際に得るのはそれだからで、この差は倍率に含める意図的な設計である。

## local test で確認したこと

| benchmark | 1 iteration が発行する operation | 何を分離するか |
| --- | --- | --- |
| `read/{層}/{4K,64K,1M}` | 既に open 済み fd への positioned read | `READ` 単体。`LOOKUP` と `OPEN` を計測から外す |
| `write/{層}/{4K,64K,1M}` | 事前確保済み file への positioned write | `WRITE` 単体。file 延長も truncate 経路も踏まない |
| `stat/{層}` | `lstat` 1 回 | attribute cache に載る metadata 経路。revoke 時に無効化される側 |
| `open_close/{層}` | `open` + `close` | `LOOKUP` → `OPEN` → `RELEASE` の handle lifecycle |
| `readdir/{層}` | 32 entry の directory を 1 周 | `OPENDIR` → `READDIR` → `RELEASEDIR` |
| `capability_check/commit` | `authorize_and_execute_classified` 1 回 | `READ` / `WRITE` が通る data 経路の認可。audit attempt を記録し `EffectExecution::Committed` を確定する |
| `capability_check/observe` | `with_active_capability` 1 回 | `LOOKUP` / `GETATTR` が通る metadata 経路の認可。effect を記録しない |
| `concurrent_read/{層}/{1..16}` | N client thread がそれぞれ自分の fd へ 4 KiB read | mount が並行要求を捌けているか。1 operation あたりの wall clock が thread 数と共に下がるか、直列化して横ばいになるか |

benchmark ごとに backing tree と mount を作り直す。`authorize_and_execute_classified` は commit 済み effect 1 件につき in-memory audit record を 1 件保持し続けるため、1 つの mount を全 benchmark で共有すると audit trail が run 全体に渡って伸び、測定対象がメモリ確保に移る。`capability_check/commit` は同じ理由で sample ごとに kernel を作り直す。

## 実行コマンド

repository root から次を実行する。`/dev/fuse` が無い環境では FUSE を使う 2 層を自動的に外し、`native` と `kernel` だけを測る。

```bash
cargo bench --locked --package capfs --bench capfs_overhead

# 1 group だけ、短時間で見る
cargo bench --locked --package capfs --bench capfs_overhead -- stat

# 変更前後を比較する（criterion が前回結果を target/criterion に保持する）
cargo bench --locked --package capfs --bench capfs_overhead -- --save-baseline before
cargo bench --locked --package capfs --bench capfs_overhead -- --baseline before
```

## 未検証の境界

この benchmark は 1 プロセスの client が、warm な backing tree に対して I/O を出す場合しか測っていない。`concurrent_read` は同一プロセス内の 16 thread までしか広げていない。したがって次はこの結果からは言えない。

- 別プロセス・別 mount からの競合、および 16 を超える並行度
- 同一 repository を複数 mount が共有し、片方の write を他方が観測する場合のコスト。page cache は open をまたがず、attribute は TTL 内で古くなりうる
- cold page cache、fsync、実 disk 待ちを含む場合の絶対値
- `CREATE` / `MKDIR` / `UNLINK` / `RMDIR` / `RENAME` の namespace 変更コスト。これらは open handle と generation を触るため、read/write とはコスト構造が違う
- capability 木が深い場合、path pattern が長い場合、subject や capability が多数ある場合の認可コスト。ここでは root 直下 prefix の capability 1 枚しか測っていない
- durable audit backend を有効にした場合のコスト。ここでの `kernel` 層は in-memory audit trail のみ
- revoke が走っている最中の競合コスト

絶対値は machine と backing filesystem に強く依存する。移植して意味があるのは層の比であって、µs の数値そのものではない。

## 関連

- [capfs 実装ガイド](README.md)
- [Direct-I/O FUSE adapter](read-only-fuse.md)
- [共有 namespace registry](namespace-registry.md)
- [capfs 設計](../design/capfs.md)
- [全体の検証戦略](../design/verification.md)
