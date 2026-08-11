# capfs 実装ガイド

[ドキュメント一覧](../README.md) / capfs 実装ガイド

この文書群は、`capfs` が filesystem operation を Capability 判定へ接続するための実装を説明する。設計上の判断は[capfs 設計](../design/capfs.md)を正とする。

| 文書 | 対象 | 内容 |
|---|---|---|
| [Backing repository の事前検証](backing-preflight.md) | [`crates/capfs/src/backing.rs`](../../crates/capfs/src/backing.rs) | root fd、link検査、resource bound、manifestの原子的なstartup import |
| [共有 namespace registry](namespace-registry.md) | [`crates/capfs/src/namespace.rs`](../../crates/capfs/src/namespace.rs) | `ObjectId`割り当て、現在path、generation、open count、namespace変更の原子性 |
| [mount ごとの node table](node-tables.md) | [`crates/capfs/src/node.rs`](../../crates/capfs/src/node.rs) | subject-local `nodeid -> ObjectId`、LOOKUP / FORGET参照数、nodeid非再利用 |
| [read-only FUSE adapter](read-only-fuse.md) | [`crates/capfs/src/read_only.rs`](../../crates/capfs/src/read_only.rs)、[`runtime.rs`](../../crates/capfs/src/runtime.rs) | metadata visibility、fd-relative I/O、file / directory handle lifecycle、毎READ / READDIRの再認可、実mount test |

現在は、link-freeなworkspaceの検査、`RepoId`とroot directory fd・namespaceのbinding、初期manifestの原子的なregistry import、VM共通namespace registry、subject-local node tableに加え、read-only FUSE adapterまで実装している。`LOOKUP`、`GETATTR`、`FORGET`、`OPEN`、`READ`、`RELEASE`、`OPENDIR`、`READDIR`、`RELEASEDIR`がroot fd、namespace、node table、Capability kernelへ接続されている。実mount上でも、revoke後の既存file descriptorからのreadと、既存directory streamからの次のlistingを拒否する。

次の実装対象は`WRITE`である。その後にcreate、remove、no-replace renameを追加する。

## 関連

- [capfs 設計](../design/capfs.md)
- [Subject lifecycle と open handle](../authority-core/subject-lifecycle-and-handles.md)
- [検証戦略](../design/verification.md)
