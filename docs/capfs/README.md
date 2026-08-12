# capfs 実装ガイド

[ドキュメント一覧](../README.md) / capfs 実装ガイド

この文書群は、`capfs` が filesystem operation を Capability 判定へ接続するための実装を説明する。設計上の判断は[capfs 設計](../design/capfs.md)を正とする。

| 文書 | 対象 | 内容 |
|---|---|---|
| [Backing repository の事前検証](backing-preflight.md) | [`crates/capfs/src/backing.rs`](../../crates/capfs/src/backing.rs) | root fd、link検査、resource bound、manifestの原子的なstartup import |
| [共有 namespace registry](namespace-registry.md) | [`crates/capfs/src/namespace.rs`](../../crates/capfs/src/namespace.rs) | `ObjectId`割り当て、現在path、generation、open count、namespace変更の原子性 |
| [mount ごとの node table](node-tables.md) | [`crates/capfs/src/node.rs`](../../crates/capfs/src/node.rs) | subject-local `nodeid -> ObjectId`、LOOKUP / FORGET参照数、nodeid非再利用 |
| [Direct-I/O FUSE adapter](read-only-fuse.md) | [`crates/capfs/src/read_only.rs`](../../crates/capfs/src/read_only.rs)、[`runtime.rs`](../../crates/capfs/src/runtime.rs) | metadata visibility、fd-relative I/O、file / directory handle lifecycle、全file mutationのtransaction、毎READ / WRITE / SETATTR / READDIRの再認可、実mount test |

現在は、link-freeなworkspaceの検査、`RepoId`とroot directory fd・namespaceのbinding、初期manifestの原子的なregistry import、VM共通namespace registry、subject-local node tableに加え、Direct-I/O FUSE adapterまで実装している。`LOOKUP`、`GETATTR`、`FORGET`、`OPEN`、`READ`、`WRITE`、`SETATTR`、`CREATE`、`MKDIR`、`UNLINK`、`RMDIR`、`RENAME`、`RELEASE`、`OPENDIR`、`READDIR`、`RELEASEDIR`がroot fd、namespace、node table、Capability kernelへ接続されている。`O_TRUNC`と`SETATTR(size)`は`Truncate`を、modeまたはatime/mtimeだけの`SETATTR`は`SetMetadata`を独立して要求する。`CREATE`は`CreateFile`と返却handleのaccess effectを複合認可し、`MKDIR`、`UNLINK`、`RMDIR`、`RENAME`も対応するfile effectを現在pathで認可する。実mount上では、revoke後の既存file descriptorからのread / write / size変更 / mode変更、既存directory streamからの次のlisting、既存parent directory fdに対する`mkdirat`を拒否する。create、remove、renameがdirectory streamの途中で成功した場合は、古いcookieを使わず`EAGAIN`で再開を要求する。

## 関連

- [capfs 設計](../design/capfs.md)
- [Subject lifecycle と open handle](../authority-core/subject-lifecycle-and-handles.md)
- [検証戦略](../design/verification.md)
