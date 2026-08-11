# capfs 実装ガイド

[ドキュメント一覧](../README.md) / capfs 実装ガイド

この文書群は、`capfs` が filesystem operation を Capability 判定へ接続するための実装を説明する。設計上の判断は[capfs 設計](../design/capfs.md)を正とする。

| 文書 | 対象 | 内容 |
|---|---|---|
| [Backing repository の事前検証](backing-preflight.md) | [`crates/capfs/src/backing.rs`](../../crates/capfs/src/backing.rs) | root fd、link検査、resource bound、manifestの原子的なstartup import |
| [共有 namespace registry](namespace-registry.md) | [`crates/capfs/src/namespace.rs`](../../crates/capfs/src/namespace.rs) | `ObjectId`割り当て、現在path、generation、open count、namespace変更の原子性 |

現在は、link-freeなworkspaceの検査、root directory fd、初期manifestの原子的なregistry import、VM共通namespace registryまで実装している。FUSE requestの変換、subject-local node table、runtime backing syscall、Capability kernelとのadapter接続はまだ含まない。

## 関連

- [capfs 設計](../design/capfs.md)
- [Subject lifecycle と open handle](../authority-core/subject-lifecycle-and-handles.md)
- [検証戦略](../design/verification.md)
