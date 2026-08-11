# capfs 実装ガイド

[ドキュメント一覧](../README.md) / capfs 実装ガイド

この文書群は、`capfs` が filesystem operation を Capability 判定へ接続するための実装を説明する。設計上の判断は[capfs 設計](../design/capfs.md)を正とする。

| 文書 | 対象 | 内容 |
|---|---|---|
| [共有 namespace registry](namespace-registry.md) | [`crates/capfs/src/namespace.rs`](../../crates/capfs/src/namespace.rs) | `ObjectId` と現在 path の対応、generation、open count、create/remove/rename の原子性 |

現在実装されているのは、link-free な workspace を前提としたVM共通 namespace registry である。FUSE request の変換、実 backing fd、repository import 時の link 検査、Capability kernel との adapter 接続はまだ含まない。

## 関連

- [capfs 設計](../design/capfs.md)
- [Subject lifecycle と open handle](../authority-core/subject-lifecycle-and-handles.md)
- [検証戦略](../design/verification.md)
