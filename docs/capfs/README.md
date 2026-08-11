# capfs 実装ガイド

[ドキュメント一覧](../README.md) / capfs 実装ガイド

この文書群は、`capfs` が filesystem operation を Capability 判定へ接続するための実装を説明する。設計上の判断は[capfs 設計](../design/capfs.md)を正とする。

| 文書 | 対象 | 内容 |
|---|---|---|
| [Backing repository の事前検証](backing-preflight.md) | [`crates/capfs/src/backing.rs`](../../crates/capfs/src/backing.rs) | root fd の取得、link・special file・mount crossing の拒否、resource bound、初期 manifest |
| [共有 namespace registry](namespace-registry.md) | [`crates/capfs/src/namespace.rs`](../../crates/capfs/src/namespace.rs) | `ObjectId` と現在 path の対応、generation、open count、create/remove/rename の原子性 |

現在は、link-free な workspace を検査して root directory fd と初期 manifest を得る処理、およびVM共通 namespace registry を実装している。FUSE request の変換、manifest から registry への startup import、runtime backing syscall、Capability kernel との adapter 接続はまだ含まない。

## 関連

- [capfs 設計](../design/capfs.md)
- [Subject lifecycle と open handle](../authority-core/subject-lifecycle-and-handles.md)
- [検証戦略](../design/verification.md)
