# ドキュメント

このディレクトリは、設計上の判断と現在の実装を分けて参照するための入口である。

| 文書群 | 対象読者 | 内容 |
|---|---|---|
| [設計書](design/README.md) | 設計者、実装者、セキュリティレビュー担当者 | 脅威モデル、Capability モデル、失効、隔離、検証戦略、実装順序 |
| [Authority core 実装ガイド](authority-core/README.md) | Rust/Lean 実装者、証明のレビュー担当者 | 現在の Authority core 各ファイルの責務、Rust と Lean の対応、定理、テスト |
| [capfs 実装ガイド](capfs/README.md) | filesystem adapter 実装者、並行境界のレビュー担当者 | backing root、startup import、ObjectId、namespace変更、mount-local node identity |
| [Broker session envelope](egress-protocol/session-envelopes.md) | Broker / transport 実装者 | session、sequence、request ID、payload hash、retry と replay 防止 |
| [Canonical Broker CBOR](egress-protocol/canonical-cbor.md) | Broker / transport 実装者 | bounded frame の中の唯一の request schema、payload hash と typed operation への復元 |

## Authority core 文書

| 文書 | 内容 |
|---|---|
| [実装ガイド](authority-core/README.md) | 実装範囲、source map、Rust と Lean の依存関係 |
| [証明の考え方](authority-core/proof-concepts.md) | 証明付きデータ、集合意味論、健全性・完全性、反射律・推移律、空集合の注意点 |
| [パスモデル](authority-core/paths.md) | `CanonicalPath`、`PathPattern`、matching、containment と証明 |
| [Repository identity](authority-core/repository-identities.md) | `RepoId` の責務と exact equality 境界 |
| [File authority](authority-core/file-authorities.md) | effect 集合、request、delegation 判定と証明 |
| [有効期間](authority-core/validity-windows.md) | 単調時刻、半開区間、時刻窓の containment と証明 |
| [Capability](authority-core/capabilities.md) | typed metadata、全 authority family の envelope、時刻付き matching、`weakerThan` と証明 |
| [HTTP fetch authority](authority-core/http-fetch-authorities.md) | canonical host / URL path、GET / HEAD、応答上限、委譲と Broker の責務境界 |
| [GitHub authority](authority-core/github-authorities.md) | installation / repository、閉じた操作、base/head branch、委譲と Broker の責務境界 |
| [Capability state](authority-core/capability-state.md) | subject、静的 envelope、発行、保持、逐次 Derive、revoke と祖先失効 |
| [Authorization guard](authority-core/authorization-guard.md) | effect commit と revoke の線形化、executor 契約、loom の positive / negative control |
| [Subject lifecycle と open handle](authority-core/subject-lifecycle-and-handles.md) | shutdown、`auth_epoch`、handle の subject/object binding と ID 非再利用 |
| [Attempt / effect audit](authority-core/audit-records.md) | 全認可試行と commit 済み effect の区別、記録失敗時の fail closed |
| [検証とテスト](authority-core/verification.md) | Rust unit・状態遷移・property・loom test、Lean example・theorem、共通 corpus の役割分担 |

## capfs 文書

| 文書 | 内容 |
|---|---|
| [実装ガイド](capfs/README.md) | 現在の実装範囲と文書一覧 |
| [Backing repository の事前検証](capfs/backing-preflight.md) | root fd、link-free tree、mount・inode identity、startup import |
| [共有 namespace registry](capfs/namespace-registry.md) | `ObjectId`割り当て、現在path、generation、open handle、namespace lock契約 |
| [mount ごとの node table](capfs/node-tables.md) | subject-local `nodeid -> ObjectId`、LOOKUP / FORGET、nodeid非再利用 |
| [Direct-I/O FUSE adapter](capfs/read-only-fuse.md) | LOOKUP / GETATTR / OPEN / READ / WRITE / SETATTR / CREATE / MKDIR / UNLINK / RMDIR / RENAME / READDIR / RELEASE、runtime backing I/O、revoke後の再認可 |

## 文書の使い分け

- 「なぜこの構造にするか」は[設計書](design/README.md)を読む。
- 「どのファイルが何を実装・証明しているか」は[Authority core 実装ガイド](authority-core/README.md)を読む。
- 「rename 中にも現在 path をどう固定するか」は[capfs 実装ガイド](capfs/README.md)を読む。
- 設計と実装が食い違って見える場合は、両方を照合し、実装済み範囲を Authority core 実装ガイドで確認する。

## 関連

- [Capability モデル](design/capability-model.md)
- [検証戦略](design/verification.md)
- [実装順序](design/implementation-plan.md)
