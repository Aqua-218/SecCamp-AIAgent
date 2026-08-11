# ドキュメント

このディレクトリは、設計上の判断と現在の実装を分けて参照するための入口である。

| 文書群 | 対象読者 | 内容 |
|---|---|---|
| [設計書](design/README.md) | 設計者、実装者、セキュリティレビュー担当者 | 脅威モデル、Capability モデル、失効、隔離、検証戦略、実装順序 |
| [Authority core 実装ガイド](authority-core/README.md) | Rust/Lean 実装者、証明のレビュー担当者 | 現在の Authority core 各ファイルの責務、Rust と Lean の対応、定理、テスト |

## Authority core 文書

| 文書 | 内容 |
|---|---|
| [実装ガイド](authority-core/README.md) | 実装範囲、source map、Rust と Lean の依存関係 |
| [証明の考え方](authority-core/proof-concepts.md) | 証明付きデータ、集合意味論、健全性・完全性、反射律・推移律、空集合の注意点 |
| [パスモデル](authority-core/paths.md) | `CanonicalPath`、`PathPattern`、matching、containment と証明 |
| [Repository identity](authority-core/repository-identities.md) | `RepoId` の責務と exact equality 境界 |
| [File authority](authority-core/file-authorities.md) | effect 集合、request、delegation 判定と証明 |
| [有効期間](authority-core/validity-windows.md) | 単調時刻、半開区間、時刻窓の containment と証明 |
| [Capability](authority-core/capabilities.md) | typed metadata、file-only envelope、時刻付き matching、`weakerThan` と証明 |
| [検証とテスト](authority-core/verification.md) | Rust unit test、Lean example、Lean theorem の役割分担 |

## 文書の使い分け

- 「なぜこの構造にするか」は[設計書](design/README.md)を読む。
- 「どのファイルが何を実装・証明しているか」は[Authority core 実装ガイド](authority-core/README.md)を読む。
- 設計と実装が食い違って見える場合は、両方を照合し、実装済み範囲を Authority core 実装ガイドで確認する。

## 関連

- [Capability モデル](design/capability-model.md)
- [検証戦略](design/verification.md)
- [実装順序](design/implementation-plan.md)
