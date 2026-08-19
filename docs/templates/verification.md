<!-- doc-type: verification -->

# 検証対応表

[<親ページ名>](README.md) / 検証対応表

> **対象読者:** <この crate の実装者、レビュー担当者、統合 test の実行担当者>

このページは `<crate>` について、local test で確認済みの境界と、未検証のまま残る境界を分けて記録する。mock / fake test の成功を、実機動作の根拠にしない。`verified` claim を書く場合も、[verification-status manifest](../verification-status.md) の declared scope と required gate に合わせる。

## local test で確認したこと

| 境界 | 検証手段 | test |
|---|---|---|
| <確認した不変条件> | <unit / property / loom / mock backend / 実 mount> | `<test 名>` |

## 実行コマンド

```bash
cargo fmt --manifest-path crates/<crate>/Cargo.toml -- --check
cargo test --manifest-path crates/<crate>/Cargo.toml
cargo clippy --manifest-path crates/<crate>/Cargo.toml --all-targets -- -D warnings
```

## 未検証の境界

<検証できていないものを、言い換えずに書く。>

| 未検証の対象 | なぜ未検証か | 何があれば検証できるか |
|---|---|---|
| <実 syscall / 外部 API / 実 VM / 特権操作> | <test double を使っている、特権が要る、外部依存がある> | <必要な環境> |

<test double に置き換えている依存を明示する。>

- `<trait 名>`: <fake の名前>。<実装が省いていること>

manifest の checker は command を実行しない。KVM、root、外部 credential、別アーキテクチャが必要な境界は、実行 artifact が無い限り `verified` と記録しない。

## 関連

- [<索引ページ>](README.md)
- [検証戦略](../design/verification.md)
- [用語集](../glossary.md)
