<!-- doc-type: exempt -->

# 検証ステータス manifest

[ドキュメント一覧](README.md) / 検証ステータス manifest

> **対象読者:** CI の gate を保守する実装者、検証結果をレビューする担当者

[`docs/verification-status.yml`](verification-status.yml) は、検証の主張を実行環境ごとに分けて記録する機械可読 manifest である。`verified` は記録された evidence を該当 scope で実行した意味だけを持ち、隣接する privileged、KVM、external の境界まで検証したことを意味しない。

## スキーマ

| field | 規約 |
|---|---|
| `schema` | 固定値 `verification-status/v1` |
| `claims[].id` | manifest 内で一意な安定 ID |
| `claims[].component` | 対象 crate または境界 |
| `claims[].scope` | `hosted`、`privileged`、`kvm`、`external` のいずれか |
| `claims[].status` | `verified` または `unverified` |
| `claims[].evidence.commands` | 証跡を再現するコマンド。checker は実行しない |
| `claims[].evidence.sources` | repository-relative な実装パス |
| `claims[].evidence.tests` | repository-relative な test パス |
| `claims[].residual_reasons` | `unverified` では必須。`verified` では空配列 |

`sources` と `tests` は存在するパスでなければならず、絶対パスや `..` による runner 外部参照は許さない。コマンドの存在だけでは検証済みにならないため、status の変更は実際にその scope の証跡を取得した変更と同時に行う。

## checker の責務

[`scripts/ci/check-doc-consistency.sh`](../scripts/ci/check-doc-consistency.sh) は、CI に固定された yq の版を使って YAML を読み、次を fail closed で検査する。

- schema、status、scope、claim ID の一意性
- evidence の command / source / test の非空性と repository 内パス
- `unverified` claim の residual reason と `verified` claim の空 reason

この checker は command を実行しない。実行結果を記録する gate、root / cgroup / KVM が必要な gate、外部サービスの利用可否はそれぞれの scope の実行 job が担う。

## 変更時の確認

```bash
scripts/ci/check-doc-consistency.sh
scripts/ci/check-doc-consistency.sh ci/fixtures/verification-status-missing-evidence.yml
```

2 つ目は負の fixture であり、意図的に失敗する。新しい claim を追加するときは、status を先に `unverified` とし、検証できていない理由を具体的に書く。

## 関連

- [検証戦略](design/verification.md)
- [CI/CD 運用](ci-cd.md)
- [文書規約](document-conventions.md)
