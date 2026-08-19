<!-- doc-type: exempt -->

# 検証ステータス manifest

[ドキュメント一覧](README.md) / 検証ステータス manifest

> **対象読者:** CI の gate を保守する実装者、検証結果をレビューする担当者

[`docs/verification-status.yml`](verification-status.yml) は、検証の主張を実行環境ごとに分けて記録する機械可読 manifest である。`verified` は、宣言した prerequisite が満たされた環境で、`gate.result: required` の command が成功し、その scope の evidence を得た意味だけを持つ。隣接する privileged、KVM、external の境界まで検証したことを意味しない。`unverified` は境界が既知だが証拠が足りない状態、`blocked` は prerequisite または外部 owner が使えず実行できない状態である。後者の2つを削除して green にすることは禁止する。
この manifest は検証結果の台帳であって、CI 実行ログや成功した test の代替ではない。manifest 自体には gate の実行時刻、CI run ID、artifact の保存場所を持たせていないため、`verified` への変更は同じ変更で取得した scope 固有の CI artifact または operator 証跡と照合する。pipeline の gate 数と claim 数も一致させない。前者は実行する検査の topology、後者は実装境界について公開する主張の集合である。

## スキーマ

| field | 規約 |
|---|---|
| `schema` | 固定値 `verification-status/v1` |
| `claims[].id` | manifest 内で一意な安定 ID |
| `claims[].component` | 対象 crate または境界 |
| `claims[].scope` | `hosted`、`privileged`、`kvm`、`external` のいずれか |
| `claims[].status` | `verified`、`unverified`、または `blocked` |
| `claims[].verification_page` | 対象境界を説明する repository-relative な `verification.md` |
| `claims[].prerequisites` | 1 件以上の `{id, description, check}`。空配列で「前提なし」と省略しない |
| `claims[].gate` | `{id, result, on_prerequisite_failure, commands}`。`result` は `required`、前提不足時は `fail` 固定 |
| `claims[].evidence.commands` | 証跡を再現するコマンド。checker は実行しない |
| `claims[].evidence.sources` | repository-relative な実装パス |
| `claims[].evidence.tests` | repository-relative な test パス |
| `claims[].residual_reasons` | `unverified` / `blocked` では必須。`verified` では空配列 |

`sources` と `tests` は存在するパスでなければならず、絶対パスや `..` による runner 外部参照は許さない。コマンドの存在だけでは検証済みにならないため、status の変更は実際にその scope の証跡を取得した変更と同時に行う。

`scope` は検査の対象環境を表し、`hosted` の成功を `privileged`、`kvm`、`external` の evidence と読み替えない。`verified` は named gate が成功した境界だけを示し、未記載の syscall、scheduler interleaving、hardware、provider 操作を含めない。

## checker の責務

[`scripts/ci/check-doc-consistency.sh`](../scripts/ci/check-doc-consistency.sh) は、CI に固定された yq の版を使って YAML を読み、次を fail closed で検査する。

- schema、status、scope、claim ID の一意性
- verification page、prerequisite、required gate の欠落・曖昧さ
- evidence の command / source / test の非空性と repository 内パス
- command が単一行の argv 形であり、shell 演算子や成功を偽装する `|| true` を含まないこと
- `verified` の直接 cargo command が `--ignored`、`--no-run`、`--list`、`--skip` などを使わないこと。実 KVM の ignored test は、前提不足を exit 2 にしている repository wrapper を gate に登録する。
- repository wrapper は `set -euo pipefail` を使い、`scripts/ci/verify-*` には非 zero の prerequisite/failure exit path があること。wrapper 内で opt-in test を呼ぶ場合も、前提不足を成功扱いしない。
- `unverified` / `blocked` claim の residual reason と `verified` claim の空 reason

この checker は command を実行しない。実行結果を記録する gate、root / cgroup / KVM が必要な gate、外部サービスの利用可否はそれぞれの scope の実行 job が担う。

## 変更時の確認

```bash
scripts/ci/check-doc-consistency.sh
scripts/ci/check-doc-consistency.sh ci/fixtures/verification-status-missing-evidence.yml
scripts/ci/check-verification-traceability.sh
scripts/ci/run.sh docs-policy
```

2 つ目は負の fixture であり、意図的に失敗する。新しい claim を追加するときは、status を先に `unverified` とし、検証できていない理由を具体的に書く。前提が外部 credential や別 runner でまだ得られない場合は `blocked` とし、前提と復旧条件を `prerequisites` と `residual_reasons` に残す。`verified` への変更は、同じ変更で evidence と required gate を追加し、wrapper を使う場合は前提不足を skip ではなく exit 2 にする。
claim を降格する場合も理由を残す。runner の一時的な unavailable、credential の失効、gate の回帰を `blocked` または `unverified` のまま記録し、証跡が無いことだけを理由に claim を削除しない。status の更新後は、該当 verification page、`docs/README.md`、完了台帳の記述が同じ scope を指していることを確認する。

## 関連

- [検証戦略](design/verification.md)
- [CI/CD 運用](ci-cd.md)
- [文書規約](document-conventions.md)
- [完了台帳](hardening/2026-08-18-completion-ledger.md)
