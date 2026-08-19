<!-- doc-type: index -->

# <crate 名 / 文書群の名前>

[ドキュメント一覧](../README.md) / <この文書群の名前>

> **対象読者:** <この crate を触る人、その境界のレビュー担当者>

<この crate が所有する境界を 2〜3 文で要約する。何を所有し、何を他の crate へ委ねているかを書く。>

## 実装範囲と検証境界

<現在どこまで実装され、どこから未検証かを 1 段落で書く。`verified` は declared scope に限る。詳細は検証対応表と verification-status manifest へ送る。>

## 文書一覧

| 文書 | 対象ソース | 内容 |
|---|---|---|
| [<概念ページ>](.md) | [`crates/<crate>/src/<module>.rs`](../../crates/<crate>/src/<module>.rs) | <守っている不変条件> |
| [<契約ページ>](.md) | [`crates/<crate>/src/<module>.rs`](../../crates/<crate>/src/<module>.rs) | <実装者の義務> |
| [検証対応表](verification.md) | — | 検証済みと未検証の境界 |
| [検証ステータス manifest](../verification-status.md) | — | scope ごとの claim、gate、evidence、blocked 理由 |

## 関連

- [<対応する設計ページ>](../design/.md)
- [決定記録](../decisions/README.md)
- [用語集](../glossary.md)
- [多言語ハブ](../i18n/README.md)
