<!-- doc-type: index -->

# 決定記録

[ドキュメント一覧](../README.md) / 決定記録

> **対象読者:** 設計判断の前提を再検討する人、新しい境界を設計する人、設計レビュー担当者

この文書群は、この repository の設計判断を 1 決定 1 ファイルで記録する。形式は [MADR](https://adr.github.io/madr/) に従い、採用した案だけでなく**却下した案とその理由**を残す。決定記録を導入した理由そのものは [0000](0000-record-architecture-decisions.md) にある。

実装が現在どうなっているかは各 crate の文書、なぜその構造にしたかは決定記録が正である。両者が食い違って見える場合、実装が変わって ADR が `Superseded` にされていない可能性を先に疑う。

## 運用

| 項目 | 規約 |
|---|---|
| ファイル名 | `NNNN-<英小文字とハイフンの slug>.md` |
| 連番 | 追記のみ。欠番を埋めない。削除しない |
| 骨格 | [`docs/templates/decision.md`](../templates/decision.md) をコピーする |
| Status | `Proposed` → `Accepted (YYYY-MM-DD)`。覆るときは `Superseded by` と後継 ADR へのリンク |
| 改訂 | 内容は書き換えない。新しい ADR を書いて元の Status を変える |
| 必須節 | `Status` / `背景と課題` / `検討した選択肢` / `決定` / `結果` / `関連` |

`検討した選択肢` に選択肢が 1 つしかない ADR は書かない。実際に他の案が無かった場合、それは決定ではなく制約であり、該当する実装ページの `正確な保証範囲` に書く。

## 決定一覧

| ADR | 決定 | Status |
|---|---|---|
| [0000](0000-record-architecture-decisions.md) | 設計判断を MADR 形式の決定記録として残す | Accepted |

## 遡って記録する対象

[0000](0000-record-architecture-decisions.md) の決定に従い、既存の主要な設計判断を遡って ADR 化する。対象は次のとおりで、上から順に書く。当時の議論記録が無いため、実装・コメント・既存文書から再構成した内容になる。

| 予定番号 | 決定 | 主な出典 |
|---|---|---|
| 0001 | `PathPattern` を `Exact` と `Prefix` の 2 種類に限定する | [パスモデル](../authority-core/paths.md) |
| 0002 | file の権限を単一の read/write ではなく 10 種の `FileEffect` に分割する | [File authority](../authority-core/file-authorities.md) |
| 0003 | 空 effect の子に対しても構造判定で repository と path の一致を要求する | [File authority](../authority-core/file-authorities.md) |
| 0004 | 認可判定を Rust と Lean で二重に実装し、共通 corpus で突き合わせる | [検証とテスト](../authority-core/verification.md) |
| 0005 | object の identity を path から分離し `ObjectId` で持つ | [共有 namespace registry](../capfs/namespace-registry.md) |
| 0006 | `ObjectId`、`nodeid`、capability ID を再利用しない | [mount ごとの node table](../capfs/node-tables.md) |
| 0007 | FUSE adapter を Direct-I/O にし、page cache に revoke を迂回させない | [Direct-I/O FUSE adapter](../capfs/read-only-fuse.md) |
| 0008 | Broker は型付きの閉じた操作だけを公開し、生 URL と任意 HTTP メソッドを持たない | [Host Egress Broker](../egress-broker/README.md) |
| 0009 | DNS 応答に非 public address が 1 つでも含まれれば応答全体を拒否する | [公開 HTTPS policy](../egress-broker/network-policy.md) |
| 0010 | redirect ごとに DNS を再解決し、同じ HTTP authority で再検査する | [公開 HTTPS policy](../egress-broker/network-policy.md) |
| 0011 | `PublishBranch` に expected-old object の plan を必須とし `force: false` で更新する | [GitHub 型付き adapter](../egress-broker/github.md) |
| 0012 | wire 境界を bounded frame とし、payload 確保前に長さを検査する | [transport 契約](../egress-broker/transport.md) |
| 0013 | caller identity を受理済み connection から解決し、wire 上の claim を認可に使わない | [Supervisor adapter](../supervisor/README.md) |
| 0014 | VM kill が失敗した場合に workspace isolation を実行しない | [Session orchestrator](../session-orchestrator/README.md) |
| 0015 | production host の identity ledger を永続化し、restart をまたいで非再利用にする | [Session orchestrator](../session-orchestrator/README.md) |
| 0016 | rollback 不可能な isolation step の失敗後は child を再利用せず終了させる | [13 step の固定順序と rollback](../runtime-isolation/apply-order.md) |

この表は着手前の一覧であり、書き終えた ADR は上の決定一覧へ移す。実際に書く段階で、複数の項目が 1 つの決定にまとまる場合や、逆に分割が必要になる場合がある。

## 関連

- [文書規約](../document-conventions.md)
- [設計書](../design/README.md)
- [ドキュメント一覧](../README.md)
- [用語集](../glossary.md)
