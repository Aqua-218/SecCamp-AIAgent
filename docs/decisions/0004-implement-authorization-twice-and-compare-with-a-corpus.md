<!-- doc-type: decision -->

# 0004. 認可判定を Rust と Lean で二重に実装し、共通 corpus で突き合わせる

[決定記録](README.md) / 0004

> **対象読者:** Authority core を触る実装者、検証範囲を評価する人

## Status

Accepted (2026-08-12)

## 背景と課題

委譲判定が誤ると、子が親より強い権限を得る。これはこの基盤で最も影響の大きい欠陥で、test で見つけられる保証が無い。判定は path、effect 集合、時刻窓、host、branch など複数軸の組み合わせで、入力空間が大きい。

判断材料。

- 判定は純粋関数で書ける。副作用も I/O も無く、証明の対象として素直な形をしている。
- 実行するのは Rust。production の hot path にあり、allocation を避けたい。
- 証明が欲しいのは「判定が通ったら権限が増えない」という一般命題で、具体例の集合ではない。
- 証明した対象と実行する対象が違えば、その差が保証の穴になる。

## 検討した選択肢

1. **Rust だけで書き、property test で担保する** — 生成した入力で不変条件を確認する
2. **Rust の検証 tool で直接証明する** — Creusot や Prusti で Rust コードに contract を書く
3. **Lean からコードを抽出する** — 証明済み定義から実行コードを生成する
4. **Rust と Lean で二重に実装し、共通 corpus で突き合わせる**

### Rust だけで書き、property test で担保する

`proptest` などで入力を生成し、健全性・推移律を性質として確認する。

- 利点: 実装が 1 つで済む。ずれが原理的に発生しない。CI の実行時間も短い。
- 欠点: 生成器が到達しない領域は確認できない。空集合、境界値、複数条件が同時に効く組み合わせは、生成器の設計次第で出ない。
- **採用しなかった理由:** 欲しいのが一般命題だった。「1 万件の生成入力で反例が出なかった」と「全入力で成り立つ」の差は、権限漏えいという故障の性質からして埋められない。property test は今も併用しているが、それだけを根拠にはしない。

### Rust の検証 tool で直接証明する

Creusot や Prusti で Rust コードに事前条件・事後条件を書き、実行するコードそのものを証明する。

- 利点: 証明した対象と実行する対象が同一になる。この決定が抱える最大の弱点が消える。
- 欠点: tool の成熟度と、証明できる Rust の範囲に制約がある。所有権や借用と絡む部分で証明が通らないことがあり、その回避のために実装を歪めることになる。tool 自体の信頼性も評価対象に加わる。
- **採用しなかった理由:** 実装の自由度を先に失うと判断した。`FileEffects` の private な `u16` bitset のように、allocation を避けるための表現を証明のために変える必要が出る。将来 tool の成熟度が変われば、この決定を見直す価値がある。**この選択肢は今も最有力の代替である。**

### Lean からコードを抽出する

Lean の定義から実行コードを生成し、それを Rust から呼ぶ。

- 利点: 証明した定義がそのまま動く。翻訳のずれが無い。
- 欠点: 生成されたコードの性能と表現が Lean 側の定義に縛られる。`FileEffect → Bool` という membership 関数として集合を持つ Lean の表現は、証明には向くが実行には向かない。抽出の正しさ自体も信頼の対象になる。
- **採用しなかった理由:** production の hot path に、性能特性を制御できないコードを置きたくなかった。認可判定は全 file 操作で走る。

## 決定

**同じ判定を Rust と Lean で別々に実装し、150 件の共通 corpus を両方へ流して結果を突き合わせる。**

役割を分ける。

| 実装 | 役割 |
|---|---|
| Rust | production で実行する。allocation なしの bitset、`u16` mask、segment 列の比較 |
| Lean | 一般命題を証明する。健全性、完全性、反射律、推移律 |
| 共通 corpus | 選んだ境界入力を両方へ流し、期待値と両者の出力を比較する |

corpus に入れるのは、canonical path の受理・拒否、`Exact` / `Prefix` matching、`pathBelow` の 4 組み合わせ、effect subset、file matching、file body containment、時刻窓の端点、Capability matching と 1 軸ずつ壊した `weakerThan`、HTTP と GitHub の各軸。positive case と、各条件を 1 つだけ壊した negative case を対にする。

## 結果

- **Lean の定理は Rust の machine code を証明していない。** これが最大の制約で、各ページの「正確な保証範囲」に明記している。corpus に無い入力で両者がずれる可能性は残る。
- 判定を変えるとき、Rust、Lean、corpus の 3 箇所を同時に直す必要がある。片方だけ変えると差分テストが落ちるので、忘れることはない。この検出こそが corpus の主目的で、副次的な効果ではない。
- Lean 側は実行効率を考えなくてよい。`allFileEffects` の有限列挙のように、証明に向いた表現を選べる。
- CI に Lean toolchain が必要になった。`scripts/ci/install-lean.sh` と `scripts/ci/run.sh differential` が該当する。ビルド時間と依存が増えた。
- corpus は有限であり、schema v1 は variant ごとの専用 row を追加する形で拡張する。新しい authority variant を足すときは、両 runner、typed dispatch、corpus、Lean 定理を同じ変更で拡張する。
- corpus は revoke を検証しない。逐次 revoke と祖先失効は stateful test、effect commit と revoke の同期境界は loom が扱う。

## 関連

- [検証とテスト](../authority-core/verification.md)
- [Authority core で使う証明の考え方](../authority-core/proof-concepts.md)
- [File authority](../authority-core/file-authorities.md)
- [検証戦略](../design/verification.md)
- [用語集](../glossary.md)
