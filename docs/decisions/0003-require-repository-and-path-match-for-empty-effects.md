<!-- doc-type: decision -->

# 0003. 空 effect の子にも repository と path の一致を要求する

[決定記録](README.md) / 0003

> **対象読者:** 委譲判定を触る実装者、Lean の完全性定理を読む人

## Status

Accepted (2026-08-12)

## 背景と課題

`fileBodyBelow` は「child が parent より強くないか」を repository の等号、effect の部分集合、path の包含という 3 条件で判定する。この構造判定と、意味論上の包含（child が許す request 集合が parent の集合に含まれること）が一致することを Lean で証明したい。

ところが effect 集合が空の child では、両者がずれる。

```text
child.effects = ∅
→ child が match する request は 1 件も無い
→ 「child の全 request を parent も許す」は反例が作れないので真
```

空集合はどの集合の部分集合でもある。だから repository も path もまったく違う child であっても、意味論上の包含だけは成立してしまう。これは[空虚な真](../authority-core/proof-concepts.md#空集合と何でも正しい命題)である。

構造判定のほうは、effect が空でも repository の等号と path の包含を要求する。したがって「意味論上は包含が成り立つのに構造判定は `false`」という組が存在する。完全性が無条件には成り立たない。

判断材料。

- 健全性（判定が `true` なら意味論上の包含）は、空でも成立する。安全側の保証には穴が無い。
- 問題は逆向きだけで、しかも「本来通せる委譲を誤って拒否する」方向。安全性ではなく利便性の話。
- 委譲データの一貫性という観点では、effect が空でも repository と path が保存されているほうが望ましい。
- 定理の形が「無条件の同値」なのか「条件付きの同値」なのかで、後続の証明の書き方が変わる。

## 検討した選択肢

1. **構造判定を緩める** — effect が空なら repository と path の検査を飛ばす
2. **空 effect の authority を型で禁止する** — `FileEffects` の構築時に空を拒否する
3. **構造判定を保ち、完全性を条件付きで証明する**

### 構造判定を緩める

`child.effects` が空なら `fileBodyBelow` を無条件に `true` にする。

- 利点: 完全性が無条件に成り立ち、`fileBodyBelow_iff_matches_subset` という単純な定理が書ける。定理の形が綺麗になる。
- 欠点: 何も許可しない child が、まったく無関係な repository と path を持てるようになる。委譲 chain を辿ったとき、途中の node が別 repository を指していても判定は通る。
- **採用しなかった理由:** 委譲 chain のレビューが壊れる。`fileBodyBelow_trans` で多段委譲を辿るとき、各段の repository と path が保存されていることは、chain を目で追えることの前提になっている。空 effect の node がそこに穴を開けると、「この chain は最初から最後まで同じ repository の話か」を判定に頼れなくなる。定理の形の綺麗さと引き換えにするには大きすぎた。

### 空 effect の authority を型で禁止する

`FileEffects::from_effects` が空を受け取ったらエラーを返す。

- 利点: 問題そのものが消える。完全性が無条件に成り立ち、構造判定も緩めなくてよい。
- 欠点: 空 effect には正当な用途がある。revoke の途中経過、権限を段階的に組み立てる過程、attenuation の結果として何も残らなかった場合。これらを型で禁止すると、呼び出し側が `Option<FileEffects>` や別の空表現を持つことになり、空集合の扱いが型の外に押し出される。
- **採用しなかった理由:** 空集合を禁止しても消えるのは名前だけで、「何も許可しない状態」は依然として存在する。それを型の外で表現させると、集合演算の結果として空になるたびに呼び出し側が分岐することになり、`FileEffects` が集合として振る舞うという性質を失う。

## 決定

**構造判定は effect が空でも repository の等号と path の包含を要求する。完全性は effect 非空を仮定した定理として証明する。**

Lean 側の定理を 3 本に分ける。

| 定理 | 主張 | 仮定 |
|---|---|---|
| `fileBodyBelow_sound` | 判定が `true` なら request 集合が包含される | 無し |
| `fileBodyBelow_complete_of_effects_nonempty` | request 集合が包含されるなら判定が `true` | `child.effects` が非空 |
| `fileBodyBelow_iff_matches_subset_of_effects_nonempty` | 判定と包含が同値 | `child.effects` が非空 |

決め手は、ずれているのが安全側ではないこと。健全性は無条件に成り立つので、`fileBodyBelow = true` を受理した結果として権限が漏れることはない。失うのは「本来通せる委譲を通す」利便性だけで、しかもその委譲は何も許可しない child を作る操作である。

定理名と仮定に `effects_nonempty` を明記して、例外を隠さない。

## 結果

- 定理が 3 本になり、利用側は「無条件に使えるのは `sound` だけ」を意識する必要がある。
- 空 effect の child を作るとき、repository と path を親と揃えなければ委譲が通らない。呼び出し側にとっては余分な制約に見える。
- この非対称性は他の authority family にも同じ形で現れる。[HTTP fetch authority](../authority-core/http-fetch-authorities.md) の method 集合、[GitHub authority](../authority-core/github-authorities.md) の operation 集合が同様。
- 「安全のための追加条件」を構造判定に入れると完全性の形が変わる、という一般則が得られた。新しい条件を足すときは、それが意味論上の包含とどうずれるかを先に確認する。

## 関連

- [File authority](../authority-core/file-authorities.md)
- [Authority core で使う証明の考え方](../authority-core/proof-concepts.md)
- [0002](0002-split-file-permissions-into-ten-effects.md)
- [用語集](../glossary.md)
