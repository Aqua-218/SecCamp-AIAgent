<!-- doc-type: decision -->

# 0001. path pattern を `Exact` と `Prefix` の 2 種類に限定する

[決定記録](README.md) / 0001

> **対象読者:** path 判定を触る実装者、権限の表現力が足りないと感じた人

## Status

Accepted (2026-08-12)

## 背景と課題

file authority は「どの path 範囲に操作してよいか」を持つ。この範囲をどう表すかで、判定の実装と証明の難しさが決まる。

判断材料は 4 つあった。

- 委譲判定は「child の範囲が parent の範囲に含まれるか」を計算する。pattern が複雑になるほど、この包含判定が難しくなる。
- Lean 側で `pathBelow_sound` を証明する必要がある。構造判定が集合包含と一致することを示せなければ、委譲の安全性が主張できない。
- 表現力が足りないと、利用側が「広めの権限」で妥協する。最小権限の粒度は pattern の表現力で決まる。
- Rust と Lean の 2 実装が同じ判定をする必要がある。実装が複雑なほど、両者がずれる余地が増える。

## 検討した選択肢

1. **glob pattern** — `src/**/*.rs` のような一般的な wildcard
2. **正規表現** — 任意の path 集合を表せる
3. **`Exact` と `Prefix` の 2 種類** — 1 point か、1 subtree か

### glob pattern

`*`、`**`、`?`、文字クラスを持つ。ほとんどの開発者が読める。

- 利点: 表現力が高く、`src/**/*.rs` のような「特定拡張子だけ」を書ける。既存 tool と表記が揃う。
- 欠点: 2 つの glob の包含判定が非自明になる。`src/**/*.rs` は `src/**` に含まれるが、`src/*/x.rs` と `src/a/**` の関係は一目で決まらない。一般には包含判定が計算量的に重く、実装ごとに `**` の意味が違う。
- **採用しなかった理由:** 包含判定を Lean で証明できる形に落とせなかった。`fileBodyBelow_sound` は「構造判定が `true` なら child の全 request を parent も許す」を示す定理で、glob どうしの包含を構造判定として書くと、証明が pattern の構文解析に依存する。委譲の安全性がこの 1 本の定理に集約されている以上、そこを証明できない表現は選べない。

### 正規表現

任意の path 集合を表せる。

- 利点: 表現力に不足がない。
- 欠点: 2 つの正規表現の包含判定は決定可能だが、オートマトンの構成を伴う。実装が重く、Lean 側で同じものを書いて一致を示すのは現実的でない。加えて、catastrophic backtracking を持つ実装では判定自体が DoS 経路になる。
- **採用しなかった理由:** 認可判定は全 file 操作の hot path にある。包含判定に非自明な計算量を持ち込むと、権限そのものが資源枯渇の入口になる。表現力の上限を上げる代わりに、判定の予測可能性を失う取引になっていた。

## 決定

**`PathPattern` を `Exact(CanonicalPath)` と `Prefix(CanonicalPath)` の 2 variant に限定する。**

包含判定は次の 3 規則だけで決まる。

```text
Exact(a)  ⊆ Exact(b)   ⟺  a = b
Exact(a)  ⊆ Prefix(b)  ⟺  b は a の prefix
Prefix(a) ⊆ Prefix(b)  ⟺  b は a の prefix
Prefix(a) ⊆ Exact(b)   ⟺  常に false（a = b でも Prefix は広い）
```

比較は segment の列で行う。文字列の前方一致ではないので、`Prefix(src)` は `src/main.rs` を含み `src-old/x` を含まない。

決め手は、この 4 規則が Lean で直接証明できる形をしていること。`pathBelow_sound` と `pathBelow_trans` が、pattern の構文解析ではなく segment 列の prefix 関係だけで示せる。glob と正規表現はどちらもこの性質を持たない。

## 結果

- 「`src` 以下の `.rs` だけ」のような拡張子単位の権限は表せない。利用側は `Prefix(src)` を渡すか、対象を `Exact` で列挙する。粒度が足りない場面が出るのは受け入れたコスト。
- `Prefix(a) ⊆ Exact(b)` が常に `false` になるのは直感に反する。`a = b` でも `Prefix` は subtree を含むので広い。ここは実装とレビューで踏みやすい。
- [パスモデル](../authority-core/paths.md)、[File authority](../authority-core/file-authorities.md)、[HTTP fetch authority](../authority-core/http-fetch-authorities.md)、[GitHub authority](../authority-core/github-authorities.md) の 4 つが、同じ 2 variant の形を共有している。URL path と branch 名も同じ規則で判定する。
- 表現力が足りないという判断になった場合、変えるべきは pattern の種類を増やすことではなく、拡張子や属性を独立した軸として authority に足すこと。この決定を覆す前に、[File authority](../authority-core/file-authorities.md) の 3 軸構造を 4 軸にする案を先に検討する。

## 関連

- [パスモデル](../authority-core/paths.md)
- [File authority](../authority-core/file-authorities.md)
- [Authority core で使う証明の考え方](../authority-core/proof-concepts.md)
- [用語集](../glossary.md)
