<!-- doc-type: decision -->

# 0009. DNS 応答に非 public address が 1 つでもあれば応答全体を拒否する

[決定記録](README.md) / 0009

> **対象読者:** egress の実装者、SSRF 対策をレビューする人

## Status

Accepted (2026-08-12)

## 背景と課題

Broker は guest の代わりに公開 HTTPS を取得する。取得先の host 名は [HTTP fetch authority](../authority-core/http-fetch-authorities.md) で認可済みだが、その名前が何を指すかは DNS が決める。

攻撃者が host 名を 1 つ authority に入れられれば、その名前の DNS 応答を通じて host の内部 network に到達できる。応答が複数 address を含む場合に、どれを使うか、どれを検査するかを決める必要があった。

判断材料。

- 通常の DNS 応答は複数 address を含む。round-robin、A と AAAA の併記、CDN の複数 edge。
- 応答の順序は resolver 側の都合で変わる。同じ問い合わせが毎回同じ順序を返すとは限らない。
- TTL 0 を返せば、再解決のたびに違う答えを返せる。
- 拒否した理由を返すと、guest がそれを DNS の観測手段として使える。

## 検討した選択肢

1. **接続に使う 1 つだけ検査する** — 選んだ address が public なら通す
2. **denied を除外して残りを使う** — public だけを残し、1 つでもあれば通す
3. **1 つでも denied があれば応答全体を拒否する**

### 接続に使う 1 つだけ検査する

先頭、あるいは選択した address だけを `is_denied` にかける。

- 利点: 実装が最も単純。検査の対象と接続先が一致するので、検査と接続の間にずれが生じない。
- 欠点: 選択の規則が resolver の応答順序に依存する。`[1.2.3.4, 169.254.169.254]` を返して先頭を選ばせ、次の解決で `[169.254.169.254, 1.2.3.4]` を返せば、2 回目は private が先頭に来る。
- **採用しなかった理由:** redirect のたびに DNS を再解決する設計なので、再解決の機会が複数ある。攻撃者が制御する権威 DNS が TTL 0 で答えを入れ替えれば、1 hop 目は public、2 hop 目は private を先頭にできる。「毎回検査している」ことは防御にならない。検査が通った回だけを使う設計そのものが、応答の入れ替えに弱い。

### denied を除外して残りを使う

応答から非 public を取り除き、残った public address へ接続する。

- 利点: 正当な混在（IPv6 が link-local で IPv4 が public、など）でも接続できる。可用性が高い。
- 欠点: 混在応答を「一部が壊れているだけ」として扱うことになる。実際には、公開 service の DNS が private address を返すこと自体が異常で、それを黙って修正して接続を続けるのは、攻撃の兆候を握り潰している。
- **採用しなかった理由:** 混在という状態そのものが signal である。正当な公開 host が `169.254.169.254` を A record に持つ理由は無い。除外して続行すると、攻撃を検出できたはずの場面で接続が成功する。可用性のために検出を捨てる取引になっていた。

## 決定

**`validate_dns_answer` は応答全体を検査し、1 つでも denied があれば `DeniedAnswer` を返す。**

```rust
if addresses.iter().copied().any(|address| self.is_denied(address)) {
    return Err(IpPolicyError::DeniedAnswer);
}
```

空応答も `EmptyAnswer` で拒否する。resolver が空を返したときに「制限が無い」と解釈する経路を作らない。

あわせて 2 つを決めた。

- IPv4-mapped / IPv4-compatible な IPv6 形式は、埋め込まれた IPv4 が public でも拒否する。`address.to_ipv4().is_some()` で判定する。層ごとに IPv4 とも IPv6 とも解釈されうる値を connector まで通すと、検査した address と接続する address が一致する保証を失う。
- `IpPolicyError` は address を持たない。`EmptyAnswer` と `DeniedAnswer` の 2 variant だけで、`Display` も範囲や IP を出さない。拒否理由に解決結果を含めると、guest が任意の名前を要求して host の内部 network を走査できる。

## 結果

- 正当な混在応答を持つ host には接続できない。IPv6 の link-local と IPv4 の public を併記する構成は、この Broker からは使えない。
- 組み込み deny range は追加のみで、削除できない。`IpPolicy::strict` が追加専用の API になっている。IPv4 15 範囲、IPv6 14 範囲を持つ。
- NAT64 (`64:ff9b::/96`)、6to4 (`2002::/16`)、Teredo (`2001::/32`) も落としている。いずれも IPv6 の中に IPv4 を埋め込む仕組みで、mapped 形式と同じ理由。
- 新しい special-purpose range が割り当てられたら、こちらで追随する必要がある。registry を自動追跡する仕組みは無い。
- この決定は host の network が別途分離されていることを前提にしていない。逆に、public address の先に内部 service がある構成は、この policy では守れない。
- [ADR 0010](0010-re-resolve-and-re-authorize-on-every-redirect.md) の redirect ごとの再解決と組で機能する。片方だけでは、初回だけ、あるいは順序だけを守ることになる。

## 関連

- [公開 HTTPS policy](../egress-broker/network-policy.md)
- [HTTP fetch authority](../authority-core/http-fetch-authorities.md)
- [0010](0010-re-resolve-and-re-authorize-on-every-redirect.md)
- [ネットワークと外部副作用の設計](../design/network-egress.md)
- [用語集](../glossary.md)
