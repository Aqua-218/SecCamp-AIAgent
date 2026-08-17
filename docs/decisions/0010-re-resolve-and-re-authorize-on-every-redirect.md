<!-- doc-type: decision -->

# 0010. redirect のたびに DNS を再解決し、同じ authority で再認可する

[決定記録](README.md) / 0010

> **対象読者:** egress の実装者、redirect 経路をレビューする人

## Status

Accepted (2026-08-12)

## 背景と課題

HTTP の 3xx 応答は次の取得先を指す。取得先は元の request とは別の host、別の path になりうる。

判断材料。

- redirect は公開 web で日常的に使われる。`http` から `https`、末尾 slash の正規化、CDN の切り替え。無効にすると多くの host が取得できない。
- reqwest を含む HTTP client library は自動 redirect を持つ。有効にすると、client が内部で次の接続を行う。
- 認可は元の request に対して行っている。redirect 先は guest が指定した URL ではない。
- [ADR 0009](0009-reject-the-whole-dns-answer-on-any-non-public-address.md) の IP policy は DNS 応答を検査するが、それは解決した時点の話。

## 検討した選択肢

1. **library の自動 redirect に任せる** — hop 数だけ制限する
2. **redirect を無効にして guest に返す** — 3xx をそのまま応答として返し、guest が次を要求する
3. **自前で処理し、hop ごとに再正規化・再認可・再解決する**

### library の自動 redirect に任せる

reqwest の redirect policy で hop 上限だけ設定する。

- 利点: 実装がほぼ不要。library が Location の解析、相対 URL の解決、cookie の扱いまで面倒を見る。
- 欠点: 2 hop 目以降の接続が library の内部で起きる。IP policy の検査、authority との照合、canonical 化のいずれも通らない。
- **採用しなかった理由:** これは検査を全部飛ばす経路そのものだった。1 hop 目で `docs.example` を認可し、その応答が `Location: https://internal.corp/` を返せば、library は認可も IP 検査もなしにそこへ接続する。redirect を「取得の続き」として扱う library の設計と、「1 request = 1 認可」という Capability の設計が根本的に噛み合わない。

### redirect を無効にして guest に返す

3xx を型付き応答として guest へ返し、次の取得は guest が改めて要求する。

- 利点: 実装が最も単純で、認可の単位と取得の単位が完全に一致する。redirect 先は guest が明示的に要求するので、authority の照合が自然に効く。
- 欠点: guest 側が redirect を処理する必要がある。guest に URL の解析と相対解決を実装させることになり、その実装が Broker の canonical 化と食い違う余地が生まれる。加えて、redirect chain の各 hop が別々の request として budget と sequence を消費する。
- **採用しなかった理由:** guest 側に URL 処理を持たせると、正規化の規則が 2 箇所に分かれる。Broker が `CanonicalUrlPath` で受理する形と、guest が組み立てる形がずれたとき、redirect だけ通る path や、逆に正当な redirect が通らない状態ができる。正規化は 1 箇所に集約したかった。

## 決定

**自動 redirect と ambient proxy を無効にし、Broker が hop ごとに全検査をやり直す。**

各 hop で通す順序。

```text
Location を読む（8 KiB 上限）
  -> canonical な HTTPS origin / port 443 / userinfo なし / query なし / fragment なし を検査
  -> CanonicalHost と CanonicalUrlPath へ正規化
  -> 元の HttpFetchAuthority と照合
  -> DNS を再解決
  -> 応答全体を IP policy で検査
  -> 検証済み SocketAddr へ接続
```

authority 照合が DNS 再解決より前にある。authority 外への redirect では、connector を 2 回目に呼ばない。`redirect_outside_authority_is_rejected_before_second_connector_call` がこの順序を固定している。

上限は hop 数 5、`Location` 8 KiB、全体 60 秒。

## 結果

- redirect chain の全 hop が同じ authority の範囲に収まる必要がある。`docs.example` の authority で `cdn.example` へ redirect する host は取得できない。公開 web では珍しくない構成なので、実運用で当たる可能性がある。当たった場合は authority に host を追加するのであって、redirect の検査を緩めない。
- reqwest の設定 1 つ（redirect policy を default に戻す）で、この決定が全部無効になる。設定が正しいことを test で固定していない。
- DNS rebindingはfake resolver testに加え、privileged HTTPS gateが制御DNSのanswer切替、system resolver、redirect後の再解決、検査済みaddressへの接続を実socketで確認する。外部authoritative DNS／recursive cacheの全挙動までは対象外である。
- `Location` の検査規則は `CanonicalUrlPath` と同じ。percent encoding と path 正規化を含む形は拒否する。両者がずれると redirect だけ通る path ができるので、[ADR 0001](0001-limit-path-patterns-to-exact-and-prefix.md) の segment 比較と同じ規則を共有している。
- [ADR 0009](0009-reject-the-whole-dns-answer-on-any-non-public-address.md) と組で機能する。この決定だけでは、再解決した応答をどう検査するかが決まらない。

## 関連

- [公開 HTTPS policy](../egress-broker/network-policy.md)
- [HTTP fetch authority](../authority-core/http-fetch-authorities.md)
- [0009](0009-reject-the-whole-dns-answer-on-any-non-public-address.md)
- [ネットワークと外部副作用の設計](../design/network-egress.md)
- [用語集](../glossary.md)
