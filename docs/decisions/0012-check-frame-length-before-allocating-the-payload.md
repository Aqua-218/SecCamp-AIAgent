<!-- doc-type: decision -->

# 0012. frame 長を payload 確保の前に検査する

[決定記録](README.md) / 0012

> **対象読者:** wire 境界を実装する人、資源枯渇の経路をレビューする人

## Status

Accepted (2026-08-12)

## 背景と課題

guest と host は `AF_VSOCK` stream で繋がる。stream には境界が無いので、message の区切りを自分で決める必要がある。

判断材料。

- guest は信用しない。stream に何を書いてもよい前提で読む。
- host 側は複数 session を同時に扱う。1 session が host の memory を食い尽くすと、他の session が巻き込まれる。
- request の内容は canonical CBOR で、その最大サイズは操作の種類から見積もれる。
- 上限を超える要求は、正当な利用では発生しない。

## 検討した選択肢

1. **区切り文字で分ける** — 改行や NUL で message を区切る
2. **length prefix を読んで、その長さの buffer を確保してから検証する**
3. **length prefix を読み、確保の前に上限を検査する**

### 区切り文字で分ける

改行区切りにして、1 行を 1 message とする。

- 利点: length を書く必要がなく、実装が単純。text protocol として読みやすい。
- 欠点: payload に区切り文字が現れる場合を escape する必要がある。escape の実装が送信側と受信側で食い違うと、message の境界がずれる。加えて、区切りが来るまで読み続けるので、上限を先に知る手段が無い。
- **採用しなかった理由:** 上限を事前に知れないのが決定的だった。区切りが来ないまま無限に書き込まれると、受信側は buffer を伸ばし続ける。上限を設けるにしても「読みながら数える」形になり、超過を検出した時点で既にその分の memory を使っている。CBOR は binary なので、escape の必要性も加わる。

### length prefix を読んで buffer を確保してから検証する

4 bytes を読み、その長さの `Vec` を確保し、読み終えてから上限を検査する。

- 利点: 実装の流れが自然。読み込みと検証が分かれる。
- 欠点: 検証の前に確保が済んでいる。guest が `0xFFFFFFFF` を書けば、host は 4 GiB の確保を試みる。
- **採用しなかった理由:** これが攻撃そのものになる。guest が 4 bytes 書くだけで host に任意サイズの allocation をさせられる。接続を張り直して繰り返せば、確保と解放だけで host を止められる。「後で検証するから安全」は、確保のコストを勘定に入れていない。

## 決定

**`ValidatedFrameLength::from_network_prefix` が上限を検査し、それを通った長さだけで payload を確保する。**

```text
4 bytes の big-endian prefix を読む
  -> ValidatedFrameLength::from_network_prefix で 1 MiB 以下か検査
  -> 通ったら、その長さで確保して読む
```

上限は 1 MiB。`FrameError::FrameTooLarge { length }` の `length` は untrusted な宣言値であって、確保した量ではない。

`ControlFrame::decode_complete` は trailing bytes を許さない。宣言した長さと実際の payload 長が一致し、その後に何も無いことを要求する。余りを黙って捨てると、1 frame に 2 つ目の message を紛れ込ませられる。

`FramedTransport` は frame の境界だけを扱う。decode も認可もしない。層を分けることで、上限の検査がどの経路でも同じ 1 箇所を通る。

## 結果

- 1 MiB を超える要求は送れない。canonical CBOR の request がこれを超える設計になったら、上限ではなく request の分割を検討する。
- 上限は frame 単位である。接続あたりの frame 数や帯域は制限していない。1 MiB 未満の frame を大量に送る flooding はこの層では止まらない。session budget が上位で効くが、それは operation の単位であって frame の単位ではない。
- 型が `ValidatedFrameLength` になっているので、検証を通していない長さで確保する経路を書こうとすると型が合わない。
- `FrameError` は `TruncatedPrefix` と `TruncatedPayload { expected, actual }` も持つ。どちらも同じ入力で必ず再現するので、retry しない。`TransportError::Io` だけが接続状態に依存する。
- 実 `AF_VSOCK` の bind / accept は未検証。module test は `Cursor` 上で frame の往復と、1 MiB 超の prefix を payload 読み込み前に拒否することを確認している。

## 関連

- [transport 契約](../egress-broker/transport.md)
- [Canonical Broker CBOR](../egress-protocol/canonical-cbor.md)
- [Broker session envelope](../egress-protocol/session-envelopes.md)
- [用語集](../glossary.md)
