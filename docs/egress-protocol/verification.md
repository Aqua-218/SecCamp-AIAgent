<!-- doc-type: verification -->

# 検証対応表

[egress-protocol](README.md) / 検証対応表

> **対象読者:** protocol を変更する実装者、レビュー担当者

この crate は純粋な状態機械の集まりで、socket も HTTP も credential も持たない。test も同じ性質で、すべて in-process の unit test である。**外部依存が無いので test double も無い。**

## local test で確認したこと

| 対象 | 境界 |
|---|---|
| `frame` | 4 bytes prefix の read / write round trip、1 MiB 超の宣言を payload 確保前に拒否、truncated prefix、truncated payload、trailing bytes |
| `cbor` | v1 schema の round trip、非正規表現の拒否、payload hash と埋め込み payload の一致検査、item 数の不一致、未知の operation discriminant |
| `session` | sequence 0 からの受理、直前の次だけの受理、完全一致 retry の `Duplicate`、別 payload での request ID 再利用の拒否、別 session の拒否、capacity 超過の拒否 |
| `budget` | 3 種の上限それぞれの枯渇、active な request ID の重複拒否、`complete` の超過時に予約が残ること |
| `operation` | 閉じた union の discriminant、`public_response_byte_limit` が `PublicFetch` のみ `Some` を返すこと |
| `response` | 型付き response の encode / decode、1 MiB の再検査 |

budget の枯渇 assertion は fixture の値（`requests = 3`、`response_bytes = 100`、`concurrent = 2`）に合わせて書かれている。`60 + 40 = 100` のように、数値が計算に埋まっている。

## 実行コマンド

```bash
cargo fmt --manifest-path crates/egress-protocol/Cargo.toml -- --check
cargo test --manifest-path crates/egress-protocol/Cargo.toml
cargo clippy --manifest-path crates/egress-protocol/Cargo.toml --all-targets -- -D warnings
```

## 未検証の境界

この crate の外にあるもの。

| 対象 | どこが持つか |
|---|---|
| 実 `AF_VSOCK` の bind / accept / read / write | [transport 契約](../egress-broker/transport.md) |
| outcome の cache と retry の実際の経路 | [frame から adapter までの 1 本道](../egress-broker/dispatch.md) |
| 認可と外部副作用の線形化 | [Authorization guard](../authority-core/authorization-guard.md) |
| clock。この crate は時刻を持たない | Capability の[有効期間](../authority-core/validity-windows.md) |

この crate 自身の未検証。

| 対象 | 何が未検証か |
|---|---|
| `SessionReplayGuard` の capacity 枯渇 | 上限に達した後、session が永久に固着することを確認する test が無い。`RequestCapacityExhausted` を返すことは確認しているが、そこから回復できないことは test で固定していない |
| restore 後の session ID | 新しい `BrokerSessionId` を取ることをこの crate は強制していない。古い ID を再利用したときに全 sequence が replay に開くことは、test ではなく doc comment にしか書かれていない |
| payload hash の binding | `SessionReplayGuard` は hash が payload を hash したものか検証しない。binding は `cbor.rs` の 1 箇所だけ。**その検査を外しても、この crate の test は落ちない可能性がある** |
| `SequenceExhausted` | `u64::MAX` まで sequence を進める test は無い |
| fuzz / property test | どの module にも無い。境界値は選んだ具体例だけ |
| 並行性 | 状態機械はいずれも `&mut self` で単一 thread。複数 thread から使う場合の保証は無い |

`BrokerEnvelope::new` が `pub const` で任意の 32 bytes を受けることに注意する。`CanonicalBrokerRequest::decode` の外で envelope を組み立てる新しい経路を書くときは、payload hash の検査を複製する必要がある。**2 つの file を必ず一緒に直す。**

## 関連

- [egress-protocol](README.md)
- [Canonical Broker CBOR](canonical-cbor.md)
- [Broker session envelope](session-envelopes.md)
- [session budget](session-budget.md)
- [Host Egress Broker](../egress-broker/README.md)
- [検証戦略](../design/verification.md)
- [用語集](../glossary.md)
