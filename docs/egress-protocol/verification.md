<!-- doc-type: verification -->

# 検証対応表

[egress-protocol](README.md) / 検証対応表

> **対象読者:** protocol を変更する実装者、レビュー担当者

この crate は純粋な状態機械の集まりで、socket も HTTP も credential も持たない。test も同じ性質で、すべて in-process の unit test である。`client` の stream 境界は `Cursor` を使う deterministic fixture で検査し、実 socket の動作はこの crate の検証結果に含めない。

## local test で確認したこと

| 対象 | 境界 |
|---|---|
| `frame` | 4 bytes prefix の read / write round trip、1 MiB 超の宣言を payload 確保前に拒否、truncated prefix、truncated payload、trailing bytes |
| `cbor` | v1 schema の round trip、非正規表現の拒否、payload hash と埋め込み payload の一致検査、item 数の不一致、未知の operation discriminant |
| `session` | `from_canonical_payload` による hash 導出、`accept_payload` の mismatch 前状態保持、sequence 0 からの受理、直前の次だけの受理、完全一致 retry の `Duplicate`、別 payload での request ID 再利用の拒否、restore 後の fresh session による旧 envelope 拒否、capacity / `u64::MAX` sequence の枯渇 |
| `budget` | 3 種の上限それぞれの枯渇、active な request ID の重複拒否、`complete` の超過時に予約が残ること |
| `operation` | 閉じた union の discriminant、`public_response_byte_limit` が `PublicFetch` のみ `Some` を返すこと |
| `response` | 型付き response の encode / decode、1 MiB の再検査、canonical chunk の wire round trip、chunk 境界、request / order / duplicate / missing / digest binding |
| `client` | bounded frame read/write、送信済み request identity の再利用拒否、response request binding、single response / chunk sequence の bounded reassembly |
| `fuzz` | `cbor_request_decode`、`frame_decode`、`response_decode`、`session_accept` の4 targetを用意し、各 decoder の allocation / ingress 境界を fuzz する。fuzz 探索の完了は unit test からは言えない |

budget の枯渇 assertion は fixture の値（`requests = 3`、`response_bytes = 100`、`concurrent = 2`）に合わせて書かれている。`60 + 40 = 100` のように、数値が計算に埋まっている。

## 実行コマンド

```bash
cargo fmt --all -- --check
cargo test --locked -p egress-protocol --all-targets
cargo clippy --locked -p egress-protocol --all-targets -- -D warnings
cargo check --manifest-path fuzz/Cargo.toml --bins --locked
cargo check --locked --workspace --all-targets
```

fuzz target の実行は `cargo-fuzz` と Linux 環境を要する。対象を個別に走らせるときは、次の4 targetを使う。

```bash
scripts/ci/run-fuzz.sh egress-protocol cbor_request_decode
scripts/ci/run-fuzz.sh egress-protocol frame_decode
scripts/ci/run-fuzz.sh egress-protocol response_decode
scripts/ci/run-fuzz.sh egress-protocol session_accept
```

`cargo check --manifest-path fuzz/Cargo.toml --bins --locked` は target の compile を確認するが、fuzz 探索の代わりにはならない。`cargo-fuzz`、root 権限、Linux の sanitizer 環境などが無い場合は、該当 target を実行せず未検証として扱う。

## 未検証の境界

この crate の外にあるもの。

| 対象 | どこが持つか |
|---|---|
| 実 `AF_VSOCK` の bind / accept / read / write | [transport 契約](../egress-broker/transport.md) |
| outcome の cache と retry の実際の経路 | [frame から adapter までの 1 本道](../egress-broker/dispatch.md) |
| 認可と外部副作用の線形化 | [Authorization guard](../authority-core/authorization-guard.md) |
| clock。この crate は時刻を持たない | Capability の[有効期間](../authority-core/validity-windows.md) |

この crate 自身の残る前提。

| 対象 | 何が未検証か |
|---|---|
| payload/hash binding | raw payload hash constructor と payload 無しの `accept` は crate-private。外部 consumer は `from_canonical_payload` と `accept_payload` だけを使い、production Broker も decoder が返した exact payload を admission 時に再検査する |
| restore 後の global no-reuse | fresh `BrokerSessionId` で pre-restore envelope を拒否することは local test で確認するが、過去の全 session ID を知る no-reuse ledger はこの crate の責務ではない |
| 並行性 | 状態機械はいずれも `&mut self` で単一 thread。複数 thread から使う場合の保証は無い |
| fuzz / property の完全性 | committed seed による bounded smoke と deterministic property はあるが、fuzz の探索完了自体は証明しない |

`CanonicalBrokerRequest::decode` は hash と embedded canonical payload を比較し、production decoder から返る envelope はこの検査を通過している。独自の ingress を追加するときは、payload と digest を別々に組み立てず、`BrokerEnvelope::from_canonical_payload` と `SessionReplayGuard::accept_payload` を使う。

## 関連

- [egress-protocol](README.md)
- [Canonical Broker CBOR](canonical-cbor.md)
- [Broker session envelope](session-envelopes.md)
- [session budget](session-budget.md)
- [Host Egress Broker](../egress-broker/README.md)
- [検証戦略](../design/verification.md)
- [用語集](../glossary.md)
