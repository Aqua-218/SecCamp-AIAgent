# Canonical Broker CBOR

[ドキュメント一覧](../README.md) / Canonical Broker CBOR

このページは [`crates/egress-protocol/src/cbor.rs`](../../crates/egress-protocol/src/cbor.rs) が担当する、Host Egress Broker の control payload schema を説明する。ここでいう canonical は「意味が同じなら同じ bytes」という都合のよい約束ではない。decoder 自身が、v1 schema の唯一の表現以外を拒否するという意味である。

この層は vsock を開かず、HTTP / GitHub API も呼ばない。既に 1 MiB 以下と検証済みの frame payload を、replay guard と typed dispatcher に渡せる値へ復元する境界である。

```mermaid
flowchart LR
    frame["bounded ControlFrame"] --> cbor["CanonicalBrokerRequest::decode"]
    cbor --> hash{"payload hash\nmatches?"}
    hash -->|"yes"| operation["closed BrokerOperation"]
    hash -->|"no"| reject["reject before replay / dispatch"]
    operation --> guard["SessionReplayGuard"]
    guard --> budget["SessionBudget"]
    budget --> adapter["future provider adapter"]
```

## v1 request schema

外側の CBOR item は、必ず次の6要素 array である。`payload` は embedded CBOR item ではなく、その canonical bytes を入れた byte string である。これにより、payload 自身を hash の対象にしながら hash を含む outer envelope を作れる。

| index | CBOR value | 意味 |
|---:|---|---|
| 0 | unsigned `1` | protocol version |
| 1 | 16-byte byte string | host-issued `BrokerSessionId` |
| 2 | unsigned integer | session 内で厳密に増える sequence |
| 3 | 16-byte byte string | caller-issued `BrokerRequestId` |
| 4 | 32-byte byte string | `SHA-256(payload)` |
| 5 | byte string | 下表の canonical operation CBOR bytes |

`CanonicalBrokerRequest::decode` は、index 4 の値と index 5 の bytes から導出した hash が違えば reject する。成功時に得られる `BrokerEnvelope` は、この同じ hash を持つ。つまり replay guard が比較する identity と、実際に decode した operation の bytes がずれない。

payload の唯一の item は、次のどちらかである。

| operation | payload array | code 以外の自由な副作用入口 |
|---|---|---|
| `PublicFetch` | `[0, method, host, path, max_response_bytes]` | ない。`method` は `0 = GET` または `1 = HEAD`、host / path は authority-core の canonical constructor を通る |
| `GitHub` | `[1, installation, repository, operation, base, head]` | ない。`operation` は `0 = PublishBranch` または `1 = CreatePullRequest`、branch は安全な shorthand として再検証する |

installation と repository は host が割り当てる opaque identity なので、この schema は文字列の意味を解釈しない。host / URL path / branch のように authority comparison に直接使う値だけを authority-core の validator で再構築する。

## reject する表現

この decoder は汎用 CBOR parser ではない。次を全て reject する。

- array の要素数違い、unknown version、unknown operation family / method / GitHub operation。
- map、tag、float、boolean、null、negative integer、意図しない CBOR major type。
- indefinite-length item、reserved additional information、最短でない integer / length header。
- UTF-8 でない text、16 / 32 byte でない identity / hash、canonical host / URL path / branch に戻せない文字列。
- inner payload または outer request の trailing bytes、payload hash mismatch、1 MiB 超の control payload。

したがって、同じ operation を別の CBOR integer width や indefinite encoding で表して、同じ `BrokerRequestId` に別の bytes を結び付けることはできない。

## 実装境界

`cbor.rs` は wire bytes を typed request にするまでを担当する。成功しただけでは、Capability を持つ、replay-safe、budget 内、または network policy を満たすことを意味しない。

| まだ別途必要なもの | 担当すべき層 |
|---|---|
| vsock listener、handshake、connection close | transport |
| Capability authorization と revoke linearization | Broker adapter + `CapabilityKernel` |
| retry outcome cache と `SessionReplayGuard` の接続 | session dispatcher |
| request count / byte / concurrency reservation | session dispatcher + `SessionBudget` |
| redirect、DNS rebinding、public IP、TLS、response streaming | public fetch adapter |
| expected-old OID、provider response、host-only credential | GitHub adapter |

この分離により、CBOR decoder へ network client や credential を置かず、transport の自由な bytes が adapter の自由な認証付き HTTP call へ変換される経路を作らない。

## 関連

- [Broker session envelope](session-envelopes.md)
- [ネットワークと外部副作用](../design/network-egress.md)
- [HTTP fetch authority](../authority-core/http-fetch-authorities.md)
- [GitHub authority](../authority-core/github-authorities.md)
