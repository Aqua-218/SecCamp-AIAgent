# transport 契約

[Host Egress Broker](README.md) / transport 契約

> **対象読者:** guest/host transport 実装者、frame 境界のレビュー担当者

transport は `AF_VSOCK` stream と `egress-protocol` の length-prefixed frame を使う。`FramedTransport::read_frame` は最初に 4 bytes を読み、big-endian length が protocol の 1 MiB 上限以下であることを確認してから payload を確保する。stream の途中終了、I/O error、上限超過は拒否する。

`AfVsockListener` は listener と accept の薄い抽象であり、request の decode、adapter の選択、Capability 認可は担当しない。accept した stream は `FramedTransport` に渡し、connection owner は `BrokerDispatcher::dispatch_transport` で frame、canonical CBOR、session、budget、認可を通過させる。

一つの session について、`SessionReplayGuard` は sequence zero を受け付け、その後は直前の sequence の次だけを受け付ける。完全に同じ `(session, sequence, request ID, payload hash)` の retry は cache 済みの `BrokerResponse` を返し、adapter を再度呼ばない。別 payload で request ID を再利用する要求、sequence skip、別 session、bounded replay capacity の超過は拒否する。

response cache も replay capacity で上限を持つ。成功した型付き response と型付き拒否 outcome の両方を保持するため、cache に残る要求の retry 結果は再計算されない。

## 検証状態

module test は `Cursor` による frame の read/write round trip と、1 MiB を越える length prefix を payload read/allocation 前に拒否することを検証する。dispatcher test は exact retry の cache、non-canonical CBOR、session/request ID binding、認可拒否、budget 拒否を検証する。実 `AF_VSOCK` の bind/accept、guest との接続、response を wire へ再 encode する server loop は未検証である。

## 関連

- [Host Egress Broker](README.md)
- [GitHub 型付き adapter](github.md)
- [公開 HTTPS policy](network-policy.md)
- [検証対応表](verification.md)
