<!-- doc-type: verification -->

# 検証対応表

[Host Egress Broker](README.md) / 検証対応表

> **対象読者:** 実装者、レビュー担当者、統合 test の実行担当者

## local test で確認したこと

| 要求 | test の焦点 | 検証の種類 |
| --- | --- | --- |
| bounded frame | 上限超過を payload read/allocation 前に拒否する | `FramedTransport` module test |
| canonical typed dispatch | public request と exact retry の response cache | dispatcher module test、fake adapter |
| session binding | wrong session と request-ID rebinding を adapter I/O 前に拒否する | dispatcher module test |
| authorization | capability mismatch を拒否として cache し、adapter を呼ばない | dispatcher module test、`CapabilityKernel` |
| private IP と DNS rebinding | private/mixed answer を拒否し、redirect ごとに再解決する | fake resolver/connector |
| redirect 再検査 | path、scheme、userinfo、query、fragment が不正な redirect を拒否する | fake connector |
| response cap | streaming 中に上限超過を拒否し、`HEAD` は本文を読まない | fake response stream |
| GitHub 事前条件 | expected-old plan がなければ provider を呼ばずに拒否する | fake provider |
| provider error | rate-limit metadata は型付きで保持し、生 body は outcome に出さない | fake provider |

## 実行コマンド

repository root から次を実行する。

```bash
cargo fmt --manifest-path crates/egress-broker/Cargo.toml -- --check
cargo test --manifest-path crates/egress-broker/Cargo.toml
cargo clippy --manifest-path crates/egress-broker/Cargo.toml --all-targets -- -D warnings
```

## 未検証の境界

この crate の local test は外部ネットワークへ接続せず、実 secret を読み込まず、`AF_VSOCK` を bind しない。したがって、次はこの test 結果からは言えない。

- 実 `AF_VSOCK` の guest/host 接続と長時間 stream
- 実 DNS、DNS rebinding、外部 HTTPS の certificate/SNI と redirect
- 実 GitHub API、`EGRESS_GITHUB_TOKEN`、provider 側の ref race
- guest supervisor から Broker までの end-to-end 統合

これらを実施していない段階で、Host Egress Broker 全体や full isolation が完成したとは扱わない。

## 関連

- [Host Egress Broker](README.md)
- [transport 契約](transport.md)
- [公開 HTTPS policy](network-policy.md)
- [GitHub 型付き adapter](github.md)
- [全体の検証戦略](../design/verification.md)
