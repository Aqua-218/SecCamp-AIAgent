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
| DNS answer 上限 | 33 件目を保持・dispatch せず `AnswerLimitExceeded` で拒否する | oversized fake resolver |
| resolver resource bound | 固定 1 worker / queue 8 の saturation、timeout 後の worker 再利用 | deterministic pool test |
| redirect 再検査 | path、scheme、userinfo、query、fragment が不正な redirect を拒否する | fake connector |
| response cap | streaming 中に上限超過を拒否し、`HEAD` は本文を読まない | fake response stream |
| GitHub 事前条件 | expected-old plan がなければ provider を呼ばずに拒否する | fake provider |
| provider error | rate-limit metadata は型付きで保持し、生 body は outcome に出さない | fake provider |
| transport policy | zero/過大 timeout を拒否し、read/write/absolute connection deadline を typed error として fail closed | `transport_policy_rejects_zero_and_excessive_deadlines`, `deadline_transport_reports_typed_read_timeout`, `deadline_transport_reports_typed_write_timeout`, `deadline_transport_reports_expired_connection_before_io` |

## dispatch と server で確認したこと

| 境界 | test |
|---|---|
| 一時的な budget 拒否の後、決着した retry が cache から返り adapter を再実行しない | `dispatcher_retries_transient_budget_denial_without_double_charging` |
| 線形化点を越えた効果が `CommittedButUnrecorded` として返り、予約 byte が計上されたままになる | `committed_but_unrecorded_is_distinct_and_keeps_the_reserved_bytes_charged` |
| journal 不能と lock poisoning が認可拒否と別の rejection になる | `audit_failure_is_reported_separately_from_authorization_denial` |
| clock を connection ごとではなく request ごとに読む | `each_request_on_one_connection_reads_the_clock_again` |
| peer CID が一致しない stream を、guest を読まずに落とす | `serve_expected_peer` の CID 検査 test |
| 1 connection が host の request 上限で止まる | `connection_stops_at_the_host_request_bound` |
| Firecracker guest が host Broker に 1 request を送り canonical authorization rejection を受ける | opt-in `real_firecracker_guest_reaches_host_broker_over_vsock` |
| deadline-aware server | timeout 到達前に dispatch を呼ばず connection を閉じる | `deadline_error_closes_connection_before_dispatch` |

## 実行コマンド

repository root から次を実行する。

```bash
cargo fmt --manifest-path crates/egress-broker/Cargo.toml -- --check
cargo test --manifest-path crates/egress-broker/Cargo.toml
cargo clippy --manifest-path crates/egress-broker/Cargo.toml --all-targets -- -D warnings
```

## 未検証の境界

この crate の local test は外部ネットワークへ接続せず、実 secret を読み込まず、`AF_VSOCK` を bind しない。一方、repository の root 権限 opt-in test は Firecracker が guest-to-host connection を転送する per-port Unix socket を bind し、guest→Broker の canonical rejection を確認する。したがって、次はこの test 結果からは言えない。

- 長時間 stream、並行接続、Firecracker 以外の実 `AF_VSOCK` transport
- Firecracker-forwarded UDS の長時間・高並行負荷。production owner が absolute deadline path を選ぶこと自体は hosted composition test と型境界で固定している。
- 実 DNS、DNS rebinding、外部 HTTPS の certificate/SNI と redirect
- OS resolver (`getaddrinfo` / `ToSocketAddrs`) の内部処理や強制キャンセル。timeout 後の lookup は固定 worker 内で完了を待つため、`OverallTimeout` はキャンセルの証明ではない。
- 実 GitHub API、`EGRESS_GITHUB_TOKEN`、provider 側の ref race
- guest supervisor が発行した capability から Broker までの end-to-end 統合

これらを実施していない段階で、Host Egress Broker 全体や full isolation が完成したとは扱わない。

## 関連

- [Host Egress Broker](README.md)
- [transport 契約](transport.md)
- [公開 HTTPS policy](network-policy.md)
- [GitHub 型付き adapter](github.md)
- [全体の検証戦略](../design/verification.md)
