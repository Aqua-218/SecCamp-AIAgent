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
| GitHub credential 境界 | 欠損 / 制御文字 credential を拒否し、provider `Debug` と typed error が token を redact する | `invalid_credential_environment_values_fail_closed`, `provider_debug_and_typed_errors_never_leak_the_token` |
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
| production SessionOwnerのguest Supervisor/CapFS/隔離後requestがdurable WALにFinal rejectionとして残る | `scripts/ci/verify-real-session-owner.sh` |
| deadline-aware server | timeout 到達前に dispatch を呼ばず connection を閉じる | `deadline_error_closes_connection_before_dispatch` |

## privileged network namespace で確認したこと

`scripts/ci/verify-real-public-https.sh` は root の isolated mount/network namespace を作り、dnsmasq の制御 DNS、CNAME、TTL 0 の answer、公開 IPv4 として扱われる test address、専用 CA、OpenSSL HTTPS server を配置する。通常の local test と違い、production の `SystemResolver` と `RustlsHttpsConnector` を実行する。

| 境界 | test |
|---|---|
| 検査済み `SocketAddr` への接続 | OS resolver が listener の無い別 address を返す状態でも、connector が policy から渡された address へ接続する |
| TLS certificate と SNI | canonical host の SAN を持つ専用 certificate のみを信頼し、実 TLS handshake と HTTP response を完了する |
| redirect 後の再解決 | DNS CNAME の A answer を 1 hop 目の後に private address へ切り替え、2 hop 目を connector 呼び出し前に拒否する |

実行コマンド:

```bash
scripts/ci/verify-real-public-https.sh
```

root、mount/network namespace、`dnsmasq`、`ip`、OpenSSL のいずれかが無ければ exit 2 で終了し、成功として扱わない。

## 実行コマンド

repository root から次を実行する。

```bash
cargo fmt --manifest-path crates/egress-broker/Cargo.toml -- --check
cargo test --manifest-path crates/egress-broker/Cargo.toml
cargo clippy --manifest-path crates/egress-broker/Cargo.toml --all-targets -- -D warnings
```

実 GitHub provider の opt-in gate は、保護された disposable repository と credential を operator が用意した場合だけ実行する。

```bash
scripts/ci/verify-live-github.sh
```

この gate は `EGRESS_GITHUB_TOKEN`、installation、exact disposable `owner/name`、base/head、expected-old/new object ID、repository に結び付いた acknowledgement を全て要求する。不足や形式不正は exit 2 で終了し、token は表示しない。実行時は `RustlsGitHubProvider` を `TypedGitHubAdapter` 経由でだけ呼び、`PublishBranch` の non-force expected-old 更新と `CreatePullRequest` の typed response を検査する。pull request と branch の cleanup は自動化していないため、operator が専用 repository を手動で片付ける。

## 未検証の境界

この crate の local test は外部ネットワークへ接続せず、実 secret を読み込まず、`AF_VSOCK` を bind しない。一方、repository の root 権限 opt-in test は Firecracker が guest-to-host connection を転送する per-port Unix socket を bind し、guest→Broker の canonical rejection を確認する。したがって、次はこの test 結果からは言えない。

- 長時間 stream、並行接続、Firecracker 以外の実 `AF_VSOCK` transport
- Firecracker-forwarded UDS の長時間・高並行負荷。production owner が absolute deadline path を選ぶこと自体は hosted composition test と型境界で固定している。
- DNSSEC、複数 CNAME の chain、外部 Internet 上の HTTPS。privileged namespace test は制御 DNS の TTL 0/CNAME/answer 切替、OS resolver、certificate/SNI、redirect 後の再解決、検査済み address への接続までを実 kernel socket で確認する。
- OS resolver (`getaddrinfo` / `ToSocketAddrs`) の内部処理や強制キャンセル。timeout 後の lookup は固定 worker 内で完了を待つため、`OverallTimeout` はキャンセルの証明ではない。
- protected disposable scope での実 GitHub API、`EGRESS_GITHUB_TOKEN`、provider 側の ref race。ignored live smoke と gate は存在するが、この checkout では credential を使った実行 evidence が無い
- guest supervisorが発行したfile capabilityから全CapFS effectを経てBrokerのcanonical rejectionへ至るend-to-end統合はKVM gateで確認済み。guestから外部providerへ到達するauthorized mutationは、上記live credential gateがblockedのため未実行

これらを実施していない段階で、Host Egress Broker 全体や full isolation が完成したとは扱わない。

## 関連

- [Host Egress Broker](README.md)
- [transport 契約](transport.md)
- [公開 HTTPS policy](network-policy.md)
- [GitHub 型付き adapter](github.md)
- [全体の検証戦略](../design/verification.md)
