# session-orchestrator

`session-orchestrator` は、workspace、Broker、Firecracker VM、subject の root
capability、workload を一つの session identity に結び付ける host lifecycle
state machine である。backend effect は lease の binding を検査してから実行する。

## identity ledger

既存の `SessionOrchestrator::new(random)` は、テストと後方互換用途のため
`InMemoryIdentityLedger` を使う。この ledger の no-reuse 範囲は一つの process
だけであり、process crash をまたぐ保証には使わない。

production host は次の durable constructor を使う。

```rust,ignore
let orchestrator = SessionOrchestrator::new_durable(random, "/var/lib/host/session-ledger")?;
```

`DurableIdentityLedger` は ledger file と `.lock` file の exclusive ownership を
取得し、次を全て確認してから既存 ledger を recovery する。

- version 付き header、record 数、committed byte 長、各 checksum
- 固定長 128-bit identity record の kind、連番、checksum
- duplicate、unknown version、非連続 record、trailing bytes、truncation
- 1,048,576 records / 約 32 MiB の上限
- symlink と non-regular file の拒否

一回の `start_session` で使う session、request、VM、subject、workspace、
capability、Broker session の 7 identity は、ledger abstraction の一つの
batch として append される。record data の `sync_data` 後に committed header を
更新してもう一度 sync し、その処理が成功した後で初めて workspace backend が
呼ばれる。write、sync、entropy、corruption、lock の失敗は typed error として
operator に返され、backend effect は発生せず lifecycle は `Ready` のままである。

append 後の sync や header 更新が不確実な場合、ledger は同一 instance で
fail closed になる。再 open でも完全な committed length と checksum を要求する
ため、壊れた suffix や record 境界での切り詰めを identity の再利用に使えない。

## lifecycle

startup は `workspace clone -> Broker establish -> VM start -> root capability
inject -> workload release` の順で commit する。失敗時は reverse dependency
order で rollback し、cleanup failure が残る場合は `Stopping` を保持して次回
retry する。stop は `root revoke -> VM kill -> Broker close -> workspace
isolation -> Closed` の順である。

snapshot に session-scoped identity が含まれる場合は backend 呼び出し前に拒否し、
restore 後の identity は必ず ledger から fresh に予約する。
