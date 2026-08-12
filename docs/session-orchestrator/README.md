<!-- doc-type: index -->

# Session orchestrator

[ドキュメント一覧](../README.md) / Session orchestrator

> **対象読者:** host lifecycle 統合担当者、Firecracker/Broker/Authority adapter の設計者、レビュー担当者

`session-orchestrator` は、隔離された一つの agent session のホスト側 lifecycle state machine である。resource の確保順序と identity binding を所有し、Authority Core、Broker listener、Firecracker runtime、workspace の production adapter を提供する。FUSE mount、provider request、特権 isolation の具体的な副作用は、それぞれの専用 adapter が所有する。

## lifecycle

startup は次の commit 順で進む。

```text
session-scoped identity のない snapshot descriptor
  -> 7つの 128-bit identity を割り当て
  -> session 専用 workspace を clone
  -> restore 後の新しい Broker session を確立
  -> 一つの Firecracker VM を起動
  -> 一つの subject へ root capability を注入
  -> 制限を適用済みの workload を release
  -> Running
```

実際の公開 state は `Ready`、`WorkspaceCloned`、`BrokerEstablished`、`VmStarted`、`RootCapabilityInjected`、`WorkloadReleased`、`Running`、`Stopping`、`Closed` である。各 backend は effect が commit point に到達した後だけ、対応する lease を返す。lease の session/resource identity が要求と一致しなければ、次の stage へ進まず失敗する。

startup failure は commit 済み resource だけを依存関係の逆順で rollback する。workload release 後の rollback は root capability revoke、VM kill、Broker close、workspace isolation の順である。VM kill が失敗した場合は、live VM が workspace を保持したまま別用途へ回らないよう workspace isolation を実行しない。

stop も同じ containment order を使い、root revoke、VM kill、Broker close、workspace isolation を試みる。どれかが失敗した場合は `Stopping` を保持し、次回は未完了 stage だけを retry する。cleanup が全て commit したときだけ `Closed` になる。startup rollback が失敗した場合も `Ready` に戻らず、未解決の host resource がある間は新しい session を受け付けない。

## identity と isolation の不変条件

- VM、session、subject、workspace、capability、request、Broker session の identity はそれぞれ 128-bit で、`CryptographicRandom` から得る。
- no-reuse ledger は、全 identity domain をまたいで過去に使用した byte value を拒否する。失敗した startup で割り当てた値も予約済みのまま残る。
- `SnapshotDescriptor` に session-scoped identity が含まれていれば restore を拒否する。snapshot source を再利用する場合も、新しい session は全ての identity を再生成する。
- 各 backend lease は session identity と、workspace、Broker、VM、capability、workload の対応 identity を保持する。foreign session または foreign resource の lease は次の stage の前に拒否する。
- 同じ `SessionOrchestrator` で active session は一つだけであり、二つ目の start は backend を呼ぶ前に拒否する。

`SessionOrchestrator::new` の process-local ledger は test と組み込み用途向けであり、restart をまたがない。production host は `SessionOrchestrator::new_durable` と永続 ledger file を使う。durable ledger は exclusive ownership、version/checksum 検証、append 後の `sync_data` を要求し、過去の identity を restart 後も再利用させない。

## 検証状態

state machine は mock backend を使う test で検証済みである。正常 startup/stop、各 stage failure の rollback、rollback failure、VM kill failure 時の workspace 保持、inherited identity と reused identity、active session の二重起動、foreign lease、stop retry を対象にする。

production adapter composition test は、実 `CapabilityKernel` と session adapter 群を使い、workspace clone、listener ownership、snapshot binding、Firecracker identity injection、Authority subject closure を一つの startup/stop 経路で検査する。command、filesystem、API、listener は test double であり、実 Firecracker、実 Broker/vsock、実 capfs、特権 workload restrictions は未検証である。mock test が pass したことを VM 実起動済みや full isolation 完成の根拠にはしない。

adapter の義務と、既存 crate へ接続するときの型・順序は [production backend 契約](contracts.md) を参照する。

focused test は次のとおりである。

```bash
cargo fmt --manifest-path crates/session-orchestrator/Cargo.toml -- --check
cargo test --manifest-path crates/session-orchestrator/Cargo.toml
cargo clippy --manifest-path crates/session-orchestrator/Cargo.toml --all-targets -- -D warnings
```

## 関連

- [production backend 契約](contracts.md)
- [Firecracker runtime](../firecracker-runtime/README.md)
- [Supervisor adapter](../supervisor/README.md)
- [Host Egress Broker](../egress-broker/README.md)
- [実装順序](../design/implementation-plan.md)
- [検証戦略](../design/verification.md)
