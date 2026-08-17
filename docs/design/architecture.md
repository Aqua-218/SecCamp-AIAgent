<!-- doc-type: design -->

# 全体アーキテクチャ

[設計書一覧](README.md) / 全体アーキテクチャ

> **対象読者:** crate をまたぐ変更を設計する人、統合順序と未接続の境界をレビューする人、この repository に初めて入る実装者

crate ごとの文書は、その境界の内側を詳しく書いている。足りないのは、8 つの crate、deployable な one-session host daemon、immutable guest image の composition が実行時にどう並ぶかを一度に見られる場所である。

個別ページと食い違ったら、個別ページのほうを正とする。ここは配置図であって仕様ではない。

## 実行時の配置

```mermaid
flowchart TB
    subgraph host["ホスト側（信頼する）"]
        orch["session-orchestrator<br/>lifecycle と no-reuse ledger"]
        akh["authority-core<br/>CapabilityKernel（host instance）"]
        broker["egress-broker<br/>vsock listener と typed adapter"]
        fcrt["firecracker-runtime<br/>artifact 固定・jailer・API 順序"]
        cred[("host-only credential")]
        fcproc["firecracker + jailer プロセス"]
        ws[("clone 済み workspace<br/>dm-verity rootfs")]
    end

    subgraph guest["guest（1 session = 1 microVM）"]
        sup["supervisor<br/>subject lifecycle と 4 KiB wire"]
        akg["authority-core<br/>CapabilityKernel（guest instance）"]
        capfs["capfs<br/>FUSE mount と操作ごとの認可"]
        iso["runtime-isolation<br/>exec 直前の 13 step"]
        wl["Agent / Tool"]
    end

    ext["公開 HTTPS / GitHub API"]

    orch --> akh
    orch --> fcrt
    orch --> broker
    cred --> broker
    fcrt ==>|"jailer 起動 / Unix socket HTTP API"| fcproc
    fcrt ==>|"identity 注入 / workload gate"| sup
    fcproc ==>|"boot"| sup
    fcrt --> ws
    orch -->|"production lease / digest-bound v2 identity"| sup
    sup --> akg
    capfs --> akg
    sup -->|"RuntimeResources"| iso
    iso ==>|"execve"| wl
    wl ==>|"file syscall / FUSE"| capfs
    wl ==>|"制御 RPC"| sup
    capfs ==>|"backing fd I/O"| ws
    sup ==>|"AF_VSOCK"| broker
    broker --> akh
    broker ==>|"TLS。credential は host に留める"| ext

    classDef trusted fill:#1565c0,color:#fff,stroke:#0d47a1;
    classDef guestside fill:#2e7d32,color:#fff,stroke:#1b5e20;
    classDef untrusted fill:#b71c1c,color:#fff,stroke:#7f0000;
    classDef data fill:#ef6c00,color:#fff,stroke:#e65100;
    classDef external fill:#616161,color:#fff,stroke:#424242;
    class orch,akh,broker,fcrt,fcproc trusted;
    class sup,akg,capfs,iso guestside;
    class wl untrusted;
    class ws,cred data;
    class ext external;
```

線の太さと種類に意味を持たせてある。

| 線 | 意味 |
|---|---|
| 細い実線 | 同一プロセス内の関数呼び出し。型で繋がっている |
| 太い実線 | プロセスや VM をまたぐ。syscall、socket、HTTP のいずれか |
| 点線 | 図に残る場合は実装不足ではなく、実装済み境界の実機検証が別途必要であることを示す。未検証項目は[実装と証拠の境界](#実装と証拠の境界)に集約する |

## 境界を越える手段は 5 種類しかない

太い線はこの 5 つに限る。ここに無い経路（生の TCP socket、guest から host への任意 file 共有、credential の guest 配布）は作らない。

| 越える境界 | 手段 | 上限 | 誰が検査するか |
|---|---|---|---|
| Agent → 自分の workspace | FUSE operation | なし（操作ごとに認可） | [capfs](../capfs/read-only-fuse.md) が毎 `READ` / `WRITE` / `SETATTR` / `READDIR` で kernel を引く |
| Agent → subject 制御 | supervisor の bounded envelope | 4 KiB、version 1、tag は `CloseSubject` と `CloseHandle` の 2 つ | [supervisor](../supervisor/README.md)。wire 上の `claimed_subject` は認可に使わない |
| guest → host egress | `AF_VSOCK` の length-prefixed frame | 4 bytes prefix、payload 1 MiB | [transport 契約](../egress-broker/transport.md) が長さを確保前に検査する |
| host → VM | Firecracker API と guest control API | — | [firecracker-runtime](../firecracker-runtime/launch-sequence.md)。`network_devices` が空でなければ artifact を読む前に拒否 |
| host → 外部 | Broker の型付き adapter | response 32 MiB、redirect 5 hop、connect 10 秒 / 全体 60 秒 | [公開 HTTPS policy](../egress-broker/network-policy.md) と [GitHub adapter](../egress-broker/github.md) |

guest に `virtio-net` は付かない。外へ出る経路が vsock 1 本しかないので、egress の検査点は Broker に集約される。

## crate 依存は実行時の形と一致しない

配置図は host と guest に分かれているが、[`Cargo.toml`](../../Cargo.toml) の依存グラフはもっと単純で、`authority-core` を底とする木になっている。

```mermaid
flowchart BT
    ac["authority-core"]
    ep["egress-protocol"]
    eb["egress-broker"]
    cf["capfs"]
    sv["supervisor"]
    fr["firecracker-runtime"]
    ri["runtime-isolation"]
    so["session-orchestrator"]

    ep --> ac
    cf --> ac
    sv --> ac
    eb --> ac
    eb --> ep
    fr --> ac
    fr --> ep
    so --> ac
    so --> eb
    so --> fr

    classDef leaf fill:#455a64,color:#fff,stroke:#263238;
    class ac,ri leaf;
```

依存グラフの矢印は「依存する側 → 依存先」である。`authority-core` と `runtime-isolation` が依存木の葉で、`supervisor` は `capfs` を、`firecracker-runtime` は `authority-core` / `egress-protocol` を、`session-orchestrator` は Firecracker と Broker を参照する。実行時の supervisor → launcher → runtime-isolation の接続は Cargo の直接依存ではなく、immutable guest image に固定した executable path と inherited gate で構成される。

`host-sessiond` は `ProductionSessionRuntimeBuilder`、実 workspace/Broker/Firecracker/authority backend を組み立てる deployable one-session daemon で、systemd unit と environment manifest も `deploy/` / `service/` にある。guest 側には [`guest-supervisor-init`](../../crates/supervisor/src/bin/guest-supervisor-init.rs) があり、固定 image の repository/effect/path policy から guest `CapabilityKernel`、CapFS runtime、`LinuxHostResources` を組み立て、`workload-isolation-launcher` へ接続する。[`guest-control-init`](../../crates/firecracker-runtime/src/bin/guest-control-init.rs) はその前段の PID 1 gate として、host-originated identity injection と image-configured supervisor release だけを受け付ける。どちらも host から任意 command、credential、authority body を受け取らない。

この構成は実装済みで、productionと同じv2 policy-digest-bound guest gate、guest supervisor composition、`Runtime::launch`のjailer/workspace lifecycle、clean snapshot capture／restore、`rootfs.source == "/"`、mount rollback、全13 CapFS effectを実KVM SessionOwner gateでも確認している。これは列挙したproduction経路の実機証拠であり、Firecracker／KVM／host kernelそのもののVM escape耐性を証明するものではない。

## 副作用は 1 つの API に集まる

file を書く経路と外部へ出る経路は、別 process の local kernel を通るが、いずれも [`CapabilityKernel::authorize_all_and_execute_classified`](../../crates/authority-core/src/kernel.rs) の read-guard/commit 規則を使う。host 側の Broker root と guest root は policy digest-bound v2 の lease/control gate で結ばれ、guest に host credential や authority body を渡さない。

| 呼ぶ側 | 何を commit するか |
|---|---|
| [`capfs/src/read_only.rs`](../../crates/capfs/src/read_only.rs) | guest FUSE operation。backing への実 I/O が commit point |
| [`egress-broker/src/dispatch.rs`](../../crates/egress-broker/src/dispatch.rs) | host の型付き adapter 呼び出し。HTTPS request か GitHub 操作 |
| [`session-orchestrator/src/authority_backend.rs`](../../crates/session-orchestrator/src/authority_backend.rs) | host root binding の発行、policy digest、revoke/subject close |

```mermaid
sequenceDiagram
    participant W as Agent / Tool
    participant F as capfs
    participant S as guest supervisor
    participant B as Broker dispatcher
    participant K as CapabilityKernel
    participant X as backing fd / 外部 API

    Note over W,X: file 経路
    W->>F: FUSE_WRITE(nodeid, fh, data)
    F->>F: ObjectId から現在 path を引く
    F->>K: authorize_all_and_execute_classified(WriteData, path)
    K->>X: read guard を保持したまま write
    X-->>K: 書けた byte 数
    K-->>F: commit receipt
    F-->>W: result

    Note over W,X: egress 経路
    W->>S: 閉じた集合の操作を要求
    S->>B: frame → canonical CBOR → replay → budget
    B->>K: authorize_and_execute_classified(HttpFetch / GitHub)
    K->>X: read guard を保持したまま TLS request
    X-->>K: 型付き response
    K-->>B: commit receipt
    B-->>S: 型付き response（body も credential も返さない）
    S-->>W: 型付き response
```

要点は guard と revoke completion の保持区間が揃っていること。`authorize_all_and_execute_classified` は認可から effect の linearization point まで read guard を保持し、`revoke_held_by` は exclusive transition と observer propagation を完了してから返る。subject close は authorization epoch を進め、open handle が無くなるまで `finish_subject_close` を成功にしない。session owner は capability revoke → VM kill → Broker close の順に cleanup stage を進め、VM kill と Broker close が済むまで workspace isolation/reuse を許さず、失敗時は `Stopping` に残して未完了 stage だけを retry する。詳細は [Authorization guard](../authority-core/authorization-guard.md) と [状態機械と revoke](state-and-revocation.md)。

## Capability Kernel は今いくつあるのか

配置図に `CapabilityKernel` を 2 つ描いたのは、現在のコードがそう読めるからである。`capfs` は `Arc<CapabilityKernel>` を受け取り、Broker の `CapabilityExecutor` も `CapabilityKernel` の impl で、どちらも同一プロセス内の instance を前提にしている。capfs は guest で、Broker は host で動く。同じ instance にはなりようがない。

`authority_core::state` の revoke と `auth_epoch` は各 `CapabilityState` を直列化する。host 側では `AuthorityCoreBackend` が guest/Broker binding を同じ host kernel に登録し、両方を revoke/close する。guest 側の固定 image は独自の guest kernel/CapFS を持つため、host lease の `AuthorityPolicyDigest` と guest-control v2 の canonical request/ack が境界を束縛し、production workload release は unbound lease/v1 API を拒否する。guest が応答しない場合の session-level completion は guest ACK ではなく VM/cgroup termination と owner の cleanup barrier によって閉じる。guest policy body 自体を host transport で受け渡す設計ではない。

## session の時間軸

startup は 4 つの state machine が噛み合って進む。orchestrator が commit 順を決め、他の 3 つはそれぞれの内側を持つ。

| orchestrator `LifecycleState` | firecracker `RuntimeState` | そこで確定すること |
|---|---|---|
| `Ready` | `New` | 7 つの 128-bit identity を ledger へ append。`sync_data` まで終わるまで backend を呼ばない |
| `WorkspaceCloned` | — | capfs の backing になる tree を clone。symlink と hard link は許さない |
| `BrokerEstablished` | — | 新しい `BrokerSessionId`、sequence は 0 から、replay guard も作り直す |
| `VmStarted` | `RestoredStopped` → `IdentityRegenerated` | pre-session snapshot を restore し、128-bit の identity を 5 つ作り直す |
| `RootCapabilityInjected` | `IdentityInjected` | production は `/actions/inject-identity-v2` へ policy encoding version + digest + 5 IDs を canonical に渡し、`identity-injected-v2` ACK を受ける。v1 は compatibility-only |
| `WorkloadReleased` | `Running` | production は同じ bound digest を `/actions/start-workload-v2` へ渡し、`workload-started-v2` ACK を受けてから 13 step isolation の `execve` を許す。v1 は compatibility-only |
| `Running` | `Running` | 定常 |

**session は VM の起動ではなく restore から始まる。** `launch` が返すのは `WorkloadStopped` で、そこから `Running` へ抜ける遷移は `RuntimeState` に無い。`launch` の 5 本の PUT と `InstanceStart` は、snapshot 元になる VM を 1 つ作るための経路であって、session ごとに通る道ではない。session を増やすときに毎回払うのは restore と identity 再生成のコストになる。

`RuntimeState::Running` も「VM が動いている」ではなく「workload の実行が明示的に許可された」を指す。VM 自体は restore の時点で立っている。snapshot 作成時は `WorkloadStopped` から Firecracker の pause acknowledgement を受けて `SnapshotPaused` へ遷移し、write failure でも paused/unknown を再利用しない。state 名を条件に何かを判断するコードを書く前に、[snapshot と identity gate](../firecracker-runtime/snapshot-and-identity.md)を読む。

restore 元に session-scoped identity が残っていれば、backend を呼ぶ前に startup 自体を拒否する。snapshot を取れるのも `WorkloadStopped` の VM だけなので、snapshot に「workload が走った後の memory」が入ることはない。

停止は逆順で、どこが失敗しても後段を諦めない。ただし 1 箇所だけ例外がある。

```text
root capability revoke + host authority completion
  -> Firecracker VM kill / cgroup termination
  -> Broker close
  -> workspace isolation
  -> Closed

revoke が in-flight effect の linearization を待って返り、VM kill と Broker close が成功したときだけ workspace isolation を実行する。
生きた VM が掴んだままの tree を、別 session へ配り直さないため。
```

guest 側では supervisor が subject ごとに同じ形の取引を持つ。`SetupStep` の 6 段（cgroup 作成 → capfs mount → control fd → subject 登録 → handle 登録 → workload 起動）を通し、shutdown では `begin_subject_close` と `finish_subject_close` の間に外部 resource の解放を挟む。exec 直前の 13 step はさらにその内側にある入れ子で、[13 step の固定順序と rollback](../runtime-isolation/apply-order.md)のとおり大半が kernel 上で戻せない。

## identity はどこで翻訳されるか

orchestrator が割り当てる 7 種の 128-bit identity は、境界を越えるたびに相手側の型へ写される。同じ概念に別の型が付くので、対応表を持っておくと追いやすい。

| `IdentityKind` | 渡る先 | 相手側の型 | 翻訳する場所 |
|---|---|---|---|
| `Session` | 全 lease | `SessionId` | orchestrator 内で完結 |
| `Workspace` | workspace adapter | `WorkspaceId` | `firecracker_workspace.rs` |
| `BrokerSession` | Broker | `egress_protocol::session::BrokerSessionId` | `egress_backend.rs`。bytes をそのまま渡す |
| `Request` | Broker の最初の control request | `BrokerRequestId` | `egress_backend.rs` |
| `Vm` | Firecracker | `VmId`、guest control API では hex 文字列 | `firecracker_backend.rs` |
| `Subject` | Authority | `authority_core::capability::SubjectId` | [`authority_backend.rs`](../../crates/session-orchestrator/src/authority_backend.rs) が hex 文字列へ変換 |
| `Capability` | Authority | `CapId` | 同上 |

orchestrator の `SubjectId` と `authority_core` の `SubjectId` は名前が同じで別の型である。adapter がこの写像を持ち、別 session の capability が lease を満たせないようにする。ただし[契約](../session-orchestrator/contracts.md)が明記しているとおり、これは検出であって防止ではない。lease を正しい identity で作る責任は backend 側に残る。

## 実装と証拠の境界

配置図の実装済みの線と、実機で動かしていない境界を分けて一覧にする。「実装済み」と「実機で確認済み」を混同しないための表である。

| 線 | 現状 | 繋ぐのに要るもの |
|---|---|---|
| supervisor → runtime-isolation | `guest-supervisor-init` → `LinuxHostResources` → image-configured `workload-isolation-launcher` の inherited start gate と close-on-exec acknowledgement が実装済み | privileged probeがlauncher／exec後の境界を確認し、KVM SessionOwner gateが`rootfs.source == "/"`を確認 |
| guest composition | `guest-supervisor-init` が固定 policy から guest kernel/CapFS/control/workload を組み立て、readiness marker を返す | real KVM runtime image はこの composition を起動するが、全 CapFS effect を証明するものではない |
| authority binding | `AuthorityPolicyDigest`、v2 canonical request/ack、bound lease、v1 compatibility parser は実装済み。production workload release は policy-bound lease を要求する | direct real KVM test で v2 digest-bound injection/start と exact ACK を確認済み。`Runtime::launch` lifecycle との一体試験は別境界 |
| host の vsock/UDS listener | `FirecrackerUnixListener` は private path、CID、Linux `SO_PEERCRED` の UID/GID/PID を検査して fail closed。deadline-aware transport API も実装済み | direct `AF_VSOCK` bind/accept、production owner の absolute connection-deadline wiring、長時間/並行 stream |
| Firecracker の実起動 | [`real_guest_control`](../../crates/firecracker-runtime/tests/real_guest_control.rs) が実 Firecracker、dm-verity rootfs、guest runtime image、guest Broker channel を通す | `Runtime::launch` 経由の実 jailer、workspace drive、snapshot restore、resource rollback |

`authority-core` と `capfs` の内側は、この表とは検証の水準が違う。前者は Rust と Lean の共通 corpus と loom、後者は `/dev/fuse` がある環境での実 mount test まで通っている。crate ごとの正確な線引きは各 [検証対応表](verification.md)を見る。

## どの箱がどの文書か

| 配置図の箱 | crate | 入口の文書 |
|---|---|---|
| CapabilityKernel | `authority-core` | [Authority core 実装ガイド](../authority-core/README.md) |
| capfs mount | `capfs` | [capfs 実装ガイド](../capfs/README.md) |
| vsock listener と typed adapter | `egress-broker` / `egress-protocol` | [Host Egress Broker](../egress-broker/README.md)、[Broker session envelope](../egress-protocol/session-envelopes.md) |
| firecracker + jailer | `firecracker-runtime` | [Firecracker runtime](../firecracker-runtime/README.md) |
| exec 直前の 13 step | `runtime-isolation` | [runtime-isolation](../runtime-isolation/README.md) |
| subject lifecycle と 4 KiB wire | `supervisor` | [Supervisor adapter](../supervisor/README.md) |
| lifecycle と no-reuse ledger | `session-orchestrator` | [Session orchestrator](../session-orchestrator/README.md) |

## 関連

- [設計書一覧](README.md)
- [脅威モデル](threat-model.md)
- [Capability モデル](capability-model.md)
- [状態機械と revoke](state-and-revocation.md)
- [ネットワークと外部副作用](network-egress.md)
- [隔離基盤](runtime-isolation.md)
- [capfs](capfs.md)
- [実装順序](implementation-plan.md)
- [検証戦略](verification.md)
- [用語集](../glossary.md)
- [決定記録](../decisions/README.md)
