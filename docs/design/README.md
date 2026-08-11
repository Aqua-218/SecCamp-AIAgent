# Capability-based Agent 実行基盤

Agent にコードを書かせるだけなら、それほど難しくない。難しいのは、生成されたコードを本当に動かし、ファイルを書き換え、外部サービスまで操作させるところにある。

この基盤では、Agent と Tool を最初から信用しない。何をしてよいかは Capability で明示し、実際の副作用が起きる場所で強制する。

## 何を守るのか

守りたい境界は3段ある。

1. Agent 同士は subject と Capability で分ける。
2. guest 内の仕組みが破られても、被害をその VM の workspace と session envelope に留める。
3. GitHub などの認証情報は guest に入れず、ホスト側だけで扱う。

```mermaid
flowchart TB
    human["人間 / セッション管理"]

    subgraph host["ホスト側の信頼境界"]
        orchestrator["Orchestrator<br/>VM と root Capability を用意"]
        broker["Egress Broker<br/>公開 Web と認証 API を仲介"]
        firecracker["Firecracker + jailer"]
        disk[("VM 専用 workspace")]
        internet["公開 Web / GitHub 等"]
    end

    subgraph vm["1セッション = 1 microVM"]
        supervisor["Supervisor"]
        kernel["Capability Kernel<br/>判定だけを担当"]
        capfs["capfs<br/>ファイル操作を強制"]

        subgraph containers["信頼しないコンテナ"]
            agent["Agent"]
            tool["Tool"]
        end
    end

    human -->|"セッション方針"| orchestrator
    orchestrator -->|"restore 後に root を注入"| supervisor
    agent -->|"制御 RPC"| supervisor
    tool -->|"制御 RPC"| supervisor
    agent -->|"通常のファイル syscall"| capfs
    tool -->|"通常のファイル syscall"| capfs
    supervisor -->|"認可を問い合わせる"| kernel
    capfs -->|"操作ごとに認可"| kernel
    capfs -->|"許可された操作だけ実行"| disk
    supervisor -->|"vsock"| broker
    broker -->|"検証済み HTTPS / API"| internet
    firecracker -->|"起動・隔離"| supervisor

    classDef trusted fill:#1565c0,color:#fff,stroke:#0d47a1;
    classDef guest fill:#2e7d32,color:#fff,stroke:#1b5e20;
    classDef untrusted fill:#b71c1c,color:#fff,stroke:#7f0000;
    classDef data fill:#ef6c00,color:#fff,stroke:#e65100;
    class orchestrator,broker,firecracker trusted;
    class supervisor,kernel,capfs guest;
    class agent,tool untrusted;
    class disk data;
```

## この設計で選んだ形

- ファイル操作は、subject ごとの `capfs` を必ず通す。
- `OPEN` 時だけでなく、実際の `READ` / `WRITE` ごとに権限を見直す。
- Agent / Tool に生のネットワークは渡さない。
- 公開 Web は GitHub に限定せず、Host Egress Broker 経由で取得できる。
- 認証付き操作は、`CreatePullRequest` のような型付き API に限定する。
- 相互不信のセッションを同じ VM に入れない。

## 文書の読み方

```mermaid
flowchart LR
    start["まず全体像"] --> threat["脅威モデル"]
    threat --> caps["Capability モデル"]
    caps --> state["状態機械と revoke"]
    state --> files["capfs"]
    state --> net["ネットワークと外部副作用"]
    files --> isolation["隔離基盤"]
    net --> isolation
    caps --> verify["検証戦略"]
    files --> verify
    isolation --> plan["実装順序"]
    verify --> plan

    click threat "threat-model.md" "脅威モデル"
    click caps "capability-model.md" "Capability モデル"
    click state "state-and-revocation.md" "状態機械と revoke"
    click files "capfs.md" "capfs"
    click net "network-egress.md" "ネットワークと外部副作用"
    click isolation "runtime-isolation.md" "隔離基盤"
    click verify "verification.md" "検証戦略"
    click plan "implementation-plan.md" "実装順序"
```

| 文書 | そこで決めること |
|---|---|
| [脅威モデル](threat-model.md) | 誰を信用し、どこまで守るか |
| [Capability モデル](capability-model.md) | 権限をどう表し、どう狭めるか |
| [状態機械と revoke](state-and-revocation.md) | 副作用と失効をどう競合させるか |
| [capfs](capfs.md) | ファイル操作をどこで止めるか |
| [隔離基盤](runtime-isolation.md) | VM、namespace、Landlock、seccomp の分担 |
| [ネットワークと外部副作用](network-egress.md) | 公開 Web と認証 API をどう分けるか |
| [検証戦略](verification.md) | 何を証明し、何をテストするか |
| [実装順序](implementation-plan.md) | どこから作れば手戻りが少ないか |

## revoke の約束

> revoke が返った後に commit される副作用は、失効した Capability やその子孫だけを根拠には実行されない。

逆に、revoke より先に線形化点を越えた操作は巻き戻さない。この線引きを曖昧にしないことが、状態機械の中心になる。

## 関連文書

- [脅威モデル](threat-model.md)
- [Capability モデル](capability-model.md)
- [状態機械と revoke](state-and-revocation.md)
