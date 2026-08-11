# 状態機械と revoke

[設計書一覧](README.md) / 状態機械と revoke

revoke で難しいのは、「止めると決めた瞬間」と「副作用が実際に起きた瞬間」が別々に存在することだ。この設計では、両者を同じ lock の上に置いて順番を一意に決める。

## 持つ状態

```text
State {
    capabilities : Map<CapId, Capability>
    held         : Map<SubjectId, Set<CapId>>
    revoked      : Set<CapId>
    issued_ids   : Set<CapId>
    subjects     : Map<SubjectId, Subject>
    open_handles : Map<HandleId, OpenHandle>
    attempts     : AppendOnlySeq<AttemptRecord>
    effects      : AppendOnlySeq<EffectRecord>
    auth_epoch   : UInt64
}
```

subject は専用の `SOCK_SEQPACKET`、専用の `capfs` mount、親 subject を持つ。request に書かれた ID は信用せず、supervisor が受信した socket fd から caller を決める。

open handle は「一度だけ使える lease」ではない。同じ fd で何度でも read / write できる代わりに、実際の操作ごとに認可をやり直す。

## subject の一生

```mermaid
stateDiagram-v2
    [*] --> Creating
    Creating --> Running: channel / mount / envelope を準備
    Creating --> Closed: 初期化失敗
    Running --> Closing: CloseSubject または KillSubject
    Closing --> Closed: cgroup 停止・revoke・fd close・unmount
    Closed --> [*]

    note right of Running
      Capability の追加は
      静的 envelope の内側だけ
    end note
```

範囲外の file Capability を既存 subject に後付けしない。必要なら、新しい subject とコンテナを作り直す。Landlock の上限を後から広げられないためである。

## 委譲

`Derive` は親を持っているだけでは通らない。親と全祖先が有効で、親が委譲可能で、子が `WeakerThan` を満たし、さらに child subject の静的 envelope 内に収まっている必要がある。

```mermaid
flowchart LR
    request["Derive request"] --> held{"親を保持している?"}
    held -->|"no"| deny["拒否"]
    held -->|"yes"| valid{"親と祖先が有効?"}
    valid -->|"no"| deny
    valid -->|"yes"| weaker{"WeakerThan?"}
    weaker -->|"no"| deny
    weaker -->|"yes"| envelope{"静的 envelope 内?"}
    envelope -->|"no"| deny
    envelope -->|"yes"| issue["新しい ID と subject を<br/>server 側で設定して発行"]

    classDef denied fill:#b71c1c,color:#fff;
    classDef issued fill:#2e7d32,color:#fff;
    class deny denied;
    class issue issued;
```

## commit と revoke の競合

effect は shared authorization guard、revoke は exclusive guard を取る。

```mermaid
sequenceDiagram
    participant A as Agent / capfs
    participant K as Capability Kernel
    participant E as Effect executor
    participant R as Revoker

    A->>K: effect を要求
    K->>K: shared guard を取得
    R->>K: Revoke(cap)
    Note over R,K: exclusive guard 待ち
    K->>K: 現在時刻で再認可
    K->>E: 線形化点まで実行
    E-->>K: accepted
    K->>K: EffectRecord を追記して guard 解放
    K-->>R: exclusive guard を取得
    R->>K: revoked に追加 / auth_epoch++
    K-->>R: revoke 完了
```

この順なら effect が先に成立する。逆に revoke が exclusive guard を先に取れば、その後の effect は再認可で落ちる。どちらに転んでも順序は曖昧にならない。

```text
CommitEffect(subject, effect):
    attempts += Started
    shared_guard.lock()
    cap := Authorize(subject, effect, monotonic_now())
    if cap is None:
        attempts += Denied
        return NotAuthorized
    result := ExecuteToLinearizationPoint(effect)
    if result.accepted:
        effects += EffectRecord(effect, cap, result)
        attempts += Accepted
    else:
        attempts += FailedBeforeCommit
```

拒否した試行は `attempts` に残すが、`effects` には入れない。`NoUnauthorizedCommit` は、実際に成立した `effects` だけを対象に検査する。

## 線形化点

| 操作 | ここを越えたら commit 済みとする |
|---|---|
| file read / write | `capfs` が backing read / write を発行した瞬間 |
| create / remove / rename / truncate | 対応する backing syscall を発行した瞬間 |
| 公開 Web 取得 | Host Broker が検証済み outbound request を受理した瞬間 |
| 認証 API | Host Broker が idempotency key 付き request を永続的に受理した瞬間 |

revoke は、これより前の操作を巻き戻すものではない。

## KillSubject

`KillSubject` は subject を `Closing` にして新規操作を止め、コンテナの cgroup 全体を停止する。その後、held Capability の revoke、control fd と open handle の close、`capfs` の unmount を行って `Closed` にする。

すでに Host Broker が受理した外部操作だけは続行し得る。

## 関連文書

- [Capability モデル](capability-model.md)
- [capfs](capfs.md)
- [ネットワークと外部副作用](network-egress.md)
