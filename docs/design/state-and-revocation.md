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
    valid -->|"yes"| delegable{"親が delegable?"}
    delegable -->|"no"| deny
    delegable -->|"yes"| weaker{"WeakerThan?"}
    weaker -->|"no"| deny
    weaker -->|"yes"| envelope{"静的 envelope 内?"}
    envelope -->|"no"| deny
    envelope -->|"yes"| issue["新しい ID・issuer・parent を<br/>server 側で設定して発行"]

    classDef denied fill:#b71c1c,color:#fff;
    classDef issued fill:#2e7d32,color:#fff;
    class deny denied;
    class issue issued;
```

## 現在の実装位置

[`crates/authority-core/src/state.rs`](../../crates/authority-core/src/state.rs) に逐次状態機械、[`crates/authority-core/src/kernel.rs`](../../crates/authority-core/src/kernel.rs) にそれを並行利用するための同期境界がある。現在は次の境界まで実装している。

| 実装済み | 次に実装する |
|---|---|
| subject 登録、root 発行、held、caller binding、parent link、`delegable` を検査する Derive | supervisor / filesystem / Broker adapter との end-to-end 接続 |
| `WeakerThan`、target envelope、逐次 revoke、祖先 chain、`auth_epoch` | durable audit backend と commit receipt |
| Running→Closing→Closed、held revoke、open-handle registry、ID 非再利用 | 実 fd lifecycle と capfs registry を一体化する adapter |
| shared effect / exclusive transition、executor の線形化点までの guard、attempt/effect audit | open handle、rename、unlink を含む capfs 競合 model |
| capfs の path/object 対応、generation、open count、全file mutationのFUSE / backing接続 | revokeとrename / unlinkを同時に含むbounded競合 model |
| direct / ancestor revokeの単一・compound effect、2 effects、negative control の Loom model | 4 thread 以上・複数 revoke / Capability tree の model |

詳細は[Capability の発行と逐次状態機械](../authority-core/capability-state.md)と[Effect commit と revoke の authorization guard](../authority-core/authorization-guard.md)を参照する。

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
    K->>K: executor return 後に guard 解放
    K-->>R: exclusive guard を取得
    R->>K: revoked に追加
    K-->>R: revoke 完了
```

この順なら effect が先に成立する。逆に revoke が exclusive guard を先に取れば、その後の effect は再認可で落ちる。どちらに転んでも順序は曖昧にならない。

現在の `CapabilityKernel::authorize_and_commit` は、最終認可、executor 呼び出し、revoke との線形化、in-memory の `AttemptRecord` / `EffectRecord` / `auth_epoch` を実装する。durable storage と provider 固有の commit receipt は adapter 側の次段階である。

```text
CommitEffect(subject, effect):
    shared_guard.lock()
    attempt := attempts.append(Started, auth_epoch)
    cap := Authorize(subject, effect, monotonic_now())
    if cap is None:
        attempt.finish(Denied)
        return NotAuthorized
    result := ExecuteToLinearizationPoint(effect)
    if result.accepted:
        attempt.finish(Committed)
    else:
        attempt.finish(FailedBeforeCommit)
```

拒否した試行は `attempts` に残すが、`effects` には入れない。現在の in-memory `EffectRecord` は `Committed` attempt だけから作る。`NoUnauthorizedCommit` は、実際に成立した `effects` だけを対象に検査する。

実装には `std::sync::RwLock` を使う。単一の `Mutex` でも安全な順序は作れるが、互いに独立した認可済み effect まで直列化する。認可直後に lock を外し、commit 前に epoch だけ再確認する方式は、外部 effect の線形化点との間に別の gap を作りやすい。そのため現在は、Capability への借用を executor closure に渡し、shared guard の寿命を closure の return まで型と所有権で結び付ける。

この lock が保証するのは safety であり、writer fairness や revoke latency の上限ではない。また executor closure から同じ kernel の exclusive transition を呼ぶと deadlock し得るため、adapter は再入してはならない。詳しい契約と loom の検査範囲は[Authorization guard](../authority-core/authorization-guard.md)に記載する。

## 線形化点

| 操作 | ここを越えたら commit 済みとする |
|---|---|
| file read / write | `capfs` が backing read / write を発行した瞬間 |
| create / remove / rename / truncate / metadata | 対応する backing syscall を発行した瞬間 |
| 公開 Web 取得 | Host Broker が検証済み outbound request を受理した瞬間 |
| 認証 API | Host Broker が idempotency key 付き request を永続的に受理した瞬間 |

revoke は、これより前の操作を巻き戻すものではない。

## KillSubject

Authority core の `begin_subject_close` は subject を `Closing` にして新規操作を止め、held Capability を revoke して `auth_epoch` を進める。supervisor はその後にコンテナの cgroup、control fd、open handle、`capfs` mount を片付ける。live handle がゼロになってから `finish_subject_close` を呼び、`Closed` にする。

すでに Host Broker が受理した外部操作だけは続行し得る。

## 設計の背景

派生元を明示した tree と祖先 revoke は、seL4 の capability derivation tree と descendant revocation の考え方を参考にしている。[seL4 Reference Manual](https://sel4.systems/Info/Docs/seL4-manual-latest.pdf)

また「既存 authority から作る authority は縮小だけ」という方向は、FreeBSD Capsicum の `cap_rights_limit` が rights を追加できず削減だけを許す性質とも一致する。[FreeBSD `cap_rights_limit(2)`](https://man.freebsd.org/cgi/man.cgi?query=cap_rights_limit&sektion=2)

どちらもこの実装の正しさを自動的に証明するものではない。ここでは、派生 link を保存する理由と、権限変更を単調な縮小に限定する設計上の先例として参照している。

## 関連文書

- [Capability モデル](capability-model.md)
- [Capability の発行と逐次状態機械](../authority-core/capability-state.md)
- [Effect commit と revoke の authorization guard](../authority-core/authorization-guard.md)
- [Subject lifecycle と open handle](../authority-core/subject-lifecycle-and-handles.md)
- [Attempt / effect audit](../authority-core/audit-records.md)
- [capfs](capfs.md)
- [ネットワークと外部副作用](network-egress.md)
