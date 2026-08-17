<!-- doc-type: design -->

# 隔離基盤

[設計書一覧](README.md) / 隔離基盤

> **対象読者:** 隔離境界の設計者、runtime-isolation と Firecracker の実装者

ここでは「同じ安全機構を何枚も重ねる」のではなく、各レイヤに違う仕事を持たせる。上のレイヤほど細かく判断し、下のレイヤほど大きな被害を止める。

## 6つの防御レイヤ

レイヤは 1 列に並んでいない。**閉じ込め**は入れ子で、**判定**は経路の上に乗る。workload が起こせることは 2 種類しかなく、file 操作と外部副作用で通る門が違う。

```mermaid
flowchart TB
    subgraph hostside["host"]
        broker["Host Egress Broker<br/>型付き 2 操作だけ<br/>現在の Capability を見る"]
        ext["公開 Web / GitHub API"]
        cred[("credential<br/>host から出ない")]
    end

    subgraph vm["Firecracker + jailer — session 全体の境界"]
        direction TB
        sup["supervisor"]
        capfs["capfs<br/>操作ごとに現在の Capability を見る"]
        ws[("subject 専用 workspace")]

        subgraph ns["namespace + cgroup v2 — process と resource の分離"]
            direction TB
            subgraph limits["exec 前に固定した上限"]
                direction LR
                sec{{"seccomp<br/>syscall の入口を削る"}}
                ll{{"Landlock<br/>path 単位の envelope"}}
            end
            wl["Agent / Tool"]
        end
    end

    wl ==>|"file syscall"| sec
    sec ==>|"allowlist を通った syscall だけ"| ll
    ll ==>|"envelope 内の path だけ"| capfs
    capfs ==> ws

    wl ==>|"外部への要求"| sup
    sup ==>|"AF_VSOCK"| broker
    cred --> broker
    broker ==>|"TLS"| ext

    classDef dynamic fill:#2e7d32,color:#fff,stroke:#1b5e20;
    classDef static fill:#1565c0,color:#fff,stroke:#0d47a1;
    classDef boundary fill:#6a1b9a,color:#fff,stroke:#4a148c;
    classDef untrusted fill:#b71c1c,color:#fff,stroke:#7f0000;
    classDef data fill:#ef6c00,color:#fff,stroke:#e65100;
    class capfs,broker dynamic;
    class sec,ll static;
    class vm,ns boundary;
    class wl untrusted;
    class ws,cred,ext data;
```

図の読み方は 3 つ。

**枠は閉じ込め、矢印は判定。** `Firecracker` と `namespace + cgroup v2` は経路上の 1 段ではなく、内側で起きたことの被害範囲を決める入れ子の枠である。破られたときに何が漏れるかは、その枠が何を囲っているかで決まる。

**file syscall と外部要求は別の門を通る。** file 操作は seccomp → Landlock → capfs の順に 3 回判定される。順序は kernel が決めるもので、seccomp が「その syscall を呼べるか」、Landlock が「その path に触れてよいか」、capfs が「今この Capability で許されるか」を見る。一方、外部への要求は file syscall を 1 度も通らない。supervisor 経由で vsock に出て、host 側の Broker が型付き操作として判定する。**Broker に file 操作は届かないし、capfs に外部要求は届かない。**

**緑と青で判定の性質が違う。** 緑（`capfs` と Broker）は現在の Capability を毎回見るので、revoke がその場で効く。青（seccomp と Landlock）は exec 前に固定した上限で、後から広げられない。狭い方に倒すのが青、追随するのが緑という分担になっている。

credential が host 側の枠から出ていないことも図に含めてある。guest はどの経路でも token に触れない。

## guest composition と workload gate

guest の composition は [`guest-supervisor-init`](../../crates/supervisor/src/bin/guest-supervisor-init.rs) が所有する。PID 1 の [`guest-control-init`](../../crates/firecracker-runtime/src/bin/guest-control-init.rs) は host CID 2 から identity bundle を一度受け取り、image に固定された guest supervisor を起動する。supervisor は固定された repository / file effect / path policy から guest `CapabilityKernel` と CapFS runtime を作り、control listener と Broker channel を準備してから `guest-supervisor-ready/v1` を返す。readiness を返す前に workspace mount、CapFS、subject bootstrap、isolation control listener、workload 側接続を全て成立させる。

workload の起動は supervisor が任意の command を受け取る API ではない。`LinuxHostResources` は image-configured `workload-isolation-launcher` を unnamed socketpair の stdin/stdout だけで起動し、launcher が正確な `ready` を返すまで release byte を送らない。launcher は `RuntimeIsolation::spawn_isolated` の child startup に加えて、CLOEXEC の exec-status writer を workload child に渡す。exec 成功時は fd が閉じて EOF になり、exec 失敗・不正 marker・timeout は `isolated` を返さず fail closed にする。supervisor/launcher の両方が ambient environment を clear し、必要な identity / channel fd だけを明示する。

これは実装されたguest pathである。runtime-isolationのprivileged probeはproduction launcherと`execve`後のworkloadを直接通し、post-execのkernel enforcementを確認する。mutableなhost rootを試験都合でremountしないため、`rootfs.source == "/"` はreadonly SquashFS rootを使うKVM SessionOwner gateで確認する。

## コンテナを起動する順番

```mermaid
sequenceDiagram
    participant S as Supervisor
    participant C as Container child
    participant K as guest kernel

    S->>K: namespace 付き child を生成
    S->>K: UID/GID map と cgroup を設定
    S->>C: rootfs / capfs / tmpfs を配置
    S->>C: 不要 fd を閉じる
    S->>C: Landlock envelope を適用
    S->>C: Linux capability を全 drop
    S->>C: no_new_privs + seccomp
    S->>C: inherited start gate の ready を受信
    S->>C: release byte を送信
    S->>C: 13 step isolation を適用
    S->>C: close-on-exec EOF を確認
    S->>C: workload を execve
```

順番を崩すと、制限前に開いた fd や余分な権限が残る。workload は、すべての制限が有効になるまで1命令も実行させない。

起動後に見えるものは次に限る。

- read-only rootfs。
- subject 専用の `/workspace` (`capfs`)。
- size 制限付き tmpfs。
- 最小限の `/proc` と `/dev`。
- 自分専用の control socket。

block device、backing mount、`/dev/fuse`、host TTY、外部 network interface は見せない。PID namespace の PID 1 は子プロセスを reap する。

## Landlock と seccomp の分担

Landlock には、subject 生成時に決めた file envelope を入れる。現在保持している Capability ではない。後から追加できる file Capability はこの envelope の内側だけなので、Landlock を緩める必要がない。

guest kernel の ABI を固定し、read、write、truncate、create、remove、refer を別々に扱う。必要な ABI がなければ起動を止める。Landlock が扱えない metadata 操作は `capfs` で拒否する。[Linux Landlock documentation](https://docs.kernel.org/userspace-api/landlock.html)

seccomp は default deny とし、少なくとも mount、追加 namespace、kernel module、`ptrace`、`process_vm_*`、`bpf`、`perf_event_open`、外部 network socket、`MAP_SHARED` を禁止する。

## Firecracker の役割

Firecracker は subject 間の細かい権限を知らない。guest 全体が壊れたときに、被害をそのセッションへ閉じるのが役目である。

- 1 VM に 1 つの相互信頼グループ。
- rootfs は read-only virtio-blk + dm-verity。
- workspace は VM ごとの read-write virtio-blk。
- host との通信は virtio-vsock。
- 標準 profile では virtio-net を付けない。
- Firecracker 自身も jailer、host namespace、cgroup、標準 seccomp filter で囲う。

## snapshot は「セッション開始前」で止める

```mermaid
sequenceDiagram
    participant H as Host
    participant V as microVM
    participant B as Egress Broker

    H->>V: guest boot
    V->>V: session 初期化前の待機点へ
    H->>V: pause を要求
    V-->>H: pause acknowledgement
    H->>H: snapshot を保存したまま paused
    Note over H,V: root / subject / credential / user workspace はまだ無い
    H->>V: snapshot restore（resume_vm=false）
    H->>V: 専用 workspace を接続
    V->>V: 新しい ID と乱数状態を用意
    V->>B: 新しい vsock session を確立
    H->>V: root Capability を注入
    V->>V: Agent 受付開始
```

同じ snapshot から複数 VM を起動すると、乱数や ID まで複製され得る。そこで snapshot にセッション固有状態を入れず、restore 後に VM / session / subject / Capability / request ID を作り直す。workspace block image も clone ごとに分ける。[Firecracker snapshot security](https://github.com/firecracker-microvm/firecracker/blob/main/docs/snapshotting/snapshot-support.md?plain=1)

実装上は `WorkloadStopped` から Firecracker の pause acknowledgement を受けて `SnapshotPaused` に遷移してから snapshot files を書く。pause 自体の応答が失われた場合は `SnapshotPauseUnknown`、write/hash が失敗した場合も paused state を再利用せず shutdown に進む。fake/runtime testでfail-closed状態機械を、production SessionOwner KVM gateでclean snapshot capture／restore、rebind、resumeを確認済みである。

## 関連

- [脅威モデル](threat-model.md)
- [capfs](capfs.md)
- [ネットワークと外部副作用](network-egress.md)
