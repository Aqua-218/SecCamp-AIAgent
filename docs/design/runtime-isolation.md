# 隔離基盤

[設計書一覧](README.md) / 隔離基盤

ここでは「同じ安全機構を何枚も重ねる」のではなく、各レイヤに違う仕事を持たせる。上のレイヤほど細かく判断し、下のレイヤほど大きな被害を止める。

## 6つの防御レイヤ

```mermaid
flowchart TB
    effect["外部サービスの副作用"]
    broker["Host Egress Broker<br/>API と公開 Web の上限"]
    vm["Firecracker<br/>セッション全体の境界"]
    container["namespace + cgroup v2<br/>process と resource の分離"]
    landlock["Landlock<br/>subject の静的 file envelope"]
    seccomp["seccomp<br/>syscall の入口を削る"]
    capfs["capfs<br/>現在の細粒度 file authority"]
    workload["Agent / Tool"]

    workload --> capfs --> seccomp --> landlock --> container --> vm --> broker --> effect

    classDef dynamic fill:#2e7d32,color:#fff;
    classDef static fill:#1565c0,color:#fff;
    classDef boundary fill:#6a1b9a,color:#fff;
    class capfs,broker dynamic;
    class seccomp,landlock,container static;
    class vm boundary;
```

`capfs` と Broker は現在の Capability を見る。Landlock 以下は、起動時に決めた上限を後から広げない。

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
    H->>H: snapshot を保存
    Note over H,V: root / subject / credential / user workspace はまだ無い
    H->>V: snapshot restore
    H->>V: 専用 workspace を接続
    V->>V: 新しい ID と乱数状態を用意
    V->>B: 新しい vsock session を確立
    H->>V: root Capability を注入
    V->>V: Agent 受付開始
```

同じ snapshot から複数 VM を起動すると、乱数や ID まで複製され得る。そこで snapshot にセッション固有状態を入れず、restore 後に VM / session / subject / Capability / request ID を作り直す。workspace block image も clone ごとに分ける。[Firecracker snapshot security](https://github.com/firecracker-microvm/firecracker/blob/main/docs/snapshotting/snapshot-support.md?plain=1)

## 関連文書

- [脅威モデル](threat-model.md)
- [capfs](capfs.md)
- [ネットワークと外部副作用](network-egress.md)
