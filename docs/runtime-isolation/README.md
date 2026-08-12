<!-- doc-type: index -->

# runtime-isolation

[ドキュメント一覧](../README.md) / runtime-isolation

> **対象読者:** guest workload を exec する直前の境界を触る実装者、特権操作のレビュー担当者

`runtime-isolation` は、workload を `execve` する直前に一度だけ実行される取引である。namespace、mount、cgroup、Landlock、capability、seccomp を決まった順に積み上げ、全部成功したら [`IsolationReceipt`](../../crates/runtime-isolation/src/backend.rs) を返す。途中で失敗したら、戻せるものだけ戻して失敗を返す。

この crate は VM の中で動く。VM 境界そのものは [firecracker-runtime](../firecracker-runtime/README.md)、VM 内 subject の lifecycle は [supervisor](../supervisor/README.md) が持つ。ここが守るのは、その内側でさらに 1 プロセスを閉じ込める部分だけ。

## crate の構造

`apply` は 13 step を 1 列に流すが、step は性質で 4 つに分かれる。**戻せるのは cgroup と mount だけ**で、残りは kernel 上で一方向にしか進まない。

```mermaid
flowchart TB
    sup["supervisor が fork した child"]

    subgraph pre["副作用の前（純粋 / 読むだけ）"]
        direction LR
        sc["SeccompPolicy<br/>禁止 syscall を型で閉じる"]
        cfg["IsolationConfig::validate<br/>危険な組み合わせを落とす"]
        det["detect_capabilities<br/>host を調べる。何も変えない"]
    end

    subgraph apply["RuntimeIsolation::apply — 13 step を固定順で"]
        direction TB
        p1["1-2 namespace / UID・GID map<br/>この namespace の中で root 相当になる"]
        p2["3-8 cgroup / rootfs pivot /<br/>workspace / tmpfs / proc・dev mask"]
        p3["9 継承 fd を閉じる<br/>proc を覆った後でないと取り戻せる"]
        p4["10-13 Landlock / capability drop /<br/>no_new_privs / seccomp"]
        p1 --> p2 --> p3 --> p4
    end

    backend{{"IsolationBackend"}}
    linux["LinuxBackend"]
    kern["namespace / cgroup v2 / mount /<br/>Landlock / seccomp"]

    receipt[("IsolationReceipt<br/>全 step 成功時のみ")]
    wl["workload（execve 後）"]
    dead["child を終了させ再利用しない"]

    sup ==> pre
    pre -->|"不足なら CapabilityUnavailable"| dead
    pre ==> apply
    apply --> backend --> linux ==> kern
    apply ==>|"成功"| receipt
    receipt ==>|"exec"| wl
    receipt -.->|"audit event に添付"| sup
    apply -->|"失敗。戻せた分だけ戻す"| dead

    classDef pure fill:#1565c0,color:#fff,stroke:#0d47a1;
    classDef reversible fill:#2e7d32,color:#fff,stroke:#1b5e20;
    classDef oneway fill:#b71c1c,color:#fff,stroke:#7f0000;
    classDef seam fill:#6a1b9a,color:#fff,stroke:#4a148c;
    classDef data fill:#ef6c00,color:#fff,stroke:#e65100;
    classDef external fill:#616161,color:#fff,stroke:#424242;
    class sc,cfg,det pure;
    class p2 reversible;
    class p1,p3,p4 oneway;
    class backend seam;
    class sup,linux,kern,wl,dead external;
    class receipt data;
```

**赤い 3 つは戻せない。** namespace から出ることも、`pivot_root` の前の root へ帰ることも、消した capability を戻すこともできない。だから rollback は緑の 1 群にしか効かず、赤に入った後で失敗したら child ごと捨てる（[ADR 0016](../decisions/0016-terminate-the-child-after-an-unrollbackable-isolation-failure.md)）。

**青は 1 つも副作用を持たない。** 設定ミスと host の不足は、namespace を作る前に落ちる。ここを通過してから失敗すると、もう元のプロセスには帰れない。

順序が効く箇所は 3 つある。`/proc` を覆う前に fd を閉じると `/proc/self/fd` から取り戻せる。`no_new_privs` より先に seccomp を入れると kernel が拒否する。`pivot_root` より先に Landlock を張ると、宣言した path が旧 root 基準で解決される。詳細は [13 step の固定順序と rollback](apply-order.md)。

## 実装範囲と検証境界

ポリシー型と 13 step の順序制御、seccomp allowlist の検査は完成していて、mock backend で検証済み。実際に syscall を叩く [`LinuxBackend`](../../crates/runtime-isolation/src/linux.rs) は書いてあるが、user namespace と cgroup v2 と Landlock が揃った環境でしか動かせないため、CI では capability detection の分岐までしか通っていない。

つまり「隔離が実際に効いている」ことはまだ確認できていない。詳細は[検証対応表](verification.md)。

## 文書一覧

| 文書 | 対象ソース | 内容 |
|---|---|---|
| [ポリシーの事前検査](isolation-config.md) | [`config.rs`](../../crates/runtime-isolation/src/config.rs) | syscall を 1 つも呼ぶ前に落とす条件。mount target の衝突、tmpfs 上限、cgroup 名 |
| [13 step の固定順序と rollback](apply-order.md) | [`backend.rs`](../../crates/runtime-isolation/src/backend.rs) | なぜこの順序なのか、戻せない step をどう扱うか |
| [seccomp allowlist](seccomp-allowlist.md) | [`syscall.rs`](../../crates/runtime-isolation/src/syscall.rs) | 禁止 syscall を型で閉じる方法、arch 依存の番号 |
| [Landlock envelope](landlock-envelope.md) | [`linux.rs`](../../crates/runtime-isolation/src/linux.rs) | rootfs と workspace に渡す access bit の差 |
| [検証対応表](verification.md) | — | mock で見た範囲と、実機で未確認の範囲 |

## 関連

- [隔離基盤の設計](../design/runtime-isolation.md)
- [Firecracker runtime](../firecracker-runtime/README.md)
- [Supervisor adapter](../supervisor/README.md)
- [決定記録](../decisions/README.md)
- [用語集](../glossary.md)
