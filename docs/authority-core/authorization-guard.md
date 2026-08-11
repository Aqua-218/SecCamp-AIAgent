# Effect commit と revoke の authorization guard

[Authority core 実装ガイド](README.md) / Authorization guard

このページは [`crates/authority-core/src/kernel.rs`](../../crates/authority-core/src/kernel.rs) が、Capability の最終認可から外部 effect の線形化点までを revoke とどう競合させるか説明する。Capability の発行・保持・祖先失効は[逐次状態機械](capability-state.md)を参照する。

## 認可と実行を別々にすると何が起きるか

次の順序では、個々の処理が正しくても revoke 完了後に effect が成立する。

```text
effect thread: Capability を確認する → 有効
revoke thread: revoke を記録する → return
effect thread: backing write を発行する
```

これは check と use の間で状態が変わる TOCTOU である。認可時に revoke 集合を正しく確認するだけでは閉じられない。

`CapabilityKernel` は `CapabilityState` 全体を reader-writer lock で保護する。effect は shared read guard、revoke と発行 transition は exclusive write guard を使う。

```mermaid
flowchart LR
    request["effect request"] --> read["shared guard"]
    read --> authorize{"final authorization"}
    authorize -->|"deny"| denied["executor を呼ばず拒否"]
    authorize -->|"allow"| execute["linearization point まで実行"]
    execute --> release["shared guard を解放"]

    revoke["revoke request"] --> write["exclusive guard"]
    write --> mark["revoked set に追加"]
    mark --> returned["guard を解放して return"]

    classDef shared fill:#1565c0,color:#fff;
    classDef exclusive fill:#b71c1c,color:#fff;
    class read,authorize,execute,release shared;
    class write,mark,returned exclusive;
```

同時に複数の認可済み effect が走ることは許すが、revoke はそれらが線形化点を越えて shared guard を返すまで待つ。

## 公開型の責務

| 型 | 責務 |
|---|---|
| `CapabilityKernel` | `CapabilityState` を同期境界に入れ、発行 transition、revoke、effect commit を直列化する |
| `CapabilityKernelError` | lock poisoning と逐次状態機械の typed error を区別する |
| `EffectCommitError<E>` | lock poisoning、認可拒否、executor のpre-commit失敗を区別する |

`register_subject`、`issue_root`、`derive`、`revoke` は exclusive guard の内側で既存の逐次 transition を呼ぶ。逐次状態機械の検査条件を複製せず、同期だけを外側に追加している。

## `authorize_and_commit`

`authorize_and_commit` は次の順序を1回の呼び出しに閉じ込める。

```text
shared guard を取得
→ caller / held / ancestor / time / request を最終確認
→ 認可に使った Capability の参照を executor へ渡す
→ executor が線形化点まで進む
→ shared guard を解放
```

Capability の参照は read guard 内の `CapabilityState` を借用している。この参照を executor 呼び出しへ渡すことで、lock の寿命が認可判定だけで終わらずexecutor完了まで続く。

認可が失敗した場合、executor は呼ばれず `EffectCommitError::NotAuthorized` を返す。executor が線形化点より前に失敗した場合は `EffectCommitError::Effect(error)` となる。

## Executor が守る契約

lock は外部 syscall がどこで成立したかを自動判定できない。`commit_to_linearization` closure は次を守る必要がある。

- backing syscall や Broker acceptance など、操作ごとに定義した線形化点を越えてから成功を返す。
- 線形化点より前の失敗だけを `Err` として返す。
- 処理を別 thread へ投げただけで成功を返さない。
- closure 内から同じ `CapabilityKernel` の `revoke`、`derive`、発行 API を呼ばない。shared guard を持ったまま exclusive guard を要求するとdeadlockし得る。

そのため `authorize_and_commit` が保証するのは、closureがこの契約を守る場合の認可とrevokeの順序である。filesystem adapter や Broker adapter が間違った線形化点でreturnすれば、その外部処理まで自動的に安全にはならない。

## Revoke と effect の2つの順序

### Effect が先に shared guard を取る

```mermaid
sequenceDiagram
    participant E as Effect
    participant K as CapabilityKernel
    participant R as Revoker

    E->>K: shared guard + final authorization
    R->>K: exclusive guard を要求
    Note over R,K: shared guard の解放待ち
    E->>E: linearization point
    E->>K: shared guard を解放
    K->>R: exclusive guard
    R->>K: revoked に追加
    K-->>R: revoke return
```

effect は revoke より先に成立した操作であり、revoke は巻き戻さない。

### Revoke が先に exclusive guard を取る

revoke が `revoked` へ追加してreturnした後、effect は shared guard を取得する。最終認可が祖先chainのrevokeを検出するため、executorは呼ばれない。

したがって、revoke がreturnした後に、失効したCapabilityだけを根拠とする新しいeffect commitは発生しない。

## Lock failure は fail closed にする

標準 `RwLock` は、exclusive writer がpanicするとpoisonedになる。kernelはpoisonを無視して内部状態を再利用せず、以後のtransitionとeffectをtyped errorで拒否する。reader内のpanicだけでは標準 `RwLock` はpoisonされないが、executorのpanicは通常どおりcallerへ伝播する。[Rust `RwLock` documentation](https://doc.rust-lang.org/std/sync/struct.RwLock.html)（2026-08-11参照）

標準 `RwLock` はreaderとwriterの取得順序やwriter starvationを保証しない。この実装が閉じるのはauthorization safetyであり、revoke latencyの上限ではない。運用で待ち時間上限が必要になった場合は、計測した上でfair lockまたは直列executorを別途評価する。

## Loom が検査するもの

通常buildでは `std::sync::RwLock` を使う。`RUSTFLAGS='--cfg loom'` を付けたmodel testでは、同じ `CapabilityKernel` のlockだけを `loom::sync::RwLock` へ差し替える。

[`crates/authority-core/tests/authorization_kernel_loom.rs`](../../crates/authority-core/tests/authorization_kernel_loom.rs) には2つのmodelがある。

| Model | 期待する結果 | 確認すること |
|---|---|---|
| production guard | 全interleavingでpass | executorが走るならrevoke returnより前、revokeが先なら認可拒否になる |
| unlocked negative control | 指定したassertionでpanic | 認可直後にguardを解放すると、revoke return後のcommit順序が実在する |

negative controlは「壊れた実装もtestが緑になる」ことを防ぐ検査である。loomはthread実行順を繰り返し変え、bounded model内の可能な並行実行を探索する。[Loom documentation](https://docs.rs/loom/latest/loom/model/fn.model.html) / [Loom repository and limitations](https://github.com/tokio-rs/loom)（2026-08-11参照）

実行コマンドは次のとおり。

```bash
RUSTFLAGS='--cfg loom' cargo test --package authority-core --test authorization_kernel_loom
RUSTFLAGS='--cfg loom' cargo clippy --package authority-core --test authorization_kernel_loom -- -D warnings
```

## 正確な保証範囲

現在のmodelは1件のeffectと1件の直接revokeを同じroot Capability上で競合させる。`CapabilityState::authorizes` が祖先chainを辿ることは逐次testで別に確認している。

次はまだ含まれない。

- attempt/effect log と `auth_epoch`。
- open handle、rename、unlinkを含むfilesystem固有の競合。
- executor adapterが実際のsyscallを正しい線形化点まで実行すること。
- writer fairness、revoke latency、負荷時の性能。
- 3 thread以上、複数Capability、複数effectを組み合わせたmodel。
- Rust状態機械やlock実装全体の数学的証明。

loom自身にもC11 memory modelの未対応部分があるため、bounded modelのpassを実システム全体の証明とは扱わない。今回のmodelはatomicだけで認可を組み立てず、reader-writer lockの排他順序を検査対象にしている。

## 関連

- [Capability の発行と逐次状態機械](capability-state.md)
- [検証とテスト](verification.md)
- [状態機械と revoke の設計](../design/state-and-revocation.md)
- [検証戦略](../design/verification.md)
- [実装順序](../design/implementation-plan.md)
