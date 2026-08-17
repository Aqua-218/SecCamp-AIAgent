<!-- doc-type: concept -->

# 13 step の固定順序と rollback

[runtime-isolation](README.md) / 13 step の固定順序と rollback

> **対象読者:** isolation backend を触る実装者、起動失敗時の後始末をレビューする人

[`backend.rs`](../../crates/runtime-isolation/src/backend.rs) の `required_steps()` は 13 個の `IsolationStep` を配列リテラルで返す。設定で並べ替えられないし、一部だけ実行することもできない。この配列が固定されている理由と、途中で失敗したときに何が起きるかを書く。

## 何を防ぎたいのか

隔離の各操作には依存関係がある。順序を 1 つ入れ替えるだけで、境界に穴が開く。

たとえば seccomp を先に入れてしまうと、その後の `mount` や `pivot_root` が自分の filter に引っかかって失敗する。逆に Landlock を `pivot_root` より先に張ると、宣言した path は旧 root 基準で解決され、pivot 後の workload には別の tree が見えてしまう。

もっと分かりやすいのは `/proc` の masking と descriptor の close の関係。

```text
危険な順序: fd を閉じる -> /proc を覆う
            ↓
            覆う前に /proc/self/fd を開いておけば、閉じたはずの fd を取り戻せる

実際の順序: /proc を覆う -> fd を閉じる
```

`no_new_privs` も同じで、これを設定する前に seccomp filter を入れると、非特権プロセスでは `seccomp(2)` 自体が `EACCES` を返す。kernel 側の前提条件なので、順序ではなく依存として扱っている。

```mermaid
flowchart TB
    ns["1 Namespaces<br/>USER NS PID NET IPC UTS CGROUP"] --> idmap["2 IdentityMap<br/>setgroups=deny 後に単一 map"]
    idmap --> cg["3 CgroupV2<br/>memory.max / pids.max"]
    cg --> rootfs["4 ReadOnlyRootfs<br/>bind + remount ro + pivot_root"]
    rootfs --> ws["5 Workspace"]
    ws --> tmp["6 LimitedTmpfs"]
    tmp --> proc["7 MaskProc"]
    proc --> dev["8 MaskDevices"]
    dev --> fd["9 CloseInheritedFileDescriptors"]
    fd --> ll["10 Landlock"]
    ll --> caps["11 DropCapabilities"]
    caps --> nnp["12 NoNewPrivs"]
    nnp --> sec["13 Seccomp"]
    sec --> exec["execve"]
```

## なぜ user namespace が最初なのか

`CLONE_NEWUSER` を含む `unshare` が成功すると、その namespace の中では root 相当の capability を持つ。以降の `mount`、`pivot_root`、cgroup への書き込みは、host の root 権限ではなくこの namespace 内の権限で行う。逆に言えば、user namespace を作れない host ではこの crate は何もできない。

`IdentityMap` で `/proc/self/setgroups` に `deny` を書いてから UID/GID map を書く順序は、kernel が要求する。`setgroups` を許可したまま map を書くと、supplementary group を落として権限を得る古い攻撃が成立するため、非特権 user namespace では書き込み自体が拒否される。

## 戻せる step と戻せない step

`RuntimeIsolation::apply` は成功した step を `completed` に積み、どれかが失敗したら逆順に `rollback_step` を呼ぶ。

```rust
Err(original) => {
    let failures = completed
        .iter()
        .rev()
        .filter_map(|completed_step| backend.rollback_step(*completed_step, config).err())
        .collect::<Vec<_>>();
```

問題は、13 step のうち大半が kernel 上で戻せないこと。namespace から出ることはできないし、`pivot_root` の前の root には帰れない。Landlock ruleset、消した capability、`no_new_privs`、seccomp filter も同様で、いずれも一方向にしか進まない。

| step | rollback |
|---|---|
| `Namespaces` | 不可 |
| `IdentityMap` | 不可 |
| `CgroupV2` | 可。作った cgroup を削除する |
| `ReadOnlyRootfs` | `pivot_root` 前なら unmount 可、後は不可 |
| `Workspace` / `LimitedTmpfs` / `MaskProc` / `MaskDevices` | 可。unmount する |
| `CloseInheritedFileDescriptors` | 不可 |
| `Landlock` | 不可 |
| `DropCapabilities` | 不可 |
| `NoNewPrivs` | 不可 |
| `Seccomp` | 不可 |

production backend は戻せない step について `rollback_step` から `BackendError` を返す。これは実装漏れではなく、明示的な申告である。

## 部分成功を成功として扱わない

rollback に 1 つでも失敗すると `IsolationError::Rollback` が返り、元の失敗と rollback 失敗の一覧が両方入る。

```rust
IsolationError::Rollback {
    original: BackendError,
    failures: Vec<BackendError>,
}
```

呼び出し側がここでやってはいけないのは、「namespace は作れたし mount も済んでいるから、seccomp だけ諦めて続行する」という判断。境界が 1 つ欠けた状態は、境界が無い状態と同じくらい危険なことがある。seccomp が無ければ workload は `socket` を呼べるし、capability を消していなければ mount を張り直せる。

supervisor は `Rollback` を受け取ったら child を再利用せず終了させる。この判断は [ADR 0016](../decisions/README.md) に記録する予定。

## `apply` を呼ぶ場所を間違えない

`create_namespaces` は `CLONE_NEWPID` を unshare する。`unshare(CLONE_NEWPID)` は呼び出したプロセス自身を新しい PID namespace に入れず、次に `fork` した子から適用される。したがって、この取引は「workload を exec する側の child」で開始しなければならない。親 supervisor が自分のプロセスで `apply` を呼ぶと、PID namespace が意図した位置にできない。

同じ理由で、rootfs の staging directory は `apply` を呼ぶ前に親が用意しておく必要がある。

## 何が助かるのか

順序が配列リテラル 1 箇所に固定されているので、「この操作はいつ実行されるのか」を追うのに実装を読む必要がない。step を増やすときも、依存関係を検討する場所が 1 つに絞られる。

receipt に完了 step が順番どおり入るため、supervisor の audit event に添付すれば「exec 前の境界が完成した」ことの機械的な証拠になる。ログの文字列ではなく型で残るので、後から欠けた step を検出できる。

## step 4 が step 7 の mount を用意する理由

`MaskProc` は `/proc` の境界を所有する step だが、staged rootfs 経路ではその procfs 自体を step 4 で作る。kernel の制約による。

user namespace の中で新しい procfs を mount するには、その mount namespace に完全に可視な procfs が既に存在していなければならない（`fs/namespace.c` の `mount_too_revealing`）。step 4 の `pivot_root` は継承した procfs を切り離すので、その後に新規 mount を試みると必ず `EPERM` になる。private な procfs を作れる時点は、継承 mount がまだ見えている step 4 しかない。

```text
step 4 で staging しない場合:
  pivot_root で継承 procfs を切り離す -> step 7 で新規 mount -> EPERM で必ず失敗

実際の順序:
  step 4: 継承 procfs が見えているうちに staged rootfs へ private procfs を mount
  step 7: その mount が procfs であり、必要な制限を全て持つことを kernel に問い直す
```

これは workspace と同じ形である。workspace の bind も step 4 で staging され、step 5 が hardening flag つきで remount して確定させる。`MaskProc` が境界の所有者であることは変わらず、mount flag を staging 時の呼び出しから推定せず `statfs` と `statvfs` で読み直すため、step 7 は実質的な検査であり続ける。

既に immutable な root から起動した guest（`rootfs.source == "/"`）は pivot しないので継承 procfs を見失わない。この経路では `MaskProc` が従来どおり新しい procfs を mount する。

## 正確な保証範囲

mock backend が保証するのは、13 step が定義順に呼ばれ、失敗時に完了済み step が逆順に rollback されることだけ。

[`tests/privileged_isolation.rs`](../../crates/runtime-isolation/tests/privileged_isolation.rs) が実 kernel 上で 13 step を適用し、完成した境界の内側から観測することで、次を確認している。staged rootfs 経路、`execve` を挟まない場合に限る。

- 13 step が実 syscall で完走し、launcher が `Ready` を受け取ること。
- seccomp filter、Landlock ruleset、read-only rootfs、device masking、fd の一掃、capability の剥奪が、それぞれ kernel によって強制されていること。
- 途中で失敗した step が launcher に正しく報告され、host 側の cgroup が解放されること。

次は依然として保証していない。

- unmount による rollback が実際に元の状態へ戻ること。失敗を注入できたのは `pivot_root` 後の `Landlock` で、そこは crate 自身が「戻せない」と申告する位置にある。確認できたのは cgroup の解放だけ。
- `rootfs.source == "/"` の guest 経路。probe は staged rootfs 経路だけを通る。
- exec 後の workload が境界を越えられないこと。probe は child 内で直接観測しており、exec を挟んでいない。
- VM 境界。host から見た隔離は [firecracker-runtime](../firecracker-runtime/README.md) の担当。

正確な線引きは [検証対応表](verification.md) にある。

## 変更時の確認点

- step を増やすときは `required_steps()` の配列、`IsolationStep` enum、`Display` 実装、`LinuxBackend::apply_step` の match、rollback 可否の申告を同時に直す。match は網羅性検査があるので実装漏れは compile error になるが、**配列への追加は忘れても compile が通る**。ここが一番踏みやすい。
- 順序を変えるときは、この文書の依存関係（`/proc` mask と fd close、`no_new_privs` と seccomp、`pivot_root` と Landlock）を先に読み直す。
- rollback 可否を「可」へ変えるときは、その操作が本当に戻るのか kernel の挙動を確認する。申告だけ変えると、部分成功を成功と誤認する経路ができる。

## 関連

- [ポリシーの事前検査](isolation-config.md)
- [seccomp allowlist](seccomp-allowlist.md)
- [Landlock envelope](landlock-envelope.md)
- [検証対応表](verification.md)
- [隔離基盤の設計](../design/runtime-isolation.md)
- [用語集](../glossary.md)
