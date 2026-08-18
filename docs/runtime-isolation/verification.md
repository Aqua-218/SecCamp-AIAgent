<!-- doc-type: verification -->

# 検証対応表

[runtime-isolation](README.md) / 検証対応表

> **対象読者:** runtime-isolation の実装者、レビュー担当者、特権環境で統合 test を回す人

この crate の検証は 2 層ある。mock backend による順序制御・設定検査・BPF プログラムの形の確認と、実 kernel 上で 13 step を適用して境界を kernel に問い直す確認。privileged probe は API 直呼びの staged rootfs と、実際の `workload-isolation-launcher` を起動して固定 workload を `execve` する経路の両方を持つ。guest 側には別に `guest-supervisor-init` → `LinuxHostResources` → `workload-isolation-launcher` の実装と opt-in Firecracker runtime-image test がある。前者だけでは「隔離が効いている」ことは言えないので、どの層で何が言えるのかを分けて書く。

## local test で確認したこと

| 境界 | 検証手段 | test |
|---|---|---|
| 13 step が定義順に実行される | 記録型 mock backend | `successful_apply_enforces_the_security_order` |
| 失敗時に完了済み step が逆順に rollback される | 記録型 mock backend | `a_failed_step_rolls_back_every_completed_step_in_reverse_order` |
| capability 不足を mutation 前に検出する | mock backend | `insufficient_capabilities_are_reported_before_any_mutation` |
| Landlock ABI が要求値未満なら起動しない | mock backend | `a_kernel_with_an_older_landlock_abi_is_rejected` |
| 不正 path と無制限 tmpfs を backend 呼び出し前に落とす | 純粋関数 | `malformed_paths_and_unbounded_tmpfs_are_rejected_before_backend_calls` |
| network / namespace syscall を allowlist に入れられない | 純粋関数 | `forbidden_network_and_namespace_syscalls_are_rejected_from_allowlist` |
| Landlock writable path が workspace の外に出られない | 純粋関数 | `writable_landlock_paths_cannot_escape_the_workspace` |
| 空 allowlist を拒否する | 純粋関数 | `empty_allowlist_is_rejected_instead_of_installing_an_unstartable_filter` |
| receipt が成功後に書き換わらない | 純粋関数 | `receipt_is_immutable_after_success` |
| 既定 policy の BPF が非 allowlist syscall を `EPERM` に落とす | 生成した命令列の検査 | `seccomp_filter_denies_every_non_allowlisted_syscall` |
| allowlist が 1 個でも filter が正しく分岐する | 生成した命令列の検査 | `seccomp_filter_without_mmap_reaches_errno_for_unknown_syscalls` |
| workspace mask はCapFS管理下のsymlinkを許し、device / socket / FIFO作成は許さない | 定数の bit 検査 | `landlock_workspace_rights_allow_capfs_symlinks_but_not_special_files` |
| Rust標準filesystem APIが実際に使うpath syscallを既定seccomp policyが許す | allowlist検査 | `conservative_seccomp_policy_covers_standard_library_capfs_operations` |
| capability detection が不足理由を必ず添える | 実 host への query | `privileged_integration_prerequisites_are_reported_without_an_ignored_test` |

test double は 1 つだけ。`IsolationBackend` を実装した記録型 mock が、呼ばれた step と順序を `Vec` に積む。この mock は syscall を一切呼ばず、失敗を注入するときも errno を捏造する。したがってこの層で言えるのは「順序と設定検査が仕様どおり」までで、`LinuxBackend` が kernel に何をさせるかは何も言えない。

guest 起動側の protocol は別 crate の unit test で固定している。`supervisor/src/linux_host.rs` の `inherited_start_gate_accepts_only_its_socketpair_endpoint`、launcher の `start_gate_uses_exact_inherited_streams` / `exec_status_accepts_only_close_without_a_failure_marker`、PID 1 の readiness malformed/timeout tests が、他プロセスが pathname や任意 fd で gate を満たせないこと、exec failure を成功扱いしないこと、readiness を全 setup 後にだけ返すことを確認する。

## 特権環境で確認したこと

[`tests/privileged_isolation.rs`](../../crates/runtime-isolation/tests/privileged_isolation.rs) が `LinuxBackend` で 13 step を実際に適用し、完成した境界の内側から kernel に問い合わせる。mock は一切使わない。

この取引は libtest harness の中では動かせない。`LinuxBackend` は multi-thread の launcher を拒否し、隔離される child は新しい PID namespace の PID 1 になるためで、この target は `harness = false` を使って自分自身を単線程の probe として再実行する。

| 境界 | 何を観測したか | scenario |
|---|---|---|
| 13 step が実 syscall で完走する | launcher が `ChildStartupStatus::Ready` を受け取る | `enforce` |
| PID namespace が分離されている | workload の `getpid()` が `1` | `enforce` |
| seccomp filter が実際に効く | `socket(2)` と `unshare(2)` が `EPERM` | `enforce` |
| 高リスク syscall corpus が既定拒否される | `bpf`、`clone3`、`io_uring_setup`、`open_tree`、`pidfd_open`、`userfaultfd` の raw syscall が全て `EPERM` | `enforce`, `launcher-post-exec` |
| Landlock ruleset が実際に効く | mount 上は書ける tmpfs への作成が `EACCES` | `enforce` |
| workspace は書けるままである | `/workspace` への作成が成功する | `enforce` |
| rootfs が read-only で mount されている | `/etc` への作成が `EROFS` | `enforce` |
| device tree が覆われている | `/dev/null` が `ENOENT` | `enforce` |
| 継承 fd が閉じられている | close-on-exec を外した fd 100 が `EBADF` | `enforce` |
| capability が全て落ちている | `/proc/self/status` の `CapEff` が `0000000000000000` | `enforce` |
| `no_new_privs` と seccomp mode が立っている | `NoNewPrivs=1`、`Seccomp=2` | `enforce` |
| production launcher の start gate が完了する | `ready` → release byte → `isolated` の順で ACK | `launcher-post-exec` |
| `execve` 後も PID namespace が続く | 再 exec された workload の `getpid()` が `1` | `launcher-post-exec` |
| `execve` 後も path / syscall 境界が続く | `socket` / `unshare` が `EPERM`、workspace は成功、tmpfs は `EACCES`、rootfs は `EROFS` | `launcher-post-exec` |
| `execve` 後の masks が効く | `/dev/null`、`/run/lock`、`/sys/kernel` が `ENOENT` | `launcher-post-exec` |
| capability / mode が exec で緩まない | `CapEff` / `CapPrm` / `CapBnd` / `CapAmb` は全て 0、`NoNewPrivs=1`、`Seccomp=2` | `launcher-post-exec` |
| exec 後の fd policy が exact である | 標準 fd は `/dev/null`、control/Broker の 2 本だけが nonstandard に残り、marker / exec-status は消える | `launcher-post-exec` |
| launcher が shell を暗黙に起動しない | `;`、`$(touch /outside)`、空白を含む argv がそのまま再 exec される | `launcher-post-exec` |
| 失敗した step が launcher に正しく報告される | `Landlock` で失敗し `termination_required=true` | `landlock-failure` |
| 実 backend の mount failure が完了済み mount を rollback する | `LimitedTmpfs` の直前で失敗し、完了済み `Workspace` の逆順 unmount、child mount namespace の消滅、host mount table の残差なしを外部観測する | `limited-tmpfs-failure` |
| launcher が host の cgroup を解放する | `/sys/fs/cgroup/<name>` が消える | failure scenarios |
| 境界未完成の workload は実行されない | child の report file が作られない | `landlock-failure`, `limited-tmpfs-failure` |

Landlock の証拠に tmpfs を使うのは意図的である。rootfs は read-only mount のため LSM hook より手前で `EROFS` になり、Landlock が効いているかどうかを区別できない。tmpfs は mount 上書き込めるので、拒否できるのは ruleset だけになる。

`launcher-post-exec` は libtest process から直接 kernel API を叩くのではなく、同じ package の production binary を起動する。workload binary 自身は probe の再 exec であり、report は隔離後も保持された supervisor control channel から親へ返す。Broker descriptor には host 上の `AF_VSOCK` local-CID pair を使うため、実際の descriptor validation（`SOCK_STREAM`、connected `AF_VSOCK`）も通る。

`rootfs.source == "/"` は host root が起動前から readonly の場合だけ同じ launcher scenario で選択する。mutable な host root を test の都合で remount してから namespace clone することはしない。通常hostではstaged rootfsのpost-exec証拠を使い、別の`verify-real-session-owner.sh`がreadonly SquashFS guest rootでliteral `/` branchと`/run`、`/sys`、`/proc`、`/dev` maskをproduction経路から実行する。

`limited-tmpfs-failure` は debug build にだけコンパイルされる test-only seam を環境変数で有効にし、実際の `LinuxBackend` が `LimitedTmpfs` syscall を呼ぶ直前に `BackendError` を返す。rootfs pivot と workspace bind mount は完了済みなので、production coordinator の逆順 rollback が workspace を unmount し、cgroup は launcher が child を reap した後に削除する。親 probe は child の mount namespace が消えたこと、probe staging tree 以下の host mount table に新しい mount が残っていないこと、workload report が存在しないことを確認する。root pivot 自体は不可逆であるため、これは「完了済み reversible mount の rollback と host cleanup」の証拠であり、pivot を元へ戻せる証拠ではない。

この層が見つけた実装の誤りは 2 件ある。どちらも mock では原理的に検出できない。

- `detect_capabilities` が cgroup 設定 root に `memory.max` / `pids.max` が存在することを要求していた。cgroup v2 でこれらの制御 file を得るのは「親が `cgroup.subtree_control` で controller を有効にした cgroup」だけで、hierarchy root には有効にする親がいない。`/sys/fs/cgroup/memory.max` はどの host にも存在せず、この repository の設定はいずれもその hierarchy root を指定するため、判定は常に失敗し特権経路全体が到達不能だった。判定は root が子へ委譲している controller を見るように直した。
- staged rootfs 経路で step 7 `MaskProc` が必ず `EPERM` になっていた。user namespace 内で新しい procfs を mount するには完全に可視な procfs が既に存在する必要があり、step 4 の `pivot_root` がその procfs を切り離した後では条件を満たせない。private procfs は継承 mount が見えている step 4 で staging し、`MaskProc` はそれを検証して確定させるようにした。workspace が step 4 で staging され step 5 で確定するのと同じ形にしてある。

## 実行コマンド

```bash
cargo fmt --manifest-path crates/runtime-isolation/Cargo.toml -- --check
cargo test --manifest-path crates/runtime-isolation/Cargo.toml
cargo clippy --manifest-path crates/runtime-isolation/Cargo.toml --all-targets -- -D warnings

# 特権環境でのみ境界を実測する。CI と local の共通入口を通す。
scripts/ci/verify-privileged-isolation.sh
scripts/ci/verify-runtime-isolation-soak.sh
scripts/ci/verify-real-session-owner.sh

# 実 aarch64 host でのみ実行する。別 architecture では明示的に exit 2。
scripts/ci/verify-privileged-isolation-aarch64.sh
```

wrapper は先に production の `workload-isolation-launcher` binary を build し、その binary を
`launcher-post-exec` scenario へ渡す。kernel feature / privilege が不足して probe が実行できない
場合は `unavailable` を stderr に出して exit 2 とし、skip を green として扱わない。

`verify-runtime-isolation-soak.sh` は同じ no-skip privileged gate を既定 20 回繰り返す。
`RUNTIME_ISOLATION_SOAK_ITERATIONS` は 1..100 の整数だけを受け入れ、無制限 run を作らない。
各反復は enforce、post-exec、Landlock failure、実 mount rollback の 4 scenario と終了後の
resource residue を再確認する。2026-08-18 の x86_64 KVM host では既定 20 回が完走した。

syscall corpus は安全な不正引数を使う。filter が退行しても kernel object を作らない値で
呼び出し、予期せず descriptor が返れば即座に close して test を失敗させる。これは選んだ
6 syscall の deny 証拠であり、Linux の全 syscall と全 argument 組合せの証明ではない。

`capability_detection.rs` と `privileged_isolation.rs` はどちらも `#[ignore]` を使っていない。権限や kernel feature が足りない環境では、`CapabilityReport` の不足理由を stderr に出したうえで detection 分岐そのものを検証する。CI で「skip されたので緑」という状態を作らないための書き方。

`privileged_isolation.rs` が要求するのは、user namespace が許可された Linux host、`memory` と `pids` を子へ委譲している cgroup v2 hierarchy、Landlock ABI 3 以上、seccomp、`clone3` / `close_range` / `pidfd_open`、host local `AF_VSOCK`。root で走らせる必要がある。probe は自分専用の mount namespace と tmpfs の中に staged rootfs を組み立てるので、host の mount table や root filesystem は変えない。

## 未検証の境界

| 未検証の対象 | なぜ未検証か | 何があれば検証できるか |
|---|---|---|
| mount syscall の部分成功後に失敗した場合の rollback | privileged probe は `LimitedTmpfs` syscall の前に失敗させるため、失敗した呼び出し自身が mount を残すケースは実測していない | `mount(2)` の戻り値を含む test-only fault seam と、対象 mount namespace を保持した観測 helper |
| aarch64 の実 kernel 上の isolation envelope | aarch64 syscall 番号表、audit architecture、cross-target build は実装・検査済みだが、実 aarch64 privileged gate はこの working tree では未実行 | delegated cgroup v2、Landlock、seccomp、namespace、AF_VSOCK を備えた root aarch64 runner |
| x86_64 / aarch64 以外の syscall 番号 | 対応表を持たない architecture は `number()` が `None` を返すため `validate` が fail closed する | 対象 arch の監査済み番号表と、その arch での privileged CI runner |

mock test が全部通っても、VM 実起動や full isolation の完成とは判断しない。この方針は [docs/README.md](../README.md) の宣言に従う。特権 test が通ったことも、上の表の範囲を超えては主張しない。

## 関連

- [runtime-isolation](README.md)
- [13 step の固定順序と rollback](apply-order.md)
- [seccomp allowlist](seccomp-allowlist.md)
- [Landlock envelope](landlock-envelope.md)
- [検証戦略](../design/verification.md)
- [用語集](../glossary.md)
