<!-- doc-type: verification -->

# 検証対応表

[runtime-isolation](README.md) / 検証対応表

> **対象読者:** runtime-isolation の実装者、レビュー担当者、特権環境で統合 test を回す人

この crate の検証は 2 層ある。mock backend による順序制御・設定検査・BPF プログラムの形の確認と、実 kernel 上で 13 step を適用して境界を kernel に問い直す確認。前者だけでは「隔離が効いている」ことは言えないので、どちらの層で何が言えるのかを分けて書く。

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
| workspace mask に device / socket / FIFO / symlink 作成が含まれない | 定数の bit 検査 | `landlock_workspace_rights_do_not_include_special_file_creation` |
| capability detection が不足理由を必ず添える | 実 host への query | `privileged_integration_prerequisites_are_reported_without_an_ignored_test` |

test double は 1 つだけ。`IsolationBackend` を実装した記録型 mock が、呼ばれた step と順序を `Vec` に積む。この mock は syscall を一切呼ばず、失敗を注入するときも errno を捏造する。したがってこの層で言えるのは「順序と設定検査が仕様どおり」までで、`LinuxBackend` が kernel に何をさせるかは何も言えない。

## 特権環境で確認したこと

[`tests/privileged_isolation.rs`](../../crates/runtime-isolation/tests/privileged_isolation.rs) が `LinuxBackend` で 13 step を実際に適用し、完成した境界の内側から kernel に問い合わせる。mock は一切使わない。

この取引は libtest harness の中では動かせない。`LinuxBackend` は multi-thread の launcher を拒否し、隔離される child は新しい PID namespace の PID 1 になるためで、この target は `harness = false` を使って自分自身を単線程の probe として再実行する。

| 境界 | 何を観測したか | scenario |
|---|---|---|
| 13 step が実 syscall で完走する | launcher が `ChildStartupStatus::Ready` を受け取る | `enforce` |
| PID namespace が分離されている | workload の `getpid()` が `1` | `enforce` |
| seccomp filter が実際に効く | `socket(2)` と `unshare(2)` が `EPERM` | `enforce` |
| Landlock ruleset が実際に効く | mount 上は書ける tmpfs への作成が `EACCES` | `enforce` |
| workspace は書けるままである | `/workspace` への作成が成功する | `enforce` |
| rootfs が read-only で mount されている | `/etc` への作成が `EROFS` | `enforce` |
| device tree が覆われている | `/dev/null` が `ENOENT` | `enforce` |
| 継承 fd が閉じられている | close-on-exec を外した fd 100 が `EBADF` | `enforce` |
| capability が全て落ちている | `/proc/self/status` の `CapEff` が `0000000000000000` | `enforce` |
| `no_new_privs` と seccomp mode が立っている | `NoNewPrivs=1`、`Seccomp=2` | `enforce` |
| 失敗した step が launcher に正しく報告される | `Landlock` で失敗し `termination_required=true` | `landlock-failure` |
| launcher が host の cgroup を解放する | `/sys/fs/cgroup/<name>` が消える | 両 scenario |
| 境界未完成の workload は実行されない | child の report file が作られない | `landlock-failure` |

Landlock の証拠に tmpfs を使うのは意図的である。rootfs は read-only mount のため LSM hook より手前で `EROFS` になり、Landlock が効いているかどうかを区別できない。tmpfs は mount 上書き込めるので、拒否できるのは ruleset だけになる。

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
```

`capability_detection.rs` と `privileged_isolation.rs` はどちらも `#[ignore]` を使っていない。権限や kernel feature が足りない環境では、`CapabilityReport` の不足理由を stderr に出したうえで detection 分岐そのものを検証する。CI で「skip されたので緑」という状態を作らないための書き方。

`privileged_isolation.rs` が要求するのは、user namespace が許可された Linux host、`memory` と `pids` を子へ委譲している cgroup v2 hierarchy、Landlock ABI 3 以上、seccomp、`clone3` / `close_range` / `pidfd_open`。root で走らせる必要がある。probe は自分専用の mount namespace の中で read-only rootfs を組み立てるので、host の mount table は変えない。

## 未検証の境界

| 未検証の対象 | なぜ未検証か | 何があれば検証できるか |
|---|---|---|
| unmount による rollback が実際に戻ること | 失敗を注入できたのは `Landlock` で、そこは `pivot_root` 後のため crate 自身が「戻せない」と申告する。確認できたのは cgroup の解放だけ | `Workspace` や `LimitedTmpfs` で失敗を注入し、child の mount namespace を外から観測する test |
| 既に immutable な root を持つ guest 経路 (`rootfs.source == "/"`) | probe は staged rootfs 経路だけを通る。`/` 経路は `/run` と `/sys` の masking を含む別分岐 | 実 guest image を持つ VM 内での同等 probe |
| workload を `execve` した後も境界が続くこと | probe は child 内で直接観測しており、exec を挟んでいない | 固定 workload binary を exec してから同じ観測を行う test |
| 実 supervisor 経由の起動 | probe は `workload-isolation-launcher` ではなく API を直接使う。control channel と egress channel は `None` | 実 `AF_UNIX` control socket と `AF_VSOCK` egress fd を用意した統合 test |
| x86_64 以外の syscall 番号 | `number()` が `None` を返すため `validate` が通らない | 対象 arch の番号表と、その arch での CI runner |

mock test が全部通っても、VM 実起動や full isolation の完成とは判断しない。この方針は [docs/README.md](../README.md) の宣言に従う。特権 test が通ったことも、上の表の範囲を超えては主張しない。

## 関連

- [runtime-isolation](README.md)
- [13 step の固定順序と rollback](apply-order.md)
- [seccomp allowlist](seccomp-allowlist.md)
- [Landlock envelope](landlock-envelope.md)
- [検証戦略](../design/verification.md)
- [用語集](../glossary.md)
