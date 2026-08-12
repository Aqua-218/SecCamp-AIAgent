<!-- doc-type: verification -->

# 検証対応表

[runtime-isolation](README.md) / 検証対応表

> **対象読者:** runtime-isolation の実装者、レビュー担当者、特権環境で統合 test を回す人

この crate は「隔離が効いている」ことをまだ確認していない。確認しているのは、その手前にある順序制御・設定検査・BPF プログラムの形だけ。区別が曖昧になると危ないので、境界をはっきり書く。

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

seccomp の 2 つは `compile_filter` が返す命令列を読んでいるだけで、filter を install していない。「この BPF プログラムは正しい形をしている」ことは言えるが、「kernel がこの形を意図どおり解釈する」ことは言えない。

## 実行コマンド

```bash
cargo fmt --manifest-path crates/runtime-isolation/Cargo.toml -- --check
cargo test --manifest-path crates/runtime-isolation/Cargo.toml
cargo clippy --manifest-path crates/runtime-isolation/Cargo.toml --all-targets -- -D warnings
```

`capability_detection.rs` は `#[ignore]` を使っていない。権限や kernel feature が足りない環境では、不足理由を stderr に出したうえで detection 分岐そのものを検証する。CI で「skip されたので緑」という状態を作らないための書き方。

## 未検証の境界

| 未検証の対象 | なぜ未検証か | 何があれば検証できるか |
|---|---|---|
| `LinuxBackend` の 13 step の実適用 | user namespace、cgroup v2 書き込み、Landlock ABI 3、seccomp install が全部必要 | 特権付き Linux host と、clone/pid namespace の child を用意する supervisor |
| seccomp filter の実効果 | filter を install していない | 特権環境で filter を入れ、禁止 syscall が `EPERM` / kill になることを確認する test |
| Landlock ruleset の実効果 | ruleset を張っていない | ABI 3 以上の kernel で、workspace 外への書き込みが `EACCES` になることを確認する test |
| `pivot_root` 後の path 解決 | mount していない | 実 rootfs staging を用意した特権 test |
| rollback 可能と申告した step が実際に戻ること | unmount / cgroup 削除を実行していない | 特権環境で失敗を注入する test |
| 継承 fd の close 漏れ | `close_range` を呼んでいない | fd を意図的に開いた状態で apply し、workload から見えないことを確認する test |
| x86_64 以外の syscall 番号 | `number()` が `None` を返すため `validate` が通らない | 対象 arch の番号表と、その arch での CI runner |

test double は 1 つだけ。`IsolationBackend` を実装した記録型 mock が、呼ばれた step と順序を `Vec` に積む。この mock は syscall を一切呼ばず、失敗を注入するときも errno を捏造する。

mock test が全部通っても、VM 実起動や full isolation の完成とは判断しない。この方針は [docs/README.md](../README.md) の宣言に従う。

## 関連

- [runtime-isolation](README.md)
- [13 step の固定順序と rollback](apply-order.md)
- [seccomp allowlist](seccomp-allowlist.md)
- [Landlock envelope](landlock-envelope.md)
- [検証戦略](../design/verification.md)
- [用語集](../glossary.md)
