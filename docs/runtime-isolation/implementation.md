# runtime-isolation 実装補助

この文書は、`docs/design/runtime-isolation.md` の実装節から参照する補助文書である。実装対象は `crates/runtime-isolation` crate であり、root workspace に登録して全体の test / lint 対象に含める。

## API の境界

`IsolationConfig` は rootfs、capfs workspace、tmpfs、cgroup v2、Landlock file envelope、seccomp allowlist、UID/GID map を一つの不変ポリシーとして受け取る。`validate()` は実 syscall の前に、絶対 clean path、mount target の衝突、tmpfs 上限、cgroup 名、Landlock ABI 最低値、空でない seccomp allowlist を検査する。

特権操作は `IsolationBackend` に分離している。テストは backend を記録型 mock に置き換えられ、本番は `LinuxBackend` が namespace、mount、pivot_root、cgroup control file、Landlock syscall、capset、`no_new_privs`、classic BPF seccomp を実行する。未検証の syscall 名、network syscall、namespace 変更、`ptrace`、`process_vm_*`、`bpf`、`perf_event_open`、device ioctl、process creation は allowlist へ追加できない。

## 固定された実行順序

1. `CLONE_NEWUSER | CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWNET | CLONE_NEWIPC | CLONE_NEWUTS | CLONE_NEWCGROUP` を作成する。
2. `/proc/self/setgroups` を `deny` にして、単一 UID/GID map を書き込む。
3. cgroup v2 を作成し、`memory.max`、`pids.max`、`cgroup.procs` を設定する。
4. rootfs を bind mount して read-only に remount し、`pivot_root` で workload の root にする。旧 root は detach unmount する。
5. workspace を bind mount し、setuid、device、実行を mount flag で無効にする。
6. size 制限付き writable tmpfs を `/tmp` に配置する。
7. `/proc` と `/dev` を空の read-only tmpfs で覆う。したがって host proc、block device、device node は workload から解決できない。
8. fd 3 以上を `close_range`（非対応 kernel では bounded fallback）で閉じる。
9. Landlock ABI を query し、要求値未満なら fail-closed で停止する。rootfs は read/execute、workspace は file data、directory、rename、truncate の範囲だけを許可する。device node、socket、FIFO、symlink の作成権は workspace に与えない。
10. effective、permitted、inheritable、ambient、bounding capability を消去する。
11. `PR_SET_NO_NEW_PRIVS` を設定する。Landlock の kernel prerequisite としても同じ操作を先に idempotent に実行する。
12. arch check 付き default-deny seccomp filter を入れる。allowlist に一致しない syscall は `EPERM`、不正 arch は process kill になる。

`RuntimeIsolation::apply` は各 step の完了を receipt に記録し、失敗時は完了済み step を逆順に rollback する。namespace、pivot_root、Landlock、capability、no_new_privs、seccomp は kernel 上で安全に逆戻りできないため、本番 backend はそれらを rollback 不可として明示的に返す。この場合 supervisor は child を再利用せず終了させる。mount と cgroup の partial failure は各 step 内でも cleanup を試みる。

## capability detection と privileged test

`LinuxBackend::detect_capabilities` は mutation 前に user namespace、cgroup v2 hierarchy、Landlock ABI、seccomp filter mode を調べる。不足時は理由付き `CapabilityReport` を返し、orchestrator は workload を起動しない。

`tests/capability_detection.rs` は `#[ignore]` を使わない。権限や kernel feature が不足する環境では、test output に不足理由を出して capability detection 分岐を検証する。特権を要する full apply は、supervisor が clone/pid namespace の child と rootfs staging directory を準備した環境で別途実行する。`LinuxBackend` は `CLONE_NEWPID` を unshare するため、呼び出し側は workload を exec する child 側でこの transaction を開始し、親 supervisor が child lifecycle を監視する。

## rollback と監査上の注意

rootfs pivot 後、または Landlock、capability drop、`no_new_privs`、seccomp 後の失敗を「部分成功」として継続してはならない。返された rollback failure は起動失敗として記録し、対象 child を終了する。`IsolationReceipt` は全 step が成功して exec 前の境界が完成したことの機械的な証拠として supervisor の audit event に添付する。
