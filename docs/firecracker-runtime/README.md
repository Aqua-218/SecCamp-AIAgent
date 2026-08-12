# Firecracker runtime

[ドキュメント一覧](../README.md) / Firecracker runtime

> **対象読者:** Firecracker 統合担当者、ホスト隔離のレビュー担当者、運用担当者

`firecracker-runtime` は Phase 6 のホスト側 runtime 境界である。pinned artifact の検証、dm-verity の準備、clone ごとの workspace 準備、jailer 起動、Firecracker API の順序制御、snapshot lifecycle、restore 後の identity 注入と workload gate を担当する。

この crate は Firecracker、jailer、guest kernel、rootfs、dm-verity、guest supervisor の実装そのものではない。`CommandRunner`、`FileSystem`、`ApiClient`、`IdentitySource` の境界を持ち、production adapter と test double を差し替えられる構造である。

## 実装済みの不変条件

- Firecracker、jailer、kernel、rootfs、dm-verity hash image、seccomp profile は、workspace や process の副作用より前に読み取り、SHA-256 を検証する。
- absolute path の `latest` component、parent traversal、all-zero digest を拒否する。mutable な artifact channel は入力にできない。
- dm-verity の data device と hash device は pinned descriptor と一致しなければならない。launch は read-only mapping を開き、mapped device を read-only root drive として送る。
- launch ごとに `clone_root` と `clone_id` から workspace path を導出し、既存 destination を拒否する。production `RealFileSystem` は copy 中に symlink と未対応の special file を拒否する。
- standard profile は private user、PID、mount、network、IPC、UTS namespace、non-zero cgroup v2 memory/CPU limit、隔離設計で要求する seccomp deny set を必須にする。
- `network_devices` は空でなければならない。host 通信に設定される Firecracker device は virtio-vsock だけである。

## lifecycle

`Runtime::launch` は artifact を検証し、workspace を clone し、dm-verity を開き、jailer を起動し、machine/boot/rootfs/workspace/vsock を設定して Firecracker の `InstanceStart` を要求する。この method の戻り値は `RuntimeState::WorkloadStopped` であり、workload start action は送らない。

`Runtime::create_snapshot` は workload が停止した pre-session state だけを受け付ける。snapshot には artifact fingerprint と、source state に存在した identity が記録される。`Runtime::restore` は同じ fingerprint を要求し、snapshot load 後も workload を停止したままにする。restore は新しい VM、session、request、subject、capability の 128-bit identity を生成し、snapshot metadata にある identity の再生成や重複を拒否する。

`inject_identity` は guest control API を呼び、成功したときだけ `IdentityInjected` へ遷移する。`start_workload` は `IdentityInjected` からのみ呼べる。control API が失敗した場合、instance state は変わらない。

launch、restore、configuration failure には逆順の rollback がある。process 起動後の failure では process を止め、dm-verity mapping を閉じ、clone workspace を削除する。cleanup error は元の error とともに返し、捨てない。通常の `shutdown` も process 停止、verity close、workspace removal を試み、いずれかが失敗すれば `RuntimeError::Cleanup` を返して `Stopped` に遷移しない。

## production adapter と契約境界

`RealCommandRunner` は `std::process::Command` で `veritysetup` と jailer を実行する。`RealFileSystem` は symlink を追従せずに artifact を読み、workspace を copy する。`UnixApiClient` は Unix-domain socket 上で bounded HTTP/1.1 request を送り、malformed response と non-2xx status を runtime 境界で拒否する。`SystemIdentitySource` は restore 後に `/dev/urandom` から新しい 128-bit 値を読む。

呼び出し側は Firecracker API socket 用と guest supervisor control socket 用に別々の `UnixApiClient` を構築し、両方を `Runtime::new` へ渡す。この crate は credential を作らず、guest に network interface も作らない。

## 検証状態

contract test は valid launch ordering、digest mismatch、`latest` 拒否、virtio-net 拒否、API error、reverse rollback、stale/duplicate identity、workload gate を検証する。`UnixApiClient` については local Unix socket の HTTP exchange も検証する。

一方、これらは test double と local Unix socket による検証である。実 Firecracker process、実 jailer namespace/cgroup、実 dm-verity device、guest kernel、guest supervisor、snapshot/restore、VM escape 境界は実行していない。したがって、この crate の状態を VM 実起動済み、または full isolation 完成済みとは扱わない。

repository root からの focused test は次のとおりである。

```bash
cargo fmt --manifest-path crates/firecracker-runtime/Cargo.toml -- --check
cargo test --manifest-path crates/firecracker-runtime/Cargo.toml
cargo clippy --manifest-path crates/firecracker-runtime/Cargo.toml --all-targets -- -D warnings
```

## 関連

- [隔離基盤の設計](../design/runtime-isolation.md)
- [session orchestrator](../session-orchestrator/README.md)
- [supervisor adapter](../supervisor/README.md)
- [実装順序](../design/implementation-plan.md)
- [検証戦略](../design/verification.md)
