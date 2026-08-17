<!-- doc-type: verification -->

# 検証対応表

[Firecracker runtime](README.md) / 検証対応表

> **対象読者:** firecracker-runtime の実装者、レビュー担当者、実機で統合 test を回す人

この crate の test は 4 層に分かれる。fake adapter を使う lifecycle test、実 Unix socket と実プロセスを使う adapter test、実 filesystem を使う workspace test、KVM host で実 Firecracker を boot する opt-in test である。最後の層だけは root、`/dev/kvm`、`/dev/vhost-vsock`、device-mapper、cgroup v2 を要求し、通常の `cargo test` では実行しない。実 Firecracker 層には、直接 API を構成する guest-control test と、production `Runtime::launch` を通る lifecycle gate の 2 本がある。

## local test で確認したこと

### lifecycle（fake command runner / filesystem / API client）

| 境界 | test |
|---|---|
| 正常な profile で dm-verity、vsock、jailer を構成し network device を作らない | `launch_valid_profile_configures_verity_vsock_and_jailer_without_network` |
| digest 不一致を side effect の前に拒否する | `digest_mismatch_is_rejected_before_any_side_effect` |
| network device を artifact 読み込みと起動の前に拒否する | `network_device_is_rejected_before_artifact_reads_or_launch` |
| API 失敗でプロセス・dm-verity・workspace を逆順に rollback する | `api_error_rolls_back_process_verity_and_workspace_in_reverse_order` |
| workspace clone 失敗で VM を起動せず部分 tree を削除する | `workspace_clone_error_removes_partial_destination_without_starting_vm` |
| shutdown が成功済み step を繰り返さず未完了だけ retry する | `shutdown_retries_each_pending_cleanup_without_repeating_successes` |
| snapshot 前に pause acknowledgement を受け、失敗時も paused state を再利用しない | `snapshot_pauses_vm_before_writing_snapshot_files`, `snapshot_create_failure_keeps_instance_explicitly_paused` |
| pause 応答の失敗を unknown state として扱い snapshot を作らない | `snapshot_pause_failure_enters_unknown_state_and_does_not_create_snapshot` |
| restore が全 identity を再生成し、注入まで workload を止める | `restore_regenerates_all_identities_and_gates_workload_until_injection` |
| host が割り当てた identity をそのまま受け入れる | `restore_accepts_exact_host_allocated_identities` |
| host identity の再利用を side effect の前に拒否する | `restore_rejects_host_identity_reuse_before_side_effects` |
| stale identity を拒否し、起動済みプロセスを rollback する | `stale_identity_is_rejected_and_restored_process_is_rolled_back` |
| 同じ identity を 2 回生成したら stale として拒否する | `duplicate_identity_generation_is_rejected_as_stale` |
| 可変 channel を指す artifact path を validation で拒否する | `latest_artifact_channel_is_rejected_by_validation` |
| workspace の source と clone path の重なりを拒否する | `overlapping_workspace_source_and_clone_paths_are_rejected` |

### `UnixApiClient`（実 Unix socket、HTTP/1.x を自前で話す）

| 境界 | test |
|---|---|
| 実 socket 上で実 HTTP を送受信する | `unix_api_client_sends_real_http_over_unix_socket` |
| 上限内の response body を受け取る | `unix_api_client_accepts_a_bounded_response_body` |
| 上限超過を body 読み込みの前に拒否する | `unix_api_client_rejects_oversized_response_before_reading_body` |
| `Content-Length` 重複と `Transfer-Encoding` の併用を拒否する | `unix_api_client_rejects_duplicate_content_lengths_and_transfer_encoding` |
| framing の欠落と不正を拒否する | `unix_api_client_rejects_missing_and_malformed_response_framing` |
| 未対応・範囲外の status line を拒否する | `unix_api_client_rejects_unsupported_and_out_of_range_status_lines` |
| 上限超過の request body を接続前に拒否する | `unix_api_client_rejects_oversized_request_body_before_connecting` |

HTTP を自前で実装しているので、request smuggling の入口になりうる箇所を個別に閉じている。`Content-Length` と `Transfer-Encoding` の併用拒否がそれ。上限は `MAX_HTTP_BODY_BYTES` と `HTTP_HEADER_LIMIT` がいずれも 64 KiB。

### `RealCommandRunner`（実プロセス）

| 境界 | test |
|---|---|
| 通常の出力を取得する | `real_command_runner_captures_normal_output` |
| stdout が上限を超えたらプロセスを終了させる | `real_command_runner_terminates_on_oversized_stdout` |
| stderr が上限を超えたらプロセスを終了させる | `real_command_runner_terminates_on_oversized_stderr` |
| 所有する終了済み child を reap する | `real_command_runner_reaps_an_already_exited_owned_child` |
| 所有しない PID に signal を送らない | `real_command_runner_rejects_unowned_pid_without_signalling_it` |

最後の 1 つは、`ProcessHandle` の PID を偽造されても他プロセスを殺さないことを見ている。`children` map に無い PID は拒否する。

### `RealFileSystem`（実 filesystem）

| 境界 | test |
|---|---|
| 所有する完成済み clone だけを公開・削除する | `real_filesystem_publishes_and_removes_only_owned_complete_clones` |
| source の alias、symlink、hard link、上限超過を拒否する | `real_filesystem_rejects_source_aliases_symlinks_hardlinks_and_bounds` |

### crash recovery の subtree 削除

| 境界 | test |
|---|---|
| jail 内の symlink を、外部の実体に触れずに unlink する | `jail_symlink_is_unlinked_without_touching_its_external_target` |
| 幅の広い木と深い木のどちらでも、1 回あたりの削除量を区切って前進する | `iterative_removal_makes_bounded_progress_across_wide_and_deep_trees` |
| この host が作り得ない深さの subtree を歩かずに拒否する | `removal_refuses_a_subtree_deeper_than_this_host_could_have_built` |
| cgroup の descendant を control file を残したまま bottom-up で削除する | `cgroup_descendant_cleanup_removes_directories_bottom_up` |

深さ制限は `MAX_WORKSPACE_DEPTH` と同じ 64 である。降下は削除 budget を消費しないので、guest が workspace 内に深い chain を作ると、最初の 1 件を unlink する前に木の底まで歩くことになる。`open_descendant_directory` は毎回 root から開き直すため、その walk は深さの 2 乗で効く。workspace は 64 段までしか作られないので、それより深い subtree は「この host が作ったものではない」として歩かずに拒否する。

symlink は「拒否」ではなく「unlink」である。`O_PATH | NOFOLLOW` で開いて種別を判定し、link 自体を消すので、外の実体には触れない。

### SHA-256

`sha256_matches_nist_empty_vector`、`sha256_matches_nist_abc_vector`、`digest_parser_rejects_wrong_length_and_accepts_case`。NIST の既知 vector 2 本と、hex parser の境界。

### 実 Firecracker / dm-verity / guest `AF_VSOCK`（opt-in）

[`scripts/ci/verify-real-guest-control.sh`](../../scripts/ci/verify-real-guest-control.sh) は pinned kernel と base rootfs から static `guest-control-init` と固定 workload を含む squashfs image を作り、その image を実 `veritysetup open` で read-only mapper として開く。mapper を root disk にした実 Firecracker に対して、[`real_firecracker_guest_control_enforces_identity_gate_over_vsock`](../../crates/firecracker-runtime/tests/real_guest_control.rs) と [`real_firecracker_guest_reaches_host_broker_over_vsock`](../../crates/firecracker-runtime/tests/real_guest_control.rs) が次を確認する。

| 境界 | 実際に確認すること |
|---|---|
| boot / artifact | KVM 上の Firecracker が read-only dm-verity mapper を root として起動する |
| guest control listener | guest PID 1 が `AF_VSOCK` port 18080 で host CID からの HTTP request を受ける |
| identity gate | identity 注入前の workload start は `409 Conflict` になる |
| identity injection | 5 個の session-bound identity と authority policy digest を canonical v2 JSON で注入し、guest の digest-bound ACK を返す |
| workload release | 同じ v2 policy digest に束縛した start だけが canonical ACK を返し、image に固定した workload を起動する |
| guest runtime composition | 別の runtime image test が `guest-supervisor-init`、readiness、`workload-isolation-launcher`、inherited gate、Broker probe を通して workload を起動する |
| workspace drive | runtime image test が writable ext4 workspace drive を guest supervisor に渡す |
| guest CapFS effects | 隔離後の固定workloadがCapFS mount上で全13 file effectを実行し、作成物を全て回収する |
| guest-to-host Broker | Firecracker が guest の CID 2 / port 18081 接続を session UDS の `_18081` socket へ転送し、host Broker が canonical request に `NotAuthorized` を返す |
| effect exclusion | 未発行 capability では public / GitHub adapter が一度も呼ばれない |

これらの test は `Runtime::launch` を経由せず、Firecracker REST API を直接構成する。PID 1 の gate は production と同じ v2 digest-bound identity/start path と exact ACK を使い、別の固定 runtime image は guest-supervisor-init → workload-isolation-launcher → 全13 CapFS effect → Broker probe を実 KVM で通す。従って authority binding、guest composition、CapFS、guest-to-host Broker transport の実境界を確認するが、runtime の jailer / snapshot lifecycleは下の別gateが担う。

### production `Runtime::launch` lifecycle（opt-in）

[`scripts/ci/verify-real-runtime-lifecycle.sh`](../../scripts/ci/verify-real-runtime-lifecycle.sh) は、pinned Firecracker/jailer、pinned kernel、pinned seccomp compiler/filter、実 `veritysetup`、実 cgroup v2 を用意し、[`real_runtime_launches_and_cleans_real_jailer_lifecycle`](../../crates/firecracker-runtime/tests/real_runtime_lifecycle.rs) を `Runtime::launch` 経由で実行する。wrapper は必須であり、環境が使えない場合も test を skip せず、root、KVM、vhost-vsock、cgroup v2、device-mapper、pinned artifact の不足を明示して終了する。guest image はこの host-side gate 専用に static BusyBox から作る最小 squashfs で、guest の CapFS や workload policy の検証を兼ねない。

| 境界 | 実際に確認すること |
|---|---|
| launch の経路 | fake adapter や直接 Firecracker API ではなく、production `Runtime::launch` → `RealCommandRunner` / `RealFileSystem` → jailer → Firecracker API を通る |
| dm-verity | 実 `veritysetup` で mapping を開き、`status` で active かつ read-only の exact mapper を観測する |
| workspace / drive | clone-specific workspace、ext4 workspace image、read-only root device の bind target が起動中に存在し、shutdown 後に消える |
| jailer / executable identity | cgroup v2 leaf の task が pinned Firecracker digest の `/proc/<pid>/exe` を実行し、UID/GID が dedicated non-root identity である |
| host isolation | Firecracker task の PID/mount namespace が host test process と異なり、`Seccomp: 2`、memory/cpu 上限、exact cgroup membership を観測する |
| API sequence | `/machine-config`、`/boot-source`、rootfs/workspace drive、vsock、`InstanceStart` が `Runtime::launch` の順序で成立し、返却 state は `WorkloadStopped` である |
| shutdown residue | process、cgroup leaf/parent、mapper、bind target、workspace image/clone、jailer root/instance directory が shutdown 後に残らない |

このgateが示すのは、指定host上でresource ownershipとjailer lifecycleが実際に成立し、shutdownがexact scopeを回収することまでである。さらに`scripts/ci/verify-real-session-owner.sh`はclean snapshotを実作成してproduction `SessionOwner`からrestoreし、guestの全13 CapFS effect、durable Broker/identity evidence、stopと全resource cleanupを一続きで検証する。VM escape proofや任意guest codeに対する完全な意味論証明は含まない。

## 実行コマンド

```bash
cargo fmt --manifest-path crates/firecracker-runtime/Cargo.toml -- --check
cargo test --manifest-path crates/firecracker-runtime/Cargo.toml
cargo clippy --manifest-path crates/firecracker-runtime/Cargo.toml --all-targets -- -D warnings

# root、KVM、vhost-vsock、device-mapper がある Linux host でだけ実行する
scripts/ci/verify-real-guest-control.sh
scripts/ci/verify-real-runtime-lifecycle.sh
scripts/ci/verify-real-session-owner.sh
```

## 未検証の境界

| 未検証の対象 | なぜ未検証か | 何があれば検証できる |
|---|---|---|
| VM escape を含む実 jailer の完全な隔離効果 | lifecycle gate は PID/mount namespace、UID、cgroup、seccomp installation を観測するが、攻撃者が escape できないことまでは証明しない | syscall deny と host boundary を含む hostile guest test |
| seccomp filterの全syscall・全引数に対する意味論 | privileged post-exec gateは代表的deny、KVM guestは標準filesystem APIに必要なallowを実測するが、Linux全syscall/引数空間を列挙しない | syscall/argument corpusを持つhostile guest test |

test double は 4 種。`CommandRunner`、`FileSystem`、`ApiClient`（Firecracker 用と guest control 用）、`IdentitySource`。実 guest-control test は Firecracker API と guest control API の両方を production transport で置き換えるが、`Runtime::launch` が使う他の境界を置き換えるものではない。

このうち `CommandRunner` と `FileSystem` は production 実装のほうにも test がある。`ApiClient` は production 実装（`UnixApiClient`）に実 socket test があるが、その相手は Firecracker ではなく test 用の listener。

mock test が全部通っても、また guest-control の実 VM test が通っても、full isolation の完成とは判断しない。この方針は [docs/README.md](../README.md) の宣言に従う。

## 関連

- [Firecracker runtime](README.md)
- [artifact の固定と fingerprint](pinned-artifacts.md)
- [起動の順序と rollback](launch-sequence.md)
- [snapshot と identity gate](snapshot-and-identity.md)
- [workspace clone](workspace-clone.md)
- [ホスト隔離プロファイル](host-isolation.md)
- [検証戦略](../design/verification.md)
- [用語集](../glossary.md)
