<!-- doc-type: verification -->

# 検証対応表

[Firecracker runtime](README.md) / 検証対応表

> **対象読者:** firecracker-runtime の実装者、レビュー担当者、実機で統合 test を回す人

この crate の test は 3 層に分かれる。fake adapter を使う lifecycle test、実 Unix socket と実プロセスを使う adapter test、実 filesystem を使う workspace test。実 Firecracker と実 VM はどの層にも出てこない。

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

### SHA-256

`sha256_matches_nist_empty_vector`、`sha256_matches_nist_abc_vector`、`digest_parser_rejects_wrong_length_and_accepts_case`。NIST の既知 vector 2 本と、hex parser の境界。

## 実行コマンド

```bash
cargo fmt --manifest-path crates/firecracker-runtime/Cargo.toml -- --check
cargo test --manifest-path crates/firecracker-runtime/Cargo.toml
cargo clippy --manifest-path crates/firecracker-runtime/Cargo.toml --all-targets -- -D warnings
```

## 未検証の境界

| 未検証の対象 | なぜ未検証か | 何があれば検証できる |
|---|---|---|
| 実 Firecracker の起動 | binary、KVM、特権が必要 | KVM が使える Linux host と pinned binary |
| 実 jailer の隔離効果 | 特権と cgroup v2 書き込みが必要 | 同上。加えて namespace / cgroup を外から観測する手段 |
| 実 dm-verity mapping | `veritysetup` と device-mapper が必要 | root 権限と hash image を用意した環境 |
| Firecracker API の受理 | fake client は status 200 を返すだけ | 実 Firecracker の API socket |
| snapshot / restore の実動作 | VM が無い | 実 VM |
| guest 側の pre-session gate | guest supervisor が別 | VM 内で init が停止していることを観測する手段 |
| identity 注入が guest へ届くこと | `control_call` が fake | guest control channel の実装と実 VM |
| seccomp filter の中身 | 宣言の文字列比較のみ、filter を解析していない | filter を parse するか、実プロセスで syscall を試す test |
| digest 照合と exec の間の差し替え | fd を保持した exec になっていない | jailer 経由の起動で fd を引き回す仕組み |

test double は 4 つ。`CommandRunner`、`FileSystem`、`ApiClient`（Firecracker 用と guest control 用の 2 つ）、`IdentitySource`。

このうち `CommandRunner` と `FileSystem` は production 実装のほうにも test がある。`ApiClient` は production 実装（`UnixApiClient`）に実 socket test があるが、その相手は Firecracker ではなく test 用の listener。

mock test が全部通っても、VM 実起動や full isolation の完成とは判断しない。この方針は [docs/README.md](../README.md) の宣言に従う。

## 関連

- [Firecracker runtime](README.md)
- [artifact の固定と fingerprint](pinned-artifacts.md)
- [起動の順序と rollback](launch-sequence.md)
- [snapshot と identity gate](snapshot-and-identity.md)
- [workspace clone](workspace-clone.md)
- [ホスト隔離プロファイル](host-isolation.md)
- [検証戦略](../design/verification.md)
- [用語集](../glossary.md)
