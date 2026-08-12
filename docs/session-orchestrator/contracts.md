# production backend 契約

[Session orchestrator](README.md) / production backend 契約

> **対象読者:** production adapter 実装者、host/guest 境界のレビュー担当者

この文書は `session-orchestrator` の backend trait へ接続するための統合契約である。orchestrator 自身は trait を呼び出す以外の副作用を持たない。backend は effect が commit point に到達した後だけ lease を返し、要求と異なる session/resource identity の lease を返してはならない。

## trait の対応

| trait | production の所有者 | commit の責務 |
| --- | --- | --- |
| `WorkspaceBackend` | host workspace/block-image adapter | private workspace を clone し、`WorkspaceId` に bind し、isolation 時に再利用不能にする |
| `BrokerBackend` | host vsock/Broker adapter | 新しい Broker connection を確立し、idempotent に close する |
| `VmBackend` | Firecracker supervisor | exact workspace と Broker binding で一つの VM を起動し、VM と全 workload process を kill する |
| `CapabilityBackend<G>` | Authority adapter | 生成済み subject を登録し、型付き root grant を注入する |
| `CapabilityRevocationBackend` | Authority adapter | root を revoke し、後続 authorization を fail closed にする |
| `WorkloadBackend` | guest supervisor/container adapter | static restriction を適用し、bind 済み workload だけを release する |

`G` は意図的に generic である。production の Authority Core adapter は `CapabilityBackend<authority_core::state::CapabilityGrant>` を実装する。test の mock は scalar grant を使えるため、Authority Core の authority を組み立てなくても state machine を検証できる。

## snapshot と identity

Firecracker snapshot は session initialization より前に停止していなければならない。VM ID、Broker session ID、request ID、subject ID、capability ID、credential、user workspace を含めてはならない。restore adapter が session-scoped identity を見つけた場合は `SnapshotDescriptor::with_inherited_ids` で報告し、orchestrator は backend 呼び出し前に startup を拒否する。

`OsEntropy` は host OS の random source を読む。別の `CryptographicRandom` を使う production host は CSPRNG でなければならない。orchestrator の process 内 ledger は、失敗した startup を含め、全 identity domain で同一 128-bit value の再利用を拒否する。これは snapshot からの identity 複製と accidental reuse を防ぐが、複数 supervisor process や process restart をまたぐ durable storage の代替ではない。

したがって supervisor は、process restart と snapshot restore をまたいで同じ no-reuse domain を永続化または調整しなければならない。process-local ledger が失われる場合は、外部 allocator が同じ不変条件を満たすことを確認してから新しい orchestrator を構築する。

## workspace adapter

`clone_workspace` は fresh な `WorkspaceId`、`SessionId`、`VmId` を含む完全な `SessionIdentity` を受け取る。実装は次を満たす。

1. 他 session から書き込めない host object へ source を clone する。
2. `WorkspaceId` と `SessionId` の durable binding を記録する。
3. clone 完了後だけ次の lease を返す。

   ```rust,ignore
   WorkspaceLease::new(identity.session_id(), identity.workspace_id())
   ```

4. `isolate_workspace` でその clone を future session の再利用対象から外す。

path や template name を identity として解釈してはならない。clone 後の後段が失敗した場合も、isolation によって同じ workspace ID を future session へ戻してはならない。

capfs repository を接続する場合は、既存 public API を次の順で使う。

```text
capfs::ImportedRepository::open(repo_id, root, limits)
  -> capfs::CapabilityFilesystem::new(imported, kernel, authority, clock)
  -> capfs::spawn_mount(filesystem, mountpoint)
```

imported repository、backing root、namespace registry、生成した workspace binding は同じ session adapter が所有する。別 session の `RepoId` や `NamespaceRegistry` をこの lease と組み合わせてはならない。

## Broker adapter

`establish_broker_session` は identity 内の fresh な `BrokerSessionId` を受け取る。production adapter は bytes を既存 egress protocol 型へ変換する。

```rust,ignore
let broker_session = egress_protocol::session::BrokerSessionId::new(
    identity.broker_session_id().as_bytes(),
);
```

connection ごとに新しい `egress_protocol::session::SessionReplayGuard` を作る。最初の control request は identity から作った fresh な `BrokerRequestId`、strict sequence、`PayloadHash::of_canonical_payload` を使う。restore 後の connection で以前の guard や sequence を再利用してはならない。

返却される session binding を検査してから、次を返す。

```rust,ignore
BrokerLease::new(identity.session_id(), identity.broker_session_id())
```

後続 request は `egress_protocol::operation::BrokerOperation` の closed union を使う。任意 URL、header、method、body、credential を渡してはならない。DNS、redirect、TLS、response size、replay、session budget は Broker が所有する。

## Firecracker adapter

`start_vm` は one-session/one-VM 境界である。`VmId` に対応する Firecracker instance を一つだけ起動し、要求された `WorkspaceId` だけを attach し、意図した vsock channel で要求された Broker session に接続する。binding を全て検証してから次を返す。

```rust,ignore
VmLease::new(
    identity.session_id(),
    identity.vm_id(),
    identity.workspace_id(),
    identity.broker_session_id(),
)
```

`kill_vm` は VM、VM の cgroup、全 workload process を kill する。rollback と stop retry が同じ identity を安全に使えるよう idempotent であること。VM kill が成功するまで workspace isolation を実行してはならない。live VM が別 session から見える workspace への handle を保持する可能性があるためである。

## Authority adapter

Authority adapter は host identity の全割り当て後に grant `G` を受け取る。`G = authority_core::state::CapabilityGrant` の場合、少なくとも次を行う。

1. orchestrator の `SubjectId` を既存の opaque `authority_core::capability::SubjectId` へ変換する。
2. grant より広くない static envelope を持つ `authority_core::state::Subject` を登録する。
3. `authority_core::kernel::CapabilityKernel::register_subject` と `issue_root`、または同じ serialized `CapabilityState` transition を呼ぶ。
4. orchestrator の `CapabilityId` と `issue_root` が返す Authority Core の `CapId` を one-to-one に対応づける。
5. root を guest supervisor の trusted control channel へ注入した後だけ、一致する `CapabilityLease` を返す。

この mapping により別 session の capability が lease を満たせてはならない。rollback または stop では mapped root に `CapabilityKernel::revoke` を呼び、その後 `begin_subject_close`、外部 resource teardown、`finish_subject_close` の順で subject lifecycle を完了する。Authority Core の `auth_epoch` を cache invalidation の source とし、revoke をまたいで allow decision を cache してはならない。

## workload release と stop

`release_workload` は startup の最終 commit である。VM、subject、root capability の lease が同じ `SessionIdentity` に一致し、guest supervisor が static envelope、namespace/mount、cgroup、Landlock、capability drop、`no_new_privs`、seccomp policy を適用してから、workload を start または release する。これらの制限と OS 操作はこの orchestrator crate ではなく production backend の責務である。

stop は次の単調な順序である。

```text
root capability revoke
  -> Firecracker VM kill
  -> Broker close
  -> workspace isolation
  -> Closed
```

orchestrator は前段の cleanup が失敗しても、後段の safe な cleanup を試みる。ただし、VM kill が失敗した場合は workspace isolation を実行しない。全 stage が commit するまで `Closed` とせず、`Stopping` に保持して未完了 stage だけを retry する。startup rollback が失敗した場合も `Ready` へ戻して次の session を受け付けてはならない。revoke、VM kill、Broker close、workspace isolation は idempotent で、effect が commit point に到達しなかった場合は failure を返す。

## 検証状態

この契約の state machine test に加え、production adapter composition test は実 `CapabilityKernel`、Broker / Firecracker / workspace adapter を同じ startup/stop 経路へ接続する。外部 command、filesystem、API、listener は test double であり、実 capfs mount、実 `AF_VSOCK`、実 Firecracker、特権 guest isolation の end-to-end test はまだない。

## 関連

- [Session orchestrator](README.md)
- [Firecracker runtime](../firecracker-runtime/README.md)
- [Supervisor adapter](../supervisor/README.md)
- [Host Egress Broker](../egress-broker/README.md)
- [実装順序](../design/implementation-plan.md)
