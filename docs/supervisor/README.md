<!-- doc-type: index -->

# Supervisor adapter

[ドキュメント一覧](../README.md) / Supervisor adapter

> **対象読者:** guest supervisor の統合担当者、Authority Core 実装者、runtime adapter のレビュー担当者

`supervisor` は、認証済み local connection、既存の `authority-core` kernel、OS runtime resource の間に置くホスト側 lifecycle adapter である。namespace、cgroup、mount、descriptor syscall 自体は実装せず、`RuntimeResources` が提供する token と操作へ委譲する。

## 文書一覧

| 節 | 対象ソース | 内容 |
|---|---|---|
| [identity 境界](#identity-境界) | [`supervisor.rs`](../../crates/supervisor/src/supervisor.rs) | connection identity から subject を解決する。wire 上の claim を認可に使わない |
| [wire protocol](#wire-protocol) | [`protocol.rs`](../../crates/supervisor/src/protocol.rs) | 4 KiB の bounded envelope、閉じた tag 集合 |
| [lifecycle](#lifecycle) | [`supervisor.rs`](../../crates/supervisor/src/supervisor.rs) | subject setup の transaction と単調な shutdown |
| [Authority と handle の境界](#authority-と-handle-の境界) | [`supervisor.rs`](../../crates/supervisor/src/supervisor.rs) | Authority Core への委譲、runtime handle の open と close |

`supervisor.rs` は 1,323 行ある。上の 4 節はその要約で、独立した概念ページと契約ページに分ける予定。

## identity 境界

transport は受理済み socket identity と peer credential を持つ `ConnectionIdentity` を渡す。`CallerResolver` はその identity を host が割り当てた `authority_core::capability::SubjectId` へ写像する。wire request に含まれる `claimed_subject` は診断用に保持できるが、`Supervisor::dispatch_wire` は認可に使わない。production caller resolver は、request bytes を decode する前に `SOCK_SEQPACKET` または同等の認証済み connection へ subject binding を確定させる必要がある。

## wire protocol

wire protocol は最大 4 KiB の bounded binary envelope である。version は固定値 1、tag は `CloseSubject` と `CloseHandle` の閉じた集合、body length は datagram 全体と一致しなければならない。文字列 field は UTF-8 で最大 256 bytes、trailing data、unknown tag、malformed length、oversized datagram は dispatch 前に拒否する。

`WireRequest` の subject field は untrusted claim であり、実際の caller は受理済み connection identity から解決する。このため、別 subject を claim した `CloseSubject` や `CloseHandle` は claim を根拠に権限を得ない。

## lifecycle

subject setup は一つの transaction であり、resource は次の順で確保する。

1. cgroup を作る。
2. subject の capability filesystem を mount する。
3. private control descriptor を開く。
4. `AuthorityKernel` に subject と static authority envelope を登録する。
5. workload を開始する。
6. すべて成功してから subject を `Running` として公開する。

途中で失敗した場合は、確保済み resource だけを rollback する。authority registration 後の rollback は `begin_subject_close` を先に行い、workload、control fd、authority handle、mount、cgroup を安全な順で cleanup し、全外部 resource の cleanup が成功した後だけ `finish_subject_close` を行う。

shutdown は単調で fail closed である。

```text
Running
  -> begin_subject_close（新規要求停止、保持 Capability の失効）
  -> stop workload
  -> close control fd と runtime handle
  -> unmount capability filesystem
  -> remove cgroup
  -> finish_subject_close
  -> Closed
```

全 safe cleanup phase を順に試み、いずれかが失敗した場合は subject を `Closing` に保持する。`Closing` と `Closed` は dispatch、root issuance、derivation、handle 操作を拒否する。transient resource failure は、未完了の cleanup を retry できる。

## Authority と handle の境界

`AuthorityKernel` は既存 Authority Core の subject registration、root issuance、derivation、revoke、subject close、open-handle registry を adapter 越しに呼ぶ。derivation の caller は常に resolver が返した subject であり、wire claim ではない。

runtime handle は、Authority Core へ registration する前に `RuntimeResources::open_handle` で開く。registration が失敗した場合は runtime handle を閉じる。handle は authority-core identity のままで、close 後の rebinding は許可しない。stale または foreign handle は resource close 前に拒否する。

## 検証状態

protocol の round trip、unknown tag、length/trailing data、4 KiB 上限は module test で検証済みである。supervisor の setup/shutdown 順序、partial setup rollback、caller identity による subject spoofing 防止、root/derive/revoke、stale handle、cleanup failure の retry は `CapabilityKernel`、`StaticCallerResolver`、`FakeResources` を使う test で検証済みである。

この crate には Linux の namespace/cgroup/mount 実装、実 socket listener、実 workload、実 guest control channel はない。したがって OS resource の実適用、実 connection credential、VM 内 end-to-end は未検証である。

focused test は次のとおりである。

```bash
cargo fmt --manifest-path crates/supervisor/Cargo.toml -- --check
cargo test --manifest-path crates/supervisor/Cargo.toml
cargo clippy --manifest-path crates/supervisor/Cargo.toml --all-targets -- -D warnings
```

## 関連

- [Authority Core の subject lifecycle](../authority-core/subject-lifecycle-and-handles.md)
- [session orchestrator](../session-orchestrator/README.md)
- [隔離基盤の設計](../design/runtime-isolation.md)
- [検証戦略](../design/verification.md)
