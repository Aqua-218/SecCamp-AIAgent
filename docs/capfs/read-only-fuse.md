# read-only FUSE adapter

[ドキュメント一覧](../README.md) / [capfs 実装ガイド](README.md) / read-only FUSE adapter

このページは、[`crates/capfs/src/read_only.rs`](../../crates/capfs/src/read_only.rs) と [`crates/capfs/src/runtime.rs`](../../crates/capfs/src/runtime.rs) が、Linuxから届くfilesystem requestをどのようにCapability判定と安全なbacking I/Oへ接続しているかを説明する。

## 何ができるようになったのか

AgentはFUSE mountに対して通常の`open`と`read`を使える。adapterはmountに固定されたsubject、Capability ID、repository IDをrequest payloadから受け取らず、trusted runtimeが構築した`MountAuthority`から使う。`ImportedRepository`もstartup時にhost-assigned `RepoId`を保持し、constructorは両者が一致しない組合せを`RepositoryMismatch`で拒否する。

実装済みのoperationは次である。

| FUSE operation | 現在の処理 |
|---|---|
| `LOOKUP` | parent nodeとchild名を共有namespaceで解決し、見えてよいobjectだけnode tableへ登録する |
| `GETATTR` | nodeまたはopen handleからobjectを得て、現在のCapabilityでmetadataを見せてよいか確認する |
| `FORGET` | mount-local lookup countを減らし、0になったnodeをretireする |
| `OPEN` | read-only flag、現在pathの`ReadData`、backing objectを確認してhandleを登録する |
| `READ` | open時の判断を使い回さず、現在pathと現在時刻でもう一度`ReadData`を確認して`pread`する |
| `RELEASE` | namespace側とAuthority側のhandleを同じobjectについて閉じ、backing fdを破棄する |

`READDIR`と変更系operationはまだ実装していない。したがって、名前を知っている許可pathは通常のpath lookupで読めるが、directory listingを使う一般的な探索は次の実装段階になる。

## metadataはどこまで見せるのか

Capabilityが`/src/private`を許可しているとき、rootと`/src`を完全に隠すと、Linuxは許可対象までpath walkできない。一方、同じ階層の`/docs`まで見せる必要はない。

そこでmetadata visibilityを次の集合にする。

```text
Visible(Capability) = 許可patternが選ぶpath ∪ そのpathへ至る祖先directory
```

たとえば`Prefix(/src/private)`なら、`/`、`/src`、`/src/private`以下は見える。`/src/public`や`/docs`は`ENOENT`になる。`Exact(/src/private/key.txt)`なら、そのfileと祖先だけが見える。

これはdata readの認可ではない。metadata visibilityはactiveなCapabilityのauthorityを検査するだけで、外部effectのaudit recordを作らない。`OPEN`と`READ`は別に`ReadData`を要求し、通常のattempt / effect auditへ記録する。

## LOOKUPでobjectが入れ替わらない理由

名前解決は次の順で行う。

```mermaid
sequenceDiagram
    participant F as read_only.rs
    participant T as NodeTable
    participant N as NamespaceRegistry
    participant K as CapabilityKernel
    participant B as runtime.rs

    F->>T: parent nodeid -> ObjectId
    F->>N: with_child(parent, name)
    Note over N: namespace read lockを保持
    N->>K: with_active_capability(subject, cap, now)
    Note over K: capability read guardを保持
    K->>B: root fdからstatx
    B-->>K: 検証済みmetadata
    K->>T: remember_lookup(ObjectId)
    T-->>F: nodeid
    F-->>F: TTL 0でreply
```

parentのdirectory確認、child pathの作成、`path -> ObjectId`解決、Capability visibility、backing metadata取得、node公開までnamespace read lockを外さない。並行renameはwrite lockを必要とするため、この途中へ割り込めない。

Capability側もactive確認からmetadata取得までshared guardを保持する。revokeが先に完了していればvisibilityは失敗し、inspectionが先に始まっていればrevokeはそのinspectionが終わるまで待つ。この順序により、「失効済みCapabilityを確認したことにして後からmetadataを返す」という中間状態を作らない。

この性質は並行処理でいう線形化可能性を使っている。各操作が一瞬で起きたように並べられる境界をlockで作り、revoke、rename、lookupのどれが先だったかを曖昧にしない。

## OPENからRELEASEまで何を対応させるのか

1回の成功した`OPEN`は、3つのresourceを同じobjectへ結び付ける。

```mermaid
flowchart LR
    fh["FUSE FileHandle<br/>mount-local u64"] --> local["OpenFile<br/>NodeId + ObjectId"]
    local --> afd["backing file descriptor"]
    local --> nh["Namespace open count"]
    local --> kh["Authority OpenHandle<br/>subject + ObjectId"]
```

FUSE handleの数値はmount内で単調に割り当て、失敗したopenの番号も再利用しない。Authority側の`HandleId`には`MountInstanceId`を含めるため、同じCapability kernelを共有するmount同士でhandle identityを混ぜない。runtimeは同じkernelを共有するmountへ異なる`MountInstanceId`を割り当てる必要がある。

`OPEN`に失敗した場合、namespace open countをrollbackし、すでに作ったAuthority handleも閉じる。`RELEASE`ではAuthority handleを閉じられた場合だけnamespace countを減らし、その後にlocal handleとbacking fdを捨てる。途中の不整合を成功として補正せず、mountを`EIO`側へ倒す。

lockを複数使うoperationは次の順序に統一している。

```text
local handle table -> namespace registry -> Capability kernel
```

逆順に取り直すcallbackを作らないことで、open、read、release、将来のrenameが互いに待つ循環を避ける。

## revoke後のreadを止める仕組み

open handleは「このfileを一度は開けた」というresource recordであり、永続的な認可結果ではない。`READ`ごとに次をやり直す。

```text
FileHandle
  -> ObjectId
  -> namespace上の現在CanonicalPath
  -> ReadData(subject, repository, current path, now)
  -> backing fdへのpread
```

Capability kernelは最終認可から`pread`が終わるまでshared guardを保持する。revokeはexclusive guardなので、結果は次のどちらかになる。

```text
READが先:   authorize -> pread完了 -> revoke完了
revokeが先: revoke完了 -> authorization denied -> preadしない
```

さらに`OPEN` replyへ`FOPEN_DIRECT_IO`を付け、entry/attribute TTLを0にする。Linux page cacheだけでreadが完了するとadapterへrequestが戻らず再認可できないため、direct I/Oはrevokeの意味を実syscallまで届けるために必要である。

## backing pathをどう開くのか

`runtime.rs`は絶対pathやprocessのcurrent directoryから対象を開かない。preflightで保持したrepository root fdを起点に、`CanonicalPath`を`openat2`へ渡す。

```text
RESOLVE_BENEATH
RESOLVE_NO_MAGICLINKS
RESOLVE_NO_SYMLINKS
RESOLVE_NO_XDEV
```

metadata用fdまたはread用fdを開いた後、そのfd自身へ`statx(AT_EMPTY_PATH)`を行う。namespaceが記録したdirectory / regular fileの種別、rootと同じmount ID、regular fileのlink count 1を再確認する。preflight後にsymlinkやhard linkへ差し替えられていれば、対象を読まず`EIO`にする。

root fdがあるだけでbacking tree全体が凍結されるわけではない。別processが通常fileの内容を直接変更することは防げないため、supervisorがbacking treeを非信頼processから隠す前提は残る。

## fail closedの返し方

FUSE境界では内部構造を細かく漏らさず、失敗の種類を次のようにまとめる。

| 状況 | errno |
|---|---|
| 権限外path、stale node、invalid child名 | `ENOENT` |
| `OPEN` / `READ`の最終認可失敗 | `EACCES` |
| write access、truncate、append、create intent | `EROFS` |
| directoryをregular fileとしてopen | `EISDIR` |
| unknown / mismatched file handle | `EBADF` |
| oversized read、壊れたflag | `EINVAL` |
| lock poison、registry不整合、backing差し替え | `EIO` |

`FORGET`にはreplyがない。zero count、rootへの通常FORGET、過剰count、未知nodeのようなprotocol/state不整合を観測した場合はmountをfatal状態にし、以後のoperationを`EIO`で拒否する。

## どう検証しているか

`read_only.rs`のmodule testは、許可範囲と祖先だけのlookup、backingとCapabilityのrepository identity不一致、write intent拒否、namespaceとAuthority両方のhandle count、位置指定read、revoke後の既存handle read拒否、releaseによるcleanup、malformed FORGET後のfail closedを直接確認する。

[`crates/capfs/tests/read_only_fuse.rs`](../../crates/capfs/tests/read_only_fuse.rs) は実際にLinux FUSEへmountする。`allowed.txt`を開いて読んだ後にCapabilityをrevokeし、同じOS file descriptorで再度readして`PermissionDenied`になることを確認する。同じmount上の権限外 siblingは`NotFound`になる。

実mount testは`/dev/fuse`が存在しない環境だけskipする。deviceが存在するのにmount設定や権限が壊れている場合はtest failureとして扱う。

まだ検査していないのは、実kernelが送るFORGETの全lifecycle、mount中の敵対的backing差し替え、rename / writeとの競合、複数thread FUSE sessionである。

## 次に実装するもの

次は`READDIR`を`ListDirectory`へ接続する。directory全体を先に返すのではなく、現在のCapabilityで見えてよいentryだけを列挙し、entryを返す直前までnamespace guardを保持する必要がある。

その後に`WRITE`、`CREATE`、`MKDIR`、`UNLINK`、`RMDIR`、no-replace `RENAME`を追加し、open handleとrevokeを含む競合testへ進む。

## 関連

- [Backing repository の事前検証](backing-preflight.md)
- [共有 namespace registry](namespace-registry.md)
- [mount ごとの node table](node-tables.md)
- [Authorization guard](../authority-core/authorization-guard.md)
- [capfs 設計](../design/capfs.md)
