<!-- doc-type: exempt -->

# 用語集

[ドキュメント一覧](README.md) / 用語集

> **対象読者:** 文書を読む全員、新しい語を導入する実装者

このページは `docs/` 全体で使う語の定義を集める。定義は現在の実装から起こしている。実装を変えて語の意味が変わる場合は、このページを同じ commit で更新する。

同じ語が文脈によって別の対象を指す場合は「[衝突する語](#衝突する語)」で明示する。まずそこを読むと、文書間の読み違いを避けられる。

## 衝突する語

これらは文脈なしで使わない。必ず修飾語を付ける。

| 語 | 文脈 | 指すもの |
|---|---|---|
| **envelope** | Broker wire | `BrokerEnvelope`。session、sequence、request ID、payload hash を持つ wire 上の封筒 |
| | Capability | authority body に typed metadata と有効期間を付けた `Capability` 全体 |
| | subject 登録 | `StaticAuthorityEnvelope`。subject 登録時に与える静的な権限一式 |
| **session** | orchestrator | 隔離された 1 つの agent session。`SessionIdentity` が識別する |
| | Broker | Broker connection の単位。`BrokerSessionId` が識別する。restore 後に新しく確立する |
| **subject** | Authority core | 権限を保持する主体。`SubjectId` が識別する |
| | supervisor | lifecycle を持つ実行単位。Authority core と同じ `SubjectId` 空間を使う |
| **generation / epoch** | capfs | `NamespaceGeneration`。共有 namespace の path mapping の単調な version |
| | Authority core | `AuthorizationEpoch`。revoke が有効になると進む session-local な counter |

`generation` と `epoch` はどちらも単調増加する `u64` だが、対象が違う。cache を持つ実装は、どちらを key に含めるべきかを取り違えない。

## Capability と authority

| 語 | 定義 |
|---|---|
| **authority body** | 権限の中身。file なら repository × effect 集合 × path pattern の 3 軸。有効期間と metadata を含まない |
| **Capability** | authority body に typed metadata と有効期間を付けた `Capability`。実際に保持・委譲されるのはこの単位 |
| **委譲 (delegation)** | 親 Capability から、親を越えない子を導出すること |
| **`weakerThan` / `below`** | 子が親を越えないことの構造判定。3 軸をそれぞれ比較する |
| **`FileEffect`** | file 操作の効果。`ReadData`、`ListDirectory`、`WriteData`、`Truncate`、`CreateFile`、`CreateDirectory`、`RemoveFile`、`RemoveDirectory`、`Rename`、`SetMetadata`、`ReadLink`、`CreateSymlink`、`CreateHardLink` の 13 種 |
| **`FileEffects`** | `FileEffect` の集合。Rust は private な `u16` bitset、Lean は membership 関数として持つ |
| **`RepoId`** | repository の identity。比較は exact equality だけで、前方一致や包含を持たない |
| **`SubjectId`** | 権限を保持する主体の identity。host が割り当てる |
| **`CapId`** | Capability の identity。再利用しない |
| **`HandleId`** | open handle の identity。subject と object の両方に binding される |
| **`AuthorizationEpoch`** | revoke が有効になると進む session-local な `u64`。cache 利用者は観測した epoch を key に含め、変化したら破棄する |
| **祖先失効** | ある Capability を revoke したとき、そこから派生した子孫も失効すること |
| **attempt** | 認可の試行。成功・失敗にかかわらず `AttemptRecord` として記録する |
| **effect commit** | 副作用が実際に確定すること。`CommitReceipt` が証拠になる |
| **commit point** | effect が確定する境界。Capability の read guard はここまで保持する |
| **fail closed** | 検査や記録が失敗した場合に、許可ではなく拒否へ倒すこと |
| **`AuthorityPolicyDigest`** | host と guest が同じ authority policy を参照していることを束縛する digest。digest の一致は policy の内容を証明するものではなく、v2 control request と lease の対応を検査するために使う |
| **revocation barrier** | revoke の完了を guest control ACK、VM 終了、Broker close などの境界と結び、後続の resource reuse を許す前に必要な完了点 |

## 証明で使う語

| 語 | 定義 |
|---|---|
| **健全性 (sound)** | 構造判定が `true` なら、意味論上の包含が成り立つこと。安全側の保証 |
| **完全性 (complete)** | 意味論上の包含が成り立つなら、構造判定が `true` になること。正しい委譲を誤拒否しない保証 |
| **反射律 (refl)** | 同じ authority どうしの比較が `true` になること |
| **推移律 (trans)** | 多段委譲しても最上位より強くならないこと |
| **空虚な真 (vacuous truth)** | 空集合はどの集合の部分集合でもあるため、要素が 1 つも無い側の全称命題が反例を持たず真になること |
| **共通 corpus** | Rust と Lean の両方へ同じ入力を流し、判定結果を突き合わせる test case 集合 |

## path

| 語 | 定義 |
|---|---|
| **`CanonicalPath`** | 正規化済みの path。型の入口で不正な形を拒否する |
| **`PathPattern`** | 許可する path の範囲。`Exact` と `Prefix` の 2 種類だけを持つ |
| **containment** | ある pattern が表す path 集合が、別の pattern の集合に含まれること |

## capfs

| 語 | 定義 |
|---|---|
| **backing repository** | 実体を持つ workspace tree。startup 前に object の種類、symlink target、hard link の名前集合を検査する |
| **root fd** | backing repository の root directory を指す file descriptor。以降の I/O は全てこれを起点にする |
| **`ObjectId`** | 共有 namespace 内の object identity。path から独立し、再利用しない |
| **`NamespaceGeneration`** | 共有 namespace の path mapping の単調な version。`initial()` が `0` |
| **`nodeid`** | subject-local な FUSE node identity。path でも `ObjectId` でもない。再利用しない |
| **node table** | subject ごとの `nodeid -> ObjectId` 対応表 |
| **open handle** | 開いたままの file / directory。rename と remove を止める根拠になる |
| **Direct-I/O** | FUSE handle に `FOPEN_DIRECT_IO` を付け、page cache を経由させない I/O mode。現在の `capfs` では writable handle にだけ使い、read-only handle は page cache と同期的な revoke invalidation を使う。全操作が direct であることを意味しない |
| **cache-aware FUSE adapter** | read-only handle の page cache を利用しつつ、`RevocationObserver` が revoke completion 前に cached inode/page を無効化する `capfs` の実装方式 |
| **`ExternalAliasPolicy`** | backing repository の外にも名前を持つ inode の扱い。既定の `Materialize` は上限内で repository 内へ内容を複製し、`Reject` は repository 全体を拒否する |
| **startup import** | 初期 manifest を registry へ原子的に取り込む処理 |

## Broker と egress

| 語 | 定義 |
|---|---|
| **bounded frame** | 4 bytes の big-endian length prefix と payload。長さを検査してから payload を確保する。上限 1 MiB |
| **canonical CBOR** | bounded frame の中で唯一許される request schema。非正規形は拒否する |
| **payload hash** | request payload の hash。retry が同一要求かの判定に使う |
| **`BrokerSessionId`** | Broker connection の identity |
| **sequence** | session 内の要求順序。`0` から始まり、直前の次だけを受理する |
| **replay guard** | 同一 `(session, sequence, request ID, payload hash)` の retry に cache 済み応答を返し、adapter を再実行しない仕組み |
| **session budget** | session ごとの利用上限。認可の前に予約する |
| **`CredentialHandle`** | credential の opaque な参照。guest へは返さない |
| **`PublishBranchPlan`** | branch 更新の事前条件。expected-old / expected-new object を持ち、これが無ければ publish できない |
| **型付き操作** | 生 URL や任意 HTTP メソッドではなく、閉じた集合として定義された操作。`GET` / `HEAD` の公開 HTTPS と `PublishBranch` / `CreatePullRequest` |

## session orchestrator と runtime

| 語 | 定義 |
|---|---|
| **lease** | backend が effect を commit した後にだけ返す証拠。session identity と対象 resource identity を保持する |
| **`IdentityKind`** | 割り当てる identity の種別。`Vm`、`Session`、`Subject`、`Workspace`、`Capability`、`Request`、`BrokerSession` の 7 種 |
| **no-reuse ledger** | 過去に使用した identity の byte value を、種別をまたいで拒否する台帳。失敗した startup で割り当てた値も予約済みのまま残す |
| **durable ledger** | restart をまたいで非再利用を保つ ledger。exclusive ownership、version/checksum 検証、append 後の `sync_data` を要求する |
| **`SnapshotDescriptor`** | restore 元の記述。session-scoped identity を含む場合は restore を拒否する |
| **pinned artifact** | hash を固定した boot artifact |
| **dm-verity** | block device の内容を hash tree で検証する Linux の仕組み |
| **jailer** | Firecracker を制限された環境で起動させる補助プロセス |
| **`IsolationReceipt`** | isolation の全 step が成功し、exec 前の境界が完成したことの機械的な証拠 |
| **rollback 不可 step** | namespace、`pivot_root`、Landlock、capability drop、`no_new_privs`、seccomp のように kernel 上で安全に戻せない step。失敗後は child を再利用しない |
| **Landlock** | path 単位の access 制限を kernel へ宣言する Linux の仕組み。ABI version を query して不足なら fail closed |
| **seccomp** | syscall の allowlist。一致しない syscall は `EPERM`、不正 arch は process kill |

## 検証状態を表す語

これらは検証の強さが違う。文書で言い換えない。

| 語 | 意味 |
|---|---|
| **mock / fake で検証済み** | test double を注入した module test で確認した。実 syscall・外部サービス・実 VM は経由していない |
| **実 mount 上で検証済み** | 実際の FUSE mount を伴う test で確認した |
| **model 検査済み** | loom などで並行実行の順序を網羅探索した |
| **証明済み** | Lean の定理として証明した。Rust バイナリを直接証明したという意味ではない |
| **`verified`** | `verification-status.yml` の宣言 scope で required gate が成功し、その scope の evidence が記録された状態。別 scope、別 runner、未列挙の入力空間まで含めない |
| **`unverified`** | 境界は既知だが、宣言した scope の required evidence がまだ揃っていない状態 |
| **`blocked`** | credential、特権 runner、別アーキテクチャ、独立 reviewer など、名前付き prerequisite または外部 owner が不足して gate を実行できない状態 |
| **evidence** | gate の実行を再現・追跡する command、source、test の組。manifest の checker は evidence command を実行しない |
| **未検証の境界** | この repository の test、gate、または declared evidence が対象にしていない範囲。`verified` の隣接範囲を自動的に含めない |

## 多言語文書で使う語

| 語 | 定義 |
|---|---|
| **localized** | `docs/i18n/<locale>/README.md` の型。先頭 marker と locale marker を持つ言語別の入口であり、翻訳の完全性や正本の言語を意味しない |
| **locale hub** | 一つの locale の詳細ページ、対応する原文、他 locale への言語ナビゲーションを集約する README |
| **canonical source** | ある記述の意味を照合する source code または原文ページ。i18n 監査で言語ごとの対応を確認するまでは、英語正本と同義に扱わない |

## 関連

- [文書規約](document-conventions.md)
- [ドキュメント一覧](README.md)
- [設計書](design/README.md)
- [決定記録](decisions/README.md)
