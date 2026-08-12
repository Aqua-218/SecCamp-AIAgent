<!-- doc-type: index -->

# ドキュメント

> **対象読者:** この repository の設計・実装・検証を追う全員

設計上の判断と現在の実装は別々に書いてある。「なぜこの構造か」を知りたいときは[設計書](design/README.md)、「なぜ別の案を採らなかったか」は[決定記録](decisions/README.md)、「今どこまで実装され、どこから未検証か」は各 crate の文書を読む。

**mock test の成功を、実機動作の根拠にしない。** コードと API が存在すること、mock / contract test が通ること、特権操作や外部サービスを含む実機検証を行ったことは、各 crate の検証対応表で区別して書く。VM 実起動と full isolation はまだ達成していない。

## 横断文書

| 文書 | 内容 |
|---|---|
| [用語集](glossary.md) | 全体で使う語の定義。文脈で意味が変わる `envelope` / `session` / `subject` / `generation` の衝突を先に載せてある |
| [決定記録](decisions/README.md) | 採用しなかった案とその理由。MADR 形式、1 決定 1 ファイル |
| [文書規約](document-conventions.md) | ページ型ごとの骨格、粒度の目安、CI が検査する構造 |
| [CI/CD operations](ci-cd.md) | GitHub Actions / GitLab CI のゲート、保護設定、署名付きリリース、障害復旧 |

## 設計

| 文書 | 内容 |
|---|---|
| [設計書](design/README.md) | 入口。何を守るのか、選んだ形、文書の読み方 |
| [全体アーキテクチャ](design/architecture.md) | 8 crate の実行時配置、境界を越える 5 つの手段、まだ繋がっていない線 |
| [脅威モデル](design/threat-model.md) | 想定する攻撃者と、防ぐ対象 |
| [Capability モデル](design/capability-model.md) | 権限の表現と委譲 |
| [状態機械と revoke](design/state-and-revocation.md) | 失効がいつから効くか |
| [capfs](design/capfs.md) | filesystem 操作を Capability 判定へ接続する境界 |
| [ネットワークと外部副作用](design/network-egress.md) | egress を閉じた型付き操作に限る理由 |
| [隔離基盤](design/runtime-isolation.md) | VM と、その内側のプロセス隔離 |
| [検証戦略](design/verification.md) | Rust test、Lean 証明、共通 corpus の役割分担 |
| [実装順序](design/implementation-plan.md) | 着手順と現在位置 |

## 実装 crate

| crate | 文書群 | 実装している境界 | 検証の境界 |
|---|---|---|---|
| `authority-core` | [Authority core](authority-core/README.md) | 権限の表現、委譲判定、状態、revoke、監査。Rust と Lean の二重実装 | unit / property / loom / Lean 定理 / 共通 corpus |
| `capfs` | [capfs](capfs/README.md) | backing root、namespace registry、node table、Direct-I/O FUSE adapter | 実 mount test を含む。実 VM 内での動作は未検証 |
| `egress-protocol` | [Broker session envelope](egress-protocol/session-envelopes.md)、[Canonical CBOR](egress-protocol/canonical-cbor.md) | bounded frame、canonical CBOR、session と sequence、budget | module test |
| `egress-broker` | [Host Egress Broker](egress-broker/README.md) | AF_VSOCK frame、replay、budget、公開 HTTPS、型付き GitHub adapter | fake resolver / connector / provider。実 vsock、外部 DNS / HTTPS / GitHub は未検証 |
| `firecracker-runtime` | [Firecracker runtime](firecracker-runtime/README.md) | artifact 固定、dm-verity、jailer、API 順序、snapshot / restore、identity gate | fake command / filesystem / API。実 Firecracker、実 jailer、実 VM は未検証 |
| `runtime-isolation` | [runtime-isolation](runtime-isolation/README.md) | exec 直前の 13 step。namespace、mount、cgroup、Landlock、capability、seccomp | mock backend と純粋関数。実 syscall は未検証 |
| `supervisor` | [Supervisor adapter](supervisor/README.md) | 認証済み connection の subject binding、wire protocol、subject lifecycle | `CapabilityKernel` と `FakeResources`。Linux resource と実 socket は未検証 |
| `session-orchestrator` | [Session orchestrator](session-orchestrator/README.md) | session identity、backend lease、startup / rollback / stop | production adapter composition test。実 VM は未検証 |

## Authority core 文書

| 文書 | 内容 |
|---|---|
| [実装ガイド](authority-core/README.md) | 実装範囲、source map、Rust と Lean の依存関係 |
| [証明の考え方](authority-core/proof-concepts.md) | 証明付きデータ、集合意味論、健全性・完全性、反射律・推移律、空集合の注意点 |
| [パスモデル](authority-core/paths.md) | `CanonicalPath`、`PathPattern`、matching、containment と証明 |
| [Repository identity](authority-core/repository-identities.md) | `RepoId` の責務と exact equality 境界 |
| [File authority](authority-core/file-authorities.md) | effect 集合、request、delegation 判定と証明 |
| [有効期間](authority-core/validity-windows.md) | 単調時刻、半開区間、時刻窓の containment と証明 |
| [Capability](authority-core/capabilities.md) | typed metadata、全 authority family の envelope、時刻付き matching、`weakerThan` と証明 |
| [HTTP fetch authority](authority-core/http-fetch-authorities.md) | canonical host / URL path、GET / HEAD、応答上限、委譲と Broker の責務境界 |
| [GitHub authority](authority-core/github-authorities.md) | installation / repository、閉じた操作、base/head branch、委譲と Broker の責務境界 |
| [Capability state](authority-core/capability-state.md) | subject、静的 envelope、発行、保持、逐次 Derive、revoke と祖先失効 |
| [Authorization guard](authority-core/authorization-guard.md) | effect commit と revoke の線形化、executor 契約、loom の positive / negative control |
| [Subject lifecycle と open handle](authority-core/subject-lifecycle-and-handles.md) | shutdown、`auth_epoch`、handle の subject/object binding と ID 非再利用 |
| [Attempt / effect audit](authority-core/audit-records.md) | 全認可試行と commit 済み effect の区別、記録失敗時の fail closed |
| [Durable audit journal](authority-core/durable-audit.md) | 2 phase WAL、crash 後の `Started`、frame 形式、改竄検出の限界 |
| [検証とテスト](authority-core/verification.md) | Rust unit・状態遷移・property・loom test、Lean example・theorem、共通 corpus の役割分担 |

## capfs 文書

| 文書 | 内容 |
|---|---|
| [実装ガイド](capfs/README.md) | 現在の実装範囲と文書一覧 |
| [Backing repository の事前検証](capfs/backing-preflight.md) | root fd、link 検査、mount・inode identity、startup import |
| [共有 namespace registry](capfs/namespace-registry.md) | `ObjectId` 割り当て、現在 path、generation、open handle、namespace lock 契約 |
| [mount ごとの node table](capfs/node-tables.md) | subject-local `nodeid -> ObjectId`、LOOKUP / FORGET、nodeid 非再利用 |
| [backing への実 I/O](capfs/runtime-backing-io.md) | root fd 相対の解決、毎回の kind / mount / nlink 検査、create と rename の原子性 |
| [Direct-I/O FUSE adapter](capfs/read-only-fuse.md) | 各 FUSE operation、runtime backing I/O、revoke 後の再認可 |

## 文書の使い分け

- 設計と実装が食い違って見える場合は、まず[決定記録](decisions/README.md)を見る。実装が変わって ADR が `Superseded` にされていない可能性がある。
- 「動くのか」を判断するときは、各 crate の検証対応表の**未検証の境界**を先に読む。
- 新しく文書を書くときは[文書規約](document-conventions.md)と `docs/templates/` を使う。

## 関連

- [設計書](design/README.md)
- [用語集](glossary.md)
- [決定記録](decisions/README.md)
- [文書規約](document-conventions.md)
