# Capability-based Agent 実行基盤

Agent が書いたコードを実際に走らせ、file を書き換えさせ、外部 API まで操作させるための実行基盤。Agent と Tool を最初から信用せず、何をしてよいかを Capability で明示し、副作用が実際に起きる場所で強制する。

Rust workspace 8 crate と、権限判定を Lean 4 で二重実装した証明群からなる。1 session を所有する deployable な `host-sessiond` と、guest 内の固定イメージ構成も実装済みである。ただし複数 session の運用面と実機で未検証の境界は残るため、何が確かで何が未検証かを[現在どこまで動くのか](#現在どこまで動くのか)に分けて書いてある。

## 何を強制するのか

守る境界は 3 段ある。

1. Agent 同士を subject と Capability で分ける。
2. guest 内の仕組みが破られても、被害をその VM の workspace と session envelope に留める。
3. GitHub などの credential は guest に入れず、host 側だけで扱う。

そのために、境界を越える手段を 5 つに限る。ここに無い経路 — 生の TCP socket、guest から host への任意 file 共有、credential の guest 配布 — は作らない。

| 越える境界 | 手段 | 上限 |
|---|---|---|
| Agent → 自分の workspace | FUSE operation | 上限ではなく、操作ごとに認可 |
| Agent → subject 制御 | supervisor の bounded envelope | 4 KiB、version 1、tag は 2 つ |
| guest → host egress | `AF_VSOCK` の length-prefixed frame | payload 1 MiB |
| host → VM | Firecracker API と guest control API | `network_devices` が空でなければ拒否 |
| host → 外部 | Broker の型付き adapter | response 32 MiB、redirect 5 hop、全体 60 秒 |

guest に `virtio-net` は付かない。外へ出る経路が vsock 1 本しかないので、egress の検査点は Broker に集約される。

file を書く経路と外へ出る経路は、途中はまったく別物でも、最後は各 trust domain の `CapabilityKernel` が提供する同じ `authorize_*_and_execute_classified` 系列に入る。認可してから効果が確定するまで Capability の read guard を離さないため、その間に走った revoke は完了を待つ。これが次の 1 行を経路によらず成立させている。

> revoke が返った後に commit される副作用は、失効した Capability やその子孫だけを根拠には実行されない。

逆に、revoke より先に線形化点を越えた操作は巻き戻さない。詳細は[状態機械と revoke](docs/design/state-and-revocation.md)。

## 実行時の配置

```mermaid
flowchart TB
    subgraph host["ホスト側（信頼する）"]
        orch["session-orchestrator<br/>lifecycle と no-reuse ledger"]
        akh["authority-core<br/>CapabilityKernel"]
        broker["egress-broker<br/>vsock listener と typed adapter"]
        fcrt["firecracker-runtime<br/>artifact 固定・jailer・API 順序"]
        cred[("host-only credential")]
        ws[("clone 済み workspace")]
    end

    subgraph guest["guest（1 session = 1 microVM）"]
        sup["supervisor<br/>subject lifecycle と 4 KiB wire"]
        akg["authority-core<br/>CapabilityKernel"]
        capfs["capfs<br/>FUSE mount と操作ごとの認可"]
        iso["runtime-isolation<br/>exec 直前の 13 step"]
        wl["Agent / Tool"]
    end

    ext["公開 HTTPS / GitHub API"]

    orch --> akh
    orch --> fcrt
    orch --> broker
    cred --> broker
    fcrt ==>|"jailer 起動 / identity 注入"| sup
    fcrt --> ws
    sup --> akg
    capfs --> akg
    sup -->|"RuntimeResources"| iso
    iso ==>|"execve"| wl
    wl ==>|"file syscall / FUSE"| capfs
    wl ==>|"制御 RPC"| sup
    capfs ==>|"backing fd I/O"| ws
    sup ==>|"AF_VSOCK"| broker
    broker --> akh
    broker ==>|"TLS。credential は host に留める"| ext

    classDef trusted fill:#1565c0,color:#fff,stroke:#0d47a1;
    classDef guestside fill:#2e7d32,color:#fff,stroke:#1b5e20;
    classDef untrusted fill:#b71c1c,color:#fff,stroke:#7f0000;
    classDef data fill:#ef6c00,color:#fff,stroke:#e65100;
    classDef external fill:#616161,color:#fff,stroke:#424242;
    class orch,akh,broker,fcrt trusted;
    class sup,akg,capfs,iso guestside;
    class wl untrusted;
    class ws,cred data;
    class ext external;
```

図の実線は現在の composition/code path を表す。実装済みでも実 KVM で未検証の境界があるため、検証の線引きは[全体アーキテクチャ](docs/design/architecture.md)と各 crate の `verification.md` を参照する。

## 現在どこまで動くのか

**mock test の成功を、実機動作の根拠にしない。** この repository はその区別を文書の構造そのものに持ち込んでいる。各 crate の検証ページには `## 未検証の境界` が必須節としてあり、CI が存在を検査する。

### まだ無いもの

- **運用面は一 session の境界に限る。** `host-sessiond` と systemd unit / environment manifest はあるが、複数 session の受け付け、API、認証、HA、operator の再起動 orchestration は無い。
- **実 `Runtime::launch` の jailer / workspace / snapshot restore と外部 DNS / HTTPS / GitHub API は未検証。** opt-in KVM test は direct Firecracker API と、固定 guest runtime image（guest supervisor、isolation launcher、Broker probe）を通すが、production の `Runtime::launch` lifecycle や外部 provider の実通信までは確認していない。
- **直接 probe の post-exec と一部 guest isolation 境界は未検証。** 13 step は特権 host 上で staged rootfs に実適用し、seccomp / Landlock / read-only rootfs / device masking / fd 一掃 / capability 剥奪を確認するが、probe 自体は `execve` を挟まない。`rootfs.source == "/"` の probe 経路と、unmount による rollback は残る。

これは書き忘れではなく順序の結果で、[実装順序](docs/design/implementation-plan.md)が「Authority core と capfs を確定してから統合する」という並びを選んでいる。

### 確かなもの

- `authority-core` の権限判定は Rust と Lean 4 の二重実装で、[150 件の共通 corpus](tests/fixtures/authority-core.tsv) に対して両者の正規化済み判定が byte 単位で一致することを CI が要求する。
- `authority-core` の認可と revoke の線形化は loom で探索し、positive / negative control 付きで検査している。
- `capfs` は `/dev/fuse` がある環境で実 mount test まで通る。
- **guest runtime-image path は実 Firecracker microVM 上で通る。** [`verify-real-guest-control.sh`](scripts/ci/verify-real-guest-control.sh) は production と同じ v2 policy-digest-bound identity/start gate と、guest-supervisor-init → workload-isolation-launcher → Broker probe の runtime image test を別々に実行する。後者は workspace setup、13 step launcher、workload、isolation を跨いだ Broker channel を確認するが、CapFS の全 effectや `Runtime::launch` lifecycle の証拠ではない。
- 13 step isolation は特権 host 上で実 syscall として適用し、seccomp / Landlock / read-only rootfs / device masking / fd 一掃 / capability 剥奪が kernel に強制されることを [`verify-privileged-isolation.sh`](scripts/ci/verify-privileged-isolation.sh) が確認する。
- workspace 全体で line coverage 75% を下限に強制している。

crate ごとの正確な線引きは各 crate の検証対応表（`docs/<crate>/verification.md`）を読む。

## repository の構成

| path | 内容 |
|---|---|
| [crates/](crates/) | Rust workspace の 8 crate。`authority-core` と `runtime-isolation` を依存木の葉とする |
| [lean/](lean/) | Lean 4 による判定の二重実装と定理。`leanprover/lean4:v4.16.0` に固定 |
| [docs/](docs/README.md) | 設計、実装、決定記録、検証対応表。ページ型ごとの構造を CI が検査する |
| [scripts/ci/](scripts/ci/) | CI と local が共有する gate 入口。pipeline から script を呼ぶだけにしてある |
| [ci/gates.yml](ci/gates.yml) | gate 定義の single source of truth。各 gate は `implemented` か `planned` を宣言し、parity check が前者は両 platform に存在すること、後者はどこにも存在しないことを証明する |
| [tests/fixtures/](tests/fixtures/) | Rust と Lean が共有する判定 corpus |
| [.github/workflows/](.github/workflows/) | `ci` / `security` / `release` |
| [.gitlab-ci.yml](.gitlab-ci.yml), [.gitlab/](.gitlab/) | 同等の GitLab pipeline |
| [deny.toml](deny.toml), [.semgrep.yml](.semgrep.yml) | dependency policy と repository 固有の静的解析 rule |

## crate 一覧

| crate | 実装している境界 | 検証の水準 |
|---|---|---|
| [authority-core](crates/authority-core/) | 権限の表現、委譲判定、状態、revoke、監査。Rust と Lean の二重実装 | unit / property / loom / Lean 定理 / 共通 corpus |
| [capfs](crates/capfs/) | backing root、namespace registry、node table、Direct-I/O FUSE adapter | 実 mount test を含む。実 VM 内は未検証 |
| [egress-protocol](crates/egress-protocol/) | bounded frame、canonical CBOR、session と sequence、budget | module test |
| [egress-broker](crates/egress-broker/) | frame、replay、budget、公開 HTTPS、型付き GitHub adapter、deadline-aware transport | fake resolver / connector / provider。Firecracker guest-to-host canonical rejection、UDS peer credential 検査は実装・local test 済み、外部 API と direct `AF_VSOCK` は未検証 |
| [firecracker-runtime](crates/firecracker-runtime/) | artifact 固定（veritysetup を含む）、dm-verity、jailer、API 順序、snapshot pause / restore、identity gate、guest-control PID 1 | fake boundary test に加え、実 Firecracker + dm-verity + guest runtime image の supervisor / isolation launcher / Broker round trip。`Runtime::launch` の実 jailer / snapshot restore は未検証 |
| [runtime-isolation](crates/runtime-isolation/) | exec 直前の 13 step。namespace、mount、cgroup、Landlock、capability、seccomp | mock backend と特権 host の実 syscall probe。launcher の inherited gate / close-on-exec ack は実装済みだが、probe の post-exec、`rootfs.source == "/"`、rollback は未検証 |
| [supervisor](crates/supervisor/) | guest composition、認証済み connection の subject binding、wire protocol、subject lifecycle、workload start gate | `guest-supervisor-init` と `LinuxHostResources` の実装、opt-in guest runtime image、v2 digest-bound start の実KVM試験。CapFS の全 effect は別の実機検証境界 |
| [session-orchestrator](crates/session-orchestrator/) | session identity、backend lease、startup / rollback / stop、deployable one-session owner | `ProductionSessionRuntimeBuilder` / `host-sessiond` composition と local tests。`Runtime::launch` を含む実 VM lifecycle は未検証 |

依存木の底に立つのは `authority-core` と `runtime-isolation` の 2 つで、どちらも workspace の他 crate に一切依存しない。前者は全ての権限判定が集まる場所で、Lean の二重実装はこの crate だけを相手に書かれている。後者は syscall を実際に発行する場所で、隔離境界が「封じ込める対象である権限ロジック」に依存しないことと、単体で監査できることの両方をこの独立性が支えている。この 2 つの不変条件は [`check-crate-isolation.sh`](scripts/ci/check-crate-isolation.sh) が `cargo tree` の実グラフに対して検査する。

逆に、両者を使う側は存在する。`supervisor` は `runtime-isolation` を、`session-orchestrator` は `firecracker-runtime` を呼ぶ。`firecracker-runtime` 自身は `authority-core` と `egress-protocol` に依存する（session identity と Broker frame の型を共有するため）。

## 開発環境の準備

Rust toolchain は [`rust-toolchain.toml`](rust-toolchain.toml) が `1.93.1` に固定する。`rustup` があれば自動で解決される。全ての cargo 呼び出しは `--locked` を使う。

CI と同じ version の外部 tool を入れる。

```bash
scripts/ci/install-cargo-tools.sh nextest coverage security
scripts/ci/install-pipeline-tools.sh   # actionlint / ShellCheck / yq
scripts/ci/install-lean.sh             # elan と Lean toolchain
```

導入先は `.ci-tools/` で、`.gitignore` 済みである。`CI_TOOLS_DIR` で移せる。

## build と test

`scripts/ci/run.sh` が CI と local の共通入口になっている。CI job が直接 cargo を呼ぶことはないので、ここを通せば CI と同じものが走る。

```bash
scripts/ci/run.sh format        # cargo fmt --check
scripts/ci/run.sh check         # 全 target / 全 feature
scripts/ci/run.sh clippy        # -D warnings
scripts/ci/run.sh docs          # rustdoc、警告を error 扱い
scripts/ci/run.sh docs-policy   # docs/ の構造検査

for shard in 1 2 3 4; do scripts/ci/run.sh test "$shard"; done
scripts/ci/run.sh doctest
scripts/ci/run.sh loom          # authority-core の線形化探索
scripts/ci/run.sh coverage      # line coverage 75% 下限
scripts/ci/run.sh audit         # RustSec
scripts/ci/run.sh deny          # license / source / wildcard policy

# scheduled deep gates (Linux; Miri filters and matrix pairs are in ci/gates.yml)
scripts/ci/install-cargo-tools.sh miri sanitizers mutation fuzz
scripts/ci/run.sh miri authority-core path::tests
scripts/ci/run.sh sanitizers address egress-protocol
scripts/ci/run.sh mutation 1 authority-core
scripts/ci/run.sh fuzz egress-protocol frame_decode
scripts/ci/run.sh benchmarks    # pure capability path; FUSE availability is reported separately
```

test shard は crate 単位で決め打ちしてある（`1` が `authority-core` と `egress-protocol`、`4` が `supervisor` と `session-orchestrator`）。1 crate だけ回すなら `cargo test -p <crate> --locked` でよい。

Lean 側と、Rust / Lean の突き合わせ。

```bash
scripts/ci/run.sh lean          # lake build
scripts/ci/run.sh differential  # 150 件 corpus の byte 単位一致
```

`capfs` の実 mount test は `/dev/fuse` を要求する。無い環境では該当 test が skip される。

特権を要する 2 つの検証は hosted pipeline では行わない。

```bash
# 13 step を実 kernel に適用し、境界を kernel に問い直す。root と cgroup v2 の委譲が要る。
scripts/ci/run.sh privileged-isolation

# 実 VM 検証。/dev/kvm を持つ host で行う。初回は guest kernel を build する。
scripts/ci/verify-real-guest-control.sh
```

guest kernel は Firecracker CI の prebuilt を使わず、[`build-guest-kernel.sh`](scripts/ci/build-guest-kernel.sh) が kernel.org の pin 済み source から build する。公開されている Firecracker CI kernel は 5.10 系・6.1 系のいずれも `CONFIG_FUSE_FS` を持たず capfs が mount できない。加えて `runtime-isolation` は Landlock ABI 3 を要求するが、これは 6.2 以降にしか存在しない。source tarball には公開 SHA-256 があるため、署名の無い prebuilt binary を信じるより provenance はむしろ良くなる。信頼の対象が version・digest・[commit 済み config](guest/kernel/)・[commit 済み patch](guest/kernel/) の 4 つに限定される。

どちらも「権限が足りないので skip、よって緑」という状態を作らない。前提を満たさない host では不足理由を出したうえで専用の exit code で終わる。

rootfs は引き続き Firecracker の bucket から取得する。この bucket は署名を公開していないため、script に書かれた digest は「この repository が観測して受け入れた bytes」であって、上流 build の信頼性を示すものではない。rootfs の hash device は download せず、その bytes からその場で `veritysetup format` する。

## CI/CD

GitHub Actions と GitLab CI に等価な fail-closed pipeline を用意し、どちらも repository が所有する同じ script を実行する。platform を移しても品質・セキュリティ・release の契約が変わらないようにするためで、[`ci/gates.yml`](ci/gates.yml) に無い gate が workflow 側にあれば parity 検査で落ちる。

manifest は「計画」と「記録」を兼ねるため、gate ごとに `status` を持つ。`implemented` は repository 所有の script が実際に走り両 platform が呼ぶ状態、`planned` は設計だけあって何も走らない状態で、parity は後者がどちらの platform にも存在しないことを要求する。この区別が無いと「毎回走る gate」と「意図だけの gate」が同じ見た目になり、parity 検査は通りようがない。現在 39 gate が implemented、planned は 0 である。nightly の Miri / sanitizer、bounded mutation / fuzz、noise-aware benchmark も実行経路と seed / baseline を持ち、`ci/gates.yml` と両 platform の deep pipeline が同じ matrix を呼び出す。

「証拠を超えて主張しない」という方針は gate 自身にも適用してある。Miri は純粋な test module のみ、sanitizer は protocol test binary、mutation / fuzz は bounded selection、benchmark は capability decision の committed baseline を実行する。特権 FUSE の可否は標準 hosted benchmark の green に変換せず、availability として別表示する。

実 VM 検証と特権 isolation 検証は hosted runner では動かないため、`kvm` / `privileged` label を持つ self-hosted runner 上で schedule 実行する。各 host に何が必要かは [CI/CD operations](docs/ci-cd.md) に書いてある。

release 境界は、この repository が今日証明できる artifact — `authority-corpus` の Linux binary — に意図的に限定してある。one-session の systemd unit と environment manifest は存在するが、複数 session の production deployment/control plane は無いため、production deployment job は置いていない。

運用の詳細（保護設定、署名付き release、障害復旧、残存リスク）は [CI/CD operations](docs/ci-cd.md) にある。

## ドキュメント

入口は [docs/README.md](docs/README.md)。目的別の行き先は次のとおり。

| 知りたいこと | 読む場所 |
|---|---|
| 何を守るのか、なぜこの構造か | [設計書](docs/design/README.md) |
| 8 crate が実行時にどう並ぶか | [全体アーキテクチャ](docs/design/architecture.md) |
| なぜ別の案を採らなかったか | [決定記録](docs/decisions/README.md) |
| 語の意味（`envelope` / `session` / `subject` / `generation` の衝突を含む） | [用語集](docs/glossary.md) |
| 今どこまで実装され、どこから未検証か | 各 crate の `docs/<crate>/verification.md` |
| 文書を追加・変更するときの規約 | [文書規約](docs/document-conventions.md) |

新しく文書を書くときは [`docs/templates/`](docs/templates/) の骨格を使う。`scripts/ci/check-docs.sh` が doc-type marker、必須節、mermaid の有無、相対リンクの解決を検査する。

```bash
scripts/ci/check-docs.sh docs/capfs/namespace-registry.md
```

## ライセンス

Copyright © 2026 Aqua-218.

このプロジェクトは [GNU Affero General Public License v3.0 only](LICENSE)（`AGPL-3.0-only`）で公開する。改変版をネットワーク越しに利用させる場合を含め、対応するソースコードの提供条件はライセンス本文に従う。
