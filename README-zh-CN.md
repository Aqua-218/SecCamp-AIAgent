<!-- locale: zh-CN -->
<!-- translation-source: README.md -->

# Airlock

Capability-based AI Agent Runtime — 基于 capability 的 AI agent 运行时

[English](README.md) · [日本語](README-ja.md) · [简体中文](README-zh-CN.md) · [繁體中文](README-zh-TW.md) · [한국어](README-ko.md) · [Español](README-es.md) · [Français](README-fr.md) · [Deutsch](README-de.md) · [Português (Brasil)](README-pt-BR.md)

[![CI](https://github.com/Aqua-218/SecCamp-AIAgent/actions/workflows/ci.yml/badge.svg)](https://github.com/Aqua-218/SecCamp-AIAgent/actions/workflows/ci.yml)
[![License: AGPL-3.0-only](https://img.shields.io/badge/license-AGPL--3.0--only-blue.svg)](LICENSE)

在 Linux 和 Firecracker 上运行不受信任的 agent 与 tool workload，同时让 capability 检查、隔离、egress policy、审计和恢复都停留在副作用发生的边界上。

> **Status:** 这是一个 source repository，并不宣称绝对隔离。在此 revision 中，verification manifest 记录了 38 个 `verified` claim 和 3 个 `blocked` claim。请先阅读下面的 scope 表，再把任何结果当作其他环境的证据。

<a id="start-here"></a>
## 从这里开始

| 目标 | 阅读 |
|---|---|
| 运行 hosted smoke test | [Quick start](#quick-start) |
| 理解 trust boundary | [Architecture and trust boundaries](#architecture-and-trust-boundaries) |
| 查看哪些已验证、哪些未验证 | [Verification status](#verification-status) 和 [`docs/verification-status.yml`](docs/verification-status.yml) |
| 部署 production daemon | [`deploy/README.md`](deploy/README.md) |
| 阅读跨 crate 设计 | [`docs/design/architecture.md`](docs/design/architecture.md) |
| 浏览全部项目文档 | [`docs/README.md`](docs/README.md) / [简体中文 docs hub](docs/i18n/zh-CN/README.md) |

<a id="overview"></a>
## 概览

runtime 将 agent、tools 和 workload process 视为 untrusted。文件操作、公开 HTTPS fetch 以及类型化 GitHub 操作都是 closed data type，而不是任意 command。`authority-core` 生成 authorization decision；CapFS 和 host Egress Broker 在 filesystem 或 external effect 发生前立即执行它。

production 的执行单元是一个 worker、一个 session 和一个 Firecracker microVM。非特权 `host-controld` 通过经过认证且受 quota 限制的 start/stop request 接纳多个 worker。每个 `host-sessiond@ID.service` 拥有一个 session 及其 cleanup record。当前 trust model 是 single-host；multi-host HA、distributed revocation 和 replicated Broker state 不在 repository 的保证范围内。

<a id="what-the-runtime-enforces"></a>
## runtime 强制的约束

- **Typed least privilege:** file effect、HTTP method 与 path、以及 GitHub operation 都由 closed Rust type 和 bounded authority envelope 表示。
- **Effect-point authorization:** CapFS 对每个 filesystem effect 重新授权；host Broker 通过 host `CapabilityKernel` 授权类型化的 external effect。
- **Revocation linearization:** authorization read guard 一直保持到 effect 的 commit point。`revoke` 返回后，后续 commit 不能只依赖已撤销的 capability 或其 descendant。撤销前已 commit 的 effect 不会 rollback。
- **No guest credentials:** provider credential 留在 host 上，从不放入 guest image，也不在 response 中返回。
- **No guest network device:** guest 没有 `virtio-net`；egress 使用 bounded `AF_VSOCK` protocol 和类型化 host adapter。
- **Identity non-reuse:** session、request、workspace、VM、Broker session、subject 和 capability identity 都记录在 durable ledger 中，restart 后不会被默默复用。
- **Bound guest startup:** pinned artifact、dm-verity、paused restore 以及绑定 policy digest 的 v2 guest acknowledgement 共同控制 workload release。
- **Fail-closed recovery:** 模糊的 effect 记录为 `CommitUnknown`；partial shutdown 和损坏的 durable record 会 fail closed，并为下一次启动留下 typed recovery state。

<a id="architecture-and-trust-boundaries"></a>
## 架构与 trust boundary

host service、pinned artifact、Firecracker/jailer 和 host kernel 属于 trusted host boundary。guest service 强制 guest-side contract；agent 与 tool process 是 untrusted。该图展示预期的 effect path，而不是 VM escape resistance 的证明。

```mermaid
flowchart TB
    operator["Operator / host-control"]
    external[["Public HTTPS / GitHub API"]]

    subgraph host["Trusted host"]
        controller["host-controld<br/>unprivileged admission"]
        worker["host-sessiond@ID<br/>one session owner"]
        authority["authority-core<br/>host CapabilityKernel"]
        runtime["firecracker-runtime<br/>Firecracker + jailer"]
        broker["egress-broker<br/>typed adapters"]
        ledger[("identity ledger / audit / WAL")]
        workspace[("per-session workspace")]
        credential[("host-only credential")]
    end

    subgraph guest["Guest microVM — workload boundary"]
        guest_gate["guest-control + supervisor<br/>identity / subject gate"]
        guest_authority["authority-core<br/>guest CapabilityKernel"]
        capfs["capfs<br/>Direct-I/O FUSE"]
        isolation["runtime-isolation<br/>ordered Linux isolation"]
        workload["Agent / Tool<br/>untrusted"]
    end

    operator -->|"authenticated start / stop"| controller
    controller -->|"fixed systemd template + polkit"| worker
    worker -->|"reserve / recover"| ledger
    worker -->|"restore + identity binding"| runtime
    worker -->|"issue exact authority"| authority
    worker -->|"open bounded channel"| broker
    runtime -->|"policy-bound v2 gate"| guest_gate
    guest_gate -->|"register subject"| guest_authority
    guest_gate -->|"mount authorized view"| capfs
    guest_gate -->|"apply isolation"| isolation
    isolation -->|"literal argv via execve"| workload
    workload -->|"file syscalls"| capfs
    capfs -->|"authorize each effect"| guest_authority
    capfs -->|"backing fd I/O"| workspace
    workload -->|"bounded request"| broker
    broker -->|"authorize external effect"| authority
    credential -->|"never enters guest"| broker
    broker -->|"TLS"| external

    classDef trusted fill:#1565c0,color:#fff,stroke:#0d47a1;
    classDef guestService fill:#2e7d32,color:#fff,stroke:#1b5e20;
    classDef untrusted fill:#b71c1c,color:#fff,stroke:#7f0000;
    classDef storage fill:#ef6c00,color:#fff,stroke:#e65100;
    classDef outside fill:#616161,color:#fff,stroke:#424242;
    class controller,worker,authority,runtime,broker trusted;
    class guest_gate,guest_authority,capfs,isolation guestService;
    class workload untrusted;
    class ledger,workspace,credential storage;
    class operator,external outside;
```

边界穿越路径被刻意保持狭窄。

| Boundary | Path | Important limits |
|---|---|---|
| Workload → workspace | CapFS Direct-I/O FUSE | 每个 effect 都重新授权；repository、path 和 effect 必须匹配 |
| Workload → supervisor | `SOCK_SEQPACKET` | 4 KiB request bound，以及由 kernel 推导的 `SO_PEERCRED` identity |
| Guest → host | `AF_VSOCK` framed transport | 4-byte length prefix、1 MiB payload bound、canonical CBOR、session/replay/budget checks |
| Host → microVM | Firecracker API plus guest-control API | Pinned artifact digests、dm-verity、paused restore、policy-bound v2 ACKs |
| Host → external provider | Typed Broker adapter | 仅允许 public HTTPS 或类型化 GitHub operation；遵守 DNS/IP、redirect、response 和 deadline policy |

raw guest TCP、任意 host filesystem sharing 和 guest credential injection 不属于该 interface。launcher 不解释 shell string，而是通过 `execve` 使用 literal argv 执行 image-configured program。如果 workload 自己启动 shell，namespace、cgroup、seccomp、Landlock、read-only rootfs 和 capability boundary 仍然适用；本项目不宣称能让 shell parsing 安全。

startup 按以下顺序 commit resource：

```text
workspace → Broker → VM → capability → workload
```

shutdown 按下面的 dependency order 进行。失败的 stage 会以 durable 形式保留，只 retry 尚未完成的 stage：

```text
capability revoke → VM kill → Broker close → workspace isolation → Closed
```

<a id="verification-status"></a>
## 验证状态

machine-readable source of truth 是 [`docs/verification-status.yml`](docs/verification-status.yml)。status 是按 scope 划分的 claim，不是覆盖所有可能环境的 green-list。`verified` 表示 required gate 在声明的 scope 中运行；`blocked` 记录不可用的 prerequisite 或 external owner。本 revision 的 manifest 包含 38 个 `verified` claim 和 3 个 `blocked` claim，没有 `unverified` claim。

| Scope | Current manifest status | Evidence and boundary |
|---|---|---|
| Hosted | 14 verified | Locked Rust tests、Clippy、property tests、durable-state tests，以及 claim 所覆盖的 Rust/Lean corpus |
| Privileged Linux | 10 verified, 1 blocked | Real FUSE、Linux isolation、rollback、supervisor resources 和 controlled HTTPS fixtures；blocked claim 是 aarch64 privileged architecture runner |
| KVM | 14 verified | Pinned Firecracker guest、dm-verity、guest-control、production `Runtime::launch` / `SessionOwner`、全部 13 个声明的 CapFS effects，以及 multi-session cleanup gates |
| External | 2 blocked | Live GitHub credential/provider mutation 和独立 external review evidence 在此 checkout 中不可用 |

这些结果不建立 VM escape resistance、host-kernel/KVM/Firecracker correctness、physical 或 microarchitectural side-channel resistance，也不建立任意 external-provider behavior。各 crate 的 verification page 列出假设和 finite-test boundary：

- [`authority-core` verification](docs/authority-core/verification.md)
- [`capfs` verification](docs/capfs/verification.md)
- [`egress-broker` verification](docs/egress-broker/verification.md)
- [`firecracker-runtime` verification](docs/firecracker-runtime/verification.md)
- [`runtime-isolation` verification](docs/runtime-isolation/verification.md)
- [`session-orchestrator` verification](docs/session-orchestrator/verification.md)
- [`supervisor` verification](docs/supervisor/verification.md)

<a id="quick-start"></a>
## 快速开始

该路径只运行 hosted code。它不会启动 service，不要求 root，不挂载 FUSE，不需要 `/dev/kvm`，也不会读取 provider credential。首次 checkout 需要网络来获取 Cargo 的 locked dependency；后续运行使用本地 Cargo cache。

<a id="prerequisites"></a>
### 前置条件

- Linux、Git 和 `rustup`
- 由 [`rust-toolchain.toml`](rust-toolchain.toml) 选择的 Rust `1.93.1`

<a id="run-a-hosted-smoke-test"></a>
### 运行 hosted smoke test

```bash
git clone https://github.com/Aqua-218/SecCamp-AIAgent.git
cd SecCamp-AIAgent

cargo test --locked -p authority-core --all-targets
cargo run --locked -p session-orchestrator --bin host-sessiond -- --help
```

第一个 command 运行 authority model 及其 corpus-facing tests。第二个 command 打印 production daemon 所需的 artifact、snapshot、authority 和 egress configuration；`host-sessiond` 刻意没有会启动不完整 production stack 的 placeholder mode。

<a id="development-and-verification"></a>
## 开发与验证

本地开发和 CI 使用同一个 [`scripts/ci/run.sh`](scripts/ci/run.sh) entry point。只安装计划运行的 gate 所需的 tool group；tool 会放在 repository 私有的 `.ci-tools/` directory 下。

```bash
scripts/ci/install-cargo-tools.sh nextest coverage security public-api
scripts/ci/install-pipeline-tools.sh
scripts/ci/install-lean.sh
```

<a id="standard-hosted-gates"></a>
### 标准 hosted gates

```bash
scripts/ci/run.sh format
scripts/ci/run.sh check
scripts/ci/run.sh clippy
scripts/ci/run.sh docs
scripts/ci/run.sh docs-policy

for shard in 1 2 3 4; do
  scripts/ci/run.sh test "$shard"
done

scripts/ci/run.sh doctest
scripts/ci/run.sh loom
scripts/ci/run.sh lean
scripts/ci/run.sh differential
scripts/ci/run.sh coverage
scripts/ci/run.sh audit
scripts/ci/run.sh deny
scripts/ci/run.sh api-surface
```

coverage gate 使用 workspace line coverage 75% 的下限。这个 threshold 是 CI gate，不是 coverage badge，也不是所有 privileged 或 KVM path 都被执行过的 claim。Miri、sanitizers、mutation testing、fuzzing 和 benchmarks 的准确 matrix 位于 [`ci/gates.yml`](ci/gates.yml)。

<a id="privileged-and-kvm-gates"></a>
### 特权 Linux 与 KVM gates

这些 command 需要其 script 声明的 prerequisite。缺少 `/dev/fuse`、`/dev/kvm`、delegated cgroup v2、device-mapper tools 或 pinned guest artifacts 是 verification failure，而不是成功的 skip。

```bash
# Root and delegated cgroup v2
scripts/ci/run.sh privileged-isolation

# Root, /dev/kvm, /dev/vhost-vsock, veritysetup, busybox, and mkfs.ext4
scripts/ci/verify-real-guest-control.sh
scripts/ci/verify-real-session-owner.sh
```

完整的 protected-runner contract 见专用的 [crate verification pages](#verification-status) 和 [`docs/ci-cd.md`](docs/ci-cd.md)。

<a id="running-host-sessiond"></a>
## 运行 `host-sessiond`

可部署的 entry point 是 [`host-sessiond`](crates/session-orchestrator/src/bin/host-sessiond.rs)。production installation procedure 要求 externally reviewed 的 full commit 和 externally authenticated 的 SHA-256 manifest；它不是通用的 `cargo install` target。

```bash
cargo build --release --locked \
  -p session-orchestrator \
  --bin host-sessiond --bin host-controld --bin host-control
```

安装、artifact pinning、system account、systemd/polkit、device access、snapshot、credential handling 和 recovery 请遵循 [`deploy/README.md`](deploy/README.md)。已提交的 example 是 service contract 的 source。

| Artifact | Purpose |
|---|---|
| [`deploy/host-sessiond-worker.env.example`](deploy/host-sessiond-worker.env.example) | Multi-session worker environment 和 pinned artifact fields |
| [`deploy/host-sessiond.env.example`](deploy/host-sessiond.env.example) | Legacy single-session environment example |
| [`service/host-sessiond@.service`](service/host-sessiond@.service) | 每个 session 一个 worker instance |
| [`service/host-sessiond-recover@.service`](service/host-sessiond-recover@.service) | Recovery-only worker cleanup |
| [`service/host-controld.service`](service/host-controld.service) | Unprivileged authenticated controller |
| [`deploy/polkit-1/rules.d/50-host-controld.rules`](deploy/polkit-1/rules.d/50-host-controld.rules) | Narrow start/stop authorization |

example service 选择 `--egress-authority none`，不读取 GitHub token。必须通过对应的 authority 和 host-only credential profile 明确启用 Public HTTPS 或 GitHub。`EGRESS_GITHUB_TOKEN` 只保留为明确的 non-systemd fallback；production systemd deployment 应使用 deploy guide 中描述的 encrypted `github-token` credential。`publish-branch` operation 还需要 host-owned expected-old-object plan。

<a id="workspace-layout"></a>
## 工作区布局

| Path | Responsibility |
|---|---|
| [`crates/authority-core/`](crates/authority-core/) | Typed authority families、delegation、policy digests、state、revocation、audit 和 durable audit |
| [`crates/capfs/`](crates/capfs/) | Repository preflight、namespace/node tables、backing I/O 和 Direct-I/O FUSE |
| [`crates/egress-protocol/`](crates/egress-protocol/) | Bounded frames、canonical CBOR、session/replay identity 和 budgets |
| [`crates/egress-broker/`](crates/egress-broker/) | Host vsock transport、public HTTPS policy、typed GitHub adapter 和 durable dispatch |
| [`crates/firecracker-runtime/`](crates/firecracker-runtime/) | Pinned artifacts、dm-verity、jailer、snapshot/restore 和 guest-control transport |
| [`crates/runtime-isolation/`](crates/runtime-isolation/) | Ordered Linux namespace、mount、cgroup、Landlock、capability 和 seccomp transaction |
| [`crates/supervisor/`](crates/supervisor/) | Guest subject 与 handle lifecycle、control socket 和 CapFS composition |
| [`crates/session-orchestrator/`](crates/session-orchestrator/) | Session lifecycle、leases、production adapters、durable recovery 和 daemon binaries |
| [`lean/`](lean/) | Lean 4 (`leanprover/lean4:v4.16.0`) authority/runtime model 和 proof corpus executables |
| [`guest/`](guest/) | Pinned guest kernel configuration 和 patch |
| [`ci/`](ci/) | Gate manifest、API baselines、benchmark baseline 和 fixtures |
| [`scripts/ci/`](scripts/ci/) | Shared GitHub、GitLab 和 local gate implementations |
| [`docs/`](docs/README.md) | Design、crate contracts、verification boundaries、decisions 和 glossary |
| [`deploy/`](deploy/README.md) 和 [`service/`](service/) | Production installation 和 systemd/polkit artifacts |

`authority-core` 和 `runtime-isolation` 仍是 dependency graph 的 leaves，因此它们的 authorization 和 isolation contracts 不依赖 higher-level orchestration。实际 dependency graph 与 runtime placement 记录在 [`docs/design/architecture.md`](docs/design/architecture.md)。

<a id="ci-and-release"></a>
## CI 与 release

[`ci/gates.yml`](ci/gates.yml) 是 pipeline topology 的 single source of truth。当前它在 validation、quality、tests、analysis、security 和 protected system verification 中声明 53 个 implemented gates。四个有序 release stage（`package`、`verify`、`publish` 和 `record`）单独追踪。GitHub Actions 和 GitLab CI 必须实现相同的 manifest-owned gates；job 缺失或意外出现时，parity 和 result reconciliation 会 fail closed。

deep workflow 由 schedule 或手动 dispatch 触发，因为普通 pull-request runner 不提供 real FUSE、KVM、device-mapper、systemd 和 external-provider fixtures。external-provider gate 是 opt-in；在此 checkout 中因为缺少 protected credential 和 disposable provider owner，仍保持 blocked。

release automation 仅限 semantic-version tag。它会为可复现的 `authority-corpus` Linux binary 打包 license text、build metadata、SPDX SBOM、checksum 和 platform-specific provenance/signature record。本 repository 不发布 version badge；workspace version、[`Cargo.toml`](Cargo.toml) 和 release workflow 才是 authoritative inputs。

runner contracts、branch protection、release recovery 和 signature handling 见 [`docs/ci-cd.md`](docs/ci-cd.md)。

<a id="documentation"></a>
## 文档

[`docs/README.md`](docs/README.md) 是 documentation index。最有用的入口包括：

| Topic | Document |
|---|---|
| 跨 crate architecture | [`docs/design/architecture.md`](docs/design/architecture.md) |
| threat model 和 non-goals | [`docs/design/threat-model.md`](docs/design/threat-model.md) |
| Capability、isolation 和 egress design | [`docs/design/README.md`](docs/design/README.md) |
| verification strategy | [`docs/design/verification.md`](docs/design/verification.md) |
| machine-readable verification claims | [`docs/verification-status.yml`](docs/verification-status.yml) |
| decision records | [`docs/decisions/README.md`](docs/decisions/README.md) |
| deployment 和 recovery | [`deploy/README.md`](deploy/README.md) |
| CI/CD operations | [`docs/ci-cd.md`](docs/ci-cd.md) |
| terminology | [`docs/glossary.md`](docs/glossary.md) |

每个 crate 的 README 和 verification page 都区分 implementation、hosted tests、privileged tests、KVM evidence 和 external-provider gaps。如果变更只涉及一个 subsystem，请从 [workspace layout](#workspace-layout) 中对应的 crate 开始阅读。

<a id="license"></a>
## 许可证

Copyright © 2026 Aqua-218.

本项目根据 [GNU Affero General Public License v3.0 only](LICENSE)（`AGPL-3.0-only`）发布。适用于使用、修改、再分发和 network service deployment 的条件请阅读 license 正文。

<a id="related"></a>
## 相关

- [Documentation index](docs/README.md)
- [Architecture](docs/design/architecture.md)
- [Threat model](docs/design/threat-model.md)
- [Verification strategy](docs/design/verification.md)
- [Deployment guide](deploy/README.md)
- [CI/CD operations](docs/ci-cd.md)
