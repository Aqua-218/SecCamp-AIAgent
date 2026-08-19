# Public API baselines

[Project README](../../README.md) / [CI/CD documentation](../../docs/ci-cd.md) / Public API baselines

> **Audience:** maintainers reviewing intentional changes to the Rust library API.

The eight `*.api` files in this directory are committed, reviewable snapshots of every
workspace library crate's public Rust API. The `api_surface` gate regenerates the same
normalized output and fails when it differs from the checked-in baseline.

## What the gate checks

```mermaid
flowchart LR
    lock["Cargo.lock"] -->|"cargo metadata --locked"| graph["Locked workspace graph"]
    graph -->|"one library package at a time"| rustdoc["Pinned nightly rustdoc JSON"]
    rustdoc -->|"cargo public-api --simplified ×3"| current["Normalized API text"]
    baseline[("Committed *.api baseline")] --> compare{"Byte-for-byte match?"}
    current --> compare
    compare -->|"yes"| pass["Gate passes"]
    compare -->|"no"| review["Review the textual diff"]
    review -->|"intentional --update"| baseline
```

The gate:

- proves that `Cargo.lock` is current with `cargo metadata --locked`;
- discovers every workspace package that exposes a library target;
- uses the dated nightly selected by
  [`install-nightly-toolchain.sh`](../../scripts/ci/install-nightly-toolchain.sh), because
  rustdoc JSON is a nightly interface;
- runs dependency resolution offline while generating the public API;
- requires one baseline for every discovered library package; and
- reports an ordinary unified diff instead of hiding API changes behind a digest.

The baseline is an API-shape check. It does not prove behavioral compatibility, semantic
versioning correctness, or the safety of a changed contract.

## Review an API change

Run the gate first so the unapproved diff is visible:

```bash
scripts/ci/install-cargo-tools.sh public-api
scripts/ci/run.sh api-surface
```

If the source change is intentional and has been reviewed, refresh every package baseline:

```bash
scripts/ci/check-api-surface.sh --update
git diff -- ci/api-baselines
scripts/ci/run.sh api-surface
```

`--update` is deliberately explicit. Do not refresh a baseline merely to make CI green;
review removals, signature changes, new public types, and feature-dependent exposure before
committing the generated diff.

## Files

| Baseline | Workspace crate |
|---|---|
| [`authority-core.api`](authority-core.api) | `authority-core` |
| [`capfs.api`](capfs.api) | `capfs` |
| [`egress-broker.api`](egress-broker.api) | `egress-broker` |
| [`egress-protocol.api`](egress-protocol.api) | `egress-protocol` |
| [`firecracker-runtime.api`](firecracker-runtime.api) | `firecracker-runtime` |
| [`runtime-isolation.api`](runtime-isolation.api) | `runtime-isolation` |
| [`session-orchestrator.api`](session-orchestrator.api) | `session-orchestrator` |
| [`supervisor.api`](supervisor.api) | `supervisor` |

## Related

- [API surface gate implementation](../../scripts/ci/check-api-surface.sh)
- [Gate manifest](../gates.yml)
- [CI/CD operations](../../docs/ci-cd.md)
