The `*.api` files are committed, reviewable baselines for the canonical output of
`cargo public-api --all-features -sss --color never` for each workspace library crate. The gate
first proves `Cargo.lock` is current with `cargo metadata --locked`, then runs rustdoc fully
offline so baseline generation cannot mutate dependency resolution.

The API gate uses a dated nightly because rustdoc JSON is nightly-only. A
public API change must be reviewed deliberately and then refreshed with:

```sh
scripts/ci/install-cargo-tools.sh public-api
scripts/ci/check-api-surface.sh --update
```

The update flag is intentionally explicit. A public API change appears as an ordinary textual
diff, so reviewers can distinguish additions, removals, and changed contracts rather than
approving an opaque digest. Every library crate is checked in the same run.
