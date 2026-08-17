The `*.sha256` files are committed baselines for the canonical output of
`cargo public-api -sss --color never` for each workspace library crate.

The API gate uses a dated nightly because rustdoc JSON is nightly-only. A
public API change must be reviewed deliberately and then refreshed with:

```sh
scripts/ci/install-cargo-tools.sh public-api
scripts/ci/check-api-surface.sh --update
```

The update flag is intentionally explicit. The digest is over the complete
sorted output, so a baseline cannot be refreshed for one crate without the
other library crates being checked in the same run.
