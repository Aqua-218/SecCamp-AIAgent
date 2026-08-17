#!/usr/bin/env bash

set -euo pipefail

# Miri, sanitizer flags, cargo-fuzz, and rustdoc JSON all depend on nightly
# interfaces. Keep the date in one place so every deep gate is reproducible on
# both CI platforms and a toolchain update is an explicit reviewable change.
readonly nightly_channel="nightly-2026-02-11"

if ! rustup toolchain list | grep -Fq "${nightly_channel}-"; then
  rustup toolchain install --no-self-update --profile minimal "${nightly_channel}"
fi

rustup component add --toolchain "${nightly_channel}" miri rust-src

printf '%s\n' "${nightly_channel}"
