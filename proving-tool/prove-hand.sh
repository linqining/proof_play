#!/usr/bin/env bash
# One-command wrapper for the prove-hand CLI (see README.md).
# Usage: ./proving-tool/prove-hand.sh [--scale small|medium|full|<N>] [other prove-hand flags]
#
# Runs from the caller's working directory (relative --program/--out-dir paths work as typed).
# RUSTUP_TOOLCHAIN is pinned so the build picks the nightly the proving stack requires,
# regardless of where it is invoked from.
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
export RUSTUP_TOOLCHAIN="nightly-2026-01-15"
if [[ ! -x "$DIR/target/release/prove-hand" ]]; then
    echo "building prove-hand (first run takes a few minutes)..." >&2
    cargo build --release --manifest-path "$DIR/Cargo.toml" --bin prove-hand
fi
exec "$DIR/target/release/prove-hand" "$@"
