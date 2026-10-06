#!/usr/bin/env bash
set -euo pipefail

: "${CARGO_TARGET_DIR:=target-bench}"
export CARGO_TARGET_DIR
unset TEXAS_RISTRETTO_SELF_VERIFY

mkdir -p "$CARGO_TARGET_DIR/results"

cargo +nightly bench --release -p poker_l1 \
  --bench task36_dag_consensus -- --noplot
cargo +nightly bench --release -p poker_l1 \
  --bench task36_bls_syscall -- --noplot

cargo +nightly run --release -p poker-hand-bench \
  | tee "$CARGO_TARGET_DIR/results/hand-bench.txt"
