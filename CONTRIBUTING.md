# Contributing

## Toolchain

This workspace uses the pinned nightly toolchain in `rust-toolchain.toml`. Stwo
requires nightly features, so run Cargo commands from the repository root. The
workspace intentionally excludes `third_party/flock`; that vendored project has
its own checks.

## Required checks

Before opening a change, run the checks relevant to the code you touched:

```bash
git diff --check
cargo check --release --workspace --lib --bins
cargo test --release --workspace -- --include-ignored
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

## Test layering

`cargo test` is a fast dev loop: multi-second prove roundtrip tests are marked
`#[ignore = "slow prove (~Ns); full gate runs `--include-ignored`"]` and are
skipped by default. Three layers:

| Layer | Command | What runs |
| --- | --- | --- |
| Dev loop | `cargo test` | everything except the ignored slow prove tests |
| Dev loop, this workspace only | `cargo test-fast` | same, skipping vendored flock's own unit tests |
| Dev loop, faster execution | `cargo test-nextest` | same crate set via nextest (parallel, isolated; no doctests) |
| Full gate (pre-merge) | `cargo test-all-nextest` (or `cargo test --workspace -- --include-ignored`) | every test, including the slow prove roundtrips |

Test-cost policy (keeps the dev loop under ~30s wall clock):

- Any single test that reliably exceeds **10s** gets
  `#[ignore = "slow prove (~10-25s); full gate runs --include-ignored"]`.
  nextest marks SLOW live at 10s and hard-kills at 30s (`.config/nextest.toml`);
  the full gate uses `profile.all` (60s slow marker, no kill).
- Tests that need a live Starknet devnet (`STARKNET_RPC_URL`) additionally
  early-return when the env is unset, so `--include-ignored` gates stay green
  without infrastructure.
- Vendored `third_party/flock` unit tests are excluded from every workspace
  test command (own workspace); they are neither built nor run by the aliases
  above.

Build-speed notes that keep the dev loop usable:

- `[profile.dev] debug = "line-tables-only"` and `debug = false` for
  dependencies keep backtraces readable (file:line for workspace code) while
  avoiding full DWARF — the previous `debug = 2` default produced 200 MB+
  rlibs and multi-minute links. Do not raise debuginfo back without measuring.
- Touching a shared workspace crate rebuilds every dependent test binary.
  During iteration, scope the run: `cargo test -p <crate>`.
- Stale artifacts from old profiles linger until cargo GC; `cargo gc` (nightly)
  or removing `target/debug` reclaims disk if it grows past ~10 GB.

`cargo test-fast` / `cargo test-all` cover the main workspace only. The
`client-wasm` crate is a standalone Cargo workspace (wasm-pack target `web`);
run its checks separately from that directory:

```bash
cd client-wasm && cargo check && cargo test
```

CI builds it via the `client-wasm (wasm-pack)` job; there is no cross-workspace
alias because Cargo aliases cannot span workspaces.

CI's `Workspace tests` job and the weekly coverage job run the full gate, so
the ignored tests stay covered; do not delete an `#[ignore]` to "fix" a slow
run — file the slowness instead. Tests for code under active development
(e.g. `poseidon252_air_component`) are deliberately NOT ignored: they stay in
the default loop so failures surface immediately.

The root crate's untrusted test helpers are only used in the release
integration-test harness below. Do not run the heavyweight proof suite in debug
mode; it is substantially slower on this project.

For the deliberate release integration-test harness, opt into the explicit
configuration while keeping the release guard enabled:

```bash
RUSTFLAGS='--cfg=texas_release_tests' \
  cargo test -p poker_texas_air --release --features test-helpers --tests
```

Do not enable `test-helpers` in a production release build. The crate rejects
that configuration unless it is a test artifact or the explicit release-test
configuration above is present.

## Benchmarks

Performance baselines live in `docs/PERFORMANCE.md` (post-Plan-D release
numbers; the repro commands are in `poker-protocol-proofs/tests/plan_d_perf.rs`,
which now lives in the separate
[`poker_protocol`](https://github.com/linqining/poker_protocol) repo — run it
from a checkout of that repo):

```bash
cargo +nightly test --release -p poker-protocol-proofs --test plan_d_perf -- --nocapture
```

(The former `poker_l1` Criterion benches — `task36_dag_consensus`,
`task36_bls_syscall` — were removed with the chain-machinery and BLS cleanup
in 2026-09.)

The full hand proving benchmark is intentionally not part of the pull-request
check because it is long-running and hardware-sensitive:

```bash
cargo run --release -p poker-hand-bench
```

When reporting a performance change, include the toolchain, CPU, Rayon thread
count, prove/verify time, proof/archive size, and peak memory where available.
