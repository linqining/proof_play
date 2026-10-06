# prove-hand — Cairo1 → Stwo prove/verify CLI

`prove-hand` is the one-command wrapper around the proving pipeline used by the poker
project's **`proved` settlement mode**. Given a Cairo1 program it compiles the program,
runs it on the Cairo VM to produce the witness, proves the execution with
[Stwo](https://github.com/starkware-libs/stwo) + the Cairo AIR, verifies the proof, prints
per-phase timings, and writes every artifact to an output directory.

```
 Cairo1 .cairo ──compile──▶ Executable JSON ──run──▶ witness ──prove──▶ proof ──verify──▶ OK/FAIL
 (gas-disabled)            (executable.json)         (in-memory)      (proof.json)      (exit code)
```

It is a **standalone, offline tool**. The game server never runs it and does not depend on
it: when `STARKNET_SETTLE_MODE=proved` a settlement prover runs `prove-hand` on any machine
(a laptop is fine), hands the proof + summary to the on-chain verifier path, and only the
proof/outputs are consumed downstream. Nothing in `texas/` links against this crate.

## Layout

```
third_party/proving/        vendored starkware-libs/proving (with our fixes, see below)
third_party/corelib-2.19.4/ vendored Cairo corelib used to compile programs
proving-tool/               this crate: CLI + convenience script
```

`proving-tool` is its **own Cargo workspace** (not a member of the zgame root workspace)
because the proving stack requires the `nightly-2026-01-15` toolchain
(`portable_simd`, `iter_array_chunks`, `raw_slice_split` in `stwo-cairo-prover`); keeping it
out of the main workspace means `cargo check` of the game crates never needs nightly.
`rust-toolchain.toml` pins the toolchain for this directory.

## Prerequisites

- Rust `nightly-2026-01-15`, pinned by `proving-tool/rust-toolchain.toml` (same pin as
  `third_party/proving/rust-toolchain.toml`; rustup installs it on first use).
  `prove-hand.sh` sets `RUSTUP_TOOLCHAIN` for you; when invoking cargo directly from the
  repo root (outside `proving-tool/`) export it yourself — see Quickstart.
- Disk: ~1 GB for the build (`proving-tool/target/`, git-ignored) and the vendored
  `third_party/` sources (~75 MB).
- The prover is parallel (rayon over all cores); no services or network needed.

## Quickstart

From the repo root (one command from a clean checkout — builds on first run):

```bash
./proving-tool/prove-hand.sh --scale small          # ~8-11 s prove
./proving-tool/prove-hand.sh --scale full           # ~24-29 s prove (default; the recursive production route measures 15-17 s/hand, see texas/src/starknet/recursion_prover.rs)
```

or, equivalently, without the wrapper:

```bash
cd proving-tool && cargo run --release --bin prove-hand -- --scale small
# from the repo root you must pin the toolchain explicitly (rust-toolchain.toml is
# directory-scoped):
RUSTUP_TOOLCHAIN=nightly-2026-01-15 \
    cargo run --release --manifest-path proving-tool/Cargo.toml --bin prove-hand -- --scale small
```

Everything lands in `proving-tool/output/<scale>/`:

| file                 | content                                                        |
|----------------------|----------------------------------------------------------------|
| `executable.json`    | compiled Cairo1 `Executable` (gas-disabled cfg)                |
| `proof.json` / `.bin`| Stwo proof (default JSON; `--proof-format binary` for ~10x smaller) |
| `public_outputs.json`| `program_hash` + public output felts (hex) of the run          |
| `summary.json`       | timings (ms per phase), steps, builtin counts, params, paths   |
| `hand_verify_bench_custom.cairo` | only for `--scale <N>`: the generated bench program |

The tool prints the same numbers to stdout and **exits non-zero if verification fails**.

## CLI

```
prove-hand [--program <path.cairo>] [--corelib <dir>] [--inputs <args.json>]
           [--scale small|medium|full|<N>] [--out-dir <dir>]
           [--proof-format json|binary|cairo_serde] [--params <params.json>]
           [--check-only [--proof <proof file>]]
```

- `--program` — any standalone Cairo1 program with an `#[executable] fn main`. Default: the
  hand-verify bench program at `--scale`.
- `--corelib` — the corelib **crate root** (the directory containing `lib.cairo`); defaults to
  the vendored `third_party/corelib-2.19.4/corelib/src`.
- `--inputs` — JSON array of hex felts, e.g. `["0x1", "0x2"]`, forwarded as program
  arguments to the runner.
- `--scale` — `small` (22 challenges), `medium` (110), `full` (220; default), or a number
  `N` which generates a custom bench with `N_CHALLENGES = N`, `N_EC = N*148/22`,
  `PAYLOAD_LEN = N*70/22` (same ratios as the shipped scales).
- `--check-only` — standalone re-verification of an existing proof (Stwo supports it):
  `./proving-tool/prove-hand.sh --check-only --scale small` re-verifies
  `proving-tool/output/small/proof.json`. Non-zero exit on failure.
- `--params` — prover parameters JSON (same schema as the upstream `run_and_prove
  --params_json`). Default is the 96-bit-security production set (blake2s channel, FRI
  pow_bits 26, blowup 1, 70 queries).

Verify an arbitrary existing proof:

```bash
cargo run --release --manifest-path proving-tool/Cargo.toml --bin prove-hand -- \
    --check-only --proof path/to/proof.json
```

## The mode story (`STARKNET_SETTLE_MODE=proved`)

Today the server settles hands on Starknet directly (`submit.rs` / `dual_settle.rs`). The
planned `proved` mode changes **who computes**, not the game logic: the hand state machine
stays in Rust; a prover runs `prove-hand` on the hand inputs and produces

- `proof.json` (or the smaller `proof.bin`) — the Stwo proof to feed a verifier, and
- `summary.json` — the machine-readable record: `timings_ms`, `execution.steps`,
  `execution.builtin_instance_counter`, and `public.program_hash` / `public.output` (the
  commitment to the public result of the run).

The server switch exists and defaults to dark: `texas/src/starknet/config.rs` reads
`STARKNET_SETTLE_MODE` (`linear`, the default and byte-identical to the old behavior, or
`proved`). In `proved` mode the server exports the settlement workload
(`hand-{id}-{binding}.json`: `hand_binding`, `hand_id`, `batch_words`, `p_batch_commitment`,
`p_batch_len` — see `dual_settle.rs::export_prover_workload` / `STARKNET_PROVER_WORK_DIR`,
default `/tmp/zgame-prover`) and calls out to `STARKNET_PROVER_URL` for an attestation;
any error or a 30 s timeout falls back to `linear` automatically. The HTTP client is still
a stub that always errors (so `proved` deterministically falls back today); wiring it to
this binary and re-checking the attestation is the remaining integration step. The game
server itself never needs the proving stack, nightly toolchain, or `third_party/` at
runtime.

### Measured timings (this tool, Apple Silicon, release, 96-bit params)

| scale  | steps   | compile | run/witness | prove     | verify | proof size |
|--------|---------|---------|-------------|-----------|--------|------------|
| small  | 43,752  | 0.45 s  | 75 ms       | 9.5–10.7 s| 12 ms  | 14 MB json / 1.5 MB bin |
| medium | 219,243 | 0.45 s  | 280 ms      | 17.0 s    | 10 ms  | 14 MB json |
| full   | 438,607 | 0.41 s  | 540 ms      | 28.7 s    | 31 ms  | 14 MB json |

These were measured while the machine had a load average of ~15–20 on 12 cores; the original
bench session on an idle machine recorded 6.7–8.4 s (small) and 23.7–24.2 s (full), so expect
anywhere in those ranges depending on load. Full-scale prove is dominated by Cairo CPU-AIR
steps (~40 µs/step) on top of a ~6.4 s fixed Stwo overhead — see the bench notes in the
project docs for the analysis. `--proof-format binary` shrinks proofs ~10x (1.5 MB at small
scale) and is what a settlement path should consume.

Two pitfalls the tool shields you from (both bit us during development):

- The Cairo1 compiler setup sets `RAYON_NUM_THREADS=1` in-process; since rayon builds its
  global pool lazily from the env, a single-process compile→prove pipeline would otherwise
  run the prover on one thread (~8x slower). `prove-hand` warms the pool with all cores
  before compiling.
- The `cairo-lang` crates must stay on 2.19.x to match the vendored corelib (2.20.0 panics
  with `` `prelude` is not a core submodule ``). `proving-tool/Cargo.lock` (seeded from the
  vendored repo's lock) pins 2.19.4 — keep it committed.

## What is real and what is stubbed

- **Real**: the whole pipeline. Compile (gas-disabled `Executable`), Cairo VM witness run,
  Stwo proof generation, standalone verification, artifact writing, and the timings above
  were all measured end-to-end with this exact tool on this repository.
- **Stubbed (workload, not pipeline)**: the default program is
  `hand_verify_bench_*.cairo`, a bench that *models* the poker `hand_verify` sigma-proof
  batch check (N Poseidon challenges + N EC muls/adds on the STARK curve + payload mix)
  with hardcoded inputs. The real `hand_verify.cairo` in
  `/Users/mac/projects/poker_texas_air` is not yet a standalone `#[executable]` program —
  follow-up work is to extract it as one (with real hand inputs as `--inputs`) and point
  `--program` at it. Nothing in this tool is specific to the bench: any standalone Cairo1
  program works.
- The `STARKNET_SETTLE_MODE=proved` server switch **is implemented but dark**: `proved`
  mode exports the workload JSON and attempts `STARKNET_PROVER_URL`, whose client is a
  stub that always errors — so every `proved` attempt deterministically falls back to
  `linear` settlement. Activating it means implementing the real HTTP client against this
  binary (workload file format is ready) and, on the contract side, replacing the interim
  prover-whitelist attestation with STARK proof verification.

## Vendored stack and our patches

`third_party/proving` is a vendored copy of `starkware-libs/proving` (upstream HEAD
`dd1787b`, "Skip the multiverifier preprocessed trace in the consts test (#134)") plus the
fixes that make the Cairo1 `Executable` path work end-to-end:

1. `crates/dev_utils/src/bin/compile_cairo1.rs` and (new)
   `crates/dev_utils/src/cairo1_compile.rs` — build the compiler DB exactly like the
   official `cairo-execute` runner: `with_cfg(gas=disabled)` +
   `skip_auto_withdraw_gas()`. Without it, corelib `poseidon_hash_span` compiles in gas
   withdrawal code the standalone runner never wires up (the "jump anomaly").
2. `crates/adapter/src/adapter.rs` — new `adapt_with_context(runner, context)`;
   `adapt()` (bootloader context) is unchanged for Cairo0 programs.
3. `crates/dev_utils/src/vm_utils.rs` — the `Executable` branch adapts with
   `PublicSegmentContext::new(entrypoint builtins)` instead of assuming all 11 builtins.
4. `crates/dev_utils/src/bin/trace_exec.rs` — debug tracer (VM steps + hints + memory).
5. `test_data/test_hand_verify_bench/` — the three bench programs.

Excluded from the vendored copy (regenerable/not needed by this pipeline): `target/`,
`.git/`, `outputs/` (generated AIR definitions), `crates/cairo-program-runner-lib/resources/`
(120 MB of compiled programs for the bootloader runner), and the upstream agent-instruction
files (`.claude/`, `.agents/`, `CLAUDE.md`). Nothing in the prove-hand dependency tree
references them; building the full vendored workspace (`cargo build` without `-p`) may
need those two data directories restored from upstream.

## Design notes

`prove-hand` is a separate crate rather than another bin inside
`third_party/proving/crates/dev_utils` because the CLI, its artifacts and its docs are
*project* code that should live in (and evolve with) the poker repo, while
`third_party/` stays a minimal, diff-against-upstream vendored tree. The shared logic it
needs (compile config, `run_and_adapt`) was promoted into the `stwo-cairo-dev-utils` **lib**
(`cairo1_compile.rs`, `vm_utils.rs`), so the wrapper contains only orchestration, timing
and reporting — no pipeline logic is duplicated.
