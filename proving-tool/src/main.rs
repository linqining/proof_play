//! `prove-hand` — one-shot CLI for the poker `proved` settlement mode.
//!
//! Wraps the (patched) starkware-libs/proving stack vendored under `third_party/proving`:
//! Cairo1 source -> gas-disabled `Executable` compile -> Cairo VM witness run -> Stwo proof
//! -> verification, with per-phase timings and all artifacts written to an output directory.
//!
//! This IS the production prover for all app-level statements: the texas server spawns it
//! directly for the snip36 settlement mode (`recursion_prover.rs`, hand_verify recursion
//! envelope) and the v2 fact-registry entry (`settlement_prover.rs`, settlement_private
//! circuit). It is NOT a replacement for the official `transaction-prover` container — that
//! one proves SNOS (Starknet OS) execution of the settlement transaction for the DAPV
//! `entry=snip36` leg, a different program/format/verifier entirely.

use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use cairo_air::utils::{
    ProofFormat, deserialize_proof_from_file, get_verification_output, serialize_proof_to_file,
};
use cairo_air::verifier::{verify_cairo, verify_cairo_ex};
use cairo_vm::types::layout_name::LayoutName;
use clap::Parser;
use serde_json::json;
use stwo::core::fri::FriConfig;
use stwo::core::vcs_lifted::blake2_merkle::{Blake2sMerkleChannel, Blake2sMerkleHasher};
use stwo_cairo_adapter::ExecutionResources;
use stwo_cairo_common::preprocessed_columns::preprocessed_trace::PreProcessedTraceVariant;
use stwo_cairo_dev_utils::cairo1_compile::compile_cairo1_executable;
use stwo_cairo_dev_utils::vm_utils::{ProgramType, run_and_adapt};
use stwo_cairo_prover::prover::{ChannelHash, LiftingSizePolicy, ProverParameters, prove_cairo};

/// Bench programs shipped with the vendored proving repo.
const BENCH_TEMPLATE: &str = include_str!("bench_template.cairo");
const BENCH_DIR_REL: &str = "third_party/proving/test_data/test_hand_verify_bench";
/// Corelib crate root (the dir containing `lib.cairo`), not the repo root.
const CORELIB_REL: &str = "third_party/corelib-2.19.4/corelib/src";

/// L1 批量终证腿钉扎（settlement_batch_private，含 acc_prev/批根入参 +
/// 电路内 poseidon 链接尾；2026-09-30 九人桌迁移后 K=1 真出证重钉，
/// /tmp/fold9/run1，历史 8 人桌钉值 0x05c400b46a261c6672cd7581436754e05da2287ba8ecdc69778d06e4ef831803）。
///
/// 程序哈希 = prove-hand K=1 出证实测（prover 参数无关）。
/// 改 cairo 源码必换哈希 → 同步更新 stark-recursion `stark_final.rs` 与
/// fact-verify `PINNED_BATCH_PROGRAM_HASH`。
pub const SETTLEMENT_BATCH_PROGRAM_HASH: &str =
    "0x03977925c8f46d896d04f4b76c18874e0f9a05a4c860f0de56236518e9faf74d";
/// L1 批腿批程序源（相对 repo root）。
pub const SETTLEMENT_BATCH_PROGRAM: &str = "proving-tool/src/settlement_batch_private.cairo";

#[derive(Parser, Debug)]
#[command(
    name = "prove-hand",
    about = "Cairo1 -> Stwo prove/verify pipeline for the poker `proved` settlement mode",
    version
)]
struct Args {
    /// Cairo1 source program. Defaults to the hand_verify bench at --scale.
    #[arg(long)]
    program: Option<PathBuf>,
    /// corelib crate dir used to compile --program (defaults to the vendored v2.19.4 corelib).
    #[arg(long)]
    corelib: Option<PathBuf>,
    /// Optional JSON file with program arguments: an array of hex felt strings, e.g. ["0x1","0x2"].
    #[arg(long)]
    inputs: Option<PathBuf>,
    /// small | medium | full, or a number N to generate a custom bench with N challenges
    /// (N_EC = N*148/22, PAYLOAD_LEN = N*70/22). Default: full.
    #[arg(long, default_value = "full")]
    scale: String,
    /// Output directory for executable.json / proof / public outputs / summary.json.
    #[arg(long)]
    out_dir: Option<PathBuf>,
    /// Proof serialization format: json | binary | cairo_serde.
    #[arg(long, value_enum, default_value_t = ProofFormat::Json)]
    proof_format: ProofFormat,
    /// Serialize ONE proof into ALL formats (proof.json / proof.serde.json /
    /// proof.bin / proof.ext.bin) and record byte sizes + felt count in
    /// summary.json — the #0 证明瘦身 measurement mode.
    #[arg(long)]
    all_formats: bool,
    /// JSON file with prover parameters (same schema as run_and_prove --params_json).
    /// Defaults to the 96-bit-security production parameters.
    #[arg(long)]
    params: Option<PathBuf>,
    /// Only verify an existing proof (no compile/run/prove). Reads --proof, or
    /// <out-dir>/proof.<json|bin> if --proof is not given.
    #[arg(long)]
    check_only: bool,
    /// Proof file to verify with --check-only.
    #[arg(long, requires = "check_only")]
    proof: Option<PathBuf>,
    /// Disable the content-addressed executable compile cache (compile every run).
    #[arg(long)]
    no_exec_cache: bool,
    /// Trace-height policy (memory optimization, 2026-09-29).
    ///
    /// - `auto`: pick the lowest-memory *sound* preprocessed-trace variant from the actual
    ///   run resources: `canonical_small` (pp domain 2^20, pp tree lifting 2^21) when every
    ///   builtin segment fits in 2^20 padded instances, else `canonical` (pp domain 2^25,
    ///   lifting 2^26). Pedersen needs no special case: the witness adapts to the variant
    ///   (wide vs narrow-window point tables, prover/src/witness/builtins.rs:48-66).
    ///   Per-opcode trace components were always adaptive (next_power_of_two of their own
    ///   instance counts, floor 2^4 SIMD lanes).
    /// - `20`: explicit current floor — no behavior change.
    /// - Any other N is rejected (fail-closed): the main-trace height has a hard semantic
    ///   floor of 2^20 imposed by the always-present `range_check_20` full-range table
    ///   component (cairo-air/src/components/range_check_20.rs:6, witness fixed
    ///   `1 << LOG_SIZE` multiplicities, claim-carried via claims.rs flatten/log_sizes).
    ///   Shrinking below 20 would change the AIR semantics and the serialized
    ///   `CairoClaim` (proof format), which the default-preserving constraint forbids;
    ///   lifting heights above the trace are the job of `--params`
    ///   `lifting_size_policy: fixed`.
    ///
    /// Default (flag absent): exactly the previous behavior (`canonical`), proofs
    /// byte-identical.
    #[arg(long, value_name = "N|auto")]
    trace_log_size: Option<String>,
}

/// Content-addressed executable compile cache outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExecCacheOutcome {
    Hit,
    Miss,
    Disabled,
}

/// Cache dir: `PROVE_HAND_CACHE_DIR` overrides, else `<repo>/proving-tool/.cache/exec-cache`.
fn exec_cache_dir(root: &Path) -> PathBuf {
    match std::env::var_os("PROVE_HAND_CACHE_DIR") {
        Some(dir) if !dir.is_empty() => PathBuf::from(dir),
        _ => root.join("proving-tool/.cache/exec-cache"),
    }
}

/// Stable 128-bit key (two independent FNV-1a lanes, no external crate) for the
/// executable compile cache. Inputs: cache schema tag, program source bytes,
/// corelib path + `lib.cairo` stat, and the prove-hand binary's own stat — a
/// rebuild (vendored compiler/corelib bump) invalidates every cached entry.
fn exec_cache_key(program: &Path, corelib: &Path) -> String {
    const FNV_OFFSET_A: u64 = 0xcbf29ce484222325;
    const FNV_OFFSET_B: u64 = 0x6c62272e07bb0142;
    const FNV_PRIME: u64 = 0x100000001b3;
    struct Lanes {
        a: u64,
        b: u64,
    }
    impl Lanes {
        fn new() -> Self {
            Self { a: FNV_OFFSET_A, b: FNV_OFFSET_B }
        }
        fn update(&mut self, bytes: &[u8]) {
            for &byte in bytes {
                self.a = (self.a ^ u64::from(byte)).wrapping_mul(FNV_PRIME);
                self.b = (self.b ^ u64::from(byte).rotate_left(17))
                    .wrapping_mul(FNV_PRIME)
                    .rotate_left(29);
            }
        }
        fn update_u64(&mut self, v: u64) {
            self.update(&v.to_le_bytes());
        }
    }
    fn stat_fingerprint(h: &mut Lanes, path: &Path) {
        let Ok(meta) = fs::metadata(path) else { return };
        h.update_u64(meta.len());
        if let Some(mtime) = meta
            .modified()
            .ok()
            .and_then(|m| m.duration_since(std::time::UNIX_EPOCH).ok())
        {
            h.update_u64(mtime.as_millis() as u64);
        }
    }
    let mut h = Lanes::new();
    h.update(b"prove-hand exec cache v1");
    h.update(&fs::read(program).unwrap_or_default());
    h.update(corelib.to_string_lossy().as_bytes());
    stat_fingerprint(&mut h, &corelib.join("lib.cairo"));
    if let Ok(exe) = std::env::current_exe() {
        stat_fingerprint(&mut h, &exe);
    }
    format!("{:016x}{:016x}", h.a, h.b)
}

fn compile_to_file_uncached(program: &Path, corelib: &Path, out: &Path) -> Result<()> {
    let executable = compile_cairo1_executable(program, Some(corelib))
        .with_context(|| format!("compile {}", program.display()))?;
    write_json(out, &serde_json::to_value(&executable)?)
        .with_context(|| format!("write {}", out.display()))
}

/// Materialize `<out-dir>/executable.json` via the content-addressed compile
/// cache: compile once per (program source, corelib, toolchain), then copy the
/// cached artifact on every later run (~ms vs ~1.5 s). Cache publishes are
/// atomic renames, so concurrent prove processes only ever race to a no-op.
fn materialize_executable(
    program: &Path,
    corelib: &Path,
    executable_path: &Path,
    cache_dir: &Path,
) -> Result<ExecCacheOutcome> {
    fs::create_dir_all(cache_dir)
        .with_context(|| format!("mkdir {}", cache_dir.display()))?;
    let cached_path = cache_dir.join(format!("exec-{}.json", exec_cache_key(program, corelib)));
    if cached_path.exists() {
        fs::copy(&cached_path, executable_path)
            .with_context(|| format!("copy cached executable from {}", cached_path.display()))?;
        return Ok(ExecCacheOutcome::Hit);
    }
    let tmp_path = cached_path.with_extension(format!("tmp-{}", std::process::id()));
    compile_to_file_uncached(program, corelib, &tmp_path)?;
    fs::rename(&tmp_path, &cached_path)
        .with_context(|| format!("publish {}", cached_path.display()))?;
    fs::copy(&cached_path, executable_path)
        .with_context(|| format!("copy compiled executable"))?;
    Ok(ExecCacheOutcome::Miss)
}

fn main() -> Result<()> {
    // Progress logs from the prover (phase spans) go to stderr; the report goes to stdout.
    // The salsa/cairo-lang compiler logs are extremely chatty at INFO, so default to WARN;
    // set PROVE_HAND_LOG=debug|info for full tracing output.
    let level = match std::env::var("PROVE_HAND_LOG").as_deref() {
        Ok("debug") | Ok("trace") => tracing::Level::DEBUG,
        Ok("info") => tracing::Level::INFO,
        Ok("off") | Ok("error") => tracing::Level::ERROR,
        _ => tracing::Level::WARN,
    };
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_target(false)
        .with_max_level(level)
        // 段关闭时打印 busy time（ms）——用于 prove 内部相位分解。
        .with_span_events(tracing_subscriber::fmt::format::FmtSpan::CLOSE)
        .init();

    let args = Args::parse();

    // Warm rayon's global pool (all cores) BEFORE the compile phase: the Cairo1 compiler setup
    // sets RAYON_NUM_THREADS=1 in-process, and the pool is built lazily from the env on first
    // parallel use — without this the prove phase below would run single-threaded (~8x slower).
    rayon::broadcast(|_| {});
    let root = repo_root();
    let scale = parse_scale(&args.scale)?;
    let out_dir =
        args.out_dir.clone().unwrap_or_else(|| root.join("proving-tool/output").join(scale.label()));
    fs::create_dir_all(&out_dir).with_context(|| format!("mkdir {}", out_dir.display()))?;

    if args.check_only {
        return check_only(&args, &out_dir);
    }

    let program = resolve_program(&args, &root, &scale, &out_dir)?;
    let corelib = args.corelib.clone().unwrap_or_else(|| root.join(CORELIB_REL));
    let proof_path = out_dir.join(proof_file_name(&args.proof_format));

    println!("prove-hand: scale={} format={}", scale.label(), format_name(&args.proof_format));
    println!("  program : {}", program.display());
    println!("  corelib : {}", corelib.display());
    println!("  out-dir : {}", out_dir.display());

    let total = Instant::now();

    // 1. Compile Cairo1 -> Executable (gas-disabled; see third_party/proving fixes).
    //    Content-addressed cache: the recursion/settlement programs are fixed per
    //    release, so recompiling per prove (~1.5 s wall) is pure waste per hand.
    let t = Instant::now();
    let executable_path = out_dir.join("executable.json");
    let cache_dir = (!args.no_exec_cache).then(|| exec_cache_dir(&root));
    let cache_outcome = match cache_dir {
        Some(dir) => match materialize_executable(&program, &corelib, &executable_path, &dir) {
            Ok(outcome) => outcome,
            Err(cache_err) => {
                tracing::warn!("exec cache: {cache_err:#}; compiling without cache");
                compile_to_file_uncached(&program, &corelib, &executable_path)?;
                ExecCacheOutcome::Disabled
            }
        },
        None => {
            compile_to_file_uncached(&program, &corelib, &executable_path)?;
            ExecCacheOutcome::Disabled
        }
    };
    let compile_dur = t.elapsed();

    // 2. Run the witness + adapt to the Stwo prover input.
    let t = Instant::now();
    let prover_input = run_and_adapt(
        &executable_path,
        ProgramType::Executable,
        LayoutName::all_cairo_stwo,
        args.inputs.as_ref(),
    )
    .context("run witness (Cairo VM)")?;
    let run_dur = t.elapsed();
    let resources = ExecutionResources::from_prover_input(&prover_input);
    // `verify_instruction` counts unique PCs; the trace length (VM steps) is the sum of the
    // per-opcode instance counts.
    let steps: usize = resources.opcodes_instance_counter.values().sum();

    // 3. Prove.
    let mut params = load_params(&args)?;
    if let Some(raw) = &args.trace_log_size {
        let policy = parse_trace_log_size(raw)?;
        apply_trace_log_size(&mut params, &policy, &resources)?;
    }
    let t = Instant::now();
    let proof = prove_cairo::<Blake2sMerkleChannel>(prover_input, params.clone())
        .context("prove (stwo)")?;
    let prove_dur = t.elapsed();

    // 4. Verify (standalone, against the serialized claim).
    let t = Instant::now();
    let public_memory = proof.claim.public_data.public_memory.clone();
    let verification = get_verification_output(&public_memory);
    verify_cairo_ex::<Blake2sMerkleChannel>(proof.clone().into(), params.include_all_preprocessed_columns)
        .context("proof verification FAILED")?;
    let verify_dur = t.elapsed();

    // 5. Serialize artifacts.
    let t = Instant::now();
    // #0 证明瘦身口径（--all-formats 时全量测）：
    // - json_bytes        = proof.json（Rust verifier JSON，生产 fact-registry 腿格式）
    // - cairo_serde_bytes = felt 流（SNIP-36 proof 字段的同族形态；×4B ≈ uint32 打包下限）
    // - bincode_raw_bytes = bincode(CairoProofForRustVerifier) 未压缩字节（上链对象口径）
    // - binary_bz2_bytes  = bzip2(best, bincode)（zchain 分块上传 wire 格式）
    let mut sizes = serde_json::Map::new();
    if args.all_formats {
        let proof_for_rust: cairo_air::CairoProofForRustVerifier<Blake2sMerkleHasher> =
            proof.clone().into();
        let bincode_raw = bincode::serialize(&proof_for_rust)
            .context("bincode serialize (size measurement)")?;

        let json_path = out_dir.join("proof.json");
        serialize_proof_to_file(&proof, &json_path, ProofFormat::Json)
            .with_context(|| format!("write {}", json_path.display()))?;

        let bin_path = out_dir.join("proof.bin");
        serialize_proof_to_file(&proof, &bin_path, ProofFormat::Binary)
            .with_context(|| format!("write {}", bin_path.display()))?;

        let ext_path = out_dir.join("proof.ext.bin");
        serialize_proof_to_file(&proof, &ext_path, ProofFormat::ExtendedBinary)
            .with_context(|| format!("write {}", ext_path.display()))?;

        sizes.insert("json_bytes".into(), json_size(&json_path).into());
        sizes.insert("bincode_raw_bytes".into(), (bincode_raw.len() as u64).into());
        sizes.insert("binary_bz2_bytes".into(), json_size(&bin_path).into());
        sizes.insert("extended_bz2_bytes".into(), json_size(&ext_path).into());

        // cairo_serde 对未启用的 builtin 会在 vendored 栈里 unwrap None 而 panic
        // （cairo-air/src/air.rs FullSegmentRanges）——隔离该 panic：仅标记
        // 不可用，不影响其余格式与证明本身。
        let serde_path = out_dir.join("proof.serde.json");
        let prev_hook = std::panic::take_hook();
        std::panic::set_hook(std::boxed::Box::new(|_| {}));
        let serde_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            serialize_proof_to_file(&proof, &serde_path, ProofFormat::CairoSerde)
        }));
        std::panic::set_hook(prev_hook);
        match serde_result {
            Ok(Ok(())) => {
                let felts = read_felt_count(&serde_path);
                sizes.insert("cairo_serde_bytes_hex".into(), json_size(&serde_path).into());
                sizes.insert("cairo_serde_felts".into(), felts.into());
                sizes.insert(
                    "snip36_u32_words_x4".into(),
                    ((felts as u64).saturating_mul(4)).into(),
                );
                sizes.insert(
                    "snip36_bytes_x32".into(),
                    ((felts as u64).saturating_mul(32)).into(),
                );
            }
            _ => {
                let _ = fs::remove_file(&serde_path);
                sizes.insert(
                    "cairo_serde_felts".into(),
                    "unavailable (unused builtin segments, vendored stack panics)".into(),
                );
            }
        }
    }
    serialize_proof_to_file(&proof, &proof_path, args.proof_format.clone())
        .with_context(|| format!("write {}", proof_path.display()))?;
    let public_outputs = json!({
        "program_hash": format!("0x{:x}", verification.program_hash),
        "output": verification
            .output
            .iter()
            .map(|fe| format!("0x{fe:x}"))
            .collect::<Vec<_>>(),
    });
    write_json(&out_dir.join("public_outputs.json"), &public_outputs)?;
    let io_dur = t.elapsed();

    let total_dur = total.elapsed();

    // 6. Report + summary.json.
    println!();
    println!("phase        wall");
    println!(
        "compile      {}  ({})",
        fmt_dur(compile_dur),
        match cache_outcome {
            ExecCacheOutcome::Hit => "cache hit",
            ExecCacheOutcome::Miss => "cache miss",
            ExecCacheOutcome::Disabled => "cache disabled",
        }
    );
    println!(
        "run/witness  {}  ({} steps)",
        fmt_dur(run_dur), steps
    );
    println!("prove        {}", fmt_dur(prove_dur));
    println!("verify       {}  OK", fmt_dur(verify_dur));
    println!("serialize    {}", fmt_dur(io_dur));
    println!("total        {}", fmt_dur(total_dur));
    println!();
    println!("builtins (padded segment counts):");
    for (name, count) in sorted_counts(&resources.builtin_instance_counter) {
        println!("  {name:<16} {count}");
    }
    let public_output_str = public_outputs["output"]
        .as_array()
        .map(|a| {
            a.iter()
                .map(|v| v.as_str().unwrap_or_default().to_string())
                .collect::<Vec<_>>()
                .join(", ")
        })
        .unwrap_or_default();
    println!("program hash : {}", public_outputs["program_hash"].as_str().unwrap_or_default());
    println!("public output: [{public_output_str}]");
    println!("proof        : {} ({})", proof_path.display(), human_size(&proof_path));

    let summary = json!({
        "tool": "prove-hand",
        "program": program,
        "corelib": corelib,
        "scale": scale.label(),
        "inputs": args.inputs,
        "verified": true,
        "compile_cache": match cache_outcome {
            ExecCacheOutcome::Hit => "hit",
            ExecCacheOutcome::Miss => "miss",
            ExecCacheOutcome::Disabled => "disabled",
        },
        "artifacts": {
            "executable": "executable.json",
            "proof": proof_path.file_name().and_then(|n| n.to_str()).unwrap_or("proof.json"),
            "public_outputs": "public_outputs.json",
        },
        "timings_ms": {
            "compile": compile_dur.as_millis() as u64,
            "run_witness": run_dur.as_millis() as u64,
            "prove": prove_dur.as_millis() as u64,
            "verify": verify_dur.as_millis() as u64,
            "serialize": io_dur.as_millis() as u64,
            "total": total_dur.as_millis() as u64,
        },
        "execution": {
            "steps": steps,
            "unique_pcs": resources.verify_instruction,
            "builtin_instance_counter": resources.builtin_instance_counter,
            "opcodes_instance_counter": resources.opcodes_instance_counter,
        },
        "public": public_outputs,
        "trace_log_size": args
            .trace_log_size
            .clone()
            .unwrap_or_else(|| "default".into()),
        "prover_params": serde_json::to_value(&params)?,
        "security_bits": params.fri_config.security_bits(),
    });
    let summary = if sizes.is_empty() {
        summary
    } else {
        let mut s = summary;
        s["sizes"] = serde_json::Value::Object(sizes);
        s
    };
    let summary_path = out_dir.join("summary.json");
    write_json(&summary_path, &summary)?;
    println!("summary      : {}", summary_path.display());
    Ok(())
}

fn check_only(args: &Args, out_dir: &Path) -> Result<()> {
    let proof_path = args.proof.clone().unwrap_or_else(|| {
        out_dir.join(proof_file_name(&args.proof_format))
    });
    if !proof_path.exists() {
        bail!(
            "no proof at {} — run the pipeline first (or pass --proof)",
            proof_path.display()
        );
    }
    println!("prove-hand: check-only {}", proof_path.display());
    let t = Instant::now();
    let proof = deserialize_proof_from_file::<Blake2sMerkleHasher>(
        &proof_path,
        args.proof_format.clone(),
    )
        .with_context(|| format!("read proof {}", proof_path.display()))?;
    let load_dur = t.elapsed();

    let t = Instant::now();
    let public_memory = proof.claim.public_data.public_memory.clone();
    let verification = get_verification_output(&public_memory);
    let result = verify_cairo::<Blake2sMerkleChannel>(proof);
    let verify_dur = t.elapsed();
    match &result {
        Ok(()) => println!("verify       {}  OK", fmt_dur(verify_dur)),
        Err(e) => println!("verify       {}  FAILED: {e}", fmt_dur(verify_dur)),
    }
    println!("load         {}", fmt_dur(load_dur));
    println!("program hash : 0x{:x}", verification.program_hash);
    println!(
        "public output: [{}]",
        verification.output.iter().map(|fe| format!("0x{fe:x}")).collect::<Vec<_>>().join(", ")
    );
    result.context("proof verification FAILED")
}

#[derive(Clone, Copy, Debug)]
enum Scale {
    Small,
    Medium,
    Full,
    /// Custom bench with N_CHALLENGES = n (N_EC and PAYLOAD_LEN derived).
    Custom(usize),
}

impl Scale {
    fn label(&self) -> String {
        match self {
            Scale::Small => "small".into(),
            Scale::Medium => "medium".into(),
            Scale::Full => "full".into(),
            Scale::Custom(n) => format!("custom{n}"),
        }
    }
}

fn parse_scale(s: &str) -> Result<Scale> {
    match s {
        "small" => Ok(Scale::Small),
        "medium" => Ok(Scale::Medium),
        "full" => Ok(Scale::Full),
        s if s.chars().all(|c| c.is_ascii_digit()) && !s.is_empty() => {
            let n: usize = s.parse().context("--scale <number> must be a challenge count")?;
            if n == 0 {
                bail!("--scale <number> must be >= 1");
            }
            Ok(Scale::Custom(n))
        }
        _ => bail!("invalid --scale '{s}': expected small | medium | full | <challenge count>"),
    }
}

fn resolve_program(args: &Args, root: &Path, scale: &Scale, out_dir: &Path) -> Result<PathBuf> {
    if let Some(program) = &args.program {
        if matches!(scale, Scale::Custom(_)) {
            bail!("--program and a numeric --scale are mutually exclusive");
        }
        return Ok(program.clone());
    }
    match scale {
        Scale::Custom(n) => {
            // Same ratios as the shipped benches (small: 22/148/70, full: 220/1480/700).
            let n_ec = (n * 148).div_ceil(22);
            let payload_len = (n * 70).div_ceil(22);
            let src = BENCH_TEMPLATE
                .replace("__N_CHALLENGES__", &n.to_string())
                .replace("__N_EC__", &n_ec.to_string())
                .replace("__PAYLOAD_LEN__", &payload_len.to_string());
            let path = out_dir.join("hand_verify_bench_custom.cairo");
            fs::write(&path, src).with_context(|| format!("write {}", path.display()))?;
            Ok(path)
        }
        named => Ok(root
            .join(BENCH_DIR_REL)
            .join(format!("hand_verify_bench_{}.cairo", named.label()))),
    }
}

/// Mirrors the 96-bit-security defaults of `stwo-cairo-prover::create_and_serialize_proof`.
fn default_params() -> ProverParameters {
    ProverParameters {
        channel_hash: ChannelHash::Blake2s,
        channel_salt: 0,
        fri_config: FriConfig {
            pow_bits: 26,
            log_last_layer_degree_bound: 0,
            log_blowup_factor: 1,
            n_queries: 70,
            fold_step: 1,
        },
        preprocessed_trace: PreProcessedTraceVariant::Canonical,
        store_polynomials_coefficients: false,
        include_all_preprocessed_columns: false,
        opt_n_id_to_big_components: None,
        lifting_size_policy: LiftingSizePolicy::Auto,
    }
}

fn load_params(args: &Args) -> Result<ProverParameters> {
    match &args.params {
        Some(path) => {
            let text = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
            Ok(serde_json::from_str(&text).with_context(|| format!("parse {}", path.display()))?)
        }
        None => Ok(default_params()),
    }
}

/// The protocol's semantic floor for the main-trace commitment height (log2).
///
/// Evidence (vendored fork, traced 2026-09-29):
/// - `cairo-air/src/components/range_check_20.rs:6`: `pub const LOG_SIZE: u32 = 20`. The
///   component is always present (`prover/src/witness/range_checks.rs` injects all 13
///   range-check components unconditionally; `cairo_claim_generator.rs` registers them and
///   `cairo-air/src/claims.rs` pushes their `LOG_SIZE` into `CairoClaim::log_sizes()`).
/// - Its 2^20 rows are the *full 20-bit value table* (`seq_20` preprocessed column, 8
///   multiplicity channels), not shrinkable padding: the witness allocates
///   `AtomicMultiplicityColumn::new(1 << LOG_SIZE)` (`prover/src/witness/components/
///   range_check_20.rs:18`) and `mul_opcode` feeds it with limbs of felt252
///   multiplications, which reach up to 2^20-1 for arbitrary (e.g. poseidon-state) felts.
/// - `prover/src/prover.rs:133-134` derives `trace_domain_log_size` as the max claim log
///   size, so the committed trace domain is >= 2^20 for every program.
///
/// Going below 20 means changing the AIR (different value table) and the serialized claim
/// (`Claim {}` carries no data; the size is a compile-time constant on both prover and
/// verifier sides), i.e. a proof-format/verifier-contract change that would break the
/// byte-identical-default requirement. The CLI therefore refuses it (fail-closed) instead
/// of silently producing an incompatible proof.
const TRACE_LOG_SIZE_FLOOR: u32 = 20;

/// Parsed `--trace-log-size` value.
#[derive(Clone, Debug)]
enum TraceLogSize {
    /// Pick the lowest-memory sound preprocessed-trace variant from actual run resources.
    Auto,
    /// Explicit trace-height floor. Only 20 (the protocol floor) is accepted.
    Explicit(u32),
}

fn parse_trace_log_size(raw: &str) -> Result<TraceLogSize> {
    if raw == "auto" {
        return Ok(TraceLogSize::Auto);
    }
    let n: u32 = raw
        .parse()
        .with_context(|| format!("--trace-log-size '{raw}': expected 'auto' or a number"))?;
    if n < TRACE_LOG_SIZE_FLOOR {
        bail!(
            "--trace-log-size {n} is below the protocol floor {TRACE_LOG_SIZE_FLOOR}: the \
             always-present range_check_20 component is a full 20-bit value table (its 2^20 \
             rows are semantics, not padding; mul_opcode looks up felt252 limbs there), and \
             its size is baked into the serialized claim — shrinking it changes the proof \
             format. See proving-tool/src/main.rs TRACE_LOG_SIZE_FLOOR for the evidence."
        );
    }
    if n > TRACE_LOG_SIZE_FLOOR {
        bail!(
            "--trace-log-size {n} above the floor has no lever here: per-component trace \
             heights are derived from actual usage and the preprocessed-trace variants cap \
             at 2^20 (canonical_small) / 2^25 (canonical). To pin a taller commitment height \
             for a recursion verifier, use --params with lifting_size_policy=fixed."
        );
    }
    Ok(TraceLogSize::Explicit(n))
}

/// Applies the trace-height policy to the prover parameters.
///
/// `auto` uses the measured execution resources. The `canonical_small` preprocessed trace
/// differs from `canonical` only in (a) `seq` columns capped at log 20 (vs 25) and (b)
/// narrow-window Pedersen point tables. (a) is safe iff every builtin segment fits in
/// 2^20 instances — each builtin's component log size equals its (padded) instance count,
/// and that is the only driver of `seq_k` demand. (b) needs no guard: the witness itself
/// adapts (`prover/src/witness/builtins.rs:48-66` picks `pedersen_builtin` on wide tables
/// / `pedersen_builtin_narrow_windows` on narrow ones; a `pedersen_builtin: 0` segment
/// key is a layout reservation, not usage). A mismatch would otherwise fail later with a
/// missing-preprocessed-column panic; resolving it up front keeps the failure explicit.
fn apply_trace_log_size(
    params: &mut ProverParameters,
    policy: &TraceLogSize,
    resources: &ExecutionResources,
) -> Result<()> {
    match policy {
        TraceLogSize::Explicit(n) => {
            println!("trace-log-size: explicit {n} == protocol floor, no change");
            Ok(())
        }
        TraceLogSize::Auto => {
            let max_builtin_instances = resources
                .builtin_instance_counter
                .values()
                .copied()
                .max()
                .unwrap_or(0);
            let fits_small = max_builtin_instances <= 1usize << TRACE_LOG_SIZE_FLOOR;
            let variant = if fits_small {
                PreProcessedTraceVariant::CanonicalSmall
            } else {
                PreProcessedTraceVariant::Canonical
            };
            println!(
                "trace-log-size: auto -> {:?}  (max_builtin_instances={max_builtin_instances}, \
                 small_cap={})",
                variant,
                1usize << TRACE_LOG_SIZE_FLOOR
            );
            params.preprocessed_trace = variant;
            Ok(())
        }
    }
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("proving-tool must live inside the project")
        .to_path_buf()
}

fn proof_file_name(format: &ProofFormat) -> String {
    match format {
        ProofFormat::Binary | ProofFormat::ExtendedBinary => "proof.bin".into(),
        _ => "proof.json".into(),
    }
}

fn format_name(format: &ProofFormat) -> &'static str {
    match format {
        ProofFormat::Json => "json",
        ProofFormat::CairoSerde => "cairo_serde",
        ProofFormat::Binary => "binary",
        ProofFormat::ExtendedBinary => "extended_binary",
    }
}

fn write_json(path: &Path, value: &serde_json::Value) -> Result<()> {
    let mut f = fs::File::create(path).with_context(|| format!("create {}", path.display()))?;
    let mut bytes = serde_json::to_string_pretty(value)?.into_bytes();
    bytes.push(b'\n');
    f.write_all(&bytes).with_context(|| format!("write {}", path.display()))?;
    Ok(())
}

fn sorted_counts(map: &std::collections::HashMap<String, usize>) -> Vec<(String, usize)> {
    let mut entries: Vec<_> = map.iter().map(|(k, v)| (k.clone(), *v)).collect();
    entries.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    entries
}

fn fmt_dur(d: Duration) -> String {
    let secs = d.as_secs_f64();
    if secs >= 1.0 { format!("{secs:.2} s") } else { format!("{} ms", d.as_millis()) }
}

/// 文件字节数（--all-formats 的尺寸统计口径；读不到返回 0）。
fn json_size(path: &Path) -> u64 {
    fs::metadata(path).map(|m| m.len()).unwrap_or(0)
}

/// proof.serde.json（hex felt 数组）的 felt 数。
fn read_felt_count(path: &Path) -> u64 {
    let text = fs::read_to_string(path).unwrap_or_default();
    text.matches("\"0x").count() as u64
}

fn human_size(path: &Path) -> String {
    let mut file = match fs::File::open(path) {
        Ok(f) => f,
        Err(_) => return "n/a".into(),
    };
    let mut buf = Vec::new();
    if file.read_to_end(&mut buf).is_err() {
        return "n/a".into();
    }
    let bytes = buf.len() as f64;
    if bytes >= 1e6 { format!("{:.1} MB", bytes / 1e6) } else { format!("{:.0} KB", bytes / 1e3) }
}
