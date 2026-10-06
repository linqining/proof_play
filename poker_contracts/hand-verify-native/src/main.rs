//! hand-verify-native — one-binary CLI for the native-Stwo hand_verify spike.
//!
//! Subcommands:
//! - `self-test` — mint honest hands (2-player / 4-player / 9-player with
//!   leave+recon), run the full host verification, prove, verify, and
//!   exercise the negative corpus (tamper / cross-hand replay / claim
//!   mismatch inside the STARK).
//! - `bench`     — prove/verify timings across payload scales, including
//!   amplified corpora, to demonstrate the O(log n)-verify property.
//! - `vectors`   — emit golden transcript vectors (challenges, rho, digest)
//!   for fixed inputs; the same vectors are pinned by an embedded test.
//! - `combined`  — cross-workspace subprocess seam: prove one combined
//!   envelope (P-layer tasks + settlement-private statement) and print a
//!   one-line JSON result (see [`combined_cmd`] for the wire format).
//!
//! Run inside `hand-verify-native/`: `cargo run --release -- self-test`.

use std::time::Instant;

// 2026-09-10 全仓统一：wire 与 crypto 层共用 starknet-crypto 0.8 的 Felt
// （= starknet-types-core Felt），无跨 Felt 桥。
use starknet_crypto::Felt;

use hand_verify_native::air::{HandBatchClaim, KindCounts};
use hand_verify_native::curve::Point;
use hand_verify_native::handbatch::{
    endorsement_challenge, hand_rho, leave_challenge, payload_digest,
    reconstruct_challenge, reveal_challenge, verify_hand, FoldEquation, LeaveCard,
    KIND_OWNERSHIP, KIND_RECONSTRUCT, KIND_REVEAL,
};
use hand_verify_native::{compose, curve, handbatch, mint, prove, recurse};

fn hand_binding(seed: u64) -> Felt {
    recurse::hand_binding(seed)
}

struct RoundTrip {
    label: &'static str,
    counts: KindCounts,
    host_verify_us: u128,
    prove_ms: u128,
    verify_us: u128,
    proof_bytes: usize,
    log_size: u32,
}

fn run_round_trip(label: &'static str, counts: KindCounts, seed: u64) -> RoundTrip {
    let hb = hand_binding(seed);
    let payload = mint::mint_hand(
        hb, counts.n_own, 0, counts.n_reveal, counts.n_leave, counts.n_recon, seed,
    );

    // 1. Host-native sigma verification (the form-① trust boundary).
    let t = Instant::now();
    let report = verify_hand(hb, &payload).expect("payload parses");
    let host_verify_us = t.elapsed().as_micros();
    assert!(report.accepted(), "minted payload must verify: {label}");
    assert_eq!(report.n_own, counts.n_own);
    assert_eq!(report.n_recon, counts.n_recon);

    // 2. Claim + prove.
    let claim =
            HandBatchClaim::new(hb, payload_digest(&payload), counts, Felt::ZERO);
    let t = Instant::now();
    let proof = prove::prove_claim(&claim).expect("prove");
    let prove_ms = t.elapsed().as_millis();

    // 3. Verify against the independently reconstructed claim.
    let t = Instant::now();
    prove::verify_claim(&claim, &proof).expect("verify");
    let verify_us = t.elapsed().as_micros();

    // Serialized proof size (bincode of the Stwo proof alone).
    let proof_bytes = bincode::serialize(&proof.stark_proof).map(|b| b.len()).unwrap_or(0);

    RoundTrip {
        label,
        counts,
        host_verify_us,
        prove_ms,
        verify_us,
        proof_bytes,
        log_size: claim.log_size,
    }
}

fn print_row(r: &RoundTrip) {
    println!(
        "| {:<14} | {:>3}+{:>3}+{:>2}+{:>2}    | {:>7} | {:>9.1} ms | {:>7.1} ms | {:>8.1} ms | {:>9} |",
        r.label,
        r.counts.n_own,
        r.counts.n_reveal,
        r.counts.n_leave,
        r.counts.n_recon,
        format!("2^{}", r.log_size),
        r.host_verify_us as f64 / 1000.0,
        r.prove_ms as f64,
        r.verify_us as f64 / 1000.0,
        format_bytes(r.proof_bytes),
    );
}

fn format_bytes(n: usize) -> String {
    if n >= 1 << 20 {
        format!("{:.1} MiB", n as f64 / (1 << 20) as f64)
    } else if n >= 1024 {
        format!("{:.1} KiB", n as f64 / 1024.0)
    } else {
        format!("{n} B")
    }
}

fn self_test() {
    println!("== self-test: honest corpora ==");
    let corpora = [
        ("2-player", KindCounts { n_own: 2, n_reveal: 18, n_leave: 1, n_recon: 1 }, 101u64),
        ("4-player", KindCounts { n_own: 4, n_reveal: 45, n_leave: 2, n_recon: 1 }, 102),
        ("9-player", KindCounts { n_own: 9, n_reveal: 207, n_leave: 3, n_recon: 2 }, 103),
    ];
    for (label, counts, seed) in corpora {
        let hb = hand_binding(seed);
        let payload = mint::mint_hand(
            hb, counts.n_own, 0, counts.n_reveal, counts.n_leave, counts.n_recon, seed,
        );
        let report = verify_hand(hb, &payload).expect("parses");
        assert!(report.accepted(), "{label} honest hand must verify");
        assert_eq!(report.n_own, counts.n_own);
        assert_eq!(report.n_reveal, counts.n_reveal);
        assert_eq!(report.n_leave, counts.n_leave);
        assert_eq!(report.n_recon, counts.n_recon);
        println!(
            "  {label}: n_eq={} residuals=identity fold=identity ✔",
            report.n_eq
        );
    }

    println!("== self-test: prove/verify round trips ==");
    for (label, counts, seed) in [
        ("2-player", KindCounts { n_own: 2, n_reveal: 18, n_leave: 1, n_recon: 1 }, 101u64),
        ("9-player", KindCounts { n_own: 9, n_reveal: 207, n_leave: 3, n_recon: 2 }, 103),
    ] {
        let hb = hand_binding(seed);
        let payload = mint::mint_hand(
            hb, counts.n_own, 0, counts.n_reveal, counts.n_leave, counts.n_recon, seed,
        );
        let claim =
            HandBatchClaim::new(hb, payload_digest(&payload), counts, Felt::ZERO);
        let proof = prove::prove_claim(&claim).expect("prove");
        prove::verify_claim(&claim, &proof).expect("verify");
        println!("  {label}: prove → verify ✔");
    }

    println!("== self-test: negative corpus ==");
    let hb = hand_binding(201);
    let seed = 201u64;

    // 1. Tampered s (ownership response word).
    let mut payload = mint::mint_hand(hb, 2, 1, 4, 0, 0, seed);
    payload[5 + 4] = payload[5 + 4] + Felt::from(1u32);
    assert!(!verify_hand(hb, &payload).unwrap().accepted(), "tampered s must reject");
    println!("  tampered ownership s → rejected ✔");

    // 2. Cross-hand replay (same payload, different binding).
    let payload = mint::mint_hand(hb, 2, 1, 4, 0, 0, seed);
    assert!(
        !verify_hand(hb + Felt::from(1u32), &payload).unwrap().accepted(),
        "cross-hand replay must reject"
    );
    println!("  cross-hand replay → rejected ✔");

    // 3. Off-curve pk.
    let mut payload = mint::mint_hand(hb, 1, 0, 0, 0, 0, seed);
    payload[5] = payload[5] + Felt::from(1u32);
    assert!(verify_hand(hb, &payload).is_err(), "off-curve pk must reject");
    println!("  off-curve pk → rejected ✔");

    // 4. STARK-level claim binding (transport check bypassed): a proof
    //    generated under a different hand binding must fail inside the
    //    protocol — this is the property an L1 verifier relies on.
    let counts = KindCounts { n_own: 2, n_reveal: 4, n_leave: 0, n_recon: 0 };
    let payload = mint::mint_hand(hb, counts.n_own, 0, counts.n_reveal, 0, 0, seed);
    let claim =
            HandBatchClaim::new(hb, payload_digest(&payload), counts, Felt::ZERO);
    let proof = prove::prove_claim(&claim).expect("prove");
    let other_hb = hb + Felt::from(7u32);
    let wrong =
            HandBatchClaim::new(other_hb, payload_digest(&payload), counts, Felt::ZERO);
    assert!(
        prove::verify_stark_against(&wrong, &proof.stark_proof).is_err(),
        "claim mismatch must reject inside the STARK"
    );
    println!("  claim mismatch (hand_binding) → rejected inside STARK ✔");

    // 5. Count mismatch at the STARK layer.
    let wrong_counts = KindCounts { n_own: 1, n_reveal: 4, n_leave: 0, n_recon: 0 };
    let wrong_counts =
            HandBatchClaim::new(hb, payload_digest(&payload), wrong_counts, Felt::ZERO);
    assert!(
        prove::verify_stark_against(&wrong_counts, &proof.stark_proof).is_err(),
        "count mismatch must reject inside the STARK"
    );
    println!("  claim count mismatch → rejected inside STARK ✔");

    println!("self-test: all green");
}

fn bench() {
    println!("== bench: host verify + native Stwo prove/verify (release) ==");
    println!("(statements = own+reveal+leave+recon)");
    println!("| {:<14} | {:<14} | {:>7} | {:>11} | {:>9} | {:>10} | {:>9} |",
        "scale", "statements", "rows", "host verify", "prove", "verify", "proof");
    println!("|-----------------|-----------------|---------|--------------|-----------|------------|-----------|");

    let scales: [(&str, KindCounts, u64); 5] = [
        ("2-player", KindCounts { n_own: 2, n_reveal: 18, n_leave: 1, n_recon: 1 }, 301),
        ("4-player", KindCounts { n_own: 4, n_reveal: 45, n_leave: 2, n_recon: 1 }, 302),
        ("9-player", KindCounts { n_own: 9, n_reveal: 207, n_leave: 3, n_recon: 2 }, 303),
        ("9p x10 (2k)", KindCounts { n_own: 90, n_reveal: 2070, n_leave: 30, n_recon: 20 }, 304),
        ("9p x40 (8k)", KindCounts { n_own: 360, n_reveal: 8280, n_leave: 120, n_recon: 80 }, 305),
    ];
    let mut results = Vec::new();
    for (label, counts, seed) in scales {
        let r = run_round_trip(label, counts, seed);
        print_row(&r);
        results.push(r);
    }

    println!();
    println!("== scaling check: verify / proof size vs statement count ==");
    let smallest = &results[0];
    let largest = results.last().unwrap();
    let count_ratio = largest.counts.total() as f64 / smallest.counts.total() as f64;
    let verify_ratio = largest.verify_us as f64 / smallest.verify_us as f64;
    println!(
        "statements ×{count_ratio:.0} (rows 2^{} → 2^{}) → verify ×{verify_ratio:.2} (FRI \
        layers grow with log_size, i.e. O(log n) with ms constants), proof {} → {}",
        smallest.log_size,
        largest.log_size,
        format_bytes(smallest.proof_bytes),
        format_bytes(largest.proof_bytes),
    );
    println!(
        "Cairo-route baseline for comparison: 13.6 s prove per 148-EC hand (M3 Pro, stwo-cairo)."
    );
}

/// Emit golden transcript vectors for fixed inputs. The embedded `vectors`
/// test pins these byte-for-byte; cross-checking them against
/// `poker-protocol-core::stark_curve::handbatch_*_challenge` (whose
/// host↔Cairo parity is pinned in the main project) is the production gate.
fn vectors() {
    let hb = Felt::from(0xB16Du64);
    let g = Point::generator();
    // Deterministic statement points: small multiples of G.
    let m = |k: u32| g.mul(Felt::from(k));
    let p2 = m(2);
    let p3 = m(3);
    let p4 = m(4);
    let p5 = m(5);
    let p6 = m(6);
    let p7 = m(7);

    let c_own = endorsement_challenge(hb, g, p2, p3);
    let c_rev = reveal_challenge(hb, p2, p3, p4, p5, p6, p7, Felt::from(8u32));
    let card = LeaveCard { in_c1: p2, in_c2: p3, out_c1: p4, out_c2: p5, a: p6 };
    let c_leave = leave_challenge(hb, p2, p3, Felt::from(8u32), &[card]);
    let c_recon = reconstruct_challenge(hb, g, p2, p3, p4, p5, p6);
    let eqs = [
        FoldEquation {
            kind: KIND_OWNERSHIP,
            s: Felt::from(11u32),
            c: c_own,
            residual: curve::Point::identity(),
        },
        FoldEquation {
            kind: KIND_REVEAL,
            s: Felt::from(12u32),
            c: c_rev,
            residual: curve::Point::identity(),
        },
        FoldEquation {
            kind: KIND_RECONSTRUCT,
            s: Felt::from(13u32),
            c: c_recon,
            residual: curve::Point::identity(),
        },
    ];
    let rho = hand_rho(hb, &eqs);
    let digest = handbatch::payload_digest(&[hb, Felt::from(1u32), Felt::from(2u32)]);

    for (name, bytes) in [
        ("hand_binding", hb.to_bytes_be()),
        ("endorsement_challenge", c_own.to_bytes_be()),
        ("reveal_challenge", c_rev.to_bytes_be()),
        ("leave_challenge", c_leave.to_bytes_be()),
        ("reconstruct_challenge", c_recon.to_bytes_be()),
        ("hand_rho", rho.to_bytes_be()),
        ("payload_digest", digest.to_bytes_be()),
    ] {
        println!("{name}: 0x{}", hex(&bytes));
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Form-② composed round trip: Cairo EC attestation (EC_OP in trace) +
/// native statement-table AIR, bound by the claim's program hash.
fn compose_cmd() {
    let counts = hand_verify_native::air::KindCounts { n_own: 2, n_reveal: 0, n_leave: 0, n_recon: 0 };
    let out_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("output/compose");
    println!("== compose: form-② (Cairo EC attestation + native table AIR) ==");
    let t = Instant::now();
    let report = compose::run_compose(counts, 601, &out_dir).expect("compose");
    println!(
        "  payload    : 2 ownership statements ({} EC_OP in cairo trace)",
        report.cairo_ec_ops
    );
    println!("  cairo half : prove {} ms (incl. compile + witness), check-only ✓", report.cairo_prove_ms);
    println!(
        "  native half: prove {} ms, verify {} ms ✓",
        report.native_prove_ms, report.native_verify_ms
    );
    println!(
        "  binding    : program hash 0x{} mixed into the native claim channel ✓",
        report.cairo_program_hash.to_bytes_be().iter().map(|b| format!("{b:02x}")).collect::<String>()
    );
    println!("  total wall : {} ms", t.elapsed().as_millis());
    println!("compose: all green");
}

/// Native felt252-mul kernel throughput: the leaf cost that the whole
/// form-② native stack multiplies by (EC step ≈ 8–12 kernel rows,
/// Poseidon permutation ≈ 1233).
fn mulbench() {
    use hand_verify_native::feltmul::{prove_felt_muls, verify_felt_muls, FeltMulClaim};
    use std::time::Instant;

    println!("== mulbench: native felt252-mod-mul kernel (trace row = 1 mul) ==");
    for log in [8u32, 10, 12] {
        let n = 1usize << log;
        let stmts: Vec<_> = (0..n as u64)
            .map(hand_verify_native::feltmul::sample_statement)
            .collect();
        let t = Instant::now();
        let proof = prove_felt_muls(&stmts, log).expect("prove");
        let prove = t.elapsed();
        let t = Instant::now();
        verify_felt_muls(&FeltMulClaim::new(log), &proof).expect("verify");
        let verify = t.elapsed();
        let muls_per_s = n as f64 / prove.as_secs_f64();
        println!(
            "| 2^{:<3} | {:>7} muls | prove {:>8.2?} | verify {:>8.2?} | {:>10.0} muls/s |",
            log, n, prove, verify, muls_per_s
        );
    }
}

/// Cairo-route recursion envelope (form-③): a 2-layer chained proof with
/// 2 tasks each, plus the negative corpus (tampered task / forged prev_acc).
fn recurse_cmd() {
    let counts = KindCounts { n_own: 2, n_reveal: 18, n_leave: 1, n_recon: 1 };
    let out_root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("output/recurse");
    println!("== recurse: Cairo-route recursion envelope (form-③) ==");
    let params = recurse::write_prod_params(&out_root).expect("params");
    let report =
        recurse::run_recursion(counts, 0, 2, 2, 1101, &out_root, Some(&params)).expect("recursion");
    for (i, layer) in report.layers.iter().enumerate() {
        println!(
            "  layer {i}: {} tasks, steps {}, EC_OP {}, prove {} ms (compile {} / run {}), \
             reverify {} ms, proof {}",
            layer.n_tasks,
            layer.steps,
            layer.ec_ops,
            layer.cairo_prove_ms,
            layer.cairo_compile_ms,
            layer.cairo_run_ms,
            layer.check_verify_ms,
            format_bytes(layer.proof_bytes),
        );
        println!(
            "    acc: 0x{}",
            layer.cairo_acc.to_bytes_be().iter().map(|b| format!("{b:02x}")).collect::<String>()
        );
    }
    println!(
        "  chain   : genesis → 0x{} (host parity ✓, {} layers, total {} ms)",
        report.host_chain_acc.to_bytes_be().iter().map(|b| format!("{b:02x}")).collect::<String>(),
        report.layers.len(),
        report.total_ms,
    );

    println!("== recurse: negative corpus ==");
    recurse::run_negative_tampered_task(
        counts,
        1201,
        &out_root.join("neg-tampered"),
        Some(&params),
    )
    .expect("tampered batch must be rejected");
    println!("  tampered task (bad s) → Cairo panic, no proof ✔");
    recurse::run_negative_wrong_prev(counts, 1202, &out_root.join("neg-prev"), Some(&params))
        .expect("forged prev_acc must be caught");
    println!("  forged prev_acc (cross-layer splice) → parity gate rejects ✔");
    println!("recurse: all green");
}

/// Recursion-envelope performance matrix: single-layer N ∈ {{1,2,4,8}} +
/// a 2-layer chain, production params (canonical_small + fast FRI).
fn recurse_perf_cmd() {
    let counts = KindCounts { n_own: 2, n_reveal: 18, n_leave: 1, n_recon: 1 };
    let out_root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("output/recurse-perf");
    println!("== recurse-perf: Cairo-route recursion envelope (canonical_small + fast FRI) ==");
    println!("(task = 2-player hand: 2 own + 18 reveal + 1 leave + 1 recon)");
    let params = recurse::write_prod_params(&out_root).expect("params");

    println!(
        "| {:<8} | {:>8} | {:>10} | {:>9} | {:>9} | {:>9} | {:>9} | {:>9} | {:>9} |",
        "tasks", "EC_OP", "steps", "compile", "run", "prove", "total", "reverify", "proof"
    );
    println!(
        "|----------|----------|------------|-----------|-----------|-----------|-----------|-----------|-----------|"
    );
    let rows = recurse::perf_sweep(counts, &[1, 2, 4, 8], 1301, &out_root, Some(&params))
        .expect("perf sweep");
    for r in &rows {
        println!(
            "| {:<8} | {:>8} | {:>10} | {:>8.1}s | {:>8.1}s | {:>8.1}s | {:>8.1}s | {:>8.1}s | {:>8} |",
            r.n_tasks,
            r.ec_ops,
            r.steps,
            r.cairo_compile_ms as f64 / 1000.0,
            r.cairo_run_ms as f64 / 1000.0,
            r.cairo_prove_ms as f64 / 1000.0,
            r.total_ms as f64 / 1000.0,
            r.check_verify_ms as f64 / 1000.0,
            format_bytes(r.proof_bytes),
        );
    }

    let unit = &rows[0];
    let biggest = rows.last().unwrap();
    let n_separate = unit.total_ms * biggest.n_tasks as u128;
    println!();
    println!(
        "amortization: {} separate proofs ≈ {:.1}s vs 1 envelope proof {:.1}s ({:.1}×)",
        biggest.n_tasks,
        n_separate as f64 / 1000.0,
        biggest.total_ms as f64 / 1000.0,
        n_separate as f64 / biggest.total_ms as f64,
    );

    println!("== 2-layer chain (2 tasks/layer) ==");
    let report = recurse::run_recursion(counts, 2, 2, 2, 1401, &out_root.join("chain"), Some(&params))
        .expect("chain");
    for (i, layer) in report.layers.iter().enumerate() {
        println!(
            "  layer {i}: prove {} ms, EC_OP {}, reverify {} ms",
            layer.cairo_prove_ms, layer.ec_ops, layer.check_verify_ms,
        );
    }
    println!(
        "  chain acc: 0x{}",
        report.host_chain_acc.to_bytes_be().iter().map(|b| format!("{b:02x}")).collect::<String>()
    );
    println!("recurse-perf: done");
}

/// combined 模式（跨 workspace 子进程缝）：从 JSON 输入驱动
/// [`hand_verify_native::combined::prove_combined_layer`]，stdout 打一行
/// JSON 结果——texas 等外部进程只消费这个稳定 CLI 契约，不链接本 crate。
///
/// # 输入 JSON（felt 一律 hex 字符串，可带/不带 0x）
///
/// ```json
/// {
///   "prev_acc": "0x…",              // 省略/null = GENESIS(0x0)
///   "out_dir": "…",                 // 证明工件目录（必填）
///   "params_path": null,            // prove-hand --params；null = 默认参数
///   "settle": {
///     "hand_id": 9,                 // u64
///     "registered_digest": "0x…",
///     "n_expected": 3,              // u64（非零 delta 计数）
///     "hand_binding": "0x…",
///     "players":     ["0x…" × 9],   // 尾部补位槽零
///     "signs":       [0|1 × 9],     // u64
///     "magnitudes":  [u64 × 9],
///     "commitments": ["0x…" × 9],
///     "action_log_digest": "0x…",
///     "action_entries": [["0x…","0x…"], …]   // 每条 2 词，≤ 30 条
///   },
///   "tasks": [ { "hand_binding": "0x…", "payload": ["0x…", …] } ]
/// }
/// ```
///
/// # 输出（stdout 单行 JSON）
///
/// 成功：`{"ok":true,"cairo_acc":"0x…","public_output":[16×"0x…"],
/// "program_hash":"0x…","steps":N,"total_ms":N,"out_dir":"…"}`——
/// `public_output` 从 MAGIC 锚定为 16 词 `[chain_acc] ++ v2 公开段(15)`
/// （prove-hand 辞書可能在段前回显 runner 词，锚定输出与 CombinedOutcome
/// 语义一致）。失败：`{"ok":false,"error":"…"}`，退出码 1。
fn combined_cmd() {
    // 参数：--input <路径>；缺省或 "-" 读 stdin。
    let args: Vec<String> = std::env::args().skip(2).collect();
    let mut input_path: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--input" => {
                i += 1;
                input_path = Some(
                    args.get(i)
                        .cloned()
                        .unwrap_or_else(|| {
                            eprintln!("combined: --input requires a path");
                            std::process::exit(2);
                        })
                );
            }
            other => {
                eprintln!("combined: unknown argument {other} (usage: combined --input <json>)");
                std::process::exit(2);
            }
        }
        i += 1;
    }
    let raw = match input_path.as_deref() {
        None | Some("-") => {
            use std::io::Read;
            let mut buf = String::new();
            std::io::stdin()
                .read_to_string(&mut buf)
                .unwrap_or_else(|e| {
                    eprintln!("combined: read stdin: {e}");
                    std::process::exit(2);
                });
            buf
        }
        Some(path) => std::fs::read_to_string(path).unwrap_or_else(|e| {
            eprintln!("combined: read {path}: {e}");
            std::process::exit(2);
        }),
    };
    match combined_run(&raw) {
        Ok(out) => println!("{out}"),
        Err(e) => {
            println!("{}", serde_json::json!({ "ok": false, "error": e }));
            std::process::exit(1);
        }
    }
}

/// JSON 值 → felt（hex 字符串，fail-loud）。
fn combined_felt(v: &serde_json::Value, ctx: &str) -> Result<Felt, String> {
    let s = v
        .as_str()
        .ok_or_else(|| format!("{ctx}: expected a hex string"))?;
    let t = s.trim().trim_start_matches("0x").trim_start_matches("0X");
    Felt::from_hex(t).map_err(|e| format!("{ctx}: bad felt hex {s:?}: {e:?}"))
}

/// JSON 值 → felt 数组。
fn combined_felt_vec(v: &serde_json::Value, ctx: &str) -> Result<Vec<Felt>, String> {
    v.as_array()
        .ok_or_else(|| format!("{ctx}: expected an array"))?
        .iter()
        .enumerate()
        .map(|(i, w)| combined_felt(w, &format!("{ctx}[{i}]")))
        .collect()
}

/// JSON 对象字段 → 固定 9 槽 felt 数组。
fn combined_felt9(obj: &serde_json::Value, key: &str) -> Result<[Felt; 9], String> {
    let v = obj
        .get(key)
        .ok_or_else(|| format!("settle.{key}: missing (9 slots required)"))?;
    let vec = combined_felt_vec(v, &format!("settle.{key}"))?;
    vec.try_into()
        .map_err(|_| format!("settle.{key}: expected exactly 9 slots"))
}

/// JSON 对象字段 → 固定 9 槽 u64 数组。
fn combined_u64_9(obj: &serde_json::Value, key: &str) -> Result<[u64; 9], String> {
    let arr = obj
        .get(key)
        .and_then(|v| v.as_array())
        .ok_or_else(|| format!("settle.{key}: expected an array of 9 u64"))?;
    if arr.len() != 9 {
        return Err(format!("settle.{key}: expected exactly 9 slots, got {}", arr.len()));
    }
    let mut out = [0u64; 9];
    for (i, v) in arr.iter().enumerate() {
        out[i] = v
            .as_u64()
            .ok_or_else(|| format!("settle.{key}[{i}]: expected u64"))?;
    }
    Ok(out)
}

/// 解析后的 combined 输入（prove 之前的纯 wire 层，测试可独立钉死）。
#[derive(Debug)]
struct CombinedInput {
    prev_acc: Felt,
    out_dir: String,
    params_path: Option<std::path::PathBuf>,
    settle: hand_verify_native::combined::SettleStatement,
    tasks: Vec<hand_verify_native::recurse::RecurseTask>,
}

/// 输入 JSON → 结构化输入（wire 解析层）。
fn combined_parse(raw: &str) -> Result<CombinedInput, String> {
    use hand_verify_native::combined::SettleStatement;
    use hand_verify_native::recurse::RecurseTask;

    let root: serde_json::Value =
        serde_json::from_str(raw).map_err(|e| format!("input JSON: {e}"))?;

    let prev_acc = match root.get("prev_acc") {
        Some(v) if !v.is_null() => combined_felt(v, "prev_acc")?,
        _ => hand_verify_native::combined::GENESIS,
    };
    let out_dir = root
        .get("out_dir")
        .and_then(|v| v.as_str())
        .ok_or("out_dir (string) is required")?
        .to_string();
    let params_path = match root.get("params_path") {
        Some(v) if !v.is_null() => Some(std::path::PathBuf::from(
            v.as_str().ok_or("params_path must be a string")?,
        )),
        _ => None,
    };

    let settle_v = root.get("settle").ok_or("settle object is required")?;
    let settle = SettleStatement {
        hand_id: settle_v
            .get("hand_id")
            .and_then(|v| v.as_u64())
            .ok_or("settle.hand_id (u64) is required")?,
        registered_digest: combined_felt(
            settle_v.get("registered_digest").ok_or("settle.registered_digest is required")?,
            "settle.registered_digest",
        )?,
        n_expected: settle_v
            .get("n_expected")
            .and_then(|v| v.as_u64())
            .ok_or("settle.n_expected (u64) is required")?,
        hand_binding: combined_felt(
            settle_v.get("hand_binding").ok_or("settle.hand_binding is required")?,
            "settle.hand_binding",
        )?,
        players: combined_felt9(settle_v, "players")?,
        signs: combined_u64_9(settle_v, "signs")?,
        magnitudes: combined_u64_9(settle_v, "magnitudes")?,
        commitments: combined_felt9(settle_v, "commitments")?,
        action_log_digest: combined_felt(
            settle_v
                .get("action_log_digest")
                .ok_or("settle.action_log_digest is required")?,
            "settle.action_log_digest",
        )?,
        action_entries: settle_v
            .get("action_entries")
            .and_then(|v| v.as_array())
            .ok_or("settle.action_entries (array, may be empty) is required")?
            .iter()
            .enumerate()
            .map(|(i, pair)| {
                let words = combined_felt_vec(pair, &format!("settle.action_entries[{i}]"))?;
                words
                    .try_into()
                    .map_err(|_| format!("settle.action_entries[{i}]: expected exactly 2 words"))
            })
            .collect::<Result<Vec<[Felt; 2]>, String>>()?,
    };

    let tasks: Vec<RecurseTask> = root
        .get("tasks")
        .and_then(|v| v.as_array())
        .ok_or("tasks (array, may be empty) is required")?
        .iter()
        .enumerate()
        .map(|(i, t)| {
            Ok(RecurseTask {
                hand_binding: combined_felt(
                    t.get("hand_binding").ok_or(format!("tasks[{i}].hand_binding is required"))?,
                    &format!("tasks[{i}].hand_binding"),
                )?,
                payload: combined_felt_vec(
                    t.get("payload").ok_or(format!("tasks[{i}].payload is required"))?,
                    &format!("tasks[{i}].payload"),
                )?,
            })
        })
        .collect::<Result<_, String>>()?;

    Ok(CombinedInput { prev_acc, out_dir, params_path, settle, tasks })
}

/// 输入 JSON → prove_combined_layer → 结果 JSON。
fn combined_run(raw: &str) -> Result<String, String> {
    use hand_verify_native::combined::{prove_combined_layer, segment_magic};

    let input = combined_parse(raw)?;
    let outcome = prove_combined_layer(
        &input.tasks,
        &input.settle,
        input.prev_acc,
        std::path::Path::new(&input.out_dir),
        input.params_path.as_deref(),
    )?;

    // 17 词锚定：[acc] ++ [MAGIC …]（与 prove_combined_layer 内部锚定同式；
    // 公开段前若有 runner 回显词，这里剥掉）。
    let magic = segment_magic();
    let pos = outcome
        .public_output
        .iter()
        .position(|w| *w == magic)
        .ok_or("SEGMENT_MAGIC not found in public output")?;
    // 切片 [pos-1, pos+16) 恰 17 词；pos+16 == len 是合法贴边情况，须放行。
    if pos == 0 || pos + 16 > outcome.public_output.len() {
        return Err("public output has no anchored 17-word segment".into());
    }
    let combined17 = outcome.public_output[pos - 1..pos + 16].to_vec();
    if combined17[0] != outcome.cairo_acc {
        return Err("anchored chain_acc != CombinedOutcome.cairo_acc".into());
    }

    Ok(serde_json::json!({
        "ok": true,
        "cairo_acc": format!("0x{:x}", outcome.cairo_acc),
        "public_output": combined17.iter().map(|f| format!("0x{f:x}")).collect::<Vec<_>>(),
        "program_hash": format!("0x{:x}", outcome.program_hash),
        "steps": outcome.steps,
        "total_ms": outcome.total_ms,
        "out_dir": outcome.out_dir.display().to_string(),
    })
    .to_string())
}

fn main() {
    let mode = std::env::args().nth(1).unwrap_or_else(|| "self-test".into());
    match mode.as_str() {
        "self-test" => self_test(),
        "bench" => bench(),
        "vectors" => vectors(),
        "compose" => compose_cmd(),
        "mulbench" => mulbench(),
        "recurse" => recurse_cmd(),
        "recurse-perf" => recurse_perf_cmd(),
        "combined" => combined_cmd(),
        "help" | "--help" | "-h" => {
            println!(
                "usage: hand-verify-native [self-test|bench|vectors|compose|mulbench|recurse|recurse-perf|combined --input <json>]"
            );
        }
        other => {
            eprintln!(
                "unknown mode: {other} (expected self-test | bench | vectors | compose | recurse | combined)"
            );
            std::process::exit(2);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Pin the golden transcript vectors. Any accidental drift in the
    /// transcript formulas (labels, word order, encoding) breaks this test.
    /// Values are generated by `cargo run --release -- vectors`; the
    /// production gate is cross-checking them against
    /// `poker-protocol-core::stark_curve` (host↔Cairo parity lives there).
    #[test]
    fn golden_vectors_pinned() {
        let hb = Felt::from(0xB16Du64);
        let g = Point::generator();
        let m = |k: u32| g.mul(Felt::from(k));
        let p2 = m(2);
        let p3 = m(3);
        let p4 = m(4);
        let p5 = m(5);
        let p6 = m(6);
        let p7 = m(7);

        // Populated from `cargo run --release -- vectors` (see
        // docs/golden-vectors.md); asserted here to pin formula drift — and,
        // since the starknet-crypto 0.8 alignment, to pin that the 0.8
        // poseidon output is byte-identical to the 0.6 vectors the corpus
        // was generated with.
        assert_eq!(
            hex(&endorsement_challenge(hb, g, p2, p3).to_bytes_be()),
            crate_golden::ENDORSEMENT,
        );
        assert_eq!(
            hex(&reveal_challenge(hb, p2, p3, p4, p5, p6, p7, Felt::from(8u32)).to_bytes_be()),
            crate_golden::REVEAL,
        );
        assert_eq!(hex(&hand_binding(1).to_bytes_be()), crate_golden::HAND_BINDING_SEED_1);
    }

    /// Inline module holding the pinned vectors (kept beside the test so a
    /// failure shows both sides of the comparison).
    mod crate_golden {
        // Generated by `cargo run --release -- vectors` (2026-09-05).
        pub const ENDORSEMENT: &str =
            "0189aed1c36bf0805ded895ee4f33d6c0dcf31dbdba0e71afaddbff230e633f4";
        pub const REVEAL: &str =
            "0229a973a7e63c4611e15f3b3789607159a9c19e533dc869e5096617b13d39c4";
        pub const HAND_BINDING_SEED_1: &str =
            "07eaa6791d6dec73dd42d4db78de231bec25b88b39faac13dcbbbc271088dac0";
    }

    /// combined CLI wire 层：输入 JSON 解析（不触发 prove）钉死——外部进程
    /// （texas prove_combined）按此形状产 JSON，这里钉住契约不漂移。
    #[test]
    fn combined_wire_parse() {
        let raw = r#"{
            "prev_acc": "0x123",
            "out_dir": "/tmp/combined-wire-test",
            "params_path": null,
            "settle": {
                "hand_id": 9,
                "registered_digest": "0xabc",
                "n_expected": 3,
                "hand_binding": "0xB16D",
                "players": ["0x1","0x2","0x3","0x0","0x0","0x0","0x0","0x0","0x0"],
                "signs": [1,0,0,0,0,0,0,0,0],
                "magnitudes": [3000,2000,1000,0,0,0,0,0,0],
                "commitments": ["0x21","0x0","0x0","0x0","0x0","0x0","0x0","0x0","0x0"],
                "action_log_digest": "0xA7",
                "action_entries": [["0xB1","0x0"],["0xB2","0xB3"]]
            },
            "tasks": [
                {"hand_binding": "0xB16D", "payload": ["0x1","0x2","0x3"]}
            ]
        }"#;
        let input = combined_parse(raw).expect("wire parses");
        assert_eq!(input.prev_acc, Felt::from(0x123u64));
        assert_eq!(input.out_dir, "/tmp/combined-wire-test");
        assert!(input.params_path.is_none());
        assert_eq!(input.settle.hand_id, 9);
        assert_eq!(input.settle.n_expected, 3);
        assert_eq!(input.settle.players[2], Felt::from(3u64));
        assert_eq!(input.settle.signs, [1, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(input.settle.magnitudes[0], 3000);
        assert_eq!(input.settle.action_entries.len(), 2);
        assert_eq!(input.settle.action_entries[1], [Felt::from(0xB2u64), Felt::from(0xB3u64)]);
        assert_eq!(input.tasks.len(), 1);
        assert_eq!(input.tasks[0].hand_binding, Felt::from(0xB16Du64));
        assert_eq!(input.tasks[0].payload, vec![Felt::from(1u64), Felt::from(2u64), Felt::from(3u64)]);

        // prev_acc 缺省 → GENESIS；坏 hex / 槽数错误 fail-loud。
        let genesis_json = r#"{"out_dir":"d","settle":{},"tasks":[]}"#;
        assert!(combined_parse(genesis_json).is_err(), "settle 字段缺失必须报错");
        let bad_hex = raw.replace("\"0x123\"", "\"not-hex\"");
        let err = combined_parse(&bad_hex).expect_err("bad felt hex must fail");
        assert!(err.contains("prev_acc"), "unexpected error: {err}");
        let bad_slots = raw.replace(
            "\"players\": [\"0x1\",\"0x2\",\"0x3\",\"0x0\",\"0x0\",\"0x0\",\"0x0\",\"0x0\",\"0x0\"]",
            "\"players\": [\"0x1\"]",
        );
        let err = combined_parse(&bad_slots).expect_err("slot count must be enforced");
        assert!(err.contains("players"), "unexpected error: {err}");
    }
}
