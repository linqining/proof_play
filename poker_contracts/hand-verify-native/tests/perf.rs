//! Performance tests for the native-Stwo hand_verify spike.
//!
//! 纪律（延续主仓库 docs/PERFORMANCE.md）：
//! - 整个文件在 debug 构建下编译排除（`cfg(not(debug_assertions))`），
//!   证明类测试一律只在 pinned nightly + `--release` 下运行；
//! - `perf_gate_single_hand` 是 release 下的常驻回归门槛（宽松阈值，
//!   只防数量级退化）；
//! - `perf_full_matrix` / `perf_batch_amortization` 是完整矩阵，`#[ignore]`
//!   按需运行：`cargo test --release --test perf -- --ignored --nocapture`。
#![cfg(not(debug_assertions))]

use std::time::{Duration, Instant};

use starknet_crypto::Felt;

use hand_verify_native::air::{HandBatchClaim, KindCounts};
use hand_verify_native::handbatch::{payload_digest, verify_hand};
use hand_verify_native::{mint, prove};

fn hand_binding(seed: u64) -> Felt {
    starknet_crypto::poseidon_hash_many(&[
        Felt::from(seed),
        Felt::from(0xB16Du64),
    ])
}

struct Measurement {
    host_verify: Duration,
    prove: Duration,
    verify: Duration,
    proof_bytes: usize,
    accepted: bool,
    stark_verified: bool,
}

/// Mint → host verify → claim → prove → verify, all timed.
fn measure(counts: KindCounts, seed: u64) -> Measurement {
    let hb = hand_binding(seed);
    let payload = mint::mint_hand(
        hb, counts.n_own, 0, counts.n_reveal, counts.n_leave, counts.n_recon, seed,
    );

    let t = Instant::now();
    let report = verify_hand(hb, &payload).expect("payload parses");
    let host_verify = t.elapsed();

    let claim =
        HandBatchClaim::new(hb, payload_digest(&payload), counts, Felt::ZERO);
    let t = Instant::now();
    let proof = prove::prove_claim(&claim).expect("prove");
    let prove = t.elapsed();

    let t = Instant::now();
    let verified = prove::verify_claim(&claim, &proof).is_ok();
    let verify = t.elapsed();

    Measurement {
        host_verify,
        prove,
        verify,
        proof_bytes: bincode::serialize(&proof.stark_proof).map(|b| b.len()).unwrap_or(0),
        accepted: report.accepted(),
        stark_verified: verified,
    }
}

fn nine_player() -> KindCounts {
    KindCounts { n_own: 9, n_reveal: 207, n_leave: 3, n_recon: 2 }
}

/// Release 常驻回归门槛：9 人满手（436 EC 方程）的直验 + 证明 + 验证
/// 必须全部在产品级预算内（M4-ACC-1 的证明就绪目标 ≤3s，这里用 1/3 作
/// 门槛留出机器余量；verify 对应 wasm 预算的量级检查）。
#[test]
fn perf_gate_single_hand() {
    let m = measure(nine_player(), 9001);
    assert!(m.accepted, "honest 9-player hand must verify");
    assert!(m.stark_verified, "proof must verify");
    assert!(
        m.host_verify < Duration::from_millis(500),
        "host verify regressed: {:?}",
        m.host_verify
    );
    assert!(
        m.prove < Duration::from_millis(1000),
        "prove regressed (baseline ~20ms): {:?}",
        m.prove
    );
    assert!(
        m.verify < Duration::from_millis(100),
        "verify regressed (baseline ~7ms): {:?}",
        m.verify
    );
    assert!(
        m.proof_bytes < 256 * 1024,
        "proof size regressed: {} B",
        m.proof_bytes
    );
}

/// 完整规模矩阵 + O(log n) 缩放检查。`cargo test --release --test perf --
/// --ignored --nocapture`
#[test]
#[ignore]
fn perf_full_matrix() {
    let scales: [(&str, KindCounts, u64); 5] = [
        ("2-player", KindCounts { n_own: 2, n_reveal: 18, n_leave: 1, n_recon: 1 }, 301),
        ("4-player", KindCounts { n_own: 4, n_reveal: 45, n_leave: 2, n_recon: 1 }, 302),
        ("9-player", KindCounts { n_own: 9, n_reveal: 207, n_leave: 3, n_recon: 2 }, 303),
        ("9p x10 (2k)", KindCounts { n_own: 90, n_reveal: 2070, n_leave: 30, n_recon: 20 }, 304),
        ("9p x40 (8k)", KindCounts { n_own: 360, n_reveal: 8280, n_leave: 120, n_recon: 80 }, 305),
    ];

    println!(
        "| {:<14} | {:>10} | {:>10} | {:>9} | {:>10} | {:>9} |",
        "scale", "host (ms)", "prove (ms)", "verify (ms)", "proof", "n_eq"
    );
    let mut measurements = Vec::new();
    for (label, counts, seed) in scales {
        let m = measure(counts, seed);
        assert!(m.accepted && m.stark_verified, "{label} must round-trip");
        println!(
            "| {:<14} | {:>10.1} | {:>10.1} | {:>11.1} | {:>10} |",
            label,
            m.host_verify.as_secs_f64() * 1000.0,
            m.prove.as_secs_f64() * 1000.0,
            m.verify.as_secs_f64() * 1000.0,
            format_bytes(m.proof_bytes),
        );
        measurements.push((label, counts.total(), m));
    }

    // 缩放断言：语句 ×432 时 verify 仍是毫秒级（O(log n)，FRI 层增长），
    // 阈值放宽到 ×10 防机器噪声误报；prove 保持亚秒级。
    let (small_total, small) = (&measurements[0].1, &measurements[0].2);
    let (large_total, large) = (&measurements[4].1, &measurements[4].2);
    let count_ratio = *large_total as f64 / *small_total as f64;
    let verify_ratio = large.verify.as_secs_f64() / small.verify.as_secs_f64();
    println!(
        "\nscaling: statements ×{count_ratio:.0} → verify ×{verify_ratio:.2}"
    );
    assert!(
        verify_ratio < 10.0,
        "verify scaling broke O(log n) envelope: ×{verify_ratio:.2}"
    );
    assert!(
        large.proof_bytes < 512 * 1024,
        "amplified proof size regressed: {} B",
        large.proof_bytes
    );
    assert!(
        large.prove < Duration::from_secs(2),
        "amplified prove regressed: {:?}",
        large.prove
    );
}

/// 批次摊销：40 手合成一个批次证明 vs 40 个独立证明。验证「按批聚合」
/// 是证明吞吐的主要杠杆（共享一棵 FRI 树）。
#[test]
#[ignore]
fn perf_batch_amortization() {
    let nine = nine_player();
    let single = measure(nine, 4001);
    let batch = measure(
        KindCounts {
            n_own: nine.n_own * 10,
            n_reveal: nine.n_reveal * 10,
            n_leave: nine.n_leave * 10,
            n_recon: nine.n_recon * 10,
        },
        4002,
    );

    let ten_separate = single.prove * 10;
    println!(
        "10 separate 9p proofs: {:?}; 1 batched 10x proof: {:?} ({:.1}x faster)",
        ten_separate,
        batch.prove,
        ten_separate.as_secs_f64() / batch.prove.as_secs_f64()
    );
    assert!(
        batch.prove < ten_separate,
        "batched proof must amortize better than separate proofs"
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
