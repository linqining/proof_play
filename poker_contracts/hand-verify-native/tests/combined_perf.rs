//! 合并证明性能矩阵（form-③ combined，直调 [`prove_combined_layer`]，
//! 与 CLI/生产同一代码路径）。
//!
//! Heavy（spawn 真实 prove-hand）：`#[ignore]`-gated，逐配置独立进程运行
//! 以便外部 `/usr/bin/time -l` 采 max RSS：
//!   cargo test --release -p hand-verify-native --test combined_perf perf_s2p3 -- --ignored --nocapture
//! 输出 TSV：config run wall_ms total_ms compile_ms cairo_run_ms prove_ms
//!           check_ms steps ec_ops proof_bytes acc_hex
#![cfg(not(debug_assertions))]

use std::path::PathBuf;
use std::time::Instant;

use starknet_crypto::{poseidon_hash_many, Felt};

use hand_verify_native::combined::{
    build_settle_statement, mint_action_sig_statement, prove_combined_layer, SettleStatement,
};
use hand_verify_native::recurse::{build_action_batch_payload, RecurseTask, GENESIS_ACC};

fn perf_dir(tag: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("output/combined-perf")
        .join(tag);
    std::fs::create_dir_all(&dir).expect("mkdir");
    dir
}

fn hand_binding(seed: u64) -> Felt {
    poseidon_hash_many(&[Felt::from(seed), Felt::from(0xC0FFEE_u64)])
}

/// 零和结算 fixture：player0 赢 (n-1)×1000 wei-chip，其余各输 1000。
/// 空动作日志（count=0 → 链根 = poseidon([DOMAIN])），与 combined_test 同形。
fn fixture(statements: usize, players: usize) -> (Vec<RecurseTask>, SettleStatement, Felt) {
    assert!((2..=8).contains(&players), "contract caps n at 2..=8");
    let hb = hand_binding(1);
    let g = hand_verify_native::curve::Point::generator();
    let sigs: Vec<_> = (0..statements)
        .map(|i| {
            mint_action_sig_statement(
                &g,
                Felt::from(101 + i),
                Felt::from(1009 + 7 * i),
                7,
                9,
                100 + i as u64,
                "bet",
                50,
            )
        })
        .collect();
    let payload = build_action_batch_payload(hb, 7, 9, &sigs).expect("payload");
    let tasks = vec![RecurseTask { hand_binding: hb, payload }];

    let wei_chip: i128 = 100_000_000_000_000;
    let players_f: Vec<Felt> = (0..players).map(|i| Felt::from(0xAAA1_u64 + i as u64)).collect();
    let mut deltas: Vec<i128> = vec![-1000 * wei_chip; players];
    deltas[0] = ((players - 1) * 1000) as i128 * wei_chip;
    let commitments: Vec<Felt> = (0..players)
        .map(|i| if i == 0 { Felt::from(0x21_u64) } else { Felt::ZERO })
        .collect();
    let ald = poseidon_hash_many(&[hand_verify_native::combined::action_log_domain()]);
    let settle =
        build_settle_statement(9, hb, &players_f, &deltas, &commitments, ald, &[]).expect("settle");
    (tasks, settle, hb)
}

fn bench_config(tag: &str, statements: usize, players: usize, runs: usize) {
    bench_config_with(tag, statements, players, runs, None)
}

/// 优化腿（2026-09-29 内存优化）：与默认腿同一 prove-hand 代码路径，仅
/// `--params canonical_small.json` 钉扎最小可靠预处理迹（pp 域 2^20 / lifting 2^21，
/// 对比默认 canonical 的 2^25 / 2^26 —— 后者是 11.3-12.6GB 峰值 RSS 的大头）。
fn bench_config_with(
    tag: &str,
    statements: usize,
    players: usize,
    runs: usize,
    params: Option<&std::path::Path>,
) {
    let (tasks, settle, _hb) = fixture(statements, players);
    let dir = perf_dir(tag);
    println!(
        "# config={tag} statements={statements} players={players} runs={runs} params={}",
        params.map(|p| p.display().to_string()).unwrap_or_else(|| "default".into())
    );
    println!("# config\trun\twall_ms\ttotal_ms\tcompile_ms\tcairo_run_ms\tprove_ms\tcheck_ms\tsteps\tec_ops\tproof_bytes\tacc");
    for run in 0..runs {
        let out = dir.join(format!("run-{run}"));
        let t0 = Instant::now();
        let outcome = prove_combined_layer(&tasks, &settle, GENESIS_ACC, &out, params)
            .unwrap_or_else(|e| panic!("{tag} run {run} failed: {e}"));
        let wall_ms = t0.elapsed().as_millis();
        println!(
            "{tag}\t{run}\t{wall_ms}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{:064x}",
            outcome.total_ms,
            outcome.cairo_compile_ms,
            outcome.cairo_run_ms,
            outcome.cairo_prove_ms,
            outcome.check_verify_ms,
            outcome.steps,
            outcome.ec_ops,
            outcome.proof_bytes,
            outcome.cairo_acc,
        );
    }
}

/// proving-tool 侧钉扎参数（canonical_small）：pp 域 2^20、无宽 pedersen 依赖时
/// 可靠（combined.cairo 只用 poseidon）。等价于 `--trace-log-size auto` 的选择。
fn canonical_small_params() -> Option<PathBuf> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../proving-tool/params/canonical_small.json");
    path.is_file().then_some(path)
}

#[test]
#[ignore]
fn perf_s2p3() {
    bench_config("s2p3", 2, 3, 3);
}

#[test]
#[ignore]
fn perf_s8p3() {
    bench_config("s8p3", 8, 3, 3);
}

#[test]
#[ignore]
fn perf_s2p8() {
    bench_config("s2p8", 2, 8, 3);
}

#[test]
#[ignore]
fn perf_s32p8() {
    bench_config("s32p8", 32, 8, 3);
}

/// 优化端点（canonical_small 预处理迹）：验收线 = 峰值 RSS ≤ 6G、acc 与默认腿
/// 逐字相同、内部 verify 通过、prove ≤ 默认 1.5×。命令同默认腿：
///   cargo test --release -p hand-verify-native --test combined_perf perf_s2p3_csmall -- --ignored --nocapture
#[test]
#[ignore]
fn perf_s2p3_csmall() {
    bench_config_with("s2p3-csmall", 2, 3, 3, canonical_small_params().as_deref());
}

#[test]
#[ignore]
fn perf_s32p8_csmall() {
    bench_config_with("s32p8-csmall", 32, 8, 3, canonical_small_params().as_deref());
}
