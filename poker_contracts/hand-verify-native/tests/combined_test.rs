//! 合并信封测试（form-③ combined）：一次 prove-hand 出一份 Stwo 证明，
//! 公开输出 = [new_acc] ++ settlement 公开段（17 词），双 parity 门
//! （acc / segment）+ `--check-only` 独立复验 + 负例。
//!
//! Heavy（spawn 真实 Cairo 管线）：`#[ignore]`-gated。运行：
//!   cargo test --release --test combined_test -- --ignored --nocapture
//! 依赖 prove-hand 二进制（cd proving-tool && cargo build --release）。
#![cfg(not(debug_assertions))]

use std::path::PathBuf;

use starknet_crypto::{poseidon_hash_many, Felt};

use hand_verify_native::combined::{
    build_settle_statement, mint_action_sig_statement, prove_combined_layer, segment_magic,
    SettleStatement,
};
use hand_verify_native::recurse::{
    build_action_batch_payload, write_prod_params, RecurseTask, GENESIS_ACC,
};

fn out_dir(tag: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("output/combined-test")
        .join(tag);
    std::fs::create_dir_all(&dir).expect("mkdir");
    dir
}

fn hand_binding(seed: u64) -> Felt {
    poseidon_hash_many(&[Felt::from(seed), Felt::from(0xC0FFEE_u64)])
}

/// 诚实合并批次：2 座位 action-sig（生产形状）+ 3 参与者结算
/// （+3000/-2000/-1000 wei 级，与 prove_sample_statement 同量级）。
/// 空动作日志（count=0 → 链根 = poseidon([DOMAIN])）。
fn honest_fixture(statements: usize) -> (Vec<RecurseTask>, SettleStatement, Felt) {
    let hb = hand_binding(1);
    let g = hand_verify_native::curve::Point::generator();
    let statements: Vec<_> = (0..statements)
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
    let payload = build_action_batch_payload(hb, 7, 9, &statements).expect("payload");
    let tasks = vec![RecurseTask { hand_binding: hb, payload }];

    let wei_chip: i128 = 100_000_000_000_000;
    let players = [Felt::from(0xAAA1_u64), Felt::from(0xAAA2_u64), Felt::from(0xAAA3_u64)];
    let deltas = [3000 * wei_chip, -2000 * wei_chip, -1000 * wei_chip];
    let commitments = [Felt::from(0x21_u64), Felt::ZERO, Felt::ZERO];
    let ald = poseidon_hash_many(&[hand_verify_native::combined::action_log_domain()]);
    let settle =
        build_settle_statement(9, hb, &players, &deltas, &commitments, ald, &[]).expect("settle");
    (tasks, settle, hb)
}

/// 一份合并证明同时覆盖 P 层与结算语句；双 parity + check-only 全绿。
#[test]
#[ignore]
fn combined_single_proof_roundtrip() {
    let params = write_prod_params(&out_dir("params")).expect("params");
    let magic = segment_magic();
    for seats in [2usize, 9] {
    let (tasks, settle, _hb) = honest_fixture(seats);
    let t = std::time::Instant::now();
    let outcome = prove_combined_layer(&tasks, &settle, GENESIS_ACC, &out_dir(&format!("roundtrip-{seats}")), Some(&params))
        .expect("combined envelope");
    let wall = t.elapsed();
    assert!(outcome.ec_ops > 0, "EC must be in the cairo trace");
    assert!(outcome.proof_bytes > 0);
    // 公开段锚定：MAGIC 之后 16 词（segment parity 已在驱动内断言）。
    assert!(outcome.public_output.contains(&magic), "segment missing");
    println!(
        "| combined {seats}p | steps {} | EC_OP {} | total {} ms (compile {} / run {} / prove {}) | \
         reverify {} ms | proof {} B | acc 0x{:x} |",
        outcome.steps,
        outcome.ec_ops,
        outcome.total_ms,
        outcome.cairo_compile_ms,
        outcome.cairo_run_ms,
        outcome.cairo_prove_ms,
        outcome.check_verify_ms,
        outcome.proof_bytes,
        outcome.cairo_acc,
    );
    // 数量级回归门（宽松阈值）。
    assert!(wall.as_secs() < 30, "order-of-magnitude regression: {wall:?}");
    }
}

/// 篡改 registered_digest → Cairo 语句断言失败 → 无证明（fail-closed）。
#[test]
#[ignore]
fn combined_rejects_tampered_digest() {
    let params = write_prod_params(&out_dir("params")).expect("params");
    let (tasks, mut settle, _hb) = honest_fixture(2);
    settle.registered_digest = segment_magic(); // 任意非期望值
    // host 预检也应先拒绝（驱动 fail-closed）；若绕过 host，Cairo 侧同样中止。
    let err = prove_combined_layer(&tasks, &settle, GENESIS_ACC, &out_dir("neg-digest"), Some(&params))
        .expect_err("tampered digest must not prove");
    assert!(err.contains("digest"), "unexpected error: {err}");
}

/// 跨手绑定负例：任务 hand_binding ≠ settle hand_binding → 拒绝（host 预检
/// 与 Cairo 侧绑定断言双保险，这里断言 host 预检路径）。
#[test]
#[ignore]
fn combined_rejects_cross_hand_binding() {
    let (tasks, settle, _hb) = honest_fixture(2);
    let wrong_binding = hand_binding(999);
    let mut alien = settle.clone();
    alien.hand_binding = wrong_binding;
    let err = prove_combined_layer(&tasks, &alien, GENESIS_ACC, &out_dir("neg-binding"), None)
        .expect_err("cross-hand batch must be rejected");
    assert!(
        err.contains("hand_binding") || err.contains("binding"),
        "unexpected error: {err}"
    );
}

/// 前缀折叠 digest 的公式对拍：n=3 时与「按实际人数折叠」一致，
/// 与「9 槽全吸收」不同——钉死 settlement_stmt.cairo 的修复语义。
#[test]
fn combined_digest_prefix_fold_semantics() {
    let (tasks, settle, _hb) = honest_fixture(2);
    assert_eq!(tasks.len(), 1);
    let n = 3;
    let mut fields = vec![Felt::from(9u64)];
    for i in 0..n {
        fields.push(settle.players[i]);
        fields.push(Felt::from(settle.signs[i]));
        fields.push(Felt::from(settle.magnitudes[i]));
    }
    fields.push(settle.action_log_digest);
    let n_fold = poseidon_hash_many(&fields);
    assert_eq!(settle.expected_digest(), n_fold, "must match on-chain n-fold");
    let mut padded = fields.clone();
    for _ in n..9 {
        padded.extend([Felt::ZERO, Felt::ZERO, Felt::ZERO]);
    }
    assert_ne!(
        poseidon_hash_many(&padded),
        n_fold,
        "9-slot fold must differ for n<9 (the fixed-slot absorption latent bug)"
    );
}
