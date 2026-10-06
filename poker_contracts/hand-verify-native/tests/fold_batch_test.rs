//! fold 批测试（FoldDesign v2 **生产形状·多桌**：fold_batch.cairo 并 102 词
//! settle wire + foldagg.rs 镜像；多桌规格 out/fold-multitable-spec.md；
//! 2026-09-30 九人桌迁移后语料/布局常量右移）。
//!
//! 测试清单（T 编号沿用设计，M 编号 = 多桌规格 §9 矩阵；负例名后缀
//! `_attack_*` 防回归语义漂移）：
//! - T1 正例（heavy）：2/5/9 人诚实聚合，K=8 手批 → 出证 verified +
//!   18 词段形状（[acc]++语句段++[roster_digest]）双 parity +
//!   `--check-only` 独立复验（P5 completeness 的电路级兑现）；
//! - T2 z̄+1 篡改 → 电路 panic 无证明（heavy；forge0_bad 方向已确认可行）；
//! - T3 跨手重放 (R̄,z̄) → 电路 panic（c 含 hand_binding）；
//! - T4 改性：host-parity 断言（公式漂移检测，**对 soundness 零证明力**
//!   ——soundness 闭合点在 roster_registry，T9/T10）；
//! - T5 伪造 prev_acc → 出证后 parity 门拒（recurse.rs:485-499 同款，heavy）；
//! - T6 off-curve / 恒等点 → 电路 panic（满阶依据：n 素 / cofactor=1 /
//!   无 2-torsion，审方 F-1 实测）；
//! - T7 perf（heavy）：K=1/8/32/64 @ P=8 生产形状 steps/RSS 扫描。验收线
//!   （fold-spec §3 诚实边界）：K=1 总量 ≤ combined 每手 12,160 + keyagg
//!   批固定层 1,628；批量边际 ≤ combined 每手 12,160（steps 轴底线——生产
//!   fold ≈11.3k/手估算 = keyagg 1,628 + 结算边际 9,405 + 签名层，结构性
//!   收益在单批单证/fact 密度 64×，不在 steps）；批 ≤ 2^20 桶；
//! - T8 KAT：BDN 域标签 / μ / M_h 真槽 / c / cm_digest 逐 felt 钉死（缺口 4
//!   + Q-2：cm_digest 8 词压缩十六进制钉值随生产版落库）；
//! - T9 forge0（heavy，_attack_A1）：wire pks 换攻击者钥 + 攻击者自签 →
//!   电路算术自洽照样出证，**断言点 = 出证后 host parity 门拒**
//!   （roster_digest ≠ 注册锚；生产对应 roster_registry 对照 segment[16]）；
//! - T10 agg1_forge（heavy，_attack_A2）：整组换 roster / n=1 同理门拒；
//! - T11/T12（heavy）：T9/T10 的 z̄+1 正控——电路对非签名的拒绝路径活跃，
//!   防「负例因电路坏而假阳性」；
//! - M8（多桌 §8）：T=1 金样回归——host 层 wire 逐 hex、heavy 层段/acc/
//!   digest 逐 felt 对 `tests/golden/fold_t1_p2k2.json`（重构前生产路径
//!   落库；steps/program_hash 不进金样）；
//! - M2/M4/M5/M6（host 单元）：多桌 wire 自定界布局、逐桌锚共享批终 acc、
//!   μ 绑定 n_t、跨桌混签 host 方程闭合、同 roster 两桌同 digest 合法；
//! - M1-b/M1-c（host 单元）：K_t=0 空桌构造器拒、T 窗口（T=0 / T>T_MAX=8 /
//!   锚数失配）prove 入口拒；
//! - M9-1（heavy 正例）：(a) T=2 不同人数桌、(b) T=2 同人数不同 roster、
//!   (c) T=8 全 8 人 ΣK=64 预算拼批 + 1.5× 余量门（M1-d）；
//! - M9-2（heavy 负例，_attack_MT*）：跨桌换 roster 电路 panic、跨桌
//!   (R̄,z̄) 重放电路 panic、换桌锚出证后 parity 门拒（m9_2c 断言门拒时
//!   proof.json 已落盘——「出证后」的实证）；
//! - M9-2d（heavy 正控，T11/T12 的多桌对应物）：诚实两桌 wire 过 m9_2a/b
//!   同一**裸出证入口**必须出证成功（m9_2a/b 的 panic 是攻击特异性而非
//!   「两桌 wire 一律失败」的假阳性）+ 同语料 z̄+1 电路 panic（多桌残差
//!   方程检查活跃，m9_2c 的门拒不掩盖死电路）；
//! - M9-3（heavy 形状负例）：尾桌截断 wire 拒、span_len 与实际词数不符拒。
//!
//! 运行（heavy 依赖 prove-hand 二进制）：
//!   cargo test -p hand-verify-native                       # 单测（T4/T8 + host 负例 + M 系 host 面）
//!   cargo test --release -p hand-verify-native \
//!     --test fold_batch_test -- --ignored --nocapture      # 全量真跑
//!   FOLD_PERF_ONLY=64 cargo test --release -p hand-verify-native \
//!     --test fold_batch_test t7 -- --ignored --nocapture   # 单档 perf（配 /usr/bin/time -l 采 RSS）

#![allow(non_snake_case)] // 测试名带 _attack_T9 等攻击标签后缀（防回归语义漂移）

use std::path::PathBuf;

use starknet_crypto::{poseidon_hash_many, Felt};

use hand_verify_native::combined::{action_log_domain, build_settle_statement, segment_magic};
use hand_verify_native::foldagg::{
    agg_pubkey, aggregate_nonces, aggregate_sign, build_batch_wire, build_batch_wire_tables,
    challenge_raw, claim_word, cm_digest_from_wire, ec_order_felt, expected_public_output,
    expected_public_output_tables, fold_acc, host_verify_batch, key_coeff_raw, mint_fold_hands,
    mint_roster_sks, msg_digest, nonce_commit, parse_settle_wire, prove_fold_batch,
    prove_fold_batch_multitable, prove_fold_batch_unchecked, prove_fold_batch_unchecked_tables,
    prove_wire_unchecked, prove_wire_unchecked_with_span, roster_digest, roster_pks_from_sks,
    verify_equation, FoldHand, FoldTable, FOLD_SEGMENT_LEN, FOLD_ROSTER_INDEX, FOLD_T_MAX,
    HAND_BLOCK_WORDS, KEYAGG_STEPS_ANCHOR, COMBINED_PER_HAND_STEPS, SETTLE_WORDS, NonceCommit,
};
use hand_verify_native::recurse::write_prod_params;

// ---------------------------------------------------------------------------
// 公共 fixture
// ---------------------------------------------------------------------------

const KAT_SEED: u64 = 0xFA17;

fn out_dir(tag: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("output/fold-batch-test")
        .join(tag);
    std::fs::create_dir_all(&dir).expect("mkdir");
    dir
}

fn det(seed: u64, i: u64) -> Felt {
    poseidon_hash_many(&[Felt::from(seed), Felt::from(i), Felt::from(0xF01Du64)])
}

/// 铸一条确定性诚实 settle wire（102 词，settlement_stmt 布局；指定
/// hand_binding；空动作日志、双席零和）——KAT 与攻击负例共用的槽词来源。
fn settle_wire(hand_id: u64, hb: Felt, seed: u64) -> Vec<Felt> {
    let players: Vec<Felt> = (0..2u64).map(|i| det(seed, 50 + i) + Felt::ONE).collect();
    let deltas: Vec<i128> = vec![1_000_000, -1_000_000];
    let cms: Vec<Felt> = (0..9u64).map(|i| det(seed, 60 + i)).collect();
    let ald = poseidon_hash_many(&[action_log_domain()]);
    build_settle_statement(hand_id, hb, &players, &deltas, &cms, ald, &[])
        .expect("settle statement must build")
        .wire_words()
}

/// 诚实批：P 人 roster + K 手（确定性），返回 (roster_pks, hands, anchor)。
fn honest_batch(players: usize, k_hands: usize, seed: u64) -> (
    Vec<(Felt, Felt)>,
    Vec<hand_verify_native::foldagg::AggregatedHand>,
    hand_verify_native::foldagg::RosterAnchor,
) {
    let sks = mint_roster_sks(players, seed);
    let pks = roster_pks_from_sks(&sks);
    let hand_seeds: Vec<u64> = (0..k_hands as u64).map(|i| seed * 1000 + i).collect();
    let hands = mint_fold_hands(&pks, &hand_seeds, seed).expect("honest mint");
    let anchor = expected_public_output(Felt::ZERO, &pks, &hands);
    (pks, hands, anchor)
}

/// canonical_small 参数（L1 批量终证腿钉扎参数集——与基线对比同口径）。
fn canonical_params() -> Option<PathBuf> {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("repo root")
        .join("proving-tool/params/canonical_small.json");
    p.exists().then_some(p)
}

/// 电路臂负例的拒因钉（t2/t3/t6/t11/t12/m9_2a/m9_2b 共用）。
///
/// **为何断言「VM assert 失败」而不是电路 panic 标签**（规格 M9-2 原文
/// 「断言失败文案含电路 panic 标签」在本出证栈不可实现，2026-09-30 实测）：
/// `panic_with_felt252('RESIDUAL_NOT_IDENTITY')` 经 Sierra `panic` 下降为
/// VM 级 ASSERT_EQ 失败，cairo-vm 3.2.0 的错误文案只含操作数
/// （vm_errors.rs「An ASSERT_EQ instruction failed: 0 != 1.」），panic 数组
/// 载荷不进文案；`assert!(cond, 'LABEL')` 形态的标签也进不来——Executable
/// 序列化（cairo-lang-casm AssembledCairoProgram）只携 bytecode+hints，
/// error_message_attributes 在落盘时即丢，且 vendored
/// dev_utils/vm_utils.rs 对 `Program::new_for_proof` 硬编码 `vec![]`。
/// 实测 t2（RESIDUAL_NOT_IDENTITY）与 t6（PK_OFF_CURVE）失败文案逐字节
/// 相同（pc=0:17、0 != 1）——**文案层无法区分拒因**，除非改造 vendored
/// 出证栈（Executable 格式 + vm_utils + cairo-vm 展示层，影响全部程序）。
///
/// 因此拒因的「标签」钉在两处可真断言的层：
/// 1. 本断言：失败必须是**电路内 VM assert**（非编译/IO/runner 错误）；
/// 2. host 镜像层钉精确标签：`t2_host`/`t3_host`
///    （`assert_eq!(err, "RESIDUAL_NOT_IDENTITY")`）与
///    `m5_cross_table_mix_host_equation_rejects_attack_MT1`（MT1/MT2 两臂
///    均断言 RESIDUAL_NOT_IDENTITY，与 m9_2a/m9_2b 同攻击形状）。
fn assert_circuit_assert_rejected(err: &str) {
    assert!(
        err.contains("An ASSERT_EQ instruction failed"),
        "rejection must be an in-circuit VM assert (panic label itself cannot surface on this \
         proving stack — see helper doc): {err}"
    );
}

// ---------------------------------------------------------------------------
// T4 —— host-parity 断言（改性：切片无注册面；对 soundness 零证明力）
// ---------------------------------------------------------------------------

/// **T4（改性，_attack_T4）**：foldagg 公式层自洽——roster_digest 输出 ==
/// H(pks) 且 P̄ == keyagg(pks)。**注明：这是 host 公式对拍，只检测公式/实现
/// 漂移，对 soundness 零证明力**——「wire pks == 注册 pks」的闭合点在生产
/// roster_registry（合约对照 segment[16]），切片负例见 T9/T10。
#[test]
fn t4_host_parity_roster_digest_and_pbar_attack_T4() {
    let (pks, hands, anchor) = honest_batch(5, 3, KAT_SEED);
    // roster_digest == H(pks)（独立内联重算，双路径一致）
    let mut words = vec![hand_verify_native::foldagg::roster_label(), Felt::from(5u64)];
    for (x, y) in &pks {
        words.push(*x);
        words.push(*y);
    }
    assert_eq!(anchor.roster_digest, poseidon_hash_many(&words));
    assert_eq!(anchor.roster_digest, roster_digest(&pks));
    // P̄ == keyagg(pks)：每手 c 都由同一 P̄ 签出（aggregate_sign 内部一次），
    // host 直验全过即 P̄ 公式与签名方程自洽
    host_verify_batch(&pks, &hands).expect("host parity");
    // 换任意一席 pk → roster_digest 必变（公式绑定性）
    let mut pks2 = pks.clone();
    pks2[0] = roster_pks_from_sks(&[det(KAT_SEED, 999)])[0];
    assert_ne!(roster_digest(&pks2), anchor.roster_digest);
}

// ---------------------------------------------------------------------------
// T8 —— KAT：BDN 域标签 / μ / M_h 真槽 / c / cm_digest 逐 felt 钉死
// ---------------------------------------------------------------------------

/// 固定 2 人 KAT fixture 的公式值（与 fold_batch.cairo 逐 felt parity 的
/// 期望侧；十六进制钉死防域分离/换序回归）。生产形状：M_h 真槽取自
/// settle wire——m1 = wire[1]（registered_digest，由语句 digest 公式定）、
/// m2 = wire[2]（n_expected = 2）、cm_digest = poseidon(wire[31..=39])
/// （9 词 c0..c8 压缩，Q-2 + 9 人桌迁移重钉）。
fn kat_fixture() -> (Vec<(Felt, Felt)>, hand_verify_native::foldagg::AggregatedHand) {
    let sks = vec![det(KAT_SEED, 0), det(KAT_SEED, 1)];
    let ws = vec![det(KAT_SEED, 100), det(KAT_SEED, 101)];
    let hb = det(KAT_SEED, 7);
    let settle = settle_wire(1, hb, KAT_SEED);
    let agg = aggregate_sign(&sks, &ws, &settle).expect("kat mint");
    let pks = roster_pks_from_sks(&sks);
    (pks, agg)
}

#[test]
fn t8_kat_labels_mu_mh_c_pinned_attack_T8() {
    let (pks, agg) = kat_fixture();
    // 域标签逐字节（ASCII short-string felt，与 Cairo '...' 字面量同编码）
    let ascii = |s: &str| {
        let b = s.as_bytes();
        let mut buf = [0u8; 32];
        buf[32 - b.len()..].copy_from_slice(b);
        Felt::from_bytes_be(&buf)
    };
    assert_eq!(hand_verify_native::foldagg::keyagg_label(), ascii("poker/fold-batch/keyagg.v1"));
    assert_eq!(hand_verify_native::foldagg::roster_label(), ascii("poker/fold-batch/roster.v1"));
    assert_eq!(hand_verify_native::foldagg::m_label(), ascii("poker/fold-batch/msg.v1"));
    assert_eq!(hand_verify_native::foldagg::sig_label(), ascii("poker/fold-batch/sig.v1"));
    assert_eq!(hand_verify_native::foldagg::claim_label(), ascii("poker/fold-batch/claim.v1"));

    // μ_0 / roster_digest —— 字节钉死（poseidon_hash_many 出口）
    let mu0 = key_coeff_raw(2, pks[0].0, pks[0].1);
    assert_eq!(
        mu0,
        Felt::from_hex(KAT_MU0).expect("kat mu0"),
        "μ_0 drifted: keyagg domain shape changed"
    );
    assert_eq!(
        agg.roster_digest,
        Felt::from_hex(KAT_ROSTER_DIGEST).expect("kat rd"),
        "roster_digest drifted"
    );

    // M_h 真槽（D2）：m1 = wire[1]、m2 = wire[2]、cm_digest = poseidon(wire[31..=39])
    let m1 = agg.hand.m1();
    let m2 = agg.hand.m2();
    let cm_digest = agg.hand.cm_digest();
    assert_eq!(
        m1,
        Felt::from_hex(KAT_M1).expect("kat m1"),
        "m1 slot drifted: registered_digest (wire[1]) formula changed"
    );
    assert_eq!(m2, Felt::from(2u64), "m2 slot must be wire[2] n_expected");
    assert_eq!(
        cm_digest,
        Felt::from_hex(KAT_CM_DIGEST).expect("kat cm_digest"),
        "cm_digest drifted: 9-word c0..c8 compression (wire[31..=39]) changed"
    );
    // 两路径一致：独立内联重算 cm_digest 与 FoldHand 派生同值
    assert_eq!(cm_digest, cm_digest_from_wire(&agg.hand.settle));
    let m_h = msg_digest(agg.hand.hand_binding(), m1, m2, cm_digest, agg.roster_digest);
    assert_eq!(m_h, agg.m_h, "host M_h two-path mismatch");
    assert_eq!(
        agg.m_h,
        Felt::from_hex(KAT_MH).expect("kat M_h"),
        "M_h drifted: message slot shape changed"
    );
    assert_eq!(
        agg.c,
        Felt::from_hex(KAT_C).expect("kat c"),
        "challenge c drifted"
    );
    // c 为 raw felt（poseidon 出口，不显式 mod n——群阶自动归约纪律，
    // 与电路 add_mul 同出口；verify_equation 的 host 侧同样 raw 进 EC）。
    let _ = ec_order_felt();
}

// KAT 钉值（固定 fixture：seed 0xFA17、2 人 roster、settle wire 由
// settle_wire(1, det(0xFA17,7), 0xFA17) 派生；改动 = 域分离/换序/槽位漂移，
// T8 必红）。9 人桌迁移（2026-09-30）：KAT_MU0/KAT_ROSTER_DIGEST/KAT_M1
// 沿用切片轮钉值（roster/digest 侧公式与 fixture 前 2 席语料不变，实测
// 未漂移）；KAT_CM_DIGEST/KAT_MH/KAT_C 随 cm×9 压缩重钉（断言失败输出
// 的 left 值即真实运行采集，非手算）：
const KAT_MU0: &str = "0340622f9a217eb20b2b9351112177337faa294eb02c0fb5035bfd3e8ac17ce6";
const KAT_ROSTER_DIGEST: &str = "04ac85cd07aebad095fef54ed9a8456effe0e05f56e6b30f074fbfc0a65817ce";
const KAT_M1: &str = "0579bd25d99b3c011f316568bd440da7f44fec8460b62e4caef2a675672241fc";
const KAT_CM_DIGEST: &str = "69d003b5d735953145749dd74674fa4c411bb4ebbe475124dfb365faccdbe14";
const KAT_MH: &str = "0b03e88e70c9c51405faea27537d03c7e1fc477610327ea6a68a749a4a09fdb";
const KAT_C: &str = "7537f4ba3b536c5ea05ab0a2a4fcc1603dd76056edf0cfa436f4388afbe64c7";

// ---------------------------------------------------------------------------
// host 负例（公式层，不需要 prove-hand——门禁常跑）
// ---------------------------------------------------------------------------

/// **T2 host 面**：z̄+1 → RESIDUAL_NOT_IDENTITY（电路 panic 的 host 对偶）。
#[test]
fn t2_host_zbar_plus_one_rejects_attack_T2() {
    let (_pks, agg) = kat_fixture();
    let err = verify_equation(agg.pbar, agg.hand.rbar, agg.c, agg.hand.zbar + Felt::ONE)
        .expect_err("z̄+1 must fail");
    assert_eq!(err, "RESIDUAL_NOT_IDENTITY");
}

/// **T3 host 面**：跨手重放 (R̄,z̄) → 换 hand_binding 改 c → 拒。
#[test]
fn t3_host_cross_hand_replay_rejects_attack_T3() {
    let (pks, hands, _anchor) = honest_batch(2, 2, KAT_SEED + 1);
    let h1 = &hands[0];
    let hb2 = hands[1].hand.hand_binding();
    // 用 h1 的 (R̄,z̄) + h2 的 binding 重算 c：必不闭合
    let pbar = hand_verify_native::foldagg::agg_pubkey(&pks).expect("pbar");
    let m_h2 = msg_digest(hb2, h1.hand.m1(), h1.hand.m2(), h1.hand.cm_digest(), h1.roster_digest);
    let c_replay = challenge_raw(hb2, m_h2, pbar, h1.hand.rbar);
    assert_ne!(c_replay, h1.c, "challenge must bind hand_binding");
    let err = verify_equation(pbar, h1.hand.rbar, c_replay, h1.hand.zbar).expect_err("replay");
    assert_eq!(err, "RESIDUAL_NOT_IDENTITY");
    // claim 绑定：不同 binding 的 M_h 必得不同 claim
    assert_ne!(claim_word(h1.hand.hand_binding(), h1.m_h), claim_word(hb2, m_h2));
}

/// **T6 host 面**：off-curve / 恒等点 fail-closed（满阶依据：n 素 /
/// cofactor=1 / 无 2-torsion，审方 F-1 实测——on-curve + 非恒等即满阶，
/// 电路 panic 标签与之逐字对应）。
#[test]
fn t6_host_off_curve_and_identity_fail_closed_attack_T6() {
    let g = hand_verify_native::curve::Point::generator();
    let (gx, gy) = g.to_affine().unwrap();
    // off-curve R̄
    let err = verify_equation((gx, gy), (gx, gy + Felt::ONE), Felt::ONE, Felt::ONE)
        .expect_err("off-curve R̄");
    assert_eq!(err, "RBAR_OFF_CURVE");
    // 恒等 P̄（(0,0) 编码：x=y=0 不在曲线上——用 from_affine=None 判恒等）
    let err = verify_equation((Felt::ZERO, Felt::ZERO), (gx, gy), Felt::ONE, Felt::ONE)
        .expect_err("identity-encoded P̄");
    assert!(err.contains("OFF_CURVE") || err.contains("IDENTITY"), "err: {err}");
    // z̄ 出域（≥ n）
    let err = verify_equation((gx, gy), (gx, gy), Felt::ONE, ec_order_felt())
        .expect_err("z̄ ≥ n");
    assert_eq!(err, "ZBAR_OUT_OF_RANGE");
}

/// **BDN 三轮镜像**：nonce 承诺 roundtrip + 篡改 R 揭露（NONCE_COMMIT_MISMATCH）。
#[test]
fn bdn_three_round_nonce_commitment_mirror() {
    let ws = vec![det(KAT_SEED, 300), det(KAT_SEED, 301), det(KAT_SEED, 302)];
    let commits: Vec<NonceCommit> = ws.iter().map(|w| nonce_commit(*w)).collect();
    let rbar = aggregate_nonces(&commits).expect("round2");
    // R̄ == Σ w_i·G（独立重算）
    let g = hand_verify_native::curve::Point::generator();
    let mut expect = hand_verify_native::curve::Point::identity();
    for w in &ws {
        expect = expect + g.mul(*w);
    }
    assert_eq!(Some(rbar), expect.to_affine());
    // 篡改揭出的 R → 承诺验证 fail-closed
    let mut bad = commits.clone();
    bad[1].r = (bad[1].r.0 + Felt::ONE, bad[1].r.1);
    let err = aggregate_nonces(&bad).expect_err("commit mismatch");
    assert_eq!(err, "NONCE_COMMIT_MISMATCH");
}

/// wire 形状：build_batch_wire 词数 = 2 + 2P + 105K，每手块 = settle 102 词
/// + (R̄x, R̄y, z̄)（电路头注释同布局；槽位锚逐位检查）。
#[test]
fn wire_layout_matches_circuit_contract() {
    let (pks, hands, _anchor) = honest_batch(3, 4, KAT_SEED + 2);
    let wire = build_batch_wire(&pks, &hands.iter().map(|h| h.hand.clone()).collect::<Vec<_>>());
    assert_eq!(wire.len(), 2 + 2 * 3 + HAND_BLOCK_WORDS * 4);
    assert_eq!(wire[0], Felt::from(3u64)); // P
    assert_eq!(wire[1 + 2 * 3], Felt::from(4u64)); // K
    for (j, h) in hands.iter().enumerate() {
        let base = 2 + 2 * 3 + HAND_BLOCK_WORDS * j;
        // settle 102 词原样摊平（hand_id@0、registered_digest@1、
        // n_expected@2、hand_binding@3、cm 槽@31..=39……）
        assert_eq!(&wire[base..base + SETTLE_WORDS], h.hand.settle.as_slice());
        assert_eq!(wire[base + 3], h.hand.hand_binding());
        // 签名见证紧跟 settle wire
        assert_eq!(wire[base + SETTLE_WORDS], h.hand.rbar.0);
        assert_eq!(wire[base + SETTLE_WORDS + 1], h.hand.rbar.1);
        assert_eq!(wire[base + SETTLE_WORDS + 2], h.hand.zbar);
    }
}

/// M_h 真槽对拍：m1/m2/cm_digest 从 settle wire 槽位派生（D2）——
/// m2（n_expected=2）≠ roster 人数（3）即证槽语义独立于 roster 规模。
#[test]
fn mh_slots_derive_from_settle_wire() {
    let (pks, hands, _anchor) = honest_batch(3, 1, KAT_SEED + 4);
    let h = &hands[0];
    assert_eq!(pks.len(), 3);
    assert_eq!(h.hand.m1(), h.hand.settle[1], "m1 must be wire[1] registered_digest");
    assert_eq!(h.hand.m2(), h.hand.settle[2], "m2 must be wire[2] n_expected");
    assert_ne!(h.hand.m2(), Felt::from(pks.len() as u64), "m2 ≠ roster size（槽语义独立）");
    assert_eq!(h.hand.cm_digest(), cm_digest_from_wire(&h.hand.settle));
    // 篡改任一 cm 槽词 → cm_digest 必变 → M_h 必变（共签消息绑定）
    let mut tampered = h.hand.settle.clone();
    tampered[SETTLE_CM_SLOT] = tampered[SETTLE_CM_SLOT] + Felt::ONE;
    assert_ne!(cm_digest_from_wire(&tampered), h.hand.cm_digest());
    let mh2 = msg_digest(h.hand.hand_binding(), h.hand.m1(), h.hand.m2(), cm_digest_from_wire(&tampered), h.roster_digest);
    assert_ne!(mh2, h.m_h);
}

/// cm 槽起点（settle wire[31..=39]，settlement_stmt.cairo 布局）。
const SETTLE_CM_SLOT: usize = 31;

/// acc 链公式对拍：expected acc == fold_acc(0, claims)（两路径一致）。
#[test]
fn acc_chain_formula_parity() {
    let (pks, hands, anchor) = honest_batch(2, 5, KAT_SEED + 3);
    let claims: Vec<Felt> = hands.iter().map(|h| h.claim).collect();
    assert_eq!(anchor.expected_acc, fold_acc(Felt::ZERO, &claims));
    // 链推进：换 prev_acc 必改期望输出（T5 门的形式依据）
    let anchor2 = expected_public_output(Felt::ONE, &pks, &hands);
    assert_ne!(anchor2.expected_acc, anchor.expected_acc);
}

// ---------------------------------------------------------------------------
// heavy：真 prove-hand 电路跑（#[ignore]；--release -- --ignored --nocapture）
// ---------------------------------------------------------------------------

/// **T1 正例**：2/5/9 人诚实聚合，K=8 手批 → verified + 18 词段形状
/// （[acc]++语句段(16)++[roster_digest]）双 parity + 独立复验。bench 表列
/// = steps / trace rows / EC_OP / poseidon / prove ms / total ms / proof B。
#[test]
#[ignore]
fn t1_honest_fold_batch_roundtrip() {
    let params = canonical_params();
    for players in [2usize, 5, 9] {
        let (pks, hands, anchor) = honest_batch(players, 8, KAT_SEED + players as u64);
        let t = std::time::Instant::now();
        let outcome = prove_fold_batch(
            Felt::ZERO,
            &pks,
            &hands,
            &anchor,
            &out_dir(&format!("t1-p{players}-k8")),
            params.as_deref(),
        )
        .expect("honest fold batch must prove");
        let wall = t.elapsed();
        assert!(outcome.ec_ops > 0, "EC must ride EC_OP in the cairo trace");
        assert!(outcome.cairo_acc == anchor.expected_acc);
        assert!(outcome.cairo_roster_digest == anchor.roster_digest);
        // 生产段形状（D1）：K 段 × 18 词；acc@0 与 roster_digest@17 批常量
        // 同值；MAGIC@1 = 'SP2M_OK'（combined 信封同位）
        assert_eq!(outcome.segments.len(), 8);
        for seg in &outcome.segments {
            assert_eq!(seg.len(), FOLD_SEGMENT_LEN);
            assert_eq!(seg[0], anchor.expected_acc);
            assert_eq!(seg[1], segment_magic(), "segment[1] must be MAGIC 'SP2M_OK'");
            assert_eq!(seg[FOLD_ROSTER_INDEX], anchor.roster_digest);
        }
        println!(
            "| T1 P={players} K=8 | steps {} | trace_rows(padded) {} | EC_OP {} | poseidon {} | \
             total {} ms (compile {} / run {} / prove {}) | reverify {} ms | proof {} B |",
            outcome.steps,
            outcome.steps.next_power_of_two(),
            outcome.ec_ops,
            outcome.poseidon_ops,
            outcome.total_ms,
            outcome.cairo_compile_ms,
            outcome.cairo_run_ms,
            outcome.cairo_prove_ms,
            outcome.check_verify_ms,
            outcome.proof_bytes,
        );
        assert!(wall.as_secs() < 120, "order-of-magnitude regression: {wall:?}");
    }
}

/// **T2**：篡改 z̄+1 → 电路 panic → 无证明（无 proof.json 产出）。
#[test]
#[ignore]
fn t2_zbar_plus_one_panics_no_proof_attack_T2() {
    let (pks, hands, _anchor) = honest_batch(2, 2, KAT_SEED + 10);
    let mut wire_hands: Vec<hand_verify_native::foldagg::FoldHand> =
        hands.iter().map(|h| h.hand.clone()).collect();
    wire_hands[1].zbar = wire_hands[1].zbar + Felt::ONE;
    let dir = out_dir("t2-zbar-plus-one");
    let err = prove_fold_batch_unchecked(Felt::ZERO, &pks, &wire_hands, &dir, None)
        .expect_err("tampered z̄ must not prove");
    assert!(err.contains("circuit rejected"), "unexpected: {err}");
    assert_circuit_assert_rejected(&err);
    assert!(!dir.join("proof.json").exists(), "panic must leave no proof");
}

/// **T3**：跨手重放——手 2 携手 1 的 (R̄,z̄)（settle wire 不同 → binding
/// 不同）→ 电路 panic。
#[test]
#[ignore]
fn t3_cross_hand_replay_panics_attack_T3() {
    let (pks, hands, _anchor) = honest_batch(2, 2, KAT_SEED + 11);
    let replayed = hand_verify_native::foldagg::FoldHand {
        settle: hands[1].hand.settle.clone(),
        rbar: hands[0].hand.rbar,
        zbar: hands[0].hand.zbar,
    };
    let wire_hands = vec![hands[0].hand.clone(), replayed];
    let dir = out_dir("t3-cross-hand-replay");
    let err = prove_fold_batch_unchecked(Felt::ZERO, &pks, &wire_hands, &dir, None)
        .expect_err("cross-hand replay must not prove");
    assert!(err.contains("circuit rejected"), "unexpected: {err}");
    assert_circuit_assert_rejected(&err);
}

/// **T5**：伪造 prev_acc → 电路照常出证，公开 acc 偏离注册链期望 → parity 门拒
/// （recurse.rs:485-499 同款；acc 门 = 链状态的切片消费面）。
#[test]
#[ignore]
fn t5_forged_prev_acc_parity_gate_rejects_attack_T5() {
    let params = canonical_params();
    let (pks, hands, anchor) = honest_batch(2, 2, KAT_SEED + 12);
    let forged_prev = Felt::ONE; // 诚实链 prev = 0
    let err = prove_fold_batch(
        forged_prev,
        &pks,
        &hands,
        &anchor,
        &out_dir("t5-forged-prev"),
        params.as_deref(),
    )
    .expect_err("forged prev_acc must be caught");
    assert!(err.contains("acc parity failure"), "unexpected: {err}");
}

/// **T6**：off-curve / 恒等 roster 点 → 电路 panic（fail-closed）。
#[test]
#[ignore]
fn t6_off_curve_pk_panics_attack_T6() {
    let (pks, hands, _anchor) = honest_batch(2, 1, KAT_SEED + 13);
    let (gx, gy) = hand_verify_native::curve::Point::generator().to_affine().unwrap();
    // (a) off-curve pk（y+1）
    let mut off = pks.clone();
    off[1] = (off[1].0, off[1].1 + Felt::ONE);
    let dir = out_dir("t6-off-curve");
    let err = prove_fold_batch_unchecked(
        Felt::ZERO,
        &off,
        &hands.iter().map(|h| h.hand.clone()).collect::<Vec<_>>(),
        &dir,
        None,
    )
    .expect_err("off-curve pk must panic");
    assert!(err.contains("circuit rejected"), "unexpected: {err}");
    assert_circuit_assert_rejected(&err);
    // (b) 恒等编码 pk：(0, 0)
    let mut ident = pks.clone();
    ident[1] = (Felt::ZERO, Felt::ZERO);
    let dir = out_dir("t6-identity-pk");
    let err = prove_fold_batch_unchecked(
        Felt::ZERO,
        &ident,
        &hands.iter().map(|h| h.hand.clone()).collect::<Vec<_>>(),
        &dir,
        None,
    )
    .expect_err("identity pk must panic");
    assert!(err.contains("circuit rejected"), "unexpected: {err}");
    assert_circuit_assert_rejected(&err);
    let _ = (gx, gy);
}

/// **T9（_attack_A1，forge0 复现形状）**：wire pks 全换攻击者钥、攻击者对
/// 自己 roster 诚实自签（settle wire/槽词与诚实手相同——攻「签名身份」不攻
/// 消息）→ 电路算术自洽**照样出证**（证明 wire pks 在电路内仍自由——这就是
/// 修复 1 第 3 步把 roster_digest 推成公开输出词的原因）；断言点 = 出证后
/// host parity 门拒（cairo roster_digest ≠ 注册锚）。生产对应 = 合约
/// roster_registry 对照 segment[16]（H1 单射）。
#[test]
#[ignore]
fn t9_forge0_attacker_roster_parity_gate_rejects_attack_A1() {
    let params = canonical_params();
    // 注册面（host 模拟）：诚实 2 人 roster 的锚
    let (_hpks, hhands, anchor) = honest_batch(2, 1, KAT_SEED + 20);
    // 攻击者：整批换钥 + 自签（同一 settle wire——攻「签名身份」不攻消息）
    let attacker_sks = vec![det(KAT_SEED, 777), det(KAT_SEED, 778)];
    let apks = roster_pks_from_sks(&attacker_sks);
    let ws = vec![det(KAT_SEED, 779), det(KAT_SEED, 780)];
    let forged =
        aggregate_sign(&attacker_sks, &ws, &hhands[0].hand.settle).expect("attacker self-sign");
    // 电路必须接受（攻击者的聚合签名对自己的 roster 成立）
    let dir = out_dir("t9-forge0");
    let proved = prove_fold_batch(
        Felt::ZERO,
        &apks,
        &[forged.clone()],
        // 锚仍是诚实 roster 的注册值——攻击者的 roster_digest 对照不上
        &anchor,
        &dir,
        params.as_deref(),
    );
    let err = proved.expect_err("attacker roster must be caught by the parity gate");
    assert!(
        err.contains("roster digest parity failure"),
        "unexpected failure mode: {err}"
    );
}

/// **T10（_attack_A2，agg1_forge 形状）**：整组换 roster（n=1 单钥）+
/// 自签 → 同 T9，出证后 parity 门拒。
#[test]
#[ignore]
fn t10_agg1_forge_swapped_roster_rejected_attack_A2() {
    let params = canonical_params();
    let (_hpks, hhands, anchor) = honest_batch(2, 1, KAT_SEED + 21);
    let attacker_sks = vec![det(KAT_SEED, 887)];
    let apks = roster_pks_from_sks(&attacker_sks);
    let ws = vec![det(KAT_SEED, 888)];
    let forged =
        aggregate_sign(&attacker_sks, &ws, &hhands[0].hand.settle).expect("attacker self-sign");
    let err = prove_fold_batch(
        Felt::ZERO,
        &apks,
        &[forged],
        &anchor,
        &out_dir("t10-agg1-forge"),
        params.as_deref(),
    )
    .expect_err("swapped roster must be caught");
    assert!(err.contains("roster digest parity failure"), "unexpected: {err}");
}

/// **T11（T9 正控，_attack_A1）**：攻击者 roster + z̄+1 → 电路 panic——
/// 确认「电路残差非恒等」这条保险对非签名活跃（防 T9 因电路坏而假阳性）。
#[test]
#[ignore]
fn t11_forged_roster_zbar_plus_one_panics_attack_A1_control() {
    let attacker_sks = vec![det(KAT_SEED, 777), det(KAT_SEED, 778)];
    let apks = roster_pks_from_sks(&attacker_sks);
    let ws = vec![det(KAT_SEED, 779), det(KAT_SEED, 780)];
    let hb = det(KAT_SEED, 20);
    let settle = settle_wire(11, hb, KAT_SEED + 30);
    let mut forged = aggregate_sign(&attacker_sks, &ws, &settle).expect("attacker self-sign");
    forged.hand.zbar = forged.hand.zbar + Felt::ONE;
    let dir = out_dir("t11-forge-zbar-plus-one");
    let err = prove_fold_batch_unchecked(Felt::ZERO, &apks, &[forged.hand], &dir, None)
        .expect_err("z̄+1 on forged roster must panic");
    assert!(err.contains("circuit rejected"), "unexpected: {err}");
    assert_circuit_assert_rejected(&err);
}

/// **T12（T10 正控，_attack_A2）**：n=1 换 roster + z̄+1 → 电路 panic。
#[test]
#[ignore]
fn t12_swapped_roster_zbar_plus_one_panics_attack_A2_control() {
    let attacker_sks = vec![det(KAT_SEED, 887)];
    let apks = roster_pks_from_sks(&attacker_sks);
    let ws = vec![det(KAT_SEED, 888)];
    let hb = det(KAT_SEED, 30);
    let settle = settle_wire(12, hb, KAT_SEED + 31);
    let mut forged = aggregate_sign(&attacker_sks, &ws, &settle).expect("attacker self-sign");
    forged.hand.zbar = forged.hand.zbar + Felt::ONE;
    let dir = out_dir("t12-n1-zbar-plus-one");
    let err = prove_fold_batch_unchecked(Felt::ZERO, &apks, &[forged.hand], &dir, None)
        .expect_err("z̄+1 on n=1 roster must panic");
    assert!(err.contains("circuit rejected"), "unexpected: {err}");
    assert_circuit_assert_rejected(&err);
}

/// **T7 perf**：K=1/8/32/64 @ P=8，生产形状 steps + 耗时扫描（RSS 由外层
/// `/usr/bin/time -l` 采集）。验收线（生产形状，提案 §3.1 诚实边界）：
/// K=1 总量 ≤ combined 每手 12,160 + keyagg 批固定层 1,628（一批只付一次）；
/// 批量边际 ≤ combined 每手 12,160（steps 轴底线——生产 fold ≈11.3k/手
/// 估算 = keyagg 1,628 + 结算边际 9,405 + 签名层；结构性收益在单批单证/
/// fact 密度 64×，不在 steps）；批 ≤ 2^20 桶。`FOLD_PERF_ONLY=<K>` 只跑
/// 单档（分档采 RSS 用）。
#[test]
#[ignore]
fn t7_perf_sweep_steps_gate() {
    let players = 8usize;
    let pks = roster_pks_from_sks(&mint_roster_sks(players, KAT_SEED + 42));
    let sizes: &[usize] = if let Ok(only) = std::env::var("FOLD_PERF_ONLY") {
        &[only.parse().expect("FOLD_PERF_ONLY must be a number")]
    } else {
        &[1, 8, 32, 64]
    };
    let params = canonical_params();
    println!("| P | K | wire | steps | rows(2^) | EC_OP | poseidon | prove ms | total ms | proof B | per-hand |");
    println!("|---|---|------|-------|----------|-------|----------|----------|----------|---------|----------|");
    let mut step_rows: Vec<(usize, u64)> = Vec::with_capacity(sizes.len());
    for &k in sizes {
        let hand_seeds: Vec<u64> = (0..k as u64).map(|i| KAT_SEED * 100 + i).collect();
        let hands = mint_fold_hands(&pks, &hand_seeds, KAT_SEED + 42).expect("mint");
        let anchor = expected_public_output(Felt::ZERO, &pks, &hands);
        let outcome = prove_fold_batch(
            Felt::ZERO,
            &pks,
            &hands,
            &anchor,
            &out_dir(&format!("t7-k{k}")),
            params.as_deref(),
        )
        .expect("perf run must prove");
        println!(
            "| {} | {} | {} | {} | 2^{} | {} | {} | {} | {} | {} | {} |",
            players,
            k,
            outcome.wire_words,
            outcome.steps,
            outcome.steps.next_power_of_two().ilog2(),
            outcome.ec_ops,
            outcome.poseidon_ops,
            outcome.cairo_prove_ms,
            outcome.total_ms,
            outcome.proof_bytes,
            outcome.steps / k as u64,
        );
        step_rows.push((k, outcome.steps));
    }
    // 验收线（生产形状）：K=1（keyagg 批固定层 + 1 手）与批量边际都不得
    // 劣于 combined 每手整证口径
    let k1 = step_rows.iter().find(|(k, _)| *k == 1).map(|(_, s)| *s);
    if let Some(s1) = k1 {
        assert!(
            s1 <= COMBINED_PER_HAND_STEPS + KEYAGG_STEPS_ANCHOR,
            "K=1 (keyagg + 1 hand) steps {s1} > combined per-hand {COMBINED_PER_HAND_STEPS} + keyagg anchor {KEYAGG_STEPS_ANCHOR}"
        );
        for &(k, s) in &step_rows {
            if k > 1 {
                let marginal = (s - s1) / (k as u64 - 1);
                assert!(
                    marginal <= COMBINED_PER_HAND_STEPS,
                    "per-hand marginal {marginal} > combined per-hand {COMBINED_PER_HAND_STEPS} at K={k}"
                );
            }
        }
    }
    for &(_, s) in &step_rows {
        assert!(s <= (1u64 << 20), "batch steps {s} exceed the 2^20 bucket");
    }
}

/// prod 参数辅助复用检查（recurse 的 write_prod_params 在本切片可用作快速档）。
#[test]
fn prod_params_helper_writable() {
    let dir = out_dir("params-prod");
    let p = write_prod_params(&dir).expect("params");
    assert!(p.exists());
}


// ---------------------------------------------------------------------------
// 多桌（out/fold-multitable-spec.md）：host 单元面——wire 布局 / 锚形状 /
// T 窗口 / 闭合链路镜像 / T=1 金样（非 heavy，门禁常跑）
// ---------------------------------------------------------------------------

/// M8 金样语料：P=2、K=2、seed 0xFA17+0x5EED（确定性；金样在多桌重构
/// **前**经当时生产路径 prove_fold_batch 出证落库，见
/// tests/golden/fold_t1_p2k2.json 的 provenance 字段）。
fn golden_t1_corpus() -> (
    Vec<(Felt, Felt)>,
    Vec<hand_verify_native::foldagg::AggregatedHand>,
    hand_verify_native::foldagg::RosterAnchor,
) {
    honest_batch(2, 2, 0xFA17u64.wrapping_add(0x5EED))
}

/// M8 金样 fixture（重构前生产路径落库；steps/program_hash 不进金样——
/// steps 走 T7 门、哈希走钉扎脚本）。
fn golden_json() -> serde_json::Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/golden/fold_t1_p2k2.json");
    serde_json::from_str(&std::fs::read_to_string(&path).expect("golden fixture readable"))
        .expect("golden fixture json")
}

fn felt_hex(f: Felt) -> String {
    format!("0x{}", f.to_bytes_be().iter().map(|b| format!("{b:02x}")).collect::<String>())
}

/// 诚实桌（roster + K_t 手，确定性）——多桌批的桌段单元（构造器强制
/// K_t ≥ 1，M1-b）。
fn honest_table(players: usize, k_hands: usize, seed: u64) -> FoldTable {
    let (pks, hands, _anchor) = honest_batch(players, k_hands, seed);
    FoldTable::new(pks, hands).expect("honest table")
}

/// 桌段列表 → 多桌 wire（prove 入口同构的测试侧构造）。
fn tables_wire(tables: &[FoldTable]) -> Vec<Felt> {
    let owned: Vec<(Vec<(Felt, Felt)>, Vec<FoldHand>)> = tables
        .iter()
        .map(|t| (t.roster_pks.clone(), t.wire_hands()))
        .collect();
    let borrowed: Vec<(&[(Felt, Felt)], &[FoldHand])> = owned
        .iter()
        .map(|(p, h)| (p.as_slice(), h.as_slice()))
        .collect();
    build_batch_wire_tables(&borrowed)
}

/// **M8（host 层）**：T=1 wire 逐 hex 对重构前金样——单桌构造器与多桌
/// 构造器（吃一桌）输出逐词相等（结构同一而非兼容模式，多桌规格 §8）。
#[test]
fn m8_t1_wire_matches_pre_multitable_golden() {
    let (pks, hands, _anchor) = golden_t1_corpus();
    let wire_hands: Vec<FoldHand> = hands.iter().map(|h| h.hand.clone()).collect();
    let single = build_batch_wire(&pks, &wire_hands);
    let multi = build_batch_wire_tables(&[(&pks, &wire_hands)]);
    assert_eq!(single, multi, "T=1: single-table and multitable constructors must be identical");
    let golden = golden_json();
    let gwire: Vec<String> = golden["wire"]
        .as_array()
        .expect("golden wire array")
        .iter()
        .map(|v| v.as_str().expect("hex word").to_string())
        .collect();
    assert_eq!(single.len(), gwire.len(), "wire word count drifted vs golden");
    for (i, w) in single.iter().enumerate() {
        assert_eq!(felt_hex(*w), gwire[i], "wire word {i} drifted vs pre-multitable golden");
    }
}

/// **M2（host 层）**：多桌 wire 自定界布局——`[P_t, pks×P_t, K_t, blocks×K_t]`
/// 串接、无全局 T 词；桌 2 头紧跟桌 1 blocks；每手块 = settle 102 +
/// (R̄x, R̄y, z̄) 与单桌块逐词同形。
#[test]
fn m2_multitable_wire_layout_self_delimiting_tables() {
    let ta = honest_table(3, 2, KAT_SEED + 420);
    let tb = honest_table(2, 1, KAT_SEED + 421);
    let wire = tables_wire(&[ta.clone(), tb.clone()]);
    // 词数 = Σ_t(2 + 2·P_t + 105·K_t)——无 T 词、无 padding 词
    let expect_len = (2 + 2 * 3 + HAND_BLOCK_WORDS * 2) + (2 + 2 * 2 + HAND_BLOCK_WORDS * 1);
    assert_eq!(wire.len(), expect_len);
    // 桌 1 头：P_1=3 @0（不是 T！）、K_1=2 @ 1+2·3（电路 words.at(cursor+1+2P)）
    assert_eq!(wire[0], Felt::from(3u64));
    assert_eq!(wire[1 + 2 * 3], Felt::from(2u64));
    // 桌 1 手 0 settle 原样摊平（首块起点 = 2+2·P_1）
    let base1 = 2 + 2 * 3;
    assert_eq!(&wire[base1..base1 + SETTLE_WORDS], ta.hands[0].hand.settle.as_slice());
    assert_eq!(wire[base1 + SETTLE_WORDS], ta.hands[0].hand.rbar.0);
    assert_eq!(wire[base1 + SETTLE_WORDS + 1], ta.hands[0].hand.rbar.1);
    assert_eq!(wire[base1 + SETTLE_WORDS + 2], ta.hands[0].hand.zbar);
    // 桌 2 头起点 = 桌 1 全段之后（自定界：cursor 越过 blocks 即下一桌）
    let t2_start = 2 + 2 * 3 + HAND_BLOCK_WORDS * 2;
    assert_eq!(wire[t2_start], Felt::from(2u64)); // P_2
    assert_eq!(wire[t2_start + 1 + 2 * 2], Felt::from(1u64)); // K_2
    let base2 = t2_start + 2 + 2 * 2;
    assert_eq!(&wire[base2..base2 + SETTLE_WORDS], tb.hands[0].hand.settle.as_slice());
    assert_eq!(wire[base2 + SETTLE_WORDS], tb.hands[0].hand.rbar.0);
    // T=2 但 wire[0]=P_1=3 ≠ 2——首词是人数不是桌数（无 T 前缀的负面证据）
    assert_ne!(wire[0], Felt::from(2u64));
}

/// **M4/M6（host 层）**：多桌锚形状——逐桌 digest 各异、expected_acc 全桌
/// 共享 = fold_acc(prev, claims 桌序串接)（Q-1 单次折叠）；换桌序 ⇒ 换 acc
/// （顺序绑定）；同 roster 两桌 digest 相同且合法（不同 run 同值允许）。
#[test]
fn m4_m6_multitable_anchors_shared_acc_table_digests() {
    let tables = vec![
        honest_table(2, 2, KAT_SEED + 405),
        honest_table(3, 1, KAT_SEED + 406),
    ];
    let anchors = expected_public_output_tables(Felt::ZERO, &tables);
    assert_eq!(anchors.len(), 2);
    assert_ne!(anchors[0].roster_digest, anchors[1].roster_digest);
    let claims: Vec<Felt> = tables.iter().flat_map(|t| t.hands.iter().map(|h| h.claim)).collect();
    let expect = fold_acc(Felt::ZERO, &claims);
    assert!(anchors.iter().all(|a| a.expected_acc == expect), "shared batch-final acc");
    // 换桌序 ⇒ 换 acc（claims 顺序绑定）
    let mut swapped = tables.clone();
    swapped.swap(0, 1);
    let swapped_anchors = expected_public_output_tables(Felt::ZERO, &swapped);
    assert_ne!(swapped_anchors[0].expected_acc, expect);
    // 同 pks 两桌（同批玩家群开两桌）：digest 相同、acc 仍折全部 claims——
    // 链层 run 分组语义下合法（多桌规格 §4.3「允许不同 run 同值」）
    let sks = mint_roster_sks(2, KAT_SEED + 405);
    let pks = roster_pks_from_sks(&sks);
    let ha = mint_fold_hands(&pks, &[9_771], KAT_SEED + 405).expect("mint a");
    let hb = mint_fold_hands(&pks, &[8_881], KAT_SEED + 405).expect("mint b");
    let same_roster = vec![
        FoldTable::new(pks.clone(), ha).expect("table a"),
        FoldTable::new(pks.clone(), hb).expect("table b"),
    ];
    let sr_anchors = expected_public_output_tables(Felt::ZERO, &same_roster);
    assert_eq!(sr_anchors[0].roster_digest, sr_anchors[1].roster_digest);
    assert_ne!(sr_anchors[0].expected_acc, anchors[0].expected_acc);
}

/// **M5（host 层，Q-M4）**：μ 绑定 n_t——同 pks 不同人数 ⇒ μ 不同 ⇒ P̄ 不同
/// （跨桌签名复用的额外一层堵截；heavy 铸造臂见 deviations）。
#[test]
fn m5_mu_binds_table_player_count_attack_MT4() {
    let pks = roster_pks_from_sks(&mint_roster_sks(3, KAT_SEED + 402));
    let mu2 = key_coeff_raw(2, pks[0].0, pks[0].1);
    let mu3 = key_coeff_raw(3, pks[0].0, pks[0].1);
    assert_ne!(mu2, mu3, "same pks different n_t must give different μ");
    let pbar2 = agg_pubkey(&pks[..2]).expect("pbar 2");
    let pbar3 = agg_pubkey(&pks).expect("pbar 3");
    assert_ne!(pbar2, pbar3, "same pks different n_t must give different P̄");
}

/// **M5（host 层，_attack_MT1/MT2）**：跨桌闭合链路的 host 镜像——M_h 含
/// 本桌 digest、c 含 M_h 与 P̄_t：桌 A 手配桌 B roster（或桌 B 手配桌 A 的
/// (R̄,z̄)）⇒ M_h/c 变 ⇒ 残差非恒等（电路第一重闭合的同构预检；heavy 电路
/// 臂见 m9_2a/m9_2b）。
#[test]
fn m5_cross_table_mix_host_equation_rejects_attack_MT1() {
    let (_pks_a, hands_a, _) = honest_batch(2, 1, KAT_SEED + 403);
    let (pks_b, hands_b, _) = honest_batch(3, 1, KAT_SEED + 404);
    let ha = &hands_a[0];
    let hb = &hands_b[0];
    let pbar_b = agg_pubkey(&pks_b).expect("pbar b");
    let rd_b = roster_digest(&pks_b);
    // (a) 桌 A 的手（m 槽不变）配桌 B 的 digest/P̄：M_h' ≠ M_h_A、c' ≠ c_A
    let m_h_mix = msg_digest(
        ha.hand.hand_binding(),
        ha.hand.m1(),
        ha.hand.m2(),
        ha.hand.cm_digest(),
        rd_b,
    );
    assert_ne!(m_h_mix, ha.m_h, "M_h must bind the owning table's roster_digest");
    let c_mix = challenge_raw(ha.hand.hand_binding(), m_h_mix, pbar_b, ha.hand.rbar);
    assert_ne!(c_mix, ha.c);
    let err = verify_equation(pbar_b, ha.hand.rbar, c_mix, ha.hand.zbar)
        .expect_err("cross-table roster mix must fail");
    assert_eq!(err, "RESIDUAL_NOT_IDENTITY");
    // (b) 桌 B 的手配桌 A 的 (R̄, z̄)（跨桌重放）：c'' ≠ c_B
    let c_replay = challenge_raw(hb.hand.hand_binding(), hb.m_h, pbar_b, ha.hand.rbar);
    assert_ne!(c_replay, hb.c);
    let err = verify_equation(pbar_b, ha.hand.rbar, c_replay, ha.hand.zbar)
        .expect_err("cross-table (R̄,z̄) replay must fail");
    assert_eq!(err, "RESIDUAL_NOT_IDENTITY");
}

/// **M1-b（host 层）**：K_t=0 空桌段由 host 构造器拒绝（电路不检——无
/// soundness 影响只浪费 steps；多桌规格 §2 附注/Q-M2）。
#[test]
fn m1b_empty_table_rejected_by_host_constructor() {
    let (pks, hands, _) = honest_batch(2, 1, KAT_SEED + 430);
    let err = FoldTable::new(pks.clone(), vec![]).expect_err("empty table must be rejected");
    assert!(err.contains("K_t = 0"), "unexpected: {err}");
    // 锚数失配（0 锚 ≠ 1 桌；2 锚 ≠ 1 桌）在 prove 入口同样 fail-closed——
    // 纯数据检查先于出证动作，无 prove-hand 也可单测
    let table = FoldTable::new(pks.clone(), hands).expect("table");
    let err = prove_fold_batch_multitable(
        Felt::ZERO,
        &[table.clone()],
        &[],
        &out_dir("m1b-no-anchors"),
        None,
    )
    .expect_err("zero anchors for one table must be rejected");
    assert!(err.contains("anchor count"), "unexpected: {err}");
    let two = expected_public_output_tables(
        Felt::ZERO,
        &[table.clone(), honest_table(2, 1, KAT_SEED + 431)],
    );
    let err = prove_fold_batch_multitable(
        Felt::ZERO,
        &[table],
        &two,
        &out_dir("m1b-two-anchors"),
        None,
    )
    .expect_err("two anchors for one table must be rejected");
    assert!(err.contains("anchor count"), "unexpected: {err}");
}

/// **M1-c（host 层）**：T 窗口——T=0 空批拒、T>T_MAX=8 拒（评审面政策，
/// 纯数据检查先于 prove-hand 存在性，无二进制也可单测）。
#[test]
fn m1c_t_window_rejects_empty_and_over_max_attack_MT5() {
    let err = prove_fold_batch_multitable(Felt::ZERO, &[], &[], &out_dir("m1c-t0"), None)
        .expect_err("empty batch (T=0) must be rejected");
    assert!(err.contains("T = 0"), "unexpected: {err}");
    let tables: Vec<FoldTable> = (0..=FOLD_T_MAX)
        .map(|i| honest_table(2, 1, KAT_SEED + 440 + i as u64))
        .collect();
    let err = prove_fold_batch_multitable(
        Felt::ZERO,
        &tables,
        &expected_public_output_tables(Felt::ZERO, &tables),
        &out_dir("m1c-t9"),
        None,
    )
    .expect_err("T > T_MAX must be rejected");
    assert!(err.contains("T_MAX"), "unexpected: {err}");
    // T = T_MAX = 8 本身放行（形状检查层）——真实出证见 m9_1c
    let ok_tables: Vec<FoldTable> = tables[..FOLD_T_MAX].to_vec();
    let anchors = expected_public_output_tables(Felt::ZERO, &ok_tables);
    assert!(hand_verify_native::foldagg::check_multitable_shape(&ok_tables, &anchors).is_ok());
}

// ---------------------------------------------------------------------------
// 多桌 heavy（#[ignore]；--release -- --ignored --nocapture）
// ---------------------------------------------------------------------------

/// **M8（heavy 层）**：T=1 出证与金样逐 felt 一致——段（18 词×K，9 人桌
/// 迁移后重采）、
/// 批终 acc、roster_digest 全对（verified 由 prove_fold_batch 内部已门）。
#[test]
#[ignore]
fn m8_t1_golden_roundtrip_heavy() {
    let (pks, hands, anchor) = golden_t1_corpus();
    let outcome = prove_fold_batch(
        Felt::ZERO,
        &pks,
        &hands,
        &anchor,
        &out_dir("m8-t1-golden"),
        canonical_params().as_deref(),
    )
    .expect("T=1 golden corpus must prove");
    let golden = golden_json();
    assert_eq!(felt_hex(outcome.cairo_acc), golden["cairo_acc"].as_str().expect("acc"));
    assert_eq!(
        felt_hex(outcome.cairo_roster_digest),
        golden["roster_digest"].as_str().expect("digest")
    );
    let gsegs = golden["public_output"]["segments"].as_array().expect("segments");
    assert_eq!(outcome.segments.len(), gsegs.len());
    for (j, gseg) in gsegs.iter().enumerate() {
        let words = gseg.as_array().expect("segment words");
        assert_eq!(outcome.segments[j].len(), words.len());
        for (w, gw) in words.iter().enumerate() {
            assert_eq!(
                felt_hex(outcome.segments[j][w]),
                gw.as_str().expect("hex word"),
                "segment {j} word {w} drifted vs pre-multitable golden"
            );
        }
    }
    println!(
        "| M8 T=1 golden | steps {} | acc {} | digest {} | reverify {} ms |",
        outcome.steps,
        &felt_hex(outcome.cairo_acc)[..18],
        &felt_hex(outcome.cairo_roster_digest)[..18],
        outcome.check_verify_ms
    );
}

/// 多桌 heavy 正例的共用断言：verified（prove 成功）+ 逐手段 word1..=16 ==
/// host expected_segment + seg[17] == 本桌锚 + 全部段 slot0 同值 ==
/// fold_acc(prev, claims 桌序串接)（M9-1 断言面，规格 §9）。
fn assert_multitable_outcome(
    prev_acc: Felt,
    tables: &[FoldTable],
    anchors: &[hand_verify_native::foldagg::RosterAnchor],
    outcome: &hand_verify_native::foldagg::FoldOutcome,
) {
    let claims: Vec<Felt> = tables.iter().flat_map(|t| t.hands.iter().map(|h| h.claim)).collect();
    let acc = fold_acc(prev_acc, &claims);
    let mut j = 0usize;
    for (t, table) in tables.iter().enumerate() {
        for h in &table.hands {
            let seg = &outcome.segments[j];
            assert_eq!(seg.len(), FOLD_SEGMENT_LEN);
            assert_eq!(seg[0], acc, "slot0 must be the shared batch-final acc");
            assert_eq!(
                seg[FOLD_ROSTER_INDEX],
                anchors[t].roster_digest,
                "slot17 must equal the OWNING table's anchor digest (hand {j} table {t})"
            );
            let expected_seg =
                parse_settle_wire(&h.hand.settle).expect("parse").expected_segment().expect("seg");
            assert_eq!(&seg[1..FOLD_ROSTER_INDEX], expected_seg.as_slice(), "hand {j} words");
            j += 1;
        }
    }
    assert_eq!(j, outcome.segments.len());
    assert_eq!(outcome.n_tables, tables.len());
    assert_eq!(outcome.cairo_acc, acc);
}

/// **M9-1(a)**：T=2 不同人数桌（P=9/K=8 + P=2/K=8，ΣK=16——9 人桌口径）。
#[test]
#[ignore]
fn m9_1a_multitable_two_tables_distinct_player_counts() {
    let tables = vec![
        honest_table(9, 8, KAT_SEED + 450),
        honest_table(2, 8, KAT_SEED + 451),
    ];
    let anchors = expected_public_output_tables(Felt::ZERO, &tables);
    assert_ne!(anchors[0].roster_digest, anchors[1].roster_digest);
    let outcome = prove_fold_batch_multitable(
        Felt::ZERO,
        &tables,
        &anchors,
        &out_dir("m9-1a-t2-p8p2-k8k8"),
        canonical_params().as_deref(),
    )
    .expect("two-table batch must prove");
    assert_eq!(outcome.table_players, vec![9, 2]);
    assert_eq!(outcome.table_hands, vec![8, 8]);
    assert_eq!(outcome.n_hands, 16);
    assert_multitable_outcome(Felt::ZERO, &tables, &anchors, &outcome);
    println!(
        "| M9-1a T=2 (9×8+2×8) | steps {} | trace 2^{} | EC_OP {} | poseidon {} | total {} ms |",
        outcome.steps,
        outcome.steps.next_power_of_two().ilog2(),
        outcome.ec_ops,
        outcome.poseidon_ops,
        outcome.total_ms
    );
}

/// **M9-1(b)**：T=2 同人数不同 roster（P=8/K=4 + P=8/K=4，ΣK=8）。
#[test]
#[ignore]
fn m9_1b_multitable_same_size_distinct_rosters() {
    let tables = vec![
        honest_table(8, 4, KAT_SEED + 452),
        honest_table(8, 4, KAT_SEED + 453),
    ];
    let anchors = expected_public_output_tables(Felt::ZERO, &tables);
    assert_ne!(anchors[0].roster_digest, anchors[1].roster_digest, "distinct rosters");
    let outcome = prove_fold_batch_multitable(
        Felt::ZERO,
        &tables,
        &anchors,
        &out_dir("m9-1b-t2-p8p8-k4k4"),
        canonical_params().as_deref(),
    )
    .expect("same-size two-table batch must prove");
    assert_multitable_outcome(Felt::ZERO, &tables, &anchors, &outcome);
    println!(
        "| M9-1b T=2 (8×4+8×4) | steps {} | total {} ms |",
        outcome.steps, outcome.total_ms
    );
}

/// **M9-1(c)**：预算上限拼批——T=8 全 9 人 ΣK=64（M1-c 政策边界，9 人桌
/// 迁移后的新最坏情形）。验收门（M1-d）：steps ≤ 2^20 桶且实测余量 ≥ 1.5×
/// （steps·3 ≤ 2^20·2）。
#[test]
#[ignore]
fn m9_1c_multitable_budget_t8_sumk64() {
    let tables: Vec<FoldTable> = (0..8u64)
        .map(|i| honest_table(9, 8, KAT_SEED + 500 + i))
        .collect();
    let anchors = expected_public_output_tables(Felt::ZERO, &tables);
    let outcome = prove_fold_batch_multitable(
        Felt::ZERO,
        &tables,
        &anchors,
        &out_dir("m9-1c-t8-p8-sumk64"),
        canonical_params().as_deref(),
    )
    .expect("T=8 ΣK=64 budget batch must prove");
    assert_multitable_outcome(Felt::ZERO, &tables, &anchors, &outcome);
    let bucket = 1u64 << 20;
    assert!(outcome.steps <= bucket, "steps {} exceed the 2^20 bucket", outcome.steps);
    assert!(
        outcome.steps * 3 <= bucket * 2,
        "measured margin {:.2}x < 1.5x (steps {})",
        bucket as f64 / outcome.steps as f64,
        outcome.steps
    );
    println!(
        "| M9-1c T=8 ΣK=64 | steps {} | margin {:.2}x | trace 2^{} | EC_OP {} | poseidon {} | total {} ms |",
        outcome.steps,
        bucket as f64 / outcome.steps as f64,
        outcome.steps.next_power_of_two().ilog2(),
        outcome.ec_ops,
        outcome.poseidon_ops,
        outcome.total_ms
    );
}

/// **M9-2(a)（_attack_MT1，跨桌换 roster）**：桌 A 的手配桌 B 的 pks 头
/// （同批两桌段，桌 A 段诚实）⇒ M_h/c 变 ⇒ 方程 z̄_A·G − c·P̄_B − R̄_A ≠ O
/// ⇒ 电路 panic、无证明（多桌规格 §5 闭合推导的电路臂）。
#[test]
#[ignore]
fn m9_2a_cross_table_roster_swap_panics_attack_MT1() {
    let (pks_a, hands_a, _) = honest_batch(2, 1, KAT_SEED + 411);
    let (pks_b, _, _) = honest_batch(3, 1, KAT_SEED + 412);
    let hands_a_wire: Vec<FoldHand> = hands_a.iter().map(|h| h.hand.clone()).collect();
    let dir = out_dir("m9-2a-cross-roster");
    let err = prove_fold_batch_unchecked_tables(
        Felt::ZERO,
        &[
            (&pks_a, &hands_a_wire), // 桌 A 段：诚实
            (&pks_b, &hands_a_wire), // 桌 B 段：桌 A 的手配桌 B roster 头
        ],
        &dir,
        None,
    )
    .expect_err("cross-table roster mix must not prove");
    assert!(err.contains("circuit rejected"), "unexpected: {err}");
    assert_circuit_assert_rejected(&err);
    assert!(!dir.join("proof.json").exists(), "panic must leave no proof");
}

/// **M9-2(b)（_attack_MT2，跨桌重放）**：桌 B 的手携桌 A 的 (R̄, z̄)
/// ⇒ c 变（R̄ 进 c）⇒ 电路 panic（与 T3 同链条的跨桌形态）。
#[test]
#[ignore]
fn m9_2b_cross_table_sig_replay_panics_attack_MT2() {
    let (pks_a, hands_a, _) = honest_batch(2, 1, KAT_SEED + 413);
    let (pks_b, hands_b, _) = honest_batch(3, 1, KAT_SEED + 414);
    let replayed = FoldHand {
        settle: hands_b[0].hand.settle.clone(),
        rbar: hands_a[0].hand.rbar,
        zbar: hands_a[0].hand.zbar,
    };
    let dir = out_dir("m9-2b-cross-replay");
    let err = prove_fold_batch_unchecked_tables(
        Felt::ZERO,
        &[
            (&pks_a, &vec![hands_a[0].hand.clone()]),
            (&pks_b, &vec![replayed]),
        ],
        &dir,
        None,
    )
    .expect_err("cross-table (R̄,z̄) replay must not prove");
    assert!(err.contains("circuit rejected"), "unexpected: {err}");
    assert_circuit_assert_rejected(&err);
    assert!(!dir.join("proof.json").exists(), "panic must leave no proof");
}

/// **M9-2(c)（_attack_MT3，parity 门臂）**：诚实两桌出证后把桌锚互换
/// ⇒ 手 0（桌 0）对照桌 1 的锚 ⇒ roster parity 门拒（带手序号与桌序号；
/// 生产对应 = 合约逐手段对照 roster_registry）。**活跃性审计**：本负例走
/// **出证后门拒**路径——prove-hand 先成功（proof.json 落盘），门在对照
/// 注册锚时才拒（foldagg.rs 门序：roster 门 → acc 门 → 段公式门，全部
/// 出证后）；断言 proof.json 存在即「后」的实证。
#[test]
#[ignore]
fn m9_2c_swapped_table_anchors_parity_gate_rejects_attack_MT3() {
    let tables = vec![
        honest_table(2, 1, KAT_SEED + 407),
        honest_table(3, 1, KAT_SEED + 408),
    ];
    let mut anchors = expected_public_output_tables(Felt::ZERO, &tables);
    anchors.reverse(); // 桌 0 的手对照桌 1 的注册锚
    let dir = out_dir("m9-2c-swap-anchors");
    let err = prove_fold_batch_multitable(
        Felt::ZERO,
        &tables,
        &anchors,
        &dir,
        canonical_params().as_deref(),
    )
    .expect_err("swapped table anchors must be caught");
    assert!(err.contains("roster digest parity failure"), "unexpected: {err}");
    assert!(err.contains("table 0"), "failure must name the table: {err}");
    assert!(
        dir.join("proof.json").exists(),
        "gate rejection must be POST-proof (proof.json on disk before the anchor check)"
    );
}

/// **M9-2d（heavy 正控，T11/T12 的多桌对应物）**：m9_2 三负例的活跃性
/// 对照，同形桌对（P=2/P=3 各 K=1，与 m9_2c 同 seed）——
/// (1) 诚实两桌 wire 走 `prove_fold_batch_unchecked_tables`（**与 m9_2a/b
///     同一裸出证入口**：无 host 门、无锚对照）必须出证成功 ⇒ m9_2a/b 的
///     电路 panic 是攻击特异拒绝，不是「两桌 wire 一律失败」的假阳性；
/// (2) 同语料桌 0 手 z̄+1（非签名）⇒ 电路 panic ⇒ 多桌电路的残差方程检查
///     活跃——m9_2c 的出证后门拒不是掩盖死电路（正例 m9_1a–c 证可证性、
///     本控证拒因通道，两方向合围）。
#[test]
#[ignore]
fn m9_2d_multitable_zbar_plus_one_panics_attack_MT_control() {
    // m9_2c 同形桌对（P=2 + P=3，各 K=1）
    let (pks_a, hands_a, _) = honest_batch(2, 1, KAT_SEED + 407);
    let (pks_b, hands_b, _) = honest_batch(3, 1, KAT_SEED + 408);
    let t0 = vec![hands_a[0].hand.clone()];
    let t1 = vec![hands_b[0].hand.clone()];
    // (1) 诚实两桌 wire 过 m9_2a/b 同一裸入口：必须出证成功（liveness）。
    prove_fold_batch_unchecked_tables(
        Felt::ZERO,
        &[(&pks_a, &t0), (&pks_b, &t1)],
        &out_dir("m9-2d-mt-honest-through-unchecked"),
        canonical_params().as_deref(),
    )
    .expect("honest two-table wire through the UNCHECKED path must prove (liveness for m9_2a/b)");
    // (2) z̄+1（非签名）⇒ 电路 panic：多桌残差方程检查活跃（m9_2c 的控）。
    let mut tampered = t0.clone();
    tampered[0].zbar = tampered[0].zbar + Felt::ONE;
    let dir = out_dir("m9-2d-zbar-plus-one-mt");
    let err = prove_fold_batch_unchecked_tables(
        Felt::ZERO,
        &[(&pks_a, &tampered), (&pks_b, &t1)],
        &dir,
        None,
    )
    .expect_err("z̄+1 on a two-table wire must panic");
    assert!(err.contains("circuit rejected"), "unexpected: {err}");
    assert_circuit_assert_rejected(&err);
    assert!(!dir.join("proof.json").exists(), "panic must leave no proof");
}

/// **M9-3(a)**：尾桌 blocks 截断（尾手块被切 5 词）⇒ 电路 slice/at 越界
/// panic ⇒ 无证明（fail-closed，多桌规格 §2）。
#[test]
#[ignore]
fn m9_3a_truncated_tail_wire_rejected() {
    let tables = vec![
        honest_table(2, 1, KAT_SEED + 415),
        honest_table(3, 1, KAT_SEED + 416),
    ];
    let wire = tables_wire(&tables);
    let cut = &wire[..wire.len() - 5];
    let dir = out_dir("m9-3a-truncated-tail");
    let err = prove_wire_unchecked(Felt::ZERO, cut, &dir, None)
        .expect_err("truncated tail wire must be rejected");
    assert!(err.contains("circuit rejected") || err.contains("error"), "unexpected: {err}");
    assert!(!dir.join("proof.json").exists(), "rejection must leave no proof");
}

/// **M9-3(c)**：span_len 与实际词数不符（±1）⇒ runner/电路拒绝——
/// span 短 1 词 = 电路吃截断 wire（尾手块缺 z̄）⇒ 越界 panic；span 长
/// 1 词 = runner 构造 Span 时输入不足 ⇒ 出证前失败。
#[test]
#[ignore]
fn m9_3c_span_len_mismatch_rejected() {
    let tables = vec![
        honest_table(2, 1, KAT_SEED + 417),
        honest_table(3, 1, KAT_SEED + 418),
    ];
    let wire = tables_wire(&tables);
    let err_short = prove_wire_unchecked_with_span(
        Felt::ZERO,
        &wire,
        wire.len() - 1,
        &out_dir("m9-3c-span-short"),
        None,
    )
    .expect_err("span shorter than wire must be rejected");
    assert!(err_short.contains("circuit rejected") || err_short.contains("error"), "{err_short}");
    let err_long = prove_wire_unchecked_with_span(
        Felt::ZERO,
        &wire,
        wire.len() + 1,
        &out_dir("m9-3c-span-long"),
        None,
    )
    .expect_err("span longer than wire must be rejected");
    assert!(err_long.contains("circuit rejected") || err_long.contains("error"), "{err_long}");
}
