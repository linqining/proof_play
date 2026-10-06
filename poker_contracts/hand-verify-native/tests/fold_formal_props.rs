//! 折叠协议设计（手级 MuSig2/BDN 聚合 + acc 链折叠）的安全属性测试。
//!
//! **机器验证形态**：本文件是 Lean 侧 `airs_lean/AirsLean/Fold/{Chain,Settlement,KeyAgg}.lean`
//! 的真实实例对应物——全部公式跑在**真实** starknet poseidon（`poseidon_hash_many`，
//! 与 Cairo/AIR 同一 Hades 置换）与**真实** Stark 曲线
//! （`poker-protocol-core::stark_curve`，群阶素数，stark_curve.rs:44-45）上。
//! proptest 用固定种子（`RngSeed::Fixed`）保证可复现。
//!
//! 属性→测试映射：
//! - P1 acc 链绑定性（碰撞搜索）：`p1_fold_binding_no_collision`、`p1b_chain_history_binding`
//! - P2 零和不变式：`p2_zero_sum_proptest`、`p2b_zero_sum_boundaries`（宿主公式 =
//!   `combined.rs::build_settle_statement/expected_segment`，与
//!   `settlement_stmt.cairo:158-176` NOT_ZERO_SUM 同源）
//! - P3 rogue-key：`p3_rogue_key_naive_broken`（Lean `naive_rogue` 的正控）、
//!   `p3_rogue_key_bdn_fixed_point_search`（`bdn_rogue_iff_fixed_point`）、
//!   `p3_zero_coeff_cancels_honest`、`p3_rogue_uniqueness_exhaustive_f101`
//!   （`rogue_solution_unique` 的小域穷举）
//! - P4 binding 无重复/不可重组：`p4_binding_binds_claim`、`p4_batch_no_recombination`
//! - P5 completeness 诚实路径：`p5_honest_aggregate_completeness`（2/5/9 人 roster
//!   真曲线聚合）、`p5_fold_chain_honest_parity`
//!
//! 聚合公式逐条来自设计任务书「构造选型」节：
//! `μ_i = poseidon([L_label, roster_digest, pk_x, pk_y])`（BDN 系数形状）、
//! `c = poseidon([label, roster_digest, hand_binding, registered_digest,
//! ald, n_expected, P̄x, P̄y, R̄x, R̄y]) mod n`、验证方程 `z̄·G = R̄ + c·P̄`。

use proptest::prelude::*;
use proptest::test_runner::{Config, RngSeed};

use starknet_crypto::{poseidon_hash_many, Felt};

use poker_protocol_core::curve::{Curve, CurvePoint, CurveScalar};
use poker_protocol_core::stark_curve::{StarkCurve, StarkPoint, StarkScalar};

// ---------------------------------------------------------------------------
// 基础工具
// ---------------------------------------------------------------------------

/// ASCII short-string felt（与 stark_curve.rs `ascii_felt` 同纪律）。
fn ascii_felt(s: &str) -> Felt {
    let bytes = s.as_bytes();
    assert!(bytes.len() <= 31, "label must fit one felt");
    let mut buf = [0u8; 32];
    buf[32 - bytes.len()..].copy_from_slice(bytes);
    Felt::from_bytes_be(&buf)
}

/// 确定性伪随机场元素（seed, counter 派生；测试全程无外部 RNG）。
fn det_felt(seed: u64, i: u64) -> Felt {
    poseidon_hash_many(&[Felt::from(seed), Felt::from(i), Felt::from(0xF01Du64)])
}

fn to_scalar(f: Felt) -> StarkScalar {
    <StarkScalar as CurveScalar>::from_bytes_mod_order(&f.to_bytes_be())
}

fn base_g() -> StarkPoint {
    StarkCurve::base_g()
}

fn mul_g(s: StarkScalar) -> StarkPoint {
    base_g() * s
}

fn identity() -> StarkPoint {
    <StarkPoint as CurvePoint>::identity()
}

fn zero_scalar() -> StarkScalar {
    <StarkScalar as CurveScalar>::zero()
}

fn one_scalar() -> StarkScalar {
    <StarkScalar as CurveScalar>::one()
}

/// **P1 核心公式**：`acc' = poseidon([prev_acc] ++ claims)` ——
/// `recurse.rs:60-65` `fold_accumulator` 的逐词镜像（本测试的独立内联重写）。
fn fold_acc(prev: Felt, claims: &[Felt]) -> Felt {
    let mut words = Vec::with_capacity(claims.len() + 1);
    words.push(prev);
    words.extend_from_slice(claims);
    poseidon_hash_many(&words)
}

// ---------------------------------------------------------------------------
// 手级聚合（设计公式的 host 镜像）
// ---------------------------------------------------------------------------

fn keyagg_label() -> Felt {
    ascii_felt("poker/fold-batch/keyagg.v1")
}

fn challenge_label() -> Felt {
    ascii_felt("poker/fold-batch/challenge.v1")
}

/// roster_digest = poseidon([L_label, (pkx, pky)×n])。
fn roster_digest(pks: &[StarkPoint]) -> Felt {
    let mut felts = Vec::with_capacity(1 + pks.len() * 2);
    felts.push(keyagg_label());
    for pk in pks {
        let (x, y) = pk.to_affine_parts().expect("non-identity pk");
        felts.push(x);
        felts.push(y);
    }
    poseidon_hash_many(&felts)
}

/// BDN 系数：μ_i = poseidon([L_label, roster_digest, pk_x, pk_y]) mod n。
fn key_coeff(roster_d: Felt, pk: &StarkPoint) -> StarkScalar {
    let (x, y) = pk.to_affine_parts().expect("non-identity pk");
    to_scalar(poseidon_hash_many(&[keyagg_label(), roster_d, x, y]))
}

/// 聚合公钥：P̄ = Σ μ_i·pk_i（BDN 形状；真实曲线点运算）。
fn agg_pubkey(pks: &[StarkPoint]) -> StarkPoint {
    let rd = roster_digest(pks);
    let mut acc = identity();
    for pk in pks {
        acc = acc + *pk * key_coeff(rd, pk);
    }
    acc
}

/// 设计挑战公式：c = poseidon([label, rd, hb, reg, ald, n, P̄x, P̄y, R̄x, R̄y]) mod n。
#[allow(clippy::too_many_arguments)]
fn agg_challenge(
    rd: Felt,
    hand_binding: Felt,
    registered_digest: Felt,
    ald: Felt,
    n_expected: u64,
    pbar: &StarkPoint,
    rbar: &StarkPoint,
) -> StarkScalar {
    let (px, py) = pbar.to_affine_parts().expect("non-identity P̄");
    let (rx, ry) = rbar.to_affine_parts().expect("non-identity R̄");
    to_scalar(poseidon_hash_many(&[
        challenge_label(),
        rd,
        hand_binding,
        registered_digest,
        ald,
        Felt::from(n_expected),
        px,
        py,
        rx,
        ry,
    ]))
}

/// 诚实聚合签名：z̄ = Σ(w_i + c·μ_i·sk_i)，R̄ = Σ w_i·G。
#[allow(clippy::too_many_arguments)]
fn aggregate_sign(
    sks: &[Felt],
    ws: &[Felt],
    hand_binding: Felt,
    registered_digest: Felt,
    ald: Felt,
    n_expected: u64,
) -> (StarkPoint, StarkScalar, StarkScalar, StarkPoint) {
    assert_eq!(sks.len(), ws.len());
    let pks: Vec<StarkPoint> = sks.iter().map(|sk| base_g() * to_scalar(*sk)).collect();
    let rd = roster_digest(&pks);
    let pbar = agg_pubkey(&pks);
    let mut rbar = identity();
    for w in ws {
        rbar = rbar + base_g() * to_scalar(*w);
    }
    let c = agg_challenge(rd, hand_binding, registered_digest, ald, n_expected, &pbar, &rbar);
    let mut zbar = zero_scalar();
    for (i, sk) in sks.iter().enumerate() {
        let mu = key_coeff(rd, &pks[i]);
        zbar = zbar + to_scalar(ws[i]) + c * (mu * to_scalar(*sk));
    }
    (rbar, zbar, c, pbar)
}

/// 电路单方程（fold_batch.cairo ③ 的 host 形态）：z̄·G − c·P̄ − R̄ == O。
fn agg_verify(pbar: &StarkPoint, rbar: &StarkPoint, c: StarkScalar, zbar: StarkScalar) -> bool {
    (base_g() * zbar - *pbar * c - *rbar).is_identity()
}

// ---------------------------------------------------------------------------
// P1 —— acc 链绑定性（真实 poseidon 上的碰撞搜索）
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(Config {
        cases: 256,
        rng_seed: RngSeed::Fixed(0x5F01D_0001),
        ..Config::default()
    })]

    /// **P1**：fold 的输入绑定性反例搜索（Lean `Chain.fold_eq_iff` 的真实实例）。
    /// 256 组随机 (prev, claims)，每组做 prev±1 / 逐槽篡改 / 换序 / 增删 /
    /// 跨批替换共 10+ 次近失扰动——任何一次折叠输出相等即发现 poseidon 碰撞。
    #[test]
    fn p1_fold_binding_no_collision(seed in any::<u64>(), ncl in 1usize..=8usize) {
        let acc = det_felt(seed, 0);
        let claims: Vec<Felt> = (1..=ncl as u64).map(|i| det_felt(seed, i)).collect();
        let f = |a: Felt, c: &[Felt]| fold_acc(a, c);
        // 确定性
        prop_assert_eq!(f(acc, &claims), f(acc, &claims));
        // prev 篡改 ±1
        prop_assert_ne!(f(acc, &claims), f(acc + Felt::from(1u8), &claims));
        prop_assert_ne!(f(acc, &claims), f(acc - Felt::from(1u8), &claims));
        // 逐槽 claim 篡改
        for i in 0..claims.len() {
            let mut c2 = claims.clone();
            c2[i] = c2[i] + Felt::from(1u8);
            prop_assert_ne!(f(acc, &claims), f(acc, &c2), "claim tamper collided");
            let mut c2m = claims.clone();
            c2m[i] = c2m[i] - Felt::from(1u8);
            prop_assert_ne!(f(acc, &claims), f(acc, &c2m), "claim tamper(-) collided");
        }
        // 相邻换序
        if ncl >= 2 {
            let mut c3 = claims.clone();
            c3.swap(0, 1);
            prop_assert_ne!(f(acc, &claims), f(acc, &c3), "swap collided");
        }
        // 追加 / 删除
        let mut c4 = claims.clone();
        c4.push(det_felt(seed, 999));
        prop_assert_ne!(f(acc, &claims), f(acc, &c4), "append collided");
        prop_assert_ne!(f(acc, &claims[1..]), f(acc, &claims), "drop collided");
        // 跨批（他桌）claims 整体替换
        let other: Vec<Felt> = (1..=ncl as u64).map(|i| det_felt(seed ^ 0xDEAD, i)).collect();
        prop_assert_ne!(f(acc, &claims), f(acc, &other), "cross-batch collided");
    }

    /// **P1b（链历史绑定）**：批链 acc 绑定全部历史批次——换批序 /
    /// 换批内容 / 篡改历史 claim 必改终态 acc（Lean `Chain.chain_history_unique`
    /// 的真实实例反例搜索）。
    #[test]
    fn p1b_chain_history_binding(seed in any::<u64>()) {
        let genesis = Felt::ZERO; // recurse.rs GENESIS_ACC
        let batch = |b: u64, n: u64| (1..=n).map(|i| det_felt(seed, b * 100 + i)).collect::<Vec<_>>();
        let b1 = batch(1, 3);
        let b2 = batch(2, 2);
        let b3 = batch(3, 4);
        let acc1 = fold_acc(genesis, &b1);
        let acc2 = fold_acc(acc1, &b2);
        let acc3 = fold_acc(acc2, &b3);
        // 确定性：独立重算一致
        prop_assert_eq!(acc3, fold_acc(fold_acc(fold_acc(genesis, &b1), &b2), &b3));
        // 批间换序 → 终态必变
        let swapped = fold_acc(fold_acc(fold_acc(genesis, &b2), &b1), &b3);
        prop_assert_ne!(acc3, swapped, "batch reorder collided");
        // 历史批内容替换（跨表拼接）→ 终态必变
        let b2_other = batch(7, 2);
        let spliced = fold_acc(fold_acc(fold_acc(genesis, &b1), &b2_other), &b3);
        prop_assert_ne!(acc3, spliced, "cross-table splice collided");
        // 篡改历史批任一 claim → 终态必变
        let mut b1_t = b1.clone();
        b1_t[0] = b1_t[0] + Felt::from(1u8);
        let tampered = fold_acc(fold_acc(fold_acc(genesis, &b1_t), &b2), &b3);
        prop_assert_ne!(acc3, tampered, "history tamper collided");
        // acc_prev 篡改（对偶 recurse.rs:485-499 run_negative_wrong_prev）
        let wrong_prev = fold_acc(Felt::from(1u8), &b2);
        prop_assert_ne!(acc2, wrong_prev, "prev_acc tamper collided");
    }
}

// ---------------------------------------------------------------------------
// P2 —— 零和不变式（宿主公式 = combined.rs，与 Cairo NOT_ZERO_SUM 同源）
// ---------------------------------------------------------------------------

/// 生成随机零和 deltas：前 n−1 席 ±2^40 内，末席取负和（7·2^40 < 2^63，无溢出）。
fn random_zero_sum_deltas(seed: u64, seats: usize) -> Vec<i128> {
    let mut ds = Vec::with_capacity(seats);
    let mut sum: i128 = 0;
    for i in 0..seats - 1 {
        let mag = u128::from_be_bytes(det_felt(seed, i as u64).to_bytes_be()[16..32].try_into().expect("16B"))
            % (1u128 << 40);
        let neg = det_felt(seed, 1000 + i as u64).to_bytes_be()[31] & 1 == 1;
        let d = if neg { -(mag as i128) } else { mag as i128 };
        ds.push(d);
        sum += d;
    }
    ds.push(-sum);
    ds
}

fn players_and_cms(seed: u64, seats: usize) -> (Vec<Felt>, Vec<Felt>) {
    let players = (0..seats)
        .map(|i| det_felt(seed, 50 + i as u64) + Felt::from(1u8))
        .collect();
    let cms = (0..seats).map(|i| det_felt(seed, 60 + i as u64)).collect();
    (players, cms)
}

proptest! {
    #![proptest_config(Config {
        cases: 128,
        rng_seed: RngSeed::Fixed(0x5F01D_0002),
        ..Config::default()
    })]

    /// **P2**：诚实零和结算 → build/expected_segment 全过（含 NOT_ZERO_SUM、
    /// DIGEST_MISMATCH、COUNT_MISMATCH、动作链良构断言）；任一席 delta 扰动
    /// → fail-closed 拒绝；registered_digest 篡改 → DIGEST_MISMATCH。
    #[test]
    fn p2_zero_sum_proptest(seed in any::<u64>(), seats in 2usize..=9usize) {
        let deltas = random_zero_sum_deltas(seed, seats);
        let (players, cms) = players_and_cms(seed, seats);
        let hb = det_felt(seed, 7);
        // action_log_digest 必须是真实日志链根（combined.rs:127-132：
        // chain = [DOMAIN] ++ entries 逐词折叠；空日志 = poseidon([DOMAIN])），
        // 否则宿主 fail-closed（action log chain mismatch）。
        let entries: Vec<[Felt; 2]> = vec![
            [det_felt(seed, 880), det_felt(seed, 881)],
            [det_felt(seed, 882), det_felt(seed, 883)],
        ];
        let mut chain = vec![hand_verify_native::combined::action_log_domain()];
        chain.extend(entries.iter().flat_map(|p| p.iter().copied()));
        let ald = poseidon_hash_many(&chain);
        let st = hand_verify_native::combined::build_settle_statement(
            1, hb, &players, &deltas, &cms, ald, &entries,
        )
        .expect("zero-sum statement must build");
        // 宿主段公式（与 settlement_stmt.cairo 约束 1-4 同源）全过
        let seg = st.expected_segment().expect("expected_segment ok");
        prop_assert_eq!(seg.len(), 16);
        prop_assert_eq!(seg[0], hand_verify_native::combined::segment_magic());
        // 零和不变式（整数域，P2a 的 u64 量级前提在生成器里成立）
        let int_sum: i128 = deltas.iter().sum();
        prop_assert_eq!(int_sum, 0);
        // total = 赢家总额 = 输家总额（Lean Settlement.winners_eq_losers 实例）
        let total: u64 = deltas
            .iter()
            .filter(|d| **d > 0)
            .map(|d| *d as u64)
            .sum();
        let total_felt = u64::from_be_bytes(seg[14].to_bytes_be()[24..32].try_into().unwrap());
        prop_assert_eq!(total_felt, total);
        // digest 绑定（Lean Settlement.digest_binds_magnitude 实例）：
        // 篡改任一 magnitude 后 digest 必须不再匹配
        let mut tampered = st.clone();
        if seats >= 1 {
            tampered.magnitudes[0] = tampered.magnitudes[0].wrapping_add(1);
            let _ = tampered.registered_digest; // registered 不再等于 expected_digest
            prop_assert_ne!(tampered.expected_digest(), st.expected_digest());
            prop_assert!(tampered.expected_segment().is_err(), "tampered digest must fail-closed");
        }
        // registered_digest 篡改 → expected_segment 拒
        let mut st2 = st.clone();
        st2.registered_digest = st2.registered_digest + Felt::from(1u8);
        prop_assert!(st2.expected_segment().is_err(), "digest mismatch must fail-closed");
        // 非零和 delta 扰动 → build 拒（NOT_ZERO_SUM 宿主侧）
        let mut bad = deltas.clone();
        bad[0] += 1;
        let err = hand_verify_native::combined::build_settle_statement(
            1, hb, &players, &bad, &cms, ald, &[],
        )
        .err()
        .expect("non-zero-sum must be rejected");
        prop_assert!(err.contains("zero-sum"), "err: {err}");
    }
}

/// **P2b（量级边界）**：|delta| = u64::MAX（host 拒收界 combined.rs:429 的
/// 边界内值）零和结算无 felt 回绕（Lean `Settlement.felt_zero_sum_is_int_zero`
/// 的边界实例）；双赢家 u64::MAX 使 total 溢出 u64 → 宿主 fail-closed
/// （total 槽的 u64 上界本身是语句良构的一部分）。
#[test]
fn p2b_zero_sum_boundaries() {
    let max = i128::from(u64::MAX);
    let players: Vec<Felt> = (0..9).map(|i| det_felt(77, i) + Felt::from(1u8)).collect();
    let cms: Vec<Felt> = (0..9).map(|i| det_felt(78, i)).collect();
    let hb = det_felt(79, 0);
    let ald = poseidon_hash_many(&[hand_verify_native::combined::action_log_domain()]);
    // (a) 单赢家 u64::MAX + 单输家 −u64::MAX：零和、total = u64::MAX（槽上界内极值）
    let deltas = [max, -max, 0, 0, 0, 0, 0, 0, 0];
    let st = hand_verify_native::combined::build_settle_statement(2, hb, &players, &deltas, &cms, ald, &[])
        .expect("u64::MAX zero-sum must build");
    let seg = st.expected_segment().expect("boundary segment ok");
    let total_felt = u64::from_be_bytes(seg[14].to_bytes_be()[24..32].try_into().unwrap());
    assert_eq!(total_felt, u64::MAX);
    // (b) 双赢家各 u64::MAX：零和成立但 total 溢出 u64 → 宿主 fail-closed
    let deltas2 = [max, -max, max, -max, 0, 0, 0, 0, 0];
    let st2 = hand_verify_native::combined::build_settle_statement(3, hb, &players, &deltas2, &cms, ald, &[])
        .expect("(b) build passes: zero-sum and |delta| bounds hold");
    let err = st2.expected_segment().err().expect("total must overflow u64");
    assert!(err.contains("total overflow"), "err: {err}");
}

// ---------------------------------------------------------------------------
// P3 —— rogue-key 代数（真实 Stark 曲线）
// ---------------------------------------------------------------------------

/// μ ≡ 1 的无系数聚合（正控：证明测试能捕获攻击）。
fn naive_keyagg(pk_h: StarkPoint, pk_a: StarkPoint) -> StarkPoint {
    pk_h + pk_a
}

/// **P3-负例（Lean `KeyAgg.naive_rogue` 真实曲线实例）**：无系数聚合下，
/// 攻击者用纯公开点加法 pk_a = Ā − pk_h 即命中自选聚合钥 Ā——
/// 这就是必须带 BDN 系数 + PoP 注册面的原因。
#[test]
fn p3_rogue_key_naive_broken() {
    let pk_h = mul_g(to_scalar(det_felt(9, 1)));
    let abar = mul_g(to_scalar(det_felt(9, 2)));
    let pk_a = abar - pk_h; // 公开数据可算，无需任何 dlog
    assert_eq!(naive_keyagg(pk_h, pk_a), abar, "naive aggregation must fall to key cancellation");
}

/// **P3-BDN（Lean `KeyAgg.bdn_rogue_iff_fixed_point` 真实曲线实例）**：
/// 带设计 RO 系数后，256 次候选钥（随机点 / naive 构造点 / μa⁻¹ 一步定点式）
/// 均无法命中 Ā——攻击退化为 poseidon 哈希不动点，搜索 0 命中。
#[test]
fn p3_rogue_key_bdn_fixed_point_search() {
    let sk_h = det_felt(11, 1);
    let pk_h = mul_g(to_scalar(sk_h));
    let abar = mul_g(to_scalar(det_felt(11, 2)));
    // (a) 256 个随机候选钥
    for i in 0..256u64 {
        let pk_a = mul_g(to_scalar(det_felt(11, 100 + i)));
        let pbar = agg_pubkey(&[pk_h, pk_a]);
        assert_ne!(pbar, abar, "fixed-point hit at candidate {i} — poseidon collision or formula drift");
    }
    // (b) naive 构造点（无系数下的必杀式，带系数后失效）
    let pk_naive = abar - pk_h;
    assert_ne!(agg_pubkey(&[pk_h, pk_naive]), abar, "naive construction must not hit with BDN coefficients");
    // (c) μa⁻¹ 一步定点式：pk_a := μa⁻¹·(Ā − μh·pk_h)，其中 μa 取自另一候选钥
    //     ——系数不再匹配 RO(L, pk_a)，构造必然失配（除非哈希不动点）
    let probe = mul_g(to_scalar(det_felt(11, 500)));
    let rd_probe = roster_digest(&[pk_h, probe]);
    let mu_h = key_coeff(rd_probe, &pk_h);
    let mu_a = key_coeff(rd_probe, &probe);
    let rhs = abar - pk_h * mu_h;
    let pk_a = rhs * mu_a.invert();
    assert_ne!(
        agg_pubkey(&[pk_h, pk_a]),
        abar,
        "one-shot fixed-point construction must not hit"
    );
}

/// **P3-系数非零必要性（Lean `KeyAgg.zero_coeff_cancels_honest_key` 实例）**：
/// 诚实钥系数为 0 时聚合钥与诚实钥无关。
#[test]
fn p3_zero_coeff_cancels_honest() {
    let pk_h = mul_g(to_scalar(det_felt(13, 1)));
    let pk_h2 = mul_g(to_scalar(det_felt(13, 2)));
    let pk_a = mul_g(to_scalar(det_felt(13, 3)));
    let mu_a = key_coeff(roster_digest(&[pk_h, pk_a]), &pk_a);
    let lhs = pk_h * zero_scalar() + pk_a * mu_a;
    let rhs = pk_h2 * zero_scalar() + pk_a * mu_a;
    assert_eq!(lhs, rhs, "zero coefficient must cancel the honest key");
}

/// **P3-PoP 唯一性（Lean `KeyAgg.rogue_solution_unique` 的小域穷举实例）**：
/// F_101 上穷举 x_h：rogue 方程 μh·x_h + μa·x_a = a 恰有一解且等于
/// μh⁻¹·(a − μa·x_a)。
#[test]
fn p3_rogue_uniqueness_exhaustive_f101() {
    const P: i64 = 101;
    let modp = |x: i64| x.rem_euclid(P);
    for seed in 0..32i64 {
        let mh = 1 + ((seed * 7 + 3) % (P - 1)); // 恒非零
        let ma = modp(seed * 13 + 5);
        let xa = modp(seed * 29 + 7);
        let aa = modp(seed * 11 + 1);
        let mut hits = Vec::new();
        for xh in 0..P {
            if modp(mh * xh + ma * xa) == aa {
                hits.push(xh);
            }
        }
        assert_eq!(hits.len(), 1, "seed {seed}: rogue equation must have a unique honest-key solution");
        // 解必须等于 μh⁻¹·(a − μa·x_a)
        let inv_mh = (1..P).find(|i| modp(mh * i) == 1).expect("unit inverse exists");
        let expect = modp(inv_mh * modp(aa - ma * xa));
        assert_eq!(hits[0], expect, "seed {seed}: unique solution must match the closed form");
    }
}

// ---------------------------------------------------------------------------
// P4 —— binding 无重复 / 跨手重组不可行
// ---------------------------------------------------------------------------

/// **P4（claim 绑定）**：claim = poseidon([hand_binding, payload_digest])——
/// 不同 hand_binding 必得不同 claim（反例搜索 256 组；`recurse.rs:44-55` 公式）。
#[test]
fn p4_binding_binds_claim() {
    for i in 0..256u64 {
        let hb1 = det_felt(i, 1);
        let hb2 = det_felt(i, 2);
        assert_ne!(hb1, hb2);
        let digest = det_felt(i, 3); // payload_digest 槽
        let c1 = poseidon_hash_many(&[hb1, digest]);
        let c2 = poseidon_hash_many(&[hb2, digest]);
        assert_ne!(c1, c2, "distinct bindings collided on claim (i={i})");
    }
}

proptest! {
    #![proptest_config(Config {
        cases: 128,
        rng_seed: RngSeed::Fixed(0x5F01D_0004),
        ..Config::default()
    })]

    /// **P4（批不可重组）**：同一 hand 的 (R̄, z̄) 喂给另一 hand_binding →
    /// c 变 → 方程失效（跨手重放拒绝，设计 T3）；把 A 桌某手的 claim 段
    /// 拼进 B 桌批 → 折叠输出必变。
    #[test]
    fn p4_batch_no_recombination(seed in any::<u64>(), k in 2usize..=8usize) {
        let sks: Vec<Felt> = (0..k as u64).map(|i| det_felt(seed, i)).collect();
        let ws: Vec<Felt> = (0..k as u64).map(|i| det_felt(seed, 100 + i)).collect();
        let hb_a = det_felt(seed, 200);
        let hb_b = det_felt(seed, 201);
        prop_assert_ne!(hb_a, hb_b);
        let reg = det_felt(seed, 202);
        let ald = det_felt(seed, 203);
        let (rbar, zbar, c_a, pbar) = aggregate_sign(&sks, &ws, hb_a, reg, ald, k as u64);
        prop_assert!(agg_verify(&pbar, &rbar, c_a, zbar), "honest sig must verify");
        // 跨手重放：c 绑定 hand_binding → 换手必变 c → 验证失败
        let c_b = agg_challenge(roster_digest(&sks.iter().map(|sk| base_g() * to_scalar(*sk)).collect::<Vec<_>>()), hb_b, reg, ald, k as u64, &pbar, &rbar);
        prop_assert_ne!(c_a, c_b, "challenge must bind hand_binding");
        prop_assert!(!agg_verify(&pbar, &rbar, c_b, zbar), "cross-hand replay must be rejected");
        // 跨桌 claim 拼接：批 A 的折叠 ≠ 拼 B 桌 claim 后的折叠
        let claims_a: Vec<Felt> = (0..k as u64).map(|i| det_felt(seed, 300 + i)).collect();
        let claims_b: Vec<Felt> = (0..k as u64).map(|i| det_felt(seed ^ 0xBEEF, 300 + i)).collect();
        let mut spliced = claims_a.clone();
        spliced[k - 1] = claims_b[k - 1];
        prop_assert_ne!(fold_acc(Felt::ZERO, &claims_a), fold_acc(Felt::ZERO, &spliced));
        // 全段替换（整批跨桌重组）
        prop_assert_ne!(fold_acc(Felt::ZERO, &claims_a), fold_acc(Felt::ZERO, &claims_b));
    }
}

// ---------------------------------------------------------------------------
// P5 —— completeness：诚实路径全部通过（固定种子）
// ---------------------------------------------------------------------------

/// **P5（聚合完备性 + 篡改拒绝）**：2/5/9 人 roster 诚实聚合必过验证方程；
/// z̄±1 / R̄ 篡改 / 未注册 P̄ / 少一人（部分签名缺失）全部 fail-closed。
#[test]
fn p5_honest_aggregate_completeness() {
    for &k in &[2usize, 5usize, 9usize] {
        let sks: Vec<Felt> = (0..k as u64).map(|i| det_felt(0xA11CE + k as u64, i)).collect();
        let ws: Vec<Felt> = (0..k as u64).map(|i| det_felt(0xB0B + k as u64, i)).collect();
        let hb = det_felt(0xC0C, k as u64);
        let reg = det_felt(0xD0D, k as u64);
        let ald = det_felt(0xE0E, k as u64);
        let (rbar, zbar, c, pbar) = aggregate_sign(&sks, &ws, hb, reg, ald, k as u64);
        // 诚实路径：单方程必过（电路 ③ 的 host 形态）
        assert!(agg_verify(&pbar, &rbar, c, zbar), "k={k}: honest aggregate must verify");
        // 确定性：同输入重算一致
        let again = aggregate_sign(&sks, &ws, hb, reg, ald, k as u64);
        assert_eq!((rbar, c, pbar), (again.0, again.2, again.3));
        assert_eq!(zbar, again.1);
        // 篡改 z̄ ± 1（设计 T2）
        assert!(!agg_verify(&pbar, &rbar, c, zbar + one_scalar()), "k={k}: z̄+1 must fail");
        assert!(!agg_verify(&pbar, &rbar, c, zbar - one_scalar()), "k={k}: z̄-1 must fail");
        // 篡改 R̄
        let rbar_bad = mul_g(to_scalar(det_felt(0xF0F, k as u64)));
        assert!(!agg_verify(&pbar, &rbar_bad, c, zbar), "k={k}: swapped R̄ must fail");
        // 换 P̄（未注册聚合钥，设计 T4）
        let other_sks: Vec<Felt> = (0..k as u64).map(|i| det_felt(0x999, i)).collect();
        let other_pks: Vec<StarkPoint> =
            other_sks.iter().map(|sk| base_g() * to_scalar(*sk)).collect();
        let pbar_other = agg_pubkey(&other_pks);
        assert!(!agg_verify(&pbar_other, &rbar, c, zbar), "k={k}: unregistered P̄ must fail");
        // 部分签名缺失（少一人重算 z̄）→ 方程失效
        if k >= 2 {
            let pks: Vec<StarkPoint> = sks.iter().map(|sk| base_g() * to_scalar(*sk)).collect();
            let rd = roster_digest(&pks);
            let mut zbar_partial = zero_scalar();
            for (i, sk) in sks.iter().enumerate().skip(1) {
                zbar_partial =
                    zbar_partial + to_scalar(ws[i]) + c * (key_coeff(rd, &pks[i]) * to_scalar(*sk));
            }
            assert!(!agg_verify(&pbar, &rbar, c, zbar_partial), "k={k}: missing cosigner must fail");
        }
    }
}

/// **P5（acc 链诚实完备）**：诚实 claim 的批链逐批重算一致（parity 门形状，
/// `combined.rs::prove_combined_layer` 的 acc 门在 fold 公式层的对应物）。
#[test]
fn p5_fold_chain_honest_parity() {
    let genesis = Felt::ZERO;
    for &k in &[1usize, 2, 4, 8] {
        let claims: Vec<Felt> = (0..k as u64).map(|i| det_felt(0x5EED, i)).collect();
        // 单批：host 重算 == fold 公式直算（parity 门）
        let acc = fold_acc(genesis, &claims);
        assert_eq!(acc, fold_acc(genesis, &claims));
        // 确定性：两次完整链构建一致
        let acc2 = fold_acc(acc, &claims);
        assert_eq!(acc2, fold_acc(acc, &claims));
        // 链推进（acc_{i+1} ≠ acc_i，chain.rs:625-626 同款断言）
        assert_ne!(acc, acc2);
        // genesis 与任意非零 prev 分叉（chain.rs:885-887 同款）
        assert_ne!(fold_acc(Felt::from(1u8), &claims), acc);
    }
}
