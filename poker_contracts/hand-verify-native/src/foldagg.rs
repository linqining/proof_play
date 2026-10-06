//! foldagg — `cairo/src/fold_batch.cairo` 的 host 侧：BDN 手级聚合铸造/验证
//! 镜像 + 批 wire 构造 + prove-hand 出证驱动（FoldDesign v2 **生产版·多桌**）。
//!
//! 与 `combined.rs`（每手合并信封）的分工：fold 批把 **T 张桌（T ≥ 1）的
//! 桌段串接**折成一份证明——roster/keyagg 每桌一次、每手 = settle 语句
//! 约束 + 3 次 poseidon + 单方程 EC 检查 + z̄ 范围检查（对手所属桌的
//! P̄_t 验证），公开输出 (ΣK) 段 18 词
//! `[acc] ++ settlement 公开段(16) ++ [本桌 roster_digest]`（fold-spec D1
//! + 多桌规格 D1a 修订：slot17 桌内常量）。**T=1 退化与单桌生产版逐词
//! 一致**（wire 桌段自定界串接、无全局 T 词——多桌规格 §2/§8，金样
//! `tests/golden/fold_t1_p2k2.json` 回归钉死）。
//!
//! 公式与电路逐 felt parity（T8 KAT 钉死）：
//! - roster_digest = poseidon([roster_label, n] ++ (pkx, pky)×n)
//! - μ_i = poseidon([keyagg_label, n, pkx, pky])（BDN/CCS'06 系数，raw felt
//!   交 `Point::mul`——与 Cairo `add_mul` 同纪律，群阶自动归约 mod n）
//! - P̄ = Σ μ_i·pk_i
//! - M_h = poseidon([m_label, hand_binding, m1, m2, cm_digest, roster_digest])
//!   **真槽（D2，与电路逐位同源）**：m1 = settle wire[1]（registered_digest）、
//!   m2 = wire[2]（n_expected）、cm_digest = poseidon(wire[31..=39])（9 词
//!   c0..c8 压缩）；ald（wire[40]）经语句内 digest 断言传递钉死（D2a），
//!   不是 M_h 独立槽
//! - c = poseidon([sig_label, hand_binding, M_h, P̄x, P̄y, R̄x, R̄y])（raw）
//! - z̄ = Σ(w_i + c·μ_i·sk_i) mod n（铸侧）；验证方程 z̄·G − c·P̄ − R̄ == O
//! - claim_i = poseidon([claim_label, hand_binding, M_h])；
//!   acc = poseidon([prev_acc] ++ claims)（批终 acc，每段 slot 0 同值——Q-1）
//!
//! BDN 三轮（nonce 承诺，抗 Drijvers 式并发会话的最低配置，risk-4）：
//! round1 各签名者对 nonce 承诺 t_i = poseidon([nonce_label, R_i 坐标])；
//! round2 全承诺到齐后揭 R_i，R̄ = Σ R_i；round3 用 c 出部分签名 z_i。
//! 承诺不进最终方程（协议面），公式面与单轮镜像一致。
//!
//! 纪律：坐标域 F_P / 标量域 Z_n 分离（与 curve.rs 同）；host 直验
//! fail-closed；parity 门在出证**之后**（roster_registry 对照面的切片模拟，
//! 见 prove_fold_batch 的门序注释）。

use std::path::{Path, PathBuf};
use std::time::Instant;

use starknet_crypto::{poseidon_hash_many, Felt};

use poker_protocol_core::curve::CurveScalar;
use poker_protocol_core::stark_curve::StarkScalar;

use crate::curve::Point;
use crate::handbatch::ascii_felt_pub;

// ---------------------------------------------------------------------------
// 域标签（与 fold_batch.cairo 常量逐字节一致）
// ---------------------------------------------------------------------------

pub fn keyagg_label() -> Felt {
    ascii_felt_pub("poker/fold-batch/keyagg.v1")
}

pub fn roster_label() -> Felt {
    ascii_felt_pub("poker/fold-batch/roster.v1")
}

pub fn m_label() -> Felt {
    ascii_felt_pub("poker/fold-batch/msg.v1")
}

pub fn sig_label() -> Felt {
    ascii_felt_pub("poker/fold-batch/sig.v1")
}

pub fn claim_label() -> Felt {
    ascii_felt_pub("poker/fold-batch/claim.v1")
}

pub fn nonce_label() -> Felt {
    ascii_felt_pub("poker/fold-batch/nonce.v1")
}

/// 群阶 n 的 felt 形（z̄ 范围检查的 host 侧）。
pub fn ec_order_felt() -> Felt {
    Felt::from_bytes_be(&poker_protocol_core::stark_curve::ec_order_bytes_be())
}

fn to_scalar(f: Felt) -> StarkScalar {
    <StarkScalar as CurveScalar>::from_bytes_mod_order(&f.to_bytes_be())
}

fn scalar_to_felt(s: StarkScalar) -> Felt {
    Felt::from_bytes_be(&s.to_bytes_be())
}

// ---------------------------------------------------------------------------
// settle wire 形状常量（与 cairo/src/settlement_stmt.cairo / fold_batch.cairo
// 逐位同步——fold-spec D1/D2）
// ---------------------------------------------------------------------------

/// settle wire 词数（settlement_stmt.cairo SETTLE_WORDS 同值）。
pub const SETTLE_WORDS: usize = 102;
/// cm 槽起点：c0..c8 = settle wire[31..=39]（settlement_stmt.cairo 布局）。
pub const SETTLE_CM_START: usize = 31;
/// cm 槽词数（9 词压缩进 cm_digest）。
pub const SETTLE_CM_WORDS: usize = 9;
/// 每手签名见证词数（R̄x, R̄y, z̄）。
pub const SIG_WORDS: usize = 3;
/// 每手 wire 块词数 = settle 102 + 签名见证 3（电路 HAND_WORDS 同值）。
pub const HAND_BLOCK_WORDS: usize = SETTLE_WORDS + SIG_WORDS;
/// 每手公开段词数 = [acc] ++ 语句公开段 16 ++ [roster_digest]（D1）。
pub const FOLD_SEGMENT_LEN: usize = 18;
/// roster_digest 在每手段内的槽位（消费面唯一新增语义收口，D1）。
pub const FOLD_ROSTER_INDEX: usize = 17;
/// 多桌批桌数上限 T_MAX（多桌规格 M1-c，host 层政策检查——评审面边界
/// 而非 steps 硬门：steps 最坏情形 T=8 全 9 人 ΣK=64 按线性模型
/// 8×(404+9×153)+6,183×64 ≈ 409,960 ≈ 2^20 的 39%；链层另有 slot17 run
/// 计数检查同值）。链层政策 `check_hand_count`（ΣK ≤ 64 且 2 的幂）
/// 零改动，host 铸侧不复检 ΣK。
pub const FOLD_T_MAX: usize = 8;

// ---------------------------------------------------------------------------
// 公式层（与 fold_batch.cairo 逐 felt parity）
// ---------------------------------------------------------------------------

/// roster_digest = poseidon([roster_label, n] ++ pks)。
pub fn roster_digest(pks: &[(Felt, Felt)]) -> Felt {
    let mut words = Vec::with_capacity(2 + 2 * pks.len());
    words.push(roster_label());
    words.push(Felt::from(pks.len() as u64));
    for (x, y) in pks {
        words.push(*x);
        words.push(*y);
    }
    poseidon_hash_many(&words)
}

/// μ 的 raw felt（poseidon 出口，不显式 mod n——与电路同出口）。
pub fn key_coeff_raw(n_players: usize, pkx: Felt, pky: Felt) -> Felt {
    poseidon_hash_many(&[keyagg_label(), Felt::from(n_players as u64), pkx, pky])
}

/// 聚合公钥 P̄ = Σ μ_i·pk_i（真实曲线；坐标/恒等由调用侧 fail-closed）。
pub fn agg_pubkey(pks: &[(Felt, Felt)]) -> Result<(Felt, Felt), String> {
    let mut acc = Point::identity();
    for (x, y) in pks {
        let pk = Point::from_affine(*x, *y).ok_or("agg_pubkey: pk off-curve")?;
        if pk.is_identity() {
            return Err("agg_pubkey: identity pk".into());
        }
        acc = acc + pk.mul(key_coeff_raw(pks.len(), *x, *y));
    }
    acc.to_affine().ok_or_else(|| "agg_pubkey: P̄ is identity (RO fixed point?)".to_string())
}

/// cm_digest = poseidon(settle wire[31..=39])（c0..c8 9 词压缩，D2/Q-2——
/// 切片的 2 词占位 poseidon([cm0,cm1]) 不迁移）。
pub fn cm_digest_from_wire(settle: &[Felt]) -> Felt {
    assert_eq!(settle.len(), SETTLE_WORDS, "settle wire must be 102 words");
    poseidon_hash_many(&settle[SETTLE_CM_START..SETTLE_CM_START + SETTLE_CM_WORDS])
}

/// M_h = poseidon([m_label, hand_binding, m1, m2, cm_digest, roster_digest])。
#[allow(clippy::too_many_arguments)]
pub fn msg_digest(
    hand_binding: Felt,
    m1: Felt,
    m2: Felt,
    cm_digest: Felt,
    roster_d: Felt,
) -> Felt {
    poseidon_hash_many(&[m_label(), hand_binding, m1, m2, cm_digest, roster_d])
}

/// c = poseidon([sig_label, hand_binding, M_h, P̄x, P̄y, R̄x, R̄y])（raw felt）。
pub fn challenge_raw(
    hand_binding: Felt,
    m_h: Felt,
    pbar: (Felt, Felt),
    rbar: (Felt, Felt),
) -> Felt {
    poseidon_hash_many(&[
        sig_label(),
        hand_binding,
        m_h,
        pbar.0,
        pbar.1,
        rbar.0,
        rbar.1,
    ])
}

/// claim_i = poseidon([claim_label, hand_binding, M_h])。
pub fn claim_word(hand_binding: Felt, m_h: Felt) -> Felt {
    poseidon_hash_many(&[claim_label(), hand_binding, m_h])
}

/// acc = poseidon([prev_acc] ++ claims)（与 recurse::fold_accumulator 同公式）。
pub fn fold_acc(prev_acc: Felt, claims: &[Felt]) -> Felt {
    let mut words = Vec::with_capacity(claims.len() + 1);
    words.push(prev_acc);
    words.extend_from_slice(claims);
    poseidon_hash_many(&words)
}

// ---------------------------------------------------------------------------
// 验证方程（fold_batch.cairo 第 5 步的 host 形态，fail-closed 全检）
// ---------------------------------------------------------------------------

/// 单方程 host 直验：与电路同序——满阶编码检查 → z̄<n → 残差 == 恒等。
/// 返回 Err 的文案即电路对应 panic 标签（parity 的负向面）。
pub fn verify_equation(
    pbar: (Felt, Felt),
    rbar: (Felt, Felt),
    c_raw: Felt,
    zbar: Felt,
) -> Result<(), String> {
    let p = Point::from_affine(pbar.0, pbar.1).ok_or("PK_OFF_CURVE (P̄)")?;
    if p.is_identity() {
        return Err("PBAR_IS_IDENTITY".into());
    }
    let r = Point::from_affine(rbar.0, rbar.1).ok_or("RBAR_OFF_CURVE")?;
    if r.is_identity() {
        return Err("RBAR_IS_IDENTITY".into());
    }
    if zbar >= ec_order_felt() {
        return Err("ZBAR_OUT_OF_RANGE".into());
    }
    // z̄·G − c·P̄ − R̄ == O（raw-felt 乘法纪律：群阶自动归约）
    let residual = Point::generator().mul(zbar) - p.mul(c_raw) - r;
    if !residual.is_identity() {
        return Err("RESIDUAL_NOT_IDENTITY".into());
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// BDN 三轮铸造镜像（round1 nonce 承诺 → round2 揭 R_i → round3 部分签名）
// ---------------------------------------------------------------------------

/// 一手折叠的 wire 槽（fold_batch.cairo per-hand 105 词块的 host 形状）。
///
/// `settle` = 102 词 settle wire（settlement_stmt.cairo 布局）；M_h 真槽
/// m1/m2/cm_digest 不再是独立槽——由 [`FoldHand::m1`]/[`FoldHand::m2`]/
/// [`FoldHand::cm_digest`] 从 wire 槽位派生（与电路逐位同源，D2）。
/// **槽语义与槽值都在共签消息里**（改性即破签名），这是修复 2/4 的承载。
#[derive(Debug, Clone)]
pub struct FoldHand {
    /// 102 词 settle wire（[hand_id, registered_digest, n_expected,
    /// hand_binding, p×9, s×9, m×9, c×9, ald, count, w×60]）。
    pub settle: Vec<Felt>,
    pub rbar: (Felt, Felt),
    pub zbar: Felt,
}

impl FoldHand {
    /// hand_binding = wire[3]（与 combined.cairo 同取法）。
    pub fn hand_binding(&self) -> Felt {
        self.settle[3]
    }

    /// m1 = wire[1]（registered_digest）——M_h 真槽（D2）。
    pub fn m1(&self) -> Felt {
        self.settle[1]
    }

    /// m2 = wire[2]（n_expected）——M_h 真槽（D2；与 roster 人数是两个
    /// 独立量，生产版逐字复制 wire[2]）。
    pub fn m2(&self) -> Felt {
        self.settle[2]
    }

    /// cm_digest = poseidon(wire[31..=39])（9 词 c0..c8 压缩，D2）。
    pub fn cm_digest(&self) -> Felt {
        cm_digest_from_wire(&self.settle)
    }
}

/// round1：nonce 承诺 t = poseidon([nonce_label, R 坐标])（承诺先行）。
#[derive(Debug, Clone)]
pub struct NonceCommit {
    pub t: Felt,
    /// round2 才揭的 nonce 点 R = w·G。
    pub r: (Felt, Felt),
}

pub fn nonce_commit(w: Felt) -> NonceCommit {
    let (rx, ry) = Point::generator().mul(w).to_affine().expect("w·G affine");
    NonceCommit { t: poseidon_hash_many(&[nonce_label(), rx, ry]), r: (rx, ry) }
}

/// round2：全承诺到齐后聚合 nonce 点 R̄ = Σ R_i（承诺验证是协议面纪律）。
pub fn aggregate_nonces(commits: &[NonceCommit]) -> Result<(Felt, Felt), String> {
    let mut acc = Point::identity();
    for c in commits {
        // 承诺绑定：揭出的 R_i 必须重出同一 t_i（防 Drijvers 式换 nonce）
        let t = poseidon_hash_many(&[nonce_label(), c.r.0, c.r.1]);
        if t != c.t {
            return Err("NONCE_COMMIT_MISMATCH".into());
        }
        let r = Point::from_affine(c.r.0, c.r.1).ok_or("nonce R off-curve")?;
        acc = acc + r;
    }
    acc.to_affine().ok_or_else(|| "R̄ is identity".to_string())
}

/// round3：部分签名 z_i = w_i + c·μ_i·sk_i (mod n)。
pub fn partial_sig(
    sk: Felt,
    w: Felt,
    c_raw: Felt,
    mu_raw: Felt,
) -> StarkScalar {
    to_scalar(w) + to_scalar(c_raw) * (to_scalar(mu_raw) * to_scalar(sk))
}

/// 批注册面锚（切片 = host 模拟 roster_registry；生产 = 合约对照 segment[16]）。
#[derive(Debug, Clone)]
pub struct RosterAnchor {
    pub roster_digest: Felt,
    pub expected_acc: Felt,
}

/// 一手聚合的完整宿主结果（铸造 + 公式重算的期望值来源）。
#[derive(Debug, Clone)]
pub struct AggregatedHand {
    pub hand: FoldHand,
    pub roster_digest: Felt,
    pub pbar: (Felt, Felt),
    pub m_h: Felt,
    pub c: Felt,
    pub claim: Felt,
}

/// BDN 三轮诚实聚合（host 镜像）：roster pks 由 sks 派生，M_h 真槽值从
/// settle wire 槽位派生（与电路逐位同源）。铸侧全走标量域（mod n），
/// 验证侧走 raw-felt EC——与「电路读 wire、群阶自动归约」逐 felt 对齐。
pub fn aggregate_sign(sks: &[Felt], ws: &[Felt], settle: &[Felt]) -> Result<AggregatedHand, String> {
    if sks.len() != ws.len() || sks.is_empty() {
        return Err("aggregate_sign: sks/ws length mismatch or empty".into());
    }
    if settle.len() != SETTLE_WORDS {
        return Err(format!(
            "aggregate_sign: settle wire len {} != {SETTLE_WORDS}",
            settle.len()
        ));
    }
    let g = Point::generator();
    let pks: Vec<(Felt, Felt)> = sks
        .iter()
        .map(|sk| g.mul(*sk).to_affine().expect("sk·G affine"))
        .collect();
    let rd = roster_digest(&pks);
    let pbar = agg_pubkey(&pks)?;

    // BDN 三轮
    let commits: Vec<NonceCommit> = ws.iter().map(|w| nonce_commit(*w)).collect();
    let rbar = aggregate_nonces(&commits)?;
    // M_h 真槽（D2）：hand_binding=wire[3]、m1=wire[1]、m2=wire[2]、
    // cm_digest=poseidon(wire[31..=39])——与 fold_batch.cairo 逐位同源。
    let hand_binding = settle[3];
    let m1 = settle[1];
    let m2 = settle[2];
    let cm_digest = cm_digest_from_wire(settle);
    let m_h = msg_digest(hand_binding, m1, m2, cm_digest, rd);
    let c = challenge_raw(hand_binding, m_h, pbar, rbar);

    let n = pks.len();
    let mut zbar = <StarkScalar as CurveScalar>::zero();
    for (i, sk) in sks.iter().enumerate() {
        let mu = key_coeff_raw(n, pks[i].0, pks[i].1);
        zbar = zbar + partial_sig(*sk, ws[i], c, mu);
    }

    Ok(AggregatedHand {
        hand: FoldHand { settle: settle.to_vec(), rbar, zbar: scalar_to_felt(zbar) },
        roster_digest: rd,
        pbar,
        m_h,
        c,
        claim: claim_word(hand_binding, m_h),
    })
}

/// 批的期望公开输出（parity 门期望侧）：
/// acc = fold_acc(prev, claims)（批终 acc），roster_digest = H(wire pks)。
/// （T4 改性：这是 host-parity 断言，对 soundness **零证明力**——它只钉
/// 公式漂移；「pks == 注册 pks」的 soundness 闭合点在生产 roster_registry，
/// 切片负例 T9/T10 走 prove 后 parity 门拒绝。）
pub fn expected_public_output(
    prev_acc: Felt,
    roster_pks: &[(Felt, Felt)],
    hands: &[AggregatedHand],
) -> RosterAnchor {
    let rd = roster_digest(roster_pks);
    let claims: Vec<Felt> = hands.iter().map(|h| h.claim).collect();
    RosterAnchor { roster_digest: rd, expected_acc: fold_acc(prev_acc, &claims) }
}

/// 多桌批的一桌（roster + 本桌 K_t 手）——wire 桌段、出证门锚与期望
/// 输出的最小单元（多桌规格 §2/§4）。桌内 roster_digest 与 P̄_t 由本桌
/// pks 派生（每桌一次）；`hands` 为空 = 构造错误（K_t=0 只浪费 keyagg
/// steps、零产出，host 构造器拒绝——M1-b；电路侧不检，Q-M2）。
#[derive(Debug, Clone)]
pub struct FoldTable {
    pub roster_pks: Vec<(Felt, Felt)>,
    pub hands: Vec<AggregatedHand>,
}

impl FoldTable {
    /// 构造器：强制 K_t ≥ 1（M1-b）。
    pub fn new(
        roster_pks: Vec<(Felt, Felt)>,
        hands: Vec<AggregatedHand>,
    ) -> Result<Self, String> {
        if hands.is_empty() {
            return Err(
                "FoldTable::new: K_t = 0 empty table rejected (host constructor, M1-b)".into(),
            );
        }
        Ok(Self { roster_pks, hands })
    }

    /// 本桌手的 wire 形态（settle + (R̄, z̄)）。
    pub fn wire_hands(&self) -> Vec<FoldHand> {
        self.hands.iter().map(|h| h.hand.clone()).collect()
    }
}

/// 多桌批的逐桌锚（出证后 parity 门对照侧，M4/M9）：桌 t 的
/// roster_digest = H(pks_t)（桌内常量——电路结构保证）；expected_acc 全桌
/// 共享 = `fold_acc(prev, claims 按桌序串接)`（Q-1：跨桌 claims 仍单次折叠）。
pub fn expected_public_output_tables(
    prev_acc: Felt,
    tables: &[FoldTable],
) -> Vec<RosterAnchor> {
    let mut claims: Vec<Felt> = Vec::new();
    let mut digests = Vec::with_capacity(tables.len());
    for t in tables {
        digests.push(roster_digest(&t.roster_pks));
        claims.extend(t.hands.iter().map(|h| h.claim));
    }
    let acc = fold_acc(prev_acc, &claims);
    digests
        .into_iter()
        .map(|rd| RosterAnchor { roster_digest: rd, expected_acc: acc })
        .collect()
}

/// 多桌 T 窗口与形状检查（M1-c，host 层政策——先于一切出证动作，纯数据
/// 检查可单测）：T ≥ 1、T ≤ T_MAX、每桌 K_t ≥ 1、锚数 == 桌数。
pub fn check_multitable_shape(
    tables: &[FoldTable],
    anchors: &[RosterAnchor],
) -> Result<(), String> {
    if tables.is_empty() {
        return Err("empty fold batch (T = 0): no table segments".into());
    }
    if tables.len() > FOLD_T_MAX {
        return Err(format!(
            "fold batch table count {} > T_MAX {} (M1-c)",
            tables.len(),
            FOLD_T_MAX
        ));
    }
    for (t, table) in tables.iter().enumerate() {
        if table.hands.is_empty() {
            return Err(format!(
                "table {t}: K_t = 0 empty table rejected (M1-b)"
            ));
        }
    }
    if anchors.len() != tables.len() {
        return Err(format!(
            "anchor count {} != table count {}",
            anchors.len(),
            tables.len()
        ));
    }
    Ok(())
}

/// settle wire（102 词）→ host 语句对象（[`crate::combined::SettleStatement`]，
/// `expected_segment` 的期望侧重算入口）。
///
/// 高位非零的数值词按 u64 界拒绝（host 解析纪律；语句真约束——digest 折叠/
/// NOT_ZERO_SUM/COUNT_MISMATCH/动作链——由电路 settlement_statement 全量
/// assert，本解析只服务 host 预检与 parity 期望侧）。
pub fn parse_settle_wire(w: &[Felt]) -> Result<crate::combined::SettleStatement, String> {
    if w.len() != SETTLE_WORDS {
        return Err(format!("settle wire len {} != {SETTLE_WORDS}", w.len()));
    }
    let u64_at = |i: usize| -> Result<u64, String> {
        let b = w[i].to_bytes_be();
        if b[..24].iter().any(|&x| x != 0) {
            return Err(format!("settle wire word {i} exceeds u64 (host parse)"));
        }
        Ok(u64::from_be_bytes(b[24..32].try_into().expect("8 bytes")))
    };
    let count = u64_at(41)?;
    if count > 30 {
        return Err(format!("settle wire action count {count} > 30 (host parse)"));
    }
    let mut signs = [0u64; 9];
    let mut magnitudes = [0u64; 9];
    for i in 0..9 {
        signs[i] = u64_at(13 + i)?;
        magnitudes[i] = u64_at(22 + i)?;
    }
    let mut entries = Vec::with_capacity(count as usize);
    for i in 0..count as usize {
        entries.push([w[42 + 2 * i], w[43 + 2 * i]]);
    }
    Ok(crate::combined::SettleStatement {
        hand_id: u64_at(0)?,
        registered_digest: w[1],
        n_expected: u64_at(2)?,
        hand_binding: w[3],
        players: w[4..13].try_into().expect("9 player slots"),
        signs,
        magnitudes,
        commitments: w[SETTLE_CM_START..SETTLE_CM_START + SETTLE_CM_WORDS]
            .try_into()
            .expect("9 commitment slots"),
        action_log_digest: w[40],
        action_entries: entries,
    })
}

/// host 直验一批（fail-closed 预检；公式层与电路同序）。
///
/// 语句层 host 镜像（`parse_settle_wire` + `expected_segment`）只承担公式
/// 漂移检测（T4 语义，对 soundness 零证明力）——真约束由电路
/// settlement_statement 全量 assert。
pub fn host_verify_batch(
    roster_pks: &[(Felt, Felt)],
    hands: &[AggregatedHand],
) -> Result<(), String> {
    for (x, y) in roster_pks {
        let pk = Point::from_affine(*x, *y).ok_or("roster pk off-curve")?;
        if pk.is_identity() {
            return Err("roster pk is identity".into());
        }
    }
    let rd = roster_digest(roster_pks);
    let pbar = agg_pubkey(roster_pks)?;
    for h in hands {
        if h.roster_digest != rd {
            return Err("hand roster_digest mismatch".into());
        }
        parse_settle_wire(&h.hand.settle)?.expected_segment()?;
        verify_equation(pbar, h.hand.rbar, h.c, h.hand.zbar)?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// wire 摊平 + prove-hand 驱动（recurse.rs:218-322 模式）
// ---------------------------------------------------------------------------

/// 多桌 batch wire（多桌规格 §2 钉死）：**桌段自定界串接、无全局 T 词**——
/// `[P_1, (pkx,pky)×P_1, K_1, blocks×K_1] ++ … ++ [P_T, pks_T, K_T, blocks×K_T]`，
/// 每手块 = settle 102 词 + (R̄x, R̄y, z̄)（与单桌块逐词同形）；词数 =
/// Σ_t(2 + 2·P_t + 105·K_t)。桌序 = wire 序 = 段序 = claims 序。
pub fn build_batch_wire_tables(tables: &[(&[(Felt, Felt)], &[FoldHand])]) -> Vec<Felt> {
    let total: usize = tables
        .iter()
        .map(|(pks, hands)| 2 + 2 * pks.len() + HAND_BLOCK_WORDS * hands.len())
        .sum();
    let mut w = Vec::with_capacity(total);
    for (pks, hands) in tables {
        w.push(Felt::from(pks.len() as u64));
        for (x, y) in *pks {
            w.push(*x);
            w.push(*y);
        }
        w.push(Felt::from(hands.len() as u64));
        for h in *hands {
            assert_eq!(
                h.settle.len(),
                SETTLE_WORDS,
                "FoldHand.settle must be a 102-word settle wire"
            );
            w.extend_from_slice(&h.settle);
            w.push(h.rbar.0);
            w.push(h.rbar.1);
            w.push(h.zbar);
        }
    }
    w
}

/// 单桌 batch wire：`[P, (pkx,pky)×P, K, (settle 102 词, R̄x, R̄y, z̄)×K]`
/// （fold_batch.cairo 头注释同布局；词数 = 2 + 2P + 105K）。**T=1 退化 =
/// 多桌构造器吃一桌**（结构同一而非兼容模式——多桌规格 §8，金样回归钉死）。
pub fn build_batch_wire(roster_pks: &[(Felt, Felt)], hands: &[FoldHand]) -> Vec<Felt> {
    build_batch_wire_tables(&[(roster_pks, hands)])
}

fn felt_hex(f: Felt) -> String {
    format!("0x{}", f.to_bytes_be().iter().map(|b| format!("{b:02x}")).collect::<String>())
}

fn cairo_fold_src() -> PathBuf {
    std::env::var("HAND_VERIFY_FOLD_SRC").map(PathBuf::from).unwrap_or_else(|_| {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("cairo/src/fold_batch.cairo")
    })
}

fn prove_hand_bin() -> PathBuf {
    std::env::var("HAND_VERIFY_PROVE_HAND").map(PathBuf::from).unwrap_or_else(|_| {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(|p| p.parent())
            .expect("crate lives inside the repo")
            .join("proving-tool/target/release/prove-hand")
    })
}

/// 写 inputs.json 的 wire 核：`[prev_acc, span_len] ++ wire`（hex felt 数组；
/// `span_len` 独立传入——形状负例（M9-3c span 与实际词数不符）走
/// `prove_wire_unchecked_with_span` 的攻击入口，正路调用必须
/// `span_len == wire.len()`）。
fn write_wire_inputs(
    prev_acc: Felt,
    wire: &[Felt],
    span_len: usize,
    out_dir: &Path,
) -> Result<PathBuf, String> {
    let mut arr = vec![felt_hex(prev_acc)];
    arr.push(format!("0x{:x}", span_len));
    arr.extend(wire.iter().map(|w| felt_hex(*w)));
    let path = out_dir.join("inputs.json");
    std::fs::write(&path, serde_json::to_string(&arr).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    Ok(path)
}

/// 多桌批写 inputs.json（`span_len` = 多桌 wire 实际词数）。
pub fn write_inputs_tables(
    prev_acc: Felt,
    tables: &[(&[(Felt, Felt)], &[FoldHand])],
    out_dir: &Path,
) -> Result<PathBuf, String> {
    let wire = build_batch_wire_tables(tables);
    write_wire_inputs(prev_acc, &wire, wire.len(), out_dir)
}

/// 单桌批写 inputs.json（`[prev_acc, span_len] ++ batch wire`，hex felt 数组；
/// T=1 退化 = 多桌写入口吃一桌，逐词一致）。
pub fn write_inputs(
    prev_acc: Felt,
    roster_pks: &[(Felt, Felt)],
    hands: &[FoldHand],
    out_dir: &Path,
) -> Result<PathBuf, String> {
    write_inputs_tables(prev_acc, &[(roster_pks, hands)], out_dir)
}

/// 一次出证的结果（recurse::LayerOutcome 的 fold 批对应物 + RSS 采集钩子）。
#[derive(Debug, Clone)]
pub struct FoldOutcome {
    pub n_players: usize,
    pub n_hands: usize,
    pub wire_words: usize,
    /// 批终 acc（每段 slot 0 同值——Q-1）。
    pub cairo_acc: Felt,
    pub cairo_roster_digest: Felt,
    pub expected_acc: Felt,
    pub expected_roster_digest: Felt,
    /// K 段 18 词公开段（[acc] ++ 语句段 16 ++ [roster_digest]）。
    pub segments: Vec<Vec<Felt>>,
    pub total_ms: u128,
    pub cairo_prove_ms: u64,
    pub cairo_run_ms: u64,
    pub cairo_compile_ms: u64,
    pub steps: u64,
    pub ec_ops: u64,
    pub poseidon_ops: u64,
    pub program_hash: Felt,
    pub proof_bytes: usize,
    pub check_verify_ms: u128,
    pub out_dir: PathBuf,
    // ---- 多桌字段（T=1 时均为单元素，语义同上）----
    /// 桌数 T（= wire 桌段数）。
    pub n_tables: usize,
    /// 逐桌人数 P_t（wire 序）。
    pub table_players: Vec<usize>,
    /// 逐桌手数 K_t（wire 序）。
    pub table_hands: Vec<usize>,
    /// 逐桌 cairo 段 slot17（每桌首段代表；D1a 桌内常量）。
    pub cairo_table_roster_digests: Vec<Felt>,
    /// 逐桌期望 roster_digest（anchors，注册面锚）。
    pub expected_table_roster_digests: Vec<Felt>,
}

/// combined 每手基线（1 手/证，9p 同机实测 12,384 steps——9 人桌迁移后
/// combined_test heavy 重测（2026-09-30）；迁移前 9p 口径 12,160、2p 锚
/// 7,204 见 docs/combined-perf-2026-09-29.md:14）。
/// 生产 fold 的 steps 验收底线：每手边际不得劣于 combined 每手整证。
pub const COMBINED_PER_HAND_STEPS: u64 = 12_384;

/// keyagg 批固定层实测锚（P=8：1,628 = 404+8×153，提案 §3.1 转引）。
/// K=1 的门 = COMBINED_PER_HAND_STEPS + 本锚（批固定层只付一次）。
/// 9 人桌口径按线性模型 +153/席（404+9×153=1,781，见迁移报告实测对照）；
/// 本锚保持 P=8 实测值与 T7（P=8 语料）门配对——P=9 K=1 实测见
/// out/fold-9seat-migration.md 的性能对照节。
pub const KEYAGG_STEPS_ANCHOR: u64 = 1_628;

fn spawn_prove_hand(
    inputs_path: &Path,
    out_dir: &Path,
    params_path: Option<&Path>,
) -> Result<(std::process::Output, u128), String> {
    let mut cmd = std::process::Command::new(prove_hand_bin());
    cmd.arg("--program")
        .arg(cairo_fold_src())
        .arg("--inputs")
        .arg(inputs_path)
        .arg("--out-dir")
        .arg(out_dir);
    if let Ok(corelib) = std::env::var("HAND_VERIFY_CORELIB") {
        cmd.arg("--corelib").arg(corelib);
    }
    if let Some(params) = params_path {
        cmd.arg("--params").arg(params);
    }
    let t = Instant::now();
    let output = cmd.output().map_err(|e| format!("spawn prove-hand: {e}"))?;
    Ok((output, t.elapsed().as_millis()))
}

fn parse_summary(out_dir: &Path) -> Result<serde_json::Value, String> {
    serde_json::from_str(
        &std::fs::read_to_string(out_dir.join("summary.json")).map_err(|e| e.to_string())?,
    )
    .map_err(|e| format!("parse summary.json: {e}"))
}

/// spawn prove-hand 并把非零退出汇报为「circuit rejected」（负例共用）。
fn run_prove_hand(
    inputs_path: &Path,
    out_dir: &Path,
    params_path: Option<&Path>,
) -> Result<(), String> {
    let (output, _ms) = spawn_prove_hand(inputs_path, out_dir, params_path)?;
    if output.status.success() {
        return Ok(());
    }
    Err(format!(
        "prove-hand failed (circuit rejected): {}",
        String::from_utf8_lossy(&output.stderr).trim()
    ))
}

fn ensure_prove_hand() -> Result<(), String> {
    if !prove_hand_bin().exists() {
        return Err(format!(
            "prove-hand binary not found at {} (build: cd proving-tool && cargo build --release)",
            prove_hand_bin().display()
        ));
    }
    Ok(())
}

/// 未经 host 门禁的裸出证（负例专用：让 prove-hand 直接命中电路 panic）。
pub fn prove_fold_batch_unchecked(
    prev_acc: Felt,
    roster_pks: &[(Felt, Felt)],
    hands: &[FoldHand],
    out_dir: &Path,
    params_path: Option<&Path>,
) -> Result<(), String> {
    prove_fold_batch_unchecked_tables(
        prev_acc,
        &[(roster_pks, hands)],
        out_dir,
        params_path,
    )
}

/// 多桌裸出证（负例专用，M9-2(a)(b) 跨桌攻击语料入口）：桌段直接拼
/// 攻击 wire——无 host 直验、无 T 窗口/构造器检查（跨桌混签/重放语料
/// 让 prove-hand 直接命中电路 panic，fail-closed 无证明）。
pub fn prove_fold_batch_unchecked_tables(
    prev_acc: Felt,
    tables: &[(&[(Felt, Felt)], &[FoldHand])],
    out_dir: &Path,
    params_path: Option<&Path>,
) -> Result<(), String> {
    std::fs::create_dir_all(out_dir).map_err(|e| e.to_string())?;
    ensure_prove_hand()?;
    let inputs_path = write_inputs_tables(prev_acc, tables, out_dir)?;
    run_prove_hand(&inputs_path, out_dir, params_path)
}

/// wire 级裸出证（M9-3 形状负例：尾桌截断等——直接吃攻击者手写的 wire）。
pub fn prove_wire_unchecked(
    prev_acc: Felt,
    wire: &[Felt],
    out_dir: &Path,
    params_path: Option<&Path>,
) -> Result<(), String> {
    prove_wire_unchecked_with_span(prev_acc, wire, wire.len(), out_dir, params_path)
}

/// wire 级裸出证 + 显式 span_len（M9-3(c)：span 声明与实际词数不符 ⇒
/// runner/电路拒绝；`span_len == wire.len()` 是正路不变量）。
pub fn prove_wire_unchecked_with_span(
    prev_acc: Felt,
    wire: &[Felt],
    span_len: usize,
    out_dir: &Path,
    params_path: Option<&Path>,
) -> Result<(), String> {
    std::fs::create_dir_all(out_dir).map_err(|e| e.to_string())?;
    ensure_prove_hand()?;
    let inputs_path = write_wire_inputs(prev_acc, wire, span_len, out_dir)?;
    run_prove_hand(&inputs_path, out_dir, params_path)
}

/// 出证一个**多桌** fold 批并过 parity 门（多桌规格 M9-1 主路径）。
///
/// 门序（对 A1/A2 的诚实承载——电路内 wire pks 仍自由，soundness 闭合点
/// 在消费面）：T 窗口/形状检查（M1-b/M1-c）→ host 直验（fail-closed 预检，
/// 只验公式面）→ 出证（电路只保证算术一致 + 语句约束 + 单方程成立）→
/// **出证后**对照注册面锚（逐手按桌序：**roster 门先行**——`seg[17] ==
/// anchors[t].roster_digest`（本桌 anchor；跨桌混签/换 roster 的失败面，
/// M9-2）→ **acc 门**——`seg[0] == anchors[t].expected_acc`（全桌共享
/// 批终 acc，T5）→ **段公式门**——段 word 1..=16 对 host
/// `expected_segment` 重算（输出形状/语句公式漂移门，T4 语义））→
/// `--check-only` 独立复验证明文件。
pub fn prove_fold_batch_multitable(
    prev_acc: Felt,
    tables: &[FoldTable],
    anchors: &[RosterAnchor],
    out_dir: &Path,
    params_path: Option<&Path>,
) -> Result<FoldOutcome, String> {
    // T 窗口/形状检查（M1-b/M1-c）先行——纯数据检查，不依赖 prove-hand，
    // 负例可单测。
    check_multitable_shape(tables, anchors)?;
    std::fs::create_dir_all(out_dir).map_err(|e| e.to_string())?;
    ensure_prove_hand()?;
    // host 直验（fail-closed 预检——只验公式面，不做注册面预判，注册面
    // 对照必须在出证之后看 cairo 输出）。逐桌：每桌对**本桌** pks 派生
    // P̄_t/roster_digest_t 并验证本桌全部手。
    for t in tables {
        host_verify_batch(&t.roster_pks, &t.hands)?;
    }

    // 多桌 wire（T=1 时与 build_batch_wire 逐词相等——结构同一，§8）
    let owned: Vec<(Vec<(Felt, Felt)>, Vec<FoldHand>)> = tables
        .iter()
        .map(|t| (t.roster_pks.clone(), t.wire_hands()))
        .collect();
    let borrowed: Vec<(&[(Felt, Felt)], &[FoldHand])> = owned
        .iter()
        .map(|(p, h)| (p.as_slice(), h.as_slice()))
        .collect();
    let wire = build_batch_wire_tables(&borrowed);
    let wire_words = wire.len();
    let inputs_path = write_wire_inputs(prev_acc, &wire, wire.len(), out_dir)?;
    let (output, total_ms) = spawn_prove_hand(&inputs_path, out_dir, params_path)?;
    if !output.status.success() {
        return Err(format!(
            "prove-hand failed (batch rejected): {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }

    let summary = parse_summary(out_dir)?;
    if !summary["verified"].as_bool().unwrap_or(false) {
        return Err("cairo proof did not verify".into());
    }
    let public: Vec<Felt> = summary["public"]["output"]
        .as_array()
        .ok_or("public output missing")?
        .iter()
        .map(|v| {
            let s = v.as_str().ok_or("public word not hex string")?;
            Felt::from_hex(s.trim_start_matches("0x")).map_err(|e| format!("parse felt: {e:?}"))
        })
        .collect::<Result<_, _>>()?;
    // runner 把 Array 返回序列化为 [len, ...elements]（forge0 单词返回 =
    // ["0x1","0x1"] 实证）——多桌批返回 (ΣK)×18 词段平铺，桌 t 的手占据
    // 连续段区间（桌序 = wire 序 = 段序）。
    let total_hands: usize = tables.iter().map(|t| t.hands.len()).sum();
    let segment_words = total_hands * FOLD_SEGMENT_LEN;
    if public.len() != 1 + segment_words || public[0] != Felt::from(segment_words as u64) {
        return Err(format!(
            "expected [len, {segment_words} segment words] public output, got {} words",
            public.len()
        ));
    }
    let mut segments: Vec<Vec<Felt>> = Vec::with_capacity(total_hands);
    for j in 0..total_hands {
        segments.push(
            public[1 + j * FOLD_SEGMENT_LEN..1 + (j + 1) * FOLD_SEGMENT_LEN].to_vec(),
        );
    }
    let cairo_acc = segments[0][0];

    // ---- parity 门（注册面切片模拟，出证后对照；roster 门先行——M9-2 的
    // 失败面是 roster 对照，T5 的失败面才是 acc）----
    let mut j = 0usize;
    for (t, table) in tables.iter().enumerate() {
        let anchor = &anchors[t];
        for h in &table.hands {
            let seg = &segments[j];
            if seg[FOLD_ROSTER_INDEX] != anchor.roster_digest {
                return Err(format!(
                    "roster digest parity failure (unregistered roster) at hand {j} (table {t}): \
                     cairo 0x{:x} != registered 0x{:x}",
                    seg[FOLD_ROSTER_INDEX], anchor.roster_digest
                ));
            }
            if seg[0] != anchor.expected_acc {
                return Err(format!(
                    "acc parity failure at hand {j}: cairo 0x{:x} != host 0x{:x}",
                    seg[0], anchor.expected_acc
                ));
            }
            // 输出形状/语句公式漂移门（T4 语义）：段 word 1..=16 必须 ==
            // host expected_segment（同一 settle wire 的 host 镜像重算）。
            let expected_seg = parse_settle_wire(&h.hand.settle)?.expected_segment()?;
            if seg[1..FOLD_ROSTER_INDEX] != *expected_seg.as_slice() {
                return Err(format!(
                    "segment parity failure at hand {j}: cairo statement words != host expected_segment"
                ));
            }
            j += 1;
        }
    }

    // ---- --check-only 独立复验 ----
    let proof_path = out_dir.join("proof.json");
    let t = Instant::now();
    let ck = std::process::Command::new(prove_hand_bin())
        .arg("--check-only")
        .arg("--proof")
        .arg(&proof_path)
        .output()
        .map_err(|e| format!("spawn prove-hand check-only: {e}"))?;
    if !ck.status.success() {
        return Err(format!(
            "standalone re-verify failed: {}",
            String::from_utf8_lossy(&ck.stderr).trim()
        ));
    }
    let check_verify_ms = t.elapsed().as_millis();

    let timings = &summary["timings_ms"];
    let table_players: Vec<usize> = tables.iter().map(|t| t.roster_pks.len()).collect();
    let table_hands: Vec<usize> = tables.iter().map(|t| t.hands.len()).collect();
    // 逐桌 cairo 段 slot17（每桌首段代表——D1a 桌内常量由电路结构保证）
    let mut cairo_table_roster_digests: Vec<Felt> = Vec::with_capacity(tables.len());
    let mut off = 0usize;
    for k in &table_hands {
        cairo_table_roster_digests.push(segments[off][FOLD_ROSTER_INDEX]);
        off += k;
    }
    let outcome = FoldOutcome {
        n_players: table_players[0],
        n_hands: total_hands,
        wire_words,
        cairo_acc,
        cairo_roster_digest: cairo_table_roster_digests[0],
        expected_acc: anchors[0].expected_acc,
        expected_roster_digest: anchors[0].roster_digest,
        segments,
        total_ms,
        cairo_prove_ms: timings["prove"].as_u64().unwrap_or(0),
        cairo_run_ms: timings["run_witness"].as_u64().unwrap_or(0),
        cairo_compile_ms: timings["compile"].as_u64().unwrap_or(0),
        steps: summary["execution"]["steps"].as_u64().unwrap_or(0),
        ec_ops: summary["execution"]["builtin_instance_counter"]["ec_op_builtin"]
            .as_u64()
            .unwrap_or(0),
        poseidon_ops: summary["execution"]["builtin_instance_counter"]["poseidon_builtin"]
            .as_u64()
            .unwrap_or(0),
        program_hash: summary["public"]["program_hash"]
            .as_str()
            .and_then(|h| Felt::from_hex(h).ok())
            .ok_or("program hash missing")?,
        proof_bytes: std::fs::metadata(&proof_path).map(|m| m.len() as usize).unwrap_or(0),
        check_verify_ms,
        out_dir: out_dir.to_path_buf(),
        n_tables: tables.len(),
        table_players,
        table_hands,
        cairo_table_roster_digests,
        expected_table_roster_digests: anchors.iter().map(|a| a.roster_digest).collect(),
    };
    Ok(outcome)
}

/// 出证一批（单桌）fold 语句并过 parity 门（T1 主路径）。
///
/// **T=1 退化 = 多桌构造器吃一桌**（`prove_fold_batch_multitable` 的单桌
/// 调用——结构同一而非兼容模式，多桌规格 §8；门序/输出字段语义与多桌
/// 核心逐位一致）。空手批（K=0）在此被构造器拒绝（M1-b；原实现在
/// 出证后 `segments[0]` 索引 panic，现改为 Err——fail-closed 不变）。
pub fn prove_fold_batch(
    prev_acc: Felt,
    roster_pks: &[(Felt, Felt)],
    hands: &[AggregatedHand],
    anchor: &RosterAnchor,
    out_dir: &Path,
    params_path: Option<&Path>,
) -> Result<FoldOutcome, String> {
    let table = FoldTable::new(roster_pks.to_vec(), hands.to_vec())?;
    prove_fold_batch_multitable(
        prev_acc,
        &[table],
        std::slice::from_ref(anchor),
        out_dir,
        params_path,
    )
}

// ---------------------------------------------------------------------------
// 确定性铸造（测试/基准语料；无 rand 依赖）
// ---------------------------------------------------------------------------

fn det_felt(seed: u64, i: u64) -> Felt {
    poseidon_hash_many(&[Felt::from(seed), Felt::from(i), Felt::from(0xF01Du64)])
}

/// 铸一张 n 人确定性 roster（sk 派生自 seed）。
pub fn mint_roster_sks(n: usize, seed: u64) -> Vec<Felt> {
    (0..n as u64).map(|i| det_felt(seed, i)).collect()
}

/// 铸一张 n 人 roster 的公钥坐标。
pub fn roster_pks_from_sks(sks: &[Felt]) -> Vec<(Felt, Felt)> {
    let g = Point::generator();
    sks.iter().map(|sk| g.mul(*sk).to_affine().expect("sk·G affine")).collect()
}

/// 铸一条诚实 102 词 settle wire（`combined::build_settle_statement` 生产
/// 接缝）：双席参与零和（seat0 赢 / seat1 输、余席 0），n_expected = 2 与
/// roster 人数语义独立——钉 m2 = wire[2] 槽（D2）；空动作日志；赢家承诺
/// 非零（cm 输出公式由语句函数承载）。
fn mint_settle_wire(
    hand_id: u64,
    hb: Felt,
    n_players: usize,
    seed: u64,
    k: u64,
) -> Result<Vec<Felt>, String> {
    if !(2..=9).contains(&n_players) {
        return Err(format!("mint_settle_wire: roster size {n_players} outside 2..=9"));
    }
    let players: Vec<Felt> =
        (0..n_players as u64).map(|i| det_felt(seed + 7, 50 + i) + Felt::ONE).collect();
    let total: i128 = 1_000_000 + 7 * k as i128;
    let mut deltas: Vec<i128> = vec![0; n_players];
    deltas[0] = total;
    deltas[1] = -total;
    let commitments: Vec<Felt> = (0..9u64).map(|i| det_felt(seed + 7, 60 + i)).collect();
    let ald = poseidon_hash_many(&[crate::combined::action_log_domain()]);
    let st = crate::combined::build_settle_statement(
        hand_id, hb, &players, &deltas, &commitments, ald, &[],
    )?;
    Ok(st.wire_words())
}

/// 铸一张 K 手 × n 人诚实 fold 批（settle wire 确定性派生；BDN nonce 从
/// seed 链）。roster pks 必须来自同一 seed 的 [`mint_roster_sks`]。
pub fn mint_fold_hands(
    roster_pks: &[(Felt, Felt)],
    hand_seeds: &[u64],
    seed: u64,
) -> Result<Vec<AggregatedHand>, String> {
    let sks = mint_roster_sks(roster_pks.len(), seed);
    let mut hands = Vec::with_capacity(hand_seeds.len());
    for (k, hs) in hand_seeds.iter().enumerate() {
        let hb = poseidon_hash_many(&[Felt::from(*hs), Felt::from(0xF01D_u64)]);
        let hand_id = 100 + k as u64;
        let settle = mint_settle_wire(hand_id, hb, roster_pks.len(), seed, k as u64)?;
        let ws: Vec<Felt> = (0..roster_pks.len() as u64)
            .map(|i| det_felt(*hs, 100 + i))
            .collect();
        hands.push(aggregate_sign(&sks, &ws, &settle)?);
    }
    Ok(hands)
}
