//! T3-FRI wrap 参照层（out/t3-fri-wrap-design.md）。
//!
//! 三个角色：
//! 1. [`extract`]：从 `hand-verify-native::prove::HandBatchProof`（真实 stwo 2.3
//!    `StarkProof<Poseidon252MerkleHasher>`）提取电路见证 [`FriWrapWitness`]。
//!    通道/几何/商公式全部走 stwo pub API——与下方手工复刻相互独立，构成差分源。
//! 2. [`derive_channel`] + [`build_tables`]：**JSON 驱动**的 FS 通道复刻与商常量
//!    表，电路综合与 [`verify_ref`] 共用；与 stwo 的一致性由 extract-vs-derive
//!    差分测试钉死。
//! 3. [`verify_ref`]：只用见证文件的公开段+见证段独立验证——电路语句的可执行
//!    规格（Rust 侧真值：M31/QM31 走 stwo 原生环，felt252 走 starknet-crypto）。
//!
//! 信任边界（v1，设计文档 §2）：承诺绑定 + 低调式 + FS 派生 + trace 行值→首层
//! 商累积一致；OOD 应答对 fold AIR 约束的满足是 stage-2。

use anyhow::{anyhow, bail, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

use starknet_crypto::Felt as StarkFelt;
use stwo::core::channel::{Channel, MerkleChannel, Poseidon252Channel};
use stwo::core::fields::cm31::CM31;
use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;
use stwo::core::pcs::quotients::{
    build_samples_with_randomness_and_periodicity, denominator_inverses, fri_answers,
    quotient_constants, ColumnSampleBatch, PointSample,
};
use stwo::core::pcs::utils::get_lifting_log_size;
use stwo::core::pcs::{PcsConfig, TreeVec};
use stwo::core::poly::circle::{CanonicCoset, CircleDomain};
use stwo::core::poly::line::LineDomain;
use stwo::core::queries::draw_queries;
use stwo::core::vcs_lifted::poseidon252_merkle::Poseidon252MerkleChannel;
use stwo::core::verifier::COMPOSITION_LOG_SPLIT;
use stwo::core::air::Component as _;
use stwo_constraint_framework::{FrameworkComponent, TraceLocationAllocator};

use crate::felt::{felt_from_starknet, felt_to_be_bytes, felt_to_starknet, Felt252};
use hand_verify_native::air::{HandBatchClaim, HandBatchEval, N_COLUMNS};
use hand_verify_native::prove::HandBatchProof;

// ---------------------------------------------------------------------------
// 协议常数（与 hand_verify_native::prove::protocol_pcs_config 原子一致）
// ---------------------------------------------------------------------------

pub const LOG_BLOWUP: u32 = 1;
pub const FOLD_STEP: u32 = 1;
pub const N_QUERIES: usize = 30;
pub const POW_BITS: u32 = 10;
pub const LOG_LAST_LAYER: u32 = 0;
/// quotient（composition）树列数：2 * SECURE_EXTENSION_DEGREE（stwo verify_ex）。
pub const N_QUOTIENT_COLS: usize = 8;

pub fn protocol_pcs_config() -> PcsConfig {
    hand_verify_native::prove::protocol_pcs_config()
}

// ---------------------------------------------------------------------------
// JSON 线格式
// ---------------------------------------------------------------------------

/// M31 坐标（u32 原值，恒 < 2^31）。
pub type M31J = u32;
/// QM31 = 4 × M31（(c0,c1,c2,c3) = (re.0, re.1, im.0, im.1)）。
pub type QM31J = [M31J; 4];
/// felt252，0x + 64 hex。
pub type FeltJ = String;
/// CirclePoint<SecureField>（x, y 各 QM31）。
pub type PointJ = [QM31J; 2];

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FriWrapWitness {
    pub log_size: u32,
    pub lifting_log_size: u32,
    pub max_log_degree_bound: u32,
    pub n_fri_layers: usize,
    pub tree_cols: [usize; 2]
    ,/// 每列 OOD 采样数（trace 列 → quotient 列 → composition 列；列间可不同）。
    pub ood_col_lens: Vec<usize>,
    pub n_query_positions: usize,

    // ---- 公开段 ----
    pub claim: ClaimJson,
    pub empty_tree_root: FeltJ,
    pub trace_root: FeltJ,
    pub quotient_root: FeltJ,
    pub fri_roots: Vec<FeltJ>,
    pub last_layer_poly: QM31J,
    pub ood_values: Vec<QM31J>,
    /// 与 ood_values 一一对应的采样点（框架 mask 点 + composition OOD 点）。
    /// v1 作为见证字段存取（语义上由 oods_point + AIR mask 决定，stage-2 进约束）。
    pub ood_points: Vec<PointJ>,
    pub pow_nonce: u64,
    pub queries: Vec<usize>,

    // ---- 见证段 ----
    pub pcs_trees: [TreeWitness; 2],
    pub fri_layers: Vec<FriLayerWitness>,
    pub derived: DerivedJson,
    pub tables: QuotientTables,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ClaimJson {
    pub hand_binding: FeltJ,
    pub payload_digest: FeltJ,
    pub cairo_program_hash: FeltJ,
    pub counts: [u32; 4],
    pub log_size: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TreeWitness {
    pub leaf_rows: Vec<Vec<M31J>>,
    pub hash_witness: Vec<FeltJ>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FriLayerWitness {
    pub subset_rows: Vec<[QM31J; 2]>,
    pub hash_witness: Vec<FeltJ>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DerivedJson {
    pub random_coeff_a: QM31J,
    pub ood_point: PointJ,
    pub random_coeff_b: QM31J,
    pub alphas: Vec<QM31J>,
    pub raw_query_words: Vec<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct QuotientTables {
    pub per_query: Vec<QueryBatchConstants>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct QueryBatchConstants {
    pub batches: Vec<BatchConstants>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BatchConstants {
    pub point: PointJ,
    /// 分母逆（CM31 = 2 × M31）。
    pub denom_inv: [M31J; 2],
    pub entries: Vec<NumEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NumEntry {
    /// 全局列索引（trace 0..17，quotient 17..25）。
    pub column_index: usize,
    pub a: QM31J,
    pub b: QM31J,
    pub c: QM31J,
}

// ---------------------------------------------------------------------------
// stwo 类型 ↔ JSON
// ---------------------------------------------------------------------------

fn m31j(v: BaseField) -> M31J {
    v.0
}

fn from_m31j(v: M31J) -> BaseField {
    BaseField::from_u32_unchecked(v)
}

fn qm31j(v: SecureField) -> QM31J {
    let a = v.to_m31_array();
    [a[0].0, a[1].0, a[2].0, a[3].0]
}

fn from_qm31j(v: &QM31J) -> SecureField {
    SecureField::from_m31_array([from_m31j(v[0]), from_m31j(v[1]), from_m31j(v[2]), from_m31j(v[3])])
}

fn pointj(p: &stwo::core::circle::CirclePoint<SecureField>) -> PointJ {
    [qm31j(p.x), qm31j(p.y)]
}

fn feltj(v: &Felt252) -> FeltJ {
    crate::felt::felt_to_hex(v)
}

fn from_feltj(s: &str) -> Result<Felt252> {
    crate::felt::felt_from_hex(s)
}

fn claim_json(claim: &HandBatchClaim) -> ClaimJson {
    ClaimJson {
        hand_binding: feltj(&felt_from_starknet(&claim.hand_binding)),
        payload_digest: feltj(&felt_from_starknet(&claim.payload_digest)),
        cairo_program_hash: feltj(&felt_from_starknet(&claim.cairo_program_hash)),
        counts: [claim.counts.n_own, claim.counts.n_reveal, claim.counts.n_leave, claim.counts.n_recon],
        log_size: claim.log_size,
    }
}

pub fn claim_from_json(j: &ClaimJson) -> Result<HandBatchClaim> {
    let felt = |s: &str| -> Result<starknet_crypto::Felt> { Ok(felt_to_starknet(&from_feltj(s)?)) };
    Ok(HandBatchClaim {
        hand_binding: felt(&j.hand_binding)?,
        payload_digest: felt(&j.payload_digest)?,
        counts: hand_verify_native::air::KindCounts {
            n_own: j.counts[0],
            n_reveal: j.counts[1],
            n_leave: j.counts[2],
            n_recon: j.counts[3],
        },
        log_size: j.log_size,
        cairo_program_hash: felt(&j.cairo_program_hash)?,
    })
}

// ---------------------------------------------------------------------------
// JSON 驱动的 Poseidon252 通道复刻（与 stwo Poseidon252Channel 逐位一致；
// 一致性由 extract-vs-derive 差分测试钉死）
// ---------------------------------------------------------------------------

fn f_u32(v: u32) -> StarkFelt {
    StarkFelt::from(v)
}

fn pow31() -> StarkFelt {
    StarkFelt::from(1u64 << 31)
}

fn pow32() -> StarkFelt {
    StarkFelt::from(2u32).pow(32u32)
}

/// felt252 大端字节右移 n 位（n ≤ 64；用于 2^31 / 2^32 的 floor-div）。
fn felt_shr_be(f: &StarkFelt, n: usize) -> StarkFelt {
    let b = StarkFelt::to_bytes_be(f);
    let mut out = [0u8; 32];
    for i in 0..32 {
        let src = i + n / 8;
        if src < 32 {
            let mut byte = b[src] << (n % 8);
            if src + 1 < 32 && n % 8 != 0 {
                byte |= b[src + 1] >> (8 - n % 8);
            }
            out[i] = byte;
        }
    }
    StarkFelt::from_bytes_be(&out)
}

fn felt_low31(f: &StarkFelt) -> u32 {
    let b = StarkFelt::to_bytes_be(f);
    (b[31] as u32) | (((b[30] & 0x7F) as u32) << 8)
}

fn felt_low32(f: &StarkFelt) -> u32 {
    let b = StarkFelt::to_bytes_be(f);
    u32::from_be_bytes([b[28], b[29], b[30], b[31]])
}

fn parse_felt(s: &str) -> anyhow::Result<StarkFelt> {
    Ok(crate::felt::felt_to_starknet(&crate::felt::felt_from_hex(s)?))
}

/// stwo 哈希（starknet-ff FieldElement）→ 本仓 Felt252（按 32B 大端转换）。
fn ff_to_feltj(f: &starknet_ff::FieldElement) -> FeltJ {
    let stark = StarkFelt::from_bytes_be(&f.to_bytes_be());
    crate::felt::felt_to_hex(&crate::felt::felt_from_starknet(&stark))
}

#[derive(Debug, Clone)]
pub struct ChannelReplica {
    pub digest: StarkFelt,
    pub n_draws: u32,
}

impl ChannelReplica {
    pub fn new() -> Self {
        Self { digest: StarkFelt::ZERO, n_draws: 0 }
    }

    fn draw_felt252(&mut self) -> StarkFelt {
        let mut state = [self.digest, f_u32(self.n_draws), StarkFelt::THREE];
        starknet_crypto::poseidon_permute_comp(&mut state);
        self.n_draws += 1;
        state[0]
    }

    pub fn mix_root(&mut self, root: StarkFelt) {
        self.digest = starknet_crypto::poseidon_hash(self.digest, root);
    }

    /// QM31 两两打包（8×M31，shift-31，前缀 digest，一次 hash_many）。
    pub fn mix_felts(&mut self, felts: &[SecureField]) {
        let shift = pow31();
        let mut res: Vec<StarkFelt> = Vec::with_capacity(felts.len() / 2 + 2);
        res.push(self.digest);
        for chunk in felts.chunks(2) {
            let packed = chunk
                .iter()
                .flat_map(|x| x.to_m31_array())
                .fold(StarkFelt::ONE, |cur, y| cur * shift.clone() + f_u32(y.0));
            res.push(packed);
        }
        self.digest = starknet_crypto::poseidon_hash_many(&res);
    }

    pub fn mix_u32s(&mut self, data: &[u32]) {
        let shift = pow32();
        let padding_len = 6 - ((data.len() + 6) % 7);
        let mut felts: Vec<StarkFelt> = data
            .iter()
            .chain(std::iter::repeat_n(&0u32, padding_len))
            .collect::<Vec<_>>()
            .chunks(7)
            .map(|chunk| {
                chunk
                    .iter()
                    .fold(StarkFelt::ZERO, |cur, y| cur * shift.clone() + f_u32(**y))
            })
            .collect();
        if padding_len != 0 {
            let last = felts.last_mut().unwrap();
            *last += StarkFelt::from((7 - padding_len) as u64)
                * (StarkFelt::from(1u128 << 124) * StarkFelt::from(1u128 << 124));
        }
        let mut all = Vec::with_capacity(felts.len() + 1);
        all.push(self.digest);
        all.extend(felts);
        self.digest = starknet_crypto::poseidon_hash_many(&all);
    }

    pub fn mix_u64(&mut self, value: u64) {
        self.digest = starknet_crypto::poseidon_hash(self.digest, StarkFelt::from(value));
    }

    fn draw_base_felts(&mut self) -> [BaseField; 8] {
        let mut cur = self.draw_felt252();
        let u32s: [u32; 8] = std::array::from_fn(|_| {
            let res = felt_low31(&cur);
            cur = felt_shr_be(&cur, 31);
            res
        });
        u32s.map(BaseField::from_u32_unchecked)
    }

    pub fn draw_secure_felt(&mut self) -> SecureField {
        let felts = self.draw_base_felts();
        SecureField::from_m31_array([felts[0], felts[1], felts[2], felts[3]])
    }

    pub fn draw_u32s(&mut self) -> Vec<u32> {
        let mut cur = self.draw_felt252();
        let words: [u32; 7] = std::array::from_fn(|_| {
            let res = felt_low32(&cur);
            cur = felt_shr_be(&cur, 32);
            res
        });
        words.to_vec()
    }

    pub fn verify_pow_nonce(&self, n_bits: u32, nonce: u64) -> bool {
        let prefixed = starknet_crypto::poseidon_hash_many(&[
            StarkFelt::from(0x1234_5678u64),
            self.digest,
            f_u32(n_bits),
        ]);
        let hash = starknet_crypto::poseidon_hash(prefixed, StarkFelt::from(nonce));
        let bytes = starknet_crypto::Felt::to_bytes_be(&hash);
        let n_zeros = u128::from_be_bytes(bytes[16..].try_into().unwrap()).trailing_zeros();
        n_zeros >= n_bits
    }
}

impl Default for ChannelReplica {
    fn default() -> Self {
        Self::new()
    }
}

/// 派生结果（原生类型，对应 `DerivedJson`）。
pub struct DerivedNative {
    pub random_coeff_a: SecureField,
    pub ood_point: stwo::core::circle::CirclePoint<SecureField>,
    pub random_coeff_b: SecureField,
    pub alphas: Vec<SecureField>,
    pub raw_query_words: Vec<u32>,
    pub queries: Vec<usize>,
}

/// 从 JSON 公开段完整重推导通道（顺序 = stwo verify 流程）。
pub fn derive_channel(w: &FriWrapWitness) -> Result<DerivedNative> {
    let claim = claim_from_json(&w.claim)?;
    let mut ch = ChannelReplica::new();
    let mut words: Vec<u32> = Vec::with_capacity(32);
    for f in [claim.hand_binding, claim.payload_digest, claim.cairo_program_hash] {
        words.extend(
            felt_to_be_bytes(&felt_from_starknet(&f))
                .chunks_exact(4)
                .map(|c| u32::from_be_bytes([c[0], c[1], c[2], c[3]])),
        );
    }
    words.extend_from_slice(&[
        claim.counts.n_own,
        claim.counts.n_reveal,
        claim.counts.n_leave,
        claim.counts.n_recon,
    ]);
    words.push(claim.log_size);
    ch.mix_u32s(&words);
    ch.mix_root(felt_to_starknet(&from_feltj(&w.empty_tree_root)?));
    ch.mix_root(felt_to_starknet(&from_feltj(&w.trace_root)?));
    let random_coeff_a = ch.draw_secure_felt();
    ch.mix_root(felt_to_starknet(&from_feltj(&w.quotient_root)?));
    let ood_point = {
        // CirclePoint::get_random_point 的参数化复刻（t = draw，x=(1−t²)/(1+t²)，y=2t/(1+t²)）
        let t = ch.draw_secure_felt();
        use stwo::core::fields::FieldExpOps;
        let one = SecureField::from(1u32);
        let t_sq = t.clone().square();
        let inv = (t_sq.clone() + one.clone()).inverse();
        stwo::core::circle::CirclePoint {
            x: (one - t_sq) * inv,
            y: (t.clone() + t) * inv,
        }
    };
    let ood: Vec<SecureField> = w.ood_values.iter().map(from_qm31j).collect();
    ch.mix_felts(&ood);
    let random_coeff_b = ch.draw_secure_felt();
    if w.fri_roots.len() != w.n_fri_layers {
        bail!("fri_roots count mismatch");
    }
    // 协议交错序：mix_root(L0) → α0 → mix_root(I_i) → α_{i+1} …（与 FriProver 一致）
    let mut alphas = Vec::with_capacity(w.n_fri_layers);
    for r in &w.fri_roots {
        ch.mix_root(felt_to_starknet(&from_feltj(r)?));
        alphas.push(ch.draw_secure_felt());
    }
    ch.mix_felts(std::slice::from_ref(&from_qm31j(&w.last_layer_poly)));
    if !ch.verify_pow_nonce(POW_BITS, w.pow_nonce) {
        bail!("pow check failed");
    }
    ch.mix_u64(w.pow_nonce);
    let mut raw = Vec::new();
    while raw.len() < N_QUERIES {
        raw.extend(ch.draw_u32s());
    }
    raw.truncate(N_QUERIES);
    let mask = (1usize << w.lifting_log_size) - 1;
    let raw: Vec<u32> = raw.into_iter().map(|x| x & mask as u32).collect();
    let queries: Vec<usize> =
        BTreeSet::from_iter(raw.iter().map(|x| *x as usize)).into_iter().collect();
    Ok(DerivedNative {
        random_coeff_a,
        ood_point,
        random_coeff_b,
        alphas,
        raw_query_words: raw,
        queries,
    })
}

// ---------------------------------------------------------------------------
// 商常量表（电路综合与 verify_ref 共用；几何/系数走 stwo pub API）
// ---------------------------------------------------------------------------

pub fn build_tables(
    column_log_sizes: &TreeVec<Vec<u32>>,
    samples: &TreeVec<Vec<Vec<PointSample>>>,
    random_coeff_b: SecureField,
    lifting_log_size: u32,
    queries: &[usize],
) -> Result<QuotientTables> {
    let swr = build_samples_with_randomness_and_periodicity(
        samples,
        column_log_sizes.clone().0.into_iter().map(IntoIterator::into_iter).collect(),
        lifting_log_size,
        random_coeff_b,
    );
    let col_refs: Vec<&Vec<(PointSample, SecureField)>> = swr.0.iter().flatten().collect();
    let batches: Vec<ColumnSampleBatch> = ColumnSampleBatch::new_vec(&col_refs);
    let qconst = quotient_constants(&batches);
    let lifting_domain = CanonicCoset::new(lifting_log_size).circle_domain();
    let mut per_query = Vec::with_capacity(queries.len());
    for &pos in queries {
        let domain_point = lifting_domain.at(bit_rev(pos, lifting_log_size));
        let points: Vec<_> = batches.iter().map(|b| b.point).collect();
        let dinv = denominator_inverses(&points, domain_point);
        let mut qb = QueryBatchConstants { batches: Vec::with_capacity(batches.len()) };
        for (bi, batch) in batches.iter().enumerate() {
            let entries = batch
                .cols_vals_randpows
                .iter()
                .zip(&qconst.line_coeffs[bi])
                .map(|(nd, (a, b, c))| NumEntry {
                    column_index: nd.column_index,
                    a: qm31j(*a),
                    b: qm31j(*b),
                    c: qm31j(*c),
                })
                .collect();
            qb.batches.push(BatchConstants {
                point: pointj(&batch.point),
                denom_inv: [dinv[bi].0 .0, dinv[bi].1 .0],
                entries,
            });
        }
        per_query.push(qb);
    }
    Ok(QuotientTables { per_query })
}

/// 商累积（表驱动——与电路同构）：∑_batch (Σ_e value·c − (a·p.y + b))·d⁻¹。
pub fn accumulate_quotients(
    table: &QueryBatchConstants,
    queried_values_at_row: &[BaseField],
    domain_y: BaseField,
) -> SecureField {
    let mut acc = SecureField::from(0u32);
    for batch in &table.batches {
        let mut numerator = SecureField::from(0u32);
        for e in &batch.entries {
            let v = queried_values_at_row[e.column_index];
            let c = from_qm31j(&e.c);
            let value = SecureField::from_m31_array([c.0 .0 * v, c.0 .1 * v, c.1 .0 * v, c.1 .1 * v]);
            let linear = from_qm31j(&e.a) * domain_y + from_qm31j(&e.b);
            numerator = numerator + value - linear;
        }
        let d = CM31(from_m31j(batch.denom_inv[0]), from_m31j(batch.denom_inv[1]));
        acc = numerator.mul_cm31(d) + acc;
    }
    acc
}

// ---------------------------------------------------------------------------
// 叶子打包 + Merkle 遍历（vcs_lifted 语义复刻）
// ---------------------------------------------------------------------------

/// M31 行 → packed felt 词列表（8-limb 分块 + 余块长度填充）。
/// 复刻 construct_felt252_from_m31s + update_leaf/finalize 的海绵等价式：
/// 叶哈希 = poseidon_hash_many(词列表)。
pub fn pack_m31_words(row: &[M31J]) -> Vec<StarkFelt> {
    row.chunks(8)
        .map(|chunk| {
            let mut felt = StarkFelt::ZERO;
            for limb in chunk {
                felt = felt * pow31() + f_u32(*limb);
            }
            if chunk.len() < 8 {
                felt += StarkFelt::from(chunk.len() as u64)
                    * (StarkFelt::from(1u128 << 124) * StarkFelt::from(1u128 << 124));
            }
            felt
        })
        .collect()
}

pub fn leaf_hash(row: &[M31J]) -> StarkFelt {
    starknet_crypto::poseidon_hash_many(&pack_m31_words(row))
}

/// vcs_lifted MerkleVerifierLifted::verify 的遍历复刻：自底向上配对/取兄弟，
/// 消费 hash_witness，校验根。
fn merkle_walk(
    root: StarkFelt,
    positions: &[usize],
    leaf_hashes: &[StarkFelt],
    hash_witness: &[FeltJ],
    height: u32,
) -> Result<()> {
    if height == 0 {
        if !hash_witness.is_empty() {
            bail!("witness too long (height 0)");
        }
        return Ok(());
    }
    let mut prev: Vec<(usize, StarkFelt)> = positions
        .iter()
        .zip(leaf_hashes)
        .map(|(p, h)| (*p, *h))
        .collect();
    let mut wit = hash_witness
        .iter()
        .map(|s| parse_felt(s))
        .collect::<Result<Vec<_>>>()?;
    wit.reverse();
    for _ in 0..height {
        let mut curr: Vec<(usize, StarkFelt)> = Vec::new();
        let mut i = 0;
        while i < prev.len() {
            if i + 1 < prev.len() && prev[i].0 ^ 1 == prev[i + 1].0 {
                let h = starknet_crypto::poseidon_hash(prev[i].1, prev[i + 1].1);
                curr.push((prev[i].0 >> 1, h));
                i += 2;
            } else {
                let w = wit.pop().ok_or_else(|| anyhow!("merkle witness short"))?;
                let (l, r) =
                    if prev[i].0 & 1 == 0 { (prev[i].1, w) } else { (w, prev[i].1) };
                curr.push((prev[i].0 >> 1, starknet_crypto::poseidon_hash(l, r)));
                i += 1;
            }
        }
        prev = curr;
    }
    if !wit.is_empty() {
        bail!("merkle witness too long");
    }
    if prev.len() != 1 || prev[0].0 != 0 {
        bail!("walk did not reach single root");
    }
    if prev[0].1 != root {
        bail!("merkle root mismatch");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// 提取：HandBatchProof → FriWrapWitness
// ---------------------------------------------------------------------------

/// 查询按子集（>>1 同组）分组，返回升序 (start, 组内查询位置)。
pub fn group_subsets(positions: &[usize]) -> Vec<(usize, Vec<usize>)> {
    let mut out: Vec<(usize, Vec<usize>)> = Vec::new();
    for &q in positions {
        let s = (q >> 1) << 1;
        match out.last_mut() {
            Some((st, qs)) if *st == s => qs.push(q),
            _ => out.push((s, vec![q])),
        }
    }
    out
}

/// 位置折叠 n 层（>>n）后去重升序。
pub fn fold_queries(positions: &[usize], n: u32) -> Vec<usize> {
    let mut out: Vec<usize> = positions.iter().map(|q| q >> n).collect();
    out.sort_unstable();
    out.dedup();
    out
}

pub fn bit_rev(i: usize, log_size: u32) -> usize {
    if log_size == 0 {
        0
    } else {
        i.reverse_bits() >> (usize::BITS - log_size)
    }
}

pub fn extract(hand: &HandBatchProof) -> Result<FriWrapWitness> {
    let claim = hand.claim;
    let proof = &hand.stark_proof;
    let config = protocol_pcs_config();
    let blowup = config.fri_config.log_blowup_factor;
    let fold_step = config.fri_config.fold_step;

    // 组件与尺寸
    let mut allocator = TraceLocationAllocator::default();
    let component = FrameworkComponent::new(
        &mut allocator,
        HandBatchEval::new(&claim),
        SecureField::from(0u32),
    );
    let components = stwo::core::air::Components {
        components: vec![&component],
        n_preprocessed_columns: 0,
    };
    let comp_bound = components.composition_log_degree_bound();
    let split_bound = comp_bound
        .checked_sub(COMPOSITION_LOG_SPLIT)
        .ok_or_else(|| anyhow!("composition bound < split"))?;
    let lifting_log_size =
        get_lifting_log_size(&config, split_bound + blowup);
    let max_log_degree_bound = lifting_log_size - blowup;
    let n_inner = (max_log_degree_bound - fold_step - LOG_LAST_LAYER) as usize;
    let n_fri_layers = 1 + n_inner;

    let commitments = &proof.commitments.0;
    if commitments.len() != 3 {
        bail!("expect 3 trees, got {}", commitments.len());
    }

    // ---- 通道（stwo 原生，独立事实源） ----
    let mut ch = Poseidon252Channel::default();
    claim.mix_into(&mut ch);
    Poseidon252MerkleChannel::mix_root(&mut ch, commitments[0]);
    Poseidon252MerkleChannel::mix_root(&mut ch, commitments[1]);
    let random_coeff_a = ch.draw_secure_felt();
    Poseidon252MerkleChannel::mix_root(&mut ch, commitments[2]);
    let oods_point = stwo::core::circle::CirclePoint::<SecureField>::get_random_point(&mut ch);
    let mut sample_points = components.mask_points(oods_point, max_log_degree_bound, false);
    sample_points.push(vec![vec![oods_point]; 2 * stwo::core::fields::qm31::SECURE_EXTENSION_DEGREE]);
    // verify_values：先混入全部 OOD 采样值，再画 RLC 系数
    let sampled_flat: Vec<SecureField> = proof
        .sampled_values
        .0
        .iter()
        .flat_map(|t| t.iter())
        .flat_map(|c| c.iter())
        .copied()
        .collect();
    ch.mix_felts(&sampled_flat);
    let random_coeff_b = ch.draw_secure_felt();

    let fri = &proof.fri_proof;
    Poseidon252MerkleChannel::mix_root(&mut ch, fri.first_layer.commitment);
    let mut alphas = vec![ch.draw_secure_felt()];
    for layer in &fri.inner_layers {
        Poseidon252MerkleChannel::mix_root(&mut ch, layer.commitment);
        alphas.push(ch.draw_secure_felt());
    }
    ch.mix_felts(&fri.last_layer_poly);

    if !ch.verify_pow_nonce(POW_BITS, proof.proof_of_work) {
        bail!("pow nonce invalid in source proof");
    }
    ch.mix_u64(proof.proof_of_work);
    let raw_positions = draw_queries(&mut ch, lifting_log_size, N_QUERIES);
    let queries: Vec<usize> =
        BTreeSet::from_iter(raw_positions.iter().copied()).into_iter().collect();
    let raw_words: Vec<u32> = raw_positions.iter().map(|x| *x as u32).collect();

    // ---- 列尺寸 ----
    let bounds = component.trace_log_degree_bounds();
    let trace_sizes: Vec<u32> = bounds[1].clone();
    if trace_sizes.len() != N_COLUMNS {
        bail!("trace col count {} != {}", trace_sizes.len(), N_COLUMNS);
    }
    let mut column_log_sizes: Vec<Vec<u32>> = Vec::new();
    column_log_sizes.push(vec![]);
    column_log_sizes.push(trace_sizes.iter().map(|l| l + blowup).collect());
    column_log_sizes.push(vec![max_log_degree_bound + blowup; N_QUOTIENT_COLS]);
    let column_log_sizes = TreeVec(column_log_sizes);

    // ---- 采样点/值 ----
    let samples: TreeVec<Vec<Vec<PointSample>>> = TreeVec(
        sample_points
            .0
            .iter()
            .zip(proof.sampled_values.0.iter())
            .map(|(pts_tree, val_tree)| {
                pts_tree
                    .iter()
                    .zip(val_tree.iter())
                    .map(|(pts, vals)| {
                        pts.iter()
                            .zip(vals.iter())
                            .map(|(p, v)| PointSample { point: *p, value: *v })
                            .collect()
                    })
                    .collect()
            })
            .collect(),
    );

    let mut ood_values: Vec<QM31J> = Vec::new();
    let mut ood_points: Vec<PointJ> = Vec::new();
    let mut ood_col_lens: Vec<usize> = Vec::new();
    for (tree_idx, tree) in proof.sampled_values.0.iter().enumerate() {
        for (ci, col) in tree.iter().enumerate() {
            if col.is_empty() {
                continue;
            }
            ood_col_lens.push(col.len());
            for (si, v) in col.iter().enumerate() {
                ood_values.push(qm31j(*v));
                ood_points.push(pointj(&sample_points.0[tree_idx][ci][si]));
            }
        }
    }

    // ---- 首层期望值（stwo fri_answers） ----
    let expected_first = fri_answers(
        column_log_sizes.clone(),
        samples.clone(),
        random_coeff_b,
        &queries,
        proof.queried_values.clone(),
        lifting_log_size,
    )
    .map_err(|e| anyhow!("fri_answers: {e}"))?;

    // ---- FRI 层：子集行 + 折叠链 ----
    let first_domain = CanonicCoset::new(lifting_log_size).circle_domain();
    let mut layer_query_values: Vec<SecureField> = expected_first;
    let mut cur_positions: Vec<usize> = queries.clone();
    let mut fri_layer_witnesses: Vec<FriLayerWitness> = Vec::new();

    for li in 0..n_fri_layers {
        let layer_proof = if li == 0 {
            &fri.first_layer
        } else {
            &fri.inner_layers[li - 1]
        };
        let subsets = group_subsets(&cur_positions);
        if subsets.is_empty() {
            bail!("empty subsets at layer {li}");
        }
        // 子集行
        let mut wit = layer_proof.fri_witness.iter();
        let mut qit = layer_query_values.iter();
        let mut rows: Vec<[QM31J; 2]> = Vec::with_capacity(subsets.len());
        for (start, qs) in &subsets {
            let mut row = [[0u32; 4]; 2];
            for (off, pos) in [*start, start + 1].into_iter().enumerate() {
                if qs.contains(&pos) {
                    let v = qit.next().ok_or_else(|| anyhow!("query evals exhausted"))?;
                    row[off] = qm31j(*v);
                } else {
                    let v = wit.next().ok_or_else(|| anyhow!("fri witness exhausted"))?;
                    row[off] = qm31j(*v);
                }
            }
            rows.push(row);
        }
        if wit.next().is_some() {
            bail!("fri witness not fully consumed at layer {li}");
        }
        let hash_witness: Vec<FeltJ> = layer_proof
            .decommitment
            .hash_witness
            .iter()
            .map(|h| ff_to_feltj(h))
            .collect();
        fri_layer_witnesses.push(FriLayerWitness { subset_rows: rows.clone(), hash_witness });

        // 折叠到下一层
        let mut next_vals: Vec<SecureField> = Vec::with_capacity(subsets.len());
        for (si, (start, _)) in subsets.iter().enumerate() {
            let row = &rows[si];
            let v0 = from_qm31j(&row[0]);
            let v1 = from_qm31j(&row[1]);
            let folded = if li == 0 {
                let initial = first_domain.index_at(bit_rev(*start, lifting_log_size));
                let cd = CircleDomain::new(stwo::core::circle::Coset::new(initial, FOLD_STEP - 1));
                stwo::core::fri::fold_circle_into_line(&[v0, v1], cd, alphas[0])[0]
            } else {
                let dom_log = lifting_log_size - li as u32;
                let src = LineDomain::new(stwo::core::circle::Coset::half_odds(dom_log));
                let initial = src.coset().index_at(bit_rev(*start, dom_log));
                let sub = LineDomain::new(stwo::core::circle::Coset::new(initial, FOLD_STEP));
                stwo::core::fri::fold_coset(vec![v0, v1], sub, alphas[li])
            };
            next_vals.push(folded);
        }
        layer_query_values = next_vals;
        cur_positions = fold_queries(&cur_positions, fold_step);
    }

    // 末层常数检查
    let last_const = fri.last_layer_poly[0];
    for v in &layer_query_values {
        if *v != last_const {
            bail!("last layer mismatch in source proof");
        }
    }

    // ---- PCS 两棵树 ----
    let mut pcs_trees = [
        TreeWitness { leaf_rows: vec![], hash_witness: vec![] },
        TreeWitness { leaf_rows: vec![], hash_witness: vec![] },
    ];
    for (ti, tree_idx) in [1usize, 2].into_iter().enumerate() {
        let cols = &proof.queried_values.0[tree_idx];
        let mut rows = Vec::with_capacity(queries.len());
        for qi in 0..queries.len() {
            let row: Vec<M31J> = cols.iter().map(|c| m31j(c[qi])).collect();
            rows.push(row);
        }
        let hash_witness: Vec<FeltJ> = proof.decommitments.0[tree_idx]
            .hash_witness
            .iter()
            .map(|h| ff_to_feltj(h))
            .collect();
        pcs_trees[ti] = TreeWitness { leaf_rows: rows, hash_witness };
    }

    // ---- 商表 ----
    let tables = build_tables(
        &column_log_sizes,
        &samples,
        random_coeff_b,
        lifting_log_size,
        &queries,
    )?;

    Ok(FriWrapWitness {
        log_size: claim.log_size,
        lifting_log_size,
        max_log_degree_bound,
        n_fri_layers,
        tree_cols: [N_COLUMNS, N_QUOTIENT_COLS],
        ood_col_lens,
        n_query_positions: queries.len(),
        claim: claim_json(&claim),
        empty_tree_root: ff_to_feltj(&commitments[0]),
        trace_root: ff_to_feltj(&commitments[1]),
        quotient_root: ff_to_feltj(&commitments[2]),
        fri_roots: std::iter::once(&fri.first_layer.commitment)
            .chain(fri.inner_layers.iter().map(|l| &l.commitment))
            .map(|h| ff_to_feltj(h))
            .collect(),
        last_layer_poly: qm31j(last_const),
        ood_values,
        ood_points,
        pow_nonce: proof.proof_of_work,
        queries,
        pcs_trees,
        fri_layers: fri_layer_witnesses,
        derived: DerivedJson {
            random_coeff_a: qm31j(random_coeff_a),
            ood_point: pointj(&oods_point),
            random_coeff_b: qm31j(random_coeff_b),
            alphas: alphas.iter().map(|a| qm31j(*a)).collect(),
            raw_query_words: raw_words,
        },
        tables,
    })
}

// ---------------------------------------------------------------------------
// 参照验证器：只用 FriWrapWitness 独立验证
// ---------------------------------------------------------------------------

pub fn verify_ref(w: &FriWrapWitness) -> Result<()> {
    // 尺寸一致性
    let expected_inner = (w.max_log_degree_bound - FOLD_STEP - LOG_LAST_LAYER) as usize;
    if w.n_fri_layers != 1 + expected_inner {
        bail!("n_fri_layers {} != {}", w.n_fri_layers, 1 + expected_inner);
    }
    if w.queries.len() != w.n_query_positions || w.queries.len() > N_QUERIES {
        bail!("query count inconsistent");
    }
    for tree in &w.pcs_trees {
        if tree.leaf_rows.len() != w.queries.len() {
            bail!("pcs tree row count");
        }
        for row in &tree.leaf_rows {
            if row.len() != w.tree_cols[0] && row.len() != w.tree_cols[1] {
                bail!("pcs tree row width");
            }
        }
    }
    let claim = claim_from_json(&w.claim)?;
    if HandBatchClaim::log_size_for(claim.counts) != claim.log_size || claim.log_size != w.log_size
    {
        bail!("claim log_size inconsistent");
    }

    // 通道重推导
    let d = derive_channel(w)?;
    if qm31j(d.random_coeff_a) != w.derived.random_coeff_a {
        bail!("random_coeff_a mismatch");
    }
    if pointj(&d.ood_point) != w.derived.ood_point {
        bail!("ood point mismatch");
    }
    if qm31j(d.random_coeff_b) != w.derived.random_coeff_b {
        bail!("random_coeff_b mismatch");
    }
    let alphas_j: Vec<QM31J> = d.alphas.iter().map(|a| qm31j(*a)).collect();
    if alphas_j != w.derived.alphas {
        bail!("alphas mismatch");
    }
    if d.queries != w.queries {
        bail!("query positions mismatch");
    }
    if d.raw_query_words != w.derived.raw_query_words {
        bail!("raw query words mismatch");
    }

    // 商表重算断言
    let column_log_sizes = TreeVec(vec![
        vec![],
        vec![w.log_size + LOG_BLOWUP; w.tree_cols[0]],
        vec![w.max_log_degree_bound + LOG_BLOWUP; w.tree_cols[1]],
    ]);
    // 从见证 OOD 值+点重建 samples（布局 = extract 展平顺序；composition
    // 伪树点必须等于派生 ood_point——这里顺带钉住一部分 mask 语义）。
    let oods_point = d.ood_point;
    let n_comp_cols = 2 * stwo::core::fields::qm31::SECURE_EXTENSION_DEGREE;
    let n_tree_cols_total = w.tree_cols[0] + w.tree_cols[1];
    // stwo 2.3 无独立商树：tree2 = composition 承诺（8 列），其 OOD 掩码即
    // ood_values 的最后 8 项（左/右半坐标）。
    if w.ood_values.len() != w.ood_points.len()
        || w.ood_col_lens.len() != n_tree_cols_total
    {
        bail!("ood layout mismatch");
    }
    for k in 0..n_comp_cols {
        let pi = w.ood_col_lens.iter().sum::<usize>() - n_comp_cols + k;
        if w.ood_points[pi] != pointj(&oods_point) {
            bail!("composition ood point != derived ood point");
        }
    }
    let mut oi = 0usize;
    let mut samples_builder: Vec<Vec<Vec<PointSample>>> = vec![vec![], vec![], vec![]];
    for (ci, &n) in w.ood_col_lens.iter().enumerate() {
        let tree_idx = if ci < w.tree_cols[0] { 1 } else { 2 };
        let mut col = Vec::with_capacity(n);
        for _s in 0..n {
            col.push(PointSample {
                point: stwo::core::circle::CirclePoint {
                    x: from_qm31j(&w.ood_points[oi][0]),
                    y: from_qm31j(&w.ood_points[oi][1]),
                },
                value: from_qm31j(&w.ood_values[oi]),
            });
            oi += 1;
        }
        samples_builder[tree_idx].push(col);
    }
    let samples = TreeVec(samples_builder);
    let tables = build_tables(
        &column_log_sizes,
        &samples,
        d.random_coeff_b,
        w.lifting_log_size,
        &w.queries,
    )?;
    if tables != w.tables {
        bail!("quotient tables mismatch");
    }

    // PCS 两棵树 Merkle
    for (ti, tree) in w.pcs_trees.iter().enumerate() {
        let hashes: Vec<StarkFelt> = tree.leaf_rows.iter().map(|r| leaf_hash(r)).collect();
        let root = from_feltj(if ti == 0 { &w.trace_root } else { &w.quotient_root })?;
        merkle_walk(felt_to_starknet(&root), &w.queries, &hashes, &tree.hash_witness, w.lifting_log_size)
            .map_err(|e| anyhow!("pcs tree {ti}: {e}"))?;
    }

    // FRI 层：Merkle + 折叠链 + 首层商绑定
    let first_domain = CanonicCoset::new(w.lifting_log_size).circle_domain();
    let mut cur_positions = w.queries.clone();
    let mut next_expected: Vec<SecureField> = Vec::new();
    for (li, layer) in w.fri_layers.iter().enumerate() {
        let subsets = group_subsets(&cur_positions);
        if layer.subset_rows.len() != subsets.len() {
            bail!("layer {li}: subset row count");
        }
        let positions: Vec<usize> = subsets.iter().map(|(s, _)| *s).collect();
        let hashes: Vec<StarkFelt> =
            layer.subset_rows.iter().map(|r| leaf_hash(&[r[0].to_vec(), r[1].to_vec()].concat())).collect();
        let height = w.lifting_log_size - li as u32;
        let root = from_feltj(&w.fri_roots[li])?;
        merkle_walk(felt_to_starknet(&root), &positions, &hashes, &layer.hash_witness, height)
            .map_err(|e| anyhow!("fri layer {li}: {e}"))?;

        // 行展开（QM31 对）
        let rows: Vec<[SecureField; 2]> = layer
            .subset_rows
            .iter()
            .map(|r| [from_qm31j(&r[0]), from_qm31j(&r[1])])
            .collect();

        // 查询位置值检查
        let mut qi = 0usize;
        for (si, (start, qs)) in subsets.iter().enumerate() {
            for off in 0..2usize {
                let pos = start + off;
                if qs.contains(&pos) {
                    let got = rows[si][off];
                    let want = if li == 0 {
                        let mut row_vals: Vec<BaseField> = Vec::with_capacity(
                            w.tree_cols[0] + w.tree_cols[1],
                        );
                        row_vals.extend(w.pcs_trees[0].leaf_rows[qi].iter().map(|x| from_m31j(*x)));
                        row_vals.extend(w.pcs_trees[1].leaf_rows[qi].iter().map(|x| from_m31j(*x)));
                        let dp = first_domain.at(bit_rev(pos, w.lifting_log_size));
                        accumulate_quotients(&w.tables.per_query[qi], &row_vals, dp.y)
                    } else {
                        next_expected[qi]
                    };
                    if got != want {
                        bail!("layer {li} query {pos}: eval mismatch");
                    }
                    qi += 1;
                }
            }
            // 折叠
            let (v0, v1) = (rows[si][0], rows[si][1]);
            let folded = if li == 0 {
                let initial = first_domain.index_at(bit_rev(*start, w.lifting_log_size));
                let cd = CircleDomain::new(stwo::core::circle::Coset::new(initial, FOLD_STEP - 1));
                stwo::core::fri::fold_circle_into_line(&[v0, v1], cd, from_qm31j(&w.derived.alphas[0]))[0]
            } else {
                let dom_log = w.lifting_log_size - li as u32;
                let src = LineDomain::new(stwo::core::circle::Coset::half_odds(dom_log));
                let initial = src.coset().index_at(bit_rev(*start, dom_log));
                let sub = LineDomain::new(stwo::core::circle::Coset::new(initial, FOLD_STEP));
                stwo::core::fri::fold_coset(vec![v0, v1], sub, from_qm31j(&w.derived.alphas[li]))
            };
            next_expected.push(folded);
        }
        cur_positions = fold_queries(&cur_positions, FOLD_STEP);
        if li + 1 < w.n_fri_layers && next_expected.len() != cur_positions.len() {
            bail!("layer {} fold count {} != {}", li, next_expected.len(), cur_positions.len());
        }
    }

    // 末层常数
    let last_const = from_qm31j(&w.last_layer_poly);
    for v in &next_expected {
        if *v != last_const {
            bail!("last layer constant mismatch");
        }
    }
    if next_expected.len() != cur_positions.len() {
        bail!("last layer count");
    }
    Ok(())
}

