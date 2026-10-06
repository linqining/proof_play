//! T3-FRI 影子证明层（out/t3-fri-wrap-design.md §6 v2）。
//!
//! 电路内直接验证 stwo 的 Poseidon252（mod STARK prime）哈希需要非原生仿真
//! （实测 ~2.4k 约束/乘法，单树 480 permute 即上亿约束，不可行）——这正是
//! SP1/RISC Zero「并行小域友好承诺」配方的动机。本模块实现影子协议：
//!
//! 1. `FrPoseidon`：Hades（t=3, RF=8, RP=83, sbox x³）直接定义在 BN254 标量域上
//!    （轮常量 = starknet 常量按 <r 嵌入）——电路内全程原生（214 mul/permute）。
//! 2. `FrHash` + `ShadowChannel`：实现 stwo 的 `MerkleHasherLifted`/`MerkleChannel`
//!    /`Channel`，于是 `prove_shadow` 用 stwo 同一 prover 管线、同一 fold AIR、
//!    同一 claim，产出第二棵独立 STARK 证明（CpuBackend, Fr 哈希树）。
//! 3. `extract_shadow` / `verify_shadow`：见证提取与独立验证（与 fri_ref 同一
//!    遍历/折叠/商累积语义，哈希面换成 Fr 原生）——是电路语句的可执行规格。
//!
//! 安全语义：影子证明本身是一条完整 STARK（30 查询 + 10 PoW，与主协议同一
//! 冻结配置），电路验证其查询层；主 Poseidon252 证明仍是链下 fact-verify 的
//! 深证据。两者共享 claim 公开段。

use anyhow::{anyhow, bail, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

use starknet_crypto::Felt as StarkFelt;
use stwo::core::channel::{Channel, MerkleChannel};
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
use stwo::core::proof::StarkProof;
use stwo::core::vcs::hash::Hash as HashMarker;
use stwo::core::vcs_lifted::merkle_hasher::MerkleHasherLifted;
use stwo::core::verifier::COMPOSITION_LOG_SPLIT;
use stwo::prover::backend::{Col, Column as _};
use stwo::prover::backend::CpuBackend;
use stwo::prover::pcs::CommitmentSchemeProver;
use stwo::prover::poly::circle::{CircleEvaluation, PolyOps};
use stwo::prover::poly::BitReversedOrder;
use stwo::prover::prove;
use stwo_constraint_framework::{FrameworkComponent, TraceLocationAllocator};

use crate::felt::{fr_from_hex, fr_to_hex, Fr};
use hand_verify_native::air::{build_trace, HandBatchClaim, HandBatchEval, N_COLUMNS};

pub use crate::fri_ref::{
    BatchConstants, ClaimJson, FriLayerWitness, FeltJ, M31J, NumEntry, PointJ,
    QueryBatchConstants, QuotientTables, QM31J, TreeWitness,
};

pub const LOG_BLOWUP: u32 = 1;
pub const FOLD_STEP: u32 = 1;
pub const N_QUERIES: usize = 30;
pub const POW_BITS: u32 = 10;
pub const LOG_LAST_LAYER: u32 = 0;
pub const N_QUOTIENT_COLS: usize = 8;

// ---------------------------------------------------------------------------
// FrPoseidon：BN254 Fr 上的 Hades（starknet 常量按 <r 嵌入）
// ---------------------------------------------------------------------------

/// 宿主参照：一轮 Hades（与 crate::poseidon 同布局，域换成 Fr）。
pub fn fr_hades(state: &mut [Fr; 3], rc: &[Fr; 107]) {
    const N_FULL: usize = 8;
    const N_PARTIAL: usize = 83;
    let sbox3 = |x: Fr| {
        let x2 = x * x;
        x2 * x
    };
    let mut idx = 0usize;
    let mix = |s: &mut [Fr; 3]| {
        let t = s[0] + s[1] + s[2];
        let s0 = t + s[0] + s[0];
        let s1 = t - s[1] - s[1];
        let s2 = t - s[2] - s[2] - s[2];
        *s = [s0, s1, s2];
    };
    let mut full = |state: &mut [Fr; 3], rc: &[Fr; 107], idx: &mut usize| {
        for i in 0..3 {
            state[i] = sbox3(state[i] + rc[*idx + i]);
        }
        mix(state);
        *idx += 3;
    };
    for _ in 0..N_FULL / 2 {
        full(state, rc, &mut idx);
    }
    for _ in 0..N_PARTIAL {
        state[2] = sbox3(state[2] + rc[idx]);
        idx += 1;
        mix(state);
    }
    for _ in 0..N_FULL / 2 {
        full(state, rc, &mut idx);
    }
    debug_assert_eq!(idx, 107);
}

/// starknet 轮常量 → Fr 表（启动期解析一次）。
pub static FR_RC: std::sync::LazyLock<[Fr; 107]> = std::sync::LazyLock::new(|| {
    std::array::from_fn(|i| {
        // ROUND_CONSTANTS 是 Fp252（STARK prime）元素；按 32B 大端嵌入 Fr（< r）
        Fr::from_be_bytes_mod_order(&crate::felt::felt_to_be_bytes(
            &crate::poseidon::ROUND_CONSTANTS[i],
        ))
    })
});

/// hash_many（sponge：成对吸收、耗尽补 1、末置换、取 s0）。
pub fn fr_hash_many(msgs: &[Fr], rc: &[Fr; 107]) -> Fr {
    let mut state = [Fr::from(0u8), Fr::from(0u8), Fr::from(0u8)];
    let one = Fr::from(1u8);
    let mut iter = msgs.iter();
    loop {
        match iter.next() {
            Some(v) => state[0] += v,
            None => {
                state[0] += one;
                break;
            }
        }
        match iter.next() {
            Some(v) => state[1] += v,
            None => {
                state[1] += one;
                break;
            }
        }
        fr_hades(&mut state, rc);
    }
    fr_hades(&mut state, rc);
    state[0]
}

// ---------------------------------------------------------------------------
// 影子哈希器 / 通道（实现 stwo trait）
// ---------------------------------------------------------------------------

/// 影子 Merkle 叶/节点哈希类型（ark Fr newtype）。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct FrH(pub Fr);

impl serde::Serialize for FrH {
    fn serialize<S: serde::Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_str(&fr_to_hex(&self.0))
    }
}

impl<'de> serde::Deserialize<'de> for FrH {
    fn deserialize<D: serde::Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        let s = String::deserialize(de)?;
        fr_from_hex(&s).map(FrH).map_err(serde::de::Error::custom)
    }
}

use ark_ff::PrimeField;
type BigInt4 = <ark_bn254::Fr as PrimeField>::BigInt;

impl core::fmt::Display for FrH {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", fr_to_hex(&self.0))
    }
}

impl HashMarker for FrH {}

/// 缓冲流语义：update_leaf 按 ≤16 列一块多次调用（CpuBackend build_leaves），
/// 内部 16 值（=2 词）触发一次吸收，跨调用保持 sponge 状态；finalize 吸收
/// 剩余词 + 词数，末置换。等价于 hash_many(整行打包词 ++ [词数])。
#[derive(Debug, Clone, Default)]
pub struct FrHasher {
    state: [Fr; 3],
    buffer: Vec<BaseField>,
    /// 已打包词总数（跨 update_leaf 累计；finalize 追加为 sponge 尾元素）。
    n_words: usize,
}

/// M31 行 → Fr 词（8-limb shift-31 打包；词数单独作 sponge 尾元素——比
/// starknet 的 bits[248:251] 长度填充在电路里更便宜）。
pub fn shift31_pows() -> std::sync::LazyLock<[Fr; 32]> {
    std::sync::LazyLock::new(|| {
        let mut out = [Fr::from(1u8); 32];
        for k in 1..32 {
            out[k] = out[k - 1] * Fr::from(1u64 << 31);
        }
        out
    })
}

pub fn pack_words(row: &[BaseField]) -> Vec<Fr> {
    let pows = &*shift31_pows();
    row.chunks(8)
        .map(|chunk| {
            let mut acc = Fr::from(0u8);
            for (k, limb) in chunk.iter().enumerate() {
                acc += Fr::from(limb.0) * pows[k];
            }
            acc
        })
        .collect()
}

impl MerkleHasherLifted for FrHasher {
    type Hash = FrH;

    fn hash_children((l, r): (Self::Hash, Self::Hash)) -> Self::Hash {
        let rc: &[Fr; 107] = &FR_RC;
        FrH(fr_hash_many(&[l.0, r.0], &rc))
    }

    fn update_leaf(&mut self, column_values: &[BaseField]) {
        let rc: &[Fr; 107] = &FR_RC;
        let pows = &*shift31_pows();
        self.buffer.extend_from_slice(column_values);
        let pack8 = |vals: &[BaseField]| {
            let mut acc = Fr::from(0u8);
            for (k, limb) in vals.iter().enumerate() {
                acc += Fr::from(limb.0) * pows[k];
            }
            acc
        };
        while self.buffer.len() >= 16 {
            let w0 = pack8(&self.buffer[0..8]);
            let w1 = pack8(&self.buffer[8..16]);
            self.state[0] += w0;
            self.state[1] += w1;
            let mut st = self.state;
            fr_hades(&mut st, rc);
            self.state = st;
            self.buffer.drain(0..16);
            self.n_words += 2;
        }
    }

    fn finalize(mut self) -> Self::Hash {
        let rc: &[Fr; 107] = &FR_RC;
        let pows = &*shift31_pows();
        let mut msgs: Vec<Fr> = self
            .buffer
            .chunks(8)
            .map(|chunk| {
                let mut acc = Fr::from(0u8);
                for (k, limb) in chunk.iter().enumerate() {
                    acc += Fr::from(limb.0) * pows[k];
                }
                acc
            })
            .collect();
        self.buffer.clear();
        let n = msgs.len();
        self.n_words += n;
        msgs.push(Fr::from(self.n_words as u64));
        // 从当前状态继续同一 sponge
        let mut iter = msgs.iter();
        loop {
            match iter.next() {
                Some(v) => self.state[0] += v,
                None => {
                    self.state[0] += Fr::from(1u8);
                    break;
                }
            }
            match iter.next() {
                Some(v) => self.state[1] += v,
                None => {
                    self.state[1] += Fr::from(1u8);
                    break;
                }
            }
            fr_hades(&mut self.state, rc);
        }
        fr_hades(&mut self.state, rc);
        FrH(self.state[0])
    }
}

/// 影子 Fiat–Shamir 通道（实现 stwo Channel；digest ∈ Fr）。
#[derive(Clone, Debug, Default)]
pub struct ShadowChannel {
    pub digest: Fr,
    pub n_draws: u32,
}

impl ShadowChannel {
    pub fn mix_root(&mut self, root: Fr) {
        let rc: &[Fr; 107] = &FR_RC;
        self.digest = fr_hash_many(&[self.digest, root], &rc);
    }

    fn draw_word(&mut self) -> Fr {
        let rc: &[Fr; 107] = &FR_RC;
        let mut state = [self.digest, Fr::from(self.n_draws), Fr::from(3u8)];
        self.n_draws += 1;
        fr_hades(&mut state, &rc);
        state[0]
    }
}

impl Channel for ShadowChannel {
    const BYTES_PER_HASH: usize = 31;

    fn verify_pow_nonce(&self, n_bits: u32, nonce: u64) -> bool {
        let rc: &[Fr; 107] = &FR_RC;
        let prefixed = fr_hash_many(&[Fr::from(0x1234_5678u64), self.digest, Fr::from(n_bits)], &rc);
        let hash = fr_hash_many(&[prefixed, Fr::from(nonce)], &rc);
        let repr: BigInt4 = hash.into_bigint();
        let limbs = repr.0; // [u64; 4]，LE
        // 取 bits[128..256]（与 stwo 的 bytes[16..] 口径一致）
        let hi = (limbs[2] >> 0) as u128 | ((limbs[3] as u128) << 64);
        let n_zeros = hi.trailing_zeros();
        n_zeros >= n_bits
    }

    fn mix_u32s(&mut self, data: &[u32]) {
        let rc: &[Fr; 107] = &FR_RC;
        let shift = Fr::from(1u64 << 32);
        let padding_len = 6 - ((data.len() + 6) % 7);
        let mut felts: Vec<Fr> = data
            .iter()
            .chain(std::iter::repeat_n(&0u32, padding_len))
            .collect::<Vec<_>>()
            .chunks(7)
            .map(|chunk| {
                chunk
                    .iter()
                    .rev()
                    .fold(Fr::from(0u8), |cur, y| cur * shift.clone() + Fr::from(**y))
            })
            .collect();
        if padding_len != 0 {
            let last = felts.last_mut().unwrap();
            *last += Fr::from((7 - padding_len) as u64) * Fr::from(1u128 << 124) * Fr::from(1u128 << 124);
        }
        let mut all = Vec::with_capacity(felts.len() + 1);
        all.push(self.digest);
        all.extend(felts);
        self.digest = fr_hash_many(&all, &rc);
    }

    fn mix_felts(&mut self, felts: &[SecureField]) {
        let rc: &[Fr; 107] = &FR_RC;
        let shift = Fr::from(1u64 << 31);
        let mut res: Vec<Fr> = Vec::with_capacity(felts.len() / 2 + 2);
        res.push(self.digest);
        for chunk in felts.chunks(2) {
            let packed = chunk
                .iter()
                .flat_map(|x| x.to_m31_array())
                .fold(Fr::from(1u8), |cur, y| cur * shift + Fr::from(y.0));
            res.push(packed);
        }
        self.digest = fr_hash_many(&res, &rc);
    }

    fn mix_u64(&mut self, value: u64) {
        let rc: &[Fr; 107] = &FR_RC;
        self.digest = fr_hash_many(&[self.digest, Fr::from(value)], &rc);
    }

    fn draw_secure_felt(&mut self) -> SecureField {
        let felts = self.draw_base_felts();
        SecureField::from_m31_array([felts[0], felts[1], felts[2], felts[3]])
    }

    fn draw_secure_felts(&mut self, n_felts: usize) -> Vec<SecureField> {
        (0..n_felts).map(|_| self.draw_secure_felt()).collect()
    }

    fn draw_u32s(&mut self) -> Vec<u32> {
        let w = self.draw_word();
        let repr: BigInt4 = w.into_bigint();
        let limbs = repr.0; // LE [u64;4]
        let bit = |i: usize| (limbs[i / 64] >> (i % 64)) & 1;
        (0..7)
            .map(|k| {
                let mut v = 0u32;
                for b in 0..32 {
                    v |= (bit(k * 32 + b) as u32) << b;
                }
                v
            })
            .collect()
    }
}

impl ShadowChannel {
    /// 8 × M31（2^31 进制位；影子协议定义：取低 8×31=248 位）。
    fn draw_base_felts(&mut self) -> [BaseField; 8] {
        let w = self.draw_word();
        let repr: BigInt4 = w.into_bigint();
        let limbs = repr.0;
        let bit = |i: usize| (limbs[i / 64] >> (i % 64)) & 1;
        std::array::from_fn(|k| {
            let mut v = 0u32;
            for b in 0..31 {
                v |= (bit(k * 31 + b) as u32) << b;
            }
            BaseField::from_u32_unchecked(v)
        })
    }
}

/// stwo `MerkleChannel`（root 混入 = hash_many([digest, root])）。
#[derive(Default)]
pub struct ShadowMerkleChannel;

impl MerkleChannel for ShadowMerkleChannel {
    type C = ShadowChannel;
    type H = FrHasher;

    fn mix_root(channel: &mut Self::C, root: <Self::H as MerkleHasherLifted>::Hash) {
        let rc: &[Fr; 107] = &FR_RC;
        channel.digest = fr_hash_many(&[channel.digest, root.0], &rc);
    }
}

// ---------------------------------------------------------------------------
// prove_shadow：同一 claim、同一 AIR、CpuBackend + 影子哈希
// ---------------------------------------------------------------------------

pub fn protocol_pcs_config() -> PcsConfig {
    hand_verify_native::prove::protocol_pcs_config()
}

pub struct ShadowProof {
    pub claim: HandBatchClaim,
    pub stark_proof: StarkProof<FrHasher>,
}

pub fn prove_shadow(claim: &HandBatchClaim) -> Result<ShadowProof> {
    let config = protocol_pcs_config();
    let blowup_log = config.fri_config.log_blowup_factor;
    let twiddles = CpuBackend::precompute_twiddles(
        CanonicCoset::new(claim.log_size + blowup_log).half_coset(),
    );

    let mut channel = ShadowChannel::default();
    claim.mix_into(&mut channel);

    let mut commitment_scheme =
        CommitmentSchemeProver::<CpuBackend, ShadowMerkleChannel>::new(config, &twiddles);

    // Tree 0: 空 preprocessed 树
    {
        let mut tree_builder = commitment_scheme.tree_builder();
        tree_builder.extend_evals(vec![]);
        tree_builder.commit(&mut channel);
    }
    // Tree 1: statement trace
    {
        let cols_data = build_trace(claim);
        let domain = CanonicCoset::new(claim.log_size).circle_domain();
        let mut evals = Vec::with_capacity(cols_data.len());
        for data in cols_data {
            let mut col = Col::<CpuBackend, BaseField>::zeros(
                1 << claim.log_size,
            );
            for (row, value) in data.into_iter().enumerate() {
                col.set(row, value);
            }
            evals.push(CircleEvaluation::<CpuBackend, _, BitReversedOrder>::new(domain, col));
        }
        let mut tree_builder = commitment_scheme.tree_builder();
        tree_builder.extend_evals(evals);
        tree_builder.commit(&mut channel);
    }

    let mut allocator = TraceLocationAllocator::default();
    let component = FrameworkComponent::new(
        &mut allocator,
        HandBatchEval::new(claim),
        SecureField::from(0u32),
    );

    let stark_proof = prove(&[&component], &mut channel, commitment_scheme)
        .map_err(|e| anyhow!("shadow prove error: {e}"))?;

    Ok(ShadowProof { claim: *claim, stark_proof })
}

// ---------------------------------------------------------------------------
// 见证（与 fri_ref::FriWrapWitness 同构，哈希面 = Fr hex；无派生字段——
// 通道全部原生可推导，alphas/raw words 只在测试里对照）
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ShadowWitness {
    pub log_size: u32,
    pub lifting_log_size: u32,
    pub max_log_degree_bound: u32,
    pub n_fri_layers: usize,
    pub tree_cols: [usize; 2],
    /// 每列 OOD 采样数（列间可不同：选择器列 1，累加器列 2）。
    pub ood_col_lens: Vec<usize>,
    pub n_query_positions: usize,

    pub claim: ClaimJson,
    pub empty_tree_root: FeltJ,
    pub trace_root: FeltJ,
    pub quotient_root: FeltJ,
    pub fri_roots: Vec<FeltJ>,
    pub last_layer_poly: QM31J,
    pub ood_values: Vec<QM31J>,
    pub ood_points: Vec<PointJ>,
    pub pow_nonce: u64,
    pub queries: Vec<usize>,

    pub pcs_trees: [TreeWitness; 2],
    pub fri_layers: Vec<FriLayerWitness>,
    pub tables: QuotientTables,
}

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

fn feltj(v: Fr) -> FeltJ {
    fr_to_hex(&v)
}

fn from_feltj(s: &str) -> Result<Fr> {
    fr_from_hex(s).map_err(Into::into)
}

fn pointj(p: &stwo::core::circle::CirclePoint<SecureField>) -> PointJ {
    [qm31j(p.x), qm31j(p.y)]
}

pub fn claim_json(claim: &HandBatchClaim) -> ClaimJson {
        let fe = |f: &starknet_crypto::Felt| -> Fr {
        // starknet Felt → Fr：按 32B 大端嵌入（< r）
        Fr::from_be_bytes_mod_order(&f.to_bytes_be())
    };
    ClaimJson {
        hand_binding: feltj(fe(&claim.hand_binding)),
        payload_digest: feltj(fe(&claim.payload_digest)),
        cairo_program_hash: feltj(fe(&claim.cairo_program_hash)),
        counts: [claim.counts.n_own, claim.counts.n_reveal, claim.counts.n_leave, claim.counts.n_recon],
        log_size: claim.log_size,
    }
}

pub fn bit_rev(i: usize, log_size: u32) -> usize {
    if log_size == 0 {
        0
    } else {
        i.reverse_bits() >> (usize::BITS - log_size)
    }
}

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

pub fn fold_queries(positions: &[usize], n: u32) -> Vec<usize> {
    let mut out: Vec<usize> = positions.iter().map(|q| q >> n).collect();
    out.sort_unstable();
    out.dedup();
    out
}

// ---------------------------------------------------------------------------
// extract_shadow
// ---------------------------------------------------------------------------

pub fn extract_shadow(hand: &ShadowProof) -> Result<ShadowWitness> {
    let claim = hand.claim;
    let proof = &hand.stark_proof;
    let config = protocol_pcs_config();
    let blowup = config.fri_config.log_blowup_factor;
    let fold_step = config.fri_config.fold_step;

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
    let lifting_log_size = get_lifting_log_size(&config, split_bound + blowup);
    let max_log_degree_bound = lifting_log_size - blowup;
    let n_inner = (max_log_degree_bound - fold_step - LOG_LAST_LAYER) as usize;
    let n_fri_layers = 1 + n_inner;

    let commitments = &proof.commitments.0;
    if commitments.len() != 3 {
        bail!("expect 3 trees, got {}", commitments.len());
    }

    // ---- 通道（影子原生） ----
    let mut ch = ShadowChannel::default();
    claim.mix_into(&mut ch);
    ShadowMerkleChannel::mix_root(&mut ch, commitments[0]);
    ShadowMerkleChannel::mix_root(&mut ch, commitments[1]);
    let _random_coeff_a = ch.draw_secure_felt();
    ShadowMerkleChannel::mix_root(&mut ch, commitments[2]);
    let oods_point = {
        // 与 stwo get_random_point 同参数化（影子协议定义）
        let t = ch.draw_secure_felt();
        use stwo::core::fields::FieldExpOps;
        let one = SecureField::from(1u32);
        let t_sq = t.clone().square();
        let inv = (t_sq.clone() + one.clone()).inverse();
        stwo::core::circle::CirclePoint { x: (one - t_sq) * inv, y: (t.clone() + t) * inv }
    };
    let mut sample_points = components.mask_points(oods_point, max_log_degree_bound, false);
    sample_points
        .push(vec![vec![oods_point]; 2 * stwo::core::fields::qm31::SECURE_EXTENSION_DEGREE]);
    // prove_values：先混入全部 OOD 采样值（tree→col→sample 展平），再画 RLC 系数
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
    ShadowMerkleChannel::mix_root(&mut ch, fri.first_layer.commitment);
    let mut alphas = vec![ch.draw_secure_felt()];
    for layer in &fri.inner_layers {
        ShadowMerkleChannel::mix_root(&mut ch, layer.commitment);
        alphas.push(ch.draw_secure_felt());
    }
    ch.mix_felts(&fri.last_layer_poly);

    if !ch.verify_pow_nonce(POW_BITS, proof.proof_of_work) {
        bail!("shadow pow invalid");
    }
    ch.mix_u64(proof.proof_of_work);
    let raw_positions: Vec<usize> = {
        let mask = (1usize << lifting_log_size) - 1;
        let mut raw = Vec::new();
        while raw.len() < N_QUERIES {
            for w in ch.draw_u32s() {
                raw.push((w & mask as u32) as usize);
                if raw.len() == N_QUERIES {
                    break;
                }
            }
        }
        raw
    };
    let queries: Vec<usize> =
        BTreeSet::from_iter(raw_positions.iter().copied()).into_iter().collect();

    // ---- 列尺寸 / 采样 ----
    use stwo::core::air::Component as _;
    let bounds = component.trace_log_degree_bounds();
    let trace_sizes: Vec<u32> = bounds[1].clone();
    if trace_sizes.len() != N_COLUMNS {
        bail!("trace col count {} != {}", trace_sizes.len(), N_COLUMNS);
    }
    let column_log_sizes = TreeVec(vec![
        vec![],
        trace_sizes.iter().map(|l| l + blowup).collect(),
        vec![max_log_degree_bound + blowup; N_QUOTIENT_COLS],
    ]);

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

    // ---- 首层期望值 ----
    let expected_first = fri_answers(
        column_log_sizes.clone(),
        samples.clone(),
        random_coeff_b,
        &queries,
        proof.queried_values.clone(),
        lifting_log_size,
    )
    .map_err(|e| anyhow!("fri_answers: {e}"))?;

    // ---- FRI 层 ----
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
        let hash_witness: Vec<FeltJ> =
            layer_proof.decommitment.hash_witness.iter().map(|h| feltj(h.0)).collect();
        fri_layer_witnesses.push(FriLayerWitness { subset_rows: rows.clone(), hash_witness });

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

    let last_const = fri.last_layer_poly[0];
    for v in &layer_query_values {
        if *v != last_const {
            bail!("last layer mismatch in shadow proof");
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
            rows.push(cols.iter().map(|c| m31j(c[qi])).collect());
        }
        let hash_witness: Vec<FeltJ> = proof.decommitments.0[tree_idx]
            .hash_witness
            .iter()
            .map(|h| feltj(h.0))
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

    Ok(ShadowWitness {
        log_size: claim.log_size,
        lifting_log_size,
        max_log_degree_bound,
        n_fri_layers,
        tree_cols: [N_COLUMNS, N_QUOTIENT_COLS],
        ood_col_lens,
        n_query_positions: queries.len(),
        claim: claim_json(&claim),
        empty_tree_root: feltj(commitments[0].0),
        trace_root: feltj(commitments[1].0),
        quotient_root: feltj(commitments[2].0),
        fri_roots: std::iter::once(&fri.first_layer.commitment)
            .chain(fri.inner_layers.iter().map(|l| &l.commitment))
            .map(|h| feltj(h.0))
            .collect(),
        last_layer_poly: qm31j(last_const),
        ood_values,
        ood_points,
        pow_nonce: proof.proof_of_work,
        queries,
        pcs_trees,
        fri_layers: fri_layer_witnesses,
        tables,
    })
}

// ---------------------------------------------------------------------------
// 商表（与 fri_ref 相同公式，独立实现）
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
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

/// 商累积（表驱动；电路同构）。
pub fn accumulate_quotients(
    table: &QueryBatchConstants,
    row: &[BaseField],
    domain_y: BaseField,
) -> SecureField {
    let mut acc = SecureField::from(0u32);
    for batch in &table.batches {
        let mut numerator = SecureField::from(0u32);
        for e in &batch.entries {
            let v = row[e.column_index];
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
// 叶子打包 + Merkle 遍历（影子语义）
// ---------------------------------------------------------------------------

pub fn shadow_leaf_hash(row: &[M31J]) -> Fr {
    let rc: &[Fr; 107] = &FR_RC;
    let pows = &*shift31_pows();
    let words: Vec<Fr> = row
        .chunks(8)
        .map(|chunk| {
            let mut acc = Fr::from(0u8);
            for (k, limb) in chunk.iter().enumerate() {
                acc += Fr::from(*limb) * pows[k];
            }
            acc
        })
        .collect();
    let n = words.len();
    let mut msgs = words;
    msgs.push(Fr::from(n as u64));
    fr_hash_many(&msgs, &rc)
}

pub fn shadow_h2(l: &Fr, r: &Fr) -> Fr {
    let rc: &[Fr; 107] = &FR_RC;
    fr_hash_many(&[*l, *r], &rc)
}

/// 影子 Merkle 遍历（消费兄弟见证，校验根）。
pub fn shadow_merkle_walk(
    root: &Fr,
    positions: &[usize],
    leaf_hashes: &[Fr],
    hash_witness: &[FeltJ],
    height: u32,
) -> Result<()> {
    let mut prev: Vec<(usize, Fr)> =
        positions.iter().zip(leaf_hashes).map(|(p, h)| (*p, *h)).collect();
    let mut wit: Vec<Fr> =
        hash_witness.iter().map(|s| from_feltj(s)).collect::<Result<Vec<_>>>()?;
    wit.reverse();
    for _ in 0..height {
        let mut curr: Vec<(usize, Fr)> = Vec::new();
        let mut i = 0;
        while i < prev.len() {
            if i + 1 < prev.len() && prev[i].0 ^ 1 == prev[i + 1].0 {
                let h = shadow_h2(&prev[i].1, &prev[i + 1].1);
                curr.push((prev[i].0 >> 1, h));
                i += 2;
            } else {
                let w = wit.pop().ok_or_else(|| anyhow!("shadow witness short"))?;
                let h = if prev[i].0 & 1 == 0 {
                    shadow_h2(&prev[i].1, &w)
                } else {
                    shadow_h2(&w, &prev[i].1)
                };
                curr.push((prev[i].0 >> 1, h));
                i += 1;
            }
        }
        prev = curr;
    }
    if !wit.is_empty() {
        bail!("shadow witness too long");
    }
    if prev[0].0 != 0 || prev[0].1 != *root {
        bail!("shadow root mismatch");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// verify_shadow：影子见证独立验证（电路语句的可执行规格）
// ---------------------------------------------------------------------------

/// JSON 驱动的通道重推导（与电路同构）。
pub struct ShadowDerived {
    pub random_coeff_a: SecureField,
    pub ood_point: stwo::core::circle::CirclePoint<SecureField>,
    pub random_coeff_b: SecureField,
    pub alphas: Vec<SecureField>,
    pub queries: Vec<usize>,
}

fn shadow_channel_derive(w: &ShadowWitness) -> Result<(ShadowChannel, ShadowDerived)> {
        let claim_j = &w.claim;
    let fe = |s: &str| -> Result<starknet_crypto::Felt> {
        let fr = from_feltj(s)?;
        let bigint: BigInt4 = fr.into_bigint();
        // limbs LE → 32B BE
        let mut bytes = [0u8; 32];
        for (li, lw) in bigint.0.iter().enumerate() {
            bytes[24 - 8 * li..32 - 8 * li].copy_from_slice(&lw.to_be_bytes());
        }
        Ok(StarkFelt::from_bytes_be(&bytes))
    };
    let claim = HandBatchClaim {
        hand_binding: fe(&claim_j.hand_binding)?,
        payload_digest: fe(&claim_j.payload_digest)?,
        counts: hand_verify_native::air::KindCounts {
            n_own: claim_j.counts[0],
            n_reveal: claim_j.counts[1],
            n_leave: claim_j.counts[2],
            n_recon: claim_j.counts[3],
        },
        log_size: claim_j.log_size,
        cairo_program_hash: fe(&claim_j.cairo_program_hash)?,
    };
    let mut ch = ShadowChannel::default();
    claim.mix_into(&mut ch);
    ch.mix_root(from_feltj(&w.empty_tree_root)?);
    ch.mix_root(from_feltj(&w.trace_root)?);
    let random_coeff_a = ch.draw_secure_felt();
    ch.mix_root(from_feltj(&w.quotient_root)?);
    let ood_point = {
        let t = ch.draw_secure_felt();
        use stwo::core::fields::FieldExpOps;
        let one = SecureField::from(1u32);
        let t_sq = t.clone().square();
        let inv = (t_sq.clone() + one.clone()).inverse();
        stwo::core::circle::CirclePoint { x: (one - t_sq) * inv, y: (t.clone() + t) * inv }
    };
    let ood: Vec<SecureField> = w.ood_values.iter().map(from_qm31j).collect();
    ch.mix_felts(&ood);
    let random_coeff_b = ch.draw_secure_felt();
    // 协议交错序：mix_root(L0) → α0 → mix_root(I_i) → α_{i+1} …（与 FriProver 一致）
    let mut alphas = Vec::with_capacity(w.n_fri_layers);
    for (i, r) in w.fri_roots.iter().enumerate() {
        ch.mix_root(from_feltj(r)?);
        alphas.push(ch.draw_secure_felt());
        let _ = i;
    }
    ch.mix_felts(&[from_qm31j(&w.last_layer_poly)]);
    if !ch.verify_pow_nonce(POW_BITS, w.pow_nonce) {
        bail!("shadow pow check failed");
    }
    ch.mix_u64(w.pow_nonce);
    let mask = (1usize << w.lifting_log_size) - 1;
    let mut raw = Vec::new();
    while raw.len() < N_QUERIES {
        for wd in ch.draw_u32s() {
            raw.push((wd & mask as u32) as usize);
            if raw.len() == N_QUERIES {
                break;
            }
        }
    }
    let queries: Vec<usize> = BTreeSet::from_iter(raw).into_iter().collect();
    Ok((
        ch,
        ShadowDerived { random_coeff_a, ood_point, random_coeff_b, alphas, queries },
    ))
}

pub fn verify_shadow(w: &ShadowWitness) -> Result<()> {
    let expected_inner = (w.max_log_degree_bound - FOLD_STEP - LOG_LAST_LAYER) as usize;
    if w.n_fri_layers != 1 + expected_inner {
        bail!("n_fri_layers mismatch");
    }
    if w.queries.len() != w.n_query_positions || w.queries.len() > N_QUERIES {
        bail!("query count inconsistent");
    }
    for (ti, tree) in w.pcs_trees.iter().enumerate() {
        if tree.leaf_rows.len() != w.queries.len() {
            bail!("pcs tree {ti} row count");
        }
        for row in &tree.leaf_rows {
            if row.len() != w.tree_cols[0] && row.len() != w.tree_cols[1] {
                bail!("pcs tree {ti} row width");
            }
        }
    }

    // 通道重推导
    let (_, d) = shadow_channel_derive(w)?;
    if d.queries != w.queries {
        bail!("query positions mismatch");
    }

    // 商表重算断言（防表篡改：常量必须由公开 OOD 值/点确定性推导）
    let column_log_sizes = TreeVec(vec![
        vec![],
        vec![w.log_size + LOG_BLOWUP; w.tree_cols[0]],
        vec![w.max_log_degree_bound + LOG_BLOWUP; w.tree_cols[1]],
    ]);
    let n_comp_cols = 2 * stwo::core::fields::qm31::SECURE_EXTENSION_DEGREE;
    let n_tree_cols_total = w.tree_cols[0] + w.tree_cols[1];
    if w.ood_values.len() != w.ood_points.len()
        || w.ood_col_lens.len() != n_tree_cols_total
    {
        bail!("ood layout mismatch");
    }
    for k in 0..n_comp_cols {
        let pi = w.ood_col_lens.iter().sum::<usize>() - n_comp_cols + k;
        if w.ood_points[pi] != pointj(&d.ood_point) {
            bail!("composition ood point != derived");
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
        let hashes: Vec<Fr> = tree.leaf_rows.iter().map(|r| shadow_leaf_hash(r)).collect();
        let root = from_feltj(if ti == 0 { &w.trace_root } else { &w.quotient_root })?;
        shadow_merkle_walk(&root, &w.queries, &hashes, &tree.hash_witness, w.lifting_log_size)
            .map_err(|e| anyhow!("pcs tree {ti}: {e}"))?;
    }

    // FRI 层
    let first_domain = CanonicCoset::new(w.lifting_log_size).circle_domain();
    let mut cur_positions = w.queries.clone();
    let mut next_expected: Vec<SecureField> = Vec::new();
    for (li, layer) in w.fri_layers.iter().enumerate() {
        // 上一层折叠输出供本层检查；本层折叠写入新的 next_expected
        let expect_now = std::mem::take(&mut next_expected);
        let subsets = group_subsets(&cur_positions);
        if layer.subset_rows.len() != subsets.len() {
            bail!("layer {li}: subset row count");
        }
        // 遍历位置 = 子集覆盖的全部位置（{2k, 2k+1}，去重升序）——与 prover 的
        // decommitment 位置口径一致（build_merkle_verification_inputs dedup）。
        let mut positions: Vec<usize> = Vec::new();
        let mut hashes: Vec<Fr> = Vec::new();
        for (si, (start, _)) in subsets.iter().enumerate() {
            let row = &layer.subset_rows[si];
            for off in 0..2usize {
                let pos = start + off;
                if positions.last() == Some(&pos) {
                    continue;
                }
                positions.push(pos);
                hashes.push(shadow_leaf_hash(row[off].as_slice()));
            }
        }
        let root = from_feltj(&w.fri_roots[li])?;
        let height = w.lifting_log_size - li as u32;
        shadow_merkle_walk(&root, &positions, &hashes, &layer.hash_witness, height)
            .map_err(|e| anyhow!("fri layer {li}: {e}"))?;

        let rows: Vec<[SecureField; 2]> = layer
            .subset_rows
            .iter()
            .map(|r| [from_qm31j(&r[0]), from_qm31j(&r[1])])
            .collect();

        let mut qi = 0usize;
        for (si, (start, qs)) in subsets.iter().enumerate() {
            for off in 0..2usize {
                let pos = start + off;
                if qs.contains(&pos) {
                    let got = rows[si][off];
                    let want = if li == 0 {
                        let mut row_vals: Vec<BaseField> =
                            Vec::with_capacity(w.tree_cols[0] + w.tree_cols[1]);
                        row_vals.extend(w.pcs_trees[0].leaf_rows[qi].iter().map(|x| from_m31j(*x)));
                        row_vals.extend(w.pcs_trees[1].leaf_rows[qi].iter().map(|x| from_m31j(*x)));
                        let dp = first_domain.at(bit_rev(pos, w.lifting_log_size));
                        accumulate_quotients(&tables.per_query[qi], &row_vals, dp.y)
                    } else {
                        expect_now[qi]
                    };
                    if got != want {
                        bail!("layer {li} query {pos}: eval mismatch");
                    }
                    qi += 1;
                }
            }
            let (v0, v1) = (rows[si][0], rows[si][1]);
            let folded = if li == 0 {
                let initial = first_domain.index_at(bit_rev(*start, w.lifting_log_size));
                let cd = CircleDomain::new(stwo::core::circle::Coset::new(initial, FOLD_STEP - 1));
                stwo::core::fri::fold_circle_into_line(&[v0, v1], cd, d.alphas[0])[0]
            } else {
                let dom_log = w.lifting_log_size - li as u32;
                let src = LineDomain::new(stwo::core::circle::Coset::half_odds(dom_log));
                let initial = src.coset().index_at(bit_rev(*start, dom_log));
                let sub = LineDomain::new(stwo::core::circle::Coset::new(initial, FOLD_STEP));
                stwo::core::fri::fold_coset(vec![v0, v1], sub, d.alphas[li])
            };
            next_expected.push(folded);
        }
        cur_positions = fold_queries(&cur_positions, FOLD_STEP);
        if li + 1 < w.n_fri_layers && next_expected.len() != cur_positions.len() {
            bail!("layer {li} fold count");
        }
    }

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


#[cfg(test)]
mod equiv_tests {
    use super::*;

    /// FrHasher（缓冲、多调用）与 shadow_leaf_hash（一次性）等价；
    /// 16+1 两调用与 17 一调用等价（复刻 build_leaves 分块）。
    #[test]
    fn fr_hasher_equiv() {
        let row: Vec<BaseField> =
            (0..17u32).map(|i| BaseField::from_u32_unchecked(i * 7 + 1)).collect();
        let row_j: Vec<M31J> = row.iter().map(|v| v.0).collect();

        let b = shadow_leaf_hash(&row_j);

        let mut h = FrHasher::default();
        h.update_leaf(&row);
        let a = h.finalize().0;
        assert_eq!(a, b, "one-call 17");

        let mut h = FrHasher::default();
        h.update_leaf(&row[..16]);
        h.update_leaf(&row[16..]);
        let c = h.finalize().0;
        assert_eq!(c, b, "16+1 two-call");

        // FRI 层 4 列
        let row4: Vec<BaseField> = row[..4].to_vec();
        let mut h = FrHasher::default();
        h.update_leaf(&row4);
        let d = h.finalize().0;
        assert_eq!(d, shadow_leaf_hash(&row_j[..4]), "4-col");
    }

    /// hash_children 与 shadow_h2 一致。
    #[test]
    fn hash_children_equiv() {
        let l = FrH(Fr::from(42u8));
        let r = FrH(Fr::from(43u8));
        assert_eq!(FrHasher::hash_children((l, r)).0, shadow_h2(&l.0, &r.0));
    }
}

// ---------------------------------------------------------------------------
// 折叠域几何常数（电路综合期宿主计算；与 verify_shadow 同公式）
// ---------------------------------------------------------------------------

/// 首层（circle→line）折叠：p.y⁻¹，p = circle_domain.at(bitrev(pos, lifting))。
pub fn circle_y_inv(lifting_log: u32, pos: usize) -> u32 {
    use stwo::core::fields::FieldExpOps;
    let d = CanonicCoset::new(lifting_log).circle_domain();
    let p = d.at(bit_rev(pos, lifting_log));
    p.y.inverse().0
}

/// 内层（line→point）折叠：x⁻¹，x = LineDomain(half_odds(dom_log)).at(bitrev(pos, dom_log))。
pub fn line_x_inv(dom_log: u32, pos: usize) -> u32 {
    use stwo::core::fields::FieldExpOps;
    let d = LineDomain::new(stwo::core::circle::Coset::half_odds(dom_log));
    let x = d.at(bit_rev(pos, dom_log));
    x.inverse().0
}

/// 首层商累积的 domain_point.y（M31）。
pub fn lifting_domain_y(lifting_log: u32, pos: usize) -> u32 {
    let d = CanonicCoset::new(lifting_log).circle_domain();
    d.at(bit_rev(pos, lifting_log)).y.0
}
