//! P2-M1 结算隐私电路（`docs/design/SETTLEMENT_PRIVACY_PLAN.md` §开发排期 / P2-M1 电路规格，已定稿）。
//!
//! 语句（公开输入）：`hand_binding, hand_id, registered_digest, n_participants`
//! 见证（私密）：`players[9], deltas[9]`（i128 → (sign, |delta| u64) 对）
//! 约束（规格四条）：
//! 1. `poseidon_hash_many([hand_id] ++ Σ(player, sign, |delta|) ++ [action_log_digest])
//!    == registered_digest`——与合约 `compute_settlement_digest` 及
//!    `texas/src/starknet/submit.rs` 逐字段一致（#18 Phase B：动作日志哈希作为
//!    吸收链尾词，把结算锚定到带 auto 标记的完整动作日志）；
//! 2. `Σ sign·|delta| == 0`（零和）；
//! 3. `n_participants == registered_count`；
//! 4. 每赢家输出认领承诺 `cm_i = poseidon(commitment_i, hand_binding, amount_lo, amount_hi)`
//!    ——与合约 `poker_dual_settlement.cairo` 写入 `claim_cms` 的公式逐字段一致
//!    （Cairo `poseidon_hash_span` 与 `poseidon_hash_many` 是同一 sponge：配对吸收、
//!    余项补 1，见 corelib `poseidon.cairo`，二者可互换）。
//!
//! ## M1 骨架边界（本模块的诚实口径）
//!
//! - **host 侧参考实现（本模块，单测覆盖）**：四条约束全部给出 Rust 参考实现，
//!   与链上公式逐字段对齐；`validate_statement` / `validate_witness` 在证明与
//!   验证入口强制执行（fail-closed，沿用 reveal-opening 的 verify 前置 validate
//!   模式）。
//! - **AIR 骨架（Stwo component，本模块）**：trace 布局按规格「每参与者一行
//!   ×(player, sign, |delta|, winner, cm)」。约束框架逐行求值，故公开语句展开为
//!   **9 行 scope**（常量列每行重复 + 每行 participant 字段与 prefix 计数），AIR
//!   将 trace 的全部语义列逐 limb 绑定到 scope，并约束 M31 原生可表达的全部关系：
//!   sign/winner booleanity、winner⇒sign、非赢家 cm 归零、cm/player/|delta| 与
//!   scope 相等、trace 计数与 scope 计数相等。§8.2 预留的三个动作域槽位中，
//!   `action_log_digest` 已由 #18 Phase B 接线（进 digest 吸收链与公开段，
//!   列位零重排）；`action_flags` / `accepted_seq_digest` 仍作为 scope 常量列
//!   **在电路上强制为零**——等电路内"合法默认"（auto-check 仅当零下注）与
//!   seq 单调约束落地（主网上线门槛）时直接替换，wire 再次零重排。
//! - **P2-M2 待接入（显式边界，非本骨架范围）**：felt252 域 Starknet-Poseidon
//!   component（digest 吸收链与 claim_cms 的原生推导）与多 limb 零和累加。
//!   M1 的 digest/零和/claim_cms 关系由 host 参考函数承担，沿用本仓库 G 层
//!   "host-verified, client-verifiable" 的既定 residual-trust 叙事。
//!
//! 语句经 borsh 编码混入 Fiat–Shamir channel，scope 承诺根在验证端重算比对
//! （与 `canonical_reveal_opening` 同款双重绑定）。
#![allow(missing_docs)]

use bincode::Options;
use borsh::{BorshDeserialize, BorshSerialize};
use starknet_crypto::Felt;
use stwo::core::channel::{Channel, Poseidon252Channel};
use stwo::core::fields::m31::M31;
use stwo::core::fields::qm31::SecureField;
use stwo::core::pcs::CommitmentSchemeVerifier;
use stwo::core::proof::StarkProof;
use stwo::core::vcs_lifted::poseidon252_merkle::{
    Poseidon252MerkleChannel, Poseidon252MerkleHasher,
};
use stwo::core::verifier::verify;
use stwo::prover::backend::simd::SimdBackend;
use stwo::prover::{CommitmentSchemeProver, prove};
use stwo_constraint_framework::preprocessed_columns::PreProcessedColumnId;
use stwo_constraint_framework::{
    EvalAtRow, FrameworkComponent, FrameworkEval, TraceLocationAllocator,
};

use crate::error::{TexasAirError, TexasAirResult};
use crate::trace_gen::MethodTrace;

/// 参与者上限（规格：witness players[9]，9 人桌常规桌型）。
pub const MAX_PARTICIPANTS: usize = 9;
/// felt252 的 16-bit limb 数（256 bit 覆盖）。
pub const FELT_LIMBS: usize = 16;
/// u64 金额的 16-bit limb 数。
pub const MAG_LIMBS: usize = 4;
/// 固定 trace 行数 = MAX_PARTICIPANTS。
pub const AIR_LOG_SIZE: u32 = 3;
pub const SETTLEMENT_PRIVATE_MAGIC: [u8; 4] = *b"SP2C";
pub const SETTLEMENT_PRIVATE_VERSION: u8 = 1;
const AIR_DOMAIN: &[u8] = b"zchain.texas.settlement-private-air.v1";

/// scope 常量列：hand_id(4) + digest(16) + binding(16) + n(1) + action(16)
/// + flags(1) + accepted-seq(16)。
const SCOPE_CONST_COLUMNS: usize = 4 + FELT_LIMBS * 4 + 2;
/// scope 每行 participant 列：player(16) + |delta|(4) + cm(16) + prefix-count(1)。
const SCOPE_ROW_COLUMNS: usize = FELT_LIMBS + MAG_LIMBS + FELT_LIMBS + 1;
const SCOPE_COLUMNS: usize = SCOPE_CONST_COLUMNS + MAX_PARTICIPANTS * SCOPE_ROW_COLUMNS;
/// trace 每行：player(16) + sign(1) + |delta|(4) + winner(1) + cm(16) + count(1)。
const AIR_TRACE_COLUMNS: usize = MAX_PARTICIPANTS
    * (FELT_LIMBS + 1 + MAG_LIMBS + 1 + FELT_LIMBS + 1);

const fn scope_hand_id() -> usize {
    0
}
const fn scope_digest() -> usize {
    scope_hand_id() + 4
}
const fn scope_binding() -> usize {
    scope_digest() + FELT_LIMBS
}
const fn scope_n_participants() -> usize {
    scope_binding() + FELT_LIMBS
}
const fn scope_action_digest() -> usize {
    scope_n_participants() + 1
}
const fn scope_action_flags() -> usize {
    scope_action_digest() + FELT_LIMBS
}
const fn scope_accepted_seq() -> usize {
    scope_action_flags() + 1
}
const fn scope_row_base(participant: usize) -> usize {
    SCOPE_CONST_COLUMNS + participant * SCOPE_ROW_COLUMNS
}
const fn scope_row_player(participant: usize) -> usize {
    scope_row_base(participant)
}
const fn scope_row_magnitude(participant: usize) -> usize {
    scope_row_player(participant) + FELT_LIMBS
}
const fn scope_row_cm(participant: usize) -> usize {
    scope_row_magnitude(participant) + MAG_LIMBS
}
const fn scope_row_count(participant: usize) -> usize {
    scope_row_cm(participant) + FELT_LIMBS
}

fn settlement_ids() -> &'static [PreProcessedColumnId] {
    static IDS: std::sync::OnceLock<Vec<PreProcessedColumnId>> = std::sync::OnceLock::new();
    IDS.get_or_init(|| {
        (0..SCOPE_COLUMNS)
            .map(|index| PreProcessedColumnId {
                id: format!("settlement.private.v1.scope.{index}").into(),
            })
            .collect()
    })
}

fn settlement_options() -> impl bincode::Options {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(16 * 1024 * 1024)
}

/// felt252 的大端 32 字节序列化（全零 = 未提供）。
pub type FeltBytes = [u8; 32];

/// felt 字节 → [`Felt`]（拒绝非规范编码，≥ P）。types-core 的
/// `from_bytes_be` 无失败路径（≥ P 输入会被静默归约），用字节往返判定
/// canonical——语义与旧 0.6 ff 库的 `Result` 完全一致。
pub fn felt_from_bytes(bytes: FeltBytes) -> Result<Felt, TexasAirError> {
    crate::state_root::felt_from_canonical_bytes(&bytes).ok_or_else(|| {
        TexasAirError::SerializationError("felt not canonical".to_string())
    })
}

fn limb_bytes(bytes: FeltBytes) -> [u32; FELT_LIMBS] {
    // 大端字节 → 低位在前 16-bit limb 序列（limb 0 为最低有效位）。
    let mut limbs = [0u32; FELT_LIMBS];
    for (limb_index, limb) in limbs.iter_mut().enumerate() {
        let hi = bytes[32 - 1 - 2 * limb_index];
        let lo = bytes[32 - 2 - 2 * limb_index];
        *limb = u32::from(lo) | (u32::from(hi) << 8);
    }
    limbs
}

fn magnitude_limbs(magnitude: u64) -> [u32; MAG_LIMBS] {
    let mut limbs = [0u32; MAG_LIMBS];
    for (index, limb) in limbs.iter_mut().enumerate() {
        *limb = ((magnitude >> (16 * index)) & 0xFFFF) as u32;
    }
    limbs
}

const ZERO_FELT: FeltBytes = [0u8; 32];

/// P2-M1 语句（公开输入）。
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct SettlementPrivateStatement {
    pub hand_id: u64,
    pub hand_binding: FeltBytes,
    pub registered_digest: FeltBytes,
    /// 固定 9 槽，未用槽位填零 felt（与 settle calldata `players` 一一对应）。
    pub players: [FeltBytes; MAX_PARTICIPANTS],
    /// wei 单位有符号变动（与 settle calldata `deltas` 一致），|delta| ≤ u64::MAX。
    pub signed_deltas: [i128; MAX_PARTICIPANTS],
    /// 非 0 变动参与者数（规格约束 3）。
    pub n_participants: u32,
    /// §8.2 预留槽位（#18 Phase B 已接线）：本手动作日志哈希
    /// （game 层 `pokergame::actions::action_log_digest` 的 starknet_keccak 链）。
    /// 进 digest 吸收链尾词 + 公开段第 15 词；空日志 = 仅域标签的确定值。
    pub action_log_digest: FeltBytes,
    /// §8.2 预留：auto/accepted-seq 标志位（强制为零，等电路内合法默认约束）。
    pub action_flags: u32,
    /// §8.2 预留：accepted-seq 向量承诺（强制为零，同上）。
    pub accepted_seq_digest: FeltBytes,
}

/// P2-M1 见证（私密）：赢家 payout commitment（合约 `vault.payout_commitment`）。
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct SettlementPrivateWitness {
    /// 与 `players` 槽位一一对应；非赢家槽忽略（建议填零）。
    pub payout_commitments: [FeltBytes; MAX_PARTICIPANTS],
}

impl SettlementPrivateStatement {
    /// 证明/验证入口的 fail-closed 门禁（规格约束 2/3 + §8.2 剩余预留零化）。
    pub fn validate(&self) -> Result<(), TexasAirError> {
        felt_from_bytes(self.hand_binding)?;
        felt_from_bytes(self.registered_digest)?;
        felt_from_bytes(self.action_log_digest)?;
        felt_from_bytes(self.accepted_seq_digest)?;
        if self.accepted_seq_digest != ZERO_FELT {
            return Err(TexasAirError::ConstraintUnsatisfied(
                "accepted-seq reserved field must be zero until the circuit wires seq \
                 monotonicity constraints"
                    .into(),
            ));
        }
        if self.action_flags != 0 {
            return Err(TexasAirError::ConstraintUnsatisfied(
                "action flags reserved field must be zero until the circuit wires the \
                 legal-default auto constraints"
                    .into(),
            ));
        }
        let mut count: u32 = 0;
        let mut sum: i128 = 0;
        for (player, delta) in self
            .players
            .iter()
            .copied()
            .zip(self.signed_deltas.iter().copied())
        {
            felt_from_bytes(player)?;
            if delta.unsigned_abs() > u64::MAX as u128 {
                return Err(TexasAirError::ConstraintUnsatisfied(
                    "|delta| exceeds u64 (digest uses u64 magnitudes)".into(),
                ));
            }
            sum = sum.checked_add(delta).ok_or_else(|| {
                TexasAirError::ConstraintUnsatisfied("delta sum overflow".into())
            })?;
            if delta != 0 {
                count = count.saturating_add(1);
            }
        }
        if count != self.n_participants {
            return Err(TexasAirError::ConstraintUnsatisfied(format!(
                "n_participants {} != non-zero delta count {count}",
                self.n_participants
            )));
        }
        if sum != 0 {
            return Err(TexasAirError::ConstraintUnsatisfied(
                "settlement is not zero-sum (spec constraint 2)".into(),
            ));
        }
        Ok(())
    }

    /// 见证校验：每个赢家（delta > 0）必须有已注册（非零）payout commitment。
    pub fn validate_witness(
        &self,
        witness: &SettlementPrivateWitness,
    ) -> Result<(), TexasAirError> {
        for (delta, commitment) in self
            .signed_deltas
            .iter()
            .copied()
            .zip(witness.payout_commitments.iter().copied())
        {
            felt_from_bytes(commitment)?;
            if delta > 0 && commitment == ZERO_FELT {
                return Err(TexasAirError::ConstraintUnsatisfied(
                    "winner payout commitment not registered (zero)".into(),
                ));
            }
        }
        Ok(())
    }

    fn winner(&self, participant: usize) -> bool {
        self.signed_deltas[participant] > 0
    }
}

/// 规格 digest 吸收序列：`[hand_id] ++ Σ(player, sign, |delta|) ++ [action_log_digest]`。
/// 与 `texas/src/starknet/submit.rs` 及合约 `compute_settlement_digest`
/// 逐字段一致（d ≥ 0 → sign=1；d == 0 → sign=1, |delta|=0；动作日志哈希
/// 为吸收链尾词——#18 Phase B）。
pub fn settlement_digest_fields(
    statement: &SettlementPrivateStatement,
) -> Result<Vec<Felt>, TexasAirError> {
    let mut fields = Vec::with_capacity(2 + 3 * MAX_PARTICIPANTS);
    fields.push(Felt::from(statement.hand_id));
    for (player, delta) in statement
        .players
        .iter()
        .copied()
        .zip(statement.signed_deltas.iter().copied())
    {
        fields.push(felt_from_bytes(player)?);
        let magnitude = u64::try_from(delta.unsigned_abs())
            .map_err(|_| TexasAirError::ConstraintUnsatisfied("magnitude overflow".into()))?;
        fields.push(Felt::from(if delta >= 0 { 1u64 } else { 0u64 }));
        fields.push(Felt::from(magnitude));
    }
    fields.push(felt_from_bytes(statement.action_log_digest)?);
    Ok(fields)
}

/// 规格约束 1：settlement digest（Starknet Poseidon）。
pub fn compute_settlement_digest(
    statement: &SettlementPrivateStatement,
) -> Result<FeltBytes, TexasAirError> {
    let digest = starknet_crypto::poseidon_hash_many(&settlement_digest_fields(statement)?);
    Ok(digest.to_bytes_be())
}

/// 规格约束 4：赢家认领承诺
/// `cm = poseidon_hash_span([commitment, hand_binding, amount_lo, amount_hi])`，
/// `amount = u256(delta_wei)`（low = delta, high = 0，delta ≤ u64::MAX）。
pub fn derive_claim_cms(
    statement: &SettlementPrivateStatement,
    witness: &SettlementPrivateWitness,
) -> Result<[FeltBytes; MAX_PARTICIPANTS], TexasAirError> {
    let binding = felt_from_bytes(statement.hand_binding)?;
    let mut cms = [ZERO_FELT; MAX_PARTICIPANTS];
    for index in 0..MAX_PARTICIPANTS {
        if !statement.winner(index) {
            continue;
        }
        let commitment = felt_from_bytes(witness.payout_commitments[index])?;
        let delta = statement.signed_deltas[index];
        let amount_low = Felt::from(delta as u64);
        let cm = starknet_crypto::poseidon_hash_many(&[
            commitment,
            binding,
            amount_low,
            Felt::ZERO,
        ]);
        cms[index] = cm.to_bytes_be();
    }
    Ok(cms)
}

/// 公开语句展开为 8 行 scope：常量列每行重复，participant 列逐行填充，
/// prefix-count 列由 host 按 winner 计数填充（scope 本身即语句承诺内容，
/// 验证端从自己的语句重算并比对承诺根）。
fn statement_scope(
    statement: &SettlementPrivateStatement,
    witness: &SettlementPrivateWitness,
) -> Result<MethodTrace, TexasAirError> {
    statement.validate()?;
    statement.validate_witness(witness)?;
    let cms = derive_claim_cms(statement, witness)?;

    let mut constants: Vec<M31> = Vec::with_capacity(SCOPE_CONST_COLUMNS);
    for limb in magnitude_limbs(statement.hand_id) {
        constants.push(M31::from(limb));
    }
    for limb in limb_bytes(statement.registered_digest) {
        constants.push(M31::from(limb));
    }
    for limb in limb_bytes(statement.hand_binding) {
        constants.push(M31::from(limb));
    }
    constants.push(M31::from(statement.n_participants));
    for limb in limb_bytes(statement.action_log_digest) {
        constants.push(M31::from(limb));
    }
    constants.push(M31::from(statement.action_flags));
    for limb in limb_bytes(statement.accepted_seq_digest) {
        constants.push(M31::from(limb));
    }
    debug_assert_eq!(constants.len(), SCOPE_CONST_COLUMNS);
    // 填充序与命名列位一致（action_log_digest 槽位 = §8.2 冻结位，#18 接线）。
    debug_assert_eq!(
        constants[scope_action_digest()..scope_action_digest() + FELT_LIMBS]
            .iter()
            .map(|m| m.0)
            .collect::<Vec<_>>(),
        limb_bytes(statement.action_log_digest).to_vec(),
        "action_log_digest must fill the frozen §8.2 column slot"
    );

    // MethodTrace 的"行"是全列宽求值点：单行包含全部 participant 列组，
    // 8 个求值点复制同一行（约束逐点生效，与 reveal-opening 同款）。
    let mut row: Vec<M31> = constants;
    let mut running: u32 = 0;
    for row_index in 0..MAX_PARTICIPANTS {
        for limb in limb_bytes(statement.players[row_index]) {
            row.push(M31::from(limb));
        }
        for limb in magnitude_limbs(statement.signed_deltas[row_index].unsigned_abs() as u64) {
            row.push(M31::from(limb));
        }
        for limb in limb_bytes(cms[row_index]) {
            row.push(M31::from(limb));
        }
        running += u32::from(statement.winner(row_index));
        row.push(M31::from(running));
    }
    debug_assert_eq!(row.len(), SCOPE_COLUMNS);
    let mut trace = MethodTrace::new(AIR_LOG_SIZE, SCOPE_COLUMNS);
    for point in 0..(1usize << AIR_LOG_SIZE) {
        trace
            .write_row(point, &row)
            .expect("fixed statement scope width");
    }
    Ok(trace)
}

/// 规格 trace 布局：每参与者一个列组 ×(player, sign, |delta|, winner, cm, count)。
/// （felt/u64 以 16-bit limb 展开进 M31 列；MethodTrace 的"行"是全列宽求值点，
/// 8 个求值点复制同一组列值。）
fn trace_row(
    statement: &SettlementPrivateStatement,
    witness: &SettlementPrivateWitness,
) -> Result<Vec<M31>, TexasAirError> {
    let cms = derive_claim_cms(statement, witness)?;
    let mut row: Vec<M31> = Vec::with_capacity(AIR_TRACE_COLUMNS);
    let mut running: u32 = 0;
    for row_index in 0..MAX_PARTICIPANTS {
        let delta = statement.signed_deltas[row_index];
        let winner = statement.winner(row_index);
        let sign = u32::from(delta >= 0);
        for limb in limb_bytes(statement.players[row_index]) {
            row.push(M31::from(limb));
        }
        row.push(M31::from(sign));
        for limb in magnitude_limbs(delta.unsigned_abs() as u64) {
            row.push(M31::from(limb));
        }
        row.push(M31::from(u32::from(winner)));
        for limb in limb_bytes(cms[row_index]) {
            row.push(M31::from(limb));
        }
        running += u32::from(winner);
        row.push(M31::from(running));
    }
    debug_assert_eq!(row.len(), AIR_TRACE_COLUMNS);
    Ok(row)
}

fn build_trace(
    statement: &SettlementPrivateStatement,
    witness: &SettlementPrivateWitness,
) -> Result<MethodTrace, TexasAirError> {
    let row = trace_row(statement, witness)?;
    let mut trace = MethodTrace::new(AIR_LOG_SIZE, AIR_TRACE_COLUMNS);
    for point in 0..(1usize << AIR_LOG_SIZE) {
        trace.write_row(point, &row)?;
    }
    Ok(trace)
}

fn mix_statement(
    channel: &mut Poseidon252Channel,
    statement: &SettlementPrivateStatement,
) -> Result<(), TexasAirError> {
    let bytes = borsh::to_vec(statement)
        .map_err(|error| TexasAirError::SerializationError(error.to_string()))?;
    channel.mix_u32s(&[u32::from(SETTLEMENT_PRIVATE_VERSION)]);
    channel.mix_u32s(&bytes.into_iter().map(u32::from).collect::<Vec<_>>());
    channel.mix_u32s(
        &AIR_DOMAIN
            .iter()
            .copied()
            .map(u32::from)
            .collect::<Vec<_>>(),
    );
    Ok(())
}

/// M1 AIR 骨架：约束清单见模块头注释。
#[derive(Clone, Copy)]
struct SettlementPrivateAir;

impl FrameworkEval for SettlementPrivateAir {
    fn log_size(&self) -> u32 {
        AIR_LOG_SIZE
    }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        AIR_LOG_SIZE + 1
    }

    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let one: E::F = M31::from(1u32).into();
        let ids = settlement_ids();

        // §8.2 预留槽位的电路约束（#18 Phase B 后的状态）：
        // - `action_log_digest` 列位已接线（digest 吸收链尾词 + 公开段第 15 词），
        //   其值经 scope 承诺根 + host digest 重算双重绑定，不再零化；
        // - `action_flags` / `accepted_seq_digest` 仍强制为零——等电路内
        //   "合法默认"/seq 单调约束（主网门槛）落地时替换，wire 零重排。
        let flags = eval.get_preprocessed_column(ids[scope_action_flags()].clone());
        eval.add_constraint(flags);
        for offset in 0..FELT_LIMBS {
            let reserved = eval.get_preprocessed_column(ids[scope_accepted_seq() + offset].clone());
            eval.add_constraint(reserved);
        }

        for participant in 0..MAX_PARTICIPANTS {
            let mut player_limbs: Vec<E::F> = Vec::with_capacity(FELT_LIMBS);
            for _ in 0..FELT_LIMBS {
                player_limbs.push(eval.next_trace_mask());
            }
            let sign = eval.next_trace_mask();
            let mut magnitude_limbs: Vec<E::F> = Vec::with_capacity(MAG_LIMBS);
            for _ in 0..MAG_LIMBS {
                magnitude_limbs.push(eval.next_trace_mask());
            }
            let winner = eval.next_trace_mask();
            let mut cm_limbs: Vec<E::F> = Vec::with_capacity(FELT_LIMBS);
            for _ in 0..FELT_LIMBS {
                cm_limbs.push(eval.next_trace_mask());
            }
            let count = eval.next_trace_mask();

            // witness ↔ 公开语句展开逐 limb 绑定。
            for (offset, player) in player_limbs.iter().enumerate() {
                let scope =
                    eval.get_preprocessed_column(ids[scope_row_player(participant) + offset].clone());
                eval.add_constraint(player.clone() - scope);
            }
            for (offset, magnitude) in magnitude_limbs.iter().enumerate() {
                let scope = eval
                    .get_preprocessed_column(ids[scope_row_magnitude(participant) + offset].clone());
                eval.add_constraint(magnitude.clone() - scope);
            }
            for (offset, cm) in cm_limbs.iter().enumerate() {
                let scope = eval.get_preprocessed_column(ids[scope_row_cm(participant) + offset].clone());
                eval.add_constraint(cm.clone() - scope);
            }
            let scope_count =
                eval.get_preprocessed_column(ids[scope_row_count(participant)].clone());
            eval.add_constraint(count - scope_count);

            // booleanity：sign ∈ {0,1}，winner ∈ {0,1}。
            eval.add_constraint(sign.clone() * (sign.clone() - one.clone()));
            eval.add_constraint(winner.clone() * (winner.clone() - one.clone()));
            // winner ⇒ sign == 1（赢家必为正变动）。
            eval.add_constraint(winner.clone() * (sign.clone() - one.clone()));
            // 非赢家（含输家与零变动）⇒ cm 归零（合约只对赢家写 claim_cms）。
            for cm in &cm_limbs {
                eval.add_constraint((one.clone() - winner.clone()) * cm.clone());
            }
        }

        eval
    }
}

/// P2-M1 归档证明（bincode 定长编码）。
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ArchivedSettlementPrivateProof {
    pub stark_proof_bytes: Vec<u8>,
}

fn prove_with_trace(
    statement: &SettlementPrivateStatement,
    witness: &SettlementPrivateWitness,
    trace: MethodTrace,
) -> TexasAirResult<ArchivedSettlementPrivateProof> {
    let scope = statement_scope(statement, witness)?;
    let config = crate::prover_context::protocol_pcs_config();
    let twiddles = crate::prover_context::simd_twiddles(
        AIR_LOG_SIZE + config.fri_config.log_blowup_factor,
    );
    let mut channel = Poseidon252Channel::default();
    mix_statement(&mut channel, statement)?;
    let mut scheme =
        CommitmentSchemeProver::<SimdBackend, Poseidon252MerkleChannel>::with_memory_pool(
            config,
            &twiddles,
            crate::prover_context::simd_base_column_pool(),
        );
    {
        let mut builder = scheme.tree_builder();
        builder.extend_evals(scope.to_evaluations());
        builder.commit(&mut channel);
    }
    {
        let mut builder = scheme.tree_builder();
        builder.extend_evals(trace.to_evaluations());
        builder.commit(&mut channel);
    }
    let ids = settlement_ids();
    let mut allocator = TraceLocationAllocator::new_with_preprocessed_columns(&ids);
    let component =
        FrameworkComponent::new(&mut allocator, SettlementPrivateAir, SecureField::from(0u32));
    let proof = prove(&[&component], &mut channel, scheme)
        .map_err(|error| TexasAirError::StwoProverError(error.to_string()))?;
    Ok(ArchivedSettlementPrivateProof {
        stark_proof_bytes: settlement_options()
            .serialize(&proof)
            .map_err(|error| TexasAirError::SerializationError(error.to_string()))?,
    })
}

/// 证明 P2-M1 语句（入口校验规格约束 2/3 与 §8.2 预留零化）。
pub fn prove_settlement_private(
    statement: &SettlementPrivateStatement,
    witness: &SettlementPrivateWitness,
) -> TexasAirResult<ArchivedSettlementPrivateProof> {
    let trace = build_trace(statement, witness)?;
    prove_with_trace(statement, witness, trace)
}

/// 验证 P2-M1 证明：重算 scope（含由见证推导的 claim_cms）并比对承诺根，
/// 再跑 AIR 约束。任何语句篡改都在 scope 根比对处失败。
pub fn verify_settlement_private(
    statement: &SettlementPrivateStatement,
    witness: &SettlementPrivateWitness,
    archive: &ArchivedSettlementPrivateProof,
) -> TexasAirResult<()> {
    let scope = statement_scope(statement, witness)?;
    let proof: StarkProof<Poseidon252MerkleHasher> = settlement_options()
        .deserialize(&archive.stark_proof_bytes)
        .map_err(|error| TexasAirError::SerializationError(error.to_string()))?;
    if proof.commitments.len() < 2 {
        return Err(TexasAirError::SerializationError(
            "settlement private proof is missing scope or trace commitment".into(),
        ));
    }
    let config = crate::prover_context::protocol_pcs_config();
    let twiddles = crate::prover_context::simd_twiddles(
        AIR_LOG_SIZE + config.fri_config.log_blowup_factor,
    );
    let mut trusted =
        CommitmentSchemeProver::<SimdBackend, Poseidon252MerkleChannel>::with_memory_pool(
            config,
            &twiddles,
            crate::prover_context::simd_base_column_pool(),
        );
    let mut scope_channel = Poseidon252Channel::default();
    {
        let mut builder = trusted.tree_builder();
        builder.extend_evals(scope.to_evaluations());
        builder.commit(&mut scope_channel);
    }
    if proof.commitments.first().copied() != trusted.roots().first().copied() {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "settlement private statement scope commitment mismatch".into(),
        ));
    }
    let mut channel = Poseidon252Channel::default();
    mix_statement(&mut channel, statement)?;
    let mut scheme = CommitmentSchemeVerifier::<Poseidon252MerkleChannel>::new(config);
    scheme.commit(
        proof.commitments[0],
        &vec![AIR_LOG_SIZE; SCOPE_COLUMNS],
        &mut channel,
    );
    scheme.commit(
        proof.commitments[1],
        &vec![AIR_LOG_SIZE; AIR_TRACE_COLUMNS],
        &mut channel,
    );
    let ids = settlement_ids();
    let mut allocator = TraceLocationAllocator::new_with_preprocessed_columns(&ids);
    let component =
        FrameworkComponent::new(&mut allocator, SettlementPrivateAir, SecureField::from(0u32));
    verify(&[&component], &mut channel, &mut scheme, proof)
        .map_err(|error| TexasAirError::ConstraintUnsatisfied(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_felt(seed: u8) -> FeltBytes {
        let mut bytes = [0u8; 32];
        bytes[31] = seed;
        bytes[30] = seed.wrapping_mul(7);
        bytes
    }

    fn sample_statement() -> SettlementPrivateStatement {
        let mut players = [ZERO_FELT; MAX_PARTICIPANTS];
        for (index, player) in players.iter_mut().enumerate() {
            if index < 3 {
                *player = sample_felt(index as u8 + 1);
            }
        }
        SettlementPrivateStatement {
            hand_id: 42,
            hand_binding: sample_felt(0xAA),
            registered_digest: ZERO_FELT, // 由 digest 对齐测试填充
            players,
            // +300 / -200 / -100，零变动 6 槽：零和成立
            signed_deltas: [300, -200, -100, 0, 0, 0, 0, 0, 0],
            n_participants: 3,
            action_log_digest: sample_felt(0x77),
            action_flags: 0,
            accepted_seq_digest: ZERO_FELT,
        }
    }

    fn sample_witness() -> SettlementPrivateWitness {
        SettlementPrivateWitness {
            payout_commitments: [
                sample_felt(0x21),
                ZERO_FELT,
                ZERO_FELT,
                ZERO_FELT,
                ZERO_FELT,
                ZERO_FELT,
                ZERO_FELT,
                ZERO_FELT,
                ZERO_FELT,
            ],
        }
    }

    #[test]
    fn digest_fields_match_settle_calldata_formula() {
        // 独立复刻 submit.rs 的拼装口径，逐字段比对参考实现（#18 Phase B：
        // 动作日志哈希为吸收链尾词）。
        let statement = sample_statement();
        let expected: Vec<Felt> = {
            let mut fields = vec![Felt::from(statement.hand_id)];
            for (player, delta) in statement
                .players
                .iter()
                .copied()
                .zip(statement.signed_deltas.iter().copied())
            {
                fields.push(Felt::from_bytes_be(&player));
                let magnitude = delta.unsigned_abs() as u64;
                fields.push(Felt::from(if delta >= 0 { 1u64 } else { 0u64 }));
                fields.push(Felt::from(magnitude));
            }
            fields.push(
                Felt::from_bytes_be(&statement.action_log_digest),
            );
            fields
        };
        let got = settlement_digest_fields(&statement).expect("digest fields");
        assert_eq!(got.len(), expected.len());
        for (a, b) in got.iter().zip(expected.iter()) {
            assert_eq!(a, b, "digest field order must match submit.rs byte-for-byte");
        }
        // 参考 digest 与独立口径的 poseidon_hash_many 一致（规格约束 1）。
        let digest = compute_settlement_digest(&statement).expect("digest");
        assert_eq!(digest, starknet_crypto::poseidon_hash_many(&expected).to_bytes_be());
        // 动作日志哈希必须真实参与吸收链（尾词改动 → digest 改动）。
        let mut other = statement.clone();
        other.action_log_digest = sample_felt(0x78);
        assert_ne!(
            compute_settlement_digest(&statement).expect("digest"),
            compute_settlement_digest(&other).expect("digest"),
            "action log digest must bind the settlement digest"
        );
    }

    #[test]
    fn claim_cms_match_contract_formula() {
        // 独立复刻合约 poseidon_hash_span(array![commitment, hand_binding,
        // amount_lo, amount_hi]) 口径；Cairo span 与 hash_many 为同一 sponge。
        let statement = sample_statement();
        let witness = sample_witness();
        let binding = Felt::from_bytes_be(&statement.hand_binding);
        let commitment =
            Felt::from_bytes_be(&witness.payout_commitments[0]);
        let expected_cm = starknet_crypto::poseidon_hash_many(&[
            commitment,
            binding,
            Felt::from(300u64), // amount_lo = delta
            Felt::ZERO,         // amount_hi
        ]);
        let cms = derive_claim_cms(&statement, &witness).expect("claim cms");
        assert_eq!(cms[0], expected_cm.to_bytes_be());
        for index in 1..MAX_PARTICIPANTS {
            assert_eq!(cms[index], ZERO_FELT, "only winners carry a claim cm");
        }
    }

    #[test]
    fn honest_statement_roundtrip_proves_and_verifies() {
        let mut statement = sample_statement();
        statement.registered_digest =
            compute_settlement_digest(&statement).expect("digest");
        let witness = sample_witness();
        let archive = prove_settlement_private(&statement, &witness).expect("prove");
        verify_settlement_private(&statement, &witness, &archive).expect("verify");
    }

    #[test]
    fn tampered_digest_fails_scope_binding() {
        let mut statement = sample_statement();
        statement.registered_digest =
            compute_settlement_digest(&statement).expect("digest");
        let witness = sample_witness();
        let archive = prove_settlement_private(&statement, &witness).expect("prove");
        let mut tampered = statement.clone();
        tampered.registered_digest = sample_felt(0xEE);
        assert!(tampered.validate().is_ok(), "tampered digest is a canonical felt");
        let error = verify_settlement_private(&tampered, &witness, &archive)
            .err()
            .expect("tampered digest must not verify");
        assert!(matches!(error, TexasAirError::ConstraintUnsatisfied(_)));
    }

    #[test]
    fn zero_sum_violation_rejected_before_prove() {
        let mut statement = sample_statement();
        statement.signed_deltas[0] = 301;
        statement.registered_digest = compute_settlement_digest(&statement).expect("digest");
        let witness = sample_witness();
        assert!(statement.validate().is_err(), "non-zero-sum must be rejected");
        assert!(prove_settlement_private(&statement, &witness).is_err());
    }

    #[test]
    fn participant_count_mismatch_rejected() {
        let mut statement = sample_statement();
        statement.n_participants = 2;
        assert!(statement.validate().is_err());
    }

    #[test]
    fn winner_without_payout_commitment_rejected() {
        let mut statement = sample_statement();
        statement.registered_digest = compute_settlement_digest(&statement).expect("digest");
        let mut witness = sample_witness();
        witness.payout_commitments[0] = ZERO_FELT;
        assert!(statement.validate_witness(&witness).is_err());
        assert!(prove_settlement_private(&statement, &witness).is_err());
    }

    #[test]
    fn reserved_flags_and_seq_must_stay_zero_until_circuit_wiring() {
        // §8.2 预留的剩余两槽（auto 标志/accepted-seq 承诺）：非零直接拒绝；
        // action_log_digest 已接线（#18 Phase B），非零合法。
        let mut statement = sample_statement();
        statement.action_flags = 1;
        assert!(statement.validate().is_err());
        let mut statement = sample_statement();
        statement.accepted_seq_digest = sample_felt(0x56);
        assert!(statement.validate().is_err());
        let mut statement = sample_statement();
        statement.action_log_digest = sample_felt(0x57);
        assert!(
            statement.validate().is_ok(),
            "wired action log digest accepts arbitrary canonical felts"
        );
    }

    #[test]
    fn non_canonical_felt_rejected() {
        let mut statement = sample_statement();
        statement.hand_binding = [0xFF; 32]; // ≥ 圳 field prime
        assert!(statement.validate().is_err());
    }

    #[test]
    fn tampered_trace_fails_air_constraints() {
        // 绕过 build_trace 手工构造 trace：把赢家列组的 sign 改成 2，违反
        // booleanity → AIR 验证必须失败（证明约束真实生效）。
        let mut statement = sample_statement();
        statement.registered_digest = compute_settlement_digest(&statement).expect("digest");
        let witness = sample_witness();
        let mut bad_row = trace_row(&statement, &witness).expect("trace row");
        bad_row[16] = M31::from(2u32); // participant 0 列组的 sign 列
        let mut trace = MethodTrace::new(AIR_LOG_SIZE, AIR_TRACE_COLUMNS);
        for point in 0..(1usize << AIR_LOG_SIZE) {
            trace.write_row(point, &bad_row).expect("write tampered point");
        }
        // 违反约束的 trace：prover 在商多项式阶段即失败，或（若完成）验证端
        // 必须拒绝——二者任一即证明约束真实生效。
        match prove_with_trace(&statement, &witness, trace) {
            Err(_) => {}
            Ok(archive) => {
                let error = verify_settlement_private(&statement, &witness, &archive)
                    .err()
                    .expect("tampered trace must not verify");
                assert!(matches!(error, TexasAirError::ConstraintUnsatisfied(_)));
            }
        }
    }

    // ===== P2-M2：prove-hand（Cairo VM → Stwo）跨语言对齐夹具 =====

    /// P2-M2 电路的 Magic 标记（`proving-tool/src/settlement_private.cairo`）。
    /// = 0x5350324d5f4f4b（'SP2M_OK' 短字符串，大端尾对齐）。
    const PROVE_MAGIC: [u8; 32] = {
        let mut b = [0u8; 32];
        b[25] = 0x53;
        b[26] = 0x50;
        b[27] = 0x32;
        b[28] = 0x4d;
        b[29] = 0x5f;
        b[30] = 0x4f;
        b[31] = 0x4b;
        b
    };

    /// 真实量级的样例手牌：wei 记账（+3000/-2000/-1000 chips × 1e14），
    /// 零变动 6 槽（sign=1, |delta|=0，与 submit.rs 的 d≥0→1 口径一致）。
    fn prove_sample_statement(action_log_digest: FeltBytes) -> SettlementPrivateStatement {
        let wei_chip: i128 = 100_000_000_000_000;
        let mut players = [ZERO_FELT; MAX_PARTICIPANTS];
        for (index, player) in players.iter_mut().enumerate() {
            if index < 3 {
                *player = sample_felt(index as u8 + 1);
            }
        }
        SettlementPrivateStatement {
            hand_id: 42,
            hand_binding: sample_felt(0xAA),
            registered_digest: ZERO_FELT,
            players,
            signed_deltas: [
                3000 * wei_chip,
                -2000 * wei_chip,
                -1000 * wei_chip,
                0,
                0,
                0,
                0,
                0,
                0,
            ],
            n_participants: 3,
            // game 层动作日志 Poseidon 链根（#18 Phase C 切片 1）。
            action_log_digest,
            action_flags: 0,
            accepted_seq_digest: ZERO_FELT,
        }
    }

    fn hex(felt: Felt) -> String {
        format!("0x{felt:x}")
    }

    /// 动作名 → 大端 ASCII felt（与 texas pokergame::actions::action_word 一致）。
    fn game_action_word(action: &str) -> Felt {
        let mut acc: u64 = 0;
        for b in action.as_bytes() {
            acc = (acc << 8) + u64::from(*b);
        }
        Felt::from(acc)
    }

    /// 样例动作日志（3 条，含 auto 代打）：词条对 = [日志打包词, 合法性词]。
    /// 日志词（低 → 高）`action(40)|flags(2)@40|amount(64)@42|seq(64)@106|
    /// seat(32)@170`；合法性词 `kind(2)|owed(64)@2|my_bet(64)@66|
    /// big_blind(64)@130`（非 auto = 0）——与 game 层 `action_entry_word` /
    /// `legality_word` 逐字段一致。
    fn sample_action_entries() -> Vec<[Felt; 2]> {
        const P2_40: &str = "0x10000000000";
        const P2_42: &str = "0x40000000000";
        const P2_106: &str = "0x400000000000000000000000000";
        const P2_170: &str = "0x4000000000000000000000000000000000000000000";
        const P2_2: &str = "0x4";
        const P2_66: &str = "0x40000000000000000";
        const P2_130: &str = "0x400000000000000000000000000000000";
        let p = |hex: &str| Felt::from_hex(hex).expect("pow2");
        let (p2_40, p2_42, p2_106, p2_170) = (p(P2_40), p(P2_42), p(P2_106), p(P2_170));
        let (p2_2, p2_66, p2_130) = (p(P2_2), p(P2_66), p(P2_130));
        let log_word = |seat: u32, seq: u64, amount: u64, auto: bool, action: &str| {
            game_action_word(action)
                + Felt::from(u8::from(auto) + 2) * p2_40
                + Felt::from(amount) * p2_42
                + Felt::from(seq) * p2_106
                + Felt::from(seat) * p2_170
        };
        let legality_word = |kind: u64, owed: u64, my_bet: u64, big_blind: u64| {
            Felt::from(kind)
                + Felt::from(owed) * p2_2
                + Felt::from(my_bet) * p2_66
                + Felt::from(big_blind) * p2_130
        };
        vec![
            // 非 auto：合法词 canonical 0。
            [log_word(0, 1, 20, false, "CALL"), Felt::ZERO],
            // auto FOLD：owed=500 / my_bet=20 / big_blind=20 → 差额 480 > 20 ⇒ Fold ✓
            [
                log_word(1, 2, 0, true, "FOLD"),
                legality_word(2, 500, 20, 20),
            ],
            // 非 auto：canonical 0。
            [log_word(0, 3, 60, false, "RAISE"), Felt::ZERO],
        ]
    }

    /// game 层动作日志 Poseidon 链根（#18 Phase C 切片 1）：
    /// `poseidon_hash_many([DOMAIN] ++ Σ packed_word)`，DOMAIN =
    /// starknet_keccak(b"zgame.action_log.v1") 的数值（与 texas
    /// `action_log_domain()` 同一冻结字面量）。
    fn game_layer_action_log_digest(entries: &[[Felt; 2]]) -> FeltBytes {
        let domain = Felt::from_hex(
            "0x11b4269299cbd19c8d701730e13001ca46cbdd2d7a74ba25d7b30be4258fa6e",
        )
        .expect("canonical domain");
        let mut fields = vec![domain];
        for pair in entries {
            // 吸收链只收日志打包词（合法性词不进 digest）。
            fields.push(pair[0]);
        }
        starknet_crypto::poseidon_hash_many(&fields).to_bytes_be()
    }

    /// 生成 prove-hand 夹具（inputs.json / expected_outputs.json）。
    ///
    /// 默认 no-op（CI 无 proving-tool 也绿）；设 `SETTLEMENT_PROVE_FIXTURES_OUT`
    /// 后写入目录，供 `proving-tool/scripts/prove-settlement.sh` 使用：
    /// Cairo VM 执行（Stwo 证明覆盖）的公开段必须与 Rust `starknet_crypto`
    /// 参考值逐 felt 一致——跨语言对齐即规格四条约束的端到端验证。
    #[test]
    fn write_prove_hand_fixtures_when_requested() {
        let Some(out_dir) = std::env::var_os("SETTLEMENT_PROVE_FIXTURES_OUT") else {
            return;
        };
        let entries = sample_action_entries();
        let chain_root = game_layer_action_log_digest(&entries);
        let statement = prove_sample_statement(chain_root);
        let mut witness = SettlementPrivateWitness {
            payout_commitments: [ZERO_FELT; MAX_PARTICIPANTS],
        };
        witness.payout_commitments[0] = sample_felt(0x21);

        let digest = compute_settlement_digest(&statement).expect("digest");
        let cms = derive_claim_cms(&statement, &witness).expect("cms");

        // settle wire（102 词，9 人桌）：[hand_id, digest, n, binding,
        // p×9, s×9, m×9, c×9, ald, count, w0..w59]——settlement_stmt.cairo
        // 同一布局。
        let mut wire: Vec<String> = vec![
            hex(Felt::from(statement.hand_id)),
            hex(felt_from_bytes(digest).expect("canonical")),
            hex(Felt::from(statement.n_participants)),
            hex(felt_from_bytes(statement.hand_binding).expect("canonical")),
        ];
        for player in &statement.players {
            wire.push(hex(felt_from_bytes(*player).expect("canonical")));
        }
        for delta in statement.signed_deltas.iter().copied() {
            wire.push(hex(Felt::from(u64::from(delta >= 0))));
        }
        for delta in statement.signed_deltas.iter().copied() {
            wire.push(hex(Felt::from(delta.unsigned_abs() as u64)));
        }
        for commitment in &witness.payout_commitments {
            wire.push(hex(felt_from_bytes(*commitment).expect("canonical")));
        }
        // #18 Phase B：wire[40] = 动作日志哈希（digest 吸收链尾词）。
        wire.push(hex(felt_from_bytes(statement.action_log_digest).expect("canonical")));
        // #18 Phase C 切片 1：词条区 = [count] ++ 30×[日志词, 合法性词]
        // （不足补零）——电路重放整链并约束补零槽 canonical。
        wire.push(hex(Felt::from(entries.len() as u64)));
        for slot in 0..30usize {
            let pair: [Felt; 2] =
                entries.get(slot).copied().unwrap_or([Felt::ZERO; 2]);
            for word in pair {
                wire.push(hex(word));
            }
        }
        assert_eq!(wire.len(), 41 + 1 + 60);
        // Span ABI（2026-09-30 重构）：prove-hand flat 输入 = [len, elements…]
        // 摊平（与 combined / fold_batch / settlement_batch 同约定）——
        // `[102] ++ wire`。
        let mut inputs: Vec<String> = Vec::with_capacity(1 + wire.len());
        inputs.push(hex(Felt::from(wire.len() as u64)));
        inputs.extend(wire);
        assert_eq!(inputs.len(), 1 + 41 + 1 + 60);

        // 公开段期望：[MAGIC, hand_id, digest, n, binding, cm_0..cm_8,
        // total_winnings, action_log_digest]（16 felt，9 人桌）
        let mut expected: Vec<String> = vec![
            hex(Felt::from_bytes_be(&PROVE_MAGIC)),
            hex(Felt::from(statement.hand_id)),
            hex(felt_from_bytes(digest).expect("canonical")),
            hex(Felt::from(statement.n_participants)),
            hex(felt_from_bytes(statement.hand_binding).expect("canonical")),
        ];
        let mut total_winnings: u64 = 0;
        for (index, cm) in cms.iter().enumerate() {
            expected.push(hex(felt_from_bytes(*cm).expect("canonical")));
            if statement.winner(index) {
                total_winnings += statement.signed_deltas[index].unsigned_abs() as u64;
            }
        }
        // v2 合约托管金额来源（Σ 赢家 |delta|，电路内累加）
        expected.push(hex(Felt::from(total_winnings)));
        // 公开段尾词 = 动作日志哈希（v2 合约对注册承诺逐 felt 比对）
        expected.push(hex(felt_from_bytes(statement.action_log_digest).expect("canonical")));

        let out = std::path::PathBuf::from(out_dir);
        std::fs::create_dir_all(&out).expect("create fixture dir");
        std::fs::write(
            out.join("settlement_inputs.json"),
            serde_json::to_string_pretty(&inputs).expect("json"),
        )
        .expect("write inputs");
        std::fs::write(
            out.join("settlement_expected_outputs.json"),
            serde_json::to_string_pretty(&expected).expect("json"),
        )
        .expect("write expected");
    }
}
