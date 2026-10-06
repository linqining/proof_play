//! `submit_shuffle_v2` AIR — 玩家提交洗牌结果（V2）。
//!
//! 移植自 `dispatch::dispatch_submit_shuffle_v2` 与 `state_machine::apply_submit_shuffle_v2`。
//!
//! ## 业务规约
//!
//! 1. `round_state == ROUND_WAITING`（shuffle 阶段语义在 `shuffle_state.phase`，
//!    合约 `constants.rs` 无 `ROUND_SHUFFLE` 常量）
//! 2. `seat_index` 未在 `completed` 列表中
//! 3. 提交 52 张新加密牌 + 52 个 DLEq proof + shuffle proof
//! 4. 状态变更：
//!    - `deck_state.encrypted` 更新
//!    - `shuffle_state.completed.push(seat_index)`
//!    - 若 `completed.len() == active_count - 1`，进入 reveal 阶段
//!    - `version += 1`
//!
//! ## 密码学调用绑定
//!
//! AIR 除协议级状态变更外，还约束 canonical shuffle precompile request digest
//! 与 verifier-issued receipt digest。生产 verifier 会重新解码 request、校验不可伪造
//! binding 的 ABI/backend/digest，并校验 table/hand/call/seat/state replay scope；
//! host-native Bayer--Groth verifier 已在该 binding 的唯一构造路径执行一次，
//! 因此这里不接受 prover 提供的裸 `success = true`。

use stwo::core::fields::m31::M31;
use stwo_constraint_framework::{EvalAtRow, FrameworkEval};

use crate::airs::common::{
    COMMON_NUM_COLUMNS, CommonConstraints, CommonRow, ZERO, u8_to_m31, u64_to_m31_limbs,
};
use crate::method_kind::MethodKind;
use crate::precompile_binding::{DIGEST_LIMBS, PrecompileAirBinding};

/// `submit_shuffle_v2` 业务特定列布局。
pub mod cols {
    use super::COMMON_NUM_COLUMNS;
    /// `INPUT_SEAT_INDEX` 列。
    pub const INPUT_SEAT_INDEX: usize = COMMON_NUM_COLUMNS + 0;
    /// `INPUT_NEW_DECK_COMMITMENT` 起始列（4 limb）。
    pub const INPUT_NEW_DECK_COMMITMENT_BASE: usize = COMMON_NUM_COLUMNS + 1;
    /// `OUTPUT_COMPLETED_COUNT` 列。
    pub const OUTPUT_COMPLETED_COUNT: usize = COMMON_NUM_COLUMNS + 5;
    /// `INPUT_SHUFFLE_PHASE` 列（调用前的 `shuffle_state.phase`）。
    pub const INPUT_SHUFFLE_PHASE: usize = COMMON_NUM_COLUMNS + 6;
    /// `INPUT_SHUFFLE_PHASE_Q` 列（phase² witness，拆 3 次 vanishing）。
    pub const INPUT_SHUFFLE_PHASE_Q: usize = COMMON_NUM_COLUMNS + 7;
    /// Precompile selector column.
    pub const PRECOMPILE_ID: usize = COMMON_NUM_COLUMNS + 8;
    /// Canonical request ABI version column.
    pub const PRECOMPILE_ABI_VERSION: usize = COMMON_NUM_COLUMNS + 9;
    /// Full request digest columns.
    pub const REQUEST_DIGEST_BASE: usize = COMMON_NUM_COLUMNS + 10;
    /// Full verifier receipt digest columns.
    pub const RECEIPT_DIGEST_BASE: usize = REQUEST_DIGEST_BASE + super::DIGEST_LIMBS;
    /// `submit_shuffle_v2` AIR 总列数。
    pub const NUM_COLUMNS: usize = RECEIPT_DIGEST_BASE + super::DIGEST_LIMBS;
}

/// `submit_shuffle_v2` 输入参数。
#[derive(Debug, Clone)]
pub struct SubmitShuffleV2Input {
    /// 提交洗牌的座位索引。
    pub seat_index: u8,
    /// 新牌组承诺哈希。
    pub new_deck_commitment: u64,
    /// 调用前的 `shuffle_state.phase`（必须 ∈ {1,2,3}）。
    pub shuffle_phase: u8,
    /// Verifier-issued precompile result bound into this AIR statement.
    pub precompile: PrecompileAirBinding,
}

/// `submit_shuffle_v2` AIR 公开输入。
#[derive(Debug, Clone)]
pub struct SubmitShuffleV2Air {
    /// log2(trace 行数)。
    pub log_size: u32,
    /// 输入参数。
    pub input: SubmitShuffleV2Input,
    /// 调用前 state_root。
    pub pre_state_root: [M31; 4],
    /// 调用后 state_root。
    pub post_state_root: [M31; 4],
    /// 表台 ID。
    pub table_id: u64,
    /// 手牌序号。
    pub hand_id: u32,
    /// 调用序号。
    pub call_seq: u32,
    /// 调用前 version。
    pub pre_version: u64,
    /// 调用后 version。
    pub post_version: u64,
}

impl SubmitShuffleV2Air {
    /// 列数。
    #[must_use]
    pub const fn num_columns() -> usize {
        cols::NUM_COLUMNS
    }
}

impl FrameworkEval for SubmitShuffleV2Air {
    fn log_size(&self) -> u32 {
        self.log_size
    }
    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_size + 1
    }
    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let statement = crate::airs::TexasAir::statement(self);
        let common = CommonConstraints::write(&mut eval, &statement);
        let is_active = common.is_active.clone();
        for constraint in common.pot_unchanged_4limb() {
            eval.add_constraint(constraint);
        }

        let input_seat_index = eval.next_trace_mask();
        let input_new_deck_commitment: Vec<_> = (0..4).map(|_| eval.next_trace_mask()).collect();
        let _output_completed_count = eval.next_trace_mask();
        // 调用前 shuffle phase 与平方 witness。
        let input_shuffle_phase = eval.next_trace_mask();
        let input_shuffle_phase_q = eval.next_trace_mask();
        let precompile_id = eval.next_trace_mask();
        let precompile_abi_version = eval.next_trace_mask();
        let request_digest: Vec<_> = (0..DIGEST_LIMBS).map(|_| eval.next_trace_mask()).collect();
        let receipt_digest: Vec<_> = (0..DIGEST_LIMBS).map(|_| eval.next_trace_mask()).collect();

        // 约束 1：seat_index == input.seat_index
        let expected_seat: E::F = M31::from(u32::from(self.input.seat_index)).into();
        eval.add_constraint(is_active.clone() * (input_seat_index - expected_seat));

        // 约束 2：完整 64-bit new_deck_commitment 一致性。
        for (limb, actual) in input_new_deck_commitment.iter().enumerate() {
            let expected: E::F =
                M31::from(((self.input.new_deck_commitment >> (limb * 16)) & 0xFFFF) as u32).into();
            eval.add_constraint(is_active.clone() * (actual.clone() - expected));
        }

        // 约束 3a：shuffle_phase == input.shuffle_phase
        let expected_phase: E::F = M31::from(u32::from(self.input.shuffle_phase)).into();
        eval.add_constraint(is_active.clone() * (input_shuffle_phase.clone() - expected_phase));
        // 约束 3b：q == shuffle_phase²（witness 一致性，degree-2）
        eval.add_constraint(
            is_active.clone()
                * (input_shuffle_phase_q.clone()
                    - input_shuffle_phase.clone() * input_shuffle_phase.clone()),
        );
        // 约束 3c：shuffle_phase ∈ {1,2,3}（非 NONE=0）。
        // vanishing (phase-1)(phase-2)(phase-3) = phase³-6phase²+11phase-6
        // 经 q=phase² 展开为 degree ≤ 2：(phase·q) - 6·q + 11·phase - 6 == 0
        let six: E::F = M31::from(6u32).into();
        let eleven: E::F = M31::from(11u32).into();
        let vp = (input_shuffle_phase.clone() * input_shuffle_phase_q.clone())
            - six.clone() * input_shuffle_phase_q.clone()
            + eleven * input_shuffle_phase.clone()
            - six;
        eval.add_constraint(is_active.clone() * vp);

        let expected_precompile_id: E::F =
            M31::from(u32::from(self.input.precompile.precompile_id)).into();
        let expected_abi_version: E::F =
            M31::from(u32::from(self.input.precompile.abi_version)).into();
        eval.add_constraint(is_active.clone() * (precompile_id - expected_precompile_id));
        eval.add_constraint(is_active.clone() * (precompile_abi_version - expected_abi_version));
        for i in 0..DIGEST_LIMBS {
            let expected_request: E::F = self.input.precompile.request_digest[i].into();
            let expected_receipt: E::F = self.input.precompile.receipt_digest[i].into();
            eval.add_constraint(is_active.clone() * (request_digest[i].clone() - expected_request));
            eval.add_constraint(is_active.clone() * (receipt_digest[i].clone() - expected_receipt));
        }

        // 约束 3（审计共性，degree-2）：round_state 不变（submit_shuffle_v2 阶段 round_state 恒为 WAITING=0）。
        eval.add_constraint(common.round_state_unchanged());
        // shuffle proof 在 verifier-issued binding 构造时由 host-native precompile 验证一次；
        // 上面的完整 request/receipt digest 列把该结果绑定到此 STARK statement。若未来要求
        // trustless recursion，可在不改变 canonical request ABI 的前提下替换为
        // Verifier AIR backend。逐牌 DLEq 仍属于 join/reveal 等后续 precompile 范围。

        eval
    }
}

/// `submit_shuffle_v2` AIR 的 trace 行。
#[derive(Debug, Clone)]
pub struct SubmitShuffleV2Row {
    /// 通用列。
    pub common: CommonRow,
    /// `INPUT_SEAT_INDEX`。
    pub input_seat_index: M31,
    /// `INPUT_NEW_DECK_COMMITMENT`（4 limb）。
    pub input_new_deck_commitment: [M31; 4],
    /// `OUTPUT_COMPLETED_COUNT`。
    pub output_completed_count: M31,
    /// 调用前的 shuffle_state.phase。
    pub input_shuffle_phase: M31,
    /// phase² witness。
    pub input_shuffle_phase_q: M31,
    /// Precompile selector.
    pub precompile_id: M31,
    /// Canonical request ABI version.
    pub precompile_abi_version: M31,
    /// Full request digest.
    pub request_digest: [M31; DIGEST_LIMBS],
    /// Full verifier receipt digest.
    pub receipt_digest: [M31; DIGEST_LIMBS],
}

impl SubmitShuffleV2Row {
    /// 构造 active 行。
    #[must_use]
    pub fn active(
        input: &SubmitShuffleV2Input,
        pre_state_root: [M31; 4],
        post_state_root: [M31; 4],
        table_id: u64,
        hand_id: u32,
        call_seq: u32,
        pre_version: u64,
        post_version: u64,
        post_completed_count: u8,
    ) -> Self {
        let sp = u8_to_m31(input.shuffle_phase);
        let q = sp * sp;
        Self {
            common: CommonRow::active(
                MethodKind::SubmitShuffleV2,
                pre_state_root,
                post_state_root,
                table_id,
                hand_id,
                call_seq,
                pre_version,
                post_version,
                0, // pre = ROUND_WAITING（shuffle 语义在 shuffle_state.phase）
                0, // post = ROUND_WAITING
                0,
                0,
                0,
                0,
            ),
            input_seat_index: u8_to_m31(input.seat_index),
            input_new_deck_commitment: u64_to_m31_limbs(input.new_deck_commitment),
            output_completed_count: u8_to_m31(post_completed_count),
            input_shuffle_phase: sp,
            input_shuffle_phase_q: q,
            precompile_id: u8_to_m31(input.precompile.precompile_id),
            precompile_abi_version: u8_to_m31(input.precompile.abi_version),
            request_digest: input.precompile.request_digest,
            receipt_digest: input.precompile.receipt_digest,
        }
    }

    /// 构造 padding 行。
    #[must_use]
    pub fn padding() -> Self {
        Self {
            common: CommonRow::padding(),
            input_seat_index: ZERO,
            input_new_deck_commitment: [ZERO; 4],
            output_completed_count: ZERO,
            input_shuffle_phase: ZERO,
            input_shuffle_phase_q: ZERO,
            precompile_id: ZERO,
            precompile_abi_version: ZERO,
            request_digest: [ZERO; DIGEST_LIMBS],
            receipt_digest: [ZERO; DIGEST_LIMBS],
        }
    }

    /// 转为列向量。
    #[must_use]
    pub fn to_vec(&self) -> Vec<M31> {
        let mut v = self.common.to_vec();
        v.push(self.input_seat_index);
        v.extend_from_slice(&self.input_new_deck_commitment);
        v.push(self.output_completed_count);
        v.push(self.input_shuffle_phase);
        v.push(self.input_shuffle_phase_q);
        v.push(self.precompile_id);
        v.push(self.precompile_abi_version);
        v.extend_from_slice(&self.request_digest);
        v.extend_from_slice(&self.receipt_digest);
        debug_assert_eq!(v.len(), cols::NUM_COLUMNS);
        v
    }
}

/// Validate the verifier-issued shuffle receipt and its exact replay scope.
pub fn validate_public_inputs(
    air: &SubmitShuffleV2Air,
    public_inputs: &crate::public_inputs::TexasPublicInputs,
) -> crate::error::TexasAirResult<()> {
    use poker_protocol::precompile_abi::ShuffleVerifyRequest;

    let binding = public_inputs.precompile_binding.as_ref().ok_or_else(|| {
        crate::error::TexasAirError::SpecViolation(
            "submit_shuffle_v2 requires a verifier-issued precompile binding".into(),
        )
    })?;
    if binding.precompile_id() != crate::precompile_binding::PokerPrecompileId::Shuffle {
        return Err(crate::error::TexasAirError::SpecViolation(
            "submit_shuffle_v2 received the wrong precompile receipt type".into(),
        ));
    }
    binding.validate_issued()?;
    if binding.air_binding() != air.input.precompile {
        return Err(crate::error::TexasAirError::SpecViolation(
            "shuffle AIR digest columns do not match the verifier-issued receipt".into(),
        ));
    }
    let request = ShuffleVerifyRequest::decode(binding.request_bytes()).map_err(|error| {
        crate::error::TexasAirError::SpecViolation(format!(
            "shuffle request canonical decode failed: {error}"
        ))
    })?;
    let expected_context = crate::precompile_binding::precompile_call_context(
        MethodKind::SubmitShuffleV2,
        air.input.seat_index,
        public_inputs.table_id,
        public_inputs.hand_id,
        public_inputs.call_seq,
        public_inputs.pre_version,
        public_inputs.post_version,
        public_inputs.pre_state_root,
        public_inputs.post_state_root,
        public_inputs.dispatch_call_digest,
    );
    if request.call_context != expected_context {
        return Err(crate::error::TexasAirError::SpecViolation(
            "shuffle precompile request is outside this table/hand/call/seat/state scope".into(),
        ));
    }
    Ok(())
}
