//! `submit_reconstruct_deck` AIR — 提交重构牌组。
//!
//! 移植自 `dispatch::dispatch_submit_reconstruct_deck` 与
//! `state_machine::apply_submit_reconstruct_deck`。
//!
//! ## 业务规约
//!
//! 1. 阶段守卫在 `reconstruct_state.phase == RECONSTRUCT_PHASE_COLLECTING`（**不是**
//!    `round_state`）；reconstruct 期间 `round_state` 保持不变（pre == post）。真正的
//!    相位约束由 `INPUT_RECONSTRUCT_PHASE` 列承载（见 evaluate）。
//! 2. `seat_index` 在 `reconstruct_assignments` 中
//! 3. 提交 ReconstructProof；完整 statement 必须匹配 aggregate/owner key、固定
//!    `init_deck` 明文点、重构 epoch，以及 pre-state 中该 seat 的上一轮未解手牌密文
//! 4. 状态变更：
//!    - verified contributions are folded into one 52-card streaming accumulator
//!    - 若所有玩家都已提交，调用 `rebuild_deck_from_reconstruct_deck`
//!    - 进入 settle 阶段
//!    - `version += 1`
//!
//! ## 密码学调用绑定
//!
//! AIR 除协议级状态变更外，还约束 canonical reconstruction precompile request
//! digest 与 verifier-issued receipt digest。host-native Bayer--Groth shuffle + cross-key +
//! slot-OR V3 verifier 在 binding 的唯一构造路径执行一次；生产 AIR verifier 随后重新解码
//! request、校验 ABI/backend/digest 和完整调用 replay scope，而不重复昂贵密码学验证。
//! 因此 reconstruction proof 的成功结果不是 prover 可伪造的布尔 witness。

use stwo::core::fields::m31::M31;
use stwo_constraint_framework::{EvalAtRow, FrameworkEval};

use poker_l1::contracts::texas_poker::constants::RECONSTRUCT_PHASE_COLLECTING;

use crate::airs::common::{COMMON_NUM_COLUMNS, CommonConstraints, CommonRow, ZERO, u8_to_m31};
use crate::method_kind::MethodKind;
use crate::precompile_binding::{DIGEST_LIMBS, PrecompileAirBinding};

/// `submit_reconstruct_deck` 业务特定列布局。
pub mod cols {
    use super::COMMON_NUM_COLUMNS;
    /// `INPUT_SEAT_INDEX` 列。
    pub const INPUT_SEAT_INDEX: usize = COMMON_NUM_COLUMNS + 0;
    /// `INPUT_RECONSTRUCT_PHASE` 列。
    pub const INPUT_RECONSTRUCT_PHASE: usize = COMMON_NUM_COLUMNS + 1;
    /// Precompile selector column.
    pub const PRECOMPILE_ID: usize = COMMON_NUM_COLUMNS + 2;
    /// Canonical request ABI version column.
    pub const PRECOMPILE_ABI_VERSION: usize = COMMON_NUM_COLUMNS + 3;
    /// Full request digest columns.
    pub const REQUEST_DIGEST_BASE: usize = COMMON_NUM_COLUMNS + 4;
    /// Full verifier receipt digest columns.
    pub const RECEIPT_DIGEST_BASE: usize = REQUEST_DIGEST_BASE + super::DIGEST_LIMBS;
    /// `submit_reconstruct_deck` AIR 总列数。
    pub const NUM_COLUMNS: usize = RECEIPT_DIGEST_BASE + super::DIGEST_LIMBS;
}

/// `submit_reconstruct_deck` 输入参数。
#[derive(Debug, Clone)]
pub struct SubmitReconstructDeckInput {
    /// 提交重构牌组的座位索引。
    pub seat_index: u8,
    /// 当前 reconstruct 阶段枚举值。
    pub reconstruct_phase: u8,
    /// Verifier-issued reconstruction precompile result.
    pub precompile: PrecompileAirBinding,
}

/// `submit_reconstruct_deck` AIR 公开输入。
#[derive(Debug, Clone)]
pub struct SubmitReconstructDeckAir {
    /// log2(trace 行数)。
    pub log_size: u32,
    /// 输入参数。
    pub input: SubmitReconstructDeckInput,
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

impl SubmitReconstructDeckAir {
    /// 列数。
    #[must_use]
    pub const fn num_columns() -> usize {
        cols::NUM_COLUMNS
    }
}

impl FrameworkEval for SubmitReconstructDeckAir {
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

        let input_seat_index = eval.next_trace_mask();
        let input_reconstruct_phase = eval.next_trace_mask();
        let precompile_id = eval.next_trace_mask();
        let precompile_abi_version = eval.next_trace_mask();
        let request_digest: Vec<_> = (0..DIGEST_LIMBS).map(|_| eval.next_trace_mask()).collect();
        let receipt_digest: Vec<_> = (0..DIGEST_LIMBS).map(|_| eval.next_trace_mask()).collect();

        // 约束 1：seat_index == input.seat_index
        let expected_seat: E::F = M31::from(u32::from(self.input.seat_index)).into();
        eval.add_constraint(is_active.clone() * (input_seat_index - expected_seat));

        // 约束 2：reconstruct_phase == input.reconstruct_phase（clone 保留原值供约束 4 使用）
        let expected_phase: E::F = M31::from(u32::from(self.input.reconstruct_phase)).into();
        eval.add_constraint(is_active.clone() * (input_reconstruct_phase.clone() - expected_phase));

        // 约束 3（审计共性，degree-2）：round_state 不变（reconstruct 阶段 round_state 恒为 WAITING=0）。
        eval.add_constraint(common.round_state_unchanged());
        for constraint in common.pot_unchanged_4limb() {
            eval.add_constraint(constraint);
        }

        // 约束 4：submit_reconstruct_deck 只允许 COLLECTING=1。旧约束接受
        // {COLLECTING, COMPLETE}，其安全性依赖 verifier 先做 VM replay；精确常量
        // 约束让该 method AIR 可安全进入未来的 canonical tagged composition。
        let collecting: E::F = M31::from(u32::from(RECONSTRUCT_PHASE_COLLECTING)).into();
        eval.add_constraint(is_active.clone() * (input_reconstruct_phase - collecting));

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

        eval
    }
}

/// `submit_reconstruct_deck` AIR 的 trace 行。
#[derive(Debug, Clone)]
pub struct SubmitReconstructDeckRow {
    /// 通用列。
    pub common: CommonRow,
    /// `INPUT_SEAT_INDEX`。
    pub input_seat_index: M31,
    /// `INPUT_RECONSTRUCT_PHASE`。
    pub input_reconstruct_phase: M31,
    /// Precompile selector.
    pub precompile_id: M31,
    /// Canonical request ABI version.
    pub precompile_abi_version: M31,
    /// Full request digest.
    pub request_digest: [M31; DIGEST_LIMBS],
    /// Full verifier receipt digest.
    pub receipt_digest: [M31; DIGEST_LIMBS],
}

impl SubmitReconstructDeckRow {
    /// 构造 active 行。
    #[must_use]
    pub fn active(
        input: &SubmitReconstructDeckInput,
        pre_state_root: [M31; 4],
        post_state_root: [M31; 4],
        table_id: u64,
        hand_id: u32,
        call_seq: u32,
        pre_version: u64,
        post_version: u64,
    ) -> Self {
        Self {
            common: CommonRow::active(
                MethodKind::SubmitReconstructDeck,
                pre_state_root,
                post_state_root,
                table_id,
                hand_id,
                call_seq,
                pre_version,
                post_version,
                0, // pre round_state（reconstruct 期间保持不变；相位守卫在
                //    INPUT_RECONSTRUCT_PHASE）
                0, // post round_state
                0,
                0,
                0,
                0,
            ),
            input_seat_index: u8_to_m31(input.seat_index),
            input_reconstruct_phase: u8_to_m31(input.reconstruct_phase),
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
            input_reconstruct_phase: ZERO,
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
        v.push(self.input_reconstruct_phase);
        v.push(self.precompile_id);
        v.push(self.precompile_abi_version);
        v.extend_from_slice(&self.request_digest);
        v.extend_from_slice(&self.receipt_digest);
        debug_assert_eq!(v.len(), cols::NUM_COLUMNS);
        v
    }
}

/// Validate the verifier-issued reconstruction receipt and replay scope.
pub fn validate_public_inputs(
    air: &SubmitReconstructDeckAir,
    public_inputs: &crate::public_inputs::TexasPublicInputs,
) -> crate::error::TexasAirResult<()> {
    use poker_protocol::precompile_abi::ReconstructionVerifyRequest;

    if air.input.reconstruct_phase != RECONSTRUCT_PHASE_COLLECTING {
        return Err(crate::error::TexasAirError::SpecViolation(
            "submit_reconstruct_deck requires reconstruct COLLECTING phase".into(),
        ));
    }
    let binding = public_inputs.precompile_binding.as_ref().ok_or_else(|| {
        crate::error::TexasAirError::SpecViolation(
            "submit_reconstruct_deck requires a verifier-issued precompile binding".into(),
        )
    })?;
    if binding.precompile_id() != crate::precompile_binding::PokerPrecompileId::ReconstructionV3 {
        return Err(crate::error::TexasAirError::SpecViolation(
            "submit_reconstruct_deck received the wrong precompile receipt type".into(),
        ));
    }
    binding.validate_issued()?;
    if binding.air_binding() != air.input.precompile {
        return Err(crate::error::TexasAirError::SpecViolation(
            "reconstruction AIR digest columns do not match the verifier-issued receipt".into(),
        ));
    }
    let request =
        ReconstructionVerifyRequest::decode(binding.request_bytes()).map_err(|error| {
            crate::error::TexasAirError::SpecViolation(format!(
                "reconstruction V3 request canonical decode failed: {error}"
            ))
        })?;
    let expected_context = crate::precompile_binding::precompile_call_context(
        MethodKind::SubmitReconstructDeck,
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
            "reconstruction precompile request is outside this table/hand/call/seat/state scope"
                .into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::public_inputs::TexasPublicInputs;

    fn air(reconstruct_phase: u8) -> SubmitReconstructDeckAir {
        SubmitReconstructDeckAir {
            log_size: 5,
            input: SubmitReconstructDeckInput {
                seat_index: 0,
                reconstruct_phase,
                precompile: PrecompileAirBinding::synthetic_unverified(),
            },
            pre_state_root: [M31::from(0u32); 4],
            post_state_root: [M31::from(0u32); 4],
            table_id: 0,
            hand_id: 0,
            call_seq: 0,
            pre_version: 0,
            post_version: 1,
        }
    }

    #[test]
    fn public_input_validation_requires_exact_collecting_phase() {
        let public_inputs =
            TexasPublicInputs::synthetic_placeholder(MethodKind::SubmitReconstructDeck);
        let complete = validate_public_inputs(&air(2), &public_inputs)
            .expect_err("COMPLETE must not be accepted as a submission phase");
        assert!(complete.to_string().contains("COLLECTING"));

        let collecting = validate_public_inputs(&air(RECONSTRUCT_PHASE_COLLECTING), &public_inputs)
            .expect_err("a synthetic request still lacks an issued receipt");
        assert!(
            collecting
                .to_string()
                .contains("verifier-issued precompile binding")
        );
    }
}
