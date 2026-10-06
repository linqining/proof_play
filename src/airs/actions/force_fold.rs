//! `force_fold` AIR — 管理员强制 fold 玩家（治理操作）。
//!
//! 移植自 `dispatch::dispatch_force_fold` 与 `state_machine::apply_force_fold`。
//!
//! ## 业务规约
//!
//! 1. 调用者是管理员（admin）
//! 2. 目标座位存在且 occupied
//! 3. 玩家未 fold
//! 4. 状态变更：`seat.folded = true`, `version += 1`
//!
//! 与 [`crate::airs::actions::fold`] 的区别：
//! - `fold`：玩家自己操作（`seat_index == current_turn`）
//! - `force_fold`：管理员强制（不要求 `seat_index == current_turn`）
//!
//! ## AIR 列布局
//!
//! - 通用列 37 个
//! - 动作列 5 个
//! - 管理员授权列 34 个：ABI、role、完整 request/receipt digest
//! - terminal settlement 列 34 个（mid-round 时全零）
//!
//! 交易签名由共识锚验证；本 AIR 绑定 canonical dispatch replay 签发的管理员授权
//! receipt，不能由 prover 自报 `is_admin = 1`。

use stwo::core::fields::m31::M31;
use stwo_constraint_framework::{EvalAtRow, FrameworkEval};

use crate::airs::actions::end_without_showdown::{self, EndWithoutShowdownRow, FoldOutcome};
use crate::airs::common::{
    COMMON_NUM_COLUMNS, CommonConstraints, CommonRow, ZERO, bool_to_m31, u8_to_m31,
};
use crate::authorization_binding::AdminAuthorizationAirBinding;
use crate::method_kind::MethodKind;
use crate::precompile_binding::DIGEST_LIMBS;

/// `force_fold` 业务特定列布局。
pub mod cols {
    use super::COMMON_NUM_COLUMNS;
    /// `INPUT_SEAT_INDEX` 列。
    pub const INPUT_SEAT_INDEX: usize = COMMON_NUM_COLUMNS + 0;
    /// `OUTPUT_FOLDED` 列。
    pub const OUTPUT_FOLDED: usize = COMMON_NUM_COLUMNS + 1;
    /// `INPUT_PRE_ROUND_STATE_Q` 列（Gap 1 witness：pre_round_state²，拆 4 次 vanishing）。
    pub const INPUT_PRE_ROUND_STATE_Q: usize = COMMON_NUM_COLUMNS + 2;
    /// `INPUT_CURRENT_TURN` witness（Gap: current_turn == seat_index）。
    pub const INPUT_CURRENT_TURN: usize = COMMON_NUM_COLUMNS + 3;
    /// `OUTPUT_CURRENT_TURN` — mid-round 推进后的下一行动座位。
    pub const OUTPUT_CURRENT_TURN: usize = COMMON_NUM_COLUMNS + 4;
    /// 管理员授权 ABI 版本。
    pub const AUTH_ABI_VERSION: usize = COMMON_NUM_COLUMNS + 5;
    /// 管理员授权角色。
    pub const AUTH_ROLE: usize = COMMON_NUM_COLUMNS + 6;
    /// 完整授权请求摘要。
    pub const AUTH_REQUEST_DIGEST_BASE: usize = COMMON_NUM_COLUMNS + 7;
    /// 完整授权成功 receipt 摘要。
    pub const AUTH_RECEIPT_DIGEST_BASE: usize = AUTH_REQUEST_DIGEST_BASE + super::DIGEST_LIMBS;
    /// `force_fold` AIR 总列数。
    pub const NUM_COLUMNS: usize =
        AUTH_RECEIPT_DIGEST_BASE + super::DIGEST_LIMBS + super::end_without_showdown::NUM_COLUMNS;
}

/// `force_fold` 输入参数。
#[derive(Debug, Clone)]
pub struct ForceFoldInput {
    /// 被强制 fold 的座位索引。
    pub seat_index: u8,
    /// Native-replayed mid-round or terminal settlement branch.
    pub outcome: FoldOutcome,
    /// Verifier-issued table-creator authorization receipt.
    pub authorization: AdminAuthorizationAirBinding,
}

/// `force_fold` AIR 公开输入。
#[derive(Debug, Clone)]
pub struct ForceFoldAir {
    /// log2(trace 行数)。
    pub log_size: u32,
    /// 输入参数。
    pub input: ForceFoldInput,
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

impl ForceFoldAir {
    /// 列数。
    #[must_use]
    pub const fn num_columns() -> usize {
        cols::NUM_COLUMNS
    }
}

impl FrameworkEval for ForceFoldAir {
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
        let output_folded = eval.next_trace_mask();
        // Gap 1 witness：pre_round_state²
        let input_pre_round_state_q = eval.next_trace_mask();
        // Gap: current_turn == seat_index witness
        let input_current_turn = eval.next_trace_mask();
        let output_current_turn = eval.next_trace_mask();
        let auth_abi_version = eval.next_trace_mask();
        let auth_role = eval.next_trace_mask();
        let auth_request_digest: Vec<_> =
            (0..DIGEST_LIMBS).map(|_| eval.next_trace_mask()).collect();
        let auth_receipt_digest: Vec<_> =
            (0..DIGEST_LIMBS).map(|_| eval.next_trace_mask()).collect();

        // 约束 1：seat_index == input.seat_index
        let expected_seat: E::F = M31::from(u32::from(self.input.seat_index)).into();
        eval.add_constraint(is_active.clone() * (input_seat_index - expected_seat.clone()));
        // 约束: current_turn == seat_index（Gap: 阻止为非当前行动座位构造动作）
        eval.add_constraint(is_active.clone() * (input_current_turn - expected_seat));

        // 约束 2：terminal reset 会清除 folded；mid-round 保留 folded。
        let expected_folded: E::F = bool_to_m31(self.input.outcome.output_folded()).into();
        eval.add_constraint(is_active.clone() * (output_folded - expected_folded));

        // 约束 3（审计共性）：必须处于下注轮（Gap 1）。
        // round_state_is_betting 用 degree-4 vanishing (rs-2)(rs-3)(rs-4)(rs-5)==0
        // 经 q=rs² witness 展开为 degree-2 项，强制 rs ∈ {PREFLOP,FLOP,TURN,RIVER}。
        eval.add_constraint(common.round_state_q_constraint(input_pre_round_state_q.clone()));
        eval.add_constraint(common.round_state_is_betting(input_pre_round_state_q));

        let expected_post_turn: E::F =
            M31::from(u32::from(self.input.outcome.post_current_turn())).into();
        eval.add_constraint(is_active.clone() * (output_current_turn - expected_post_turn));

        // 约束 5：绑定 host-native canonical authorization request/receipt。
        let expected_abi: E::F = M31::from(u32::from(self.input.authorization.abi_version)).into();
        let expected_role: E::F = M31::from(u32::from(self.input.authorization.role)).into();
        eval.add_constraint(is_active.clone() * (auth_abi_version - expected_abi));
        eval.add_constraint(is_active.clone() * (auth_role - expected_role));
        for limb in 0..DIGEST_LIMBS {
            let request: E::F = self.input.authorization.request_digest[limb].into();
            let receipt: E::F = self.input.authorization.receipt_digest[limb].into();
            eval.add_constraint(is_active.clone() * (auth_request_digest[limb].clone() - request));
            eval.add_constraint(is_active.clone() * (auth_receipt_digest[limb].clone() - receipt));
        }

        match &self.input.outcome {
            FoldOutcome::MidRound { .. } => {
                eval.add_constraint(common.round_state_unchanged());
                for constraint in common.pot_unchanged_4limb() {
                    eval.add_constraint(constraint);
                }
                end_without_showdown::evaluate(&mut eval, &common, None);
            }
            FoldOutcome::EndWithoutShowdown(settlement) => {
                end_without_showdown::evaluate(&mut eval, &common, Some(settlement));
            }
        }

        eval
    }
}

/// `force_fold` AIR 的 trace 行。
#[derive(Debug, Clone)]
pub struct ForceFoldRow {
    /// 通用列。
    pub common: CommonRow,
    /// `INPUT_SEAT_INDEX`。
    pub input_seat_index: M31,
    /// `OUTPUT_FOLDED`。
    pub output_folded: M31,
    /// Gap 1 witness：pre_round_state²。
    pub input_pre_round_state_q: M31,
    /// `INPUT_CURRENT_TURN` witness（Gap: current_turn == seat_index）。
    pub input_current_turn: M31,
    /// `OUTPUT_CURRENT_TURN` — mid-round 的下一行动座位。
    pub output_current_turn: M31,
    /// Verifier-issued administrator authorization binding.
    pub authorization: AdminAuthorizationAirBinding,
    /// Shared terminal settlement columns; zero for mid-round folds.
    pub settlement: EndWithoutShowdownRow,
}

impl ForceFoldRow {
    /// 构造 active 行。
    #[must_use]
    pub fn active(
        input: &ForceFoldInput,
        pre_state_root: [M31; 4],
        post_state_root: [M31; 4],
        table_id: u64,
        hand_id: u32,
        call_seq: u32,
        pre_version: u64,
        post_version: u64,
        pre_round_state: u8,
        post_round_state: u8,
    ) -> Self {
        let rs_m31 = u8_to_m31(pre_round_state);
        Self {
            common: CommonRow::active(
                MethodKind::ForceFold,
                pre_state_root,
                post_state_root,
                table_id,
                hand_id,
                call_seq,
                pre_version,
                post_version,
                pre_round_state,
                post_round_state,
                0,
                0,
                0,
                0,
            ),
            input_seat_index: u8_to_m31(input.seat_index),
            output_folded: bool_to_m31(input.outcome.output_folded()),
            // Gap 1 witness：pre_round_state²（M31 域内）
            input_pre_round_state_q: rs_m31 * rs_m31,
            input_current_turn: u8_to_m31(input.seat_index), // current_turn == seat_index
            output_current_turn: u8_to_m31(input.outcome.post_current_turn()),
            authorization: input.authorization,
            settlement: match &input.outcome {
                FoldOutcome::MidRound { .. } => EndWithoutShowdownRow::zero(),
                FoldOutcome::EndWithoutShowdown(settlement) => {
                    EndWithoutShowdownRow::active(settlement)
                }
            },
        }
    }

    /// 构造 padding 行。
    #[must_use]
    pub fn padding() -> Self {
        Self {
            common: CommonRow::padding(),
            input_seat_index: ZERO,
            output_folded: ZERO,
            input_pre_round_state_q: ZERO,
            input_current_turn: ZERO,
            output_current_turn: ZERO,
            authorization: AdminAuthorizationAirBinding {
                abi_version: 0,
                role: 0,
                request_digest: [ZERO; DIGEST_LIMBS],
                receipt_digest: [ZERO; DIGEST_LIMBS],
            },
            settlement: EndWithoutShowdownRow::zero(),
        }
    }

    /// 转为列向量。
    #[must_use]
    pub fn to_vec(&self) -> Vec<M31> {
        let mut v = self.common.to_vec();
        v.push(self.input_seat_index);
        v.push(self.output_folded);
        v.push(self.input_pre_round_state_q);
        v.push(self.input_current_turn);
        v.push(self.output_current_turn);
        v.push(M31::from(u32::from(self.authorization.abi_version)));
        v.push(M31::from(u32::from(self.authorization.role)));
        v.extend_from_slice(&self.authorization.request_digest);
        v.extend_from_slice(&self.authorization.receipt_digest);
        self.settlement.append_to(&mut v);
        debug_assert_eq!(v.len(), cols::NUM_COLUMNS);
        v
    }
}
