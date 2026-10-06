//! `check` AIR — 玩家过牌（不下注且无需跟注）。
//!
//! 移植自 `dispatch::dispatch_check` 与 `state_machine::apply_check`。
//!
//! ## 业务规约
//!
//! 1. 当前处于下注轮
//! 2. `seat_index == current_turn`
//! 3. 当前下注 `current_bet == seat.bet`（无需跟注）
//! 4. 玩家未 fold、未 all_in
//! 5. 状态变更：`seat.acted_this_round = true`, `version += 1`；若本次 check
//!    使所有可行动玩家完成本轮，则合约还会收集下注并进入下一轮 reveal 阶段。
//!
//! ## AIR 列布局
//!
//! - 通用列 37 个
//! - 基础业务列 9 个
//! - shared end-betting-round columns 7 个（mid-round 时全零）

use stwo::core::fields::m31::M31;
use stwo_constraint_framework::{EvalAtRow, FrameworkEval};

use crate::airs::actions::end_betting_round::{self, BettingOutcome, EndBettingRoundRow};
use crate::airs::common::{
    COMMON_NUM_COLUMNS, CommonConstraints, CommonRow, ZERO, u8_to_m31, u64_to_m31_limbs,
};
use crate::method_kind::MethodKind;

/// `check` 业务特定列布局。
pub mod cols {
    use super::COMMON_NUM_COLUMNS;
    /// `INPUT_SEAT_INDEX` 列。
    pub const INPUT_SEAT_INDEX: usize = COMMON_NUM_COLUMNS + 0;
    /// `INPUT_CURRENT_BET` 起始列（4 limb，必须 == seat.bet 才能 check）。
    pub const INPUT_CURRENT_BET_BASE: usize = COMMON_NUM_COLUMNS + 1;
    /// `OUTPUT_ACTED` 列（1 = 已行动）。
    pub const OUTPUT_ACTED: usize = COMMON_NUM_COLUMNS + 5;
    /// `INPUT_PRE_ROUND_STATE_Q` 列（Gap 1 witness：pre_round_state²，拆 4 次 vanishing）。
    pub const INPUT_PRE_ROUND_STATE_Q: usize = COMMON_NUM_COLUMNS + 6;
    /// `INPUT_CURRENT_TURN` witness（Gap: current_turn == seat_index）。
    pub const INPUT_CURRENT_TURN: usize = COMMON_NUM_COLUMNS + 7;
    /// `OUTPUT_CURRENT_TURN` — mid-round 推进后的下一行动座位。
    pub const OUTPUT_CURRENT_TURN: usize = COMMON_NUM_COLUMNS + 8;
    /// `check` AIR 总列数。
    pub const NUM_COLUMNS: usize = COMMON_NUM_COLUMNS + 9 + super::end_betting_round::NUM_COLUMNS;
}

/// `check` 输入参数。
#[derive(Debug, Clone)]
pub struct CheckInput {
    /// 执行 check 的座位索引。
    pub seat_index: u8,
    /// 当前下注额（必须 == seat.bet）。
    pub current_bet: u64,
    /// 该座位已下注额（合约守卫：`seat.bet >= current_bet` 才允许 check；
    /// 实际等价于 `seat.bet == current_bet`，因为若 `seat.bet > current_bet`
    /// 玩家本应被退还差额而非 check；AIR 约束完整 64-bit 相等）。
    pub seat_bet: u64,
    /// Canonical mid-round or bet-collection branch derived by native replay.
    pub outcome: BettingOutcome,
}

/// `check` AIR 公开输入。
#[derive(Debug, Clone)]
pub struct CheckAir {
    /// log2(trace 行数)。
    pub log_size: u32,
    /// 输入参数。
    pub input: CheckInput,
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

impl CheckAir {
    /// 列数。
    #[must_use]
    pub const fn num_columns() -> usize {
        cols::NUM_COLUMNS
    }
}

impl FrameworkEval for CheckAir {
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
        let input_current_bet = [
            eval.next_trace_mask(),
            eval.next_trace_mask(),
            eval.next_trace_mask(),
            eval.next_trace_mask(),
        ];
        let output_acted = eval.next_trace_mask();
        // Gap 1 witness：pre_round_state²
        let input_pre_round_state_q = eval.next_trace_mask();
        // Gap: current_turn == seat_index witness
        let input_current_turn = eval.next_trace_mask();
        let output_current_turn = eval.next_trace_mask();

        // 约束 1：seat_index == input.seat_index
        let expected_seat: E::F = M31::from(u32::from(self.input.seat_index)).into();
        eval.add_constraint(is_active.clone() * (input_seat_index - expected_seat.clone()));
        // 约束: current_turn == seat_index（Gap: 阻止为非当前行动座位构造动作）
        eval.add_constraint(is_active.clone() * (input_current_turn - expected_seat));

        // 约束 2/2b：current_bet 完整 4-limb 绑定，并证明 seat.bet == current_bet。
        // 两个值均为 verifier 从 canonical u64 状态重建的常量，因此逐 limb 等式同时
        // 固定了每个 limb 的 16-bit canonical range，而不是接受 prover 自选 M31 值。
        let expected_bet = u64_to_m31_limbs(self.input.current_bet);
        let expected_seat_bet = u64_to_m31_limbs(self.input.seat_bet);
        for limb in 0..4 {
            eval.add_constraint(
                is_active.clone()
                    * (input_current_bet[limb].clone() - E::F::from(expected_bet[limb])),
            );
            eval.add_constraint(
                is_active.clone()
                    * (input_current_bet[limb].clone() - E::F::from(expected_seat_bet[limb])),
            );
        }

        // 约束 3：output_acted == 1
        let one: E::F = M31::from(1u32).into();
        eval.add_constraint(is_active.clone() * (output_acted - one));

        // 约束 4（审计共性）：调用前必须处于下注轮（Gap 1）。
        // round_state_is_betting 用 degree-4 vanishing (rs-2)(rs-3)(rs-4)(rs-5)==0
        // 经 q=rs² witness 展开为 degree-2 项，强制 rs ∈ {PREFLOP,FLOP,TURN,RIVER}。
        eval.add_constraint(common.round_state_q_constraint(input_pre_round_state_q.clone()));
        eval.add_constraint(common.round_state_is_betting(input_pre_round_state_q));

        match &self.input.outcome {
            BettingOutcome::MidRound { .. } => {
                eval.add_constraint(common.round_state_unchanged());
                for constraint in common.pot_unchanged_4limb() {
                    eval.add_constraint(constraint);
                }
                end_betting_round::evaluate(&mut eval, &common, None);
            }
            BettingOutcome::EndBettingRound(completion) => {
                end_betting_round::evaluate(&mut eval, &common, Some(completion));
            }
        }

        let expected_post_turn: E::F =
            M31::from(u32::from(self.input.outcome.post_current_turn())).into();
        eval.add_constraint(is_active * (output_current_turn - expected_post_turn));

        eval
    }
}

/// `check` AIR 的 trace 行。
#[derive(Debug, Clone)]
pub struct CheckRow {
    /// 通用列。
    pub common: CommonRow,
    /// `INPUT_SEAT_INDEX`。
    pub input_seat_index: M31,
    /// `INPUT_CURRENT_BET`（4 limb）。
    pub input_current_bet: [M31; 4],
    /// `OUTPUT_ACTED`。
    pub output_acted: M31,
    /// Gap 1 witness：pre_round_state²。
    pub input_pre_round_state_q: M31,
    /// `INPUT_CURRENT_TURN` witness（Gap: current_turn == seat_index）。
    pub input_current_turn: M31,
    /// `OUTPUT_CURRENT_TURN` — 下一行动座位，或终局 sentinel。
    pub output_current_turn: M31,
    /// Shared round-completion columns; zero for mid-round checks.
    pub round_completion: EndBettingRoundRow,
}

impl CheckRow {
    /// 构造 active 行。
    #[must_use]
    pub fn active(
        input: &CheckInput,
        pre_state_root: [M31; 4],
        post_state_root: [M31; 4],
        table_id: u64,
        hand_id: u32,
        call_seq: u32,
        pre_version: u64,
        post_version: u64,
        pre_round_state: u8,
        post_round_state: u8,
        pre_pot: u64,
        post_pot: u64,
    ) -> Self {
        let rs_m31 = u8_to_m31(pre_round_state);
        Self {
            common: CommonRow::active(
                MethodKind::Check,
                pre_state_root,
                post_state_root,
                table_id,
                hand_id,
                call_seq,
                pre_version,
                post_version,
                pre_round_state,
                post_round_state,
                pre_pot,
                post_pot,
                0,
                0,
            ),
            input_seat_index: u8_to_m31(input.seat_index),
            input_current_bet: u64_to_m31_limbs(input.current_bet),
            output_acted: M31::from(1u32),
            // Gap 1 witness：pre_round_state²（M31 域内）
            input_pre_round_state_q: rs_m31 * rs_m31,
            input_current_turn: u8_to_m31(input.seat_index), // current_turn == seat_index
            output_current_turn: u8_to_m31(input.outcome.post_current_turn()),
            round_completion: match &input.outcome {
                BettingOutcome::MidRound { .. } => EndBettingRoundRow::zero(),
                BettingOutcome::EndBettingRound(completion) => {
                    EndBettingRoundRow::active(completion, pre_pot, post_pot)
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
            input_current_bet: [ZERO; 4],
            output_acted: ZERO,
            input_pre_round_state_q: ZERO,
            input_current_turn: ZERO,
            output_current_turn: ZERO,
            round_completion: EndBettingRoundRow::zero(),
        }
    }

    /// 转为列向量。
    #[must_use]
    pub fn to_vec(&self) -> Vec<M31> {
        let mut v = self.common.to_vec();
        v.push(self.input_seat_index);
        v.extend_from_slice(&self.input_current_bet);
        v.push(self.output_acted);
        v.push(self.input_pre_round_state_q);
        v.push(self.input_current_turn);
        v.push(self.output_current_turn);
        self.round_completion.append_to(&mut v);
        debug_assert_eq!(v.len(), cols::NUM_COLUMNS);
        v
    }
}
