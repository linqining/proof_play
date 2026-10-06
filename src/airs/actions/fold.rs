//! `fold` AIR — 玩家主动 fold（弃牌）。
//!
//! 移植自 `dispatch::dispatch_fold` 与 `state_machine::apply_fold`。
//!
//! ## 业务规约
//!
//! 1. 当前 `round_state ∈ {PREFLOP, FLOP, TURN, RIVER}`（下注轮）
//! 2. `seat_index` 是当前行动玩家（`current_turn == seat_index`）
//! 3. 玩家未 fold、未 all_in
//! 4. mid-round：`seat.folded = true` 并推进 turn
//! 5. last-player-standing：收集当前 bets、扣 rake、奖励赢家并 reset 到 WAITING
//!
//! ## AIR 列布局
//!
//! - 通用列 37 个
//! - fold branch columns 5 个
//! - shared terminal settlement columns 34 个（mid-round 时全零）

use stwo::core::fields::m31::M31;
use stwo_constraint_framework::{EvalAtRow, FrameworkEval};

use crate::airs::actions::end_without_showdown::{self, EndWithoutShowdownRow, FoldOutcome};
use crate::airs::common::{
    COMMON_NUM_COLUMNS, CommonConstraints, CommonRow, ZERO, bool_to_m31, u8_to_m31,
};
use crate::method_kind::MethodKind;

/// `fold` 业务特定列布局。
pub mod cols {
    use super::COMMON_NUM_COLUMNS;
    /// `INPUT_SEAT_INDEX` 列。
    pub const INPUT_SEAT_INDEX: usize = COMMON_NUM_COLUMNS + 0;
    /// `OUTPUT_FOLDED` 列（1 = 已 fold，0 = 未 fold）。
    pub const OUTPUT_FOLDED: usize = COMMON_NUM_COLUMNS + 1;
    /// `INPUT_PRE_ROUND_STATE_Q` 列（Gap 1 witness：pre_round_state²，拆 4 次 vanishing）。
    pub const INPUT_PRE_ROUND_STATE_Q: usize = COMMON_NUM_COLUMNS + 2;
    /// `INPUT_CURRENT_TURN` witness（Gap: current_turn == seat_index）。
    pub const INPUT_CURRENT_TURN: usize = COMMON_NUM_COLUMNS + 3;
    /// `OUTPUT_CURRENT_TURN` — mid-round 推进后的下一行动座位。
    pub const OUTPUT_CURRENT_TURN: usize = COMMON_NUM_COLUMNS + 4;
    /// `fold` AIR 总列数。
    pub const NUM_COLUMNS: usize =
        COMMON_NUM_COLUMNS + 5 + super::end_without_showdown::NUM_COLUMNS;
}

/// `fold` 输入参数。
#[derive(Debug, Clone)]
pub struct FoldInput {
    /// 执行 fold 的座位索引。
    pub seat_index: u8,
    /// Native-replayed mid-round or terminal settlement branch.
    pub outcome: FoldOutcome,
}

/// `fold` AIR 公开输入。
#[derive(Debug, Clone)]
pub struct FoldAir {
    /// log2(trace 行数)。
    pub log_size: u32,
    /// 输入参数。
    pub input: FoldInput,
    /// 调用前 state_root（4 limb）。
    pub pre_state_root: [M31; 4],
    /// 调用后 state_root（4 limb）。
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

impl FoldAir {
    /// 列数。
    #[must_use]
    pub const fn num_columns() -> usize {
        cols::NUM_COLUMNS
    }
}

impl FrameworkEval for FoldAir {
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

        // 约束 1：seat_index == input.seat_index
        let expected_seat: E::F = M31::from(u32::from(self.input.seat_index)).into();
        eval.add_constraint(is_active.clone() * (input_seat_index - expected_seat.clone()));
        // 约束: current_turn == seat_index（Gap: 阻止为非当前行动座位构造动作）
        eval.add_constraint(is_active.clone() * (input_current_turn - expected_seat));

        // 约束 2：必须从下注轮进入已重放的 mid-round 或 terminal 分支。
        // round_state_is_betting 用 degree-4 vanishing (rs-2)(rs-3)(rs-4)(rs-5)==0
        // 经 q=rs² witness 展开为 degree-2 项，强制 rs ∈ {PREFLOP,FLOP,TURN,RIVER}，
        // 阻止恶意 prover 在 ROUND_WAITING 下构造 fold trace。
        eval.add_constraint(common.round_state_q_constraint(input_pre_round_state_q.clone()));
        eval.add_constraint(common.round_state_is_betting(input_pre_round_state_q));

        let expected_folded: E::F = bool_to_m31(self.input.outcome.output_folded()).into();
        eval.add_constraint(is_active.clone() * (output_folded - expected_folded));
        let expected_post_turn: E::F =
            M31::from(u32::from(self.input.outcome.post_current_turn())).into();
        eval.add_constraint(is_active * (output_current_turn - expected_post_turn));

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

/// `fold` AIR 的 trace 行。
#[derive(Debug, Clone)]
pub struct FoldRow {
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
    /// Shared terminal settlement columns; zero for mid-round folds.
    pub settlement: EndWithoutShowdownRow,
}

impl FoldRow {
    /// 构造 active 行。
    #[must_use]
    pub fn active(
        input: &FoldInput,
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
                MethodKind::Fold,
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
            output_folded: bool_to_m31(input.outcome.output_folded()),
            // Gap 1 witness：pre_round_state²（M31 域内）
            input_pre_round_state_q: rs_m31 * rs_m31,
            input_current_turn: u8_to_m31(input.seat_index), // current_turn == seat_index
            output_current_turn: u8_to_m31(input.outcome.post_current_turn()),
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
        self.settlement.append_to(&mut v);
        debug_assert_eq!(v.len(), cols::NUM_COLUMNS);
        v
    }
}
