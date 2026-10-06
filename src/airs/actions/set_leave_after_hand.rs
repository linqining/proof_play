//! `set_leave_after_hand` AIR — 显式设置玩家是否在本手结束后离场。
//!
//! 此方法只设置一个已占用座位的 `want_leave` 标记，不改变底池、轮次、手牌或
//! 筹码池。实际退款和座位清理由后续 `reset_for_next_hand` 处理。因此它是一个
//! 可独立证明的单步 transition，与局中 `fold_with_proof` 的加密层剥离语义相互独立。

use stwo::core::fields::m31::M31;
use stwo_constraint_framework::{EvalAtRow, FrameworkEval};

use crate::airs::common::{COMMON_NUM_COLUMNS, CommonConstraints, CommonRow, ZERO, u8_to_m31};
use crate::method_kind::MethodKind;

/// `set_leave_after_hand` 业务列布局。
pub mod cols {
    use super::COMMON_NUM_COLUMNS;

    /// 目标座位。
    pub const INPUT_SEAT_INDEX: usize = COMMON_NUM_COLUMNS;
    /// 调用前的 `want_leave` 标记。
    pub const PRE_WANT_LEAVE: usize = COMMON_NUM_COLUMNS + 1;
    /// 调用后的 `want_leave` 标记。
    pub const POST_WANT_LEAVE: usize = COMMON_NUM_COLUMNS + 2;
    /// 座位已占用的 verifier-trusted witness。
    pub const INPUT_SEAT_OCCUPIED: usize = COMMON_NUM_COLUMNS + 3;
    /// 总列数。
    pub const NUM_COLUMNS: usize = COMMON_NUM_COLUMNS + 4;
}

/// `set_leave_after_hand` 的公开业务输入。
#[derive(Debug, Clone)]
pub struct SetLeaveAfterHandInput {
    /// 要设置预约状态的座位。
    pub seat_index: u8,
    /// 显式请求的目标状态。
    pub want_leave: bool,
    /// 调用前预约状态。
    pub pre_want_leave: bool,
}

/// `set_leave_after_hand` 的 AIR。
#[derive(Debug, Clone)]
pub struct SetLeaveAfterHandAir {
    /// trace 的 log2 行数。
    pub log_size: u32,
    /// 公开业务输入。
    pub input: SetLeaveAfterHandInput,
    /// 调用前 state root。
    pub pre_state_root: [M31; 4],
    /// 调用后 state root。
    pub post_state_root: [M31; 4],
    /// 表台 ID。
    pub table_id: u64,
    /// 手牌 ID。
    pub hand_id: u32,
    /// 调用序号。
    pub call_seq: u32,
    /// 调用前版本。
    pub pre_version: u64,
    /// 调用后版本。
    pub post_version: u64,
}

impl SetLeaveAfterHandAir {
    /// 总列数。
    #[must_use]
    pub const fn num_columns() -> usize {
        cols::NUM_COLUMNS
    }
}

impl FrameworkEval for SetLeaveAfterHandAir {
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
        let pre_want_leave = eval.next_trace_mask();
        let post_want_leave = eval.next_trace_mask();
        let input_seat_occupied = eval.next_trace_mask();

        let expected_seat: E::F = M31::from(u32::from(self.input.seat_index)).into();
        let expected_pre: E::F = M31::from(u32::from(self.input.pre_want_leave)).into();
        let expected_post: E::F = M31::from(u32::from(self.input.want_leave)).into();
        let one: E::F = M31::from(1u32).into();

        // Bind all business columns to verifier-reconstructed values. `bool` input types
        // make the two expected values canonical bits. State-changing commands only receive a
        // proof task, so the sum constraint proves the pre-state differs from the explicit target.
        eval.add_constraint(is_active.clone() * (input_seat_index - expected_seat));
        eval.add_constraint(is_active.clone() * (pre_want_leave.clone() - expected_pre));
        eval.add_constraint(is_active.clone() * (post_want_leave.clone() - expected_post));
        eval.add_constraint(is_active.clone() * (pre_want_leave + post_want_leave - one.clone()));
        eval.add_constraint(is_active.clone() * (input_seat_occupied - one));

        // The state-machine method has no other table-level effect.
        eval.add_constraint(common.round_state_unchanged());
        for constraint in common.pot_unchanged_4limb() {
            eval.add_constraint(constraint);
        }

        eval
    }
}

/// Active/padding trace row for [`SetLeaveAfterHandAir`].
#[derive(Debug, Clone)]
pub struct SetLeaveAfterHandRow {
    /// Shared statement columns.
    pub common: CommonRow,
    /// Target seat.
    pub input_seat_index: M31,
    /// Pre-update flag.
    pub pre_want_leave: M31,
    /// Explicit post-update flag.
    pub post_want_leave: M31,
    /// Occupancy witness.
    pub input_seat_occupied: M31,
}

impl SetLeaveAfterHandRow {
    /// Construct an active row from independently reconstructed table fields.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn active(
        input: &SetLeaveAfterHandInput,
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
        Self {
            common: CommonRow::active(
                MethodKind::SetLeaveAfterHand,
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
            pre_want_leave: M31::from(u32::from(input.pre_want_leave)),
            post_want_leave: M31::from(u32::from(input.want_leave)),
            input_seat_occupied: M31::from(1u32),
        }
    }

    /// Construct a padding row.
    #[must_use]
    pub fn padding() -> Self {
        Self {
            common: CommonRow::padding(),
            input_seat_index: ZERO,
            pre_want_leave: ZERO,
            post_want_leave: ZERO,
            input_seat_occupied: ZERO,
        }
    }

    /// Flatten the row in trace-column order.
    #[must_use]
    pub fn to_vec(&self) -> Vec<M31> {
        let mut values = self.common.to_vec();
        values.push(self.input_seat_index);
        values.push(self.pre_want_leave);
        values.push(self.post_want_leave);
        values.push(self.input_seat_occupied);
        debug_assert_eq!(values.len(), cols::NUM_COLUMNS);
        values
    }
}
