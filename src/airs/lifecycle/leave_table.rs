//! `leave_table` AIR — 简单离座（仅在 WAITING 状态）。
//!
//! ## 业务规约
//! 1. `round_state == ROUND_WAITING`
//! 2. `seat_index < max_players`
//! 3. 座位非空
//! 4. 退款：`refund = seat.stack + seat.pending_addon`
//! 5. 资金守恒：`chip_pool -= refund`
//! 6. 状态变更：`seat = Seat::empty()`, `call_seq += 1`

use stwo::core::fields::m31::M31;
use stwo_constraint_framework::{EvalAtRow, FrameworkEval};

use crate::airs::common::{
    COMMON_NUM_COLUMNS, CommonConstraints, CommonRow, ZERO, compute_add_carries, u8_to_m31,
    u64_to_m31_limbs,
};
use crate::method_kind::MethodKind;

/// `leave_table` 业务特定列布局。
pub mod cols {
    use super::COMMON_NUM_COLUMNS;
    /// `INPUT_SEAT_INDEX` 列。
    pub const INPUT_SEAT_INDEX: usize = COMMON_NUM_COLUMNS + 0;
    /// `OUTPUT_REFUND_AMOUNT` 起始列（4 limb）。
    pub const OUTPUT_REFUND_BASE: usize = COMMON_NUM_COLUMNS + 1;
    /// `INPUT_SEAT_OCCUPIED` boolean witness（Gap 3）：诚实 host 只对占用座位离座，
    /// 故前置「座位非空」由该列 == 1 强制。
    pub const INPUT_SEAT_OCCUPIED: usize = COMMON_NUM_COLUMNS + 5;
    /// `INPUT_SEAT_STACK` 起始列（4 limb）— 退款计算。
    pub const INPUT_SEAT_STACK_BASE: usize = COMMON_NUM_COLUMNS + 6;
    /// `INPUT_SEAT_PENDING_ADDON` 起始列（4 limb）— 退款计算。
    pub const INPUT_SEAT_PENDING_ADDON_BASE: usize = COMMON_NUM_COLUMNS + 10;
    /// `INPUT_PRE_CHIP_POOL` 起始列（4 limb）— chip_pool 守恒。
    pub const INPUT_PRE_CHIP_POOL_BASE: usize = COMMON_NUM_COLUMNS + 14;
    /// `OUTPUT_POST_CHIP_POOL` 起始列（4 limb）— chip_pool 守恒。
    pub const OUTPUT_POST_CHIP_POOL_BASE: usize = COMMON_NUM_COLUMNS + 18;
    /// `refund = stack + pending_addon` 的 3 个 ripple-carry bit。
    pub const REFUND_ADD_CARRY_BASE: usize = COMMON_NUM_COLUMNS + 22;
    /// `pre_chip_pool = post_chip_pool + stack` 的 3 个 ripple-carry bit。
    pub const CHIP_POOL_SUB_CARRY_BASE: usize = COMMON_NUM_COLUMNS + 25;
    /// 总列数。
    pub const NUM_COLUMNS: usize = COMMON_NUM_COLUMNS + 28;
}

/// `leave_table` 输入参数。
#[derive(Debug, Clone)]
pub struct LeaveTableInput {
    /// 座位索引。
    pub seat_index: u8,
}

/// `leave_table` AIR。
#[derive(Debug, Clone)]
pub struct LeaveTableAir {
    /// log2(行数)。
    pub log_size: u32,
    /// 输入参数。
    pub input: LeaveTableInput,
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

impl LeaveTableAir {
    /// 列数。
    #[must_use]
    pub const fn num_columns() -> usize {
        cols::NUM_COLUMNS
    }
}

impl FrameworkEval for LeaveTableAir {
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
        let refund_0 = eval.next_trace_mask();
        let refund_1 = eval.next_trace_mask();
        let refund_2 = eval.next_trace_mask();
        let refund_3 = eval.next_trace_mask();
        // Gap 3 boolean witness（座位非空）。
        let input_seat_occupied = eval.next_trace_mask();
        // Gap：座位 stack（4 limb）— 退款计算。
        let seat_stack_0 = eval.next_trace_mask();
        let seat_stack_1 = eval.next_trace_mask();
        let seat_stack_2 = eval.next_trace_mask();
        let seat_stack_3 = eval.next_trace_mask();
        // Gap：座位 pending_addon（4 limb）— 退款计算。
        let seat_pending_addon_0 = eval.next_trace_mask();
        let seat_pending_addon_1 = eval.next_trace_mask();
        let seat_pending_addon_2 = eval.next_trace_mask();
        let seat_pending_addon_3 = eval.next_trace_mask();
        // Gap：pre/post chip_pool（4 limb）— chip_pool 守恒。
        let pre_chip_pool_0 = eval.next_trace_mask();
        let pre_chip_pool_1 = eval.next_trace_mask();
        let pre_chip_pool_2 = eval.next_trace_mask();
        let pre_chip_pool_3 = eval.next_trace_mask();
        let post_chip_pool_0 = eval.next_trace_mask();
        let post_chip_pool_1 = eval.next_trace_mask();
        let post_chip_pool_2 = eval.next_trace_mask();
        let post_chip_pool_3 = eval.next_trace_mask();
        let refund_add_carry_0 = eval.next_trace_mask();
        let refund_add_carry_1 = eval.next_trace_mask();
        let refund_add_carry_2 = eval.next_trace_mask();
        let chip_pool_sub_carry_0 = eval.next_trace_mask();
        let chip_pool_sub_carry_1 = eval.next_trace_mask();
        let chip_pool_sub_carry_2 = eval.next_trace_mask();

        // 约束：seat_index == input.seat_index
        let expected: E::F = M31::from(u32::from(self.input.seat_index)).into();
        eval.add_constraint(is_active.clone() * (input_seat_index - expected));

        // 约束 2（审计 leave_table 前置，degree-2）：pre_round_state == WAITING(0)。
        eval.add_constraint(common.round_state_eq(0));
        // 约束 3（degree-2）：round_state 不变。
        eval.add_constraint(common.round_state_unchanged());
        for constraint in common.pot_unchanged_4limb() {
            eval.add_constraint(constraint);
        }
        // 约束 4（Gap 3，degree-2）：input_seat_occupied == 1 — 诚实 host 只对占用座位离座。
        let one: E::F = M31::from(1u32).into();
        eval.add_constraint(is_active.clone() * (input_seat_occupied - one));
        let refund = [refund_0, refund_1, refund_2, refund_3];
        let seat_stack = [seat_stack_0, seat_stack_1, seat_stack_2, seat_stack_3];
        let seat_pending_addon = [
            seat_pending_addon_0,
            seat_pending_addon_1,
            seat_pending_addon_2,
            seat_pending_addon_3,
        ];
        let pre_chip_pool = [
            pre_chip_pool_0,
            pre_chip_pool_1,
            pre_chip_pool_2,
            pre_chip_pool_3,
        ];
        let post_chip_pool = [
            post_chip_pool_0,
            post_chip_pool_1,
            post_chip_pool_2,
            post_chip_pool_3,
        ];
        let refund_add_carry = [refund_add_carry_0, refund_add_carry_1, refund_add_carry_2];
        let chip_pool_sub_carry = [
            chip_pool_sub_carry_0,
            chip_pool_sub_carry_1,
            chip_pool_sub_carry_2,
        ];

        // 退款：refund = stack + pending_addon。
        for constraint in
            common.limb4_delta(&seat_stack, &refund, &seat_pending_addon, &refund_add_carry)
        {
            eval.add_constraint(constraint);
        }
        // 资金池减法用反向加法表达，从而显式约束跨 limb 借位且禁止下溢。
        for constraint in common.limb4_delta_rev(
            &pre_chip_pool,
            &post_chip_pool,
            &refund,
            &chip_pool_sub_carry,
        ) {
            eval.add_constraint(constraint);
        }
        eval
    }
}

/// `leave_table` trace 行。
#[derive(Debug, Clone)]
pub struct LeaveTableRow {
    /// 通用列。
    pub common: CommonRow,
    /// 座位索引。
    pub input_seat_index: M31,
    /// 退款金额。
    pub output_refund: [M31; 4],
    /// `INPUT_SEAT_OCCUPIED` boolean witness（Gap 3）。
    pub input_seat_occupied: M31,
    /// `INPUT_SEAT_STACK`（4 limb）— 退款计算。
    pub input_seat_stack: [M31; 4],
    /// `INPUT_SEAT_PENDING_ADDON`（4 limb）— 退款计算。
    pub input_seat_pending_addon: [M31; 4],
    /// `INPUT_PRE_CHIP_POOL`（4 limb）— chip_pool 守恒。
    pub input_pre_chip_pool: [M31; 4],
    /// `OUTPUT_POST_CHIP_POOL`（4 limb）— chip_pool 守恒。
    pub output_post_chip_pool: [M31; 4],
    /// `refund = stack + pending_addon` 的 ripple-carry bit。
    pub refund_add_carry: [M31; 3],
    /// `pre_chip_pool = post_chip_pool + refund` 的 ripple-carry bit。
    pub chip_pool_sub_carry: [M31; 3],
}

impl LeaveTableRow {
    /// active 行。
    #[must_use]
    pub fn active(
        input: &LeaveTableInput,
        pre_state_root: [M31; 4],
        post_state_root: [M31; 4],
        table_id: u64,
        hand_id: u32,
        call_seq: u32,
        pre_version: u64,
        post_version: u64,
        seat_stack: u64,
        seat_pending_addon: u64,
        pre_chip_pool: u64,
        post_chip_pool: u64,
    ) -> Self {
        let refund = seat_stack
            .checked_add(seat_pending_addon)
            .expect("leave_table refund must not overflow");
        assert_eq!(
            post_chip_pool.checked_add(refund),
            Some(pre_chip_pool),
            "leave_table chip_pool subtraction must not underflow"
        );
        Self {
            common: CommonRow::active(
                MethodKind::LeaveTable,
                pre_state_root,
                post_state_root,
                table_id,
                hand_id,
                call_seq,
                pre_version,
                post_version,
                0,
                0,
                0,
                0,
                0,
                0,
            ),
            input_seat_index: u8_to_m31(input.seat_index),
            output_refund: u64_to_m31_limbs(refund),
            // Gap 3：诚实 host 只对占用座位离座。
            input_seat_occupied: M31::from(1u32),
            // 退款计算字段。
            input_seat_stack: u64_to_m31_limbs(seat_stack),
            input_seat_pending_addon: u64_to_m31_limbs(seat_pending_addon),
            // chip_pool 守恒：post = pre - (stack + pending_addon)。
            input_pre_chip_pool: u64_to_m31_limbs(pre_chip_pool),
            output_post_chip_pool: u64_to_m31_limbs(post_chip_pool),
            refund_add_carry: compute_add_carries(seat_stack, seat_pending_addon),
            chip_pool_sub_carry: compute_add_carries(post_chip_pool, refund),
        }
    }
    /// padding 行。
    #[must_use]
    pub fn padding() -> Self {
        Self {
            common: CommonRow::padding(),
            input_seat_index: ZERO,
            output_refund: [ZERO; 4],
            input_seat_occupied: ZERO,
            input_seat_stack: [ZERO; 4],
            input_seat_pending_addon: [ZERO; 4],
            input_pre_chip_pool: [ZERO; 4],
            output_post_chip_pool: [ZERO; 4],
            refund_add_carry: [ZERO; 3],
            chip_pool_sub_carry: [ZERO; 3],
        }
    }
    /// 转列向量。
    #[must_use]
    pub fn to_vec(&self) -> Vec<M31> {
        let mut v = self.common.to_vec();
        v.push(self.input_seat_index);
        v.extend_from_slice(&self.output_refund);
        v.push(self.input_seat_occupied);
        v.extend_from_slice(&self.input_seat_stack);
        v.extend_from_slice(&self.input_seat_pending_addon);
        v.extend_from_slice(&self.input_pre_chip_pool);
        v.extend_from_slice(&self.output_post_chip_pool);
        v.extend_from_slice(&self.refund_add_carry);
        v.extend_from_slice(&self.chip_pool_sub_carry);
        debug_assert_eq!(v.len(), cols::NUM_COLUMNS);
        v
    }
}
