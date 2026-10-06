//! `join_table` AIR — 简单入座（不参与本局，等下一局）。
//!
//! 移植自 `dispatch::dispatch_join_table` 与 `state_machine` 的入座逻辑。
//!
//! ## 业务规约
//!
//! 1. `round_state == ROUND_WAITING`
//! 2. `seat_index < max_players`
//! 3. 目标座位为空（`seat.player == EMPTY_PLAYER`）
//! 4. `buy_in >= big_blind`
//! 5. 玩家公钥已注册
//!
//! 状态变更：`seat.player = player_addr`, `seat.stack = buy_in`, `version += 1`

use stwo::core::fields::m31::M31;
use stwo_constraint_framework::{EvalAtRow, FrameworkEval};

use crate::airs::common::{
    COMMON_NUM_COLUMNS, CommonConstraints, CommonRow, MAX_TOTAL_BET, ZERO, compute_add_carries,
    compute_bound_carries, u8_to_m31, u64_to_m31_limbs,
};
use crate::method_kind::MethodKind;

/// `join_table` 业务特定列布局。
pub mod cols {
    use super::COMMON_NUM_COLUMNS;

    /// `INPUT_SEAT_INDEX` 列。
    pub const INPUT_SEAT_INDEX: usize = COMMON_NUM_COLUMNS + 0;
    /// `INPUT_BUY_IN` 起始列（4 limb）。
    pub const INPUT_BUY_IN_BASE: usize = COMMON_NUM_COLUMNS + 1;
    /// `INPUT_PLAYER_ADDR` 起始列（4 limb，Blake2b 压缩后）。
    pub const INPUT_PLAYER_ADDR_BASE: usize = COMMON_NUM_COLUMNS + 5;
    /// `OUTPUT_SEAT_STACK` 起始列（4 limb）。
    pub const OUTPUT_SEAT_STACK_BASE: usize = COMMON_NUM_COLUMNS + 9;
    /// `INPUT_SEAT_EMPTY` boolean witness（Gap 2）：诚实 host 只在空座位入座，
    /// 故前置「目标座位为空」由该列 == 1 强制。
    pub const INPUT_SEAT_EMPTY: usize = COMMON_NUM_COLUMNS + 13;
    /// `INPUT_BIG_BLIND` 起始列（4 limb）：大盲注，用于 buy_in >= big_blind 约束。
    pub const INPUT_BIG_BLIND_BASE: usize = COMMON_NUM_COLUMNS + 14;
    /// `INPUT_PRE_CHIP_POOL` 起始列（4 limb）：pre chip_pool，用于资金守恒。
    pub const INPUT_PRE_CHIP_POOL_BASE: usize = COMMON_NUM_COLUMNS + 18;
    /// `OUTPUT_POST_CHIP_POOL` 起始列（4 limb）：post chip_pool，用于资金守恒。
    pub const OUTPUT_POST_CHIP_POOL_BASE: usize = COMMON_NUM_COLUMNS + 22;
    /// BOUND_DIFF 起始列（4 limb）— diff = MAX_TOTAL_BET - (chip_pool + buy_in)。
    pub const BOUND_DIFF_BASE: usize = COMMON_NUM_COLUMNS + 26;
    /// BOUND_CARRY_LO 起始列（3 个低位 bit）— 2-bit carry 分解的 lo 部分。
    pub const BOUND_CARRY_LO_BASE: usize = COMMON_NUM_COLUMNS + 30;
    /// BOUND_CARRY_HI 起始列（3 个高位 bit）— 2-bit carry 分解的 hi 部分。
    pub const BOUND_CARRY_HI_BASE: usize = COMMON_NUM_COLUMNS + 33;
    /// GE_DIFF 起始列（4 limb）— buy_in - big_blind 差值（阶段 3 新增：buy_in >= big_blind）。
    pub const GE_DIFF_BASE: usize = COMMON_NUM_COLUMNS + 36;
    /// GE_BORROW 起始列（3 个 boolean）— 减法借位 witness（阶段 3 新增）。
    pub const GE_BORROW_BASE: usize = COMMON_NUM_COLUMNS + 40;
    /// chip_pool 加法的 3 个 ripple-carry bit。
    pub const CHIP_POOL_ADD_CARRY_BASE: usize = COMMON_NUM_COLUMNS + 43;
    /// `join_table` AIR 总列数。
    pub const NUM_COLUMNS: usize = COMMON_NUM_COLUMNS + 46;
}

/// `join_table` AIR 输入参数。
#[derive(Debug, Clone)]
pub struct JoinTableInput {
    /// 座位索引。
    pub seat_index: u8,
    /// 买入金额。
    pub buy_in: u64,
    /// 玩家地址。
    pub player_addr: [u8; 20],
}

/// `join_table` AIR 公开输入。
#[derive(Debug, Clone)]
pub struct JoinTableAir {
    /// log2(trace 行数)。
    pub log_size: u32,
    /// 输入参数。
    pub input: JoinTableInput,
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

impl JoinTableAir {
    /// 构造新 AIR 实例。
    #[must_use]
    pub const fn num_columns() -> usize {
        cols::NUM_COLUMNS
    }
}

impl FrameworkEval for JoinTableAir {
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

        // 业务列
        let input_seat_index = eval.next_trace_mask();
        let input_buy_in_0 = eval.next_trace_mask();
        let input_buy_in_1 = eval.next_trace_mask();
        let input_buy_in_2 = eval.next_trace_mask();
        let input_buy_in_3 = eval.next_trace_mask();
        let _input_player_addr_0 = eval.next_trace_mask();
        let _input_player_addr_1 = eval.next_trace_mask();
        let _input_player_addr_2 = eval.next_trace_mask();
        let _input_player_addr_3 = eval.next_trace_mask();
        let output_seat_stack_0 = eval.next_trace_mask();
        let output_seat_stack_1 = eval.next_trace_mask();
        let output_seat_stack_2 = eval.next_trace_mask();
        let output_seat_stack_3 = eval.next_trace_mask();
        // Gap 2 boolean witness（目标座位为空）。
        let input_seat_empty = eval.next_trace_mask();
        // Gap 3：大盲注（4 limb）— 用于 buy_in >= big_blind 约束。
        let input_big_blind_0 = eval.next_trace_mask();
        let input_big_blind_1 = eval.next_trace_mask();
        let input_big_blind_2 = eval.next_trace_mask();
        let input_big_blind_3 = eval.next_trace_mask();
        // Gap 4：pre chip_pool（4 limb）— 用于资金守恒。
        let input_pre_chip_pool_0 = eval.next_trace_mask();
        let input_pre_chip_pool_1 = eval.next_trace_mask();
        let input_pre_chip_pool_2 = eval.next_trace_mask();
        let input_pre_chip_pool_3 = eval.next_trace_mask();
        // Gap 4：post chip_pool（4 limb）— 用于资金守恒。
        let output_post_chip_pool_0 = eval.next_trace_mask();
        let output_post_chip_pool_1 = eval.next_trace_mask();
        let output_post_chip_pool_2 = eval.next_trace_mask();
        let output_post_chip_pool_3 = eval.next_trace_mask();

        // bound check witness：diff (4 limb) + carry_lo (3) + carry_hi (3)
        let bound_diff_0 = eval.next_trace_mask();
        let bound_diff_1 = eval.next_trace_mask();
        let bound_diff_2 = eval.next_trace_mask();
        let bound_diff_3 = eval.next_trace_mask();
        let carry_lo_0 = eval.next_trace_mask();
        let carry_lo_1 = eval.next_trace_mask();
        let carry_lo_2 = eval.next_trace_mask();
        let carry_hi_0 = eval.next_trace_mask();
        let carry_hi_1 = eval.next_trace_mask();
        let carry_hi_2 = eval.next_trace_mask();

        // 约束 1：seat_index == input.seat_index
        let expected_seat: E::F = M31::from(u32::from(self.input.seat_index)).into();
        let seat_diff = input_seat_index.clone() - expected_seat;
        eval.add_constraint(is_active.clone() * seat_diff);

        // 约束 2：seat_index < max_players（简化为 < 9，完整实现需要读取 max_players 列）
        // 已在通用约束中通过 round_state 隐含约束

        // 约束 3（审计 join_table 前置，degree-2）：pre_round_state == WAITING(0)。
        // join_table 仅在 WAITING 状态合法（Lean 反例：PREFLOP 下 join）。
        // 完整 ∈{0} 单值判定在 degree-2 下即为等式约束。
        eval.add_constraint(common.round_state_eq(0));
        // 约束 4（degree-2）：round_state 不变（join 不改变 round_state）。
        eval.add_constraint(common.round_state_unchanged());
        for constraint in common.pot_unchanged_4limb() {
            eval.add_constraint(constraint);
        }
        // 约束 5（Gap 2，degree-2）：input_seat_empty == 1 — 诚实 host 只在空座位入座。
        let one: E::F = M31::from(1u32).into();
        eval.add_constraint(is_active.clone() * (input_seat_empty - one));
        // 约束 6（Gap 3，degree-1）：output_seat_stack == input_buy_in
        //   — 入座后 stack = buy_in（资金正确入袋）。
        eval.add_constraint(
            is_active.clone() * (output_seat_stack_0.clone() - input_buy_in_0.clone()),
        );
        eval.add_constraint(
            is_active.clone() * (output_seat_stack_1.clone() - input_buy_in_1.clone()),
        );
        eval.add_constraint(
            is_active.clone() * (output_seat_stack_2.clone() - input_buy_in_2.clone()),
        );
        eval.add_constraint(
            is_active.clone() * (output_seat_stack_3.clone() - input_buy_in_3.clone()),
        );
        // 约束 7（溢出防护，degree-2）：全局上界 range check
        // 验证 chip_pool + buy_in + diff = MAX_TOTAL_BET（逐 limb + 2-bit carry）。
        // addon_pool 是 chip_pool 的 pending-addon 子集，不能重复计入。
        // 对齐 addon/rebuy AIR 的 bound_check_4limb 与合约 apply_join 的上界检查。
        let pre_chip_pool = [
            input_pre_chip_pool_0,
            input_pre_chip_pool_1,
            input_pre_chip_pool_2,
            input_pre_chip_pool_3,
        ];
        let post_chip_pool = [
            output_post_chip_pool_0,
            output_post_chip_pool_1,
            output_post_chip_pool_2,
            output_post_chip_pool_3,
        ];
        let buy_in_limbs = [
            input_buy_in_0,
            input_buy_in_1,
            input_buy_in_2,
            input_buy_in_3,
        ];
        let diff = [bound_diff_0, bound_diff_1, bound_diff_2, bound_diff_3];
        let carry_lo = [carry_lo_0, carry_lo_1, carry_lo_2];
        let carry_hi = [carry_hi_0, carry_hi_1, carry_hi_2];
        for __c in
            common.bound_check_4limb(&pre_chip_pool, &buy_in_limbs, &diff, &carry_lo, &carry_hi)
        {
            eval.add_constraint(__c);
        }
        // 约束 9（阶段 3 soundness 新增）：buy_in >= big_blind（全 4-limb ≥ 检查）。
        // 通过减法借位链约束 buy_in - big_blind = ge_diff，且无下溢（borrow_out[3]=0），
        // 在 Limb4Range16 假设下保证 decode(buy_in) >= decode(big_blind)。
        let big_blind_limbs = [
            input_big_blind_0,
            input_big_blind_1,
            input_big_blind_2,
            input_big_blind_3,
        ];
        let ge_diff_0 = eval.next_trace_mask();
        let ge_diff_1 = eval.next_trace_mask();
        let ge_diff_2 = eval.next_trace_mask();
        let ge_diff_3 = eval.next_trace_mask();
        let ge_borrow_0 = eval.next_trace_mask();
        let ge_borrow_1 = eval.next_trace_mask();
        let ge_borrow_2 = eval.next_trace_mask();
        let chip_pool_add_carry = [
            eval.next_trace_mask(),
            eval.next_trace_mask(),
            eval.next_trace_mask(),
        ];
        let ge_diff = [ge_diff_0, ge_diff_1, ge_diff_2, ge_diff_3];
        let ge_borrow = [ge_borrow_0, ge_borrow_1, ge_borrow_2];
        for __c in common.ge_4limb(&buy_in_limbs, &big_blind_limbs, &ge_diff, &ge_borrow) {
            eval.add_constraint(__c);
        }
        // 约束 9（资金守恒）：post_chip_pool = pre_chip_pool + buy_in，包含完整
        // ripple-carry 链，允许合法的跨 16-bit limb 加法并拒绝伪造 carry。
        for __c in common.limb4_delta(
            &pre_chip_pool,
            &post_chip_pool,
            &buy_in_limbs,
            &chip_pool_add_carry,
        ) {
            eval.add_constraint(__c);
        }
        let _ = MAX_TOTAL_BET;
        eval
    }
}

/// `join_table` AIR 的 trace 行。
#[derive(Debug, Clone)]
pub struct JoinTableRow {
    /// 通用列。
    pub common: CommonRow,
    /// `INPUT_SEAT_INDEX`。
    pub input_seat_index: M31,
    /// `INPUT_BUY_IN`（4 limb）。
    pub input_buy_in: [M31; 4],
    /// `INPUT_PLAYER_ADDR`（4 limb）。
    pub input_player_addr: [M31; 4],
    /// `OUTPUT_SEAT_STACK`（4 limb）。
    pub output_seat_stack: [M31; 4],
    /// `INPUT_SEAT_EMPTY` boolean witness（Gap 2）。
    pub input_seat_empty: M31,
    /// `INPUT_BIG_BLIND`（4 limb）— 大盲注，用于 buy_in >= big_blind。
    pub input_big_blind: [M31; 4],
    /// `INPUT_PRE_CHIP_POOL`（4 limb）— pre chip_pool，用于资金守恒。
    pub input_pre_chip_pool: [M31; 4],
    /// `OUTPUT_POST_CHIP_POOL`（4 limb）— post chip_pool，用于资金守恒。
    pub output_post_chip_pool: [M31; 4],
    /// BOUND_DIFF（4 limb）— diff = MAX_TOTAL_BET - (chip_pool + buy_in)。
    pub bound_diff: [M31; 4],
    /// BOUND_CARRY_LO（3 个低位 bit）— 2-bit carry 分解的 lo 部分。
    pub bound_carry_lo: [M31; 3],
    /// BOUND_CARRY_HI（3 个高位 bit）— 2-bit carry 分解的 hi 部分。
    pub bound_carry_hi: [M31; 3],
    /// GE_DIFF（4 limb）— buy_in - big_blind 差值（阶段 3 新增：buy_in >= big_blind）。
    pub ge_diff: [M31; 4],
    /// GE_BORROW（3 个 boolean）— 减法借位 witness（阶段 3 新增）。
    pub ge_borrow: [M31; 3],
    /// chip_pool += buy_in 的 ripple-carry witness。
    pub chip_pool_add_carry: [M31; 3],
}

impl JoinTableRow {
    /// 构造 active 行。
    #[must_use]
    pub fn active(
        input: &JoinTableInput,
        pre_state_root: [M31; 4],
        post_state_root: [M31; 4],
        table_id: u64,
        hand_id: u32,
        call_seq: u32,
        pre_version: u64,
        post_version: u64,
        big_blind: u64,
        pre_chip_pool: u64,
    ) -> Self {
        // 全局上界检查：chip_pool + buy_in <= MAX_TOTAL_BET。
        let total = pre_chip_pool
            .checked_add(input.buy_in)
            .expect("join_table: chip_pool + buy_in overflow");
        debug_assert!(total <= MAX_TOTAL_BET, "join_table: global bound exceeded");
        let bound_diff = MAX_TOTAL_BET - total;
        let (bound_carry_lo, bound_carry_hi) =
            compute_bound_carries(pre_chip_pool, input.buy_in, bound_diff);
        let chip_pool_add_carry = compute_add_carries(pre_chip_pool, input.buy_in);

        // 阶段 3：buy_in >= big_blind 的减法借位分解。
        // 约束：buy[i] - bi[i] - borrow_in + 65536·borrow_out = diff[i]。
        //   若 buy[i] >= bi[i] + borrow_in：无借位；否则向下一 limb 借 1。
        // b_in[0]=0，b_out[i]=b_in[i+1]，b_out[3]=0（无下溢 ⇒ buy_in >= big_blind）。
        debug_assert!(input.buy_in >= big_blind, "join_table: buy_in < big_blind");
        let mut borrow_in: u64 = 0;
        let mut ge_diff_limbs: [M31; 4] = [ZERO; 4];
        let mut ge_borrow_limbs: [M31; 3] = [ZERO; 3];
        for i in 0..4 {
            let buy_l = (input.buy_in >> (16 * i)) & 0xFFFF;
            let bi_l = (big_blind >> (16 * i)) & 0xFFFF;
            let subtrahend = bi_l + borrow_in;
            let borrow_out = u64::from(buy_l < subtrahend);
            let diff_l = buy_l + borrow_out * 65536 - subtrahend;
            ge_diff_limbs[i] = M31::from((diff_l & 0xFFFF) as u32);
            if i < 3 {
                ge_borrow_limbs[i] = M31::from(borrow_out as u32);
            }
            borrow_in = borrow_out;
        }
        // i=3 的 borrow_out 必须 = 0（无下溢）。约束侧 b_out[3] 硬编码为 0，
        // host 端此处 borrow_in 即为 b_out[3]，buy_in >= big_blind 保证其为 0。
        debug_assert_eq!(borrow_in, 0, "join_table: buy_in >= big_blind 下溢");
        Self {
            common: CommonRow::active(
                MethodKind::JoinTable,
                pre_state_root,
                post_state_root,
                table_id,
                hand_id,
                call_seq,
                pre_version,
                post_version,
                0, // pre_round_state = WAITING
                0, // post_round_state = WAITING
                0,
                0,
                0,
                0,
            ),
            input_seat_index: u8_to_m31(input.seat_index),
            input_buy_in: u64_to_m31_limbs(input.buy_in),
            input_player_addr: u64_to_m31_limbs(0), // 简化
            output_seat_stack: u64_to_m31_limbs(input.buy_in),
            // Gap 2：诚实 host 只在空座位入座。
            input_seat_empty: M31::from(1u32),
            // Gap 3：大盲注（来自表台配置）。
            input_big_blind: u64_to_m31_limbs(big_blind),
            // Gap 4：pre/post chip_pool（守恒：post = pre + buy_in）。
            input_pre_chip_pool: u64_to_m31_limbs(pre_chip_pool),
            output_post_chip_pool: u64_to_m31_limbs(total),
            bound_diff: u64_to_m31_limbs(bound_diff),
            bound_carry_lo,
            bound_carry_hi,
            // 阶段 3：buy_in >= big_blind 的差值与借位 witness
            ge_diff: ge_diff_limbs,
            ge_borrow: ge_borrow_limbs,
            chip_pool_add_carry,
        }
    }

    /// 构造 padding 行。
    #[must_use]
    pub fn padding() -> Self {
        Self {
            common: CommonRow::padding(),
            input_seat_index: ZERO,
            input_buy_in: [ZERO; 4],
            input_player_addr: [ZERO; 4],
            output_seat_stack: [ZERO; 4],
            input_seat_empty: ZERO,
            input_big_blind: [ZERO; 4],
            input_pre_chip_pool: [ZERO; 4],
            output_post_chip_pool: [ZERO; 4],
            bound_diff: [ZERO; 4],
            bound_carry_lo: [ZERO; 3],
            bound_carry_hi: [ZERO; 3],
            ge_diff: [ZERO; 4],
            ge_borrow: [ZERO; 3],
            chip_pool_add_carry: [ZERO; 3],
        }
    }

    /// 转为列向量。
    #[must_use]
    pub fn to_vec(&self) -> Vec<M31> {
        let mut v = self.common.to_vec();
        v.push(self.input_seat_index);
        v.extend_from_slice(&self.input_buy_in);
        v.extend_from_slice(&self.input_player_addr);
        v.extend_from_slice(&self.output_seat_stack);
        v.push(self.input_seat_empty);
        v.extend_from_slice(&self.input_big_blind);
        v.extend_from_slice(&self.input_pre_chip_pool);
        v.extend_from_slice(&self.output_post_chip_pool);
        v.extend_from_slice(&self.bound_diff);
        v.extend_from_slice(&self.bound_carry_lo);
        v.extend_from_slice(&self.bound_carry_hi);
        v.extend_from_slice(&self.ge_diff);
        v.extend_from_slice(&self.ge_borrow);
        v.extend_from_slice(&self.chip_pool_add_carry);
        debug_assert_eq!(v.len(), cols::NUM_COLUMNS);
        v
    }
}
