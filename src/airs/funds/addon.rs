//! `addon` AIR — 玩家追加筹码（**下一手生效**）。
//!
//! 移植自 `dispatch::dispatch_addon` 与 `state_machine::apply_addon`。
//!
//! ## 业务规约
//!
//! 1. `seat_index` 必须是已占用座位（`is_occupied()`）
//! 2. `amount > 0`
//! 3. 状态变更（**关键：不动 stack**）：
//!    - `seats[seat].pending_addon += amount`
//!    - `table.chip_pool += amount`
//!    - `call_seq += 1`
//!
//! ## 为什么不动 stack
//!
//! addon 设计为「下一手生效」：
//! - **不破坏当前 `side_pot` 分层**（all-in 后的钱不能凭空增加）
//! - **不允许玩家利用 addon 在 all-in 后"加码"破坏结算**
//! - 实际入账发生在 `reset_for_next_hand` 第一阶段（合并到 stack）
//!
//! ## AIR 列布局
//!
//! - 通用列 37 个
//! - 业务列 43 个：
//!   - `INPUT_SEAT_INDEX`
//!   - `INPUT_AMOUNT_BASE[4]`（4 limb，追加金额）
//!   - `PRE_PENDING_ADDON_BASE[4]`（4 limb，调用前 pending_addon）
//!   - `POST_PENDING_ADDON_BASE[4]`（4 limb，调用后 pending_addon；约束 = pre + amount）
//!   - `INPUT_SEAT_OCCUPIED`（Gap 3 boolean witness）
//!   - `INPUT_AMOUNT_INV`（Gap 9 invertibility witness）
//!   - `INPUT_PRE_CHIP_POOL_BASE[4]`（4 limb，调用前 chip_pool，用于全局上界检查）
//!   - `BOUND_DIFF_BASE[4]`（4 limb，diff = MAX_TOTAL_BET - total，用于全局上界 range check）
//!   - `BOUND_CARRY_LO_BASE[3]`（3 个进位低位 bit，2-bit carry 分解）
//!   - `BOUND_CARRY_HI_BASE[3]`（3 个进位高位 bit，2-bit carry 分解）
//!   - `PENDING_ADD_CARRY_BASE[3]`（pending_addon 的 ripple carry）
//!   - `OUTPUT_POST_CHIP_POOL_BASE[4]`
//!   - `CHIP_POOL_ADD_CARRY_BASE[3]`
//!
//! 共 37 + 39 = 76 列。

use stwo::core::fields::m31::M31;
use stwo_constraint_framework::{EvalAtRow, FrameworkEval};

use crate::airs::common::{
    COMMON_NUM_COLUMNS, CommonConstraints, CommonRow, MAX_TOTAL_BET, ZERO, compute_add_carries,
    compute_bound_carries, u8_to_m31, u64_to_m31_limbs,
};
use crate::method_kind::MethodKind;

/// `addon` 业务特定列布局。
pub mod cols {
    use super::COMMON_NUM_COLUMNS;
    /// `INPUT_SEAT_INDEX` 列。
    pub const INPUT_SEAT_INDEX: usize = COMMON_NUM_COLUMNS + 0;
    /// `INPUT_AMOUNT` 起始列（4 limb，追加金额）。
    pub const INPUT_AMOUNT_BASE: usize = COMMON_NUM_COLUMNS + 1;
    /// `PRE_PENDING_ADDON` 起始列（4 limb，调用前 pending_addon）。
    pub const PRE_PENDING_ADDON_BASE: usize = COMMON_NUM_COLUMNS + 5;
    /// `POST_PENDING_ADDON` 起始列（4 limb，调用后 pending_addon）。
    pub const POST_PENDING_ADDON_BASE: usize = COMMON_NUM_COLUMNS + 9;
    /// `INPUT_SEAT_OCCUPIED` boolean witness（Gap 3）：诚实 host 只对占用座位 addon。
    pub const INPUT_SEAT_OCCUPIED: usize = COMMON_NUM_COLUMNS + 13;
    /// `INPUT_AMOUNT_INV` invertibility witness（Gap 9）：amount 四个 limb 之和的乘法逆元。
    pub const INPUT_AMOUNT_INV: usize = COMMON_NUM_COLUMNS + 14;
    /// PRE_CHIP_POOL 起始列（4 limb）— 调用前 chip_pool，用于全局上界检查。
    pub const INPUT_PRE_CHIP_POOL_BASE: usize = COMMON_NUM_COLUMNS + 15;
    /// BOUND_DIFF 起始列（4 limb）— diff = MAX_TOTAL_BET - (chip_pool + amount)。
    pub const BOUND_DIFF_BASE: usize = COMMON_NUM_COLUMNS + 19;
    /// BOUND_CARRY_LO 起始列（3 个低位 bit）— 2-bit carry 分解的 lo 部分。
    pub const BOUND_CARRY_LO_BASE: usize = COMMON_NUM_COLUMNS + 23;
    /// BOUND_CARRY_HI 起始列（3 个高位 bit）— 2-bit carry 分解的 hi 部分。
    pub const BOUND_CARRY_HI_BASE: usize = COMMON_NUM_COLUMNS + 26;
    /// pending_addon 加法的 3 个 ripple-carry bit。
    pub const PENDING_ADD_CARRY_BASE: usize = COMMON_NUM_COLUMNS + 29;
    /// OUTPUT_POST_CHIP_POOL 起始列（4 limb）— 调用后完整桌台锁仓。
    pub const OUTPUT_POST_CHIP_POOL_BASE: usize = COMMON_NUM_COLUMNS + 32;
    /// chip_pool 加法的 3 个 ripple-carry bit。
    pub const CHIP_POOL_ADD_CARRY_BASE: usize = COMMON_NUM_COLUMNS + 36;
    /// `addon` AIR 总列数。
    pub const NUM_COLUMNS: usize = COMMON_NUM_COLUMNS + 39;
}

/// `addon` 输入参数。
#[derive(Debug, Clone)]
pub struct AddonInput {
    /// 目标座位索引。
    pub seat_index: u8,
    /// 追加金额（必须 > 0）。
    pub amount: u64,
}

/// `addon` AIR 公开输入。
#[derive(Debug, Clone)]
pub struct AddonAir {
    /// log2(trace 行数)。
    pub log_size: u32,
    /// 输入参数。
    pub input: AddonInput,
    /// 调用前 state_root（4 limb）。
    pub pre_state_root: [M31; 4],
    /// 调用后 state_root（4 limb）。
    pub post_state_root: [M31; 4],
    /// 表台 ID。
    pub table_id: u64,
    /// 手牌序号（addon 可在任意时刻调用，hand_id 标识调用时的手牌）。
    pub hand_id: u32,
    /// 调用序号。
    pub call_seq: u32,
    /// 调用前 version。
    pub pre_version: u64,
    /// 调用后 version。
    pub post_version: u64,
}

impl AddonAir {
    /// 列数。
    #[must_use]
    pub const fn num_columns() -> usize {
        cols::NUM_COLUMNS
    }
}

impl FrameworkEval for AddonAir {
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

        // 读取业务列
        let input_seat_index = eval.next_trace_mask();
        let input_amount: [E::F; 4] = [
            eval.next_trace_mask(),
            eval.next_trace_mask(),
            eval.next_trace_mask(),
            eval.next_trace_mask(),
        ];
        // pre_pending / post_pending：完整 4 limb（阶段 3 升级）
        let pre_pending: [E::F; 4] = [
            eval.next_trace_mask(),
            eval.next_trace_mask(),
            eval.next_trace_mask(),
            eval.next_trace_mask(),
        ];
        let post_pending: [E::F; 4] = [
            eval.next_trace_mask(),
            eval.next_trace_mask(),
            eval.next_trace_mask(),
            eval.next_trace_mask(),
        ];
        // Gap 3 boolean witness（座位非空）+ Gap 9 invertibility witness（amount > 0）。
        let input_seat_occupied = eval.next_trace_mask();
        let input_amount_inv = eval.next_trace_mask();

        // 约束 1：seat_index == input.seat_index
        let expected_seat: E::F = M31::from(u32::from(self.input.seat_index)).into();
        eval.add_constraint(is_active.clone() * (input_seat_index - expected_seat));

        // 约束 2：amount 完整 4-limb 一致性。
        let expected_amount = u64_to_m31_limbs(self.input.amount);
        for i in 0..4 {
            let expected: E::F = expected_amount[i].into();
            eval.add_constraint(is_active.clone() * (input_amount[i].clone() - expected));
        }

        // 约束 4（审计共性，degree-2）：round_state 不变（addon 不改变 round_state）。
        eval.add_constraint(common.round_state_unchanged());
        for constraint in common.pot_unchanged_4limb() {
            eval.add_constraint(constraint);
        }

        // 约束 5（Gap 3，degree-2）：input_seat_occupied == 1 — 诚实 host 只对占用座位 addon。
        let one: E::F = M31::from(1u32).into();
        eval.add_constraint(is_active.clone() * (input_seat_occupied - one.clone()));
        // 约束 6（Gap 9，degree-2）：四个 16-bit limb 之和非零。
        let amount_sum = input_amount[0].clone()
            + input_amount[1].clone()
            + input_amount[2].clone()
            + input_amount[3].clone();
        eval.add_constraint(is_active.clone() * (amount_sum * input_amount_inv - one.clone()));

        // 全局上界检查（对齐合约 apply_addon 的 chip_pool + amount <= MAX_TOTAL_BET）
        // 读取 pre_chip_pool 全 4 limb
        let pre_chip_pool_0 = eval.next_trace_mask();
        let pre_chip_pool_1 = eval.next_trace_mask();
        let pre_chip_pool_2 = eval.next_trace_mask();
        let pre_chip_pool_3 = eval.next_trace_mask();
        // 读取 bound check witness：diff (4 limb) + carry_lo (3) + carry_hi (3)
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

        // 约束 7（溢出防护，degree-2）：全局上界 range check
        // 验证 chip_pool + amount + diff = MAX_TOTAL_BET（逐 limb + 2-bit carry）
        let chip_pool = [
            pre_chip_pool_0,
            pre_chip_pool_1,
            pre_chip_pool_2,
            pre_chip_pool_3,
        ];
        let amount = input_amount.clone();
        let diff = [bound_diff_0, bound_diff_1, bound_diff_2, bound_diff_3];
        let carry_lo = [carry_lo_0, carry_lo_1, carry_lo_2];
        let carry_hi = [carry_hi_0, carry_hi_1, carry_hi_2];
        for __c in common.bound_check_4limb(&chip_pool, &amount, &diff, &carry_lo, &carry_hi) {
            eval.add_constraint(__c);
        }

        // 约束 8：座位 pending_addon 增加 amount。
        let pending_add_carry: [E::F; 3] = [
            eval.next_trace_mask(),
            eval.next_trace_mask(),
            eval.next_trace_mask(),
        ];
        for __c in common.limb4_delta(
            &pre_pending,
            &post_pending,
            &input_amount,
            &pending_add_carry,
        ) {
            eval.add_constraint(__c);
        }
        // 约束 9：chip_pool 是完整 TableVault 锁仓，addon 到账后同步增加 amount。
        let post_chip_pool: [E::F; 4] = [
            eval.next_trace_mask(),
            eval.next_trace_mask(),
            eval.next_trace_mask(),
            eval.next_trace_mask(),
        ];
        let chip_pool_add_carry: [E::F; 3] = [
            eval.next_trace_mask(),
            eval.next_trace_mask(),
            eval.next_trace_mask(),
        ];
        for __c in common.limb4_delta(&chip_pool, &post_chip_pool, &amount, &chip_pool_add_carry) {
            eval.add_constraint(__c);
        }

        eval
    }
}

/// `addon` AIR 的 trace 行。
#[derive(Debug, Clone)]
pub struct AddonRow {
    /// 通用列。
    pub common: CommonRow,
    /// `INPUT_SEAT_INDEX`。
    pub input_seat_index: M31,
    /// `INPUT_AMOUNT`（4 limb）。
    pub input_amount: [M31; 4],
    /// `PRE_PENDING_ADDON`（4 limb）。
    pub pre_pending_addon: [M31; 4],
    /// `POST_PENDING_ADDON`（4 limb）。
    pub post_pending_addon: [M31; 4],
    /// `INPUT_SEAT_OCCUPIED` boolean witness（Gap 3）。
    pub input_seat_occupied: M31,
    /// `INPUT_AMOUNT_INV` invertibility witness（Gap 9）。
    pub input_amount_inv: M31,
    /// PRE_CHIP_POOL（4 limb）— 全局上界检查用。
    pub pre_chip_pool: [M31; 4],
    /// BOUND_DIFF（4 limb）— diff = MAX_TOTAL_BET - (chip_pool + amount)。
    pub bound_diff: [M31; 4],
    /// BOUND_CARRY_LO（3 个低位 bit）— 2-bit carry 分解的 lo 部分。
    pub bound_carry_lo: [M31; 3],
    /// BOUND_CARRY_HI（3 个高位 bit）— 2-bit carry 分解的 hi 部分。
    pub bound_carry_hi: [M31; 3],
    /// pending_addon 加法的 3 个 ripple-carry bit。
    pub pending_add_carry: [M31; 3],
    /// OUTPUT_POST_CHIP_POOL（4 limb）— 调用后完整桌台锁仓。
    pub post_chip_pool: [M31; 4],
    /// chip_pool 加法的 3 个 ripple-carry bit。
    pub chip_pool_add_carry: [M31; 3],
}

impl AddonRow {
    /// 构造 active 行。
    ///
    /// # 参数
    /// - `input`: addon 输入（seat_index + amount）
    /// - `pre_pending_addon`: 调用前的 pending_addon 值
    /// - `pre_chip_pool` / `post_chip_pool`: 调用前后的完整桌台锁仓
    /// - 其他通用字段（state_root / table_id / hand_id / version / round_state / pot）
    #[must_use]
    pub fn active(
        input: &AddonInput,
        pre_pending_addon: u64,
        pre_chip_pool: u64,
        post_chip_pool: u64,
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
        // post_pending = pre_pending + amount（host 端预计算，AIR 端约束一致性）
        let post_pending = pre_pending_addon
            .checked_add(input.amount)
            .expect("addon pending addition must not overflow");
        let amount_limbs = u64_to_m31_limbs(input.amount);
        let amount_sum = amount_limbs.into_iter().fold(ZERO, |sum, limb| sum + limb);
        let input_amount_inv = amount_sum.inverse();
        // 全局上界检查：chip_pool + amount <= MAX_TOTAL_BET。
        let total = pre_chip_pool
            .checked_add(input.amount)
            .expect("addon chip_pool addition must not overflow");
        debug_assert!(
            total <= MAX_TOTAL_BET,
            "addon bound check failed: {total} > {MAX_TOTAL_BET}"
        );
        let diff = MAX_TOTAL_BET - total;
        debug_assert_eq!(post_chip_pool, total, "addon post chip_pool mismatch");
        let (bound_carry_lo, bound_carry_hi) =
            compute_bound_carries(pre_chip_pool, input.amount, diff);
        Self {
            common: CommonRow::active(
                MethodKind::Addon,
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
            input_amount: u64_to_m31_limbs(input.amount),
            pre_pending_addon: u64_to_m31_limbs(pre_pending_addon),
            post_pending_addon: u64_to_m31_limbs(post_pending),
            // Gap 3：诚实 host 只对占用座位 addon。
            input_seat_occupied: M31::from(1u32),
            // Gap 9：amount 四个 limb 之和的乘法逆元。
            input_amount_inv,
            pre_chip_pool: u64_to_m31_limbs(pre_chip_pool),
            bound_diff: u64_to_m31_limbs(diff),
            bound_carry_lo,
            bound_carry_hi,
            pending_add_carry: compute_add_carries(pre_pending_addon, input.amount),
            post_chip_pool: u64_to_m31_limbs(post_chip_pool),
            chip_pool_add_carry: compute_add_carries(pre_chip_pool, input.amount),
        }
    }

    /// 构造 padding 行。
    #[must_use]
    pub fn padding() -> Self {
        Self {
            common: CommonRow::padding(),
            input_seat_index: ZERO,
            input_amount: [ZERO; 4],
            pre_pending_addon: [ZERO; 4],
            post_pending_addon: [ZERO; 4],
            input_seat_occupied: ZERO,
            input_amount_inv: ZERO,
            pre_chip_pool: [ZERO; 4],
            bound_diff: [ZERO; 4],
            bound_carry_lo: [ZERO; 3],
            bound_carry_hi: [ZERO; 3],
            pending_add_carry: [ZERO; 3],
            post_chip_pool: [ZERO; 4],
            chip_pool_add_carry: [ZERO; 3],
        }
    }

    /// 转为列向量。
    #[must_use]
    pub fn to_vec(&self) -> Vec<M31> {
        let mut v = self.common.to_vec();
        v.push(self.input_seat_index);
        v.extend_from_slice(&self.input_amount);
        v.extend_from_slice(&self.pre_pending_addon);
        v.extend_from_slice(&self.post_pending_addon);
        v.push(self.input_seat_occupied);
        v.push(self.input_amount_inv);
        v.extend_from_slice(&self.pre_chip_pool);
        v.extend_from_slice(&self.bound_diff);
        v.extend_from_slice(&self.bound_carry_lo);
        v.extend_from_slice(&self.bound_carry_hi);
        v.extend_from_slice(&self.pending_add_carry);
        v.extend_from_slice(&self.post_chip_pool);
        v.extend_from_slice(&self.chip_pool_add_carry);
        debug_assert_eq!(v.len(), cols::NUM_COLUMNS);
        v
    }
}
