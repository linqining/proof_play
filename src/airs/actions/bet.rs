//! `bet` AIR — 玩家主动下注（postflop 第一个下注者）。
//!
//! 移植自 `dispatch::dispatch_bet` 与 `state_machine::apply_bet`。
//!
//! ## 业务规约
//!
//! `bet` 在语义上是 `raise` 的特例：当当前轮无已有下注（`current_bet == seat.bet`）
//! 时，玩家主动开注。实现上 `apply_bet` 复用 `apply_raise(total_bet = seat.bet + amount)`，
//! 因此本 AIR 的列布局与约束与 [`super::raise`] 高度一致。
//!
//! 1. 当前处于下注轮
//! 2. `seat_index == current_turn`
//! 3. `amount > 0`
//! 4. `current_bet == seat.bet`（无已有下注，否则应使用 call/raise）
//! 5. 状态变更（复用 raise）：`seat.stack -= amount`, `seat.bet += amount`,
//!    `seat.total_bet += amount`；mid-round 时 `pot` 不变，round completion
//!    时收集全部 live bets 并推进到下一 reveal phase
//! 6. 玩家标记 `acted_this_round = true`
//! 7. mid-round 时推进到下一行动座位
//!
//! ## AIR 列布局
//!
//! - 通用列 37 个
//! - 业务列 11 个：`INPUT_SEAT_INDEX`, `INPUT_AMOUNT_BASE[4]`,
//!   `OUTPUT_SEAT_BET_BASE[4]`, `OUTPUT_ACTED`
//! - shared end-betting-round columns 7 个（mid-round 时全零）

use stwo::core::fields::m31::M31;
use stwo_constraint_framework::{EvalAtRow, FrameworkEval};

use crate::airs::actions::end_betting_round::{self, BettingOutcome, EndBettingRoundRow};
use crate::airs::common::{
    COMMON_NUM_COLUMNS, CommonConstraints, CommonRow, ZERO, u8_to_m31, u64_to_m31_limbs,
};
use crate::method_kind::MethodKind;

/// `bet` 业务特定列布局。
pub mod cols {
    use super::COMMON_NUM_COLUMNS;
    /// `INPUT_SEAT_INDEX` 列。
    pub const INPUT_SEAT_INDEX: usize = COMMON_NUM_COLUMNS + 0;
    /// `INPUT_AMOUNT` 起始列（4 limb，下注增量）。
    pub const INPUT_AMOUNT_BASE: usize = COMMON_NUM_COLUMNS + 1;
    /// `OUTPUT_SEAT_BET` 起始列（4 limb，下注后 seat.bet = pre_bet + amount）。
    pub const OUTPUT_SEAT_BET_BASE: usize = COMMON_NUM_COLUMNS + 5;
    /// `OUTPUT_ACTED` 列（acted_this_round 标记）。
    pub const OUTPUT_ACTED: usize = COMMON_NUM_COLUMNS + 9;
    /// `INPUT_PRE_ROUND_STATE_Q` 列（Gap 1 witness：pre_round_state²，拆 4 次 vanishing）。
    pub const INPUT_PRE_ROUND_STATE_Q: usize = COMMON_NUM_COLUMNS + 10;
    /// `INPUT_CURRENT_TURN` witness（Gap: current_turn == seat_index）。
    pub const INPUT_CURRENT_TURN: usize = COMMON_NUM_COLUMNS + 11;
    /// `PRE_SEAT_BET` 起始列（4 limb）— 阶段 3 新增（bet delta）。
    pub const PRE_SEAT_BET_BASE: usize = COMMON_NUM_COLUMNS + 12;
    /// `PRE_SEAT_STACK` 起始列（4 limb）— 阶段 3 新增（stack delta）。
    pub const PRE_SEAT_STACK_BASE: usize = COMMON_NUM_COLUMNS + 16;
    /// `OUTPUT_SEAT_STACK` 起始列（4 limb）— 阶段 3 新增（stack delta）。
    pub const OUTPUT_SEAT_STACK_BASE: usize = COMMON_NUM_COLUMNS + 20;
    /// `PRE_SEAT_TOTAL_BET` 起始列（4 limb）— 阶段 3 新增（total_bet delta）。
    pub const PRE_SEAT_TOTAL_BET_BASE: usize = COMMON_NUM_COLUMNS + 24;
    /// `OUTPUT_SEAT_TOTAL_BET` 起始列（4 limb）— 阶段 3 新增（total_bet delta）。
    pub const OUTPUT_SEAT_TOTAL_BET_BASE: usize = COMMON_NUM_COLUMNS + 28;
    /// 保留列（旧 amount limb0 inverse witness，现强制为 0）。
    pub const INPUT_AMOUNT_INV: usize = COMMON_NUM_COLUMNS + 32;
    /// `OUTPUT_CURRENT_TURN` — mid-round 推进后的下一行动座位。
    pub const OUTPUT_CURRENT_TURN: usize = COMMON_NUM_COLUMNS + 33;
    /// `bet` AIR 总列数。
    pub const NUM_COLUMNS: usize = COMMON_NUM_COLUMNS + 34 + super::end_betting_round::NUM_COLUMNS;
}

/// `bet` 输入参数。
#[derive(Debug, Clone)]
pub struct BetInput {
    /// 执行 bet 的座位索引。
    pub seat_index: u8,
    /// 下注金额（增量，必须 > 0）。
    pub amount: u64,
    /// 调用前 betting_round.current_bet（verifier-trusted）。
    pub pre_current_bet: u64,
    /// 调用前 betting_round.min_raise（verifier-trusted）。
    pub pre_min_raise: u64,
    /// 调用前 seat.bet（verifier-trusted）。
    pub pre_seat_bet: u64,
    /// 调用前 seat.stack（verifier-trusted）。
    pub pre_seat_stack: u64,
    /// 调用前 seat.total_bet（verifier-trusted）。
    pub pre_seat_total_bet: u64,
    /// Native VM replay selected branch.
    pub outcome: BettingOutcome,
}

/// `bet` AIR 公开输入。
#[derive(Debug, Clone)]
pub struct BetAir {
    /// log2(trace 行数)。
    pub log_size: u32,
    /// 输入参数。
    pub input: BetInput,
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

impl BetAir {
    /// 列数。
    #[must_use]
    pub const fn num_columns() -> usize {
        cols::NUM_COLUMNS
    }
}

impl FrameworkEval for BetAir {
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
        // input_amount：完整 4 limb（阶段 3 soundness 升级）
        let input_amount: [E::F; 4] = [
            eval.next_trace_mask(),
            eval.next_trace_mask(),
            eval.next_trace_mask(),
            eval.next_trace_mask(),
        ];
        // output_seat_bet：完整 4 limb
        let output_seat_bet: [E::F; 4] = [
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
        // 阶段 3 新增列
        let pre_seat_bet: [E::F; 4] = [
            eval.next_trace_mask(),
            eval.next_trace_mask(),
            eval.next_trace_mask(),
            eval.next_trace_mask(),
        ];
        let pre_seat_stack: [E::F; 4] = [
            eval.next_trace_mask(),
            eval.next_trace_mask(),
            eval.next_trace_mask(),
            eval.next_trace_mask(),
        ];
        let output_seat_stack: [E::F; 4] = [
            eval.next_trace_mask(),
            eval.next_trace_mask(),
            eval.next_trace_mask(),
            eval.next_trace_mask(),
        ];
        let pre_seat_total_bet: [E::F; 4] = [
            eval.next_trace_mask(),
            eval.next_trace_mask(),
            eval.next_trace_mask(),
            eval.next_trace_mask(),
        ];
        let output_seat_total_bet: [E::F; 4] = [
            eval.next_trace_mask(),
            eval.next_trace_mask(),
            eval.next_trace_mask(),
            eval.next_trace_mask(),
        ];
        // 旧 amount limb0 inverse witness；完整 u64 判零改由 trusted 常量完成。
        let input_amount_inv = eval.next_trace_mask();
        let output_current_turn = eval.next_trace_mask();

        // 约束 1：seat_index == input.seat_index
        let expected_seat: E::F = M31::from(u32::from(self.input.seat_index)).into();
        eval.add_constraint(is_active.clone() * (input_seat_index - expected_seat.clone()));
        // 约束: current_turn == seat_index（Gap: 阻止为非当前行动座位构造动作）
        eval.add_constraint(is_active.clone() * (input_current_turn - expected_seat));

        // 约束 2：资金 witness 绑定 verifier-trusted AIR 常量，并复现 apply_bet →
        // process_raise 的静态金额规则。
        let total_bet = self.input.pre_seat_bet.checked_add(self.input.amount);
        let total_bet_value = total_bet.unwrap_or(0);
        let raise_amount = total_bet_value.saturating_sub(self.input.pre_current_bet);
        let is_all_in = self.input.amount == self.input.pre_seat_stack;
        let post_stack_u64 = self.input.pre_seat_stack.checked_sub(self.input.amount);
        let post_bet_u64 = self.input.pre_seat_bet.checked_add(self.input.amount);
        let post_total_u64 = self.input.pre_seat_total_bet.checked_add(self.input.amount);
        let bet_is_valid = self.input.amount > 0
            && total_bet.is_some()
            && self.input.pre_current_bet <= self.input.pre_seat_bet
            && total_bet_value > self.input.pre_current_bet
            && self.input.amount <= self.input.pre_seat_stack
            && (raise_amount >= self.input.pre_min_raise || is_all_in)
            && post_stack_u64.is_some()
            && post_bet_u64.is_some()
            && post_total_u64.is_some();
        let one: E::F = M31::from(1u32).into();
        let valid: E::F = M31::from(u32::from(bet_is_valid)).into();
        eval.add_constraint(is_active.clone() * (valid - one.clone()));

        let expected_amount = u64_to_m31_limbs(self.input.amount);
        let expected_pre_bet = u64_to_m31_limbs(self.input.pre_seat_bet);
        let expected_pre_stack = u64_to_m31_limbs(self.input.pre_seat_stack);
        let expected_pre_total = u64_to_m31_limbs(self.input.pre_seat_total_bet);
        let expected_post_stack = u64_to_m31_limbs(post_stack_u64.unwrap_or(0));
        let expected_post_bet = u64_to_m31_limbs(post_bet_u64.unwrap_or(0));
        let expected_post_total = u64_to_m31_limbs(post_total_u64.unwrap_or(0));
        for i in 0..4 {
            eval.add_constraint(
                is_active.clone() * (input_amount[i].clone() - expected_amount[i].into()),
            );
            eval.add_constraint(
                is_active.clone() * (pre_seat_bet[i].clone() - expected_pre_bet[i].into()),
            );
            eval.add_constraint(
                is_active.clone() * (pre_seat_stack[i].clone() - expected_pre_stack[i].into()),
            );
            eval.add_constraint(
                is_active.clone() * (pre_seat_total_bet[i].clone() - expected_pre_total[i].into()),
            );
            eval.add_constraint(
                is_active.clone() * (output_seat_stack[i].clone() - expected_post_stack[i].into()),
            );
            eval.add_constraint(
                is_active.clone() * (output_seat_bet[i].clone() - expected_post_bet[i].into()),
            );
            eval.add_constraint(
                is_active.clone()
                    * (output_seat_total_bet[i].clone() - expected_post_total[i].into()),
            );
        }

        // 不能用 amount limb0 判零：合法 amount=65536 的低 limb 也是 0。
        // 旧 witness 强制为 0，避免留下自由列。
        eval.add_constraint(is_active.clone() * input_amount_inv);

        // 约束 3：output_acted == 1（玩家已行动）
        eval.add_constraint(is_active.clone() * (output_acted - one));

        // 约束 4（审计共性）：必须处于下注轮（Gap 1）。
        eval.add_constraint(common.round_state_q_constraint(input_pre_round_state_q.clone()));
        eval.add_constraint(common.round_state_is_postflop_betting(input_pre_round_state_q));

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
        // stack/bet/total_bet 已绑定到 verifier 端 checked u64 运算的逐 limb常量；
        // 不使用无 carry 的逐 limb delta。

        let expected_post_turn: E::F =
            M31::from(u32::from(self.input.outcome.post_current_turn())).into();
        eval.add_constraint(is_active * (output_current_turn - expected_post_turn));

        eval
    }
}

/// `bet` AIR 的 trace 行。
#[derive(Debug, Clone)]
pub struct BetRow {
    /// 通用列。
    pub common: CommonRow,
    /// `INPUT_SEAT_INDEX`。
    pub input_seat_index: M31,
    /// `INPUT_AMOUNT`（4 limb）。
    pub input_amount: [M31; 4],
    /// `OUTPUT_SEAT_BET`（4 limb）。
    pub output_seat_bet: [M31; 4],
    /// `OUTPUT_ACTED`。
    pub output_acted: M31,
    /// Gap 1 witness：pre_round_state²。
    pub input_pre_round_state_q: M31,
    /// `INPUT_CURRENT_TURN` witness（Gap: current_turn == seat_index）。
    pub input_current_turn: M31,
    /// `PRE_SEAT_BET`（4 limb）— 阶段 3 新增。
    pub pre_seat_bet: [M31; 4],
    /// `PRE_SEAT_STACK`（4 limb）— 阶段 3 新增。
    pub pre_seat_stack: [M31; 4],
    /// `OUTPUT_SEAT_STACK`（4 limb）— 阶段 3 新增。
    pub output_seat_stack: [M31; 4],
    /// `PRE_SEAT_TOTAL_BET`（4 limb）— 阶段 3 新增。
    pub pre_seat_total_bet: [M31; 4],
    /// `OUTPUT_SEAT_TOTAL_BET`（4 limb）— 阶段 3 新增。
    pub output_seat_total_bet: [M31; 4],
    /// 保留列（旧 amount limb0 inverse witness，固定为 0）。
    pub input_amount_inv: M31,
    /// `OUTPUT_CURRENT_TURN` — mid-round 的下一行动座位，否则为 sentinel。
    pub output_current_turn: M31,
    /// Shared round-completion columns; zero for mid-round bets.
    pub round_completion: EndBettingRoundRow,
}

impl BetRow {
    /// 构造 active 行。
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn active(
        input: &BetInput,
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
        post_seat_bet: u64,
        pre_seat_bet: u64,
        pre_seat_stack: u64,
        post_seat_stack: u64,
        pre_seat_total_bet: u64,
        post_seat_total_bet: u64,
    ) -> Self {
        let rs_m31 = u8_to_m31(pre_round_state);
        Self {
            common: CommonRow::active(
                MethodKind::Bet,
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
            input_amount: u64_to_m31_limbs(input.amount),
            output_seat_bet: u64_to_m31_limbs(post_seat_bet),
            output_acted: M31::from(1u32),
            // Gap 1 witness：pre_round_state²（M31 域内）
            input_pre_round_state_q: rs_m31 * rs_m31,
            input_current_turn: u8_to_m31(input.seat_index), // current_turn == seat_index
            pre_seat_bet: u64_to_m31_limbs(pre_seat_bet),
            pre_seat_stack: u64_to_m31_limbs(pre_seat_stack),
            output_seat_stack: u64_to_m31_limbs(post_seat_stack),
            pre_seat_total_bet: u64_to_m31_limbs(pre_seat_total_bet),
            output_seat_total_bet: u64_to_m31_limbs(post_seat_total_bet),
            input_amount_inv: ZERO,
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
            input_amount: [ZERO; 4],
            output_seat_bet: [ZERO; 4],
            output_acted: ZERO,
            input_pre_round_state_q: ZERO,
            input_current_turn: ZERO,
            pre_seat_bet: [ZERO; 4],
            pre_seat_stack: [ZERO; 4],
            output_seat_stack: [ZERO; 4],
            pre_seat_total_bet: [ZERO; 4],
            output_seat_total_bet: [ZERO; 4],
            input_amount_inv: ZERO,
            output_current_turn: ZERO,
            round_completion: EndBettingRoundRow::zero(),
        }
    }

    /// 转为列向量。
    #[must_use]
    pub fn to_vec(&self) -> Vec<M31> {
        let mut v = self.common.to_vec();
        v.push(self.input_seat_index);
        v.extend_from_slice(&self.input_amount);
        v.extend_from_slice(&self.output_seat_bet);
        v.push(self.output_acted);
        v.push(self.input_pre_round_state_q);
        v.push(self.input_current_turn);
        v.extend_from_slice(&self.pre_seat_bet);
        v.extend_from_slice(&self.pre_seat_stack);
        v.extend_from_slice(&self.output_seat_stack);
        v.extend_from_slice(&self.pre_seat_total_bet);
        v.extend_from_slice(&self.output_seat_total_bet);
        v.push(self.input_amount_inv);
        v.push(self.output_current_turn);
        self.round_completion.append_to(&mut v);
        debug_assert_eq!(v.len(), cols::NUM_COLUMNS);
        v
    }
}
