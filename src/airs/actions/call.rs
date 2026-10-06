//! `call` AIR — 玩家跟注（匹配当前最高下注）。
//!
//! 移植自 `dispatch::dispatch_call` 与 `state_machine::apply_call`。
//!
//! ## 业务规约
//!
//! 1. 当前处于下注轮
//! 2. `seat_index == current_turn`
//! 3. 玩家未 fold、未 all_in
//! 4. 跟注金额 = `current_bet - seat.bet`（受 stack 限制）
//! 5. 状态变更：
//!    - `seat.stack -= call_amount`
//!    - `seat.bet += call_amount`
//!    - `seat.total_bet += call_amount`
//!    - 若 `seat.stack == 0` 则 `seat.all_in = true`
//!    - mid-round 时 `pot` 不变（下注暂存在 `seat.bet`）
//!    - round completion 时收集全部 live bets 并推进到下一 reveal phase
//!    - `version += 1`
//!
//! ## AIR 列布局
//!
//! - 通用列 37 个
//! - 业务列 34 个：`INPUT_SEAT_INDEX`, `INPUT_CALL_AMOUNT_BASE[4]`,
//!   `OUTPUT_SEAT_STACK_BASE[4]`, `OUTPUT_SEAT_BET_BASE[4]`,
//!   `OUTPUT_ALL_IN`, `OUTPUT_ACTED`, `INPUT_PRE_ROUND_STATE_Q`,
//!   `INPUT_CURRENT_TURN`, `PRE_SEAT_BET_BASE[4]`
//! - shared end-betting-round columns 7 个（mid-round 时全零）

use stwo::core::fields::m31::M31;
use stwo_constraint_framework::{EvalAtRow, FrameworkEval};

use crate::airs::actions::end_betting_round::{self, BettingOutcome, EndBettingRoundRow};
use crate::airs::common::{
    COMMON_NUM_COLUMNS, CommonConstraints, CommonRow, ZERO, u8_to_m31, u64_to_m31_limbs,
};
use crate::method_kind::MethodKind;

/// `call` 业务特定列布局。
pub mod cols {
    use super::COMMON_NUM_COLUMNS;
    /// `INPUT_SEAT_INDEX` 列。
    pub const INPUT_SEAT_INDEX: usize = COMMON_NUM_COLUMNS + 0;
    /// `INPUT_CALL_AMOUNT` 起始列（4 limb）。
    pub const INPUT_CALL_AMOUNT_BASE: usize = COMMON_NUM_COLUMNS + 1;
    /// `OUTPUT_SEAT_STACK` 起始列（4 limb）。
    pub const OUTPUT_SEAT_STACK_BASE: usize = COMMON_NUM_COLUMNS + 5;
    /// `OUTPUT_SEAT_BET` 起始列（4 limb）。
    pub const OUTPUT_SEAT_BET_BASE: usize = COMMON_NUM_COLUMNS + 9;
    /// `OUTPUT_ALL_IN` 列（1 = all-in）。
    pub const OUTPUT_ALL_IN: usize = COMMON_NUM_COLUMNS + 13;
    /// `OUTPUT_ACTED` 列（1 = 已行动）。
    pub const OUTPUT_ACTED: usize = COMMON_NUM_COLUMNS + 14;
    /// `INPUT_PRE_ROUND_STATE_Q` 列（Gap 1 witness：pre_round_state²，拆 4 次 vanishing）。
    pub const INPUT_PRE_ROUND_STATE_Q: usize = COMMON_NUM_COLUMNS + 15;
    /// `INPUT_CURRENT_TURN` witness（Gap: current_turn == seat_index）。
    pub const INPUT_CURRENT_TURN: usize = COMMON_NUM_COLUMNS + 16;
    /// `PRE_SEAT_BET` 起始列（4 limb）— 调用前 seat.bet，用于 bet delta 约束。
    /// 对齐合约 apply_call 的 `seat.bet = seat.bet.checked_add(call_amt)?`。
    pub const PRE_SEAT_BET_BASE: usize = COMMON_NUM_COLUMNS + 17;
    /// `PRE_SEAT_STACK` 起始列（4 limb）— 调用前 seat.stack，用于 stack delta 约束（阶段 3 soundness 升级）。
    pub const PRE_SEAT_STACK_BASE: usize = COMMON_NUM_COLUMNS + 21;
    /// `OUTPUT_SEAT_TOTAL_BET` 起始列（4 limb）— 调用后 seat.total_bet（阶段 3 新增）。
    pub const OUTPUT_SEAT_TOTAL_BET_BASE: usize = COMMON_NUM_COLUMNS + 25;
    /// `PRE_SEAT_TOTAL_BET` 起始列（4 limb）— 调用前 seat.total_bet（阶段 3 新增）。
    pub const PRE_SEAT_TOTAL_BET_BASE: usize = COMMON_NUM_COLUMNS + 29;
    /// `OUTPUT_CURRENT_TURN` — mid-round 推进后的下一行动座位。
    pub const OUTPUT_CURRENT_TURN: usize = COMMON_NUM_COLUMNS + 33;
    /// `call` AIR 总列数。
    pub const NUM_COLUMNS: usize = COMMON_NUM_COLUMNS + 34 + super::end_betting_round::NUM_COLUMNS;
}

/// `call` 输入参数。
#[derive(Debug, Clone)]
pub struct CallInput {
    /// 执行 call 的座位索引。
    pub seat_index: u8,
    /// 跟注金额。
    pub call_amount: u64,
    /// 调用前 betting_round.current_bet（verifier-trusted）。
    pub pre_current_bet: u64,
    /// 调用前 seat.bet（verifier-trusted）。
    pub pre_seat_bet: u64,
    /// 调用前 seat.stack（verifier-trusted）。
    pub pre_seat_stack: u64,
    /// 调用前 seat.total_bet（verifier-trusted）。
    pub pre_seat_total_bet: u64,
    /// Canonical mid-round or bet-collection branch derived by native replay.
    pub outcome: BettingOutcome,
}

/// `call` AIR 公开输入。
#[derive(Debug, Clone)]
pub struct CallAir {
    /// log2(trace 行数)。
    pub log_size: u32,
    /// 输入参数。
    pub input: CallInput,
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

impl CallAir {
    /// 列数。
    #[must_use]
    pub const fn num_columns() -> usize {
        cols::NUM_COLUMNS
    }
}

impl FrameworkEval for CallAir {
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
        // input_call_amount：完整 4 limb（阶段 3 soundness 升级：之前仅约束 limb 0）
        let input_call_amount: [E::F; 4] = [
            eval.next_trace_mask(),
            eval.next_trace_mask(),
            eval.next_trace_mask(),
            eval.next_trace_mask(),
        ];
        // output_seat_stack：完整 4 limb
        let output_seat_stack: [E::F; 4] = [
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
        let output_all_in = eval.next_trace_mask();
        let output_acted = eval.next_trace_mask();
        // Gap 1 witness：pre_round_state²
        let input_pre_round_state_q = eval.next_trace_mask();
        // Gap: current_turn == seat_index witness
        let input_current_turn = eval.next_trace_mask();
        // pre_seat_bet：完整 4 limb（对齐合约 checked_add）
        let pre_seat_bet: [E::F; 4] = [
            eval.next_trace_mask(),
            eval.next_trace_mask(),
            eval.next_trace_mask(),
            eval.next_trace_mask(),
        ];
        // 阶段 3 新增：pre_seat_stack、output_seat_total_bet、pre_seat_total_bet（各 4 limb）
        let pre_seat_stack: [E::F; 4] = [
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
        let pre_seat_total_bet: [E::F; 4] = [
            eval.next_trace_mask(),
            eval.next_trace_mask(),
            eval.next_trace_mask(),
            eval.next_trace_mask(),
        ];
        let output_current_turn = eval.next_trace_mask();

        // 约束 1：seat_index == input.seat_index
        let expected_seat: E::F = M31::from(u32::from(self.input.seat_index)).into();
        eval.add_constraint(is_active.clone() * (input_seat_index - expected_seat.clone()));
        // 约束: current_turn == seat_index（Gap: 阻止为非当前行动座位构造动作）
        eval.add_constraint(is_active.clone() * (input_current_turn - expected_seat));

        // 约束 2：所有资金 witness 都绑定 verifier-trusted AIR 常量，且 call_amount
        // 必须等于 VM 的 min(current_bet - seat.bet, stack)。
        let expected_call_amount = self
            .input
            .pre_current_bet
            .saturating_sub(self.input.pre_seat_bet)
            .min(self.input.pre_seat_stack);
        let post_stack_u64 = self
            .input
            .pre_seat_stack
            .checked_sub(self.input.call_amount);
        let post_bet_u64 = self.input.pre_seat_bet.checked_add(self.input.call_amount);
        let post_total_u64 = self
            .input
            .pre_seat_total_bet
            .checked_add(self.input.call_amount);
        let call_is_exact: E::F = M31::from(u32::from(
            self.input.call_amount == expected_call_amount
                && post_stack_u64.is_some()
                && post_bet_u64.is_some()
                && post_total_u64.is_some(),
        ))
        .into();
        let one: E::F = M31::from(1u32).into();
        eval.add_constraint(is_active.clone() * (call_is_exact - one.clone()));

        let expected_amount = u64_to_m31_limbs(self.input.call_amount);
        let expected_pre_bet = u64_to_m31_limbs(self.input.pre_seat_bet);
        let expected_pre_stack = u64_to_m31_limbs(self.input.pre_seat_stack);
        let expected_pre_total = u64_to_m31_limbs(self.input.pre_seat_total_bet);
        let expected_post_stack = u64_to_m31_limbs(post_stack_u64.unwrap_or(0));
        let expected_post_bet = u64_to_m31_limbs(post_bet_u64.unwrap_or(0));
        let expected_post_total = u64_to_m31_limbs(post_total_u64.unwrap_or(0));
        for i in 0..4 {
            eval.add_constraint(
                is_active.clone() * (input_call_amount[i].clone() - expected_amount[i].into()),
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

        // 约束 3：output_acted == 1
        eval.add_constraint(is_active.clone() * (output_acted - one));

        // 约束 4（审计共性）：必须处于下注轮（Gap 1）。
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
        // stack/bet/total_bet 已绑定到 verifier 端 checked u64 运算的逐 limb 常量；
        // 不使用无 carry 的逐 limb delta，因此跨 16-bit limb 的进位保持正确。

        // all_in 与 VM 公式一致；下一行动座位绑定 verifier-trusted AIR 输入。
        let expected_all_in: E::F = M31::from(u32::from(
            self.input.call_amount > 0 && self.input.call_amount == self.input.pre_seat_stack,
        ))
        .into();
        eval.add_constraint(is_active.clone() * (output_all_in - expected_all_in));
        let expected_post_turn: E::F =
            M31::from(u32::from(self.input.outcome.post_current_turn())).into();
        eval.add_constraint(is_active * (output_current_turn - expected_post_turn));
        eval
    }
}

/// `call` AIR 的 trace 行。
#[derive(Debug, Clone)]
pub struct CallRow {
    /// 通用列。
    pub common: CommonRow,
    /// `INPUT_SEAT_INDEX`。
    pub input_seat_index: M31,
    /// `INPUT_CALL_AMOUNT`（4 limb）。
    pub input_call_amount: [M31; 4],
    /// `OUTPUT_SEAT_STACK`（4 limb）。
    pub output_seat_stack: [M31; 4],
    /// `OUTPUT_SEAT_BET`（4 limb）。
    pub output_seat_bet: [M31; 4],
    /// `OUTPUT_ALL_IN`。
    pub output_all_in: M31,
    /// `OUTPUT_ACTED`。
    pub output_acted: M31,
    /// Gap 1 witness：pre_round_state²。
    pub input_pre_round_state_q: M31,
    /// `INPUT_CURRENT_TURN` witness（Gap: current_turn == seat_index）。
    pub input_current_turn: M31,
    /// `PRE_SEAT_BET`（4 limb）— 调用前 seat.bet。
    pub pre_seat_bet: [M31; 4],
    /// `PRE_SEAT_STACK`（4 limb）— 调用前 seat.stack（阶段 3 新增）。
    pub pre_seat_stack: [M31; 4],
    /// `OUTPUT_SEAT_TOTAL_BET`（4 limb）— 调用后 seat.total_bet（阶段 3 新增）。
    pub output_seat_total_bet: [M31; 4],
    /// `PRE_SEAT_TOTAL_BET`（4 limb）— 调用前 seat.total_bet（阶段 3 新增）。
    pub pre_seat_total_bet: [M31; 4],
    /// `OUTPUT_CURRENT_TURN` — mid-round 的下一行动座位。
    pub output_current_turn: M31,
    /// Shared round-completion columns; zero for mid-round calls.
    pub round_completion: EndBettingRoundRow,
}

impl CallRow {
    /// 构造 active 行。
    ///
    /// # 参数
    /// - `post_seat_stack`: 调用后座位 stack
    /// - `post_seat_bet`: 调用后座位 bet
    /// - `is_all_in`: 是否 all-in
    /// - `pre_seat_bet`: 调用前座位 bet（对齐合约 checked_add 修复）
    /// - `pre_seat_stack`: 调用前座位 stack（阶段 3 新增，stack delta 约束）
    /// - `post_seat_total_bet`: 调用后座位 total_bet（阶段 3 新增）
    /// - `pre_seat_total_bet`: 调用前座位 total_bet（阶段 3 新增）
    #[must_use]
    pub fn active(
        input: &CallInput,
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
        post_seat_stack: u64,
        post_seat_bet: u64,
        is_all_in: bool,
        pre_seat_bet: u64,
        pre_seat_stack: u64,
        post_seat_total_bet: u64,
        pre_seat_total_bet: u64,
    ) -> Self {
        let rs_m31 = u8_to_m31(pre_round_state);
        Self {
            common: CommonRow::active(
                MethodKind::Call,
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
            input_call_amount: u64_to_m31_limbs(input.call_amount),
            output_seat_stack: u64_to_m31_limbs(post_seat_stack),
            output_seat_bet: u64_to_m31_limbs(post_seat_bet),
            output_all_in: M31::from(u32::from(is_all_in)),
            output_acted: M31::from(1u32),
            // Gap 1 witness：pre_round_state²（M31 域内）
            input_pre_round_state_q: rs_m31 * rs_m31,
            input_current_turn: u8_to_m31(input.seat_index), // current_turn == seat_index
            pre_seat_bet: u64_to_m31_limbs(pre_seat_bet),
            pre_seat_stack: u64_to_m31_limbs(pre_seat_stack),
            output_seat_total_bet: u64_to_m31_limbs(post_seat_total_bet),
            pre_seat_total_bet: u64_to_m31_limbs(pre_seat_total_bet),
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
            input_call_amount: [ZERO; 4],
            output_seat_stack: [ZERO; 4],
            output_seat_bet: [ZERO; 4],
            output_all_in: ZERO,
            output_acted: ZERO,
            input_pre_round_state_q: ZERO,
            input_current_turn: ZERO,
            pre_seat_bet: [ZERO; 4],
            pre_seat_stack: [ZERO; 4],
            output_seat_total_bet: [ZERO; 4],
            pre_seat_total_bet: [ZERO; 4],
            output_current_turn: ZERO,
            round_completion: EndBettingRoundRow::zero(),
        }
    }

    /// 转为列向量。
    #[must_use]
    pub fn to_vec(&self) -> Vec<M31> {
        let mut v = self.common.to_vec();
        v.push(self.input_seat_index);
        v.extend_from_slice(&self.input_call_amount);
        v.extend_from_slice(&self.output_seat_stack);
        v.extend_from_slice(&self.output_seat_bet);
        v.push(self.output_all_in);
        v.push(self.output_acted);
        v.push(self.input_pre_round_state_q);
        v.push(self.input_current_turn);
        v.extend_from_slice(&self.pre_seat_bet);
        v.extend_from_slice(&self.pre_seat_stack);
        v.extend_from_slice(&self.output_seat_total_bet);
        v.extend_from_slice(&self.pre_seat_total_bet);
        v.push(self.output_current_turn);
        self.round_completion.append_to(&mut v);
        debug_assert_eq!(v.len(), cols::NUM_COLUMNS);
        v
    }
}
