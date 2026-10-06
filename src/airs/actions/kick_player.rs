//! `kick_player` AIR — 踢出玩家（管理员操作）。
//!
//! 移植自 `dispatch::dispatch_kick_player` 与 `state_machine::apply_kick_player`。
//!
//! ## 业务规约
//!
//! 1. 调用者是管理员（admin）
//! 2. 目标座位存在且 occupied
//! 3. 退还玩家剩余 stack + pending addon 到其地址
//! 4. 状态变更（与 fold **不同**的资金流向）：
//!    - **`table.pot += seat.bet; seat.bet = 0`**（被踢者当前下注立即入底池，
//!      见 `state_machine::kick_player_internal` state_machine.rs:2689）
//!    - `seat.stack = 0`, `seat.left_during_hand = true`, `seat.folded = true`
//!    - `seat.all_in = false`, `seat.is_waiting = false`, `seat.pk = identity`
//!    - ordinary active-hand path retains the player marker for hand accounting; a later reset
//!      removes the zero-stack occupied seat
//!    - ordinary kick: `version += 1`, final `pot = pre_pot + kicked_bet`
//!    - canonical settlement/reset cascade: `version += 2`, final round is WAITING and pot is 0;
//!      the intermediate collection and complete award/reset projection are bound by the
//!      independent BetCollection and Settlement STARK proofs.
//!
//! ## AIR 列布局
//!
//! - 通用列 37 个
//! - 基础业务列 26 个：`INPUT_SEAT_INDEX`, `OUTPUT_REFUND_BASE[4]`,
//!   `OUTPUT_KICKED`, `KICKED_BET_BASE[4]`, `INPUT_SEAT_OCCUPIED`,
//!   `POT_ADD_CARRY_BASE[3]`, `RESET_CASCADE`, refund source limbs/carries
//! - 管理员授权列 34 个：ABI、role、完整 request/receipt digest
//!
//! 资金流向约束（全 4 limb，对齐合约 checked_add 修复）：除 seat_index / refund /
//! kicked 一致性外，普通路径强制 **`post_pot = pre_pot + kicked_bet`**（全 4 limb
//! delta，底池增量 == 被踢者下注）；reset cascade 路径强制最终
//! **`post_round = WAITING && post_pot = 0`**。退款还必须满足完整 checked-u64
//! `refund = pre_stack + pre_pending_addon`。交易签名由共识锚验证；AIR 绑定 canonical
//! dispatch replay 签发的管理员 authorization receipt。

use stwo::core::fields::m31::M31;
use stwo_constraint_framework::{EvalAtRow, FrameworkEval};

use poker_l1::contracts::texas_poker::constants::ROUND_WAITING;

use crate::airs::common::{
    COMMON_NUM_COLUMNS, CommonConstraints, CommonRow, ZERO, compute_add_carries, u8_to_m31,
    u64_to_m31_limbs,
};
use crate::authorization_binding::AdminAuthorizationAirBinding;
use crate::method_kind::MethodKind;
use crate::precompile_binding::DIGEST_LIMBS;

/// `kick_player` 业务特定列布局。
pub mod cols {
    use super::COMMON_NUM_COLUMNS;
    /// `INPUT_SEAT_INDEX` 列。
    pub const INPUT_SEAT_INDEX: usize = COMMON_NUM_COLUMNS + 0;
    /// `OUTPUT_REFUND` 起始列（4 limb，退还玩家 stack）。
    pub const OUTPUT_REFUND_BASE: usize = COMMON_NUM_COLUMNS + 1;
    /// `OUTPUT_KICKED` 列（1 = 已踢出）。
    pub const OUTPUT_KICKED: usize = COMMON_NUM_COLUMNS + 5;
    /// `KICKED_BET` 起始列（4 limb）— 被踢者当前下注（pot += kicked_bet）。
    /// 对齐合约 kick_player_internal 的 `table.pot = table.pot.checked_add(seat.bet)?`。
    pub const KICKED_BET_BASE: usize = COMMON_NUM_COLUMNS + 6;
    /// `INPUT_SEAT_OCCUPIED` boolean witness（Gap 3）。
    pub const INPUT_SEAT_OCCUPIED: usize = COMMON_NUM_COLUMNS + 10;
    /// pot 加法的 3 个 ripple-carry bit。
    pub const POT_ADD_CARRY_BASE: usize = COMMON_NUM_COLUMNS + 11;
    /// 是否触发 canonical settlement/reset cascade。
    pub const RESET_CASCADE: usize = COMMON_NUM_COLUMNS + 14;
    /// 被踢座位调用前 stack（4 limb）。
    pub const INPUT_PRE_STACK_BASE: usize = COMMON_NUM_COLUMNS + 15;
    /// 被踢座位调用前 pending addon（4 limb）。
    pub const INPUT_PRE_PENDING_ADDON_BASE: usize = COMMON_NUM_COLUMNS + 19;
    /// `pre_stack + pending_addon = refund` 的 ripple carry。
    pub const REFUND_ADD_CARRY_BASE: usize = COMMON_NUM_COLUMNS + 23;
    /// 管理员授权 ABI 版本。
    pub const AUTH_ABI_VERSION: usize = COMMON_NUM_COLUMNS + 26;
    /// 管理员授权角色。
    pub const AUTH_ROLE: usize = COMMON_NUM_COLUMNS + 27;
    /// 完整授权请求摘要。
    pub const AUTH_REQUEST_DIGEST_BASE: usize = COMMON_NUM_COLUMNS + 28;
    /// 完整授权成功 receipt 摘要。
    pub const AUTH_RECEIPT_DIGEST_BASE: usize = AUTH_REQUEST_DIGEST_BASE + super::DIGEST_LIMBS;
    /// `kick_player` AIR 总列数。
    pub const NUM_COLUMNS: usize = AUTH_RECEIPT_DIGEST_BASE + super::DIGEST_LIMBS;
}

/// `kick_player` 输入参数。
#[derive(Debug, Clone)]
pub struct KickPlayerInput {
    /// 被踢出的座位索引。
    pub seat_index: u8,
    /// 退还金额（= seat.stack + seat.pending_addon）。
    pub refund: u64,
    /// 被踢座位调用前 stack。
    pub pre_stack: u64,
    /// 被踢座位调用前 pending addon。
    pub pre_pending_addon: u64,
    /// 被踢者当前下注（kick 时立即并入底池：`pot += kicked_bet`）。
    pub kicked_bet: u64,
    /// Native version bumps: one for the kick and one more when it cascades into reset.
    pub version_increment: u8,
    /// Whether the native kick cascaded through settlement/reset to WAITING.
    pub reset_cascade: bool,
    /// Verifier-issued table-creator authorization receipt.
    pub authorization: AdminAuthorizationAirBinding,
}

/// `kick_player` AIR 公开输入。
#[derive(Debug, Clone)]
pub struct KickPlayerAir {
    /// log2(trace 行数)。
    pub log_size: u32,
    /// 输入参数。
    pub input: KickPlayerInput,
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

impl KickPlayerAir {
    /// 列数。
    #[must_use]
    pub const fn num_columns() -> usize {
        cols::NUM_COLUMNS
    }
}

impl FrameworkEval for KickPlayerAir {
    fn log_size(&self) -> u32 {
        self.log_size
    }
    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_size + 1
    }
    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let statement = crate::airs::TexasAir::statement(self);
        let common = CommonConstraints::write_with_version_increment(
            &mut eval,
            &statement,
            u64::from(self.input.version_increment),
        );
        let is_active = common.is_active.clone();

        let input_seat_index = eval.next_trace_mask();
        let output_refund = [
            eval.next_trace_mask(),
            eval.next_trace_mask(),
            eval.next_trace_mask(),
            eval.next_trace_mask(),
        ];
        let output_kicked = eval.next_trace_mask();
        // KICKED_BET（4 limb）— 被踢者当前下注，pot += kicked_bet
        let kicked_bet_0 = eval.next_trace_mask();
        let kicked_bet_1 = eval.next_trace_mask();
        let kicked_bet_2 = eval.next_trace_mask();
        let kicked_bet_3 = eval.next_trace_mask();
        let kicked_bet_limbs = [
            kicked_bet_0.clone(),
            kicked_bet_1.clone(),
            kicked_bet_2.clone(),
            kicked_bet_3.clone(),
        ];
        // Gap 3 boolean witness（座位非空）。
        let input_seat_occupied = eval.next_trace_mask();
        let pot_add_carry: [E::F; 3] = [
            eval.next_trace_mask(),
            eval.next_trace_mask(),
            eval.next_trace_mask(),
        ];
        let reset_cascade = eval.next_trace_mask();
        let pre_stack = [
            eval.next_trace_mask(),
            eval.next_trace_mask(),
            eval.next_trace_mask(),
            eval.next_trace_mask(),
        ];
        let pre_pending_addon = [
            eval.next_trace_mask(),
            eval.next_trace_mask(),
            eval.next_trace_mask(),
            eval.next_trace_mask(),
        ];
        let refund_add_carry = [
            eval.next_trace_mask(),
            eval.next_trace_mask(),
            eval.next_trace_mask(),
        ];
        let auth_abi_version = eval.next_trace_mask();
        let auth_role = eval.next_trace_mask();
        let auth_request_digest: Vec<_> =
            (0..DIGEST_LIMBS).map(|_| eval.next_trace_mask()).collect();
        let auth_receipt_digest: Vec<_> =
            (0..DIGEST_LIMBS).map(|_| eval.next_trace_mask()).collect();

        // 约束 1：seat_index == input.seat_index
        let expected_seat: E::F = M31::from(u32::from(self.input.seat_index)).into();
        eval.add_constraint(is_active.clone() * (input_seat_index - expected_seat));

        // 约束 2：refund 与两个来源金额均完整绑定为 verifier-owned u64 limbs。
        let expected_refund = u64_to_m31_limbs(self.input.refund);
        let expected_stack = u64_to_m31_limbs(self.input.pre_stack);
        let expected_pending = u64_to_m31_limbs(self.input.pre_pending_addon);
        for limb in 0..4 {
            eval.add_constraint(
                is_active.clone()
                    * (output_refund[limb].clone() - E::F::from(expected_refund[limb])),
            );
            eval.add_constraint(
                is_active.clone() * (pre_stack[limb].clone() - E::F::from(expected_stack[limb])),
            );
            eval.add_constraint(
                is_active.clone()
                    * (pre_pending_addon[limb].clone() - E::F::from(expected_pending[limb])),
            );
        }
        // 完整 ripple-carry 同时证明无 u64 overflow。
        for constraint in common.limb4_delta(
            &pre_stack,
            &output_refund,
            &pre_pending_addon,
            &refund_add_carry,
        ) {
            eval.add_constraint(constraint);
        }

        // 约束 3：output_kicked == 1
        let one: E::F = M31::from(1u32).into();
        eval.add_constraint(is_active.clone() * (output_kicked - one.clone()));

        // 约束 4（资金流向不变量，全 4 limb）：kick 时被踢者当前下注立即并入底池
        //   `table.pot = table.pot.checked_add(seat.bet)?`（state_machine.rs）
        //   即 post_pot = pre_pot + kicked_bet（全 4 limb delta）
        //   对齐合约 checked_add 修复：溢出时合约返回 Err，AIR 约束 delta 一致性。
        let expected_kicked_bet = u64_to_m31_limbs(self.input.kicked_bet);
        for i in 0..4 {
            eval.add_constraint(
                is_active.clone()
                    * (kicked_bet_limbs[i].clone() - E::F::from(expected_kicked_bet[i])),
            );
        }

        // 约束 5：reset_cascade 是公开绑定的 boolean witness。
        let expected_reset: E::F = M31::from(u32::from(self.input.reset_cascade)).into();
        eval.add_constraint(is_active.clone() * (reset_cascade.clone() - expected_reset.clone()));
        eval.add_constraint(reset_cascade.clone() * (reset_cascade - one.clone()));

        // 约束 6：普通路径保持旧语义；cascade 路径绑定最终 WAITING/zero-pot 边界。
        // Branch selectors come from the verifier-reconstructed AIR input, so multiplying the
        // existing degree-2 common constraints does not raise their algebraic degree.
        let ordinary = one.clone() - expected_reset.clone();
        for constraint in common.pot_delta_4limb(&kicked_bet_limbs, &pot_add_carry) {
            eval.add_constraint(ordinary.clone() * constraint);
        }
        eval.add_constraint(ordinary * common.round_state_unchanged());
        let waiting: E::F = M31::from(u32::from(ROUND_WAITING)).into();
        eval.add_constraint(
            is_active.clone()
                * expected_reset.clone()
                * (common.post_round_state.clone() - waiting),
        );
        for limb in &common.post_pot {
            eval.add_constraint(is_active.clone() * expected_reset.clone() * limb.clone());
        }

        // 约束 7（Gap 3，degree-2）：input_seat_occupied == 1 — 诚实 host 只踢占用座位。
        eval.add_constraint(is_active.clone() * (input_seat_occupied - one.clone()));

        // 约束 8：绑定 host-native canonical authorization request/receipt。
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

        eval
    }
}

/// `kick_player` AIR 的 trace 行。
#[derive(Debug, Clone)]
pub struct KickPlayerRow {
    /// 通用列。
    pub common: CommonRow,
    /// `INPUT_SEAT_INDEX`。
    pub input_seat_index: M31,
    /// `OUTPUT_REFUND`（4 limb）。
    pub output_refund: [M31; 4],
    /// `OUTPUT_KICKED`。
    pub output_kicked: M31,
    /// `KICKED_BET`（4 limb）— 被踢者当前下注。
    pub kicked_bet: [M31; 4],
    /// `INPUT_SEAT_OCCUPIED` boolean witness（Gap 3）。
    pub input_seat_occupied: M31,
    /// pot 加法的 3 个 ripple-carry bit。
    pub pot_add_carry: [M31; 3],
    /// 是否触发 settlement/reset cascade。
    pub reset_cascade: M31,
    /// 被踢座位调用前 stack。
    pub input_pre_stack: [M31; 4],
    /// 被踢座位调用前 pending addon。
    pub input_pre_pending_addon: [M31; 4],
    /// refund checked-add ripple carry。
    pub refund_add_carry: [M31; 3],
    /// Verifier-issued administrator authorization binding.
    pub authorization: AdminAuthorizationAirBinding,
}

impl KickPlayerRow {
    /// 构造 active 行。
    #[must_use]
    pub fn active(
        input: &KickPlayerInput,
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
                MethodKind::KickPlayer,
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
            output_refund: u64_to_m31_limbs(input.refund),
            output_kicked: M31::from(1u32),
            kicked_bet: u64_to_m31_limbs(input.kicked_bet),
            // Gap 3：诚实 host 只踢占用座位。
            input_seat_occupied: M31::from(1u32),
            pot_add_carry: if input.reset_cascade {
                [ZERO; 3]
            } else {
                compute_add_carries(pre_pot, input.kicked_bet)
            },
            reset_cascade: M31::from(u32::from(input.reset_cascade)),
            input_pre_stack: u64_to_m31_limbs(input.pre_stack),
            input_pre_pending_addon: u64_to_m31_limbs(input.pre_pending_addon),
            refund_add_carry: compute_add_carries(input.pre_stack, input.pre_pending_addon),
            authorization: input.authorization,
        }
    }

    /// 构造 padding 行。
    #[must_use]
    pub fn padding() -> Self {
        Self {
            common: CommonRow::padding(),
            input_seat_index: ZERO,
            output_refund: [ZERO; 4],
            output_kicked: ZERO,
            kicked_bet: [ZERO; 4],
            input_seat_occupied: ZERO,
            pot_add_carry: [ZERO; 3],
            reset_cascade: ZERO,
            input_pre_stack: [ZERO; 4],
            input_pre_pending_addon: [ZERO; 4],
            refund_add_carry: [ZERO; 3],
            authorization: AdminAuthorizationAirBinding {
                abi_version: 0,
                role: 0,
                request_digest: [ZERO; DIGEST_LIMBS],
                receipt_digest: [ZERO; DIGEST_LIMBS],
            },
        }
    }

    /// 转为列向量。
    #[must_use]
    pub fn to_vec(&self) -> Vec<M31> {
        let mut v = self.common.to_vec();
        v.push(self.input_seat_index);
        v.extend_from_slice(&self.output_refund);
        v.push(self.output_kicked);
        v.extend_from_slice(&self.kicked_bet);
        v.push(self.input_seat_occupied);
        v.extend_from_slice(&self.pot_add_carry);
        v.push(self.reset_cascade);
        v.extend_from_slice(&self.input_pre_stack);
        v.extend_from_slice(&self.input_pre_pending_addon);
        v.extend_from_slice(&self.refund_add_carry);
        v.push(M31::from(u32::from(self.authorization.abi_version)));
        v.push(M31::from(u32::from(self.authorization.role)));
        v.extend_from_slice(&self.authorization.request_digest);
        v.extend_from_slice(&self.authorization.receipt_digest);
        debug_assert_eq!(v.len(), cols::NUM_COLUMNS);
        v
    }
}
