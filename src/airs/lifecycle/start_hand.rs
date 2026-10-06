//! `start_hand` AIR — 开始新一局（投盲注 + 进入 shuffle 阶段）。
//!
//! ## 业务规约（对齐 `state_machine::start_hand`）
//! 1. `round_state == ROUND_WAITING`
//! 2. 活跃玩家数 ≥ `MIN_PLAYERS_TO_START`（= 2）
//! 3. 状态变更：`button` 旋转到下一个占用座；**`round_state` 保持 `ROUND_WAITING`**
//!    （合约在 `start_hand` 后并不改 `round_state`，只有当 preflop reveal phase
//!    完成时才转为 `ROUND_PREFLOP`，见 `check_reveal_phase_complete`）。
//!    真正进入 shuffle 的语义由独立的 `shuffle_state.phase = SHUFFLE_PHASE_BEFORE_PREFLOP`
//!    表达，**不属于 `round_state`**（合约 `constants.rs` 无 `ROUND_SHUFFLE` 常量）。
//! 4. **Ante 配置**：声明本手的 ante_mode / ante_amount / ante_collected，
//!    约束 ante_mode 与公开输入一致，ante_collected 在 NONE 模式下 == 0

use stwo::core::fields::m31::M31;
use stwo_constraint_framework::{EvalAtRow, FrameworkEval};

use crate::airs::common::{
    COMMON_NUM_COLUMNS, CommonConstraints, CommonRow, ZERO, compute_add_carries, u8_to_m31,
    u64_to_m31_limbs,
};
use crate::authorization_binding::AdminAuthorizationAirBinding;
use crate::method_kind::MethodKind;
use crate::precompile_binding::DIGEST_LIMBS;

/// `start_hand` 业务特定列布局。
pub mod cols {
    use super::COMMON_NUM_COLUMNS;
    /// `INPUT_ACTIVE_COUNT` 列。
    pub const INPUT_ACTIVE_COUNT: usize = COMMON_NUM_COLUMNS + 0;
    /// `OUTPUT_NEW_BUTTON` 列。
    pub const OUTPUT_NEW_BUTTON: usize = COMMON_NUM_COLUMNS + 1;
    /// `OUTPUT_NEW_ROUND_STATE` 列。
    pub const OUTPUT_NEW_ROUND_STATE: usize = COMMON_NUM_COLUMNS + 2;
    /// `OUTPUT_ANTE_MODE` 列（0=NONE, 1=NORMAL, 2=BBA）。
    pub const OUTPUT_ANTE_MODE: usize = COMMON_NUM_COLUMNS + 3;
    /// `OUTPUT_ANTE_AMOUNT` 起始列（完整 4×16-bit u64）。
    pub const OUTPUT_ANTE_AMOUNT_BASE: usize = COMMON_NUM_COLUMNS + 4;
    /// `OUTPUT_ANTE_COLLECTED` 起始列（完整 4×16-bit u64）。
    pub const OUTPUT_ANTE_COLLECTED_BASE: usize = COMMON_NUM_COLUMNS + 8;
    /// `INPUT_ACTIVE_COUNT_INV` 列（Gap 4 witness：active_count*(active_count-1) 的乘法逆元）。
    pub const INPUT_ACTIVE_COUNT_INV: usize = COMMON_NUM_COLUMNS + 12;
    /// `INPUT_ACTIVE_COUNT_PROD` 列（Gap 4 witness：active_count*(active_count-1)）。
    /// 引入此中间列把 `prod * inv == 1` 约束降到 degree-2（两列乘积），
    /// 否则 `active_count*(active_count-1)*inv` 是三列乘积，degree 超过 Stwo 上界。
    pub const INPUT_ACTIVE_COUNT_PROD: usize = COMMON_NUM_COLUMNS + 13;
    /// `pre_pot + ante_collected = post_pot` 的 ripple carry。
    pub const ANTE_POT_ADD_CARRY_BASE: usize = COMMON_NUM_COLUMNS + 14;
    /// Creator authorization ABI version.
    pub const AUTH_ABI_VERSION: usize = COMMON_NUM_COLUMNS + 17;
    /// Creator authorization role.
    pub const AUTH_ROLE: usize = COMMON_NUM_COLUMNS + 18;
    /// Creator authorization request digest.
    pub const AUTH_REQUEST_DIGEST_BASE: usize = COMMON_NUM_COLUMNS + 19;
    /// Creator authorization receipt digest.
    pub const AUTH_RECEIPT_DIGEST_BASE: usize = AUTH_REQUEST_DIGEST_BASE + super::DIGEST_LIMBS;
    /// 总列数。
    pub const NUM_COLUMNS: usize = AUTH_RECEIPT_DIGEST_BASE + super::DIGEST_LIMBS;
}

/// `start_hand` 输入参数。
#[derive(Debug, Clone)]
pub struct StartHandInput {
    /// 活跃玩家数。
    pub active_count: u8,
    /// 移动后的庄家座位。
    pub new_button: u8,
    /// Ante 模式（0=NONE, 1=NORMAL, 2=BBA）。
    pub ante_mode: u8,
    /// Ante 金额。
    pub ante_amount: u64,
    /// 本手实际收取的 ante 总额；短码座位只缴纳其剩余 stack。
    pub ante_collected: u64,
    /// 调用前底池。
    pub pre_pot: u64,
    /// 调用后底池。
    pub post_pot: u64,
    /// Verifier-issued table-creator authorization receipt.
    pub authorization: AdminAuthorizationAirBinding,
}

/// `start_hand` AIR。
#[derive(Debug, Clone)]
pub struct StartHandAir {
    /// log2(行数)。
    pub log_size: u32,
    /// 输入参数。
    pub input: StartHandInput,
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

impl StartHandAir {
    /// 列数。
    #[must_use]
    pub const fn num_columns() -> usize {
        cols::NUM_COLUMNS
    }
}

impl FrameworkEval for StartHandAir {
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

        let input_active_count = eval.next_trace_mask();
        let output_new_button = eval.next_trace_mask();
        let output_new_round_state = eval.next_trace_mask();
        let output_ante_mode = eval.next_trace_mask();
        let output_ante_amount = [
            eval.next_trace_mask(),
            eval.next_trace_mask(),
            eval.next_trace_mask(),
            eval.next_trace_mask(),
        ];
        let output_ante_collected = [
            eval.next_trace_mask(),
            eval.next_trace_mask(),
            eval.next_trace_mask(),
            eval.next_trace_mask(),
        ];
        // Gap 4 witnesses：active_count*(active_count-1) 及其乘法逆元
        let input_active_count_inv = eval.next_trace_mask();
        let input_active_count_prod = eval.next_trace_mask();
        let ante_pot_add_carry = [
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

        // 约束 1：active_count == input.active_count
        let expected_count: E::F = M31::from(u32::from(self.input.active_count)).into();
        eval.add_constraint(is_active.clone() * (input_active_count.clone() - expected_count));

        // 约束 2a（Gap 4 part 1）：prod == active_count*(active_count-1)（degree-2 两列乘积）。
        // 用中间列 prod 把三列乘积拆成两个两列乘积约束，避免 degree 超过 Stwo 上界。
        let one: E::F = M31::from(1u32).into();
        let count_minus_one = input_active_count.clone() - one.clone();
        eval.add_constraint(
            is_active.clone()
                * (input_active_count_prod.clone() - input_active_count.clone() * count_minus_one),
        );

        // 约束 2b（Gap 4 part 2）：prod * inv == 1（degree-2 两列乘积）。
        // 强制 active_count*(active_count-1) ≠ 0，即 active_count ∉ {0,1} → active_count ≥ 2。
        eval.add_constraint(
            is_active.clone()
                * (input_active_count_prod.clone() * input_active_count_inv.clone() - one),
        );
        // 约束 2c：移动后的 button 与 verifier-trusted 输入一致。
        let expected_button: E::F = M31::from(u32::from(self.input.new_button)).into();
        eval.add_constraint(is_active.clone() * (output_new_button - expected_button));
        // 约束 3：output_new_round_state == ROUND_WAITING (常量)
        // 合约 start_hand 后 round_state 仍为 ROUND_WAITING=0；真正进入 shuffle 由
        // shuffle_state.phase 表达（SHUFFLE_PHASE_BEFORE_PREFLOP=3），不属于 round_state。
        let expected_round: E::F = M31::from(0u32).into();
        eval.add_constraint(is_active.clone() * (output_new_round_state - expected_round));

        // 约束 3b（审计 start_hand 前置，degree-2）：pre_round_state == WAITING(0)。
        // start_hand 仅在 WAITING 状态合法（Lean 反例：PREFLOP 下 start_hand）。
        eval.add_constraint(common.round_state_eq(0));

        // 约束 4（Ante）：ante_mode 与公开输入一致
        let expected_ante_mode: E::F = M31::from(u32::from(self.input.ante_mode)).into();
        eval.add_constraint(is_active.clone() * (output_ante_mode - expected_ante_mode));

        // 约束 5/6（Ante）：金额与累计金额均完整绑定为 canonical u64 limbs。
        //   - NONE 模式 (mode==0)：host 设置 ante_collected = 0
        //   - NORMAL/BBA：host 按 canonical per-seat `min(ante_amount, stack)` 结果重建
        // verifier 从 canonical post-state 重建两个 u64，因此逐 limb 常量等式同时固定
        // 16-bit range，拒绝跨 limb 截断或高位替换。
        let expected_amount = u64_to_m31_limbs(self.input.ante_amount);
        let expected_collected = u64_to_m31_limbs(self.input.ante_collected);
        for limb in 0..4 {
            eval.add_constraint(
                is_active.clone()
                    * (output_ante_amount[limb].clone() - E::F::from(expected_amount[limb])),
            );
            eval.add_constraint(
                is_active.clone()
                    * (output_ante_collected[limb].clone() - E::F::from(expected_collected[limb])),
            );
        }

        // 约束 7：ante 资金完整进入 pot，使用 4×16-bit ripple carry，并拒绝
        // 最高 limb overflow。pre/post pot 同样来自 verifier 重建的 canonical u64。
        let expected_pre_pot = u64_to_m31_limbs(self.input.pre_pot);
        let expected_post_pot = u64_to_m31_limbs(self.input.post_pot);
        for limb in 0..4 {
            eval.add_constraint(
                is_active.clone()
                    * (common.pre_pot[limb].clone() - E::F::from(expected_pre_pot[limb])),
            );
            eval.add_constraint(
                is_active.clone()
                    * (common.post_pot[limb].clone() - E::F::from(expected_post_pot[limb])),
            );
        }
        for constraint in common.limb4_delta(
            &common.pre_pot,
            &common.post_pot,
            &output_ante_collected,
            &ante_pot_add_carry,
        ) {
            eval.add_constraint(constraint);
        }

        let expected_abi: E::F = M31::from(u32::from(self.input.authorization.abi_version)).into();
        let expected_role: E::F = M31::from(u32::from(self.input.authorization.role)).into();
        eval.add_constraint(is_active.clone() * (auth_abi_version - expected_abi));
        eval.add_constraint(is_active.clone() * (auth_role - expected_role));
        for limb in 0..DIGEST_LIMBS {
            eval.add_constraint(
                is_active.clone()
                    * (auth_request_digest[limb].clone()
                        - E::F::from(self.input.authorization.request_digest[limb])),
            );
            eval.add_constraint(
                is_active.clone()
                    * (auth_receipt_digest[limb].clone()
                        - E::F::from(self.input.authorization.receipt_digest[limb])),
            );
        }

        eval
    }
}

/// `start_hand` trace 行。
#[derive(Debug, Clone)]
pub struct StartHandRow {
    /// 通用列。
    pub common: CommonRow,
    /// 活跃玩家数。
    pub input_active_count: M31,
    /// 新 button。
    pub output_new_button: M31,
    /// 新 round_state。
    pub output_new_round_state: M31,
    /// Ante 模式。
    pub output_ante_mode: M31,
    /// Ante 金额（完整 4×16-bit u64）。
    pub output_ante_amount: [M31; 4],
    /// Ante 已收（完整 4×16-bit u64）。
    pub output_ante_collected: [M31; 4],
    /// Gap 4 witness：active_count*(active_count-1) 的乘法逆元（M31 域内）。
    pub input_active_count_inv: M31,
    /// Gap 4 witness：active_count*(active_count-1)（中间列，拆三列乘积为两个两列乘积）。
    pub input_active_count_prod: M31,
    /// ante 加入 pot 的 3 个 ripple-carry bit。
    pub ante_pot_add_carry: [M31; 3],
    /// Verifier-issued table-creator authorization binding.
    pub authorization: AdminAuthorizationAirBinding,
}

impl StartHandRow {
    /// active 行。
    ///
    /// # 参数
    /// - `active_count_inv`: `active_count*(active_count-1)` 在 M31 域内的乘法逆元。
    ///   host 端由 `(active_count as u64 * (active_count-1) as u64)` 求 inverse 得到。
    ///   active_count ≥ 2 时该值非零，满足 Gap 4 约束。
    /// - `active_count_prod`: `active_count*(active_count-1)`（host 计算）。
    #[must_use]
    pub fn active(
        input: &StartHandInput,
        active_count_inv: M31,
        active_count_prod: M31,
        pre_state_root: [M31; 4],
        post_state_root: [M31; 4],
        table_id: u64,
        hand_id: u32,
        call_seq: u32,
        pre_version: u64,
        post_version: u64,
    ) -> Self {
        Self {
            common: CommonRow::active(
                MethodKind::StartHand,
                pre_state_root,
                post_state_root,
                table_id,
                hand_id,
                call_seq,
                pre_version,
                post_version,
                0, // pre = ROUND_WAITING
                0, // post = ROUND_WAITING（合约 start_hand 后 round_state 不变）
                input.pre_pot,
                input.post_pot,
                0,
                0,
            ),
            input_active_count: u8_to_m31(input.active_count),
            output_new_button: u8_to_m31(input.new_button),
            output_new_round_state: M31::from(0u32), // ROUND_WAITING
            output_ante_mode: u8_to_m31(input.ante_mode),
            output_ante_amount: u64_to_m31_limbs(input.ante_amount),
            output_ante_collected: u64_to_m31_limbs(input.ante_collected),
            input_active_count_inv: active_count_inv,
            input_active_count_prod: active_count_prod,
            ante_pot_add_carry: if input.pre_pot.checked_add(input.ante_collected)
                == Some(input.post_pot)
            {
                compute_add_carries(input.pre_pot, input.ante_collected)
            } else {
                [ZERO; 3]
            },
            authorization: input.authorization,
        }
    }
    /// padding 行。
    #[must_use]
    pub fn padding() -> Self {
        Self {
            common: CommonRow::padding(),
            input_active_count: ZERO,
            output_new_button: ZERO,
            output_new_round_state: ZERO,
            output_ante_mode: ZERO,
            output_ante_amount: [ZERO; 4],
            output_ante_collected: [ZERO; 4],
            // padding 行 is_active=0，约束自动满足（gated），witness 值任意；用 ZERO。
            input_active_count_inv: ZERO,
            input_active_count_prod: ZERO,
            ante_pot_add_carry: [ZERO; 3],
            authorization: AdminAuthorizationAirBinding {
                abi_version: 0,
                role: 0,
                request_digest: [ZERO; DIGEST_LIMBS],
                receipt_digest: [ZERO; DIGEST_LIMBS],
            },
        }
    }
    /// 转列向量。
    #[must_use]
    pub fn to_vec(&self) -> Vec<M31> {
        let mut v = self.common.to_vec();
        v.push(self.input_active_count);
        v.push(self.output_new_button);
        v.push(self.output_new_round_state);
        v.push(self.output_ante_mode);
        v.extend_from_slice(&self.output_ante_amount);
        v.extend_from_slice(&self.output_ante_collected);
        v.push(self.input_active_count_inv);
        v.push(self.input_active_count_prod);
        v.extend_from_slice(&self.ante_pot_add_carry);
        v.push(M31::from(u32::from(self.authorization.abi_version)));
        v.push(M31::from(u32::from(self.authorization.role)));
        v.extend_from_slice(&self.authorization.request_digest);
        v.extend_from_slice(&self.authorization.receipt_digest);
        debug_assert_eq!(v.len(), cols::NUM_COLUMNS);
        v
    }
}
