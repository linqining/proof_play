//! `submit_player_reveal_tokens` AIR — 提交揭牌令牌。
//!
//! 移植自 `dispatch::dispatch_submit_player_reveal_tokens` 与
//! `state_machine::apply_submit_player_reveal_tokens`。
//!
//! ## 业务规约
//!
//! 1. 阶段守卫绑定由 `RevealPurpose + HandPhase.street` 唯一投影的 numeric phase；
//!    `round_state` 在 reveal 期间可为 WAITING（preflop reveal）或 PREFLOP..SHOWDOWN，
//!    且单次 submit 不改变 `round_state`（pre == post）。真正的相位约束由
//!    `INPUT_REVEAL_PHASE` 列承载（见 evaluate）。
//! 2. `seat_index` 在 `reveal_assignments` 中
//! 3. 提交 RevealTokenProof（DLEq 证明 reveal token 正确性）
//! 4. 状态变更：
//!    - `reveal_token_state.revealed[seat_index] = true`
//!    - 若所有需揭示的玩家都已提交，进入 reconstruct 阶段
//!    - `version += 1`
//!
//! ## 密码学调用绑定
//!
//! AIR 约束 canonical batched reveal-token request digest 与 verifier-issued
//! receipt digest。生产 verifier 会按 pre-state assignment 重建 exact ciphertext、
//! token、registered player key、proof 和 replay scope，并重新执行原生验证。

use stwo::core::fields::m31::M31;
use stwo_constraint_framework::{EvalAtRow, FrameworkEval};

use crate::airs::common::{
    COMMON_NUM_COLUMNS, CommonConstraints, CommonRow, ZERO, compute_add_carries, u8_to_m31,
    u64_to_m31_limbs,
};
use crate::method_kind::MethodKind;
use crate::precompile_binding::{DIGEST_LIMBS, PrecompileAirBinding, digest_to_m31_limbs};
use crate::settlement_binding::{SETTLEMENT_SEATS, SettlementPlanBinding};

/// `submit_player_reveal_tokens` 业务特定列布局。
pub mod cols {
    use super::COMMON_NUM_COLUMNS;
    /// `INPUT_SEAT_INDEX` 列。
    pub const INPUT_SEAT_INDEX: usize = COMMON_NUM_COLUMNS + 0;
    /// `INPUT_REVEAL_PHASE` 列。
    pub const INPUT_REVEAL_PHASE: usize = COMMON_NUM_COLUMNS + 1;
    /// `OUTPUT_REVEALED_COUNT` 列。
    pub const OUTPUT_REVEALED_COUNT: usize = COMMON_NUM_COLUMNS + 2;
    /// `INPUT_REVEAL_PHASE_Q1` 列（Gap 7 witness：reveal_phase²，拆 6 次 vanishing）。
    pub const INPUT_REVEAL_PHASE_Q1: usize = COMMON_NUM_COLUMNS + 3;
    /// `INPUT_REVEAL_PHASE_Q2` 列（Gap 7 witness：reveal_phase⁴ = q1²）。
    pub const INPUT_REVEAL_PHASE_Q2: usize = COMMON_NUM_COLUMNS + 4;
    /// Precompile selector column.
    pub const PRECOMPILE_ID: usize = COMMON_NUM_COLUMNS + 5;
    /// Canonical request ABI version column.
    pub const PRECOMPILE_ABI_VERSION: usize = COMMON_NUM_COLUMNS + 6;
    /// Full request digest columns.
    pub const REQUEST_DIGEST_BASE: usize = COMMON_NUM_COLUMNS + 7;
    /// Full verifier receipt digest columns.
    pub const RECEIPT_DIGEST_BASE: usize = REQUEST_DIGEST_BASE + super::DIGEST_LIMBS;
    /// Terminal-settlement activation flag.
    pub const SETTLEMENT_ACTIVE: usize = RECEIPT_DIGEST_BASE + super::DIGEST_LIMBS;
    /// Canonical settlement-plan digest columns.
    pub const SETTLEMENT_DIGEST_BASE: usize = SETTLEMENT_ACTIVE + 1;
    /// Number of active runouts.
    pub const SETTLEMENT_RUNOUT_COUNT: usize = SETTLEMENT_DIGEST_BASE + super::DIGEST_LIMBS;
    /// Gross-pot u64 limbs.
    pub const SETTLEMENT_GROSS_BASE: usize = SETTLEMENT_RUNOUT_COUNT + 1;
    /// Rake u64 limbs.
    pub const SETTLEMENT_RAKE_BASE: usize = SETTLEMENT_GROSS_BASE + 4;
    /// Total-awards u64 limbs.
    pub const SETTLEMENT_TOTAL_AWARDS_BASE: usize = SETTLEMENT_RAKE_BASE + 4;
    /// Nine fixed per-seat award projections.
    pub const SETTLEMENT_AWARDS_BASE: usize = SETTLEMENT_TOTAL_AWARDS_BASE + 4;
    /// Ripple carries for `total_awards + rake = gross_pot`.
    pub const SETTLEMENT_CONSERVATION_CARRY_BASE: usize =
        SETTLEMENT_AWARDS_BASE + super::SETTLEMENT_SEATS * 4;
    /// `submit_player_reveal_tokens` AIR 总列数。
    pub const NUM_COLUMNS: usize = SETTLEMENT_CONSERVATION_CARRY_BASE + 3;
}

/// `submit_player_reveal_tokens` 输入参数。
#[derive(Debug, Clone)]
pub struct SubmitPlayerRevealTokensInput {
    /// 提交令牌的座位索引。
    pub seat_index: u8,
    /// 调用准入时（pre-dispatch）的 reveal 阶段枚举值。
    ///
    /// 最后一个被分配的玩家提交 token 后，状态机会将 post-dispatch 阶段推进到
    /// `NONE`；这不改变本次调用在非 `NONE` 阶段获准执行的事实。
    pub reveal_phase: u8,
    /// External-command version increment. Every committed dispatch is exactly one;
    /// settlement composition is carried by the tagged settlement projection below.
    pub version_increment: u8,
    /// Verifier-issued batched reveal-token verification result.
    pub precompile: PrecompileAirBinding,
    /// Verifier-replayed normalized showdown settlement; zero for non-terminal reveals.
    pub settlement: SettlementPlanBinding,
}

/// `submit_player_reveal_tokens` AIR 公开输入。
#[derive(Debug, Clone)]
pub struct SubmitPlayerRevealTokensAir {
    /// log2(trace 行数)。
    pub log_size: u32,
    /// 输入参数。
    pub input: SubmitPlayerRevealTokensInput,
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

impl SubmitPlayerRevealTokensAir {
    /// 列数。
    #[must_use]
    pub const fn num_columns() -> usize {
        cols::NUM_COLUMNS
    }
}

impl FrameworkEval for SubmitPlayerRevealTokensAir {
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
        let input_reveal_phase = eval.next_trace_mask();
        let _output_revealed_count = eval.next_trace_mask();
        // Gap 7 witnesses：reveal_phase² 与 reveal_phase⁴
        let input_reveal_phase_q1 = eval.next_trace_mask();
        let input_reveal_phase_q2 = eval.next_trace_mask();
        let precompile_id = eval.next_trace_mask();
        let precompile_abi_version = eval.next_trace_mask();
        let request_digest: Vec<_> = (0..DIGEST_LIMBS).map(|_| eval.next_trace_mask()).collect();
        let receipt_digest: Vec<_> = (0..DIGEST_LIMBS).map(|_| eval.next_trace_mask()).collect();
        let settlement_active = eval.next_trace_mask();
        let settlement_digest: Vec<_> = (0..DIGEST_LIMBS).map(|_| eval.next_trace_mask()).collect();
        let settlement_runout_count = eval.next_trace_mask();
        let settlement_gross: [E::F; 4] = std::array::from_fn(|_| eval.next_trace_mask());
        let settlement_rake: [E::F; 4] = std::array::from_fn(|_| eval.next_trace_mask());
        let settlement_total_awards: [E::F; 4] = std::array::from_fn(|_| eval.next_trace_mask());
        let settlement_awards: [[E::F; 4]; SETTLEMENT_SEATS] =
            std::array::from_fn(|_| std::array::from_fn(|_| eval.next_trace_mask()));
        let settlement_conservation_carry: [E::F; 3] =
            std::array::from_fn(|_| eval.next_trace_mask());

        // 约束 1：seat_index == input.seat_index
        let expected_seat: E::F = M31::from(u32::from(self.input.seat_index)).into();
        eval.add_constraint(is_active.clone() * (input_seat_index - expected_seat));

        // 约束 2：reveal_phase == input.reveal_phase（clone 保留原值供约束 4 使用）
        let expected_phase: E::F = M31::from(u32::from(self.input.reveal_phase)).into();
        eval.add_constraint(is_active.clone() * (input_reveal_phase.clone() - expected_phase));

        // 约束 3（审计共性，degree-2）：round_state 不变（reveal 阶段 round_state 恒为 WAITING=0）。
        eval.add_constraint(common.round_state_unchanged());

        // 约束 4（Gap 7：RevealPhasePositive）：reveal_phase ∈ {1..6}（非 NONE=0）。
        // vanishing 多项式 (rp-1)(rp-2)(rp-3)(rp-4)(rp-5)(rp-6) = rp⁶-21rp⁵+175rp⁴-735rp³+1624rp²-1764rp+720。
        // 6 次多项式（单列自乘 6 次）degree 超过 Stwo 上界，故引入 witness q1=rp²、q2=rp⁴，
        // 展开为 degree ≤ 2 项：720 -1764·rp +1624·q1 -735·(rp·q1) +175·q2 -21·(rp·q2) +(q1·q2)。
        // 阻止恶意 prover 在 reveal_phase=0（无 reveal 进行）下构造 trace。
        let rp = input_reveal_phase.clone();
        let q1 = input_reveal_phase_q1.clone();
        let q2 = input_reveal_phase_q2.clone();
        // witness 一致性（degree-2 两列乘积）
        eval.add_constraint(is_active.clone() * (q1.clone() - rp.clone() * rp.clone()));
        eval.add_constraint(is_active.clone() * (q2.clone() - q1.clone() * q1.clone()));
        // 展开的 6 次 vanishing（每项 degree ≤ 2）
        let c720: E::F = M31::from(720u32).into();
        let c1764: E::F = M31::from(1764u32).into();
        let c1624: E::F = M31::from(1624u32).into();
        let c735: E::F = M31::from(735u32).into();
        let c175: E::F = M31::from(175u32).into();
        let c21: E::F = M31::from(21u32).into();
        let vp = c720 - c1764 * rp.clone() + c1624 * q1.clone() - c735 * (rp.clone() * q1.clone())
            + c175 * q2.clone()
            - c21 * (rp.clone() * q2.clone())
            + (q1 * q2);
        eval.add_constraint(is_active.clone() * vp);

        let expected_precompile_id: E::F =
            M31::from(u32::from(self.input.precompile.precompile_id)).into();
        let expected_abi_version: E::F =
            M31::from(u32::from(self.input.precompile.abi_version)).into();
        eval.add_constraint(is_active.clone() * (precompile_id - expected_precompile_id));
        eval.add_constraint(is_active.clone() * (precompile_abi_version - expected_abi_version));
        for i in 0..DIGEST_LIMBS {
            let expected_request: E::F = self.input.precompile.request_digest[i].into();
            let expected_receipt: E::F = self.input.precompile.receipt_digest[i].into();
            eval.add_constraint(is_active.clone() * (request_digest[i].clone() - expected_request));
            eval.add_constraint(is_active.clone() * (receipt_digest[i].clone() - expected_receipt));
        }

        let expected_settlement_active: E::F =
            M31::from(u32::from(self.input.settlement.active)).into();
        eval.add_constraint(
            is_active.clone() * (settlement_active.clone() - expected_settlement_active),
        );
        let expected_settlement_digest = digest_to_m31_limbs(self.input.settlement.plan_digest);
        for i in 0..DIGEST_LIMBS {
            let expected: E::F = expected_settlement_digest[i].into();
            eval.add_constraint(is_active.clone() * (settlement_digest[i].clone() - expected));
        }
        let expected_runouts: E::F =
            M31::from(u32::from(self.input.settlement.runout_count)).into();
        eval.add_constraint(
            is_active.clone() * (settlement_runout_count.clone() - expected_runouts),
        );
        let expected_u64s = [
            u64_to_m31_limbs(self.input.settlement.gross_pot),
            u64_to_m31_limbs(self.input.settlement.rake),
            u64_to_m31_limbs(self.input.settlement.total_awards),
        ];
        for (actual, expected) in [
            &settlement_gross,
            &settlement_rake,
            &settlement_total_awards,
        ]
        .into_iter()
        .zip(expected_u64s)
        {
            for limb in 0..4 {
                let expected: E::F = expected[limb].into();
                eval.add_constraint(is_active.clone() * (actual[limb].clone() - expected));
            }
        }
        for (seat, actual) in settlement_awards.iter().enumerate() {
            let expected = u64_to_m31_limbs(self.input.settlement.awards[seat]);
            for limb in 0..4 {
                let expected: E::F = expected[limb].into();
                eval.add_constraint(is_active.clone() * (actual[limb].clone() - expected));
            }
        }
        for constraint in common.limb4_delta(
            &settlement_total_awards,
            &settlement_gross,
            &settlement_rake,
            &settlement_conservation_carry,
        ) {
            eval.add_constraint(constraint);
        }
        let one: E::F = M31::from(1u32).into();
        eval.add_constraint(settlement_active.clone() * (settlement_active - one));

        eval
    }
}

/// `submit_player_reveal_tokens` AIR 的 trace 行。
#[derive(Debug, Clone)]
pub struct SubmitPlayerRevealTokensRow {
    /// 通用列。
    pub common: CommonRow,
    /// `INPUT_SEAT_INDEX`。
    pub input_seat_index: M31,
    /// `INPUT_REVEAL_PHASE`。
    pub input_reveal_phase: M31,
    /// `OUTPUT_REVEALED_COUNT`。
    pub output_revealed_count: M31,
    /// Gap 7 witness：reveal_phase²。
    pub input_reveal_phase_q1: M31,
    /// Gap 7 witness：reveal_phase⁴。
    pub input_reveal_phase_q2: M31,
    /// Precompile selector.
    pub precompile_id: M31,
    /// Canonical request ABI version.
    pub precompile_abi_version: M31,
    /// Full request digest.
    pub request_digest: [M31; DIGEST_LIMBS],
    /// Full verifier receipt digest.
    pub receipt_digest: [M31; DIGEST_LIMBS],
    /// Terminal-settlement activation flag.
    pub settlement_active: M31,
    /// Canonical settlement-plan digest.
    pub settlement_digest: [M31; DIGEST_LIMBS],
    /// Number of runouts.
    pub settlement_runout_count: M31,
    /// Gross pot.
    pub settlement_gross: [M31; 4],
    /// Rake.
    pub settlement_rake: [M31; 4],
    /// Total awards.
    pub settlement_total_awards: [M31; 4],
    /// Fixed per-seat awards.
    pub settlement_awards: [[M31; 4]; SETTLEMENT_SEATS],
    /// Conservation ripple carries.
    pub settlement_conservation_carry: [M31; 3],
}

impl SubmitPlayerRevealTokensRow {
    /// 构造 active 行。
    #[must_use]
    pub fn active(
        input: &SubmitPlayerRevealTokensInput,
        pre_state_root: [M31; 4],
        post_state_root: [M31; 4],
        table_id: u64,
        hand_id: u32,
        call_seq: u32,
        pre_version: u64,
        post_version: u64,
        post_revealed_count: u8,
    ) -> Self {
        let rp_m31 = u8_to_m31(input.reveal_phase);
        let q1 = rp_m31 * rp_m31;
        let q2 = q1 * q1;
        Self {
            common: CommonRow::active(
                MethodKind::SubmitPlayerRevealTokens,
                pre_state_root,
                post_state_root,
                table_id,
                hand_id,
                call_seq,
                pre_version,
                post_version,
                0, // pre round_state（reveal 期间可为 0/2..6；真实值由调用方传入，
                //    此处默认 0=ROUND_WAITING。相位守卫在 INPUT_REVEAL_PHASE）
                0, // post round_state（单次 submit 不改 round_state）
                0,
                0,
                0,
                0,
            ),
            input_seat_index: u8_to_m31(input.seat_index),
            input_reveal_phase: rp_m31,
            output_revealed_count: u8_to_m31(post_revealed_count),
            // Gap 7 witnesses：reveal_phase² 与 reveal_phase⁴（M31 域内）
            input_reveal_phase_q1: q1,
            input_reveal_phase_q2: q2,
            precompile_id: u8_to_m31(input.precompile.precompile_id),
            precompile_abi_version: u8_to_m31(input.precompile.abi_version),
            request_digest: input.precompile.request_digest,
            receipt_digest: input.precompile.receipt_digest,
            settlement_active: u8_to_m31(u8::from(input.settlement.active)),
            settlement_digest: digest_to_m31_limbs(input.settlement.plan_digest),
            settlement_runout_count: u8_to_m31(input.settlement.runout_count),
            settlement_gross: u64_to_m31_limbs(input.settlement.gross_pot),
            settlement_rake: u64_to_m31_limbs(input.settlement.rake),
            settlement_total_awards: u64_to_m31_limbs(input.settlement.total_awards),
            settlement_awards: input.settlement.awards.map(u64_to_m31_limbs),
            settlement_conservation_carry: if input
                .settlement
                .total_awards
                .checked_add(input.settlement.rake)
                == Some(input.settlement.gross_pot)
            {
                compute_add_carries(input.settlement.total_awards, input.settlement.rake)
            } else {
                [ZERO; 3]
            },
        }
    }

    /// 构造 padding 行。
    #[must_use]
    pub fn padding() -> Self {
        Self {
            common: CommonRow::padding(),
            input_seat_index: ZERO,
            input_reveal_phase: ZERO,
            output_revealed_count: ZERO,
            input_reveal_phase_q1: ZERO,
            input_reveal_phase_q2: ZERO,
            precompile_id: ZERO,
            precompile_abi_version: ZERO,
            request_digest: [ZERO; DIGEST_LIMBS],
            receipt_digest: [ZERO; DIGEST_LIMBS],
            settlement_active: ZERO,
            settlement_digest: [ZERO; DIGEST_LIMBS],
            settlement_runout_count: ZERO,
            settlement_gross: [ZERO; 4],
            settlement_rake: [ZERO; 4],
            settlement_total_awards: [ZERO; 4],
            settlement_awards: [[ZERO; 4]; SETTLEMENT_SEATS],
            settlement_conservation_carry: [ZERO; 3],
        }
    }

    /// 转为列向量。
    #[must_use]
    pub fn to_vec(&self) -> Vec<M31> {
        let mut v = self.common.to_vec();
        v.push(self.input_seat_index);
        v.push(self.input_reveal_phase);
        v.push(self.output_revealed_count);
        v.push(self.input_reveal_phase_q1);
        v.push(self.input_reveal_phase_q2);
        v.push(self.precompile_id);
        v.push(self.precompile_abi_version);
        v.extend_from_slice(&self.request_digest);
        v.extend_from_slice(&self.receipt_digest);
        v.push(self.settlement_active);
        v.extend_from_slice(&self.settlement_digest);
        v.push(self.settlement_runout_count);
        v.extend_from_slice(&self.settlement_gross);
        v.extend_from_slice(&self.settlement_rake);
        v.extend_from_slice(&self.settlement_total_awards);
        for award in &self.settlement_awards {
            v.extend_from_slice(award);
        }
        v.extend_from_slice(&self.settlement_conservation_carry);
        debug_assert_eq!(v.len(), cols::NUM_COLUMNS);
        v
    }
}
