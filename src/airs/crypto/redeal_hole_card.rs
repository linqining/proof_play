//! `redeal_hole_card` AIR — 持有者换掉解密失败的底牌（死槽恢复）。
//!
//! 换牌本身不携带密码学证明（"牌坏了"只有持有者可解，链上不可验证也无需
//! 验证：换掉好牌只伤害持有者自己）；它是一个纯状态转换——deck 发牌游标
//! 前进、`(seat, slot)` 账本条目换绑新牌、下注轮挂起进 `HandPhase::Redealing`。
//! 后续换牌令牌的密码学验证由 [`super::submit_player_reveal_tokens`] 的窗口
//! 语义承担。因此本 AIR 采用轻量语句绑定布局：业务列全部绑定 verifier 从
//! canonical dispatch 重放重算的期望值。

use poker_l1::contracts::texas_poker::types::HandPhase;
use stwo::core::fields::m31::M31;
use stwo_constraint_framework::{EvalAtRow, FrameworkEval};

use crate::airs::common::{COMMON_NUM_COLUMNS, CommonConstraints, CommonRow, ZERO, u8_to_m31};
use crate::airs::validation::validate_canonical_dispatch;
use crate::error::{TexasAirError, TexasAirResult};
use crate::method_kind::MethodKind;
use crate::public_inputs::TexasPublicInputs;

/// `HandPhase::Betting` 的 union tag（pre 相位）。
const PHASE_TAG_BETTING: u32 = 4;
/// `HandPhase::Redealing` 的 union tag（post 相位）。
const PHASE_TAG_REDEALING: u32 = 6;

/// `redeal_hole_card` 业务列布局。
pub mod cols {
    use super::COMMON_NUM_COLUMNS;

    /// 持有者座位。
    pub const INPUT_SEAT_INDEX: usize = COMMON_NUM_COLUMNS;
    /// 被换的底牌槽位（0/1）。
    pub const INPUT_CARD_SLOT: usize = COMMON_NUM_COLUMNS + 1;
    /// 换入的新牌 deck 索引（pre 态 `cards_dealt` 游标位）。
    pub const NEW_CARD_INDEX: usize = COMMON_NUM_COLUMNS + 2;
    /// pre 相位 tag（Betting）。
    pub const PRE_PHASE_TAG: usize = COMMON_NUM_COLUMNS + 3;
    /// post 相位 tag（Redealing）。
    pub const POST_PHASE_TAG: usize = COMMON_NUM_COLUMNS + 4;
    /// 总列数。
    pub const NUM_COLUMNS: usize = COMMON_NUM_COLUMNS + 5;
}

/// `redeal_hole_card` 的公开业务输入。
#[derive(Debug, Clone)]
pub struct RedealHoleCardInput {
    /// 持有者座位。
    pub seat_index: u8,
    /// 被换的槽位。
    pub card_slot: u8,
    /// 换入的新牌 deck 索引。
    pub new_card_index: u8,
}

/// `redeal_hole_card` 的 AIR。
#[derive(Debug, Clone)]
pub struct RedealHoleCardAir {
    /// trace 的 log2 行数。
    pub log_size: u32,
    /// 公开业务输入。
    pub input: RedealHoleCardInput,
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

impl RedealHoleCardAir {
    /// 总列数。
    #[must_use]
    pub const fn num_columns() -> usize {
        cols::NUM_COLUMNS
    }
}

impl FrameworkEval for RedealHoleCardAir {
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
        let input_card_slot = eval.next_trace_mask();
        let new_card_index = eval.next_trace_mask();
        let pre_phase_tag = eval.next_trace_mask();
        let post_phase_tag = eval.next_trace_mask();

        let expected_seat: E::F = M31::from(u32::from(self.input.seat_index)).into();
        let expected_slot: E::F = M31::from(u32::from(self.input.card_slot)).into();
        let expected_new_index: E::F = M31::from(u32::from(self.input.new_card_index)).into();
        let expected_pre_tag: E::F = M31::from(PHASE_TAG_BETTING).into();
        let expected_post_tag: E::F = M31::from(PHASE_TAG_REDEALING).into();

        // 绑定全部业务列到 verifier 重放的期望值。
        eval.add_constraint(is_active.clone() * (input_seat_index - expected_seat));
        eval.add_constraint(is_active.clone() * (input_card_slot - expected_slot));
        eval.add_constraint(is_active.clone() * (new_card_index - expected_new_index));
        eval.add_constraint(is_active.clone() * (pre_phase_tag - expected_pre_tag));
        eval.add_constraint(is_active.clone() * (post_phase_tag - expected_post_tag));

        // 换牌不动钱、不换街（street 挂起前后一致）。
        eval.add_constraint(common.round_state_unchanged());
        for constraint in common.pot_unchanged_4limb() {
            eval.add_constraint(constraint);
        }

        eval
    }
}

/// Active/padding trace row for [`RedealHoleCardAir`].
#[derive(Debug, Clone)]
pub struct RedealHoleCardRow {
    /// Shared statement columns.
    pub common: CommonRow,
    /// 持有者座位。
    pub input_seat_index: M31,
    /// 被换的槽位。
    pub input_card_slot: M31,
    /// 换入的新牌 deck 索引。
    pub new_card_index: M31,
    /// pre 相位 tag。
    pub pre_phase_tag: M31,
    /// post 相位 tag。
    pub post_phase_tag: M31,
}

impl RedealHoleCardRow {
    /// Construct an active row from independently reconstructed table fields.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn active(
        input: &RedealHoleCardInput,
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
                MethodKind::RedealHoleCard,
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
            input_card_slot: u8_to_m31(input.card_slot),
            new_card_index: u8_to_m31(input.new_card_index),
            pre_phase_tag: M31::from(PHASE_TAG_BETTING),
            post_phase_tag: M31::from(PHASE_TAG_REDEALING),
        }
    }

    /// Construct a padding row.
    #[must_use]
    pub fn padding() -> Self {
        Self {
            common: CommonRow::padding(),
            input_seat_index: ZERO,
            input_card_slot: ZERO,
            new_card_index: ZERO,
            pre_phase_tag: ZERO,
            post_phase_tag: ZERO,
        }
    }

    /// Flatten the row in trace-column order.
    #[must_use]
    pub fn to_vec(&self) -> Vec<M31> {
        let mut values = self.common.to_vec();
        values.push(self.input_seat_index);
        values.push(self.input_card_slot);
        values.push(self.new_card_index);
        values.push(self.pre_phase_tag);
        values.push(self.post_phase_tag);
        debug_assert_eq!(values.len(), cols::NUM_COLUMNS);
        values
    }
}

/// Production verifier-side reconstruction for the redeal row.
///
/// # Errors
/// 重放的 dispatch 与 verifier 信任的语句不一致时返回 `SpecViolation`。
pub fn validate_public_inputs(
    air: &RedealHoleCardAir,
    public_inputs: &TexasPublicInputs,
) -> TexasAirResult<()> {
    const METHOD: &str = "redeal_hole_card";
    let dispatch = validate_canonical_dispatch(public_inputs, MethodKind::RedealHoleCard)?;
    let pre = &dispatch.pre;
    let post = &dispatch.post;

    // pre 必须是挂起前的高保真下注轮：Betting 相位。
    let HandPhase::Betting {
        street: pre_street, ..
    } = &pre.hand_phase
    else {
        return Err(TexasAirError::SpecViolation(
            "{METHOD}: pre-state must be an active betting round".into(),
        ));
    };
    let HandPhase::Redealing {
        street: post_street,
        state,
        ..
    } = &post.hand_phase
    else {
        return Err(TexasAirError::SpecViolation(
            "{METHOD}: post-state must be a redeal token window".into(),
        ));
    };
    if pre_street != post_street {
        return Err(TexasAirError::SpecViolation(
            "{METHOD}: redeal must not change the betting street".into(),
        ));
    }

    // 窗口必须恰好一个 assignment，指向 (seat, slot) 的新牌。
    if state.assignments.len() != 1 {
        return Err(TexasAirError::SpecViolation(
            "{METHOD}: redeal window must carry exactly one assignment".into(),
        ));
    }
    let assignment = &state.assignments[0];
    if assignment.encrypted_card_index != air.input.new_card_index {
        return Err(TexasAirError::SpecViolation(
            "{METHOD}: assignment card index does not match the redeal input".into(),
        ));
    }
    if u64::from(assignment.encrypted_card_index) != u64::from(pre.deck_state.cards_dealt) {
        return Err(TexasAirError::SpecViolation(
            "{METHOD}: redeal must consume the current deck cursor".into(),
        ));
    }

    // 账本换绑：新 (seat, slot) 指向新牌；pre 的游标位旧条目已消失。
    let new_partial = post
        .deck_state
        .owner_readable_hole_cards
        .get(air.input.seat_index, air.input.card_slot)
        .ok_or_else(|| {
            TexasAirError::SpecViolation(
                "{METHOD}: post-state ledger missing the redealt slot".into(),
            )
        })?;
    if new_partial.encrypted_card_index != air.input.new_card_index {
        return Err(TexasAirError::SpecViolation(
            "{METHOD}: ledger entry does not point at the replacement card".into(),
        ));
    }
    if pre
        .deck_state
        .owner_readable_hole_cards
        .get(air.input.seat_index, air.input.card_slot)
        .is_some_and(|old| old.encrypted_card_index == air.input.new_card_index)
    {
        return Err(TexasAirError::SpecViolation(
            "{METHOD}: pre-state already references the replacement card".into(),
        ));
    }

    // 发牌游标恰好前进 1。
    if post.deck_state.cards_dealt
        != pre
            .deck_state
            .cards_dealt
            .checked_add(1)
            .ok_or_else(|| TexasAirError::SpecViolation("{METHOD}: cards_dealt overflow".into()))?
    {
        return Err(TexasAirError::SpecViolation(
            "{METHOD}: deck cursor must advance by exactly one".into(),
        ));
    }

    // 抽屉里的完整账本不允许出现重复 deck 索引（insert 的不变量在重放中已保证）。
    let mut seen = std::collections::BTreeSet::new();
    for (_, _, card) in post.deck_state.owner_readable_hole_cards.iter() {
        if !seen.insert(card.encrypted_card_index) {
            return Err(TexasAirError::SpecViolation(
                "{METHOD}: duplicate deck index in post ledger".into(),
            ));
        }
    }

    // pot 不变（换牌不动资金）。
    if pre.pot != post.pot {
        return Err(TexasAirError::SpecViolation(
            "{METHOD}: pot must be unchanged by a redeal".into(),
        ));
    }

    Ok(())
}
