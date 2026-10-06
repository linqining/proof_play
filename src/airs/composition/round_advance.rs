//! Betting-round and reveal-phase advancement AIR component.

use borsh::{BorshDeserialize, BorshSerialize};
use poker_l1::contracts::texas_poker::constants::{
    ROUND_FLOP, ROUND_PREFLOP, ROUND_RIVER, ROUND_SHOWDOWN, ROUND_TURN,
};
use poker_l1::contracts::texas_poker::types::NO_SEAT;
use stwo::core::fields::m31::M31;
use stwo_constraint_framework::EvalAtRow;

use super::{STAGE_HEADER_NUM_COLUMNS, StageHeaderRow, bind_u64, evaluate_stage_header};
use crate::airs::common::{u8_to_m31, u64_to_m31_limbs};

/// Canonical encoding for `Option<u8>::None` in a stage row.
pub const NO_CURRENT_TURN: u8 = NO_SEAT;

/// Number of columns in the round-advance component row.
pub const NUM_COLUMNS: usize = STAGE_HEADER_NUM_COLUMNS + 6 + 8;

/// Canonical projection of a betting-round completion.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct RoundAdvancePlan {
    /// Whether a `RoundAdvanced` transition occurred.
    pub active: bool,
    /// Betting round before advancement.
    pub pre_round_state: u8,
    /// Betting round after advancement.
    pub post_round_state: u8,
    /// Reveal phase before advancement.
    pub pre_reveal_phase: u8,
    /// Reveal phase after advancement.
    pub post_reveal_phase: u8,
    /// Current turn before advancement, using [`NO_CURRENT_TURN`] for `None`.
    pub pre_current_turn: u8,
    /// Current turn after advancement, using [`NO_CURRENT_TURN`] for `None`.
    pub post_current_turn: u8,
    /// Pot conserved from the collection output into the new round.
    pub post_pot: u64,
    /// Community-card count recorded by the native event.
    pub community_cards_count: u64,
}

impl RoundAdvancePlan {
    /// Canonical zero payload for a dispatch without round advancement.
    #[must_use]
    pub const fn inactive() -> Self {
        Self {
            active: false,
            pre_round_state: 0,
            post_round_state: 0,
            pre_reveal_phase: 0,
            post_reveal_phase: 0,
            pre_current_turn: 0,
            post_current_turn: 0,
            post_pot: 0,
            community_cards_count: 0,
        }
    }
}

/// Fixed-width witness row for [`RoundAdvancePlan`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoundAdvanceRow {
    header: StageHeaderRow,
    states: [M31; 6],
    post_pot: [M31; 4],
    community_cards_count: [M31; 4],
}

impl RoundAdvanceRow {
    /// Build the canonical row.
    #[must_use]
    pub fn new(plan: &RoundAdvancePlan, link: &super::StageLink) -> Self {
        Self {
            header: StageHeaderRow::new(link),
            states: [
                u8_to_m31(plan.pre_round_state),
                u8_to_m31(plan.post_round_state),
                u8_to_m31(plan.pre_reveal_phase),
                u8_to_m31(plan.post_reveal_phase),
                u8_to_m31(plan.pre_current_turn),
                u8_to_m31(plan.post_current_turn),
            ],
            post_pot: u64_to_m31_limbs(plan.post_pot),
            community_cards_count: u64_to_m31_limbs(plan.community_cards_count),
        }
    }

    /// Serialize the row in canonical trace-column order.
    #[must_use]
    pub fn to_vec(&self) -> Vec<M31> {
        let mut values = Vec::with_capacity(NUM_COLUMNS);
        self.header.append_to(&mut values);
        values.extend_from_slice(&self.states);
        values.extend_from_slice(&self.post_pot);
        values.extend_from_slice(&self.community_cards_count);
        debug_assert_eq!(values.len(), NUM_COLUMNS);
        values
    }
}

/// Read and constrain one round-advance component row.
pub fn evaluate<E: EvalAtRow>(eval: &mut E, plan: &RoundAdvancePlan, link: &super::StageLink) {
    evaluate_stage_header(eval, link);
    let states: [E::F; 6] = std::array::from_fn(|_| eval.next_trace_mask());
    let post_pot: [E::F; 4] = std::array::from_fn(|_| eval.next_trace_mask());
    let community_cards_count: [E::F; 4] = std::array::from_fn(|_| eval.next_trace_mask());
    let expected_states = [
        plan.pre_round_state,
        plan.post_round_state,
        plan.pre_reveal_phase,
        plan.post_reveal_phase,
        plan.pre_current_turn,
        plan.post_current_turn,
    ];
    for (actual, expected) in states.iter().zip(expected_states) {
        eval.add_constraint(actual.clone() - M31::from(u32::from(expected)).into());
    }
    bind_u64(eval, &post_pot, plan.post_pot);
    bind_u64(eval, &community_cards_count, plan.community_cards_count);

    let legal = !plan.active
        || matches!(
            (plan.pre_round_state, plan.post_round_state),
            (ROUND_PREFLOP, ROUND_FLOP)
                | (ROUND_FLOP, ROUND_TURN)
                | (ROUND_TURN, ROUND_RIVER)
                | (ROUND_RIVER, ROUND_SHOWDOWN)
        );
    let legal: E::F = M31::from(u32::from(legal)).into();
    let one: E::F = M31::from(1u32).into();
    eval.add_constraint(legal - one.clone());
    let turn_cleared = !plan.active || plan.post_current_turn == NO_CURRENT_TURN;
    let turn_cleared: E::F = M31::from(u32::from(turn_cleared)).into();
    eval.add_constraint(turn_cleared - one);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::airs::composition::plan::{StageKind, StageLink};

    #[test]
    fn row_uses_fixed_none_sentinel() {
        let plan = RoundAdvancePlan {
            active: true,
            pre_round_state: ROUND_PREFLOP,
            post_round_state: ROUND_FLOP,
            pre_reveal_phase: 0,
            post_reveal_phase: 2,
            pre_current_turn: 1,
            post_current_turn: NO_CURRENT_TURN,
            post_pot: 200,
            community_cards_count: 0,
        };
        let link = StageLink {
            active: true,
            stage_kind: StageKind::RoundAdvance,
            stage_index: 2,
            plan_digest: [1; 32],
            input_digest: [2; 32],
            output_digest: [3; 32],
        };
        assert_eq!(
            RoundAdvanceRow::new(&plan, &link).to_vec().len(),
            NUM_COLUMNS
        );
    }
}
