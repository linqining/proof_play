//! Shared AIR columns for collecting bets and completing a betting round.
//!
//! The native VM first applies the acting seat update, then collects every
//! live seat bet into the pot and advances to the next reveal phase. This
//! component proves the pot arithmetic shared by check, call, raise, and bet.
//! Complete table semantics remain bound by the
//! production verifier's canonical VM replay.

use poker_l1::contracts::texas_poker::constants::{
    ROUND_FLOP, ROUND_PREFLOP, ROUND_RIVER, ROUND_SHOWDOWN, ROUND_TURN,
};
use poker_l1::contracts::texas_poker::types::{NO_SEAT, TexasPokerTable};
use stwo::core::fields::m31::M31;
use stwo_constraint_framework::EvalAtRow;

use crate::airs::common::{CommonConstraints, ZERO, compute_add_carries, u64_to_m31_limbs};
use crate::error::{TexasAirError, TexasAirResult};

/// Trace sentinel for current_turn None after a completed betting round.
pub const NO_CURRENT_TURN: u8 = NO_SEAT;

/// Number of shared round-completion columns.
pub const NUM_COLUMNS: usize = 7;

/// Verifier-reconstructed inputs for bet collection and round advancement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndBettingRoundInput {
    /// Sum of all live bets after applying the acting seat's action delta.
    pub collected_bets: u64,
    /// Betting state entered while the corresponding reveal phase starts.
    pub post_round_state: u8,
}

/// Canonical branch selected by native VM replay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BettingOutcome {
    /// The current betting round remains active.
    MidRound {
        /// Next active seat.
        post_current_turn: u8,
    },
    /// The action collects bets and starts the next reveal phase.
    EndBettingRound(EndBettingRoundInput),
}

impl BettingOutcome {
    /// Trace encoding of the post-dispatch turn.
    #[must_use]
    pub const fn post_current_turn(&self) -> u8 {
        match self {
            Self::MidRound { post_current_turn } => *post_current_turn,
            Self::EndBettingRound(_) => NO_CURRENT_TURN,
        }
    }
}

/// Derive the supported betting branch from canonical replayed tables.
pub(crate) fn derive_betting_outcome(
    pre: &TexasPokerTable,
    post: &TexasPokerTable,
    action_bet_delta: u64,
    method: &str,
) -> TexasAirResult<BettingOutcome> {
    if pre.betting_round().is_none() {
        return Err(TexasAirError::SpecViolation(format!(
            "{method}: pre-state is not a betting round"
        )));
    }

    if post.betting_round().is_some()
        && post.round_state() == pre.round_state()
        && post.pot == pre.pot
        && post.current_turn() != NO_CURRENT_TURN
    {
        let post_current_turn = post.current_turn();
        return Ok(BettingOutcome::MidRound { post_current_turn });
    }

    if post.betting_round().is_some() || post.current_turn() != NO_CURRENT_TURN {
        return Err(TexasAirError::UnsupportedBettingTransition(format!(
            "{method}: transition is neither mid-round nor bet collection plus round advancement"
        )));
    }

    let expected_post_round = match pre.round_state() {
        ROUND_PREFLOP => ROUND_FLOP,
        ROUND_FLOP => ROUND_TURN,
        ROUND_TURN => ROUND_RIVER,
        ROUND_RIVER => ROUND_SHOWDOWN,
        _ => {
            return Err(TexasAirError::UnsupportedBettingTransition(format!(
                "{method}: unsupported pre-round {} for round completion",
                pre.round_state()
            )));
        }
    };
    if post.round_state() != expected_post_round {
        return Err(TexasAirError::UnsupportedBettingTransition(format!(
            "{method}: round completion expected post round {expected_post_round}, got {}",
            post.round_state()
        )));
    }

    let pre_live_bets = pre.seats.iter().try_fold(0u64, |total, seat| {
        total
            .checked_add(seat.bet())
            .ok_or_else(|| TexasAirError::SpecViolation(format!("{method}: live bet sum overflow")))
    })?;
    let collected_bets = pre_live_bets.checked_add(action_bet_delta).ok_or_else(|| {
        TexasAirError::SpecViolation(format!("{method}: action-adjusted bet sum overflow"))
    })?;
    let expected_post_pot = pre.pot.checked_add(collected_bets).ok_or_else(|| {
        TexasAirError::SpecViolation(format!("{method}: completed-round pot overflow"))
    })?;
    if post.pot != expected_post_pot {
        return Err(TexasAirError::SpecViolation(format!(
            "{method}: completed-round pot {}, expected {expected_post_pot}",
            post.pot
        )));
    }
    if post.seats.iter().any(|seat| seat.bet() != 0) {
        return Err(TexasAirError::SpecViolation(format!(
            "{method}: completed round did not clear every live bet"
        )));
    }

    Ok(BettingOutcome::EndBettingRound(EndBettingRoundInput {
        collected_bets,
        post_round_state: expected_post_round,
    }))
}

/// Trace projection of EndBettingRoundInput.
#[derive(Debug, Clone)]
pub struct EndBettingRoundRow {
    collected_bets: [M31; 4],
    pot_collect_carry: [M31; 3],
}

impl EndBettingRoundRow {
    /// Construct active completion columns.
    #[must_use]
    pub fn active(input: &EndBettingRoundInput, pre_pot: u64, post_pot: u64) -> Self {
        let pot_collect_carry = if pre_pot.checked_add(input.collected_bets) == Some(post_pot) {
            compute_add_carries(pre_pot, input.collected_bets)
        } else {
            // Malformed low-level AIR inputs must fail constraints, not panic
            // while their witness row is assembled.
            [ZERO; 3]
        };
        Self {
            collected_bets: u64_to_m31_limbs(input.collected_bets),
            pot_collect_carry,
        }
    }

    /// Zero columns for a mid-round branch or padding row.
    #[must_use]
    pub const fn zero() -> Self {
        Self {
            collected_bets: [ZERO; 4],
            pot_collect_carry: [ZERO; 3],
        }
    }

    /// Append columns in their canonical order.
    pub fn append_to(&self, values: &mut Vec<M31>) {
        values.extend_from_slice(&self.collected_bets);
        values.extend_from_slice(&self.pot_collect_carry);
    }
}

/// Read and constrain all shared round-completion columns.
pub fn evaluate<E: EvalAtRow>(
    eval: &mut E,
    common: &CommonConstraints<E>,
    input: Option<&EndBettingRoundInput>,
) {
    let collected_bets: [E::F; 4] = std::array::from_fn(|_| eval.next_trace_mask());
    let pot_collect_carry: [E::F; 3] = std::array::from_fn(|_| eval.next_trace_mask());

    eval.add_constraint(common.button_unchanged());

    let Some(input) = input else {
        for value in collected_bets.into_iter().chain(pot_collect_carry) {
            eval.add_constraint(value);
        }
        return;
    };

    let expected_collected = u64_to_m31_limbs(input.collected_bets);
    for (actual, expected) in collected_bets.iter().zip(expected_collected) {
        eval.add_constraint(actual.clone() - expected.into());
    }
    for constraint in common.limb4_delta(
        &common.pre_pot,
        &common.post_pot,
        &collected_bets,
        &pot_collect_carry,
    ) {
        eval.add_constraint(constraint);
    }
    eval.add_constraint(
        common.post_round_state.clone() - M31::from(u32::from(input.post_round_state)).into(),
    );
}
