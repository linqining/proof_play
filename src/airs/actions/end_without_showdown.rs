//! Shared AIR columns for a last-player-standing fold settlement.
//!
//! This component covers the canonical `end_without_showdown` branch followed
//! by `reset_for_next_hand`. It proves the three monetary equalities that are
//! specific to this branch while the production verifier independently replays
//! the complete reset and binds its full pre/post state images.

use poker_l1::contracts::texas_poker::constants::ROUND_WAITING;
use poker_l1::contracts::texas_poker::types::{NO_SEAT, TexasPokerTable};
use stwo::core::fields::m31::M31;
use stwo_constraint_framework::EvalAtRow;

use crate::airs::common::{
    CommonConstraints, ZERO, compute_add_carries, u8_to_m31, u64_to_m31_limbs,
};
use crate::airs::composition::settlement::{SettlementKind, SettlementStagePlan};
use crate::error::{TexasAirError, TexasAirResult};

/// Sentinel trace value for `current_turn: None`.
pub const NO_CURRENT_TURN: u8 = NO_SEAT;

/// Number of shared terminal-settlement columns.
pub const NUM_COLUMNS: usize = 34;

/// Verifier-reconstructed settlement statement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndWithoutShowdownInput {
    /// The only non-folded player before reset.
    pub winner_seat: u8,
    /// Sum of live `seat.bet()` values collected by the terminal fold.
    pub collected_bets: u64,
    /// Pot after live bets are collected and before rake.
    pub gross_pot: u64,
    /// Rake deducted from the gross pot.
    pub rake: u64,
    /// Net amount credited to the winner.
    pub award: u64,
    /// Winner stack before settlement.
    pub pre_winner_stack: u64,
    /// Winner stack after settlement/reset.
    pub post_winner_stack: u64,
}

/// Canonical fold branch selected by native VM replay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FoldOutcome {
    /// The hand continues with another acting seat.
    MidRound {
        /// Next active seat.
        post_current_turn: u8,
    },
    /// The fold leaves one player and atomically settles/resets the hand.
    EndWithoutShowdown(EndWithoutShowdownInput),
}

impl FoldOutcome {
    /// Trace encoding of the post-dispatch turn.
    #[must_use]
    pub const fn post_current_turn(&self) -> u8 {
        match self {
            Self::MidRound { post_current_turn } => *post_current_turn,
            Self::EndWithoutShowdown(_) => NO_CURRENT_TURN,
        }
    }

    /// Whether reset has cleared the transient folded flag.
    #[must_use]
    pub const fn output_folded(&self) -> bool {
        matches!(self, Self::MidRound { .. })
    }
}

/// Derive the only supported fold branch from canonical replayed tables.
pub(crate) fn derive_fold_outcome(
    pre: &TexasPokerTable,
    post: &TexasPokerTable,
    acting_seat: u8,
    method: &str,
    settlement: Option<&SettlementStagePlan>,
) -> TexasAirResult<FoldOutcome> {
    if pre.betting_round().is_none() {
        return Err(TexasAirError::SpecViolation(format!(
            "{method}: pre-state is not a betting round"
        )));
    }
    if u64::from(post.call_seq) != u64::from(pre.call_seq).saturating_add(1) {
        return Err(TexasAirError::SpecViolation(format!(
            "{method}: transition must perform exactly one version bump"
        )));
    }

    if post.betting_round().is_some()
        && post.round_state() == pre.round_state()
        && post.pot == pre.pot
        && post.current_turn() != NO_CURRENT_TURN
    {
        let post_current_turn = post.current_turn();
        return Ok(FoldOutcome::MidRound { post_current_turn });
    }

    if post.round_state() != ROUND_WAITING
        || post.betting_round().is_some()
        || post.current_turn() != NO_CURRENT_TURN
        || post.pot != 0
    {
        return Err(TexasAirError::UnsupportedBettingTransition(format!(
            "{method}: transition is neither mid-round nor end_without_showdown + reset"
        )));
    }

    let active: Vec<usize> = pre
        .seats
        .iter()
        .enumerate()
        .filter(|(_, seat)| seat.is_occupied() && !seat.is_folded() && !seat.is_waiting())
        .map(|(index, _)| index)
        .collect();
    if active.len() != 2 || !active.contains(&usize::from(acting_seat)) {
        return Err(TexasAirError::SpecViolation(format!(
            "{method}: terminal fold must start with exactly two active players"
        )));
    }
    let winner_index = *active
        .iter()
        .find(|&&index| index != usize::from(acting_seat))
        .expect("two active players include the acting seat");
    let winner_seat = u8::try_from(winner_index)
        .map_err(|_| TexasAirError::SpecViolation(format!("{method}: winner seat exceeds u8")))?;
    let pre_winner = &pre.seats[winner_index];

    let collected_bets = pre.seats.iter().try_fold(0u64, |total, seat| {
        total
            .checked_add(seat.bet())
            .ok_or_else(|| TexasAirError::SpecViolation(format!("{method}: live bet sum overflow")))
    })?;
    let gross_pot = pre
        .pot
        .checked_add(collected_bets)
        .ok_or_else(|| TexasAirError::SpecViolation(format!("{method}: gross pot overflow")))?;
    let award = if let Some(settlement) = settlement {
        if settlement.kind != SettlementKind::WithoutShowdown
            || settlement.awards[winner_index] == 0
            || settlement
                .awards
                .iter()
                .enumerate()
                .any(|(index, award)| index != winner_index && *award != 0)
        {
            return Err(TexasAirError::SpecViolation(format!(
                "{method}: composite settlement does not identify the canonical sole winner"
            )));
        }
        settlement.awards[winner_index]
    } else {
        let post_winner = post.seats.get(winner_index).ok_or_else(|| {
            TexasAirError::SpecViolation(format!("{method}: post winner seat is missing"))
        })?;
        if !post_winner.is_occupied() || post_winner.player() != pre_winner.player() {
            return Err(TexasAirError::UnsupportedBettingTransition(format!(
                "{method}: terminal reset removed or replaced the winner seat"
            )));
        }
        post_winner
            .stack()
            .checked_sub(pre_winner.stack())
            .ok_or_else(|| {
                TexasAirError::SpecViolation(format!("{method}: winner stack decreased"))
            })?
    };
    let rake = gross_pot.checked_sub(award).ok_or_else(|| {
        TexasAirError::SpecViolation(format!("{method}: winner award exceeds gross pot"))
    })?;
    let winner_after_award = pre_winner
        .stack()
        .checked_add(award)
        .ok_or_else(|| TexasAirError::SpecViolation(format!("{method}: winner stack overflow")))?;

    Ok(FoldOutcome::EndWithoutShowdown(EndWithoutShowdownInput {
        winner_seat,
        collected_bets,
        gross_pot,
        rake,
        award,
        pre_winner_stack: pre_winner.stack(),
        post_winner_stack: winner_after_award,
    }))
}

/// Trace projection of [`EndWithoutShowdownInput`].
#[derive(Debug, Clone)]
pub struct EndWithoutShowdownRow {
    winner_seat: M31,
    collected_bets: [M31; 4],
    gross_pot: [M31; 4],
    rake: [M31; 4],
    award: [M31; 4],
    pre_winner_stack: [M31; 4],
    post_winner_stack: [M31; 4],
    pot_collect_carry: [M31; 3],
    rake_split_carry: [M31; 3],
    winner_stack_carry: [M31; 3],
}

impl EndWithoutShowdownRow {
    /// Construct the terminal settlement columns.
    #[must_use]
    pub fn active(input: &EndWithoutShowdownInput) -> Self {
        let pot_collect_carry = input
            .gross_pot
            .checked_sub(input.collected_bets)
            .map_or([ZERO; 3], |pre_pot| {
                checked_add_carries(pre_pot, input.collected_bets, input.gross_pot)
            });
        Self {
            winner_seat: u8_to_m31(input.winner_seat),
            collected_bets: u64_to_m31_limbs(input.collected_bets),
            gross_pot: u64_to_m31_limbs(input.gross_pot),
            rake: u64_to_m31_limbs(input.rake),
            award: u64_to_m31_limbs(input.award),
            pre_winner_stack: u64_to_m31_limbs(input.pre_winner_stack),
            post_winner_stack: u64_to_m31_limbs(input.post_winner_stack),
            pot_collect_carry,
            rake_split_carry: checked_add_carries(input.award, input.rake, input.gross_pot),
            winner_stack_carry: checked_add_carries(
                input.pre_winner_stack,
                input.award,
                input.post_winner_stack,
            ),
        }
    }

    /// Zero columns for a non-terminal branch or padding row.
    #[must_use]
    pub const fn zero() -> Self {
        Self {
            winner_seat: ZERO,
            collected_bets: [ZERO; 4],
            gross_pot: [ZERO; 4],
            rake: [ZERO; 4],
            award: [ZERO; 4],
            pre_winner_stack: [ZERO; 4],
            post_winner_stack: [ZERO; 4],
            pot_collect_carry: [ZERO; 3],
            rake_split_carry: [ZERO; 3],
            winner_stack_carry: [ZERO; 3],
        }
    }

    /// Append columns in their canonical order.
    pub fn append_to(&self, values: &mut Vec<M31>) {
        values.push(self.winner_seat);
        values.extend_from_slice(&self.collected_bets);
        values.extend_from_slice(&self.gross_pot);
        values.extend_from_slice(&self.rake);
        values.extend_from_slice(&self.award);
        values.extend_from_slice(&self.pre_winner_stack);
        values.extend_from_slice(&self.post_winner_stack);
        values.extend_from_slice(&self.pot_collect_carry);
        values.extend_from_slice(&self.rake_split_carry);
        values.extend_from_slice(&self.winner_stack_carry);
    }
}

fn checked_add_carries(lhs: u64, rhs: u64, expected: u64) -> [M31; 3] {
    if lhs.checked_add(rhs) == Some(expected) {
        compute_add_carries(lhs, rhs)
    } else {
        // Malformed externally constructed AIR inputs must fail constraints,
        // not panic while their witness row is being assembled.
        [ZERO; 3]
    }
}

/// Read and constrain all shared terminal columns.
pub fn evaluate<E: EvalAtRow>(
    eval: &mut E,
    common: &CommonConstraints<E>,
    input: Option<&EndWithoutShowdownInput>,
) {
    let winner_seat = eval.next_trace_mask();
    let collected_bets: [E::F; 4] = std::array::from_fn(|_| eval.next_trace_mask());
    let gross_pot: [E::F; 4] = std::array::from_fn(|_| eval.next_trace_mask());
    let rake: [E::F; 4] = std::array::from_fn(|_| eval.next_trace_mask());
    let award: [E::F; 4] = std::array::from_fn(|_| eval.next_trace_mask());
    let pre_winner_stack: [E::F; 4] = std::array::from_fn(|_| eval.next_trace_mask());
    let post_winner_stack: [E::F; 4] = std::array::from_fn(|_| eval.next_trace_mask());
    let pot_collect_carry: [E::F; 3] = std::array::from_fn(|_| eval.next_trace_mask());
    let rake_split_carry: [E::F; 3] = std::array::from_fn(|_| eval.next_trace_mask());
    let winner_stack_carry: [E::F; 3] = std::array::from_fn(|_| eval.next_trace_mask());

    let Some(input) = input else {
        eval.add_constraint(winner_seat);
        for value in collected_bets
            .into_iter()
            .chain(gross_pot)
            .chain(rake)
            .chain(award)
            .chain(pre_winner_stack)
            .chain(post_winner_stack)
            .chain(pot_collect_carry)
            .chain(rake_split_carry)
            .chain(winner_stack_carry)
        {
            eval.add_constraint(value);
        }
        return;
    };

    eval.add_constraint(winner_seat - M31::from(u32::from(input.winner_seat)).into());
    let expected = [
        u64_to_m31_limbs(input.collected_bets),
        u64_to_m31_limbs(input.gross_pot),
        u64_to_m31_limbs(input.rake),
        u64_to_m31_limbs(input.award),
        u64_to_m31_limbs(input.pre_winner_stack),
        u64_to_m31_limbs(input.post_winner_stack),
    ];
    let actual = [
        &collected_bets,
        &gross_pot,
        &rake,
        &award,
        &pre_winner_stack,
        &post_winner_stack,
    ];
    for (actual, expected) in actual.into_iter().zip(expected) {
        for limb in 0..4 {
            eval.add_constraint(actual[limb].clone() - expected[limb].into());
        }
    }

    for constraint in common.limb4_delta(
        &common.pre_pot,
        &gross_pot,
        &collected_bets,
        &pot_collect_carry,
    ) {
        eval.add_constraint(constraint);
    }
    for constraint in common.limb4_delta(&award, &gross_pot, &rake, &rake_split_carry) {
        eval.add_constraint(constraint);
    }
    for constraint in common.limb4_delta(
        &pre_winner_stack,
        &post_winner_stack,
        &award,
        &winner_stack_carry,
    ) {
        eval.add_constraint(constraint);
    }
    for limb in &common.post_pot {
        eval.add_constraint(limb.clone());
    }
    eval.add_constraint(
        common.post_round_state.clone() - M31::from(u32::from(ROUND_WAITING)).into(),
    );
    eval.add_constraint(common.button_unchanged());
}
