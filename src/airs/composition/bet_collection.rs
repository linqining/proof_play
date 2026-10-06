//! Fixed nine-seat bet collection AIR component.

use borsh::{BorshDeserialize, BorshSerialize};
use stwo::core::fields::m31::M31;
use stwo_constraint_framework::EvalAtRow;

use super::seat_update::COMPOSITION_SEATS;
use super::{
    STAGE_HEADER_NUM_COLUMNS, StageHeaderRow, bind_u64, evaluate_stage_header, evaluate_u64_add,
};
use crate::airs::common::{ZERO, compute_add_carries, u64_to_m31_limbs};

/// Number of columns in the collection component row.
pub const NUM_COLUMNS: usize = STAGE_HEADER_NUM_COLUMNS
    + 4
    + COMPOSITION_SEATS * 4
    + 4
    + 4
    + COMPOSITION_SEATS * 4
    + COMPOSITION_SEATS * 3
    + 3;

/// Canonical fixed-seat wager collection projection.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct BetCollectionPlan {
    /// Whether native execution performed the collection phase.
    pub active: bool,
    /// Pot before collecting current-round bets.
    pub pre_pot: u64,
    /// Per-seat bets after the acting-seat update and before collection.
    pub seat_bets: [u64; COMPOSITION_SEATS],
    /// Sum of all fixed-seat bets.
    pub collected_bets: u64,
    /// Pot immediately after collection.
    pub post_pot: u64,
}

impl BetCollectionPlan {
    /// Canonical zero payload when collection is not executed.
    #[must_use]
    pub const fn inactive() -> Self {
        Self {
            active: false,
            pre_pot: 0,
            seat_bets: [0; COMPOSITION_SEATS],
            collected_bets: 0,
            post_pot: 0,
        }
    }
}

/// Fixed-width witness row for [`BetCollectionPlan`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BetCollectionRow {
    header: StageHeaderRow,
    pre_pot: [M31; 4],
    seat_bets: [[M31; 4]; COMPOSITION_SEATS],
    collected_bets: [M31; 4],
    post_pot: [M31; 4],
    accumulators: [[M31; 4]; COMPOSITION_SEATS],
    sum_carries: [[M31; 3]; COMPOSITION_SEATS],
    pot_carry: [M31; 3],
}

impl BetCollectionRow {
    /// Build the canonical running-sum witness.
    #[must_use]
    pub fn new(plan: &BetCollectionPlan, link: &super::StageLink) -> Self {
        let mut running = 0u64;
        let mut accumulators = [[ZERO; 4]; COMPOSITION_SEATS];
        let mut sum_carries = [[ZERO; 3]; COMPOSITION_SEATS];
        for index in 0..COMPOSITION_SEATS {
            let next = running.checked_add(plan.seat_bets[index]);
            if let Some(next) = next {
                sum_carries[index] = compute_add_carries(running, plan.seat_bets[index]);
                running = next;
                accumulators[index] = u64_to_m31_limbs(running);
            }
        }
        let pot_carry = if plan.pre_pot.checked_add(plan.collected_bets) == Some(plan.post_pot) {
            compute_add_carries(plan.pre_pot, plan.collected_bets)
        } else {
            [ZERO; 3]
        };
        Self {
            header: StageHeaderRow::new(link),
            pre_pot: u64_to_m31_limbs(plan.pre_pot),
            seat_bets: plan.seat_bets.map(u64_to_m31_limbs),
            collected_bets: u64_to_m31_limbs(plan.collected_bets),
            post_pot: u64_to_m31_limbs(plan.post_pot),
            accumulators,
            sum_carries,
            pot_carry,
        }
    }

    /// Serialize the row in canonical trace-column order.
    #[must_use]
    pub fn to_vec(&self) -> Vec<M31> {
        let mut values = Vec::with_capacity(NUM_COLUMNS);
        self.header.append_to(&mut values);
        values.extend_from_slice(&self.pre_pot);
        for bet in &self.seat_bets {
            values.extend_from_slice(bet);
        }
        values.extend_from_slice(&self.collected_bets);
        values.extend_from_slice(&self.post_pot);
        for accumulator in &self.accumulators {
            values.extend_from_slice(accumulator);
        }
        for carry in &self.sum_carries {
            values.extend_from_slice(carry);
        }
        values.extend_from_slice(&self.pot_carry);
        debug_assert_eq!(values.len(), NUM_COLUMNS);
        values
    }
}

/// Read and constrain one bet-collection component row.
pub fn evaluate<E: EvalAtRow>(eval: &mut E, plan: &BetCollectionPlan, link: &super::StageLink) {
    evaluate_stage_header(eval, link);
    let pre_pot: [E::F; 4] = std::array::from_fn(|_| eval.next_trace_mask());
    let seat_bets: [[E::F; 4]; COMPOSITION_SEATS] =
        std::array::from_fn(|_| std::array::from_fn(|_| eval.next_trace_mask()));
    let collected_bets: [E::F; 4] = std::array::from_fn(|_| eval.next_trace_mask());
    let post_pot: [E::F; 4] = std::array::from_fn(|_| eval.next_trace_mask());
    let accumulators: [[E::F; 4]; COMPOSITION_SEATS] =
        std::array::from_fn(|_| std::array::from_fn(|_| eval.next_trace_mask()));
    let sum_carries: [[E::F; 3]; COMPOSITION_SEATS] =
        std::array::from_fn(|_| std::array::from_fn(|_| eval.next_trace_mask()));
    let pot_carry: [E::F; 3] = std::array::from_fn(|_| eval.next_trace_mask());

    bind_u64(eval, &pre_pot, plan.pre_pot);
    bind_u64(eval, &collected_bets, plan.collected_bets);
    bind_u64(eval, &post_pot, plan.post_pot);
    for (actual, expected) in seat_bets.iter().zip(plan.seat_bets) {
        bind_u64(eval, actual, expected);
    }

    let zero: [E::F; 4] = std::array::from_fn(|_| M31::from(0u32).into());
    for index in 0..COMPOSITION_SEATS {
        let previous = if index == 0 {
            &zero
        } else {
            &accumulators[index - 1]
        };
        evaluate_u64_add(
            eval,
            previous,
            &seat_bets[index],
            &accumulators[index],
            &sum_carries[index],
        );
    }
    for limb in 0..4 {
        eval.add_constraint(
            accumulators[COMPOSITION_SEATS - 1][limb].clone() - collected_bets[limb].clone(),
        );
    }
    evaluate_u64_add(eval, &pre_pot, &collected_bets, &post_pot, &pot_carry);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::airs::composition::plan::{StageKind, StageLink};

    #[test]
    fn running_sum_projects_all_nine_seats() {
        let plan = BetCollectionPlan {
            active: true,
            pre_pot: 100,
            seat_bets: [1, 2, 3, 4, 5, 6, 7, 8, 9],
            collected_bets: 45,
            post_pot: 145,
        };
        let link = StageLink {
            active: true,
            stage_kind: StageKind::BetCollection,
            stage_index: 1,
            plan_digest: [1; 32],
            input_digest: [2; 32],
            output_digest: [3; 32],
        };
        assert_eq!(
            BetCollectionRow::new(&plan, &link).to_vec().len(),
            NUM_COLUMNS
        );
    }
}
