//! Acting-seat mutation AIR component.

use borsh::{BorshDeserialize, BorshSerialize};
use stwo::core::fields::m31::M31;
use stwo_constraint_framework::EvalAtRow;

use super::{
    STAGE_HEADER_NUM_COLUMNS, StageHeaderRow, bind_bool, bind_u64, evaluate_stage_header,
    evaluate_u64_add,
};
use crate::airs::common::{ZERO, compute_add_carries, u64_to_m31_limbs};

/// Fixed seat width shared by all composition components.
pub const COMPOSITION_SEATS: usize = 9;

/// Number of columns in the seat-update component row.
pub const NUM_COLUMNS: usize = STAGE_HEADER_NUM_COLUMNS + 1 + 9 * 4 + 4 + 18 + 3 * 3;

/// Canonical acting-seat delta and per-round acted-flag projection.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct SeatUpdatePlan {
    /// Whether this dispatch contains a betting-seat action.
    pub active: bool,
    /// Acting seat index.
    pub seat_index: u8,
    /// Stack before the action.
    pub pre_stack: u64,
    /// Stack immediately after the action, before later stages.
    pub post_stack: u64,
    /// Stack amount consumed by the action.
    pub stack_debit: u64,
    /// Round bet before the action.
    pub pre_bet: u64,
    /// Round bet immediately after the action.
    pub post_bet: u64,
    /// Amount credited to the round bet.
    pub bet_credit: u64,
    /// Hand-total wager before the action.
    pub pre_total_bet: u64,
    /// Hand-total wager immediately after the action.
    pub post_total_bet: u64,
    /// Amount credited to the hand-total wager.
    pub total_bet_credit: u64,
    /// Fold flag before the action.
    pub pre_folded: bool,
    /// Fold flag immediately after the action.
    pub post_folded: bool,
    /// All-in flag before the action.
    pub pre_all_in: bool,
    /// All-in flag immediately after the action.
    pub post_all_in: bool,
    /// Fixed-seat acted flags before the action.
    pub acted_before: [bool; COMPOSITION_SEATS],
    /// Fixed-seat acted flags immediately after the action.
    pub acted_after: [bool; COMPOSITION_SEATS],
}

impl SeatUpdatePlan {
    /// Canonical zero payload for a dispatch without a seat-update stage.
    #[must_use]
    pub const fn inactive() -> Self {
        Self {
            active: false,
            seat_index: 0,
            pre_stack: 0,
            post_stack: 0,
            stack_debit: 0,
            pre_bet: 0,
            post_bet: 0,
            bet_credit: 0,
            pre_total_bet: 0,
            post_total_bet: 0,
            total_bet_credit: 0,
            pre_folded: false,
            post_folded: false,
            pre_all_in: false,
            post_all_in: false,
            acted_before: [false; COMPOSITION_SEATS],
            acted_after: [false; COMPOSITION_SEATS],
        }
    }
}

/// Fixed-width witness row for [`SeatUpdatePlan`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeatUpdateRow {
    header: StageHeaderRow,
    seat_index: M31,
    amounts: [[M31; 4]; 9],
    flags: [M31; 4],
    acted_before: [M31; COMPOSITION_SEATS],
    acted_after: [M31; COMPOSITION_SEATS],
    stack_carry: [M31; 3],
    bet_carry: [M31; 3],
    total_bet_carry: [M31; 3],
}

impl SeatUpdateRow {
    /// Build a row from a verifier-derived plan and its stage link.
    #[must_use]
    pub fn new(plan: &SeatUpdatePlan, link: &super::StageLink) -> Self {
        let stack_carry = if plan.post_stack.checked_add(plan.stack_debit) == Some(plan.pre_stack) {
            compute_add_carries(plan.post_stack, plan.stack_debit)
        } else {
            [ZERO; 3]
        };
        let bet_carry = if plan.pre_bet.checked_add(plan.bet_credit) == Some(plan.post_bet) {
            compute_add_carries(plan.pre_bet, plan.bet_credit)
        } else {
            [ZERO; 3]
        };
        let total_bet_carry =
            if plan.pre_total_bet.checked_add(plan.total_bet_credit) == Some(plan.post_total_bet) {
                compute_add_carries(plan.pre_total_bet, plan.total_bet_credit)
            } else {
                [ZERO; 3]
            };
        Self {
            header: StageHeaderRow::new(link),
            seat_index: M31::from(u32::from(plan.seat_index)),
            amounts: [
                u64_to_m31_limbs(plan.pre_stack),
                u64_to_m31_limbs(plan.post_stack),
                u64_to_m31_limbs(plan.stack_debit),
                u64_to_m31_limbs(plan.pre_bet),
                u64_to_m31_limbs(plan.post_bet),
                u64_to_m31_limbs(plan.bet_credit),
                u64_to_m31_limbs(plan.pre_total_bet),
                u64_to_m31_limbs(plan.post_total_bet),
                u64_to_m31_limbs(plan.total_bet_credit),
            ],
            flags: [
                M31::from(u32::from(plan.pre_folded)),
                M31::from(u32::from(plan.post_folded)),
                M31::from(u32::from(plan.pre_all_in)),
                M31::from(u32::from(plan.post_all_in)),
            ],
            acted_before: plan.acted_before.map(|value| M31::from(u32::from(value))),
            acted_after: plan.acted_after.map(|value| M31::from(u32::from(value))),
            stack_carry,
            bet_carry,
            total_bet_carry,
        }
    }

    /// Serialize the row in canonical trace-column order.
    #[must_use]
    pub fn to_vec(&self) -> Vec<M31> {
        let mut values = Vec::with_capacity(NUM_COLUMNS);
        self.header.append_to(&mut values);
        values.push(self.seat_index);
        for amount in &self.amounts {
            values.extend_from_slice(amount);
        }
        values.extend_from_slice(&self.flags);
        values.extend_from_slice(&self.acted_before);
        values.extend_from_slice(&self.acted_after);
        values.extend_from_slice(&self.stack_carry);
        values.extend_from_slice(&self.bet_carry);
        values.extend_from_slice(&self.total_bet_carry);
        debug_assert_eq!(values.len(), NUM_COLUMNS);
        values
    }
}

/// Read and constrain one seat-update component row.
pub fn evaluate<E: EvalAtRow>(eval: &mut E, plan: &SeatUpdatePlan, link: &super::StageLink) {
    evaluate_stage_header(eval, link);
    let seat_index = eval.next_trace_mask();
    let amounts: [[E::F; 4]; 9] =
        std::array::from_fn(|_| std::array::from_fn(|_| eval.next_trace_mask()));
    let flags: [E::F; 4] = std::array::from_fn(|_| eval.next_trace_mask());
    let acted_before: [E::F; COMPOSITION_SEATS] = std::array::from_fn(|_| eval.next_trace_mask());
    let acted_after: [E::F; COMPOSITION_SEATS] = std::array::from_fn(|_| eval.next_trace_mask());
    let stack_carry: [E::F; 3] = std::array::from_fn(|_| eval.next_trace_mask());
    let bet_carry: [E::F; 3] = std::array::from_fn(|_| eval.next_trace_mask());
    let total_bet_carry: [E::F; 3] = std::array::from_fn(|_| eval.next_trace_mask());

    eval.add_constraint(seat_index - M31::from(u32::from(plan.seat_index)).into());
    let expected_amounts = [
        plan.pre_stack,
        plan.post_stack,
        plan.stack_debit,
        plan.pre_bet,
        plan.post_bet,
        plan.bet_credit,
        plan.pre_total_bet,
        plan.post_total_bet,
        plan.total_bet_credit,
    ];
    for (actual, expected) in amounts.iter().zip(expected_amounts) {
        bind_u64(eval, actual, expected);
    }
    for (actual, expected) in flags.into_iter().zip([
        plan.pre_folded,
        plan.post_folded,
        plan.pre_all_in,
        plan.post_all_in,
    ]) {
        bind_bool(eval, actual, expected);
    }
    for (actual, expected) in acted_before.into_iter().zip(plan.acted_before) {
        bind_bool(eval, actual, expected);
    }
    for (actual, expected) in acted_after.into_iter().zip(plan.acted_after) {
        bind_bool(eval, actual, expected);
    }

    evaluate_u64_add(eval, &amounts[1], &amounts[2], &amounts[0], &stack_carry);
    evaluate_u64_add(eval, &amounts[3], &amounts[5], &amounts[4], &bet_carry);
    evaluate_u64_add(
        eval,
        &amounts[6],
        &amounts[8],
        &amounts[7],
        &total_bet_carry,
    );
    for limb in 0..4 {
        eval.add_constraint(amounts[2][limb].clone() - amounts[5][limb].clone());
        eval.add_constraint(amounts[2][limb].clone() - amounts[8][limb].clone());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::airs::composition::plan::{StageKind, StageLink};

    #[test]
    fn row_has_fixed_width_and_full_digest_headers() {
        let link = StageLink {
            active: false,
            stage_kind: StageKind::SeatUpdate,
            stage_index: 0,
            plan_digest: [1; 32],
            input_digest: [2; 32],
            output_digest: [3; 32],
        };
        assert_eq!(
            SeatUpdateRow::new(&SeatUpdatePlan::inactive(), &link)
                .to_vec()
                .len(),
            NUM_COLUMNS
        );
    }
}
