//! Deterministic settlement, refund, addon-credit and reset AIR component.

use borsh::{BorshDeserialize, BorshSerialize};
use stwo::core::fields::m31::M31;
use stwo_constraint_framework::EvalAtRow;

use super::seat_update::COMPOSITION_SEATS;
use super::{
    STAGE_HEADER_NUM_COLUMNS, StageHeaderRow, bind_bool, bind_u64, evaluate_stage_header,
    evaluate_u64_add,
};
use crate::airs::common::{ZERO, compute_add_carries, u64_to_m31_limbs};
use crate::precompile_binding::{DIGEST_LIMBS, digest_to_m31_limbs};

/// Number of columns in the settlement/reset component row.
pub const NUM_COLUMNS: usize = STAGE_HEADER_NUM_COLUMNS
    + 1
    + DIGEST_LIMBS
    + 1
    + 9 * 4
    + 6 * COMPOSITION_SEATS * 4
    + COMPOSITION_SEATS
    + 4 * COMPOSITION_SEATS * 4
    + 4 * COMPOSITION_SEATS * 3
    + 3 * 3
    + 1;

/// Settlement/reset algorithm selected by canonical native replay.
#[derive(Debug, Clone, Copy, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
#[borsh(use_discriminant = true)]
#[repr(u8)]
pub enum SettlementKind {
    /// No settlement or reset occurred.
    None = 0,
    /// Last-player-standing award without showdown.
    WithoutShowdown = 1,
    /// Canonical side-pot/showdown settlement plan.
    Showdown = 2,
    /// Reset-only flow, including a WAITING-state nested kick reset.
    ResetOnly = 3,
}

/// Canonical fixed-seat settlement and reset projection.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct SettlementStagePlan {
    /// Whether settlement/reset occurred.
    pub active: bool,
    /// Settlement/reset discriminator.
    pub kind: SettlementKind,
    /// Native deterministic plan digest; synthesized for no-showdown and reset-only flows.
    pub native_plan_digest: [u8; 32],
    /// Number of showdown runouts; zero outside showdown.
    pub runout_count: u8,
    /// Pot before rake.
    pub gross_pot: u64,
    /// Rake removed from table custody.
    pub rake: u64,
    /// Sum of all seat awards.
    pub total_awards: u64,
    /// Fixed nine-seat aggregate awards.
    pub awards: [u64; COMPOSITION_SEATS],
    /// TableVault balance before the complete dispatch.
    pub pre_chip_pool: u64,
    /// TableVault balance after settlement/reset/refunds.
    pub post_chip_pool: u64,
    /// Fixed-seat addon amounts merged into stacks during reset.
    pub addon_credits: [u64; COMPOSITION_SEATS],
    /// Fixed-seat refunds leaving TableVault custody.
    pub refunds: [u64; COMPOSITION_SEATS],
    /// Pending-addon portions refunded directly before reset crediting.
    pub addon_refunds: [u64; COMPOSITION_SEATS],
    /// Sum of all addon credits.
    pub total_addon_credits: u64,
    /// Sum of all refunds.
    pub total_refunds: u64,
    /// Sum of directly refunded pending addons.
    pub total_addon_refunds: u64,
    /// Fixed-seat stacks in the canonical post table.
    pub post_stacks: [u64; COMPOSITION_SEATS],
    /// Fixed-seat pending addons in the canonical post table.
    pub post_pending_addons: [u64; COMPOSITION_SEATS],
    /// Fixed-seat occupancy flags in the canonical post table.
    pub post_occupied: [bool; COMPOSITION_SEATS],
    /// Whether reset to the next-hand waiting state was applied.
    pub reset_applied: bool,
}

impl SettlementStagePlan {
    /// Canonical zero payload for a non-terminal dispatch.
    #[must_use]
    pub const fn inactive() -> Self {
        Self {
            active: false,
            kind: SettlementKind::None,
            native_plan_digest: [0; 32],
            runout_count: 0,
            gross_pot: 0,
            rake: 0,
            total_awards: 0,
            awards: [0; COMPOSITION_SEATS],
            pre_chip_pool: 0,
            post_chip_pool: 0,
            addon_credits: [0; COMPOSITION_SEATS],
            refunds: [0; COMPOSITION_SEATS],
            addon_refunds: [0; COMPOSITION_SEATS],
            total_addon_credits: 0,
            total_refunds: 0,
            total_addon_refunds: 0,
            post_stacks: [0; COMPOSITION_SEATS],
            post_pending_addons: [0; COMPOSITION_SEATS],
            post_occupied: [false; COMPOSITION_SEATS],
            reset_applied: false,
        }
    }
}

type Limbs = [M31; 4];
type Carries = [M31; 3];

fn sum_witness(
    values: &[u64; COMPOSITION_SEATS],
) -> ([[M31; 4]; COMPOSITION_SEATS], [[M31; 3]; COMPOSITION_SEATS]) {
    let mut running = 0u64;
    let mut accumulators = [[ZERO; 4]; COMPOSITION_SEATS];
    let mut carries = [[ZERO; 3]; COMPOSITION_SEATS];
    for index in 0..COMPOSITION_SEATS {
        if let Some(next) = running.checked_add(values[index]) {
            carries[index] = compute_add_carries(running, values[index]);
            running = next;
            accumulators[index] = u64_to_m31_limbs(running);
        }
    }
    (accumulators, carries)
}

fn add_carries(lhs: u64, rhs: u64, sum: u64) -> Carries {
    if lhs.checked_add(rhs) == Some(sum) {
        compute_add_carries(lhs, rhs)
    } else {
        [ZERO; 3]
    }
}

/// Fixed-width witness row for [`SettlementStagePlan`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SettlementRow {
    header: StageHeaderRow,
    kind: M31,
    native_plan_digest: [M31; DIGEST_LIMBS],
    runout_count: M31,
    scalars: [Limbs; 9],
    arrays: [[[M31; 4]; COMPOSITION_SEATS]; 6],
    post_occupied: [M31; COMPOSITION_SEATS],
    accumulators: [[[M31; 4]; COMPOSITION_SEATS]; 4],
    sum_carries: [[[M31; 3]; COMPOSITION_SEATS]; 4],
    equation_carries: [[M31; 3]; 3],
    reset_applied: M31,
}

impl SettlementRow {
    /// Build canonical running-sum and custody-conservation witnesses.
    #[must_use]
    pub fn new(plan: &SettlementStagePlan, link: &super::StageLink) -> Self {
        let (award_acc, award_carries) = sum_witness(&plan.awards);
        let (addon_acc, addon_carries) = sum_witness(&plan.addon_credits);
        let (refund_acc, refund_carries) = sum_witness(&plan.refunds);
        let (addon_refund_acc, addon_refund_carries) = sum_witness(&plan.addon_refunds);
        let chip_after_refunds = plan
            .post_chip_pool
            .checked_add(plan.total_refunds)
            .unwrap_or(0);
        Self {
            header: StageHeaderRow::new(link),
            kind: M31::from(u32::from(plan.kind as u8)),
            native_plan_digest: digest_to_m31_limbs(plan.native_plan_digest),
            runout_count: M31::from(u32::from(plan.runout_count)),
            scalars: [
                u64_to_m31_limbs(plan.gross_pot),
                u64_to_m31_limbs(plan.rake),
                u64_to_m31_limbs(plan.total_awards),
                u64_to_m31_limbs(plan.pre_chip_pool),
                u64_to_m31_limbs(plan.post_chip_pool),
                u64_to_m31_limbs(plan.total_addon_credits),
                u64_to_m31_limbs(plan.total_refunds),
                u64_to_m31_limbs(plan.total_addon_refunds),
                u64_to_m31_limbs(chip_after_refunds),
            ],
            arrays: [
                plan.awards.map(u64_to_m31_limbs),
                plan.addon_credits.map(u64_to_m31_limbs),
                plan.refunds.map(u64_to_m31_limbs),
                plan.addon_refunds.map(u64_to_m31_limbs),
                plan.post_stacks.map(u64_to_m31_limbs),
                plan.post_pending_addons.map(u64_to_m31_limbs),
            ],
            post_occupied: plan.post_occupied.map(|value| M31::from(u32::from(value))),
            accumulators: [award_acc, addon_acc, refund_acc, addon_refund_acc],
            sum_carries: [
                award_carries,
                addon_carries,
                refund_carries,
                addon_refund_carries,
            ],
            equation_carries: [
                add_carries(plan.total_awards, plan.rake, plan.gross_pot),
                add_carries(plan.post_chip_pool, plan.total_refunds, chip_after_refunds),
                add_carries(chip_after_refunds, plan.rake, plan.pre_chip_pool),
            ],
            reset_applied: M31::from(u32::from(plan.reset_applied)),
        }
    }

    /// Serialize the row in canonical trace-column order.
    #[must_use]
    pub fn to_vec(&self) -> Vec<M31> {
        let mut values = Vec::with_capacity(NUM_COLUMNS);
        self.header.append_to(&mut values);
        values.push(self.kind);
        values.extend_from_slice(&self.native_plan_digest);
        values.push(self.runout_count);
        for scalar in &self.scalars {
            values.extend_from_slice(scalar);
        }
        for array in &self.arrays {
            for value in array {
                values.extend_from_slice(value);
            }
        }
        values.extend_from_slice(&self.post_occupied);
        for set in &self.accumulators {
            for value in set {
                values.extend_from_slice(value);
            }
        }
        for set in &self.sum_carries {
            for carry in set {
                values.extend_from_slice(carry);
            }
        }
        for carry in &self.equation_carries {
            values.extend_from_slice(carry);
        }
        values.push(self.reset_applied);
        debug_assert_eq!(values.len(), NUM_COLUMNS);
        values
    }
}

/// Read and constrain one settlement/reset component row.
pub fn evaluate<E: EvalAtRow>(eval: &mut E, plan: &SettlementStagePlan, link: &super::StageLink) {
    evaluate_stage_header(eval, link);
    let kind = eval.next_trace_mask();
    let native_plan_digest: [E::F; DIGEST_LIMBS] = std::array::from_fn(|_| eval.next_trace_mask());
    let runout_count = eval.next_trace_mask();
    let scalars: [[E::F; 4]; 9] =
        std::array::from_fn(|_| std::array::from_fn(|_| eval.next_trace_mask()));
    let arrays: [[[E::F; 4]; COMPOSITION_SEATS]; 6] = std::array::from_fn(|_| {
        std::array::from_fn(|_| std::array::from_fn(|_| eval.next_trace_mask()))
    });
    let post_occupied: [E::F; COMPOSITION_SEATS] = std::array::from_fn(|_| eval.next_trace_mask());
    let accumulators: [[[E::F; 4]; COMPOSITION_SEATS]; 4] = std::array::from_fn(|_| {
        std::array::from_fn(|_| std::array::from_fn(|_| eval.next_trace_mask()))
    });
    let sum_carries: [[[E::F; 3]; COMPOSITION_SEATS]; 4] = std::array::from_fn(|_| {
        std::array::from_fn(|_| std::array::from_fn(|_| eval.next_trace_mask()))
    });
    let equation_carries: [[E::F; 3]; 3] =
        std::array::from_fn(|_| std::array::from_fn(|_| eval.next_trace_mask()));
    let reset_applied = eval.next_trace_mask();

    eval.add_constraint(kind - M31::from(u32::from(plan.kind as u8)).into());
    for (actual, expected) in native_plan_digest
        .iter()
        .zip(digest_to_m31_limbs(plan.native_plan_digest))
    {
        eval.add_constraint(actual.clone() - expected.into());
    }
    eval.add_constraint(runout_count - M31::from(u32::from(plan.runout_count)).into());
    let expected_scalars = [
        plan.gross_pot,
        plan.rake,
        plan.total_awards,
        plan.pre_chip_pool,
        plan.post_chip_pool,
        plan.total_addon_credits,
        plan.total_refunds,
        plan.total_addon_refunds,
        plan.post_chip_pool
            .checked_add(plan.total_refunds)
            .unwrap_or(0),
    ];
    for (actual, expected) in scalars.iter().zip(expected_scalars) {
        bind_u64(eval, actual, expected);
    }
    let expected_arrays = [
        plan.awards,
        plan.addon_credits,
        plan.refunds,
        plan.addon_refunds,
        plan.post_stacks,
        plan.post_pending_addons,
    ];
    for (actual_set, expected_set) in arrays.iter().zip(expected_arrays) {
        for (actual, expected) in actual_set.iter().zip(expected_set) {
            bind_u64(eval, actual, expected);
        }
    }
    for (actual, expected) in post_occupied.into_iter().zip(plan.post_occupied) {
        bind_bool(eval, actual, expected);
    }
    bind_bool(eval, reset_applied, plan.reset_applied);

    let zero: [E::F; 4] = std::array::from_fn(|_| M31::from(0u32).into());
    for set in 0..4 {
        for index in 0..COMPOSITION_SEATS {
            let previous = if index == 0 {
                &zero
            } else {
                &accumulators[set][index - 1]
            };
            evaluate_u64_add(
                eval,
                previous,
                &arrays[set][index],
                &accumulators[set][index],
                &sum_carries[set][index],
            );
        }
    }
    for limb in 0..4 {
        eval.add_constraint(
            accumulators[0][COMPOSITION_SEATS - 1][limb].clone() - scalars[2][limb].clone(),
        );
        eval.add_constraint(
            accumulators[1][COMPOSITION_SEATS - 1][limb].clone() - scalars[5][limb].clone(),
        );
        eval.add_constraint(
            accumulators[2][COMPOSITION_SEATS - 1][limb].clone() - scalars[6][limb].clone(),
        );
        eval.add_constraint(
            accumulators[3][COMPOSITION_SEATS - 1][limb].clone() - scalars[7][limb].clone(),
        );
    }
    evaluate_u64_add(
        eval,
        &scalars[2],
        &scalars[1],
        &scalars[0],
        &equation_carries[0],
    );
    evaluate_u64_add(
        eval,
        &scalars[4],
        &scalars[6],
        &scalars[8],
        &equation_carries[1],
    );
    evaluate_u64_add(
        eval,
        &scalars[8],
        &scalars[1],
        &scalars[3],
        &equation_carries[2],
    );

    if plan.reset_applied {
        for seat in &arrays[5] {
            for limb in seat {
                eval.add_constraint(limb.clone());
            }
        }
    }
    let legal = match plan.kind {
        SettlementKind::None => !plan.active && !plan.reset_applied && plan.runout_count == 0,
        SettlementKind::WithoutShowdown => {
            plan.active && plan.reset_applied && plan.runout_count == 0
        }
        SettlementKind::Showdown => {
            plan.active && plan.reset_applied && matches!(plan.runout_count, 1 | 2)
        }
        SettlementKind::ResetOnly => {
            plan.active
                && plan.reset_applied
                && plan.runout_count == 0
                && plan.gross_pot == 0
                && plan.rake == 0
                && plan.total_awards == 0
        }
    };
    let one: E::F = M31::from(1u32).into();
    let legal: E::F = M31::from(u32::from(legal)).into();
    eval.add_constraint(legal - one);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::airs::composition::plan::{StageKind, StageLink};

    #[test]
    fn row_sums_multi_winner_awards_and_reset_ledgers() {
        let plan = SettlementStagePlan {
            active: true,
            kind: SettlementKind::Showdown,
            native_plan_digest: [7; 32],
            runout_count: 2,
            gross_pot: 200,
            rake: 10,
            total_awards: 190,
            awards: [95, 0, 0, 0, 95, 0, 0, 0, 0],
            pre_chip_pool: 1_000,
            post_chip_pool: 965,
            addon_credits: [0, 25, 0, 0, 0, 0, 0, 0, 0],
            refunds: [0, 0, 0, 25, 0, 0, 0, 0, 0],
            addon_refunds: [0; COMPOSITION_SEATS],
            total_addon_credits: 25,
            total_refunds: 25,
            total_addon_refunds: 0,
            post_stacks: [95, 25, 0, 0, 95, 0, 0, 0, 0],
            post_pending_addons: [0; COMPOSITION_SEATS],
            post_occupied: [true, true, false, false, true, false, false, false, false],
            reset_applied: true,
        };
        let link = StageLink {
            active: true,
            stage_kind: StageKind::Settlement,
            stage_index: 3,
            plan_digest: [1; 32],
            input_digest: [2; 32],
            output_digest: [3; 32],
        };
        assert_eq!(SettlementRow::new(&plan, &link).to_vec().len(), NUM_COLUMNS);
    }
}
