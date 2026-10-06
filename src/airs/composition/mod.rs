//! Composable transition components shared by compound Texas Poker dispatches.
//!
//! Native execution applies these stages in one atomic dispatch: seat mutation,
//! bet collection, round advancement, then optional settlement/reset. This module
//! gives those stages a fixed-width verifier-owned ABI and commits adjacent stages
//! through deterministic boundary digests. The components can be embedded in the
//! current method AIRs and later promoted to independent proofs without inventing
//! persistent intermediate table roots.

pub(crate) mod air;
pub mod bet_collection;
pub mod plan;
pub mod proof;
pub mod round_advance;
pub mod seat_update;
pub mod settlement;

use stwo::core::fields::m31::M31;
use stwo_constraint_framework::EvalAtRow;

use crate::precompile_binding::{DIGEST_LIMBS, digest_to_m31_limbs};

pub use plan::{
    COMPOSITE_PLAN_VERSION, ComponentStatement, CompositeTransitionPlan, StageKind, StageLink,
    derive_composite_transition_plan, derive_composite_transition_plan_from_task,
    supports_composite_proof,
};
pub(crate) use proof::prove_composition_batch_without_self_verify;
pub use proof::{
    ArchivedComponentProof, ArchivedCompositionBatchProofBundle, ArchivedCompositionProofBundle,
    ArchivedTaggedStageProof, COMPOSITION_BATCH_PROOF_BUNDLE_VERSION,
    COMPOSITION_PROOF_BUNDLE_VERSION, MAX_COMPOSITION_BATCH_TASKS, prove_composition_batch,
    prove_composition_bundle, verify_composition_batch, verify_composition_bundle,
};
pub use settlement::SettlementKind;

/// Columns shared by every composable stage.
pub const STAGE_HEADER_NUM_COLUMNS: usize = 3 + 3 * DIGEST_LIMBS;

/// Fixed-width trace projection of one stage link.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StageHeaderRow {
    active: M31,
    stage_kind: M31,
    stage_index: M31,
    plan_digest: [M31; DIGEST_LIMBS],
    input_digest: [M31; DIGEST_LIMBS],
    output_digest: [M31; DIGEST_LIMBS],
}

impl StageHeaderRow {
    /// Construct the canonical header row for a verifier-derived link.
    #[must_use]
    pub fn new(link: &StageLink) -> Self {
        Self {
            active: M31::from(u32::from(link.active)),
            stage_kind: M31::from(u32::from(link.stage_kind as u8)),
            stage_index: M31::from(u32::from(link.stage_index)),
            plan_digest: digest_to_m31_limbs(link.plan_digest),
            input_digest: digest_to_m31_limbs(link.input_digest),
            output_digest: digest_to_m31_limbs(link.output_digest),
        }
    }

    /// Append columns in canonical ABI order.
    pub fn append_to(&self, values: &mut Vec<M31>) {
        values.push(self.active);
        values.push(self.stage_kind);
        values.push(self.stage_index);
        values.extend_from_slice(&self.plan_digest);
        values.extend_from_slice(&self.input_digest);
        values.extend_from_slice(&self.output_digest);
    }
}

/// Read and bind a stage header to its verifier-owned link.
pub fn evaluate_stage_header<E: EvalAtRow>(eval: &mut E, link: &StageLink) {
    let active = eval.next_trace_mask();
    let stage_kind = eval.next_trace_mask();
    let stage_index = eval.next_trace_mask();
    let plan_digest: [E::F; DIGEST_LIMBS] = std::array::from_fn(|_| eval.next_trace_mask());
    let input_digest: [E::F; DIGEST_LIMBS] = std::array::from_fn(|_| eval.next_trace_mask());
    let output_digest: [E::F; DIGEST_LIMBS] = std::array::from_fn(|_| eval.next_trace_mask());

    eval.add_constraint(active - M31::from(u32::from(link.active)).into());
    eval.add_constraint(stage_kind - M31::from(u32::from(link.stage_kind as u8)).into());
    eval.add_constraint(stage_index - M31::from(u32::from(link.stage_index)).into());

    for (actual, expected) in plan_digest
        .iter()
        .zip(digest_to_m31_limbs(link.plan_digest))
    {
        eval.add_constraint(actual.clone() - expected.into());
    }
    for (actual, expected) in input_digest
        .iter()
        .zip(digest_to_m31_limbs(link.input_digest))
    {
        eval.add_constraint(actual.clone() - expected.into());
    }
    for (actual, expected) in output_digest
        .iter()
        .zip(digest_to_m31_limbs(link.output_digest))
    {
        eval.add_constraint(actual.clone() - expected.into());
    }
}

pub(crate) fn evaluate_u64_add<E: EvalAtRow>(
    eval: &mut E,
    lhs: &[E::F; 4],
    rhs: &[E::F; 4],
    sum: &[E::F; 4],
    carry: &[E::F; 3],
) {
    let zero: E::F = M31::from(0u32).into();
    let one: E::F = M31::from(1u32).into();
    let base: E::F = M31::from(65_536u32).into();
    let carry_in = [
        zero.clone(),
        carry[0].clone(),
        carry[1].clone(),
        carry[2].clone(),
    ];
    let carry_out = [carry[0].clone(), carry[1].clone(), carry[2].clone(), zero];
    for limb in 0..4 {
        eval.add_constraint(
            lhs[limb].clone() + rhs[limb].clone() + carry_in[limb].clone()
                - sum[limb].clone()
                - base.clone() * carry_out[limb].clone(),
        );
    }
    for bit in carry {
        eval.add_constraint(bit.clone() * (bit.clone() - one.clone()));
    }
}

pub(crate) fn bind_u64<E: EvalAtRow>(eval: &mut E, actual: &[E::F; 4], expected: u64) {
    for (actual, expected) in actual
        .iter()
        .zip(crate::airs::common::u64_to_m31_limbs(expected))
    {
        eval.add_constraint(actual.clone() - expected.into());
    }
}

pub(crate) fn bind_bool<E: EvalAtRow>(eval: &mut E, actual: E::F, expected: bool) {
    let one: E::F = M31::from(1u32).into();
    eval.add_constraint(actual.clone() - M31::from(u32::from(expected)).into());
    eval.add_constraint(actual.clone() * (actual - one));
}
