//! `fold_with_proof` AIR — fold plus encrypted-deck layer removal.
//!
//! The native VM verifies a `LeaveKind` DLEq proof, removes the player's public
//! key from the aggregate key, replaces the encrypted deck, marks the acting
//! seat folded, and either advances to the next active seat or, when only one
//! player remains, proves the shared end-without-showdown settlement/reset.
//!
//! Cryptography follows the repository's host-native trust model: the verifier
//! reconstructs the exact DLEq request from canonical dispatch state, executes
//! the native BLS12-381 verifier once, and binds the complete request/receipt
//! digests into this statement.

use stwo::core::fields::m31::M31;
use stwo_constraint_framework::{EvalAtRow, FrameworkEval};

use crate::airs::actions::end_without_showdown::{self, EndWithoutShowdownRow, FoldOutcome};
use crate::airs::common::{
    COMMON_NUM_COLUMNS, CommonConstraints, CommonRow, ZERO, bool_to_m31, u8_to_m31,
    u64_to_m31_limbs,
};
use crate::method_kind::MethodKind;
use crate::precompile_binding::{DIGEST_LIMBS, PrecompileAirBinding};

/// `fold_with_proof` business-column layout.
pub mod cols {
    use super::COMMON_NUM_COLUMNS;

    /// Acting seat.
    pub const INPUT_SEAT_INDEX: usize = COMMON_NUM_COLUMNS;
    /// Fold marker written by the transition.
    pub const OUTPUT_FOLDED: usize = COMMON_NUM_COLUMNS + 1;
    /// `pre_round_state²` witness used by the betting-round membership check.
    pub const INPUT_PRE_ROUND_STATE_Q: usize = COMMON_NUM_COLUMNS + 2;
    /// Current turn before the action.
    pub const INPUT_CURRENT_TURN: usize = COMMON_NUM_COLUMNS + 3;
    /// Current turn after the non-terminal action.
    pub const OUTPUT_CURRENT_TURN: usize = COMMON_NUM_COLUMNS + 4;
    /// Four u16 limbs of the pre-dispatch encrypted-deck commitment.
    pub const INPUT_OLD_DECK_COMMITMENT_BASE: usize = COMMON_NUM_COLUMNS + 5;
    /// Four u16 limbs of the post-dispatch encrypted-deck commitment.
    pub const OUTPUT_NEW_DECK_COMMITMENT_BASE: usize = COMMON_NUM_COLUMNS + 9;
    /// Native precompile selector.
    pub const PRECOMPILE_ID: usize = COMMON_NUM_COLUMNS + 13;
    /// Canonical request ABI version.
    pub const PRECOMPILE_ABI_VERSION: usize = COMMON_NUM_COLUMNS + 14;
    /// Full request digest columns.
    pub const REQUEST_DIGEST_BASE: usize = COMMON_NUM_COLUMNS + 15;
    /// Full verifier receipt digest columns.
    pub const RECEIPT_DIGEST_BASE: usize = REQUEST_DIGEST_BASE + super::DIGEST_LIMBS;
    /// Total trace width.
    pub const NUM_COLUMNS: usize = RECEIPT_DIGEST_BASE
        + super::DIGEST_LIMBS
        + crate::airs::actions::end_without_showdown::NUM_COLUMNS;
}

/// Verifier-owned inputs for one `fold_with_proof` transition.
#[derive(Debug, Clone)]
pub struct FoldWithProofInput {
    /// Acting seat.
    pub seat_index: u8,
    /// Native-replayed mid-round or terminal settlement branch.
    pub outcome: FoldOutcome,
    /// Commitment to the exact pre-dispatch encrypted deck.
    pub old_deck_commitment: u64,
    /// Commitment to the exact post-dispatch encrypted deck.
    pub new_deck_commitment: u64,
    /// Verifier-issued native DLEq receipt projection.
    pub precompile: PrecompileAirBinding,
}

/// AIR statement for `fold_with_proof`.
#[derive(Debug, Clone)]
pub struct FoldWithProofAir {
    /// log2(trace rows).
    pub log_size: u32,
    /// Method-specific input.
    pub input: FoldWithProofInput,
    /// Pre-state root projection.
    pub pre_state_root: [M31; 4],
    /// Post-state root projection.
    pub post_state_root: [M31; 4],
    /// Table identifier.
    pub table_id: u64,
    /// Hand identifier.
    pub hand_id: u32,
    /// Call sequence.
    pub call_seq: u32,
    /// Pre-dispatch version.
    pub pre_version: u64,
    /// Post-dispatch version.
    pub post_version: u64,
}

impl FoldWithProofAir {
    /// Trace width.
    #[must_use]
    pub const fn num_columns() -> usize {
        cols::NUM_COLUMNS
    }
}

impl FrameworkEval for FoldWithProofAir {
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
        let output_folded = eval.next_trace_mask();
        let input_pre_round_state_q = eval.next_trace_mask();
        let input_current_turn = eval.next_trace_mask();
        let output_current_turn = eval.next_trace_mask();
        let old_deck_commitment: Vec<_> = (0..4).map(|_| eval.next_trace_mask()).collect();
        let new_deck_commitment: Vec<_> = (0..4).map(|_| eval.next_trace_mask()).collect();
        let precompile_id = eval.next_trace_mask();
        let precompile_abi_version = eval.next_trace_mask();
        let request_digest: Vec<_> = (0..DIGEST_LIMBS).map(|_| eval.next_trace_mask()).collect();
        let receipt_digest: Vec<_> = (0..DIGEST_LIMBS).map(|_| eval.next_trace_mask()).collect();

        let expected_seat: E::F = M31::from(u32::from(self.input.seat_index)).into();
        eval.add_constraint(is_active.clone() * (input_seat_index - expected_seat.clone()));
        eval.add_constraint(is_active.clone() * (input_current_turn - expected_seat));

        eval.add_constraint(common.round_state_q_constraint(input_pre_round_state_q.clone()));
        eval.add_constraint(common.round_state_is_betting(input_pre_round_state_q));
        let expected_folded: E::F = bool_to_m31(self.input.outcome.output_folded()).into();
        eval.add_constraint(is_active.clone() * (output_folded - expected_folded));
        let expected_post_turn: E::F =
            M31::from(u32::from(self.input.outcome.post_current_turn())).into();
        eval.add_constraint(is_active.clone() * (output_current_turn - expected_post_turn));

        let expected_old = u64_to_m31_limbs(self.input.old_deck_commitment);
        let expected_new = u64_to_m31_limbs(self.input.new_deck_commitment);
        for limb in 0..4 {
            let old: E::F = expected_old[limb].into();
            let new: E::F = expected_new[limb].into();
            eval.add_constraint(is_active.clone() * (old_deck_commitment[limb].clone() - old));
            eval.add_constraint(is_active.clone() * (new_deck_commitment[limb].clone() - new));
        }

        let expected_precompile_id: E::F =
            M31::from(u32::from(self.input.precompile.precompile_id)).into();
        let expected_abi_version: E::F =
            M31::from(u32::from(self.input.precompile.abi_version)).into();
        eval.add_constraint(is_active.clone() * (precompile_id - expected_precompile_id));
        eval.add_constraint(is_active.clone() * (precompile_abi_version - expected_abi_version));
        for limb in 0..DIGEST_LIMBS {
            let expected_request: E::F = self.input.precompile.request_digest[limb].into();
            let expected_receipt: E::F = self.input.precompile.receipt_digest[limb].into();
            eval.add_constraint(
                is_active.clone() * (request_digest[limb].clone() - expected_request),
            );
            eval.add_constraint(
                is_active.clone() * (receipt_digest[limb].clone() - expected_receipt),
            );
        }

        match &self.input.outcome {
            FoldOutcome::MidRound { .. } => {
                eval.add_constraint(common.round_state_unchanged());
                for constraint in common.pot_unchanged_4limb() {
                    eval.add_constraint(constraint);
                }
                end_without_showdown::evaluate(&mut eval, &common, None);
            }
            FoldOutcome::EndWithoutShowdown(settlement) => {
                end_without_showdown::evaluate(&mut eval, &common, Some(settlement));
            }
        }

        eval
    }
}

/// One trace row for `fold_with_proof`.
#[derive(Debug, Clone)]
pub struct FoldWithProofRow {
    /// Shared method columns.
    pub common: CommonRow,
    /// Acting seat.
    pub input_seat_index: M31,
    /// Fold marker.
    pub output_folded: M31,
    /// Betting-round membership witness.
    pub input_pre_round_state_q: M31,
    /// Pre-dispatch current turn.
    pub input_current_turn: M31,
    /// Post-dispatch current turn.
    pub output_current_turn: M31,
    /// Pre-dispatch encrypted-deck commitment.
    pub old_deck_commitment: [M31; 4],
    /// Post-dispatch encrypted-deck commitment.
    pub new_deck_commitment: [M31; 4],
    /// Native precompile selector.
    pub precompile_id: M31,
    /// Canonical request ABI version.
    pub precompile_abi_version: M31,
    /// Full request digest.
    pub request_digest: [M31; DIGEST_LIMBS],
    /// Full verifier receipt digest.
    pub receipt_digest: [M31; DIGEST_LIMBS],
    /// Shared terminal settlement columns; zero for mid-round folds.
    pub settlement: EndWithoutShowdownRow,
}

impl FoldWithProofRow {
    /// Construct the active row from verifier-replayed state.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn active(
        input: &FoldWithProofInput,
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
        let round = u8_to_m31(pre_round_state);
        Self {
            common: CommonRow::active(
                MethodKind::FoldWithProof,
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
            output_folded: bool_to_m31(input.outcome.output_folded()),
            input_pre_round_state_q: round * round,
            input_current_turn: u8_to_m31(input.seat_index),
            output_current_turn: u8_to_m31(input.outcome.post_current_turn()),
            old_deck_commitment: u64_to_m31_limbs(input.old_deck_commitment),
            new_deck_commitment: u64_to_m31_limbs(input.new_deck_commitment),
            precompile_id: u8_to_m31(input.precompile.precompile_id),
            precompile_abi_version: u8_to_m31(input.precompile.abi_version),
            request_digest: input.precompile.request_digest,
            receipt_digest: input.precompile.receipt_digest,
            settlement: match &input.outcome {
                FoldOutcome::MidRound { .. } => EndWithoutShowdownRow::zero(),
                FoldOutcome::EndWithoutShowdown(settlement) => {
                    EndWithoutShowdownRow::active(settlement)
                }
            },
        }
    }

    /// Construct a padding row.
    #[must_use]
    pub fn padding() -> Self {
        Self {
            common: CommonRow::padding(),
            input_seat_index: ZERO,
            output_folded: ZERO,
            input_pre_round_state_q: ZERO,
            input_current_turn: ZERO,
            output_current_turn: ZERO,
            old_deck_commitment: [ZERO; 4],
            new_deck_commitment: [ZERO; 4],
            precompile_id: ZERO,
            precompile_abi_version: ZERO,
            request_digest: [ZERO; DIGEST_LIMBS],
            receipt_digest: [ZERO; DIGEST_LIMBS],
            settlement: EndWithoutShowdownRow::zero(),
        }
    }

    /// Flatten the row into trace-column order.
    #[must_use]
    pub fn to_vec(&self) -> Vec<M31> {
        let mut values = self.common.to_vec();
        values.push(self.input_seat_index);
        values.push(self.output_folded);
        values.push(self.input_pre_round_state_q);
        values.push(self.input_current_turn);
        values.push(self.output_current_turn);
        values.extend_from_slice(&self.old_deck_commitment);
        values.extend_from_slice(&self.new_deck_commitment);
        values.push(self.precompile_id);
        values.push(self.precompile_abi_version);
        values.extend_from_slice(&self.request_digest);
        values.extend_from_slice(&self.receipt_digest);
        self.settlement.append_to(&mut values);
        debug_assert_eq!(values.len(), cols::NUM_COLUMNS);
        values
    }
}
