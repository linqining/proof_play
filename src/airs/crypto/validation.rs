//! Canonical verifier-side reconstruction for crypto protocol AIR rows.
//!
//! These validators close the state-root/business-row detachment gap by
//! replaying the complete native dispatch and rebuilding the exact row accepted
//! by each AIR.  They do not turn the current protocol-state AIRs into embedded
//! DLEq or reveal-token verifiers; that separate cryptographic closure remains
//! explicit in the individual AIR modules.

use super::fold_with_proof::{FoldWithProofAir, FoldWithProofInput, FoldWithProofRow};
use super::submit_player_reveal_tokens::{
    SubmitPlayerRevealTokensAir, SubmitPlayerRevealTokensInput, SubmitPlayerRevealTokensRow,
};
use super::submit_reconstruct_deck::{
    SubmitReconstructDeckAir, SubmitReconstructDeckInput, SubmitReconstructDeckRow,
};
use super::submit_shuffle_v2::{SubmitShuffleV2Air, SubmitShuffleV2Input, SubmitShuffleV2Row};
use crate::airs::actions::end_without_showdown::derive_fold_outcome;
use crate::airs::validation::{validate_canonical_dispatch, validate_row};
use crate::deck_commitment::deck_commitment;
use crate::error::{TexasAirError, TexasAirResult};
use crate::method_kind::MethodKind;
use crate::precompile_binding::{
    LeaveDleqVerifyRequest, PokerPrecompileId, RevealTokenVerifyRequest, precompile_call_context,
};
use crate::prove_task::MethodInput;
use crate::public_inputs::TexasPublicInputs;
use crate::state_root::state_root_to_air_limbs;
use poker_l1::contracts::texas_poker::dispatch::{
    FoldWithProofArgs, SubmitReconstructDeckArgs, SubmitRevealTokensArgs, SubmitShuffleV2Args,
};

/// Bind a `fold_with_proof` transition to its exact dispatch and
/// verifier-issued leave-layer DLEq receipt.
pub(crate) fn validate_fold_with_proof(
    air: &FoldWithProofAir,
    public_inputs: &TexasPublicInputs,
) -> TexasAirResult<()> {
    const METHOD: &str = "fold_with_proof";
    let canonical = validate_canonical_dispatch(public_inputs, MethodKind::FoldWithProof)?;
    let args: FoldWithProofArgs = borsh::from_slice(&canonical.replay_args).map_err(|error| {
        TexasAirError::SerializationError(format!("{METHOD}: raw args borsh: {error}"))
    })?;
    let MethodInput::FoldWithProof { seat_index } = &canonical.method_input else {
        return Err(TexasAirError::SpecViolation(
            "fold_with_proof: replayed task has the wrong MethodInput variant".into(),
        ));
    };
    if *seat_index != args.seat_index {
        return Err(TexasAirError::SpecViolation(
            "fold_with_proof: replayed MethodInput does not match raw args".into(),
        ));
    }
    let composition = crate::airs::composition::derive_composite_transition_plan(
        MethodKind::FoldWithProof,
        &canonical.pre,
        &canonical.post,
        Some(args.seat_index),
        &canonical.events,
    )?;
    let outcome = derive_fold_outcome(
        &canonical.pre,
        &canonical.post,
        args.seat_index,
        METHOD,
        Some(&composition.settlement),
    )?;

    let binding = public_inputs.precompile_binding.as_ref().ok_or_else(|| {
        TexasAirError::SpecViolation(
            "fold_with_proof requires a verifier-issued precompile binding".into(),
        )
    })?;
    if binding.precompile_id() != PokerPrecompileId::DleqLeave {
        return Err(TexasAirError::SpecViolation(
            "fold_with_proof received the wrong precompile receipt type".into(),
        ));
    }
    let player_pk = canonical
        .pre
        .seats
        .get(usize::from(args.seat_index))
        .ok_or_else(|| {
            TexasAirError::SpecViolation(
                "fold_with_proof seat is outside the canonical pre-table".into(),
            )
        })?
        .pk()
        .copied()
        .ok_or_else(|| {
            TexasAirError::SpecViolation("fold_with_proof seat has no live Mental Poker key".into())
        })?;
    let expected_context = precompile_call_context(
        MethodKind::FoldWithProof,
        args.seat_index,
        public_inputs.table_id,
        public_inputs.hand_id,
        public_inputs.call_seq,
        public_inputs.pre_version,
        public_inputs.post_version,
        public_inputs.pre_state_root,
        public_inputs.post_state_root,
        public_inputs.dispatch_call_digest,
    );
    let expected_request = LeaveDleqVerifyRequest::new(
        expected_context,
        canonical.pre.deck_state.encrypted.to_vec(),
        args.output_cards,
        player_pk,
        args.fold_proof,
    );
    if binding.request_bytes() != expected_request.encode()? {
        return Err(TexasAirError::SpecViolation(
            "fold_with_proof precompile request does not match canonical dispatch".into(),
        ));
    }
    binding.validate_issued()?;

    let input = FoldWithProofInput {
        seat_index: args.seat_index,
        outcome,
        old_deck_commitment: deck_commitment(&canonical.pre),
        new_deck_commitment: deck_commitment(&canonical.post),
        precompile: binding.air_binding(),
    };
    if air.input.seat_index != input.seat_index
        || air.input.outcome != input.outcome
        || air.input.old_deck_commitment != input.old_deck_commitment
        || air.input.new_deck_commitment != input.new_deck_commitment
        || air.input.precompile != input.precompile
    {
        return Err(TexasAirError::SpecViolation(
            "fold_with_proof: AIR input does not match the canonical dispatch".into(),
        ));
    }

    let row = FoldWithProofRow::active(
        &input,
        state_root_to_air_limbs(public_inputs.pre_state_root),
        state_root_to_air_limbs(public_inputs.post_state_root),
        public_inputs.table_id,
        public_inputs.hand_id,
        public_inputs.call_seq,
        u64::from(canonical.pre.call_seq),
        u64::from(canonical.post.call_seq),
        canonical.pre.round_state(),
        canonical.post.round_state(),
        canonical.pre.pot,
        canonical.post.pot,
    );
    validate_row(public_inputs, &row.to_vec(), METHOD)
}

/// Bind reveal-token submission to its exact authenticated dispatch and post table.
pub(crate) fn validate_submit_player_reveal_tokens(
    air: &SubmitPlayerRevealTokensAir,
    public_inputs: &TexasPublicInputs,
) -> TexasAirResult<()> {
    const METHOD: &str = "submit_player_reveal_tokens";
    let canonical =
        validate_canonical_dispatch(public_inputs, MethodKind::SubmitPlayerRevealTokens)?;
    let args: SubmitRevealTokensArgs =
        borsh::from_slice(&canonical.replay_args).map_err(|error| {
            TexasAirError::SerializationError(format!("{METHOD}: raw args borsh: {error}"))
        })?;
    let MethodInput::SubmitPlayerRevealTokens { seat_index } = &canonical.method_input else {
        return Err(TexasAirError::SpecViolation(
            "submit_player_reveal_tokens: replayed task has the wrong MethodInput variant".into(),
        ));
    };
    if *seat_index != args.seat_index {
        return Err(TexasAirError::SpecViolation(
            "submit_player_reveal_tokens: replayed MethodInput does not match raw args".into(),
        ));
    }

    let binding = public_inputs.precompile_binding.as_ref().ok_or_else(|| {
        TexasAirError::SpecViolation(
            "submit_player_reveal_tokens requires a verifier-issued precompile binding".into(),
        )
    })?;
    if binding.precompile_id() != PokerPrecompileId::RevealToken {
        return Err(TexasAirError::SpecViolation(
            "submit_player_reveal_tokens received the wrong precompile receipt type".into(),
        ));
    }
    let expected_context = precompile_call_context(
        MethodKind::SubmitPlayerRevealTokens,
        args.seat_index,
        public_inputs.table_id,
        public_inputs.hand_id,
        public_inputs.call_seq,
        public_inputs.pre_version,
        public_inputs.post_version,
        public_inputs.pre_state_root,
        public_inputs.post_state_root,
        public_inputs.dispatch_call_digest,
    );
    let expected_request =
        RevealTokenVerifyRequest::from_dispatch(expected_context, &canonical.pre, &args)?;
    if binding.request_bytes() != expected_request.encode()? {
        return Err(TexasAirError::SpecViolation(
            "submit_player_reveal_tokens precompile request does not match the canonical dispatch"
                .into(),
        ));
    }
    binding.validate_issued()?;

    let version_increment = reveal_version_increment(&canonical.pre, &canonical.post)?;
    let settlement =
        crate::settlement_binding::SettlementPlanBinding::from_replay(&canonical.events)?;
    let input = SubmitPlayerRevealTokensInput {
        seat_index: args.seat_index,
        reveal_phase: canonical.pre.reveal_phase(),
        version_increment,
        precompile: binding.air_binding(),
        settlement,
    };
    if air.input.seat_index != input.seat_index
        || air.input.reveal_phase != input.reveal_phase
        || air.input.version_increment != input.version_increment
        || air.input.precompile != input.precompile
        || air.input.settlement != input.settlement
    {
        return Err(TexasAirError::SpecViolation(
            "submit_player_reveal_tokens: AIR input does not match the canonical dispatch".into(),
        ));
    }

    let post_revealed_count = count_as_u8(
        canonical.post.reveal_assignments().len(),
        METHOD,
        "post reveal assignment",
    )?;
    let mut row = SubmitPlayerRevealTokensRow::active(
        &input,
        state_root_to_air_limbs(public_inputs.pre_state_root),
        state_root_to_air_limbs(public_inputs.post_state_root),
        public_inputs.table_id,
        public_inputs.hand_id,
        public_inputs.call_seq,
        u64::from(canonical.pre.call_seq),
        u64::from(canonical.post.call_seq),
        post_revealed_count,
    );
    row.common.pre_pot = crate::airs::common::u64_to_m31_limbs(canonical.pre.pot);
    row.common.post_pot = crate::airs::common::u64_to_m31_limbs(canonical.post.pot);
    validate_row(public_inputs, &row.to_vec(), METHOD)
}

/// Bind a verifier-issued shuffle receipt to the exact VM dispatch and row.
pub(crate) fn validate_submit_shuffle_v2(
    air: &SubmitShuffleV2Air,
    public_inputs: &TexasPublicInputs,
) -> TexasAirResult<()> {
    const METHOD: &str = "submit_shuffle_v2";
    let canonical = validate_canonical_dispatch(public_inputs, MethodKind::SubmitShuffleV2)?;
    let args: SubmitShuffleV2Args = borsh::from_slice(&canonical.replay_args).map_err(|error| {
        TexasAirError::SerializationError(format!("{METHOD}: raw args borsh: {error}"))
    })?;
    let MethodInput::SubmitShuffleV2 { seat_index } = &canonical.method_input else {
        return Err(TexasAirError::SpecViolation(
            "submit_shuffle_v2: replayed task has the wrong MethodInput variant".into(),
        ));
    };
    if *seat_index != args.seat_index {
        return Err(TexasAirError::SpecViolation(
            "submit_shuffle_v2: replayed MethodInput does not match raw args".into(),
        ));
    }

    let binding = public_inputs.precompile_binding.as_ref().ok_or_else(|| {
        TexasAirError::SpecViolation(
            "submit_shuffle_v2 requires a verifier-issued precompile binding".into(),
        )
    })?;
    let input = SubmitShuffleV2Input {
        seat_index: args.seat_index,
        new_deck_commitment: deck_commitment(&canonical.post),
        shuffle_phase: canonical.pre.shuffle_phase(),
        precompile: binding.air_binding(),
    };
    if air.input.seat_index != input.seat_index
        || air.input.new_deck_commitment != input.new_deck_commitment
        || air.input.shuffle_phase != input.shuffle_phase
        || air.input.precompile != input.precompile
    {
        return Err(TexasAirError::SpecViolation(
            "submit_shuffle_v2: AIR input does not match the canonical dispatch".into(),
        ));
    }

    let post_completed_count = count_as_u8(
        canonical.post.shuffle_state().completed_mask.count_ones() as usize,
        METHOD,
        "post completed player",
    )?;
    let mut row = SubmitShuffleV2Row::active(
        &input,
        state_root_to_air_limbs(public_inputs.pre_state_root),
        state_root_to_air_limbs(public_inputs.post_state_root),
        public_inputs.table_id,
        public_inputs.hand_id,
        public_inputs.call_seq,
        u64::from(canonical.pre.call_seq),
        u64::from(canonical.post.call_seq),
        post_completed_count,
    );
    row.common.pre_pot = crate::airs::common::u64_to_m31_limbs(canonical.pre.pot);
    row.common.post_pot = crate::airs::common::u64_to_m31_limbs(canonical.post.pot);
    validate_row(public_inputs, &row.to_vec(), METHOD)?;
    super::submit_shuffle_v2::validate_public_inputs(air, public_inputs)
}

/// Bind a verifier-issued reconstruction receipt to the exact VM dispatch and row.
pub(crate) fn validate_submit_reconstruct_deck(
    air: &SubmitReconstructDeckAir,
    public_inputs: &TexasPublicInputs,
) -> TexasAirResult<()> {
    const METHOD: &str = "submit_reconstruct_deck";
    let canonical = validate_canonical_dispatch(public_inputs, MethodKind::SubmitReconstructDeck)?;
    let args: SubmitReconstructDeckArgs =
        borsh::from_slice(&canonical.replay_args).map_err(|error| {
            TexasAirError::SerializationError(format!("{METHOD}: raw args borsh: {error}"))
        })?;
    let MethodInput::SubmitReconstructDeck { seat_index } = &canonical.method_input else {
        return Err(TexasAirError::SpecViolation(
            "submit_reconstruct_deck: replayed task has the wrong MethodInput variant".into(),
        ));
    };
    if *seat_index != args.seat_index {
        return Err(TexasAirError::SpecViolation(
            "submit_reconstruct_deck: replayed MethodInput does not match raw args".into(),
        ));
    }

    let binding = public_inputs.precompile_binding.as_ref().ok_or_else(|| {
        TexasAirError::SpecViolation(
            "submit_reconstruct_deck requires a verifier-issued precompile binding".into(),
        )
    })?;
    let input = SubmitReconstructDeckInput {
        seat_index: args.seat_index,
        reconstruct_phase: canonical.pre.reconstruct_phase(),
        precompile: binding.air_binding(),
    };
    if air.input.seat_index != input.seat_index
        || air.input.reconstruct_phase != input.reconstruct_phase
        || air.input.precompile != input.precompile
    {
        return Err(TexasAirError::SpecViolation(
            "submit_reconstruct_deck: AIR input does not match the canonical dispatch".into(),
        ));
    }

    let mut row = SubmitReconstructDeckRow::active(
        &input,
        state_root_to_air_limbs(public_inputs.pre_state_root),
        state_root_to_air_limbs(public_inputs.post_state_root),
        public_inputs.table_id,
        public_inputs.hand_id,
        public_inputs.call_seq,
        u64::from(canonical.pre.call_seq),
        u64::from(canonical.post.call_seq),
    );
    row.common.pre_pot = crate::airs::common::u64_to_m31_limbs(canonical.pre.pot);
    row.common.post_pot = crate::airs::common::u64_to_m31_limbs(canonical.post.pot);
    validate_row(public_inputs, &row.to_vec(), METHOD)?;
    super::submit_reconstruct_deck::validate_public_inputs(air, public_inputs)
}

fn reveal_version_increment(
    pre: &poker_l1::contracts::texas_poker::types::TexasPokerTable,
    post: &poker_l1::contracts::texas_poker::types::TexasPokerTable,
) -> TexasAirResult<u8> {
    let expected_post_version = u64::from(pre.call_seq).checked_add(1).ok_or_else(|| {
        TexasAirError::SpecViolation("submit_player_reveal_tokens: pre-version overflow".into())
    })?;
    if u64::from(post.call_seq) != expected_post_version {
        return Err(TexasAirError::SpecViolation(format!(
            "submit_player_reveal_tokens: expected one external-command version increment to {expected_post_version}, got {}",
            u64::from(post.call_seq)
        )));
    }
    Ok(1)
}

fn count_as_u8(count: usize, method: &str, field: &str) -> TexasAirResult<u8> {
    u8::try_from(count).map_err(|_| {
        TexasAirError::SpecViolation(format!("{method}: {field} count {count} exceeds u8"))
    })
}
