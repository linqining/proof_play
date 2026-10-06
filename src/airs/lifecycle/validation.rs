//! Production verifier-side reconstruction for lifecycle AIRs.
//!
//! Lifecycle statements bind full table roots and a replicated business row,
//! but roots and rows must also describe the exact authenticated VM call.  The
//! helpers here verify the dispatch-call preimage against its transcript-bound
//! digest, replay native Texas Poker dispatch, compare the complete post table,
//! and finally rebuild the row accepted by each AIR.

use poker_l1::contracts::texas_poker::dispatch::{JoinTableArgs, LeaveTableArgs};
use stwo::core::fields::m31::M31;

use super::join_table::{JoinTableAir, JoinTableInput, JoinTableRow};
use super::leave_table::{LeaveTableAir, LeaveTableInput, LeaveTableRow};
use super::start_hand::{StartHandAir, StartHandInput, StartHandRow};
use crate::airs::validation::{validate_canonical_dispatch, validate_row};
use crate::authorization_binding::AdminAuthorizationBinding;
use crate::error::{TexasAirError, TexasAirResult};
use crate::method_kind::MethodKind;
use crate::prove_task::MethodInput;
use crate::public_inputs::TexasPublicInputs;
use crate::state_root::state_root_to_air_limbs;

/// Replay canonical `start_hand` and reconstruct its complete trusted row.
pub(crate) fn validate_start_hand(
    air: &StartHandAir,
    public_inputs: &TexasPublicInputs,
) -> TexasAirResult<()> {
    const METHOD: &str = "start_hand";
    let canonical = validate_canonical_dispatch(public_inputs, MethodKind::StartHand)?;
    if !matches!(canonical.method_input, MethodInput::Empty) {
        return Err(TexasAirError::SpecViolation(
            "start_hand: replayed task has the wrong MethodInput variant".into(),
        ));
    }

    let active_count = u8::try_from(
        canonical
            .pre
            .seats
            .iter()
            .filter(|seat| seat.is_occupied())
            .count(),
    )
    .map_err(|_| TexasAirError::SpecViolation("start_hand: active count exceeds u8".into()))?;
    let ante_collected = canonical
        .post
        .pot
        .checked_sub(canonical.pre.pot)
        .ok_or_else(|| {
            TexasAirError::SpecViolation(
                "start_hand: canonical pot decreased while collecting ante".into(),
            )
        })?;
    let input = StartHandInput {
        active_count,
        new_button: canonical.post.button,
        ante_mode: canonical.post.ante_mode,
        ante_amount: canonical.post.ante_amount,
        ante_collected,
        pre_pot: canonical.pre.pot,
        post_pot: canonical.post.pot,
        authorization: AdminAuthorizationBinding::verify_table_creator(
            MethodKind::StartHand,
            &canonical.call.context,
            &canonical.call.selector,
            &canonical.call.raw_args,
            canonical.pre.creator,
            public_inputs.table_id,
            public_inputs.hand_id,
            public_inputs.call_seq,
            u64::from(canonical.pre.call_seq),
            u64::from(canonical.post.call_seq),
            public_inputs.pre_state_root,
            public_inputs.post_state_root,
            public_inputs.dispatch_call_digest,
        )?
        .air_binding(),
    };
    if air.input.active_count != input.active_count
        || air.input.new_button != input.new_button
        || air.input.ante_mode != input.ante_mode
        || air.input.ante_amount != input.ante_amount
        || air.input.ante_collected != input.ante_collected
        || air.input.pre_pot != input.pre_pot
        || air.input.post_pot != input.post_pot
        || air.input.authorization != input.authorization
    {
        return Err(TexasAirError::SpecViolation(
            "start_hand: AIR input does not match the canonical dispatch".into(),
        ));
    }

    let count = M31::from(u32::from(active_count));
    let count_product = count * (count - M31::from(1u32));
    let row = StartHandRow::active(
        &input,
        count_product.inverse(),
        count_product,
        state_root_to_air_limbs(public_inputs.pre_state_root),
        state_root_to_air_limbs(public_inputs.post_state_root),
        public_inputs.table_id,
        public_inputs.hand_id,
        public_inputs.call_seq,
        u64::from(canonical.pre.call_seq),
        u64::from(canonical.post.call_seq),
    );
    validate_row(public_inputs, &row.to_vec(), METHOD)
}

/// Replay canonical `join_table` and reconstruct its complete trusted row.
pub(crate) fn validate_join_table(
    air: &JoinTableAir,
    public_inputs: &TexasPublicInputs,
) -> TexasAirResult<()> {
    const METHOD: &str = "join_table";
    let canonical = validate_canonical_dispatch(public_inputs, MethodKind::JoinTable)?;
    let args: JoinTableArgs = borsh::from_slice(&canonical.replay_args).map_err(|error| {
        TexasAirError::SerializationError(format!("{METHOD}: raw args borsh: {error}"))
    })?;
    let MethodInput::Join { player, buy_in } = canonical.method_input else {
        return Err(TexasAirError::SpecViolation(
            "join_table: replayed task has the wrong MethodInput variant".into(),
        ));
    };
    if player != args.player || buy_in != args.buy_in {
        return Err(TexasAirError::SpecViolation(
            "join_table: replayed MethodInput does not match raw args".into(),
        ));
    }

    let seat_index = canonical.pre.find_empty_seat().ok_or_else(|| {
        TexasAirError::SpecViolation("join_table: canonical pre-table has no empty seat".into())
    })?;
    if air.input.seat_index != seat_index
        || air.input.player_addr != args.player
        || air.input.buy_in != args.buy_in
    {
        return Err(TexasAirError::SpecViolation(
            "join_table: AIR input does not match the canonical dispatch".into(),
        ));
    }
    let post_seat = canonical
        .post
        .seats
        .get(usize::from(seat_index))
        .ok_or_else(|| TexasAirError::SpecViolation("join_table: post seat missing".into()))?;
    if post_seat.player() != args.player || post_seat.stack() != args.buy_in {
        return Err(TexasAirError::SpecViolation(
            "join_table: canonical post seat does not match the dispatch args".into(),
        ));
    }

    let input = JoinTableInput {
        seat_index,
        buy_in: args.buy_in,
        player_addr: args.player,
    };
    let mut row = JoinTableRow::active(
        &input,
        state_root_to_air_limbs(public_inputs.pre_state_root),
        state_root_to_air_limbs(public_inputs.post_state_root),
        public_inputs.table_id,
        public_inputs.hand_id,
        public_inputs.call_seq,
        u64::from(canonical.pre.call_seq),
        u64::from(canonical.post.call_seq),
        canonical.pre.big_blind,
        canonical.pre.chip_pool,
    );
    row.common.pre_pot = crate::airs::common::u64_to_m31_limbs(canonical.pre.pot);
    row.common.post_pot = crate::airs::common::u64_to_m31_limbs(canonical.post.pot);
    validate_row(public_inputs, &row.to_vec(), METHOD)
}

/// Replay canonical `leave_table` and reconstruct its complete trusted row.
pub(crate) fn validate_leave_table(
    air: &LeaveTableAir,
    public_inputs: &TexasPublicInputs,
) -> TexasAirResult<()> {
    const METHOD: &str = "leave_table";
    let canonical = validate_canonical_dispatch(public_inputs, MethodKind::LeaveTable)?;
    let args: LeaveTableArgs = borsh::from_slice(&canonical.replay_args).map_err(|error| {
        TexasAirError::SerializationError(format!("{METHOD}: raw args borsh: {error}"))
    })?;
    let MethodInput::SeatOnly { seat_index } = canonical.method_input else {
        return Err(TexasAirError::SpecViolation(
            "leave_table: replayed task has the wrong MethodInput variant".into(),
        ));
    };
    if seat_index != args.seat_index || air.input.seat_index != args.seat_index {
        return Err(TexasAirError::SpecViolation(
            "leave_table: AIR/task seat index does not match raw args".into(),
        ));
    }
    let pre_seat = canonical
        .pre
        .seats
        .get(usize::from(args.seat_index))
        .ok_or_else(|| TexasAirError::SpecViolation("leave_table: pre seat missing".into()))?;

    let input = LeaveTableInput {
        seat_index: args.seat_index,
    };
    let mut row = LeaveTableRow::active(
        &input,
        state_root_to_air_limbs(public_inputs.pre_state_root),
        state_root_to_air_limbs(public_inputs.post_state_root),
        public_inputs.table_id,
        public_inputs.hand_id,
        public_inputs.call_seq,
        u64::from(canonical.pre.call_seq),
        u64::from(canonical.post.call_seq),
        pre_seat.stack(),
        pre_seat.pending_addon(),
        canonical.pre.chip_pool,
        canonical.post.chip_pool,
    );
    row.common.pre_pot = crate::airs::common::u64_to_m31_limbs(canonical.pre.pot);
    row.common.post_pot = crate::airs::common::u64_to_m31_limbs(canonical.post.pot);
    validate_row(public_inputs, &row.to_vec(), METHOD)
}
