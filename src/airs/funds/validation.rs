//! Production verifier-side reconstruction for funds AIRs.
//!
//! A Fiat-Shamir-bound state root and a separately bound business row are not
//! enough: without canonical replay, both can be individually valid while
//! describing different transitions. These validators decode the complete
//! pre/post table images, replay the native funds state machine, and rebuild
//! the exact row accepted by the AIR.

use poker_l1::contracts::texas_poker::state_machine;
use poker_l1::contracts::texas_poker::types::TexasPokerTable;
use stwo::core::fields::m31::M31;

use super::addon::{AddonAir, AddonInput, AddonRow};
use super::rebuy::{RebuyAir, RebuyInput, RebuyRow};
use crate::error::{TexasAirError, TexasAirResult};
use crate::method_kind::MethodKind;
use crate::public_inputs::TexasPublicInputs;
use crate::state_root::{state_root_to_air_limbs, table_from_state_preimage};

#[derive(Debug, Clone, Copy)]
enum FundsAction {
    Addon { seat_index: u8, amount: u64 },
    Rebuy { seat_index: u8, amount: u64 },
}

impl FundsAction {
    const fn method_name(self) -> &'static str {
        match self {
            Self::Addon { .. } => "addon",
            Self::Rebuy { .. } => "rebuy",
        }
    }

    const fn kind(self) -> MethodKind {
        match self {
            Self::Addon { .. } => MethodKind::Addon,
            Self::Rebuy { .. } => MethodKind::Rebuy,
        }
    }
}

struct ValidatedFundsTables {
    pre: TexasPokerTable,
    post: TexasPokerTable,
}

fn validate_native_funds_transition(
    public_inputs: &TexasPublicInputs,
    action: FundsAction,
) -> TexasAirResult<ValidatedFundsTables> {
    let method = action.method_name();
    if public_inputs.kind != action.kind() {
        return Err(TexasAirError::SpecViolation(format!(
            "{method}: public-input method kind mismatch"
        )));
    }

    let pre = table_from_state_preimage(&public_inputs.pre_image)?;
    let post = table_from_state_preimage(&public_inputs.post_image)?;
    if pre.id != post.id
        || public_inputs.table_id != pre.id.creation_nonce
        || public_inputs.table_id != post.id.creation_nonce
        || public_inputs.pre_version != u64::from(pre.call_seq)
        || public_inputs.post_version != u64::from(post.call_seq)
        || public_inputs.hand_id != pre.hand_id
        || public_inputs.hand_id != post.hand_id
        || public_inputs.call_seq != post.call_seq
    {
        return Err(TexasAirError::SpecViolation(format!(
            "{method}: public metadata does not match canonical pre/post tables"
        )));
    }

    let expected_call_seq = pre.call_seq.checked_add(1).ok_or_else(|| {
        TexasAirError::SpecViolation(format!("{method}: call_seq overflow during VM replay"))
    })?;
    if post.call_seq != expected_call_seq {
        return Err(TexasAirError::SpecViolation(format!(
            "{method}: post call_seq must equal pre call_seq + 1"
        )));
    }

    let mut replay = pre.clone();
    let mut events = Vec::new();
    let result = match action {
        FundsAction::Addon { seat_index, amount } => {
            state_machine::apply_addon(&mut replay, seat_index, amount, &mut events)
        }
        FundsAction::Rebuy { seat_index, amount } => {
            state_machine::apply_rebuy(&mut replay, seat_index, amount, &mut events)
        }
    };
    result.map_err(|error| {
        TexasAirError::SpecViolation(format!(
            "{method}: canonical pre-state cannot execute native VM action: {error}"
        ))
    })?;

    // `dispatch` advances sequence metadata after the state-machine helper.
    replay.call_seq = expected_call_seq;
    replay.hand_id = pre.hand_id;
    if replay != post {
        return Err(TexasAirError::SpecViolation(format!(
            "{method}: canonical post-table differs from native VM replay"
        )));
    }

    Ok(ValidatedFundsTables { pre, post })
}

fn validate_row(
    public_inputs: &TexasPublicInputs,
    expected_row: &[M31],
    method: &str,
) -> TexasAirResult<()> {
    let trusted_row = public_inputs.require_expected_trace_row(expected_row.len())?;
    if trusted_row != expected_row {
        return Err(TexasAirError::SpecViolation(format!(
            "{method}: trusted trace row was not reconstructed from canonical public inputs"
        )));
    }
    Ok(())
}

/// Replay canonical `addon` semantics and reconstruct its complete trusted row.
pub(crate) fn validate_addon(
    air: &AddonAir,
    public_inputs: &TexasPublicInputs,
) -> TexasAirResult<()> {
    let input = AddonInput {
        seat_index: air.input.seat_index,
        amount: air.input.amount,
    };
    let tables = validate_native_funds_transition(
        public_inputs,
        FundsAction::Addon {
            seat_index: input.seat_index,
            amount: input.amount,
        },
    )?;
    let pre_seat = tables
        .pre
        .seats
        .get(usize::from(input.seat_index))
        .ok_or_else(|| {
            TexasAirError::SpecViolation(format!(
                "addon: seat_index {} is outside canonical table",
                input.seat_index
            ))
        })?;
    let mut row = AddonRow::active(
        &input,
        pre_seat.pending_addon(),
        tables.pre.chip_pool,
        tables.post.chip_pool,
        state_root_to_air_limbs(public_inputs.pre_state_root),
        state_root_to_air_limbs(public_inputs.post_state_root),
        public_inputs.table_id,
        public_inputs.hand_id,
        public_inputs.call_seq,
        u64::from(tables.pre.call_seq),
        u64::from(tables.post.call_seq),
        tables.pre.round_state(),
        tables.post.round_state(),
    );
    row.common.pre_pot = crate::airs::common::u64_to_m31_limbs(tables.pre.pot);
    row.common.post_pot = crate::airs::common::u64_to_m31_limbs(tables.post.pot);
    validate_row(public_inputs, &row.to_vec(), "addon")
}

/// Replay canonical `rebuy` semantics and reconstruct its complete trusted row.
pub(crate) fn validate_rebuy(
    air: &RebuyAir,
    public_inputs: &TexasPublicInputs,
) -> TexasAirResult<()> {
    let input = RebuyInput {
        seat_index: air.input.seat_index,
        amount: air.input.amount,
    };
    let tables = validate_native_funds_transition(
        public_inputs,
        FundsAction::Rebuy {
            seat_index: input.seat_index,
            amount: input.amount,
        },
    )?;
    let pre_seat = tables
        .pre
        .seats
        .get(usize::from(input.seat_index))
        .ok_or_else(|| {
            TexasAirError::SpecViolation(format!(
                "rebuy: seat_index {} is outside canonical table",
                input.seat_index
            ))
        })?;
    let mut row = RebuyRow::active(
        &input,
        pre_seat.stack(),
        tables.pre.chip_pool,
        tables.post.chip_pool,
        state_root_to_air_limbs(public_inputs.pre_state_root),
        state_root_to_air_limbs(public_inputs.post_state_root),
        public_inputs.table_id,
        public_inputs.hand_id,
        public_inputs.call_seq,
        u64::from(tables.pre.call_seq),
        u64::from(tables.post.call_seq),
        tables.pre.round_state(),
        tables.post.round_state(),
    );
    row.common.pre_pot = crate::airs::common::u64_to_m31_limbs(tables.pre.pot);
    row.common.post_pot = crate::airs::common::u64_to_m31_limbs(tables.post.pot);
    validate_row(public_inputs, &row.to_vec(), "rebuy")
}
