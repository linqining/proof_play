//! Production verifier-side reconstruction for betting action AIRs.
//!
//! The state roots and a complete trace row are Fiat-Shamir bound, but that is
//! insufficient if both are supplied independently: a malicious prover could
//! commit to real table roots and a different, self-consistent action row. This
//! module decodes the canonical table preimages, replays the native VM action,
//! and reconstructs the exact AIR row before Stwo verification.

use poker_l1::contracts::texas_poker::constants::FOLD_REASON_FORCE_ADMIN;
use poker_l1::contracts::texas_poker::dispatch::SeatIndexArgs;
use poker_l1::contracts::texas_poker::state_machine;
use poker_l1::contracts::texas_poker::types::{Seat, TexasPokerTable};
use stwo::core::fields::m31::M31;

use super::bet::{BetAir, BetRow};
use super::call::{CallAir, CallRow};
use super::check::{CheckAir, CheckRow};
use super::end_betting_round::derive_betting_outcome;
use super::end_without_showdown::derive_fold_outcome;
use super::fold::{FoldAir, FoldRow};
use super::force_fold::{ForceFoldAir, ForceFoldRow};
use super::kick_player::{KickPlayerAir, KickPlayerInput, KickPlayerRow};
use super::raise::{RaiseAir, RaiseRow};
use super::set_leave_after_hand::{SetLeaveAfterHandAir, SetLeaveAfterHandRow};
use crate::airs::validation::{
    validate_canonical_dispatch, validate_row as validate_canonical_row,
};
use crate::authorization_binding::AdminAuthorizationBinding;
use crate::error::{TexasAirError, TexasAirResult};
use crate::method_kind::MethodKind;
use crate::prove_task::MethodInput;
use crate::public_inputs::TexasPublicInputs;
use crate::state_root::{state_root_to_air_limbs, table_from_state_preimage};

#[derive(Debug, Clone, Copy)]
enum NativeAction {
    Fold { seat_index: u8 },
    Check { seat_index: u8 },
    Call { seat_index: u8 },
    Raise { seat_index: u8, total_bet: u64 },
    Bet { seat_index: u8, amount: u64 },
    ForceFold { seat_index: u8 },
}

impl NativeAction {
    const fn name(self) -> &'static str {
        match self {
            Self::Fold { .. } => "fold",
            Self::Check { .. } => "check",
            Self::Call { .. } => "call",
            Self::Raise { .. } => "raise",
            Self::Bet { .. } => "bet",
            Self::ForceFold { .. } => "force_fold",
        }
    }

    const fn seat_index(self) -> u8 {
        match self {
            Self::Fold { seat_index }
            | Self::Check { seat_index }
            | Self::Call { seat_index }
            | Self::Raise { seat_index, .. }
            | Self::Bet { seat_index, .. }
            | Self::ForceFold { seat_index } => seat_index,
        }
    }
}

struct ValidatedTables {
    pre: TexasPokerTable,
    post: TexasPokerTable,
    composition: crate::airs::composition::CompositeTransitionPlan,
}

fn validate_native_mid_round(
    public_inputs: &TexasPublicInputs,
    expected_kind: MethodKind,
    action: NativeAction,
    allow_round_completion: bool,
) -> TexasAirResult<ValidatedTables> {
    let method = action.name();
    if public_inputs.kind != expected_kind {
        return Err(TexasAirError::SpecViolation(format!(
            "{method}: public-input method kind mismatch"
        )));
    }

    let pre = table_from_state_preimage(&public_inputs.pre_image)?;
    let post = table_from_state_preimage(&public_inputs.post_image)?;
    if public_inputs.pre_version != u64::from(pre.call_seq)
        || public_inputs.post_version != u64::from(post.call_seq)
        || public_inputs.table_id != pre.id.creation_nonce
        || public_inputs.table_id != post.id.creation_nonce
        || public_inputs.hand_id != post.hand_id
        || public_inputs.call_seq != post.call_seq
        || pre.hand_id != post.hand_id
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
        NativeAction::Fold { seat_index } => {
            state_machine::apply_fold(&mut replay, seat_index, &mut events)
        }
        NativeAction::Check { seat_index } => {
            state_machine::apply_check(&mut replay, seat_index, &mut events)
        }
        NativeAction::Call { seat_index } => {
            state_machine::apply_call(&mut replay, seat_index, &mut events)
        }
        NativeAction::Raise {
            seat_index,
            total_bet,
        } => state_machine::apply_raise(&mut replay, seat_index, total_bet, &mut events),
        NativeAction::Bet { seat_index, amount } => {
            state_machine::apply_bet(&mut replay, seat_index, amount, &mut events)
        }
        NativeAction::ForceFold { seat_index } => state_machine::apply_fold_internal(
            &mut replay,
            seat_index,
            FOLD_REASON_FORCE_ADMIN,
            &mut events,
        ),
    };
    result.map_err(|error| {
        TexasAirError::SpecViolation(format!(
            "{method}: canonical pre-state cannot execute native VM action: {error}"
        ))
    })?;

    let normalization_time = public_inputs
        .require_dispatch_call()?
        .context
        .block_timestamp;
    state_machine::normalize_until_blocked(&mut replay, normalization_time, &mut events).map_err(
        |error| {
            TexasAirError::SpecViolation(format!(
                "{method}: deterministic normalization replay failed: {error}"
            ))
        },
    )?;

    // dispatch() advances sequence metadata outside the state-machine helper.
    replay.call_seq = expected_call_seq;
    replay.hand_id = pre.hand_id;
    if replay != post {
        return Err(TexasAirError::SpecViolation(format!(
            "{method}: canonical post-table differs from native VM replay"
        )));
    }

    // Reconstruct the normalized four-stage plan from the same native replay.
    // Existing method rows remain the proof entry point during migration, but
    // every production action verification now also passes the shared component
    // ABI and event-consistency checks.
    let composition = crate::airs::composition::derive_composite_transition_plan(
        expected_kind,
        &pre,
        &post,
        Some(action.seat_index()),
        &events,
    )?;

    let completes_betting_round = post.round_state() != pre.round_state()
        || post.betting_round().is_none()
        || post.pot != pre.pot;
    if pre.betting_round().is_none() || (completes_betting_round && !allow_round_completion) {
        return Err(TexasAirError::UnsupportedBettingTransition(format!(
            "{method} triggered an unsupported betting-round completion; this AIR only accepts the canonical mid-round branch or its explicitly modeled clean collection branch"
        )));
    }

    Ok(ValidatedTables {
        pre,
        post,
        composition,
    })
}

fn seat<'a>(table: &'a TexasPokerTable, seat_index: u8, method: &str) -> TexasAirResult<&'a Seat> {
    table.seats.get(usize::from(seat_index)).ok_or_else(|| {
        TexasAirError::SpecViolation(format!(
            "{method}: seat_index {seat_index} is outside canonical table"
        ))
    })
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

pub(crate) fn validate_fold(
    air: &FoldAir,
    public_inputs: &TexasPublicInputs,
) -> TexasAirResult<()> {
    let tables = validate_native_mid_round(
        public_inputs,
        MethodKind::Fold,
        NativeAction::Fold {
            seat_index: air.input.seat_index,
        },
        true,
    )?;
    let expected_outcome = derive_fold_outcome(
        &tables.pre,
        &tables.post,
        air.input.seat_index,
        "fold",
        Some(&tables.composition.settlement),
    )?;
    if air.input.outcome != expected_outcome {
        return Err(TexasAirError::SpecViolation(
            "fold: AIR outcome does not match the canonical dispatch".into(),
        ));
    }
    let row = FoldRow::active(
        &air.input,
        state_root_to_air_limbs(public_inputs.pre_state_root),
        state_root_to_air_limbs(public_inputs.post_state_root),
        public_inputs.table_id,
        public_inputs.hand_id,
        public_inputs.call_seq,
        u64::from(tables.pre.call_seq),
        u64::from(tables.post.call_seq),
        tables.pre.round_state(),
        tables.post.round_state(),
        tables.pre.pot,
        tables.post.pot,
    );
    validate_row(public_inputs, &row.to_vec(), "fold")
}

pub(crate) fn validate_check(
    air: &CheckAir,
    public_inputs: &TexasPublicInputs,
) -> TexasAirResult<()> {
    let tables = validate_native_mid_round(
        public_inputs,
        MethodKind::Check,
        NativeAction::Check {
            seat_index: air.input.seat_index,
        },
        true,
    )?;
    let pre_seat = seat(&tables.pre, air.input.seat_index, "check")?;
    let pre_round = tables.pre.betting_round().expect("mid-round checked");
    let outcome = derive_betting_outcome(&tables.pre, &tables.post, 0, "check")?;
    if air.input.current_bet != pre_round.current_bet
        || air.input.seat_bet != pre_seat.bet()
        || air.input.outcome != outcome
    {
        return Err(TexasAirError::SpecViolation(
            "check: AIR input does not match canonical table fields".into(),
        ));
    }
    let row = CheckRow::active(
        &air.input,
        state_root_to_air_limbs(public_inputs.pre_state_root),
        state_root_to_air_limbs(public_inputs.post_state_root),
        public_inputs.table_id,
        public_inputs.hand_id,
        public_inputs.call_seq,
        u64::from(tables.pre.call_seq),
        u64::from(tables.post.call_seq),
        tables.pre.round_state(),
        tables.post.round_state(),
        tables.pre.pot,
        tables.post.pot,
    );
    validate_row(public_inputs, &row.to_vec(), "check")
}

pub(crate) fn validate_call(
    air: &CallAir,
    public_inputs: &TexasPublicInputs,
) -> TexasAirResult<()> {
    let tables = validate_native_mid_round(
        public_inputs,
        MethodKind::Call,
        NativeAction::Call {
            seat_index: air.input.seat_index,
        },
        true,
    )?;
    let pre_seat = seat(&tables.pre, air.input.seat_index, "call")?;
    let post_seat = seat(&tables.post, air.input.seat_index, "call")?;
    let pre_round = tables.pre.betting_round().expect("mid-round checked");
    let call_amount = pre_round.process_call(pre_seat.bet(), pre_seat.stack());
    let outcome = derive_betting_outcome(&tables.pre, &tables.post, call_amount, "call")?;
    let action_post_bet = pre_seat
        .bet()
        .checked_add(call_amount)
        .ok_or_else(|| TexasAirError::SpecViolation("call: action seat.bet() overflow".into()))?;
    if air.input.call_amount != call_amount
        || air.input.pre_current_bet != pre_round.current_bet
        || air.input.pre_seat_bet != pre_seat.bet()
        || air.input.pre_seat_stack != pre_seat.stack()
        || air.input.pre_seat_total_bet != pre_seat.total_bet()
        || air.input.outcome != outcome
    {
        return Err(TexasAirError::SpecViolation(
            "call: AIR input does not match canonical table fields".into(),
        ));
    }
    let row = CallRow::active(
        &air.input,
        state_root_to_air_limbs(public_inputs.pre_state_root),
        state_root_to_air_limbs(public_inputs.post_state_root),
        public_inputs.table_id,
        public_inputs.hand_id,
        public_inputs.call_seq,
        u64::from(tables.pre.call_seq),
        u64::from(tables.post.call_seq),
        tables.pre.round_state(),
        tables.post.round_state(),
        tables.pre.pot,
        tables.post.pot,
        post_seat.stack(),
        action_post_bet,
        post_seat.is_all_in(),
        pre_seat.bet(),
        pre_seat.stack(),
        post_seat.total_bet(),
        pre_seat.total_bet(),
    );
    validate_row(public_inputs, &row.to_vec(), "call")
}

pub(crate) fn validate_raise(
    air: &RaiseAir,
    public_inputs: &TexasPublicInputs,
) -> TexasAirResult<()> {
    let tables = validate_native_mid_round(
        public_inputs,
        MethodKind::Raise,
        NativeAction::Raise {
            seat_index: air.input.seat_index,
            total_bet: air.input.raise_to,
        },
        true,
    )?;
    let pre_seat = seat(&tables.pre, air.input.seat_index, "raise")?;
    let post_seat = seat(&tables.post, air.input.seat_index, "raise")?;
    let pre_round = tables.pre.betting_round().expect("mid-round checked");
    let action_delta = air
        .input
        .raise_to
        .checked_sub(pre_seat.bet())
        .ok_or_else(|| TexasAirError::SpecViolation("raise: action bet decreased".into()))?;
    let mut action_round = pre_round;
    action_round
        .process_raise(air.input.raise_to, pre_seat.bet(), pre_seat.stack())
        .map_err(|error| {
            TexasAirError::SpecViolation(format!(
                "raise: cannot reconstruct action-round state: {error}"
            ))
        })?;
    let outcome = derive_betting_outcome(&tables.pre, &tables.post, action_delta, "raise")?;
    if air.input.min_raise != pre_round.min_raise
        || air.input.pre_current_bet != pre_round.current_bet
        || air.input.pre_seat_stack != pre_seat.stack()
        || air.input.pre_seat_bet != pre_seat.bet()
        || air.input.pre_seat_total_bet != pre_seat.total_bet()
        || air.input.outcome != outcome
    {
        return Err(TexasAirError::SpecViolation(
            "raise: AIR input does not match canonical table fields".into(),
        ));
    }
    let row = RaiseRow::active(
        &air.input,
        state_root_to_air_limbs(public_inputs.pre_state_root),
        state_root_to_air_limbs(public_inputs.post_state_root),
        public_inputs.table_id,
        public_inputs.hand_id,
        public_inputs.call_seq,
        u64::from(tables.pre.call_seq),
        u64::from(tables.post.call_seq),
        tables.pre.round_state(),
        tables.post.round_state(),
        tables.pre.pot,
        tables.post.pot,
        pre_seat.stack(),
        pre_seat.bet(),
        pre_seat.total_bet(),
        post_seat.stack(),
        air.input.raise_to,
        post_seat.total_bet(),
        action_round.current_bet,
        action_round.min_raise,
        post_seat.is_all_in(),
    );
    validate_row(public_inputs, &row.to_vec(), "raise")
}

pub(crate) fn validate_bet(air: &BetAir, public_inputs: &TexasPublicInputs) -> TexasAirResult<()> {
    let tables = validate_native_mid_round(
        public_inputs,
        MethodKind::Bet,
        NativeAction::Bet {
            seat_index: air.input.seat_index,
            amount: air.input.amount,
        },
        true,
    )?;
    let pre_seat = seat(&tables.pre, air.input.seat_index, "bet")?;
    let post_seat = seat(&tables.post, air.input.seat_index, "bet")?;
    let pre_round = tables.pre.betting_round().expect("mid-round checked");
    let action_post_bet = pre_seat
        .bet()
        .checked_add(air.input.amount)
        .ok_or_else(|| TexasAirError::SpecViolation("bet: action seat.bet() overflow".into()))?;
    let mut action_round = pre_round;
    action_round
        .process_raise(action_post_bet, pre_seat.bet(), pre_seat.stack())
        .map_err(|error| {
            TexasAirError::SpecViolation(format!(
                "bet: cannot reconstruct action-round state: {error}"
            ))
        })?;
    let outcome = derive_betting_outcome(&tables.pre, &tables.post, air.input.amount, "bet")?;
    if air.input.pre_current_bet != pre_round.current_bet
        || air.input.pre_min_raise != pre_round.min_raise
        || air.input.pre_seat_bet != pre_seat.bet()
        || air.input.pre_seat_stack != pre_seat.stack()
        || air.input.pre_seat_total_bet != pre_seat.total_bet()
        || air.input.outcome != outcome
    {
        return Err(TexasAirError::SpecViolation(
            "bet: AIR input does not match canonical table fields".into(),
        ));
    }
    let row = BetRow::active(
        &air.input,
        state_root_to_air_limbs(public_inputs.pre_state_root),
        state_root_to_air_limbs(public_inputs.post_state_root),
        public_inputs.table_id,
        public_inputs.hand_id,
        public_inputs.call_seq,
        u64::from(tables.pre.call_seq),
        u64::from(tables.post.call_seq),
        tables.pre.round_state(),
        tables.post.round_state(),
        tables.pre.pot,
        tables.post.pot,
        action_post_bet,
        pre_seat.bet(),
        pre_seat.stack(),
        post_seat.stack(),
        pre_seat.total_bet(),
        post_seat.total_bet(),
    );
    validate_row(public_inputs, &row.to_vec(), "bet")
}

pub(crate) fn validate_force_fold(
    air: &ForceFoldAir,
    public_inputs: &TexasPublicInputs,
) -> TexasAirResult<()> {
    let canonical = validate_canonical_dispatch(public_inputs, MethodKind::ForceFold)?;
    let authorization = AdminAuthorizationBinding::verify_table_creator(
        MethodKind::ForceFold,
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
    .air_binding();
    let tables = validate_native_mid_round(
        public_inputs,
        MethodKind::ForceFold,
        NativeAction::ForceFold {
            seat_index: air.input.seat_index,
        },
        true,
    )?;
    let expected_outcome = derive_fold_outcome(
        &tables.pre,
        &tables.post,
        air.input.seat_index,
        "force_fold",
        Some(&tables.composition.settlement),
    )?;
    if air.input.outcome != expected_outcome || air.input.authorization != authorization {
        return Err(TexasAirError::SpecViolation(
            "force_fold: AIR input/authorization does not match canonical dispatch".into(),
        ));
    }
    let mut row = ForceFoldRow::active(
        &air.input,
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
    validate_row(public_inputs, &row.to_vec(), "force_fold")
}

/// Replay the complete administrator dispatch and reconstruct the exact kick row.
pub(crate) fn validate_kick_player(
    air: &KickPlayerAir,
    public_inputs: &TexasPublicInputs,
) -> TexasAirResult<()> {
    const METHOD: &str = "kick_player_v2";
    let canonical = validate_canonical_dispatch(public_inputs, MethodKind::KickPlayer)?;
    let args: SeatIndexArgs = borsh::from_slice(&canonical.replay_args).map_err(|error| {
        TexasAirError::SerializationError(format!("{METHOD}: raw args borsh: {error}"))
    })?;
    let MethodInput::Kick { seat_index } = canonical.method_input else {
        return Err(TexasAirError::SpecViolation(
            "kick_player: replayed task has the wrong MethodInput variant".into(),
        ));
    };
    if seat_index != args.seat_index {
        return Err(TexasAirError::SpecViolation(
            "kick_player_v2: replayed MethodInput does not match raw args".into(),
        ));
    }

    let pre_seat = seat(&canonical.pre, args.seat_index, METHOD)?;
    let expected_post_pot = canonical
        .pre
        .pot
        .checked_add(pre_seat.bet())
        .ok_or_else(|| TexasAirError::SpecViolation("kick_player: pot overflow".into()))?;
    let expected_version = u64::from(canonical.pre.call_seq)
        .checked_add(1)
        .ok_or_else(|| TexasAirError::SpecViolation("kick_player: pre-version overflow".into()))?;
    if u64::from(canonical.post.call_seq) != expected_version {
        return Err(TexasAirError::UnsupportedBettingTransition(
            "kick_player must increment the external-command version exactly once".into(),
        ));
    }
    let version_increment = 1;
    let reset_cascade = if canonical.post.round_state()
        == poker_l1::contracts::texas_poker::constants::ROUND_WAITING
        && canonical.post.pot == 0
    {
        let composition =
            crate::airs::composition::plan::derive_composite_transition_plan_from_public_inputs(
                public_inputs,
            )?;
        composition.settlement.active
            && composition.settlement.reset_applied
            && match composition.settlement.kind {
                crate::airs::composition::SettlementKind::WithoutShowdown => true,
                crate::airs::composition::SettlementKind::ResetOnly => {
                    canonical.pre.round_state()
                        == poker_l1::contracts::texas_poker::constants::ROUND_WAITING
                        && canonical.pre.pot == 0
                        && pre_seat.bet() == 0
                }
                crate::airs::composition::SettlementKind::None
                | crate::airs::composition::SettlementKind::Showdown => false,
            }
    } else {
        false
    };
    let simple = !reset_cascade
        && canonical.post.round_state() == canonical.pre.round_state()
        && canonical.post.pot == expected_post_pot;
    if !simple && !reset_cascade {
        return Err(TexasAirError::UnsupportedBettingTransition(
            "kick_player triggered an unsupported active-hand advance/settlement cascade".into(),
        ));
    }

    let input = KickPlayerInput {
        seat_index: args.seat_index,
        refund: pre_seat
            .stack()
            .checked_add(pre_seat.pending_addon())
            .ok_or_else(|| TexasAirError::SpecViolation("kick_player refund overflow".into()))?,
        pre_stack: pre_seat.stack(),
        pre_pending_addon: pre_seat.pending_addon(),
        kicked_bet: pre_seat.bet(),
        version_increment,
        reset_cascade,
        authorization: AdminAuthorizationBinding::verify_table_creator(
            MethodKind::KickPlayer,
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
    if air.input.seat_index != input.seat_index
        || air.input.refund != input.refund
        || air.input.pre_stack != input.pre_stack
        || air.input.pre_pending_addon != input.pre_pending_addon
        || air.input.kicked_bet != input.kicked_bet
        || air.input.version_increment != input.version_increment
        || air.input.reset_cascade != input.reset_cascade
        || air.input.authorization != input.authorization
    {
        return Err(TexasAirError::SpecViolation(
            "kick_player: AIR input does not match the canonical dispatch".into(),
        ));
    }

    let row = KickPlayerRow::active(
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
    validate_canonical_row(public_inputs, &row.to_vec(), METHOD)
}

/// Reconstruct and bind the complete explicit single-seat update performed by
/// `set_leave_after_hand`.
///
/// The method is valid in every table phase, but must leave every table-level
/// field unchanged apart from the selected occupied seat's `want_leave`, the
/// normal version bump, and dispatch's call sequence bump. Permission is
/// checked by the full dispatch replay in the Orchestrator; the raw state
/// preimages here provide the same canonical-row protection used by betting
/// actions for direct verifier callers.
pub(crate) fn validate_set_leave_after_hand(
    air: &SetLeaveAfterHandAir,
    public_inputs: &TexasPublicInputs,
) -> TexasAirResult<()> {
    const METHOD: &str = "set_leave_after_hand";
    if public_inputs.kind != MethodKind::SetLeaveAfterHand {
        return Err(TexasAirError::SpecViolation(format!(
            "{METHOD}: public-input method kind mismatch"
        )));
    }

    let pre = table_from_state_preimage(&public_inputs.pre_image)?;
    let post = table_from_state_preimage(&public_inputs.post_image)?;
    if public_inputs.pre_version != u64::from(pre.call_seq)
        || public_inputs.post_version != u64::from(post.call_seq)
        || public_inputs.table_id != pre.id.creation_nonce
        || public_inputs.table_id != post.id.creation_nonce
        || public_inputs.hand_id != pre.hand_id
        || public_inputs.hand_id != post.hand_id
        || public_inputs.call_seq != post.call_seq
    {
        return Err(TexasAirError::SpecViolation(format!(
            "{METHOD}: public metadata does not match canonical pre/post tables"
        )));
    }

    let expected_call_seq = pre.call_seq.checked_add(1).ok_or_else(|| {
        TexasAirError::SpecViolation(format!("{METHOD}: call_seq overflow during VM replay"))
    })?;
    if post.call_seq != expected_call_seq {
        return Err(TexasAirError::SpecViolation(format!(
            "{METHOD}: post call_seq must equal pre call_seq + 1"
        )));
    }
    if pre.hand_id != post.hand_id {
        return Err(TexasAirError::SpecViolation(format!(
            "{METHOD}: hand_id must remain unchanged"
        )));
    }

    let pre_seat = seat(&pre, air.input.seat_index, METHOD)?;
    if !pre_seat.is_occupied() {
        return Err(TexasAirError::SpecViolation(format!(
            "{METHOD}: target seat is not occupied"
        )));
    }
    let mut replay = pre.clone();
    let mut events = Vec::new();
    let changed = state_machine::apply_set_leave_after_hand(
        &mut replay,
        air.input.seat_index,
        air.input.want_leave,
        &mut events,
    )
    .map_err(|error| {
        TexasAirError::SpecViolation(format!("{METHOD}: native VM replay failed: {error}"))
    })?;
    if !changed {
        return Err(TexasAirError::SpecViolation(format!(
            "{METHOD}: proof-bearing transition must change want_leave"
        )));
    }
    replay.call_seq = expected_call_seq;
    replay.hand_id = pre.hand_id;
    if replay != post {
        return Err(TexasAirError::SpecViolation(format!(
            "{METHOD}: canonical post-table differs from native VM replay"
        )));
    }

    let _ = seat(&post, air.input.seat_index, METHOD)?;
    if air.input.pre_want_leave != pre.seat_wants_leave(air.input.seat_index)
        || air.input.want_leave != post.seat_wants_leave(air.input.seat_index)
        || air.input.want_leave == air.input.pre_want_leave
    {
        return Err(TexasAirError::SpecViolation(format!(
            "{METHOD}: AIR input does not match canonical explicit want_leave update"
        )));
    }

    let row = SetLeaveAfterHandRow::active(
        &air.input,
        state_root_to_air_limbs(public_inputs.pre_state_root),
        state_root_to_air_limbs(public_inputs.post_state_root),
        public_inputs.table_id,
        public_inputs.hand_id,
        public_inputs.call_seq,
        u64::from(pre.call_seq),
        u64::from(post.call_seq),
        pre.round_state(),
        post.round_state(),
        pre.pot,
        post.pot,
    );
    validate_row(public_inputs, &row.to_vec(), METHOD)
}
