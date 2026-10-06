//! Shared production verifier-side reconstruction for Texas Poker AIRs.
//!
//! Method AIRs bind state roots and a verifier-trusted business row, but those
//! values must also describe the exact authenticated VM dispatch.  This module
//! verifies the transcript-bound dispatch-call preimage, replays native Texas
//! Poker dispatch, compares the complete post table and exposes the canonical
//! task used by method-specific row reconstruction.

use poker_l1::contracts::texas_poker::dispatch::{dispatch, replay_dispatch_args};
use poker_l1::contracts::texas_poker::types::TexasPokerTable;
use stwo::core::fields::m31::M31;

use crate::error::{TexasAirError, TexasAirResult};
use crate::method_kind::MethodKind;
use crate::prove_task::{DispatchOutput, MethodInput};
use crate::public_inputs::{DispatchCallPublicInput, TexasPublicInputs};
use crate::state_root::table_from_state_preimage;

/// Canonical verifier-owned result of replaying one dispatch call.
pub(crate) struct CanonicalDispatch {
    /// Complete table before dispatch.
    pub(crate) pre: TexasPokerTable,
    /// Complete table after dispatch.
    pub(crate) post: TexasPokerTable,
    /// Transcript-bound dispatch context, selector and raw arguments.
    pub(crate) call: DispatchCallPublicInput,
    /// Legacy boundary ABI reconstructed from authenticated canonical command data.
    pub(crate) replay_args: Vec<u8>,
    /// One transient decode of the canonical command payload for stage validators.
    pub(crate) method_input: MethodInput,
    /// Events emitted by the canonical native replay.
    pub(crate) events: Vec<poker_l1::contracts::texas_poker::events::TexasPokerEvent>,
}

/// Replay an exact dispatch call and bind every verifier-controlled task field.
pub(crate) fn validate_canonical_dispatch(
    public_inputs: &TexasPublicInputs,
    expected_kind: MethodKind,
) -> TexasAirResult<CanonicalDispatch> {
    let method = expected_kind.method_name();
    if public_inputs.kind != expected_kind {
        return Err(TexasAirError::SpecViolation(format!(
            "{method}: public-input method kind mismatch"
        )));
    }

    let call = public_inputs.require_dispatch_call()?.clone();
    if call.selector != expected_kind.selector() {
        return Err(TexasAirError::SpecViolation(format!(
            "{method}: dispatch selector does not match method kind"
        )));
    }

    let pre = table_from_state_preimage(&public_inputs.pre_image)?;
    let post = table_from_state_preimage(&public_inputs.post_image)?;
    if pre.id != post.id
        || public_inputs.table_id != pre.id.creation_nonce
        || public_inputs.table_id != post.id.creation_nonce
        || public_inputs.pre_version != u64::from(pre.call_seq)
        || public_inputs.post_version != u64::from(post.call_seq)
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

    let replay_args =
        replay_dispatch_args(expected_kind as u8, &call.raw_args, &call.context, &pre).map_err(
            |error| {
                TexasAirError::SpecViolation(format!(
                    "{method}: canonical command cannot reconstruct dispatch ABI: {error}"
                ))
            },
        )?;
    let mut replay = pre.clone();
    let result =
        dispatch(&call.context, &mut replay, &call.selector, &replay_args).map_err(|error| {
            TexasAirError::SpecViolation(format!(
                "{method}: canonical pre-state cannot execute native VM dispatch: {error}"
            ))
        })?;
    if replay != post {
        return Err(TexasAirError::SpecViolation(format!(
            "{method}: canonical post-table differs from native VM dispatch replay"
        )));
    }

    let output: DispatchOutput = borsh::from_slice(&result.return_value).map_err(|error| {
        TexasAirError::SerializationError(format!(
            "{method}: replayed dispatch output borsh: {error}"
        ))
    })?;
    let task = output.prove_task.ok_or_else(|| {
        TexasAirError::SpecViolation(format!(
            "{method}: replayed state-changing dispatch produced no prove task"
        ))
    })?;
    let method_input = task.method_input()?;
    if task.method_kind != expected_kind
        || task.context != call.context
        || task.selector() != call.selector
        || task.raw_args != call.raw_args
        || task.pre_table != pre
        || task.post_table != post
        || task.table_id != public_inputs.table_id
        || task.hand_id != public_inputs.hand_id
        || task.call_seq != public_inputs.call_seq
    {
        return Err(TexasAirError::SpecViolation(format!(
            "{method}: replayed prove task does not match verifier public inputs"
        )));
    }

    Ok(CanonicalDispatch {
        pre,
        post,
        call,
        replay_args,
        method_input,
        events: output.events,
    })
}

/// Compare a verifier-trusted row with a row rebuilt from canonical state.
pub(crate) fn validate_row(
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
