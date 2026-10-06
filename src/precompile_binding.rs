//! Trusted host binding for poker cryptographic precompile calls.
//!
//! A binding is issued only after the native backend verifies the canonical
//! request. Its fields are private and it has no wire deserializer, so safe
//! callers cannot fabricate a successful receipt. Production AIR verification
//! validates the issued capability's canonical bytes, ABI/backend identity and
//! both digests without repeating the expensive native proof verification; a
//! proof-carried `success = true` value is never accepted.

use blake2::Blake2bVar;
use blake2::digest::{Update, VariableOutput};
use borsh::{BorshDeserialize, BorshSerialize};
use poker_l1::contracts::texas_poker::types::{RevealTarget, seat_mask_contains};
use poker_protocol::crypto::types::{DefaultCurve, ECPoint, ElGamalCiphertext, N_CARDS};
use poker_protocol::precompile::{
    NativeReconstructionVerifier, NativeBls12381ShuffleVerifier,
};
use poker_protocol::precompile_abi::{
    RECONSTRUCTION_ABI_VERSION, ReconstructionVerifier, ReconstructionVerifyRequest,
    SHUFFLE_ABI_VERSION, ShuffleVerifier, ShuffleVerifyRequest,
};
use poker_protocol::zk_shuffle::dleq_proof::{DLEqProof, LeaveKind};
use poker_protocol::zk_shuffle::reveal_token_proof::RevealTokenProof;
use poker_protocol::zk_shuffle::transcript_ext::PoseidonFeltTranscript;
use stwo::core::fields::m31::M31;

use crate::error::{TexasAirError, TexasAirResult};
use crate::method_kind::MethodKind;
use crate::state_root::StateRoot;
use crate::texas_canonical::CanonicalTransitionWitness;

/// Number of M31 columns used for one full 256-bit digest.
pub const DIGEST_LIMBS: usize = 16;

/// Canonical ABI version for a Texas leave-layer DLEq verification request.
pub const LEAVE_DLEQ_ABI_VERSION: u8 = 1;

/// Canonical ABI version for batched reveal-token DLEq verification.
pub const REVEAL_TOKEN_ABI_VERSION: u8 = 1;

/// Canonical request for verifying one player's encrypted-deck layer removal.
///
/// The DLEq transcript is the 2026-09 Poseidon-epoch leave domain shared with
/// the L1 state machine factory (`utils::new_leave_transcript`).
/// `call_context` is committed by the request/receipt digests so an otherwise
/// valid proof cannot reuse a verifier receipt at another table, hand, call
/// sequence, state transition, or dispatch.
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct LeaveDleqVerifyRequest {
    abi_version: u8,
    call_context: Vec<u8>,
    input_cards: Vec<ElGamalCiphertext>,
    output_cards: Vec<ElGamalCiphertext>,
    player_pk: ECPoint,
    leave_proof: DLEqProof<DefaultCurve, LeaveKind>,
}

impl LeaveDleqVerifyRequest {
    /// Build a request with the current ABI version.
    #[must_use]
    pub fn new(
        call_context: Vec<u8>,
        input_cards: Vec<ElGamalCiphertext>,
        output_cards: Vec<ElGamalCiphertext>,
        player_pk: ECPoint,
        leave_proof: DLEqProof<DefaultCurve, LeaveKind>,
    ) -> Self {
        Self {
            abi_version: LEAVE_DLEQ_ABI_VERSION,
            call_context,
            input_cards,
            output_cards,
            player_pk,
            leave_proof,
        }
    }

    /// Strict canonical encoding used by request digests.
    pub fn encode(&self) -> TexasAirResult<Vec<u8>> {
        self.validate_shape()?;
        borsh::to_vec(self).map_err(|error| {
            TexasAirError::SerializationError(format!(
                "leave DLEq request Borsh encode failed: {error}"
            ))
        })
    }

    /// Strict canonical decoding with trailing-byte and shape rejection.
    pub fn decode(bytes: &[u8]) -> TexasAirResult<Self> {
        let request: Self = borsh::from_slice(bytes).map_err(|error| {
            TexasAirError::SerializationError(format!(
                "leave DLEq request Borsh decode failed: {error}"
            ))
        })?;
        request.validate_shape()?;
        Ok(request)
    }

    fn validate_shape(&self) -> TexasAirResult<()> {
        if self.abi_version != LEAVE_DLEQ_ABI_VERSION {
            return Err(TexasAirError::SpecViolation(format!(
                "unsupported leave DLEq ABI version {}",
                self.abi_version
            )));
        }
        if self.call_context.is_empty() {
            return Err(TexasAirError::SpecViolation(
                "leave DLEq request requires a non-empty call context".into(),
            ));
        }
        if self.input_cards.len() != N_CARDS || self.output_cards.len() != N_CARDS {
            return Err(TexasAirError::SpecViolation(format!(
                "leave DLEq request requires exactly {N_CARDS} input/output cards, got {}/{}",
                self.input_cards.len(),
                self.output_cards.len()
            )));
        }
        Ok(())
    }
}

/// One exact reveal-token statement selected by a dispatch assignment index.
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct RevealTokenVerifyItem {
    assignment_index: u8,
    encrypted_card: ElGamalCiphertext,
    reveal_token: ECPoint,
    proof: RevealTokenProof<DefaultCurve>,
}

/// Canonical batched request for one `submit_player_reveal_tokens` dispatch.
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct RevealTokenVerifyRequest {
    abi_version: u8,
    call_context: Vec<u8>,
    seat_index: u8,
    reveal_phase: u8,
    player_pk: ECPoint,
    items: Vec<RevealTokenVerifyItem>,
}

impl RevealTokenVerifyRequest {
    /// Rebuild the exact proof statements consumed by the native L1 dispatch.
    pub fn from_dispatch(
        call_context: Vec<u8>,
        pre_table: &poker_l1::contracts::texas_poker::types::TexasPokerTable,
        args: &poker_l1::contracts::texas_poker::dispatch::SubmitRevealTokensArgs,
    ) -> TexasAirResult<Self> {
        use poker_l1::contracts::texas_poker::constants::REVEAL_PHASE_SHOWDOWN;

        if args.reveal_tokens.len() != args.proofs.len() {
            return Err(TexasAirError::SpecViolation(
                "reveal-token/proof request vectors have different lengths".into(),
            ));
        }
        if args.reveal_tokens.is_empty() || args.reveal_tokens.len() > N_CARDS {
            return Err(TexasAirError::SpecViolation(format!(
                "reveal-token request requires 1..={N_CARDS} statements"
            )));
        }
        let seat = pre_table
            .seats
            .get(usize::from(args.seat_index))
            .ok_or_else(|| {
                TexasAirError::SpecViolation(
                    "reveal-token seat is outside the canonical pre-table".into(),
                )
            })?;
        if !seat.is_occupied() {
            return Err(TexasAirError::SpecViolation(
                "reveal-token seat is not occupied in the canonical pre-table".into(),
            ));
        }
        let reveal_state = pre_table.reveal_token_state().ok_or_else(|| {
            TexasAirError::SpecViolation(
                "reveal-token request requires an active or suspended reveal".into(),
            )
        })?;
        let reveal_phase = pre_table.reveal_phase();

        let assignment_indices = reveal_state
            .assignments
            .iter()
            .enumerate()
            .filter_map(|(index, assignment)| {
                seat_mask_contains(assignment.pending_mask(), args.seat_index)
                    .then_some(index as u8)
            })
            .collect::<Vec<_>>();
        if assignment_indices.len() != args.reveal_tokens.len() {
            return Err(TexasAirError::SpecViolation(format!(
                "reveal-token request must cover all {} pending assignments, got {} token/proof pairs",
                assignment_indices.len(),
                args.reveal_tokens.len()
            )));
        }

        let mut items = Vec::with_capacity(assignment_indices.len());
        for ((assignment_index, reveal_token), proof) in assignment_indices
            .iter()
            .zip(&args.reveal_tokens)
            .zip(&args.proofs)
        {
            let slot = usize::from(*assignment_index);
            let assignment = reveal_state.assignments.get(slot).ok_or_else(|| {
                TexasAirError::SpecViolation(format!(
                    "reveal assignment index {assignment_index} is outside the canonical pre-table"
                ))
            })?;
            if assignment.is_ready() {
                return Err(TexasAirError::SpecViolation(format!(
                    "reveal assignment index {assignment_index} is already resolved"
                )));
            }
            if !seat_mask_contains(assignment.pending_mask(), args.seat_index) {
                return Err(TexasAirError::SpecViolation(format!(
                    "reveal seat {} is not pending for assignment {assignment_index}",
                    args.seat_index
                )));
            }
            let card_index = usize::from(assignment.encrypted_card_index);
            let encrypted_card = if reveal_phase == REVEAL_PHASE_SHOWDOWN {
                let RevealTarget::Hole {
                    seat_index: owner_seat,
                    card_slot,
                } = assignment.target
                else {
                    return Err(TexasAirError::SpecViolation(format!(
                        "showdown reveal assignment {assignment_index} does not target a hole card"
                    )));
                };
                if owner_seat != args.seat_index {
                    return Err(TexasAirError::SpecViolation(format!(
                        "showdown reveal seat {} does not own target seat {owner_seat}",
                        args.seat_index
                    )));
                }
                pre_table
                    .deck_state
                    .owner_readable_hole_cards
                    .get(owner_seat, card_slot)
                    .filter(|card| usize::from(card.encrypted_card_index) == card_index)
                    .map(|card| card.ciphertext)
            } else {
                pre_table.deck_state.encrypted.get(card_index).copied()
            }
            .ok_or_else(|| {
                TexasAirError::SpecViolation(format!(
                    "reveal assignment {assignment_index} references missing ciphertext {}",
                    assignment.encrypted_card_index
                ))
            })?;
            items.push(RevealTokenVerifyItem {
                assignment_index: *assignment_index,
                encrypted_card,
                reveal_token: *reveal_token,
                proof: *proof,
            });
        }

        let request = Self {
            abi_version: REVEAL_TOKEN_ABI_VERSION,
            call_context,
            seat_index: args.seat_index,
            reveal_phase,
            player_pk: seat.pk().copied().ok_or_else(|| {
                TexasAirError::SpecViolation(
                    "reveal-token seat has no live Mental Poker key".into(),
                )
            })?,
            items,
        };
        request.validate_shape()?;
        Ok(request)
    }

    /// Strict canonical encoding used by request digests.
    pub fn encode(&self) -> TexasAirResult<Vec<u8>> {
        self.validate_shape()?;
        borsh::to_vec(self).map_err(|error| {
            TexasAirError::SerializationError(format!(
                "reveal-token request Borsh encode failed: {error}"
            ))
        })
    }

    /// Strict canonical decoding with trailing-byte and shape rejection.
    pub fn decode(bytes: &[u8]) -> TexasAirResult<Self> {
        let request: Self = borsh::from_slice(bytes).map_err(|error| {
            TexasAirError::SerializationError(format!(
                "reveal-token request Borsh decode failed: {error}"
            ))
        })?;
        request.validate_shape()?;
        Ok(request)
    }

    fn validate_shape(&self) -> TexasAirResult<()> {
        if self.abi_version != REVEAL_TOKEN_ABI_VERSION {
            return Err(TexasAirError::SpecViolation(format!(
                "unsupported reveal-token ABI version {}",
                self.abi_version
            )));
        }
        if self.call_context.is_empty() {
            return Err(TexasAirError::SpecViolation(
                "reveal-token request requires a non-empty call context".into(),
            ));
        }
        if !(1..=6).contains(&self.reveal_phase) {
            return Err(TexasAirError::SpecViolation(format!(
                "invalid reveal-token phase {}",
                self.reveal_phase
            )));
        }
        if self.items.is_empty() || self.items.len() > N_CARDS {
            return Err(TexasAirError::SpecViolation(format!(
                "reveal-token request requires 1..={N_CARDS} statements"
            )));
        }
        let mut seen = [false; 256];
        for item in &self.items {
            let slot = usize::from(item.assignment_index);
            if seen[slot] {
                return Err(TexasAirError::SpecViolation(format!(
                    "duplicate reveal assignment index {}",
                    item.assignment_index
                )));
            }
            seen[slot] = true;
        }
        Ok(())
    }
}

/// Poker proof precompile selected by a call binding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PokerPrecompileId {
    /// Bayer--Groth shuffle proof verification.
    Shuffle = 1,
    /// Batched DLEq verification for removing one player's encryption layer.
    DleqLeave = 2,
    /// Reconstruction V3 slot-OR verification.
    ReconstructionV3 = 3,
    /// Batched reveal-token Chaum--Pedersen verification.
    RevealToken = 4,
}

/// Native backend identity committed by the receipt digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PrecompileBackendId {
    /// Auditable Rust BLS12-381 reference verifier.
    NativeBls12381V1 = 1,
}

/// AIR-visible projection of a verified precompile call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrecompileAirBinding {
    /// Precompile selector.
    pub precompile_id: u8,
    /// Canonical request ABI version.
    pub abi_version: u8,
    /// Full request digest represented by sixteen big-endian u16 limbs.
    pub request_digest: [M31; DIGEST_LIMBS],
    /// Full verifier-issued receipt digest represented identically.
    pub receipt_digest: [M31; DIGEST_LIMBS],
}

impl PrecompileAirBinding {
    /// Zero binding used only by mechanism tests that exercise the explicitly
    /// untrusted `verify_method` compatibility entry point.
    #[cfg(any(test, feature = "test-helpers"))]
    #[must_use]
    pub fn synthetic_unverified() -> Self {
        Self {
            precompile_id: 0,
            abi_version: 0,
            request_digest: [M31::from(0u32); DIGEST_LIMBS],
            receipt_digest: [M31::from(0u32); DIGEST_LIMBS],
        }
    }
}

/// Verifier-issued binding containing the canonical precompile request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrecompileCallBinding {
    precompile_id: PokerPrecompileId,
    abi_version: u8,
    backend_id: PrecompileBackendId,
    request_bytes: Vec<u8>,
    request_digest: [u8; 32],
    receipt_digest: [u8; 32],
}

impl PrecompileCallBinding {
    /// Verify and bind a canonical shuffle request with the native backend.
    pub fn verify_shuffle(request: &ShuffleVerifyRequest) -> TexasAirResult<Self> {
        let request_bytes = request.encode().map_err(precompile_error)?;
        NativeBls12381ShuffleVerifier
            .verify(request)
            .map_err(precompile_error)?;
        Ok(Self::issue(
            PokerPrecompileId::Shuffle,
            SHUFFLE_ABI_VERSION,
            request_bytes,
        ))
    }

    /// Verify and bind a canonical leave-layer DLEq request.
    pub fn verify_leave_dleq(request: &LeaveDleqVerifyRequest) -> TexasAirResult<Self> {
        let request_bytes = request.encode()?;
        let mut transcript = poker_l1::contracts::texas_poker::utils::new_leave_transcript();
        if !request.leave_proof.verify(
            &request.input_cards,
            &request.output_cards,
            &request.player_pk.0,
            &mut transcript,
        ) {
            return Err(TexasAirError::SpecViolation(
                "poker precompile verification failed: leave DLEq proof rejected".into(),
            ));
        }
        Ok(Self::issue(
            PokerPrecompileId::DleqLeave,
            LEAVE_DLEQ_ABI_VERSION,
            request_bytes,
        ))
    }

    /// Verify and bind every reveal-token proof in one canonical dispatch request.
    pub fn verify_reveal_tokens(request: &RevealTokenVerifyRequest) -> TexasAirResult<Self> {
        let request_bytes = request.encode()?;
        for item in &request.items {
            item.proof
                .verify(
                    &item.encrypted_card,
                    &item.reveal_token.0,
                    &request.player_pk.0,
                    &mut PoseidonFeltTranscript::new_domain(
                    poker_protocol::transcript_domains::REVEAL_TOKEN_V3_POSEIDON,
                ),
                )
                .map_err(|error| {
                    TexasAirError::SpecViolation(format!(
                        "poker precompile verification failed: reveal-token proof rejected: {error:?}"
                    ))
                })?;
        }
        Ok(Self::issue(
            PokerPrecompileId::RevealToken,
            REVEAL_TOKEN_ABI_VERSION,
            request_bytes,
        ))
    }

    /// Verify and bind a canonical reconstruction V3 request with the native backend.
    pub fn verify_reconstruction_v3(
        request: &ReconstructionVerifyRequest,
    ) -> TexasAirResult<Self> {
        let request_bytes = request.encode().map_err(precompile_error)?;
        NativeReconstructionVerifier
            .verify(request)
            .map_err(precompile_error)?;
        Ok(Self::issue(
            PokerPrecompileId::ReconstructionV3,
            RECONSTRUCTION_ABI_VERSION,
            request_bytes,
        ))
    }

    fn issue(precompile_id: PokerPrecompileId, abi_version: u8, request_bytes: Vec<u8>) -> Self {
        let backend_id = PrecompileBackendId::NativeBls12381V1;
        let request_digest = precompile_request_digest(&request_bytes);
        let mut receipt = Vec::with_capacity(4 + 32);
        receipt.extend_from_slice(&[
            precompile_id as u8,
            abi_version,
            backend_id as u8,
            1, // verified-success result code
        ]);
        receipt.extend_from_slice(&request_digest);
        let receipt_digest = hash256(b"zchain.poker.precompile.receipt.v1", &receipt);
        Self {
            precompile_id,
            abi_version,
            backend_id,
            request_bytes,
            request_digest,
            receipt_digest,
        }
    }

    /// Re-run canonical decoding and native verification, then recompute every
    /// committed field. This is the production verifier's fail-closed check.
    pub fn reverify(&self) -> TexasAirResult<()> {
        let rebuilt = match self.precompile_id {
            PokerPrecompileId::Shuffle => {
                let request =
                    ShuffleVerifyRequest::decode(&self.request_bytes).map_err(precompile_error)?;
                Self::verify_shuffle(&request)?
            }
            PokerPrecompileId::DleqLeave => {
                let request = LeaveDleqVerifyRequest::decode(&self.request_bytes)?;
                Self::verify_leave_dleq(&request)?
            }
            PokerPrecompileId::ReconstructionV3 => {
                let request = ReconstructionVerifyRequest::decode(&self.request_bytes)
                    .map_err(precompile_error)?;
                Self::verify_reconstruction_v3(&request)?
            }
            PokerPrecompileId::RevealToken => {
                let request = RevealTokenVerifyRequest::decode(&self.request_bytes)?;
                Self::verify_reveal_tokens(&request)?
            }
        };
        if &rebuilt != self {
            return Err(TexasAirError::SpecViolation(
                "precompile binding metadata/digest does not match canonical re-verification"
                    .into(),
            ));
        }
        Ok(())
    }

    /// Validate an already verifier-issued capability without repeating its
    /// expensive native cryptographic verification.
    ///
    /// `PrecompileCallBinding` has private fields and no deserialization or
    /// unchecked constructor. In safe Rust, every instance therefore comes
    /// from one of the `verify_*` constructors above, which has already run the
    /// corresponding host-native verifier. This check still fails closed on a
    /// non-canonical request, wrong ABI/backend, or mismatched request/receipt
    /// digest before the capability is bound into an AIR statement.
    pub(crate) fn validate_issued(&self) -> TexasAirResult<()> {
        let (abi_version, request_bytes) = match self.precompile_id {
            PokerPrecompileId::Shuffle => {
                let request =
                    ShuffleVerifyRequest::decode(&self.request_bytes).map_err(precompile_error)?;
                (
                    SHUFFLE_ABI_VERSION,
                    request.encode().map_err(precompile_error)?,
                )
            }
            PokerPrecompileId::DleqLeave => {
                let request = LeaveDleqVerifyRequest::decode(&self.request_bytes)?;
                (LEAVE_DLEQ_ABI_VERSION, request.encode()?)
            }
            PokerPrecompileId::ReconstructionV3 => {
                let request = ReconstructionVerifyRequest::decode(&self.request_bytes)
                    .map_err(precompile_error)?;
                (
                    RECONSTRUCTION_ABI_VERSION,
                    request.encode().map_err(precompile_error)?,
                )
            }
            PokerPrecompileId::RevealToken => {
                let request = RevealTokenVerifyRequest::decode(&self.request_bytes)?;
                (REVEAL_TOKEN_ABI_VERSION, request.encode()?)
            }
        };
        if request_bytes != self.request_bytes {
            return Err(TexasAirError::SpecViolation(
                "precompile binding request is not canonically encoded".into(),
            ));
        }
        let rebuilt = Self::issue(self.precompile_id, abi_version, request_bytes);
        if &rebuilt != self {
            return Err(TexasAirError::SpecViolation(
                "precompile binding metadata/digest does not match its verifier-issued receipt"
                    .into(),
            ));
        }
        Ok(())
    }

    /// Precompile selector.
    #[must_use]
    pub const fn precompile_id(&self) -> PokerPrecompileId {
        self.precompile_id
    }

    /// Canonical request ABI version.
    #[must_use]
    pub const fn abi_version(&self) -> u8 {
        self.abi_version
    }

    /// Backend identity committed by the receipt.
    #[must_use]
    pub const fn backend_id(&self) -> PrecompileBackendId {
        self.backend_id
    }

    /// Full canonical request digest.
    #[must_use]
    pub const fn request_digest(&self) -> [u8; 32] {
        self.request_digest
    }

    /// Full verifier-issued receipt digest.
    #[must_use]
    pub const fn receipt_digest(&self) -> [u8; 32] {
        self.receipt_digest
    }

    /// Canonical request bytes retained for independent verifier replay.
    #[must_use]
    pub fn request_bytes(&self) -> &[u8] {
        &self.request_bytes
    }

    /// Convert the full digests to AIR columns without truncation.
    #[must_use]
    pub fn air_binding(&self) -> PrecompileAirBinding {
        PrecompileAirBinding {
            precompile_id: self.precompile_id as u8,
            abi_version: self.abi_version,
            request_digest: digest_to_m31_limbs(self.request_digest),
            receipt_digest: digest_to_m31_limbs(self.receipt_digest),
        }
    }
}

/// Construct the canonical replay scope included in every proof request.
#[allow(clippy::too_many_arguments)]
#[must_use]
pub fn precompile_call_context(
    kind: MethodKind,
    seat_index: u8,
    table_id: u64,
    hand_id: u32,
    call_seq: u32,
    pre_version: u64,
    post_version: u64,
    pre_state_root: StateRoot,
    post_state_root: StateRoot,
    dispatch_call_digest: [u8; 32],
) -> Vec<u8> {
    let mut context = Vec::with_capacity(128);
    context.extend_from_slice(b"zchain.texas_poker.precompile_call.v1");
    context.extend_from_slice(&[kind as u8, seat_index]);
    context.extend_from_slice(&table_id.to_le_bytes());
    context.extend_from_slice(&hand_id.to_le_bytes());
    context.extend_from_slice(&call_seq.to_le_bytes());
    context.extend_from_slice(&pre_version.to_le_bytes());
    context.extend_from_slice(&post_version.to_le_bytes());
    context.extend_from_slice(&pre_state_root.bytes());
    context.extend_from_slice(&post_state_root.bytes());
    context.extend_from_slice(&dispatch_call_digest);
    context
}

/// Construct a no-replay call scope for a direct canonical crypto transition.
///
/// Unlike [`precompile_call_context`], this scope contains no dispatch-call
/// digest or `ProveTask` material.  It binds the request to both complete
/// canonical endpoint images and to a domain-separated transition commitment
/// with the request digest itself zeroed, avoiding a circular commitment.
#[must_use]
pub fn canonical_precompile_call_context(witness: &CanonicalTransitionWitness) -> Vec<u8> {
    // This family authenticates its endpoint images through the Blake2b
    // lookup stack, so the context binds the Blake2b statement digests (the
    // same values `validate_hash_statement_binding` re-derives), NOT the
    // BLAKE3 `CanonicalStateImage::commitment` used by the hand-bundle path.
    let blake2b_image_digest = |image: &crate::texas_canonical::CanonicalStateImage| {
        let preimage = crate::canonical_state_hash::canonical_state_image_preimage(image)
            .expect("canonical state image is serializable");
        let mut hasher = Blake2bVar::new(32).expect("32 <= 64");
        hasher.update(&preimage);
        let mut out = [0u8; 32];
        hasher.finalize_variable(&mut out).expect("digest length");
        out
    };
    canonical_precompile_call_context_from_digests(
        witness,
        blake2b_image_digest(&witness.pre),
        blake2b_image_digest(&witness.post),
        witness.crypto_scope_commitment(),
    )
}

/// Construct the canonical call context from already-authenticated digest
/// statements.  This is the verifier-side form used by the lookup-backed
/// reconstruction binding proof so it does not need to invoke native Blake2b.
#[must_use]
pub fn canonical_precompile_call_context_from_digests(
    witness: &CanonicalTransitionWitness,
    pre_state_commitment: [u8; 32],
    post_state_commitment: [u8; 32],
    crypto_scope_commitment: [u8; 32],
) -> Vec<u8> {
    let mut context = Vec::with_capacity(256);
    context.extend_from_slice(b"zchain.texas.canonical_precompile_call.v1");
    context.extend_from_slice(&witness.pre.abi_version.to_le_bytes());
    context.extend_from_slice(&[witness.kind as u8, witness.action.seat]);
    context.extend_from_slice(&witness.pre.table_id.to_le_bytes());
    context.extend_from_slice(&witness.pre.hand_id.to_le_bytes());
    context.extend_from_slice(&witness.post.hand_id.to_le_bytes());
    context.extend_from_slice(&witness.pre.call_seq.to_le_bytes());
    context.extend_from_slice(&witness.post.call_seq.to_le_bytes());
    context.extend_from_slice(&pre_state_commitment);
    context.extend_from_slice(&post_state_commitment);
    context.extend_from_slice(&witness.pre.state_root);
    context.extend_from_slice(&witness.post.state_root);
    context.extend_from_slice(&crypto_scope_commitment);
    context
}

/// Exact Blake2b message whose digest is
/// [`CanonicalTransitionWitness::crypto_scope_commitment`].
pub fn canonical_crypto_scope_preimage(witness: &CanonicalTransitionWitness) -> Vec<u8> {
    let mut payload = witness.clone();
    payload.action.proof_commitment = [0; 32];
    payload.transition_commitment = [0; 32];
    payload.nullifier = [0; 32];
    let encoded = borsh::to_vec(&payload)
        .expect("canonical transition witness has an infallible fixed Borsh encoding");
    let mut preimage =
        Vec::with_capacity(b"zchain.texas.canonical-crypto-scope.v1".len() + encoded.len());
    preimage.extend_from_slice(b"zchain.texas.canonical-crypto-scope.v1");
    preimage.extend_from_slice(&encoded);
    preimage
}

/// Domain-separated digest of one canonical poker-precompile request.
///
/// This is the value stored in a direct canonical transition's
/// `action.proof_commitment`.  The lookup-backed Blake2b component can prove
/// the identical byte-to-digest relation when the crypto request is composed
/// into host-zero admission.
#[must_use]
pub fn precompile_request_digest(request_bytes: &[u8]) -> [u8; 32] {
    let preimage = precompile_request_preimage(request_bytes);
    let mut hasher = Blake2bVar::new(32).expect("32 <= 64");
    hasher.update(&preimage);
    let mut digest = [0u8; 32];
    hasher.finalize_variable(&mut digest).expect("32 <= 64");
    digest
}

/// Exact standard-Blake2b message used by [`precompile_request_digest`].
#[must_use]
pub fn precompile_request_preimage(request_bytes: &[u8]) -> Vec<u8> {
    let domain = b"zchain.poker.precompile.request.v1";
    let mut preimage = Vec::with_capacity(domain.len() + 8 + request_bytes.len());
    preimage.extend_from_slice(domain);
    preimage.extend_from_slice(&(request_bytes.len() as u64).to_le_bytes());
    preimage.extend_from_slice(request_bytes);
    preimage
}

/// Represent a 256-bit digest by sixteen exact u16 limbs in M31.
#[must_use]
pub fn digest_to_m31_limbs(digest: [u8; 32]) -> [M31; DIGEST_LIMBS] {
    std::array::from_fn(|i| {
        M31::from(u32::from(u16::from_be_bytes([
            digest[2 * i],
            digest[2 * i + 1],
        ])))
    })
}

fn hash256(domain: &[u8], payload: &[u8]) -> [u8; 32] {
    let mut hasher = Blake2bVar::new(32).expect("32 <= 64");
    hasher.update(domain);
    hasher.update(&(payload.len() as u64).to_le_bytes());
    hasher.update(payload);
    let mut digest = [0u8; 32];
    hasher.finalize_variable(&mut digest).expect("32 <= 64");
    digest
}

fn precompile_error(error: impl std::fmt::Display) -> TexasAirError {
    TexasAirError::SpecViolation(format!("poker precompile verification failed: {error}"))
}
