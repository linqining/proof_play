//! RistrettoAirV2 player sigma proofs: key ownership, reveal tokens, deck
//! remasking, and deck layer removal (leave/fold).
//!
//! These complete the mental-poker protocol surface referenced from zgame's
//! `poker-protocol-proofs` (`pk_ownership`, `reveal_token_proof`,
//! `remask_proof`, `leave_proof`) under the V2 trust model already
//! established by the shuffle and reconstruction routes:
//!
//! - every Fiat--Shamir challenge is derived from a Flock-BLAKE3 chain
//!   transcript seeded over a proof-kind domain, absorbing the caller's
//!   statement context first; one Flock STARK covers the chain statements;
//! - the sigma equations are verified natively (public points, public
//!   scalars), the same trust class as the V2 shuffle and reconstruction
//!   verifiers;
//! - the witnesses (secret keys, nonce blinding) never enter any STARK
//!   trace, so every proof stays honest-verifier zero knowledge.
//!
//! # Equations
//!
//! - key ownership (Schnorr): `G·s = A + pk·c` for witness `sk` with
//!   `pk = sk·G`.
//! - reveal token (Chaum--Pedersen): `G·s = T1 + pk·c` and
//!   `ct.c1·s = T2 + token·c`, proving one `sk` behind both `pk` and
//!   `token = sk·ct.c1`; the caller checks the revealed plaintext
//!   `ct.c2 − token` separately.
//! - deck remask / leave (batched DLEQ over the fixed 52-card deck):
//!   `G·s = B + pk·c` and `input_i.c1·s = A_i + d2_i·c` for every card,
//!   where `d2_i = ±(output_i.c2 − input_i.c2)` selects the remask
//!   (add a key layer) or leave (remove one) direction.  Per-card
//!   commitments defeat aggregate-shuffle attacks across cards.
//!
//! # Path A
//!
//! Each proof's in-circuit obligation is two (or 53) fixed-base/variable-base
//! scalar-multiplication equalities over public points — at most 106
//! in-circuit multiplications per deck-sized proof.  The recursion boundary
//! is the proof wire plus the Flock transcript statements, mirroring
//! [`crate::ristretto_shuffle_air::RistrettoAirV2ShuffleInCircuitComponents`].

#![allow(missing_docs)]

use borsh::{BorshDeserialize, BorshSerialize};
use rand_core::{CryptoRng, RngCore};

use poker_protocol_core::{
    CryptoTranscript, Curve, CurvePoint, CurveScalar, ElGamalCiphertextGeneric, RistrettoCurve,
};

use crate::error::{TexasAirError, TexasAirResult};
use crate::hash_prover::{ArchivedHashProof, HashProofProvider};
use crate::ristretto_shuffle_air::{FlockShuffleTranscript, RistrettoShuffleV2ChallengeWire};

type RistrettoPoint = <RistrettoCurve as Curve>::Point;
type RistrettoScalar = <RistrettoCurve as Curve>::Scalar;
pub type RistrettoCiphertext = ElGamalCiphertextGeneric<RistrettoCurve>;

/// Fixed deck size shared by every deck-level proof.
pub const RISTRETTO_PLAYER_PROOF_DECK_SIZE: usize = 52;

/// Transcript protocol names, one per proof kind.
pub const PK_OWNERSHIP_PROTOCOL: &[u8] = b"poker/ristretto-air/v2/pk-ownership";
pub const REVEAL_TOKEN_PROTOCOL: &[u8] = b"poker/ristretto-air/v2/reveal-token";
pub const REMASK_PROTOCOL: &[u8] = b"poker/ristretto-air/v2/remask";
pub const LEAVE_PROTOCOL: &[u8] = b"poker/ristretto-air/v2/leave";

fn decode_point(bytes: &[u8; 32], label: &str) -> TexasAirResult<RistrettoPoint> {
    RistrettoPoint::from_compressed(bytes)
        .ok_or_else(|| TexasAirError::SpecViolation(format!("{label} failed to decompress")))
}

fn decode_scalar(bytes: &[u8; 32], label: &str) -> TexasAirResult<RistrettoScalar> {
    <RistrettoScalar as CurveScalar>::from_canonical_bytes(bytes)
        .ok_or_else(|| TexasAirError::SpecViolation(format!("{label} is not canonical")))
}

fn point_bytes(point: &RistrettoPoint) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(point.compress().as_bytes());
    out
}

fn scalar_bytes(scalar: &RistrettoScalar) -> [u8; 32] {
    let mut out = [0u8; 32];
    let bytes = scalar.as_bytes();
    out.copy_from_slice(&bytes[..32]);
    out
}

/// A player sigma proof: the wire, its single recorded challenge image, and
/// the Flock STARK over the transcript chain statements.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ArchivedRistrettoPlayerProof {
    /// Recorded transcript challenge image (splice detection; must equal the
    /// verifier's native re-derivation).
    pub challenge: RistrettoShuffleV2ChallengeWire,
    /// Flock STARK over `[init, flush]` chain statements.
    pub flock: ArchivedHashProof,
}

/// Prove the Flock layer once from a completed transcript.
fn finish_player_proof(
    transcript: &FlockShuffleTranscript,
) -> TexasAirResult<ArchivedRistrettoPlayerProof> {
    let challenges = transcript.challenges();
    let [challenge] = challenges else {
        return Err(TexasAirError::SpecViolation(format!(
            "player sigma transcript must derive exactly one challenge (got {})",
            challenges.len()
        )));
    };
    let flock = crate::blake3_flock::FlockProvider.prove_statements(transcript.statements())?;
    Ok(ArchivedRistrettoPlayerProof {
        challenge: *challenge,
        flock,
    })
}

/// Verify the Flock layer and the recorded challenge image against a
/// verifier-side transcript run.
fn verify_player_proof(
    proof: &ArchivedRistrettoPlayerProof,
    transcript: &mut FlockShuffleTranscript,
) -> TexasAirResult<RistrettoScalar> {
    // Derive the challenge exactly as the prover did, after every absorb.
    let derived = transcript.challenge::<RistrettoCurve>(b"challenge").scalar;
    let challenges = transcript.challenges();
    let [challenge] = challenges else {
        return Err(TexasAirError::SpecViolation(
            "player sigma transcript must derive exactly one challenge".into(),
        ));
    };
    if *challenge != proof.challenge {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "player sigma challenge image is detached from the transcript".into(),
        ));
    }
    let scalar = <RistrettoScalar as CurveScalar>::from_canonical_bytes(&challenge.image)
        .ok_or_else(|| TexasAirError::SpecViolation("challenge image is not canonical".into()))?;
    debug_assert_eq!(
        scalar, derived,
        "recorded image and derived challenge must agree"
    );
    crate::blake3_flock::FlockProvider.verify_statements(&proof.flock, transcript.statements())?;
    Ok(scalar)
}

// ============================================================================
// Key ownership
// ============================================================================

/// Schnorr ownership wire: `G·response = commitment + pk·c`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct RistrettoPkOwnershipWire {
    pub commitment: [u8; 32],
    pub response: [u8; 32],
}

/// Prove knowledge of `sk` with `pk = sk·G` under the Flock transcript.
pub fn prove_pk_ownership(
    sk: &RistrettoScalar,
    pk: &RistrettoPoint,
    context: &[u8],
    rng: &mut (impl CryptoRng + RngCore),
) -> TexasAirResult<(RistrettoPkOwnershipWire, ArchivedRistrettoPlayerProof)> {
    if *sk == RistrettoScalar::zero() || pk.is_identity() || RistrettoCurve::base_g() * *sk != *pk {
        return Err(TexasAirError::SpecViolation(
            "pk-ownership witness does not match the public key".into(),
        ));
    }
    let mut transcript = FlockShuffleTranscript::new(PK_OWNERSHIP_PROTOCOL);
    transcript.absorb(b"context", context);
    transcript.absorb(b"pk", &point_bytes(pk));
    let mut nonce;
    let mut commitment;
    loop {
        nonce = RistrettoScalar::random(rng);
        if nonce == RistrettoScalar::zero() {
            continue;
        }
        commitment = RistrettoCurve::base_g() * nonce;
        if !commitment.is_identity() {
            break;
        }
    }
    transcript.absorb(b"commitment", &point_bytes(&commitment));
    let challenge = transcript.challenge::<RistrettoCurve>(b"challenge").scalar;
    let response = nonce + challenge * *sk;
    let wire = RistrettoPkOwnershipWire {
        commitment: point_bytes(&commitment),
        response: scalar_bytes(&response),
    };
    Ok((wire, finish_player_proof(&transcript)?))
}

/// Verify one key-ownership proof.
pub fn verify_pk_ownership(
    pk: &RistrettoPoint,
    context: &[u8],
    wire: &RistrettoPkOwnershipWire,
    proof: &ArchivedRistrettoPlayerProof,
) -> TexasAirResult<()> {
    if pk.is_identity() {
        return Err(TexasAirError::SpecViolation(
            "pk-ownership public key is the identity".into(),
        ));
    }
    let commitment = decode_point(&wire.commitment, "pk-ownership commitment")?;
    let response = decode_scalar(&wire.response, "pk-ownership response")?;
    if commitment.is_identity() {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "pk-ownership commitment is the identity".into(),
        ));
    }
    let mut transcript = FlockShuffleTranscript::new(PK_OWNERSHIP_PROTOCOL);
    transcript.absorb(b"context", context);
    transcript.absorb(b"pk", &point_bytes(pk));
    transcript.absorb(b"commitment", &wire.commitment);
    let challenge = verify_player_proof(proof, &mut transcript)?;
    if RistrettoCurve::base_g() * response != commitment + *pk * challenge {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "pk-ownership equation is not satisfied".into(),
        ));
    }
    Ok(())
}

// ============================================================================
// Reveal token
// ============================================================================

/// Chaum--Pedersen reveal-token wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct RistrettoRevealTokenWire {
    /// `T1 = G·omega`.
    pub commitment_t1: [u8; 32],
    /// `T2 = ct.c1·omega`.
    pub commitment_t2: [u8; 32],
    /// `s = omega + c·sk`.
    pub response: [u8; 32],
}

fn absorb_reveal_statement(
    transcript: &mut FlockShuffleTranscript,
    context: &[u8],
    pk: &RistrettoPoint,
    ciphertext: &RistrettoCiphertext,
    reveal_token: &RistrettoPoint,
) {
    transcript.absorb(b"context", context);
    transcript.absorb(b"pk", &point_bytes(pk));
    transcript.absorb(b"c1", &point_bytes(&ciphertext.c1));
    transcript.absorb(b"c2", &point_bytes(&ciphertext.c2));
    transcript.absorb(b"reveal_token", &point_bytes(reveal_token));
}

/// Prove `token = sk·ct.c1` with the same `sk` behind `pk = sk·G`.
///
/// The caller binds the decrypted plaintext by checking `ct.c2 − token`
/// against the expected card; that state-machine check is outside this
/// relation.
pub fn prove_reveal_token(
    sk: &RistrettoScalar,
    pk: &RistrettoPoint,
    ciphertext: &RistrettoCiphertext,
    reveal_token: &RistrettoPoint,
    context: &[u8],
    rng: &mut (impl CryptoRng + RngCore),
) -> TexasAirResult<(RistrettoRevealTokenWire, ArchivedRistrettoPlayerProof)> {
    if *sk == RistrettoScalar::zero()
        || pk.is_identity()
        || RistrettoCurve::base_g() * *sk != *pk
        || !ciphertext.is_valid()
        || reveal_token.is_identity()
        || *reveal_token != ciphertext.c1 * *sk
    {
        return Err(TexasAirError::SpecViolation(
            "reveal-token witness does not match the statement".into(),
        ));
    }
    let mut transcript = FlockShuffleTranscript::new(REVEAL_TOKEN_PROTOCOL);
    absorb_reveal_statement(&mut transcript, context, pk, ciphertext, reveal_token);
    let (nonce, t1, t2) = loop {
        let nonce = RistrettoScalar::random(rng);
        if nonce == RistrettoScalar::zero() {
            continue;
        }
        let t1 = RistrettoCurve::base_g() * nonce;
        let t2 = ciphertext.c1 * nonce;
        if !t1.is_identity() && !t2.is_identity() {
            break (nonce, t1, t2);
        }
    };
    transcript.absorb(b"t1", &point_bytes(&t1));
    transcript.absorb(b"t2", &point_bytes(&t2));
    let challenge = transcript.challenge::<RistrettoCurve>(b"challenge").scalar;
    let response = nonce + challenge * *sk;
    let wire = RistrettoRevealTokenWire {
        commitment_t1: point_bytes(&t1),
        commitment_t2: point_bytes(&t2),
        response: scalar_bytes(&response),
    };
    Ok((wire, finish_player_proof(&transcript)?))
}

/// Verify one reveal-token proof.
pub fn verify_reveal_token(
    pk: &RistrettoPoint,
    ciphertext: &RistrettoCiphertext,
    reveal_token: &RistrettoPoint,
    context: &[u8],
    wire: &RistrettoRevealTokenWire,
    proof: &ArchivedRistrettoPlayerProof,
) -> TexasAirResult<()> {
    if !ciphertext.is_valid() || pk.is_identity() || reveal_token.is_identity() {
        return Err(TexasAirError::SpecViolation(
            "reveal-token statement contains identity points".into(),
        ));
    }
    let t1 = decode_point(&wire.commitment_t1, "reveal-token commitment")?;
    let t2 = decode_point(&wire.commitment_t2, "reveal-token commitment")?;
    let response = decode_scalar(&wire.response, "reveal-token response")?;
    if t1.is_identity() || t2.is_identity() {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "reveal-token commitment is the identity".into(),
        ));
    }
    let mut transcript = FlockShuffleTranscript::new(REVEAL_TOKEN_PROTOCOL);
    absorb_reveal_statement(&mut transcript, context, pk, ciphertext, reveal_token);
    transcript.absorb(b"t1", &wire.commitment_t1);
    transcript.absorb(b"t2", &wire.commitment_t2);
    let challenge = verify_player_proof(proof, &mut transcript)?;
    let first = RistrettoCurve::base_g() * response == t1 + *pk * challenge;
    let second = ciphertext.c1 * response == t2 + *reveal_token * challenge;
    if !first || !second {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "reveal-token equation is not satisfied".into(),
        ));
    }
    Ok(())
}

// ============================================================================
// Batched deck DLEQ: remask (add key layer) and leave (remove key layer)
// ============================================================================

/// Direction of the deck transition proved by the batched DLEQ.
#[derive(Debug, Clone, Copy, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum RistrettoDeckDleqDirection {
    /// `output.c2 = input.c2 + input.c1·sk` (remask: add an encryption
    /// layer under the leaving/masking player's key).
    Remask,
    /// `output.c2 = input.c2 − input.c1·sk` (leave: remove one encryption
    /// layer, used by `fold_with_proof` when the aggregate key drops the
    /// player).
    Leave,
}

impl RistrettoDeckDleqDirection {
    /// Transcript protocol name.
    pub fn protocol(self) -> &'static [u8] {
        match self {
            Self::Remask => REMASK_PROTOCOL,
            Self::Leave => LEAVE_PROTOCOL,
        }
    }

    pub(crate) fn compute_d2(
        self,
        input_c2: &RistrettoPoint,
        output_c2: &RistrettoPoint,
    ) -> RistrettoPoint {
        match self {
            Self::Remask => *output_c2 - *input_c2,
            Self::Leave => *input_c2 - *output_c2,
        }
    }
}

/// Batched deck DLEQ wire over the fixed 52-card deck.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct RistrettoDeckDleqWire {
    /// Per-card commitments `A_i = input_i.c1·omega`.
    pub per_card_commitments: [[u8; 32]; RISTRETTO_PLAYER_PROOF_DECK_SIZE],
    /// Key commitment `B = G·omega`.
    pub commitment_pk: [u8; 32],
    /// Shared response `s = omega + c·sk`.
    pub response: [u8; 32],
}

fn absorb_deck_dleq_statement(
    transcript: &mut FlockShuffleTranscript,
    context: &[u8],
    pk: &RistrettoPoint,
    input: &[RistrettoCiphertext],
    output: &[RistrettoCiphertext],
    commitments: &[[u8; 32]; RISTRETTO_PLAYER_PROOF_DECK_SIZE],
    commitment_pk: &[u8; 32],
) {
    transcript.absorb(b"context", context);
    transcript.absorb(b"pk", &point_bytes(pk));
    for ciphertext in input {
        transcript.absorb(b"in_c1", &point_bytes(&ciphertext.c1));
        transcript.absorb(b"in_c2", &point_bytes(&ciphertext.c2));
    }
    for ciphertext in output {
        transcript.absorb(b"out_c1", &point_bytes(&ciphertext.c1));
        transcript.absorb(b"out_c2", &point_bytes(&ciphertext.c2));
    }
    for commitment in commitments {
        transcript.absorb(b"a_i", commitment);
    }
    transcript.absorb(b"commitment_pk", commitment_pk);
}

/// Prove one batched deck DLEQ in either direction.
pub fn prove_deck_dleq(
    direction: RistrettoDeckDleqDirection,
    input: &[RistrettoCiphertext],
    output: &[RistrettoCiphertext],
    sk: &RistrettoScalar,
    pk: &RistrettoPoint,
    context: &[u8],
    rng: &mut (impl CryptoRng + RngCore),
) -> TexasAirResult<(RistrettoDeckDleqWire, ArchivedRistrettoPlayerProof)> {
    if input.len() != RISTRETTO_PLAYER_PROOF_DECK_SIZE || output.len() != input.len() {
        return Err(TexasAirError::SpecViolation(
            "deck DLEQ requires the fixed 52-card deck".into(),
        ));
    }
    if *sk == RistrettoScalar::zero() || pk.is_identity() || RistrettoCurve::base_g() * *sk != *pk {
        return Err(TexasAirError::SpecViolation(
            "deck DLEQ witness does not match the public key".into(),
        ));
    }
    for index in 0..input.len() {
        if !input[index].is_valid() || !output[index].is_valid() {
            return Err(TexasAirError::SpecViolation(
                "deck DLEQ ciphertext is invalid".into(),
            ));
        }
        if input[index].c1 != output[index].c1 {
            return Err(TexasAirError::SpecViolation(
                "deck DLEQ requires c1 invariance".into(),
            ));
        }
        let d2 = direction.compute_d2(&input[index].c2, &output[index].c2);
        if d2.is_identity() || d2 != input[index].c1 * *sk {
            return Err(TexasAirError::SpecViolation(
                "deck DLEQ output deck does not match the witness key".into(),
            ));
        }
    }
    let mut nonce;
    let mut commitments = [[0u8; 32]; RISTRETTO_PLAYER_PROOF_DECK_SIZE];
    let mut commitment_pk;
    loop {
        nonce = RistrettoScalar::random(rng);
        if nonce == RistrettoScalar::zero() {
            continue;
        }
        commitment_pk = RistrettoCurve::base_g() * nonce;
        let mut degenerate = commitment_pk.is_identity();
        for (index, commitment) in commitments.iter_mut().enumerate() {
            let point = input[index].c1 * nonce;
            *commitment = point_bytes(&point);
            degenerate |= point.is_identity();
        }
        if !degenerate {
            break;
        }
    }
    let mut transcript = FlockShuffleTranscript::new(direction.protocol());
    absorb_deck_dleq_statement(
        &mut transcript,
        context,
        pk,
        input,
        output,
        &commitments,
        &point_bytes(&commitment_pk),
    );
    let challenge = transcript.challenge::<RistrettoCurve>(b"challenge").scalar;
    let response = nonce + challenge * *sk;
    let wire = RistrettoDeckDleqWire {
        per_card_commitments: commitments,
        commitment_pk: point_bytes(&commitment_pk),
        response: scalar_bytes(&response),
    };
    Ok((wire, finish_player_proof(&transcript)?))
}

/// Convenience constructors matching the zgame naming.
pub fn prove_remask(
    input: &[RistrettoCiphertext],
    output: &[RistrettoCiphertext],
    sk: &RistrettoScalar,
    pk: &RistrettoPoint,
    context: &[u8],
    rng: &mut (impl CryptoRng + RngCore),
) -> TexasAirResult<(RistrettoDeckDleqWire, ArchivedRistrettoPlayerProof)> {
    prove_deck_dleq(
        RistrettoDeckDleqDirection::Remask,
        input,
        output,
        sk,
        pk,
        context,
        rng,
    )
}

/// Leave direction used by `fold_with_proof` and table departure.
pub fn prove_leave(
    input: &[RistrettoCiphertext],
    output: &[RistrettoCiphertext],
    sk: &RistrettoScalar,
    pk: &RistrettoPoint,
    context: &[u8],
    rng: &mut (impl CryptoRng + RngCore),
) -> TexasAirResult<(RistrettoDeckDleqWire, ArchivedRistrettoPlayerProof)> {
    prove_deck_dleq(
        RistrettoDeckDleqDirection::Leave,
        input,
        output,
        sk,
        pk,
        context,
        rng,
    )
}

/// Verify one batched deck DLEQ.
pub fn verify_deck_dleq(
    direction: RistrettoDeckDleqDirection,
    input: &[RistrettoCiphertext],
    output: &[RistrettoCiphertext],
    pk: &RistrettoPoint,
    context: &[u8],
    wire: &RistrettoDeckDleqWire,
    proof: &ArchivedRistrettoPlayerProof,
) -> TexasAirResult<()> {
    if input.len() != RISTRETTO_PLAYER_PROOF_DECK_SIZE || output.len() != input.len() {
        return Err(TexasAirError::SpecViolation(
            "deck DLEQ requires the fixed 52-card deck".into(),
        ));
    }
    if pk.is_identity() {
        return Err(TexasAirError::SpecViolation(
            "deck DLEQ public key is the identity".into(),
        ));
    }
    for index in 0..input.len() {
        if !input[index].is_valid() || !output[index].is_valid() {
            return Err(TexasAirError::SpecViolation(
                "deck DLEQ ciphertext is invalid".into(),
            ));
        }
        if input[index].c1 != output[index].c1 {
            return Err(TexasAirError::ConstraintUnsatisfied(
                "deck DLEQ c1 invariance failed".into(),
            ));
        }
    }
    let mut commitments = [RistrettoPoint::identity(); RISTRETTO_PLAYER_PROOF_DECK_SIZE];
    for (index, bytes) in wire.per_card_commitments.iter().enumerate() {
        commitments[index] = decode_point(bytes, "deck DLEQ per-card commitment")?;
        if commitments[index].is_identity() {
            return Err(TexasAirError::ConstraintUnsatisfied(
                "deck DLEQ per-card commitment is the identity".into(),
            ));
        }
    }
    let commitment_pk = decode_point(&wire.commitment_pk, "deck DLEQ key commitment")?;
    let response = decode_scalar(&wire.response, "deck DLEQ response")?;
    if commitment_pk.is_identity() {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "deck DLEQ key commitment is the identity".into(),
        ));
    }
    let mut transcript = FlockShuffleTranscript::new(direction.protocol());
    absorb_deck_dleq_statement(
        &mut transcript,
        context,
        pk,
        input,
        output,
        &wire.per_card_commitments,
        &wire.commitment_pk,
    );
    let challenge = verify_player_proof(proof, &mut transcript)?;
    if RistrettoCurve::base_g() * response != commitment_pk + *pk * challenge {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "deck DLEQ key equation is not satisfied".into(),
        ));
    }
    for index in 0..RISTRETTO_PLAYER_PROOF_DECK_SIZE {
        let d2 = direction.compute_d2(&input[index].c2, &output[index].c2);
        if input[index].c1 * response != commitments[index] + d2 * challenge {
            return Err(TexasAirError::ConstraintUnsatisfied(
                "deck DLEQ per-card equation is not satisfied".into(),
            ));
        }
    }
    Ok(())
}

/// Verify the remask direction.
pub fn verify_remask(
    input: &[RistrettoCiphertext],
    output: &[RistrettoCiphertext],
    pk: &RistrettoPoint,
    context: &[u8],
    wire: &RistrettoDeckDleqWire,
    proof: &ArchivedRistrettoPlayerProof,
) -> TexasAirResult<()> {
    verify_deck_dleq(
        RistrettoDeckDleqDirection::Remask,
        input,
        output,
        pk,
        context,
        wire,
        proof,
    )
}

/// Verify the leave direction.
pub fn verify_leave(
    input: &[RistrettoCiphertext],
    output: &[RistrettoCiphertext],
    pk: &RistrettoPoint,
    context: &[u8],
    wire: &RistrettoDeckDleqWire,
    proof: &ArchivedRistrettoPlayerProof,
) -> TexasAirResult<()> {
    verify_deck_dleq(
        RistrettoDeckDleqDirection::Leave,
        input,
        output,
        pk,
        context,
        wire,
        proof,
    )
}

// ============================================================================
// fold_with_proof V2 crypto layer
// ============================================================================

/// Complete `fold_with_proof` V2 crypto statement: the acting player folds,
/// their key layer is removed from the encrypted deck, and the aggregate key
/// drops their public key.  After this proof the seat is folded in the
/// canonical state machine and is excluded from every later reveal-token
/// assignment.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ArchivedRistrettoFoldWithProofV2 {
    /// Leave-direction DLEQ wire over the deck transition.
    pub deck: RistrettoDeckDleqWire,
    /// Flock transcript proof.
    pub proof: ArchivedRistrettoPlayerProof,
    /// New aggregate public key (`old_aggregate − player_pk`).
    pub new_aggregate_pk: [u8; 32],
    /// Digest binding the caller's canonical transition context
    /// (table/hand/seat/call sequence), absorbed into the transcript.
    pub context_digest: [u8; 32],
}

/// The deck transition applied by a folding player: remove their key layer.
pub fn fold_deck_transition(
    input: &[RistrettoCiphertext],
    sk: &RistrettoScalar,
) -> TexasAirResult<Vec<RistrettoCiphertext>> {
    if input.len() != RISTRETTO_PLAYER_PROOF_DECK_SIZE {
        return Err(TexasAirError::SpecViolation(
            "fold deck transition requires the fixed 52-card deck".into(),
        ));
    }
    let mut output = Vec::with_capacity(input.len());
    for ciphertext in input {
        let unmasked = RistrettoCiphertext {
            c1: ciphertext.c1,
            c2: ciphertext.c2 - ciphertext.c1 * *sk,
        };
        if !unmasked.is_valid() {
            return Err(TexasAirError::SpecViolation(
                "fold deck transition produced an invalid ciphertext".into(),
            ));
        }
        output.push(unmasked);
    }
    Ok(output)
}

/// Prove the complete `fold_with_proof` crypto relation.
pub fn prove_fold_with_proof_v2(
    player_sk: &RistrettoScalar,
    player_pk: &RistrettoPoint,
    aggregate_pk: &RistrettoPoint,
    input_deck: &[RistrettoCiphertext],
    context_digest: [u8; 32],
    rng: &mut (impl CryptoRng + RngCore),
) -> TexasAirResult<(Vec<RistrettoCiphertext>, ArchivedRistrettoFoldWithProofV2)> {
    let output_deck = fold_deck_transition(input_deck, player_sk)?;
    let new_aggregate = *aggregate_pk - *player_pk;
    let mut context = context_digest.to_vec();
    context.extend_from_slice(&point_bytes(&new_aggregate));
    let (deck, proof) = prove_leave(
        input_deck,
        &output_deck,
        player_sk,
        player_pk,
        &context,
        rng,
    )?;
    Ok((
        output_deck,
        ArchivedRistrettoFoldWithProofV2 {
            deck,
            proof,
            new_aggregate_pk: point_bytes(&new_aggregate),
            context_digest,
        },
    ))
}

/// Verify the complete `fold_with_proof` crypto relation.  The aggregate-key
/// update is checked natively (public point arithmetic) alongside the DLEQ.
pub fn verify_fold_with_proof_v2(
    player_pk: &RistrettoPoint,
    aggregate_pk: &RistrettoPoint,
    input_deck: &[RistrettoCiphertext],
    output_deck: &[RistrettoCiphertext],
    archive: &ArchivedRistrettoFoldWithProofV2,
) -> TexasAirResult<()> {
    let new_aggregate = decode_point(&archive.new_aggregate_pk, "fold new aggregate key")?;
    if new_aggregate != *aggregate_pk - *player_pk {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "fold aggregate-key update is detached from the player key".into(),
        ));
    }
    let mut context = archive.context_digest.to_vec();
    context.extend_from_slice(&archive.new_aggregate_pk);
    verify_leave(
        input_deck,
        output_deck,
        player_pk,
        &context,
        &archive.deck,
        &archive.proof,
    )
}


// ============================================================================
// Poseidon2-M31 admission path (Flock-free)
// ============================================================================

use crate::ristretto_poseidon2_air::Poseidon2ChainSpec;
use crate::ristretto_poseidon2_transcript::Poseidon2M31Transcript;

fn absorb_deck_dleq_statement_poseidon2(
    transcript: &mut Poseidon2M31Transcript,
    context: &[u8],
    pk: &RistrettoPoint,
    input: &[RistrettoCiphertext],
    output: &[RistrettoCiphertext],
    commitments: &[[u8; 32]; RISTRETTO_PLAYER_PROOF_DECK_SIZE],
    commitment_pk: &[u8; 32],
) {
    transcript.append_message(b"context", context);
    transcript.append_message(b"pk", &point_bytes(pk));
    for ciphertext in input {
        transcript.append_message(b"in_c1", &point_bytes(&ciphertext.c1));
        transcript.append_message(b"in_c2", &point_bytes(&ciphertext.c2));
    }
    for ciphertext in output {
        transcript.append_message(b"out_c1", &point_bytes(&ciphertext.c1));
        transcript.append_message(b"out_c2", &point_bytes(&ciphertext.c2));
    }
    for commitment in commitments {
        transcript.append_message(b"a_i", commitment);
    }
    transcript.append_message(b"commitment_pk", commitment_pk);
}

/// Derive the deck-DLEQ challenge from the Poseidon2-M31 transcript.
pub(crate) fn derive_deck_dleq_challenge_poseidon2(
    direction: RistrettoDeckDleqDirection,
    input: &[RistrettoCiphertext],
    output: &[RistrettoCiphertext],
    pk: &RistrettoPoint,
    context: &[u8],
    wire: &RistrettoDeckDleqWire,
) -> TexasAirResult<(RistrettoScalar, Poseidon2ChainSpec)> {
    if input.len() != RISTRETTO_PLAYER_PROOF_DECK_SIZE || output.len() != input.len() {
        return Err(TexasAirError::SpecViolation(
            "deck DLEQ requires the fixed 52-card deck".into(),
        ));
    }
    let mut transcript = Poseidon2M31Transcript::new(direction.protocol());
    absorb_deck_dleq_statement_poseidon2(
        &mut transcript,
        context,
        pk,
        input,
        output,
        &wire.per_card_commitments,
        &wire.commitment_pk,
    );
    let challenge = transcript.challenge::<RistrettoCurve>(b"challenge").scalar;
    Ok((challenge, transcript.into_chain_spec()))
}

/// Prove one batched deck DLEQ under the Poseidon2-M31 transcript (the
/// Flock-free admission path); the transcript run is the foldable chain.
pub fn prove_deck_dleq_poseidon2(
    direction: RistrettoDeckDleqDirection,
    input: &[RistrettoCiphertext],
    output: &[RistrettoCiphertext],
    sk: &RistrettoScalar,
    pk: &RistrettoPoint,
    context: &[u8],
    rng: &mut (impl CryptoRng + RngCore),
) -> TexasAirResult<(RistrettoDeckDleqWire, Poseidon2ChainSpec)> {
    if input.len() != RISTRETTO_PLAYER_PROOF_DECK_SIZE || output.len() != input.len() {
        return Err(TexasAirError::SpecViolation(
            "deck DLEQ requires the fixed 52-card deck".into(),
        ));
    }
    if *sk == RistrettoScalar::zero() || pk.is_identity() || RistrettoCurve::base_g() * *sk != *pk {
        return Err(TexasAirError::SpecViolation(
            "deck DLEQ witness does not match the public key".into(),
        ));
    }
    for index in 0..input.len() {
        if !input[index].is_valid() || !output[index].is_valid() {
            return Err(TexasAirError::SpecViolation(
                "deck DLEQ ciphertext is invalid".into(),
            ));
        }
        if input[index].c1 != output[index].c1 {
            return Err(TexasAirError::SpecViolation(
                "deck DLEQ requires c1 invariance".into(),
            ));
        }
        let d2 = direction.compute_d2(&input[index].c2, &output[index].c2);
        if d2.is_identity() || d2 != input[index].c1 * *sk {
            return Err(TexasAirError::SpecViolation(
                "deck DLEQ output deck does not match the witness key".into(),
            ));
        }
    }
    let mut nonce;
    let mut commitments = [[0u8; 32]; RISTRETTO_PLAYER_PROOF_DECK_SIZE];
    let mut commitment_pk;
    loop {
        nonce = RistrettoScalar::random(rng);
        if nonce == RistrettoScalar::zero() {
            continue;
        }
        commitment_pk = RistrettoCurve::base_g() * nonce;
        let mut degenerate = commitment_pk.is_identity();
        for (index, commitment) in commitments.iter_mut().enumerate() {
            let point = input[index].c1 * nonce;
            *commitment = point_bytes(&point);
            degenerate |= point.is_identity();
        }
        if !degenerate {
            break;
        }
    }
    let mut transcript = Poseidon2M31Transcript::new(direction.protocol());
    absorb_deck_dleq_statement_poseidon2(
        &mut transcript,
        context,
        pk,
        input,
        output,
        &commitments,
        &point_bytes(&commitment_pk),
    );
    let challenge = transcript.challenge::<RistrettoCurve>(b"challenge").scalar;
    let response = nonce + challenge * *sk;
    let wire = RistrettoDeckDleqWire {
        per_card_commitments: commitments,
        commitment_pk: point_bytes(&commitment_pk),
        response: scalar_bytes(&response),
    };
    Ok((wire, transcript.into_chain_spec()))
}

/// Verify one Poseidon2-path deck DLEQ natively; returns the replayed
/// chain statement for folding.
pub fn verify_deck_dleq_poseidon2(
    direction: RistrettoDeckDleqDirection,
    input: &[RistrettoCiphertext],
    output: &[RistrettoCiphertext],
    pk: &RistrettoPoint,
    context: &[u8],
    wire: &RistrettoDeckDleqWire,
) -> TexasAirResult<Poseidon2ChainSpec> {
    let (challenge, spec) =
        derive_deck_dleq_challenge_poseidon2(direction, input, output, pk, context, wire)?;
    let response = decode_scalar(&wire.response, "deck DLEQ response")?;
    let commitment_pk = decode_point(&wire.commitment_pk, "deck DLEQ key commitment")?;
    if RistrettoCurve::base_g() * response != commitment_pk + *pk * challenge {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "deck DLEQ key equation is not satisfied".into(),
        ));
    }
    for index in 0..input.len() {
        let d2 = direction.compute_d2(&input[index].c2, &output[index].c2);
        let commitment = decode_point(&wire.per_card_commitments[index], "card commitment")?;
        if input[index].c1 * response != commitment + d2 * challenge {
            return Err(TexasAirError::ConstraintUnsatisfied(
                "deck DLEQ per-card equation is not satisfied".into(),
            ));
        }
    }
    Ok(spec)
}

/// Derive the pk-ownership challenge from the Poseidon2-M31 transcript
/// (same absorb order as the Flock path); the whole run is the foldable
/// chain statement.
pub(crate) fn derive_pk_ownership_challenge_poseidon2(
    pk: &RistrettoPoint,
    context: &[u8],
    wire: &RistrettoPkOwnershipWire,
) -> (RistrettoScalar, Poseidon2ChainSpec) {
    let mut transcript = Poseidon2M31Transcript::new(PK_OWNERSHIP_PROTOCOL);
    transcript.append_message(b"context", context);
    transcript.append_message(b"pk", &point_bytes(pk));
    transcript.append_message(b"commitment", &wire.commitment);
    let challenge = transcript.challenge::<RistrettoCurve>(b"challenge").scalar;
    (challenge, transcript.into_chain_spec())
}

/// Derive the reveal-token challenge from the Poseidon2-M31 transcript.
pub(crate) fn derive_reveal_token_challenge_poseidon2(
    pk: &RistrettoPoint,
    ciphertext: &RistrettoCiphertext,
    reveal_token: &RistrettoPoint,
    context: &[u8],
    wire: &RistrettoRevealTokenWire,
) -> (RistrettoScalar, Poseidon2ChainSpec) {
    let mut transcript = Poseidon2M31Transcript::new(REVEAL_TOKEN_PROTOCOL);
    transcript.append_message(b"context", context);
    transcript.append_message(b"pk", &point_bytes(pk));
    transcript.append_message(b"c1", &point_bytes(&ciphertext.c1));
    transcript.append_message(b"c2", &point_bytes(&ciphertext.c2));
    transcript.append_message(b"reveal_token", &point_bytes(reveal_token));
    transcript.append_message(b"t1", &wire.commitment_t1);
    transcript.append_message(b"t2", &wire.commitment_t2);
    let challenge = transcript.challenge::<RistrettoCurve>(b"challenge").scalar;
    (challenge, transcript.into_chain_spec())
}

/// Prove knowledge of `sk` with `pk = sk·G` under the Poseidon2-M31
/// transcript: the Fiat--Shamir run is returned as a foldable chain
/// statement instead of a Flock archive.
pub fn prove_pk_ownership_poseidon2(
    sk: &RistrettoScalar,
    pk: &RistrettoPoint,
    context: &[u8],
    rng: &mut (impl CryptoRng + RngCore),
) -> TexasAirResult<(RistrettoPkOwnershipWire, Poseidon2ChainSpec)> {
    if *sk == RistrettoScalar::zero() || pk.is_identity() || RistrettoCurve::base_g() * *sk != *pk {
        return Err(TexasAirError::SpecViolation(
            "pk-ownership witness does not match the public key".into(),
        ));
    }
    let mut transcript = Poseidon2M31Transcript::new(PK_OWNERSHIP_PROTOCOL);
    transcript.append_message(b"context", context);
    transcript.append_message(b"pk", &point_bytes(pk));
    let (nonce, commitment) = loop {
        let nonce = RistrettoScalar::random(rng);
        if nonce == RistrettoScalar::zero() {
            continue;
        }
        let commitment = RistrettoCurve::base_g() * nonce;
        if !commitment.is_identity() {
            break (nonce, commitment);
        }
    };
    transcript.append_message(b"commitment", &point_bytes(&commitment));
    let challenge = transcript.challenge::<RistrettoCurve>(b"challenge").scalar;
    let response = nonce + challenge * *sk;
    let wire = RistrettoPkOwnershipWire {
        commitment: point_bytes(&commitment),
        response: scalar_bytes(&response),
    };
    Ok((wire, transcript.into_chain_spec()))
}

/// Verify one Poseidon2-path key-ownership proof natively; returns the
/// replayed chain statement for folding.
pub fn verify_pk_ownership_poseidon2(
    pk: &RistrettoPoint,
    context: &[u8],
    wire: &RistrettoPkOwnershipWire,
) -> TexasAirResult<Poseidon2ChainSpec> {
    if pk.is_identity() {
        return Err(TexasAirError::SpecViolation(
            "pk-ownership public key is the identity".into(),
        ));
    }
    let commitment = decode_point(&wire.commitment, "pk-ownership commitment")?;
    let response = decode_scalar(&wire.response, "pk-ownership response")?;
    if commitment.is_identity() {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "pk-ownership commitment is the identity".into(),
        ));
    }
    let (challenge, spec) = derive_pk_ownership_challenge_poseidon2(pk, context, wire);
    if RistrettoCurve::base_g() * response != commitment + *pk * challenge {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "pk-ownership equation is not satisfied".into(),
        ));
    }
    Ok(spec)
}

/// Prove `token = sk·ct.c1` under the Poseidon2-M31 transcript.
pub fn prove_reveal_token_poseidon2(
    sk: &RistrettoScalar,
    pk: &RistrettoPoint,
    ciphertext: &RistrettoCiphertext,
    reveal_token: &RistrettoPoint,
    context: &[u8],
    rng: &mut (impl CryptoRng + RngCore),
) -> TexasAirResult<(RistrettoRevealTokenWire, Poseidon2ChainSpec)> {
    if *sk == RistrettoScalar::zero()
        || pk.is_identity()
        || RistrettoCurve::base_g() * *sk != *pk
        || !ciphertext.is_valid()
        || reveal_token.is_identity()
        || *reveal_token != ciphertext.c1 * *sk
    {
        return Err(TexasAirError::SpecViolation(
            "reveal-token witness does not match the statement".into(),
        ));
    }
    let mut transcript = Poseidon2M31Transcript::new(REVEAL_TOKEN_PROTOCOL);
    transcript.append_message(b"context", context);
    transcript.append_message(b"pk", &point_bytes(pk));
    transcript.append_message(b"c1", &point_bytes(&ciphertext.c1));
    transcript.append_message(b"c2", &point_bytes(&ciphertext.c2));
    transcript.append_message(b"reveal_token", &point_bytes(reveal_token));
    let (nonce, t1, t2) = loop {
        let nonce = RistrettoScalar::random(rng);
        if nonce == RistrettoScalar::zero() {
            continue;
        }
        let t1 = RistrettoCurve::base_g() * nonce;
        let t2 = ciphertext.c1 * nonce;
        if !t1.is_identity() && !t2.is_identity() {
            break (nonce, t1, t2);
        }
    };
    transcript.append_message(b"t1", &point_bytes(&t1));
    transcript.append_message(b"t2", &point_bytes(&t2));
    let challenge = transcript.challenge::<RistrettoCurve>(b"challenge").scalar;
    let response = nonce + challenge * *sk;
    let wire = RistrettoRevealTokenWire {
        commitment_t1: point_bytes(&t1),
        commitment_t2: point_bytes(&t2),
        response: scalar_bytes(&response),
    };
    Ok((wire, transcript.into_chain_spec()))
}

/// Verify one Poseidon2-path reveal-token proof natively; returns the
/// replayed chain statement for folding.
pub fn verify_reveal_token_poseidon2(
    pk: &RistrettoPoint,
    ciphertext: &RistrettoCiphertext,
    reveal_token: &RistrettoPoint,
    context: &[u8],
    wire: &RistrettoRevealTokenWire,
) -> TexasAirResult<Poseidon2ChainSpec> {
    let (challenge, spec) =
        derive_reveal_token_challenge_poseidon2(pk, ciphertext, reveal_token, context, wire);
    let response = decode_scalar(&wire.response, "reveal-token response")?;
    let t1 = decode_point(&wire.commitment_t1, "reveal-token t1")?;
    let t2 = decode_point(&wire.commitment_t2, "reveal-token t2")?;
    if RistrettoCurve::base_g() * response != t1 + *pk * challenge
        || ciphertext.c1 * response != t2 + *reveal_token * challenge
    {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "reveal-token equation is not satisfied".into(),
        ));
    }
    Ok(spec)
}

#[cfg(test)]
mod tests {

    #[test]
    fn poseidon2_batched_reveal_and_fold_roundtrip() {
        let mut rng = test_rng();
        let (sk, pk) = keypair(&mut rng);
        let cards = sample_deck(&pk, &mut rng);
        let tokens: Vec<RistrettoPoint> = cards.iter().map(|ct| ct.c1 * sk).collect();

        let (wire, spec) =
            prove_reveal_tokens_batched_poseidon2(&sk, &pk, &cards, &tokens, b"showdown", &mut rng)
                .expect("poseidon2 batched reveal proof");
        spec.validate().expect("spec shape");
        let replayed = verify_reveal_tokens_batched_poseidon2(&pk, &cards, &tokens, b"showdown", &wire)
            .expect("poseidon2 batched reveal verify");
        assert_eq!(spec, replayed);
        // Wrong context and tampered response both fail.
        assert!(
            verify_reveal_tokens_batched_poseidon2(&pk, &cards, &tokens, b"other", &wire).is_err()
        );
        let mut tampered = wire;
        tampered.response[20] ^= 1;
        assert!(
            verify_reveal_tokens_batched_poseidon2(&pk, &cards, &tokens, b"showdown", &tampered)
                .is_err()
        );

        // Fold twin: prove a leave over the same deck and verify.
        let (mask_sk, mask_pk) = keypair(&mut rng);
        let (folded, archive) = prove_fold_with_proof_v2_poseidon2(
            &mask_sk,
            &mask_pk,
            &pk,
            &cards,
            [0xAB; 32],
            &mut rng,
        )
        .expect("poseidon2 fold proof");
        archive.chain_spec.validate().expect("fold spec shape");
        verify_fold_with_proof_v2_poseidon2(&mask_pk, &pk, &cards, &folded, &archive)
            .expect("poseidon2 fold verify");
        // Spliced output deck must fail.
        let mut swapped = folded.clone();
        swapped[0].c2 = folded[1].c2;
        assert!(
            verify_fold_with_proof_v2_poseidon2(&mask_pk, &pk, &cards, &swapped, &archive).is_err()
        );
    }
    use super::*;

    #[test]
    fn poseidon2_player_proofs_prove_verify_and_reject() {
        use rand::SeedableRng;
        use rand::rngs::StdRng;
        let mut rng = StdRng::seed_from_u64(0x51DE_0002);

        let sk = RistrettoScalar::random(&mut rng);
        let pk = RistrettoCurve::base_g() * sk;
        let (wire, spec) =
            prove_pk_ownership_poseidon2(&sk, &pk, b"hand-1-seat-0", &mut rng)
                .expect("poseidon2 ownership proof");
        spec.validate().expect("spec shape");
        let replayed = verify_pk_ownership_poseidon2(&pk, b"hand-1-seat-0", &wire)
            .expect("poseidon2 ownership verify");
        assert_eq!(spec, replayed);
        // Wrong context derives a different challenge.
        assert!(verify_pk_ownership_poseidon2(&pk, b"other-context", &wire).is_err());
        // Tampered response breaks the equation.
        let mut tampered = wire;
        tampered.response[3] ^= 1;
        assert!(verify_pk_ownership_poseidon2(&pk, b"hand-1-seat-0", &tampered).is_err());

        let card = RistrettoCurve::hash_to_curve(b"poseidon2/card/1");
        let randomness = RistrettoScalar::random(&mut rng);
        let ciphertext = RistrettoCiphertext::encrypt(&card, &pk, &randomness);
        let reveal_token = ciphertext.c1 * sk;
        let (wire, spec) = prove_reveal_token_poseidon2(
            &sk,
            &pk,
            &ciphertext,
            &reveal_token,
            b"hand-1-reveal",
            &mut rng,
        )
        .expect("poseidon2 reveal proof");
        let replayed = verify_reveal_token_poseidon2(
            &pk,
            &ciphertext,
            &reveal_token,
            b"hand-1-reveal",
            &wire,
        )
        .expect("poseidon2 reveal verify");
        assert_eq!(spec, replayed);
        let mut tampered = wire;
        tampered.commitment_t1[5] ^= 1;
        assert!(
            verify_reveal_token_poseidon2(&pk, &ciphertext, &reveal_token, b"hand-1-reveal", &tampered)
                .is_err()
        );
    }

    fn test_rng() -> rand::rngs::StdRng {
        use rand::SeedableRng;
        rand::rngs::StdRng::seed_from_u64(0x0F01_D2A3)
    }

    fn keypair(rng: &mut rand::rngs::StdRng) -> (RistrettoScalar, RistrettoPoint) {
        let sk = RistrettoScalar::random(rng);
        (sk, RistrettoCurve::base_g() * sk)
    }

    fn sample_deck(pk: &RistrettoPoint, rng: &mut rand::rngs::StdRng) -> Vec<RistrettoCiphertext> {
        (0..RISTRETTO_PLAYER_PROOF_DECK_SIZE)
            .map(|index| {
                let card = RistrettoCurve::hash_to_curve(format!("bench/card/{index}").as_bytes());
                let randomness = RistrettoScalar::random(rng);
                RistrettoCiphertext::encrypt(&card, pk, &randomness)
            })
            .collect()
    }

    #[test]
#[ignore = "slow prove (~10-25s); full gate runs --include-ignored"]
    fn pk_ownership_roundtrip_and_tamper() {
        let mut rng = test_rng();
        let (sk, pk) = keypair(&mut rng);
        let (wire, proof) = prove_pk_ownership(&sk, &pk, b"table7-hand3", &mut rng).unwrap();
        verify_pk_ownership(&pk, b"table7-hand3", &wire, &proof).unwrap();

        // Wrong context detaches the challenge schedule.
        assert!(verify_pk_ownership(&pk, b"table8-hand3", &wire, &proof).is_err());

        // Wrong key fails the equation.
        let (_, other_pk) = keypair(&mut rng);
        assert!(verify_pk_ownership(&other_pk, b"table7-hand3", &wire, &proof).is_err());

        // Spliced response byte (kept canonical via byte 20).
        let mut tampered = wire;
        tampered.response[20] ^= 1;
        assert!(verify_pk_ownership(&pk, b"table7-hand3", &tampered, &proof).is_err());
    }

    #[ignore = "slow prove (~7s); full gate runs `--include-ignored`"]
    #[test]
    fn reveal_token_roundtrip_and_tamper() {
        let mut rng = test_rng();
        let (sk, pk) = keypair(&mut rng);
        let card = RistrettoCurve::hash_to_curve(b"bench/card/17");
        let randomness = RistrettoScalar::random(&mut rng);
        let ciphertext = RistrettoCiphertext::encrypt(&card, &pk, &randomness);
        let token = ciphertext.c1 * sk;
        assert_eq!(
            ciphertext.c2 - token,
            card,
            "token must reveal the plaintext"
        );

        let (wire, proof) =
            prove_reveal_token(&sk, &pk, &ciphertext, &token, b"reveal-ctx", &mut rng).unwrap();
        verify_reveal_token(&pk, &ciphertext, &token, b"reveal-ctx", &wire, &proof).unwrap();

        // A token from a different key fails.
        let (other_sk, _) = keypair(&mut rng);
        let wrong_token = ciphertext.c1 * other_sk;
        assert!(
            verify_reveal_token(&pk, &ciphertext, &wrong_token, b"reveal-ctx", &wire, &proof)
                .is_err()
        );

        // Token bound to a different ciphertext fails.
        let other = RistrettoCiphertext::encrypt(&card, &pk, &RistrettoScalar::random(&mut rng));
        assert!(verify_reveal_token(&pk, &other, &token, b"reveal-ctx", &wire, &proof).is_err());

        // Spliced commitment.
        let mut tampered = wire;
        tampered.commitment_t2[20] ^= 1;
        assert!(
            verify_reveal_token(&pk, &ciphertext, &token, b"reveal-ctx", &tampered, &proof)
                .is_err()
        );
    }

    #[test]
#[ignore = "slow prove (~10-25s); full gate runs --include-ignored"]
    fn remask_and_leave_roundtrip_with_direction_binding() {
        let mut rng = test_rng();
        let (sk, pk) = keypair(&mut rng);
        let input = sample_deck(&pk, &mut rng);

        // Remask: add a layer under a second key.
        let (mask_sk, mask_pk) = keypair(&mut rng);
        let remasked: Vec<RistrettoCiphertext> = input
            .iter()
            .map(|ct| RistrettoCiphertext {
                c1: ct.c1,
                c2: ct.c2 + ct.c1 * mask_sk,
            })
            .collect();
        let (remask_wire, remask_proof) = prove_remask(
            &input,
            &remasked,
            &mask_sk,
            &mask_pk,
            b"remask-ctx",
            &mut rng,
        )
        .unwrap();
        verify_remask(
            &input,
            &remasked,
            &mask_pk,
            b"remask-ctx",
            &remask_wire,
            &remask_proof,
        )
        .unwrap();

        // A remask proof must not verify in the leave direction.
        assert!(
            verify_leave(
                &input,
                &remasked,
                &mask_pk,
                b"remask-ctx",
                &remask_wire,
                &remask_proof
            )
            .is_err()
        );

        // Leave: strip the layer back.
        let (leave_wire, leave_proof) = prove_leave(
            &remasked,
            &input,
            &mask_sk,
            &mask_pk,
            b"leave-ctx",
            &mut rng,
        )
        .unwrap();
        verify_leave(
            &remasked,
            &input,
            &mask_pk,
            b"leave-ctx",
            &leave_wire,
            &leave_proof,
        )
        .unwrap();

        // Splicing one output card breaks the per-card equation.
        let mut swapped = remasked.clone();
        swapped[5].c2 = remasked[6].c2;
        assert!(
            verify_remask(
                &input,
                &swapped,
                &mask_pk,
                b"remask-ctx",
                &remask_wire,
                &remask_proof
            )
            .is_err()
        );

        // Splicing a per-card commitment breaks the equation set.
        let mut tampered = remask_wire;
        tampered.per_card_commitments[9][20] ^= 1;
        assert!(
            verify_remask(
                &input,
                &remasked,
                &mask_pk,
                b"remask-ctx",
                &tampered,
                &remask_proof
            )
            .is_err()
        );

        let _ = (sk, pk);
    }

    #[test]
#[ignore = "slow prove (~10-25s); full gate runs --include-ignored"]
    fn reveal_tokens_batched_roundtrip_and_tamper() {
        let mut rng = test_rng();
        let (sk, pk) = keypair(&mut rng);
        let cards = sample_deck(&pk, &mut rng)[..11].to_vec();
        let tokens: Vec<RistrettoPoint> = cards.iter().map(|card| card.c1 * sk).collect();
        let (wire, proof) =
            prove_reveal_tokens_batched(&sk, &pk, &cards, &tokens, b"showdown-ctx", &mut rng)
                .unwrap();
        verify_reveal_tokens_batched(&pk, &cards, &tokens, b"showdown-ctx", &wire, &proof).unwrap();

        // One tampered token breaks its per-card equation.
        let mut swapped = tokens.clone();
        swapped[4] = tokens[5];
        assert!(
            verify_reveal_tokens_batched(&pk, &cards, &swapped, b"showdown-ctx", &wire, &proof)
                .is_err()
        );

        // A token list from another key fails.
        let (other_sk, _) = keypair(&mut rng);
        let wrong: Vec<RistrettoPoint> = cards.iter().map(|card| card.c1 * other_sk).collect();
        assert!(
            verify_reveal_tokens_batched(&pk, &cards, &wrong, b"showdown-ctx", &wire, &proof)
                .is_err()
        );

        // Spliced per-card commitment.
        let mut tampered = wire.clone();
        tampered.commitment_t2[7][20] ^= 1;
        assert!(
            verify_reveal_tokens_batched(&pk, &cards, &tokens, b"showdown-ctx", &tampered, &proof)
                .is_err()
        );

        // Spliced response.
        let mut tampered = wire;
        tampered.response[20] ^= 1;
        assert!(
            verify_reveal_tokens_batched(&pk, &cards, &tokens, b"showdown-ctx", &tampered, &proof)
                .is_err()
        );
    }

    #[test]
#[ignore = "slow prove (~10-25s); full gate runs --include-ignored"]
    fn fold_with_proof_roundtrip_and_tamper() {
        let mut rng = test_rng();
        let (sk, pk) = keypair(&mut rng);
        let (_, other_pk) = keypair(&mut rng);
        let aggregate = pk + other_pk;
        let input = sample_deck(&aggregate, &mut rng);
        let context_digest = [0x5A; 32];

        let (output, archive) =
            prove_fold_with_proof_v2(&sk, &pk, &aggregate, &input, context_digest, &mut rng)
                .unwrap();
        verify_fold_with_proof_v2(&pk, &aggregate, &input, &output, &archive).unwrap();

        // The new aggregate must drop exactly the folding key.
        let new_aggregate = decode_point(&archive.new_aggregate_pk, "aggregate").unwrap();
        assert_eq!(new_aggregate, other_pk);

        // Tampered aggregate update.
        let mut tampered = archive.clone();
        tampered.new_aggregate_pk[20] ^= 1;
        assert!(verify_fold_with_proof_v2(&pk, &aggregate, &input, &output, &tampered).is_err());

        // Tampered deck output.
        let mut swapped = output.clone();
        swapped[3].c2 = output[4].c2;
        assert!(verify_fold_with_proof_v2(&pk, &aggregate, &input, &swapped, &archive).is_err());

        // Tampered response.
        let mut tampered = archive.clone();
        tampered.deck.response[20] ^= 1;
        assert!(verify_fold_with_proof_v2(&pk, &aggregate, &input, &output, &tampered).is_err());
    }
}

// ============================================================================
// Batched reveal tokens (one proof per player over every revealed card)
// ============================================================================

/// Batched reveal-token wire: one Schnorr-style response shared by every
/// revealed card of one player.  Per-card commitments `T2_i = card_i.c1·ω`
/// prevent aggregate attacks across cards.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct RistrettoRevealTokensBatchWire {
    /// `T1 = G·ω`.
    pub commitment_t1: [u8; 32],
    /// One `T2_i = cards[i].c1·ω` per revealed card, in statement order.
    pub commitment_t2: Vec<[u8; 32]>,
    /// `s = ω + c·sk`.
    pub response: [u8; 32],
}

fn absorb_reveal_batch_statement(
    transcript: &mut FlockShuffleTranscript,
    context: &[u8],
    pk: &RistrettoPoint,
    cards: &[RistrettoCiphertext],
    tokens: &[RistrettoPoint],
    commitment_t1: &[u8; 32],
    commitment_t2: &[[u8; 32]],
) {
    transcript.absorb(b"context", context);
    transcript.absorb(b"pk", &point_bytes(pk));
    for ciphertext in cards {
        transcript.absorb(b"c1", &point_bytes(&ciphertext.c1));
        transcript.absorb(b"c2", &point_bytes(&ciphertext.c2));
    }
    for token in tokens {
        transcript.absorb(b"reveal_token", &point_bytes(token));
    }
    transcript.absorb(b"t1", commitment_t1);
    for commitment in commitment_t2 {
        transcript.absorb(b"t2", commitment);
    }
}

/// Prove, in one batched DLEQ, that the same registered `sk` behind
/// `pk = sk·G` produces every `tokens[i] = sk·cards[i].c1`.
///
/// This collapses a player's whole showdown submission (one proof per
/// revealed card) into a single proof: one Flock transcript, one challenge,
/// one response — an order-of-magnitude size and latency win on the reveal
/// phase.
pub fn prove_reveal_tokens_batched(
    sk: &RistrettoScalar,
    pk: &RistrettoPoint,
    cards: &[RistrettoCiphertext],
    tokens: &[RistrettoPoint],
    context: &[u8],
    rng: &mut (impl CryptoRng + RngCore),
) -> TexasAirResult<(RistrettoRevealTokensBatchWire, ArchivedRistrettoPlayerProof)> {
    if cards.is_empty() || cards.len() != tokens.len() {
        return Err(TexasAirError::SpecViolation(
            "batched reveal tokens require matching non-empty card/token lists".into(),
        ));
    }
    if *sk == RistrettoScalar::zero() || pk.is_identity() || RistrettoCurve::base_g() * *sk != *pk {
        return Err(TexasAirError::SpecViolation(
            "batched reveal-token witness does not match the public key".into(),
        ));
    }
    for (card, token) in cards.iter().zip(tokens) {
        if !card.is_valid() || token.is_identity() || *token != card.c1 * *sk {
            return Err(TexasAirError::SpecViolation(
                "batched reveal-token witness does not match a statement entry".into(),
            ));
        }
    }
    let (nonce, t1) = loop {
        let nonce = RistrettoScalar::random(rng);
        if nonce == RistrettoScalar::zero() {
            continue;
        }
        let t1 = RistrettoCurve::base_g() * nonce;
        if !t1.is_identity() {
            break (nonce, t1);
        }
    };
    let mut commitment_t2 = Vec::with_capacity(cards.len());
    let mut degenerate = false;
    for card in cards {
        let point = card.c1 * nonce;
        degenerate |= point.is_identity();
        commitment_t2.push(point_bytes(&point));
    }
    if degenerate {
        return Err(TexasAirError::SpecViolation(
            "batched reveal-token commitment degenerated to the identity; reseed".into(),
        ));
    }
    let mut transcript = FlockShuffleTranscript::new(REVEAL_TOKEN_PROTOCOL);
    absorb_reveal_batch_statement(
        &mut transcript,
        context,
        pk,
        cards,
        tokens,
        &point_bytes(&t1),
        &commitment_t2,
    );
    let challenge = transcript.challenge::<RistrettoCurve>(b"challenge").scalar;
    let response = nonce + challenge * *sk;
    let wire = RistrettoRevealTokensBatchWire {
        commitment_t1: point_bytes(&t1),
        commitment_t2,
        response: scalar_bytes(&response),
    };
    Ok((wire, finish_player_proof(&transcript)?))
}

/// Verify one batched reveal-token proof.
pub fn verify_reveal_tokens_batched(
    pk: &RistrettoPoint,
    cards: &[RistrettoCiphertext],
    tokens: &[RistrettoPoint],
    context: &[u8],
    wire: &RistrettoRevealTokensBatchWire,
    proof: &ArchivedRistrettoPlayerProof,
) -> TexasAirResult<()> {
    if cards.is_empty() || cards.len() != tokens.len() || wire.commitment_t2.len() != cards.len() {
        return Err(TexasAirError::SpecViolation(
            "batched reveal-token statement shapes disagree".into(),
        ));
    }
    if pk.is_identity() {
        return Err(TexasAirError::SpecViolation(
            "batched reveal-token public key is the identity".into(),
        ));
    }
    for (card, token) in cards.iter().zip(tokens) {
        if !card.is_valid() || token.is_identity() {
            return Err(TexasAirError::SpecViolation(
                "batched reveal-token statement contains identity points".into(),
            ));
        }
    }
    let t1 = decode_point(&wire.commitment_t1, "batched reveal-token commitment")?;
    let response = decode_scalar(&wire.response, "batched reveal-token response")?;
    if t1.is_identity() {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "batched reveal-token commitment is the identity".into(),
        ));
    }
    let mut commitments = Vec::with_capacity(cards.len());
    for bytes in &wire.commitment_t2 {
        let point = decode_point(bytes, "batched reveal-token per-card commitment")?;
        if point.is_identity() {
            return Err(TexasAirError::ConstraintUnsatisfied(
                "batched reveal-token per-card commitment is the identity".into(),
            ));
        }
        commitments.push(point);
    }
    let mut transcript = FlockShuffleTranscript::new(REVEAL_TOKEN_PROTOCOL);
    absorb_reveal_batch_statement(
        &mut transcript,
        context,
        pk,
        cards,
        tokens,
        &wire.commitment_t1,
        &wire.commitment_t2,
    );
    let challenge = verify_player_proof(proof, &mut transcript)?;
    if RistrettoCurve::base_g() * response != t1 + *pk * challenge {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "batched reveal-token key equation is not satisfied".into(),
        ));
    }
    for ((card, token), commitment) in cards.iter().zip(tokens).zip(&commitments) {
        if card.c1 * response != *commitment + *token * challenge {
            return Err(TexasAirError::ConstraintUnsatisfied(
                "batched reveal-token per-card equation is not satisfied".into(),
            ));
        }
    }
    Ok(())
}

// ============================================================================
// Batched reveal tokens, Poseidon2-M31 route (Flock-free deployment path)
// ============================================================================

fn absorb_reveal_batch_statement_poseidon2(
    transcript: &mut Poseidon2M31Transcript,
    context: &[u8],
    pk: &RistrettoPoint,
    cards: &[RistrettoCiphertext],
    tokens: &[RistrettoPoint],
    commitment_t1: &[u8; 32],
    commitment_t2: &[[u8; 32]],
) {
    transcript.append_message(b"context", context);
    transcript.append_message(b"pk", &point_bytes(pk));
    for ciphertext in cards {
        transcript.append_message(b"c1", &point_bytes(&ciphertext.c1));
        transcript.append_message(b"c2", &point_bytes(&ciphertext.c2));
    }
    for token in tokens {
        transcript.append_message(b"reveal_token", &point_bytes(token));
    }
    transcript.append_message(b"t1", commitment_t1);
    for commitment in commitment_t2 {
        transcript.append_message(b"t2", commitment);
    }
}

/// Prove one batched reveal-token DLEQ under the Poseidon2-M31 transcript
/// (deployment-route twin of [`prove_reveal_tokens_batched`]; the returned
/// chain spec folds into the unified admission STARK's Poseidon2 segment
/// instead of carrying a Flock archive).
pub fn prove_reveal_tokens_batched_poseidon2(
    sk: &RistrettoScalar,
    pk: &RistrettoPoint,
    cards: &[RistrettoCiphertext],
    tokens: &[RistrettoPoint],
    context: &[u8],
    rng: &mut (impl CryptoRng + RngCore),
) -> TexasAirResult<(RistrettoRevealTokensBatchWire, Poseidon2ChainSpec)> {
    if cards.is_empty() || cards.len() != tokens.len() {
        return Err(TexasAirError::SpecViolation(
            "batched reveal tokens require matching non-empty card/token lists".into(),
        ));
    }
    if *sk == RistrettoScalar::zero() || pk.is_identity() || RistrettoCurve::base_g() * *sk != *pk {
        return Err(TexasAirError::SpecViolation(
            "batched reveal-token witness does not match the public key".into(),
        ));
    }
    for (card, token) in cards.iter().zip(tokens) {
        if !card.is_valid() || token.is_identity() || *token != card.c1 * *sk {
            return Err(TexasAirError::SpecViolation(
                "batched reveal-token witness does not match a statement entry".into(),
            ));
        }
    }
    let (nonce, t1) = loop {
        let nonce = RistrettoScalar::random(rng);
        if nonce == RistrettoScalar::zero() {
            continue;
        }
        let t1 = RistrettoCurve::base_g() * nonce;
        if !t1.is_identity() {
            break (nonce, t1);
        }
    };
    let mut commitment_t2 = Vec::with_capacity(cards.len());
    let mut degenerate = false;
    for card in cards {
        let point = card.c1 * nonce;
        degenerate |= point.is_identity();
        commitment_t2.push(point_bytes(&point));
    }
    if degenerate {
        return Err(TexasAirError::SpecViolation(
            "batched reveal-token commitment degenerated to the identity; reseed".into(),
        ));
    }
    let mut transcript = Poseidon2M31Transcript::new(REVEAL_TOKEN_PROTOCOL);
    absorb_reveal_batch_statement_poseidon2(
        &mut transcript,
        context,
        pk,
        cards,
        tokens,
        &point_bytes(&t1),
        &commitment_t2,
    );
    let challenge = transcript.challenge::<RistrettoCurve>(b"challenge").scalar;
    let response = nonce + challenge * *sk;
    let wire = RistrettoRevealTokensBatchWire {
        commitment_t1: point_bytes(&t1),
        commitment_t2,
        response: scalar_bytes(&response),
    };
    Ok((wire, transcript.into_chain_spec()))
}

/// Verify one Poseidon2-path batched reveal-token proof natively; returns
/// the replayed chain statement for folding.
pub fn verify_reveal_tokens_batched_poseidon2(
    pk: &RistrettoPoint,
    cards: &[RistrettoCiphertext],
    tokens: &[RistrettoPoint],
    context: &[u8],
    wire: &RistrettoRevealTokensBatchWire,
) -> TexasAirResult<Poseidon2ChainSpec> {
    if cards.is_empty() || cards.len() != tokens.len() || wire.commitment_t2.len() != cards.len() {
        return Err(TexasAirError::SpecViolation(
            "batched reveal-token statement shapes disagree".into(),
        ));
    }
    if pk.is_identity() {
        return Err(TexasAirError::SpecViolation(
            "batched reveal-token public key is the identity".into(),
        ));
    }
    for (card, token) in cards.iter().zip(tokens) {
        if !card.is_valid() || token.is_identity() {
            return Err(TexasAirError::SpecViolation(
                "batched reveal-token statement contains identity points".into(),
            ));
        }
    }
    let t1 = decode_point(&wire.commitment_t1, "batched reveal-token commitment")?;
    let response = decode_scalar(&wire.response, "batched reveal-token response")?;
    if t1.is_identity() {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "batched reveal-token commitment is the identity".into(),
        ));
    }
    let mut commitments = Vec::with_capacity(cards.len());
    for bytes in &wire.commitment_t2 {
        let point = decode_point(bytes, "batched reveal-token per-card commitment")?;
        if point.is_identity() {
            return Err(TexasAirError::ConstraintUnsatisfied(
                "batched reveal-token per-card commitment is the identity".into(),
            ));
        }
        commitments.push(point);
    }
    let mut transcript = Poseidon2M31Transcript::new(REVEAL_TOKEN_PROTOCOL);
    absorb_reveal_batch_statement_poseidon2(
        &mut transcript,
        context,
        pk,
        cards,
        tokens,
        &wire.commitment_t1,
        &wire.commitment_t2,
    );
    let challenge = transcript.challenge::<RistrettoCurve>(b"challenge").scalar;
    if RistrettoCurve::base_g() * response != t1 + *pk * challenge {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "batched reveal-token key equation is not satisfied".into(),
        ));
    }
    for ((card, token), commitment) in cards.iter().zip(tokens).zip(&commitments) {
        if card.c1 * response != *commitment + *token * challenge {
            return Err(TexasAirError::ConstraintUnsatisfied(
                "batched reveal-token per-card equation is not satisfied".into(),
            ));
        }
    }
    Ok(transcript.into_chain_spec())
}

// ============================================================================
// fold_with_proof V2, Poseidon2-M31 route (Flock-free deployment path)
// ============================================================================

/// Poseidon2-route twin of [`ArchivedRistrettoFoldWithProofV2`]: the deck
/// DLEQ wire plus the foldable transcript chain spec, no Flock archive.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ArchivedRistrettoFoldWithProofV2Poseidon2 {
    /// Leave-direction DLEQ wire over the deck transition.
    pub deck: RistrettoDeckDleqWire,
    /// Poseidon2-M31 transcript chain schedule.
    pub chain_spec: Poseidon2ChainSpec,
    /// New aggregate public key (`old_aggregate − player_pk`).
    pub new_aggregate_pk: [u8; 32],
    /// Digest binding the caller's canonical transition context.
    pub context_digest: [u8; 32],
}

/// Prove the complete `fold_with_proof` crypto relation under the
/// Poseidon2-M31 transcript.
pub fn prove_fold_with_proof_v2_poseidon2(
    player_sk: &RistrettoScalar,
    player_pk: &RistrettoPoint,
    aggregate_pk: &RistrettoPoint,
    input_deck: &[RistrettoCiphertext],
    context_digest: [u8; 32],
    rng: &mut (impl CryptoRng + RngCore),
) -> TexasAirResult<(Vec<RistrettoCiphertext>, ArchivedRistrettoFoldWithProofV2Poseidon2)> {
    let output_deck = fold_deck_transition(input_deck, player_sk)?;
    let new_aggregate = *aggregate_pk - *player_pk;
    let mut context = context_digest.to_vec();
    context.extend_from_slice(&point_bytes(&new_aggregate));
    let (deck, chain_spec) = prove_deck_dleq_poseidon2(
        RistrettoDeckDleqDirection::Leave,
        input_deck,
        &output_deck,
        player_sk,
        player_pk,
        &context,
        rng,
    )?;
    Ok((
        output_deck,
        ArchivedRistrettoFoldWithProofV2Poseidon2 {
            deck,
            chain_spec,
            new_aggregate_pk: point_bytes(&new_aggregate),
            context_digest,
        },
    ))
}

/// Verify the Poseidon2-route `fold_with_proof` relation natively.
pub fn verify_fold_with_proof_v2_poseidon2(
    player_pk: &RistrettoPoint,
    aggregate_pk: &RistrettoPoint,
    input_deck: &[RistrettoCiphertext],
    output_deck: &[RistrettoCiphertext],
    archive: &ArchivedRistrettoFoldWithProofV2Poseidon2,
) -> TexasAirResult<()> {
    let new_aggregate = decode_point(&archive.new_aggregate_pk, "fold new aggregate key")?;
    if new_aggregate != *aggregate_pk - *player_pk {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "fold aggregate-key update is detached from the player key".into(),
        ));
    }
    let mut context = archive.context_digest.to_vec();
    context.extend_from_slice(&archive.new_aggregate_pk);
    verify_deck_dleq_poseidon2(
        RistrettoDeckDleqDirection::Leave,
        input_deck,
        output_deck,
        player_pk,
        &context,
        &archive.deck,
    )
    .map(|_| ())
}

/// Derive the batched reveal-token challenge from the Poseidon2-M31
/// transcript (the admission decomposition's replay of
/// [`prove_reveal_tokens_batched_poseidon2`]).
#[must_use]
pub fn derive_reveal_tokens_batched_challenge_poseidon2(
    pk: &RistrettoPoint,
    cards: &[RistrettoCiphertext],
    tokens: &[RistrettoPoint],
    context: &[u8],
    wire: &RistrettoRevealTokensBatchWire,
) -> (RistrettoScalar, Poseidon2ChainSpec) {
    let mut transcript = Poseidon2M31Transcript::new(REVEAL_TOKEN_PROTOCOL);
    absorb_reveal_batch_statement_poseidon2(
        &mut transcript,
        context,
        pk,
        cards,
        tokens,
        &wire.commitment_t1,
        &wire.commitment_t2,
    );
    let challenge = transcript.challenge::<RistrettoCurve>(b"challenge").scalar;
    (challenge, transcript.into_chain_spec())
}
