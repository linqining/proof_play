//! Blake2b-256 authentication of canonical Texas state-image byte preimages.
//!
//! `CanonicalStateImage::commitment` is `Blake2b-256(domain || Borsh(image))`.
//! This module turns that byte-level relation into a shared lookup-backed
//! STARK statement.  The canonical transition AIR binds its fixed 841-limb
//! state-image projection to the same endpoint bytes; admission remains closed
//! until the remaining VM and Ristretto relations are composed as well.

#![allow(missing_docs)]

use crate::error::{TexasAirError, TexasAirResult};
use crate::hash_prover::HashProofProvider as _;
use crate::texas_canonical::CanonicalStateImage;

/// Domain prefix used by `CanonicalStateImage::commitment`.
pub const CANONICAL_STATE_IMAGE_DOMAIN: &[u8] = b"zchain.texas.canonical-state.v3";

/// The two Blake2b statements for one canonical transition's state endpoints.
/// The first statement authenticates the pre-image and the second the
/// post-image.  They share one lookup-table commitment.
#[derive(Debug, Clone, PartialEq, Eq, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct ArchivedCanonicalStateImageHashProof {
    pub hashes: crate::blake3_flock::ArchivedFlockHashesProof,
}

/// Return the exact byte preimage covered by a canonical state commitment.
/// This is a prover-side serialization routine; verification consumes the
/// archived byte statement and invokes only STARK verification.
pub fn canonical_state_image_preimage(image: &CanonicalStateImage) -> TexasAirResult<Vec<u8>> {
    let encoded = borsh::to_vec(image)
        .map_err(|error| TexasAirError::SerializationError(error.to_string()))?;
    let mut preimage = Vec::with_capacity(CANONICAL_STATE_IMAGE_DOMAIN.len() + encoded.len());
    preimage.extend_from_slice(CANONICAL_STATE_IMAGE_DOMAIN);
    preimage.extend_from_slice(&encoded);
    Ok(preimage)
}

/// Prove the two endpoint state-image commitments with one shared Blake2b
/// lookup proof.  Native Blake2b is not used to form or verify the result.
pub fn prove_canonical_state_image_hashes(
    pre: &CanonicalStateImage,
    post: &CanonicalStateImage,
) -> TexasAirResult<ArchivedCanonicalStateImageHashProof> {
    let statements = vec![
        crate::hash_prover::HashStatement::new(
            canonical_state_image_preimage(pre)?,
            pre.commitment(),
        ),
        crate::hash_prover::HashStatement::new(
            canonical_state_image_preimage(post)?,
            post.commitment(),
        ),
    ];
    let hashes = crate::blake3_flock::FlockProvider
        .prove_statements(&statements)
        .map_err(|error| {
            TexasAirError::SpecViolation(format!("flock state-image proof failed: {error:?}"))
        })?;
    let crate::hash_prover::ArchivedHashProof::Flock(hashes) = hashes else {
        return Err(TexasAirError::SpecViolation(
            "flock backend must produce flock proofs".into(),
        ));
    };
    Ok(ArchivedCanonicalStateImageHashProof { hashes })
}

/// Verify that the archived endpoint byte statements hash to the exact public
/// canonical commitments.  This function neither serializes images nor calls
/// a native hash implementation.
pub fn verify_canonical_state_image_hashes(
    archive: &ArchivedCanonicalStateImageHashProof,
    pre_commitment: [u8; 32],
    post_commitment: [u8; 32],
) -> TexasAirResult<()> {
    let statements = &archive.hashes.statements;
    let [pre, post] = statements.as_slice() else {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "canonical state-image hash proof must contain exactly two endpoint statements".into(),
        ));
    };
    if pre.digest != pre_commitment || post.digest != post_commitment {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "canonical state-image hash proof is detached from an endpoint commitment".into(),
        ));
    }
    crate::blake3_flock::verify_flock_archive(&archive.hashes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::texas_canonical::{
        CANONICAL_ABI_VERSION, CanonicalPhase, CanonicalSeat, MAX_CANONICAL_SEATS,
        NO_CANONICAL_SEAT,
    };

    fn image() -> CanonicalStateImage {
        CanonicalStateImage {
            abi_version: CANONICAL_ABI_VERSION,
            table_id: 7,
            hand_id: 1,
            call_seq: 0,
            phase: CanonicalPhase::Waiting,
            phase_subtag: 0,
            street: 0,
            current_turn: NO_CANONICAL_SEAT,
            deadline_ms: 0,
            shuffle_timeout_ms: 10_000,
            reveal_timeout_ms: 10_000,
            betting_timeout_ms: 30_000,
            reconstruct_timeout_ms: 10_000,
            showdown_display_ms: 3_000,
            current_bet: 0,
            min_raise: 0,
            chip_pool: 0,
            pot: 0,
            button: 0,
            last_bb_seat: NO_CANONICAL_SEAT,
            max_players: 2,
            acted_mask: 0,
            leave_after_hand_mask: 0,
            protocol_pending_mask: 0,
            board_cards_commitment: [1; 32],
            deck_commitment: [2; 32],
            reveal_commitment: [3; 32],
            reconstruction_commitment: [4; 32],
            run_it_twice_commitment: [5; 32],
            rules_commitment: [6; 32],
            governance_commitment: [7; 32],
            settlement_commitment: [8; 32],
            custody_commitment: [9; 32],
            lifecycle_root: [10; 32],
            overlay_root: [11; 32],
            state_root: [12; 32],
            seats: [CanonicalSeat::EMPTY; MAX_CANONICAL_SEATS],
        }
    }

    #[test]
    fn preimage_is_the_exact_native_commitment_input() {
        let image = image();
        let preimage = canonical_state_image_preimage(&image).unwrap();
        assert_eq!(
            image.commitment(),
            crate::blake3_flock::blake3_chain_digest(&preimage)
        );
    }

    #[test]
    fn verifier_rejects_an_endpoint_commitment_splice_before_stark_work() {
        let image = image();
        let preimage = canonical_state_image_preimage(&image).unwrap();
        let hashes = crate::blake3_flock::ArchivedFlockHashesProof {
            statements: vec![
                crate::hash_prover::HashStatement {
                    message: preimage.clone(),
                    digest: image.commitment(),
                },
                crate::hash_prover::HashStatement {
                    message: preimage,
                    digest: image.commitment(),
                },
            ],
            chains: Vec::new(),
            merkles: Vec::new(),
        };
        let archive = ArchivedCanonicalStateImageHashProof { hashes };
        let mut wrong = image.commitment();
        wrong[0] ^= 1;
        assert!(verify_canonical_state_image_hashes(&archive, wrong, image.commitment()).is_err());
    }

    #[test]
    #[ignore = "proves two multi-block canonical state-image hashes through the shared lookup batch"]
    fn state_image_hash_proof_roundtrip_binds_both_endpoint_commitments() {
        let pre = image();
        let mut post = pre.clone();
        post.call_seq = 1;
        let archive = prove_canonical_state_image_hashes(&pre, &post).unwrap();
        verify_canonical_state_image_hashes(&archive, pre.commitment(), post.commitment()).unwrap();

        let mut tampered = archive;
        tampered.hashes.statements[1].digest[0] ^= 1;
        assert!(
            verify_canonical_state_image_hashes(&tampered, pre.commitment(), post.commitment(),)
                .is_err()
        );
    }
}
