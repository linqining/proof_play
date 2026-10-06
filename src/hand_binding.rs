//! Unified hand binding across the two proof tracks (docs/design/DUAL_PROOF_PROTOCOL.md
//! §6 — soundness core).
//!
//! The dual-proof settlement accepts a hand only when **both** proofs carry
//! the same `hand_binding`:
//!
//! - **P** (poker_protocol sigma proofs on BN254): every per-player proof's
//!   authenticated registration context references this digest;
//! - **G** (牌局过程 STARK): the canonical state mirror's public inputs carry
//!   the same digest.
//!
//! This prevents cross-hand recombination ("拼装攻击"): a P proof from hand A
//! cannot be paired with a G proof from hand B, because the binding digest is
//! Poseidon-sensitive to every field.
//!
//! Encoding discipline: every input is a canonical felt252 and the digest is
//! `starknet_crypto::poseidon_hash_many`, matching `settlement_hash.cairo`'s
//! conventions so the Cairo verifier (`PokerDualSettlement`) can recompute
//! the same value from calldata.
//!
//! Layout (domain tag first, then fixed fields, then per-player and
//! per-shuffle repetitions):
//!
//! ```text
//! hand_binding = poseidon_hash_many(
//!     DOMAIN_TAG,
//!     table_id, hand_id, num_players,
//!     players[0..num_players],              // ordered seat addresses
//!     num_decks, deck_commitments[0..num_decks],  // deck_commit_0..deck_commit_N
//!     reveal_commitment,
//!     state_root_pre, state_root_post,
//!     settlement_digest,
//! )
//! ```

use crate::error::{TexasAirError, TexasAirResult};
use starknet_crypto::Felt;

/// Domain separator, ASCII-encoded into a felt. The Cairo verifier must
/// embed the identical value.
pub const HAND_BINDING_DOMAIN: &[u8] = b"poker_dual_hand_binding_v1";

/// Maximum deck commitments bound into one hand: initial deck plus one per
/// player shuffle (nine-seat table).
pub const MAX_DECK_COMMITMENTS: usize = 10;

/// Inputs to the unified hand binding digest.
#[derive(Debug, Clone)]
pub struct HandBindingInput {
    /// Table identifier (Cairo-side storage key component).
    pub table_id: u64,
    /// Hand identifier within the table; monotonic per table.
    pub hand_id: u64,
    /// Ordered seat addresses (seat order is binding-sensitive).
    pub players: Vec<Felt>,
    /// Deck commitment chain: `deck_commit_0` (canonical aggregate-key deck)
    /// through the final post-shuffle commitment. Length must be 1..=10.
    pub deck_commitments: Vec<Felt>,
    /// Reveal-commitment digest over all public reveal tokens.
    pub reveal_commitment: Felt,
    /// Canonical state root before the hand.
    pub state_root_pre: Felt,
    /// Canonical state root after the hand.
    pub state_root_post: Felt,
    /// The existing Poseidon settlement digest (`settlement_hash.cairo`).
    pub settlement_digest: Felt,
}

impl HandBindingInput {
    /// Shape validation: seat and deck-chain length bounds.
    pub fn validate(&self) -> TexasAirResult<()> {
        if self.players.is_empty() || self.players.len() > crate::texas_canonical::MAX_CANONICAL_SEATS {
            return Err(TexasAirError::SpecViolation(format!(
                "hand_binding players out of range: {}",
                self.players.len()
            )));
        }
        if self.deck_commitments.is_empty()
            || self.deck_commitments.len() > MAX_DECK_COMMITMENTS
        {
            return Err(TexasAirError::SpecViolation(format!(
                "hand_binding deck commitments out of range: {}",
                self.deck_commitments.len()
            )));
        }
        Ok(())
    }
}

/// Compute the unified hand binding digest.
pub fn compute_hand_binding(input: &HandBindingInput) -> TexasAirResult<Felt> {
    input.validate()?;

    let mut fields: Vec<Felt> = Vec::with_capacity(
        5 + input.players.len() + input.deck_commitments.len(),
    );
    fields.push(domain_tag_felt());
    fields.push(Felt::from(input.table_id));
    fields.push(Felt::from(input.hand_id));
    fields.push(Felt::from(input.players.len() as u64));
    fields.extend_from_slice(&input.players);
    fields.push(Felt::from(input.deck_commitments.len() as u64));
    fields.extend_from_slice(&input.deck_commitments);
    fields.push(input.reveal_commitment);
    fields.push(input.state_root_pre);
    fields.push(input.state_root_post);
    fields.push(input.settlement_digest);

    Ok(starknet_crypto::poseidon_hash_many(&fields))
}

/// felt252 of [`HAND_BINDING_DOMAIN`] (big-endian, modulo the Stark prime;
/// the ASCII string is 25 bytes, well below 2^251).
fn domain_tag_felt() -> Felt {
    Felt::from_bytes_be_slice(HAND_BINDING_DOMAIN)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn felt(v: u64) -> Felt {
        Felt::from(v)
    }

    fn sample() -> HandBindingInput {
        HandBindingInput {
            table_id: 1,
            hand_id: 42,
            players: vec![felt(0xaaaa), felt(0xbbbb), felt(0xcccc)],
            deck_commitments: vec![felt(0x1111), felt(0x2222), felt(0x3333), felt(0x4444)],
            reveal_commitment: felt(0x5555),
            state_root_pre: felt(0x6666),
            state_root_post: felt(0x7777),
            settlement_digest: felt(0x8888),
        }
    }

    #[test]
    fn binding_is_deterministic_and_matches_manual_encoding() {
        let input = sample();
        let a = compute_hand_binding(&input).unwrap();
        let b = compute_hand_binding(&input).unwrap();
        assert_eq!(a, b);
        assert_ne!(a, Felt::ZERO);

        // Manual layout check: the digest must equal poseidon_hash_many over
        // the documented field order.
        let expected = starknet_crypto::poseidon_hash_many(&[
            domain_tag_felt(),
            felt(1),
            felt(42),
            felt(3),
            felt(0xaaaa),
            felt(0xbbbb),
            felt(0xcccc),
            felt(4),
            felt(0x1111),
            felt(0x2222),
            felt(0x3333),
            felt(0x4444),
            felt(0x5555),
            felt(0x6666),
            felt(0x7777),
            felt(0x8888),
        ]);
        assert_eq!(a, expected);
    }

    #[test]
    fn binding_is_sensitive_to_every_field() {
        let base = compute_hand_binding(&sample()).unwrap();

        let mut cases: Vec<HandBindingInput> = Vec::new();
        let mut c = sample();
        c.table_id += 1;
        cases.push(c);
        let mut c = sample();
        c.hand_id += 1;
        cases.push(c);
        let mut c = sample();
        c.players[1] = felt(0xbeef);
        cases.push(c);
        let mut c = sample();
        c.players.reverse(); // seat order is binding-sensitive
        cases.push(c);
        let mut c = sample();
        c.deck_commitments[2] = felt(0xd00d);
        cases.push(c);
        let mut c = sample();
        c.reveal_commitment = felt(0xf00d);
        cases.push(c);
        let mut c = sample();
        c.state_root_pre = felt(0x1234);
        cases.push(c);
        let mut c = sample();
        c.state_root_post = felt(0x5678);
        cases.push(c);
        let mut c = sample();
        c.settlement_digest = felt(0x9abc);
        cases.push(c);

        for (i, case) in cases.iter().enumerate() {
            let digest = compute_hand_binding(case).unwrap();
            assert_ne!(base, digest, "case {i} must change the binding");
        }
    }

    #[test]
    fn binding_rejects_out_of_range_shapes() {
        let mut c = sample();
        c.players.clear();
        assert!(compute_hand_binding(&c).is_err());

        let mut c = sample();
        c.players = (0..10).map(felt).collect();
        assert!(compute_hand_binding(&c).is_err());

        let mut c = sample();
        c.deck_commitments.clear();
        assert!(compute_hand_binding(&c).is_err());

        let mut c = sample();
        c.deck_commitments = (0..11).map(felt).collect();
        assert!(compute_hand_binding(&c).is_err());
    }

    #[test]
    fn binding_accepts_full_nine_seat_ten_deck_shape() {
        let c = HandBindingInput {
            table_id: u64::MAX,
            hand_id: u64::MAX,
            players: (0..9).map(felt).collect(),
            deck_commitments: (0..10).map(felt).collect(),
            reveal_commitment: felt(1),
            state_root_pre: felt(2),
            state_root_post: felt(3),
            settlement_digest: felt(4),
        };
        assert!(compute_hand_binding(&c).is_ok());
    }
}
