//! Canonical commitment for the encrypted Texas Poker deck.
//!
//! The commitment is intentionally computed over the ordered ciphertext bytes,
//! not just the number of cards.  This binds every compressed G1 point while
//! keeping the current AIR public-input schema's compact `u64` interface.

use blake2::Blake2bVar;
use blake2::digest::{Update, VariableOutput};
use borsh::to_vec;
use poker_l1::contracts::texas_poker::types::TexasPokerTable;

const DOMAIN: &[u8] = b"zchain.texas_poker.deck_ciphertexts.v1";

/// Return the domain-separated commitment for the table's ordered ciphertext deck.
///
/// Each ciphertext uses the protocol crate's canonical Borsh encoding (two
/// compressed BLS12-381 G1 points).  The first eight digest bytes are retained
/// because the method AIR statement currently exposes a `u64` commitment.
#[must_use]
pub fn deck_commitment(table: &TexasPokerTable) -> u64 {
    let encoded = to_vec(&table.deck_state.encrypted)
        .expect("ElGamal ciphertext Borsh serialization is infallible");
    let mut material = Vec::with_capacity(DOMAIN.len() + 1 + 8 + encoded.len());
    material.extend_from_slice(DOMAIN);
    material.push(1); // encoding version
    material.extend_from_slice(&(table.deck_state.encrypted.len() as u64).to_be_bytes());
    material.extend_from_slice(&encoded);

    let mut digest = [0u8; 32];
    let mut hasher = Blake2bVar::new(32).expect("Blake2b-256 output size is valid");
    hasher.update(&material);
    hasher
        .finalize_variable(&mut digest)
        .expect("fixed Blake2b output buffer has the configured size");
    u64::from_be_bytes(digest[..8].try_into().expect("8-byte commitment prefix"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use poker_l1::contracts::texas_poker::utils::{g1_generator as g1_gen, g1_identity as g1_id, G1Projective};
    use poker_l1::object_model::ObjectID;
    use poker_l1::contracts::texas_poker::types::{ElGamalCiphertext, TexasPokerTable};

    fn table_with_ciphertexts(count: usize, second: G1Projective) -> TexasPokerTable {
        let mut table = TexasPokerTable::new(
            ObjectID::new([0xCC; 20], 0),
            [0u8; 20],
            6,
            50,
            100,
        );
        let g = g1_gen();
        table.deck_state.encrypted = (0..count)
            .map(|_| ElGamalCiphertext { c1: g, c2: second })
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        table
    }

    #[test]
    fn commitment_changes_when_ciphertext_changes_at_same_length() {
        let first = table_with_ciphertexts(52, g1_gen());
        let second = table_with_ciphertexts(52, g1_id());
        assert_ne!(deck_commitment(&first), deck_commitment(&second));
    }

    #[test]
    fn commitment_is_order_sensitive_and_deterministic() {
        let mut first = table_with_ciphertexts(52, g1_gen());
        first.deck_state.encrypted[1].c1 = g1_id();
        let mut second = first.clone();
        second.deck_state.encrypted.swap(0, 1);
        assert_ne!(deck_commitment(&first), deck_commitment(&second));
        assert_eq!(deck_commitment(&first), deck_commitment(&first));
    }
}
