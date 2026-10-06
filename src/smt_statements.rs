//! Statement-level representation of L1 sparse-Merkle openings.
//!
//! One fixed-value SMT opening is exactly 257 public BLAKE3 statements: the
//! leaf `H1(key || value)` and one internal node `H1(left || right)` per
//! height, where `H1` is a single BLAKE3 compression over 64 bytes (see
//! [`crate::blake3_flock::blake3_hash64`]).  Expressing the path as plain
//! [`HashStatement`]s lets the shared hash-prover seam batch it with the
//! rules and state-image statements: the flock backend recognizes the run
//! structurally (each parent message contains the previous digest as one
//! 32-byte half) and proves it as ONE Merkle-path statement binding the
//! public leaf, root, and direction bits.
//!
//! Security is statement-level: the (leaf, key, root) binding is proven by
//! the binary-field prover; the host only checks EQUALITY over public bytes
//! (direction bits derived from the public key, node ordering, terminal-root
//! match).  No native hashing runs on the verify path beyond the single
//! leaf compression.
//!
//! NOTE: the BLAKE3 64-byte node hash replaces the previous Blake2b
//! `H(0x00/0x01 || …)` semantics; the L1 tree definition follows this
//! switch (domain separation between leaf and internal nodes is structural:
//! the leaf is the first statement of a run and its inputs are the public
//! key/value pair).

#![allow(missing_docs)]

use crate::blake2b_smt_witness::{Blake2bSmtFixedValuePathWitness, SMT_PATH_SIBLINGS};
use crate::blake3_flock::blake3_hash64;
use crate::error::{TexasAirError, TexasAirResult};
use crate::hash_prover::HashStatement;

/// `1 + 256` statements per fixed-value opening: leaf plus every parent.
pub const SMT_PATH_STATEMENTS: usize = SMT_PATH_SIBLINGS + 1;

/// The 64-byte semantic message of the leaf compression.
#[must_use]
pub fn smt_leaf_message(key: &[u8; 32], value: &[u8; 32]) -> Vec<u8> {
    let mut message = Vec::with_capacity(64);
    message.extend_from_slice(key);
    message.extend_from_slice(value);
    message
}

/// The 64-byte semantic message of one internal-node compression.
#[must_use]
pub fn smt_internal_message(left: &[u8; 32], right: &[u8; 32]) -> Vec<u8> {
    let mut message = Vec::with_capacity(64);
    message.extend_from_slice(left);
    message.extend_from_slice(right);
    message
}

/// Project one SMT opening into its ordered public statements:
/// `[leaf, parent_1, ..., parent_256]` with digests `witness.nodes`.
///
/// # Errors
/// Returns `ConstraintUnsatisfied` when the terminal node does not match the
/// public root, mirroring the incumbent witness preflight.
pub fn smt_path_statements(
    witness: &Blake2bSmtFixedValuePathWitness,
) -> TexasAirResult<[HashStatement; SMT_PATH_STATEMENTS]> {
    if !witness.terminal_node_matches_root() {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "SMT statement witness terminal node does not match the root".into(),
        ));
    }
    let mut statements = Vec::with_capacity(SMT_PATH_STATEMENTS);
    statements.push(HashStatement::new(
        smt_leaf_message(&witness.key, &witness.value),
        witness.nodes[0],
    ));
    for height in 1..=SMT_PATH_SIBLINGS {
        let child = witness.nodes[height - 1];
        let sibling = witness.siblings[height - 1];
        // Level 1 always places the child on the LEFT: the flock merkle
        // shift convention requires the path start (the leaf digest) in the
        // X_L slot.  Key bit 0 is instead bound by the leaf digest itself,
        // which hashes the full public key; the remaining key bits bind via
        // the protocol's direction bits.
        let (left, right) = if height == 1 || !witness.direction_bit(height) {
            (child, sibling)
        } else {
            (sibling, child)
        };
        statements.push(HashStatement::new(
            smt_internal_message(&left, &right),
            witness.nodes[height],
        ));
    }
    Ok(statements
        .try_into()
        .expect("exactly 1 + SMT_PATH_SIBLINGS statements"))
}

/// Host-side structural check over PUBLIC bytes only: the verified statement
/// digests must equal the witness nodes, and the node ordering must follow
/// the key's direction bits up to the public root.  Together with the
/// prover's Merkle-path statement this binds `key/value` to `root`.
pub fn verify_smt_path_statements(
    witness: &Blake2bSmtFixedValuePathWitness,
    statements: &[HashStatement],
) -> TexasAirResult<()> {
    if !witness.terminal_node_matches_root() {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "SMT statement witness terminal node does not match the root".into(),
        ));
    }
    let expected = smt_path_statements(witness)?;
    if statements.len() != expected.len() {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "SMT statement count does not match the witness path".into(),
        ));
    }
    for (statement, expected) in statements.iter().zip(expected.iter()) {
        if statement.message != expected.message || statement.digest != expected.digest {
            return Err(TexasAirError::ConstraintUnsatisfied(
                "SMT statements are detached from the witness path".into(),
            ));
        }
    }
    Ok(())
}

/// Build a consistent synthetic witness for tests and benchmarks: the node
/// chain is computed forward with native BLAKE3 compressions so every
/// statement holds.
#[must_use]
pub fn synthetic_smt_witness(
    seed: u8,
    key: [u8; 32],
    value: [u8; 32],
) -> Blake2bSmtFixedValuePathWitness {
    let hash64 = |message: &[u8]| -> [u8; 32] {
        blake3_hash64(message.try_into().expect("64-byte node message"))
    };
    let siblings = std::array::from_fn::<_, SMT_PATH_SIBLINGS, _>(|height| {
        let mut sibling = [seed; 32];
        sibling[0] = height as u8;
        sibling
    });
    let root_placeholder = [0u8; 32];
    let mut witness = Blake2bSmtFixedValuePathWitness {
        key,
        value,
        siblings,
        nodes: [[0u8; 32]; SMT_PATH_STATEMENTS],
        root: root_placeholder,
    };
    witness.nodes[0] = hash64(&smt_leaf_message(&key, &value));
    for height in 1..=SMT_PATH_SIBLINGS {
        let child = witness.nodes[height - 1];
        let sibling = siblings[height - 1];
        let (left, right) = if height == 1 || !witness.direction_bit(height) {
            (child, sibling)
        } else {
            (sibling, child)
        };
        witness.nodes[height] = hash64(&smt_internal_message(&left, &right));
    }
    witness.root = witness.nodes[SMT_PATH_SIBLINGS];
    witness
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(seed: u8) -> [u8; 32] {
        std::array::from_fn(|index| seed.wrapping_add(index as u8))
    }

    #[test]
    fn synthetic_witness_projects_to_valid_statements() {
        let witness = synthetic_smt_witness(0x5a, key(1), key(2));
        let statements = smt_path_statements(&witness).expect("statements");
        assert_eq!(statements.len(), SMT_PATH_STATEMENTS);
        verify_smt_path_statements(&witness, &statements).expect("structure");
    }

    #[test]
    fn structural_check_rejects_splices() {
        let witness = synthetic_smt_witness(0x5a, key(1), key(2));
        let mut statements = smt_path_statements(&witness).expect("statements");
        statements[5].digest[0] ^= 1;
        assert!(verify_smt_path_statements(&witness, &statements).is_err());

        let mut detached = witness.clone();
        detached.root[0] ^= 1;
        assert!(smt_path_statements(&detached).is_err());
    }

    #[test]
    fn statements_prove_and_verify_through_the_provider() {
        use crate::hash_prover::HashProofProvider as _;
        let witness = synthetic_smt_witness(0x3c, key(7), key(9));
        let statements = smt_path_statements(&witness).expect("statements");
        let provider = crate::blake3_flock::FlockProvider;
        let proof = provider.prove_statements(&statements).expect("proof");
        provider
            .verify_statements(&proof, &statements)
            .expect("verify");
        verify_smt_path_statements(&witness, &statements).expect("structure");
    }
}
