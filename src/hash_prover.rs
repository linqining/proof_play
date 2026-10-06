//! Backend-agnostic hash statement proving seam.
//!
//! The hash layer is migrating to a binary-field prover (Binius/Flock class)
//! while the M31 lookup stack remains the audited legacy fallback.  This
//! module is the single seam both backends plug into: callers construct
//! public `preimage -> digest` statements and ask a [`HashProofProvider`] to
//! prove or verify them, without knowing which proving system produced the
//! artifact.  The statement type is backend-neutral
//! ([`HashStatement`]); the process-wide default backend is the BLAKE3
//! flock chain digest (see [`default_hash_provider`]).
//!
//! Splice protection is provider-level and order-sensitive: verification
//! fails unless the supplied statements equal, byte for byte and in order,
//! the statements the proof actually covers.

#![allow(missing_docs)]

use crate::blake2b_lookup_compression::ArchivedBlake2bLookupHashesProof;
use crate::error::{TexasAirError, TexasAirResult};

/// One public hash statement: `digest = H(message)` (BLAKE3 flock chain
/// digest under the default backend).
#[derive(Debug, Clone, PartialEq, Eq, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct HashStatement {
    pub message: Vec<u8>,
    pub digest: [u8; 32],
}

impl HashStatement {
    #[must_use]
    pub fn new(message: Vec<u8>, digest: [u8; 32]) -> Self {
        Self { message, digest }
    }
}

/// A backend-tagged proof over an ordered list of hash statements.
#[derive(Debug, Clone, PartialEq, Eq, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub enum ArchivedHashProof {
    /// The shared lookup-backed M31 STARK (legacy Blake2b fallback archive).
    LookupStack(ArchivedBlake2bLookupHashesProof),
    /// The binary-field BLAKE3 flock backend.
    Flock(crate::blake3_flock::ArchivedFlockHashesProof),
}

impl ArchivedHashProof {
    /// The ordered statements this proof covers.
    #[must_use]
    pub fn statements(&self) -> Vec<HashStatement> {
        match self {
            ArchivedHashProof::LookupStack(inner) => inner
                .statements
                .iter()
                .map(|statement| HashStatement::new(statement.message.clone(), statement.digest))
                .collect(),
            ArchivedHashProof::Flock(inner) => inner
                .statements
                .iter()
                .map(|statement| HashStatement::new(statement.message.clone(), statement.digest))
                .collect(),
        }
    }
}

/// Prove and verify ordered hash statement batches.
pub trait HashProofProvider {
    /// Prove every statement in one shared proof.
    fn prove_statements(
        &self,
        statements: &[HashStatement],
    ) -> TexasAirResult<ArchivedHashProof>;

    /// Verify a proof against the exact ordered statement list.  Any splice,
    /// reorder, or statement substitution fails closed.
    fn verify_statements(
        &self,
        proof: &ArchivedHashProof,
        statements: &[HashStatement],
    ) -> TexasAirResult<()> {
        // Compare the covered messages (cheap borrows) and digests without
        // cloning each statement.  Layout-equivalence of the two backends'
        // `statements` fields is not assumed: we match on the variant and
        // walk the inner Vec directly.
        match proof {
            ArchivedHashProof::Flock(inner) => {
                if inner.statements.len() != statements.len() {
                    return Err(TexasAirError::ConstraintUnsatisfied(
                        "hash proof statement count does not match the request".into(),
                    ));
                }
                for (covered, requested) in inner.statements.iter().zip(statements.iter()) {
                    if covered.message != requested.message || covered.digest != requested.digest {
                        return Err(TexasAirError::ConstraintUnsatisfied(
                            "hash proof is detached from the requested statements".into(),
                        ));
                    }
                }
            }
            ArchivedHashProof::LookupStack(inner) => {
                if inner.statements.len() != statements.len() {
                    return Err(TexasAirError::ConstraintUnsatisfied(
                        "hash proof statement count does not match the request".into(),
                    ));
                }
                for (covered, requested) in inner.statements.iter().zip(statements.iter()) {
                    if covered.message != requested.message || covered.digest != requested.digest {
                        return Err(TexasAirError::ConstraintUnsatisfied(
                            "hash proof is detached from the requested statements".into(),
                        ));
                    }
                }
            }
        }
        self.verify_proof(proof)
    }

    /// Verify the proof's internal consistency (backend-specific).
    fn verify_proof(&self, proof: &ArchivedHashProof) -> TexasAirResult<()>;
}

/// The process-wide default provider: the binary-field BLAKE3 flock
/// backend.  Callers that do not care about the backend (tests, the hand
/// bench, transitional consumers) use this; the admission path may inject an
/// explicit provider.
#[must_use]
pub fn default_hash_provider() -> crate::blake3_flock::FlockProvider {
    crate::blake3_flock::FlockProvider
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest_of(message: &[u8]) -> [u8; 32] {
        crate::blake3_flock::blake3_chain_digest(message)
    }

    #[test]
    fn provider_round_trips_ordered_statements() {
        let statements = vec![
            HashStatement::new(
                b"zchain.texas.rules.v2".to_vec(),
                digest_of(b"zchain.texas.rules.v2"),
            ),
            HashStatement::new(vec![7u8; 200], digest_of(&[7u8; 200])),
        ];
        let provider = default_hash_provider();
        let proof = provider.prove_statements(&statements).expect("proof");
        provider
            .verify_statements(&proof, &statements)
            .expect("verify");
    }

    #[test]
    fn provider_rejects_splices_reorders_and_substitutions() {
        let statements = vec![
            HashStatement::new(b"first".to_vec(), digest_of(b"first")),
            HashStatement::new(b"second".to_vec(), digest_of(b"second")),
        ];
        let provider = default_hash_provider();
        let proof = provider.prove_statements(&statements).expect("proof");

        let reordered = vec![statements[1].clone(), statements[0].clone()];
        assert!(provider.verify_statements(&proof, &reordered).is_err());

        let mut wrong_digest = statements.clone();
        wrong_digest[0].digest[0] ^= 1;
        assert!(provider.verify_statements(&proof, &wrong_digest).is_err());

        let truncated = vec![statements[0].clone()];
        assert!(provider.verify_statements(&proof, &truncated).is_err());

        let extended = statements
            .iter()
            .cloned()
            .chain(std::iter::once(HashStatement::new(
                b"extra".to_vec(),
                digest_of(b"extra"),
            )))
            .collect::<Vec<_>>();
        assert!(provider.verify_statements(&proof, &extended).is_err());
    }

    #[test]
    fn provider_rejects_empty_batches() {
        assert!(default_hash_provider().prove_statements(&[]).is_err());
    }
}
