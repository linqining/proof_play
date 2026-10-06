//! Proven state-root binding — removes the host hash recomputation boundary.
//!
//! `root = H(preimage)` used to be established by the trusted host
//! recomputing Poseidon252 inside `verify_roots`.  This module replaces that
//! with a flock-proven statement pair: the prover covers
//!
//! ```text
//! statement[0] = BLAKE3(domain || pre_hot_bytes)  == pre_state_root
//! statement[1] = BLAKE3(domain || post_hot_bytes) == post_state_root
//! ```
//!
//! in one ordered [`ArchivedHashProof`].  The verifier deterministically
//! derives the hot bytes from the transcript-bound preimage, assembles the
//! exact expected statements, and lets the hash proof establish the binding;
//! no hash is recomputed and trusted on the verification path.
//!
//! Splice protection is inherited from the provider seam: verification
//! fails unless the supplied statements equal, byte for byte and in order,
//! the statements the proof actually covers.

use crate::error::{TexasAirError, TexasAirResult};
use crate::hash_prover::{ArchivedHashProof, HashStatement, HashProofProvider};
use crate::state_root::{StateRoot, hot_table_state_bytes};

/// One proven `(hot_bytes, root)` endpoint statement.
#[derive(Debug, Clone, PartialEq, Eq, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct StateRootEndpointStatement {
    /// Domain-separated preimage digested into the root.
    pub message: Vec<u8>,
    /// Claimed BLAKE3 chain digest of the message.
    pub root: [u8; 32],
}

impl StateRootEndpointStatement {
    /// Derive the statement for one table endpoint.
    ///
    /// The statement message is the domain-prefixed hot bytes, so the flock
    /// chain proves `root = BLAKE3_chain(domain || hot_bytes)` directly.
    pub fn from_table(
        table: &poker_l1::contracts::texas_poker::types::TexasPokerTable,
    ) -> TexasAirResult<Self> {
        Ok(Self::from_preimage(hot_table_state_bytes(table)?))
    }

    /// Derive the statement from already-canonical hot bytes.
    #[must_use]
    pub fn from_preimage(preimage: Vec<u8>) -> Self {
        let mut message = crate::state_root::STATE_ROOT_DOMAIN.to_vec();
        message.extend_from_slice(&preimage);
        let root = crate::blake3_flock::blake3_chain_digest(&message);
        Self { message, root }
    }
}

/// Flock-backed proof that both state-root endpoints hash to their public
/// roots.
#[derive(Debug, Clone, PartialEq, Eq, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct ArchivedStateRootBindingProof {
    /// Ordered `[pre, post]` endpoint statements covered by the proof.
    pub endpoints: [StateRootEndpointStatement; 2],
    /// Backend-agnostic hash proof over the ordered statements.
    pub proof: ArchivedHashProof,
}

/// Canonical message encoding for synthetic (non-table) mechanism-test
/// images: each field's 32-byte big-endian representation, concatenated.
/// Both the synthetic-root helper and `verify_roots` derive it identically,
/// so the binding statement is never ambiguous.
#[must_use]
pub fn synthetic_image_message(image: &[starknet_crypto::Felt]) -> Vec<u8> {
    let mut message = Vec::with_capacity(image.len() * 32);
    for field in image {
        message.extend_from_slice(&field.to_bytes_be());
    }
    message
}

fn provider_statements(endpoints: &[StateRootEndpointStatement; 2]) -> [HashStatement; 2] {
    [
        HashStatement::new(endpoints[0].message.clone(), endpoints[0].root),
        HashStatement::new(endpoints[1].message.clone(), endpoints[1].root),
    ]
}

/// Maximum number of memoized binding proofs kept resident.
///
/// Each cached value embeds full flock witness statements, so an unbounded
/// cache would grow without limit in a long-lived prover. When the cap is
/// reached the oldest half of the entries (by insertion order) is evicted;
/// this is a simple FIFO approximation of LRU, not a true LRU. Hit semantics
/// are unchanged: a hit still returns the identical memoized proof.
const BINDING_CACHE_CAPACITY: usize = 1024;

#[derive(Default)]
struct BindingCache {
    entries: std::collections::HashMap<[u8; 64], std::sync::Arc<ArchivedStateRootBindingProof>>,
    insertion_order: std::collections::VecDeque<[u8; 64]>,
}

impl BindingCache {
    fn get(&self, key: &[u8; 64]) -> Option<std::sync::Arc<ArchivedStateRootBindingProof>> {
        self.entries.get(key).map(std::sync::Arc::clone)
    }

    fn insert(&mut self, key: [u8; 64], proof: std::sync::Arc<ArchivedStateRootBindingProof>) {
        if self.entries.len() >= BINDING_CACHE_CAPACITY {
            let evict = self.entries.len() - BINDING_CACHE_CAPACITY / 2;
            for _ in 0..evict {
                if let Some(oldest) = self.insertion_order.pop_front() {
                    self.entries.remove(&oldest);
                }
            }
        }
        if self.entries.insert(key, proof).is_none() {
            self.insertion_order.push_back(key);
        }
    }
}

static BINDING_CACHE: std::sync::LazyLock<std::sync::Mutex<BindingCache>> =
    std::sync::LazyLock::new(|| std::sync::Mutex::new(BindingCache::default()));

fn binding_cache_key(endpoints: &[StateRootEndpointStatement; 2]) -> [u8; 64] {
    let mut key = [0u8; 64];
    key[..32].copy_from_slice(&endpoints[0].root);
    key[32..].copy_from_slice(&endpoints[1].root);
    key
}

/// Prove both endpoint statements in one ordered hash proof.
///
/// Proofs are deterministic functions of the endpoint statements, so results
/// are memoized per `(pre.root, post.root)` pair: repeated proves of the same
/// transition (tests, multi-stage component proofs sharing one base) reuse
/// the identical proof instead of regenerating the flock witnesses.
pub fn prove_state_root_binding(
    pre: StateRootEndpointStatement,
    post: StateRootEndpointStatement,
) -> TexasAirResult<ArchivedStateRootBindingProof> {
    let endpoints = [pre, post];
    let key = binding_cache_key(&endpoints);
    let cached = {
        let guard = BINDING_CACHE
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        guard.get(&key)
    };
    if let Some(cached) = cached {
        if cached.endpoints == endpoints {
            return Ok((*cached).clone());
        }
    }
    let statements = provider_statements(&endpoints);
    let proof = crate::hash_prover::default_hash_provider().prove_statements(&statements)?;
    let archive = std::sync::Arc::new(ArchivedStateRootBindingProof { endpoints, proof });
    let result = (*archive).clone();
    BINDING_CACHE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .insert(key, archive);
    Ok(result)
}

/// Prove the binding for a complete method public-input statement by
/// deriving both endpoints exactly as the verifier will.
pub fn prove_state_root_binding_for_inputs(
    public_inputs: &crate::public_inputs::TexasPublicInputs,
) -> TexasAirResult<ArchivedStateRootBindingProof> {
    let (pre, post) = public_inputs.root_endpoint_statements()?;
    prove_state_root_binding(pre, post)
}

/// Verify the binding against exactly the expected endpoint statements.
///
/// The expected statements are derived deterministically from public data
/// (transcript-bound hot bytes and claimed roots); any splice, reorder, or
/// substitution fails closed, and no hash is recomputed on trust.
pub fn verify_state_root_binding(
    archive: &ArchivedStateRootBindingProof,
    pre: &StateRootEndpointStatement,
    post: &StateRootEndpointStatement,
) -> TexasAirResult<()> {
    if archive.endpoints[0] != *pre || archive.endpoints[1] != *post {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "state-root binding endpoints are detached from the public statements".into(),
        ));
    }
    let statements = provider_statements(&[pre.clone(), post.clone()]);
    crate::hash_prover::default_hash_provider().verify_statements(&archive.proof, &statements)
}

impl ArchivedStateRootBindingProof {
    /// Public pre/post roots covered by the proof.
    #[must_use]
    pub fn roots(&self) -> [StateRoot; 2] {
        [
            StateRoot::from_bytes(self.endpoints[0].root),
            StateRoot::from_bytes(self.endpoints[1].root),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use poker_l1::contracts::texas_poker::types::TexasPokerTable;

    fn table(id: u8) -> TexasPokerTable {
        poker_l1::contracts::texas_poker::types::TexasPokerTable::new(
            poker_l1::object_model::ObjectID::new([id; 20], 7),
            [0xCD; 20],
            6,
            50,
            100,
        )
    }

    #[test]
    fn proves_and_verifies_both_endpoints() {
        let pre = StateRootEndpointStatement::from_table(&table(1)).unwrap();
        let post = StateRootEndpointStatement::from_table(&table(2)).unwrap();
        let archive = prove_state_root_binding(pre.clone(), post.clone()).unwrap();
        verify_state_root_binding(&archive, &pre, &post).unwrap();
    }

    #[test]
    fn verifier_rejects_spliced_roots_and_messages() {
        let pre = StateRootEndpointStatement::from_table(&table(1)).unwrap();
        let post = StateRootEndpointStatement::from_table(&table(2)).unwrap();
        let archive = prove_state_root_binding(pre.clone(), post.clone()).unwrap();

        let mut spliced_root = pre.clone();
        spliced_root.root[0] ^= 1;
        assert!(verify_state_root_binding(&archive, &spliced_root, &post).is_err());

        let mut spliced_message = post.clone();
        spliced_message.message[0] ^= 1;
        assert!(verify_state_root_binding(&archive, &pre, &spliced_message).is_err());

        // Swapping endpoints is an order change and must fail closed.
        assert!(verify_state_root_binding(&archive, &post, &pre).is_err());
    }
}
