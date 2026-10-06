//! Host-side verification receipts for method-proof chains.
//!
//! This module deliberately does **not** claim recursive proof compression.  It
//! records that the native verifier accepted each method proof, then checks the
//! business metadata and state-root continuity before a caller treats the
//! sequence as a locally verified host-side chain. [`ExpectedChainAnchor`] is
//! required to bind that local result to an authenticated complete call range.
//!
//! A [`VerifiedChain`] is therefore an acceptance artifact for a trusted host
//! process.  It is not transferable evidence that an Aggregator STARK verified
//! its children; the current recursive backend does not provide that circuit.

use starknet_crypto::Felt;

use crate::airs::TexasAir;
use crate::error::{TexasAirError, TexasAirResult};
use crate::method_kind::MethodKind;
use crate::prover::MethodProof;
use crate::public_inputs::TexasPublicInputs;
use crate::state_root::StateRoot;

/// Consensus-derived expectation for one complete host-verified chain range.
///
/// This value is only a *trust anchor* when its fields come from authenticated
/// block/transaction data (or another consensus commitment). Constructing it
/// from the same untrusted [`crate::prove_task::ProveTask`] values being proved
/// does not establish inclusion or batch completeness.
#[derive(Debug, Clone)]
pub struct ExpectedChainAnchor {
    table_id: u64,
    hand_id: u32,
    first_call_seq: u32,
    pre_state_root: StateRoot,
    post_state_root: StateRoot,
    pre_version: u64,
    post_version: u64,
    dispatch_call_digests: Vec<[u8; 32]>,
}

impl ExpectedChainAnchor {
    /// Construct an expected complete chain range.
    ///
    /// The number of dispatch digests defines the exact receipt count and the
    /// inclusive call-sequence range beginning at `first_call_seq`.
    ///
    /// # Errors
    ///
    /// Returns an error for an empty range or a call-sequence overflow.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        table_id: u64,
        hand_id: u32,
        first_call_seq: u32,
        pre_state_root: StateRoot,
        post_state_root: StateRoot,
        pre_version: u64,
        post_version: u64,
        dispatch_call_digests: Vec<[u8; 32]>,
    ) -> TexasAirResult<Self> {
        if dispatch_call_digests.is_empty() {
            return Err(TexasAirError::RecursionError(
                "expected chain anchor must contain at least one dispatch digest".into(),
            ));
        }
        let offset = u32::try_from(dispatch_call_digests.len() - 1).map_err(|_| {
            TexasAirError::RecursionError("expected chain range does not fit u32".into())
        })?;
        first_call_seq.checked_add(offset).ok_or_else(|| {
            TexasAirError::RecursionError("expected chain call_seq range overflow".into())
        })?;
        Ok(Self {
            table_id,
            hand_id,
            first_call_seq,
            pre_state_root,
            post_state_root,
            pre_version,
            post_version,
            dispatch_call_digests,
        })
    }

    fn last_call_seq(&self) -> u32 {
        self.first_call_seq
            + u32::try_from(self.dispatch_call_digests.len() - 1)
                .expect("constructor checked digest count")
    }

    /// Table identifier authenticated by the anchor.
    #[must_use]
    pub const fn table_id(&self) -> u64 {
        self.table_id
    }

    /// Hand identifier authenticated by the anchor.
    #[must_use]
    pub const fn hand_id(&self) -> u32 {
        self.hand_id
    }

    /// Inclusive first call sequence of the anchored range.
    #[must_use]
    pub const fn first_call_seq(&self) -> u32 {
        self.first_call_seq
    }

    /// Inclusive last call sequence of the anchored range.
    #[must_use]
    pub fn last_call_seq_public(&self) -> u32 {
        self.last_call_seq()
    }

    /// Pre-state root (single-table Poseidon252) at the range start.
    #[must_use]
    pub const fn pre_state_root(&self) -> StateRoot {
        self.pre_state_root
    }

    /// Post-state root (single-table Poseidon252) at the range end.
    #[must_use]
    pub const fn post_state_root(&self) -> StateRoot {
        self.post_state_root
    }

    /// Pre state version at the range start.
    #[must_use]
    pub const fn pre_version(&self) -> u64 {
        self.pre_version
    }

    /// Post state version at the range end.
    #[must_use]
    pub const fn post_version(&self) -> u64 {
        self.post_version
    }

    /// Per-call dispatch digests defining the exact receipt count and order.
    #[must_use]
    pub fn dispatch_call_digests(&self) -> &[[u8; 32]] {
        &self.dispatch_call_digests
    }
}

/// Receipt issued only after the native method-proof verifier succeeds.
///
/// The fields are intentionally private so downstream code cannot construct a
/// receipt from descriptor data alone. Receipt issuance is crate-private and
/// reachable in production only from the Orchestrator after full VM replay.
/// The caller must still anchor the task source or the chain endpoints in data
/// authenticated by the surrounding consensus system.
#[derive(Debug, Clone)]
pub struct VerificationReceipt {
    kind: MethodKind,
    pre_state_root: StateRoot,
    post_state_root: StateRoot,
    table_id: u64,
    hand_id: u32,
    call_seq: u32,
    pre_version: u64,
    post_version: u64,
    dispatch_call_digest: [u8; 32],
    proof_commitments: Vec<Felt>,
    log_size: u32,
    num_columns: usize,
}

impl VerificationReceipt {
    /// Method kind authenticated by the verified proof's public inputs.
    #[must_use]
    pub const fn kind(&self) -> MethodKind {
        self.kind
    }

    /// State root before the method call.
    #[must_use]
    pub const fn pre_state_root(&self) -> StateRoot {
        self.pre_state_root
    }

    /// State root after the method call.
    #[must_use]
    pub const fn post_state_root(&self) -> StateRoot {
        self.post_state_root
    }

    /// Table identifier.
    #[must_use]
    pub const fn table_id(&self) -> u64 {
        self.table_id
    }

    /// Hand identifier.
    #[must_use]
    pub const fn hand_id(&self) -> u32 {
        self.hand_id
    }

    /// Method-call sequence number.
    #[must_use]
    pub const fn call_seq(&self) -> u32 {
        self.call_seq
    }

    /// State version before the verified method execution.
    #[must_use]
    pub const fn pre_version(&self) -> u64 {
        self.pre_version
    }

    /// State version after the verified method execution.
    #[must_use]
    pub const fn post_version(&self) -> u64 {
        self.post_version
    }

    /// Digest of the exact VM dispatch call replayed and accepted by the host.
    /// Authentication of the task source is an external consensus responsibility.
    #[must_use]
    pub const fn dispatch_call_digest(&self) -> [u8; 32] {
        self.dispatch_call_digest
    }

    /// Commitment roots of the method proof accepted by the native verifier.
    #[must_use]
    pub fn proof_commitments(&self) -> &[Felt] {
        &self.proof_commitments
    }

    /// Trace log size used by the verified method proof.
    #[must_use]
    pub const fn log_size(&self) -> u32 {
        self.log_size
    }

    /// Number of original-trace columns used by the verified method proof.
    #[must_use]
    pub const fn num_columns(&self) -> usize {
        self.num_columns
    }
}

/// Verify one method proof natively and issue an opaque safe-Rust receipt.
///
/// The expected AIR and public inputs must be reconstructed independently by
/// the verifier. Private fields prevent descriptor-only fabrication, but a
/// caller can still ask the public Orchestrator to prove an arbitrary valid
/// offline transition. Consensus provenance comes only from an external anchor.
/// This host step does not turn the result into a recursively verifiable proof.
///
/// # Errors
///
/// Returns an error when the native Stwo verifier rejects the proof.
pub(crate) fn verify_method_against_and_issue_receipt<A>(
    proof: MethodProof<A>,
    expected_air: &A,
    expected_public_inputs: &TexasPublicInputs,
) -> TexasAirResult<VerificationReceipt>
where
    A: TexasAir,
{
    // stwo 的 Poseidon252MerkleHasher 哈希类型仍是旧 ff 库的 FieldElement
    // （stwo 2.3 内部类型，见根 Cargo.toml 注释）；逐字节拷贝为本仓统一的
    // starknet_crypto::Felt（同一 felt252 值，无语义变化）。
    let proof_commitments = proof
        .stark_proof
        .commitments
        .iter()
        .map(|f| Felt::from_bytes_be(&f.to_bytes_be()))
        .collect();
    let log_size = expected_air.log_size();
    let num_columns = expected_air.trace_num_columns();

    crate::verifier::verify_method_against(proof, expected_air.clone(), expected_public_inputs)?;

    Ok(VerificationReceipt {
        kind: expected_public_inputs.kind,
        pre_state_root: expected_public_inputs.pre_state_root,
        post_state_root: expected_public_inputs.post_state_root,
        table_id: expected_public_inputs.table_id,
        hand_id: expected_public_inputs.hand_id,
        call_seq: expected_public_inputs.call_seq,
        pre_version: expected_public_inputs.pre_version,
        post_version: expected_public_inputs.post_version,
        dispatch_call_digest: expected_public_inputs.dispatch_call_digest,
        proof_commitments,
        log_size,
        num_columns,
    })
}

/// Issue one receipt after the caller has verified a heterogeneous tagged batch proof.
///
/// This constructor is crate-private because the proof verification and the opaque receipt
/// issuance must remain one operation at the public API boundary.
pub(crate) fn issue_tagged_batch_receipt(
    task: &crate::prove_task::ProveTask,
    proof_commitments: Vec<Felt>,
    log_size: u32,
    num_columns: usize,
) -> TexasAirResult<VerificationReceipt> {
    crate::orchestrator::validate_full_dispatch_task(task)?;
    Ok(VerificationReceipt {
        kind: task.method_kind,
        pre_state_root: crate::state_root::compute_state_root(&task.pre_table)?,
        post_state_root: crate::state_root::compute_state_root(&task.post_table)?,
        table_id: task.table_id,
        hand_id: task.hand_id,
        call_seq: task.call_seq,
        pre_version: u64::from(task.pre_table.call_seq),
        post_version: u64::from(task.post_table.call_seq),
        dispatch_call_digest: crate::prove_task::dispatch_call_digest(
            &task.context,
            &task.selector(),
            &task.raw_args,
        )?,
        proof_commitments,
        log_size,
        num_columns,
    })
}

/// A sequence of natively verified method proofs with checked metadata continuity.
///
/// Construction validates that all receipts belong to the same table and hand,
/// call sequences are consecutive, and every previous post-state root equals
/// the next pre-state root.
///
/// Descriptor-only summaries are intentionally not accepted by this API:
///
/// ```compile_fail
/// use poker_texas_air::verified_chain::VerifiedChain;
///
/// let descriptor: ChildDescriptor = todo!();
/// let _ = VerifiedChain::try_from_receipts(vec![descriptor]);
/// ```
#[derive(Debug, Clone)]
pub struct VerifiedChain {
    receipts: Vec<VerificationReceipt>,
}

impl VerifiedChain {
    /// Build a verified chain from receipts issued by the native verifier.
    ///
    /// # Errors
    ///
    /// Returns an error for an empty chain, mixed table/hand identifiers,
    /// non-consecutive call sequences, or a broken state-root link.
    pub(crate) fn try_from_receipts(receipts: Vec<VerificationReceipt>) -> TexasAirResult<Self> {
        validate_receipt_chain(&receipts)?;
        Ok(Self { receipts })
    }

    /// Receipts in verified execution order.
    #[must_use]
    pub fn receipts(&self) -> &[VerificationReceipt] {
        &self.receipts
    }

    /// Number of verified method proofs in the chain.
    #[must_use]
    pub fn len(&self) -> usize {
        self.receipts.len()
    }

    /// Whether the chain contains no receipts.
    ///
    /// A successfully constructed chain is never empty; this method is
    /// provided for normal collection-style inspection.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.receipts.is_empty()
    }

    /// Common table identifier for the chain.
    #[must_use]
    pub fn table_id(&self) -> u64 {
        self.receipts[0].table_id
    }

    /// Common hand identifier for the chain.
    #[must_use]
    pub fn hand_id(&self) -> u32 {
        self.receipts[0].hand_id
    }

    /// Verify this local receipt chain against an externally authenticated range.
    ///
    /// Besides adjacent continuity, this binds the exact receipt count, table,
    /// hand, inclusive call-sequence range, full-width endpoint roots/versions,
    /// and every replayed dispatch digest. It remains an O(N) host acceptance
    /// artifact, not a transferable recursive proof.
    ///
    /// # Errors
    ///
    /// Returns an error when any anchored field or dispatch digest differs.
    pub fn verify_against_anchor(&self, expected: &ExpectedChainAnchor) -> TexasAirResult<()> {
        validate_receipt_chain(&self.receipts)?;
        if self.receipts.len() != expected.dispatch_call_digests.len() {
            return Err(anchor_mismatch(format!(
                "receipt count {} does not match expected {}",
                self.receipts.len(),
                expected.dispatch_call_digests.len()
            )));
        }

        let first = &self.receipts[0];
        let last = self.receipts.last().expect("non-empty chain validated");
        if first.table_id != expected.table_id || last.table_id != expected.table_id {
            return Err(anchor_mismatch("table_id differs from expected anchor"));
        }
        if first.hand_id != expected.hand_id || last.hand_id != expected.hand_id {
            return Err(anchor_mismatch("hand_id differs from expected anchor"));
        }
        if first.call_seq != expected.first_call_seq || last.call_seq != expected.last_call_seq() {
            return Err(anchor_mismatch(format!(
                "call_seq range {}..={} does not match expected {}..={}",
                first.call_seq,
                last.call_seq,
                expected.first_call_seq,
                expected.last_call_seq()
            )));
        }
        if first.pre_state_root != expected.pre_state_root
            || last.post_state_root != expected.post_state_root
        {
            return Err(anchor_mismatch(
                "full-width state-root endpoints differ from expected anchor",
            ));
        }
        if first.pre_version != expected.pre_version || last.post_version != expected.post_version {
            return Err(anchor_mismatch(
                "state-version endpoints differ from expected anchor",
            ));
        }
        for (index, (receipt, digest)) in self
            .receipts
            .iter()
            .zip(&expected.dispatch_call_digests)
            .enumerate()
        {
            if receipt.dispatch_call_digest != *digest {
                return Err(anchor_mismatch(format!(
                    "dispatch digest differs at receipt index {index}"
                )));
            }
        }
        Ok(())
    }
}

/// Incremental host-side verifier for heterogeneous method AIR proof types.
///
/// Each call to [`push`](Self::push) is generic, so one builder can accept the
/// different concrete AIR types used by successive poker methods.
#[derive(Debug, Default, Clone)]
pub(crate) struct VerifiedChainBuilder {
    receipts: Vec<VerificationReceipt>,
}

impl VerifiedChainBuilder {
    /// Append a receipt previously issued by the native verifier.
    ///
    /// This accepts only [`VerificationReceipt`], whose fields are private and
    /// which safe external code can obtain only from a successful native
    /// verification. Descriptor-only summaries therefore cannot enter the
    /// trusted chain through this path.
    ///
    /// # Errors
    ///
    /// Returns an error if the receipt does not continue the existing
    /// table/hand/state/sequence/version chain.
    pub(crate) fn push_receipt(&mut self, receipt: VerificationReceipt) -> TexasAirResult<()> {
        if let Some(previous) = self.receipts.last() {
            validate_adjacent_receipts(previous, &receipt)?;
        }
        self.receipts.push(receipt);
        Ok(())
    }

    /// Clear accumulated receipts to begin a new chain segment.
    ///
    /// Used when crossing a `hand_id` boundary (e.g. after `start_hand` advances
    /// the hand id): the single-hand continuity invariant in
    /// [`validate_adjacent_receipts`] forbids receipts from two different hands in
    /// one chain, so a driver that spans multiple hands must start a fresh segment.
    pub(crate) fn clear_receipts(&mut self) {
        self.receipts.clear();
    }

    /// Snapshot the currently accumulated host-verified chain.
    ///
    /// # Errors
    ///
    /// Returns an error if no verified receipts have been added.
    pub(crate) fn snapshot(&self) -> TexasAirResult<VerifiedChain> {
        VerifiedChain::try_from_receipts(self.receipts.clone())
    }
}

#[cfg(test)]
impl VerifiedChain {
    /// Test-only constructor that runs the same chain validation as
    /// [`VerifiedChain::try_from_receipts`] but is reachable from sibling
    /// test modules without going through the production verifier.
    pub(crate) fn test_only_from_receipts(
        receipts: Vec<VerificationReceipt>,
    ) -> TexasAirResult<Self> {
        Self::try_from_receipts(receipts)
    }
}

#[cfg(test)]
impl VerificationReceipt {
    /// Test-only synthetic receipt factory.
    ///
    /// Production code must continue to obtain receipts only through
    /// [`verify_method_against_and_issue_receipt`] /
    /// [`issue_tagged_batch_receipt`] so the receipt fields remain bound to
    /// the native verifier and the VM-replayed dispatch call.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn test_only_new(
        table_id: u64,
        hand_id: u32,
        call_seq: u32,
        pre: StateRoot,
        post: StateRoot,
    ) -> Self {
        Self {
            kind: MethodKind::Check,
            pre_state_root: pre,
            post_state_root: post,
            table_id,
            hand_id,
            call_seq,
            pre_version: u64::from(call_seq),
            post_version: u64::from(call_seq) + 1,
            dispatch_call_digest: [call_seq as u8; 32],
            proof_commitments: vec![Felt::from(u64::from(call_seq) + 1)],
            log_size: 10,
            num_columns: 1,
        }
    }
}

fn validate_receipt_chain(receipts: &[VerificationReceipt]) -> TexasAirResult<()> {
    if receipts.is_empty() {
        return Err(TexasAirError::RecursionError(
            "verified chain must contain at least one method proof".into(),
        ));
    }
    for pair in receipts.windows(2) {
        validate_adjacent_receipts(&pair[0], &pair[1])?;
    }
    Ok(())
}

fn validate_adjacent_receipts(
    left: &VerificationReceipt,
    right: &VerificationReceipt,
) -> TexasAirResult<()> {
    if left.table_id != right.table_id {
        return Err(TexasAirError::RecursionError(format!(
            "verified chain crosses tables: {} -> {}",
            left.table_id, right.table_id
        )));
    }
    if left.hand_id != right.hand_id {
        return Err(TexasAirError::RecursionError(format!(
            "verified chain crosses hands: {} -> {}",
            left.hand_id, right.hand_id
        )));
    }
    let expected_seq = left
        .call_seq
        .checked_add(1)
        .ok_or_else(|| TexasAirError::RecursionError("verified chain call_seq overflow".into()))?;
    if right.call_seq != expected_seq {
        return Err(TexasAirError::RecursionError(format!(
            "verified chain call_seq is not consecutive: expected {}, got {}",
            expected_seq, right.call_seq
        )));
    }
    if left.post_state_root != right.pre_state_root {
        return Err(TexasAirError::RecursionError(format!(
            "verified chain state root is discontinuous at call_seq {} -> {}",
            left.call_seq, right.call_seq
        )));
    }
    if left.post_version != right.pre_version {
        return Err(TexasAirError::RecursionError(format!(
            "verified chain state version is discontinuous at call_seq {} -> {}",
            left.call_seq, right.call_seq
        )));
    }
    Ok(())
}

fn anchor_mismatch(message: impl Into<String>) -> TexasAirError {
    TexasAirError::RecursionError(format!(
        "verified chain anchor mismatch: {}",
        message.into()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn receipt(
        table_id: u64,
        hand_id: u32,
        call_seq: u32,
        pre: u64,
        post: u64,
    ) -> VerificationReceipt {
        VerificationReceipt {
            kind: MethodKind::Check,
            pre_state_root: StateRoot::from_field(Felt::from(pre)),
            post_state_root: StateRoot::from_field(Felt::from(post)),
            table_id,
            hand_id,
            call_seq,
            pre_version: u64::from(call_seq),
            post_version: u64::from(call_seq) + 1,
            dispatch_call_digest: [call_seq as u8; 32],
            proof_commitments: vec![Felt::from(call_seq as u64 + 1)],
            log_size: 10,
            num_columns: 1,
        }
    }

    #[test]
    fn builds_contiguous_host_verified_chain() {
        let chain = VerifiedChain::try_from_receipts(vec![
            receipt(7, 3, 10, 100, 101),
            receipt(7, 3, 11, 101, 102),
        ])
        .expect("contiguous receipts should form a chain");
        assert_eq!(chain.len(), 2);
        assert_eq!(chain.table_id(), 7);
        assert_eq!(chain.hand_id(), 3);
    }

    #[test]
    fn verifies_exact_consensus_anchored_range() {
        let chain = VerifiedChain::try_from_receipts(vec![
            receipt(7, 3, 10, 100, 101),
            receipt(7, 3, 11, 101, 102),
        ])
        .unwrap();
        let anchor = ExpectedChainAnchor::new(
            7,
            3,
            10,
            StateRoot::from_field(Felt::from(100u64)),
            StateRoot::from_field(Felt::from(102u64)),
            10,
            12,
            vec![[10; 32], [11; 32]],
        )
        .unwrap();
        chain.verify_against_anchor(&anchor).unwrap();
    }

    #[test]
    fn rejects_incomplete_or_wrong_dispatch_anchor() {
        let chain = VerifiedChain::try_from_receipts(vec![
            receipt(7, 3, 10, 100, 101),
            receipt(7, 3, 11, 101, 102),
        ])
        .unwrap();
        let incomplete = ExpectedChainAnchor::new(
            7,
            3,
            10,
            StateRoot::from_field(Felt::from(100u64)),
            StateRoot::from_field(Felt::from(101u64)),
            10,
            11,
            vec![[10; 32]],
        )
        .unwrap();
        assert!(chain.verify_against_anchor(&incomplete).is_err());

        let wrong_digest = ExpectedChainAnchor::new(
            7,
            3,
            10,
            StateRoot::from_field(Felt::from(100u64)),
            StateRoot::from_field(Felt::from(102u64)),
            10,
            12,
            vec![[10; 32], [99; 32]],
        )
        .unwrap();
        assert!(chain.verify_against_anchor(&wrong_digest).is_err());
    }

    #[test]
    fn rejects_empty_or_overflowing_anchor_ranges() {
        let root = StateRoot::from_field(Felt::ONE);
        assert!(ExpectedChainAnchor::new(7, 3, 0, root, root, 0, 0, vec![]).is_err());
        assert!(
            ExpectedChainAnchor::new(7, 3, u32::MAX, root, root, 0, 0, vec![[1; 32], [2; 32]],)
                .is_err()
        );
    }

    #[test]
    fn rejects_cross_table_receipts() {
        let result = VerifiedChain::try_from_receipts(vec![
            receipt(7, 3, 10, 100, 101),
            receipt(8, 3, 11, 101, 102),
        ]);
        assert!(result.is_err());
    }

    #[test]
    fn rejects_cross_hand_receipts() {
        let result = VerifiedChain::try_from_receipts(vec![
            receipt(7, 3, 10, 100, 101),
            receipt(7, 4, 11, 101, 102),
        ]);
        assert!(result.is_err());
    }

    #[test]
    fn rejects_non_consecutive_or_broken_state_chain() {
        let bad_seq = VerifiedChain::try_from_receipts(vec![
            receipt(7, 3, 10, 100, 101),
            receipt(7, 3, 12, 101, 102),
        ]);
        assert!(bad_seq.is_err());

        let bad_root = VerifiedChain::try_from_receipts(vec![
            receipt(7, 3, 10, 100, 101),
            receipt(7, 3, 11, 999, 102),
        ]);
        assert!(bad_root.is_err());
    }

    #[test]
    fn rejects_broken_version_chain() {
        let mut second = receipt(7, 3, 11, 101, 102);
        second.pre_version = 99;
        let result = VerifiedChain::try_from_receipts(vec![receipt(7, 3, 10, 100, 101), second]);
        assert!(result.is_err());
    }
}
