//! Stage-4 outer aggregation for stage-3 dual-proof packages.
//!
//! This module deliberately implements a safe, transferable **O(N) host-
//! verified aggregate**, not recursive proof compression. Every child package
//! is decoded and verified against an independently authenticated
//! [`ProveTask`]. The resulting verifier receipts are checked for exact table,
//! hand, call-sequence, state-root, and state-version continuity.
//!
//! The aggregate commitment additionally binds the exact encoded child bytes,
//! every dispatch digest, poker request/receipt digest, backend identity, and
//! accepted Stwo commitment root. The existing descriptor-only Aggregator AIR
//! is not used as evidence that child proofs were verified.

use blake2::Blake2bVar;
use blake2::digest::{Update, VariableOutput};
use rayon::prelude::*;

use crate::method_precompile_dual::{
    DualProofBundle, MAX_CRYPTO_REQUEST_BYTES, MAX_STARK_PROOF_BYTES, prove_dual_proof_verified,
    verify_dual_proof,
};
use crate::error::{TexasAirError, TexasAirResult};
use crate::precompile_binding::PrecompileCallBinding;
use crate::prove_task::ProveTask;
use crate::state_root::StateRoot;
use crate::verified_chain::{ExpectedChainAnchor, VerificationReceipt, VerifiedChain};

/// Wire magic for a stage-4 outer aggregate.
pub const OUTER_AGGREGATE_MAGIC: [u8; 8] = *b"ZPOUTR04";
/// Current outer-aggregate envelope version.
pub const OUTER_AGGREGATE_VERSION: u8 = 1;
/// Minimum number of children in an aggregate.
pub const MIN_OUTER_CHILDREN: usize = 2;
/// Maximum number of children accepted in one aggregate.
pub const MAX_OUTER_CHILDREN: usize = 64;
/// Maximum accepted encoded outer aggregate size.
pub const MAX_OUTER_AGGREGATE_BYTES: usize = 256 * 1024 * 1024;

const HEADER_LEN: usize = 144;
const MAX_OUTER_CHILD_BYTES: usize = 20 + MAX_STARK_PROOF_BYTES + MAX_CRYPTO_REQUEST_BYTES;

/// Untrusted transport envelope aggregating an ordered child-proof range.
///
/// All metadata is recomputed after child verification. Private fields prevent
/// local callers from bypassing the same invariants used by strict wire decode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OuterAggregateBundle {
    version: u8,
    table_id: u64,
    hand_id: u32,
    first_call_seq: u32,
    pre_version: u64,
    post_version: u64,
    pre_state_root: StateRoot,
    post_state_root: StateRoot,
    aggregate_digest: [u8; 32],
    children: Vec<DualProofBundle>,
}

impl OuterAggregateBundle {
    /// Envelope version.
    #[must_use]
    pub const fn version(&self) -> u8 {
        self.version
    }

    /// Table identifier claimed by the untrusted envelope.
    #[must_use]
    pub const fn table_id(&self) -> u64 {
        self.table_id
    }

    /// Hand identifier claimed by the untrusted envelope.
    #[must_use]
    pub const fn hand_id(&self) -> u32 {
        self.hand_id
    }

    /// Inclusive first call sequence claimed by the envelope.
    #[must_use]
    pub const fn first_call_seq(&self) -> u32 {
        self.first_call_seq
    }

    /// State version at the beginning of the aggregated range.
    #[must_use]
    pub const fn pre_version(&self) -> u64 {
        self.pre_version
    }

    /// State version at the end of the aggregated range.
    #[must_use]
    pub const fn post_version(&self) -> u64 {
        self.post_version
    }

    /// Full-width state root at the beginning of the range.
    #[must_use]
    pub const fn pre_state_root(&self) -> StateRoot {
        self.pre_state_root
    }

    /// Full-width state root at the end of the range.
    #[must_use]
    pub const fn post_state_root(&self) -> StateRoot {
        self.post_state_root
    }

    /// Domain-separated commitment to the exact children and verified semantics.
    #[must_use]
    pub const fn aggregate_digest(&self) -> [u8; 32] {
        self.aggregate_digest
    }

    /// Ordered stage-3 child packages.
    #[must_use]
    pub fn children(&self) -> &[DualProofBundle] {
        &self.children
    }

    /// Encode the outer aggregate using strict fixed-width metadata and
    /// length-prefixed canonical child envelopes.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid child count or any size overflow.
    pub fn encode(&self) -> TexasAirResult<Vec<u8>> {
        validate_child_count(self.children.len())?;
        let mut total_len = HEADER_LEN;
        for child in &self.children {
            let child_len = child.encoded_len()?;
            if child_len > MAX_OUTER_CHILD_BYTES {
                return Err(wire_error("encoded child exceeds outer child limit"));
            }
            total_len = total_len
                .checked_add(4)
                .and_then(|value| value.checked_add(child_len))
                .ok_or_else(|| wire_error("outer aggregate length overflow"))?;
        }
        if total_len > MAX_OUTER_AGGREGATE_BYTES {
            return Err(wire_error("outer aggregate exceeds total size limit"));
        }
        let child_count = u32::try_from(self.children.len())
            .map_err(|_| wire_error("outer child count exceeds u32"))?;
        let mut out = Vec::with_capacity(total_len);
        out.extend_from_slice(&OUTER_AGGREGATE_MAGIC);
        out.extend_from_slice(&[self.version, 0]); // version, flags
        out.extend_from_slice(&0u16.to_le_bytes()); // reserved
        out.extend_from_slice(&child_count.to_le_bytes());
        out.extend_from_slice(&self.table_id.to_le_bytes());
        out.extend_from_slice(&self.hand_id.to_le_bytes());
        out.extend_from_slice(&self.first_call_seq.to_le_bytes());
        out.extend_from_slice(&self.pre_version.to_le_bytes());
        out.extend_from_slice(&self.post_version.to_le_bytes());
        out.extend_from_slice(&self.pre_state_root.bytes());
        out.extend_from_slice(&self.post_state_root.bytes());
        out.extend_from_slice(&self.aggregate_digest);
        debug_assert_eq!(out.len(), HEADER_LEN);
        for child in &self.children {
            let len = child.encoded_len()?;
            let len =
                u32::try_from(len).map_err(|_| wire_error("outer child length exceeds u32"))?;
            out.extend_from_slice(&len.to_le_bytes());
            child.encode_into(&mut out)?;
        }
        debug_assert_eq!(out.len(), total_len);
        Ok(out)
    }

    /// Strictly decode an outer aggregate.
    ///
    /// Unknown versions or flags, non-zero reserved bytes, invalid roots,
    /// invalid child envelopes, truncation, oversized fields, and trailing data
    /// are rejected before proof verification.
    ///
    /// # Errors
    ///
    /// Returns [`TexasAirError::SerializationError`] for malformed wire data.
    pub fn decode(bytes: &[u8]) -> TexasAirResult<Self> {
        if bytes.len() < HEADER_LEN {
            return Err(wire_error("outer aggregate header is truncated"));
        }
        if bytes.len() > MAX_OUTER_AGGREGATE_BYTES {
            return Err(wire_error("outer aggregate exceeds total size limit"));
        }
        if bytes[..8] != OUTER_AGGREGATE_MAGIC {
            return Err(wire_error("outer aggregate magic mismatch"));
        }
        let version = bytes[8];
        if version != OUTER_AGGREGATE_VERSION {
            return Err(wire_error(format!(
                "unsupported outer aggregate version {version}"
            )));
        }
        if bytes[9] != 0 || bytes[10..12] != [0, 0] {
            return Err(wire_error(
                "outer aggregate flags/reserved bytes are non-zero",
            ));
        }
        let child_count = read_u32(bytes, 12)? as usize;
        validate_child_count(child_count)?;
        let table_id = read_u64(bytes, 16)?;
        let hand_id = read_u32(bytes, 24)?;
        let first_call_seq = read_u32(bytes, 28)?;
        let pre_version = read_u64(bytes, 32)?;
        let post_version = read_u64(bytes, 40)?;
        let pre_state_root = decode_root(&bytes[48..80])?;
        let post_state_root = decode_root(&bytes[80..112])?;
        let aggregate_digest = bytes[112..144].try_into().expect("fixed digest slice");

        let mut cursor = HEADER_LEN;
        let mut children = Vec::with_capacity(child_count);
        for index in 0..child_count {
            let length_end = cursor
                .checked_add(4)
                .ok_or_else(|| wire_error("outer child length offset overflow"))?;
            if length_end > bytes.len() {
                return Err(wire_error(format!(
                    "outer child {index} length prefix is truncated"
                )));
            }
            let child_len = u32::from_le_bytes(
                bytes[cursor..length_end]
                    .try_into()
                    .expect("fixed child length slice"),
            ) as usize;
            if child_len == 0 || child_len > MAX_OUTER_CHILD_BYTES {
                return Err(wire_error(format!(
                    "outer child {index} length is outside the accepted range"
                )));
            }
            let child_end = length_end
                .checked_add(child_len)
                .ok_or_else(|| wire_error("outer child end offset overflow"))?;
            if child_end > bytes.len() {
                return Err(wire_error(format!(
                    "outer child {index} payload is truncated"
                )));
            }
            children.push(DualProofBundle::decode(&bytes[length_end..child_end])?);
            cursor = child_end;
        }
        if cursor != bytes.len() {
            return Err(wire_error("outer aggregate contains trailing bytes"));
        }
        Ok(Self {
            version,
            table_id,
            hand_id,
            first_call_seq,
            pre_version,
            post_version,
            pre_state_root,
            post_state_root,
            aggregate_digest,
            children,
        })
    }
}

/// Verifier-issued acceptance artifact for a complete outer aggregate.
#[derive(Debug, Clone)]
pub struct VerifiedOuterAggregate {
    chain: VerifiedChain,
    precompile_bindings: Vec<PrecompileCallBinding>,
    aggregate_digest: [u8; 32],
}

impl VerifiedOuterAggregate {
    /// Host-verified child receipt chain.
    #[must_use]
    pub const fn chain(&self) -> &VerifiedChain {
        &self.chain
    }

    /// Independently reverified poker-precompile bindings in child order.
    #[must_use]
    pub fn precompile_bindings(&self) -> &[PrecompileCallBinding] {
        &self.precompile_bindings
    }

    /// Verified aggregate commitment.
    #[must_use]
    pub const fn aggregate_digest(&self) -> [u8; 32] {
        self.aggregate_digest
    }

    /// Bind the verified aggregate to an externally authenticated exact range.
    ///
    /// # Errors
    ///
    /// Returns an error if count, table, hand, sequence range, endpoint roots,
    /// endpoint versions, or any dispatch digest differs from the anchor.
    pub fn verify_against_anchor(&self, anchor: &ExpectedChainAnchor) -> TexasAirResult<()> {
        self.chain.verify_against_anchor(anchor)
    }
}

#[cfg(test)]
impl VerifiedOuterAggregate {
    /// Test-only constructor that bypasses the proof verifier but keeps the
    /// public surface identical so downstream code paths (calldata builders,
    /// settlement adapters) can be exercised without driving a full proof run.
    pub(crate) fn test_only_new(chain: VerifiedChain, aggregate_digest: [u8; 32]) -> Self {
        Self {
            chain,
            precompile_bindings: Vec::new(),
            aggregate_digest,
        }
    }
}

/// Generate every stage-3 child proof and construct a verified outer aggregate.
///
/// # Errors
///
/// Returns an error if the task count is invalid or any child prove/verify,
/// continuity, or aggregate construction step fails.
pub fn prove_outer_aggregate(tasks: &[ProveTask]) -> TexasAirResult<OuterAggregateBundle> {
    validate_child_count(tasks.len())?;
    // Fast path: every child was proved and natively verified in this process
    // against the same independently reconstructed task material that
    // `verify_dual_proof` would use, so receipts and precompile bindings are
    // carried in memory instead of re-decoding and re-verifying the fresh
    // packages. Children arriving from bytes still take the full
    // `aggregate_dual_proofs` path.
    // Child proofs are independent until the receipt chain is assembled.
    // Rayon preserves the input order in `collect`, so the resulting bundle,
    // digest, and first-error behavior remain deterministic.
    let proven: Vec<TexasAirResult<ProvenDualProofResult>> = tasks
        .par_iter()
        .map(|task| prove_dual_proof_verified(task).map(ProvenDualProofResult::from))
        .collect();
    let mut children = Vec::with_capacity(proven.len());
    let mut receipts = Vec::with_capacity(proven.len());
    let mut bindings = Vec::with_capacity(proven.len());
    for item in proven {
        let item = item?;
        receipts.push(item.receipt);
        bindings.push(item.binding);
        children.push(item.bundle);
    }
    let chain = VerifiedChain::try_from_receipts(receipts)?;
    build_bundle(children, &chain, &bindings)
}

/// Owned child result used to keep the parallel prove path's output explicit
/// and avoid cloning acceptance artifacts before ordered chain assembly.
struct ProvenDualProofResult {
    bundle: DualProofBundle,
    receipt: VerificationReceipt,
    binding: PrecompileCallBinding,
}

impl From<crate::method_precompile_dual::ProvenDualProof> for ProvenDualProofResult {
    fn from(value: crate::method_precompile_dual::ProvenDualProof) -> Self {
        Self {
            bundle: value.bundle,
            receipt: value.receipt,
            binding: value.binding,
        }
    }
}

/// Verify and aggregate an existing ordered list of stage-3 child packages.
///
/// This is the distributed-prover construction path: each supplied child is
/// independently reverified before the aggregate commitment is issued.
///
/// # Errors
///
/// Returns an error for count mismatch, an invalid child, a discontinuous
/// receipt chain, or an encoding failure.
pub fn aggregate_dual_proofs(
    tasks: &[ProveTask],
    children: Vec<DualProofBundle>,
) -> TexasAirResult<OuterAggregateBundle> {
    let verified = verify_children(tasks, &children)?;
    build_bundle(children, &verified.chain, &verified.precompile_bindings)
}

/// Verify every child, the ordered continuity chain, all envelope metadata,
/// and the aggregate commitment.
///
/// # Errors
///
/// Returns an error if the trusted task list and package differ in count or
/// order, if any child half fails, or if any aggregate field was substituted.
pub fn verify_outer_aggregate(
    tasks: &[ProveTask],
    bundle: &OuterAggregateBundle,
) -> TexasAirResult<VerifiedOuterAggregate> {
    if bundle.version != OUTER_AGGREGATE_VERSION {
        return Err(wire_error("unsupported in-memory outer aggregate version"));
    }
    let verified = verify_children(tasks, &bundle.children)?;
    validate_bundle_metadata(bundle, &verified.chain)?;
    let expected_digest = aggregate_digest(bundle, &verified.chain, &verified.precompile_bindings)?;
    if bundle.aggregate_digest != expected_digest {
        return Err(TexasAirError::RecursionError(
            "outer aggregate semantic commitment mismatch".into(),
        ));
    }
    Ok(VerifiedOuterAggregate {
        chain: verified.chain,
        precompile_bindings: verified.precompile_bindings,
        aggregate_digest: expected_digest,
    })
}

struct VerifiedChildren {
    chain: VerifiedChain,
    precompile_bindings: Vec<PrecompileCallBinding>,
}

fn verify_children(
    tasks: &[ProveTask],
    children: &[DualProofBundle],
) -> TexasAirResult<VerifiedChildren> {
    validate_child_count(children.len())?;
    if tasks.len() != children.len() {
        return Err(TexasAirError::RecursionError(format!(
            "outer aggregate task/child count mismatch: {} tasks, {} children",
            tasks.len(),
            children.len()
        )));
    }
    // Verify children in parallel (fail-closed: index-ordered first error wins).
    // Each child is an independent dual proof with its own bincode-decoded
    // Stwo proof and borsh-decoded flock binding; the chain assembly below
    // remains serial because receipts are order-sensitive.
    let verified: Vec<TexasAirResult<crate::method_precompile_dual::VerifiedDualProof>> = tasks
        .par_iter()
        .zip(children.par_iter())
        .map(|(task, child)| verify_dual_proof(task, child))
        .collect();
    let mut receipts = Vec::with_capacity(children.len());
    let mut precompile_bindings = Vec::with_capacity(children.len());
    for result in verified {
        let verified = result?;
        receipts.push(verified.receipt().clone());
        precompile_bindings.push(verified.precompile_binding().clone());
    }
    let chain = VerifiedChain::try_from_receipts(receipts)?;
    Ok(VerifiedChildren {
        chain,
        precompile_bindings,
    })
}

fn build_bundle(
    children: Vec<DualProofBundle>,
    chain: &VerifiedChain,
    bindings: &[PrecompileCallBinding],
) -> TexasAirResult<OuterAggregateBundle> {
    let first = chain
        .receipts()
        .first()
        .ok_or_else(|| TexasAirError::RecursionError("outer chain is empty".into()))?;
    let last = chain
        .receipts()
        .last()
        .ok_or_else(|| TexasAirError::RecursionError("outer chain is empty".into()))?;
    let mut bundle = OuterAggregateBundle {
        version: OUTER_AGGREGATE_VERSION,
        table_id: first.table_id(),
        hand_id: first.hand_id(),
        first_call_seq: first.call_seq(),
        pre_version: first.pre_version(),
        post_version: last.post_version(),
        pre_state_root: first.pre_state_root(),
        post_state_root: last.post_state_root(),
        aggregate_digest: [0; 32],
        children,
    };
    bundle.aggregate_digest = aggregate_digest(&bundle, chain, bindings)?;
    // Enforce the same transport size bounds as `encode` without re-serializing
    // the (already child-wise encoded) megabyte-scale payloads.
    let mut total_len = HEADER_LEN;
    for child in &bundle.children {
        let child_len = child.encoded_len()?;
        if child_len > MAX_OUTER_CHILD_BYTES {
            return Err(wire_error("encoded child exceeds outer child limit"));
        }
        total_len = total_len
            .checked_add(4)
            .and_then(|value| value.checked_add(child_len))
            .ok_or_else(|| wire_error("outer aggregate length overflow"))?;
    }
    if total_len > MAX_OUTER_AGGREGATE_BYTES {
        return Err(wire_error("outer aggregate exceeds total size limit"));
    }
    Ok(bundle)
}

fn validate_bundle_metadata(
    bundle: &OuterAggregateBundle,
    chain: &VerifiedChain,
) -> TexasAirResult<()> {
    let first = chain
        .receipts()
        .first()
        .ok_or_else(|| TexasAirError::RecursionError("outer chain is empty".into()))?;
    let last = chain
        .receipts()
        .last()
        .ok_or_else(|| TexasAirError::RecursionError("outer chain is empty".into()))?;
    let matches = bundle.table_id == first.table_id()
        && bundle.hand_id == first.hand_id()
        && bundle.first_call_seq == first.call_seq()
        && bundle.pre_version == first.pre_version()
        && bundle.post_version == last.post_version()
        && bundle.pre_state_root == first.pre_state_root()
        && bundle.post_state_root == last.post_state_root();
    if !matches {
        return Err(TexasAirError::RecursionError(
            "outer aggregate endpoint metadata does not match verified child receipts".into(),
        ));
    }
    Ok(())
}

fn aggregate_digest(
    bundle: &OuterAggregateBundle,
    chain: &VerifiedChain,
    bindings: &[PrecompileCallBinding],
) -> TexasAirResult<[u8; 32]> {
    if chain.receipts().len() != bundle.children.len() || bindings.len() != bundle.children.len() {
        return Err(TexasAirError::RecursionError(
            "outer aggregate digest input count mismatch".into(),
        ));
    }
    // Header material is fixed-size: version + child count + table/hand ids +
    // call seq + two versions + two 32-byte roots.
    let header_material_len = 1 + 4 + 8 + 8 + 8 + 8 + 8 + 32 + 32;
    let receipts = chain.receipts();
    let per_child_len = |receipt: &VerificationReceipt| {
        4 + 4 + 32 // index, length, child digest
            + 1 + 8 + 8 + 8 + 8 + 8 + 32 + 32 + 32 + 4 + 8 + 4 // receipt fields
            + 32 * receipt.proof_commitments().len()
            + 3 + 32 + 32 // binding ids and digests
    };
    let mut material =
        Vec::with_capacity(header_material_len + receipts.iter().map(per_child_len).sum::<usize>());
    material.extend_from_slice(&[bundle.version]);
    material.extend_from_slice(&(bundle.children.len() as u32).to_le_bytes());
    material.extend_from_slice(&bundle.table_id.to_le_bytes());
    material.extend_from_slice(&bundle.hand_id.to_le_bytes());
    material.extend_from_slice(&bundle.first_call_seq.to_le_bytes());
    material.extend_from_slice(&bundle.pre_version.to_le_bytes());
    material.extend_from_slice(&bundle.post_version.to_le_bytes());
    material.extend_from_slice(&bundle.pre_state_root.bytes());
    material.extend_from_slice(&bundle.post_state_root.bytes());

    // Encode + digest each child in parallel; the per-index results are then
    // appended strictly in order, so the concatenated material — and hence
    // the final digest — stays byte-for-byte identical to the sequential
    // version.
    let child_digests = bundle
        .children
        .par_iter()
        .map(|child| {
            let payload_len = child.encoded_len()?;
            let mut hasher = Blake2bVar::new(32).expect("32 <= 64");
            hasher.update(b"zchain.poker.outer_aggregate.child_bytes.v1");
            hasher.update(&(payload_len as u64).to_le_bytes());
            child.update_hasher(&mut hasher)?;
            let mut digest = [0u8; 32];
            hasher.finalize_variable(&mut digest).expect("32 <= 64");
            Ok((payload_len, digest))
        })
        .collect::<TexasAirResult<Vec<_>>>()?;

    for (index, ((child_digest, receipt), binding)) in child_digests
        .into_iter()
        .zip(receipts)
        .zip(bindings)
        .enumerate()
    {
        let (child_len, child_digest) = child_digest;
        material.extend_from_slice(&(index as u32).to_le_bytes());
        material.extend_from_slice(&(child_len as u32).to_le_bytes());
        material.extend_from_slice(&child_digest);
        append_receipt(&mut material, receipt);
        material.extend_from_slice(&[
            binding.precompile_id() as u8,
            binding.abi_version(),
            binding.backend_id() as u8,
        ]);
        material.extend_from_slice(&binding.request_digest());
        material.extend_from_slice(&binding.receipt_digest());
    }
    Ok(hash256(
        b"zchain.poker.outer_aggregate.semantic.v1",
        &material,
    ))
}

fn append_receipt(material: &mut Vec<u8>, receipt: &VerificationReceipt) {
    material.extend_from_slice(&[receipt.kind() as u8]);
    material.extend_from_slice(&receipt.table_id().to_le_bytes());
    material.extend_from_slice(&receipt.hand_id().to_le_bytes());
    material.extend_from_slice(&receipt.call_seq().to_le_bytes());
    material.extend_from_slice(&receipt.pre_version().to_le_bytes());
    material.extend_from_slice(&receipt.post_version().to_le_bytes());
    material.extend_from_slice(&receipt.pre_state_root().bytes());
    material.extend_from_slice(&receipt.post_state_root().bytes());
    material.extend_from_slice(&receipt.dispatch_call_digest());
    material.extend_from_slice(&receipt.log_size().to_le_bytes());
    material.extend_from_slice(&(receipt.num_columns() as u64).to_le_bytes());
    material.extend_from_slice(&(receipt.proof_commitments().len() as u32).to_le_bytes());
    for commitment in receipt.proof_commitments() {
        material.extend_from_slice(&commitment.to_bytes_be());
    }
}

fn validate_child_count(count: usize) -> TexasAirResult<()> {
    if !(MIN_OUTER_CHILDREN..=MAX_OUTER_CHILDREN).contains(&count) {
        return Err(wire_error(format!(
            "outer child count {count} is outside {MIN_OUTER_CHILDREN}..={MAX_OUTER_CHILDREN}"
        )));
    }
    Ok(())
}

fn read_u32(bytes: &[u8], offset: usize) -> TexasAirResult<u32> {
    let end = offset
        .checked_add(4)
        .ok_or_else(|| wire_error("u32 offset overflow"))?;
    let slice = bytes
        .get(offset..end)
        .ok_or_else(|| wire_error("u32 field is truncated"))?;
    Ok(u32::from_le_bytes(
        slice.try_into().expect("fixed u32 slice"),
    ))
}

fn read_u64(bytes: &[u8], offset: usize) -> TexasAirResult<u64> {
    let end = offset
        .checked_add(8)
        .ok_or_else(|| wire_error("u64 offset overflow"))?;
    let slice = bytes
        .get(offset..end)
        .ok_or_else(|| wire_error("u64 field is truncated"))?;
    Ok(u64::from_le_bytes(
        slice.try_into().expect("fixed u64 slice"),
    ))
}

fn decode_root(bytes: &[u8]) -> TexasAirResult<StateRoot> {
    let root_bytes: &[u8; 32] = bytes
        .try_into()
        .map_err(|_| wire_error("state root must contain 32 bytes"))?;
    Ok(StateRoot::from_bytes(*root_bytes))
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

fn wire_error(message: impl Into<String>) -> TexasAirError {
    TexasAirError::SerializationError(message.into())
}
