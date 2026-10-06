//! Transferable two-part proof packages for poker cryptographic calls.
//!
//! A package contains both halves required to accept a crypto-bearing Texas
//! Poker transition:
//!
//! 1. the Stwo method proof for the state transition and AIR digest columns;
//! 2. the complete canonical poker-precompile request, including the
//!    shuffle, leave/fold layer DLEq, reveal-token, or Reconstruction V3 proof.
//!
//! The package does **not** carry a trusted AIR or trusted public inputs.
//! Verification requires the independently authenticated [`ProveTask`], replays
//! its VM dispatch, rebuilds the canonical request/AIR/public inputs, verifies
//! the native crypto proof, and finally verifies the Stwo proof. This prevents
//! either half from being detached, substituted, or replayed in another call
//! scope.

use bincode::Options;
use blake2::{
    Blake2bVar,
    digest::Update,
};
use poker_protocol::precompile::{
    build_reconstruction_request, build_bls12381_shuffle_request,
};
use poker_protocol::precompile_abi::{
    RECONSTRUCTION_ABI_VERSION, ReconstructionVerifyRequest, SHUFFLE_ABI_VERSION,
    ShuffleVerifyRequest, TranscriptId,
};
use stwo::core::proof::StarkProof;
use stwo::core::vcs_lifted::poseidon252_merkle::Poseidon252MerkleHasher;

use crate::airs::actions::end_without_showdown::derive_fold_outcome;
use crate::airs::crypto::fold_with_proof::{
    FoldWithProofAir, FoldWithProofInput, FoldWithProofRow,
};
use crate::airs::crypto::submit_player_reveal_tokens::{
    SubmitPlayerRevealTokensAir, SubmitPlayerRevealTokensInput, SubmitPlayerRevealTokensRow,
};
use crate::airs::crypto::submit_reconstruct_deck::{
    SubmitReconstructDeckAir, SubmitReconstructDeckInput, SubmitReconstructDeckRow,
};
use crate::airs::crypto::submit_shuffle_v2::{
    SubmitShuffleV2Air, SubmitShuffleV2Input, SubmitShuffleV2Row,
};
use crate::deck_commitment::deck_commitment;
use crate::error::{TexasAirError, TexasAirResult};
use crate::method_kind::MethodKind;
use crate::orchestrator::{replay_reveal_settlement_binding, validate_full_dispatch_task};
use crate::precompile_binding::{
    LEAVE_DLEQ_ABI_VERSION, LeaveDleqVerifyRequest, PokerPrecompileId, PrecompileCallBinding,
    REVEAL_TOKEN_ABI_VERSION, RevealTokenVerifyRequest, precompile_call_context,
};
use crate::proof_archive::ArchivedMethodProof;
use crate::prove_task::{MethodInput, ProveTask};
use crate::prover::{MethodProof, prove_method};
use crate::public_inputs::TexasPublicInputs;
use crate::state_root::{compute_state_root, state_root_to_air_limbs, table_state_preimage};
use crate::trace_gen::generic_trace::{SINGLE_METHOD_LOG_SIZE as MIN_LOG_SIZE, gen_method_trace};
use crate::verified_chain::{VerificationReceipt, verify_method_against_and_issue_receipt};

/// Wire-format magic for a stage-3 dual proof package.
pub const DUAL_PROOF_MAGIC: [u8; 8] = *b"ZPDUAL03";
/// Current dual-proof envelope version.
pub const DUAL_PROOF_VERSION: u8 = 2;
/// Maximum accepted serialized Stwo proof size.
pub const MAX_STARK_PROOF_BYTES: usize = 64 * 1024 * 1024;
/// Maximum accepted canonical poker-precompile request size.
pub const MAX_CRYPTO_REQUEST_BYTES: usize = 4 * 1024 * 1024;

const HEADER_LEN: usize = 8 + 4 + 4 + 4 + 4;
const MAX_ROOT_BINDING_BYTES: usize = 4 * 1024 * 1024;

/// Untrusted transport envelope containing both proof halves.
///
/// Fields are private so locally constructed values use the same invariants as
/// decoded wire data. None of these fields is trusted during verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DualProofBundle {
    version: u8,
    method_kind: MethodKind,
    precompile_id: PokerPrecompileId,
    abi_version: u8,
    stark_proof_bytes: Vec<u8>,
    crypto_request_bytes: Vec<u8>,
    root_binding_bytes: Vec<u8>,
}

impl DualProofBundle {
    /// Envelope version.
    #[must_use]
    pub const fn version(&self) -> u8 {
        self.version
    }

    /// Method selector claimed by the untrusted envelope.
    #[must_use]
    pub const fn method_kind(&self) -> MethodKind {
        self.method_kind
    }

    /// Poker precompile claimed by the untrusted envelope.
    #[must_use]
    pub const fn precompile_id(&self) -> PokerPrecompileId {
        self.precompile_id
    }

    /// Canonical poker request ABI version claimed by the envelope.
    #[must_use]
    pub const fn abi_version(&self) -> u8 {
        self.abi_version
    }

    /// Serialized Stwo proof bytes.
    #[must_use]
    pub fn stark_proof_bytes(&self) -> &[u8] {
        &self.stark_proof_bytes
    }

    /// Serialized proven state-root binding bytes.
    #[must_use]
    pub fn root_binding(&self) -> &[u8] {
        &self.root_binding_bytes
    }

    /// Complete canonical poker-precompile request bytes.
    #[must_use]
    pub fn crypto_request_bytes(&self) -> &[u8] {
        &self.crypto_request_bytes
    }

    /// Encode the envelope using fixed-width little-endian lengths.
    ///
    /// # Errors
    ///
    /// Rejects a payload exceeding the configured proof or request limit.
    pub fn encode(&self) -> TexasAirResult<Vec<u8>> {
        validate_lengths(
            self.stark_proof_bytes.len(),
            self.crypto_request_bytes.len(),
        )?;
        let proof_len = u32::try_from(self.stark_proof_bytes.len()).map_err(|_| {
            TexasAirError::SerializationError("dual proof length exceeds u32".into())
        })?;
        let request_len = u32::try_from(self.crypto_request_bytes.len()).map_err(|_| {
            TexasAirError::SerializationError("crypto request length exceeds u32".into())
        })?;
        let binding_len = u32::try_from(self.root_binding_bytes.len()).map_err(|_| {
            TexasAirError::SerializationError("root binding length exceeds u32".into())
        })?;
        let mut out = Vec::with_capacity(
            HEADER_LEN
                + self.stark_proof_bytes.len()
                + self.crypto_request_bytes.len()
                + self.root_binding_bytes.len(),
        );
        out.extend_from_slice(&DUAL_PROOF_MAGIC);
        out.extend_from_slice(&[
            self.version,
            self.method_kind as u8,
            self.precompile_id as u8,
            self.abi_version,
        ]);
        out.extend_from_slice(&proof_len.to_le_bytes());
        out.extend_from_slice(&request_len.to_le_bytes());
        out.extend_from_slice(&binding_len.to_le_bytes());
        out.extend_from_slice(&self.stark_proof_bytes);
        out.extend_from_slice(&self.crypto_request_bytes);
        out.extend_from_slice(&self.root_binding_bytes);
        Ok(out)
    }

    /// Hash the canonical envelope bytes without allocating a second full
    /// encoded buffer. The caller supplies the domain and payload length
    /// framing used by the outer aggregate digest.
    pub(crate) fn update_hasher(&self, hasher: &mut Blake2bVar) -> TexasAirResult<usize> {
        let encoded_len = self.encoded_len()?;
        hasher.update(&DUAL_PROOF_MAGIC);
        hasher.update(&[
            self.version,
            self.method_kind as u8,
            self.precompile_id as u8,
            self.abi_version,
        ]);
        hasher.update(&(self.stark_proof_bytes.len() as u32).to_le_bytes());
        hasher.update(&(self.crypto_request_bytes.len() as u32).to_le_bytes());
        hasher.update(&(self.root_binding_bytes.len() as u32).to_le_bytes());
        hasher.update(&self.stark_proof_bytes);
        hasher.update(&self.crypto_request_bytes);
        hasher.update(&self.root_binding_bytes);
        Ok(encoded_len)
    }

    /// Append the canonical envelope bytes to an existing output buffer.
    pub(crate) fn encode_into(&self, out: &mut Vec<u8>) -> TexasAirResult<usize> {
        let start = out.len();
        let encoded_len = self.encoded_len()?;
        let proof_len = u32::try_from(self.stark_proof_bytes.len()).map_err(|_| {
            TexasAirError::SerializationError("dual proof length exceeds u32".into())
        })?;
        let request_len = u32::try_from(self.crypto_request_bytes.len()).map_err(|_| {
            TexasAirError::SerializationError("crypto request length exceeds u32".into())
        })?;
        let binding_len = u32::try_from(self.root_binding_bytes.len()).map_err(|_| {
            TexasAirError::SerializationError("root binding length exceeds u32".into())
        })?;
        out.extend_from_slice(&DUAL_PROOF_MAGIC);
        out.extend_from_slice(&[
            self.version,
            self.method_kind as u8,
            self.precompile_id as u8,
            self.abi_version,
        ]);
        out.extend_from_slice(&proof_len.to_le_bytes());
        out.extend_from_slice(&request_len.to_le_bytes());
        out.extend_from_slice(&binding_len.to_le_bytes());
        out.extend_from_slice(&self.stark_proof_bytes);
        out.extend_from_slice(&self.crypto_request_bytes);
        out.extend_from_slice(&self.root_binding_bytes);
        debug_assert_eq!(out.len() - start, encoded_len);
        Ok(encoded_len)
    }

    /// Exact encoded length of [`DualProofBundle::encode`] without building
    /// the wire bytes.
    ///
    /// Applies the same length validation as `encode` so callers can enforce
    /// transport size bounds on freshly proved packages without re-serializing
    /// megabyte-scale proof payloads.
    ///
    /// # Errors
    ///
    /// Rejects a payload exceeding the configured proof or request limit.
    pub(crate) fn encoded_len(&self) -> TexasAirResult<usize> {
        validate_lengths(
            self.stark_proof_bytes.len(),
            self.crypto_request_bytes.len(),
        )?;
        let proof_len = u32::try_from(self.stark_proof_bytes.len()).map_err(|_| {
            TexasAirError::SerializationError("dual proof length exceeds u32".into())
        })?;
        let request_len = u32::try_from(self.crypto_request_bytes.len()).map_err(|_| {
            TexasAirError::SerializationError("crypto request length exceeds u32".into())
        })?;
        let binding_len = u32::try_from(self.root_binding_bytes.len()).map_err(|_| {
            TexasAirError::SerializationError("root binding length exceeds u32".into())
        })?;
        Ok(HEADER_LEN + proof_len as usize + request_len as usize + binding_len as usize)
    }

    /// Strictly decode a dual-proof envelope.
    ///
    /// Unknown versions/selectors, invalid method/precompile combinations,
    /// oversized fields, truncation, and trailing bytes are rejected.
    ///
    /// # Errors
    ///
    /// Returns [`TexasAirError::SerializationError`] for malformed wire data.
    pub fn decode(bytes: &[u8]) -> TexasAirResult<Self> {
        if bytes.len() < HEADER_LEN {
            return Err(wire_error("dual proof header is truncated"));
        }
        if bytes[..8] != DUAL_PROOF_MAGIC {
            return Err(wire_error("dual proof magic mismatch"));
        }
        let version = bytes[8];
        if version != DUAL_PROOF_VERSION {
            return Err(wire_error(format!(
                "unsupported dual proof version {version}"
            )));
        }
        let method_kind = MethodKind::from_u8(bytes[9])
            .ok_or_else(|| wire_error("unknown dual proof method kind"))?;
        let precompile_id = match bytes[10] {
            1 => PokerPrecompileId::Shuffle,
            2 => PokerPrecompileId::DleqLeave,
            3 => PokerPrecompileId::ReconstructionV3,
            4 => PokerPrecompileId::RevealToken,
            _ => return Err(wire_error("unknown poker precompile id")),
        };
        let abi_version = bytes[11];
        validate_route(method_kind, precompile_id, abi_version)?;
        let proof_len = u32::from_le_bytes(bytes[12..16].try_into().expect("fixed slice")) as usize;
        let request_len =
            u32::from_le_bytes(bytes[16..20].try_into().expect("fixed slice")) as usize;
        let binding_len =
            u32::from_le_bytes(bytes[20..24].try_into().expect("fixed slice")) as usize;
        validate_lengths(proof_len, request_len)?;
        if binding_len > MAX_ROOT_BINDING_BYTES {
            return Err(wire_error("dual proof root binding length is invalid"));
        }
        let expected_len = HEADER_LEN
            .checked_add(proof_len)
            .and_then(|len| len.checked_add(request_len))
            .and_then(|len| len.checked_add(binding_len))
            .ok_or_else(|| wire_error("dual proof total length overflow"))?;
        if bytes.len() != expected_len {
            return Err(wire_error(format!(
                "dual proof length mismatch: header declares {expected_len}, received {}",
                bytes.len()
            )));
        }
        let proof_end = HEADER_LEN + proof_len;
        let request_end = proof_end + request_len;
        Ok(Self {
            version,
            method_kind,
            precompile_id,
            abi_version,
            stark_proof_bytes: bytes[HEADER_LEN..proof_end].to_vec(),
            crypto_request_bytes: bytes[proof_end..request_end].to_vec(),
            root_binding_bytes: bytes[request_end..].to_vec(),
        })
    }
}

/// Result of verifying both halves against an independently supplied task.
///
/// Private fields ensure this acceptance object can only be issued by the
/// verifier path in this module.
#[derive(Debug, Clone)]
pub struct VerifiedDualProof {
    receipt: VerificationReceipt,
    precompile_binding: PrecompileCallBinding,
}

impl VerifiedDualProof {
    /// Native-verifier receipt for the accepted Stwo method proof.
    #[must_use]
    pub const fn receipt(&self) -> &VerificationReceipt {
        &self.receipt
    }

    /// Independently reverified binding for the accepted crypto request.
    #[must_use]
    pub const fn precompile_binding(&self) -> &PrecompileCallBinding {
        &self.precompile_binding
    }
}

/// Build both proof halves for a supported crypto task.
///
/// The task is replayed before proof generation. Other method kinds are
/// rejected because they do not yet have a stage-3 poker-precompile binding.
///
/// # Errors
///
/// Returns an error when VM replay, crypto verification, trace generation,
/// Stwo proving, or serialization fails.
pub fn prove_dual_proof(task: &ProveTask) -> TexasAirResult<DualProofBundle> {
    Ok(prove_dual_proof_inner(task, false)?.bundle)
}

/// A freshly proved stage-3 package together with its in-memory acceptance
/// artifacts.
///
/// The receipt and binding are produced by the same `prepare` pass that built
/// the proof, so downstream in-process aggregation does not need to re-run
/// crypto precompile verification or re-deserialize the Stwo proof. This value
/// must never cross a serialization boundary; external consumers only see the
/// [`DualProofBundle`] and must use [`verify_dual_proof`].
pub(crate) struct ProvenDualProof {
    /// Freshly encoded stage-3 transport bundle.
    pub(crate) bundle: DualProofBundle,
    /// Receipt issued by the single native verification of the fresh proof.
    pub(crate) receipt: VerificationReceipt,
    /// Precompile binding accepted during the prove-side `prepare` pass.
    pub(crate) binding: PrecompileCallBinding,
}

/// Internal prove result before optional receipt issuance.
struct ProvenDualParts {
    bundle: DualProofBundle,
    receipt: Option<VerificationReceipt>,
    binding: PrecompileCallBinding,
}

/// Prove a stage-3 package and verify it exactly once in-process.
///
/// This is the internal aggregation fast path: `prepare` already verified the
/// canonical crypto request, so the freshly proved Stwo method proof is
/// verified once (against the same independently reconstructed AIR and public
/// inputs used by [`verify_dual_proof`]) purely to issue its receipt. No
/// serialized proof is ever decoded back.
pub(crate) fn prove_dual_proof_verified(task: &ProveTask) -> TexasAirResult<ProvenDualProof> {
    let parts = prove_dual_proof_inner(task, true)?;
    Ok(ProvenDualProof {
        bundle: parts.bundle,
        receipt: parts.receipt.expect("receipt issuance was requested"),
        binding: parts.binding,
    })
}

fn prove_dual_proof_inner(
    task: &ProveTask,
    issue_receipt: bool,
) -> TexasAirResult<ProvenDualParts> {
    match prepare(task, None)? {
        PreparedMethod::Shuffle {
            air,
            mut public_inputs,
            row,
            binding,
            request_bytes,
        } => {
            let row_values = row.to_vec();
            public_inputs.bind_expected_trace_row(&row_values)?;
            let trace = gen_method_trace(
                SubmitShuffleV2Air::num_columns(),
                &row_values,
                &SubmitShuffleV2Row::padding().to_vec(),
            )?;
            let proof = prove_method(
                &trace,
                air,
                SubmitShuffleV2Air::num_columns(),
                public_inputs,
            )?;
            let bundle = bundle_from_stark(
                MethodKind::SubmitShuffleV2,
                PokerPrecompileId::Shuffle,
                SHUFFLE_ABI_VERSION,
                &proof.stark_proof,
                request_bytes,
                &proof.root_binding,
            )?;
            // Borrow the air+inputs from the produced proof instead of cloning
            // before `proof` is moved into the verify call.
            let expected_air = proof.air.clone();
            let expected_inputs = proof.public_inputs.clone();
            let receipt = issue_receipt
                .then(|| {
                    verify_method_against_and_issue_receipt(proof, &expected_air, &expected_inputs)
                })
                .transpose()?;
            Ok(ProvenDualParts {
                bundle,
                receipt,
                binding,
            })
        }
        PreparedMethod::Reconstruction {
            air,
            mut public_inputs,
            row,
            binding,
            request_bytes,
        } => {
            let row_values = row.to_vec();
            public_inputs.bind_expected_trace_row(&row_values)?;
            let trace = gen_method_trace(
                SubmitReconstructDeckAir::num_columns(),
                &row_values,
                &SubmitReconstructDeckRow::padding().to_vec(),
            )?;
            let proof = prove_method(
                &trace,
                air,
                SubmitReconstructDeckAir::num_columns(),
                public_inputs,
            )?;
            let expected_air = proof.air.clone();
            let expected_inputs = proof.public_inputs.clone();
            let bundle = bundle_from_stark(
                MethodKind::SubmitReconstructDeck,
                PokerPrecompileId::ReconstructionV3,
                RECONSTRUCTION_ABI_VERSION,
                &proof.stark_proof,
                request_bytes,
                &proof.root_binding,
            )?;
            let receipt = issue_receipt
                .then(|| {
                    verify_method_against_and_issue_receipt(proof, &expected_air, &expected_inputs)
                })
                .transpose()?;
            Ok(ProvenDualParts {
                bundle,
                receipt,
                binding,
            })
        }
        PreparedMethod::Fold {
            air,
            mut public_inputs,
            row,
            binding,
            request_bytes,
        } => {
            let row_values = row.to_vec();
            public_inputs.bind_expected_trace_row(&row_values)?;
            let trace = gen_method_trace(
                FoldWithProofAir::num_columns(),
                &row_values,
                &FoldWithProofRow::padding().to_vec(),
            )?;
            let proof = prove_method(&trace, air, FoldWithProofAir::num_columns(), public_inputs)?;
            let expected_air = proof.air.clone();
            let expected_inputs = proof.public_inputs.clone();
            let bundle = bundle_from_stark(
                MethodKind::FoldWithProof,
                PokerPrecompileId::DleqLeave,
                LEAVE_DLEQ_ABI_VERSION,
                &proof.stark_proof,
                request_bytes,
                &proof.root_binding,
            )?;
            let receipt = issue_receipt
                .then(|| {
                    verify_method_against_and_issue_receipt(proof, &expected_air, &expected_inputs)
                })
                .transpose()?;
            Ok(ProvenDualParts {
                bundle,
                receipt,
                binding,
            })
        }
        PreparedMethod::Reveal {
            air,
            mut public_inputs,
            row,
            binding,
            request_bytes,
        } => {
            let row_values = row.to_vec();
            public_inputs.bind_expected_trace_row(&row_values)?;
            let trace = gen_method_trace(
                SubmitPlayerRevealTokensAir::num_columns(),
                &row_values,
                &SubmitPlayerRevealTokensRow::padding().to_vec(),
            )?;
            let proof = prove_method(
                &trace,
                air,
                SubmitPlayerRevealTokensAir::num_columns(),
                public_inputs,
            )?;
            let expected_air = proof.air.clone();
            let expected_inputs = proof.public_inputs.clone();
            let bundle = bundle_from_stark(
                MethodKind::SubmitPlayerRevealTokens,
                PokerPrecompileId::RevealToken,
                REVEAL_TOKEN_ABI_VERSION,
                &proof.stark_proof,
                request_bytes,
                &proof.root_binding,
            )?;
            let receipt = issue_receipt
                .then(|| {
                    verify_method_against_and_issue_receipt(proof, &expected_air, &expected_inputs)
                })
                .transpose()?;
            Ok(ProvenDualParts {
                bundle,
                receipt,
                binding,
            })
        }
    }
}

/// Repackage an already archived, natively verified method proof as a dual
/// proof without running the prover again.
///
/// The canonical precompile request is rebuilt from `task`; the archive only
/// supplies the serialized Stwo half and is never trusted for method metadata.
/// This is the bridge used by proving-service outer aggregation after restart.
pub fn dual_proof_from_archived(
    task: &ProveTask,
    archive: &ArchivedMethodProof,
) -> TexasAirResult<DualProofBundle> {
    if archive.method_kind() != task.method_kind {
        return Err(TexasAirError::SpecViolation(
            "archived dual proof method kind does not match task".into(),
        ));
    }
    let prepared = prepare(task, None)?;
    let (method_kind, precompile_id, abi_version, request_bytes, num_columns, log_size) =
        match prepared {
            PreparedMethod::Shuffle {
                request_bytes, air, ..
            } => (
                MethodKind::SubmitShuffleV2,
                PokerPrecompileId::Shuffle,
                SHUFFLE_ABI_VERSION,
                request_bytes,
                SubmitShuffleV2Air::num_columns(),
                air.log_size,
            ),
            PreparedMethod::Reconstruction {
                request_bytes, air, ..
            } => (
                MethodKind::SubmitReconstructDeck,
                PokerPrecompileId::ReconstructionV3,
                RECONSTRUCTION_ABI_VERSION,
                request_bytes,
                SubmitReconstructDeckAir::num_columns(),
                air.log_size,
            ),
            PreparedMethod::Fold {
                request_bytes, air, ..
            } => (
                MethodKind::FoldWithProof,
                PokerPrecompileId::DleqLeave,
                LEAVE_DLEQ_ABI_VERSION,
                request_bytes,
                FoldWithProofAir::num_columns(),
                air.log_size,
            ),
            PreparedMethod::Reveal {
                request_bytes, air, ..
            } => (
                MethodKind::SubmitPlayerRevealTokens,
                PokerPrecompileId::RevealToken,
                REVEAL_TOKEN_ABI_VERSION,
                request_bytes,
                SubmitPlayerRevealTokensAir::num_columns(),
                air.log_size,
            ),
        };
    if archive.num_columns()? != num_columns || archive.log_size() != log_size {
        return Err(TexasAirError::SpecViolation(
            "archived dual proof trace shape does not match canonical task".into(),
        ));
    }
    let stark = archive.decode_stark()?;
    let root_binding = archive.decode_root_binding()?;
    bundle_from_stark(
        method_kind,
        precompile_id,
        abi_version,
        &stark,
        request_bytes,
        &root_binding,
    )
}

/// Verify both proof halves against an independently authenticated task.
///
/// Verification never falls back to package-carried AIR or public inputs:
/// those values are reconstructed from `task` after a complete VM replay.
///
/// # Errors
///
/// Returns an error if either proof half is invalid or if any method, ABI,
/// request, digest, state, seat, table, hand, call, version, or dispatch scope
/// binding differs.
pub fn verify_dual_proof(
    task: &ProveTask,
    bundle: &DualProofBundle,
) -> TexasAirResult<VerifiedDualProof> {
    if bundle.version != DUAL_PROOF_VERSION {
        return Err(wire_error("unsupported in-memory dual proof version"));
    }
    if bundle.method_kind != task.method_kind {
        return Err(TexasAirError::SpecViolation(
            "dual proof method kind does not match trusted task".into(),
        ));
    }
    validate_route(bundle.method_kind, bundle.precompile_id, bundle.abi_version)?;

    match prepare(task, Some(&bundle.crypto_request_bytes))? {
        PreparedMethod::Shuffle {
            air,
            mut public_inputs,
            row,
            binding,
            ..
        } => {
            let row_values = row.to_vec();
            public_inputs.bind_expected_trace_row(&row_values)?;
            let stark_proof = decode_stark(&bundle.stark_proof_bytes)?;
            let root_binding = decode_root_binding(&bundle.root_binding_bytes)?;
            let proof = MethodProof {
                stark_proof,
                air: air.clone(),
                log_size: air.log_size,
                num_columns: SubmitShuffleV2Air::num_columns(),
                root_binding,
                public_inputs: public_inputs.clone(),
            };
            let receipt = verify_method_against_and_issue_receipt(proof, &air, &public_inputs)?;
            Ok(VerifiedDualProof {
                receipt,
                precompile_binding: binding,
            })
        }
        PreparedMethod::Reconstruction {
            air,
            mut public_inputs,
            row,
            binding,
            ..
        } => {
            let row_values = row.to_vec();
            public_inputs.bind_expected_trace_row(&row_values)?;
            let stark_proof = decode_stark(&bundle.stark_proof_bytes)?;
            let root_binding = decode_root_binding(&bundle.root_binding_bytes)?;
            let proof = MethodProof {
                stark_proof,
                air: air.clone(),
                log_size: air.log_size,
                num_columns: SubmitReconstructDeckAir::num_columns(),
                root_binding,
                public_inputs: public_inputs.clone(),
            };
            let receipt = verify_method_against_and_issue_receipt(proof, &air, &public_inputs)?;
            Ok(VerifiedDualProof {
                receipt,
                precompile_binding: binding,
            })
        }
        PreparedMethod::Fold {
            air,
            mut public_inputs,
            row,
            binding,
            ..
        } => {
            let row_values = row.to_vec();
            public_inputs.bind_expected_trace_row(&row_values)?;
            let stark_proof = decode_stark(&bundle.stark_proof_bytes)?;
            let root_binding = decode_root_binding(&bundle.root_binding_bytes)?;
            let proof = MethodProof {
                stark_proof,
                air: air.clone(),
                log_size: air.log_size,
                num_columns: FoldWithProofAir::num_columns(),
                root_binding,
                public_inputs: public_inputs.clone(),
            };
            let receipt = verify_method_against_and_issue_receipt(proof, &air, &public_inputs)?;
            Ok(VerifiedDualProof {
                receipt,
                precompile_binding: binding,
            })
        }
        PreparedMethod::Reveal {
            air,
            mut public_inputs,
            row,
            binding,
            ..
        } => {
            let row_values = row.to_vec();
            public_inputs.bind_expected_trace_row(&row_values)?;
            let stark_proof = decode_stark(&bundle.stark_proof_bytes)?;
            let root_binding = decode_root_binding(&bundle.root_binding_bytes)?;
            let proof = MethodProof {
                stark_proof,
                air: air.clone(),
                log_size: air.log_size,
                num_columns: SubmitPlayerRevealTokensAir::num_columns(),
                root_binding,
                public_inputs: public_inputs.clone(),
            };
            let receipt = verify_method_against_and_issue_receipt(proof, &air, &public_inputs)?;
            Ok(VerifiedDualProof {
                receipt,
                precompile_binding: binding,
            })
        }
    }
}

enum PreparedMethod {
    Shuffle {
        air: SubmitShuffleV2Air,
        public_inputs: TexasPublicInputs,
        row: SubmitShuffleV2Row,
        binding: PrecompileCallBinding,
        request_bytes: Vec<u8>,
    },
    Reconstruction {
        air: SubmitReconstructDeckAir,
        public_inputs: TexasPublicInputs,
        row: SubmitReconstructDeckRow,
        binding: PrecompileCallBinding,
        request_bytes: Vec<u8>,
    },
    Fold {
        air: FoldWithProofAir,
        public_inputs: TexasPublicInputs,
        row: FoldWithProofRow,
        binding: PrecompileCallBinding,
        request_bytes: Vec<u8>,
    },
    Reveal {
        air: SubmitPlayerRevealTokensAir,
        public_inputs: TexasPublicInputs,
        row: SubmitPlayerRevealTokensRow,
        binding: PrecompileCallBinding,
        request_bytes: Vec<u8>,
    },
}

fn prepare(task: &ProveTask, supplied_request: Option<&[u8]>) -> TexasAirResult<PreparedMethod> {
    validate_full_dispatch_task(task)?;
    let pre_image = table_state_preimage(&task.pre_table)?;
    let post_image = table_state_preimage(&task.post_table)?;
    let pre_root = compute_state_root(&task.pre_table)?;
    let post_root = compute_state_root(&task.post_table)?;
    let mut public_inputs = TexasPublicInputs {
        pre_image,
        post_image,
        pre_state_root: pre_root,
        post_state_root: post_root,
        kind: task.method_kind,
        table_id: task.table_id,
        hand_id: task.hand_id,
        call_seq: task.call_seq,
        pre_version: u64::from(task.pre_table.call_seq),
        post_version: u64::from(task.post_table.call_seq),
        dispatch_call_digest: [0u8; 32],
        dispatch_call: None,
        precompile_binding: None,
        expected_trace_row: None,
        component: None,
    };
    public_inputs.bind_dispatch_call(
        task.context.clone(),
        task.selector(),
        task.raw_args.clone(),
    )?;
    let method_input = task.method_input()?;
    let replay_args = task.replay_args()?;

    match task.method_kind {
        MethodKind::SubmitShuffleV2 => {
            let MethodInput::SubmitShuffleV2 { seat_index } = &method_input else {
                return Err(TexasAirError::SpecViolation(
                    "submit_shuffle_v2 task has the wrong MethodInput variant".into(),
                ));
            };
            let args: poker_l1::contracts::texas_poker::dispatch::SubmitShuffleV2Args =
                borsh::from_slice(&replay_args).map_err(|error| {
                    TexasAirError::SerializationError(format!(
                        "submit_shuffle_v2 raw args borsh: {error}"
                    ))
                })?;
            if args.seat_index != *seat_index {
                return Err(TexasAirError::SpecViolation(
                    "submit_shuffle_v2 seat differs between task fields".into(),
                ));
            }
            let aggregated_pk = task
                .pre_table
                .derived_aggregated_pk()
                .map_err(|error| TexasAirError::SpecViolation(error.to_string()))?
                .ok_or_else(|| {
                    TexasAirError::SpecViolation(
                        "submit_shuffle_v2 requires an aggregated public key".into(),
                    )
                })?;
            let call_context = call_context(task, *seat_index, &public_inputs);
            let expected_request = build_bls12381_shuffle_request(
                poker_protocol::transcript_domains::SHUFFLE_V2_POSEIDON,
                &call_context,
                TranscriptId::Poseidon252,
                &aggregated_pk.0,
                &task.pre_table.deck_state.encrypted,
                &args.output_cards,
                &args.shuffle_proof,
            )
            .map_err(|error| {
                TexasAirError::SpecViolation(format!(
                    "submit_shuffle_v2 request construction failed: {error}"
                ))
            })?;
            let expected_bytes = expected_request.encode().map_err(|error| {
                TexasAirError::SerializationError(format!(
                    "submit_shuffle_v2 request encoding failed: {error}"
                ))
            })?;
            let request_bytes = require_expected_request(supplied_request, expected_bytes)?;
            let request = ShuffleVerifyRequest::decode(&request_bytes).map_err(|error| {
                TexasAirError::SpecViolation(format!(
                    "shuffle request canonical decode failed: {error}"
                ))
            })?;
            let binding = PrecompileCallBinding::verify_shuffle(&request)?;
            let input = SubmitShuffleV2Input {
                seat_index: *seat_index,
                new_deck_commitment: deck_commitment(&task.post_table),
                // Admission is determined by the pre-dispatch shuffle phase. The final shuffler
                // legitimately drives the post-state to NONE after `advance_shuffle`.
                shuffle_phase: task.pre_table.shuffle_phase(),
                precompile: binding.air_binding(),
            };
            let mut row = SubmitShuffleV2Row::active(
                &input,
                state_root_to_air_limbs(pre_root),
                state_root_to_air_limbs(post_root),
                task.table_id,
                task.hand_id,
                task.call_seq,
                u64::from(task.pre_table.call_seq),
                u64::from(task.post_table.call_seq),
                task.post_table.shuffle_state().completed_mask.count_ones() as u8,
            );
            row.common.pre_pot = crate::airs::common::u64_to_m31_limbs(task.pre_table.pot);
            row.common.post_pot = crate::airs::common::u64_to_m31_limbs(task.post_table.pot);
            let air = SubmitShuffleV2Air {
                log_size: MIN_LOG_SIZE,
                input,
                pre_state_root: state_root_to_air_limbs(pre_root),
                post_state_root: state_root_to_air_limbs(post_root),
                table_id: task.table_id,
                hand_id: task.hand_id,
                call_seq: task.call_seq,
                pre_version: u64::from(task.pre_table.call_seq),
                post_version: u64::from(task.post_table.call_seq),
            };
            public_inputs.precompile_binding = Some(binding.clone());
            Ok(PreparedMethod::Shuffle {
                air,
                public_inputs,
                row,
                binding,
                request_bytes,
            })
        }
        MethodKind::SubmitReconstructDeck => {
            let MethodInput::SubmitReconstructDeck { seat_index } = &method_input else {
                return Err(TexasAirError::SpecViolation(
                    "submit_reconstruct_deck task has the wrong MethodInput variant".into(),
                ));
            };
            let args: poker_l1::contracts::texas_poker::dispatch::SubmitReconstructDeckArgs =
                borsh::from_slice(&replay_args).map_err(|error| {
                    TexasAirError::SerializationError(format!(
                        "submit_reconstruct_deck raw args borsh: {error}"
                    ))
                })?;
            if args.seat_index != *seat_index {
                return Err(TexasAirError::SpecViolation(
                    "submit_reconstruct_deck seat differs between task fields".into(),
                ));
            }
            let call_context = call_context(task, *seat_index, &public_inputs);
            let expected_request = build_reconstruction_request(
                poker_protocol::transcript_domains::RECONSTRUCT_POSEIDON,
                &call_context,
                TranscriptId::Poseidon252,
                &args.statement,
                &args.proof,
            )
            .map_err(|error| {
                TexasAirError::SpecViolation(format!(
                    "submit_reconstruct_deck request construction failed: {error}"
                ))
            })?;
            let expected_bytes = expected_request.encode().map_err(|error| {
                TexasAirError::SerializationError(format!(
                    "submit_reconstruct_deck request encoding failed: {error}"
                ))
            })?;
            let request_bytes = require_expected_request(supplied_request, expected_bytes)?;
            let request =
                ReconstructionVerifyRequest::decode(&request_bytes).map_err(|error| {
                    TexasAirError::SpecViolation(format!(
                        "reconstruction V3 request canonical decode failed: {error}"
                    ))
                })?;
            let binding = PrecompileCallBinding::verify_reconstruction_v3(&request)?;
            let input = SubmitReconstructDeckInput {
                seat_index: *seat_index,
                reconstruct_phase: task.pre_table.reconstruct_phase(),
                precompile: binding.air_binding(),
            };
            let row = SubmitReconstructDeckRow::active(
                &input,
                state_root_to_air_limbs(pre_root),
                state_root_to_air_limbs(post_root),
                task.table_id,
                task.hand_id,
                task.call_seq,
                u64::from(task.pre_table.call_seq),
                u64::from(task.post_table.call_seq),
            );
            let air = SubmitReconstructDeckAir {
                log_size: MIN_LOG_SIZE,
                input,
                pre_state_root: state_root_to_air_limbs(pre_root),
                post_state_root: state_root_to_air_limbs(post_root),
                table_id: task.table_id,
                hand_id: task.hand_id,
                call_seq: task.call_seq,
                pre_version: u64::from(task.pre_table.call_seq),
                post_version: u64::from(task.post_table.call_seq),
            };
            public_inputs.precompile_binding = Some(binding.clone());
            Ok(PreparedMethod::Reconstruction {
                air,
                public_inputs,
                row,
                binding,
                request_bytes,
            })
        }
        MethodKind::FoldWithProof => {
            let MethodInput::FoldWithProof { seat_index } = &method_input else {
                return Err(TexasAirError::SpecViolation(
                    "fold_with_proof task has the wrong MethodInput variant".into(),
                ));
            };
            let args: poker_l1::contracts::texas_poker::dispatch::FoldWithProofArgs =
                borsh::from_slice(&replay_args).map_err(|error| {
                    TexasAirError::SerializationError(format!(
                        "fold_with_proof raw args borsh: {error}"
                    ))
                })?;
            if args.seat_index != *seat_index {
                return Err(TexasAirError::SpecViolation(
                    "fold_with_proof seat differs between task fields".into(),
                ));
            }
            let outcome = derive_fold_outcome(
                &task.pre_table,
                &task.post_table,
                *seat_index,
                "fold_with_proof",
                Some(
                    &crate::airs::composition::derive_composite_transition_plan_from_task(task)?
                        .settlement,
                ),
            )?;
            let player_pk = task
                .pre_table
                .seats
                .get(usize::from(*seat_index))
                .ok_or_else(|| {
                    TexasAirError::SpecViolation(
                        "fold_with_proof seat is outside the canonical pre-table".into(),
                    )
                })?
                .pk()
                .copied()
                .ok_or_else(|| {
                    TexasAirError::SpecViolation(
                        "fold_with_proof seat has no live Mental Poker key".into(),
                    )
                })?;
            let expected_request = LeaveDleqVerifyRequest::new(
                call_context(task, *seat_index, &public_inputs),
                task.pre_table.deck_state.encrypted.to_vec(),
                args.output_cards,
                player_pk,
                args.fold_proof,
            );
            let request_bytes =
                require_expected_request(supplied_request, expected_request.encode()?)?;
            let request = LeaveDleqVerifyRequest::decode(&request_bytes)?;
            let binding = PrecompileCallBinding::verify_leave_dleq(&request)?;
            let input = FoldWithProofInput {
                seat_index: *seat_index,
                outcome,
                old_deck_commitment: deck_commitment(&task.pre_table),
                new_deck_commitment: deck_commitment(&task.post_table),
                precompile: binding.air_binding(),
            };
            let row = FoldWithProofRow::active(
                &input,
                state_root_to_air_limbs(pre_root),
                state_root_to_air_limbs(post_root),
                task.table_id,
                task.hand_id,
                task.call_seq,
                u64::from(task.pre_table.call_seq),
                u64::from(task.post_table.call_seq),
                task.pre_table.round_state(),
                task.post_table.round_state(),
                task.pre_table.pot,
                task.post_table.pot,
            );
            let air = FoldWithProofAir {
                log_size: MIN_LOG_SIZE,
                input,
                pre_state_root: state_root_to_air_limbs(pre_root),
                post_state_root: state_root_to_air_limbs(post_root),
                table_id: task.table_id,
                hand_id: task.hand_id,
                call_seq: task.call_seq,
                pre_version: u64::from(task.pre_table.call_seq),
                post_version: u64::from(task.post_table.call_seq),
            };
            public_inputs.precompile_binding = Some(binding.clone());
            Ok(PreparedMethod::Fold {
                air,
                public_inputs,
                row,
                binding,
                request_bytes,
            })
        }
        MethodKind::SubmitPlayerRevealTokens => {
            let MethodInput::SubmitPlayerRevealTokens { seat_index } = &method_input else {
                return Err(TexasAirError::SpecViolation(
                    "submit_player_reveal_tokens task has the wrong MethodInput variant".into(),
                ));
            };
            let args: poker_l1::contracts::texas_poker::dispatch::SubmitRevealTokensArgs =
                borsh::from_slice(&replay_args).map_err(|error| {
                    TexasAirError::SerializationError(format!(
                        "submit_player_reveal_tokens raw args borsh: {error}"
                    ))
                })?;
            if args.seat_index != *seat_index {
                return Err(TexasAirError::SpecViolation(
                    "submit_player_reveal_tokens seat differs between task fields".into(),
                ));
            }
            let call_context = call_context(task, *seat_index, &public_inputs);
            let expected_request =
                RevealTokenVerifyRequest::from_dispatch(call_context, &task.pre_table, &args)?;
            let expected_bytes = expected_request.encode()?;
            let request_bytes = require_expected_request(supplied_request, expected_bytes)?;
            let request = RevealTokenVerifyRequest::decode(&request_bytes)?;
            let binding = PrecompileCallBinding::verify_reveal_tokens(&request)?;
            let version_increment = reveal_version_increment(task)?;
            let input = SubmitPlayerRevealTokensInput {
                seat_index: *seat_index,
                reveal_phase: task.pre_table.reveal_phase(),
                version_increment,
                precompile: binding.air_binding(),
                settlement: replay_reveal_settlement_binding(task)?,
            };
            let post_revealed_count = u8::try_from(task.post_table.reveal_assignments().len())
                .map_err(|_| {
                    TexasAirError::SpecViolation(
                        "submit_player_reveal_tokens assignment count exceeds u8".into(),
                    )
                })?;
            let mut row = SubmitPlayerRevealTokensRow::active(
                &input,
                state_root_to_air_limbs(pre_root),
                state_root_to_air_limbs(post_root),
                task.table_id,
                task.hand_id,
                task.call_seq,
                u64::from(task.pre_table.call_seq),
                u64::from(task.post_table.call_seq),
                post_revealed_count,
            );
            row.common.pre_pot = crate::airs::common::u64_to_m31_limbs(task.pre_table.pot);
            row.common.post_pot = crate::airs::common::u64_to_m31_limbs(task.post_table.pot);
            let air = SubmitPlayerRevealTokensAir {
                log_size: MIN_LOG_SIZE,
                input,
                pre_state_root: state_root_to_air_limbs(pre_root),
                post_state_root: state_root_to_air_limbs(post_root),
                table_id: task.table_id,
                hand_id: task.hand_id,
                call_seq: task.call_seq,
                pre_version: u64::from(task.pre_table.call_seq),
                post_version: u64::from(task.post_table.call_seq),
            };
            public_inputs.precompile_binding = Some(binding.clone());
            Ok(PreparedMethod::Reveal {
                air,
                public_inputs,
                row,
                binding,
                request_bytes,
            })
        }
        other => Err(TexasAirError::NotImplemented(format!(
            "{} has no stage-3 dual proof package",
            other.method_name()
        ))),
    }
}

fn call_context(task: &ProveTask, seat_index: u8, pi: &TexasPublicInputs) -> Vec<u8> {
    precompile_call_context(
        task.method_kind,
        seat_index,
        pi.table_id,
        pi.hand_id,
        pi.call_seq,
        pi.pre_version,
        pi.post_version,
        pi.pre_state_root,
        pi.post_state_root,
        pi.dispatch_call_digest,
    )
}

fn require_expected_request(supplied: Option<&[u8]>, expected: Vec<u8>) -> TexasAirResult<Vec<u8>> {
    if let Some(bytes) = supplied {
        if bytes != expected {
            return Err(TexasAirError::SpecViolation(
                "dual proof crypto request does not match the canonical trusted task request"
                    .into(),
            ));
        }
        // Byte-equal to `expected`; return the already-allocated canonical
        // buffer instead of copying the supplied slice again.
        Ok(expected)
    } else {
        Ok(expected)
    }
}

fn bundle_from_stark(
    method_kind: MethodKind,
    precompile_id: PokerPrecompileId,
    abi_version: u8,
    stark_proof: &StarkProof<Poseidon252MerkleHasher>,
    crypto_request_bytes: Vec<u8>,
    root_binding: &crate::state_root_binding::ArchivedStateRootBindingProof,
) -> TexasAirResult<DualProofBundle> {
    let stark_proof_bytes = bincode_options()
        .serialize(stark_proof)
        .map_err(|error| wire_error(format!("Stwo proof serialization failed: {error}")))?;
    validate_lengths(stark_proof_bytes.len(), crypto_request_bytes.len())?;
    let root_binding_bytes = borsh::to_vec(root_binding)
        .map_err(|error| wire_error(format!("root binding serialization failed: {error}")))?;
    Ok(DualProofBundle {
        version: DUAL_PROOF_VERSION,
        method_kind,
        precompile_id,
        abi_version,
        stark_proof_bytes,
        crypto_request_bytes,
        root_binding_bytes,
    })
}

fn decode_root_binding(
    bytes: &[u8],
) -> TexasAirResult<crate::state_root_binding::ArchivedStateRootBindingProof> {
    borsh::from_slice(bytes)
        .map_err(|error| wire_error(format!("dual proof root binding decoding failed: {error}")))
}

fn decode_stark(bytes: &[u8]) -> TexasAirResult<StarkProof<Poseidon252MerkleHasher>> {
    if bytes.is_empty() || bytes.len() > MAX_STARK_PROOF_BYTES {
        return Err(wire_error("invalid serialized Stwo proof length"));
    }
    bincode_options()
        .reject_trailing_bytes()
        .deserialize(bytes)
        .map_err(|error| wire_error(format!("Stwo proof decoding failed: {error}")))
}

fn bincode_options() -> impl Options {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(MAX_STARK_PROOF_BYTES as u64)
}

fn validate_route(
    method_kind: MethodKind,
    precompile_id: PokerPrecompileId,
    abi_version: u8,
) -> TexasAirResult<()> {
    let valid = matches!(
        (method_kind, precompile_id, abi_version),
        (
            MethodKind::SubmitShuffleV2,
            PokerPrecompileId::Shuffle,
            SHUFFLE_ABI_VERSION
        ) | (
            MethodKind::SubmitReconstructDeck,
            PokerPrecompileId::ReconstructionV3,
            RECONSTRUCTION_ABI_VERSION
        ) | (
            MethodKind::FoldWithProof,
            PokerPrecompileId::DleqLeave,
            LEAVE_DLEQ_ABI_VERSION
        ) | (
            MethodKind::SubmitPlayerRevealTokens,
            PokerPrecompileId::RevealToken,
            REVEAL_TOKEN_ABI_VERSION
        )
    );
    if !valid {
        return Err(wire_error(
            "dual proof method/precompile/ABI route is not supported",
        ));
    }
    Ok(())
}

fn reveal_version_increment(task: &ProveTask) -> TexasAirResult<u8> {
    let expected_post_version = u64::from(task.pre_table.call_seq)
        .checked_add(1)
        .ok_or_else(|| {
            TexasAirError::SpecViolation("submit_player_reveal_tokens pre-version overflow".into())
        })?;
    if u64::from(task.post_table.call_seq) != expected_post_version {
        return Err(TexasAirError::SpecViolation(format!(
            "submit_player_reveal_tokens: expected one external-command version increment to {expected_post_version}, got {}",
            u64::from(task.post_table.call_seq)
        )));
    }
    Ok(1)
}

fn validate_lengths(proof_len: usize, request_len: usize) -> TexasAirResult<()> {
    if proof_len == 0 || proof_len > MAX_STARK_PROOF_BYTES {
        return Err(wire_error(format!(
            "Stwo proof length {proof_len} is outside 1..={MAX_STARK_PROOF_BYTES}"
        )));
    }
    if request_len == 0 || request_len > MAX_CRYPTO_REQUEST_BYTES {
        return Err(wire_error(format!(
            "crypto request length {request_len} is outside 1..={MAX_CRYPTO_REQUEST_BYTES}"
        )));
    }
    Ok(())
}

fn wire_error(message: impl Into<String>) -> TexasAirError {
    TexasAirError::SerializationError(message.into())
}

#[cfg(test)]
mod tests {
    use blake2::digest::VariableOutput;
    use super::*;

    #[test]
    fn streaming_child_hash_matches_legacy_encoded_digest() {
        let bundle = DualProofBundle {
            version: DUAL_PROOF_VERSION,
            method_kind: MethodKind::SubmitShuffleV2,
            precompile_id: PokerPrecompileId::Shuffle,
            abi_version: SHUFFLE_ABI_VERSION,
            stark_proof_bytes: vec![0x11; 3],
            crypto_request_bytes: vec![0x22; 5],
            root_binding_bytes: vec![0x33; 2],
        };
        let encoded = bundle.encode().unwrap();
        assert_eq!(bundle.encoded_len().unwrap(), encoded.len());

        let domain = b"zchain.poker.outer_aggregate.child_bytes.v1";
        let mut legacy = Blake2bVar::new(32).unwrap();
        legacy.update(domain);
        legacy.update(&(encoded.len() as u64).to_le_bytes());
        legacy.update(&encoded);
        let mut legacy_digest = [0u8; 32];
        legacy.finalize_variable(&mut legacy_digest).unwrap();

        let mut streaming = Blake2bVar::new(32).unwrap();
        streaming.update(domain);
        streaming.update(&(encoded.len() as u64).to_le_bytes());
        assert_eq!(bundle.update_hasher(&mut streaming).unwrap(), encoded.len());
        let mut streaming_digest = [0u8; 32];
        streaming.finalize_variable(&mut streaming_digest).unwrap();

        assert_eq!(streaming_digest, legacy_digest);

        let mut appended = Vec::new();
        assert_eq!(bundle.encode_into(&mut appended).unwrap(), encoded.len());
        assert_eq!(appended, encoded);
    }
}
