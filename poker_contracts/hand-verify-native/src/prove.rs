//! Prove / verify round trip for the hand-batch statement AIR.
//!
//! Flow (mirrors the main project's `prover.rs` / `verifier.rs` on Stwo 2.3):
//! mix the claim into the Fiat–Shamir channel *before* any commit or draw,
//! commit an empty preprocessed tree, commit the statement trace, prove, and
//! verify against an independently supplied expected claim.

use stwo::core::channel::Poseidon252Channel;
use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;
use stwo::core::fri::FriConfig;
use stwo::core::pcs::{CommitmentSchemeVerifier, PcsConfig};
use stwo::core::poly::circle::CanonicCoset;
use stwo::core::proof::StarkProof;
use stwo::core::vcs_lifted::poseidon252_merkle::{
    Poseidon252MerkleChannel, Poseidon252MerkleHasher,
};
use stwo::core::verifier::verify;
use stwo::core::air::Component;
use stwo::prover::backend::simd::SimdBackend;
use stwo::prover::backend::{Col, Column as _};
use stwo::prover::pcs::CommitmentSchemeProver;
use stwo::prover::poly::circle::{CircleEvaluation, PolyOps};
use stwo::prover::poly::BitReversedOrder;
use stwo::prover::prove;
use stwo_constraint_framework::{FrameworkComponent, TraceLocationAllocator};

use crate::air::{build_trace, HandBatchClaim, HandBatchEval, N_COLUMNS};

/// Canonical PCS profile — deliberately identical to the main project's
/// (`prover_context::protocol_pcs_config`): 10 PoW bits + 30 FRI queries,
/// blowup 1, fold step 1. Prover and verifier must change it atomically.
pub fn protocol_pcs_config() -> PcsConfig {
    PcsConfig {
        pow_bits: 10,
        fri_config: FriConfig::new(0, 1, 30, 1),
        lifting_log_size: None,
    }
}

/// A proof plus the claim it stands for. The claim must be transported
/// alongside the proof (or re-derived by the verifier); the proof alone does
/// not authenticate it.
#[derive(Clone)]
pub struct HandBatchProof {
    pub claim: HandBatchClaim,
    pub stark_proof: StarkProof<Poseidon252MerkleHasher>,
}

/// Prove a claim. The caller must have run the full host-side verification
/// ([`crate::handbatch::verify_hand`]) beforehand — the AIR does not attest
/// the EC results (form-① boundary, see README).
pub fn prove_claim(claim: &HandBatchClaim) -> Result<HandBatchProof, String> {
    let config = protocol_pcs_config();
    let blowup_log = config.fri_config.log_blowup_factor;
    let twiddles = SimdBackend::precompute_twiddles(
        CanonicCoset::new(claim.log_size + blowup_log).half_coset(),
    );

    let mut channel = Poseidon252Channel::default();
    claim.mix_into(&mut channel);

    let mut commitment_scheme =
        CommitmentSchemeProver::<SimdBackend, Poseidon252MerkleChannel>::new(config, &twiddles);

    // Tree 0: empty preprocessed trace (the AIR uses none).
    {
        let mut tree_builder = commitment_scheme.tree_builder();
        tree_builder.extend_evals(vec![]);
        tree_builder.commit(&mut channel);
    }

    // Tree 1: the statement trace.
    {
        let cols_data = build_trace(claim);
        let domain = CanonicCoset::new(claim.log_size).circle_domain();
        let mut evals = Vec::with_capacity(cols_data.len());
        for data in cols_data {
            let mut col = Col::<SimdBackend, BaseField>::zeros(1 << claim.log_size);
            for (row, value) in data.into_iter().enumerate() {
                col.set(row, value);
            }
            evals.push(CircleEvaluation::<SimdBackend, _, BitReversedOrder>::new(domain, col));
        }
        let mut tree_builder = commitment_scheme.tree_builder();
        tree_builder.extend_evals(evals);
        tree_builder.commit(&mut channel);
    }

    let mut allocator = TraceLocationAllocator::default();
    let component = FrameworkComponent::new(
        &mut allocator,
        HandBatchEval::new(claim),
        SecureField::from(0u32),
    );

    let stark_proof = prove(&[&component], &mut channel, commitment_scheme)
        .map_err(|e| format!("stwo prove error: {e}"))?;

    Ok(HandBatchProof { claim: *claim, stark_proof })
}

/// Verify a proof against an independently constructed expected claim.
pub fn verify_claim(expected_claim: &HandBatchClaim, proof: &HandBatchProof) -> Result<(), String> {
    if proof.claim != *expected_claim {
        return Err("claim mismatch: transported claim differs from expected".into());
    }
    verify_stark_against(expected_claim, &proof.stark_proof)
}

/// Verify the STARK alone against an expected claim, bypassing the
/// transported-claim equality pre-check. Exposed for negative tests: a proof
/// generated under a different claim must fail here (channel binding), which
/// is the property an L1 verifier relies on when it derives the claim itself.
pub fn verify_stark_against(
    expected_claim: &HandBatchClaim,
    stark_proof: &StarkProof<Poseidon252MerkleHasher>,
) -> Result<(), String> {
    let config = protocol_pcs_config();

    let mut channel = Poseidon252Channel::default();
    expected_claim.mix_into(&mut channel);

    let mut commitment_scheme = CommitmentSchemeVerifier::<Poseidon252MerkleChannel>::new(config);

    // Tree 0: empty preprocessed trace.
    commitment_scheme.commit(stark_proof.commitments[0], &[], &mut channel);

    // Tree 1: statement trace — column count and log size from the AIR.
    let component = FrameworkComponent::new(
        &mut TraceLocationAllocator::default(),
        HandBatchEval::new(expected_claim),
        SecureField::from(0u32),
    );
    let sizes = component.trace_log_degree_bounds();
    let trace_sizes = &sizes[1];
    if trace_sizes.len() != N_COLUMNS {
        return Err(format!("unexpected trace column count: {}", trace_sizes.len()));
    }
    commitment_scheme.commit(stark_proof.commitments[1], trace_sizes, &mut channel);

    verify(
        &[&component],
        &mut channel,
        &mut commitment_scheme,
        stark_proof.clone(),
    )
    .map_err(|e| format!("stwo verify error: {e}"))
}
