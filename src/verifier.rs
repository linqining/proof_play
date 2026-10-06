//! Verifier 入口 — 单方法 verify + 聚合 verify。
//!
//! ## API
//!
//! - [`verify_method`] — 泛型 verify，支持任意 method AIR（阶段 2-4）

use stwo::core::channel::Poseidon252Channel;
use stwo::core::pcs::CommitmentSchemeVerifier;
use stwo::core::vcs_lifted::poseidon252_merkle::Poseidon252MerkleChannel;
use stwo::core::verifier::{VerificationError, verify};
use stwo_constraint_framework::{FrameworkComponent, TraceLocationAllocator};

use crate::airs::TexasAir;
use crate::airs::bound::BoundAir;
use crate::error::{TexasAirError, TexasAirResult};
use crate::prover::MethodProof;
use crate::public_inputs::TexasPublicInputs;

/// 泛型 method verify — 验证任意 method AIR 的 L1 proof。
///
/// 这是低层 proof verifier，不等同于完整 VM 语义或共识来源验证。下注 action AIR
/// 会通过 [`TexasAir::validate_public_inputs`] 重建 canonical table/action；多数 legacy
/// AIR 仍使用默认 no-op hook。需要 verifier-issued receipt 的生产调用方应走
/// [`crate::orchestrator::Orchestrator`]，由其先完整 replay VM dispatch。
///
/// # 参数
/// - `proof`: 由 [`crate::prover::prove_method`] 生成的 `MethodProof<A>`
///
/// # 返回
/// - `Ok(())` — 验证通过
/// - `Err(TexasAirError)` — 验证失败
///
/// # Errors
///
/// - `TexasAirError::ConstraintUnsatisfied` — AIR 约束不满足
/// - `TexasAirError::StwoProverError` — Stwo verifier 内部错误
pub fn verify_method_against<A>(
    proof: MethodProof<A>,
    expected_air: A,
    expected_public_inputs: &TexasPublicInputs,
) -> TexasAirResult<()>
where
    A: TexasAir,
{
    verify_method_inner(proof, expected_air, expected_public_inputs, true)
}

fn verify_method_inner<A>(
    proof: MethodProof<A>,
    expected_air: A,
    expected_public_inputs: &TexasPublicInputs,
    validate_canonical_state: bool,
) -> TexasAirResult<()>
where
    A: TexasAir,
{
    let timing = crate::prove_timing::enabled().then(|| {
        (
            crate::prove_timing::method_label(expected_public_inputs),
            std::time::Instant::now(),
        )
    });
    let config = crate::prover_context::protocol_pcs_config();
    let statement = expected_air.statement();
    if !statement.kind.is_production_air_enabled() {
        return Err(TexasAirError::NotImplemented(format!(
            "{} is a registered selector without an enabled production AIR",
            statement.kind.method_name()
        )));
    }
    expected_public_inputs.verify_roots(&proof.root_binding)?;
    expected_public_inputs.verify_air_statement(&statement)?;
    if validate_canonical_state {
        expected_air.validate_public_inputs(expected_public_inputs)?;
    }
    let log_size = expected_air.log_size();
    let num_columns = expected_air.trace_num_columns();
    if proof.log_size != log_size || proof.num_columns != num_columns {
        return Err(TexasAirError::SpecViolation(format!(
            "proof/AIR shape mismatch: proof=({}, {}), AIR=({}, {})",
            proof.log_size, proof.num_columns, log_size, num_columns
        )));
    }
    let expected_trace_row = expected_public_inputs.require_expected_trace_row(num_columns)?;
    // All other `proof` fields are consumed above; move the (multi-megabyte)
    // StarkProof out instead of deep-cloning its FRI layers. MethodProof has
    // no Drop impl, so the partial move is allowed.
    let stark_proof = proof.stark_proof;

    // 1. Channel + CommitmentSchemeVerifier
    let mut channel = Poseidon252Channel::default();
    expected_public_inputs.mix_into(&mut channel);
    let mut commitment_scheme = CommitmentSchemeVerifier::<Poseidon252MerkleChannel>::new(config);

    // 2. 从 proof 读取 preprocessed commitment（tree 0，空 trace）
    let preprocessed_commitment = *stark_proof.commitments.get(0).ok_or_else(|| {
        TexasAirError::StwoProverError(format!(
            "proof.commitments 长度不足：期望 ≥1，实际 {}",
            stark_proof.commitments.len()
        ))
    })?;
    commitment_scheme.commit(preprocessed_commitment, &[], &mut channel);

    // 3. 从 proof 读取 trace commitment（tree 1，num_columns 列）
    let trace_commitment = *stark_proof.commitments.get(1).ok_or_else(|| {
        TexasAirError::StwoProverError(format!(
            "proof.commitments 长度不足：期望 ≥2，实际 {}",
            stark_proof.commitments.len()
        ))
    })?;
    let trace_log_sizes = vec![log_size; num_columns];
    commitment_scheme.commit(trace_commitment, &trace_log_sizes, &mut channel);

    // 4. Build the component from verifier-trusted AIR data.
    let mut allocator = TraceLocationAllocator::default();
    let component = FrameworkComponent::new(
        &mut allocator,
        BoundAir::new(expected_air, expected_trace_row),
        stwo::core::fields::qm31::SecureField::from(0u32),
    );

    // 5. 验证
    verify(
        &[&component],
        &mut channel,
        &mut commitment_scheme,
        stark_proof,
    )
    .map_err(|e: VerificationError| TexasAirError::ConstraintUnsatisfied(e.to_string()))?;

    if let Some((timing_label, timing_start)) = timing {
        crate::prove_timing::record(
            timing_label,
            crate::prove_timing::TimingKind::Verify,
            timing_start,
            Some(num_columns),
        );
    }
    Ok(())
}

/// Test-only compatibility entry point. Production callers must provide an
/// independently trusted statement through [`verify_method_against`].
#[cfg(any(test, feature = "test-helpers"))]
pub fn verify_method<A>(proof: MethodProof<A>) -> TexasAirResult<()>
where
    A: TexasAir,
{
    let expected_air = proof.air.clone();
    let expected_public_inputs = proof.public_inputs.clone();
    // Historical mechanism tests use synthetic, non-table preimages. This
    // compatibility entry point already trusts proof-carried metadata, so it
    // deliberately skips the production canonical-table validation hook.
    verify_method_inner(proof, expected_air, &expected_public_inputs, false)
}

