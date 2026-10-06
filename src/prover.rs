//! Prover 入口 — 单方法 prove + 聚合 prove。
//!
//! ## API
//!
//! - [`prove_method`] — 泛型 prove，支持任意 method AIR（阶段 2-4）
//! - `aggregate_proofs` — 保护性聚合入口；可信递归闭环完成前默认拒绝

use stwo::core::channel::Poseidon252Channel;
use stwo::core::proof::StarkProof;
use stwo::core::vcs_lifted::poseidon252_merkle::{
    Poseidon252MerkleChannel, Poseidon252MerkleHasher,
};
use stwo::prover::backend::simd::SimdBackend;
use stwo::prover::pcs::CommitmentSchemeProver;
use stwo::prover::{ProvingError, prove};
use stwo_constraint_framework::{FrameworkComponent, TraceLocationAllocator};

use crate::airs::TexasAir;
use crate::airs::bound::BoundAir;
use crate::error::{TexasAirError, TexasAirResult};
use crate::public_inputs::TexasPublicInputs;
use crate::trace_gen::MethodTrace;

/// 泛型 method proof（适用于任意 method AIR）。
///
/// 阶段 2-4 引入：替代为每个方法定义专用 Proof 类型。
#[derive(Debug, Clone)]
pub struct MethodProof<A: TexasAir> {
    /// Stwo 内部 proof。
    pub stark_proof: StarkProof<Poseidon252MerkleHasher>,
    /// AIR 公开输入（用于 verify）。
    pub air: A,
    /// trace log_size。
    pub log_size: u32,
    /// trace 列数（用于 verifier 重建 commitment）。
    pub num_columns: usize,
    /// Flock-proven `root = BLAKE3(hot bytes)` binding for both endpoints.
    pub root_binding: crate::state_root_binding::ArchivedStateRootBindingProof,
    /// Prover-declared public inputs (diagnostic/test transport only).
    /// Production verification must supply an independent expected value.
    pub public_inputs: TexasPublicInputs,
}

/// 泛型 method prove — 生成任意 method AIR 的 L1 proof。
///
/// 这是低层 AIR prover：它要求完整 trusted-row 绑定，但不会自行认证任务来源或
/// replay 整个 VM dispatch。生产 receipt 路径应由 [`crate::orchestrator::Orchestrator`]
/// 先完成这些检查后再调用。
///
/// # 参数
/// - `trace`: 已构造的 `MethodTrace`（trace 数据）
/// - `air`: AIR 公开输入实例
/// - `num_columns`: trace 列数
///
/// # 返回
/// `MethodProof<A>`，可由 [`crate::verifier::verify_method`] 验证。
///
/// # Errors
///
/// - `TexasAirError::StwoProverError` — Stwo prover 内部错误（约束不满足）
pub fn prove_method<A>(
    trace: &MethodTrace,
    air: A,
    num_columns: usize,
    public_inputs: TexasPublicInputs,
) -> TexasAirResult<MethodProof<A>>
where
    A: TexasAir,
{
    let timing = crate::prove_timing::enabled().then(|| {
        (
            crate::prove_timing::method_label(&public_inputs),
            std::time::Instant::now(),
        )
    });
    let log_size = trace.log_size;
    let statement = air.statement();
    if !statement.kind.is_production_air_enabled() {
        return Err(TexasAirError::NotImplemented(format!(
            "{} is a registered selector without an enabled production AIR",
            statement.kind.method_name()
        )));
    }
    if num_columns != trace.num_columns || num_columns != air.trace_num_columns() {
        return Err(TexasAirError::SpecViolation(format!(
            "trace/AIR column mismatch: argument={num_columns}, trace={}, AIR={}",
            trace.num_columns,
            air.trace_num_columns()
        )));
    }
    if trace.log_size != air.log_size() {
        return Err(TexasAirError::SpecViolation(format!(
            "trace/AIR log-size mismatch: trace={}, AIR={}",
            trace.log_size,
            air.log_size()
        )));
    }
    let public_inputs = prepare_public_inputs_for_trace(public_inputs, trace, num_columns)?;
    let root_binding =
        crate::state_root_binding::prove_state_root_binding_for_inputs(&public_inputs)?;
    public_inputs.verify_roots(&root_binding)?;
    public_inputs.verify_air_statement(&statement)?;
    let expected_trace_row = public_inputs.require_expected_trace_row(num_columns)?;

    // 1. PCS 配置 + twiddles
    let config = crate::prover_context::protocol_pcs_config();
    let blowup_log = config.fri_config.log_blowup_factor;
    let twiddles = crate::prover_context::simd_twiddles(log_size + blowup_log);

    // 2. Channel + CommitmentSchemeProver
    let mut channel = Poseidon252Channel::default();
    // soundness 关键：在任何 commit/draw 之前，把完整公开输入 mix 进 Fiat-Shamir channel，
    // 把证明绑定到 state_root（preimage + 重算 root）。详见 TexasPublicInputs。
    public_inputs.mix_into(&mut channel);
    let mut commitment_scheme =
        CommitmentSchemeProver::<SimdBackend, Poseidon252MerkleChannel>::with_memory_pool(
            config,
            &twiddles,
            crate::prover_context::simd_base_column_pool(),
        );

    // 3. 提交空 preprocessed trace（tree 0）
    {
        let mut tree_builder = commitment_scheme.tree_builder();
        tree_builder.extend_evals(vec![]);
        tree_builder.commit(&mut channel);
    }

    // 4. 提交 original trace（tree 1）
    {
        let columns = trace.to_evaluations();
        let mut tree_builder = commitment_scheme.tree_builder();
        tree_builder.extend_evals(columns);
        tree_builder.commit(&mut channel);
    }

    // 5. 构建 AIR component
    let mut allocator = TraceLocationAllocator::default();
    let component = FrameworkComponent::new(
        &mut allocator,
        BoundAir::new(air.clone(), expected_trace_row),
        stwo::core::fields::qm31::SecureField::from(0u32),
    );

    // 6. 生成证明
    let stark_proof = prove(&[&component], &mut channel, commitment_scheme)
        .map_err(|e: ProvingError| TexasAirError::StwoProverError(e.to_string()))?;

    if let Some((timing_label, timing_start)) = timing {
        crate::prove_timing::record(
            timing_label,
            crate::prove_timing::TimingKind::Prove,
            timing_start,
            Some(num_columns),
        );
    }
    Ok(MethodProof {
        stark_proof,
        air,
        log_size,
        num_columns,
        root_binding,
        public_inputs,
    })
}

/// Require a trusted row in production and validate it against the supplied
/// trace. Test-only compatibility builds may derive it from row zero so the
/// historical mechanism tests keep exercising Stwo.
pub(crate) fn prepare_public_inputs_for_trace(
    public_inputs: TexasPublicInputs,
    trace: &MethodTrace,
    num_columns: usize,
) -> TexasAirResult<TexasPublicInputs> {
    let trace_row = trace.first_row()?;
    if trace_row.len() != num_columns {
        return Err(TexasAirError::SpecViolation(format!(
            "trace row width {} does not match declared width {num_columns}",
            trace_row.len()
        )));
    }

    let public_inputs = if public_inputs.expected_trace_row.is_none() {
        #[cfg(any(test, feature = "test-helpers"))]
        {
            let mut public_inputs = public_inputs;
            public_inputs.bind_expected_trace_row(&trace_row)?;
            public_inputs
        }

        #[cfg(not(any(test, feature = "test-helpers")))]
        {
            return Err(TexasAirError::SpecViolation(
                "production proving requires a verifier-reconstructed expected trace row".into(),
            ));
        }
    } else {
        public_inputs
    };

    let expected = public_inputs.require_expected_trace_row(num_columns)?;
    if expected != trace_row {
        return Err(TexasAirError::SpecViolation(
            "prover trace row does not match trusted expected trace row".into(),
        ));
    }
    Ok(public_inputs)
}

